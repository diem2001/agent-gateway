/**
 * Cause metadata of an unknown failure through the real runtime (MVP-7852): the compiled gateway
 * (`dist/server.js`, built by `npm run build`) runs as a child process with the production Claude
 * Agent SDK, its bundled runtime inside a real bubblewrap sandbox, and a scripted Anthropic API that
 * never answers the agent request ("hang"). The test ends the runtime's launcher, the sandbox
 * process the gateway spawned, and reads what the client and the operator log show.
 *
 * - exit 3: a test-owned `AGENT_SANDBOX_BWRAP` wrapper runs the real bwrap, then ends it and exits 3.
 * - SIGKILL: the same wrapper ends the real bwrap, closes its own output so the runtime's output stream
 *   ends first, and then SIGKILLs itself: the gateway's launcher process is terminated by SIGKILL.
 *   (An external SIGKILL of the launcher while its output is still open is not this row: the SDK
 *   never learns of it, and the gateway ends the run itself; see launcher-external-kill-process.test.ts.)
 * - Documented behavior, not an acceptance row: a runtime killed INSIDE the sandbox makes the launcher
 *   exit 137, so the line shows `exit=137 signal=none`, never `signal=SIGKILL`.
 *
 * Expected texts are written out here (not imported from run-failure.ts). Linux only: /proc and bwrap.
 */
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { startFakeAnthropicApi, type FakeAnthropicApi } from "./helpers/fake-anthropic-api.js";
import { descendants, gatewayRequest, spawnGateway, type Cleanup, type SpawnedGateway } from "./helpers/git-process-gateway.js";

const unknownFailure = (queryId: string): string =>
  `The AI request failed on the gateway for an unknown reason. Please try again. If it keeps failing, ask your gateway administrator to check the gateway logs (reference: ${queryId}).`;

/** Material the runtime, the wrapper or the SDK error text carry; none may reach a client or the gateway output. */
const RAW_MARKERS = ["SENTINEL-STDERR", "Claude Code process exited", "terminated by signal", "API Error"];

const cleanups: Cleanup[] = [];

afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()!();
});

interface NdjsonEvent {
  seq: number;
  type: string;
  [key: string]: unknown;
}

function parseNdjson(text: string): NdjsonEvent[] {
  return text
    .split("\n")
    .filter((line) => line.trim().length > 0)
    .map((line) => JSON.parse(line) as NdjsonEvent);
}

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

async function waitFor(what: string, condition: () => boolean, timeoutMs = 30_000): Promise<void> {
  const end = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}`);
    await sleep(50);
  }
}

function directChildren(pid: number): number[] {
  const found: number[] = [];
  for (const task of fs.readdirSync(`/proc/${pid}/task`)) {
    try {
      const text = fs.readFileSync(`/proc/${pid}/task/${task}/children`, "utf8").trim();
      if (text) found.push(...text.split(/\s+/).map(Number));
    } catch {
      // Thread ended while reading.
    }
  }
  return found;
}

function cmdline(pid: number): string {
  try {
    return fs.readFileSync(`/proc/${pid}/cmdline`, "utf8").replaceAll("\0", " ");
  } catch {
    return "";
  }
}

/** The sandbox process the gateway spawned for the run: its direct child started with `--args` (bwrap). */
function launcherOf(gw: SpawnedGateway): number | null {
  return directChildren(gw.child.pid!).find((pid) => cmdline(pid).includes("--args")) ?? null;
}

type WrapperMode = "pass" | "exit3" | "sigkill";

/**
 * A bwrap stand-in. `pass` runs the real bwrap. The other modes run it, wait for a trigger file and end it:
 * `exit3` then exits 3, `sigkill` closes its own output and SIGKILLs itself half a second later.
 */
function makeWrapper(): { path: string; setMode: (mode: WrapperMode) => void; trigger: () => void } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mvp7852-launcher-"));
  cleanups.push(() => fs.rmSync(dir, { recursive: true, force: true }));
  const script = path.join(dir, "bwrap");
  fs.writeFileSync(path.join(dir, "mode"), "pass");
  fs.writeFileSync(
    script,
    String.raw`#!/bin/bash
DIR='${dir}'
MODE=$(cat "$DIR/mode" 2>/dev/null || echo pass)
if [ "$MODE" = pass ]; then exec /usr/bin/bwrap "$@"; fi
exec 5<&0
/usr/bin/bwrap "$@" <&5 &
REAL=$!
while [ ! -e "$DIR/trigger" ]; do sleep 0.05; done
echo SENTINEL-STDERR >&2
kill -KILL "$REAL" 2>/dev/null
wait "$REAL" 2>/dev/null
if [ "$MODE" = exit3 ]; then exit 3; fi
exec 1>&- 2>&-
sleep 0.5
kill -KILL $$
`,
    { mode: 0o755 },
  );
  return {
    path: script,
    setMode: (mode) => fs.writeFileSync(path.join(dir, "mode"), mode),
    trigger: () => fs.writeFileSync(path.join(dir, "trigger"), ""),
  };
}

async function rig(wrapperPath?: string): Promise<{ api: FakeAnthropicApi; gw: SpawnedGateway }> {
  const api = await startFakeAnthropicApi({ toolName: "no-such-tool-7852", mode: "hang" });
  cleanups.push(() => api.close());
  const gw = await spawnGateway(cleanups, {
    rootPrefix: "mvp7852-gw-",
    env: {
      ANTHROPIC_BASE_URL: api.baseUrl,
      ANTHROPIC_API_KEY: "sk-ant-fake-cause-fields-7852",
      DISABLE_TELEMETRY: "1",
      CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
      ...(wrapperPath ? { AGENT_SANDBOX_BWRAP: wrapperPath } : {}),
    },
  });
  const end = Date.now() + 20_000;
  for (;;) {
    const health = await gatewayRequest(gw.port, "GET", "/health");
    if (health.json?.isolation === "ok") break;
    if (Date.now() > end) throw new Error(`isolation is ${String(health.json?.isolation)}`);
    await sleep(100);
  }
  return { api, gw };
}

interface Outcome {
  queryId: string;
  events: NdjsonEvent[];
  text: string;
  replayText: string;
}

/** Starts a query, waits until the runtime's request reached the fake API, runs `disturb`, and returns the finished outcome. */
async function failedQuery(gw: SpawnedGateway, api: FakeAnthropicApi, disturb: () => Promise<void> | void): Promise<Outcome> {
  const queryId = `q7852-${randomBytes(4).toString("hex")}`;
  const response = gatewayRequest(gw.port, "POST", "/v1/query", { queryId, prompt: "hi", model: "claude-opus-5-5", useSession: false });
  await waitFor("the runtime's request at the fake API", () => api.mainRequests().length > 0);
  await disturb();
  const res = await response;
  expect(res.status).toBe(200);
  await waitFor("no runtime process left", () => descendants(gw.child.pid!).length === 0);
  const replay = await gatewayRequest(gw.port, "GET", `/v1/query/${queryId}/events`);
  expect(replay.status).toBe(200);
  return { queryId, events: parseNdjson(res.text), text: res.text, replayText: replay.text };
}

/** The client saw one unchanged unknown error with the reference, and no raw material reached it or the gateway output. */
function expectUnknownFailure(outcome: Outcome, gw: SpawnedGateway): void {
  const errors = outcome.events.filter((e) => e.type === "error");
  expect.soft(errors).toHaveLength(1);
  expect.soft(outcome.events.at(-1)?.type).toBe("error");
  expect.soft(Object.keys(errors[0] ?? {}).sort()).toEqual(["content", "seq", "type"]);
  expect.soft(errors[0]?.content).toBe(unknownFailure(outcome.queryId));
  expect.soft(outcome.events.some((e) => e.type === "done")).toBe(false);
  expect.soft(parseNdjson(outcome.replayText)).toEqual(outcome.events);
  for (const marker of RAW_MARKERS) {
    expect.soft(outcome.text, `the stream contains ${marker}`).not.toContain(marker);
    expect.soft(outcome.replayText, `the replay contains ${marker}`).not.toContain(marker);
    expect.soft(gw.output(), `the gateway output contains ${marker}`).not.toContain(marker);
  }
}

/** The operator line of this reference. */
function operatorLine(gw: SpawnedGateway, queryId: string): string {
  const lines = gw.output().split("\n").filter((line) => line.includes(`Error queryId=${queryId} `));
  expect(lines).toHaveLength(1);
  return lines[0].slice(lines[0].indexOf("Error queryId="));
}

const PREFIX = (queryId: string): string => `Error queryId=${queryId} kind=unknown apiStatus=none providerType=none installed=`;
const tailOf = (line: string): string => line.split(" ").slice(-4).join(" ");

describe("the referenced log line names the cause of an unknown failure (real runtime, real bwrap)", () => {
  it("runtime process exits with code 3: errorClass=Error errno=none exit=3 signal=none", async () => {
    const wrapper = makeWrapper();
    const { api, gw } = await rig(wrapper.path);
    wrapper.setMode("exit3");

    const outcome = await failedQuery(gw, api, () => wrapper.trigger());

    expectUnknownFailure(outcome, gw);
    const line = operatorLine(gw, outcome.queryId);
    expect(line.startsWith(PREFIX(outcome.queryId))).toBe(true);
    expect(tailOf(line)).toBe("errorClass=Error errno=none exit=3 signal=none");
  }, 120_000);

  it("runtime process is terminated by SIGKILL (the launcher): errorClass=Error errno=none exit=none signal=SIGKILL", async () => {
    const wrapper = makeWrapper();
    const { api, gw } = await rig(wrapper.path);
    wrapper.setMode("sigkill");

    const outcome = await failedQuery(gw, api, () => wrapper.trigger());

    expectUnknownFailure(outcome, gw);
    const line = operatorLine(gw, outcome.queryId);
    expect(line.startsWith(PREFIX(outcome.queryId))).toBe(true);
    expect(tailOf(line)).toBe("errorClass=Error errno=none exit=none signal=SIGKILL");
  }, 120_000);

  it("documented limit: a runtime killed with SIGKILL inside the sandbox shows exit=137 and signal=none", async () => {
    const { api, gw } = await rig();

    const outcome = await failedQuery(gw, api, () => {
      const launcher = launcherOf(gw);
      expect(launcher, "the gateway's sandbox launcher process").not.toBeNull();
      const runtime = descendants(launcher!).find((pid) => /cli\.js|claude/.test(cmdline(pid)));
      expect(runtime, "the runtime process inside the sandbox").toBeDefined();
      process.kill(runtime!, "SIGKILL");
    });

    expectUnknownFailure(outcome, gw);
    const line = operatorLine(gw, outcome.queryId);
    expect(tailOf(line)).toBe("errorClass=Error errno=none exit=137 signal=none");
  }, 120_000);
});
