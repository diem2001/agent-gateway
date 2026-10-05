/**
 * A launcher that ends by a signal the gateway did not send (MVP-7964): the compiled gateway
 * (`dist/server.js`, built by `npm run build`) runs as a child process with the production Claude Agent
 * SDK, its bundled runtime inside a real bubblewrap sandbox, and a scripted Anthropic API that never
 * answers the agent request ("hang"). The test ends the runtime's launcher, the sandbox process the
 * gateway spawned, from outside, and reads what the client and the operator log show.
 *
 * - R1: the real launcher is SIGKILLed from outside while its output is open.
 * - R2: a test-owned `AGENT_SANDBOX_BWRAP` wrapper keeps the launcher's output open through a helper
 *   process of its own, is SIGKILLed from outside, and the test ends the helper later: the output
 *   stays open after the launcher exit, and a late end of the output must change nothing.
 * - R3: the client goes away: the gateway's own cleanup ends the launcher and is not an outside kill.
 * - R4: the run deadline ends the launcher, again the gateway's own cleanup.
 * - R5 (MVP-8000, the Outcome Probe of the run deadline): the SDK ignores the abort (a patched copy of `dist/` hands the
 *   SDK a private abort controller that never fires), so the runtime stays alive and the SDK iterator never settles;
 *   the run deadline must still end the request within limit + 2 s, kill the sandbox, revoke the run's model proxy
 *   token, free the conversation and leave the gateway alive. `MVP8000_DIST_ROOT` names a tree whose `dist/` the
 *   patched copy is made from (the red run on the baseline); default is this worktree.
 *
 * The kill rows bound the end of the request at 10 s after the kill with the run deadline at 120 s
 * (`MVP7964_KILL_ROW_TIMEOUT_MS` overrides the deadline for the red run on the baseline). Expected texts
 * are written out here (not imported from run-failure.ts). Linux only: /proc and bwrap.
 */
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { startFakeAnthropicApi, type FakeAnthropicApi } from "./helpers/fake-anthropic-api.js";
import { GATEWAY_API_KEY, REPO_ROOT, descendants, gatewayRequest, spawnGateway, type Cleanup, type SpawnedGateway } from "./helpers/git-process-gateway.js";

const KILL_ROW_DEADLINE_MS = Number(process.env.MVP7964_KILL_ROW_TIMEOUT_MS ?? "120000");
/** The end of the request must follow the kill within this bound, far below the run deadline. */
const END_BOUND_MS = 10_000;

const unknownFailure = (queryId: string): string =>
  `The AI request failed on the gateway for an unknown reason. Please try again. If it keeps failing, ask your gateway administrator to check the gateway logs (reference: ${queryId}).`;

const deadlineFailure = (queryId: string): string =>
  `The request was stopped because it ran longer than the gateway's limit of 1 minute. Its results were not saved. Try again with a smaller task, or ask your gateway administrator to raise the limit. (reference: ${queryId})`;

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

/** The sandbox process the gateway spawned for the run: its direct child started with `--args` (bwrap) or the wrapper. */
function launcherOf(gw: SpawnedGateway): number | null {
  return directChildren(gw.child.pid!).find((pid) => cmdline(pid).includes("--args")) ?? null;
}

/**
 * A bwrap stand-in for R2. In mode `pass` (the boot self-check) it runs the real bwrap; in mode `hold` it runs the real bwrap in the background and starts a `sleep` helper that
 * inherits the launcher's output, records the helper's pid, waits for the trigger file and then
 * SIGKILLs itself, so the launcher ends while the helper keeps the output pipe open.
 */
function makeHoldWrapper(): { path: string; hold: () => void; trigger: () => void; helperPid: () => number | null; endHelper: () => void } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mvp7964-launcher-"));
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
sleep 600 <&- &
echo $! > "$DIR/helper.pid"
echo $REAL > "$DIR/real.pid"
while [ ! -e "$DIR/trigger" ]; do sleep 0.05; done
echo SENTINEL-STDERR >&2
kill -KILL $$
`,
    { mode: 0o755 },
  );
  const pidOf = (name: string): number | null => {
    try {
      const pid = Number(fs.readFileSync(path.join(dir, name), "utf8").trim());
      return Number.isInteger(pid) && pid > 0 ? pid : null;
    } catch {
      return null;
    }
  };
  /** Ends a pid this wrapper started, only while it still is that process. */
  const endOwned = (name: string, marker: string): void => {
    const pid = pidOf(name);
    if (pid !== null && cmdline(pid).includes(marker)) {
      try {
        process.kill(pid, "SIGKILL");
      } catch {
        // Already gone.
      }
    }
  };
  cleanups.push(() => {
    endOwned("helper.pid", "sleep 600");
    endOwned("real.pid", "--args");
    fs.rmSync(dir, { recursive: true, force: true });
  });
  return {
    path: script,
    hold: () => fs.writeFileSync(path.join(dir, "mode"), "hold"),
    trigger: () => fs.writeFileSync(path.join(dir, "trigger"), ""),
    helperPid: () => pidOf("helper.pid"),
    endHelper: () => endOwned("helper.pid", "sleep 600"),
  };
}

async function rig(options: { wrapperPath?: string; deadlineMs: number; distServer?: string }): Promise<{ api: FakeAnthropicApi; gw: SpawnedGateway }> {
  const api = await startFakeAnthropicApi({ toolName: "no-such-tool-7964", mode: "hang" });
  cleanups.push(() => api.close());
  const gw = await spawnGateway(cleanups, {
    rootPrefix: "mvp7964-gw-",
    distServer: options.distServer,
    env: {
      ANTHROPIC_BASE_URL: api.baseUrl,
      ANTHROPIC_API_KEY: "sk-ant-fake-launcher-kill-7964",
      DISABLE_TELEMETRY: "1",
      CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
      AGENT_RUN_TIMEOUT_MS: String(options.deadlineMs),
      ...(options.wrapperPath ? { AGENT_SANDBOX_BWRAP: options.wrapperPath } : {}),
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
  /** Milliseconds from the end of `disturb` to the end of the response. */
  endedAfterMs: number;
}

/** Starts a query, waits until the runtime's request reached the fake API, runs `disturb`, and returns the finished outcome. */
async function disturbedQuery(gw: SpawnedGateway, api: FakeAnthropicApi, disturb: () => Promise<void> | void): Promise<Outcome> {
  const queryId = `q7964-${randomBytes(4).toString("hex")}`;
  const response = gatewayRequest(gw.port, "POST", "/v1/query", { queryId, prompt: "hi", model: "claude-opus-5-5", useSession: false });
  await waitFor("the runtime's request at the fake API", () => api.mainRequests().length > 0);
  await disturb();
  const disturbedAt = Date.now();
  const res = await response;
  const endedAfterMs = Date.now() - disturbedAt;
  expect(res.status).toBe(200);
  await waitFor("no runtime process left", () => descendants(gw.child.pid!).length === 0);
  const replay = await gatewayRequest(gw.port, "GET", `/v1/query/${queryId}/events`);
  expect(replay.status).toBe(200);
  return { queryId, events: parseNdjson(res.text), text: res.text, replayText: replay.text, endedAfterMs };
}

/** The client saw exactly one terminal error with the given text, no `done`, and no raw material reached it or the gateway output. */
function expectOneError(outcome: Outcome, gw: SpawnedGateway, content: string): void {
  const errors = outcome.events.filter((e) => e.type === "error");
  expect.soft(errors).toHaveLength(1);
  expect.soft(outcome.events.at(-1)?.type).toBe("error");
  expect.soft(Object.keys(errors[0] ?? {}).sort()).toEqual(["content", "seq", "type"]);
  expect.soft(errors[0]?.content).toBe(content);
  expect.soft(outcome.events.some((e) => e.type === "done")).toBe(false);
  expect.soft(parseNdjson(outcome.replayText)).toEqual(outcome.events);
  for (const marker of RAW_MARKERS) {
    expect.soft(outcome.text, `the stream contains ${marker}`).not.toContain(marker);
    expect.soft(outcome.replayText, `the replay contains ${marker}`).not.toContain(marker);
    expect.soft(gw.output(), `the gateway output contains ${marker}`).not.toContain(marker);
  }
}

/** Every operator failure line of this reference. */
function linesOf(gw: SpawnedGateway, queryId: string): string[] {
  return gw
    .output()
    .split("\n")
    .filter((line) => line.includes(`Error queryId=${queryId}`))
    .map((line) => line.slice(line.indexOf("Error queryId=")));
}

const tailOf = (line: string): string => line.split(" ").slice(-4).join(" ");

async function expectHealthy(gw: SpawnedGateway): Promise<void> {
  const health = await gatewayRequest(gw.port, "GET", "/health");
  expect(health.status).toBe(200);
}

/** The exact one-line evidence of a kill row, to stderr (vitest swallows console.log of passing tests). */
function evidence(row: string, outcome: Outcome, line: string | undefined): void {
  process.stderr.write(`LAUNCHER-KILL-EVIDENCE ${row} endedAfterMs=${outcome.endedAfterMs} line=${line ?? "none"}\n`);
}

describe("an outside signal ends the launcher: the request ends promptly with one unknown failure (real runtime, real bwrap)", () => {
  it("R1: SIGKILL of the real launcher while its output is open: ends within the bound, signal=SIGKILL, one error", async () => {
    const { api, gw } = await rig({ deadlineMs: KILL_ROW_DEADLINE_MS });

    const outcome = await disturbedQuery(gw, api, () => {
      const launcher = launcherOf(gw);
      expect(launcher, "the gateway's sandbox launcher process").not.toBeNull();
      process.kill(launcher!, "SIGKILL");
    });

    const lines = linesOf(gw, outcome.queryId);
    evidence("R1", outcome, lines[0]);
    expect.soft(outcome.endedAfterMs, "the request ended within the bound after the kill").toBeLessThan(END_BOUND_MS);
    expectOneError(outcome, gw, unknownFailure(outcome.queryId));
    expect(lines).toHaveLength(1);
    expect.soft(lines[0].startsWith(`Error queryId=${outcome.queryId} kind=unknown apiStatus=none providerType=none installed=`)).toBe(true);
    expect.soft(tailOf(lines[0])).toMatch(/^errorClass=(Error|none) errno=none exit=none signal=SIGKILL$/);
    await expectHealthy(gw);
  }, 180_000);

  it("R2: launcher SIGKILLed while a helper holds its output open: same outcome, and a late end of the output changes nothing", async () => {
    const wrapper = makeHoldWrapper();
    const { api, gw } = await rig({ wrapperPath: wrapper.path, deadlineMs: KILL_ROW_DEADLINE_MS });
    wrapper.hold();

    const outcome = await disturbedQuery(gw, api, async () => {
      await waitFor("the wrapper's helper process", () => wrapper.helperPid() !== null);
      wrapper.trigger();
    });

    const lines = linesOf(gw, outcome.queryId);
    evidence("R2", outcome, lines[0]);
    expect.soft(outcome.endedAfterMs, "the request ended within the bound after the kill").toBeLessThan(END_BOUND_MS);
    expectOneError(outcome, gw, unknownFailure(outcome.queryId));
    expect(lines).toHaveLength(1);
    expect.soft(tailOf(lines[0])).toBe("errorClass=none errno=none exit=none signal=SIGKILL");

    // The output stream ends late: nothing more reaches the client or the log, and the gateway lives on.
    wrapper.endHelper();
    await sleep(3_000);
    const replay = await gatewayRequest(gw.port, "GET", `/v1/query/${outcome.queryId}/events`);
    expect(parseNdjson(replay.text)).toEqual(outcome.events);
    expect(linesOf(gw, outcome.queryId)).toEqual(lines);
    await expectHealthy(gw);
  }, 180_000);

  it("R3: the client goes away: only the aborted line, no unknown failure, no signal=SIGKILL", async () => {
    const { api, gw } = await rig({ deadlineMs: KILL_ROW_DEADLINE_MS });
    const queryId = `q7964-${randomBytes(4).toString("hex")}`;
    const payload = Buffer.from(JSON.stringify({ queryId, prompt: "hi", model: "claude-opus-5-5", useSession: false }), "utf8");
    const req = http.request({
      host: "127.0.0.1",
      port: gw.port,
      method: "POST",
      path: "/v1/query",
      agent: false,
      headers: { Authorization: `Bearer ${GATEWAY_API_KEY}`, "Content-Type": "application/json", "Content-Length": payload.length },
    });
    req.on("error", () => {});
    req.on("response", (res) => res.resume());
    req.end(payload);
    await waitFor("the runtime's request at the fake API", () => api.mainRequests().length > 0);
    req.destroy();

    await waitFor("the aborted line", () => linesOf(gw, queryId).length > 0, 20_000);
    await waitFor("no runtime process left", () => descendants(gw.child.pid!).length === 0);
    await sleep(3_000);
    const lines = linesOf(gw, queryId);
    expect(lines).toEqual([`Error queryId=${queryId} kind=aborted`]);
    expect(gw.output()).not.toContain("signal=SIGKILL");
    await expectHealthy(gw);
  }, 180_000);

  it("R4: the run deadline: one deadline error and line, no unknown failure, no signal=SIGKILL", async () => {
    const { api, gw } = await rig({ deadlineMs: 8_000 });
    const queryId = `q7964-${randomBytes(4).toString("hex")}`;
    const res = await gatewayRequest(gw.port, "POST", "/v1/query", { queryId, prompt: "hi", model: "claude-opus-5-5", useSession: false });
    expect(res.status).toBe(200);
    expect(api.mainRequests().length).toBeGreaterThan(0);
    await waitFor("no runtime process left", () => descendants(gw.child.pid!).length === 0);
    await sleep(3_000);
    const outcome: Outcome = { queryId, events: parseNdjson(res.text), text: res.text, replayText: res.text, endedAfterMs: 0 };

    expectOneError(outcome, gw, deadlineFailure(queryId));
    const lines = linesOf(gw, queryId);
    expect(lines).toHaveLength(1);
    expect(lines[0]).toContain("kind=run_deadline");
    expect(lines[0]).not.toContain("kind=unknown");
    expect(gw.output()).not.toContain("signal=SIGKILL");
    await expectHealthy(gw);
  }, 180_000);
});

/**
 * A copy of `dist/` whose SDK call gets a private abort controller that never fires: the SDK then ignores the run's
 * abort, the runtime stays alive and the SDK's iterator never settles (the case MVP-8000 closes). The patch is checked
 * to apply, so a changed call site fails loudly instead of testing nothing.
 */
function ignoresAbortDist(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "mvp8000-dist-"));
  cleanups.push(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.cpSync(path.join(process.env.MVP8000_DIST_ROOT ?? REPO_ROOT, "dist"), path.join(root, "dist"), { recursive: true });
  fs.copyFileSync(path.join(REPO_ROOT, "package.json"), path.join(root, "package.json"));
  fs.symlinkSync(path.join(REPO_ROOT, "node_modules"), path.join(root, "node_modules"));
  const file = path.join(root, "dist", "agent.js");
  const source = fs.readFileSync(file, "utf8");
  const call = "query({ prompt: promptArg, options })";
  expect(source, "the SDK call site in dist/agent.js").toContain(call);
  fs.writeFileSync(file, source.replace(call, "query({ prompt: promptArg, options: { ...options, abortController: new AbortController() } })"));
  return path.join(root, "dist", "server.js");
}

/** The run token and the model proxy URL the runtime of the running sandbox was given (its launcher's own environment). */
function runtimeProxyOf(gw: SpawnedGateway): { token: string; baseUrl: URL } {
  const launcher = launcherOf(gw);
  expect(launcher, "the gateway's sandbox launcher process").not.toBeNull();
  const env = new Map(
    fs
      .readFileSync(`/proc/${launcher}/environ`, "utf8")
      .split("\0")
      .filter((entry) => entry.includes("="))
      .map((entry) => [entry.slice(0, entry.indexOf("=")), entry.slice(entry.indexOf("=") + 1)] as const),
  );
  return { token: env.get("ANTHROPIC_API_KEY") ?? "", baseUrl: new URL(env.get("ANTHROPIC_BASE_URL") ?? "http://invalid") };
}

/** One POST to the model proxy with the given run token; resolves with the HTTP status. */
function proxyStatus(proxy: { token: string; baseUrl: URL }): Promise<number> {
  return new Promise((resolve, reject) => {
    const payload = Buffer.from(JSON.stringify({ model: "claude-opus-5-5", max_tokens: 8, messages: [{ role: "user", content: "token control" }] }), "utf8");
    const req = http.request(
      { host: proxy.baseUrl.hostname, port: Number(proxy.baseUrl.port), method: "POST", path: "/v1/messages", agent: false, headers: { "x-api-key": proxy.token, "anthropic-version": "2023-06-01", "Content-Type": "application/json", "Content-Length": payload.length } },
      (res) => {
        res.resume();
        res.on("end", () => resolve(res.statusCode ?? 0));
      },
    );
    req.on("error", reject);
    req.end(payload);
  });
}

describe("the run deadline ends the request although the SDK ignores the abort (MVP-8000, real runtime, real bwrap)", () => {
  it("R5: ends within limit + 2 s with one deadline error, kills the sandbox, revokes the proxy token, frees the conversation", async () => {
    const LIMIT_MS = 3_000;
    const { api, gw } = await rig({ deadlineMs: LIMIT_MS, distServer: ignoresAbortDist() });
    const queryId = `q8000-${randomBytes(4).toString("hex")}`;
    const conversation = `conv8000-${randomBytes(4).toString("hex")}`;
    const started = Date.now();
    const response = gatewayRequest(gw.port, "POST", "/v1/query", { queryId, sessionId: conversation, prompt: "hi", model: "claude-opus-5-5", useSession: true });
    const settled = response.then((res) => res);
    await waitFor("the runtime's request at the fake API", () => api.mainRequests().length > 0).catch((error: unknown) => {
      throw new Error(`${String(error)}; gateway output: ${gw.output().slice(-1500)}`);
    });
    const proxy = runtimeProxyOf(gw);
    expect(proxy.token.startsWith("mpt_"), "the run's model proxy token").toBe(true);
    // Control: while the run is live its token is accepted by the proxy, so a refusal later is the revocation.
    expect(await proxyStatus(proxy)).toBe(200);

    const res = await Promise.race([settled, sleep(LIMIT_MS + 2_000).then(() => null)]);
    const endedAfterMs = Date.now() - started;
    process.stderr.write(`DEADLINE-UNCOOPERATIVE-EVIDENCE R5 endedAfterMs=${endedAfterMs} limitMs=${LIMIT_MS} open=${res === null}\n`);
    expect(res, `the request was still open ${endedAfterMs} ms after it started (limit ${LIMIT_MS} ms)`).not.toBeNull();
    expect(res!.status).toBe(200);
    expect(endedAfterMs).toBeGreaterThanOrEqual(LIMIT_MS);
    expect(endedAfterMs).toBeLessThan(LIMIT_MS + 2_000);

    const events = parseNdjson(res!.text);
    const outcome: Outcome = { queryId, events, text: res!.text, replayText: (await gatewayRequest(gw.port, "GET", `/v1/query/${queryId}/events`)).text, endedAfterMs };
    expectOneError(outcome, gw, deadlineFailure(queryId));
    const lines = linesOf(gw, queryId);
    expect(lines).toHaveLength(1);
    expect(lines[0]).toContain("kind=run_deadline");
    expect(gw.output()).not.toContain("signal=SIGKILL");
    expect(gw.output()).not.toContain("kind=unknown");

    // The sandbox was killed by the stop itself: nothing of it is left within a second of the answer.
    await waitFor("no runtime process left", () => descendants(gw.child.pid!).length === 0, 1_000);
    // The run's model proxy token no longer works.
    expect(await proxyStatus(proxy)).toBe(401);

    // The conversation is free again: a follow-up is admitted and completes (a run with no tool at all is answered by the fake API).
    const followUp = await gatewayRequest(gw.port, "POST", "/v1/query", { queryId: `${queryId}-next`, sessionId: conversation, prompt: "hi again", model: "claude-opus-5-5", useSession: true, enforcedTools: [] });
    const followEvents = parseNdjson(followUp.text);
    expect(followEvents.some((e) => e.type === "done"), followUp.text).toBe(true);
    expect(followEvents.some((e) => e.type === "error")).toBe(false);

    await sleep(1_000);
    const output = gw.output();
    for (const text of ["Unhandled", "unhandled", "Uncaught", "uncaught"]) expect(output, `the gateway output contains ${text}`).not.toContain(text);
    expect(gw.child.exitCode).toBeNull();
    expect(gw.child.signalCode).toBeNull();
    await expectHealthy(gw);
  }, 180_000);
});

