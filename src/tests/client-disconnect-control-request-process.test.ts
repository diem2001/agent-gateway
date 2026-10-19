/**
 * A client that disconnects while its run is still handling a tool call (MVP-7866): the compiled gateway
 * (`dist/server.js`, built by `npm run build`) runs as a child process with the production Claude Agent SDK
 * (0.1.77), its bundled runtime inside a real bubblewrap sandbox, and a scripted Anthropic API. The model
 * calls a registered webhook tool; a loopback webhook stub holds that call open until the test releases it.
 *
 * The SDK answers a runtime's tool call (a control request) from a promise nobody awaits. When the answer is
 * written after the run was aborted, the write throws; without a guard that rejection ends the whole gateway
 * process. The rows measure what other clients and the operator see, not the SDK's internals.
 *
 * - P1: client A disconnects while its webhook call is held; the held call is released after A's launcher is
 *   gone but while the runtime's output is still open (a `AGENT_SANDBOX_BWRAP` wrapper keeps it open through a
 *   helper process, the shape of the owned chain where the runtime kept running after the abort). Client B is
 *   mid-run on the same gateway the whole time.
 * - P2: the same flow with the real launcher (no wrapper) and the release 0 ms and 20 ms after the disconnect.
 * - P3: control, nobody disconnects.
 *
 * Counts at the model boundary: requests the fake Anthropic API received for A's prompt. Linux only: /proc and bwrap.
 */
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import net, { type AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { FINAL_ANSWER, startFakeAnthropicApi, type FakeAnthropicApi } from "./helpers/fake-anthropic-api.js";
import { GATEWAY_API_KEY, gatewayRequest, spawnGateway, type Cleanup, type SpawnedGateway } from "./helpers/git-process-gateway.js";

const PROMPT_A = "PROBE-7866-A hold the tool call";
const PROMPT_B = "PROBE-7866-B hold the tool call";
const TOOL_A = "mcp__agent-gateway-tools__probe_hold_a";
const TOOL_B = "mcp__agent-gateway-tools__probe_hold_b";
/** The operator line the gateway writes when a client's abort is the cause of the end of a run. */
const GUARD_LINE = "late abort rejection ignored";

const cleanups: Cleanup[] = [];

afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()!();
});

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

async function waitFor(what: string, condition: () => boolean, timeoutMs = 30_000): Promise<void> {
  const end = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}`);
    await sleep(50);
  }
}

function cmdline(pid: number): string {
  try {
    return fs.readFileSync(`/proc/${pid}/cmdline`, "utf8").replaceAll("\0", " ");
  } catch {
    return "";
  }
}

/* ------------------------------------------------------------------ */
/*  Webhook stub that holds each call until released                    */
/* ------------------------------------------------------------------ */

interface HoldingServer {
  base: string;
  /** Paths of the requests that arrived, in order. */
  hits: string[];
  /** Answers every held request of `urlPath` (and any later one at once). */
  release: (urlPath: string) => void;
}

async function holdingServer(): Promise<HoldingServer> {
  const hits: string[] = [];
  const held = new Map<string, http.ServerResponse[]>();
  const released = new Set<string>();
  const sockets = new Set<net.Socket>();
  const answer = (res: http.ServerResponse, urlPath: string): void => {
    try {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ output: `HELD-ANSWER ${urlPath}` }));
    } catch {
      // The caller already went away.
    }
  };
  const server = http.createServer((req, res) => {
    const urlPath = req.url ?? "";
    hits.push(urlPath);
    req.resume();
    req.on("end", () => {
      if (released.has(urlPath)) return answer(res, urlPath);
      held.set(urlPath, [...(held.get(urlPath) ?? []), res]);
    });
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  cleanups.push(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
  return {
    base: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    hits,
    release: (urlPath) => {
      released.add(urlPath);
      for (const res of held.get(urlPath) ?? []) answer(res, urlPath);
      held.delete(urlPath);
    },
  };
}

/* ------------------------------------------------------------------ */
/*  Launcher wrapper that keeps the runtime's output open               */
/* ------------------------------------------------------------------ */

interface HoldWrapper {
  path: string;
  /** The NEXT launch is held; the launch after it and every other one passes through to the real bwrap. */
  holdNextLaunch: () => void;
  launcherPid: () => number | null;
  endHelper: () => void;
}

/**
 * A bwrap stand-in. A launch that claims the one-shot `hold` marker runs the real bwrap in the background and
 * starts a `sleep` helper that inherits the launcher's output, so the output stays open after the launcher is
 * terminated by the SDK's SIGTERM; every other launch (the boot self-check, the other client) runs the real bwrap.
 */
function makeHoldWrapper(): HoldWrapper {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mvp7866-launcher-"));
  const script = path.join(dir, "bwrap");
  fs.writeFileSync(
    script,
    String.raw`#!/bin/bash
DIR='${dir}'
if ! mv "$DIR/hold" "$DIR/held" 2>/dev/null; then exec /usr/bin/bwrap "$@"; fi
exec 5<&0
/usr/bin/bwrap "$@" <&5 &
REAL=$!
sleep 600 <&- &
echo $! > "$DIR/helper.pid"
echo $REAL > "$DIR/real.pid"
echo $$ > "$DIR/launcher.pid"
while true; do sleep 0.05; done
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
    endOwned("launcher.pid", "--args");
    fs.rmSync(dir, { recursive: true, force: true });
  });
  return {
    path: script,
    holdNextLaunch: () => fs.writeFileSync(path.join(dir, "hold"), ""),
    launcherPid: () => pidOf("launcher.pid"),
    endHelper: () => endOwned("helper.pid", "sleep 600"),
  };
}

/* ------------------------------------------------------------------ */
/*  Rig                                                                 */
/* ------------------------------------------------------------------ */

interface Rig {
  api: FakeAnthropicApi;
  gw: SpawnedGateway;
  webhook: HoldingServer;
}

async function rig(wrapperPath?: string): Promise<Rig> {
  const webhook = await holdingServer();
  const api = await startFakeAnthropicApi({
    toolName: "unused-7866",
    exactTool: [
      { name: TOOL_A, input: { id: "A" }, prompt: PROMPT_A },
      { name: TOOL_B, input: { id: "B" }, prompt: PROMPT_B },
    ],
  });
  cleanups.push(() => api.close());
  const gw = await spawnGateway(cleanups, {
    rootPrefix: "mvp7866-gw-",
    env: {
      ANTHROPIC_BASE_URL: api.baseUrl,
      ANTHROPIC_API_KEY: "sk-ant-fake-disconnect-7866",
      DISABLE_TELEMETRY: "1",
      CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
      ...(wrapperPath ? { AGENT_SANDBOX_BWRAP: wrapperPath } : {}),
    },
  });
  for (const name of ["probe_hold_a", "probe_hold_b"]) {
    const put = await gatewayRequest(gw.port, "PUT", `/v1/tools/${name}`, {
      description: `Probe tool ${name}.`,
      input_schema: { type: "object", properties: { id: { type: "string" } } },
      webhook_url: `${webhook.base}/${name}`,
    });
    expect(put.status, put.text).toBeLessThan(300);
  }
  const end = Date.now() + 20_000;
  for (;;) {
    const health = await gatewayRequest(gw.port, "GET", "/health");
    if (health.json?.isolation === "ok") break;
    if (Date.now() > end) throw new Error(`isolation is ${String(health.json?.isolation)}`);
    await sleep(100);
  }
  return { api, gw, webhook };
}

/** Client A: a streaming request the test can cut. */
function startClientA(gw: SpawnedGateway, queryId: string): { disconnect: () => void } {
  const payload = Buffer.from(JSON.stringify({ queryId, prompt: PROMPT_A, model: "claude-opus-5-5", useSession: false }), "utf8");
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
  return { disconnect: () => req.destroy() };
}

interface ClientBResult {
  status: number;
  events: { type: string; [key: string]: unknown }[];
  text: string;
}

/** Client B: a normal request on its own connection; a dead gateway shows as status 0. */
function startClientB(gw: SpawnedGateway, queryId: string): Promise<ClientBResult> {
  return gatewayRequest(gw.port, "POST", "/v1/query", { queryId, prompt: PROMPT_B, model: "claude-opus-5-5", useSession: false }).then(
    (res) => ({
      status: res.status,
      events: res.text
        .split("\n")
        .filter((line) => line.trim().startsWith("{"))
        .map((line) => JSON.parse(line) as { type: string }),
      text: res.text,
    }),
    (err: unknown) => ({ status: 0, events: [], text: String(err) }),
  );
}

/** Resolves with `fallback` when `promise` has not settled after `ms`, so a hung gateway shows as a failed row, not a test timeout. */
function within<T>(promise: Promise<T>, ms: number, fallback: T): Promise<T> {
  return Promise.race([promise, sleep(ms).then(() => fallback)]);
}

const alive = (gw: SpawnedGateway): boolean => gw.child.exitCode === null && gw.child.signalCode === null;

/** Model-boundary requests that carry A's prompt (the runtime's warmup requests are not part of the run). */
const requestsForA = (api: FakeAnthropicApi): number => api.requests.filter((r) => !r.warmup && r.userTexts.some((t) => t.includes(PROMPT_A))).length;

function linesOf(gw: SpawnedGateway, queryId: string): string[] {
  return gw
    .output()
    .split("\n")
    .filter((line) => line.includes(`queryId=${queryId}`))
    .map((line) => line.slice(line.indexOf("queryId=")));
}

const guardLines = (gw: SpawnedGateway): number => gw.output().split("\n").filter((line) => line.includes(GUARD_LINE)).length;

function evidence(row: string, fields: Record<string, unknown>): void {
  process.stderr.write(`DISCONNECT-EVIDENCE ${row} ${Object.entries(fields).map(([k, v]) => `${k}=${String(v)}`).join(" ")}\n`);
}

/** What every disconnect row asserts once the dust has settled. */
async function expectOnlyRunAEnded(r: Rig, queryA: string, b: ClientBResult, modelRequestsAfterAbort: number): Promise<void> {
  const health = await within(gatewayRequest(r.gw.port, "GET", "/health").catch(() => ({ status: 0 })), 10_000, { status: -1 });
  expect.soft(alive(r.gw), `the gateway process is alive (exit=${String(r.gw.child.exitCode)} signal=${String(r.gw.child.signalCode)})`).toBe(true);
  expect.soft(health.status, "/health answers").toBe(200);
  for (const marker of ["AbortError", "Unhandled", "uncaught"]) expect.soft(r.gw.output(), `the gateway output contains ${marker}`).not.toContain(marker);
  expect.soft(guardLines(r.gw), "guard lines").toBeLessThanOrEqual(1);
  expect.soft(b.status, `client B's response (${b.text.slice(0, 120)})`).toBe(200);
  expect.soft(b.events.some((e) => e.type === "done"), "client B got done").toBe(true);
  expect.soft(b.text, "client B got the final answer").toContain(FINAL_ANSWER);
  expect.soft(b.events.some((e) => e.type === "error"), "client B got no error").toBe(false);
  expect.soft(requestsForA(r.api), "model requests for the aborted run did not grow after the abort").toBe(modelRequestsAfterAbort);
  const lines = linesOf(r.gw, queryA);
  expect.soft(lines.some((line) => line.includes("empty response") || line.includes("attempt ")), "a retry line for A").toBe(false);
  expect.soft(lines.filter((line) => line.includes(" kind=")), "failure lines for A").toEqual([`queryId=${queryA} kind=aborted`]);
}

/** The scenario of P1 and P2: A and B are mid-run, A disconnects, A's held call is released, B's later. */
async function disconnectScenario(options: { wrapper?: HoldWrapper; releaseDelayMs?: number; row: string }): Promise<void> {
  const r = await rig(options.wrapper?.path);
  const queryA = `q7866-a-${randomBytes(4).toString("hex")}`;
  const queryB = `q7866-b-${randomBytes(4).toString("hex")}`;

  options.wrapper?.holdNextLaunch();
  const a = startClientA(r.gw, queryA);
  await waitFor("A's webhook call", () => r.webhook.hits.includes("/probe_hold_a"));
  const b = startClientB(r.gw, queryB);
  await waitFor("B's webhook call", () => r.webhook.hits.includes("/probe_hold_b"));

  a.disconnect();
  let modelRequestsAfterAbort: number;
  if (options.wrapper) {
    await waitFor("A's launcher to end", () => {
      const pid = options.wrapper!.launcherPid();
      return pid !== null && !cmdline(pid).includes("--args");
    });
    modelRequestsAfterAbort = requestsForA(r.api);
    r.webhook.release("/probe_hold_a");
    await sleep(2_000);
  } else {
    if (options.releaseDelayMs) await sleep(options.releaseDelayMs);
    r.webhook.release("/probe_hold_a");
    await waitFor("the aborted line for A", () => linesOf(r.gw, queryA).some((line) => line.includes("kind=aborted")), 20_000).catch(() => {});
    modelRequestsAfterAbort = requestsForA(r.api);
    await sleep(1_000);
  }
  const aliveAfterRelease = alive(r.gw);

  r.webhook.release("/probe_hold_b");
  const resultB = await within(b, 30_000, { status: -1, events: [], text: "client B got no answer within 30 s" });
  options.wrapper?.endHelper();
  await sleep(3_000);

  evidence(options.row, {
    aliveAfterRelease,
    aliveAtEnd: alive(r.gw),
    bStatus: resultB.status,
    bDone: resultB.events.some((e) => e.type === "done"),
    modelRequestsAfterAbort,
    modelRequestsAtEnd: requestsForA(r.api),
    guardLines: guardLines(r.gw),
    linesForA: linesOf(r.gw, queryA).join(" | "),
  });
  if (!alive(r.gw) || resultB.status !== 200) process.stderr.write(`DISCONNECT-GATEWAY-OUTPUT ${options.row}\n${r.gw.output().slice(-3000)}\n`);
  await expectOnlyRunAEnded(r, queryA, resultB, modelRequestsAfterAbort);
}

describe("a client disconnect while a tool call is held ends only that run (real runtime, real bwrap)", () => {
  it("P1: A disconnects, its held call is released while the runtime output is still open: gateway lives, B completes, no new attempt for A", async () => {
    await disconnectScenario({ wrapper: makeHoldWrapper(), row: "P1" });
  }, 180_000);

  for (const releaseDelayMs of [0, 20]) {
    for (const round of [1, 2, 3]) {
      it(`P2: real launcher, release ${releaseDelayMs} ms after the disconnect (round ${round}): gateway lives, B completes, no new attempt for A`, async () => {
        await disconnectScenario({ releaseDelayMs, row: `P2-${releaseDelayMs}ms-${round}` });
      }, 180_000);
    }
  }

  it("P3: control, nobody disconnects: A and B complete and no guard line is written", async () => {
    const r = await rig();
    const queryA = `q7866-a-${randomBytes(4).toString("hex")}`;
    const queryB = `q7866-b-${randomBytes(4).toString("hex")}`;
    const resultA = gatewayRequest(r.gw.port, "POST", "/v1/query", { queryId: queryA, prompt: PROMPT_A, model: "claude-opus-5-5", useSession: false });
    const resultB = startClientB(r.gw, queryB);
    await waitFor("both webhook calls", () => r.webhook.hits.includes("/probe_hold_a") && r.webhook.hits.includes("/probe_hold_b"));
    r.webhook.release("/probe_hold_a");
    r.webhook.release("/probe_hold_b");
    const a = await resultA;
    const b = await resultB;
    expect(a.status).toBe(200);
    expect(a.text).toContain(FINAL_ANSWER);
    expect(b.status).toBe(200);
    expect(b.text).toContain(FINAL_ANSWER);
    expect(guardLines(r.gw)).toBe(0);
    expect(alive(r.gw)).toBe(true);
  }, 180_000);
});
