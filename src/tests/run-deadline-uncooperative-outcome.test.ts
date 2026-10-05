/**
 * The run deadline (AGENT_RUN_TIMEOUT_MS) ends the request even when the Claude Agent SDK ignores the
 * abort and never settles (MVP-8000), through the REAL query.ts + agent.ts + retry.ts path with ONLY the
 * SDK boundary (`query()`) mocked. The runtime process is not started here (the SDK is mocked); the
 * real-runtime row is in launcher-external-kill-process.test.ts and the bounded kill of a real launcher
 * in sandbox.test.ts. The stop of the sandbox is observed through the `SandboxRun` seams.
 *
 * Expected values are written out here, not imported from run-failure.ts or agent.ts.
 * One SDK mock per file (two registrations made tests flaky, see memory).
 */
import { EventEmitter } from "node:events";
import fs from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import express from "express";
import request from "supertest";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

// A request that never ends must fail its row with the message of finishedQuery, not with the framework timeout.
vi.setConfig({ testTimeout: 30_000 });

const INIT = { type: "system", subtype: "init", claude_code_version: "2.0.77", skills: [] };
const LIMIT_MS = 1500;
const deadlineText = (queryId: string): string =>
  `The request was stopped because it ran longer than the gateway's limit of 1 minute. Its results were not saved. Try again with a smaller task, or ask your gateway administrator to raise the limit. (reference: ${queryId})`;
const BUSY_TEXT = "This conversation is still answering an earlier request. Please wait until it has finished, then try again.";

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** What the mocked SDK does after its first message. The default never settles and ignores the abort. */
type SdkBehavior = (signal: AbortSignal) => AsyncGenerator<Record<string, unknown>, void, undefined> | Promise<never> | Promise<void>;

let afterInit: SdkBehavior = () => new Promise<never>(() => {});
let sdkQueryCalls = 0;
let logLines: string[] = [];
let order: string[] = [];
let persistDir = "";
let sessionsFile = "";
let unhandled: unknown[] = [];

const onUnhandled = (reason: unknown): void => {
  unhandled.push(reason);
};

beforeAll(() => {
  persistDir = fs.mkdtempSync(path.join(os.tmpdir(), "mvp8000-outcome-"));
  sessionsFile = path.join(persistDir, "sessions.json");
});

afterAll(async () => {
  await sleep(150);
  fs.rmSync(persistDir, { recursive: true, force: true });
});

beforeEach(async () => {
  vi.resetModules();
  logLines = [];
  order = [];
  unhandled = [];
  sdkQueryCalls = 0;
  afterInit = () => new Promise<never>(() => {});
  fs.rmSync(sessionsFile, { force: true });
  vi.stubEnv("SESSION_PERSIST_PATH", sessionsFile);
  vi.stubEnv("AGENT_RUN_TIMEOUT_MS", String(LIMIT_MS));
  process.on("unhandledRejection", onUnhandled);
  vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
    const line = args.map(String).join(" ");
    logLines.push(line);
    if (line.startsWith("[query] Error queryId=")) order.push("error-line");
  });
  vi.doMock("@anthropic-ai/claude-agent-sdk", () => ({
    createSdkMcpServer: vi.fn((options) => ({ type: "sdk", name: options.name })),
    query: vi.fn(({ options }: { options: { abortController: AbortController } }) => {
      sdkQueryCalls++;
      return (async function* () {
        yield INIT;
        const rest = afterInit(options.abortController.signal);
        if (typeof (rest as AsyncGenerator).next === "function") yield* rest as AsyncGenerator<Record<string, unknown>>;
        else await rest;
      })();
    }),
  }));
});

afterEach(() => {
  process.off("unhandledRejection", onUnhandled);
  vi.doUnmock("@anthropic-ai/claude-agent-sdk");
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

async function createApp() {
  const { queryRouter } = await import("../query.js");
  const app = express();
  app.use(express.json());
  app.use(queryRouter);
  return app;
}

function parseNdjson(text: string): Record<string, unknown>[] {
  return text
    .split("\n")
    .filter((line) => line.trim().length > 0)
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}

const lineOf = (queryId: string): string[] => logLines.filter((line) => line.startsWith(`[query] Error queryId=${queryId}`));

interface Finished {
  elapsedMs: number;
  events: Record<string, unknown>[];
}

/** One request to its end, or a test-side timeout so a request that never ends fails the row instead of hanging it. */
async function finishedQuery(app: express.Express, body: Record<string, unknown>, giveUpMs = LIMIT_MS + 4_000): Promise<Finished> {
  const started = Date.now();
  const pending = request(app).post("/v1/query").send(body).then((res) => res);
  const res = await Promise.race([pending, sleep(giveUpMs).then(() => null)]);
  const elapsedMs = Date.now() - started;
  if (res === null) throw new Error(`the request was still open ${elapsedMs} ms after it started (limit ${LIMIT_MS} ms)`);
  expect(res.status).toBe(200);
  return { elapsedMs, events: parseNdjson(res.text) };
}

/** The request ended with exactly one deadline error as its last event and no `done`. */
function expectDeadlineError(events: Record<string, unknown>[], queryId: string): void {
  const errors = events.filter((e) => e.type === "error");
  expect(errors).toHaveLength(1);
  expect(events.at(-1)).toBe(errors[0]);
  expect(Object.keys(errors[0]).sort()).toEqual(["content", "seq", "type"]);
  expect(errors[0].content).toBe(deadlineText(queryId));
  expect(events.some((e) => e.type === "done")).toBe(false);
}

describe("a run whose SDK ignores the abort and never settles", () => {
  it("U1: the request ends with the deadline error within the limit plus 2 s, one failure line, no unhandled rejection", async () => {
    const app = await createApp();

    const { elapsedMs, events } = await finishedQuery(app, { queryId: "q-u1", prompt: "hi", useSession: false });

    expect(elapsedMs).toBeGreaterThanOrEqual(LIMIT_MS);
    expect(elapsedMs).toBeLessThan(LIMIT_MS + 2_000);
    expectDeadlineError(events, "q-u1");
    expect(lineOf("q-u1")).toHaveLength(1);
    expect(lineOf("q-u1")[0]).toContain("kind=run_deadline");
    expect(logLines.filter((line) => line.includes("signal=SIGKILL") || line.includes("kind=unknown"))).toEqual([]);
    await sleep(200);
    expect(unhandled).toEqual([]);
  });

  it("U2: output the SDK produces after the stop adds no event, no line and no saved session", async () => {
    afterInit = async function* () {
      await sleep(LIMIT_MS + 2_500);
      yield { type: "assistant", message: { content: [{ type: "text", text: "late answer" }, { type: "tool_use", id: "tool-late", name: "Read", input: {} }] } };
      yield { type: "result", subtype: "success", is_error: false, session_id: "sdk-late", usage: {}, total_cost_usd: 0 };
    } as unknown as SdkBehavior;
    const app = await createApp();

    const { elapsedMs, events } = await finishedQuery(app, { queryId: "q-u2", sessionId: "conv-u2", prompt: "hi", useSession: true });
    await sleep(2_000);

    expect(elapsedMs).toBeLessThan(LIMIT_MS + 2_000);
    expectDeadlineError(events, "q-u2");
    expect(events.some((e) => e.type === "text" || e.type === "tool_use")).toBe(false);
    expect(lineOf("q-u2")).toHaveLength(1);
    const replay = await request(app).get("/v1/query/q-u2/events");
    expect(parseNdjson(replay.text)).toEqual(events);
    const saved = fs.existsSync(sessionsFile) ? fs.readFileSync(sessionsFile, "utf8") : "";
    expect(saved).not.toContain("sdk-late");
    expect(unhandled).toEqual([]);
  });

  it("U3: the conversation stays busy until the stop has finished, then a new request on it is admitted", async () => {
    const { SandboxRun } = await import("../sandbox.js");
    const proto = SandboxRun.prototype as unknown as { disposeAfterDeadline: (...args: unknown[]) => Promise<unknown> };
    const original = proto.disposeAfterDeadline;
    let stopping = false;
    vi.spyOn(proto, "disposeAfterDeadline").mockImplementation(async function (this: unknown, ...args: unknown[]) {
      stopping = true;
      await sleep(400);
      return original.apply(this, args);
    });
    const app = await createApp();
    const body = { sessionId: "conv-u3", prompt: "hi", useSession: true };

    const first = finishedQuery(app, { ...body, queryId: "q-u3-first" });
    const stopBy = Date.now() + LIMIT_MS + 4_000;
    while (!stopping && Date.now() < stopBy) await sleep(20);
    expect(stopping).toBe(true);
    const callsWhileStopping = sdkQueryCalls;
    const second = await finishedQuery(app, { ...body, queryId: "q-u3-second" }, 3_000);
    const firstDone = await first;

    expect(second.events.map((e) => ({ type: e.type, content: e.content }))).toEqual([{ type: "error", content: BUSY_TEXT }]);
    expect(sdkQueryCalls).toBe(callsWhileStopping);
    expectDeadlineError(firstDone.events, "q-u3-first");

    afterInit = async function* () {
      yield { type: "assistant", message: { content: [{ type: "text", text: "all good" }] } };
      yield { type: "result", subtype: "success", is_error: false, session_id: "sdk-ok", usage: {}, total_cost_usd: 0 };
    } as unknown as SdkBehavior;
    const third = await finishedQuery(app, { ...body, queryId: "q-u3-third" });
    expect(third.events.some((e) => e.type === "done")).toBe(true);
    expect(third.events.some((e) => e.type === "error")).toBe(false);
  });

  it("U4: relay and model proxy tokens are revoked and the sandbox is stopped before the error reaches the client", async () => {
    const { credentialRelay } = await import("../mcp-credential-relay.js");
    const { gatewayModelProxy } = await import("../model-proxy.js");
    const { SandboxRun } = await import("../sandbox.js");
    await credentialRelay.start();
    try {
      const registered: string[] = [];
      const revoked: string[] = [];
      const originalRegister = credentialRelay.register.bind(credentialRelay);
      vi.spyOn(credentialRelay, "register").mockImplementation((binding) => {
        const result = originalRegister(binding);
        registered.push(result.token);
        return result;
      });
      const originalRevoke = credentialRelay.revoke.bind(credentialRelay);
      vi.spyOn(credentialRelay, "revoke").mockImplementation((token) => {
        revoked.push(token);
        order.push("relay-revoke");
        originalRevoke(token);
      });
      const proxy = gatewayModelProxy();
      const proxyRevoked: string[] = [];
      vi.spyOn(proxy, "revoke").mockImplementation((token) => {
        proxyRevoked.push(token);
        order.push("proxy-revoke");
      });
      const proto = SandboxRun.prototype as unknown as { disposeAfterDeadline: (...args: unknown[]) => Promise<unknown> };
      const original = proto.disposeAfterDeadline;
      let stoppedByDeadline = 0;
      vi.spyOn(proto, "disposeAfterDeadline").mockImplementation(async function (this: { proxyToken: string | null }, ...args: unknown[]) {
        stoppedByDeadline++;
        order.push("sandbox-stop");
        this.proxyToken = "mpt_synthetic-run-token";
        return original.apply(this, args);
      });
      const app = await createApp();

      const { events } = await finishedQuery(app, {
        queryId: "q-u4",
        prompt: "hi",
        useSession: false,
        mcpServers: { "with-header": { url: "http://127.0.0.1:9/mcp", headers: { Authorization: "Bearer synthetic-secret" } } },
      });

      expectDeadlineError(events, "q-u4");
      expect(registered).toHaveLength(1);
      expect(revoked).toEqual(registered);
      expect(proxyRevoked).toEqual(["mpt_synthetic-run-token"]);
      expect(stoppedByDeadline).toBe(1);
      const errorLine = order.indexOf("error-line");
      expect(order.indexOf("relay-revoke")).toBeGreaterThanOrEqual(0);
      expect(order.indexOf("relay-revoke")).toBeLessThan(errorLine);
      expect(order.indexOf("proxy-revoke")).toBeLessThan(errorLine);
      expect(order.indexOf("sandbox-stop")).toBeLessThan(errorLine);
    } finally {
      await credentialRelay.close();
    }
  });

  it("U5: a runtime whose exit cannot be confirmed does not hold the request, but keeps its conversation busy until it exits", async () => {
    const { SandboxRun } = await import("../sandbox.js");
    const stub = Object.assign(new EventEmitter(), { exitCode: null, signalCode: null, pid: 2_147_483_000, kill: vi.fn(() => true) });
    vi.spyOn(SandboxRun.prototype, "child", "get").mockImplementation(() => stub as never);
    const app = await createApp();
    const body = { sessionId: "conv-u5", prompt: "hi", useSession: true };

    const first = await finishedQuery(app, { ...body, queryId: "q-u5-first" });

    expect(first.elapsedMs).toBeLessThan(LIMIT_MS + 2_000);
    expectDeadlineError(first.events, "q-u5-first");
    expect(lineOf("q-u5-first")).toHaveLength(1);
    expect(logLines.filter((line) => /^\[query\] sandbox exit not confirmed after deadline stop queryId=q-u5-first waitedMs=\d+$/.test(line))).toHaveLength(1);
    expect(stub.kill).toHaveBeenCalledWith("SIGKILL");

    const callsBefore = sdkQueryCalls;
    const second = await finishedQuery(app, { ...body, queryId: "q-u5-second" }, 3_000);
    expect(second.events.map((e) => ({ type: e.type, content: e.content }))).toEqual([{ type: "error", content: BUSY_TEXT }]);
    expect(sdkQueryCalls).toBe(callsBefore);

    stub.emit("exit", null, "SIGKILL");
    await sleep(100);
    afterInit = async function* () {
      yield { type: "assistant", message: { content: [{ type: "text", text: "all good" }] } };
      yield { type: "result", subtype: "success", is_error: false, session_id: "sdk-ok", usage: {}, total_cost_usd: 0 };
    } as unknown as SdkBehavior;
    const third = await finishedQuery(app, { ...body, queryId: "q-u5-third" });
    expect(third.events.some((e) => e.type === "done")).toBe(true);
  });
});

describe("runs that do not hit the deadline are unchanged", () => {
  it("a normal run ends with done, no error and no failure line", async () => {
    afterInit = async function* () {
      yield { type: "assistant", message: { content: [{ type: "text", text: "all good" }] } };
      yield { type: "result", subtype: "success", is_error: false, session_id: "sdk-ok", usage: {}, total_cost_usd: 0 };
    } as unknown as SdkBehavior;
    const app = await createApp();

    const { events } = await finishedQuery(app, { queryId: "q-normal", prompt: "hi", useSession: false });

    expect(events.some((e) => e.type === "done")).toBe(true);
    expect(events.some((e) => e.type === "error")).toBe(false);
    expect(lineOf("q-normal")).toEqual([]);
  });

  it("a cooperative SDK that rejects on the abort ends the request with the deadline text before the grace is used up", async () => {
    afterInit = (signal) =>
      new Promise<never>((_, reject) => {
        class AbortError extends Error {}
        signal.addEventListener("abort", () => reject(new AbortError("Claude Code process aborted by user")), { once: true });
      });
    const app = await createApp();

    const { elapsedMs, events } = await finishedQuery(app, { queryId: "q-coop", prompt: "hi", useSession: false });

    expect(elapsedMs).toBeGreaterThanOrEqual(LIMIT_MS);
    expect(elapsedMs).toBeLessThan(LIMIT_MS + 900);
    expectDeadlineError(events, "q-coop");
    expect(lineOf("q-coop")).toHaveLength(1);
    expect(lineOf("q-coop")[0]).toContain("kind=run_deadline");
  });

  it("a client abort ends with the aborted line only: no deadline failure, no unknown failure", async () => {
    afterInit = (signal) =>
      new Promise<never>((_, reject) => {
        class AbortError extends Error {}
        signal.addEventListener("abort", () => reject(new AbortError("Claude Code process aborted by user")), { once: true });
      });
    const app = await createApp();
    const server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
    try {
      const { port } = server.address() as AddressInfo;
      const payload = Buffer.from(JSON.stringify({ queryId: "q-cancel", prompt: "hi", useSession: false }), "utf8");
      const req = http.request({ host: "127.0.0.1", port, method: "POST", path: "/v1/query", agent: false, headers: { "Content-Type": "application/json", "Content-Length": payload.length } });
      req.on("error", () => {});
      const gotFirstEvent = new Promise<void>((resolve) => req.on("response", (res) => res.once("data", () => resolve())));
      req.end(payload);
      await gotFirstEvent;
      req.destroy();
      const end = Date.now() + 5_000;
      while (lineOf("q-cancel").length === 0 && Date.now() < end) await sleep(50);
      await sleep(LIMIT_MS + 500);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }

    expect(lineOf("q-cancel")).toEqual(["[query] Error queryId=q-cancel kind=aborted"]);
    expect(logLines.filter((line) => line.includes("kind=run_deadline") || line.includes("signal=SIGKILL"))).toEqual([]);
    expect(unhandled).toEqual([]);
  });
});
