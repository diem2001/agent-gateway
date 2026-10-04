/**
 * The gateway-side watch for a launcher that ended by an outside signal (MVP-7964), through the REAL
 * query.ts + agent.ts + retry.ts path with ONLY the Claude Agent SDK boundary (`query()`) mocked.
 * The launcher's end is supplied through the `SandboxRun.unownedExit` and `SandboxRun.runtimeExit` seams, the
 * ones the gateway reads the launcher process from (as in query-failure-cause-outcome.test.ts); what makes
 * the watch silent for the gateway's own endings is covered by sandbox.test.ts and the process rows.
 *
 * Expected values are written out here, not imported from run-failure.ts or agent.ts.
 * One SDK mock per file (two registrations made tests flaky, see memory).
 */
import fs from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import express from "express";
import request from "supertest";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const INIT = { type: "system", subtype: "init", claude_code_version: "2.0.77", skills: [] };
const unknownFailure = (queryId: string): string =>
  `The AI request failed on the gateway for an unknown reason. Please try again. If it keeps failing, ask your gateway administrator to check the gateway logs (reference: ${queryId}).`;
const TAIL_GATEWAY_DETECTED = "kind=unknown apiStatus=none providerType=none installed=2.0.77 required=none errorClass=none errno=none exit=none signal=SIGKILL";
const TAIL_SDK_DETECTED = "kind=unknown apiStatus=none providerType=none installed=2.0.77 required=none errorClass=Error errno=none exit=none signal=SIGKILL";

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** What the mocked SDK does after it delivered its first message and the launcher has "ended". */
type SdkBehavior = (signal: AbortSignal) => AsyncGenerator<Record<string, unknown>, void, undefined> | Promise<never> | Promise<void>;

let afterInit: SdkBehavior = () => new Promise<never>(() => {});
let launcherEnds = true;
let logLines: string[] = [];
let persistDir = "";
let unhandled: unknown[] = [];

const onUnhandled = (reason: unknown): void => {
  unhandled.push(reason);
};

beforeAll(() => {
  persistDir = fs.mkdtempSync(path.join(os.tmpdir(), "mvp7964-outcome-"));
  vi.stubEnv("SESSION_PERSIST_PATH", path.join(persistDir, "sessions.json"));
});

afterAll(async () => {
  vi.unstubAllEnvs();
  await sleep(150);
  fs.rmSync(persistDir, { recursive: true, force: true });
});

function sdkError(message = "Claude Code process exited with code 1 SENTINEL-MSG"): Error {
  const error = new Error(message);
  Object.assign(error, { stderr: "SENTINEL-STDERR" });
  return error;
}

function abortError(): Error {
  class AbortError extends Error {}
  return new AbortError("Claude Code process aborted by user");
}

beforeEach(() => {
  vi.resetModules();
  logLines = [];
  unhandled = [];
  launcherEnds = true;
  afterInit = () => new Promise<never>(() => {});
  process.on("unhandledRejection", onUnhandled);
  vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
    logLines.push(args.map(String).join(" "));
  });
  vi.doMock("@anthropic-ai/claude-agent-sdk", () => ({
    createSdkMcpServer: vi.fn((options) => ({ type: "sdk", name: options.name })),
    query: vi.fn(({ options }: { options: { abortController: AbortController } }) =>
      (async function* () {
        yield INIT;
        markLauncherEnded();
        const rest = afterInit(options.abortController.signal);
        if (typeof (rest as AsyncGenerator).next === "function") yield* rest as AsyncGenerator<Record<string, unknown>>;
        else await rest;
      })(),
    ),
  }));
});

afterEach(() => {
  process.off("unhandledRejection", onUnhandled);
  vi.doUnmock("@anthropic-ai/claude-agent-sdk");
  vi.unstubAllEnvs();
  vi.stubEnv("SESSION_PERSIST_PATH", path.join(persistDir, "sessions.json"));
  vi.restoreAllMocks();
});

let endLauncher: () => void = () => {};
function markLauncherEnded(): void {
  if (launcherEnds) endLauncher();
}

async function createApp() {
  const { SandboxRun } = await import("../sandbox.js");
  const ended = new Promise<{ exitCode: number | null; signalCode: NodeJS.Signals | null }>((resolve) => {
    endLauncher = () => resolve({ exitCode: null, signalCode: "SIGKILL" });
  });
  vi.spyOn(SandboxRun.prototype, "unownedExit").mockImplementation(() => ended);
  vi.spyOn(SandboxRun.prototype, "runtimeExit", "get").mockImplementation(() => (launcherEnds ? { exitCode: null, signalCode: "SIGKILL" } : null));
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

/** One query to its end; asserts the one unchanged unknown error and no `done`. */
async function failedQuery(app: express.Express, queryId: string): Promise<Finished> {
  const started = Date.now();
  const res = await request(app).post("/v1/query").send({ queryId, prompt: "hi", useSession: false });
  const elapsedMs = Date.now() - started;
  expect(res.status).toBe(200);
  const events = parseNdjson(res.text);
  const errors = events.filter((e) => e.type === "error");
  expect(errors).toHaveLength(1);
  expect(events.at(-1)).toBe(errors[0]);
  expect(Object.keys(errors[0]).sort()).toEqual(["content", "seq", "type"]);
  expect(errors[0].content).toBe(unknownFailure(queryId));
  expect(events.some((e) => e.type === "done")).toBe(false);
  expect(res.text).not.toContain("SENTINEL");
  return { elapsedMs, events };
}

describe("a launcher that ended by an outside signal while the SDK has not noticed", () => {
  it("O1: the watch ends the run after the grace with one unknown error and signal=SIGKILL", async () => {
    const app = await createApp();

    const { elapsedMs } = await failedQuery(app, "q-o1");

    expect(elapsedMs).toBeGreaterThanOrEqual(900);
    expect(elapsedMs).toBeLessThan(5_000);
    expect(lineOf("q-o1")).toEqual([`[query] Error queryId=q-o1 ${TAIL_GATEWAY_DETECTED}`]);
    expect(unhandled).toEqual([]);
  });

  it("O2: an SDK error that arrives after the watch ended the run adds no event, no line and no unhandled rejection", async () => {
    afterInit = async () => {
      await sleep(1_500);
      throw sdkError();
    };
    const app = await createApp();

    const { events } = await failedQuery(app, "q-o2");
    await sleep(1_000);

    expect(lineOf("q-o2")).toEqual([`[query] Error queryId=q-o2 ${TAIL_GATEWAY_DETECTED}`]);
    const replay = await request(app).get("/v1/query/q-o2/events");
    expect(parseNdjson(replay.text)).toEqual(events);
    expect(unhandled).toEqual([]);
  });

  it("O3: an SDK success that arrives after the watch ended the run adds no done event and no line", async () => {
    afterInit = async function* () {
      await sleep(1_500);
      yield { type: "assistant", message: { content: [{ type: "text", text: "late answer" }] } };
      yield { type: "result", subtype: "success", is_error: false, session_id: "sdk-late", usage: {}, total_cost_usd: 0 };
    } as unknown as SdkBehavior;
    const app = await createApp();

    const { events } = await failedQuery(app, "q-o3");
    await sleep(1_000);

    expect(events.some((e) => e.type === "text" || e.type === "tool_use")).toBe(false);
    expect(lineOf("q-o3")).toEqual([`[query] Error queryId=q-o3 ${TAIL_GATEWAY_DETECTED}`]);
    const replay = await request(app).get("/v1/query/q-o3/events");
    expect(parseNdjson(replay.text)).toEqual(events);
    expect(unhandled).toEqual([]);
  });

  it("O4: an SDK end inside the grace takes the existing path: one error, errorClass from the SDK error, watch silent", async () => {
    afterInit = async () => {
      await sleep(300);
      throw sdkError();
    };
    const app = await createApp();

    const { elapsedMs } = await failedQuery(app, "q-o4");
    await sleep(1_500);

    expect(elapsedMs).toBeLessThan(900);
    expect(lineOf("q-o4")).toEqual([`[query] Error queryId=q-o4 ${TAIL_SDK_DETECTED}`]);
    expect(unhandled).toEqual([]);
  });

  it("O4b: messages inside the grace are still processed before the SDK's own end", async () => {
    afterInit = async function* () {
      await sleep(200);
      yield { type: "assistant", message: { content: [{ type: "tool_use", id: "tool-o4b", name: "Read", input: {} }] } };
      await sleep(200);
      throw sdkError();
    } as unknown as SdkBehavior;
    const app = await createApp();

    const { events } = await failedQuery(app, "q-o4b");

    expect(events.some((e) => e.type === "tool_use" && e.toolUseId === "tool-o4b")).toBe(true);
    expect(lineOf("q-o4b")).toEqual([`[query] Error queryId=q-o4b ${TAIL_SDK_DETECTED}`]);
  });
});

describe("a run that did not end by an outside signal", () => {
  it("O5: a client abort ends with the aborted line only: no unknown failure, no signal=SIGKILL", async () => {
    launcherEnds = false;
    afterInit = (signal) =>
      new Promise<never>((_, reject) => {
        signal.addEventListener("abort", () => reject(abortError()), { once: true });
      });
    const app = await createApp();
    const server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
    try {
      const { port } = server.address() as AddressInfo;
      const payload = Buffer.from(JSON.stringify({ queryId: "q-o5", prompt: "hi", useSession: false }), "utf8");
      const req = http.request({ host: "127.0.0.1", port, method: "POST", path: "/v1/query", agent: false, headers: { "Content-Type": "application/json", "Content-Length": payload.length } });
      req.on("error", () => {});
      const gotFirstEvent = new Promise<void>((resolve) => req.on("response", (res) => res.once("data", () => resolve())));
      req.end(payload);
      await gotFirstEvent;
      req.destroy();
      const end = Date.now() + 5_000;
      while (lineOf("q-o5").length === 0 && Date.now() < end) await sleep(50);
      await sleep(1_500);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }

    expect(lineOf("q-o5")).toEqual(["[query] Error queryId=q-o5 kind=aborted"]);
    expect(logLines.filter((line) => line.includes("signal=SIGKILL"))).toEqual([]);
    expect(unhandled).toEqual([]);
  });

  it("a normal run ends as before and the watch stays silent", async () => {
    launcherEnds = false;
    afterInit = async function* () {
      yield { type: "assistant", message: { content: [{ type: "text", text: "all good" }] } };
      yield { type: "result", subtype: "success", is_error: false, session_id: "sdk-ok", usage: {}, total_cost_usd: 0 };
    } as unknown as SdkBehavior;
    const app = await createApp();

    const res = await request(app).post("/v1/query").send({ queryId: "q-normal", prompt: "hi", useSession: false });
    const events = parseNdjson(res.text);

    expect(events.some((e) => e.type === "done")).toBe(true);
    expect(events.some((e) => e.type === "error")).toBe(false);
    expect(lineOf("q-normal")).toEqual([]);
  });
});
