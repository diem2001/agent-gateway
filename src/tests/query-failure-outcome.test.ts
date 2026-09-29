/**
 * Failed runs through the REAL query.ts + agent.ts + retry.ts path (MVP-7685),
 * with ONLY the Claude Agent SDK boundary (`query()`) mocked. Each SDK call
 * plays the next scripted attempt: the messages the runtime writes to stdout,
 * optionally followed by the error the SDK throws when the runtime exits 1.
 *
 * Expected texts are written out here (not imported from run-failure.ts).
 * One SDK mock per file (two registrations made tests flaky, see memory).
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import express from "express";
import request from "supertest";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

interface Attempt {
  messages: Record<string, unknown>[];
  /** Thrown after the messages, like the SDK after a nonzero runtime exit. */
  throws?: Error;
}

let script: Attempt[] = [];
let sdkCalls: { sessionId?: unknown; resume?: unknown }[] = [];
let logLines: string[] = [];

const SENTINEL = "SENTINEL-7685-RAW";
const INIT = { type: "system", subtype: "init", claude_code_version: "2.0.77", skills: [] };
const EXIT_1 = (): Error => new Error("Claude Code process exited with code 1");

function apiError(status: number, error: Record<string, unknown>): string {
  return `API Error: ${status} ${JSON.stringify({ type: "error", error })}`;
}

/** The runtime's stdout for a provider rejection: init, error-flagged assistant message, is_error result. */
function rejectionMessages(text: string, assistantError = "unknown"): Record<string, unknown>[] {
  return [
    INIT,
    { type: "assistant", error: assistantError, message: { model: "<synthetic>", content: [{ type: "text", text }] } },
    { type: "result", subtype: "success", is_error: true, result: text, session_id: "sdk-failed-session", usage: { input_tokens: 0, output_tokens: 0 }, total_cost_usd: 0 },
  ];
}

function answerMessages(sessionId = "sdk-ok-session"): Record<string, unknown>[] {
  return [
    INIT,
    { type: "stream_event", event: { type: "content_block_delta", delta: { type: "text_delta", text: "fine answer" } } },
    { type: "assistant", message: { content: [{ type: "text", text: "fine answer" }] } },
    { type: "result", subtype: "success", is_error: false, result: "fine answer", session_id: sessionId, usage: { input_tokens: 3, output_tokens: 2 }, total_cost_usd: 0.001 },
  ];
}

const VERSION_TEXT = apiError(400, {
  type: "invalid_request_error",
  code: "claude_code_version_too_old",
  message: `This model requires Claude Code version 2.1.280 or newer. ${SENTINEL}`,
});
const RATE_LIMIT_TEXT = apiError(429, { type: "rate_limit_error", message: `slow down ${SENTINEL}` });

const RETRY_WILL_NOT_HELP = "Retrying will not help until the administrator has done this.";
const VERSION_BOTH = `The AI runtime on the gateway server is too old for the selected model (installed 2.0.77, required 2.1.280 or newer). Ask your gateway administrator to update the gateway runtime. ${RETRY_WILL_NOT_HELP}`;
const BUSY = "The AI provider is busy right now. Please try again in a few minutes.";
const unknownFailure = (queryId: string): string =>
  `The AI request failed on the gateway for an unknown reason. Please try again. If it keeps failing, ask your gateway administrator to check the gateway logs (reference: ${queryId}).`;

let persistDir = "";

beforeAll(() => {
  persistDir = fs.mkdtempSync(path.join(os.tmpdir(), "mvp7685-outcome-"));
  vi.stubEnv("SESSION_PERSIST_PATH", path.join(persistDir, "sessions.json"));
});

afterAll(async () => {
  vi.unstubAllEnvs();
  // The session store saves 100 ms after a change and would re-create the directory.
  await new Promise((resolve) => setTimeout(resolve, 150));
  fs.rmSync(persistDir, { recursive: true, force: true });
});

beforeEach(() => {
  vi.resetModules();
  script = [];
  sdkCalls = [];
  logLines = [];
  vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
    logLines.push(args.map(String).join(" "));
  });
  vi.doMock("@anthropic-ai/claude-agent-sdk", () => ({
    createSdkMcpServer: vi.fn((options) => ({ type: "sdk", name: options.name })),
    query: vi.fn(({ options }: { options: Record<string, unknown> }) => {
      sdkCalls.push({ sessionId: options.sessionId, resume: options.resume });
      const attempt = script.shift() ?? { messages: answerMessages() };
      return (async function* () {
        for (const message of attempt.messages) yield message;
        if (attempt.throws) throw attempt.throws;
      })();
    }),
  }));
});

afterEach(() => {
  vi.doUnmock("@anthropic-ai/claude-agent-sdk");
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

interface Outcome {
  events: Record<string, unknown>[];
  text: string;
  replayText: string;
}

async function send(app: express.Express, queryId: string, body: Record<string, unknown> = {}): Promise<Outcome> {
  const res = await request(app).post("/v1/query").send({ queryId, prompt: "hi", useSession: false, ...body });
  expect(res.status).toBe(200);
  const replay = await request(app).get(`/v1/query/${queryId}/events`);
  expect(replay.status).toBe(200);
  expect(parseNdjson(replay.text)).toEqual(parseNdjson(res.text));
  return { events: parseNdjson(res.text), text: res.text, replayText: replay.text };
}

/** Exactly one terminal error event {seq, type, content}, no done, no raw material in stream, replay or logs. */
function expectFailure(outcome: Outcome, content: string, raw: string[] = [SENTINEL, "API Error", "claude_code_version_too_old", "Claude Code process exited"]): void {
  const errors = outcome.events.filter((e) => e.type === "error");
  expect(errors).toHaveLength(1);
  expect(outcome.events.at(-1)).toBe(errors[0]);
  expect(Object.keys(errors[0]).sort()).toEqual(["content", "seq", "type"]);
  expect(errors[0].content).toBe(content);
  expect(outcome.events.some((e) => e.type === "done")).toBe(false);
  for (const needle of raw) {
    expect(outcome.text).not.toContain(needle);
    expect(outcome.replayText).not.toContain(needle);
    expect(logLines.filter((line) => line.includes(needle))).toEqual([]);
  }
}

describe("failed runs end with one safe error event and no done (SDK boundary mocked)", () => {
  it("subtype success + is_error true with a clean exit (no throw) is an error, not done", async () => {
    script = [{ messages: rejectionMessages(VERSION_TEXT) }];
    const outcome = await send(await createApp(), "q-exit0");

    expectFailure(outcome, VERSION_BOTH);
    expect(sdkCalls).toHaveLength(1);
    expect(logLines).toContain("[query] Error queryId=q-exit0 kind=runtime_version_unsupported apiStatus=400 providerType=invalid_request_error installed=2.0.77 required=2.1.280");
  });

  it("a structured rejection followed by the thrown exit error keeps the diagnostic: one attempt, version message", async () => {
    script = [{ messages: rejectionMessages(VERSION_TEXT), throws: EXIT_1() }];
    const outcome = await send(await createApp(), "q-exit1");

    expectFailure(outcome, VERSION_BOTH);
    // Permanent: no retry and no empty-response loop.
    expect(sdkCalls).toHaveLength(1);
    expect(outcome.events.some((e) => e.type === "rate_limited")).toBe(false);
  });

  it("exit 1 without any diagnostic gives the generic failure with the log reference", async () => {
    script = [{ messages: [INIT], throws: EXIT_1() }];
    const outcome = await send(await createApp(), "q-nodiag");

    expectFailure(outcome, unknownFailure("q-nodiag"));
    expect(sdkCalls).toHaveLength(1);
  });

  it("malformed result text gives the generic failure without the raw output", async () => {
    script = [{ messages: rejectionMessages(`API Error: 400 <html>${SENTINEL}</html>`), throws: EXIT_1() }];
    const outcome = await send(await createApp(), "q-malformed");

    expectFailure(outcome, unknownFailure("q-malformed"), [SENTINEL, "API Error", "<html>"]);
    expect(sdkCalls).toHaveLength(1);
  });

  it("a spoofed 'API Error: 429' in ordinary model text followed by the exit error is unknown after exactly one attempt", async () => {
    script = [
      {
        messages: [INIT, { type: "assistant", message: { content: [{ type: "text", text: RATE_LIMIT_TEXT }] } }],
        throws: EXIT_1(),
      },
    ];
    const outcome = await send(await createApp(), "q-spoof");

    expectFailure(outcome, unknownFailure("q-spoof"));
    expect(sdkCalls).toHaveLength(1);
    expect(outcome.events.some((e) => e.type === "rate_limited")).toBe(false);
  });

  it("a thrown SDK SyntaxError quoting stdout is unknown, with no quoted text in the stream or the logs", async () => {
    script = [{ messages: [INIT], throws: new SyntaxError(`Unexpected token in JSON: "${SENTINEL} rate limit 429"`) }];
    const outcome = await send(await createApp(), "q-syntax");

    expectFailure(outcome, unknownFailure("q-syntax"), [SENTINEL, "Unexpected token", "rate limit 429"]);
    expect(sdkCalls).toHaveLength(1);
  });
});

describe("transient failures keep the existing retry budget", () => {
  it("a 429 on every attempt is retried 3 times, then ends with the busy message", async () => {
    script = Array.from({ length: 4 }, () => ({ messages: rejectionMessages(RATE_LIMIT_TEXT, "rate_limit"), throws: EXIT_1() }));
    const outcome = await send(await createApp(), "q-busy");

    expectFailure(outcome, BUSY, [SENTINEL, "API Error", "Claude Code process exited"]);
    expect(outcome.text).not.toContain("rate_limit_error");
    expect(sdkCalls).toHaveLength(4);
    expect(outcome.events.filter((e) => e.type === "rate_limited").map((e) => e.attempt)).toEqual([1, 2, 3]);
    expect(logLines.filter((line) => line.startsWith("[retry]"))).toEqual([
      "[retry] queryId=q-busy kind=transient attempt 1/3, waiting 1000ms",
      "[retry] queryId=q-busy kind=transient attempt 2/3, waiting 2000ms",
      "[retry] queryId=q-busy kind=transient attempt 3/3, waiting 4000ms",
    ]);
  }, 20_000);

  it("a 429 once, then an answer: the request completes with done", async () => {
    script = [{ messages: rejectionMessages(RATE_LIMIT_TEXT, "rate_limit"), throws: EXIT_1() }, { messages: answerMessages() }];
    const outcome = await send(await createApp(), "q-busy-once");

    expect(outcome.events.some((e) => e.type === "error")).toBe(false);
    expect(outcome.events.at(-1)?.type).toBe("done");
    expect(sdkCalls).toHaveLength(2);
    expect(outcome.text).not.toContain(SENTINEL);
  }, 20_000);

  it("an empty answer from a successful run is still retried (empty-response retry)", async () => {
    script = [
      { messages: [INIT, { type: "result", subtype: "success", is_error: false, result: "", session_id: "sdk-empty", usage: {}, total_cost_usd: 0 }] },
      { messages: answerMessages("sdk-empty") },
    ];
    const outcome = await send(await createApp(), "q-empty");

    expect(outcome.events.at(-1)?.type).toBe("done");
    expect(sdkCalls).toHaveLength(2);
  }, 20_000);
});

describe("retries resume only an established session", () => {
  it("a transient failure before session establishment retries fresh under a new SDK session ID", async () => {
    script = [{ messages: rejectionMessages(RATE_LIMIT_TEXT, "rate_limit"), throws: EXIT_1() }, { messages: answerMessages("sdk-fresh") }];
    const outcome = await send(await createApp(), "q-fresh-retry", { useSession: true, sessionId: "client-fresh" });

    expect(outcome.events.at(-1)?.type).toBe("done");
    expect(sdkCalls).toHaveLength(2);
    expect(sdkCalls[0].resume).toBeUndefined();
    expect(sdkCalls[1].resume).toBeUndefined();
    expect(typeof sdkCalls[1].sessionId).toBe("string");
    expect(sdkCalls[1].sessionId).not.toBe(sdkCalls[0].sessionId);
  }, 20_000);

  it("a failed request confirms no session: the next request with the same client session ID starts fresh", async () => {
    const app = await createApp();
    script = [{ messages: rejectionMessages(VERSION_TEXT), throws: EXIT_1() }];
    expectFailure(await send(app, "q-first", { useSession: true, sessionId: "client-a" }), VERSION_BOTH);

    script = [{ messages: answerMessages("sdk-second") }];
    const second = await send(app, "q-second", { useSession: true, sessionId: "client-a" });

    expect(second.events.at(-1)?.type).toBe("done");
    expect(sdkCalls).toHaveLength(2);
    expect(sdkCalls[1].resume).toBeUndefined();
    expect(sdkCalls[1].sessionId).not.toBe(sdkCalls[0].sessionId);
    expect(logLines.some((line) => line.includes("Updated SDK sessionId for client-a: sdk-failed-session"))).toBe(false);

    // Now established: the third request resumes the confirmed session.
    script = [{ messages: answerMessages("sdk-second") }];
    const third = await send(app, "q-third", { useSession: true, sessionId: "client-a" });
    expect(third.events.at(-1)?.type).toBe("done");
    expect(sdkCalls[2].resume).toBe("sdk-second");
  }, 20_000);

  it("a transient failure on a resumed (established) session retries by resuming it", async () => {
    const app = await createApp();
    script = [{ messages: answerMessages("sdk-est") }];
    await send(app, "q-est-1", { useSession: true, sessionId: "client-b" });

    script = [{ messages: rejectionMessages(RATE_LIMIT_TEXT, "rate_limit"), throws: EXIT_1() }, { messages: answerMessages("sdk-est") }];
    const outcome = await send(app, "q-est-2", { useSession: true, sessionId: "client-b" });

    expect(outcome.events.at(-1)?.type).toBe("done");
    expect(sdkCalls.map((c) => c.resume)).toEqual([undefined, "sdk-est", "sdk-est"]);
  }, 20_000);
});
