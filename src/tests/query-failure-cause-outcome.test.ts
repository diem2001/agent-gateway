/**
 * Cause metadata of an unknown failure reaches the operator log line through the
 * REAL query.ts + agent.ts + retry.ts path (MVP-7852), with ONLY the Claude Agent
 * SDK boundary (`query()`) mocked. Runtime exit metadata is supplied through the
 * `SandboxRun.runtimeExit` getter, the seam the gateway reads the launcher process from.
 *
 * Expected values are written out here, not imported from run-failure.ts.
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
  throws?: unknown;
}

let script: Attempt[] = [];
let logLines: string[] = [];

const INIT = { type: "system", subtype: "init", claude_code_version: "2.0.77", skills: [] };
const SENTINELS = ["SENTINEL-MSG", "SENTINEL-STDERR", "SENTINEL-BODY", "PRIVATE_TOKEN", "SIGSECRET", "LeakyCustomError"];
const unknownFailure = (queryId: string): string =>
  `The AI request failed on the gateway for an unknown reason. Please try again. If it keeps failing, ask your gateway administrator to check the gateway logs (reference: ${queryId}).`;

class LeakyCustomError extends Error {}

/** An error shaped like the SDK's exit error, carrying sentinels in every untrusted place. */
function sdkError(options: { code?: unknown; custom?: boolean; message?: string } = {}): Error {
  const error = options.custom ? new LeakyCustomError(options.message ?? "SENTINEL-MSG") : new Error(options.message ?? "Claude Code process exited with code 1 SENTINEL-MSG");
  Object.assign(error, { stderr: "SENTINEL-STDERR" });
  if (options.code !== undefined) Object.assign(error, { code: options.code });
  return error;
}

let persistDir = "";
let runtimeExit: { exitCode: unknown; signalCode: unknown } | null = null;

beforeAll(() => {
  persistDir = fs.mkdtempSync(path.join(os.tmpdir(), "mvp7852-outcome-"));
  vi.stubEnv("SESSION_PERSIST_PATH", path.join(persistDir, "sessions.json"));
});

afterAll(async () => {
  vi.unstubAllEnvs();
  await new Promise((resolve) => setTimeout(resolve, 150));
  fs.rmSync(persistDir, { recursive: true, force: true });
});

function mockSdk(): void {
  vi.doMock("@anthropic-ai/claude-agent-sdk", () => ({
    createSdkMcpServer: vi.fn((options) => ({ type: "sdk", name: options.name })),
    query: vi.fn(() => {
      const attempt: Attempt = script.shift() ?? { messages: [INIT] };
      return (async function* () {
        for (const message of attempt.messages) yield message;
        if (attempt.throws !== undefined) throw attempt.throws;
      })();
    }),
  }));
}

beforeEach(() => {
  vi.resetModules();
  script = [];
  logLines = [];
  runtimeExit = null;
  vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
    logLines.push(args.map(String).join(" "));
  });
  mockSdk();
});

afterEach(() => {
  vi.doUnmock("@anthropic-ai/claude-agent-sdk");
  vi.doUnmock("../sdk-run-logs.js");
  vi.unstubAllEnvs();
  vi.stubEnv("SESSION_PERSIST_PATH", path.join(persistDir, "sessions.json"));
  vi.restoreAllMocks();
});

async function createApp() {
  const { SandboxRun } = await import("../sandbox.js");
  vi.spyOn(SandboxRun.prototype, "runtimeExit", "get").mockImplementation(() => runtimeExit as never);
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

/** Sends one query and asserts the unchanged public outcome; returns the operator line of that reference. */
async function failAndReadLogLine(queryId: string): Promise<string> {
  const app = await createApp();
  const res = await request(app).post("/v1/query").send({ queryId, prompt: "hi", useSession: false });
  expect(res.status).toBe(200);
  const replay = await request(app).get(`/v1/query/${queryId}/events`);
  const events = parseNdjson(res.text);
  expect(parseNdjson(replay.text)).toEqual(events);

  const errors = events.filter((e) => e.type === "error");
  expect(errors).toHaveLength(1);
  expect(events.at(-1)).toBe(errors[0]);
  expect(Object.keys(errors[0]).sort()).toEqual(["content", "seq", "type"]);
  expect(errors[0].content).toBe(unknownFailure(queryId));
  expect(events.some((e) => e.type === "done")).toBe(false);

  const operatorLines = logLines.filter((line) => line.startsWith(`[query] Error queryId=${queryId} `));
  expect(operatorLines).toHaveLength(1);
  for (const sentinel of [...SENTINELS, "Claude Code process exited", "API Error"]) {
    expect(res.text).not.toContain(sentinel);
    expect(replay.text).not.toContain(sentinel);
    expect(logLines.filter((line) => line.includes(sentinel))).toEqual([]);
  }
  return operatorLines[0];
}

const PREFIX = "kind=unknown apiStatus=none providerType=none installed=2.0.77 required=none";
const tail = (errorClass: string, errno: string, exit: string, signal: string): string => `${PREFIX} errorClass=${errorClass} errno=${errno} exit=${exit} signal=${signal}`;

const UNPARSEABLE_BODY = 'API Error: 502 <html>SENTINEL-BODY {"error":{"code":"ECONNRESET"}}</html>';

interface Row {
  fixture: string;
  attempt: () => Attempt;
  runtime?: { exitCode: unknown; signalCode: unknown };
  expected: string;
}

const ROWS: Row[] = [
  { fixture: "Error with no code, exit or signal", attempt: () => ({ messages: [INIT], throws: sdkError() }), expected: tail("Error", "none", "none", "none") },
  { fixture: 'Error with code "PRIVATE_TOKEN"', attempt: () => ({ messages: [INIT], throws: sdkError({ code: "PRIVATE_TOKEN" }) }), expected: tail("Error", "other", "none", "none") },
  {
    fixture: 'Error with runtime signal metadata "SIGSECRET"',
    attempt: () => ({ messages: [INIT], throws: sdkError() }),
    runtime: { exitCode: null, signalCode: "SIGSECRET" },
    expected: tail("Error", "none", "none", "other"),
  },
  {
    fixture: 'Error with runtime exit metadata "1; PRIVATE_TOKEN" (string)',
    attempt: () => ({ messages: [INIT], throws: sdkError() }),
    runtime: { exitCode: "1; PRIVATE_TOKEN", signalCode: null },
    expected: tail("Error", "none", "none", "none"),
  },
  {
    fixture: "Error with runtime exit metadata 1.5 (non-integer)",
    attempt: () => ({ messages: [INIT], throws: sdkError() }),
    runtime: { exitCode: 1.5, signalCode: null },
    expected: tail("Error", "none", "none", "none"),
  },
  {
    fixture: 'LeakyCustomError (not allowlisted) with code "ENOSPC"',
    attempt: () => ({ messages: [INIT], throws: sdkError({ custom: true, code: "ENOSPC" }) }),
    expected: tail("other", "ENOSPC", "none", "none"),
  },
  {
    fixture: 'Error with runtime signal metadata "SIGKILL" and code "PRIVATE_TOKEN"',
    attempt: () => ({ messages: [INIT], throws: sdkError({ code: "PRIVATE_TOKEN" }) }),
    runtime: { exitCode: null, signalCode: "SIGKILL" },
    expected: tail("Error", "other", "none", "SIGKILL"),
  },
  {
    fixture: 'Error whose message only says "exited with code 137 SIGKILL ENOSPC"',
    attempt: () => ({ messages: [INIT], throws: sdkError({ message: "Claude Code process exited with code 137 SIGKILL ENOSPC SENTINEL-MSG" }) }),
    expected: tail("Error", "none", "none", "none"),
  },
  {
    fixture: 'Error from an unparseable provider body containing "code":"ECONNRESET"',
    attempt: () => ({
      messages: [
        INIT,
        { type: "assistant", error: "unknown", message: { model: "<synthetic>", content: [{ type: "text", text: UNPARSEABLE_BODY }] } },
        { type: "result", subtype: "success", is_error: true, result: UNPARSEABLE_BODY, session_id: "sdk-failed", usage: {}, total_cost_usd: 0 },
      ],
      throws: sdkError(),
    }),
    expected: "kind=unknown apiStatus=502 providerType=none installed=2.0.77 required=none errorClass=Error errno=none exit=none signal=none",
  },
];

describe.each(["info", "debug"])("invalid metadata falls back per field while valid trusted fields survive (LOG_LEVEL=%s)", (level) => {
  ROWS.forEach(({ fixture, attempt, runtime, expected }, index) => {
    it(fixture, async () => {
      vi.stubEnv("LOG_LEVEL", level);
      script = [attempt()];
      runtimeExit = runtime ?? null;
      const queryId = `q-${level}-${index}`;
      expect(await failAndReadLogLine(queryId)).toBe(`[query] Error queryId=${queryId} ${expected}`);
    });
  });
});

describe("positive rows through the real failure path", () => {
  it("runtime process exits with code 3 (trusted exit metadata)", async () => {
    script = [{ messages: [INIT], throws: sdkError() }];
    runtimeExit = { exitCode: 3, signalCode: null };
    const line = await failAndReadLogLine("q-exit-3");
    expect(line).toBe(`[query] Error queryId=q-exit-3 ${tail("Error", "none", "3", "none")}`);
  });

  it("runtime process is terminated by SIGKILL (trusted signal metadata)", async () => {
    script = [{ messages: [INIT], throws: sdkError() }];
    runtimeExit = { exitCode: null, signalCode: "SIGKILL" };
    const line = await failAndReadLogLine("q-sigkill");
    expect(line).toBe(`[query] Error queryId=q-sigkill ${tail("Error", "none", "none", "SIGKILL")}`);
  });

  it("a gateway-internal step throws a Node system error with code ENOSPC (full disk)", async () => {
    // A genuine system error: writing to /dev/full fails with ENOSPC.
    let diskFull: unknown;
    try {
      fs.writeFileSync("/dev/full", "x");
    } catch (error) {
      diskFull = error;
    }
    expect((diskFull as { code?: string }).code).toBe("ENOSPC");
    vi.doMock("../sdk-run-logs.js", async (importOriginal) => ({
      ...(await importOriginal<typeof import("../sdk-run-logs.js")>()),
      createRunLogDir: () => {
        throw diskFull;
      },
    }));
    const line = await failAndReadLogLine("q-enospc");
    expect(line).toBe("[query] Error queryId=q-enospc kind=unknown apiStatus=none providerType=none installed=none required=none errorClass=Error errno=ENOSPC exit=none signal=none");
  });
});
