/**
 * Run failures through the real runtime (MVP-7685): the compiled gateway
 * (`dist/server.js`, built by `npm run build`) runs as a child process with the
 * production Claude Agent SDK and its bundled Claude runtime, which talks to a
 * scripted stand-in for the Anthropic Messages API. The runtime writes the
 * provider rejection to stdout and exits 1; the client must receive one safe,
 * actionable `error` event, no `done`, and none of the raw diagnostic.
 *
 * Expected texts are written out here on purpose (not imported from
 * `run-failure.ts`), so a wording change in production fails this test.
 * "Attempts" are the gateway's runtime runs (one `SDK options:` log line and
 * one runtime session each); the runtime itself repeats a failed streaming
 * request once without streaming, so provider request counts are per session.
 * The child gets an environment allowlist and fresh temp directories
 * (helpers/git-process-gateway.ts). Linux only: process cleanup reads /proc.
 */
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  FINAL_ANSWER,
  MALFORMED_BODY,
  VERSION_REQUIRED,
  startFakeAnthropicApi,
  type FakeAnthropicApi,
  type FakeApiMode,
} from "./helpers/fake-anthropic-api.js";
import { REPO_ROOT, descendants, gatewayRequest, spawnGateway, type Cleanup, type SpawnedGateway } from "./helpers/git-process-gateway.js";

/** The bundled runtime version declared by the SDK package. */
const INSTALLED = (JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "node_modules", "@anthropic-ai", "claude-agent-sdk", "package.json"), "utf8")) as { claudeCodeVersion: string }).claudeCodeVersion;

const RETRY_WILL_NOT_HELP = "Retrying will not help until the administrator has done this.";
const VERSION_BOTH = `The AI runtime on the gateway server is too old for the selected model (installed ${INSTALLED}, required ${VERSION_REQUIRED} or newer). Ask your gateway administrator to update the gateway runtime. ${RETRY_WILL_NOT_HELP}`;
const VERSION_INSTALLED_ONLY = `The AI runtime on the gateway server is too old for the selected model (installed ${INSTALLED}; a newer version is required). Ask your gateway administrator to update the gateway runtime. ${RETRY_WILL_NOT_HELP}`;
const AUTHENTICATION = `The gateway could not authenticate with the AI provider. Ask your gateway administrator to check the gateway's authentication. ${RETRY_WILL_NOT_HELP}`;
const BUSY = "The AI provider is busy right now. Please try again in a few minutes.";
const unknownFailure = (queryId: string): string =>
  `The AI request failed on the gateway for an unknown reason. Please try again. If it keeps failing, ask your gateway administrator to check the gateway logs (reference: ${queryId}).`;

/** Raw diagnostic material the runtime prints for a provider rejection; none may reach a client or a log. */
const RAW_MARKERS = ["API Error", "invalid_request_error", "authentication_error", "claude_code_version_too_old", "rate_limit_error", "PROBE-7685-MALFORMED", "invalid x-api-key", "Invalid API key", "Claude Code process exited"];

/** The gateway output without the allowlisted `providerType=<type>` field of the failure log line. */
function logWithoutProviderType(output: string): string {
  return output.replace(/ providerType=\S+/g, "");
}

/** The retry budget of retry.ts; a permanent failure must arrive well within it. */
const RETRY_BUDGET_MS = 60_000;

const cleanups: Cleanup[] = [];

afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()!();
});

async function fakeApi(mode: FakeApiMode, privateMaterial: string[] = []): Promise<FakeAnthropicApi> {
  const api = await startFakeAnthropicApi({ toolName: "no-such-tool-7685", mode, privateMaterial });
  cleanups.push(() => api.close());
  return api;
}

async function gateway(api: FakeAnthropicApi, env: Record<string, string> = {}): Promise<SpawnedGateway> {
  return spawnGateway(cleanups, {
    rootPrefix: "mvp7685-gw-",
    env: {
      ANTHROPIC_BASE_URL: api.baseUrl,
      ANTHROPIC_API_KEY: "sk-ant-fake-run-failure-7685",
      DISABLE_TELEMETRY: "1",
      CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
      ...env,
    },
  });
}

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

interface QueryOutcome {
  queryId: string;
  events: NdjsonEvent[];
  /** The raw NDJSON body of the query response. */
  text: string;
  /** The raw NDJSON body of GET /v1/query/:id/events after the run. */
  replayText: string;
  replay: NdjsonEvent[];
  elapsedMs: number;
}

async function waitForNoDescendants(pid: number, timeoutMs = 20_000): Promise<void> {
  const started = Date.now();
  while (descendants(pid).length > 0) {
    if (Date.now() - started > timeoutMs) throw new Error(`runtime processes still alive after ${timeoutMs} ms`);
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
}

async function runQuery(gw: SpawnedGateway, body: Record<string, unknown>): Promise<QueryOutcome> {
  const queryId = `q7685-${randomBytes(4).toString("hex")}`;
  const started = Date.now();
  const res = await gatewayRequest(gw.port, "POST", "/v1/query", { queryId, prompt: "hi", model: "claude-opus-5-5", useSession: false, ...body });
  const elapsedMs = Date.now() - started;
  expect(res.status).toBe(200);
  await waitForNoDescendants(gw.child.pid!);
  const replay = await gatewayRequest(gw.port, "GET", `/v1/query/${queryId}/events`);
  expect(replay.status).toBe(200);
  return { queryId, events: parseNdjson(res.text), text: res.text, replayText: replay.text, replay: parseNdjson(replay.text), elapsedMs };
}

/** Exactly one terminal `error` event with exactly the keys seq/type/content, no `done`, and the same content on replay. */
function expectSingleError(outcome: QueryOutcome, content: string): void {
  const errors = outcome.events.filter((e) => e.type === "error");
  expect.soft(errors).toHaveLength(1);
  expect.soft(outcome.events.at(-1)?.type).toBe("error");
  expect.soft(Object.keys(errors[0] ?? {}).sort()).toEqual(["content", "seq", "type"]);
  expect.soft(errors[0]?.content).toBe(content);
  expect.soft(outcome.events.some((e) => e.type === "done")).toBe(false);
  expect.soft(outcome.replay).toEqual(outcome.events);
}

function expectAbsent(haystack: string, needles: string[], where: string): void {
  const found = needles.filter((needle) => haystack.includes(needle));
  expect.soft(found, `${where} contains raw diagnostic material`).toEqual([]);
}

/** Runtime sessions of the main provider requests, in order of first appearance. */
function sessions(api: FakeAnthropicApi): string[] {
  return [...new Set(api.mainRequests().map((r) => r.session))];
}

/** `SDK options: sessionId=<id> isResume=<bool>` lines of the gateway log (one per attempt), in order. */
function sdkOptionLines(output: string): { sessionId: string; isResume: boolean }[] {
  return [...output.matchAll(/SDK options: sessionId=(\S+) isResume=(true|false)/g)].map((m) => ({ sessionId: m[1], isResume: m[2] === "true" }));
}

async function readSessions(gw: SpawnedGateway): Promise<Record<string, { sessionId: string; sdkSessionId?: string }>> {
  // The session store saves 100 ms after a change.
  await new Promise((resolve) => setTimeout(resolve, 300));
  const file = path.join(gw.dirs.persist, "sessions.json");
  // Since MVP-7679 conversations are stored below their API-key label; the rows here use one label.
  const saved = JSON.parse(fs.readFileSync(file, "utf8")) as {
    sessions?: Record<string, { sessionId: string; sdkSessionId?: string }>;
    sessionsByLabel?: Record<string, Record<string, { sessionId: string; sdkSessionId?: string }>>;
  };
  return Object.assign({}, saved.sessions ?? {}, ...Object.values(saved.sessionsByLabel ?? {}));
}

interface FailureRow {
  name: string;
  mode: FakeApiMode;
  expected: (queryId: string) => string;
  kind: string;
}

const FAILURE_ROWS: FailureRow[] = [
  {
    name: "a structured version rejection followed by exit 1 gives the version message with both versions",
    mode: "version-too-old",
    expected: () => VERSION_BOTH,
    kind: "runtime_version_unsupported",
  },
  {
    name: "a version rejection without a required version names only the installed one",
    mode: "version-too-old-no-versions",
    expected: () => VERSION_INSTALLED_ONLY,
    kind: "runtime_version_unsupported",
  },
  {
    name: "a non-retryable authentication rejection tells the user an administrator must check gateway authentication",
    mode: "auth-rejected",
    expected: () => AUTHENTICATION,
    kind: "authentication",
  },
  {
    name: "a malformed (non-JSON) provider body gives the generic failure with a log reference",
    mode: "malformed",
    expected: (queryId) => unknownFailure(queryId),
    kind: "unknown",
  },
];

describe("a failed run reaches the client as one safe, actionable error event (real runtime)", () => {
  for (const row of FAILURE_ROWS) {
    it(row.name, async () => {
      const api = await fakeApi(row.mode);
      const gw = await gateway(api);

      const outcome = await runQuery(gw, {});

      expectSingleError(outcome, row.expected(outcome.queryId));
      // A permanent failure is not retried: one attempt (one runtime session), error well within the retry budget.
      expect.soft(sdkOptionLines(gw.output())).toHaveLength(1);
      expect.soft(sessions(api)).toHaveLength(1);
      expect.soft(api.mainRequests().length).toBeGreaterThan(0);
      expect.soft(api.mainRequests().length).toBeLessThanOrEqual(2);
      expect.soft(outcome.events.some((e) => e.type === "rate_limited")).toBe(false);
      expect.soft(outcome.elapsedMs).toBeLessThan(RETRY_BUDGET_MS / 2);
      // No raw diagnostic in the stream, the replay, any text event or the gateway's own output.
      expectAbsent(outcome.text, RAW_MARKERS, "the NDJSON stream");
      expectAbsent(outcome.replayText, RAW_MARKERS, "the event replay");
      expectAbsent(logWithoutProviderType(gw.output()), RAW_MARKERS, "the gateway output");
      expect.soft(gw.output()).toContain(`Error queryId=${outcome.queryId} kind=${row.kind} `);
    }, 90_000);
  }

  it("a retryable 429 is retried within the existing budget and the retried run completes normally", async () => {
    const api = await fakeApi("rate-limited-once");
    const gw = await gateway(api);

    const outcome = await runQuery(gw, {});

    expect.soft(outcome.events.filter((e) => e.type === "rate_limited" && e.status === "retrying")).toHaveLength(1);
    expect.soft(outcome.events.some((e) => e.type === "error")).toBe(false);
    expect.soft(outcome.events.at(-1)?.type).toBe("done");
    expect.soft(outcome.events.filter((e) => e.type === "text").map((e) => e.content).join("")).toContain(FINAL_ANSWER);
    expect.soft(sdkOptionLines(gw.output())).toHaveLength(2);
    expect.soft(sessions(api)).toHaveLength(2);
    expectAbsent(logWithoutProviderType(gw.output()), RAW_MARKERS, "the gateway output");
  }, 90_000);

  it("a 429 on every attempt ends with the busy message after the retry budget's attempts", async () => {
    const api = await fakeApi("rate-limited");
    const gw = await gateway(api);

    const outcome = await runQuery(gw, {});

    expectSingleError(outcome, BUSY);
    // 1 attempt + 3 retries (retry.ts RETRY_MAX_ATTEMPTS = 3), each a fresh runtime session.
    expect.soft(sdkOptionLines(gw.output())).toHaveLength(4);
    expect.soft(sessions(api)).toHaveLength(4);
    expect.soft(outcome.events.filter((e) => e.type === "rate_limited" && e.status === "retrying")).toHaveLength(3);
    expectAbsent(outcome.text, RAW_MARKERS, "the NDJSON stream");
    expectAbsent(logWithoutProviderType(gw.output()), RAW_MARKERS, "the gateway output");
  }, 90_000);
});

describe("private diagnostic material never reaches the client or the logs (real runtime)", () => {
  for (const level of ["info", "debug"] as const) {
    it(`at LOG_LEVEL=${level}: token, Authorization header, prompt echo and stack trace stay out; the version cause stays understandable`, async () => {
      const token = `sk-ant-api03-${randomBytes(12).toString("hex")}`;
      const bearer = `Bearer ${randomBytes(12).toString("hex")}`;
      const privatePrompt = `PrivatePrompt${randomBytes(8).toString("hex")}`;
      // Sentinels sit right next to the version text the classifier reads.
      const api = await fakeApi("private-material", [`token=${token}`, `Authorization: ${bearer}`]);
      const gw = await gateway(api, { LOG_LEVEL: level });

      const outcome = await runQuery(gw, { prompt: `hi ${privatePrompt}` });

      expectSingleError(outcome, VERSION_BOTH);
      const providerOnly = [token, bearer, "/srv/provider/src/gate.js", "processTicksAndRejections", "Request was:"];
      expectAbsent(outcome.text, [...providerOnly, privatePrompt, ...RAW_MARKERS], "the NDJSON stream");
      expectAbsent(outcome.replayText, [...providerOnly, privatePrompt, ...RAW_MARKERS], "the event replay");
      expectAbsent(logWithoutProviderType(gw.output()), [...providerOnly, ...RAW_MARKERS], "the gateway output");
      // The client's own prompt may appear only in the debug request preview of its own request.
      const promptLines = gw
        .output()
        .split("\n")
        .filter((line) => line.includes(privatePrompt));
      if (level === "info") expect.soft(promptLines).toEqual([]);
      else expect.soft(promptLines.every((line) => line.startsWith("[req] POST /v1/query "))).toBe(true);
    }, 90_000);
  }
});

describe("sessions after a failed first request (real runtime)", () => {
  it("a failure before session establishment is not confirmed; the next request with the same client session ID starts fresh and completes", async () => {
    const api = await fakeApi("fail-first");
    const gw = await gateway(api);
    const clientSession = `client-${randomBytes(4).toString("hex")}`;

    const first = await runQuery(gw, { sessionId: clientSession, useSession: true, prompt: "first-prompt-7685" });

    expectSingleError(first, VERSION_BOTH);
    const afterFirst = await readSessions(gw);
    expect.soft(afterFirst[clientSession]).toBeDefined();
    expect.soft(afterFirst[clientSession]?.sdkSessionId).toBeUndefined();

    const second = await runQuery(gw, { sessionId: clientSession, useSession: true, prompt: "second-prompt-7685" });

    expect.soft(second.events.some((e) => e.type === "error")).toBe(false);
    expect.soft(second.events.at(-1)?.type).toBe("done");
    expect.soft(second.events.at(-1)?.sessionId).toBe(clientSession);
    expect.soft(second.events.filter((e) => e.type === "text").map((e) => e.content).join("")).toContain(FINAL_ANSWER);
    expect.soft(gw.output()).not.toContain("No conversation found");
    // Fresh start: not a resume, a new SDK session ID, and the failed turn is not part of the new conversation.
    const options = sdkOptionLines(gw.output());
    expect.soft(options).toHaveLength(2);
    expect.soft(options.map((o) => o.isResume)).toEqual([false, false]);
    expect.soft(options[1]?.sessionId).not.toBe(options[0]?.sessionId);
    // The second request runs in a new runtime session that does not carry the failed turn.
    expect.soft(sessions(api)).toHaveLength(2);
    const secondRequests = api.mainRequests().filter((r) => r.session === sessions(api)[1]);
    expect.soft(secondRequests.length).toBeGreaterThan(0);
    expect.soft(secondRequests.every((r) => r.userTexts.join(" ").includes("second-prompt-7685"))).toBe(true);
    expect.soft(secondRequests.some((r) => r.userTexts.join(" ").includes("first-prompt-7685"))).toBe(false);
    const afterSecond = await readSessions(gw);
    expect.soft(afterSecond[clientSession]?.sdkSessionId).toBeTruthy();
  }, 90_000);

  it("an established session still resumes: the second request carries the first turn", async () => {
    const api = await fakeApi("normal");
    const gw = await gateway(api);
    const clientSession = `client-${randomBytes(4).toString("hex")}`;

    const first = await runQuery(gw, { sessionId: clientSession, useSession: true, prompt: "first-prompt-7685" });
    expect.soft(first.events.at(-1)?.type).toBe("done");
    const established = (await readSessions(gw))[clientSession]?.sdkSessionId;
    expect.soft(established).toBeTruthy();

    const second = await runQuery(gw, { sessionId: clientSession, useSession: true, prompt: "second-prompt-7685" });

    expect.soft(second.events.some((e) => e.type === "error")).toBe(false);
    expect.soft(second.events.at(-1)?.type).toBe("done");
    const options = sdkOptionLines(gw.output());
    expect.soft(options.map((o) => o.isResume)).toEqual([false, true]);
    expect.soft(options[1]?.sessionId).toBe(established);
    const secondRequest = api.mainRequests().at(-1);
    expect.soft(secondRequest?.userTexts.join(" ")).toContain("first-prompt-7685");
    expect.soft(secondRequest?.userTexts.join(" ")).toContain("second-prompt-7685");
  }, 90_000);
});
