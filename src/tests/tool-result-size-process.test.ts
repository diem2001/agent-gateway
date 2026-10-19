/**
 * Tool result size classes against the real runtime (MVP-8089): the compiled gateway
 * (`dist/server.js`, built by `npm run build`) runs as a child process with the production
 * Claude Agent SDK and its native runtime, which talks to a scripted stand-in for the Anthropic
 * Messages API and to a loopback MCP stub registered as `jira`, so every result passes the
 * gateway's credential relay like a real mcp-jira result.
 *
 * What the runtime does with a result depends on its size and on the tool's own declaration:
 * a tool that lists `_meta["anthropic/maxResultSizeChars"]` (mcp-jira declares 250,000, MVP-8102)
 * gets that threshold for text results, every other tool the runtime default of 50,000
 * characters. Above its threshold the runtime saves the result to a file in the conversation's
 * home and the model receives a notice that names the file instead. The stub's text is a start
 * marker, a filler and an end marker of exactly N characters, so a full delivery is proven by
 * the exact payload and a bounded one by the missing end marker.
 *
 * The notice texts are the runtime's, not the gateway's: the pinned parts below are the stable
 * ones, and a runtime upgrade that changes them must change the docs section "Tool result size
 * limits" with them. Measured on Claude Code 2.1.292: an annotated tool above its limit always
 * yields the saved-output preview, even at 3 MiB; the `Error: result (` notice is what a tool
 * WITHOUT the annotation gets far above the default.
 *
 * Red control: `SIZE_PROBE_OMIT_ANNOTATION=1` makes the stub list no `_meta`; rows S1, S2 and R1
 * must then fail (preview instead of the end marker). Rows C1 and D3 keep that contrast in every run.
 */
import { afterEach, describe, expect, it } from "vitest";
import { FINAL_ANSWER, startFakeAnthropicApi, type FakeAnthropicApi } from "./helpers/fake-anthropic-api.js";
import { gatewayRequest, spawnGateway, type Cleanup, type SpawnedGateway } from "./helpers/git-process-gateway.js";
import { SIZE_END_MARKER, SIZE_START_MARKER, STUB_TOOL_NAME, framedToolText, startOAuthMcpStub, type OAuthMcpStub } from "./helpers/oauth-mcp-stub.js";

const PROMPT = "PROBE-8089 call the scripted tool";
const TOOL = `mcp__jira__${STUB_TOOL_NAME}`;
const ANNOTATION = { "anthropic/maxResultSizeChars": 250_000 };
const OMIT_ANNOTATION = process.env.SIZE_PROBE_OMIT_ANNOTATION === "1";
const RUN_TIMEOUT_MS = 120_000;

const cleanups: Cleanup[] = [];

afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()!();
});

interface NdjsonEvent {
  type: string;
  [key: string]: unknown;
}

interface Observed {
  stub: OAuthMcpStub;
  api: FakeAnthropicApi;
  gateway: SpawnedGateway;
  events: NdjsonEvent[];
  /** The scripted call's results as the runtime returned them to the "model". */
  results: { isError: boolean; text: string }[];
}

/** One ordinary or enforced chat in which the "model" calls the stub tool once. */
async function observe(options: { chars: number; annotated: boolean; enforcedTools?: string[] }): Promise<Observed> {
  const stub = await startOAuthMcpStub({
    toolResultChars: options.chars,
    toolMeta: options.annotated && !OMIT_ANNOTATION ? { [STUB_TOOL_NAME]: ANNOTATION } : undefined,
  });
  cleanups.push(() => stub.close());
  const api = await startFakeAnthropicApi({ toolName: STUB_TOOL_NAME });
  cleanups.push(() => api.close());
  const gateway = await spawnGateway(cleanups, {
    rootPrefix: "mvp8089-size-",
    env: {
      ANTHROPIC_BASE_URL: api.baseUrl,
      ANTHROPIC_API_KEY: "sk-ant-fake-result-size-8089",
      DISABLE_TELEMETRY: "1",
      CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
    },
  });
  const registered = await gatewayRequest(gateway.port, "PUT", "/v1/mcp-servers/jira", { type: "http", url: stub.url });
  expect(registered.status, registered.text).toBe(201);
  const res = await gatewayRequest(gateway.port, "POST", "/v1/query", {
    queryId: `q-8089-${Date.now()}`,
    prompt: PROMPT,
    model: "claude-sonnet-4-5",
    useSession: false,
    user_id: "user-8089",
    conversation_id: "conv-8089",
    ...(options.enforcedTools ? { enforcedTools: options.enforcedTools } : {}),
  });
  expect(res.status).toBe(200);
  const events = res.text
    .split("\n")
    .filter((line) => line.trim().startsWith("{"))
    .map((line) => JSON.parse(line) as NdjsonEvent);
  return { stub, api, gateway, events, results: api.requests.flatMap((q) => q.toolResults) };
}

/** What every row shares: one call reached the stub, one result came back, the run ended normally. */
function expectOneCallAndNormalEnd(o: Observed): void {
  expect(o.stub.toolCalls, "tools/call at the stub").toEqual([STUB_TOOL_NAME]);
  expect(o.results, "tool results the model received").toHaveLength(1);
  expect(o.results[0].isError).toBe(false);
  expect(o.events.at(-1)?.type).toBe("done");
  expect(o.events.filter((e) => e.type === "text").map((e) => e.content).join("")).toContain(FINAL_ANSWER);
}

/** The caller's `tool_result` event: no `success` field (the call completed), output cut by the gateway at 3,000 characters. */
function toolResultEvent(o: Observed): NdjsonEvent {
  const events = o.events.filter((e) => e.type === "tool_result");
  expect(events).toHaveLength(1);
  expect(events[0].toolName).toBe(TOOL);
  expect(events[0]).not.toHaveProperty("success");
  return events[0];
}

function expectFullDelivery(o: Observed, chars: number): void {
  expectOneCallAndNormalEnd(o);
  const text = o.results[0].text;
  expect(text.length).toBe(chars);
  expect(text.startsWith(SIZE_START_MARKER)).toBe(true);
  expect(text.endsWith(SIZE_END_MARKER)).toBe(true);
  expect(text === framedToolText(chars), "payload differs from what the stub sent").toBe(true);
  expect(String(toolResultEvent(o).output).startsWith(SIZE_START_MARKER)).toBe(true);
}

/** The runtime's saved-output preview: a notice with the first 2 KB, naming a file in the conversation's `tool-results` directory. */
const PREVIEW_PARTS = ["<persisted-output>\nOutput too large (", "Full output saved to: ", "/tool-results/", "Preview (first 2KB):"];
/** The runtime's notice for a tool WITHOUT the annotation far above the default. */
const NOTICE_PARTS = ["Error: result (", "characters across 1 line) exceeds maximum allowed tokens. Output has been saved to ", "/tool-results/"];

function expectBounded(o: Observed, parts: string[]): void {
  expectOneCallAndNormalEnd(o);
  const text = o.results[0].text;
  for (const part of parts) expect(text, `missing "${part}"`).toContain(part);
  expect(text.includes(SIZE_END_MARKER), "the end marker must not arrive").toBe(false);
  expect(text.length, "the model receives a notice, not the text").toBeLessThan(5_000);
  const event = toolResultEvent(o);
  for (const part of parts) expect(String(event.output), `event output misses "${part}"`).toContain(part);
}

describe("an annotated Jira tool: results up to 250,000 characters arrive in full (real runtime)", () => {
  it("S1: 200,000 characters, ordinary chat", async () => {
    const o = await observe({ chars: 200_000, annotated: true });
    expectFullDelivery(o, 200_000);
  }, RUN_TIMEOUT_MS);

  it("S2: 250,000 characters (the limit), ordinary chat", async () => {
    const o = await observe({ chars: 250_000, annotated: true });
    expectFullDelivery(o, 250_000);
  }, RUN_TIMEOUT_MS);

  it("S3: 250,001 characters give the saved-output preview naming the saved file", async () => {
    const o = await observe({ chars: 250_001, annotated: true });
    expectBounded(o, PREVIEW_PARTS);
    expect(o.results[0].text).toContain(SIZE_START_MARKER);
  }, RUN_TIMEOUT_MS);

  it("S4: 3,145,728 characters give a notice naming the saved file, no full text and no end marker", async () => {
    const o = await observe({ chars: 3_145_728, annotated: true });
    // Measured: the annotated tool gets the same saved-output preview at any size above its limit.
    expectBounded(o, PREVIEW_PARTS);
  }, RUN_TIMEOUT_MS);

  it("R1: 200,000 characters in a run whose tool grant excludes Read and Bash arrive in full", async () => {
    const o = await observe({ chars: 200_000, annotated: true, enforcedTools: [TOOL] });
    expect(o.events[0]).toEqual({ seq: 0, type: "tool_policy", enforced: true, tools: [TOOL] });
    const offered = new Set(o.api.mainRequests().flatMap((q) => q.tools));
    expect([...offered]).toEqual([TOOL]);
    expect(offered.has("Read") || offered.has("Bash")).toBe(false);
    expectFullDelivery(o, 200_000);
  }, RUN_TIMEOUT_MS);
});

describe("a tool without the annotation keeps the runtime default of 50,000 characters (real runtime)", () => {
  it("D1: 50,000 characters (the default limit) arrive in full", async () => {
    const o = await observe({ chars: 50_000, annotated: false });
    expectFullDelivery(o, 50_000);
  }, RUN_TIMEOUT_MS);

  it("D2: 50,001 characters give the saved-output preview naming the saved file", async () => {
    const o = await observe({ chars: 50_001, annotated: false });
    expectBounded(o, PREVIEW_PARTS);
  }, RUN_TIMEOUT_MS);

  it("D3: 3,145,728 characters give the too-large notice naming the saved file", async () => {
    const o = await observe({ chars: 3_145_728, annotated: false });
    expectBounded(o, NOTICE_PARTS);
  }, RUN_TIMEOUT_MS);

  it("C1 (control for S1): 200,000 characters without the annotation give the preview, not the full text", async () => {
    const o = await observe({ chars: 200_000, annotated: false });
    expectBounded(o, PREVIEW_PARTS);
  }, RUN_TIMEOUT_MS);
});
