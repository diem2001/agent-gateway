/**
 * Outcome Probe for MVP-6304 (Observable-Outcome AC):
 *
 *   "Given the main agent spawns a sub-agent via the Task/Agent tool, and the
 *    sub-agent makes tool calls, when the gateway streams the NDJSON events, then
 *    each sub-agent tool_use event carries parentToolUseId = the toolUseId of the
 *    spawning Task/Agent tool_use, and conversation-level (main-agent) tool_use
 *    events carry parentToolUseId = null."
 *
 * This test exercises the REAL query.ts + agent.ts + retry.ts path end-to-end,
 * mocking ONLY the Claude Agent SDK boundary (`query()`). The mocked SDK stream
 * yields a main-agent assistant message (parent_tool_use_id: null) and a
 * sub-agent assistant message (parent_tool_use_id: "tu_parent"), each carrying a
 * tool_use block. We parse the resulting NDJSON and assert the producer contract
 * consumed downstream by MVP-6306 (reqlift): the tool_use event gains
 * parentToolUseId (string | null), always present, while toolName/toolUseId/
 * input/startedAt are unchanged.
 */
import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

beforeEach(() => {
  vi.resetModules();
  vi.doMock("@anthropic-ai/claude-agent-sdk", () => ({
    createSdkMcpServer: vi.fn((options) => ({ type: "sdk", name: options.name })),
    query: vi.fn(() => {
      return (async function* () {
        // Main-conversation (top-level) assistant message → parent_tool_use_id: null.
        // The tool_use block carries `name` because this mock does not drive the
        // stream_event content_block_start path that would otherwise register it.
        yield {
          type: "assistant",
          parent_tool_use_id: null,
          message: {
            content: [
              // Non-empty assistant text so retry's "empty response" guard does not
              // re-run the query (a real assistant turn that calls a tool also
              // carries text; mirrors the multimodal Outcome Probe's "ack").
              { type: "text", text: "ack" },
              {
                type: "tool_use",
                id: "tu_top_1",
                name: "WebSearch",
                input: { query: "auth libraries" },
              },
            ],
          },
        };
        // Sub-agent assistant message spawned by a Task tool_use → parent_tool_use_id
        // is the spawning Task/Agent tool_use id.
        yield {
          type: "assistant",
          parent_tool_use_id: "tu_parent",
          message: {
            content: [
              {
                type: "tool_use",
                id: "tu_child_7",
                name: "Bash",
                input: { command: "ls -la" },
              },
            ],
          },
        };
        // Emit a result so the NDJSON `done` event is produced and retry's
        // "empty response" guard does not re-run the query.
        yield { type: "result", usage: { input_tokens: 1, output_tokens: 1 }, total_cost_usd: 0, sessionId: "sdk-session" };
      })();
    }),
  }));
});

afterEach(() => {
  vi.doUnmock("@anthropic-ai/claude-agent-sdk");
});

async function createApp() {
  const { queryRouter } = await import("../query.js");
  const app = express();
  app.use(express.json({ limit: "25mb" }));
  app.use(queryRouter);
  return app;
}

/** Parse an NDJSON response body into an array of event objects. */
function parseNdjson(text: string): Array<Record<string, unknown>> {
  return text
    .split("\n")
    .filter((line) => line.trim().length > 0)
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}

describe("Outcome Probe — tool_use NDJSON events carry parentToolUseId", () => {
  it("main-agent tool_use has parentToolUseId === null; sub-agent tool_use has parentToolUseId === the spawning Task tool_use id", async () => {
    const app = await createApp();

    const res = await request(app)
      .post("/v1/query")
      .send({ queryId: "probe-parent-tool-use-id", prompt: "run a task", useSession: false });

    expect(res.status).toBe(200);
    const events = parseNdjson(res.text);

    const toolUseEvents = events.filter((e) => e.type === "tool_use");
    expect(toolUseEvents).toHaveLength(2);

    const topLevel = toolUseEvents.find((e) => e.toolUseId === "tu_top_1");
    const subAgent = toolUseEvents.find((e) => e.toolUseId === "tu_child_7");
    expect(topLevel).toBeDefined();
    expect(subAgent).toBeDefined();

    // Observable outcome: attribution by emitter.
    // Main conversation agent → parentToolUseId is null (always present, not omitted).
    expect("parentToolUseId" in topLevel!).toBe(true);
    expect(topLevel!.parentToolUseId).toBeNull();

    // Sub-agent spawned by a Task → parentToolUseId is the spawning Task tool_use id.
    expect("parentToolUseId" in subAgent!).toBe(true);
    expect(subAgent!.parentToolUseId).toBe("tu_parent");

    // Regression: existing tool_use fields are unchanged in shape and value.
    expect(topLevel!.toolName).toBe("WebSearch");
    expect(topLevel!.input).toBe("auth libraries");
    expect(typeof topLevel!.startedAt).toBe("number");
    expect(typeof topLevel!.seq).toBe("number");

    expect(subAgent!.toolName).toBe("Bash");
    expect(subAgent!.input).toBe("ls -la");
    expect(typeof subAgent!.startedAt).toBe("number");
    expect(typeof subAgent!.seq).toBe("number");
  });
});
