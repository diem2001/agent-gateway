/**
 * Outcome Probe for MVP-3138 (Observable-Outcome AC):
 *
 *   "A gateway client sends text+image content and the AI receives a properly
 *    structured APIUserMessage with content blocks; existing text-only queries
 *    continue unchanged."
 *
 * This test exercises the REAL query.ts + agent.ts + retry.ts path end-to-end,
 * mocking ONLY the Claude Agent SDK boundary (`query()`) so we can observe the
 * exact `prompt` argument the SDK receives and confirm the NDJSON stream emits a
 * `done` event identically for both text-only and multimodal queries.
 */
import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ContentBlock } from "../query.js";

// Captures the `prompt` argument passed to the mocked SDK query() per invocation.
let capturedPrompts: unknown[] = [];

beforeEach(() => {
  vi.resetModules();
  capturedPrompts = [];
  vi.doMock("@anthropic-ai/claude-agent-sdk", () => ({
    createSdkMcpServer: vi.fn((options) => ({ type: "sdk", name: options.name })),
    query: vi.fn(({ prompt }) => {
      capturedPrompts.push(prompt);
      return (async function* () {
        // Emit a non-empty assistant message so retry's "empty response" guard
        // does not re-run the query, then a result so `done` is emitted.
        yield { type: "assistant", message: { content: [{ type: "text", text: "ack" }] } };
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

describe("Outcome Probe — multimodal content reaches the SDK as a structured user message", () => {
  it("(a) text-only query: SDK receives a string prompt and the NDJSON 'done' event is emitted", async () => {
    const app = await createApp();

    const res = await request(app)
      .post("/v1/query")
      .send({ queryId: "probe-text", prompt: "hello there", useSession: false });

    expect(res.status).toBe(200);
    const events = parseNdjson(res.text);
    expect(events.some((e) => e.type === "done")).toBe(true);

    // Backward compat: the SDK receives the original string prompt, not an iterable.
    expect(capturedPrompts).toHaveLength(1);
    expect(typeof capturedPrompts[0]).toBe("string");
    expect(capturedPrompts[0]).toBe("hello there");
  });

  it("(b) multimodal query: SDK receives an AsyncIterable yielding one SDKUserMessage with the unmodified image block, and 'done' is emitted identically", async () => {
    const app = await createApp();
    const content: ContentBlock[] = [
      { type: "text", text: "describe this image" },
      {
        type: "image",
        source: { type: "base64", media_type: "image/jpeg", data: "/9j/4AAQSkZJR0=" },
      },
    ];

    const res = await request(app)
      .post("/v1/query")
      .send({ queryId: "probe-multimodal", content, useSession: false });

    expect(res.status).toBe(200);
    const events = parseNdjson(res.text);
    // The NDJSON stream emits a `done` event identically to the text-only case.
    expect(events.some((e) => e.type === "done")).toBe(true);

    // The SDK receives an AsyncIterable (not a string) for multimodal input.
    expect(capturedPrompts).toHaveLength(1);
    const promptArg = capturedPrompts[0] as AsyncIterable<{
      type: string;
      session_id: string;
      parent_tool_use_id: null;
      message: { role: string; content: ContentBlock[] };
    }>;
    expect(typeof promptArg).not.toBe("string");
    expect(typeof (promptArg as { [Symbol.asyncIterator]?: unknown })[Symbol.asyncIterator]).toBe(
      "function",
    );

    // Drain the iterable and assert the structured SDKUserMessage.
    const yielded: Array<{
      type: string;
      message: { role: string; content: ContentBlock[] };
    }> = [];
    for await (const msg of promptArg) yielded.push(msg);

    expect(yielded).toHaveLength(1);
    expect(yielded[0].type).toBe("user");
    expect(yielded[0].message.role).toBe("user");
    expect(yielded[0].message.content).toEqual(content);

    // The image block is passed through to the SDK WITHOUT modification (AC).
    expect(yielded[0].message.content[1]).toEqual({
      type: "image",
      source: { type: "base64", media_type: "image/jpeg", data: "/9j/4AAQSkZJR0=" },
    });
  });
});
