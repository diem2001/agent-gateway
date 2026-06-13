/**
 * MVP-5677: MCP image content blocks on tool_result messages are forwarded as
 * an optional `images[]` field ({data, mimeType}) on the NDJSON tool_result
 * event, so per-run MCP screenshots (e.g. chrome-devtools-mcp) can reach the
 * caller. The text path is unchanged (3000-char truncation stays). Bounds:
 * max 5 images per event, max 15 MB decoded per image (dropped + warn).
 */
import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Content yielded by the mocked SDK as the tool_result block's content.
let toolResultContent: unknown = [];

beforeEach(() => {
  vi.resetModules();
  vi.doMock("@anthropic-ai/claude-agent-sdk", () => ({
    createSdkMcpServer: vi.fn((options) => ({ type: "sdk", name: options.name })),
    query: vi.fn(() => {
      return (async function* () {
        yield { type: "assistant", message: { content: [{ type: "text", text: "taking screenshot" }] } };
        yield {
          type: "user",
          tool_use_result: {},
          message: {
            role: "user",
            content: [
              { type: "tool_result", tool_use_id: "tu_img", content: toolResultContent },
            ],
          },
        };
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
  app.use(express.json());
  app.use(queryRouter);
  return app;
}

function parseNdjson(text: string): Array<Record<string, unknown>> {
  return text
    .split("\n")
    .filter((line) => line.trim().length > 0)
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}

async function runAndGetToolResult(): Promise<Record<string, unknown>> {
  const app = await createApp();
  const res = await request(app)
    .post("/v1/query")
    .send({ queryId: "q-img", prompt: "screenshot please", useSession: false });
  expect(res.status).toBe(200);
  const events = parseNdjson(res.text);
  const toolResult = events.find((e) => e.type === "tool_result");
  expect(toolResult).toBeDefined();
  return toolResult as Record<string, unknown>;
}

describe("tool_result image forwarding (NDJSON images[])", () => {
  it("forwards an Anthropic-shaped image block alongside the text output", async () => {
    toolResultContent = [
      { type: "text", text: "Screenshot captured" },
      { type: "image", source: { type: "base64", media_type: "image/png", data: "iVBORw0KGgo=" } },
    ];

    const toolResult = await runAndGetToolResult();
    expect(toolResult.output).toBe("Screenshot captured");
    expect(toolResult.images).toEqual([{ data: "iVBORw0KGgo=", mimeType: "image/png" }]);
  });

  it("forwards an MCP-shaped image block ({data, mimeType})", async () => {
    toolResultContent = [{ type: "image", data: "AAAA", mimeType: "image/jpeg" }];

    const toolResult = await runAndGetToolResult();
    expect(toolResult.images).toEqual([{ data: "AAAA", mimeType: "image/jpeg" }]);
  });

  it("omits the images field entirely for text-only tool results (path unchanged)", async () => {
    toolResultContent = [{ type: "text", text: "plain output" }];

    const toolResult = await runAndGetToolResult();
    expect(toolResult.output).toBe("plain output");
    expect("images" in toolResult).toBe(false);
  });

  it("keeps the 3000-char text truncation when images are present", async () => {
    toolResultContent = [
      { type: "text", text: "x".repeat(4000) },
      { type: "image", data: "AAAA", mimeType: "image/png" },
    ];

    const toolResult = await runAndGetToolResult();
    const output = toolResult.output as string;
    expect(output.length).toBeLessThan(4000);
    expect(output.endsWith("... (truncated)")).toBe(true);
    expect(toolResult.images).toHaveLength(1);
  });

  it("forwards at most 5 images per tool_result (excess dropped)", async () => {
    toolResultContent = Array.from({ length: 7 }, (_, i) => ({
      type: "image",
      data: `IMG${i}`,
      mimeType: "image/png",
    }));

    const toolResult = await runAndGetToolResult();
    const images = toolResult.images as Array<{ data: string }>;
    expect(images).toHaveLength(5);
    expect(images.map((i) => i.data)).toEqual(["IMG0", "IMG1", "IMG2", "IMG3", "IMG4"]);
  });
});

describe("extractToolResultImages (unit)", () => {
  it("drops images whose decoded size exceeds 15 MB but keeps smaller siblings", async () => {
    const { extractToolResultImages } = await import("../agent.js");
    // 15 MB decoded ≈ 20 MB base64 chars; exceed it.
    const oversize = "a".repeat(21 * 1024 * 1024);
    const images = extractToolResultImages(
      [
        { type: "image", data: oversize, mimeType: "image/png" },
        { type: "image", data: "small", mimeType: "image/png" },
      ],
      "tu_x",
    );
    expect(images).toEqual([{ data: "small", mimeType: "image/png" }]);
  });

  it("ignores malformed image blocks (missing data or mimeType) and non-arrays", async () => {
    const { extractToolResultImages } = await import("../agent.js");
    expect(extractToolResultImages("not an array", "tu_x")).toEqual([]);
    expect(
      extractToolResultImages(
        [
          { type: "image" },
          { type: "image", data: "", mimeType: "image/png" },
          { type: "image", data: "ok", mimeType: 42 },
          { type: "image", source: { type: "url", url: "http://x" } },
          null,
        ],
        "tu_x",
      ),
    ).toEqual([]);
  });
});
