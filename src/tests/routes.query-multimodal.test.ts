import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ContentBlock } from "../query.js";

let runQueryWithRetryMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  vi.resetModules();
  runQueryWithRetryMock = vi.fn().mockResolvedValue({
    response: "ok",
    resultData: { usage: {}, total_cost_usd: 0, sessionId: "sdk-session" },
  });
  vi.doMock("../retry.js", () => ({ runQueryWithRetry: runQueryWithRetryMock }));
});

afterEach(() => {
  vi.doUnmock("../retry.js");
});

async function createApp() {
  const { queryRouter } = await import("../query.js");
  const app = express();
  app.use(express.json({ limit: "25mb" }));
  app.use(queryRouter);
  // Minimal global error handler mirroring server.ts so over-limit / bad-body
  // requests surface the body-parser client status instead of a generic 500.
  app.use(
    (
      err: Error & { status?: number; statusCode?: number; type?: string },
      _req: express.Request,
      res: express.Response,
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      _next: express.NextFunction,
    ) => {
      const status = err.status || err.statusCode;
      if (typeof status === "number" && status >= 400 && status < 500) {
        res.status(status).json({
          error: err.type === "entity.too.large" ? "Request body too large" : "Bad request",
        });
        return;
      }
      res.status(500).json({ error: "Internal server error" });
    },
  );
  return app;
}

describe("POST /v1/query multimodal content", () => {
  it("(1) backward compat: text-only prompt is wrapped as a single text block and forwarded", async () => {
    const app = await createApp();

    const res = await request(app)
      .post("/v1/query")
      .send({ queryId: "q-text", prompt: "hello world" });

    expect(res.status).toBe(200);
    expect(runQueryWithRetryMock).toHaveBeenCalledOnce();
    const params = runQueryWithRetryMock.mock.calls[0][0];
    expect(params.prompt).toBe("hello world");
    expect(params.content).toEqual([{ type: "text", text: "hello world" }]);
  });

  it("(2) content array with a text block is forwarded verbatim", async () => {
    const app = await createApp();
    const content: ContentBlock[] = [{ type: "text", text: "analyze this" }];

    const res = await request(app)
      .post("/v1/query")
      .send({ queryId: "q-content-text", content });

    expect(res.status).toBe(200);
    const params = runQueryWithRetryMock.mock.calls[0][0];
    expect(params.content).toEqual(content);
  });

  it("(3) content array with image + text is forwarded with base64 source intact and unmodified", async () => {
    const app = await createApp();
    const content: ContentBlock[] = [
      { type: "text", text: "what is in this image?" },
      {
        type: "image",
        source: { type: "base64", media_type: "image/png", data: "aGVsbG8=" },
      },
    ];

    const res = await request(app)
      .post("/v1/query")
      .send({ queryId: "q-multimodal", content });

    expect(res.status).toBe(200);
    const params = runQueryWithRetryMock.mock.calls[0][0];
    expect(params.content).toEqual(content);
    // Image source must be passed through without modification.
    expect(params.content[1].source).toEqual({
      type: "base64",
      media_type: "image/png",
      data: "aGVsbG8=",
    });
  });

  it("(4) precedence: content present + prompt present → content wins", async () => {
    const app = await createApp();
    const content: ContentBlock[] = [{ type: "text", text: "from content" }];

    const res = await request(app)
      .post("/v1/query")
      .send({ queryId: "q-precedence", prompt: "from prompt", content });

    expect(res.status).toBe(200);
    const params = runQueryWithRetryMock.mock.calls[0][0];
    expect(params.content).toEqual(content);
    expect(params.content).not.toEqual([{ type: "text", text: "from prompt" }]);
  });

  it("(5) neither content nor prompt → 400 and no SDK call", async () => {
    const app = await createApp();

    const res = await request(app).post("/v1/query").send({ queryId: "q-empty" });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe("queryId and prompt or content are required");
    expect(runQueryWithRetryMock).not.toHaveBeenCalled();
  });

  it("(5b) empty content array falls back to missing-input 400 when no prompt", async () => {
    const app = await createApp();

    const res = await request(app)
      .post("/v1/query")
      .send({ queryId: "q-empty-arr", content: [] });

    expect(res.status).toBe(400);
    expect(runQueryWithRetryMock).not.toHaveBeenCalled();
  });

  it("(6) malformed image block (wrong source.type) → 400 and no SDK call", async () => {
    const app = await createApp();

    const res = await request(app)
      .post("/v1/query")
      .send({
        queryId: "q-bad-image",
        content: [
          { type: "image", source: { type: "url", media_type: "image/png", data: "x" } },
        ],
      });

    expect(res.status).toBe(400);
    expect(runQueryWithRetryMock).not.toHaveBeenCalled();
  });

  it("(6b) malformed image block (missing source.data) → 400 and no SDK call", async () => {
    const app = await createApp();

    const res = await request(app)
      .post("/v1/query")
      .send({
        queryId: "q-bad-image-2",
        content: [{ type: "image", source: { type: "base64", media_type: "image/png" } }],
      });

    expect(res.status).toBe(400);
    expect(runQueryWithRetryMock).not.toHaveBeenCalled();
  });

  it("(6c) unknown block type → 400", async () => {
    const app = await createApp();

    const res = await request(app)
      .post("/v1/query")
      .send({ queryId: "q-bad-type", content: [{ type: "video", url: "x" }] });

    expect(res.status).toBe(400);
    expect(runQueryWithRetryMock).not.toHaveBeenCalled();
  });

  it("(7) 25MB boundary: a body just over the JSON limit is rejected with 413", async () => {
    const app = await createApp();
    // Build a JSON body that exceeds 25MB of base64 image data.
    const oversized = "A".repeat(26 * 1024 * 1024);
    const body = JSON.stringify({
      queryId: "q-oversized",
      content: [
        { type: "image", source: { type: "base64", media_type: "image/png", data: oversized } },
      ],
    });

    const res = await request(app)
      .post("/v1/query")
      .set("Content-Type", "application/json")
      .send(body);

    expect(res.status).toBe(413);
    expect(runQueryWithRetryMock).not.toHaveBeenCalled();
  });

  it("(7b) at-limit body under 25MB is accepted (200)", async () => {
    const app = await createApp();
    // ~20MB of base64 data — comfortably under the 25MB limit.
    const sized = "A".repeat(20 * 1024 * 1024);
    const body = JSON.stringify({
      queryId: "q-at-limit",
      content: [
        { type: "image", source: { type: "base64", media_type: "image/png", data: sized } },
      ],
    });

    const res = await request(app)
      .post("/v1/query")
      .set("Content-Type", "application/json")
      .send(body);

    expect(res.status).toBe(200);
    expect(runQueryWithRetryMock).toHaveBeenCalledOnce();
  });
});

describe("agent.ts retry-replay: SDKUserMessage iterable is rebuilt per runQuery call", () => {
  it("(8) constructs a FRESH consumable content stream on each runQuery invocation", async () => {
    vi.resetModules();
    const capturedPrompts: unknown[] = [];
    vi.doMock("@anthropic-ai/claude-agent-sdk", () => ({
      createSdkMcpServer: vi.fn((options) => ({ type: "sdk", name: options.name })),
      query: vi.fn(({ prompt }) => {
        capturedPrompts.push(prompt);
        return (async function* () {
          yield { type: "result", usage: {}, total_cost_usd: 0, sessionId: "sdk-session" };
        })();
      }),
    }));

    const { runQuery } = await import("../agent.js");
    const content: ContentBlock[] = [
      { type: "text", text: "hi" },
      { type: "image", source: { type: "base64", media_type: "image/png", data: "aGVsbG8=" } },
    ];

    // Simulate the retry path: runQuery is called twice with the same content array.
    await runQuery({
      content,
      abortController: new AbortController(),
      onEvent: () => undefined,
    });
    await runQuery({
      content,
      isResume: true,
      abortController: new AbortController(),
      onEvent: () => undefined,
    });

    expect(capturedPrompts).toHaveLength(2);

    // Each call must produce a DIFFERENT (fresh) AsyncIterable instance.
    expect(capturedPrompts[0]).not.toBe(capturedPrompts[1]);

    // Both iterables must independently yield the unmodified content blocks,
    // proving neither was consumed/reused across attempts.
    for (const promptArg of capturedPrompts) {
      const iterable = promptArg as AsyncIterable<{
        type: string;
        message: { role: string; content: ContentBlock[] };
      }>;
      const yielded: Array<{ message: { content: ContentBlock[] } }> = [];
      for await (const msg of iterable) yielded.push(msg);
      expect(yielded).toHaveLength(1);
      expect(yielded[0].message.content).toEqual(content);
      // Image block passed through without modification.
      expect(yielded[0].message.content[1]).toEqual(content[1]);
    }

    vi.doUnmock("@anthropic-ai/claude-agent-sdk");
  });
});
