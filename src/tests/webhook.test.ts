import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import type { ToolDefinition } from "../tools.js";

const TOOL: ToolDefinition = {
  name: "test-tool",
  description: "A test tool",
  input_schema: { type: "object", properties: { query: { type: "string" } } },
  webhook_url: "https://example.com/webhook",
  timeout_ms: 5000,
};

const CONTEXT = {
  user_id: "u1",
  conversation_id: "c1",
  session_id: "s1",
  api_key_label: "test",
};

describe("executeWebhook", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("returns output on successful POST", async () => {
    const mockFetch = vi.mocked(fetch);
    mockFetch.mockResolvedValueOnce(
      new Response(JSON.stringify({ output: "result text", metadata: { score: 0.9 } }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    const { executeWebhook } = await import("../webhook.js");
    const result = await executeWebhook(TOOL, "tool-use-1", "test-tool", { query: "hello" }, CONTEXT);

    expect(result.output).toBe("result text");
    expect("isError" in result).toBe(false);
  });

  it("sends correct request payload", async () => {
    const mockFetch = vi.mocked(fetch);
    mockFetch.mockResolvedValueOnce(
      new Response(JSON.stringify({ output: "ok" }), { status: 200 }),
    );

    const { executeWebhook } = await import("../webhook.js");
    await executeWebhook(TOOL, "tool-use-42", "test-tool", { query: "test" }, CONTEXT);

    expect(mockFetch).toHaveBeenCalledOnce();
    const [url, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(TOOL.webhook_url);
    expect(init.method).toBe("POST");

    const body = JSON.parse(init.body as string);
    expect(body.tool_use_id).toBe("tool-use-42");
    expect(body.tool_name).toBe("test-tool");
    expect(body.input).toEqual({ query: "test" });
    expect(body.context.user_id).toBe("u1");
    expect(body.context.api_key_label).toBe("test");
  });

  it("returns isError on non-2xx response", async () => {
    const mockFetch = vi.mocked(fetch);
    mockFetch.mockResolvedValueOnce(
      new Response("Bad Request", { status: 400 }),
    );

    const { executeWebhook } = await import("../webhook.js");
    const result = await executeWebhook(TOOL, "tu1", "test-tool", {}, CONTEXT);

    expect("isError" in result && result.isError).toBe(true);
    expect(result.output).toMatch(/400/);
  });

  it("returns isError on network error", async () => {
    const mockFetch = vi.mocked(fetch);
    mockFetch.mockRejectedValueOnce(new Error("ECONNREFUSED"));

    const { executeWebhook } = await import("../webhook.js");
    const result = await executeWebhook(TOOL, "tu1", "test-tool", {}, CONTEXT);

    expect("isError" in result && result.isError).toBe(true);
    expect(result.output).toMatch(/Tool webhook failed: ECONNREFUSED/);
  });

  it("returns isError on timeout", async () => {
    const mockFetch = vi.mocked(fetch);
    const timeoutError = new Error("The operation was aborted due to timeout");
    timeoutError.name = "TimeoutError";
    mockFetch.mockRejectedValueOnce(timeoutError);

    const { executeWebhook } = await import("../webhook.js");
    const result = await executeWebhook(TOOL, "tu1", "test-tool", {}, CONTEXT);

    expect("isError" in result && result.isError).toBe(true);
    expect(result.output).toMatch(/timed out after 5000ms/);
  });

  it("uses default timeout of 30000ms when timeout_ms is not set", async () => {
    const mockFetch = vi.mocked(fetch);
    const timeoutError = new Error("timeout");
    timeoutError.name = "TimeoutError";
    mockFetch.mockRejectedValueOnce(timeoutError);

    const toolNoTimeout: ToolDefinition = { ...TOOL, timeout_ms: undefined };
    const { executeWebhook } = await import("../webhook.js");
    const result = await executeWebhook(toolNoTimeout, "tu1", "test-tool", {}, CONTEXT);

    expect(result.output).toMatch(/timed out after 30000ms/);
  });
});
