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
    expect(body).toEqual({ query: "test" });

    const headers = init.headers as Record<string, string>;
    expect(headers["X-Webhook-Tool-Use-Id"]).toBe("tool-use-42");
    expect(headers["X-Webhook-Tool-Name"]).toBe("test-tool");
    expect(JSON.parse(headers["X-Webhook-Context"])).toMatchObject({
      user_id: "u1",
      api_key_label: "test",
    });
  });

  it("a tool's own 4xx refusal reaches the model with its message, wrapped with the status", async () => {
    const mockFetch = vi.mocked(fetch);
    mockFetch.mockResolvedValueOnce(new Response("Bad Request", { status: 400, headers: { "Content-Type": "text/plain; charset=utf-8" } }));

    const { executeWebhook } = await import("../webhook.js");
    const result = await executeWebhook(TOOL, "tu1", "test-tool", {}, CONTEXT);

    expect(result).toEqual({ output: "The tool rejected the request (HTTP 400): Bad Request", isError: true });
  });

  it.each([
    ["reqlift's {error:{code,message}} body", JSON.stringify({ error: { code: "bad_input", message: "Draft title is required." } }), "application/json", "Draft title is required."],
    ["a string `error`", JSON.stringify({ error: "Project not found" }), "application/json", "Project not found"],
    ["a `message` field", JSON.stringify({ message: "Quota exceeded for this project" }), "application/json", "Quota exceeded for this project"],
    ["error.message wins over error and message", JSON.stringify({ error: { message: "first" }, message: "third" }), "application/json", "first"],
    ["a plain-text Axum rejection", "Failed to deserialize the JSON body into the target type", "text/plain; charset=utf-8", "Failed to deserialize the JSON body into the target type"],
  ])("message extraction: %s", async (_label, body, contentType, expected) => {
    vi.mocked(fetch).mockResolvedValueOnce(new Response(body, { status: 422, headers: { "Content-Type": contentType } }));
    const { executeWebhook } = await import("../webhook.js");
    const result = await executeWebhook(TOOL, "tu1", "test-tool", {}, CONTEXT);
    expect(result).toEqual({ output: `The tool rejected the request (HTTP 422): ${expected}`, isError: true });
  });

  it("an HTML or unknown body is not echoed", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(new Response("<html><body>proxy error SECRET-PAGE</body></html>", { status: 400, headers: { "Content-Type": "text/html" } }));
    const { executeWebhook } = await import("../webhook.js");
    const result = await executeWebhook(TOOL, "tu1", "test-tool", {}, CONTEXT);
    expect(result).toEqual({ output: "The tool rejected the request (HTTP 400).", isError: true });
  });

  it("a refusal message is at most 500 characters, without control characters, with known secret values masked", async () => {
    const secret = "SYNTH-GATEWAY-KEY-7679";
    const bearer = "SYNTH-FORWARDED-BEARER-7679";
    const body = JSON.stringify({ error: { message: `line1\u0000\nline2 ${secret} and ${bearer} ${"x".repeat(900)}` } });
    vi.mocked(fetch).mockResolvedValueOnce(new Response(body, { status: 400, headers: { "Content-Type": "application/json" } }));
    const { executeWebhook } = await import("../webhook.js");
    const result = await executeWebhook(TOOL, "tu1", "test-tool", {}, CONTEXT, bearer, [secret]);
    const text = result.output;
    expect(text.startsWith("The tool rejected the request (HTTP 400): line1")).toBe(true);
    expect(text).toContain("[REDACTED] and [REDACTED]");
    expect(text).not.toContain(secret);
    expect(text).not.toContain(bearer);
    // eslint-disable-next-line no-control-regex
    expect(text).not.toMatch(/[\u0000-\u001f]/);
    expect(text.length).toBeLessThanOrEqual("The tool rejected the request (HTTP 400): ".length + 500);
  });

  it.each([
    [401, "TOOL_AUTH_UNAVAILABLE", `TOOL_AUTH_UNAVAILABLE: "test-tool" did not accept the gateway's credential. Ask your gateway administrator to check this tool's credential; retrying will not help.`],
    [403, "TOOL_AUTH_UNAVAILABLE", `TOOL_AUTH_UNAVAILABLE: "test-tool" did not accept the gateway's credential. Ask your gateway administrator to check this tool's credential; retrying will not help.`],
    [408, "TOOL_UNAVAILABLE", `TOOL_UNAVAILABLE: "test-tool" could not be reached or failed. Try again later; if it keeps happening, tell your gateway administrator.`],
    [429, "TOOL_UNAVAILABLE", `TOOL_UNAVAILABLE: "test-tool" could not be reached or failed. Try again later; if it keeps happening, tell your gateway administrator.`],
    [500, "TOOL_UNAVAILABLE", `TOOL_UNAVAILABLE: "test-tool" could not be reached or failed. Try again later; if it keeps happening, tell your gateway administrator.`],
    [503, "TOOL_UNAVAILABLE", `TOOL_UNAVAILABLE: "test-tool" could not be reached or failed. Try again later; if it keeps happening, tell your gateway administrator.`],
  ])("HTTP %i is %s with the fixed text and no upstream body", async (status, code, text) => {
    vi.mocked(fetch).mockResolvedValueOnce(new Response(JSON.stringify({ error: "UPSTREAM-BODY-SECRET Bearer abc" }), { status, headers: { "Content-Type": "application/json" } }));
    const { executeWebhook } = await import("../webhook.js");
    const result = await executeWebhook(TOOL, "tu1", "test-tool", {}, CONTEXT);
    expect(result).toEqual({ output: text, isError: true, code });
  });

  it("a redirect is refused without following it: one request, redirect: manual, the fixed text", async () => {
    const mockFetch = vi.mocked(fetch);
    mockFetch.mockResolvedValueOnce(new Response(null, { status: 302, headers: { Location: "https://attacker.example/collect" } }));
    const { executeWebhook } = await import("../webhook.js");
    const result = await executeWebhook(TOOL, "tu1", "test-tool", { q: "x" }, CONTEXT, "client-bearer");
    expect(mockFetch).toHaveBeenCalledOnce();
    expect((mockFetch.mock.calls[0][1] as RequestInit).redirect).toBe("manual");
    expect(result).toEqual({
      output: `TOOL_UNAVAILABLE: "test-tool" tried to send the request to another address, which the gateway does not allow. Tell your gateway administrator; retrying will not help.`,
      isError: true,
      code: "TOOL_UNAVAILABLE",
    });
    expect(result.output).not.toContain("attacker");
  });

  it("returns TOOL_UNAVAILABLE on a network error without the error text", async () => {
    vi.mocked(fetch).mockRejectedValueOnce(new Error("connect ECONNREFUSED 10.0.0.5:8443"));
    const { executeWebhook } = await import("../webhook.js");
    const result = await executeWebhook(TOOL, "tu1", "test-tool", {}, CONTEXT);
    expect(result).toEqual({
      output: `TOOL_UNAVAILABLE: "test-tool" could not be reached or failed. Try again later; if it keeps happening, tell your gateway administrator.`,
      isError: true,
      code: "TOOL_UNAVAILABLE",
    });
  });

  it("returns TOOL_TIMEOUT with the configured seconds", async () => {
    const timeoutError = new Error("The operation was aborted due to timeout");
    timeoutError.name = "TimeoutError";
    vi.mocked(fetch).mockRejectedValueOnce(timeoutError);
    const { executeWebhook } = await import("../webhook.js");
    const result = await executeWebhook(TOOL, "tu1", "test-tool", {}, CONTEXT);
    expect(result).toEqual({
      output: `TOOL_TIMEOUT: "test-tool" did not answer within 5 seconds. Try again later or with a smaller request; if it keeps happening, tell your gateway administrator.`,
      isError: true,
      code: "TOOL_TIMEOUT",
    });
  });

  it("uses default timeout of 30000ms when timeout_ms is not set (30 seconds in the text)", async () => {
    const timeoutError = new Error("timeout");
    timeoutError.name = "TimeoutError";
    vi.mocked(fetch).mockRejectedValueOnce(timeoutError);
    const toolNoTimeout: ToolDefinition = { ...TOOL, timeout_ms: undefined };
    const { executeWebhook } = await import("../webhook.js");
    const result = await executeWebhook(toolNoTimeout, "tu1", "test-tool", {}, CONTEXT);
    expect(result.output).toContain("did not answer within 30 seconds");
  });

  it("rounds a sub-second timeout up to 1 second", async () => {
    const timeoutError = new Error("timeout");
    timeoutError.name = "TimeoutError";
    vi.mocked(fetch).mockRejectedValueOnce(timeoutError);
    const { executeWebhook } = await import("../webhook.js");
    const result = await executeWebhook({ ...TOOL, timeout_ms: 200 }, "tu1", "test-tool", {}, CONTEXT);
    expect(result.output).toContain("did not answer within 1 seconds");
  });

  it.each([
    ["a body that is not JSON", "<html>ok</html>"],
    ["an empty body", ""],
    ["a body over the size cap", `{"output":"${"x".repeat(9 * 1024 * 1024)}"}`],
  ])("a 2xx answer that cannot be read is TOOL_RESPONSE_INVALID: %s", async (_label, body) => {
    vi.mocked(fetch).mockResolvedValueOnce(new Response(body, { status: 200 }));
    const { executeWebhook } = await import("../webhook.js");
    const result = await executeWebhook(TOOL, "tu1", "test-tool", {}, CONTEXT);
    expect(result).toEqual({
      output: `TOOL_RESPONSE_INVALID: "test-tool" sent an answer the gateway could not read. If it keeps happening, tell your gateway administrator.`,
      isError: true,
      code: "TOOL_RESPONSE_INVALID",
    });
  });

  it("a successful answer that is not {output} is returned as its JSON text, unmasked", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(new Response(JSON.stringify({ rows: [1, 2] }), { status: 200 }));
    const { executeWebhook } = await import("../webhook.js");
    const result = await executeWebhook(TOOL, "tu1", "test-tool", {}, CONTEXT);
    expect(result).toEqual({ output: '{"rows":[1,2]}' });
  });

  it("the bearer is forwarded only when given, and the input keys `context` and `user_id` stay in the body", async () => {
    const mockFetch = vi.mocked(fetch);
    mockFetch.mockResolvedValue(new Response(JSON.stringify({ output: "ok" }), { status: 200 }));
    const { executeWebhook } = await import("../webhook.js");
    await executeWebhook(TOOL, "tu1", "test-tool", { context: { user_id: "attacker" }, user_id: "attacker", api_key_label: "other" }, CONTEXT, "client-bearer");
    await executeWebhook(TOOL, "tu2", "test-tool", {}, CONTEXT);
    const [, first] = mockFetch.mock.calls[0] as [string, RequestInit];
    const [, second] = mockFetch.mock.calls[1] as [string, RequestInit];
    expect((first.headers as Record<string, string>).Authorization).toBe("Bearer client-bearer");
    expect((second.headers as Record<string, string>).Authorization).toBeUndefined();
    // The context header comes only from the authenticated request; agent-supplied keys are plain body fields.
    expect(JSON.parse((first.headers as Record<string, string>)["X-Webhook-Context"])).toEqual(CONTEXT);
    expect(JSON.parse(first.body as string)).toEqual({ context: { user_id: "attacker" }, user_id: "attacker", api_key_label: "other" });
  });
});
