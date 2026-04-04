import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import type { ToolDefinition } from "../tools.js";
import type { WebhookContext } from "../webhook.js";

const TOOL: ToolDefinition = {
  name: "weather",
  description: "Get weather for a city",
  input_schema: { type: "object", properties: { city: { type: "string" } } },
  webhook_url: "https://example.com/weather",
  timeout_ms: 10000,
};

const CONTEXT: WebhookContext = {
  user_id: "u42",
  conversation_id: "conv1",
  session_id: "sess1",
  api_key_label: "mykey",
};

describe("createToolMcpServer", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("creates an MCP server with type 'sdk'", async () => {
    const { createToolMcpServer } = await import("../tool-server.js");
    const server = createToolMcpServer([TOOL], CONTEXT);

    expect(server.type).toBe("sdk");
    expect(server.name).toBe("agent-gateway-tools");
    expect(server.instance).toBeDefined();
  });

  it("creates an MCP server with a live instance", async () => {
    const { createToolMcpServer } = await import("../tool-server.js");
    const server = createToolMcpServer([TOOL], CONTEXT);

    // McpServer instance should have a connect method
    expect(typeof server.instance.connect).toBe("function");
  });

  it("tool handler calls executeWebhook and returns output", async () => {
    const mockFetch = vi.mocked(fetch);
    mockFetch.mockResolvedValueOnce(
      new Response(JSON.stringify({ output: "Sunny, 25°C" }), { status: 200 }),
    );

    const { createToolMcpServer } = await import("../tool-server.js");
    const server = createToolMcpServer([TOOL], CONTEXT);

    // _registeredTools is a plain Record<string, RegisteredTool> in @modelcontextprotocol/sdk
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const registeredTools = (server.instance as any)._registeredTools as Record<string, any>;
    expect(registeredTools).toBeDefined();

    const weatherTool = registeredTools["weather"];
    expect(weatherTool).toBeDefined();

    const result = await weatherTool.handler({ city: "Berlin" }, { requestId: "req-1" });
    expect(result.content[0].text).toBe("Sunny, 25°C");
    expect(result.isError).toBeFalsy();
  });

  it("tool handler returns isError on webhook failure", async () => {
    const mockFetch = vi.mocked(fetch);
    mockFetch.mockRejectedValueOnce(new Error("ECONNREFUSED"));

    const { createToolMcpServer } = await import("../tool-server.js");
    const server = createToolMcpServer([TOOL], CONTEXT);

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const registeredTools = (server.instance as any)._registeredTools as Record<string, any>;
    const weatherTool = registeredTools["weather"];

    const result = await weatherTool.handler({ city: "Berlin" }, { requestId: "req-2" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/Tool webhook failed/);
  });

  it("creates separate servers per call (context isolation)", async () => {
    const { createToolMcpServer } = await import("../tool-server.js");

    const ctx1: WebhookContext = { user_id: "user-A" };
    const ctx2: WebhookContext = { user_id: "user-B" };

    const server1 = createToolMcpServer([TOOL], ctx1);
    const server2 = createToolMcpServer([TOOL], ctx2);

    expect(server1.instance).not.toBe(server2.instance);
  });

  it("returns empty tool list server when no tools provided", async () => {
    const { createToolMcpServer } = await import("../tool-server.js");
    const server = createToolMcpServer([], CONTEXT);

    expect(server.type).toBe("sdk");
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const registeredTools = (server.instance as any)._registeredTools as Record<string, unknown>;
    expect(Object.keys(registeredTools).length).toBe(0);
  });
});
