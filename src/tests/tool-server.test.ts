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
    expect(result.content[0].text).toBe('TOOL_UNAVAILABLE: "weather" could not be reached or failed. Try again later; if it keeps happening, tell your gateway administrator.');
  });

  it("creates separate servers per call (context isolation)", async () => {
    const { createToolMcpServer } = await import("../tool-server.js");

    const ctx1: WebhookContext = { user_id: "user-A" };
    const ctx2: WebhookContext = { user_id: "user-B" };

    const server1 = createToolMcpServer([TOOL], ctx1);
    const server2 = createToolMcpServer([TOOL], ctx2);

    expect(server1.instance).not.toBe(server2.instance);
  });

  it("tools/list advertises the registered property type and description (JSON-RPC, MVP-7697)", async () => {
    const { createToolMcpServer } = await import("../tool-server.js");
    const described: ToolDefinition = {
      ...TOOL,
      input_schema: { type: "object", properties: { city: { type: "string", description: "City name" } }, required: ["city"] },
    };
    const server = createToolMcpServer([described], CONTEXT);

    const responses = new Map<number, unknown>();
    const transport = {
      onmessage: undefined as ((message: unknown) => void) | undefined,
      async start() {},
      async close() {},
      async send(message: { id?: number; result?: unknown }) {
        if (message.id !== undefined) responses.set(message.id, message.result);
      },
    };
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await server.instance.connect(transport as any);
    transport.onmessage!({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } } });
    transport.onmessage!({ jsonrpc: "2.0", method: "notifications/initialized" });
    transport.onmessage!({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
    await vi.waitFor(() => expect(responses.has(2)).toBe(true));

    const [listed] = (responses.get(2) as { tools: { name: string; description: string; inputSchema: Record<string, unknown> }[] }).tools;
    expect(listed.name).toBe("weather");
    expect(listed.description).toBe("Get weather for a city");
    expect(listed.inputSchema.properties).toEqual({ city: { type: "string", description: "City name" } });
    expect(listed.inputSchema.required).toEqual(["city"]);
  });

  it("tools/list declares no result size limit: webhook tools keep the runtime default (MVP-8089)", async () => {
    const { createToolMcpServer } = await import("../tool-server.js");
    const server = createToolMcpServer([TOOL, { ...TOOL, name: "forecast" }], CONTEXT);

    const responses = new Map<number, unknown>();
    const transport = {
      onmessage: undefined as ((message: unknown) => void) | undefined,
      async start() {},
      async close() {},
      async send(message: { id?: number; result?: unknown }) {
        if (message.id !== undefined) responses.set(message.id, message.result);
      },
    };
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await server.instance.connect(transport as any);
    transport.onmessage!({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } } });
    transport.onmessage!({ jsonrpc: "2.0", method: "notifications/initialized" });
    transport.onmessage!({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
    await vi.waitFor(() => expect(responses.has(2)).toBe(true));

    const { tools } = responses.get(2) as { tools: { name: string; _meta?: Record<string, unknown> }[] };
    expect(tools.map((t) => t.name)).toEqual(["weather", "forecast"]);
    for (const tool of tools) expect(JSON.stringify(tool._meta ?? {}), tool.name).not.toContain("maxResultSizeChars");
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
