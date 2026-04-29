import { beforeEach, describe, expect, it, vi } from "vitest";
import type { McpServerDefinition } from "../mcp-registry.js";

let sdkOptions: Array<Record<string, unknown>> = [];
let releaseQueries: Array<() => void> = [];

beforeEach(() => {
  vi.resetModules();
  sdkOptions = [];
  releaseQueries = [];
  vi.doMock("@anthropic-ai/claude-agent-sdk", () => ({
    createSdkMcpServer: vi.fn((options) => ({ type: "sdk", name: options.name })),
    query: vi.fn(({ options }) => {
      sdkOptions.push(options as Record<string, unknown>);
      return (async function* () {
        await new Promise<void>((resolve) => releaseQueries.push(resolve));
        yield { type: "result", usage: {}, total_cost_usd: 0, sessionId: "sdk-session" };
      })();
    }),
  }));
});

async function registerServer(def: Partial<McpServerDefinition> & Pick<McpServerDefinition, "name" | "type">) {
  const { registerMcpServer } = await import("../mcp-registry.js");
  const now = new Date().toISOString();
  registerMcpServer({
    description: "",
    enabled: true,
    createdAt: now,
    updatedAt: now,
    ...def,
  } as McpServerDefinition);
}

async function waitForSdkCalls(count: number) {
  const started = Date.now();
  while (sdkOptions.length < count && Date.now() - started < 1000) {
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

describe("request-scoped MCP override isolation", () => {
  it("keeps overlapping same-server HTTP Authorization overrides isolated and leaves registry state unchanged", async () => {
    await registerServer({
      name: "jira",
      type: "http",
      url: "http://127.0.0.1:3002/mcp",
      headers: { Authorization: "Basic STATIC" },
    });
    const { runQuery } = await import("../agent.js");
    const { getEnabledMcpServers } = await import("../mcp-registry.js");
    const before = JSON.stringify(getEnabledMcpServers());

    const first = runQuery({
      prompt: "first",
      abortController: new AbortController(),
      onEvent: () => undefined,
      mcpCredentialOverrides: { jira: { headers: { Authorization: "Basic USER_A" } } },
    });
    const second = runQuery({
      prompt: "second",
      abortController: new AbortController(),
      onEvent: () => undefined,
      mcpCredentialOverrides: { jira: { headers: { Authorization: "Basic USER_B" } } },
    });

    await waitForSdkCalls(2);
    expect(sdkOptions).toHaveLength(2);
    releaseQueries.forEach((release) => release());
    await Promise.all([first, second]);

    const firstMcp = sdkOptions[0].mcpServers as Record<string, { headers: Record<string, string> }>;
    const secondMcp = sdkOptions[1].mcpServers as Record<string, { headers: Record<string, string> }>;
    expect(firstMcp.jira.headers.Authorization).toBe("Basic USER_A");
    expect(secondMcp.jira.headers.Authorization).toBe("Basic USER_B");
    expect(JSON.stringify(getEnabledMcpServers())).toBe(before);
  });
});
