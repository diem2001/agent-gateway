import { beforeEach, describe, expect, it, vi } from "vitest";
import type { McpServerDefinition } from "../mcp-registry.js";

let sdkOptions: Array<Record<string, unknown>> = [];

beforeEach(() => {
  vi.resetModules();
  sdkOptions = [];
  vi.doMock("@anthropic-ai/claude-agent-sdk", () => ({
    createSdkMcpServer: vi.fn((options) => ({ type: "sdk", name: options.name })),
    query: vi.fn(({ options }) => {
      sdkOptions.push(options as Record<string, unknown>);
      return (async function* () {
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

describe("HTTP header override spike", () => {
  it("transmits different per-request Authorization overrides for the same HTTP server", async () => {
    await registerServer({
      name: "jira",
      type: "http",
      url: "http://127.0.0.1:3002/mcp",
      headers: { Authorization: "Basic STATIC" },
    });
    const { runQuery } = await import("../agent.js");

    await runQuery({
      prompt: "first",
      abortController: new AbortController(),
      onEvent: () => undefined,
      mcpCredentialOverrides: { jira: { headers: { Authorization: "Basic USER_A" } } },
    });
    await runQuery({
      prompt: "second",
      abortController: new AbortController(),
      onEvent: () => undefined,
      mcpCredentialOverrides: { jira: { headers: { Authorization: "Basic USER_B" } } },
    });

    const firstMcp = sdkOptions[0].mcpServers as Record<string, { headers: Record<string, string> }>;
    const secondMcp = sdkOptions[1].mcpServers as Record<string, { headers: Record<string, string> }>;
    expect(firstMcp.jira.headers.Authorization).toBe("Basic USER_A");
    expect(secondMcp.jira.headers.Authorization).toBe("Basic USER_B");
  });
});
