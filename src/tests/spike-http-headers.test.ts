import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { McpServerDefinition } from "../mcp-registry.js";
import { RELAY_URL, startRecordingUpstream, touchHttpMcpServers, type RecordingUpstream } from "./helpers/relay-upstream.js";

let sdkOptions: Array<Record<string, unknown>> = [];
let relayStatuses: Array<Record<string, number>> = [];
let upstream: RecordingUpstream | null = null;

beforeEach(async () => {
  vi.resetModules();
  sdkOptions = [];
  relayStatuses = [];
  vi.doMock("@anthropic-ai/claude-agent-sdk", () => ({
    createSdkMcpServer: vi.fn((options) => ({ type: "sdk", name: options.name })),
    query: vi.fn(({ options }) => {
      sdkOptions.push(options as Record<string, unknown>);
      return (async function* () {
        // The runtime's part: use each server while this run's relay token is valid.
        relayStatuses.push(await touchHttpMcpServers(options as Record<string, unknown>));
        yield { type: "result", usage: {}, total_cost_usd: 0, sessionId: "sdk-session" };
      })();
    }),
  }));
  upstream = await startRecordingUpstream();
  const { credentialRelay } = await import("../mcp-credential-relay.js");
  await credentialRelay.start();
});

afterEach(async () => {
  const { credentialRelay } = await import("../mcp-credential-relay.js");
  await credentialRelay.close();
  await upstream?.close();
  upstream = null;
  vi.doUnmock("@anthropic-ai/claude-agent-sdk");
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
      url: `${upstream!.origin}/mcp`,
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

    // The runtime sees only a per-run relay URL, never the header.
    const firstMcp = sdkOptions[0].mcpServers as Record<string, { url: string; headers?: Record<string, string> }>;
    const secondMcp = sdkOptions[1].mcpServers as Record<string, { url: string; headers?: Record<string, string> }>;
    expect(firstMcp.jira).toEqual({ type: "http", url: expect.stringMatching(RELAY_URL) });
    expect(secondMcp.jira).toEqual({ type: "http", url: expect.stringMatching(RELAY_URL) });
    expect(firstMcp.jira.url).not.toBe(secondMcp.jira.url);
    // Each run's override reaches the MCP server through the relay.
    expect(relayStatuses).toEqual([{ jira: 200 }, { jira: 200 }]);
    expect(upstream!.headersAt("/mcp").map((h) => h.authorization)).toEqual(["Basic USER_A", "Basic USER_B"]);
  });
});
