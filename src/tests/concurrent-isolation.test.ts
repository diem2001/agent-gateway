import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { McpServerDefinition } from "../mcp-registry.js";
import { RELAY_URL, postJsonRpc, startRecordingUpstream, type RecordingUpstream } from "./helpers/relay-upstream.js";

let sdkOptions: Array<Record<string, unknown>> = [];
let releaseQueries: Array<() => void> = [];
let upstream: RecordingUpstream | null = null;

beforeEach(async () => {
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
      url: `${upstream!.origin}/mcp`,
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
    const firstMcp = sdkOptions[0].mcpServers as Record<string, { url: string; headers?: Record<string, string> }>;
    const secondMcp = sdkOptions[1].mcpServers as Record<string, { url: string; headers?: Record<string, string> }>;
    expect(firstMcp.jira).toEqual({ type: "http", url: expect.stringMatching(RELAY_URL) });
    expect(secondMcp.jira).toEqual({ type: "http", url: expect.stringMatching(RELAY_URL) });

    // While both runs overlap, each relay URL carries its own run's override, in either order.
    expect(await postJsonRpc(secondMcp.jira.url)).toBe(200);
    expect(await postJsonRpc(firstMcp.jira.url)).toBe(200);
    expect(upstream!.headersAt("/mcp").map((h) => h.authorization)).toEqual(["Basic USER_B", "Basic USER_A"]);

    releaseQueries.forEach((release) => release());
    await Promise.all([first, second]);

    // Both runs ended: their relay URLs are revoked.
    expect(await postJsonRpc(firstMcp.jira.url)).toBe(404);
    expect(await postJsonRpc(secondMcp.jira.url)).toBe(404);
    expect(JSON.stringify(getEnabledMcpServers())).toBe(before);
  });
});
