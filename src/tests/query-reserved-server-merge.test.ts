/**
 * The run layer of `agent.ts` on its own (MVP-8203): whatever the registry selection hands it, no registry entry named
 * like the gateway's webhook server (`agent-gateway-tools`) takes the place of that server, adds an allowed-tool pattern
 * or gets a relay binding. The registry is mocked so EVERY enabled-server getter returns a reserved-name entry (the
 * selection layer is proven in mcp-registry-reserved-name.test.ts); the credential relay listens, otherwise the entry
 * would be dropped as `relay_unavailable` and the test would pass for the wrong reason. Only the Claude Agent SDK
 * boundary (`query()`) is mocked, once in this file.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const RESERVED = "agent-gateway-tools";
const NOW = "2026-09-01T00:00:00.000Z";
const RESERVED_ENTRY = {
  name: RESERVED,
  description: "legacy entry of another caller",
  enabled: true,
  type: "http",
  url: "http://alpha.example.test/mcp",
  headers: { "X-Alpha": "alpha-header-value" },
  allowedToolsPattern: "mcp__alpha-private__*",
  owner: "alpha",
  createdAt: NOW,
  updatedAt: NOW,
};
const CONTROL_ENTRY = { ...RESERVED_ENTRY, name: "alpha-tools", description: "an ordinary entry", allowedToolsPattern: undefined };

let capturedOptions: Record<string, unknown>[] = [];
let tempDir = "";

beforeEach(() => {
  vi.resetModules();
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gateway-reserved-merge-"));
  process.env.TOOLS_PERSIST_PATH = path.join(tempDir, "tools.json");
  process.env.MCP_SERVERS_PERSIST_PATH = path.join(tempDir, "mcp-servers.json");
  process.env.SESSION_PERSIST_PATH = path.join(tempDir, "sessions.json");
  capturedOptions = [];
  vi.spyOn(console, "log").mockImplementation(() => undefined);
  vi.doMock("@anthropic-ai/claude-agent-sdk", () => ({
    query: vi.fn(({ options }) => {
      capturedOptions.push(options as Record<string, unknown>);
      return (async function* () {
        yield { type: "system", subtype: "init", claude_code_version: "2.0.77", skills: [] };
        yield { type: "assistant", message: { content: [{ type: "text", text: "ack" }] } };
        yield { type: "result", subtype: "success", is_error: false, result: "fine", session_id: "sdk-s", usage: { input_tokens: 1, output_tokens: 1 }, total_cost_usd: 0 };
      })();
    }),
  }));
  vi.doMock("../mcp-registry.js", async (importOriginal) => {
    const actual = await importOriginal<typeof import("../mcp-registry.js")>();
    return { ...actual, getEnabledMcpServers: () => [RESERVED_ENTRY, CONTROL_ENTRY], getRunMcpServers: () => [RESERVED_ENTRY, CONTROL_ENTRY] };
  });
});

afterEach(async () => {
  const { credentialRelay } = await import("../mcp-credential-relay.js");
  await credentialRelay.close();
  vi.doUnmock("@anthropic-ai/claude-agent-sdk");
  vi.doUnmock("../mcp-registry.js");
  vi.restoreAllMocks();
  delete process.env.TOOLS_PERSIST_PATH;
  delete process.env.MCP_SERVERS_PERSIST_PATH;
  delete process.env.SESSION_PERSIST_PATH;
  await new Promise((resolve) => setTimeout(resolve, 150));
  fs.rmSync(tempDir, { recursive: true, force: true });
});

async function createApp() {
  const { registerTool } = await import("../tools.js");
  registerTool({
    name: "reqlift_ping",
    description: "ping",
    input_schema: { type: "object", properties: { text: { type: "string" } } },
    webhook_url: "http://webhook.test/reqlift_ping",
    owner: "reqlift",
  });
  const { credentialRelay } = await import("../mcp-credential-relay.js");
  await credentialRelay.start();
  // Precondition: with the relay down every registry server is left out and the rows below would pass for the wrong reason.
  expect(credentialRelay.isListening()).toBe(true);
  const registered: string[] = [];
  const register = credentialRelay.register.bind(credentialRelay);
  vi.spyOn(credentialRelay, "register").mockImplementation((binding) => {
    registered.push(binding.serverName);
    return register(binding);
  });
  const { queryRouter } = await import("../query.js");
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.clientLabel = (req.headers["x-test-label"] as string | undefined) ?? "reqlift";
    next();
  });
  app.use(queryRouter);
  return { app, registered };
}

async function runAs(app: express.Express, label: string) {
  const res = await request(app).post("/v1/query").set("x-test-label", label).send({ queryId: `q-${label}-${Math.random().toString(36).slice(2)}`, prompt: "go", useSession: false, user_id: "user-1" });
  expect(res.status).toBe(200);
  expect(capturedOptions).toHaveLength(1);
  return {
    mcpServers: (capturedOptions[0].mcpServers ?? {}) as Record<string, { type?: string; url?: string; instance?: unknown }>,
    allowedTools: capturedOptions[0].allowedTools as string[],
  };
}

describe("the run's server map never lets a registry entry take the webhook server's place (MVP-8203)", () => {
  it("a caller with a webhook tool: the key holds the gateway's own in-process server, with no pattern and no relay binding for the entry", async () => {
    const { app, registered } = await createApp();
    const { mcpServers, allowedTools } = await runAs(app, "reqlift");
    expect(mcpServers[RESERVED].instance).toBeDefined();
    expect(mcpServers[RESERVED].url).toBeUndefined();
    expect(allowedTools).not.toContain("mcp__agent-gateway-tools__*");
    expect(allowedTools).not.toContain("mcp__alpha-private__*");
    expect(registered).not.toContain(RESERVED);
  });

  it("a caller without a webhook tool: the key is absent from the run", async () => {
    const { app, registered } = await createApp();
    const { mcpServers, allowedTools } = await runAs(app, "diemcrm");
    expect(Object.keys(mcpServers)).not.toContain(RESERVED);
    expect(allowedTools).not.toContain("mcp__agent-gateway-tools__*");
    expect(allowedTools).not.toContain("mcp__alpha-private__*");
    expect(registered).not.toContain(RESERVED);
  });

  it("control: an ordinary registry entry served by the same mock is attached with its pattern and a relay binding", async () => {
    const { app, registered } = await createApp();
    const { mcpServers, allowedTools } = await runAs(app, "reqlift");
    expect(mcpServers["alpha-tools"]).toMatchObject({ type: "http" });
    expect(mcpServers["alpha-tools"].url).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/mcp\//);
    expect(allowedTools).toContain("mcp__alpha-tools__*");
    expect(registered).toContain("alpha-tools");
  });
});
