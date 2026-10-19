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
let registryEntries: Record<string, unknown>[] = [RESERVED_ENTRY, CONTROL_ENTRY];
let logs: string[] = [];

beforeEach(() => {
  vi.resetModules();
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gateway-reserved-merge-"));
  process.env.TOOLS_PERSIST_PATH = path.join(tempDir, "tools.json");
  process.env.MCP_SERVERS_PERSIST_PATH = path.join(tempDir, "mcp-servers.json");
  process.env.SESSION_PERSIST_PATH = path.join(tempDir, "sessions.json");
  capturedOptions = [];
  registryEntries = [RESERVED_ENTRY, CONTROL_ENTRY];
  logs = [];
  vi.spyOn(console, "log").mockImplementation((...args) => {
    logs.push(args.map(String).join(" "));
  });
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
    return { ...actual, getEnabledMcpServers: () => registryEntries, getRunMcpServers: () => registryEntries };
  });
});

afterEach(async () => {
  const { credentialRelay } = await import("../mcp-credential-relay.js");
  await credentialRelay.close();
  vi.doUnmock("@anthropic-ai/claude-agent-sdk");
  vi.doUnmock("../mcp-registry.js");
  vi.doUnmock("../tool-grant.js");
  vi.doUnmock("../mcp-request-servers.js");
  vi.restoreAllMocks();
  delete process.env.TOOLS_PERSIST_PATH;
  delete process.env.MCP_SERVERS_PERSIST_PATH;
  delete process.env.SESSION_PERSIST_PATH;
  await new Promise((resolve) => setTimeout(resolve, 150));
  fs.rmSync(tempDir, { recursive: true, force: true });
});

async function createApp(webhookTool: { name: string; owner: string } = { name: "reqlift_ping", owner: "reqlift" }) {
  const { registerTool } = await import("../tools.js");
  registerTool({
    name: webhookTool.name,
    description: "ping",
    input_schema: { type: "object", properties: { text: { type: "string" } } },
    webhook_url: `http://webhook.test/${webhookTool.name}`,
    owner: webhookTool.owner,
  });
  const { credentialRelay } = await import("../mcp-credential-relay.js");
  await credentialRelay.start();
  // Precondition: with the relay down every registry server is left out and the rows below would pass for the wrong reason.
  expect(credentialRelay.isListening()).toBe(true);
  const registered: string[] = [];
  const tokens: string[] = [];
  const revoked: string[] = [];
  const register = credentialRelay.register.bind(credentialRelay);
  vi.spyOn(credentialRelay, "register").mockImplementation((binding) => {
    registered.push(binding.serverName);
    const bound = register(binding);
    tokens.push(bound.token);
    return bound;
  });
  const revoke = credentialRelay.revoke.bind(credentialRelay);
  vi.spyOn(credentialRelay, "revoke").mockImplementation((token) => {
    revoked.push(token);
    revoke(token);
  });
  const { queryRouter } = await import("../query.js");
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.clientLabel = (req.headers["x-test-label"] as string | undefined) ?? "reqlift";
    next();
  });
  app.use(queryRouter);
  return { app, registered, tokens, revoked };
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

/**
 * Every name that begins with `agent-gateway-tools` is kept out of the run by the run layer on its own (MVP-8235), and the
 * run asserts before the runtime starts that no server can produce a webhook tool's full name. The registry getters are
 * mocked to return the prefixed entries, so the selection layer cannot be what keeps them out.
 */
describe("the run layer drops every reserved-prefix server and asserts the tool names (MVP-8235)", () => {
  const PREFIXED_ENTRY = { ...RESERVED_ENTRY, name: "agent-gateway-tools__x", description: "legacy prefixed entry of another caller", allowedToolsPattern: "mcp__alpha-private__*" };
  const NOW_BODY = (label: string) => ({ queryId: `q-${label}-${Math.random().toString(36).slice(2)}`, prompt: "go", useSession: false, user_id: "user-1" });
  const post = (app: express.Express, label: string, extra: Record<string, unknown> = {}) => request(app).post("/v1/query").set("x-test-label", label).send({ ...NOW_BODY(label), ...extra });
  const ndjson = (text: string) => text.split("\n").filter(Boolean).map((line) => JSON.parse(line) as { type: string; content?: string });

  it("(1) a prefixed registry entry and a prefixed request server are dropped: no map key, no pattern, no relay binding, and the run proceeds", async () => {
    registryEntries = [PREFIXED_ENTRY, CONTROL_ENTRY];
    // The request-server validator is a pass-through here, so the run layer's own filter is what is under test.
    vi.doMock("../mcp-request-servers.js", async (importOriginal) => {
      const actual = await importOriginal<typeof import("../mcp-request-servers.js")>();
      return { ...actual, validateRequestMcpServers: (value: unknown) => (value === undefined ? {} : { servers: value }) };
    });
    const { app, registered } = await createApp();
    const res = await post(app, "reqlift", { mcpServers: { "agent-gateway-tools__req": { type: "http", url: "http://beta.example.test/mcp" } } });
    expect(res.status).toBe(200);
    expect(capturedOptions).toHaveLength(1);
    const mcpServers = (capturedOptions[0].mcpServers ?? {}) as Record<string, { instance?: unknown }>;
    const allowedTools = capturedOptions[0].allowedTools as string[];
    expect(Object.keys(mcpServers).sort()).toEqual(["agent-gateway-tools", "alpha-tools"]);
    expect(mcpServers["agent-gateway-tools"].instance).toBeDefined();
    expect(allowedTools).not.toContain("mcp__agent-gateway-tools__x__*");
    expect(allowedTools).not.toContain("mcp__agent-gateway-tools__req__*");
    expect(allowedTools).not.toContain("mcp__alpha-private__*");
    expect(registered).not.toContain("agent-gateway-tools__x");
    // Control: the ordinary entry beside them is attached and bound.
    expect(allowedTools).toContain("mcp__alpha-tools__*");
    expect(registered).toContain("alpha-tools");
  });

  it("(2) the assertion is live: with the helper narrowed to the exact name, agent-gateway-tools__x against the webhook tool x__y refuses the run before the runtime starts", async () => {
    registryEntries = [PREFIXED_ENTRY, CONTROL_ENTRY];
    vi.doMock("../tool-grant.js", async (importOriginal) => {
      const actual = await importOriginal<typeof import("../tool-grant.js")>();
      return { ...actual, isReservedMcpServerName: (name: string) => name === "agent-gateway-tools" };
    });
    const { app, registered, tokens, revoked } = await createApp({ name: "x__y", owner: "alpha" });
    const res = await post(app, "alpha");
    // Precondition: the narrowed filter let the prefixed entry through to a relay binding, so only the assertion can stop the run.
    expect(registered).toContain("agent-gateway-tools__x");
    expect(capturedOptions).toHaveLength(0);
    const events = ndjson(res.text);
    const errors = events.filter((event) => event.type === "error");
    expect(errors).toHaveLength(1);
    expect(errors[0].content).toMatch(/^The AI request failed on the gateway for an unknown reason\. Please try again\./);
    expect(errors[0].content).toMatch(/\(reference: q-alpha-[a-z0-9]+\)\.$/);
    expect(events.some((event) => event.type === "done")).toBe(false);
    expect(logs.filter((line) => line === "[audit] mcp.run.tool_name_clash serverName=agent-gateway-tools__x")).toHaveLength(1);
    expect(logs.filter((line) => line.includes("tool_name_clash"))).toHaveLength(1);
    expect(tokens.length).toBeGreaterThan(0);
    expect([...revoked].sort()).toEqual([...tokens].sort());
  });

  it("(3) the re-assert is pinned: with the helper unable to filter, an entry named exactly agent-gateway-tools still leaves the key holding the in-process webhook server", async () => {
    registryEntries = [RESERVED_ENTRY, CONTROL_ENTRY];
    vi.doMock("../tool-grant.js", async (importOriginal) => {
      const actual = await importOriginal<typeof import("../tool-grant.js")>();
      return { ...actual, isReservedMcpServerName: () => false };
    });
    const { app } = await createApp();
    const res = await post(app, "reqlift");
    expect(res.status).toBe(200);
    expect(capturedOptions).toHaveLength(1);
    const mcpServers = capturedOptions[0].mcpServers as Record<string, { instance?: unknown; url?: string }>;
    expect(mcpServers["agent-gateway-tools"].instance).toBeDefined();
    expect(mcpServers["agent-gateway-tools"].url).toBeUndefined();
    expect(logs.filter((line) => line.includes("tool_name_clash"))).toEqual([]);
  });

  it("control: the same setup as (2) with an ordinary name beta-docs against the webhook tool x__y runs", async () => {
    registryEntries = [{ ...PREFIXED_ENTRY, name: "beta-docs", allowedToolsPattern: undefined }, CONTROL_ENTRY];
    vi.doMock("../tool-grant.js", async (importOriginal) => {
      const actual = await importOriginal<typeof import("../tool-grant.js")>();
      return { ...actual, isReservedMcpServerName: (name: string) => name === "agent-gateway-tools" };
    });
    const { app, registered } = await createApp({ name: "x__y", owner: "alpha" });
    const res = await post(app, "alpha");
    expect(res.status).toBe(200);
    expect(capturedOptions).toHaveLength(1);
    expect(registered).toContain("beta-docs");
    expect(ndjson(res.text).some((event) => event.type === "error")).toBe(false);
    expect(logs.filter((line) => line.includes("tool_name_clash"))).toEqual([]);
  });
});
