/**
 * Outcome Probe for MVP-6755 (Observable-Outcome AC):
 *
 *   "When a client POSTs /v1/query with mcpServers { chrome-devtools: {command, args} },
 *    the gateway injects that server into the SDK query options AND allows its tools,
 *    while the gateway's own webhook tools + registered servers still load and keep
 *    precedence (the request cannot override them)."
 *
 * This is the regression that reqlift recon depends on: it sends a per-run
 * chrome-devtools MCP server in the request body to drive a browser. Before this
 * fix the gateway silently dropped the field, so recon never got its browser tools.
 *
 * The test exercises the REAL query.ts + retry.ts + agent.ts path end-to-end,
 * mocking ONLY the Claude Agent SDK boundary (`query()`) so we can observe the
 * exact `options` the SDK receives — mirroring how reqlift calls the gateway.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Captures the `options` argument passed to the mocked SDK query() per invocation.
let capturedOptions: Array<Record<string, unknown>> = [];

beforeEach(() => {
  vi.resetModules();
  capturedOptions = [];
  vi.doMock("@anthropic-ai/claude-agent-sdk", () => ({
    createSdkMcpServer: vi.fn((options) => ({ type: "sdk", name: options.name })),
    query: vi.fn(({ options }) => {
      capturedOptions.push(options as Record<string, unknown>);
      return (async function* () {
        yield { type: "assistant", message: { content: [{ type: "text", text: "ack" }] } };
        yield {
          type: "result",
          usage: { input_tokens: 1, output_tokens: 1 },
          total_cost_usd: 0,
          sessionId: "sdk-session",
        };
      })();
    }),
  }));
});

afterEach(() => {
  vi.doUnmock("@anthropic-ai/claude-agent-sdk");
});

async function createApp() {
  const { queryRouter } = await import("../query.js");
  const app = express();
  app.use(express.json());
  app.use(queryRouter);
  return app;
}

const CHROME_DEVTOOLS = {
  "chrome-devtools": {
    command: "npx",
    args: ["chrome-devtools-mcp", "--browser-url=http://recon-abc:9222"],
  },
};

describe("Outcome Probe — per-query mcpServers reaches the SDK options (MVP-6755)", () => {
  it("(a) injects the request server and allows its tools when no allowedTools is sent", async () => {
    const app = await createApp();

    const res = await request(app)
      .post("/v1/query")
      .send({ queryId: "probe-cdt", prompt: "navigate", useSession: false, mcpServers: CHROME_DEVTOOLS });

    expect(res.status).toBe(200);
    expect(capturedOptions).toHaveLength(1);
    const options = capturedOptions[0];

    // The server is present in the SDK mcpServers map with the exact spec.
    const mcpServers = options.mcpServers as Record<string, unknown>;
    expect(mcpServers).toBeDefined();
    expect(mcpServers["chrome-devtools"]).toEqual(CHROME_DEVTOOLS["chrome-devtools"]);

    // Its tools are allowed (reqlift recon sends no allowedTools → default branch
    // must add the pattern, otherwise the SDK never exposes mcp__chrome-devtools__*).
    expect(options.allowedTools as string[]).toContain("mcp__chrome-devtools__*");
  });

  it("(b) a request mcpServers cannot override the reserved agent-gateway-tools name", async () => {
    const app = await createApp();

    const res = await request(app)
      .post("/v1/query")
      .send({
        queryId: "probe-reserved",
        prompt: "x",
        useSession: false,
        mcpServers: { "agent-gateway-tools": { command: "evil", args: [] } },
      });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/agent-gateway-tools/);
    expect(capturedOptions).toHaveLength(0);
  });

  it("(e) a legacy registry entry named agent-gateway-tools does not change how a request server of that name is refused (MVP-8203)", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gateway-reserved-request-"));
    process.env.MCP_SERVERS_PERSIST_PATH = path.join(tempDir, "mcp-servers.json");
    try {
      const { registerMcpServer } = await import("../mcp-registry.js");
      const now = "2026-09-01T00:00:00.000Z";
      registerMcpServer({ name: "agent-gateway-tools", description: "legacy", enabled: true, type: "http", url: "http://alpha.example.test/mcp", owner: "alpha", createdAt: now, updatedAt: now });
      const app = await createApp();

      const res = await request(app)
        .post("/v1/query")
        .send({
          queryId: "probe-reserved-legacy",
          prompt: "x",
          useSession: false,
          mcpServers: { "agent-gateway-tools": { command: "evil", args: [] } },
        });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/must not use a server name beginning with "agent-gateway-tools"/);
      expect(capturedOptions).toHaveLength(0);
    } finally {
      delete process.env.MCP_SERVERS_PERSIST_PATH;
      await new Promise((resolve) => setTimeout(resolve, 150));
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("(c) rejects a malformed server (no command and no url) with 400", async () => {
    const app = await createApp();

    const res = await request(app)
      .post("/v1/query")
      .send({
        queryId: "probe-malformed",
        prompt: "x",
        useSession: false,
        mcpServers: { broken: { foo: "bar" } },
      });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/command.*url|url.*command/i);
    expect(capturedOptions).toHaveLength(0);
  });

  it("(d) omitting mcpServers leaves the SDK options unchanged (no mcpServers key)", async () => {
    const app = await createApp();

    const res = await request(app)
      .post("/v1/query")
      .send({ queryId: "probe-none", prompt: "hello", useSession: false });

    expect(res.status).toBe(200);
    expect(capturedOptions).toHaveLength(1);
    // No registered servers + no webhook tools + no request servers ⇒ no mcpServers key.
    expect(capturedOptions[0].mcpServers).toBeUndefined();
  });
});

/**
 * Every server name that begins with `agent-gateway-tools` is refused in a request (MVP-8235), before the name rule and
 * the registered-name conflict check, with one fixed text that echoes nothing of the request. An excluded legacy registry
 * entry of such a name does not change how another caller's enforced webhook tool is validated.
 */
describe("request mcpServers: every name beginning with agent-gateway-tools is refused (MVP-8235)", () => {
  const FIXED = 'mcpServers must not use a server name beginning with "agent-gateway-tools"';
  const NOW = "2026-09-01T00:00:00.000Z";
  let tempDir = "";

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gateway-reserved-prefix-"));
    process.env.MCP_SERVERS_PERSIST_PATH = path.join(tempDir, "mcp-servers.json");
  });

  afterEach(async () => {
    delete process.env.MCP_SERVERS_PERSIST_PATH;
    await new Promise((resolve) => setTimeout(resolve, 150));
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  async function store(...names: string[]) {
    const { registerMcpServer } = await import("../mcp-registry.js");
    for (const name of names) registerMcpServer({ name, description: "stored", enabled: true, type: "http", url: `http://${name}.example.test/mcp`, owner: "alpha", createdAt: NOW, updatedAt: NOW });
  }

  const post = (app: express.Express, body: Record<string, unknown>) => request(app).post("/v1/query").send({ queryId: "probe-prefix", prompt: "x", useSession: false, ...body });

  it.each(["agent-gateway-tools", "agent-gateway-tools_", "agent-gateway-tools__x", "agent-gateway-tools-x"])(
    "%s is refused with the fixed text and the SDK query is never called",
    async (name) => {
      const app = await createApp();
      const res = await post(app, { mcpServers: { [name]: { command: "evil", args: [] } } });
      expect(res.status).toBe(400);
      expect(res.body.error).toBe(FIXED);
      expect(capturedOptions).toHaveLength(0);
    },
  );

  it("a 40-character prefixed name still gets the reserved text, not the name-rule text", async () => {
    const name = `agent-gateway-tools__${"x".repeat(19)}`;
    expect(name).toHaveLength(40);
    const app = await createApp();
    const res = await post(app, { mcpServers: { [name]: { command: "evil", args: [] } } });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe(FIXED);
    expect(JSON.stringify(res.body)).not.toContain(name);
    expect(capturedOptions).toHaveLength(0);
  });

  it("with a legacy registry entry of the same name, the reserved text wins over the registered-name conflict", async () => {
    await store("agent-gateway-tools__x");
    const app = await createApp();
    const res = await post(app, { mcpServers: { "agent-gateway-tools__x": { command: "evil", args: [] } } });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe(FIXED);
    expect(capturedOptions).toHaveLength(0);
  });

  it("enforced row: an enabled legacy agent-gateway-tools__x does not make another caller's enforced webhook tool ambiguous", async () => {
    await store("agent-gateway-tools__x");
    const app = await createApp();
    const res = await post(app, { enforcedTools: ["mcp__agent-gateway-tools__x__y"] });
    expect(res.status).toBe(200);
    expect(capturedOptions).toHaveLength(1);
  });

  it("control: a genuine registry ambiguity (docs and docs__a) is still refused for an enforced tool", async () => {
    await store("docs", "docs__a");
    const app = await createApp();
    const res = await post(app, { enforcedTools: ["mcp__docs__a__b"] });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/matches more than one MCP server/);
    expect(capturedOptions).toHaveLength(0);
  });

  it("control: a request server named beta-docs runs", async () => {
    const app = await createApp();
    const res = await post(app, { mcpServers: { "beta-docs": { command: "node", args: [] } } });
    expect(res.status).toBe(200);
    expect(capturedOptions).toHaveLength(1);
    expect(Object.keys(capturedOptions[0].mcpServers as Record<string, unknown>)).toEqual(["beta-docs"]);
  });
});
