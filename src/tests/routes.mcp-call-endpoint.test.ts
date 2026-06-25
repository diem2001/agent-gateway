import fs from "node:fs";
import http, { type Server } from "node:http";
import os from "node:os";
import path from "node:path";
import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { McpServerDefinition } from "../mcp-registry.js";

let tempDir: string;
let servers: Server[] = [];

beforeEach(() => {
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gateway-mcp-call-"));
  process.env.MCP_SERVERS_PERSIST_PATH = path.join(tempDir, "mcp-servers.json");
  process.env.MCP_CALL_TIMEOUT_MS = "500";
  servers = [];
  vi.resetModules();
});

afterEach(async () => {
  await Promise.all(servers.map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  delete process.env.MCP_SERVERS_PERSIST_PATH;
  delete process.env.MCP_CALL_TIMEOUT_MS;
  fs.rmSync(tempDir, { recursive: true, force: true });
  vi.doUnmock("@anthropic-ai/claude-agent-sdk");
});

async function createApp() {
  const { default: mcpRoutes } = await import("../routes/mcp.js");
  const app = express();
  app.use(express.json());
  app.use(mcpRoutes);
  return app;
}

// Auth app: mirrors server.ts wiring (authMiddleware runs globally before mcpRoutes).
async function createAuthApp() {
  const { authMiddleware, loadApiKeys } = await import("../auth.js");
  loadApiKeys();
  const { default: mcpRoutes } = await import("../routes/mcp.js");
  const app = express();
  app.use(express.json());
  app.use(authMiddleware);
  app.use(mcpRoutes);
  return app;
}

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

async function startFakeMcpServer(
  handler: (req: http.IncomingMessage, res: http.ServerResponse) => void,
) {
  const server = http.createServer(handler);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("fake server did not bind a port");
  return `http://127.0.0.1:${address.port}/mcp`;
}

/** Respond to a JSON-RPC tools/call with the given result member. */
function toolsCallResponder(result: unknown, recordAuth?: (auth: string) => void) {
  return (req: http.IncomingMessage, res: http.ServerResponse) => {
    if (recordAuth) recordAuth(String(req.headers.authorization ?? ""));
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify({ jsonrpc: "2.0", id: "agent-gateway-mcp-call", result }));
  };
}

describe("POST /v1/mcp-servers/:name/call — contract matrix", () => {
  it("success: 200, body = the fake server's tools/call result verbatim", async () => {
    const url = await startFakeMcpServer(
      toolsCallResponder({ content: [{ type: "text", text: "hello" }], isError: false }),
    );
    await registerServer({ name: "jira", type: "http", url });
    const app = await createApp();

    const res = await request(app)
      .post("/v1/mcp-servers/jira/call")
      .send({ tool: "echo", arguments: { q: 1 } });

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ content: [{ type: "text", text: "hello" }], isError: false });
  });

  it("unknown server: 400 MCP_SERVER_NOT_FOUND, no upstream request", async () => {
    let upstreamHit = false;
    const url = await startFakeMcpServer((_req, res) => {
      upstreamHit = true;
      res.end("{}");
    });
    // Register under a DIFFERENT name so the live upstream exists but is never targeted.
    await registerServer({ name: "registered", type: "http", url });
    const app = await createApp();

    const res = await request(app)
      .post("/v1/mcp-servers/missing/call")
      .send({ tool: "echo", arguments: {} });

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe("MCP_SERVER_NOT_FOUND");
    expect(upstreamHit).toBe(false);
  });

  it("registered-but-disabled: 400 MCP_SERVER_DISABLED; fake server received NO request", async () => {
    let upstreamHit = false;
    const url = await startFakeMcpServer((_req, res) => {
      upstreamHit = true;
      res.end("{}");
    });
    await registerServer({ name: "disabled", type: "http", url, enabled: false });
    const app = await createApp();

    const res = await request(app)
      .post("/v1/mcp-servers/disabled/call")
      .send({ tool: "echo", arguments: {} });

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe("MCP_SERVER_DISABLED");
    expect(upstreamHit).toBe(false);
  });

  it("invalid tool (missing): 400 MCP_CALL_INVALID", async () => {
    await registerServer({ name: "jira", type: "http", url: "http://127.0.0.1:9/mcp" });
    const app = await createApp();

    const res = await request(app).post("/v1/mcp-servers/jira/call").send({ arguments: {} });

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe("MCP_CALL_INVALID");
  });

  it("invalid tool (empty string): 400 MCP_CALL_INVALID", async () => {
    await registerServer({ name: "jira", type: "http", url: "http://127.0.0.1:9/mcp" });
    const app = await createApp();

    const res = await request(app).post("/v1/mcp-servers/jira/call").send({ tool: "", arguments: {} });

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe("MCP_CALL_INVALID");
  });

  it("invalid arguments (not an object): 400 MCP_CALL_INVALID", async () => {
    await registerServer({ name: "jira", type: "http", url: "http://127.0.0.1:9/mcp" });
    const app = await createApp();

    const res = await request(app).post("/v1/mcp-servers/jira/call").send({ tool: "echo", arguments: "nope" });

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe("MCP_CALL_INVALID");
  });

  it("invalid credentials override (non-string map): 400 MCP_OVERRIDE_INVALID", async () => {
    await registerServer({ name: "jira", type: "http", url: "http://127.0.0.1:9/mcp" });
    const app = await createApp();

    const res = await request(app)
      .post("/v1/mcp-servers/jira/call")
      .send({ tool: "echo", arguments: {}, credentials: { headers: { Authorization: 42 } } });

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe("MCP_OVERRIDE_INVALID");
  });

  it("upstream 401/403: 401 MCP_AUTH_FAILED; creds NOT leaked in body", async () => {
    const url = await startFakeMcpServer((_req, res) => {
      res.writeHead(401, { "Content-Type": "text/plain" });
      res.end("bad token Basic SECRET_TOKEN");
    });
    await registerServer({ name: "jira", type: "http", url });
    const app = await createApp();

    const res = await request(app)
      .post("/v1/mcp-servers/jira/call")
      .send({ tool: "echo", arguments: {}, credentials: { headers: { Authorization: "Basic SECRET_TOKEN" } } });

    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe("MCP_AUTH_FAILED");
    expect(JSON.stringify(res.body)).not.toContain("SECRET_TOKEN");
  });

  it("slow/no-response: 504 MCP_TIMEOUT (never hangs)", async () => {
    const url = await startFakeMcpServer((_req, _res) => {
      // Hold the request open past MCP_CALL_TIMEOUT_MS (500ms).
    });
    await registerServer({ name: "slow", type: "http", url });
    const app = await createApp();

    const res = await request(app)
      .post("/v1/mcp-servers/slow/call")
      .send({ tool: "echo", arguments: {}, credentials: { headers: { Authorization: "Basic SECRET_TOKEN" } } });

    expect(res.status).toBe(504);
    expect(res.body.error.code).toBe("MCP_TIMEOUT");
    expect(JSON.stringify(res.body)).not.toContain("SECRET_TOKEN");
  });

  it("dead port: 502 MCP_NETWORK_ERROR; creds NOT leaked", async () => {
    await registerServer({ name: "dead", type: "http", url: "http://127.0.0.1:9/mcp" });
    const app = await createApp();

    const res = await request(app)
      .post("/v1/mcp-servers/dead/call")
      .send({ tool: "echo", arguments: {}, credentials: { headers: { Authorization: "Basic SECRET_TOKEN" } } });

    expect(res.status).toBe(502);
    expect(res.body.error.code).toBe("MCP_NETWORK_ERROR");
    expect(JSON.stringify(res.body)).not.toContain("SECRET_TOKEN");
  });

  it("tool-level error: 200, body isError:true (NOT the gateway envelope)", async () => {
    const url = await startFakeMcpServer(
      toolsCallResponder({ content: [{ type: "text", text: "boom" }], isError: true }),
    );
    await registerServer({ name: "jira", type: "http", url });
    const app = await createApp();

    const res = await request(app)
      .post("/v1/mcp-servers/jira/call")
      .send({ tool: "echo", arguments: {} });

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ content: [{ type: "text", text: "boom" }], isError: true });
    expect(res.body.error).toBeUndefined();
  });

  it("parses Streamable HTTP text/event-stream tools/call responses", async () => {
    const url = await startFakeMcpServer((_req, res) => {
      res.writeHead(200, { "Content-Type": "text/event-stream" });
      res.end([
        "event: message",
        'data: {"jsonrpc":"2.0","id":"agent-gateway-mcp-call","result":{"content":[{"type":"text","text":"sse-ok"}],"isError":false}}',
        "",
      ].join("\n"));
    });
    await registerServer({ name: "jira", type: "http", url });
    const app = await createApp();

    const res = await request(app).post("/v1/mcp-servers/jira/call").send({ tool: "echo", arguments: {} });

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ content: [{ type: "text", text: "sse-ok" }], isError: false });
  });

  it("returns ONLY the JSON-RPC result member — a stray top-level upstream field must NOT leak", async () => {
    const url = await startFakeMcpServer((_req, res) => {
      res.setHeader("Content-Type", "application/json");
      // Upstream envelope carries a stray top-level field alongside `result`.
      res.end(
        JSON.stringify({
          jsonrpc: "2.0",
          id: "agent-gateway-mcp-call",
          result: { content: [{ type: "text", text: "ok" }], isError: false },
          STRAY_TOP_LEVEL: "leak-me",
        }),
      );
    });
    await registerServer({ name: "jira", type: "http", url });
    const app = await createApp();

    const res = await request(app).post("/v1/mcp-servers/jira/call").send({ tool: "echo", arguments: {} });

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ content: [{ type: "text", text: "ok" }], isError: false });
    // The stray top-level upstream field must not appear anywhere in the response body.
    expect(res.body.STRAY_TOP_LEVEL).toBeUndefined();
    expect(JSON.stringify(res.body)).not.toContain("leak-me");
  });
});

describe("POST /v1/mcp-servers/:name/call — auth precedence", () => {
  beforeEach(() => {
    process.env.API_KEYS = "caller:good-key";
  });
  afterEach(() => {
    delete process.env.API_KEYS;
  });

  it("no/malformed Bearer: 401 plain { error } ; fake server received NO request", async () => {
    let upstreamHit = false;
    const url = await startFakeMcpServer((_req, res) => {
      upstreamHit = true;
      res.end("{}");
    });
    await registerServer({ name: "jira", type: "http", url });
    const app = await createAuthApp();

    const res = await request(app)
      .post("/v1/mcp-servers/jira/call")
      .send({ tool: "echo", arguments: {} }); // no Authorization header

    expect(res.status).toBe(401);
    expect(res.body).toEqual({ error: "Missing or malformed Authorization header" });
    expect(upstreamHit).toBe(false);
  });

  it("unrecognized API key: 401 plain { error } ; no upstream request", async () => {
    let upstreamHit = false;
    const url = await startFakeMcpServer((_req, res) => {
      upstreamHit = true;
      res.end("{}");
    });
    await registerServer({ name: "jira", type: "http", url });
    const app = await createAuthApp();

    const res = await request(app)
      .post("/v1/mcp-servers/jira/call")
      .set("Authorization", "Bearer wrong-key")
      .send({ tool: "echo", arguments: {} });

    expect(res.status).toBe(401);
    expect(res.body).toEqual({ error: "Invalid API key" });
    expect(upstreamHit).toBe(false);
  });
});

describe("POST /v1/mcp-servers/:name/call — Outcome Probe (Observable-Outcome AC)", () => {
  it("a registered tool executes via /call with NO LLM, result verbatim, per-caller creds honored with no cross-bleed", async () => {
    // The Agent SDK (the only LLM/token path) must NOT be loaded by the /call path.
    // This factory runs only if the SDK module is actually imported; if /call ever
    // pulled in agent.ts → @anthropic-ai/claude-agent-sdk, sdkLoaded would flip true.
    let sdkLoaded = false;
    vi.doMock("@anthropic-ai/claude-agent-sdk", () => {
      sdkLoaded = true;
      return { query: () => { throw new Error("LLM path must not run for /call"); } };
    });

    const seenAuth: string[] = [];
    const url = await startFakeMcpServer((req, res) => {
      const auth = String(req.headers.authorization ?? "");
      seenAuth.push(auth);
      res.setHeader("Content-Type", "application/json");
      res.end(
        JSON.stringify({
          jsonrpc: "2.0",
          id: "agent-gateway-mcp-call",
          result: { content: [{ type: "text", text: `OK:${auth}` }], isError: false },
        }),
      );
    });
    await registerServer({ name: "X", type: "http", url, headers: { Authorization: "STATIC" } });
    const app = await createApp();

    // CALLER_A
    const resA = await request(app)
      .post("/v1/mcp-servers/X/call")
      .send({ tool: "echo", arguments: { q: 1 }, credentials: { headers: { Authorization: "Basic CALLER_A" } } });

    expect(resA.status).toBe(200);
    // Result verbatim: the fake server echoed the exact inbound Authorization it saw.
    expect(resA.body).toEqual({ content: [{ type: "text", text: "OK:Basic CALLER_A" }], isError: false });

    // CALLER_B — per-caller isolation, no bleed from A's override.
    const resB = await request(app)
      .post("/v1/mcp-servers/X/call")
      .send({ tool: "echo", arguments: { q: 2 }, credentials: { headers: { Authorization: "Basic CALLER_B" } } });

    expect(resB.status).toBe(200);
    expect(resB.body).toEqual({ content: [{ type: "text", text: "OK:Basic CALLER_B" }], isError: false });

    // The upstream saw exactly each caller's override, in order, with no cross-bleed.
    expect(seenAuth).toEqual(["Basic CALLER_A", "Basic CALLER_B"]);

    // No LLM/Agent-SDK module was loaded and no token path ran for either call.
    expect(sdkLoaded).toBe(false);
  });
});
