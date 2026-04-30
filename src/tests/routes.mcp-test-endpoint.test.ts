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
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gateway-mcp-test-"));
  process.env.MCP_SERVERS_PERSIST_PATH = path.join(tempDir, "mcp-servers.json");
  process.env.MCP_TEST_TIMEOUT_MS = "500";
  servers = [];
  vi.resetModules();
});

afterEach(async () => {
  await Promise.all(servers.map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  delete process.env.MCP_SERVERS_PERSIST_PATH;
  delete process.env.MCP_TEST_TIMEOUT_MS;
  fs.rmSync(tempDir, { recursive: true, force: true });
});

async function createApp() {
  const { default: mcpRoutes } = await import("../routes/mcp.js");
  const app = express();
  app.use(express.json());
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

describe("POST /v1/mcp-servers/:name/test", () => {
  it("merges headers, calls tools/list, and returns tool names", async () => {
    const seenAuth: string[] = [];
    const seenAccept: string[] = [];
    const url = await startFakeMcpServer((req, res) => {
      seenAuth.push(String(req.headers.authorization ?? ""));
      seenAccept.push(String(req.headers.accept ?? ""));
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ jsonrpc: "2.0", id: "agent-gateway-mcp-test", result: { tools: [{ name: "search" }] } }));
    });
    await registerServer({
      name: "jira",
      type: "http",
      url,
      headers: { Authorization: "STATIC" },
    });
    const app = await createApp();

    const res = await request(app)
      .post("/v1/mcp-servers/jira/test")
      .send({ headers: { Authorization: "Basic USER_X" } });

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ ok: true, toolCount: 1, tools: [{ name: "search" }] });
    expect(seenAuth).toEqual(["Basic USER_X"]);
    expect(seenAccept).toEqual(["application/json, text/event-stream"]);
  });

  it("parses Streamable HTTP text/event-stream tools/list responses", async () => {
    const url = await startFakeMcpServer((_req, res) => {
      res.writeHead(200, { "Content-Type": "text/event-stream" });
      res.end([
        "event: message",
        'data: {"jsonrpc":"2.0","id":"agent-gateway-mcp-test","result":{"tools":[{"name":"get_issue"}]}}',
        "",
      ].join("\n"));
    });
    await registerServer({ name: "jira", type: "http", url });
    const app = await createApp();

    const res = await request(app).post("/v1/mcp-servers/jira/test").send({});

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ ok: true, toolCount: 1, tools: [{ name: "get_issue" }] });
  });

  it("allows disabled registered servers because the endpoint validates before enabling", async () => {
    const url = await startFakeMcpServer((_req, res) => {
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ result: { tools: [] } }));
    });
    await registerServer({ name: "disabled", type: "http", url, enabled: false });
    const app = await createApp();

    const res = await request(app).post("/v1/mcp-servers/disabled/test").send({});

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ ok: true, toolCount: 0, tools: [] });
  });

  it("returns MCP_SERVER_NOT_FOUND for unknown servers", async () => {
    const app = await createApp();

    const res = await request(app).post("/v1/mcp-servers/missing/test").send({});

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe("MCP_SERVER_NOT_FOUND");
  });

  it("maps upstream 401/403 to sanitized MCP_AUTH_FAILED", async () => {
    const url = await startFakeMcpServer((_req, res) => {
      res.writeHead(401, { "Content-Type": "text/plain" });
      res.end("bad token Basic USER_X");
    });
    await registerServer({ name: "jira", type: "http", url });
    const app = await createApp();

    const res = await request(app)
      .post("/v1/mcp-servers/jira/test")
      .send({ headers: { Authorization: "Basic USER_X" } });

    expect(res.status).toBe(401);
    expect(res.body.error).toEqual({ code: "MCP_AUTH_FAILED", message: "upstream returned 401" });
    expect(JSON.stringify(res.body)).not.toContain("USER_X");
  });

  it("maps transport failures to sanitized MCP_NETWORK_ERROR", async () => {
    await registerServer({ name: "missing-upstream", type: "http", url: "http://127.0.0.1:9/mcp" });
    const app = await createApp();

    const res = await request(app)
      .post("/v1/mcp-servers/missing-upstream/test")
      .send({ headers: { Authorization: "Basic USER_X" } });

    expect(res.status).toBe(502);
    expect(res.body.error.code).toBe("MCP_NETWORK_ERROR");
    expect(JSON.stringify(res.body)).not.toContain("USER_X");
  });

  it("maps slow upstream responses to MCP_TIMEOUT", async () => {
    const url = await startFakeMcpServer((_req, _res) => {
      // Keep the request open past the test timeout.
    });
    await registerServer({ name: "slow", type: "http", url });
    const app = await createApp();

    const res = await request(app)
      .post("/v1/mcp-servers/slow/test")
      .send({ headers: { Authorization: "Basic USER_X" } });

    expect(res.status).toBe(504);
    expect(res.body.error.code).toBe("MCP_TIMEOUT");
    expect(JSON.stringify(res.body)).not.toContain("USER_X");
  });
});
