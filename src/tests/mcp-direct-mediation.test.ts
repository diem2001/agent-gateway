/**
 * The direct (LLM-free) MCP paths behind the same trusted rules (MVP-7679, Gate C): the direct call refuses a
 * server that requires a user credential before any upstream request, never follows a redirect (call, test and
 * health), and merges credential headers case-insensitively with the override winning, like the relay.
 */
import fs from "node:fs";
import http, { type IncomingHttpHeaders } from "node:http";
import os from "node:os";
import path from "node:path";
import type { AddressInfo } from "node:net";
import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { McpServerDefinition } from "../mcp-registry.js";
import { mergeHeaders } from "../mcp-overrides.js";
import { TEST_OWNER, mountOwnerAuth } from "./helpers/owner-auth.js";

let tempDir: string;
const closers: (() => Promise<void>)[] = [];

beforeEach(() => {
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "mvp7679-direct-"));
  process.env.MCP_SERVERS_PERSIST_PATH = path.join(tempDir, "mcp-servers.json");
  vi.spyOn(console, "log").mockImplementation(() => undefined);
  vi.resetModules();
});

afterEach(async () => {
  while (closers.length > 0) await closers.pop()!();
  vi.restoreAllMocks();
  delete process.env.MCP_SERVERS_PERSIST_PATH;
  await new Promise((resolve) => setTimeout(resolve, 150));
  fs.rmSync(tempDir, { recursive: true, force: true });
});

interface Recorded {
  hits: { method: string; path: string; headers: IncomingHttpHeaders }[];
  origin: string;
}

async function upstream(handler: (req: http.IncomingMessage, res: http.ServerResponse, body: string) => void): Promise<Recorded> {
  const hits: Recorded["hits"] = [];
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      hits.push({ method: req.method ?? "", path: req.url ?? "", headers: req.headers });
      handler(req, res, Buffer.concat(chunks).toString("utf8"));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  closers.push(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
  return { hits, origin: `http://127.0.0.1:${(server.address() as AddressInfo).port}` };
}

const okAnswer = (_req: http.IncomingMessage, res: http.ServerResponse, body: string): void => {
  const message = JSON.parse(body || "{}") as { id?: unknown; method?: string };
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ jsonrpc: "2.0", id: message.id, result: message.method === "tools/list" ? { tools: [{ name: "t" }] } : { content: [{ type: "text", text: "ok" }] } }));
};

async function app() {
  const { default: mcpRoutes } = await import("../routes/mcp.js");
  const server = express();
  server.use(express.json());
  await mountOwnerAuth(server);
  server.use(mcpRoutes);
  return server;
}

async function register(def: Partial<McpServerDefinition> & Pick<McpServerDefinition, "name" | "type">) {
  const { registerMcpServer } = await import("../mcp-registry.js");
  const now = new Date().toISOString();
  registerMcpServer({ description: "", enabled: true, owner: TEST_OWNER, createdAt: now, updatedAt: now, ...def } as McpServerDefinition);
}

describe("mergeHeaders", () => {
  it.each([
    [{ Authorization: "a" }, { authorization: "b" }, { authorization: "b" }],
    [{ authorization: "a" }, { Authorization: "b" }, { Authorization: "b" }],
    [{ AUTHORIZATION: "a", "X-Static": "s" }, { authorization: "b" }, { "X-Static": "s", authorization: "b" }],
    [{}, { A: "1" }, { A: "1" }],
    [{ A: "1" }, {}, { A: "1" }],
    [{ A: "1", a: "2" }, {}, { a: "2" }],
    [{}, { A: "1", a: "2" }, { a: "2" }],
  ])("%j + %j = %j", (base, override, expected) => {
    expect(mergeHeaders(base, override)).toEqual(expected);
  });
});

describe("the direct call", () => {
  it("a server that requires a user credential is refused with 401 MCP_AUTH_FAILED before any upstream request when none is given", async () => {
    const up = await upstream(okAnswer);
    await register({ name: "aida", type: "http", url: `${up.origin}/mcp`, headers: { Authorization: "Basic SHARED" }, requireUserCredentials: true });
    const server = await app();
    for (const credentials of [undefined, {}, { headers: {} }, { headers: { Authorization: "" } }, { env: { TOKEN: "x" } }]) {
      const res = await request(server).post("/v1/mcp-servers/aida/call").send({ tool: "t", arguments: {}, ...(credentials ? { credentials } : {}) });
      expect(res.status, JSON.stringify(credentials)).toBe(401);
      expect(res.body).toEqual({ error: { code: "MCP_AUTH_FAILED", message: "this server requires the user's credential and none was provided" } });
    }
    expect(up.hits).toEqual([]);
  });

  it("with the user's credential the call goes upstream with that credential only", async () => {
    const up = await upstream(okAnswer);
    await register({ name: "aida", type: "http", url: `${up.origin}/mcp`, headers: { Authorization: "Basic SHARED", "X-Static": "s" }, requireUserCredentials: true });
    const server = await app();
    const res = await request(server).post("/v1/mcp-servers/aida/call").send({ tool: "t", arguments: {}, credentials: { headers: { authorization: "Bearer USER" } } });
    expect(res.status).toBe(200);
    expect(up.hits).toHaveLength(1);
    // One case-insensitive merge: the user's value replaced the shared one, whatever the casing.
    expect(up.hits[0].headers.authorization).toBe("Bearer USER");
    expect(up.hits[0].headers["x-static"]).toBe("s");
  });

  it("a server without the flag still works without a credential (unchanged)", async () => {
    const up = await upstream(okAnswer);
    await register({ name: "jira", type: "http", url: `${up.origin}/mcp`, headers: { Authorization: "Basic SHARED" } });
    const res = await request(await app()).post("/v1/mcp-servers/jira/call").send({ tool: "t", arguments: {} });
    expect(res.status).toBe(200);
    expect(up.hits[0].headers.authorization).toBe("Basic SHARED");
  });

  it.each([301, 302, 307, 308])("a %i answer is not followed: 502 MCP_NETWORK_ERROR and the target gets no request and no credential", async (status) => {
    const target = await upstream(okAnswer);
    const up = await upstream((_req, res) => {
      res.writeHead(status, { Location: `${target.origin}/collect` });
      res.end();
    });
    await register({ name: "jira", type: "http", url: `${up.origin}/mcp`, headers: { Authorization: "Basic SHARED" } });
    const res = await request(await app()).post("/v1/mcp-servers/jira/call").send({ tool: "t", arguments: {} });
    expect(res.status).toBe(502);
    expect(res.body.error.code).toBe("MCP_NETWORK_ERROR");
    expect(JSON.stringify(res.body)).not.toContain(target.origin);
    expect(target.hits).toEqual([]);
  });
});

describe("the test endpoint and the health check", () => {
  it("a redirect on the test endpoint is not followed", async () => {
    const target = await upstream(okAnswer);
    const up = await upstream((_req, res) => {
      res.writeHead(302, { Location: `${target.origin}/collect` });
      res.end();
    });
    await register({ name: "jira", type: "http", url: `${up.origin}/mcp`, headers: { Authorization: "Basic SHARED" } });
    const res = await request(await app()).post("/v1/mcp-servers/jira/test").send({});
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(JSON.stringify(res.body)).not.toContain(target.origin);
    expect(target.hits).toEqual([]);
  });

  it("a redirect on the health check is an error and the target gets no request", async () => {
    const target = await upstream(okAnswer);
    const up = await upstream((_req, res) => {
      res.writeHead(302, { Location: `${target.origin}/health` });
      res.end();
    });
    const { checkMcpServerHealth } = await import("../mcp-registry.js");
    const result = await checkMcpServerHealth({ name: "jira", description: "", enabled: true, type: "http", url: `${up.origin}/mcp`, headers: { Authorization: "Basic SHARED" }, createdAt: "", updatedAt: "" });
    expect(result).toEqual({ status: "error", detail: "HTTP 302" });
    expect(target.hits).toEqual([]);
  });

  it("the test endpoint merges headers case-insensitively with the override winning", async () => {
    const up = await upstream(okAnswer);
    await register({ name: "jira", type: "http", url: `${up.origin}/mcp`, headers: { Authorization: "Basic SHARED" } });
    const res = await request(await app()).post("/v1/mcp-servers/jira/test").send({ headers: { authorization: "Bearer USER" } });
    expect(res.status).toBe(200);
    expect(up.hits[0].headers.authorization).toBe("Bearer USER");
  });
});
