/**
 * Health, test and call failures name a fixed category and never quote stored configuration (MVP-7957): a legacy
 * stored header whose name or value cannot be sent, a stored address that cannot be used (user info, unparsable,
 * not http(s)) and an unreachable upstream each answer with one fixed text; the markers planted in the stored values
 * appear in no response and no log line, and no request leaves the gateway for a value it cannot send. Controls: an
 * authorized /test and /call still send the stored header, and a registered stdio entry still hands the trusted
 * execution path its stored args.
 */
import fs from "node:fs";
import http, { type Server } from "node:http";
import os from "node:os";
import path from "node:path";
import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { McpServerDefinition } from "../mcp-registry.js";
import { TEST_OWNER, mountOwnerAuth } from "./helpers/owner-auth.js";

const MARKER = "FAIL-MARKER-7957-gggg7777";
const TEXT = {
  header: "a stored header of this server cannot be sent",
  address: "the stored server address cannot be used",
  unreachable: "the MCP server could not be reached",
};

let tempDir = "";
let servers: Server[] = [];
let logs: string[] = [];

beforeEach(() => {
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gateway-failure-text-"));
  process.env.MCP_SERVERS_PERSIST_PATH = path.join(tempDir, "mcp-servers.json");
  process.env.MCP_TEST_TIMEOUT_MS = "500";
  process.env.MCP_CALL_TIMEOUT_MS = "500";
  servers = [];
  logs = [];
  for (const method of ["log", "error", "warn"] as const) {
    vi.spyOn(console, method).mockImplementation((...args) => {
      logs.push(args.map(String).join(" "));
    });
  }
  vi.resetModules();
});

afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(servers.map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  delete process.env.MCP_SERVERS_PERSIST_PATH;
  delete process.env.MCP_TEST_TIMEOUT_MS;
  delete process.env.MCP_CALL_TIMEOUT_MS;
  await new Promise((resolve) => setTimeout(resolve, 150));
  fs.rmSync(tempDir, { recursive: true, force: true });
});

async function createApp() {
  const { default: mcpRoutes } = await import("../routes/mcp.js");
  const app = express();
  app.use(express.json());
  await mountOwnerAuth(app);
  app.use(mcpRoutes);
  return app;
}

async function seed(name: string, fields: Record<string, unknown>) {
  const { registerMcpServer } = await import("../mcp-registry.js");
  const now = new Date().toISOString();
  registerMcpServer({ name, description: "", enabled: true, type: "http", owner: TEST_OWNER, createdAt: now, updatedAt: now, ...fields } as McpServerDefinition);
}

async function startUpstream(handler?: (req: http.IncomingMessage, res: http.ServerResponse) => void) {
  const hits: Array<{ headers: http.IncomingHttpHeaders }> = [];
  const server = http.createServer((req, res) => {
    hits.push({ headers: req.headers });
    if (handler) return handler(req, res);
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { tools: [{ name: "echo" }], content: [{ type: "text", text: "ok" }] } }));
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("upstream did not bind a port");
  return { url: `http://127.0.0.1:${address.port}/mcp`, hits };
}

type Route = "health" | "test" | "call";
const ROUTES: Route[] = ["health", "test", "call"];

async function hit(app: express.Express, name: string, route: Route) {
  if (route === "health") return request(app).get(`/v1/mcp-servers/${name}/health`);
  if (route === "test") return request(app).post(`/v1/mcp-servers/${name}/test`).send({});
  return request(app).post(`/v1/mcp-servers/${name}/call`).send({ tool: "echo", arguments: {} });
}

/** The fixed failure as the route answers it: the error envelope for test/call, the health detail for health. */
function expectFixed(route: Route, res: request.Response, text: string) {
  if (route === "health") {
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ status: "error", detail: text });
  } else {
    expect(res.status).toBe(502);
    expect(res.body).toEqual({ error: { code: "MCP_NETWORK_ERROR", message: text } });
  }
  expect(res.text).not.toContain(MARKER);
  expect(logs.join("\n")).not.toContain(MARKER);
}

describe("a stored header that cannot be sent", () => {
  const cases: Array<[string, Record<string, string>]> = [
    ["a value with CR and LF", { Authorization: `Bearer ${MARKER}\r\nX-Evil: 1` }],
    ["a name with a space", { [`X-Bad Name ${MARKER}`]: "value" }],
    ["a name with a line break", { [`X-Bad\nName-${MARKER}`]: "value" }],
    ["a value with NUL", { Authorization: `Bearer ${MARKER}\0` }],
  ];

  for (const [label, headers] of cases) {
    for (const route of ROUTES) {
      it(`${label}: ${route} answers the fixed header text, sends nothing and echoes no marker`, async () => {
        const upstream = await startUpstream();
        await seed("legacy", { url: upstream.url, headers });
        const res = await hit(await createApp(), "legacy", route);
        expectFixed(route, res, TEXT.header);
        expect(upstream.hits).toEqual([]);
      });
    }
  }

  it("the audit lines of test and call carry reason=header and no value", async () => {
    const upstream = await startUpstream();
    await seed("legacy", { url: upstream.url, headers: { Authorization: `Bearer ${MARKER}\r\nX: 1` } });
    const app = await createApp();
    await hit(app, "legacy", "test");
    await hit(app, "legacy", "call");
    expect(logs).toContain("[audit] mcp.test.called serverName=legacy result=network_error reason=header");
    expect(logs).toContain("[audit] mcp.call.called serverName=legacy tool=echo result=network_error reason=header");
  });
});

describe("a stored address that cannot be used", () => {
  const cases: Array<[string, unknown]> = [
    ["user info", `http://${MARKER}:pw@127.0.0.1:9/mcp`],
    ["an unparsable string", `not a url ${MARKER}`],
    ["a non-http scheme", `ftp://127.0.0.1/${MARKER}`],
    ["null", null],
    ["a number", 42],
  ];

  for (const [label, url] of cases) {
    for (const route of ROUTES) {
      it(`${label}: ${route} answers the fixed address text and echoes no marker`, async () => {
        await seed("legacy", { url, headers: { Authorization: `Bearer ${MARKER}` } });
        const res = await hit(await createApp(), "legacy", route);
        expectFixed(route, res, TEXT.address);
      });
    }
  }

  it("the audit lines carry reason=address", async () => {
    await seed("legacy", { url: `http://${MARKER}@127.0.0.1:9/mcp` });
    const app = await createApp();
    await hit(app, "legacy", "test");
    await hit(app, "legacy", "call");
    expect(logs).toContain("[audit] mcp.test.called serverName=legacy result=network_error reason=address");
    expect(logs).toContain("[audit] mcp.call.called serverName=legacy tool=echo result=network_error reason=address");
  });
});

describe("an unreachable upstream", () => {
  for (const route of ROUTES) {
    it(`${route}: the fixed unreachable text, not the transport library's message`, async () => {
      await seed("dead", { url: "http://127.0.0.1:9/mcp", headers: { Authorization: `Bearer ${MARKER}` } });
      const res = await hit(await createApp(), "dead", route);
      expectFixed(route, res, TEXT.unreachable);
      expect(res.text).not.toMatch(/fetch failed|ECONNREFUSED/i);
    });
  }

  it("the audit lines carry reason=unreachable", async () => {
    await seed("dead", { url: "http://127.0.0.1:9/mcp" });
    const app = await createApp();
    await hit(app, "dead", "test");
    await hit(app, "dead", "call");
    expect(logs).toContain("[audit] mcp.test.called serverName=dead result=network_error reason=unreachable");
    expect(logs).toContain("[audit] mcp.call.called serverName=dead tool=echo result=network_error reason=unreachable");
  });
});

describe("controls: authorized use still sees the stored values", () => {
  it("/test and /call send the stored header and return the upstream's own answer unchanged", async () => {
    const upstream = await startUpstream();
    await seed("jira", { url: upstream.url, headers: { Authorization: "Basic STORED-7957" } });
    const app = await createApp();

    const test = await hit(app, "jira", "test");
    expect(test.status).toBe(200);
    expect(test.body).toEqual({ ok: true, toolCount: 1, tools: [{ name: "echo" }] });
    const call = await hit(app, "jira", "call");
    expect(call.status).toBe(200);
    expect(call.body).toEqual({ tools: [{ name: "echo" }], content: [{ type: "text", text: "ok" }] });
    expect(upstream.hits.map((h) => h.headers.authorization)).toEqual(["Basic STORED-7957", "Basic STORED-7957"]);
  });

  it("health sends the stored header too and keeps the upstream's health answer", async () => {
    const upstream = await startUpstream((_req, res) => {
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ status: "up" }));
    });
    await seed("jira", { url: upstream.url, headers: { Authorization: "Basic STORED-7957" } });
    const res = await hit(await createApp(), "jira", "health");
    expect(res.body).toEqual({ name: "jira", status: "ok", detail: JSON.stringify({ status: "up" }) });
    expect(upstream.hits[0].headers.authorization).toBe("Basic STORED-7957");
  });

  it("the trusted execution path still receives the stored stdio args, though no client can read them", async () => {
    await seed("local", { type: "stdio", command: "node", args: ["server.js", `--token=${MARKER}`] });
    const { buildMcpServersForSdk, getMcpServer } = await import("../mcp-registry.js");
    const config = buildMcpServersForSdk([getMcpServer("local")!]);
    expect(config).toEqual({ local: { command: "node", args: ["server.js", `--token=${MARKER}`] } });
  });
});
