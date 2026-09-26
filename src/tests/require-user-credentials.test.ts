/**
 * Registry field `requireUserCredentials` (DEC-AIDA-001 = A) and the
 * header/env validation that guards every credential entry point.
 *
 * Run attachment goes through the real query.ts + retry.ts + agent.ts path with
 * only the Claude Agent SDK boundary mocked, so the tests observe the exact
 * `options` the SDK receives. The real-runtime proof (no request reaches a
 * left-out server) is in sdk-login-guard-process.test.ts.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { McpServerDefinition, UserCredentialSchema } from "../mcp-registry.js";
import { RELAY_URL, startRecordingUpstream, touchHttpMcpServers, type RecordingUpstream } from "./helpers/relay-upstream.js";

let capturedOptions: Array<Record<string, unknown>> = [];
let logs: string[] = [];
let tempDir = "";
let upstream: RecordingUpstream;

beforeEach(async () => {
  vi.resetModules();
  capturedOptions = [];
  logs = [];
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "mvp7667-require-"));
  process.env.MCP_SERVERS_PERSIST_PATH = path.join(tempDir, "mcp-servers.json");
  vi.spyOn(console, "log").mockImplementation((...args) => {
    logs.push(args.map(String).join(" "));
  });
  vi.doMock("@anthropic-ai/claude-agent-sdk", () => ({
    createSdkMcpServer: vi.fn((options) => ({ type: "sdk", name: options.name })),
    query: vi.fn(({ options }) => {
      capturedOptions.push(options as Record<string, unknown>);
      return (async function* () {
        // The runtime's part: use each registered http server through its relay URL.
        await touchHttpMcpServers(options as Record<string, unknown>);
        yield { type: "assistant", message: { content: [{ type: "text", text: "ack" }] } };
        yield { type: "result", usage: { input_tokens: 1, output_tokens: 1 }, total_cost_usd: 0, sessionId: "sdk-session" };
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
  await upstream.close();
  vi.restoreAllMocks();
  vi.doUnmock("@anthropic-ai/claude-agent-sdk");
  delete process.env.MCP_SERVERS_PERSIST_PATH;
  // The registry persists 100 ms after a change; let that write land before removing its directory.
  await new Promise((resolve) => setTimeout(resolve, 150));
  fs.rmSync(tempDir, { recursive: true, force: true });
});

async function createApp() {
  const { queryRouter } = await import("../query.js");
  const { default: mcpRoutes } = await import("../routes/mcp.js");
  const app = express();
  app.use(express.json());
  app.use(queryRouter);
  app.use(mcpRoutes);
  return app;
}

const AIDA_SCHEMA: UserCredentialSchema = {
  fields: [
    { key: "token", label: "Token", type: "password", required: true },
    { key: "tenant", label: "Tenant", type: "text", required: true },
  ],
  outputs: [
    { target: "headers", outputKey: "Authorization", template: "Bearer {token}" },
    { target: "headers", outputKey: "X-Tenant", template: "{tenant}" },
  ],
};

async function register(app: express.Express, name: string, body: Partial<McpServerDefinition>) {
  const res = await request(app).put(`/v1/mcp-servers/${name}`).send(body);
  expect(res.status).toBeLessThan(300);
}

/** Registers the flagged `aida` (http) and the unflagged `jira` (http, static header). */
async function registerAidaAndJira(app: express.Express, aida: Partial<McpServerDefinition> = {}) {
  await register(app, "aida", { type: "http", url: `${upstream.origin}/aida`, headers: { "X-Static": "s" }, requireUserCredentials: true, ...aida });
  await register(app, "jira", { type: "http", url: `${upstream.origin}/jira`, headers: { Authorization: "Basic STATIC" } });
}

async function runQuery(app: express.Express, extra: Record<string, unknown> = {}) {
  capturedOptions = [];
  const res = await request(app).post("/v1/query").send({ queryId: `q-${Math.random()}`, prompt: "go", useSession: false, ...extra });
  expect(res.status).toBe(200);
  expect(capturedOptions).toHaveLength(1);
  const options = capturedOptions[0];
  return {
    servers: (options.mcpServers ?? {}) as Record<string, { url?: string; headers?: Record<string, string>; env?: Record<string, string>; command?: string }>,
    allowedTools: options.allowedTools as string[],
  };
}

const omittedLine = (name: string) => `mcp.server.omitted serverName=${name} reason=missing_user_credential`;

describe("requireUserCredentials: a flagged server is left out of runs without the user's credential", () => {
  const missing: [string, Record<string, unknown> | undefined][] = [
    ["no mcpCredentialOverrides at all", undefined],
    ["no entry for aida", { jira: { headers: { Authorization: "Basic USER" } } }],
    ["an empty entry", { aida: {} }],
    ["an entry with only empty values", { aida: { headers: { Authorization: "" } } }],
    ["an entry for the wrong target (env on an http server)", { aida: { env: { TOKEN: "t" } } }],
  ];

  for (const [label, overrides] of missing) {
    it(`${label}: aida is absent, its tools are not allowed, an audit line names it`, async () => {
      const app = await createApp();
      await registerAidaAndJira(app);

      const { servers, allowedTools } = await runQuery(app, overrides ? { mcpCredentialOverrides: overrides } : {});

      expect(Object.keys(servers)).not.toContain("aida");
      expect(allowedTools).not.toContain("mcp__aida__*");
      expect(logs.join("\n")).toContain(omittedLine("aida"));
      expect(upstream.headersAt("/aida")).toEqual([]);
      // The unflagged server is attached as before.
      expect(servers.jira).toEqual({ type: "http", url: expect.stringMatching(RELAY_URL) });
      expect(allowedTools).toContain("mcp__jira__*");
    });
  }

  it("a full entry: aida is attached with the overridden Authorization, merged over its static headers", async () => {
    const app = await createApp();
    await registerAidaAndJira(app);

    const { servers, allowedTools } = await runQuery(app, { mcpCredentialOverrides: { aida: { headers: { Authorization: "Bearer USER_TOKEN" } } } });

    expect(servers.aida).toEqual({ type: "http", url: expect.stringMatching(RELAY_URL) });
    expect(upstream.headersAt("/aida")).toEqual([expect.objectContaining({ "x-static": "s", authorization: "Bearer USER_TOKEN" })]);
    expect(allowedTools).toContain("mcp__aida__*");
    expect(logs.join("\n")).not.toContain(omittedLine("aida"));
  });

  it("with a userCredentialSchema, a partial entry is missing and a full one attaches", async () => {
    const app = await createApp();
    await registerAidaAndJira(app, { userCredentialSchema: AIDA_SCHEMA });

    const partial = await runQuery(app, { mcpCredentialOverrides: { aida: { headers: { Authorization: "Bearer T" } } } });
    expect(Object.keys(partial.servers)).not.toContain("aida");

    const emptyKey = await runQuery(app, { mcpCredentialOverrides: { aida: { headers: { Authorization: "Bearer T", "X-Tenant": "" } } } });
    expect(Object.keys(emptyKey.servers)).not.toContain("aida");

    expect(upstream.headersAt("/aida")).toEqual([]);

    const full = await runQuery(app, { mcpCredentialOverrides: { aida: { headers: { Authorization: "Bearer T", "X-Tenant": "acme" } } } });
    expect(full.servers.aida?.url).toMatch(RELAY_URL);
    expect(upstream.headersAt("/aida")).toEqual([expect.objectContaining({ authorization: "Bearer T", "x-tenant": "acme" })]);
  });

  it("a custom allowedToolsPattern is removed with the server and kept when it is attached", async () => {
    const app = await createApp();
    await registerAidaAndJira(app, { allowedToolsPattern: "mcp__aida__search_*" });

    const without = await runQuery(app);
    expect(without.allowedTools).not.toContain("mcp__aida__search_*");

    const withCredential = await runQuery(app, { mcpCredentialOverrides: { aida: { headers: { Authorization: "Bearer T" } } } });
    expect(withCredential.allowedTools).toContain("mcp__aida__search_*");
  });

  it("a request-supplied server cannot take the name of a left-out server", async () => {
    const app = await createApp();
    await registerAidaAndJira(app);

    const { servers, allowedTools } = await runQuery(app, { mcpServers: { aida: { command: "node", args: ["impostor.js"] } } });

    expect(Object.keys(servers)).not.toContain("aida");
    expect(allowedTools).not.toContain("mcp__aida__*");
  });

  it("a flagged stdio server needs a non-empty env value", async () => {
    const app = await createApp();
    await register(app, "local", { type: "stdio", command: "node", args: ["server.js"], requireUserCredentials: true });

    const without = await runQuery(app, { mcpCredentialOverrides: { local: { env: { TOKEN: "" } } } });
    expect(Object.keys(without.servers)).not.toContain("local");

    const withCredential = await runQuery(app, { mcpCredentialOverrides: { local: { env: { TOKEN: "user-token" } } } });
    expect(withCredential.servers.local).toEqual({ command: "node", args: ["server.js"], env: { TOKEN: "user-token" } });
  });

  it("every server without the flag (absent or false) behaves exactly as before, with and without overrides", async () => {
    const app = await createApp();
    await register(app, "jira", { type: "http", url: `${upstream.origin}/jira`, headers: { Authorization: "Basic STATIC" } });
    await register(app, "wiki", { type: "http", url: `${upstream.origin}/wiki`, requireUserCredentials: false });
    await register(app, "local", { type: "stdio", command: "node", args: ["server.js"], env: { TOKEN: "static" } });

    const plain = await runQuery(app);
    expect(plain.servers).toEqual({
      jira: { type: "http", url: expect.stringMatching(RELAY_URL) },
      wiki: { type: "http", url: expect.stringMatching(RELAY_URL) },
      local: { command: "node", args: ["server.js"], env: { TOKEN: "static" } },
    });
    expect(plain.allowedTools).toEqual(expect.arrayContaining(["mcp__jira__*", "mcp__wiki__*", "mcp__local__*"]));
    expect(upstream.headersAt("/jira").map((h) => h.authorization)).toEqual(["Basic STATIC"]);
    expect(upstream.headersAt("/wiki").map((h) => h.authorization)).toEqual([undefined]);

    const overridden = await runQuery(app, { mcpCredentialOverrides: { jira: { headers: { Authorization: "Basic USER" } } } });
    expect(overridden.servers.wiki).toEqual({ type: "http", url: expect.stringMatching(RELAY_URL) });
    expect(upstream.headersAt("/jira").map((h) => h.authorization)).toEqual(["Basic STATIC", "Basic USER"]);
    expect(logs.join("\n")).not.toContain("mcp.server.omitted");
  });
});

describe("requireUserCredentials in the registry API", () => {
  it("round-trips through PUT, detail, list, persistence and reload; absent when not sent", async () => {
    const app = await createApp();
    const put = await request(app).put("/v1/mcp-servers/aida").send({ type: "http", url: "http://aida.invalid/mcp", requireUserCredentials: true });
    await request(app).put("/v1/mcp-servers/jira").send({ type: "http", url: "http://jira.invalid/mcp" });

    expect(put.status).toBe(201);
    expect(put.body.requireUserCredentials).toBe(true);
    expect((await request(app).get("/v1/mcp-servers/aida")).body.requireUserCredentials).toBe(true);
    const list = (await request(app).get("/v1/mcp-servers")).body.servers as McpServerDefinition[];
    expect(list.find((s) => s.name === "aida")?.requireUserCredentials).toBe(true);
    expect("requireUserCredentials" in list.find((s) => s.name === "jira")!).toBe(false);

    await new Promise((resolve) => setTimeout(resolve, 150));
    const persisted = JSON.parse(fs.readFileSync(process.env.MCP_SERVERS_PERSIST_PATH!, "utf8")) as McpServerDefinition[];
    expect(persisted.find((s) => s.name === "aida")?.requireUserCredentials).toBe(true);

    vi.resetModules();
    const registry = await import("../mcp-registry.js");
    registry.loadMcpServers();
    expect(registry.getMcpServer("aida")?.requireUserCredentials).toBe(true);
  });

  it("a PUT without the field clears it; /restart keeps it", async () => {
    const app = await createApp();
    await request(app).put("/v1/mcp-servers/aida").send({ type: "http", url: "http://aida.invalid/mcp", requireUserCredentials: true });

    await request(app).post("/v1/mcp-servers/aida/restart").send({});
    expect((await request(app).get("/v1/mcp-servers/aida")).body.requireUserCredentials).toBe(true);

    await request(app).put("/v1/mcp-servers/aida").send({ type: "http", url: "http://aida.invalid/mcp" });
    expect("requireUserCredentials" in (await request(app).get("/v1/mcp-servers/aida")).body).toBe(false);
  });

  it("a non-boolean value → 400", async () => {
    const app = await createApp();
    const res = await request(app).put("/v1/mcp-servers/aida").send({ type: "http", url: "http://aida.invalid/mcp", requireUserCredentials: "yes" });
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: "requireUserCredentials must be a boolean" });
  });

  it("true together with type sse → 400; false with sse is accepted", async () => {
    const app = await createApp();
    const refused = await request(app).put("/v1/mcp-servers/aida").send({ type: "sse", url: "http://aida.invalid/sse", requireUserCredentials: true });
    expect(refused.status).toBe(400);
    expect(refused.body).toEqual({ error: "requireUserCredentials is not supported for sse transport" });

    const accepted = await request(app).put("/v1/mcp-servers/aida").send({ type: "sse", url: "http://aida.invalid/sse", requireUserCredentials: false });
    expect(accepted.status).toBe(201);
  });
});

describe("header and env values that cannot be sent are refused on every credential entry point", () => {
  const BAD_HEADERS: [string, Record<string, string>][] = [
    ["a CR/LF in a value", { Authorization: "Bearer A\r\nX-Injected: 1" }],
    ["a NUL in a value", { Authorization: "Bearer A\u0000B" }],
    ["a name that is not a token", { "Bad Name": "v" }],
  ];

  for (const [label, headers] of BAD_HEADERS) {
    it(`${label}: PUT, mcpCredentialOverrides, /test and /call answer 400 without echoing the value`, async () => {
      const app = await createApp();
      await request(app).put("/v1/mcp-servers/jira").send({ type: "http", url: "http://127.0.0.1:9/mcp" });

      const put = await request(app).put("/v1/mcp-servers/other").send({ type: "http", url: "http://127.0.0.1:9/mcp", headers });
      expect(put.status).toBe(400);
      expect(put.body).toEqual({ error: "headers holds a name or value that cannot be sent as an HTTP header" });

      const query = await request(app).post("/v1/query").send({ queryId: "q-bad", prompt: "go", mcpCredentialOverrides: { jira: { headers } } });
      expect(query.status).toBe(400);
      expect(query.body).toEqual({ error: { code: "MCP_OVERRIDE_INVALID", message: "jira.headers holds a name or value that cannot be sent as an HTTP header" } });

      const test = await request(app).post("/v1/mcp-servers/jira/test").send({ headers });
      expect(test.status).toBe(400);
      expect(test.body.error.code).toBe("MCP_OVERRIDE_INVALID");

      const call = await request(app).post("/v1/mcp-servers/jira/call").send({ tool: "t", arguments: {}, credentials: { headers } });
      expect(call.status).toBe(400);
      expect(call.body).toEqual({ error: { code: "MCP_OVERRIDE_INVALID", message: "credentials.headers holds a name or value that cannot be sent as an HTTP header" } });

      expect(capturedOptions).toHaveLength(0);
    });
  }

  it("a non-string header map on PUT → 400", async () => {
    const app = await createApp();
    const res = await request(app).put("/v1/mcp-servers/other").send({ type: "http", url: "http://127.0.0.1:9/mcp", headers: { Authorization: 42 } });
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: "headers must be a string map" });
  });

  it("a NUL in an env value → 400 on PUT and in mcpCredentialOverrides", async () => {
    const app = await createApp();
    await request(app).put("/v1/mcp-servers/local").send({ type: "stdio", command: "node" });

    const put = await request(app).put("/v1/mcp-servers/other").send({ type: "stdio", command: "node", env: { TOKEN: "a\u0000b" } });
    expect(put.status).toBe(400);
    expect(put.body).toEqual({ error: "env holds a name or value that cannot be passed to a process" });

    const query = await request(app).post("/v1/query").send({ queryId: "q-env", prompt: "go", mcpCredentialOverrides: { local: { env: { TOKEN: "a\u0000b" } } } });
    expect(query.status).toBe(400);
    expect(query.body.error.code).toBe("MCP_OVERRIDE_INVALID");
  });
});
