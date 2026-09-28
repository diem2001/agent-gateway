/**
 * Every Examples row of "Credential values never reach the log" (MVP-7667):
 * the gateway's parsers, logging middleware, query and registry routes and
 * global error handler at debug level, with only the Claude Agent SDK boundary
 * mocked. Sentinels are distinct random alphanumeric strings; each body is
 * padded so that an unredacted log line would be cut inside a sentinel, and no
 * 6-character window of any sentinel may appear in any captured line.
 */
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { McpServerDefinition } from "../mcp-registry.js";
import { RELAY_URL, startRecordingUpstream, touchHttpMcpServers, type RecordingUpstream } from "./helpers/relay-upstream.js";

let logs: string[] = [];

async function registerServer(def: Partial<McpServerDefinition> & Pick<McpServerDefinition, "name" | "type">) {
  const { registerMcpServer } = await import("../mcp-registry.js");
  const now = new Date().toISOString();
  registerMcpServer({ description: "", enabled: true, createdAt: now, updatedAt: now, ...def } as McpServerDefinition);
}

const BASE62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const REQUEST_CUT = 2000;
const RESPONSE_CUT = 500;
/** A sentinel starts this many characters before a cut, so an unredacted log line would end inside it. */
const INSIDE_CUT = 8;

/** A distinct random alphanumeric credential of 24 characters. */
function sentinel(): string {
  const bytes = randomBytes(24);
  return Array.from(bytes, (b) => BASE62[b % BASE62.length]).join("");
}

/** Every 6-character window of every sentinel that appears in a captured line. */
function leakedFragments(lines: string[], sentinels: string[]): string[] {
  const text = lines.join("\n");
  const leaks: string[] = [];
  for (const s of sentinels) {
    for (let i = 0; i + 6 <= s.length; i++) if (text.includes(s.slice(i, i + 6))) leaks.push(s.slice(i, i + 6));
  }
  return leaks;
}

/** Padding that puts `needle` at `target` in JSON.stringify(build(padding)). */
function padFor(build: (pad: string) => unknown, needle: string, target: number): string {
  const index = JSON.stringify(build("")).indexOf(needle);
  if (index < 0 || index > target) throw new Error("needle not found or already past the target");
  return "p".repeat(target - index);
}

describe("credential values never reach the log (every Examples row)", { timeout: 20_000 }, () => {
  let persistDir = "";
  let upstream: RecordingUpstream | null = null;

  beforeEach(async () => {
    vi.resetModules();
    logs = [];
    persistDir = fs.mkdtempSync(path.join(os.tmpdir(), "mvp7667-redaction-"));
    process.env.MCP_SERVERS_PERSIST_PATH = path.join(persistDir, "mcp-servers.json");
    for (const method of ["log", "error", "warn"] as const) {
      vi.spyOn(console, method).mockImplementation((...args) => {
        logs.push(args.map(String).join(" "));
      });
    }
    // A non-empty answer, so the retry layer runs the query exactly once.
    vi.doMock("@anthropic-ai/claude-agent-sdk", () => ({
      createSdkMcpServer: vi.fn((options) => ({ type: "sdk", name: options.name })),
      query: vi.fn(({ options }) =>
        (async function* () {
          // The runtime's part: use each registered http server through its relay URL.
          await touchHttpMcpServers(options as Record<string, unknown>);
          yield { type: "assistant", message: { content: [{ type: "text", text: "ok" }] } };
          yield { type: "result", usage: {}, total_cost_usd: 0, sessionId: "sdk-session" };
        })(),
      ),
    }));
    upstream = await startRecordingUpstream();
    const { credentialRelay } = await import("../mcp-credential-relay.js");
    await credentialRelay.start();
  });

  afterEach(async () => {
    const { credentialRelay } = await import("../mcp-credential-relay.js");
    await credentialRelay.close();
    const { setLogLevel } = await import("../logging.js");
    setLogLevel("info");
    await upstream?.close();
    upstream = null;
    vi.restoreAllMocks();
    vi.doUnmock("@anthropic-ai/claude-agent-sdk");
    delete process.env.MCP_SERVERS_PERSIST_PATH;
    // The registry persists 100 ms after a change; let that write land before removing its directory.
    await new Promise((resolve) => setTimeout(resolve, 150));
    fs.rmSync(persistDir, { recursive: true, force: true });
  });

  /** The gateway's parsers, logging middleware, query and registry routes and global error handler, at debug level. */
  async function gatewayApp() {
    const { requestLoggingMiddleware, setLogLevel, globalErrorHandler } = await import("../logging.js");
    const { queryRouter } = await import("../query.js");
    const { default: mcpRoutes } = await import("../routes/mcp.js");
    setLogLevel("debug");
    const app = express();
    app.use(express.json({ limit: "25mb" }));
    app.use(express.text({ limit: "10mb", type: "text/*" }));
    app.use(requestLoggingMiddleware);
    app.use(queryRouter);
    app.use(mcpRoutes);
    app.use(globalErrorHandler);
    return app;
  }

  async function sdkOptions(): Promise<Record<string, unknown>> {
    const sdk = await import("@anthropic-ai/claude-agent-sdk");
    const calls = (sdk.query as unknown as { mock: { calls: [{ options: Record<string, unknown> }][] } }).mock.calls;
    expect(calls.length).toBe(1);
    return calls[0][0].options;
  }

  it("POST /v1/query with mcpServers[*].headers: the log shows [REDACTED], the MCP client gets the real value", async () => {
    const app = await gatewayApp();
    const secret = sentinel();
    const build = (pad: string) => ({
      queryId: "q-headers",
      prompt: `p${pad}`,
      mcpServers: { remote: { type: "http", url: "http://127.0.0.1:9/mcp", headers: { Authorization: `Bearer ${secret}` } } },
    });
    const body = build(padFor(build, `Bearer ${secret}`, REQUEST_CUT - INSIDE_CUT));
    expect(JSON.stringify(body).indexOf(secret)).toBeLessThan(REQUEST_CUT);
    expect(JSON.stringify(body).indexOf(secret) + secret.length).toBeGreaterThan(REQUEST_CUT);
    logs = [];

    const res = await request(app).post("/v1/query").send(body);

    expect(res.status).toBe(200);
    // The cut falls right after the credential's position, so only the start of the marker is visible.
    expect(logs.join("\n")).toContain('"headers":{"Authorization":"[REDACT');
    expect(leakedFragments(logs, [secret])).toEqual([]);
    const servers = (await sdkOptions()).mcpServers as Record<string, { headers?: Record<string, string> }>;
    expect(servers.remote.headers?.Authorization).toBe(`Bearer ${secret}`);
  });

  it("POST /v1/query with mcpServers[*].env: the log shows [REDACTED], the MCP client gets the real value", async () => {
    const app = await gatewayApp();
    const secret = sentinel();
    const build = (pad: string) => ({
      queryId: "q-env",
      prompt: `p${pad}`,
      mcpServers: { local: { command: "node", args: ["server.js"], env: { API_TOKEN: secret } } },
    });
    const body = build(padFor(build, secret, REQUEST_CUT - INSIDE_CUT));
    logs = [];

    const res = await request(app).post("/v1/query").send(body);

    expect(res.status).toBe(200);
    expect(logs.join("\n")).toContain('"env":{"API_TOKEN":"[REDACT');
    expect(leakedFragments(logs, [secret])).toEqual([]);
    const servers = (await sdkOptions()).mcpServers as Record<string, { env?: Record<string, string> }>;
    expect(servers.local.env?.API_TOKEN).toBe(secret);
  });

  it("POST /v1/query with mcpCredentialOverrides: unchanged redaction, the MCP client gets the real value", async () => {
    await registerServer({ name: "jira", type: "http", url: `${upstream!.origin}/mcp` });
    const app = await gatewayApp();
    const secret = sentinel();
    const build = (pad: string) => ({
      queryId: "q-overrides",
      prompt: `p${pad}`,
      mcpCredentialOverrides: { jira: { headers: { Authorization: `Basic ${secret}` } } },
    });
    const body = build(padFor(build, `Basic ${secret}`, REQUEST_CUT - INSIDE_CUT));
    logs = [];

    const res = await request(app).post("/v1/query").send(body);

    expect(res.status).toBe(200);
    expect(logs.join("\n")).toContain('"mcpCredentialOverrides":{"jira":{"headers":{"Authorization":"[REDACT');
    expect(leakedFragments(logs, [secret])).toEqual([]);
    // The runtime gets a relay URL; the real value reaches the MCP server through the relay.
    const servers = (await sdkOptions()).mcpServers as Record<string, { url?: string; headers?: Record<string, string> }>;
    expect(servers.jira).toEqual({ type: "http", url: expect.stringMatching(RELAY_URL) });
    expect(upstream!.headersAt("/mcp").map((h) => h.authorization)).toEqual([`Basic ${secret}`]);
  });

  it("a non-map headers or env value is redacted whole", async () => {
    const app = await gatewayApp();
    const secret = sentinel();
    const other = sentinel();
    logs = [];

    await request(app)
      .post("/v1/query")
      .send({ queryId: "q-shapes", prompt: "p", mcpServers: { odd: { command: "node", env: [secret] }, odd2: { url: "http://x/mcp", headers: `Bearer ${other}` } } });

    expect(logs.join("\n")).toContain('"env":"[REDACTED]"');
    expect(logs.join("\n")).toContain('"headers":"[REDACTED]"');
    expect(leakedFragments(logs, [secret, other])).toEqual([]);
  });

  /** A registry definition whose credential sits `INSIDE_CUT` characters before the response preview cut. */
  function registryBody(name: string, transport: "http" | "stdio", secret: string, listPrefix = 0) {
    const credentials =
      transport === "http"
        ? { url: "http://127.0.0.1:9/mcp", headers: { Authorization: `Bearer ${secret}` } }
        : { command: "node", args: ["server.js"], env: { API_TOKEN: secret } };
    // Same key order as the stored definition, which is what the API answers with.
    const shape = (description: string) =>
      transport === "http"
        ? { name, description, enabled: true, type: transport, ...credentials }
        : { name, description, enabled: true, type: transport, ...credentials };
    const description = padFor(shape, secret, RESPONSE_CUT - INSIDE_CUT - listPrefix);
    return { type: transport, description, ...credentials };
  }

  function expectCutInsideSecret(responseText: string, secret: string) {
    const index = responseText.indexOf(secret);
    expect(index).toBeGreaterThan(RESPONSE_CUT - secret.length);
    expect(index).toBeLessThan(RESPONSE_CUT);
  }

  for (const transport of ["http", "stdio"] as const) {
    const key = transport === "http" ? "headers" : "env";
    const redactedMap = transport === "http" ? '"headers":{"Authorization":"[REDACTED]"}' : '"env":{"API_TOKEN":"[REDACTED]"}';
    // The response preview is cut near the credential, so only the start of the marker is visible there.
    const redactedPreview = transport === "http" ? '"headers":{"Authorization":"[REDACT' : '"env":{"API_TOKEN":"[REDACT';

    it(`registry create and update with ${key}: request and response preview redacted, the client gets the real value`, async () => {
      const app = await gatewayApp();
      const created = sentinel();
      const updated = sentinel();
      logs = [];

      const createRes = await request(app).put("/v1/mcp-servers/aida").send(registryBody("aida", transport, created));
      const updateRes = await request(app).put("/v1/mcp-servers/aida").send(registryBody("aida", transport, updated));

      expect(createRes.status).toBe(201);
      expect(updateRes.status).toBe(200);
      expectCutInsideSecret(createRes.text, created);
      expectCutInsideSecret(updateRes.text, updated);
      expect(JSON.stringify(createRes.body[key])).toContain(created);
      expect(JSON.stringify(updateRes.body[key])).toContain(updated);
      const reqLines = logs.filter((l) => l.startsWith("[req] PUT"));
      const resLines = logs.filter((l) => l.startsWith("[res] PUT"));
      expect(reqLines).toHaveLength(2);
      expect(resLines).toHaveLength(2);
      for (const line of reqLines) expect(line).toContain(redactedMap);
      for (const line of resLines) expect(line).toContain(redactedPreview);
      expect(leakedFragments(logs, [created, updated])).toEqual([]);
    });

    it(`registry detail read with ${key}: response preview redacted, the client gets the real value`, async () => {
      const app = await gatewayApp();
      const secret = sentinel();
      await request(app).put("/v1/mcp-servers/aida").send(registryBody("aida", transport, secret));
      logs = [];

      const res = await request(app).get("/v1/mcp-servers/aida");

      expect(res.status).toBe(200);
      expectCutInsideSecret(res.text, secret);
      expect(JSON.stringify(res.body[key])).toContain(secret);
      expect(logs.find((l) => l.startsWith("[res] GET"))).toContain(redactedPreview);
      expect(leakedFragments(logs, [secret])).toEqual([]);
    });

    it(`registry list read with ${key}: response preview redacted, the client gets the real value`, async () => {
      const app = await gatewayApp();
      const secret = sentinel();
      const listPrefix = '{"servers":['.length;
      await request(app).put("/v1/mcp-servers/aida").send(registryBody("aida", transport, secret, listPrefix));
      logs = [];

      const res = await request(app).get("/v1/mcp-servers");

      expect(res.status).toBe(200);
      expectCutInsideSecret(res.text, secret);
      expect(JSON.stringify(res.body.servers[0][key])).toContain(secret);
      expect(logs.find((l) => l.startsWith("[res] GET"))).toContain(redactedPreview);
      expect(leakedFragments(logs, [secret])).toEqual([]);
    });
  }

  it("POST /v1/mcp-servers/{name}/test and /call: unchanged redaction, including their error answers", async () => {
    const app = await gatewayApp();
    await request(app).put("/v1/mcp-servers/jira").send({ type: "http", url: "http://127.0.0.1:9/mcp" });
    const secrets = [sentinel(), sentinel(), sentinel(), sentinel()];
    logs = [];

    const test = await request(app)
      .post("/v1/mcp-servers/jira/test")
      .send({ headers: { Authorization: `Bearer ${secrets[0]}` }, env: { TOKEN: secrets[1] } });
    const call = await request(app)
      .post("/v1/mcp-servers/jira/call")
      .send({ tool: "echo", arguments: {}, credentials: { headers: { Authorization: `Bearer ${secrets[2]}` }, env: { TOKEN: secrets[3] } } });

    expect(test.status).toBe(502);
    expect(call.status).toBe(502);
    expect(logs.join("\n")).toContain('"headers":{"Authorization":"[REDACTED]"}');
    expect(leakedFragments(logs, secrets)).toEqual([]);
  });

  it("an unparseable registry answer is not previewed", async () => {
    const { requestLoggingMiddleware, setLogLevel } = await import("../logging.js");
    setLogLevel("debug");
    const secret = sentinel();
    const app = express();
    app.use(requestLoggingMiddleware);
    app.get("/v1/mcp-servers/raw", (_req, res) => res.type("text/plain").send(`headers: Authorization=${secret}`));
    logs = [];

    await request(app).get("/v1/mcp-servers/raw");

    expect(logs.find((l) => l.startsWith("[res] GET"))).toContain("[unparseable body omitted]");
    expect(leakedFragments(logs, [secret])).toEqual([]);
  });

  it("a text/* request body is logged as its length only", async () => {
    const app = await gatewayApp();
    const secret = sentinel();
    const text = `Authorization: Bearer ${secret}`;
    logs = [];

    await request(app).post("/v1/query").set("Content-Type", "text/plain").send(text);

    expect(logs.find((l) => l.startsWith("[req] POST"))).toContain(`[text body, ${text.length} chars]`);
    expect(leakedFragments(logs, [secret])).toEqual([]);
  });

  it("a malformed JSON body logs only the parser error type and status, no fragment of it", async () => {
    const app = await gatewayApp();
    const secret = sentinel();
    logs = [];

    const res = await request(app)
      .put("/v1/mcp-servers/aida")
      .set("Content-Type", "application/json")
      // An unquoted value: Node's parser message then quotes about ten characters of it
      // (Unexpected token 'X', ..."rization":XXXXXXXXXX"... is not valid JSON).
      .send(`{"type":"http","headers":{"Authorization":${secret}}}`);

    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: "Bad request" });
    expect(logs.join("\n")).toContain("[error] request body rejected type=entity.parse.failed status=400");
    expect(leakedFragments(logs, [secret])).toEqual([]);
  });
});
