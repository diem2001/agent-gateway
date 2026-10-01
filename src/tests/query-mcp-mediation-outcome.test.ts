/**
 * Which MCP servers reach the runtime as relay URLs, and with what binding (MVP-7679, Gate C), through the REAL
 * query.ts + retry.ts + agent.ts path with only the Claude Agent SDK boundary mocked and the real relay
 * listening: registered http and SSE servers, per-user overrides (one case-insensitive merge, the override wins),
 * request servers with headers, the grant given to each binding, the "no credential" decision and the revocation at
 * the end of the run. No header value may appear anywhere in the runtime's options.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { McpServerDefinition } from "../mcp-registry.js";
import type { RelayBinding } from "../mcp-credential-relay.js";
import { RELAY_URL, startRecordingUpstream, type RecordingUpstream } from "./helpers/relay-upstream.js";

let capturedOptions: Record<string, unknown>[] = [];
let registered: RelayBinding[] = [];
let tokensRevokedAtEnd: string[] = [];
let tempDir = "";
let upstream: RecordingUpstream;

beforeEach(async () => {
  vi.resetModules();
  capturedOptions = [];
  registered = [];
  tokensRevokedAtEnd = [];
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "mvp7679-mediation-"));
  process.env.MCP_SERVERS_PERSIST_PATH = path.join(tempDir, "mcp-servers.json");
  process.env.TOOLS_PERSIST_PATH = path.join(tempDir, "tools.json");
  process.env.SESSION_PERSIST_PATH = path.join(tempDir, "sessions.json");
  vi.spyOn(console, "log").mockImplementation(() => undefined);
  vi.doMock("@anthropic-ai/claude-agent-sdk", () => ({
    createSdkMcpServer: vi.fn((options) => ({ type: "sdk", name: options.name })),
    query: vi.fn(({ options }) => {
      capturedOptions.push(options as Record<string, unknown>);
      return (async function* () {
        yield { type: "assistant", message: { content: [{ type: "text", text: "ack" }] } };
        yield { type: "result", usage: { input_tokens: 1, output_tokens: 1 }, total_cost_usd: 0, sessionId: "sdk-session" };
      })();
    }),
  }));
  upstream = await startRecordingUpstream();
  const { credentialRelay } = await import("../mcp-credential-relay.js");
  await credentialRelay.start();
  const originalRegister = credentialRelay.register.bind(credentialRelay);
  vi.spyOn(credentialRelay, "register").mockImplementation((binding) => {
    registered.push(binding);
    return originalRegister(binding);
  });
  const originalRevoke = credentialRelay.revoke.bind(credentialRelay);
  vi.spyOn(credentialRelay, "revoke").mockImplementation((token) => {
    tokensRevokedAtEnd.push(token);
    originalRevoke(token);
  });
});

afterEach(async () => {
  const { credentialRelay } = await import("../mcp-credential-relay.js");
  await credentialRelay.close();
  await upstream.close();
  vi.restoreAllMocks();
  vi.doUnmock("@anthropic-ai/claude-agent-sdk");
  delete process.env.MCP_SERVERS_PERSIST_PATH;
  delete process.env.TOOLS_PERSIST_PATH;
  delete process.env.SESSION_PERSIST_PATH;
  await new Promise((resolve) => setTimeout(resolve, 150));
  fs.rmSync(tempDir, { recursive: true, force: true });
});

async function createApp() {
  const { queryRouter } = await import("../query.js");
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.clientLabel = "reqlift";
    next();
  });
  app.use(queryRouter);
  return app;
}

async function register(def: Partial<McpServerDefinition> & Pick<McpServerDefinition, "name" | "type">) {
  const { registerMcpServer } = await import("../mcp-registry.js");
  const now = new Date().toISOString();
  registerMcpServer({ description: "", enabled: true, createdAt: now, updatedAt: now, ...def } as McpServerDefinition);
}

const post = (app: express.Express, body: Record<string, unknown>) => request(app).post("/v1/query").send({ queryId: `q-${Math.random()}`, prompt: "go", useSession: false, ...body });
const options = () => capturedOptions[0] as { mcpServers?: Record<string, Record<string, unknown>>; allowedTools?: string[] };
const bindingFor = (name: string) => registered.find((b) => b.serverName === name)!;

describe("registered servers", () => {
  it("an http server and an SSE server both reach the runtime as { type: http, url: relay URL } with the same tool names, and no header value anywhere", async () => {
    await register({ name: "jira", type: "http", url: `${upstream.origin}/jira`, headers: { Authorization: "Basic SYNTH-JIRA-SHARED-7679" } });
    await register({ name: "feed", type: "sse", url: `${upstream.origin}/feed`, headers: { "X-Api-Key": "SYNTH-FEED-KEY-7679" } });
    const app = await createApp();
    expect((await post(app, {})).status).toBe(200);
    expect(options().mcpServers).toEqual({ jira: { type: "http", url: expect.stringMatching(RELAY_URL) }, feed: { type: "http", url: expect.stringMatching(RELAY_URL) } });
    expect(options().allowedTools).toEqual(expect.arrayContaining(["mcp__jira__*", "mcp__feed__*"]));
    expect(bindingFor("jira")).toMatchObject({ kind: "http", url: `${upstream.origin}/jira`, headers: { Authorization: "Basic SYNTH-JIRA-SHARED-7679" } });
    expect(bindingFor("feed")).toMatchObject({ kind: "sse", url: `${upstream.origin}/feed`, headers: { "X-Api-Key": "SYNTH-FEED-KEY-7679" } });
    const everything = JSON.stringify(capturedOptions[0], (key, value) => (key === "abortController" || key === "spawnClaudeCodeProcess" ? undefined : value));
    for (const secret of ["SYNTH-JIRA-SHARED-7679", "SYNTH-FEED-KEY-7679"]) expect(everything).not.toContain(secret);
  });

  it("the run's tokens are revoked when the run ends", async () => {
    await register({ name: "jira", type: "http", url: `${upstream.origin}/jira` });
    const app = await createApp();
    await post(app, {});
    const url = options().mcpServers!.jira.url as string;
    const token = url.slice(url.lastIndexOf("/") + 1);
    expect(tokensRevokedAtEnd).toContain(token);
  });

  it("an override replaces the shared header of the same name in any casing: one credential travels", async () => {
    await register({ name: "jira", type: "http", url: `${upstream.origin}/jira`, headers: { Authorization: "Basic SHARED", "X-Static": "s" } });
    await register({ name: "feed", type: "sse", url: `${upstream.origin}/feed`, headers: { "X-Api-Key": "SHARED-KEY" } });
    const app = await createApp();
    await post(app, { mcpCredentialOverrides: { jira: { headers: { authorization: "Bearer USER" } }, feed: { headers: { "x-api-key": "USER-KEY" } } } });
    expect(bindingFor("jira").headers).toEqual({ "X-Static": "s", authorization: "Bearer USER" });
    expect(bindingFor("feed").headers).toEqual({ "x-api-key": "USER-KEY" });
    expect(bindingFor("jira").credentialSource).toBe("user");
    expect(bindingFor("feed").credentialSource).toBe("user");
  });

  it("without an override the credential is the shared one", async () => {
    await register({ name: "jira", type: "http", url: `${upstream.origin}/jira`, headers: { Authorization: "Basic SHARED" } });
    const app = await createApp();
    await post(app, {});
    expect(bindingFor("jira").credentialSource).toBe("gateway");
  });

  it("a server whose schema composes headers and a run without them: the binding answers tools/call with no credential; with them it does not", async () => {
    const schema = {
      fields: [{ key: "token", label: "Token", type: "password" as const, required: true }],
      outputs: [{ target: "headers" as const, outputKey: "Authorization", template: "Bearer {token}" }],
    };
    await register({ name: "aida", type: "http", url: `${upstream.origin}/aida`, headers: { Authorization: "Basic SHARED" }, userCredentialSchema: schema });
    await register({ name: "plain", type: "http", url: `${upstream.origin}/plain` });
    const app = await createApp();
    await post(app, {});
    expect(bindingFor("aida").noUserCredential).toBe(true);
    expect(bindingFor("plain").noUserCredential).toBe(false);
    registered = [];
    capturedOptions = [];
    await post(app, { mcpCredentialOverrides: { aida: { headers: { Authorization: "Bearer USER" } } } });
    expect(bindingFor("aida").noUserCredential).toBe(false);
  });

  it("the grant of a binding reflects the trusted policy and the caller's narrowing", async () => {
    await register({ name: "jira", type: "http", url: `${upstream.origin}/jira` });
    const grantModule = await import("../tool-grant.js");
    grantModule.setToolPolicy(grantModule.parseToolPolicy(JSON.stringify({ labels: { reqlift: { deny: ["mcp__jira__delete_issue"] } } }), ["reqlift"]));
    const app = await createApp();
    await post(app, {});
    const { grant } = bindingFor("jira");
    expect(grant.allowsTool("get_issue")).toBe(true);
    expect(grant.allowsTool("delete_issue")).toBe(false);
    expect(grant.coversServer).toBe(false);
    registered = [];
    capturedOptions = [];
    grantModule.setToolPolicy(null);
    await post(app, { allowedTools: ["mcp__jira__get_issue"] });
    expect(bindingFor("jira").grant.allowsTool("get_issue")).toBe(true);
    expect(bindingFor("jira").grant.allowsTool("update_issue")).toBe(false);
    registered = [];
    capturedOptions = [];
    await post(app, {});
    expect(bindingFor("jira").grant.coversServer).toBe(true);
  });
});

describe("request servers", () => {
  it("an http server with headers goes through the relay (user credential source); one without headers connects directly", async () => {
    const app = await createApp();
    await post(app, {
      mcpServers: {
        withHeaders: { type: "http", url: `${upstream.origin}/with`, headers: { Authorization: "Bearer SYNTH-REQUEST-HEADER-7679" } },
        noHeaders: { url: `${upstream.origin}/no` },
        feed: { type: "sse", url: `${upstream.origin}/sse`, headers: { "X-Key": "SYNTH-REQUEST-SSE-7679" } },
      },
    });
    expect(options().mcpServers).toEqual({
      withHeaders: { type: "http", url: expect.stringMatching(RELAY_URL) },
      noHeaders: { type: "http", url: `${upstream.origin}/no` },
      feed: { type: "http", url: expect.stringMatching(RELAY_URL) },
    });
    expect(bindingFor("withHeaders")).toMatchObject({ kind: "http", headers: { Authorization: "Bearer SYNTH-REQUEST-HEADER-7679" }, credentialSource: "user" });
    expect(bindingFor("feed")).toMatchObject({ kind: "sse", credentialSource: "user" });
    expect(registered.map((b) => b.serverName).sort()).toEqual(["feed", "withHeaders"]);
    const everything = JSON.stringify(capturedOptions[0], (key, value) => (key === "abortController" || key === "spawnClaudeCodeProcess" ? undefined : value));
    expect(everything).not.toContain("SYNTH-REQUEST-HEADER-7679");
    expect(everything).not.toContain("SYNTH-REQUEST-SSE-7679");
  });

  it("a request http server whose URL carries a user name, password or query goes through the relay too (nothing credential-like on the runtime's command line)", async () => {
    const app = await createApp();
    await post(app, {
      mcpServers: {
        userinfo: { url: `http://svc-user:SYNTH-URL-PASSWORD-7679@127.0.0.1:${new URL(upstream.origin).port}/mcp` },
        tokenised: { type: "sse", url: `${upstream.origin}/sse?token=SYNTH-URL-QUERY-TOKEN-7679` },
        plain: { url: `${upstream.origin}/plain` },
      },
    });
    expect(options().mcpServers).toEqual({
      userinfo: { type: "http", url: expect.stringMatching(RELAY_URL) },
      tokenised: { type: "http", url: expect.stringMatching(RELAY_URL) },
      plain: { type: "http", url: `${upstream.origin}/plain` },
    });
    const everything = JSON.stringify(capturedOptions[0], (key, value) => (key === "abortController" || key === "spawnClaudeCodeProcess" ? undefined : value));
    expect(everything).not.toContain("SYNTH-URL-PASSWORD-7679");
    expect(everything).not.toContain("SYNTH-URL-QUERY-TOKEN-7679");
    expect(bindingFor("tokenised").url).toContain("SYNTH-URL-QUERY-TOKEN-7679");
    expect(bindingFor("tokenised").kind).toBe("sse");
  });

  it("when the relay is not listening, request servers with headers and registered http/SSE servers are left out, never connected directly", async () => {
    await register({ name: "jira", type: "http", url: `${upstream.origin}/jira`, headers: { Authorization: "Basic SHARED" } });
    await register({ name: "feed", type: "sse", url: `${upstream.origin}/feed`, headers: { "X-Api-Key": "SHARED" } });
    const { credentialRelay } = await import("../mcp-credential-relay.js");
    await credentialRelay.close();
    const app = await createApp();
    await post(app, { mcpServers: { withHeaders: { type: "http", url: `${upstream.origin}/with`, headers: { Authorization: "Bearer X" } }, noHeaders: { url: `${upstream.origin}/no` } } });
    expect(Object.keys(options().mcpServers ?? {})).toEqual(["noHeaders"]);
    expect(registered).toEqual([]);
  });
});
