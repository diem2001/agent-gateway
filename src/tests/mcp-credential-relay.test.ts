/**
 * The credential relay (src/mcp-credential-relay.ts) against loopback upstreams:
 * forwarding and header allowlists, refusal answers, session handling, limits,
 * revocation, and the fail-closed run assembly when the relay is not listening.
 */
import http, { type IncomingHttpHeaders, type IncomingMessage, type ServerResponse } from "node:http";
import net, { type AddressInfo } from "node:net";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { CredentialRelay } from "../mcp-credential-relay.js";
import { startOAuthMcpStub, type OAuthMcpStub, type OAuthStubOptions } from "./helpers/oauth-mcp-stub.js";

const cleanups: (() => Promise<void> | void)[] = [];
let logs: string[] = [];

beforeEach(() => {
  logs = [];
  vi.spyOn(console, "log").mockImplementation((...args) => {
    logs.push(args.map(String).join(" "));
  });
});

afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()!();
  vi.restoreAllMocks();
});

async function relay(options?: ConstructorParameters<typeof CredentialRelay>[0]): Promise<CredentialRelay> {
  const created = new CredentialRelay(options);
  await created.start();
  cleanups.push(() => created.close());
  return created;
}

async function stub(options: OAuthStubOptions = {}): Promise<OAuthMcpStub> {
  const created = await startOAuthMcpStub(options);
  cleanups.push(() => created.close());
  return created;
}

/** A raw upstream for answers the MCP stub does not give. */
async function rawUpstream(handler: (req: IncomingMessage, res: ServerResponse) => void): Promise<{ url: string; hits: () => number }> {
  let hits = 0;
  const server = http.createServer((req, res) => {
    hits++;
    handler(req, res);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  cleanups.push(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
  return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/mcp`, hits: () => hits };
}

interface Answer {
  status: number;
  headers: IncomingHttpHeaders;
  text: string;
}

function send(url: string, init: { method?: string; body?: unknown; rawBody?: Buffer; headers?: Record<string, string>; path?: string } = {}): Promise<Answer> {
  const target = new URL(url);
  const payload = init.rawBody ?? (init.body === undefined ? undefined : Buffer.from(JSON.stringify(init.body)));
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: target.hostname,
        port: target.port,
        path: init.path ?? target.pathname,
        method: init.method ?? "POST",
        agent: false,
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json, text/event-stream",
          ...(payload ? { "Content-Length": payload.length } : {}),
          ...init.headers,
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, text: Buffer.concat(chunks).toString("utf8") }));
      },
    );
    req.on("error", reject);
    req.end(payload);
  });
}

const rpc = (method: string, id?: number, params: Record<string, unknown> = {}) => ({ jsonrpc: "2.0", ...(id === undefined ? {} : { id }), method, params });

describe("credential relay: forwarding", () => {
  it("forwards to the bound URL with the bound headers; the runtime's Authorization and Cookie never reach the upstream", async () => {
    const upstream = await stub();
    const r = await relay();
    const { url } = r.register({ serverName: "records", url: upstream.url, headers: { Authorization: "Bearer BOUND", "X-Static": "s" } });

    const res = await send(url, { body: rpc("initialize", 1), headers: { Authorization: "Bearer RUNTIME", Cookie: "c=1" } });

    expect(res.status).toBe(200);
    expect(JSON.parse(res.text).result.serverInfo.name).toBe("oauth-mcp-stub");
    const received = upstream.requests[0].headers;
    expect(received.authorization).toBe("Bearer BOUND");
    expect(received["x-static"]).toBe("s");
    expect(received.cookie).toBeUndefined();
  });

  it("round-trips Mcp-Session-Id and returns only Content-Type and Mcp-Session-Id", async () => {
    const upstream = await stub();
    const r = await relay();
    const { url } = r.register({ serverName: "records", url: upstream.url, headers: {} });

    const init = await send(url, { body: rpc("initialize", 1) });
    const session = init.headers["mcp-session-id"] as string;
    const list = await send(url, { body: rpc("tools/list", 2), headers: { "Mcp-Session-Id": session, "Mcp-Protocol-Version": "2025-06-18" } });

    expect(session).toBe("stub-session-1");
    expect(list.status).toBe(200);
    expect(JSON.parse(list.text).result.tools[0].name).toBe("lookup_record");
    expect(upstream.requests[1].headers["mcp-session-id"]).toBe(session);
    expect(upstream.requests[1].headers["mcp-protocol-version"]).toBe("2025-06-18");
  });

  it("drops every upstream response header except Content-Type and Mcp-Session-Id", async () => {
    const upstream = await rawUpstream((req, res) => {
      req.resume();
      res.writeHead(200, {
        "Content-Type": "application/json",
        "Mcp-Session-Id": "s-1",
        "WWW-Authenticate": 'Bearer resource_metadata="http://x/.well-known/oauth-protected-resource"',
        "Set-Cookie": "session=abc",
        Location: "http://elsewhere.invalid/",
        "X-Other": "1",
      });
      res.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result: {} }));
    });
    const r = await relay();
    const { url } = r.register({ serverName: "records", url: upstream.url, headers: {} });

    const res = await send(url, { body: rpc("ping", 1) });

    expect(res.status).toBe(200);
    expect(res.headers["mcp-session-id"]).toBe("s-1");
    expect(res.headers["content-type"]).toBe("application/json");
    for (const name of ["www-authenticate", "set-cookie", "location", "x-other"]) expect(res.headers[name]).toBeUndefined();
  });

  it("streams a text/event-stream answer", async () => {
    const upstream = await stub({ responseMode: "sse" });
    const r = await relay();
    const { url } = r.register({ serverName: "records", url: upstream.url, headers: {} });

    const res = await send(url, { body: rpc("initialize", 1) });

    expect(res.headers["content-type"]).toBe("text/event-stream");
    expect(res.text).toMatch(/^event: message\ndata: \{.*"serverInfo"/);
  });

  it("streams a multi-MB tool result unchanged", async () => {
    const upstream = await stub({ toolResultBytes: 6 * 1024 * 1024 });
    const r = await relay();
    const { url } = r.register({ serverName: "records", url: upstream.url, headers: {} });

    const res = await send(url, { body: rpc("tools/call", 3, { name: "lookup_record", arguments: { id: "R-1" } }) });

    const text = JSON.parse(res.text).result.content[0].text as string;
    expect(text.length).toBe("RECORD-7667-OK ".length + 6 * 1024 * 1024);
  });

  it("passes an upstream session miss (404 on a request with Mcp-Session-Id) as a bodiless 404", async () => {
    const upstream = await stub({ loseSessionOn: "tools/list" });
    const r = await relay();
    const { url } = r.register({ serverName: "records", url: upstream.url, headers: {} });
    const init = await send(url, { body: rpc("initialize", 1) });

    const miss = await send(url, { body: rpc("tools/list", 2), headers: { "Mcp-Session-Id": init.headers["mcp-session-id"] as string } });
    const again = await send(url, { body: rpc("initialize", 3) });

    expect(miss.status).toBe(404);
    expect(miss.text).toBe("");
    expect(again.status).toBe(200);
  });
});

describe("credential relay: an upstream refusal never reaches the runtime", () => {
  it("401 on tools/call: HTTP 200 with a tool error result naming the server, no WWW-Authenticate", async () => {
    const upstream = await stub({ refuse: "tools-call" });
    const r = await relay();
    const { url } = r.register({ serverName: "records", url: upstream.url, headers: {} });

    const res = await send(url, { body: rpc("tools/call", 7, { name: "lookup_record", arguments: {} }) });

    expect(res.status).toBe(200);
    expect(res.headers["www-authenticate"]).toBeUndefined();
    expect(JSON.parse(res.text)).toEqual({
      jsonrpc: "2.0",
      id: 7,
      result: { content: [{ type: "text", text: 'MCP server "records" refused the credential' }], isError: true },
    });
    expect(logs.join("\n")).toContain("mcp.relay.refused serverName=records reason=credential_refused status=401");
  });

  it("401 on initialize: a JSON-RPC error, so the server contributes no tools", async () => {
    const upstream = await stub({ refuse: "initialize" });
    const r = await relay();
    const { url } = r.register({ serverName: "records", url: upstream.url, headers: {} });

    const res = await send(url, { body: rpc("initialize", 1) });

    expect(res.status).toBe(200);
    expect(JSON.parse(res.text)).toEqual({ jsonrpc: "2.0", id: 1, error: { code: -32001, message: 'MCP server "records" refused the credential' } });
  });

  it("a refused notification answers 202; a refused batch answers an array", async () => {
    const upstream = await stub({ refuse: "initialize" });
    const r = await relay();
    const { url } = r.register({ serverName: "records", url: upstream.url, headers: {} });

    const note = await send(url, { body: rpc("notifications/initialized") });
    const batch = await send(url, { body: [rpc("tools/call", 1, { name: "x" }), rpc("tools/list", 2), rpc("notifications/cancelled")] });

    expect(note.status).toBe(202);
    expect(note.text).toBe("");
    const answers = JSON.parse(batch.text) as { id: number; result?: { isError: boolean }; error?: unknown }[];
    expect(answers.map((a) => a.id)).toEqual([1, 2]);
    expect(answers[0].result?.isError).toBe(true);
    expect(answers[1].error).toBeDefined();
  });

  it("403, a redirect and a 500 are refused without following the redirect or echoing the body", async () => {
    let redirectTargetHits = 0;
    const target = await rawUpstream((req, res) => {
      redirectTargetHits++;
      req.resume();
      res.end("{}");
    });
    for (const [status, extra] of [
      [403, {}],
      [302, { Location: target.url }],
      [500, {}],
    ] as const) {
      const upstream = await rawUpstream((req, res) => {
        req.resume();
        res.writeHead(status, { "Content-Type": "text/plain", ...extra });
        res.end("UPSTREAM-BODY-7667");
      });
      const r = await relay();
      const { url } = r.register({ serverName: "records", url: upstream.url, headers: {} });

      const res = await send(url, { body: rpc("tools/call", 1, { name: "x" }) });

      expect(res.status).toBe(200);
      expect(res.text).not.toContain("UPSTREAM-BODY-7667");
      expect(JSON.parse(res.text).result.content[0].text).toBe(
        status === 403 ? 'MCP server "records" refused the credential' : 'MCP server "records" unavailable',
      );
    }
    expect(redirectTargetHits).toBe(0);
    expect(target.hits()).toBe(0);
  });

  it("an unreachable upstream answers unavailable", async () => {
    const closed = net.createServer();
    await new Promise<void>((resolve) => closed.listen(0, "127.0.0.1", () => resolve()));
    const port = (closed.address() as AddressInfo).port;
    await new Promise<void>((resolve) => closed.close(() => resolve()));
    const r = await relay();
    const { url } = r.register({ serverName: "records", url: `http://127.0.0.1:${port}/mcp`, headers: {} });

    const res = await send(url, { body: rpc("tools/call", 1, { name: "x" }) });

    expect(JSON.parse(res.text).result).toEqual({ content: [{ type: "text", text: 'MCP server "records" unavailable' }], isError: true });
  });

  it("an upstream idle past the timeout answers unavailable", async () => {
    const upstream = await rawUpstream((req) => req.resume());
    const r = await relay({ idleTimeoutMs: 300 });
    const { url } = r.register({ serverName: "records", url: upstream.url, headers: {} });

    const started = Date.now();
    const res = await send(url, { body: rpc("initialize", 1) });

    expect(Date.now() - started).toBeGreaterThanOrEqual(250);
    expect(JSON.parse(res.text).error.message).toBe('MCP server "records" unavailable');
  });
});

describe("credential relay: what is never forwarded", () => {
  it("GET answers 405 and DELETE 204; neither answer depends on the upstream", async () => {
    const upstream = await stub({ refuse: "get-stream" });
    const r = await relay();
    const { url } = r.register({ serverName: "records", url: upstream.url, headers: {} });

    const get = await send(url, { method: "GET" });
    const del = await send(url, { method: "DELETE", headers: { "Mcp-Session-Id": "stub-session-9" } });

    expect(get.status).toBe(405);
    expect(del.status).toBe(204);
    expect(upstream.requests.filter((q) => q.method === "GET")).toHaveLength(0);
  });

  it("OAuth discovery, registration, authorize, token and sub-paths get a local 404", async () => {
    const upstream = await stub();
    const r = await relay();
    const { url, token } = r.register({ serverName: "records", url: upstream.url, headers: {} });
    const origin = new URL(url).origin;

    for (const path of [
      "/.well-known/oauth-protected-resource",
      `/.well-known/oauth-protected-resource/mcp/${token}`,
      "/.well-known/oauth-authorization-server",
      "/register",
      "/authorize",
      "/token",
      `/mcp/${token}/register`,
      `/mcp/${token}?x=1`,
      "/mcp/",
    ]) {
      const res = await send(origin, { path, body: rpc("initialize", 1) });
      expect(res.status, path).toBe(404);
    }
    expect(upstream.requests).toHaveLength(0);
  });

  it("an unknown or revoked token gets 404; a Host other than 127.0.0.1:<port> gets 403", async () => {
    const upstream = await stub();
    const r = await relay();
    const { url, token } = r.register({ serverName: "records", url: upstream.url, headers: {} });

    const wrongHost = await send(url, { body: rpc("initialize", 1), headers: { Host: `localhost:${new URL(url).port}` } });
    r.revoke(token);
    const revoked = await send(url, { body: rpc("initialize", 1) });
    const unknown = await send(url.replace(token, "A".repeat(22)), { body: rpc("initialize", 1) });

    expect(wrongHost.status).toBe(403);
    expect(revoked.status).toBe(404);
    expect(unknown.status).toBe(404);
    expect(upstream.requests).toHaveLength(0);
  });

  it("an oversized POST body gets a JSON-RPC error and is not forwarded", async () => {
    const upstream = await stub();
    const r = await relay({ maxBodyBytes: 1024 });
    const { url } = r.register({ serverName: "records", url: upstream.url, headers: {} });

    const res = await send(url, { body: rpc("tools/call", 1, { name: "x", arguments: { blob: "x".repeat(4096) } }) });

    expect(res.status).toBe(200);
    expect(JSON.parse(res.text).error).toEqual({ code: -32600, message: 'MCP request to "records" is too large' });
    expect(upstream.requests).toHaveLength(0);
  });

  it("revoking a token destroys its in-flight upstream request", async () => {
    let upstreamClosed = false;
    const upstream = await rawUpstream((req) => {
      req.resume();
      req.socket.on("close", () => (upstreamClosed = true));
    });
    const r = await relay();
    const { url, token } = r.register({ serverName: "records", url: upstream.url, headers: {} });

    const pending = send(url, { body: rpc("initialize", 1) }).then(
      () => "answered",
      () => "destroyed",
    );
    while (upstream.hits() === 0) await new Promise((resolve) => setTimeout(resolve, 10));
    r.revoke(token);

    expect(await pending).toBe("destroyed");
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(upstreamClosed).toBe(true);
  });

  it("never logs the relay URL, path or token", async () => {
    const upstream = await stub({ refuse: "tools-call" });
    const r = await relay();
    const { url, token } = r.register({ serverName: "records", url: upstream.url, headers: {} });

    await send(url, { body: rpc("tools/call", 1, { name: "x" }) });
    await send(url, { body: rpc("tools/call", 2, { name: "x", arguments: { blob: "x".repeat(64) } }) });

    expect(logs.length).toBeGreaterThan(0);
    expect(logs.join("\n")).not.toContain(token);
    expect(logs.join("\n")).not.toContain(new URL(url).port);
  });
});

describe("fail closed: without a listening relay, registered http servers are left out of the run", () => {
  it("omits them with reason relay_unavailable and drops a request server that takes their name", async () => {
    vi.resetModules();
    const captured: Record<string, unknown>[] = [];
    vi.doMock("@anthropic-ai/claude-agent-sdk", () => ({
      createSdkMcpServer: vi.fn(),
      query: vi.fn(({ options }) => {
        captured.push(options);
        return (async function* () {
          yield { type: "result", usage: {}, total_cost_usd: 0 };
        })();
      }),
    }));
    cleanups.push(() => {
      vi.doUnmock("@anthropic-ai/claude-agent-sdk");
    });
    const { registerMcpServer } = await import("../mcp-registry.js");
    const now = new Date().toISOString();
    registerMcpServer({ name: "jira", description: "", enabled: true, type: "http", url: "http://jira.invalid/mcp", createdAt: now, updatedAt: now });
    registerMcpServer({ name: "local", description: "", enabled: true, type: "stdio", command: "node", createdAt: now, updatedAt: now });
    const { runQuery } = await import("../agent.js");

    await runQuery({
      prompt: "go",
      abortController: new AbortController(),
      onEvent: () => undefined,
      requestMcpServers: { jira: { url: "http://impostor.invalid/mcp", type: "http" } },
    });

    const servers = captured[0].mcpServers as Record<string, unknown>;
    expect(Object.keys(servers)).toEqual(["local"]);
    expect(captured[0].allowedTools).not.toContain("mcp__jira__*");
    expect(logs.join("\n")).toContain("mcp.server.omitted serverName=jira reason=relay_unavailable");
  });
});
