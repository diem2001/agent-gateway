/**
 * The credential relay (src/mcp-credential-relay.ts) against loopback upstreams:
 * forwarding and header allowlists, refusal answers, session handling, limits,
 * revocation, and the fail-closed run assembly when the relay is not listening.
 */
import http, { type IncomingHttpHeaders, type IncomingMessage, type ServerResponse } from "node:http";
import net, { type AddressInfo } from "node:net";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { CredentialRelay, type RelayGrant } from "../mcp-credential-relay.js";
import { startOAuthMcpStub, type OAuthMcpStub, type OAuthStubOptions } from "./helpers/oauth-mcp-stub.js";

const ALLOW_ALL: RelayGrant = { allowsTool: () => true, coversServer: true };
const GATEWAY_REFUSED = `TOOL_AUTH_UNAVAILABLE: "records" did not accept the gateway's credential. Ask your gateway administrator to check this tool's credential; retrying will not help.`;
const UNAVAILABLE = 'TOOL_UNAVAILABLE: "records" could not be reached or failed. Try again later; if it keeps happening, tell your gateway administrator.';
const REDIRECTED = 'TOOL_UNAVAILABLE: "records" tried to send the request to another address, which the gateway does not allow. Tell your gateway administrator; retrying will not help.';
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
    const { url } = r.register({ grant: ALLOW_ALL, serverName: "records", url: upstream.url, headers: { Authorization: "Bearer BOUND", "X-Static": "s" } });

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
    const { url } = r.register({ grant: ALLOW_ALL, serverName: "records", url: upstream.url, headers: {} });

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
    const { url } = r.register({ grant: ALLOW_ALL, serverName: "records", url: upstream.url, headers: {} });

    const res = await send(url, { body: rpc("ping", 1) });

    expect(res.status).toBe(200);
    expect(res.headers["mcp-session-id"]).toBe("s-1");
    expect(res.headers["content-type"]).toBe("application/json");
    for (const name of ["www-authenticate", "set-cookie", "location", "x-other"]) expect(res.headers[name]).toBeUndefined();
  });

  it("an event-stream answer comes back as one JSON message (the runtime sees JSON only)", async () => {
    const upstream = await stub({ responseMode: "sse" });
    const r = await relay();
    const { url } = r.register({ grant: ALLOW_ALL, serverName: "records", url: upstream.url, headers: {} });

    const res = await send(url, { body: rpc("initialize", 1) });

    expect(res.headers["content-type"]).toBe("application/json");
    expect(JSON.parse(res.text)).toMatchObject({ jsonrpc: "2.0", id: 1, result: { serverInfo: { name: "oauth-mcp-stub" } } });
  });

  it("returns a multi-MB tool result unchanged", async () => {
    const upstream = await stub({ toolResultBytes: 6 * 1024 * 1024 });
    const r = await relay();
    const { url } = r.register({ grant: ALLOW_ALL, serverName: "records", url: upstream.url, headers: {} });

    const res = await send(url, { body: rpc("tools/call", 3, { name: "lookup_record", arguments: { id: "R-1" } }) });

    const text = JSON.parse(res.text).result.content[0].text as string;
    expect(text.length).toBe("RECORD-7667-OK ".length + 6 * 1024 * 1024);
  });

  it("passes an upstream session miss (404 on a request with Mcp-Session-Id) as a bodiless 404", async () => {
    const upstream = await stub({ loseSessionOn: "tools/list" });
    const r = await relay();
    const { url } = r.register({ grant: ALLOW_ALL, serverName: "records", url: upstream.url, headers: {} });
    const init = await send(url, { body: rpc("initialize", 1) });

    const miss = await send(url, { body: rpc("tools/list", 2), headers: { "Mcp-Session-Id": init.headers["mcp-session-id"] as string } });
    const again = await send(url, { body: rpc("initialize", 3) });

    expect(miss.status).toBe(404);
    expect(miss.text).toBe("");
    expect(again.status).toBe(200);
  });
});

describe("credential relay: an upstream refusal never reaches the runtime", () => {
  it("401 on tools/call: HTTP 200 with the fixed TOOL_AUTH_UNAVAILABLE tool error result, no WWW-Authenticate", async () => {
    const upstream = await stub({ refuse: "tools-call" });
    const r = await relay();
    const { url } = r.register({ grant: ALLOW_ALL, serverName: "records", url: upstream.url, headers: {} });

    const res = await send(url, { body: rpc("tools/call", 7, { name: "lookup_record", arguments: {} }) });

    expect(res.status).toBe(200);
    expect(res.headers["www-authenticate"]).toBeUndefined();
    expect(JSON.parse(res.text)).toEqual({
      jsonrpc: "2.0",
      id: 7,
      result: { content: [{ type: "text", text: GATEWAY_REFUSED }], isError: true },
    });
    expect(logs.join("\n")).toContain("mcp.relay.refused serverName=records reason=credential_refused status=401");
  });

  it("401 on initialize: a JSON-RPC error, so the server contributes no tools", async () => {
    const upstream = await stub({ refuse: "initialize" });
    const r = await relay();
    const { url } = r.register({ grant: ALLOW_ALL, serverName: "records", url: upstream.url, headers: {} });

    const res = await send(url, { body: rpc("initialize", 1) });

    expect(res.status).toBe(200);
    expect(JSON.parse(res.text)).toEqual({ jsonrpc: "2.0", id: 1, error: { code: -32001, message: GATEWAY_REFUSED } });
  });

  it("a refused notification answers 202 with no body", async () => {
    const upstream = await stub({ refuse: "initialize" });
    const r = await relay();
    const { url } = r.register({ grant: ALLOW_ALL, serverName: "records", url: upstream.url, headers: {} });

    const note = await send(url, { body: rpc("notifications/initialized") });

    expect(note.status).toBe(202);
    expect(note.text).toBe("");
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
      const { url } = r.register({ grant: ALLOW_ALL, serverName: "records", url: upstream.url, headers: {} });

      const res = await send(url, { body: rpc("tools/call", 1, { name: "x" }) });

      expect(res.status).toBe(200);
      expect(res.text).not.toContain("UPSTREAM-BODY-7667");
      expect(JSON.parse(res.text).result.content[0].text).toBe(status === 403 ? GATEWAY_REFUSED : status === 302 ? REDIRECTED : UNAVAILABLE);
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
    const { url } = r.register({ grant: ALLOW_ALL, serverName: "records", url: `http://127.0.0.1:${port}/mcp`, headers: {} });

    const res = await send(url, { body: rpc("tools/call", 1, { name: "x" }) });

    expect(JSON.parse(res.text).result).toEqual({ content: [{ type: "text", text: UNAVAILABLE }], isError: true });
  });

  it("an upstream idle past the timeout answers TOOL_TIMEOUT", async () => {
    const upstream = await rawUpstream((req) => req.resume());
    const r = await relay({ idleTimeoutMs: 300 });
    const { url } = r.register({ grant: ALLOW_ALL, serverName: "records", url: upstream.url, headers: {} });

    const started = Date.now();
    const res = await send(url, { body: rpc("initialize", 1) });

    expect(Date.now() - started).toBeGreaterThanOrEqual(250);
    expect(JSON.parse(res.text).error.message).toBe('TOOL_TIMEOUT: "records" did not answer within 1 seconds. Try again later or with a smaller request; if it keeps happening, tell your gateway administrator.');
  });
});

describe("credential relay: what is never forwarded", () => {
  it("GET answers 405 and DELETE 204; neither answer depends on the upstream", async () => {
    const upstream = await stub({ refuse: "get-stream" });
    const r = await relay();
    const { url } = r.register({ grant: ALLOW_ALL, serverName: "records", url: upstream.url, headers: {} });

    const get = await send(url, { method: "GET" });
    const del = await send(url, { method: "DELETE", headers: { "Mcp-Session-Id": "stub-session-9" } });

    expect(get.status).toBe(405);
    expect(del.status).toBe(204);
    expect(upstream.requests.filter((q) => q.method === "GET")).toHaveLength(0);
  });

  it("OAuth discovery, registration, authorize, token and sub-paths get a local 404", async () => {
    const upstream = await stub();
    const r = await relay();
    const { url, token } = r.register({ grant: ALLOW_ALL, serverName: "records", url: upstream.url, headers: {} });
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
    const { url, token } = r.register({ grant: ALLOW_ALL, serverName: "records", url: upstream.url, headers: {} });

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
    const { url } = r.register({ grant: ALLOW_ALL, serverName: "records", url: upstream.url, headers: {} });

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
    const { url, token } = r.register({ grant: ALLOW_ALL, serverName: "records", url: upstream.url, headers: {} });

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

  it.each([
    ["a single request", rpc("tools/call", 1, { name: "x", arguments: {} })],
    ["a batch", [rpc("tools/call", 1, { name: "x", arguments: {} }), rpc("tools/call", 2, { name: "y", arguments: {} })]],
  ])("revoking a token while %s is still uploading closes the connection and sends nothing upstream", async (_label, message) => {
    const seenAuth: (string | undefined)[] = [];
    const upstream = await rawUpstream((req, res) => {
      seenAuth.push(req.headers.authorization);
      req.resume();
      req.on("end", () => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end('{"jsonrpc":"2.0","id":1,"result":{}}');
      });
    });
    const r = await relay();
    const { url, token } = r.register({ grant: ALLOW_ALL, serverName: "records", url: upstream.url, headers: { Authorization: "Bearer RUN-SECRET" } });
    const body = JSON.stringify(message);
    const half = Math.floor(body.length / 2);

    let closedBeforeRest = false;
    let restSent = false;
    const outcome = await new Promise<string>((resolve) => {
      const req = http.request(url, { method: "POST", agent: false, headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) } }, (res) => {
        res.resume();
        res.on("end", () => resolve(`status ${res.statusCode}`));
        res.on("error", () => resolve("destroyed"));
      });
      req.on("error", () => resolve("destroyed"));
      req.on("socket", (socket) => socket.on("close", () => (closedBeforeRest ||= !restSent)));
      req.write(body.slice(0, half));
      setTimeout(() => {
        r.revoke(token);
        setTimeout(() => {
          restSent = true;
          if (!req.destroyed) req.end(body.slice(half));
        }, 100);
      }, 150);
    });
    await new Promise((resolve) => setTimeout(resolve, 100));

    expect(outcome).toBe("destroyed");
    expect(closedBeforeRest).toBe(true);
    expect(upstream.hits()).toBe(0);
    expect(seenAuth).toEqual([]);
  });

  it("revoking a token destroys its in-flight DELETE", async () => {
    let upstreamClosed = false;
    const upstream = await rawUpstream((req) => {
      req.resume();
      req.socket.on("close", () => (upstreamClosed = true));
    });
    const r = await relay();
    const { url, token } = r.register({ grant: ALLOW_ALL, serverName: "records", url: upstream.url, headers: {} });

    const pending = send(url, { method: "DELETE", headers: { "Mcp-Session-Id": "stub-session-9" } }).then(
      () => "answered",
      () => "destroyed",
    );
    while (upstream.hits() === 0) await new Promise((resolve) => setTimeout(resolve, 10));
    r.revoke(token);

    expect(await pending).toBe("destroyed");
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(upstreamClosed).toBe(true);
  });

  it("after revocation every relay entry point answers a local 404: POST, batch POST, GET stream and DELETE", async () => {
    const upstream = await rawUpstream((req, res) => {
      req.resume();
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end("{}");
    });
    const r = await relay();
    const { url, token } = r.register({ grant: ALLOW_ALL, serverName: "records", url: upstream.url, headers: { Authorization: "Bearer RUN-SECRET" } });
    r.revoke(token);

    const answers = [
      await send(url, { body: rpc("tools/call", 1, { name: "x" }) }),
      await send(url, { body: [rpc("tools/call", 1, { name: "x" }), rpc("tools/list", 2)] }),
      await send(url, { method: "GET", headers: { Accept: "text/event-stream" } }),
      await send(url, { method: "DELETE", headers: { "Mcp-Session-Id": "stub-session-9" } }),
    ];

    expect(answers.map((a) => a.status)).toEqual([404, 404, 404, 404]);
    expect(answers.map((a) => a.text)).toEqual(["", "", "", ""]);
    expect(upstream.hits()).toBe(0);
  });

  it("never logs the relay URL, path or token", async () => {
    const upstream = await stub({ refuse: "tools-call" });
    const r = await relay();
    const { url, token } = r.register({ grant: ALLOW_ALL, serverName: "records", url: upstream.url, headers: {} });

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


/* ------------------------------------------------------------------ */
/*  MVP-7679: message rules, grant, answer validation, credentials      */
/* ------------------------------------------------------------------ */

const DENIED = "TOOL_DENIED: This tool is not allowed for this request. Do not retry; continue without it or tell the user.";
const INVALID = 'TOOL_RESPONSE_INVALID: "records" sent an answer the gateway could not read. If it keeps happening, tell your gateway administrator.';
const NO_CREDENTIAL = 'TOOL_AUTH_UNAVAILABLE: No credential for "records" was provided with this request. Ask the user to connect their account; retrying will not help.';
const USER_REFUSED = `TOOL_AUTH_UNAVAILABLE: "records" did not accept the user's credential. Ask the user to reconnect their account; retrying will not help.`;

/** An upstream that records every raw body and header set it receives and answers like the MCP stub. */
async function recordingUpstream(answer?: (body: string, res: ServerResponse) => boolean): Promise<{ url: string; bodies: string[]; headers: IncomingHttpHeaders[] }> {
  const bodies: string[] = [];
  const headers: IncomingHttpHeaders[] = [];
  const created = await rawUpstream((req, res) => {
    headers.push(req.headers);
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf8");
      bodies.push(body);
      if (answer?.(body, res)) return;
      const message = JSON.parse(body) as { id?: unknown };
      if (message.id === undefined) {
        res.writeHead(202);
        res.end();
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ jsonrpc: "2.0", id: message.id, result: { ok: true } }));
    });
  });
  return { url: created.url, bodies, headers };
}

const only = (...tools: string[]): RelayGrant => ({ allowsTool: (tool) => tools.includes(tool), coversServer: false });

describe("relay message rules: what is refused locally, with zero upstream requests", () => {
  const utf16 = Buffer.from(JSON.stringify(rpc("tools/call", 1, { name: "lookup_record", arguments: {} })), "utf16le");
  const bom = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(JSON.stringify(rpc("tools/call", 1, { name: "lookup_record", arguments: {} })))]);
  const badUtf8 = Buffer.concat([Buffer.from('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lookup_record","arguments":{"a":"'), Buffer.from([0xff, 0xfe]), Buffer.from('"}}}')]);

  it.each<[string, Buffer | unknown, number | null]>([
    ["a body that is not JSON", Buffer.from("{nope"), null],
    ["a body with a byte order mark", bom, null],
    ["a UTF-16 body", utf16, null],
    ["a body with invalid UTF-8", badUtf8, null],
    ["an empty body", Buffer.alloc(0), null],
    ["a JSON string", Buffer.from('"tools/call"'), null],
    ["a JSON number", Buffer.from("42"), null],
    ["null", Buffer.from("null"), null],
    ["a batch of allowed requests", [rpc("tools/list", 1), rpc("ping", 2)], null],
    ["an empty batch", [], null],
    ["a response from the runtime (no method)", { jsonrpc: "2.0", id: 5, result: {} }, 5],
    ["a message whose method is not a string", { jsonrpc: "2.0", id: 6, method: 7 }, 6],
    ["a request with an object id", { jsonrpc: "2.0", id: { a: 1 }, method: "ping" }, null],
    ["tools/call without params", { jsonrpc: "2.0", id: 8, method: "tools/call" }, 8],
    ["tools/call whose params are an array", { jsonrpc: "2.0", id: 9, method: "tools/call", params: [] }, 9],
    ["tools/call without a name", rpc("tools/call", 10, { arguments: {} }), 10],
    ["tools/call with a numeric name", rpc("tools/call", 11, { name: 5 }), 11],
    ["tools/call with an empty name", rpc("tools/call", 12, { name: "" }), 12],
    ["tools/call with arguments that are an array", rpc("tools/call", 13, { name: "lookup_record", arguments: [] }), 13],
    ["tools/call with arguments that are a string", rpc("tools/call", 14, { name: "lookup_record", arguments: "x" }), 14],
  ])("%s", async (_label, message, id) => {
    const upstream = await stub();
    const r = await relay();
    const { url } = r.register({ grant: ALLOW_ALL, serverName: "records", url: upstream.url, headers: { Authorization: "Bearer BOUND" } });

    const res = Buffer.isBuffer(message) ? await send(url, { rawBody: message }) : await send(url, { body: message });

    expect(res.status).toBe(200);
    expect(JSON.parse(res.text)).toEqual({ jsonrpc: "2.0", id, error: { code: -32600, message: DENIED } });
    expect(upstream.requests).toHaveLength(0);
    expect(logs.join("\n")).toContain("mcp.relay.refused serverName=records reason=invalid_message");
  });
});

describe("relay grant: tools/call by exact name", () => {
  it("a tool in the grant is forwarded; every other name is TOOL_DENIED as a tool error with the request's id and no upstream request", async () => {
    const upstream = await stub({ toolNames: ["lookup_record", "delete_record"] });
    const r = await relay();
    const { url } = r.register({ grant: only("lookup_record"), serverName: "records", url: upstream.url, headers: {} });

    const allowed = await send(url, { body: rpc("tools/call", 1, { name: "lookup_record", arguments: { id: "R-1" } }) });
    expect(JSON.parse(allowed.text).result.content[0].text).toContain("RECORD-7667-OK");
    for (const [index, name] of ["delete_record", "lookup_record ", "LOOKUP_RECORD", "lookup_record\u0000", "mcp__records__delete_record"].entries()) {
      const res = await send(url, { body: rpc("tools/call", 100 + index, { name, arguments: {} }) });
      expect(JSON.parse(res.text), JSON.stringify(name)).toEqual({ jsonrpc: "2.0", id: 100 + index, result: { content: [{ type: "text", text: DENIED }], isError: true } });
    }
    expect(upstream.toolCalls).toEqual(["lookup_record"]);
    expect(logs.join("\n")).toContain("mcp.relay.refused serverName=records reason=tool_denied");
  });

  it("a denied notification-shaped tools/call (no id) is acknowledged with 202 and nothing is sent upstream", async () => {
    const upstream = await stub();
    const r = await relay();
    const { url } = r.register({ grant: only(), serverName: "records", url: upstream.url, headers: {} });
    const res = await send(url, { body: { jsonrpc: "2.0", method: "tools/call", params: { name: "x" } } });
    expect(res.status).toBe(202);
    expect(upstream.requests).toHaveLength(0);
  });
});

describe("relay methods are default-deny", () => {
  const FORWARDED = [
    ["initialize", rpc("initialize", 1, { protocolVersion: "2025-06-18" })],
    ["ping", rpc("ping", 2)],
    ["tools/list", rpc("tools/list", 3)],
  ] as const;

  it.each(FORWARDED)("%s is forwarded whatever the grant", async (method, message) => {
    const upstream = await stub();
    const r = await relay();
    const { url } = r.register({ grant: only(), serverName: "records", url: upstream.url, headers: {} });
    const res = await send(url, { body: message });
    expect(JSON.parse(res.text).result).toBeDefined();
    expect(upstream.requests.flatMap((q) => q.rpcMethods)).toEqual([method]);
  });

  it.each(["notifications/initialized", "notifications/cancelled", "notifications/progress", "notifications/roots/list_changed"])("the client notification %s is forwarded (202)", async (method) => {
    const upstream = await stub();
    const r = await relay();
    const { url } = r.register({ grant: only(), serverName: "records", url: upstream.url, headers: {} });
    const res = await send(url, { body: rpc(method) });
    expect(res.status).toBe(202);
    expect(upstream.requests.flatMap((q) => q.rpcMethods)).toEqual([method]);
  });

  it.each(["resources/list", "resources/read", "resources/subscribe", "prompts/list", "prompts/get", "completion/complete", "logging/setLevel", "sampling/createMessage", "notifications/unknown", "tools/list_changed", "x"])(
    "%s is TOOL_DENIED unless the grant covers the whole server",
    async (method) => {
      const upstream = await stub();
      const r = await relay();
      const { url } = r.register({ grant: only("lookup_record"), serverName: "records", url: upstream.url, headers: {} });
      const res = await send(url, { body: method.startsWith("notifications/") ? rpc(method) : rpc(method, 7) });
      if (method.startsWith("notifications/")) {
        expect(res.status).toBe(202);
        expect(res.text).toBe("");
      } else {
        expect(JSON.parse(res.text)).toEqual({ jsonrpc: "2.0", id: 7, error: { code: -32001, message: DENIED } });
      }
      expect(upstream.requests).toHaveLength(0);
      expect(logs.join("\n")).toContain("mcp.relay.refused serverName=records reason=method_denied");
    },
  );

  it.each(["resources/list", "prompts/get", "completion/complete", "logging/setLevel"])("%s is forwarded when the grant covers the whole server", async (method) => {
    const upstream = await stub();
    const r = await relay();
    const { url } = r.register({ grant: { allowsTool: () => true, coversServer: true }, serverName: "records", url: upstream.url, headers: {} });
    await send(url, { body: rpc(method, 7) });
    expect(upstream.requests.flatMap((q) => q.rpcMethods)).toEqual([method]);
  });
});

describe("relay forwards the re-serialized parsed message, never the raw bytes", () => {
  it("duplicate keys and whitespace are gone, the content type is application/json whatever the runtime sent, and only allowlisted headers travel", async () => {
    const upstream = await recordingUpstream();
    const r = await relay();
    const { url } = r.register({ grant: ALLOW_ALL, serverName: "records", url: upstream.url, headers: { Authorization: "Bearer BOUND" } });
    const raw = Buffer.from('{ "jsonrpc": "2.0",\n "id": 1, "method": "ping" ,"id": 2 }');

    const res = await send(url, { rawBody: raw, headers: { "Content-Type": "text/plain", Authorization: "Bearer RUNTIME", Cookie: "c=1", "X-Agent": "evil", "Mcp-Session-Id": "s-1", "Content-Length": String(raw.length) } });

    expect(JSON.parse(res.text).id).toBe(2);
    expect(upstream.bodies).toEqual(['{"jsonrpc":"2.0","id":2,"method":"ping"}']);
    expect(upstream.headers[0]["content-type"]).toBe("application/json");
    expect(upstream.headers[0].authorization).toBe("Bearer BOUND");
    expect(upstream.headers[0].cookie).toBeUndefined();
    expect(upstream.headers[0]["x-agent"]).toBeUndefined();
    expect(upstream.headers[0]["mcp-session-id"]).toBe("s-1");
    expect(upstream.headers[0]["content-length"]).toBe(String(upstream.bodies[0].length));
  });

  it("a changed Authorization header from the agent cannot replace the bound credential (every casing)", async () => {
    const upstream = await recordingUpstream();
    const r = await relay();
    const { url } = r.register({ grant: ALLOW_ALL, serverName: "records", url: upstream.url, headers: { authorization: "Bearer BOUND" } });
    for (const name of ["Authorization", "authorization", "AUTHORIZATION", "X-Authorization"]) await send(url, { body: rpc("ping", 1), headers: { [name]: "Bearer AGENT" } });
    expect(upstream.headers.map((h) => h.authorization)).toEqual(["Bearer BOUND", "Bearer BOUND", "Bearer BOUND", "Bearer BOUND"]);
    expect(upstream.headers.every((h) => h["x-authorization"] === undefined)).toBe(true);
  });
});

describe("relay validates the upstream answer", () => {
  const bad: [string, string, string][] = [
    ["a body that is not JSON", "<html>ok</html>", "application/json"],
    ["an empty body", "", "application/json"],
    ["an answer for another id", JSON.stringify({ jsonrpc: "2.0", id: 999, result: {} }), "application/json"],
    ["an answer without result or error", JSON.stringify({ jsonrpc: "2.0", id: 1 }), "application/json"],
    ["a batch answer", JSON.stringify([{ jsonrpc: "2.0", id: 1, result: {} }]), "application/json"],
    ["a JSON answer with a text content type", JSON.stringify({ jsonrpc: "2.0", id: 1, result: {} }), "text/html"],
    ["an event stream with no message for the id", 'event: message\ndata: {"jsonrpc":"2.0","id":2,"result":{}}\n\n', "text/event-stream"],
    ["an event stream whose data is not JSON", "event: message\ndata: nope\n\n", "text/event-stream"],
    ["an empty event stream", "", "text/event-stream"],
  ];

  it.each(bad)("%s is TOOL_RESPONSE_INVALID, with no upstream detail", async (_label, body, contentType) => {
    const upstream = await rawUpstream((req, res) => {
      req.resume();
      res.writeHead(200, { "Content-Type": contentType });
      res.end(body);
    });
    const r = await relay();
    const { url } = r.register({ grant: ALLOW_ALL, serverName: "records", url: upstream.url, headers: {} });
    const res = await send(url, { body: rpc("tools/call", 1, { name: "x", arguments: {} }) });
    expect(JSON.parse(res.text)).toEqual({ jsonrpc: "2.0", id: 1, result: { content: [{ type: "text", text: INVALID }], isError: true } });
    expect(res.text).not.toContain("html");
    expect(logs.join("\n")).toContain("mcp.relay.refused serverName=records reason=invalid_response");
  });

  it("an answer over the size cap is TOOL_RESPONSE_INVALID", async () => {
    const upstream = await stub({ toolResultBytes: 4096 });
    const r = await relay({ maxResponseBytes: 1024 });
    const { url } = r.register({ grant: ALLOW_ALL, serverName: "records", url: upstream.url, headers: {} });
    const res = await send(url, { body: rpc("tools/call", 1, { name: "lookup_record", arguments: { id: "R-1" } }) });
    expect(JSON.parse(res.text).result.content[0].text).toBe(INVALID);
  });

  it("an event stream with a progress notification before the answer returns the answer as JSON", async () => {
    const upstream = await rawUpstream((req, res) => {
      req.resume();
      res.writeHead(200, { "Content-Type": "text/event-stream" });
      res.write('event: message\ndata: {"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1}}\n\n');
      res.write('event: message\ndata: {"jsonrpc":"2.0","id":3,"method":"sampling/createMessage","params":{}}\n\n');
      res.end('event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"done"}]}}\n\n');
    });
    const r = await relay();
    const { url } = r.register({ grant: ALLOW_ALL, serverName: "records", url: upstream.url, headers: {} });
    const res = await send(url, { body: rpc("tools/call", 1, { name: "x", arguments: {} }) });
    expect(res.headers["content-type"]).toBe("application/json");
    expect(JSON.parse(res.text)).toEqual({ jsonrpc: "2.0", id: 1, result: { content: [{ type: "text", text: "done" }] } });
  });

  it("an upstream JSON-RPC error and a tool-level isError result pass through unchanged", async () => {
    const upstream = await rawUpstream((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (chunk: Buffer) => chunks.push(chunk));
      req.on("end", () => {
        const message = JSON.parse(Buffer.concat(chunks).toString("utf8")) as { id: number; method: string };
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(message.method === "tools/call" ? { jsonrpc: "2.0", id: message.id, result: { isError: true, content: [{ type: "text", text: "the tool says no" }] } } : { jsonrpc: "2.0", id: message.id, error: { code: -32602, message: "bad params" } }));
      });
    });
    const r = await relay();
    const { url } = r.register({ grant: ALLOW_ALL, serverName: "records", url: upstream.url, headers: {} });
    const call = await send(url, { body: rpc("tools/call", 1, { name: "x" }) });
    const list = await send(url, { body: rpc("tools/list", 2) });
    expect(JSON.parse(call.text).result).toEqual({ isError: true, content: [{ type: "text", text: "the tool says no" }] });
    expect(JSON.parse(list.text).error).toEqual({ code: -32602, message: "bad params" });
  });

  it("a notification is accepted with 202 whatever the upstream body says", async () => {
    const upstream = await rawUpstream((req, res) => {
      req.resume();
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end("<html>whatever</html>");
    });
    const r = await relay();
    const { url } = r.register({ grant: ALLOW_ALL, serverName: "records", url: upstream.url, headers: {} });
    const res = await send(url, { body: rpc("notifications/initialized") });
    expect(res.status).toBe(202);
    expect(res.text).toBe("");
  });
});

describe("relay credentials", () => {
  it("a server that needs a user credential and the run carries none: tools/call is TOOL_AUTH_UNAVAILABLE with no upstream request; the handshake still goes upstream", async () => {
    const upstream = await stub();
    const r = await relay();
    const { url } = r.register({ grant: ALLOW_ALL, serverName: "records", url: upstream.url, headers: { Authorization: "Basic SHARED" }, noUserCredential: true });

    const call = await send(url, { body: rpc("tools/call", 1, { name: "lookup_record", arguments: {} }) });
    const init = await send(url, { body: rpc("initialize", 2) });
    const list = await send(url, { body: rpc("tools/list", 3) });

    expect(JSON.parse(call.text)).toEqual({ jsonrpc: "2.0", id: 1, result: { content: [{ type: "text", text: NO_CREDENTIAL }], isError: true } });
    expect(JSON.parse(init.text).result).toBeDefined();
    expect(JSON.parse(list.text).result.tools).toHaveLength(1);
    expect(upstream.toolCalls).toEqual([]);
    expect(logs.join("\n")).toContain("mcp.relay.refused serverName=records reason=no_credential");
  });

  it.each([
    ["user", USER_REFUSED],
    ["gateway", GATEWAY_REFUSED],
    [undefined, GATEWAY_REFUSED],
  ] as const)("a refused credential from source %s reads with the matching text", async (credentialSource, text) => {
    const upstream = await stub({ refuse: "tools-call" });
    const r = await relay();
    const { url } = r.register({ grant: ALLOW_ALL, serverName: "records", url: upstream.url, headers: {}, credentialSource });
    const res = await send(url, { body: rpc("tools/call", 1, { name: "lookup_record", arguments: {} }) });
    expect(JSON.parse(res.text).result.content[0].text).toBe(text);
  });

  it("a refused credential is never retried with another: one upstream request per message", async () => {
    const upstream = await stub({ refuse: "tools-call" });
    const r = await relay();
    const { url } = r.register({ grant: ALLOW_ALL, serverName: "records", url: upstream.url, headers: { Authorization: "Bearer USER" } });
    await send(url, { body: rpc("tools/call", 1, { name: "lookup_record", arguments: {} }) });
    expect(upstream.requests).toHaveLength(1);
    expect(upstream.authorizations()).toEqual(["Bearer USER"]);
    expect(upstream.counters.registration + upstream.counters.authorize + upstream.counters.token + upstream.counters.metadata).toBe(0);
  });
});

describe("relay deadlines", () => {
  it("an upstream that keeps sending but never finishes a tools/call is cut off at the overall deadline", async () => {
    const upstream = await rawUpstream((req, res) => {
      req.resume();
      res.writeHead(200, { "Content-Type": "text/event-stream" });
      const timer = setInterval(() => res.write(": keep-alive\n\n"), 50);
      res.on("close", () => clearInterval(timer));
    });
    const r = await relay({ toolTimeoutMs: 400, idleTimeoutMs: 5000 });
    const { url } = r.register({ grant: ALLOW_ALL, serverName: "records", url: upstream.url, headers: {} });

    const started = Date.now();
    const res = await send(url, { body: rpc("tools/call", 1, { name: "x", arguments: {} }) });
    const elapsed = Date.now() - started;

    expect(elapsed).toBeGreaterThanOrEqual(350);
    expect(elapsed).toBeLessThan(3000);
    expect(JSON.parse(res.text).result).toEqual({
      content: [{ type: "text", text: 'TOOL_TIMEOUT: "records" did not answer within 1 seconds. Try again later or with a smaller request; if it keeps happening, tell your gateway administrator.' }],
      isError: true,
    });
  });

  it("the overall deadline applies to tools/call only: a slow initialize is bounded by the idle timeout", async () => {
    const upstream = await rawUpstream((req, res) => {
      req.resume();
      setTimeout(() => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { ok: true } }));
      }, 600);
    });
    const r = await relay({ toolTimeoutMs: 200, idleTimeoutMs: 5000 });
    const { url } = r.register({ grant: ALLOW_ALL, serverName: "records", url: upstream.url, headers: {} });
    const res = await send(url, { body: rpc("initialize", 1) });
    expect(JSON.parse(res.text).result).toEqual({ ok: true });
  });

  it("the deadline comes from AGENT_MCP_TOOL_TIMEOUT_MS when the relay is not given one", async () => {
    process.env.AGENT_MCP_TOOL_TIMEOUT_MS = "300";
    cleanups.push(() => {
      delete process.env.AGENT_MCP_TOOL_TIMEOUT_MS;
    });
    const upstream = await rawUpstream((req) => req.resume());
    const r = await relay({ idleTimeoutMs: 5000 });
    const { url } = r.register({ grant: ALLOW_ALL, serverName: "records", url: upstream.url, headers: {} });
    const started = Date.now();
    const res = await send(url, { body: rpc("tools/call", 1, { name: "x", arguments: {} }) });
    expect(Date.now() - started).toBeLessThan(2500);
    expect(JSON.parse(res.text).result.content[0].text).toContain("TOOL_TIMEOUT");
  });
});

describe("relay redirects are never followed", () => {
  it.each([301, 302, 303, 307, 308])("a %i answer to tools/call and to initialize is the redirect text; the target gets no request and no credential", async (status) => {
    const target = await recordingUpstream();
    const upstream = await rawUpstream((req, res) => {
      req.resume();
      res.writeHead(status, { Location: target.url });
      res.end();
    });
    const r = await relay();
    const { url } = r.register({ grant: ALLOW_ALL, serverName: "records", url: upstream.url, headers: { Authorization: "Bearer BOUND" } });
    const call = await send(url, { body: rpc("tools/call", 1, { name: "x", arguments: {} }) });
    const init = await send(url, { body: rpc("initialize", 2) });
    expect(JSON.parse(call.text).result.content[0].text).toBe(REDIRECTED);
    expect(JSON.parse(init.text).error.message).toBe(REDIRECTED);
    expect(target.bodies).toEqual([]);
  });
});
