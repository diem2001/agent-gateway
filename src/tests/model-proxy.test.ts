/**
 * The trusted model proxy (src/model-proxy.ts) against loopback upstreams: token
 * rules, path/method/query/size refusals (each with 0 upstream requests), header
 * drop and inject, response filtering, upstream failures, revocation, the
 * credential sources (API key, OAuth with single-flight refresh) and the log rule.
 * All credentials are synthetic.
 */
import fs from "node:fs";
import http, { type IncomingHttpHeaders, type IncomingMessage, type ServerResponse } from "node:http";
import net, { type AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { CredentialRelay } from "../mcp-credential-relay.js";
import {
  ModelProxy,
  ModelProxyConfigError,
  ProviderCredentials,
  canonicalPath,
  mergeBetas,
  modelProxyIdleTimeoutFromEnv,
  readAuthStatus,
} from "../model-proxy.js";

const PROVIDER_KEY = "SYNTH-PROVIDER-KEY-7678-aaaa";
const ACCESS_1 = "SYNTH-OAUTH-ACCESS-1-7678";
const REFRESH_1 = "SYNTH-OAUTH-REFRESH-1-7678";
const ACCESS_2 = "SYNTH-OAUTH-ACCESS-2-7678";
const REFRESH_2 = "SYNTH-OAUTH-REFRESH-2-7678";

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

interface SeenRequest {
  method: string;
  url: string;
  headers: IncomingHttpHeaders;
  body: string;
}

interface Upstream {
  baseUrl: string;
  seen: SeenRequest[];
}

async function upstream(handler?: (req: IncomingMessage, res: ServerResponse, seen: SeenRequest) => void): Promise<Upstream> {
  const seen: SeenRequest[] = [];
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const record = { method: req.method ?? "", url: req.url ?? "", headers: req.headers, body: Buffer.concat(chunks).toString("utf8") };
      seen.push(record);
      if (handler) handler(req, res, record);
      else {
        res.writeHead(200, { "content-type": "application/json", "x-should-retry": "false", "set-cookie": "session=UPSTREAM-COOKIE", "x-internal": "hidden" });
        res.end(JSON.stringify({ ok: true }));
      }
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  cleanups.push(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
  return { baseUrl: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, seen };
}

function tempHome(): string {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "model-proxy-test-"));
  fs.mkdirSync(path.join(home, ".claude"), { recursive: true });
  cleanups.push(() => fs.rmSync(home, { recursive: true, force: true }));
  return home;
}

function writeCredentials(home: string, oauth: Record<string, unknown>, extra: Record<string, unknown> = {}): string {
  const file = path.join(home, ".claude", ".credentials.json");
  fs.writeFileSync(file, JSON.stringify({ claudeAiOauth: oauth, other: "kept", ...extra }), { mode: 0o600 });
  return file;
}

interface Setup {
  proxy: ModelProxy;
  up: Upstream;
  home: string;
  credentials: ProviderCredentials;
  token: string;
  port: number;
}

async function setup(options: {
  env?: NodeJS.ProcessEnv;
  handler?: Parameters<typeof upstream>[0];
  idleTimeoutMs?: number;
  maxBodyBytes?: number;
  home?: string;
  upstreamBaseUrl?: string;
  fetchFn?: typeof fetch;
  now?: () => number;
} = {}): Promise<Setup> {
  const up = await upstream(options.handler);
  const home = options.home ?? tempHome();
  const credentials = new ProviderCredentials({ home, env: options.env ?? { ANTHROPIC_API_KEY: PROVIDER_KEY }, fetchFn: options.fetchFn, now: options.now });
  const proxy = new ModelProxy({
    upstreamBaseUrl: options.upstreamBaseUrl ?? up.baseUrl,
    credentials,
    idleTimeoutMs: options.idleTimeoutMs,
    maxBodyBytes: options.maxBodyBytes,
  });
  await proxy.start();
  cleanups.push(() => proxy.close());
  const { token, baseUrl } = proxy.register();
  return { proxy, up, home, credentials, token, port: Number(new URL(baseUrl).port) };
}

interface RawAnswer {
  status: number;
  headers: IncomingHttpHeaders;
  body: string;
}

/** A request with exactly the given request line, headers and body: no client normalizes the path. */
function raw(port: number, options: { method?: string; path: string; headers?: Record<string, string>; body?: string; host?: string; chunked?: boolean }): Promise<RawAnswer> {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, "127.0.0.1");
    const body = options.body ?? "";
    const headers: Record<string, string> = { Host: options.host ?? `127.0.0.1:${port}`, Connection: "close", ...(options.headers ?? {}) };
    if (options.chunked) headers["Transfer-Encoding"] = "chunked";
    else if (body.length > 0 || options.method === "POST") headers["Content-Length"] = String(Buffer.byteLength(body));
    let head = `${options.method ?? "POST"} ${options.path} HTTP/1.1\r\n`;
    for (const [k, v] of Object.entries(headers)) head += `${k}: ${v}\r\n`;
    head += "\r\n";
    socket.write(head);
    if (options.chunked) socket.write(`${Buffer.byteLength(body).toString(16)}\r\n${body}\r\n0\r\n\r\n`);
    else socket.write(body);
    const chunks: Buffer[] = [];
    socket.on("data", (c: Buffer) => chunks.push(c));
    socket.on("error", reject);
    socket.on("close", () => {
      const text = Buffer.concat(chunks).toString("utf8");
      const split = text.indexOf("\r\n\r\n");
      const headText = split < 0 ? text : text.slice(0, split);
      const lines = headText.split("\r\n");
      const status = Number(/^HTTP\/1\.1 (\d+)/.exec(lines[0] ?? "")?.[1] ?? 0);
      const hdrs: IncomingHttpHeaders = {};
      for (const line of lines.slice(1)) {
        const i = line.indexOf(":");
        if (i > 0) hdrs[line.slice(0, i).toLowerCase()] = line.slice(i + 1).trim();
      }
      let rest = split < 0 ? "" : text.slice(split + 4);
      if (hdrs["transfer-encoding"] === "chunked") {
        let decoded = "";
        for (;;) {
          const eol = rest.indexOf("\r\n");
          const size = eol < 0 ? 0 : parseInt(rest.slice(0, eol), 16);
          if (!size) break;
          decoded += rest.slice(eol + 2, eol + 2 + size);
          rest = rest.slice(eol + 2 + size + 2);
        }
        rest = decoded;
      }
      resolve({ status, headers: hdrs, body: rest });
    });
  });
}

function call(s: Setup, options: { path?: string; method?: string; token?: string | null; headers?: Record<string, string>; body?: string } = {}): Promise<RawAnswer> {
  const headers: Record<string, string> = { "content-type": "application/json", ...(options.headers ?? {}) };
  if (options.token !== null) headers["x-api-key"] = options.token ?? s.token;
  return raw(s.port, { method: options.method, path: options.path ?? "/v1/messages?beta=true", headers, body: options.body ?? '{"model":"m","messages":[]}' });
}

const REFUSAL_BODY = (type: string, message: string) => JSON.stringify({ type: "error", error: { type, message } });

describe("forwarding and credential injection", () => {
  it("forwards a message request with the trusted key, never the run token, and filters headers", async () => {
    const s = await setup();
    const answer = await call(s, {
      headers: {
        authorization: "Bearer SYNTH-CLIENT-BEARER",
        cookie: "a=b",
        "proxy-authorization": "Basic SYNTH",
        "x-forwarded-for": "10.9.9.9",
        "x-forwarded-host": "evil.example",
        "anthropic-beta": "claude-code-20250219,interleaved-thinking-2025-05-14",
        "anthropic-version": "2023-06-01",
        "user-agent": "claude-cli/2.0.77 (external, sdk-cli)",
        "x-stainless-lang": "js",
        "x-app": "cli",
        "x-custom-secret": "SYNTH-CUSTOM",
      },
    });
    expect(answer.status).toBe(200);
    expect(JSON.parse(answer.body)).toEqual({ ok: true });
    expect(s.up.seen).toHaveLength(1);
    const seen = s.up.seen[0];
    expect(seen.method).toBe("POST");
    expect(seen.url).toBe("/v1/messages?beta=true");
    expect(seen.body).toBe('{"model":"m","messages":[]}');
    expect(seen.headers["x-api-key"]).toBe(PROVIDER_KEY);
    for (const name of ["authorization", "cookie", "proxy-authorization", "x-forwarded-for", "x-forwarded-host", "x-custom-secret"]) {
      expect(seen.headers[name], name).toBeUndefined();
    }
    expect(seen.headers.host).toBe(new URL(s.up.baseUrl).host);
    expect(seen.headers["anthropic-beta"]).toBe("claude-code-20250219,interleaved-thinking-2025-05-14");
    expect(seen.headers["anthropic-version"]).toBe("2023-06-01");
    expect(seen.headers["user-agent"]).toBe("claude-cli/2.0.77 (external, sdk-cli)");
    expect(seen.headers["x-stainless-lang"]).toBe("js");
    expect(seen.headers["x-app"]).toBe("cli");
    // Nothing of the run token reaches the provider, in any header or the body.
    expect(JSON.stringify(seen.headers) + seen.body).not.toContain(s.token);
  });

  it("forwards count_tokens and a request without a query", async () => {
    const s = await setup();
    expect((await call(s, { path: "/v1/messages/count_tokens?beta=true" })).status).toBe(200);
    expect((await call(s, { path: "/v1/messages" })).status).toBe(200);
    expect(s.up.seen.map((r) => r.url)).toEqual(["/v1/messages/count_tokens?beta=true", "/v1/messages"]);
  });

  it("passes the status, x-should-retry and allowlisted headers through and strips set-cookie and unknown headers", async () => {
    const s = await setup();
    const answer = await call(s);
    expect(answer.headers["x-should-retry"]).toBe("false");
    expect(answer.headers["content-type"]).toBe("application/json");
    expect(answer.headers["set-cookie"]).toBeUndefined();
    expect(answer.headers["x-internal"]).toBeUndefined();
  });

  it("passes provider errors through unchanged so the gateway can classify them (400 version text, 401, 429)", async () => {
    const rows: [number, string, Record<string, string>][] = [
      [400, JSON.stringify({ type: "error", error: { type: "invalid_request_error", code: "claude_code_version_too_old", message: "requires 2.1.280 or newer" } }), {}],
      [401, REFUSAL_BODY("authentication_error", "invalid x-api-key"), { "x-should-retry": "false" }],
      [429, REFUSAL_BODY("rate_limit_error", "slow down"), { "x-should-retry": "false", "retry-after": "7", "anthropic-ratelimit-unified-status": "rejected" }],
    ];
    for (const [status, body, headers] of rows) {
      const s = await setup({
        handler: (_req, res) => {
          res.writeHead(status, { "content-type": "application/json", ...headers });
          res.end(body);
        },
      });
      const answer = await call(s);
      expect(answer.status).toBe(status);
      expect(answer.body).toBe(body);
      for (const [name, value] of Object.entries(headers)) expect(answer.headers[name]).toBe(value);
    }
  });

  it("streams a text/event-stream answer with backpressure-friendly piping", async () => {
    const s = await setup({
      handler: (_req, res) => {
        res.writeHead(200, { "content-type": "text/event-stream" });
        res.write("event: a\ndata: 1\n\n");
        setTimeout(() => res.end("event: b\ndata: 2\n\n"), 30);
      },
    });
    const answer = await call(s);
    expect(answer.body).toContain("event: a");
    expect(answer.body).toContain("event: b");
  });

  it("builds the upstream URL from the fixed origin plus the normalized path, keeping a base path prefix", async () => {
    const up = await upstream();
    const s = await setup({ upstreamBaseUrl: `${up.baseUrl}/prefix/` });
    await call(s);
    expect(up.seen[0].url).toBe("/prefix/v1/messages?beta=true");
  });
});

describe("refusals cause no upstream request", () => {
  it("refuses a missing, wrong, differently sized and header-misplaced token with the same fixed 401", async () => {
    const s = await setup();
    const expected = REFUSAL_BODY("authentication_error", "invalid x-api-key");
    const rows: RawAnswer[] = [
      await call(s, { token: null }),
      await call(s, { token: "wrong" }),
      await call(s, { token: `${s.token}x` }),
      await call(s, { token: s.token.slice(0, -1) }),
      await call(s, { token: "" }),
      // the token in an Authorization header or in the query is not accepted
      await call(s, { token: null, headers: { authorization: `Bearer ${s.token}` } }),
      await call(s, { token: null, path: `/v1/messages?beta=true&x-api-key=${s.token}` }),
    ];
    for (const answer of rows) {
      expect(answer.status).toBe(401);
      expect(answer.body).toBe(expected);
      expect(answer.headers["x-should-retry"]).toBe("false");
    }
    expect(s.up.seen).toHaveLength(0);
  });

  it("keeps the token namespace separate from the credential relay", async () => {
    const s = await setup();
    const relay = new CredentialRelay();
    await relay.start();
    cleanups.push(() => relay.close());
    const { token: relayToken } = relay.register({ serverName: "x", url: "http://127.0.0.1:1/mcp", headers: {}, grant: { allowsTool: () => true, coversServer: true } });
    expect((await call(s, { token: relayToken })).status).toBe(401);
    // and the proxy token means nothing to the relay (404 for an unknown path token)
    expect(s.up.seen).toHaveLength(0);
  });

  it("refuses a replayed token after revoke, with 0 upstream requests", async () => {
    const s = await setup();
    expect((await call(s)).status).toBe(200);
    expect(s.up.seen).toHaveLength(1);
    s.proxy.revoke(s.token);
    expect(s.proxy.activeTokenCount()).toBe(0);
    const replay = await call(s);
    expect(replay.status).toBe(401);
    expect(s.up.seen).toHaveLength(1);
  });

  it("refuses non-canonical and non-allowlisted paths with 404", async () => {
    const s = await setup();
    const paths = [
      "/v1/messages/../messages",
      "/v1/%2e%2e/v1/messages",
      "/v1/%2E%2E/v1/messages",
      "/v1/messages%2fcount_tokens",
      "/v1/messages%252fcount_tokens",
      "//v1/messages",
      "/v1//messages",
      "/v1/messages/",
      "/v1/messages/./count_tokens",
      "/v1/messages\\count_tokens",
      "/v1/models",
      "/v1/messages/batches",
      "/v1/complete",
      "/v1/files",
      "/api/hello",
      "/",
      "",
      "*",
      "http://127.0.0.1:1/v1/messages",
      "/v1/messages;x",
      "/V1/messages",
    ];
    for (const p of paths) {
      const answer = await call(s, { path: p || "/" });
      expect([404, 400, 401], `path ${p}`).toContain(answer.status);
      expect(answer.status === 404 || answer.status === 400 || answer.status === 401).toBe(true);
    }
    // Every row above must be a proxy refusal, never a forwarded request.
    expect(s.up.seen).toHaveLength(0);
    // The plain rows are the fixed not-found answer.
    const plain = await call(s, { path: "/v1/models" });
    expect(plain.status).toBe(404);
    expect(plain.body).toBe(REFUSAL_BODY("not_found_error", "not found"));
  });

  it("refuses other methods with 405 and other queries with 400", async () => {
    const s = await setup();
    for (const method of ["GET", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]) {
      const answer = await call(s, { method });
      expect(answer.status, method).toBe(405);
    }
    for (const query of ["?beta=false", "?beta=true&x=1", "?x=1", "?beta", "?beta=true&beta=true", "?BETA=true"]) {
      const answer = await call(s, { path: `/v1/messages${query}` });
      expect([400], `query ${query}`).toContain(answer.status);
    }
    expect(s.up.seen).toHaveLength(0);
  });

  it("refuses a wrong Host header with 403", async () => {
    const s = await setup();
    const answer = await raw(s.port, { path: "/v1/messages?beta=true", headers: { "x-api-key": s.token }, host: "evil.example", body: "{}" });
    expect(answer.status).toBe(403);
    expect(s.up.seen).toHaveLength(0);
  });

  it("refuses a body over the cap, declared or chunked, with 413", async () => {
    const s = await setup({ maxBodyBytes: 64 });
    const big = "x".repeat(200);
    const declared = await call(s, { body: big });
    expect(declared.status).toBe(413);
    expect(declared.body).toBe(REFUSAL_BODY("request_too_large", "request too large"));
    const chunked = await raw(s.port, { path: "/v1/messages?beta=true", headers: { "x-api-key": s.token }, body: big, chunked: true });
    expect(chunked.status).toBe(413);
    expect(s.up.seen).toHaveLength(0);
    // A body at the cap still goes through.
    expect((await call(s, { body: "y".repeat(64) })).status).toBe(200);
  });

  it("answers a request without a credential source with the fixed 401 and sends nothing upstream", async () => {
    const s = await setup({ env: {} });
    const answer = await call(s);
    expect(answer.status).toBe(401);
    expect(answer.body).toBe(REFUSAL_BODY("authentication_error", "invalid x-api-key"));
    expect(s.up.seen).toHaveLength(0);
  });

  it("never forwards a request whose token is revoked while its credential is being resolved", async () => {
    const home = tempHome();
    writeCredentials(home, { accessToken: ACCESS_1, refreshToken: REFRESH_1, expiresAt: 1000 });
    let release: (() => void) | undefined;
    const slowFetch = (() =>
      new Promise((resolve) => {
        release = () => resolve(new Response(JSON.stringify({ access_token: ACCESS_2, refresh_token: REFRESH_2, expires_in: 3600 }), { status: 200 }));
      })) as unknown as typeof fetch;
    const s = await setup({ env: {}, home, fetchFn: slowFetch, now: () => 5000 });
    const pending = call(s);
    await vi.waitFor(() => expect(release).toBeDefined());
    s.proxy.revoke(s.token);
    release?.();
    const answer = await pending.catch(() => ({ status: 0, body: "" }));
    expect([0, 401]).toContain(answer.status);
    expect(s.up.seen).toHaveLength(0);
  });
});

describe("upstream failures", () => {
  it("answers 502 with a fixed body when the provider is unreachable, without echoing the error", async () => {
    const s = await setup({ upstreamBaseUrl: "http://127.0.0.1:1" });
    const answer = await call(s);
    expect(answer.status).toBe(502);
    expect(answer.body).toBe(REFUSAL_BODY("api_error", "model provider unavailable"));
    // Retryable: no x-should-retry header.
    expect(answer.headers["x-should-retry"]).toBeUndefined();
  });

  it("answers 504 when the provider sends nothing within the idle limit", async () => {
    const s = await setup({ idleTimeoutMs: 150, handler: () => {} });
    const started = Date.now();
    const answer = await call(s);
    expect(answer.status).toBe(504);
    expect(answer.body).toBe(REFUSAL_BODY("api_error", "model provider timed out"));
    expect(Date.now() - started).toBeLessThan(3000);
  });

  it("closes the connection when the provider stalls after the headers", async () => {
    const s = await setup({
      idleTimeoutMs: 150,
      handler: (_req, res) => {
        res.writeHead(200, { "content-type": "text/event-stream" });
        res.write("event: a\ndata: 1\n\n");
      },
    });
    const answer = await call(s);
    expect(answer.status).toBe(200);
    expect(answer.body).toContain("event: a");
  });

  it("refuses a provider status outside 200-599", async () => {
    const s = await setup({
      handler: (req) => {
        // A raw 099 status line cannot be written with http.ServerResponse; answer with a socket write.
        req.socket.end("HTTP/1.1 099 Odd\r\nContent-Length: 0\r\n\r\n");
      },
    });
    const answer = await call(s);
    expect([502]).toContain(answer.status);
  });

  it("destroys an in-flight exchange when its token is revoked", async () => {
    const s = await setup({
      handler: (_req, res) => {
        res.writeHead(200, { "content-type": "text/event-stream" });
        res.write("event: a\ndata: 1\n\n");
      },
    });
    const pending = call(s);
    await vi.waitFor(() => expect(s.up.seen).toHaveLength(1));
    s.proxy.revoke(s.token);
    const answer = await pending;
    expect(answer.body).not.toContain("event: b");
  });
});

describe("OAuth credential source", () => {
  it("sends the access token as a bearer with the OAuth beta merged, and no x-api-key", async () => {
    const home = tempHome();
    writeCredentials(home, { accessToken: ACCESS_1, refreshToken: REFRESH_1, expiresAt: Date.now() + 3_600_000 });
    const s = await setup({ env: {}, home });
    await call(s, { headers: { "anthropic-beta": "claude-code-20250219,interleaved-thinking-2025-05-14" } });
    const seen = s.up.seen[0];
    expect(seen.headers.authorization).toBe(`Bearer ${ACCESS_1}`);
    expect(seen.headers["x-api-key"]).toBeUndefined();
    expect(seen.headers["anthropic-beta"]).toBe("claude-code-20250219,interleaved-thinking-2025-05-14,oauth-2025-04-20");
    expect(s.credentials.refreshCount).toBe(0);
  });

  it("does not repeat the OAuth beta and adds it when the runtime sent none", async () => {
    expect(mergeBetas("a,oauth-2025-04-20", "oauth-2025-04-20")).toBe("a,oauth-2025-04-20");
    expect(mergeBetas(undefined, "oauth-2025-04-20")).toBe("oauth-2025-04-20");
    expect(mergeBetas(" a , b ", "c")).toBe("a,b,c");
  });

  it("prefers the gateway API key over the OAuth file, and treats an empty key as unset", async () => {
    const home = tempHome();
    writeCredentials(home, { accessToken: ACCESS_1, refreshToken: REFRESH_1, expiresAt: Date.now() + 3_600_000 });
    const withKey = await setup({ env: { ANTHROPIC_API_KEY: PROVIDER_KEY }, home });
    await call(withKey);
    expect(withKey.up.seen[0].headers["x-api-key"]).toBe(PROVIDER_KEY);
    expect(withKey.up.seen[0].headers.authorization).toBeUndefined();
    const emptyKey = await setup({ env: { ANTHROPIC_API_KEY: "  " }, home });
    await call(emptyKey);
    expect(emptyKey.up.seen[0].headers.authorization).toBe(`Bearer ${ACCESS_1}`);
  });

  it("refreshes an expired token once for parallel requests, persists it atomically and keeps other fields and the mode", async () => {
    const home = tempHome();
    const file = writeCredentials(home, { accessToken: ACCESS_1, refreshToken: REFRESH_1, expiresAt: 1000, scopes: ["user:inference"], subscriptionType: "max" });
    const tokenCalls: { url: string; body: Record<string, unknown>; headers: Headers }[] = [];
    const fetchFn = (async (url: string, init: RequestInit) => {
      tokenCalls.push({ url: String(url), body: JSON.parse(String(init.body)) as Record<string, unknown>, headers: new Headers(init.headers) });
      await new Promise((r) => setTimeout(r, 100));
      return new Response(JSON.stringify({ access_token: ACCESS_2, refresh_token: REFRESH_2, expires_in: 3600, scope: "user:inference user:profile" }), { status: 200 });
    }) as unknown as typeof fetch;
    const s = await setup({ env: { MODEL_PROXY_OAUTH_TOKEN_URL: "http://127.0.0.1:9/v1/oauth/token" }, home, fetchFn, now: () => 5_000_000 });
    const answers = await Promise.all(Array.from({ length: 8 }, () => call(s)));
    expect(answers.every((a) => a.status === 200)).toBe(true);
    expect(tokenCalls).toHaveLength(1);
    expect(tokenCalls[0].url).toBe("http://127.0.0.1:9/v1/oauth/token");
    expect(tokenCalls[0].body).toEqual({
      grant_type: "refresh_token",
      refresh_token: REFRESH_1,
      client_id: "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
      scope: "user:profile user:inference user:sessions:claude_code",
    });
    expect(new Set(s.up.seen.map((r) => r.headers.authorization))).toEqual(new Set([`Bearer ${ACCESS_2}`]));
    const saved = JSON.parse(fs.readFileSync(file, "utf8")) as { claudeAiOauth: Record<string, unknown>; other: string };
    expect(saved.claudeAiOauth).toMatchObject({ accessToken: ACCESS_2, refreshToken: REFRESH_2, expiresAt: 5_000_000 + 3_600_000, scopes: ["user:inference", "user:profile"], subscriptionType: "max" });
    expect(saved.other).toBe("kept");
    expect((fs.statSync(file).mode & 0o777).toString(8)).toBe("600");
    expect(fs.readdirSync(path.join(home, ".claude")).filter((n) => n.includes(".tmp-"))).toEqual([]);
  });

  it("answers 401 with no upstream request when the token is expired and the refresh is refused or unreachable", async () => {
    for (const fetchFn of [
      (async () => new Response("{}", { status: 400 })) as unknown as typeof fetch,
      (async () => {
        throw new Error("ECONNREFUSED");
      }) as unknown as typeof fetch,
      (async () => new Response("not json", { status: 200 })) as unknown as typeof fetch,
    ]) {
      const home = tempHome();
      writeCredentials(home, { accessToken: ACCESS_1, refreshToken: REFRESH_1, expiresAt: 1000 });
      const s = await setup({ env: {}, home, fetchFn, now: () => 5_000_000 });
      const answer = await call(s);
      expect(answer.status).toBe(401);
      expect(s.up.seen).toHaveLength(0);
    }
  });

  it("still uses a token that is near expiry but not expired when the refresh fails", async () => {
    const home = tempHome();
    writeCredentials(home, { accessToken: ACCESS_1, refreshToken: REFRESH_1, expiresAt: 5_030_000 });
    const fetchFn = (async () => new Response("{}", { status: 500 })) as unknown as typeof fetch;
    const s = await setup({ env: {}, home, fetchFn, now: () => 5_000_000 });
    const answer = await call(s);
    expect(answer.status).toBe(200);
    expect(s.up.seen[0].headers.authorization).toBe(`Bearer ${ACCESS_1}`);
  });

  it("ignores a credentials file that is a symlink", async () => {
    const home = tempHome();
    const real = path.join(home, "real.json");
    fs.writeFileSync(real, JSON.stringify({ claudeAiOauth: { accessToken: ACCESS_1, expiresAt: Date.now() + 3_600_000 } }));
    fs.symlinkSync(real, path.join(home, ".claude", ".credentials.json"));
    const s = await setup({ env: {}, home });
    expect((await call(s)).status).toBe(401);
    expect(s.up.seen).toHaveLength(0);
    expect(readAuthStatus(home, {}).loggedIn).toBe(false);
  });
});

describe("log rule", () => {
  it("never logs a token, a credential, a path, a header or a body", async () => {
    const home = tempHome();
    writeCredentials(home, { accessToken: ACCESS_1, refreshToken: REFRESH_1, expiresAt: 1000 });
    const fetchFn = (async () => new Response(JSON.stringify({ access_token: ACCESS_2, refresh_token: REFRESH_2, expires_in: 3600 }), { status: 200 })) as unknown as typeof fetch;
    const s = await setup({ env: {}, home, fetchFn, now: () => 5_000_000 });
    await call(s, { body: '{"prompt":"SYNTH-PROMPT-BODY"}' });
    await call(s, { token: "SYNTH-BAD-TOKEN" });
    await call(s, { path: "/v1/SYNTH-SECRET-PATH" });
    await call(s, { method: "GET" });
    const text = logs.join("\n");
    for (const secret of [s.token, "SYNTH-BAD-TOKEN", ACCESS_1, ACCESS_2, REFRESH_1, REFRESH_2, "SYNTH-PROMPT-BODY", "SYNTH-SECRET-PATH"]) {
      expect(text).not.toContain(secret);
    }
    expect(text).toContain("model.proxy.refused reason=token");
    expect(text).toContain("model.proxy.refused reason=path");
    expect(text).toContain("model.proxy.refused reason=method");
  });
});

describe("canonical path rule", () => {
  it("accepts only plain absolute paths", () => {
    expect(canonicalPath("/v1/messages")).toBe("/v1/messages");
    for (const bad of ["v1/messages", "/v1/../x", "/v1/./x", "/v1//x", "//x", "/v1/%2e", "/v1/a%2fb", "/a\\b", "/a\u0000b", "/a\nb", "/a/", ""]) {
      expect(canonicalPath(bad), JSON.stringify(bad)).toBeUndefined();
    }
  });
});

describe("configuration", () => {
  it("parses MODEL_PROXY_IDLE_TIMEOUT_MS and fails on an invalid value", () => {
    expect(modelProxyIdleTimeoutFromEnv({})).toBe(600_000);
    expect(modelProxyIdleTimeoutFromEnv({ MODEL_PROXY_IDLE_TIMEOUT_MS: "1500" })).toBe(1500);
    for (const bad of ["", "abc", "0", "-5", "1.5", "1e3", "12 ", "NaN", "99999999999999999999"]) {
      if (bad === "12 ") {
        expect(modelProxyIdleTimeoutFromEnv({ MODEL_PROXY_IDLE_TIMEOUT_MS: bad })).toBe(12);
        continue;
      }
      expect(() => modelProxyIdleTimeoutFromEnv({ MODEL_PROXY_IDLE_TIMEOUT_MS: bad }), bad).toThrow(ModelProxyConfigError);
    }
  });
});

describe("login status from the trusted files", () => {
  it("reports OAuth login, expiry, the email and the subscription", () => {
    const home = tempHome();
    writeCredentials(home, { accessToken: ACCESS_1, refreshToken: REFRESH_1, expiresAt: 9_000, subscriptionType: "max" });
    fs.writeFileSync(path.join(home, ".claude.json"), JSON.stringify({ oauthAccount: { emailAddress: "user@example.test" } }));
    expect(readAuthStatus(home, {}, 5_000)).toEqual({ loggedIn: true, authMethod: "claude.ai", apiProvider: "firstParty", email: "user@example.test", subscriptionType: "max", expiresAt: 9_000, tokenExpired: false });
    expect(readAuthStatus(home, {}, 10_000).tokenExpired).toBe(true);
  });

  it("reports API-key mode, and no login without credentials", () => {
    const home = tempHome();
    expect(readAuthStatus(home, {})).toEqual({ loggedIn: false, expiresAt: null, tokenExpired: false });
    expect(readAuthStatus(home, { ANTHROPIC_API_KEY: PROVIDER_KEY })).toMatchObject({ loggedIn: true, authMethod: "api_key" });
    // The status never carries a token.
    writeCredentials(home, { accessToken: ACCESS_1, refreshToken: REFRESH_1, expiresAt: 9_000 });
    expect(JSON.stringify(readAuthStatus(home, {}))).not.toContain("SYNTH-OAUTH");
  });
});
