import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import fs from "node:fs";
import http, { type IncomingMessage, type ServerResponse } from "node:http";
import https from "node:https";
import type { AddressInfo } from "node:net";
import path from "node:path";
import { log } from "./logging.js";
import { atomicWriteFileSync } from "./persistence.js";

/**
 * Trusted model proxy (MVP-7678, Gate B).
 *
 * The agent's Claude runtime never receives the provider credential. It gets a
 * loopback base URL and a random per-run token as its only "API key"; this
 * proxy checks the token, forwards the two provider calls the runtime makes
 * to the gateway's own provider origin, and adds the trusted credential on the
 * way (the gateway's `ANTHROPIC_API_KEY`, otherwise the OAuth access token of
 * the trusted `.credentials.json`, refreshed on the trusted side).
 *
 * The proxy listens on its own `node:http` server on 127.0.0.1, like the
 * credential relay (never an Express route, so no gateway middleware or request
 * log sees it). It never logs a header, a body, a token or a path.
 */

/* ------------------------------------------------------------------ */
/*  Constants pinned by the Gate A spike (MVP-7678 comment 37960)       */
/* ------------------------------------------------------------------ */

/** The only provider calls the bundled runtime makes: `POST /v1/messages` and `POST /v1/messages/count_tokens`, both with `?beta=true`. */
const ALLOWED_PATHS = new Set(["/v1/messages", "/v1/messages/count_tokens"]);
const ALLOWED_QUERY = "beta=true";

export const MODEL_PROXY_IDLE_TIMEOUT_MS = 600_000;
/** Largest request body (long transcripts and images). Bigger requests are refused before any upstream request. */
export const MODEL_PROXY_MAX_BODY_BYTES = 32 * 1024 * 1024;

const FORWARDED_REQUEST_HEADERS = new Set([
  "accept",
  "accept-encoding",
  "accept-language",
  "anthropic-beta",
  "anthropic-dangerous-direct-browser-access",
  "anthropic-version",
  "content-type",
  "sec-fetch-mode",
  "user-agent",
  "x-app",
]);
const FORWARDED_REQUEST_HEADER_PREFIX = "x-stainless-";
const RETURNED_RESPONSE_HEADERS = new Set(["content-type", "content-encoding", "cache-control", "retry-after", "request-id", "x-request-id", "x-should-retry"]);
const RETURNED_RESPONSE_HEADER_PREFIX = "anthropic-ratelimit-";

const OAUTH_BETA = "oauth-2025-04-20";
const OAUTH_CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
const OAUTH_SCOPE = "user:profile user:inference user:sessions:claude_code";
const DEFAULT_OAUTH_TOKEN_URL = "https://console.anthropic.com/v1/oauth/token";
/** An access token with less than this left is refreshed before it is used. */
const REFRESH_SKEW_MS = 60_000;
const REFRESH_TIMEOUT_MS = 15_000;
const CREDENTIALS_MAX_BYTES = 1024 * 1024;

/* ------------------------------------------------------------------ */
/*  Provider credentials (trusted side only)                            */
/* ------------------------------------------------------------------ */

interface OAuthRecord {
  accessToken?: unknown;
  refreshToken?: unknown;
  expiresAt?: unknown;
  scopes?: unknown;
  subscriptionType?: unknown;
  [key: string]: unknown;
}

interface CredentialsFile {
  claudeAiOauth?: OAuthRecord;
  [key: string]: unknown;
}

export type CredentialOutcome =
  | { ok: true; headers: Record<string, string> }
  | { ok: false; reason: "no_credential" | "expired" };

export interface ProviderCredentialsOptions {
  /** Trusted home directory; the credentials file is `<home>/.claude/.credentials.json`. */
  home: string;
  /** The gateway's environment (for `ANTHROPIC_API_KEY` and `MODEL_PROXY_OAUTH_TOKEN_URL`). */
  env?: NodeJS.ProcessEnv;
  fetchFn?: typeof fetch;
  now?: () => number;
}

/**
 * Reads a trusted file without following a symlink: it must be a regular file
 * owned by the gateway user. Anything else is treated as absent.
 */
function readTrustedJson(file: string): unknown {
  let fd: number | undefined;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const stat = fs.fstatSync(fd);
    const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
    if (!stat.isFile() || stat.size > CREDENTIALS_MAX_BYTES || (uid !== undefined && stat.uid !== uid)) return undefined;
    return JSON.parse(fs.readFileSync(fd, "utf8")) as unknown;
  } catch {
    return undefined;
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

function asCredentialsFile(value: unknown): CredentialsFile | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as CredentialsFile) : undefined;
}

/** Merges the runtime's own `anthropic-beta` value with the OAuth beta, without duplicates. */
export function mergeBetas(incoming: string | undefined, extra: string): string {
  const parts = (incoming ?? "")
    .split(",")
    .map((p) => p.trim())
    .filter((p) => p.length > 0);
  if (!parts.includes(extra)) parts.push(extra);
  return parts.join(",");
}

export class ProviderCredentials {
  private readonly file: string;
  private readonly env: NodeJS.ProcessEnv;
  private readonly fetchFn: typeof fetch;
  private readonly now: () => number;
  private refreshing: Promise<boolean> | null = null;
  /** Number of refresh requests sent (tests). */
  refreshCount = 0;

  constructor(options: ProviderCredentialsOptions) {
    this.file = path.join(options.home, ".claude", ".credentials.json");
    this.env = options.env ?? process.env;
    this.fetchFn = options.fetchFn ?? fetch;
    this.now = options.now ?? Date.now;
  }

  /**
   * The upstream credential headers for one request: the gateway's API key when
   * set (non-empty), otherwise the OAuth access token with the OAuth beta merged
   * into `incomingBeta`. Never returns a value for the runtime.
   */
  async headersFor(incomingBeta: string | undefined): Promise<CredentialOutcome> {
    const apiKey = this.env.ANTHROPIC_API_KEY;
    if (typeof apiKey === "string" && apiKey.trim().length > 0) {
      return { ok: true, headers: { "x-api-key": apiKey.trim() } };
    }
    let oauth = this.readOAuth();
    if (!oauth || typeof oauth.accessToken !== "string" || oauth.accessToken.length === 0) return { ok: false, reason: "no_credential" };
    if (this.needsRefresh(oauth)) {
      const refreshed = await this.refresh();
      const latest = this.readOAuth();
      if (latest) oauth = latest;
      // A failed refresh still allows a token that has not expired yet.
      if (!refreshed && this.isExpired(oauth)) return { ok: false, reason: "expired" };
    }
    if (typeof oauth.accessToken !== "string" || oauth.accessToken.length === 0) return { ok: false, reason: "no_credential" };
    return { ok: true, headers: { authorization: `Bearer ${oauth.accessToken}`, "anthropic-beta": mergeBetas(incomingBeta, OAUTH_BETA) } };
  }

  private readOAuth(): OAuthRecord | undefined {
    const oauth = asCredentialsFile(readTrustedJson(this.file))?.claudeAiOauth;
    return oauth && typeof oauth === "object" ? oauth : undefined;
  }

  private expiresAt(oauth: OAuthRecord): number | undefined {
    return typeof oauth.expiresAt === "number" && Number.isFinite(oauth.expiresAt) ? oauth.expiresAt : undefined;
  }

  private isExpired(oauth: OAuthRecord): boolean {
    const expiresAt = this.expiresAt(oauth);
    return expiresAt !== undefined && expiresAt <= this.now();
  }

  private needsRefresh(oauth: OAuthRecord): boolean {
    const expiresAt = this.expiresAt(oauth);
    return expiresAt !== undefined && expiresAt - this.now() < REFRESH_SKEW_MS;
  }

  /** One refresh at a time: concurrent callers share the in-flight request. */
  private refresh(): Promise<boolean> {
    if (!this.refreshing) {
      this.refreshing = this.doRefresh().finally(() => {
        this.refreshing = null;
      });
    }
    return this.refreshing;
  }

  private async doRefresh(): Promise<boolean> {
    const current = asCredentialsFile(readTrustedJson(this.file));
    const oauth = current?.claudeAiOauth;
    if (!current || !oauth || typeof oauth.refreshToken !== "string" || oauth.refreshToken.length === 0) {
      log("audit", "model.proxy.refresh_failed reason=no_refresh_token");
      return false;
    }
    const tokenUrl = this.env.MODEL_PROXY_OAUTH_TOKEN_URL || DEFAULT_OAUTH_TOKEN_URL;
    this.refreshCount++;
    try {
      const response = await this.fetchFn(tokenUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ grant_type: "refresh_token", refresh_token: oauth.refreshToken, client_id: OAUTH_CLIENT_ID, scope: OAUTH_SCOPE }),
        redirect: "error",
        signal: AbortSignal.timeout(REFRESH_TIMEOUT_MS),
      });
      if (!response.ok) {
        log("audit", `model.proxy.refresh_failed reason=status status=${response.status}`);
        return false;
      }
      const data = (await response.json()) as { access_token?: unknown; refresh_token?: unknown; expires_in?: unknown; scope?: unknown };
      if (typeof data.access_token !== "string" || data.access_token.length === 0 || typeof data.expires_in !== "number" || !(data.expires_in > 0)) {
        log("audit", "model.proxy.refresh_failed reason=bad_response");
        return false;
      }
      const next: CredentialsFile = {
        ...current,
        claudeAiOauth: {
          ...oauth,
          accessToken: data.access_token,
          refreshToken: typeof data.refresh_token === "string" && data.refresh_token.length > 0 ? data.refresh_token : oauth.refreshToken,
          expiresAt: this.now() + data.expires_in * 1000,
          ...(typeof data.scope === "string" && data.scope.length > 0 ? { scopes: data.scope.split(" ") } : {}),
        },
      };
      atomicWriteFileSync(this.file, JSON.stringify(next));
      log("audit", "model.proxy.refreshed");
      return true;
    } catch {
      log("audit", "model.proxy.refresh_failed reason=unreachable");
      return false;
    }
  }
}

/* ------------------------------------------------------------------ */
/*  Login status from the trusted files                                 */
/* ------------------------------------------------------------------ */

export interface AuthStatus {
  loggedIn: boolean;
  authMethod?: "claude.ai" | "api_key";
  apiProvider?: "firstParty";
  email?: string;
  subscriptionType?: string;
  expiresAt: number | null;
  tokenExpired: boolean;
}

/**
 * The login state for `GET /v1/auth/status`, read from the trusted files. The
 * bundled runtime has no `auth status` subcommand (it would treat the words as
 * a prompt and start a model call), so the state comes from the files it keeps.
 */
export function readAuthStatus(home: string, env: NodeJS.ProcessEnv = process.env, now: number = Date.now()): AuthStatus {
  const apiKey = env.ANTHROPIC_API_KEY;
  const oauth = asCredentialsFile(readTrustedJson(path.join(home, ".claude", ".credentials.json")))?.claudeAiOauth;
  const expiresAt = oauth && typeof oauth.expiresAt === "number" ? oauth.expiresAt : null;
  const hasOAuth = !!oauth && typeof oauth.accessToken === "string" && oauth.accessToken.length > 0;
  let email: string | undefined;
  const profile = readTrustedJson(path.join(home, ".claude.json"));
  if (profile && typeof profile === "object") {
    const account = (profile as { oauthAccount?: { emailAddress?: unknown } }).oauthAccount;
    if (account && typeof account.emailAddress === "string") email = account.emailAddress;
  }
  const status: AuthStatus = {
    loggedIn: hasOAuth || (typeof apiKey === "string" && apiKey.trim().length > 0),
    expiresAt,
    tokenExpired: expiresAt !== null && now > expiresAt,
  };
  if (typeof apiKey === "string" && apiKey.trim().length > 0) {
    status.authMethod = "api_key";
    status.apiProvider = "firstParty";
  } else if (hasOAuth) {
    status.authMethod = "claude.ai";
    status.apiProvider = "firstParty";
    if (email) status.email = email;
    if (typeof oauth?.subscriptionType === "string") status.subscriptionType = oauth.subscriptionType;
  }
  return status;
}

/* ------------------------------------------------------------------ */
/*  Configuration                                                       */
/* ------------------------------------------------------------------ */

export class ModelProxyConfigError extends Error {
  constructor(readonly key: string) {
    super(`invalid value for ${key}`);
  }
}

/** The idle limit from `MODEL_PROXY_IDLE_TIMEOUT_MS`; an invalid value (non-numeric, 0, negative) throws so startup fails. */
export function modelProxyIdleTimeoutFromEnv(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env.MODEL_PROXY_IDLE_TIMEOUT_MS;
  if (raw === undefined) return MODEL_PROXY_IDLE_TIMEOUT_MS;
  if (!/^[0-9]+$/.test(raw.trim())) throw new ModelProxyConfigError("MODEL_PROXY_IDLE_TIMEOUT_MS");
  const value = Number(raw.trim());
  if (!Number.isSafeInteger(value) || value <= 0) throw new ModelProxyConfigError("MODEL_PROXY_IDLE_TIMEOUT_MS");
  return value;
}

/* ------------------------------------------------------------------ */
/*  The proxy                                                           */
/* ------------------------------------------------------------------ */

export interface ModelProxyOptions {
  /** Provider origin (and optional path prefix). Default: the gateway's own `ANTHROPIC_BASE_URL`, else `https://api.anthropic.com`. */
  upstreamBaseUrl?: string;
  credentials: ProviderCredentials;
  idleTimeoutMs?: number;
  maxBodyBytes?: number;
}

interface ActiveToken {
  digest: Buffer;
  /** Requests still uploading and upstream exchanges in flight, destroyed on revoke. */
  inFlight: Set<{ destroy: () => void }>;
  revoked: boolean;
}

type Refusal = "token" | "host" | "path" | "method" | "query" | "too_large" | "credential" | "unavailable" | "timeout";

function digestOf(token: string): Buffer {
  return createHash("sha256").update(token).digest();
}

function errorBody(type: string, message: string): string {
  return JSON.stringify({ type: "error", error: { type, message } });
}

/** Fixed, sanitized answers of the proxy itself. Nothing of the request is echoed. */
const ANSWERS: Record<Refusal, { status: number; type: string; message: string; retry: boolean }> = {
  token: { status: 401, type: "authentication_error", message: "invalid x-api-key", retry: false },
  host: { status: 403, type: "permission_error", message: "forbidden", retry: false },
  path: { status: 404, type: "not_found_error", message: "not found", retry: false },
  method: { status: 405, type: "invalid_request_error", message: "method not allowed", retry: false },
  query: { status: 400, type: "invalid_request_error", message: "invalid query", retry: false },
  too_large: { status: 413, type: "request_too_large", message: "request too large", retry: false },
  credential: { status: 401, type: "authentication_error", message: "invalid x-api-key", retry: false },
  unavailable: { status: 502, type: "api_error", message: "model provider unavailable", retry: true },
  timeout: { status: 504, type: "api_error", message: "model provider timed out", retry: true },
};

/**
 * The request path after decoding and normalization, or undefined when it is not
 * canonical. Percent-encoding, dot segments, empty segments, backslashes and
 * control characters are all refused (`..`, `%2e`, `%2f`, `//`), so what reaches
 * the allowlist is exactly the path that is sent upstream.
 */
export function canonicalPath(rawPath: string): string | undefined {
  if (!rawPath.startsWith("/") || rawPath.includes("%") || rawPath.includes("\\") || /[\u0000-\u001f\u007f]/.test(rawPath)) return undefined;
  if (rawPath.includes("//")) return undefined;
  const segments = rawPath.split("/").slice(1);
  if (segments.some((s) => s === "" || s === "." || s === "..")) return undefined;
  return rawPath;
}

export class ModelProxy {
  private server: http.Server | null = null;
  private port = 0;
  private readonly tokens: ActiveToken[] = [];
  private readonly upstream: URL;
  private readonly credentials: ProviderCredentials;
  private readonly idleTimeoutMs: number;
  private readonly maxBodyBytes: number;
  /** Requests sent upstream, for tests and audit. */
  upstreamRequests = 0;

  constructor(options: ModelProxyOptions) {
    this.upstream = new URL(options.upstreamBaseUrl ?? (process.env.ANTHROPIC_BASE_URL || "https://api.anthropic.com"));
    this.credentials = options.credentials;
    this.idleTimeoutMs = options.idleTimeoutMs ?? MODEL_PROXY_IDLE_TIMEOUT_MS;
    this.maxBodyBytes = options.maxBodyBytes ?? MODEL_PROXY_MAX_BODY_BYTES;
  }

  /** Starts the loopback listener on an ephemeral port. */
  async start(): Promise<void> {
    if (this.server) return;
    const server = http.createServer((req, res) => this.handle(req, res));
    server.on("clientError", (_err, socket) => socket.destroy());
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => {
        server.off("error", reject);
        resolve();
      });
    });
    this.server = server;
    this.port = (server.address() as AddressInfo).port;
    server.on("close", () => {
      this.server = null;
    });
  }

  isListening(): boolean {
    return this.server !== null && this.server.listening;
  }

  /** A new run token and the base URL for the runtime (`ANTHROPIC_BASE_URL`). */
  register(): { token: string; baseUrl: string } {
    if (!this.isListening()) throw new Error("model proxy is not listening");
    const token = `mpt_${randomBytes(32).toString("base64url")}`;
    this.tokens.push({ digest: digestOf(token), inFlight: new Set(), revoked: false });
    return { token, baseUrl: `http://127.0.0.1:${this.port}` };
  }

  /** Revokes a token and destroys its in-flight exchanges; later requests with it get 401 and no upstream request. */
  revoke(token: string): void {
    const digest = digestOf(token);
    const index = this.tokens.findIndex((t) => timingSafeEqual(t.digest, digest));
    if (index < 0) return;
    const [entry] = this.tokens.splice(index, 1);
    entry.revoked = true;
    for (const exchange of entry.inFlight) exchange.destroy();
    entry.inFlight.clear();
  }

  activeTokenCount(): number {
    return this.tokens.length;
  }

  async close(): Promise<void> {
    for (const entry of [...this.tokens]) {
      entry.revoked = true;
      for (const exchange of entry.inFlight) exchange.destroy();
      entry.inFlight.clear();
    }
    this.tokens.length = 0;
    const server = this.server;
    if (!server) return;
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }

  /** Constant-time lookup: every stored digest is compared, there is no early exit. */
  private lookup(presented: unknown): ActiveToken | undefined {
    if (typeof presented !== "string" || presented.length === 0) return undefined;
    const digest = digestOf(presented);
    let found: ActiveToken | undefined;
    for (const entry of this.tokens) {
      if (timingSafeEqual(entry.digest, digest)) found = entry;
    }
    return found;
  }

  private handle(req: IncomingMessage, res: ServerResponse): void {
    try {
      this.route(req, res);
    } catch {
      this.refuse(req, res, "unavailable");
    }
  }

  private refuse(req: IncomingMessage, res: ServerResponse, reason: Refusal): void {
    req.resume();
    log("audit", `model.proxy.refused reason=${reason}`);
    if (res.headersSent || res.destroyed) {
      res.destroy();
      return;
    }
    const answer = ANSWERS[reason];
    const body = errorBody(answer.type, answer.message);
    res.writeHead(answer.status, {
      "content-type": "application/json",
      "content-length": Buffer.byteLength(body),
      ...(answer.retry ? {} : { "x-should-retry": "false" }),
    });
    res.end(body);
  }

  private route(req: IncomingMessage, res: ServerResponse): void {
    // Order: host, token, then the shape of the request. A request without the token learns nothing about the allowlist.
    if (req.headers.host !== `127.0.0.1:${this.port}`) return this.refuse(req, res, "host");
    const entry = this.lookup(req.headers["x-api-key"]);
    if (!entry) return this.refuse(req, res, "token");

    const rawUrl = req.url ?? "";
    const queryStart = rawUrl.indexOf("?");
    const rawPath = queryStart < 0 ? rawUrl : rawUrl.slice(0, queryStart);
    const rawQuery = queryStart < 0 ? "" : rawUrl.slice(queryStart + 1);
    const pathname = canonicalPath(rawPath);
    if (!pathname || !ALLOWED_PATHS.has(pathname)) return this.refuse(req, res, "path");
    if (req.method !== "POST") return this.refuse(req, res, "method");
    if (rawQuery !== "" && rawQuery !== ALLOWED_QUERY) return this.refuse(req, res, "query");
    const declared = req.headers["content-length"];
    if (typeof declared === "string" && Number(declared) > this.maxBodyBytes) return this.refuse(req, res, "too_large");

    this.readBody(req, res, entry, (body) => void this.forward(req, res, entry, pathname, rawQuery, body));
  }

  private readBody(req: IncomingMessage, res: ServerResponse, entry: ActiveToken, done: (body: Buffer) => void): void {
    const chunks: Buffer[] = [];
    let size = 0;
    let tooLarge = false;
    // A request whose body is still arriving is in flight too: revoking the token closes its connection.
    const upload = {
      destroy: () => {
        req.destroy();
        res.destroy();
      },
    };
    entry.inFlight.add(upload);
    res.on("close", () => entry.inFlight.delete(upload));
    // No progress while uploading ends the request.
    let uploaded = false;
    req.setTimeout(this.idleTimeoutMs, () => {
      if (uploaded) return;
      entry.inFlight.delete(upload);
      this.refuse(req, res, "timeout");
      req.destroy();
    });
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > this.maxBodyBytes) tooLarge = true;
      if (!tooLarge) chunks.push(chunk);
      else chunks.length = 0;
    });
    req.on("error", () => res.destroy());
    req.on("end", () => {
      uploaded = true;
      // The socket timer was for the upload only; the upstream exchange has its own.
      req.setTimeout(0);
      entry.inFlight.delete(upload);
      if (tooLarge) return this.refuse(req, res, "too_large");
      done(Buffer.concat(chunks));
    });
  }

  private async forward(req: IncomingMessage, res: ServerResponse, entry: ActiveToken, pathname: string, rawQuery: string, body: Buffer): Promise<void> {
    if (entry.revoked || res.destroyed) return this.refuse(req, res, "token");

    const headers: Record<string, string> = {};
    for (const [name, value] of Object.entries(req.headers)) {
      if (typeof value !== "string") continue;
      if (FORWARDED_REQUEST_HEADERS.has(name) || name.startsWith(FORWARDED_REQUEST_HEADER_PREFIX)) headers[name] = value;
    }
    const credential = await this.credentials.headersFor(headers["anthropic-beta"]);
    // The credential lookup may have taken a refresh: the token may be revoked or the client gone meanwhile.
    if (entry.revoked || res.destroyed) return this.refuse(req, res, "token");
    if (!credential.ok) return this.refuse(req, res, "credential");
    Object.assign(headers, credential.headers);
    headers["content-length"] = String(body.length);

    const basePath = this.upstream.pathname.replace(/\/+$/, "");
    const target = new URL(`${basePath}${pathname}${rawQuery ? `?${rawQuery}` : ""}`, this.upstream.origin);
    const transport = target.protocol === "https:" ? https : http;

    let settled = false;
    const exchange = { destroy: () => {} };
    const finish = (): void => {
      settled = true;
      entry.inFlight.delete(exchange);
    };
    const fail = (reason: Refusal): void => {
      if (settled) return;
      finish();
      this.refuse(req, res, reason);
    };

    const upstream = transport.request(target, { method: "POST", headers, agent: false });
    this.upstreamRequests++;
    exchange.destroy = () => {
      upstream.destroy();
      res.destroy();
    };
    entry.inFlight.add(exchange);
    upstream.setTimeout(this.idleTimeoutMs, () => {
      upstream.destroy();
      if (res.headersSent) {
        finish();
        res.destroy();
      } else {
        fail("timeout");
      }
    });
    upstream.on("error", () => {
      if (res.headersSent) {
        finish();
        res.destroy();
      } else {
        fail("unavailable");
      }
    });
    res.on("close", () => {
      if (!settled) {
        finish();
        upstream.destroy();
      }
    });

    upstream.on("response", (upstreamRes) => {
      try {
        // The status, x-should-retry and the allowlisted headers pass through; set-cookie and everything else stay behind.
        const responseHeaders: Record<string, string> = {};
        for (const [name, value] of Object.entries(upstreamRes.headers)) {
          if (typeof value !== "string") continue;
          if (RETURNED_RESPONSE_HEADERS.has(name) || name.startsWith(RETURNED_RESPONSE_HEADER_PREFIX)) responseHeaders[name] = value;
        }
        const status = upstreamRes.statusCode ?? 0;
        if (status < 200 || status > 599) {
          upstreamRes.resume();
          fail("unavailable");
          return;
        }
        res.writeHead(status, responseHeaders);
        upstreamRes.on("error", () => {
          finish();
          res.destroy();
        });
        upstreamRes.on("end", () => finish());
        // Streams with backpressure (JSON or text/event-stream).
        upstreamRes.pipe(res);
      } catch {
        upstream.destroy();
        fail("unavailable");
      }
    });

    upstream.end(body);
  }
}

/* ------------------------------------------------------------------ */
/*  The gateway's proxy                                                 */
/* ------------------------------------------------------------------ */

let gatewayProxy: ModelProxy | null = null;

/** The gateway's proxy, created on first use from the environment (server.ts starts it, agent.ts registers run tokens). */
export function gatewayModelProxy(): ModelProxy {
  gatewayProxy ??= new ModelProxy({
    credentials: new ProviderCredentials({ home: process.env.HOME || "/home/node" }),
    idleTimeoutMs: modelProxyIdleTimeoutFromEnv(),
  });
  return gatewayProxy;
}
