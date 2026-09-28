import { randomBytes } from "node:crypto";
import http, { type IncomingMessage, type ServerResponse } from "node:http";
import https from "node:https";
import type { AddressInfo } from "node:net";
import { log } from "./logging.js";

/**
 * Credential relay for registered http MCP servers (MVP-7667).
 *
 * The Claude runtime never receives a registered server's URL or credential.
 * It gets a loopback URL with a per-run token instead; this relay forwards
 * requests on that exact path to the bound upstream with the run's headers.
 * Two things follow:
 * - an upstream refusal (401/403 with `WWW-Authenticate`, a redirect, any other
 *   non-2xx, an unreachable upstream) never reaches the runtime, so the
 *   runtime's MCP OAuth client never starts a login inside the gateway: a
 *   refused `tools/call` becomes a tool error result, a refused `initialize` or
 *   list request a JSON-RPC error;
 * - header values stay out of the runtime's command line and log files.
 *
 * The relay listens on its own `node:http` server on 127.0.0.1 (never an Express
 * route, so no gateway middleware or request log sees it). The URL, the path and
 * the token are never logged.
 */

export interface RelayBinding {
  serverName: string;
  /** Upstream MCP endpoint (the registered url). */
  url: string;
  /** Static registry headers merged with the run's override. */
  headers: Record<string, string>;
}

export interface CredentialRelayOptions {
  /** No-progress limit for one upstream exchange; on expiry the runtime gets the "unavailable" answer. */
  idleTimeoutMs?: number;
  /** POST bodies are buffered up to this size to read the JSON-RPC method and id. */
  maxBodyBytes?: number;
}

export const RELAY_IDLE_TIMEOUT_MS = 120_000;
/** The gateway's JSON body limit. */
export const RELAY_MAX_BODY_BYTES = 25 * 1024 * 1024;

const RELAY_PATH_PREFIX = "/mcp/";
const FORWARDED_REQUEST_HEADERS = ["accept", "content-type", "mcp-session-id", "mcp-protocol-version", "last-event-id"];
const RETURNED_RESPONSE_HEADERS = ["content-type", "mcp-session-id"];

interface JsonRpcMessage {
  jsonrpc?: unknown;
  id?: unknown;
  method?: unknown;
}

interface ActiveBinding extends RelayBinding {
  /** Requests still uploading, upstream requests and runtime responses in flight, destroyed on revoke. */
  inFlight: Set<{ destroy: () => void }>;
  /** Set by revoke(); a revoked binding never sends another upstream request. */
  revoked: boolean;
}

type RefusalReason = "refused the credential" | "unavailable";

/** One JSON-RPC answer per request in the body; notifications and responses get none. */
function refusalAnswers(messages: JsonRpcMessage[], serverName: string, reason: RefusalReason): unknown[] {
  const text = `MCP server "${serverName}" ${reason}`;
  return messages
    .filter((m) => typeof m.method === "string" && m.id !== undefined && m.id !== null)
    .map((m) =>
      m.method === "tools/call"
        ? { jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text }], isError: true } }
        : { jsonrpc: "2.0", id: m.id, error: { code: -32001, message: text } },
    );
}

function parseMessages(body: Buffer): { messages: JsonRpcMessage[]; batch: boolean } {
  try {
    const parsed = JSON.parse(body.toString("utf8")) as unknown;
    if (Array.isArray(parsed)) return { messages: parsed.filter((m) => m && typeof m === "object") as JsonRpcMessage[], batch: true };
    if (parsed && typeof parsed === "object") return { messages: [parsed as JsonRpcMessage], batch: false };
  } catch {
    // Not JSON: answered as a single request without an id.
  }
  return { messages: [], batch: false };
}

function sendJson(res: ServerResponse, status: number, payload: unknown): void {
  const text = JSON.stringify(payload);
  res.writeHead(status, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(text) });
  res.end(text);
}

function sendEmpty(res: ServerResponse, status: number): void {
  res.writeHead(status, { "Content-Length": 0 });
  res.end();
}

export class CredentialRelay {
  private server: http.Server | null = null;
  private port = 0;
  private readonly bindings = new Map<string, ActiveBinding>();
  private readonly idleTimeoutMs: number;
  private readonly maxBodyBytes: number;

  constructor(options: CredentialRelayOptions = {}) {
    this.idleTimeoutMs = options.idleTimeoutMs ?? RELAY_IDLE_TIMEOUT_MS;
    this.maxBodyBytes = options.maxBodyBytes ?? RELAY_MAX_BODY_BYTES;
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

  /** Binds a new token to the run's upstream URL and header snapshot; returns the URL for the runtime. */
  register(binding: RelayBinding): { token: string; url: string } {
    if (!this.isListening()) throw new Error("credential relay is not listening");
    const token = randomBytes(16).toString("base64url");
    this.bindings.set(token, { ...binding, headers: { ...binding.headers }, inFlight: new Set(), revoked: false });
    return { token, url: `http://127.0.0.1:${this.port}${RELAY_PATH_PREFIX}${token}` };
  }

  /** Revokes a token and destroys its in-flight exchanges; later requests with it get 404. */
  revoke(token: string): void {
    const binding = this.bindings.get(token);
    if (!binding) return;
    this.bindings.delete(token);
    binding.revoked = true;
    for (const exchange of binding.inFlight) exchange.destroy();
    binding.inFlight.clear();
  }

  async close(): Promise<void> {
    for (const token of [...this.bindings.keys()]) this.revoke(token);
    const server = this.server;
    if (!server) return;
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }

  private handle(req: IncomingMessage, res: ServerResponse): void {
    try {
      this.route(req, res);
    } catch {
      this.fail(res);
    }
  }

  /** Last resort: nothing in the relay may end the gateway process. */
  private fail(res: ServerResponse): void {
    try {
      if (!res.headersSent) sendJson(res, 200, { jsonrpc: "2.0", id: null, error: { code: -32001, message: "MCP relay unavailable" } });
      else res.destroy();
    } catch {
      res.destroy();
    }
  }

  private route(req: IncomingMessage, res: ServerResponse): void {
    if (req.headers.host !== `127.0.0.1:${this.port}`) {
      req.resume();
      sendEmpty(res, 403);
      return;
    }
    const rawUrl = req.url ?? "";
    const token = rawUrl.startsWith(RELAY_PATH_PREFIX) ? rawUrl.slice(RELAY_PATH_PREFIX.length) : "";
    // Only the exact endpoint path: no sub-path, no query, no /.well-known, registration, authorize or token path.
    const binding = /^[A-Za-z0-9_-]+$/.test(token) ? this.bindings.get(token) : undefined;
    if (!binding) {
      req.resume();
      sendEmpty(res, 404);
      return;
    }

    if (req.method === "POST") {
      this.readBody(req, res, binding, (body) => this.forward(req, res, binding, "POST", body));
      return;
    }
    req.resume();
    if (req.method === "DELETE") {
      // Session end: forwarded best effort, always answered 204.
      this.forward(req, res, binding, "DELETE", Buffer.alloc(0));
      return;
    }
    // GET (the server-to-client event stream) is not relayed.
    sendEmpty(res, 405);
  }

  private readBody(req: IncomingMessage, res: ServerResponse, binding: ActiveBinding, done: (body: Buffer) => void): void {
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
    binding.inFlight.add(upload);
    res.on("close", () => binding.inFlight.delete(upload));
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > this.maxBodyBytes) tooLarge = true;
      if (!tooLarge) chunks.push(chunk);
      else chunks.length = 0;
    });
    req.on("error", () => res.destroy());
    req.on("end", () => {
      binding.inFlight.delete(upload);
      try {
        if (tooLarge) {
          log("audit", `mcp.relay.refused serverName=${binding.serverName} reason=body_too_large`);
          sendJson(res, 200, { jsonrpc: "2.0", id: null, error: { code: -32600, message: `MCP request to "${binding.serverName}" is too large` } });
          return;
        }
        done(Buffer.concat(chunks));
      } catch {
        this.fail(res);
      }
    });
  }

  private forward(req: IncomingMessage, res: ServerResponse, binding: ActiveBinding, method: "POST" | "DELETE", body: Buffer): void {
    // Every forward re-checks the binding: after revoke() no upstream request is sent with the run's credential.
    if (binding.revoked) {
      if (res.headersSent || res.destroyed) res.destroy();
      else sendEmpty(res, 404);
      return;
    }
    const { messages, batch } = method === "POST" ? parseMessages(body) : { messages: [], batch: false };
    const sessionHeader = req.headers["mcp-session-id"];
    const hadSession = typeof sessionHeader === "string" && sessionHeader.length > 0;

    const headers: Record<string, string> = {};
    for (const name of FORWARDED_REQUEST_HEADERS) {
      const value = req.headers[name];
      if (typeof value === "string") headers[name] = value;
    }
    // The run's credential; any Authorization or Cookie from the runtime is never forwarded.
    Object.assign(headers, binding.headers);
    headers["content-length"] = String(body.length);

    let settled = false;
    const exchange = { destroy: () => {} };
    const finish = (): void => {
      settled = true;
      binding.inFlight.delete(exchange);
    };

    const refuse = (reason: RefusalReason, status?: number): void => {
      if (settled) return;
      finish();
      log("audit", `mcp.relay.refused serverName=${binding.serverName} reason=${reason === "unavailable" ? "unavailable" : "credential_refused"}${status ? ` status=${status}` : ""}`);
      if (res.headersSent) {
        res.destroy();
        return;
      }
      if (method === "DELETE") {
        sendEmpty(res, 204);
        return;
      }
      const answers = refusalAnswers(messages, binding.serverName, reason);
      if (messages.length > 0 && answers.length === 0) {
        sendEmpty(res, 202);
        return;
      }
      const payload = answers.length === 0 ? { jsonrpc: "2.0", id: null, error: { code: -32001, message: `MCP server "${binding.serverName}" ${reason}` } } : batch ? answers : answers[0];
      sendJson(res, 200, payload);
    };

    let target: URL;
    try {
      target = new URL(binding.url);
    } catch {
      refuse("unavailable");
      return;
    }
    const transport = target.protocol === "https:" ? https : http;
    const upstream = transport.request(target, { method, headers, agent: false });
    exchange.destroy = () => {
      upstream.destroy();
      res.destroy();
    };
    binding.inFlight.add(exchange);
    upstream.setTimeout(this.idleTimeoutMs, () => {
      upstream.destroy();
      refuse("unavailable");
    });
    upstream.on("error", () => refuse("unavailable"));
    res.on("close", () => {
      if (!settled) {
        finish();
        upstream.destroy();
      }
    });

    upstream.on("response", (upstreamRes) => {
      try {
        const status = upstreamRes.statusCode ?? 0;
        if (method === "DELETE") {
          upstreamRes.resume();
          if (!settled) {
            finish();
            sendEmpty(res, 204);
          }
          return;
        }
        if (status === 404 && hadSession) {
          // Session miss: passed on as a bodiless 404, as the upstream answered it.
          upstreamRes.resume();
          if (!settled) {
            finish();
            sendEmpty(res, 404);
          }
          return;
        }
        if (status < 200 || status >= 300) {
          // Never passed through, body never echoed.
          upstreamRes.resume();
          refuse(status === 401 || status === 403 ? "refused the credential" : "unavailable", status);
          return;
        }
        const responseHeaders: Record<string, string> = {};
        for (const name of RETURNED_RESPONSE_HEADERS) {
          const value = upstreamRes.headers[name];
          if (typeof value === "string") responseHeaders[name] = value;
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
        if (!settled) finish();
        this.fail(res);
      }
    });

    upstream.end(body);
  }
}

/** The gateway's relay, started with the server (server.ts) and used by every run (agent.ts). */
export const credentialRelay = new CredentialRelay();
