import { randomBytes } from "node:crypto";
import http, { type IncomingMessage, type ServerResponse } from "node:http";
import https from "node:https";
import type { AddressInfo } from "node:net";
import { log } from "./logging.js";
import { BRIDGE_MAX_BUFFER_BYTES, SseBridge, type JsonRpcObject, type McpBridge } from "./mcp-bridge.js";
import { describeFailure, mcpToolTimeoutMs, type ToolFailure } from "./tool-mediation.js";

/**
 * The trusted MCP relay (MVP-7667, MVP-7679).
 *
 * The Claude runtime never receives a credential-bearing MCP server's URL, header or environment. It gets a
 * loopback URL with a per-run token instead (`{ type: "http", url }`, the server name and so every
 * `mcp__<server>__<tool>` name unchanged); this relay holds the run's binding (upstream, credential headers,
 * grant) until the run ends. Everything the runtime, or any process in the run's sandbox, sends to that URL is
 * treated as untrusted input:
 * - a body that does not parse as strict UTF-8 JSON (a BOM, another encoding), every batch and every message
 *   without a `method` is refused locally; what is forwarded is the re-serialized parsed message, never the raw
 *   bytes, always with `content-type: application/json`;
 * - the method is default-deny: `initialize`, `ping`, `tools/list`, the client notifications and a `tools/call`
 *   whose `params.name` is exactly in the run's grant are forwarded; anything else only when the grant covers the
 *   whole server; every other message is answered TOOL_DENIED without an upstream request;
 * - upstream answers are buffered (bounded), validated and re-sent as one JSON message; an upstream failure
 *   becomes one of the fixed TOOL_* texts (tool-mediation.ts) and never reaches the runtime as a 401, a redirect or
 *   a body, so the runtime's MCP OAuth client never starts a login inside the gateway;
 * - a `sse` binding is served by the SSE bridge (mcp-bridge.ts), a `stdio` binding by the tool sandbox bridge.
 *
 * The relay listens on its own `node:http` server on 127.0.0.1 (never an Express route, so no gateway middleware
 * or request log sees it). The URL, the path and the token are never logged.
 */

/** What the run's tool grant allows for one server (tool-grant.ts), resolved by the caller. */
export interface RelayGrant {
  /** Whether `tools/call` of this exact tool name (the part after `mcp__<server>__`) is granted. */
  allowsTool: (tool: string) => boolean;
  /** Whether every tool of the server is granted (so methods beyond `tools/call` may be forwarded). */
  coversServer: boolean;
}

export interface RelayBinding {
  serverName: string;
  /** Upstream MCP endpoint (the registered url). */
  url: string;
  /** Static registry headers merged with the run's override (one case-insensitive merge, the override wins). */
  headers: Record<string, string>;
  grant: RelayGrant;
  /** "http" (default): Streamable HTTP upstream. "sse": the SSE transport, served by the SSE bridge. "stdio": a tool sandbox (a bridge is given). */
  kind?: "http" | "sse" | "stdio";
  /** Where the run's credential for this server came from; it picks the text of a refused credential. */
  credentialSource?: "user" | "gateway";
  /** The server needs a per-user credential and the run carries none: `tools/call` is answered without a request. */
  noUserCredential?: boolean;
  /** A bridge that serves this binding instead of a direct upstream request (the stdio kind, mcp-stdio-sandbox.ts). */
  bridge?: McpBridge;
}

export interface CredentialRelayOptions {
  /** No-progress limit for one upstream exchange; on expiry the runtime gets the timeout answer. */
  idleTimeoutMs?: number;
  /** POST bodies are buffered up to this size to read the JSON-RPC message. */
  maxBodyBytes?: number;
  /** An upstream answer larger than this is refused as unreadable. */
  maxResponseBytes?: number;
  /** Overall deadline of a mediated `tools/call` (AGENT_MCP_TOOL_TIMEOUT_MS); defaults to the configured key. */
  toolTimeoutMs?: number;
}

export const RELAY_IDLE_TIMEOUT_MS = 120_000;
/** Connections the loopback listener holds at once, and requests one binding processes at once. */
export const RELAY_MAX_CONNECTIONS = 512;
export const RELAY_MAX_IN_FLIGHT_PER_BINDING = 32;
/** The gateway's JSON body limit. */
export const RELAY_MAX_BODY_BYTES = 25 * 1024 * 1024;
export const RELAY_MAX_RESPONSE_BYTES = BRIDGE_MAX_BUFFER_BYTES;

const RELAY_PATH_PREFIX = "/mcp/";
const FORWARDED_REQUEST_HEADERS = ["accept", "mcp-session-id", "mcp-protocol-version", "last-event-id"];
const RETURNED_RESPONSE_HEADERS = ["mcp-session-id"];

/** Methods every grant may use (the handshake and the model-visible tool list). */
const ALWAYS_METHODS = new Set(["initialize", "ping", "tools/list"]);
/** Client notifications the relay forwards. */
const NOTIFICATIONS = new Set(["notifications/initialized", "notifications/cancelled", "notifications/progress", "notifications/roots/list_changed"]);

interface ActiveBinding extends RelayBinding {
  /** Requests still uploading, upstream requests and runtime responses in flight, destroyed on revoke. */
  inFlight: Set<{ destroy: () => void }>;
  /** Set by revoke(); a revoked binding never sends another upstream request. */
  revoked: boolean;
  /** Messages being processed (answered or not yet) for this binding. */
  active: number;
  bridge?: McpBridge;
}

/** One parsed, checked message of the runtime. */
interface Inspected {
  message: JsonRpcObject;
  method: string;
  id: unknown;
  hasId: boolean;
  tool?: string;
}

type Inspection = { ok: true; value: Inspected } | { ok: false; reason: "invalid_message" | "method_denied" | "tool_denied"; id: unknown };

/** The parsed message of a body, or null when the body is not one strict UTF-8 JSON object. */
function parseObject(body: Buffer): { object: JsonRpcObject } | { batch: true } | null {
  // A BOM is refused (JSON.parse of a decoded BOM would also fail, but the intent is explicit).
  if (body.length >= 3 && body[0] === 0xef && body[1] === 0xbb && body[2] === 0xbf) return null;
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(body);
  } catch {
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  if (Array.isArray(parsed)) return { batch: true };
  if (typeof parsed !== "object" || parsed === null) return null;
  return { object: parsed as JsonRpcObject };
}

function isRequestId(id: unknown): boolean {
  return typeof id === "string" || (typeof id === "number" && Number.isFinite(id));
}

function inspect(body: Buffer, serverName: string, grant: RelayGrant): Inspection {
  const parsed = parseObject(body);
  if (!parsed || "batch" in parsed) return { ok: false, reason: "invalid_message", id: null };
  const message = parsed.object;
  const hasId = message.id !== undefined && message.id !== null;
  const id = hasId && isRequestId(message.id) ? message.id : null;
  // A JSON-RPC response (no method) from the runtime is not accepted: nothing here answers server requests.
  if (typeof message.method !== "string") return { ok: false, reason: "invalid_message", id };
  if (hasId && !isRequestId(message.id)) return { ok: false, reason: "invalid_message", id: null };
  const method = message.method;
  if (method === "tools/call") {
    const params = message.params;
    if (typeof params !== "object" || params === null || Array.isArray(params)) return { ok: false, reason: "invalid_message", id };
    const { name, arguments: args } = params as { name?: unknown; arguments?: unknown };
    if (typeof name !== "string" || name.length === 0) return { ok: false, reason: "invalid_message", id };
    if (args !== undefined && (typeof args !== "object" || args === null || Array.isArray(args))) return { ok: false, reason: "invalid_message", id };
    if (!grant.allowsTool(name)) return { ok: false, reason: "tool_denied", id };
    return { ok: true, value: { message, method, id, hasId, tool: name } };
  }
  void serverName;
  if (ALWAYS_METHODS.has(method) || NOTIFICATIONS.has(method)) return { ok: true, value: { message, method, id, hasId } };
  // resources/*, prompts/*, completion/*, logging and anything else: only when the grant covers the whole server.
  if (grant.coversServer) return { ok: true, value: { message, method, id, hasId } };
  return { ok: false, reason: "method_denied", id };
}

function sendJson(res: ServerResponse, status: number, payload: unknown, extra: Record<string, string> = {}): void {
  const text = JSON.stringify(payload);
  res.writeHead(status, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(text), ...extra });
  res.end(text);
}

function sendEmpty(res: ServerResponse, status: number): void {
  res.writeHead(status, { "Content-Length": 0 });
  res.end();
}

/** The JSON-RPC answer of a failed message: an `isError` result for `tools/call`, an error object otherwise. */
function failureAnswer(method: string | null, id: unknown, text: string): unknown {
  return method === "tools/call"
    ? { jsonrpc: "2.0", id, result: { content: [{ type: "text", text }], isError: true } }
    : { jsonrpc: "2.0", id, error: { code: -32001, message: text } };
}

/** The JSON-RPC answer matching `id` in an upstream body (JSON or event stream), or null. */
function answerFromBody(text: string, contentType: string, id: unknown): JsonRpcObject | null {
  const matches = (value: unknown): value is JsonRpcObject =>
    typeof value === "object" && value !== null && !Array.isArray(value) && JSON.stringify((value as JsonRpcObject).id) === JSON.stringify(id) && ("result" in (value as object) || "error" in (value as object));
  if (/^application\/json/i.test(contentType)) {
    try {
      const parsed: unknown = JSON.parse(text);
      return matches(parsed) ? parsed : null;
    } catch {
      return null;
    }
  }
  if (/^text\/event-stream/i.test(contentType)) {
    for (const rawEvent of text.split(/\r\n\r\n|\n\n|\r\r/)) {
      const data: string[] = [];
      let event = "message";
      for (const line of rawEvent.split(/\r\n|\n|\r/)) {
        if (line.startsWith("data:")) data.push(line.slice(5).replace(/^ /, ""));
        else if (line.startsWith("event:")) event = line.slice(6).trim();
      }
      if (event !== "message" || data.length === 0) continue;
      try {
        const parsed: unknown = JSON.parse(data.join("\n"));
        if (matches(parsed)) return parsed;
      } catch {
        // Not a message: skipped.
      }
    }
  }
  return null;
}

export class CredentialRelay {
  private server: http.Server | null = null;
  private port = 0;
  private readonly bindings = new Map<string, ActiveBinding>();
  private readonly idleTimeoutMs: number;
  private readonly maxBodyBytes: number;
  private readonly maxResponseBytes: number;
  private readonly toolTimeoutOverride: number | undefined;

  constructor(options: CredentialRelayOptions = {}) {
    this.idleTimeoutMs = options.idleTimeoutMs ?? RELAY_IDLE_TIMEOUT_MS;
    this.maxBodyBytes = options.maxBodyBytes ?? RELAY_MAX_BODY_BYTES;
    this.maxResponseBytes = options.maxResponseBytes ?? RELAY_MAX_RESPONSE_BYTES;
    this.toolTimeoutOverride = options.toolTimeoutMs;
  }

  /** The overall deadline of one `tools/call`: the option, else AGENT_MCP_TOOL_TIMEOUT_MS (validated at startup). */
  private toolTimeoutMs(): number {
    if (this.toolTimeoutOverride !== undefined) return this.toolTimeoutOverride;
    try {
      return mcpToolTimeoutMs();
    } catch {
      return 600_000;
    }
  }

  /** Starts the loopback listener on an ephemeral port. */
  async start(): Promise<void> {
    if (this.server) return;
    const server = http.createServer((req, res) => this.handle(req, res));
    server.on("clientError", (_err, socket) => socket.destroy());
    // A process in an agent sandbox can reach this port: bound what it can hold open, and never let a listener
    // error (for example running out of file descriptors) end the gateway.
    server.maxConnections = RELAY_MAX_CONNECTIONS;
    server.headersTimeout = 15_000;
    server.requestTimeout = 0;
    server.keepAliveTimeout = 5_000;
    server.on("error", () => log("audit", "mcp.relay.listener_error"));
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

  /** Binds a new token to the run's upstream, credential headers and grant; returns the URL for the runtime. */
  register(binding: RelayBinding): { token: string; url: string } {
    if (!this.isListening()) throw new Error("credential relay is not listening");
    const token = randomBytes(16).toString("base64url");
    const active: ActiveBinding = { ...binding, headers: { ...binding.headers }, inFlight: new Set(), revoked: false, active: 0 };
    if (binding.kind === "sse" && !binding.bridge) {
      active.bridge = new SseBridge({ serverName: binding.serverName, url: binding.url, headers: active.headers, idleTimeoutMs: this.idleTimeoutMs, maxBufferBytes: this.maxResponseBytes });
    }
    this.bindings.set(token, active);
    return { token, url: `http://127.0.0.1:${this.port}${RELAY_PATH_PREFIX}${token}` };
  }

  /** Revokes a token and destroys its in-flight exchanges and bridge; later requests with it get 404. */
  revoke(token: string): void {
    const binding = this.bindings.get(token);
    if (!binding) return;
    this.bindings.delete(token);
    binding.revoked = true;
    for (const exchange of binding.inFlight) exchange.destroy();
    binding.inFlight.clear();
    try {
      binding.bridge?.close();
    } catch {
      // Closing is best effort.
    }
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
      if (!res.headersSent) sendJson(res, 200, { jsonrpc: "2.0", id: null, error: { code: -32001, message: describeFailure({ kind: "unreachable", name: "mcp" }).message } });
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
      this.readBody(req, res, binding, (body) => this.handleMessage(req, res, binding, body));
      return;
    }
    req.resume();
    if (req.method === "DELETE") {
      // Session end: forwarded best effort to a Streamable HTTP upstream, always answered 204.
      if (binding.kind === "sse" || binding.bridge) sendEmpty(res, 204);
      else this.forwardDelete(req, res, binding);
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

  /** Answers a message the relay does not forward (or that failed) in the shape the runtime expects. */
  private answerFailure(res: ServerResponse, binding: ActiveBinding, inspected: { method: string | null; id: unknown; hasId: boolean }, failure: ToolFailure, reason: string, status?: number): void {
    log("audit", `mcp.relay.refused serverName=${binding.serverName} reason=${reason}${status ? ` status=${status}` : ""}`);
    if (res.headersSent) {
      res.destroy();
      return;
    }
    // A notification gets no answer.
    if (inspected.method !== null && !inspected.hasId) {
      sendEmpty(res, 202);
      return;
    }
    sendJson(res, 200, failureAnswer(inspected.method, inspected.id, describeFailure(failure).message));
  }

  private handleMessage(req: IncomingMessage, res: ServerResponse, binding: ActiveBinding, body: Buffer): void {
    // Every message re-checks the binding: after revoke() no upstream request is sent with the run's credential.
    if (binding.revoked) {
      if (res.headersSent || res.destroyed) res.destroy();
      else sendEmpty(res, 404);
      return;
    }
    const inspection = inspect(body, binding.serverName, binding.grant);
    if (!inspection.ok) {
      const denied: ToolFailure = { kind: "denied" };
      const reason = inspection.reason;
      log("audit", `mcp.relay.refused serverName=${binding.serverName} reason=${reason}`);
      if (inspection.reason === "invalid_message") {
        sendJson(res, 200, { jsonrpc: "2.0", id: inspection.id, error: { code: -32600, message: describeFailure(denied).message } });
        return;
      }
      // Denied tool or method: the model-visible shape of the original request.
      const parsed = parseObject(body);
      const method = parsed && "object" in parsed && typeof parsed.object.method === "string" ? parsed.object.method : null;
      const hasId = inspection.id !== null;
      if (method !== null && !hasId) {
        sendEmpty(res, 202);
        return;
      }
      sendJson(res, 200, failureAnswer(method, inspection.id, describeFailure(denied).message));
      return;
    }
    const value = inspection.value;

    if (value.method === "tools/call" && binding.noUserCredential) {
      this.answerFailure(res, binding, value, { kind: "no_credential", name: binding.serverName }, "no_credential");
      return;
    }

    // Requests in flight per binding are bounded: nothing an agent process sends can pile up unbounded work.
    if (binding.active >= RELAY_MAX_IN_FLIGHT_PER_BINDING) {
      this.answerFailure(res, binding, value, { kind: "unreachable", name: binding.serverName }, "too_many_requests");
      return;
    }
    binding.active++;
    res.once("close", () => {
      binding.active--;
    });

    const isToolCall = value.method === "tools/call";
    const deadlineMs = isToolCall ? this.toolTimeoutMs() : this.idleTimeoutMs;
    if (binding.bridge) {
      this.viaBridge(res, binding, value, deadlineMs);
      return;
    }
    this.forwardToUpstream(req, res, binding, value, deadlineMs);
  }

  private viaBridge(res: ServerResponse, binding: ActiveBinding, value: Inspected, deadlineMs: number): void {
    const bridge = binding.bridge!;
    let settled = false;
    const exchange = { destroy: () => res.destroy() };
    binding.inFlight.add(exchange);
    res.on("close", () => binding.inFlight.delete(exchange));
    bridge
      .request(value.message, deadlineMs)
      .then((result) => {
        if (settled || binding.revoked || res.destroyed) return;
        settled = true;
        binding.inFlight.delete(exchange);
        if (result.kind === "failure") {
          const failure = this.withSource(result.failure, binding);
          this.answerFailure(res, binding, value, failure, failureReason(failure));
          return;
        }
        if (result.kind === "accepted") {
          sendEmpty(res, 202);
          return;
        }
        sendJson(res, 200, result.message);
      })
      .catch(() => {
        if (settled) return;
        settled = true;
        binding.inFlight.delete(exchange);
        this.answerFailure(res, binding, value, { kind: "unreachable", name: binding.serverName }, "unavailable");
      });
  }

  /** A refused credential reads differently when it came from the user's request. */
  private withSource(failure: ToolFailure, binding: ActiveBinding): ToolFailure {
    if (failure.kind === "gateway_credential_refused" && binding.credentialSource === "user") return { kind: "user_credential_refused", name: failure.name };
    return failure;
  }

  private forwardDelete(req: IncomingMessage, res: ServerResponse, binding: ActiveBinding): void {
    if (binding.revoked) {
      sendEmpty(res, 404);
      return;
    }
    const headers: Record<string, string> = {};
    for (const name of FORWARDED_REQUEST_HEADERS) {
      const value = req.headers[name];
      if (typeof value === "string") headers[name] = value;
    }
    Object.assign(headers, binding.headers);
    let target: URL;
    try {
      target = new URL(binding.url);
    } catch {
      sendEmpty(res, 204);
      return;
    }
    const transport = target.protocol === "https:" ? https : http;
    const upstream = transport.request(target, { method: "DELETE", headers, agent: false });
    const exchange = {
      destroy: () => {
        upstream.destroy();
        res.destroy();
      },
    };
    binding.inFlight.add(exchange);
    let answered = false;
    const end = (): void => {
      if (answered) return;
      answered = true;
      binding.inFlight.delete(exchange);
      if (!res.headersSent && !res.destroyed) sendEmpty(res, 204);
    };
    upstream.setTimeout(this.idleTimeoutMs, () => {
      upstream.destroy();
      end();
    });
    upstream.on("error", end);
    upstream.on("response", (upstreamRes) => {
      upstreamRes.resume();
      end();
    });
    upstream.end();
  }

  private forwardToUpstream(req: IncomingMessage, res: ServerResponse, binding: ActiveBinding, value: Inspected, deadlineMs: number): void {
    const sessionHeader = req.headers["mcp-session-id"];
    const hadSession = typeof sessionHeader === "string" && sessionHeader.length > 0;
    // The re-serialized parsed message, never the runtime's raw bytes.
    const body = Buffer.from(JSON.stringify(value.message), "utf8");

    const headers: Record<string, string> = {};
    for (const name of FORWARDED_REQUEST_HEADERS) {
      const header = req.headers[name];
      if (typeof header === "string") headers[name] = header;
    }
    // The run's credential; any Authorization or Cookie from the runtime is never forwarded.
    Object.assign(headers, binding.headers);
    headers["content-type"] = "application/json";
    headers["content-length"] = String(body.length);

    let settled = false;
    const exchange = { destroy: () => {} };
    let overallTimer: NodeJS.Timeout | undefined;
    const finish = (): void => {
      settled = true;
      if (overallTimer) clearTimeout(overallTimer);
      binding.inFlight.delete(exchange);
    };
    const refuse = (failure: ToolFailure, status?: number): void => {
      if (settled) return;
      finish();
      this.answerFailure(res, binding, value, this.withSource(failure, binding), failureReason(failure), status);
    };

    let target: URL;
    try {
      target = new URL(binding.url);
    } catch {
      refuse({ kind: "unreachable", name: binding.serverName });
      return;
    }
    const transport = target.protocol === "https:" ? https : http;
    const upstream = transport.request(target, { method: "POST", headers, agent: false });
    exchange.destroy = () => {
      upstream.destroy();
      res.destroy();
    };
    binding.inFlight.add(exchange);
    const timeoutFailure = (ms: number): ToolFailure => ({ kind: "timeout", name: binding.serverName, timeoutMs: ms });
    upstream.setTimeout(this.idleTimeoutMs, () => {
      upstream.destroy();
      refuse(timeoutFailure(this.idleTimeoutMs));
    });
    // The overall deadline of the exchange: a slow but progressing upstream is cut off too (a mediated tool call
    // gets AGENT_MCP_TOOL_TIMEOUT_MS, every other message the no-progress limit as a whole).
    overallTimer = setTimeout(() => {
      upstream.destroy();
      refuse(timeoutFailure(deadlineMs));
    }, deadlineMs);
    upstream.on("error", () => refuse({ kind: "unreachable", name: binding.serverName }));
    res.on("close", () => {
      if (!settled) {
        finish();
        upstream.destroy();
      }
    });

    upstream.on("response", (upstreamRes) => {
      try {
        const status = upstreamRes.statusCode ?? 0;
        if (status === 404 && hadSession) {
          // Session miss: passed on as a bodiless 404, as the upstream answered it.
          upstreamRes.resume();
          if (!settled) {
            finish();
            sendEmpty(res, 404);
          }
          return;
        }
        if (status >= 300 && status < 400) {
          upstreamRes.resume();
          refuse({ kind: "redirect", name: binding.serverName }, status);
          return;
        }
        if (status === 401 || status === 403) {
          upstreamRes.resume();
          refuse({ kind: "gateway_credential_refused", name: binding.serverName }, status);
          return;
        }
        if (status < 200 || status >= 300) {
          // 5xx, 429 and every other non-2xx: never passed through, body never echoed.
          upstreamRes.resume();
          refuse({ kind: "unreachable", name: binding.serverName }, status);
          return;
        }
        const returned: Record<string, string> = {};
        for (const name of RETURNED_RESPONSE_HEADERS) {
          const header = upstreamRes.headers[name];
          if (typeof header === "string") returned[name] = header;
        }
        // A notification (no id) is accepted whatever the body says.
        if (!value.hasId) {
          upstreamRes.resume();
          upstreamRes.on("end", () => {
            if (settled) return;
            finish();
            sendEmpty(res, 202);
          });
          return;
        }
        const chunks: Buffer[] = [];
        let size = 0;
        let tooLarge = false;
        upstreamRes.on("error", () => refuse({ kind: "unreachable", name: binding.serverName }));
        upstreamRes.on("data", (chunk: Buffer) => {
          size += chunk.length;
          if (size > this.maxResponseBytes) {
            tooLarge = true;
            chunks.length = 0;
            upstream.destroy();
            refuse({ kind: "invalid_response", name: binding.serverName });
            return;
          }
          if (!tooLarge) chunks.push(chunk);
        });
        upstreamRes.on("end", () => {
          if (settled) return;
          const answer = answerFromBody(Buffer.concat(chunks).toString("utf8"), String(upstreamRes.headers["content-type"] ?? ""), value.id);
          if (!answer) {
            refuse({ kind: "invalid_response", name: binding.serverName });
            return;
          }
          finish();
          sendJson(res, 200, answer, returned);
        });
      } catch {
        upstream.destroy();
        if (!settled) finish();
        this.fail(res);
      }
    });

    upstream.end(body);
  }
}

/** The audit reason of a failure (fixed words, no value). */
function failureReason(failure: ToolFailure): string {
  switch (failure.kind) {
    case "denied":
      return "denied";
    case "no_credential":
      return "no_credential";
    case "user_credential_refused":
    case "gateway_credential_refused":
      return "credential_refused";
    case "unreachable":
      return "unavailable";
    case "redirect":
      return "redirect";
    case "timeout":
      return "timeout";
    case "invalid_response":
      return "invalid_response";
  }
}

/** The gateway's relay, started with the server (server.ts) and used by every run (agent.ts). */
export const credentialRelay = new CredentialRelay();
