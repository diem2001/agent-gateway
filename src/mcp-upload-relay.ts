/**
 * Streaming upload relay (SC-5):
 *
 *   POST /v1/mcp-servers/{name}/uploads/{targetPath}?{query}
 *   Authorization: Bearer <gateway API key>
 *   X-MCP-Credential-Headers: base64(UTF-8 JSON {"Authorization": "..."})   optional
 *   <raw bytes>
 *
 * is forwarded as `POST <origin of the registered url>/uploads/{targetPath}?{query}`
 * and the MCP server's status and body come back verbatim.
 *
 * The gateway is a dumb pipe here: the body is never parsed, buffered, stored or
 * logged. Each received chunk is written to the upstream request and dropped;
 * when the upstream socket is full, the sender is paused (backpressure end to
 * end). Target path and query are taken from the raw request URL, never from a
 * decoded or normalized path, so `%2e%2e` or `%2F` cannot turn into another path.
 */

import http, { type ClientRequest, type IncomingMessage } from "node:http";
import https from "node:https";
import type { NextFunction, Request, RequestHandler, Response } from "express";
import { DEFAULT_GC_BUDGET, GcBudget } from "./gc-budget.js";
import { log } from "./logging.js";
import type { McpServerDefinition } from "./mcp-registry.js";

export const DEFAULT_UPLOAD_IDLE_TIMEOUT_MS = 60_000;
/** Upper bound on the sender body read and discarded after a refusal. */
export const DEFAULT_DRAIN_LIMIT_BYTES = 1024 * 1024;
export const DEFAULT_DRAIN_LIMIT_MS = 5_000;
/** Node's own `requestTimeout` default, kept for every route except the relay. */
export const NON_UPLOAD_BODY_DEADLINE_MS = 300_000;
/** Server-wide `requestTimeout`, so a slow but progressing upload is not cut at 5 minutes. */
export const SERVER_REQUEST_TIMEOUT_MS = 3_600_000;

export const CREDENTIAL_HEADER = "x-mcp-credential-headers";

/* ------------------------------------------------------------------ */
/*  The one path rule: parser skip, pre-auth guard and target          */
/* ------------------------------------------------------------------ */

/**
 * Upload path, matched case-insensitively like Express routes. Express matches
 * the route with this same expression, so routing and target extraction agree.
 */
export const UPLOAD_ROUTE = /^\/v1\/mcp-servers\/[^/]+\/uploads(?:\/[\s\S]*)?$/i;
const UPLOAD_PARTS = /^\/v1\/mcp-servers\/([^/]+)\/uploads(?:\/([\s\S]*))?$/i;
const ABSOLUTE_FORM = /^[a-z][a-z0-9+.-]*:\/\/[^/?#]*/i;

export interface UploadPathMatch {
  /** Server name segment, still percent-encoded. */
  rawName: string;
  /** Everything after `/uploads/`, raw; empty when absent. */
  target: string;
  /** Everything after the first `?`, raw; null when the URL has no `?`. */
  query: string | null;
}

/** Applies the upload path rule to a raw request URL (never decoded). */
export function matchUploadPath(rawUrl: string): UploadPathMatch | null {
  const url = rawUrl.replace(ABSOLUTE_FORM, "");
  const queryStart = url.indexOf("?");
  const rawPath = queryStart === -1 ? url : url.slice(0, queryStart);
  const match = UPLOAD_PARTS.exec(rawPath);
  if (!match) return null;
  return {
    rawName: match[1],
    target: match[2] ?? "",
    query: queryStart === -1 ? null : url.slice(queryStart + 1),
  };
}

function rawRequestUrl(req: IncomingMessage): string {
  return (req as Request).originalUrl ?? req.url ?? "";
}

export function isUploadRequest(req: IncomingMessage): boolean {
  return req.method === "POST" && matchUploadPath(rawRequestUrl(req)) !== null;
}

/**
 * Refuses an empty target, a `.` or `..` segment (also percent-encoded), an
 * encoded slash or backslash, a backslash, and characters an HTTP request line
 * cannot carry. Everything else is forwarded byte for byte.
 */
export function isValidUploadTarget(target: string, query: string | null): boolean {
  if (target.length === 0) return false;
  if (/\\|%2f|%5c/i.test(target)) return false;
  for (const segment of target.split("/")) {
    const dots = segment.replace(/%2e/gi, ".");
    if (dots === "." || dots === "..") return false;
  }
  const requestLineSafe = /^[!-ÿ]*$/;
  return requestLineSafe.test(target) && (query === null || requestLineSafe.test(query));
}

/* ------------------------------------------------------------------ */
/*  X-MCP-Credential-Headers                                            */
/* ------------------------------------------------------------------ */

export type CredentialHeaderResult = { ok: true; authorization: string | null } | { ok: false };

const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;
const INVALID = { ok: false } as const;

/**
 * Strict parse of the credential override header: one header, canonical base64
 * of a UTF-8 JSON object whose values are strings without CR, LF or NUL, and no
 * two keys that differ only in case. Only `Authorization` is used; it must be
 * printable ASCII. The parsed object is never copied or spread.
 */
export function parseCredentialHeader(req: IncomingMessage): CredentialHeaderResult {
  const values = req.headersDistinct[CREDENTIAL_HEADER];
  if (values === undefined) return { ok: true, authorization: null };
  if (values.length !== 1) return INVALID;
  const raw = values[0];
  if (raw.length === 0 || raw.length % 4 !== 0 || !BASE64.test(raw)) return INVALID;
  const bytes = Buffer.from(raw, "base64");
  if (bytes.toString("base64") !== raw) return INVALID;

  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    return INVALID;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return INVALID;

  const seen = new Set<string>();
  let authorization: string | null = null;
  for (const key of Object.keys(parsed)) {
    const value: unknown = (parsed as Record<string, unknown>)[key];
    if (typeof value !== "string" || /[\r\n\0]/.test(value)) return INVALID;
    const lower = key.toLowerCase();
    if (seen.has(lower)) return INVALID;
    seen.add(lower);
    if (lower === "authorization") authorization = value;
  }
  if (authorization !== null && !/^[\x20-\x7e]+$/.test(authorization)) return INVALID;
  return { ok: true, authorization };
}

/* ------------------------------------------------------------------ */
/*  Upstream request                                                    */
/* ------------------------------------------------------------------ */

/** Registered static headers that never travel on an upload. */
const NOT_FROM_REGISTRATION = new Set([
  "host",
  "content-length",
  "content-type",
  "transfer-encoding",
  "connection",
  "keep-alive",
  "upgrade",
  "te",
  "trailer",
  "expect",
]);

export interface UpstreamRequest {
  transport: typeof http | typeof https;
  options: http.RequestOptions;
}

/**
 * Builds the upstream request: origin of the registered url + `/uploads/` + raw
 * target + raw query. The path is passed as a string, never through `new URL()`,
 * which would normalize it. Returns null for a url that does not parse or is not
 * http(s).
 */
export function buildUpstreamRequest(
  srv: McpServerDefinition,
  target: string,
  query: string | null,
  authorization: string | null,
  incoming: IncomingMessage,
): UpstreamRequest | null {
  let base: URL;
  try {
    base = new URL(srv.url ?? "");
  } catch {
    return null;
  }
  if (base.protocol !== "http:" && base.protocol !== "https:") return null;

  // Null prototype: a registered header named `__proto__` stays a plain key.
  const headers: Record<string, string> = Object.create(null);
  for (const [name, value] of Object.entries(srv.headers ?? {})) {
    const lower = name.toLowerCase();
    if (NOT_FROM_REGISTRATION.has(lower) || lower.startsWith("proxy-")) continue;
    if (authorization !== null && lower === "authorization") continue;
    headers[name] = value;
  }
  // The override wins over a static Authorization, like credentials.headers on /call.
  if (authorization !== null) headers.Authorization = authorization;
  const contentType = incoming.headers["content-type"];
  if (contentType !== undefined) headers["Content-Type"] = contentType;
  const contentLength = incoming.headers["content-length"];
  if (contentLength !== undefined) headers["Content-Length"] = contentLength;

  return {
    transport: base.protocol === "https:" ? https : http,
    options: {
      protocol: base.protocol,
      hostname: base.hostname.replace(/^\[(.*)\]$/, "$1"),
      port: base.port || undefined,
      path: `/uploads/${target}${query === null ? "" : `?${query}`}`,
      method: "POST",
      headers,
      // A fresh connection per upload, never a pooled socket.
      agent: false,
    },
  };
}

/* ------------------------------------------------------------------ */
/*  Error bodies                                                        */
/* ------------------------------------------------------------------ */

export const UPLOAD_MESSAGES = {
  overrideInvalid:
    "X-MCP-Credential-Headers must be a single base64-encoded JSON object of string values; Authorization must be printable ASCII",
  targetInvalid:
    "The upload target path is empty or contains a dot segment, an encoded slash, a backslash or a character a request line cannot carry",
  unsupported: (name: string) =>
    `${name} uses stdio transport; uploads can only be relayed to http or sse servers`,
  notReached: (name: string) => `The MCP server ${name} could not be reached; nothing was sent`,
  unconfirmed: (name: string) =>
    `The connection to the MCP server ${name} dropped before it answered; the outcome is unconfirmed. Check the target's attachments before retrying`,
  idle: (ms: number) => `No upload progress for ${ms} ms; the relay was aborted`,
  idleUnconfirmed: (ms: number) =>
    `The MCP server did not answer for ${ms} ms after the whole upload was sent; the outcome is unconfirmed. Check the target's attachments before retrying`,
};

function sendError(res: Response, status: number, code: string, message: string): void {
  res.status(status).json({ error: { code, message } });
}

/* ------------------------------------------------------------------ */
/*  Configuration                                                       */
/* ------------------------------------------------------------------ */

/** Reads MCP_UPLOAD_IDLE_TIMEOUT_MS; invalid values fall back to the default. */
export function readUploadIdleTimeout(raw: string | undefined): number {
  if (raw === undefined || raw === "") return DEFAULT_UPLOAD_IDLE_TIMEOUT_MS;
  const value = /^[0-9]+$/.test(raw) ? Number(raw) : NaN;
  if (Number.isSafeInteger(value) && value > 0) return value;
  log(
    "config",
    `MCP_UPLOAD_IDLE_TIMEOUT_MS must be a positive integer; using ${DEFAULT_UPLOAD_IDLE_TIMEOUT_MS}`,
  );
  return DEFAULT_UPLOAD_IDLE_TIMEOUT_MS;
}

/* ------------------------------------------------------------------ */
/*  Middleware: body parsers, body deadline, pre-auth guard             */
/* ------------------------------------------------------------------ */

/** Runs `parser` for every request except an upload, whatever its Content-Type. */
export function skipForUploads(parser: RequestHandler): RequestHandler {
  return (req, res, next) => {
    if (isUploadRequest(req)) {
      next();
      return;
    }
    parser(req, res, next);
  };
}

/**
 * The server-wide `requestTimeout` is raised for the relay; every other route
 * keeps Node's previous bound: a request body still incomplete this long after
 * the request reached the app closes the connection.
 */
export function nonUploadBodyDeadline(deadlineMs = NON_UPLOAD_BODY_DEADLINE_MS): RequestHandler {
  return (req, res, next) => {
    if (req.complete || isUploadRequest(req)) {
      next();
      return;
    }
    const timer = setTimeout(() => {
      if (!req.complete) req.socket.destroy();
    }, deadlineMs);
    timer.unref();
    const clear = () => clearTimeout(timer);
    req.once("end", clear);
    res.once("close", clear);
    next();
  };
}

/**
 * After an early answer: reads and discards at most `limitBytes` of the rest of
 * the sender body, then stops reading. Resolves when the body ended, the sender
 * closed the connection, or `limitMs` passed, whichever comes first. Nothing is
 * kept.
 *
 * The connection is not closed as soon as the byte cap is hit: closing a socket
 * with unread data makes the kernel reset it, and a sender still writing would
 * then fail with ECONNRESET before it read the answer. Waiting (without
 * reading) gives it time to read the answer and close the connection itself.
 */
function drainBounded(req: IncomingMessage, limitBytes: number, limitMs: number): Promise<void> {
  return new Promise((resolve) => {
    if (req.complete || req.destroyed) {
      resolve();
      return;
    }
    let seen = 0;
    const finish = () => {
      clearTimeout(timer);
      req.off("data", onData);
      req.off("end", finish);
      req.off("close", finish);
      req.off("error", finish);
      req.pause();
      resolve();
    };
    const onData = (chunk: Buffer) => {
      seen += chunk.length;
      if (seen >= limitBytes) {
        req.off("data", onData);
        req.pause();
      }
    };
    const timer = setTimeout(finish, limitMs);
    timer.unref();
    req.on("data", onData);
    req.once("end", finish);
    req.once("close", finish);
    req.once("error", finish);
    req.resume();
  });
}

export interface UploadGuardOptions {
  drainLimitBytes?: number;
  drainLimitMs?: number;
}

/**
 * Runs before API-key auth on the upload path. Every answer carries
 * `Connection: close`. When an answer (a refusal, a relay error or an early
 * upstream answer) is complete while the sender is still sending, the answer is
 * written first; then at most `drainLimitBytes` of the rest is read and
 * discarded, and the connection is closed when the sender closes it or
 * `drainLimitMs` after the answer. A caller without a key therefore cannot keep
 * the gateway reading a large body.
 */
export function uploadConnectionGuard(options: UploadGuardOptions = {}): RequestHandler {
  const limitBytes = options.drainLimitBytes ?? DEFAULT_DRAIN_LIMIT_BYTES;
  const limitMs = options.drainLimitMs ?? DEFAULT_DRAIN_LIMIT_MS;
  return (req: Request, res: Response, next: NextFunction) => {
    if (!isUploadRequest(req)) {
      next();
      return;
    }
    res.setHeader("Connection", "close");
    const originalEnd = res.end.bind(res) as (...args: unknown[]) => Response;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (res as any).end = function (...args: unknown[]): Response {
      if (req.complete || req.destroyed || res.writableEnded) return originalEnd(...args);
      const [chunk, encoding] = args;
      if (chunk !== undefined && typeof chunk !== "function") {
        res.write(chunk as Buffer | string, (typeof encoding === "string" ? encoding : "utf8") as BufferEncoding);
      }
      res.once("finish", () => req.socket.destroy());
      void drainBounded(req, limitBytes, limitMs).then(() => originalEnd());
      return res;
    };
    next();
  };
}

/* ------------------------------------------------------------------ */
/*  The relay                                                           */
/* ------------------------------------------------------------------ */

type RelayResult = "ok" | "upstream_answer" | "upstream_failed" | "timeout" | "client_aborted";

/**
 * One relayed upload: the sender's request, the upstream request, the idle
 * timer and the single audit line. Every exit path goes through `settle()`.
 */
class UploadRelay {
  private upstream: ClientRequest | null = null;
  private timer: NodeJS.Timeout | null = null;
  private connected = false;
  private bodySent = false;
  private answered = false;
  private settled = false;
  private bytes = 0;
  /** Frees the dropped chunk buffers every 2 MiB (needs `--expose-gc`). */
  private readonly gcBudget = new GcBudget(DEFAULT_GC_BUDGET);

  constructor(
    private readonly req: Request,
    private readonly res: Response,
    private readonly serverName: string,
    private readonly idleTimeoutMs: number,
  ) {}

  start(upstreamRequest: UpstreamRequest): void {
    const { req, res } = this;
    this.touch();
    // The sender went away before the relay answered: abort the upstream request.
    res.once("close", () => {
      if (!res.writableFinished) this.senderGone();
    });

    let upstream: ClientRequest;
    try {
      upstream = upstreamRequest.transport.request(upstreamRequest.options);
    } catch {
      // Invalid registered header value: rejected before any connection.
      this.failBeforeAnswer();
      return;
    }
    this.upstream = upstream;
    const connectEvent = upstreamRequest.options.protocol === "https:" ? "secureConnect" : "connect";
    upstream.on("socket", (socket) => socket.once(connectEvent, () => (this.connected = true)));
    upstream.on("finish", () => (this.bodySent = true));
    upstream.on("response", (upstreamRes) => this.onResponse(upstreamRes));
    upstream.on("error", () => this.failBeforeAnswer());
    upstream.on("close", () => this.failBeforeAnswer());

    req.on("data", this.onData);
    req.on("end", this.onEnd);
  }

  private readonly onData = (chunk: Buffer): void => {
    this.bytes += chunk.length;
    this.touch();
    this.gcBudget.add(chunk.length);
    const upstream = this.upstream!;
    if (!upstream.write(chunk)) {
      this.req.pause();
      upstream.once("drain", () => this.req.resume());
    }
  };

  private readonly onEnd = (): void => {
    this.upstream?.end();
  };

  private stopForwarding(): void {
    this.req.off("data", this.onData);
    this.req.off("end", this.onEnd);
    this.req.pause();
  }

  private touch(): void {
    if (this.settled) return;
    if (this.timer) clearTimeout(this.timer);
    this.timer = setTimeout(() => this.expire(), this.idleTimeoutMs);
    this.timer.unref();
  }

  /** Ends the relay once; returns false when it had already ended. */
  private settle(status: number | null, result: RelayResult): boolean {
    if (this.settled) return false;
    this.settled = true;
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    this.stopForwarding();
    log(
      "audit",
      `mcp.upload.relayed serverName=${this.serverName} status=${status ?? "-"} bytes=${this.bytes} result=${result}`,
    );
    return true;
  }

  private onResponse(upstreamRes: IncomingMessage): void {
    const { res } = this;
    if (this.settled) {
      upstreamRes.resume();
      return;
    }
    this.answered = true;
    this.touch();
    // An answer before the whole body was sent (an early refusal): stop sending.
    if (!this.bodySent) this.stopForwarding();

    const status = upstreamRes.statusCode ?? 502;
    const headers: Record<string, string> = {};
    const contentType = upstreamRes.headers["content-type"];
    if (contentType !== undefined) headers["Content-Type"] = contentType;
    const contentLength = upstreamRes.headers["content-length"];
    if (contentLength !== undefined) headers["Content-Length"] = contentLength;
    res.writeHead(status, headers);

    upstreamRes.on("data", (chunk: Buffer) => {
      this.touch();
      if (!res.write(chunk)) {
        upstreamRes.pause();
        res.once("drain", () => upstreamRes.resume());
      }
    });
    upstreamRes.on("end", () => {
      if (!this.settle(status, status >= 200 && status < 300 ? "ok" : "upstream_answer")) return;
      this.upstream?.destroy();
      res.end();
    });
    upstreamRes.on("close", () => {
      if (upstreamRes.complete) return;
      // The answer broke off after its status line: it can no longer change.
      if (this.settle(status, "upstream_failed")) res.destroy();
    });
  }

  /** Upstream error or close before any answer arrived. */
  private failBeforeAnswer(): void {
    if (this.answered) return;
    const sent = this.connected;
    if (!this.settle(502, "upstream_failed")) return;
    this.upstream?.destroy();
    sendError(
      this.res,
      502,
      "UPLOAD_UPSTREAM_FAILED",
      sent ? UPLOAD_MESSAGES.unconfirmed(this.serverName) : UPLOAD_MESSAGES.notReached(this.serverName),
    );
  }

  private expire(): void {
    const bodySent = this.bodySent;
    const headersSent = this.res.headersSent;
    if (!this.settle(headersSent ? null : 504, "timeout")) return;
    this.upstream?.destroy();
    if (headersSent) {
      this.res.destroy();
      return;
    }
    sendError(
      this.res,
      504,
      "UPLOAD_TIMEOUT",
      bodySent ? UPLOAD_MESSAGES.idleUnconfirmed(this.idleTimeoutMs) : UPLOAD_MESSAGES.idle(this.idleTimeoutMs),
    );
  }

  private senderGone(): void {
    if (!this.settle(null, "client_aborted")) return;
    this.upstream?.destroy();
  }
}

export interface RelayInput {
  srv: McpServerDefinition;
  match: UploadPathMatch;
  authorization: string | null;
  idleTimeoutMs: number;
}

/** Starts the relay after every gateway check has passed. */
export function relayUpload(req: Request, res: Response, input: RelayInput): void {
  const upstream = buildUpstreamRequest(
    input.srv,
    input.match.target,
    input.match.query,
    input.authorization,
    req,
  );
  if (!upstream) {
    log(
      "audit",
      `mcp.upload.relayed serverName=${input.srv.name} status=502 bytes=0 result=upstream_failed`,
    );
    sendError(res, 502, "UPLOAD_UPSTREAM_FAILED", UPLOAD_MESSAGES.notReached(input.srv.name));
    return;
  }
  new UploadRelay(req, res, input.srv.name, input.idleTimeoutMs).start(upstream);
}

/** Answers a gateway refusal on the upload path with the shared error envelope. */
export function refuseUpload(res: Response, status: number, code: string, message: string): void {
  sendError(res, status, code, message);
}
