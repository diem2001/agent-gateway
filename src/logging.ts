import type { Request, Response, NextFunction } from "express";

/* ------------------------------------------------------------------ */
/*  Runtime logging — mutable level, controllable via /v1/logging       */
/* ------------------------------------------------------------------ */

export type LogLevel = "off" | "info" | "debug";

let logLevel: LogLevel = (process.env.LOG_LEVEL as LogLevel) || "info";

export function getLogLevel(): LogLevel {
  return logLevel;
}

export function setLogLevel(level: LogLevel): LogLevel {
  const previous = logLevel;
  logLevel = level;
  // Always print level changes, even when "off"
  console.log(`[logging] Level changed: ${previous} -> ${level}`);
  return previous;
}

export function log(category: string, ...args: unknown[]): void {
  if (logLevel === "off") return;
  console.log(`[${category}]`, ...args);
}

export function logDebug(category: string, ...args: unknown[]): void {
  if (logLevel !== "debug") return;
  console.log(`[${category}]`, ...args);
}

const REDACTED = "[REDACTED]";

/** Keys whose whole value is a credential container: MCP `headers` (http/sse) and `env` (stdio). */
const CREDENTIAL_KEYS = new Set(["headers", "env"]);

/** Keys whose value is a secret by itself: the SSH private key of the git routes. */
const SECRET_VALUE_KEYS = new Set(["sshKey"]);

const URL_SCHEME = /[a-z][a-z0-9+.-]*:\/\//i;

/**
 * Replace everything between `://` and the last `@` of `segment` with `***`;
 * a segment without `://`, or without `@` after it, is returned unchanged.
 */
function redactFromSchemeToLastAt(segment: string): string {
  const scheme = URL_SCHEME.exec(segment);
  if (!scheme) return segment;
  const start = scheme.index + scheme[0].length;
  const lastAt = segment.lastIndexOf("@");
  return lastAt < start ? segment : segment.slice(0, start) + "***" + segment.slice(lastAt);
}

/**
 * Remove URL credentials from free text such as git's error output. Tokens
 * reach git unencoded and git echoes a URL it cannot parse as is, so a token
 * may contain `/`, whitespace, quotes or `@`: on every line, everything from
 * the first `scheme://` to the last `@` becomes `***`. This may also hide a
 * host or path after an earlier URL on the same line; that is accepted.
 */
export function redactUrlCredentials(text: string): string {
  return text
    .split(/(\r\n|\r|\n)/)
    .map((part) => redactFromSchemeToLastAt(part))
    .join("");
}

/** Remove the credentials of a whole URL value: everything from `scheme://` to its last `@`, line breaks included. */
export function redactUrlValue(url: string): string {
  return redactFromSchemeToLastAt(url);
}

/** Every string under a `url` key, at any depth, as a URL value. */
function redactUrlEntry(value: unknown): unknown {
  if (typeof value === "string") return redactUrlValue(value);
  if (Array.isArray(value)) return value.map(redactUrlEntry);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, entry]) => [key, redactUrlEntry(entry)]));
  }
  return value;
}

/**
 * Replace the whole value of a `headers`/`env` key: a map keeps its keys with
 * "[REDACTED]" values, any other shape becomes "[REDACTED]".
 */
function redactCredentialValue(value: unknown): unknown {
  if (value === undefined) return undefined;
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return Object.fromEntries(Object.keys(value as Record<string, unknown>).map((key) => [key, REDACTED]));
  }
  return REDACTED;
}

/**
 * A copy of a parsed JSON value for the log, with every `headers` and `env` key
 * redacted at any depth. This covers `mcpServers[*]` and `mcpCredentialOverrides`
 * of POST /v1/query, the /test and /call bodies, and registry definitions in
 * request and response bodies. Every `sshKey` value becomes "[REDACTED]" and
 * every string under a `url` key loses its URL credentials (the git routes'
 * clone URL can carry an access token). The original value is never changed.
 */
export function redactCredentialsForLog(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactCredentialsForLog);
  if (!value || typeof value !== "object") return value;
  const copy: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
    if (CREDENTIAL_KEYS.has(key)) copy[key] = redactCredentialValue(entry);
    else if (SECRET_VALUE_KEYS.has(key)) copy[key] = entry === undefined ? undefined : REDACTED;
    else if (key === "url") copy[key] = redactUrlEntry(entry);
    else copy[key] = redactCredentialsForLog(entry);
  }
  return copy;
}

const REQUEST_BODY_PREVIEW_CHARS = 2000;
const RESPONSE_PREVIEW_CHARS = 500;

/** Registry routes answer with definitions that hold credentials; an unparseable answer there is not previewed. */
function isMcpRegistryPath(url: string): boolean {
  const pathname = url.split("?")[0];
  return pathname === "/v1/mcp-servers" || pathname.startsWith("/v1/mcp-servers/");
}

function requestBodyPreview(body: unknown): string {
  // express.text() bodies are not JSON and cannot be redacted by key: length only.
  if (typeof body === "string") return `[text body, ${body.length} chars]`;
  return JSON.stringify(redactCredentialsForLog(body)).substring(0, REQUEST_BODY_PREVIEW_CHARS);
}

/** Redacted, then shortened: no prefix of a credential value can reach the log. */
function responsePreview(url: string, chunk: unknown): string {
  const text = Buffer.isBuffer(chunk) ? chunk.toString("utf8") : String(chunk);
  try {
    return JSON.stringify(redactCredentialsForLog(JSON.parse(text))).substring(0, RESPONSE_PREVIEW_CHARS);
  } catch {
    if (isMcpRegistryPath(url)) return "[unparseable body omitted]";
    return redactUrlCredentials(text).substring(0, RESPONSE_PREVIEW_CHARS);
  }
}

/**
 * The global error handler. Body-parser errors (they carry a `type` such as
 * "entity.parse.failed") are logged as type and status only: Node's JSON error
 * message quotes part of the body, which may hold a credential. A client-error
 * status set by body-parser (413 for an over-limit body, 400 for malformed JSON)
 * is honored, so bad requests are not masked as a generic 500.
 */
export function globalErrorHandler(err: Error, _req: Request, res: Response, _next: NextFunction): void {
  const bodyErr = err as Error & { status?: number; statusCode?: number; type?: string };
  const status = bodyErr.status || bodyErr.statusCode;
  log("error", typeof bodyErr.type === "string" ? `request body rejected type=${bodyErr.type} status=${status ?? "unknown"}` : err.message);
  if (typeof status === "number" && status >= 400 && status < 500) {
    res.status(status).json({ error: bodyErr.type === "entity.too.large" ? "Request body too large" : "Bad request" });
    return;
  }
  res.status(500).json({ error: "Internal server error" });
}

/* ------------------------------------------------------------------ */
/*  Request/Response logging middleware                                  */
/* ------------------------------------------------------------------ */

export function requestLoggingMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  const start = Date.now();
  const { method, url } = req;

  // Skip /health logging
  if (url === "/health") {
    next();
    return;
  }

  if (logLevel !== "off") {
    const body = logLevel === "debug" && req.body ? " " + requestBodyPreview(req.body) : "";
    log("req", `${method} ${url}${body}`);
  }

  // Capture response for logging
  const originalEnd = res.end.bind(res) as typeof res.end;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (res as any).end = function (
    this: Response,
    ...endArgs: unknown[]
  ): Response {
    const duration = Date.now() - start;
    if (logLevel !== "off") {
      const chunk = endArgs[0];
      const preview = logLevel === "debug" && chunk ? " " + responsePreview(url, chunk) : "";
      log("res", `${method} ${url} ${res.statusCode} ${duration}ms${preview}`);
    }
    return (originalEnd as Function).apply(this, endArgs) as Response;
  };

  next();
}
