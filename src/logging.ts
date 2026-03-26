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
    const body =
      logLevel === "debug" && req.body
        ? " " +
          (typeof req.body === "string"
            ? req.body
            : JSON.stringify(req.body)
          ).substring(0, 2000)
        : "";
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
      const preview =
        logLevel === "debug" && chunk
          ? " " + String(chunk).substring(0, 500)
          : "";
      log("res", `${method} ${url} ${res.statusCode} ${duration}ms${preview}`);
    }
    return (originalEnd as Function).apply(this, endArgs) as Response;
  };

  next();
}
