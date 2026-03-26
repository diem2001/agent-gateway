import type { Request, Response, NextFunction } from "express";
import { log } from "./logging.js";

/* ------------------------------------------------------------------ */
/*  API Key auth middleware                                              */
/* ------------------------------------------------------------------ */

// Parsed at startup: Map<key, label> for O(1) lookup
const apiKeys = new Map<string, string>();

/**
 * Parse API_KEYS env var.
 * Format: "label1:key1,label2:key2"
 */
export function loadApiKeys(): void {
  const raw = process.env.API_KEYS || "";
  apiKeys.clear();

  if (!raw.trim()) {
    log("auth", "WARNING: No API_KEYS configured — all authenticated routes will reject");
    return;
  }

  for (const entry of raw.split(",")) {
    const trimmed = entry.trim();
    if (!trimmed) continue;

    const colonIdx = trimmed.indexOf(":");
    if (colonIdx <= 0) {
      log("auth", `Skipping malformed API_KEYS entry: "${trimmed}"`);
      continue;
    }

    const label = trimmed.substring(0, colonIdx);
    const key = trimmed.substring(colonIdx + 1);

    if (!key) {
      log("auth", `Skipping empty key for label "${label}"`);
      continue;
    }

    apiKeys.set(key, label);
  }

  log("auth", `Loaded ${apiKeys.size} API key(s)`);
}

/**
 * Express middleware: validates Bearer token on all routes except /health.
 * Sets req.clientLabel on success.
 */
export function authMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  // Skip auth for health endpoint
  if (req.path === "/health") {
    next();
    return;
  }

  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    res.status(401).json({ error: "Missing or malformed Authorization header" });
    return;
  }

  const token = authHeader.substring(7); // Strip "Bearer "
  const label = apiKeys.get(token);

  if (!label) {
    res.status(401).json({ error: "Invalid API key" });
    return;
  }

  // Attach client label for audit logging
  (req as Request & { clientLabel: string }).clientLabel = label;

  next();
}

// Extend Express Request type
declare global {
  namespace Express {
    interface Request {
      clientLabel?: string;
    }
  }
}
