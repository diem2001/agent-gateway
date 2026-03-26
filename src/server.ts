import "dotenv/config";
import express from "express";
import { loadApiKeys, authMiddleware } from "./auth.js";
import {
  log,
  getLogLevel,
  setLogLevel,
  requestLoggingMiddleware,
  type LogLevel,
} from "./logging.js";
import {
  loadSessions,
  listSessions,
  deleteSession,
  getSessionCount,
  getSettings,
  updateSettings,
  type SessionSettings,
} from "./sessions.js";
import { queryRouter } from "./query.js";

/* ------------------------------------------------------------------ */
/*  Bootstrap                                                           */
/* ------------------------------------------------------------------ */

const app = express();
app.use(express.json({ limit: "10mb" }));

// Load API keys from env
loadApiKeys();

// Restore sessions from disk
loadSessions();

// Logging middleware (before auth so we log rejected requests too)
app.use(requestLoggingMiddleware);

// Auth middleware (skips /health internally)
app.use(authMiddleware);

// Query routes (POST /v1/query, GET /v1/query/:queryId/events)
app.use(queryRouter);

/* ------------------------------------------------------------------ */
/*  Routes: Health (unauthenticated)                                    */
/* ------------------------------------------------------------------ */

const VERSION = process.env.npm_package_version || "0.1.0";

app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    version: VERSION,
    uptime: Math.round(process.uptime()),
    sessions: getSessionCount(),
  });
});

/* ------------------------------------------------------------------ */
/*  Routes: Logging control (authenticated)                             */
/* ------------------------------------------------------------------ */

app.get("/v1/logging", (_req, res) => {
  res.json({ level: getLogLevel() });
});

app.put("/v1/logging", (req, res) => {
  const { level } = req.body as { level?: string };
  const validLevels: LogLevel[] = ["off", "info", "debug"];

  if (!level || !validLevels.includes(level as LogLevel)) {
    res.status(400).json({
      error: "level must be one of: off, info, debug",
    });
    return;
  }

  const previous = setLogLevel(level as LogLevel);
  res.json({ level, previous });
});

/* ------------------------------------------------------------------ */
/*  Routes: Session management (authenticated)                          */
/* ------------------------------------------------------------------ */

app.get("/v1/sessions", (_req, res) => {
  res.json({ sessions: listSessions(), count: getSessionCount() });
});

app.delete("/v1/sessions/:id", (req, res) => {
  const deleted = deleteSession(req.params.id);
  if (!deleted) {
    res.status(404).json({ error: "Session not found" });
    return;
  }
  res.json({ deleted: true });
});

/* ------------------------------------------------------------------ */
/*  Routes: Settings (authenticated)                                    */
/* ------------------------------------------------------------------ */

app.get("/v1/settings", (_req, res) => {
  res.json(getSettings());
});

app.put("/v1/settings", (req, res) => {
  const body = req.body as Partial<SessionSettings>;

  if (
    body.sessionIdleTimeoutMs !== undefined &&
    (typeof body.sessionIdleTimeoutMs !== "number" ||
      body.sessionIdleTimeoutMs < 0)
  ) {
    res
      .status(400)
      .json({ error: "sessionIdleTimeoutMs must be a non-negative number" });
    return;
  }

  const settings = updateSettings(body);
  res.json(settings);
});

/* ------------------------------------------------------------------ */
/*  Global error handler                                                */
/* ------------------------------------------------------------------ */

app.use(
  (
    err: Error,
    _req: express.Request,
    res: express.Response,
    _next: express.NextFunction,
  ) => {
    log("error", err.message);
    res.status(500).json({ error: "Internal server error" });
  },
);

/* ------------------------------------------------------------------ */
/*  Start server                                                        */
/* ------------------------------------------------------------------ */

const PORT = parseInt(process.env.PORT || "3001", 10);
const HOST = process.env.HOST || "0.0.0.0";

app.listen(PORT, HOST, () => {
  log("server", `Agent Gateway v${VERSION} listening on ${HOST}:${PORT}`);
  log("server", `Log level: ${getLogLevel()}`);
  log("server", `Sessions: ${getSessionCount()} active`);
});

export default app;
