import "dotenv/config";
import express from "express";
import { loadApiKeys, authMiddleware } from "./auth.js";
import {
  log,
  getLogLevel,
  setLogLevel,
  requestLoggingMiddleware,
  globalErrorHandler,
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
import sshRoutes from "./routes/ssh.js";
import authRoutes from "./routes/auth.js";
import workspaceRoutes from "./routes/workspace.js";
import toolRoutes from "./routes/tools.js";
import { loadTools } from "./tools.js";
import { loadMcpServers } from "./mcp-registry.js";
import mcpRoutes from "./routes/mcp.js";
import gitRoutes from "./routes/git.js";
import {
  SERVER_REQUEST_TIMEOUT_MS,
  nonUploadBodyDeadline,
  skipForUploads,
  uploadConnectionGuard,
} from "./mcp-upload-relay.js";

/* ------------------------------------------------------------------ */
/*  Bootstrap                                                           */
/* ------------------------------------------------------------------ */

const app = express();
// The upload relay (POST /v1/mcp-servers/:name/uploads/*) streams its body
// untouched: the parsers never run for it, whatever its Content-Type. Every
// other request body keeps a 300 s deadline, until it is answered, although
// the server-wide requestTimeout below is raised for the relay.
app.use(nonUploadBodyDeadline());
app.use(skipForUploads(express.json({ limit: "25mb" })));
app.use(skipForUploads(express.text({ limit: "10mb", type: "text/*" })));

// Load API keys from env
loadApiKeys();

// Restore sessions from disk
loadSessions();

// Restore tools and MCP servers from disk
loadTools();
loadMcpServers();

// Logging middleware (before auth so we log rejected requests too)
app.use(requestLoggingMiddleware);

// Upload path only: Connection: close and a bounded drain for every refusal,
// including the API-key 401 below.
app.use(uploadConnectionGuard());

// Auth middleware (skips /health internally)
app.use(authMiddleware);

// Query routes (POST /v1/query, GET /v1/query/:queryId/events)
app.use(queryRouter);

// Workspace routes: SSH keys, auth, memory/agents/skills CRUD
app.use(sshRoutes);
app.use(authRoutes);
app.use(workspaceRoutes);
app.use(gitRoutes);

// Tool registry routes
app.use(toolRoutes);

// MCP server registry routes
app.use(mcpRoutes);

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

app.use(globalErrorHandler);

/* ------------------------------------------------------------------ */
/*  Start server                                                        */
/* ------------------------------------------------------------------ */

const PORT = parseInt(process.env.PORT || "3001", 10);
const HOST = process.env.HOST || "0.0.0.0";

export const server = app.listen(PORT, HOST, () => {
  log("server", `Agent Gateway v${VERSION} listening on ${HOST}:${PORT}`);
  log("server", `Log level: ${getLogLevel()}`);
  log("server", `Sessions: ${getSessionCount()} active`);
});
// Node's 300 s default would cut a slow but progressing upload; the relay's own
// idle timeout bounds it instead (MCP_UPLOAD_IDLE_TIMEOUT_MS).
server.requestTimeout = SERVER_REQUEST_TIMEOUT_MS;

export default app;
