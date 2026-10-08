import "dotenv/config";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import express from "express";
import { loadApiKeys, authMiddleware, getApiKeyLabels } from "./auth.js";
import {
  log,
  logAlways,
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
import { McpServerOwnersConfigError, applyMcpServerOwners, parseMcpServerOwners } from "./mcp-server-owners.js";
import { persistenceReport } from "./persistence.js";
import { installShutdownHandlers } from "./shutdown.js";
import { installAbortRejectionGuard } from "./process-guards.js";
import mcpRoutes from "./routes/mcp.js";
import gitRoutes from "./routes/git.js";
import { credentialRelay } from "./mcp-credential-relay.js";
import { ModelProxyConfigError, gatewayModelProxy } from "./model-proxy.js";
import { IsolationConfigError, isolationStatus, loadIsolationConfig, runIsolationSelfCheck, sweepSandboxRuns } from "./sandbox.js";
import { stripSdkDebugEnv, sweepRunLogDirs } from "./sdk-run-logs.js";
import { ToolPolicyConfigError, loadToolPolicy } from "./tool-grant.js";
import { McpToolTimeoutConfigError, mcpToolTimeoutMs } from "./tool-mediation.js";
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

// Registered MCP servers have an owner (MVP-7925). The operator mapping assigns the owner of entries that have
// none; a malformed mapping stops startup with one fixed line, like the other configuration keys.
try {
  applyMcpServerOwners(parseMcpServerOwners(process.env.MCP_SERVER_OWNERS), getApiKeyLabels());
} catch (e) {
  if (!(e instanceof McpServerOwnersConfigError)) throw e;
  logAlways("server", e.logLine);
  process.exit(1);
}

// Runtime log files and credentials (MVP-7667): no SDK debug log, no leftover
// run directories, and the loopback relay every registered http MCP server is
// reached through. A relay that fails to start leaves those servers out of runs.
stripSdkDebugEnv();
sweepRunLogDirs();
credentialRelay.start().catch((e: unknown) => {
  log("server", `Credential relay failed to start: ${e instanceof Error ? e.message : String(e)}`);
});

// Isolation (MVP-7678): every new configuration key is validated now; an invalid value stops
// startup with one fixed line, nothing falls back silently.
try {
  loadIsolationConfig();
  void gatewayModelProxy();
  // MVP-7679: the trusted tool policy and the deadline of mediated MCP calls, validated like the keys above.
  loadToolPolicy(process.env, getApiKeyLabels());
  mcpToolTimeoutMs();
} catch (e) {
  if (e instanceof IsolationConfigError || e instanceof ToolPolicyConfigError || e instanceof McpToolTimeoutConfigError) logAlways("server", e.logLine);
  else if (e instanceof ModelProxyConfigError) logAlways("server", `FATAL config key=${e.key} reason=must be a positive whole number of milliseconds`);
  else throw e;
  process.exit(1);
}
// Leftover run directories of a crashed gateway.
try {
  sweepSandboxRuns();
} catch {
  // A missing or unusable storage root is reported by the self-check below.
}
// The trusted model proxy is the only holder of the provider credential; then a real sandbox
// start sets /health `isolation`.
gatewayModelProxy()
  .start()
  .catch((e: unknown) => {
    log("server", `Model proxy failed to start: ${e instanceof Error ? e.message : String(e)}`);
  })
  .then(() => runIsolationSelfCheck());

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
    // Additive (MVP-7678): "ok" once a sandbox has started and passed its check, "unavailable" after a
    // permanent start problem until a later start succeeds, "starting" until the boot self-check is done.
    isolation: isolationStatus(),
    // Additive (MVP-7616): "degraded" plus the issue list while any state file
    // is preserved aside, unwritable or failing to save.
    ...persistenceReport(),
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

// Scoped to the caller's API-key label (MVP-7678): a label sees and deletes its own conversations and the
// ownerless ones from before the update; another label's conversation answers 404.
app.get("/v1/sessions", (req, res) => {
  const visible = listSessions(req.clientLabel);
  res.json({ sessions: visible, count: visible.length });
});

app.delete("/v1/sessions/:id", (req, res) => {
  const deleted = deleteSession(req.params.id, req.clientLabel);
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

export const server = app.listen(PORT, HOST, (error?: Error) => {
  // Express 5 hands a listen error (a taken port) to this callback; without the exit the gateway would log
  // "listening" and stay up without serving its port (MVP-8129).
  if (error) {
    logAlways("server", `FATAL listen host=${HOST} port=${PORT} code=${(error as NodeJS.ErrnoException).code ?? "unknown"} reason=the listen port could not be opened`);
    process.exit(1);
  }
  log("server", `Agent Gateway v${VERSION} listening on ${HOST}:${PORT}`);
  log("server", `Log level: ${getLogLevel()}`);
  log("server", `Sessions: ${getSessionCount()} active`);
});
// Node's 300 s default would cut a slow but progressing upload; the relay's own
// idle timeout bounds it instead (MCP_UPLOAD_IDLE_TIMEOUT_MS).
server.requestTimeout = SERVER_REQUEST_TIMEOUT_MS;

// Clean stop on SIGTERM/SIGINT (MVP-7616), only when this file is the process
// entry point: tests that import server.js in-process keep their own signals.
function isEntryPoint(): boolean {
  if (!process.argv[1]) return false;
  try {
    return fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}
if (isEntryPoint()) {
  installShutdownHandlers(server);
  installAbortRejectionGuard();
}

export default app;
