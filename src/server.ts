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

/* ------------------------------------------------------------------ */
/*  Bootstrap                                                           */
/* ------------------------------------------------------------------ */

const app = express();
app.use(express.json({ limit: "10mb" }));

// Load API keys from env
loadApiKeys();

// Logging middleware (before auth so we log rejected requests too)
app.use(requestLoggingMiddleware);

// Auth middleware (skips /health internally)
app.use(authMiddleware);

/* ------------------------------------------------------------------ */
/*  Routes: Health (unauthenticated)                                    */
/* ------------------------------------------------------------------ */

const VERSION = process.env.npm_package_version || "0.1.0";

app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    version: VERSION,
    uptime: Math.round(process.uptime()),
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
});

export default app;
