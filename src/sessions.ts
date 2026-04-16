import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { log } from "./logging.js";

/* ------------------------------------------------------------------ */
/*  Types                                                               */
/* ------------------------------------------------------------------ */

export interface Session {
  sessionId: string;
  systemPrompt: string;
  model: string;
  lastUsed: number;
}

export interface SessionSettings {
  sessionIdleTimeoutMs: number;
}

interface PersistedData {
  sessions: Record<string, Session>;
  settings: SessionSettings;
}

/* ------------------------------------------------------------------ */
/*  State                                                               */
/* ------------------------------------------------------------------ */

const sessions = new Map<string, Session>();

let sessionIdleTimeoutMs =
  parseInt(process.env.SESSION_IDLE_TIMEOUT_MS || "0", 10) || 0;

const CLEANUP_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes
const PERSIST_PATH =
  process.env.SESSION_PERSIST_PATH || "./data/sessions.json";

let persistTimer: ReturnType<typeof setTimeout> | null = null;

/* ------------------------------------------------------------------ */
/*  Persistence                                                         */
/* ------------------------------------------------------------------ */

export function loadSessions(): void {
  try {
    if (fs.existsSync(PERSIST_PATH)) {
      const raw = fs.readFileSync(PERSIST_PATH, "utf-8");
      const data: PersistedData = JSON.parse(raw);
      const now = Date.now();

      // Restore settings
      if (
        data.settings &&
        typeof data.settings.sessionIdleTimeoutMs === "number"
      ) {
        sessionIdleTimeoutMs = data.settings.sessionIdleTimeoutMs;
      }

      // Restore sessions (filter expired ones)
      for (const [id, session] of Object.entries(data.sessions || {})) {
        if (
          sessionIdleTimeoutMs > 0 &&
          now - session.lastUsed >= sessionIdleTimeoutMs
        ) {
          continue;
        }
        sessions.set(id, session);
      }

      log("sessions", `Restored ${sessions.size} session(s) from disk`);
    }
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    log("sessions", `Failed to load: ${msg}`);
  }
}

export function persistSessions(): void {
  if (persistTimer) return; // debounce
  persistTimer = setTimeout(() => {
    persistTimer = null;
    try {
      const dir = path.dirname(PERSIST_PATH);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }

      const data: PersistedData = {
        sessions: Object.fromEntries(sessions),
        settings: { sessionIdleTimeoutMs },
      };
      fs.writeFileSync(PERSIST_PATH, JSON.stringify(data, null, 2));
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      log("sessions", `Failed to persist: ${msg}`);
    }
  }, 100);
}

/* ------------------------------------------------------------------ */
/*  Session lookup / creation                                           */
/* ------------------------------------------------------------------ */

export interface GetSessionResult {
  sessionId: string;
  isNew: boolean;
}

export function getSession(
  sessionId: string,
  systemPrompt: string,
  model: string,
  useSession = true,
): GetSessionResult {
  if (!useSession) {
    return { sessionId: randomUUID(), isNew: true };
  }

  const existing = sessions.get(sessionId);

  if (existing) {
    // Always resume existing session — the client (Reqlift) decides which session to use
    existing.lastUsed = Date.now();
    existing.systemPrompt = systemPrompt;
    existing.model = model;
    persistSessions();
    return { sessionId: existing.sessionId, isNew: false };
  }

  // Create new session
  const claudeSessionId = randomUUID();
  sessions.set(sessionId, {
    sessionId: claudeSessionId,
    systemPrompt,
    model,
    lastUsed: Date.now(),
  });
  persistSessions();

  log("sessions", `Created session ${sessionId}`);
  return { sessionId: claudeSessionId, isNew: true };
}

/* ------------------------------------------------------------------ */
/*  CRUD                                                                */
/* ------------------------------------------------------------------ */

export function listSessions(): Array<{
  id: string;
  model: string;
  lastUsed: number;
}> {
  const result: Array<{ id: string; model: string; lastUsed: number }> = [];
  for (const [id, session] of sessions) {
    result.push({ id, model: session.model, lastUsed: session.lastUsed });
  }
  return result;
}

export function updateSessionSdkId(clientId: string, sdkSessionId: string): void {
  const existing = sessions.get(clientId);
  if (existing && existing.sessionId !== sdkSessionId) {
    existing.sessionId = sdkSessionId;
    persistSessions();
    log("sessions", `Updated SDK sessionId for ${clientId}: ${sdkSessionId}`);
  }
}

export function deleteSession(sessionId: string): boolean {
  const deleted = sessions.delete(sessionId);
  if (deleted) {
    persistSessions();
    log("sessions", `Deleted session ${sessionId}`);
  }
  return deleted;
}

export function getSessionCount(): number {
  return sessions.size;
}

/* ------------------------------------------------------------------ */
/*  Settings                                                            */
/* ------------------------------------------------------------------ */

export function getSettings(): SessionSettings {
  return { sessionIdleTimeoutMs };
}

export function updateSettings(
  updates: Partial<SessionSettings>,
): SessionSettings {
  if (typeof updates.sessionIdleTimeoutMs === "number") {
    sessionIdleTimeoutMs = updates.sessionIdleTimeoutMs;
    log(
      "sessions",
      `Idle timeout updated to ${sessionIdleTimeoutMs}ms`,
    );
  }
  persistSessions();
  return { sessionIdleTimeoutMs };
}

/* ------------------------------------------------------------------ */
/*  Periodic cleanup                                                    */
/* ------------------------------------------------------------------ */

setInterval(() => {
  if (sessionIdleTimeoutMs <= 0) return;
  const now = Date.now();
  let cleaned = 0;
  for (const [id, session] of sessions) {
    if (now - session.lastUsed > sessionIdleTimeoutMs) {
      sessions.delete(id);
      cleaned++;
    }
  }
  if (cleaned > 0) {
    log(
      "sessions",
      `Cleaned ${cleaned} idle session(s). Active: ${sessions.size}`,
    );
    persistSessions();
  }
}, CLEANUP_INTERVAL_MS);
