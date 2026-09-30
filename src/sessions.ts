import { randomBytes, randomUUID } from "node:crypto";
import { log } from "./logging.js";
import { createPersistentStore } from "./persistence.js";

/* ------------------------------------------------------------------ */
/*  Types                                                               */
/* ------------------------------------------------------------------ */

/** The caller a conversation belongs to: the API-key label and the `user_id` of the request (null when it had none). */
export interface SessionOwner {
  label: string;
  userId: string | null;
}

export interface Session {
  sessionId: string;
  sdkSessionId?: string;  // Set after first successful SDK response
  systemPrompt: string;
  model: string;
  lastUsed: number;
  /**
   * Who created the conversation (MVP-7678). A conversation can only be continued by the exact same owner;
   * `null` and a present `user_id` are different owners. Entries from before the isolation update have none
   * and are refused on resume.
   */
  owner?: SessionOwner;
  /** Random name of the conversation's sandbox home below the storage root. Entries without one are legacy. */
  sandboxDirId?: string;
}

/** The shape of a `sandboxDirId`: 12 random bytes in hex. */
export const SANDBOX_DIR_ID = /^[0-9a-f]{24}$/;

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

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Every session must be an object with a numeric `lastUsed`, whatever the idle
 * timeout, because the expiry check and GET /v1/sessions read it. A missing
 * `sessions` or `settings` key and a non-numeric timeout load as before.
 */
function isPersistedData(data: unknown): boolean {
  if (!isObject(data)) return false;
  if (data.sessions === undefined || data.sessions === null) return true;
  return (
    isObject(data.sessions) &&
    Object.values(data.sessions).every(
      (session) => isObject(session) && typeof session.lastUsed === "number" && hasValidIsolationFields(session),
    )
  );
}

/**
 * The fields added by the isolation update are optional (older files load), but a present one must be
 * usable: an owner with a label and a string or null user id, a directory id of the expected shape.
 * An entry that fails this sets the whole file aside like any other unexpected content (MVP-7616).
 */
function hasValidIsolationFields(session: Record<string, unknown>): boolean {
  if (session.owner !== undefined) {
    const owner = session.owner;
    if (!isObject(owner) || typeof owner.label !== "string" || owner.label.length === 0) return false;
    if (owner.userId !== null && typeof owner.userId !== "string") return false;
  }
  if (session.sandboxDirId !== undefined && !(typeof session.sandboxDirId === "string" && SANDBOX_DIR_ID.test(session.sandboxDirId))) return false;
  return true;
}

const store = createPersistentStore({
  area: "sessions",
  file: PERSIST_PATH,
  snapshot: (): PersistedData => ({
    sessions: Object.fromEntries(sessions),
    settings: { sessionIdleTimeoutMs },
  }),
  isValid: isPersistedData,
});

/* ------------------------------------------------------------------ */
/*  Persistence                                                         */
/* ------------------------------------------------------------------ */

export function loadSessions(): void {
  const data = store.load() as PersistedData | undefined;
  if (!data) return;
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

/** Debounced atomic save (src/persistence.ts). */
export function persistSessions(): void {
  store.schedule();
}

/** Save sessions and settings now; false when the save failed or is suppressed. */
export function flushSessions(): boolean {
  return store.flush();
}

/* ------------------------------------------------------------------ */
/*  Session lookup / creation                                           */
/* ------------------------------------------------------------------ */

export interface GetSessionResult {
  sessionId: string;
  isNew: boolean;
  /** The conversation's sandbox home name; absent for a request without a session and for a legacy entry. */
  sandboxDirId?: string;
}

export type Admission = { kind: "new" } | { kind: "resume"; sandboxDirId: string } | { kind: "refused"; reason: "legacy" | "other_owner" };

let legacyRefusals = 0;

function sameOwner(a: SessionOwner, b: SessionOwner): boolean {
  return a.label === b.label && a.userId === b.userId;
}

/**
 * Decides, without changing anything, whether `caller` may use the conversation `clientId`: no such
 * conversation means a new one; the exact owner resumes; any other caller is refused; an entry from before
 * the update (no recorded owner or home) is refused for everyone, because the gateway has no record of who
 * it belongs to. Must run before `getSession`, which updates the entry.
 */
export function admitSession(clientId: string, caller: SessionOwner): Admission {
  const existing = sessions.get(clientId);
  if (!existing) return { kind: "new" };
  if (!existing.owner || !existing.sandboxDirId) {
    legacyRefusals++;
    // Counts only: no conversation id, no caller.
    log("audit", `sessions.legacy.refused total=${legacyRefusals}`);
    return { kind: "refused", reason: "legacy" };
  }
  if (!sameOwner(existing.owner, caller)) return { kind: "refused", reason: "other_owner" };
  return { kind: "resume", sandboxDirId: existing.sandboxDirId };
}

export function getSession(
  sessionId: string,
  systemPrompt: string,
  model: string,
  useSession = true,
  caller?: SessionOwner,
): GetSessionResult {
  if (!useSession) {
    return { sessionId: randomUUID(), isNew: true };
  }

  const existing = sessions.get(sessionId);

  if (existing) {
    existing.lastUsed = Date.now();
    existing.systemPrompt = systemPrompt;
    existing.model = model;
    if (existing.sdkSessionId) {
      persistSessions();
      // SDK has acknowledged this session — safe to resume
      return { sessionId: existing.sdkSessionId, isNew: false, sandboxDirId: existing.sandboxDirId };
    }
    // Session exists but SDK never confirmed it (e.g. first query failed) — start
    // fresh under a NEW SDK session ID: the runtime would append to the failed
    // attempt's transcript if the old ID were reused.
    existing.sessionId = randomUUID();
    persistSessions();
    log("sessions", `Session ${sessionId} has no confirmed SDK session — starting new query`);
    return { sessionId: existing.sessionId, isNew: true, sandboxDirId: existing.sandboxDirId };
  }

  // Create new session: it records its owner and a random sandbox home name.
  const claudeSessionId = randomUUID();
  const sandboxDirId = randomBytes(12).toString("hex");
  sessions.set(sessionId, {
    sessionId: claudeSessionId,
    systemPrompt,
    model,
    lastUsed: Date.now(),
    ...(caller ? { owner: { label: caller.label, userId: caller.userId }, sandboxDirId } : {}),
  });
  persistSessions();

  log("sessions", `Created session ${sessionId}`);
  return { sessionId: claudeSessionId, isNew: true, sandboxDirId: caller ? sandboxDirId : undefined };
}

/* ------------------------------------------------------------------ */
/*  CRUD                                                                */
/* ------------------------------------------------------------------ */

/** A caller sees its own label's conversations and the ownerless legacy entries (as before the update). */
function visibleTo(session: Session, callerLabel: string | undefined): boolean {
  return callerLabel === undefined || !session.owner || session.owner.label === callerLabel;
}

export function listSessions(callerLabel?: string): Array<{
  id: string;
  model: string;
  lastUsed: number;
}> {
  const result: Array<{ id: string; model: string; lastUsed: number }> = [];
  for (const [id, session] of sessions) {
    if (!visibleTo(session, callerLabel)) continue;
    result.push({ id, model: session.model, lastUsed: session.lastUsed });
  }
  return result;
}

export function updateSessionSdkId(clientId: string, sdkSessionId: string): void {
  const existing = sessions.get(clientId);
  if (existing && existing.sdkSessionId !== sdkSessionId) {
    existing.sdkSessionId = sdkSessionId;
    persistSessions();
    log("sessions", `Updated SDK sessionId for ${clientId}: ${sdkSessionId}`);
  }
}

/** Deletes the entry; a conversation of another label is reported as not found (and stays). */
export function deleteSession(sessionId: string, callerLabel?: string): boolean {
  const existing = sessions.get(sessionId);
  if (existing && !visibleTo(existing, callerLabel)) return false;
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
