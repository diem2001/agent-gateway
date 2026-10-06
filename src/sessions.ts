import { randomBytes, randomUUID } from "node:crypto";
import { log } from "./logging.js";
import { createPersistentStore } from "./persistence.js";

/* ------------------------------------------------------------------ */
/*  Types                                                               */
/* ------------------------------------------------------------------ */

/**
 * The caller of a request: the API-key label and the `user_id` of the request (null when it had none). The label
 * decides which conversations the caller can reach (DEC-ISO-007, MVP-8044); the `user_id` is recorded on a new
 * conversation as informational metadata and never read for an admission decision.
 */
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
   * Who created the conversation (MVP-7678): the API-key label it belongs to and the creator's `user_id`
   * (informational only, may be absent in a stored file). Any writer of the label can continue it. Entries from
   * before the isolation update have no owner and are refused on resume.
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
  /** Ownerless legacy entries (from before the isolation update), keyed by the raw client id. */
  sessions: Record<string, Session>;
  /**
   * Conversations per API-key label (MVP-7679): `sessionsByLabel[<label>][<client id>]`. A separate additive map, so
   * a client id can never collide with a legacy raw id, and one label's ids are invisible to another.
   */
  sessionsByLabel?: Record<string, Record<string, Session>>;
  settings: SessionSettings;
}

/* ------------------------------------------------------------------ */
/*  State                                                               */
/* ------------------------------------------------------------------ */

/** Ownerless legacy entries by raw client id: refused for every caller, listed and deletable as before. */
const sessions = new Map<string, Session>();
/** Conversations per API-key label. Every entry has an owner and a sandbox home. */
const sessionsByLabel = new Map<string, Map<string, Session>>();

function labelMap(label: string, create: boolean): Map<string, Session> | undefined {
  let map = sessionsByLabel.get(label);
  if (!map && create) {
    map = new Map();
    sessionsByLabel.set(label, map);
  }
  return map;
}

function labelEntry(label: string, clientId: string): Session | undefined {
  return sessionsByLabel.get(label)?.get(clientId);
}

function allSessions(): Session[] {
  return [...sessions.values(), ...[...sessionsByLabel.values()].flatMap((map) => [...map.values()])];
}

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
  const sessionsOk =
    data.sessions === undefined ||
    data.sessions === null ||
    (isObject(data.sessions) &&
      Object.values(data.sessions).every((session) => isObject(session) && typeof session.lastUsed === "number" && hasValidIsolationFields(session)));
  if (!sessionsOk) return false;
  const byLabel = data.sessionsByLabel;
  if (byLabel === undefined || byLabel === null) return true;
  if (!isObject(byLabel)) return false;
  // Every per-label entry must be a complete conversation of that label.
  return Object.entries(byLabel).every(
    ([label, map]) =>
      isObject(map) &&
      Object.values(map).every(
        (session) =>
          isObject(session) &&
          typeof session.lastUsed === "number" &&
          hasValidIsolationFields(session) &&
          isObject(session.owner) &&
          session.owner.label === label &&
          typeof session.sandboxDirId === "string",
      ),
  );
}

/**
 * The fields added by the isolation update are optional (older files load), but a present one must be
 * usable: an owner with a label and, when it carries one, a string or null creator user id (the key may be absent:
 * the label decides, MVP-8044), a directory id of the expected shape.
 * An entry that fails this sets the whole file aside like any other unexpected content (MVP-7616).
 */
function hasValidIsolationFields(session: Record<string, unknown>): boolean {
  if (session.owner !== undefined) {
    const owner = session.owner;
    if (!isObject(owner) || typeof owner.label !== "string" || owner.label.length === 0) return false;
    if (owner.userId !== undefined && owner.userId !== null && typeof owner.userId !== "string") return false;
  }
  if (session.sandboxDirId !== undefined && !(typeof session.sandboxDirId === "string" && SANDBOX_DIR_ID.test(session.sandboxDirId))) return false;
  return true;
}

const store = createPersistentStore({
  area: "sessions",
  file: PERSIST_PATH,
  snapshot: (): PersistedData => ({
    sessions: Object.fromEntries(sessions),
    sessionsByLabel: Object.fromEntries([...sessionsByLabel].map(([label, map]) => [label, Object.fromEntries(map)])),
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

  const expired = (session: Session): boolean => sessionIdleTimeoutMs > 0 && now - session.lastUsed >= sessionIdleTimeoutMs;

  // Restore sessions (filter expired ones). An entry with an owner and a home (written by the isolation update)
  // moves into its label's map; an ownerless one stays a legacy entry under its raw id.
  for (const [id, session] of Object.entries(data.sessions || {})) {
    if (expired(session)) continue;
    if (session.owner && session.sandboxDirId) labelMap(session.owner.label, true)!.set(id, session);
    else sessions.set(id, session);
  }
  // Per-label entries win over a moved entry of the same label and id.
  for (const [label, map] of Object.entries(data.sessionsByLabel || {})) {
    for (const [id, session] of Object.entries(map)) {
      if (!expired(session)) labelMap(label, true)!.set(id, session);
    }
  }

  log("sessions", `Restored ${getSessionCount()} session(s) from disk`);
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

export type Admission = { kind: "new" } | { kind: "resume"; sandboxDirId: string } | { kind: "refused"; reason: "legacy" };

let legacyRefusals = 0;

/**
 * Decides, without changing anything, whether `caller` may use the conversation `clientId`: conversations are
 * keyed by (API-key label, client id), so another label's conversation is not visible and the caller gets a new
 * one; within the label any `user_id`, null or present, resumes (the app decides who may write, DEC-ISO-007); an
 * entry from before the isolation update (no recorded owner or home, raw id) is refused for everyone, because the
 * gateway has no record of who it belongs to. Must run before `getSession`, which updates the entry.
 */
export function admitSession(clientId: string, caller: SessionOwner): Admission {
  const own = labelEntry(caller.label, clientId);
  if (own) {
    if (!own.owner || !own.sandboxDirId) return { kind: "refused", reason: "legacy" };
    return { kind: "resume", sandboxDirId: own.sandboxDirId };
  }
  // Another label's conversation with the same id is invisible here: this caller gets a new conversation of its
  // own. Only an ownerless legacy entry under the raw id is visible (and refused: nobody knows its owner).
  if (sessions.has(clientId)) {
    legacyRefusals++;
    // Counts only: no conversation id, no caller.
    log("audit", `sessions.legacy.refused total=${legacyRefusals}`);
    return { kind: "refused", reason: "legacy" };
  }
  return { kind: "new" };
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

  const existing = caller ? labelEntry(caller.label, sessionId) : sessions.get(sessionId);

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

  // Create new session: it records its owner and a random sandbox home name, below its label.
  const claudeSessionId = randomUUID();
  const sandboxDirId = randomBytes(12).toString("hex");
  const entry: Session = {
    sessionId: claudeSessionId,
    systemPrompt,
    model,
    lastUsed: Date.now(),
    ...(caller ? { owner: { label: caller.label, userId: caller.userId }, sandboxDirId } : {}),
  };
  if (caller) labelMap(caller.label, true)!.set(sessionId, entry);
  else sessions.set(sessionId, entry);
  persistSessions();

  log("sessions", `Created session ${sessionId}`);
  return { sessionId: claudeSessionId, isNew: true, sandboxDirId: caller ? sandboxDirId : undefined };
}

/* ------------------------------------------------------------------ */
/*  CRUD                                                                */
/* ------------------------------------------------------------------ */

/**
 * A caller sees its own label's conversations and the ownerless legacy entries (as before the update), by raw id.
 * Another label's conversation is not listed.
 */
export function listSessions(callerLabel?: string): Array<{
  id: string;
  model: string;
  lastUsed: number;
}> {
  const result: Array<{ id: string; model: string; lastUsed: number }> = [];
  const seen = new Set<string>();
  const add = (id: string, session: Session): void => {
    if (seen.has(id)) return;
    seen.add(id);
    result.push({ id, model: session.model, lastUsed: session.lastUsed });
  };
  if (callerLabel === undefined) {
    for (const map of sessionsByLabel.values()) for (const [id, session] of map) add(id, session);
  } else {
    for (const [id, session] of sessionsByLabel.get(callerLabel) ?? []) add(id, session);
  }
  for (const [id, session] of sessions) add(id, session);
  return result;
}

export function updateSessionSdkId(clientId: string, sdkSessionId: string, label?: string): void {
  const existing = label !== undefined ? labelEntry(label, clientId) : sessions.get(clientId);
  if (existing && existing.sdkSessionId !== sdkSessionId) {
    existing.sdkSessionId = sdkSessionId;
    persistSessions();
    log("sessions", `Updated SDK sessionId for ${clientId}: ${sdkSessionId}`);
  }
}

/**
 * Deletes the caller's own entry of that id; failing that, an ownerless legacy entry. Another label's
 * conversation is reported as not found (and stays). Without a label (tests) the legacy map is used.
 */
export function deleteSession(sessionId: string, callerLabel?: string): boolean {
  let deleted = false;
  const own = callerLabel !== undefined ? labelMap(callerLabel, false) : undefined;
  if (own?.delete(sessionId)) deleted = true;
  else if (sessions.delete(sessionId)) deleted = true;
  if (deleted) {
    persistSessions();
    log("sessions", `Deleted session ${sessionId}`);
  }
  return deleted;
}

export function getSessionCount(): number {
  return allSessions().length;
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
  for (const [label, map] of sessionsByLabel) {
    for (const [id, session] of map) {
      if (now - session.lastUsed > sessionIdleTimeoutMs) {
        map.delete(id);
        cleaned++;
      }
    }
    if (map.size === 0) sessionsByLabel.delete(label);
  }
  if (cleaned > 0) {
    log(
      "sessions",
      `Cleaned ${cleaned} idle session(s). Active: ${getSessionCount()}`,
    );
    persistSessions();
  }
}, CLEANUP_INTERVAL_MS);
