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
  /**
   * Set (MVP-7402) when the conversation was deleted or expired but its folder is not confirmed gone yet: the entry
   * is then a tombstone that keeps the folder reference, blocks every query and is erased by the gateway itself.
   */
  erasePendingSince?: number;
}

/** What stays of an erased conversation: when it happened, nothing else (no folder name, no content). */
export interface ErasedMarker {
  erasedAt: number;
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
  /** Erased conversations per label and client id (MVP-7402): answers the owning label's late DELETE with 200. */
  erasedByLabel?: Record<string, Record<string, ErasedMarker>>;
  settings: SessionSettings;
}

/* ------------------------------------------------------------------ */
/*  State                                                               */
/* ------------------------------------------------------------------ */

/** Ownerless legacy entries by raw client id: refused for every caller, listed and deletable as before. */
const sessions = new Map<string, Session>();
/** Conversations per API-key label. Every entry has an owner and a sandbox home. */
const sessionsByLabel = new Map<string, Map<string, Session>>();
/** Erased markers per label (MVP-7402). Maps, never plain objects: a client id is caller-controlled (`__proto__`). */
const erasedByLabel = new Map<string, Map<string, ErasedMarker>>();

/** A conversation id for a log line: bounded to 128 characters and JSON-escaped, so it can never forge a line (MVP-7402). */
export function logId(id: string): string {
  return JSON.stringify(id.slice(0, 128));
}

function labelMap(label: string, create: boolean): Map<string, Session> | undefined {
  let map = sessionsByLabel.get(label);
  if (!map && create) {
    map = new Map();
    sessionsByLabel.set(label, map);
  }
  return map;
}

function markerMap(label: string, create: boolean): Map<string, ErasedMarker> | undefined {
  let map = erasedByLabel.get(label);
  if (!map && create) {
    map = new Map();
    erasedByLabel.set(label, map);
  }
  return map;
}

function labelEntry(label: string, clientId: string): Session | undefined {
  return sessionsByLabel.get(label)?.get(clientId);
}

function allSessions(): Session[] {
  return [...sessions.values(), ...[...sessionsByLabel.values()].flatMap((map) => [...map.values()])];
}

/** An entry that is not an erasure-pending tombstone. */
const live = (session: Session): boolean => session.erasePendingSince === undefined;

let sessionIdleTimeoutMs =
  parseInt(process.env.SESSION_IDLE_TIMEOUT_MS || "0", 10) || 0;

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
  if (!hasValidMarkers(data.erasedByLabel)) return false;
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

/** `erasedByLabel`: absent, or labels (non-empty names) of client ids whose marker holds a finite `erasedAt` and nothing else. */
function hasValidMarkers(markers: unknown): boolean {
  if (markers === undefined || markers === null) return true;
  if (!isObject(markers)) return false;
  return Object.entries(markers).every(
    ([label, map]) =>
      label.length > 0 &&
      isObject(map) &&
      Object.values(map).every((marker) => isObject(marker) && Object.keys(marker).length === 1 && typeof marker.erasedAt === "number" && Number.isFinite(marker.erasedAt)),
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
  // A tombstone belongs to a conversation with an owner and a folder; a legacy entry never has one (MVP-7402).
  if (session.erasePendingSince !== undefined) {
    if (typeof session.erasePendingSince !== "number" || !Number.isFinite(session.erasePendingSince)) return false;
    if (session.owner === undefined || session.sandboxDirId === undefined) return false;
  }
  return true;
}

const store = createPersistentStore({
  area: "sessions",
  file: PERSIST_PATH,
  snapshot: (): PersistedData => ({
    sessions: Object.fromEntries(sessions),
    sessionsByLabel: Object.fromEntries([...sessionsByLabel].map(([label, map]) => [label, Object.fromEntries(map)])),
    // Additive: absent until the first erasure, so a file that never saw one is written back unchanged.
    ...(erasedByLabel.size > 0 ? { erasedByLabel: Object.fromEntries([...erasedByLabel].map(([label, map]) => [label, Object.fromEntries(map)])) } : {}),
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
  // An expired conversation with a folder is not dropped (MVP-7402): it becomes a tombstone that the startup sweep
  // erases. An expired legacy entry is dropped as before; no file is touched.
  const restoreOwned = (label: string, id: string, session: Session): void => {
    if (live(session) && expired(session)) session.erasePendingSince = now;
    labelMap(label, true)!.set(id, session);
  };

  // Restore sessions. An entry with an owner and a home (written by the isolation update)
  // moves into its label's map; an ownerless one stays a legacy entry under its raw id.
  for (const [id, session] of Object.entries(data.sessions || {})) {
    if (session.owner && session.sandboxDirId) restoreOwned(session.owner.label, id, session);
    else if (!expired(session)) sessions.set(id, session);
  }
  // Per-label entries win over a moved entry of the same label and id.
  for (const [label, map] of Object.entries(data.sessionsByLabel || {})) {
    for (const [id, session] of Object.entries(map)) restoreOwned(label, id, session);
  }
  // Markers of conversations that are gone; a restored entry of the same id means the id is in use again.
  for (const [label, map] of Object.entries(data.erasedByLabel || {})) {
    for (const [id, marker] of Object.entries(map)) {
      if (labelEntry(label, id)) continue;
      markerMap(label, true)!.set(id, { erasedAt: marker.erasedAt });
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

export type Admission = { kind: "new" } | { kind: "resume"; sandboxDirId: string } | { kind: "refused"; reason: "legacy" | "erasing" };

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
    // A deleted or expired conversation whose folder is not confirmed gone: nothing may resume or extend it (MVP-7402).
    if (!live(own)) return { kind: "refused", reason: "erasing" };
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
    log("sessions", `Session ${logId(sessionId)} has no confirmed SDK session — starting new query`);
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
  if (caller) {
    labelMap(caller.label, true)!.set(sessionId, entry);
    // The id is in use again: a later DELETE concerns this new conversation, not the erased one.
    markerMap(caller.label, false)?.delete(sessionId);
  } else sessions.set(sessionId, entry);
  persistSessions();

  log("sessions", `Created session ${logId(sessionId)}`);
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
    for (const map of sessionsByLabel.values()) for (const [id, session] of map) if (live(session)) add(id, session);
  } else {
    for (const [id, session] of sessionsByLabel.get(callerLabel) ?? []) if (live(session)) add(id, session);
  }
  for (const [id, session] of sessions) add(id, session);
  return result;
}

export function updateSessionSdkId(clientId: string, sdkSessionId: string, label?: string): void {
  const existing = label !== undefined ? labelEntry(label, clientId) : sessions.get(clientId);
  if (existing && existing.sdkSessionId !== sdkSessionId) {
    existing.sdkSessionId = sdkSessionId;
    persistSessions();
    log("sessions", `Updated SDK sessionId for ${logId(clientId)}: ${sdkSessionId}`);
  }
}

/** Conversations that can be used or listed: tombstones (erasure pending) are not counted. */
export function getSessionCount(): number {
  return allSessions().filter(live).length;
}

/* ------------------------------------------------------------------ */
/*  Erasure state (MVP-7402; the erase path is session-erasure.ts)      */
/* ------------------------------------------------------------------ */

/** The caller's own conversation of that id, if any: its folder name and whether it is already a tombstone. */
export function ownedConversation(label: string, clientId: string): { sandboxDirId: string; pending: boolean } | undefined {
  const entry = labelEntry(label, clientId);
  if (!entry?.sandboxDirId) return undefined;
  return { sandboxDirId: entry.sandboxDirId, pending: !live(entry) };
}

/** True when the label has an erased marker for that id. */
export function hasErasedMarker(label: string, clientId: string): boolean {
  return markerMap(label, false)?.has(clientId) ?? false;
}

/** True when an ownerless legacy entry (from before the isolation update) exists under that raw id. */
export function hasLegacyEntry(clientId: string): boolean {
  return sessions.has(clientId);
}

/** Set when the last flush of a new tombstone failed: the sweep saves again (it stays pending in memory meanwhile). */
let pendingFlushFailed = false;

/**
 * Marks the caller's conversation erasure-pending (idempotent), in memory: the caller of the erase path saves it
 * (`persistTombstonesNow`) before it answers 503, so every tombstone a caller was told about survives a restart. A
 * delete that completes at once never needs the tombstone on disk. False when there is no such conversation.
 */
export function markErasePending(label: string, clientId: string): boolean {
  const entry = labelEntry(label, clientId);
  if (!entry?.sandboxDirId) return false;
  if (live(entry)) entry.erasePendingSince = Date.now();
  return true;
}

/** Saves now, because a caller was told "pending". A failed save is repeated by every sweep until it succeeds. */
export function persistTombstonesNow(): void {
  pendingFlushFailed = !flushSessions();
}

/** Saves again after a failed save of a tombstone; a no-op otherwise. */
export function reflushPending(): void {
  if (pendingFlushFailed) pendingFlushFailed = !flushSessions();
}

/** True when any other entry (of any label, legacy included) references the same folder name. */
export function folderSharedWithOther(label: string, clientId: string, sandboxDirId: string): boolean {
  const self = labelEntry(label, clientId);
  return allSessions().some((entry) => entry !== self && entry.sandboxDirId === sandboxDirId);
}

/**
 * The folder is gone: in one step the entry is removed and the label's marker written, then saved like every other
 * change (debounced, flushed at shutdown). The erasure itself does not depend on the save: a restart that finds the
 * entry still on disk as a tombstone finds its folder absent and completes it. Nothing happens when the entry is gone
 * or no longer names that folder.
 */
export function completeErasure(label: string, clientId: string, sandboxDirId: string): boolean {
  const map = labelMap(label, false);
  const entry = map?.get(clientId);
  if (!map || !entry || entry.sandboxDirId !== sandboxDirId) return false;
  map.delete(clientId);
  markerMap(label, true)!.set(clientId, { erasedAt: Date.now() });
  persistSessions();
  return true;
}

/** Every tombstone, for the sweep. */
export function pendingConversations(): Array<{ label: string; clientId: string; sandboxDirId: string }> {
  const out: Array<{ label: string; clientId: string; sandboxDirId: string }> = [];
  for (const [label, map] of sessionsByLabel) {
    for (const [clientId, entry] of map) if (!live(entry) && entry.sandboxDirId) out.push({ label, clientId, sandboxDirId: entry.sandboxDirId });
  }
  return out;
}

/** The tombstone that names that folder, for the release of its conversation lock. */
export function pendingConversationForDir(sandboxDirId: string): { label: string; clientId: string } | undefined {
  return pendingConversations().find((p) => p.sandboxDirId === sandboxDirId);
}

/** The number of tombstones: the aggregate `erasurePending` of /health (no ids, no labels). */
export function erasurePendingCount(): number {
  return allSessions().filter((entry) => !live(entry)).length;
}

/**
 * Idle expiry: an idle conversation with a folder becomes a tombstone (the caller erases it); an idle legacy entry is
 * dropped without any file being touched, as before. Returns how many entries each rule took.
 */
export function expireIdleSessions(now: number = Date.now()): { marked: number; dropped: number } {
  if (sessionIdleTimeoutMs <= 0) return { marked: 0, dropped: 0 };
  let marked = 0;
  let dropped = 0;
  for (const [id, session] of sessions) {
    if (now - session.lastUsed > sessionIdleTimeoutMs) {
      sessions.delete(id);
      dropped++;
    }
  }
  for (const map of sessionsByLabel.values()) {
    for (const session of map.values()) {
      if (live(session) && now - session.lastUsed > sessionIdleTimeoutMs) {
        session.erasePendingSince = now;
        marked++;
      }
    }
  }
  if (marked + dropped > 0) {
    log("sessions", `Expired ${marked + dropped} idle session(s). Active: ${getSessionCount()}`);
    if (marked > 0) pendingFlushFailed = !flushSessions();
    else persistSessions();
  }
  return { marked, dropped };
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
