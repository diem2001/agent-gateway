import { execFile } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import type { Request, Response } from "express";
import { log } from "./logging.js";
import { loadIsolationConfig, onConversationRunReleased, tryLockConversation } from "./sandbox.js";
import {
  SANDBOX_DIR_ID,
  completeErasure,
  expireIdleSessions,
  folderSharedWithOther,
  hasErasedMarker,
  hasLegacyEntry,
  logId,
  markErasePending,
  ownedConversation,
  pendingConversationForDir,
  pendingConversations,
  reflushPending,
} from "./sessions.js";

/**
 * Erasure of a deleted conversation (MVP-7402).
 *
 * Deleting a conversation removes its private folder (`<AGENT_SANDBOX_ROOT>/sessions/<sandboxDirId>`: transcripts,
 * tool results, uploaded images, the work area). The gateway reports success only when the folder is confirmed gone.
 * Until then the conversation is a tombstone in `sessions.json` (`erasePendingSince`): blocked for every query,
 * hidden from the list, counted in /health `erasurePending`. A finished erasure leaves a content-free marker so the
 * owner's late retry answers 200 every time.
 *
 * The folder is only ever reached through a validated `sandboxDirId` of the caller's own entry, never through a
 * caller-supplied id, and only while the conversation lock is held (a sandbox that still uses the home is never
 * raced). Links are never followed and mounts never crossed.
 */

/* ------------------------------------------------------------------ */
/*  The erase helper                                                    */
/* ------------------------------------------------------------------ */

/** Fixed failure words: logged and counted, never a path, message or content. */
export type ErasureFailureCode =
  | "invalid_dir_id"
  | "root_invalid"
  | "unexpected_type"
  | "mount_boundary"
  | "tool_missing"
  | "rm_failed"
  | "incomplete"
  | "dir_shared";

export type ErasureResult = { ok: true } | { ok: false; code: ErasureFailureCode };

/** GNU coreutils at absolute paths: their traversal works relative to open directories, so any depth is removable. */
const CHMOD = "/usr/bin/chmod";
const RM = "/usr/bin/rm";

function toolUsable(file: string): boolean {
  try {
    const stat = fs.lstatSync(file);
    if (!stat.isFile()) return false;
    fs.accessSync(file, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

function lstatOrNull(p: string): fs.Stats | null {
  try {
    return fs.lstatSync(p);
  } catch {
    return null;
  }
}

/** A real directory (never a link) owned by the gateway user and not group or world writable. */
function trustedDirectory(stat: fs.Stats | null): stat is fs.Stats {
  if (!stat || !stat.isDirectory()) return false;
  const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
  return (uid === undefined || stat.uid === uid) && (stat.mode & 0o022) === 0;
}

/**
 * True when a mount point is `dir` or lies below it, or the mount table cannot be read (then nothing is assumed).
 * The mount table is the gateway's own; the agent cannot create mounts on the host, so this only catches an
 * operator's bind mount, before any tool touches the tree.
 */
function mountBelow(dir: string): boolean {
  let table: string;
  try {
    table = fs.readFileSync("/proc/self/mountinfo", "utf8");
  } catch {
    return true;
  }
  for (const line of table.split("\n")) {
    const raw = line.split(" ")[4];
    if (raw === undefined) continue;
    const mountPoint = raw.replace(/\\([0-7]{3})/g, (_m, octal: string) => String.fromCharCode(parseInt(octal, 8)));
    if (mountPoint === dir || mountPoint.startsWith(`${dir}/`)) return true;
  }
  return false;
}

function run(file: string, args: string[]): Promise<boolean> {
  return new Promise((resolve) => {
    // No shell, no inherited environment: the child gets nothing of the gateway's credentials.
    execFile(file, args, { env: { LC_ALL: "C" }, maxBuffer: 1024 * 1024, windowsHide: true }, (error) => resolve(error === null));
  });
}

/**
 * Removes `<root>/sessions/<dirId>` and reports whether it is gone. Absent counts as gone only when the root and its
 * `sessions` directory are the trusted real directories on one device (a missing or relinked directory is never
 * "already erased"). A link or non-directory in the folder's place is refused and left alone. The removal first gives
 * the gateway user `u+rwx` on every directory (the agent may have made some unreadable; links are not followed), then
 * removes recursively without crossing a device; both steps work at any depth.
 */
export async function eraseConversationDir(root: string, dirId: string): Promise<ErasureResult> {
  if (!SANDBOX_DIR_ID.test(dirId)) return { ok: false, code: "invalid_dir_id" };
  const rootStat = lstatOrNull(root);
  if (!trustedDirectory(rootStat)) return { ok: false, code: "root_invalid" };
  let real: string;
  try {
    real = fs.realpathSync(root);
  } catch {
    return { ok: false, code: "root_invalid" };
  }
  if (real !== path.resolve(root)) return { ok: false, code: "root_invalid" };
  const sessionsDir = path.join(root, "sessions");
  const sessionsStat = lstatOrNull(sessionsDir);
  if (!trustedDirectory(sessionsStat) || sessionsStat.dev !== rootStat.dev) return { ok: false, code: "root_invalid" };

  const dir = path.join(sessionsDir, dirId);
  const stat = lstatOrNull(dir);
  if (!stat) return { ok: true };
  const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
  if (!stat.isDirectory() || (uid !== undefined && stat.uid !== uid)) return { ok: false, code: "unexpected_type" };
  if (stat.dev !== sessionsStat.dev || mountBelow(dir)) return { ok: false, code: "mount_boundary" };
  if (!toolUsable(CHMOD) || !toolUsable(RM)) return { ok: false, code: "tool_missing" };

  // A chmod problem is not decisive: the removal below reports whether the folder could be removed anyway.
  await run(CHMOD, ["-R", "u+rwx", "--", dir]);
  const removed = await run(RM, ["-rf", "--one-file-system", "--", dir]);
  if (lstatOrNull(dir)) return { ok: false, code: removed ? "incomplete" : "rm_failed" };
  return { ok: true };
}

/* ------------------------------------------------------------------ */
/*  The erase path                                                      */
/* ------------------------------------------------------------------ */

/** Test seams (no effect by default): a replacement for the removal and the bound of the DELETE wait. */
export const erasureSeams: {
  remove?: (root: string, dirId: string) => Promise<ErasureResult>;
  deleteWaitMs?: number;
} = {};

/** A DELETE waits at most this long for the removal, then answers 503 while the removal continues. */
const DELETE_WAIT_MS = 5000;

/** One attempt per folder at a time: a concurrent caller joins the attempt already running. */
const inFlight = new Map<string, Promise<boolean>>();

function failed(clientId: string, code: ErasureFailureCode): void {
  log("sessions", `sessions.erasure.failed id=${logId(clientId)} code=${code}`);
}

async function runAttempt(label: string, clientId: string, dirId: string): Promise<boolean> {
  // A folder name referenced by two entries (a tampered or buggy file) would let one erase take the other's data.
  if (folderSharedWithOther(label, clientId, dirId)) {
    failed(clientId, "dir_shared");
    return false;
  }
  // The same lock a run holds: a held lock is not a failure, the erasure waits for the run's release.
  const lock = tryLockConversation(dirId, "eraser");
  if (!lock) return false;
  let result: ErasureResult;
  try {
    const root = loadIsolationConfig().sandboxRoot;
    result = await (erasureSeams.remove ?? eraseConversationDir)(root, dirId);
  } catch {
    result = { ok: false, code: "root_invalid" };
  } finally {
    lock.release();
  }
  if (!result.ok) {
    failed(clientId, result.code);
    return false;
  }
  // Entry out and marker in, in one step; the answer does not depend on whether the save succeeded.
  completeErasure(label, clientId, dirId);
  log("sessions", `sessions.erasure.done id=${logId(clientId)}`);
  return true;
}

/**
 * Tries to finish the erasure of the label's conversation: true when its folder is gone (entry removed, marker
 * written), false when it stays pending (a run holds it, a file system error, a shared folder name).
 */
export function eraseOwnedConversation(label: string, clientId: string): Promise<boolean> {
  const own = ownedConversation(label, clientId);
  if (!own) return Promise.resolve(false);
  const running = inFlight.get(own.sandboxDirId);
  if (running) return running;
  const attempt = runAttempt(label, clientId, own.sandboxDirId).finally(() => inFlight.delete(own.sandboxDirId));
  inFlight.set(own.sandboxDirId, attempt);
  return attempt;
}

/* ------------------------------------------------------------------ */
/*  DELETE /v1/sessions/:id                                             */
/* ------------------------------------------------------------------ */

export type DeleteOutcome = "deleted" | "pending" | "legacy" | "not_found";

function withinBound(attempt: Promise<boolean>): Promise<boolean> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(false), erasureSeams.deleteWaitMs ?? DELETE_WAIT_MS);
    timer.unref();
    void attempt.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      () => {
        clearTimeout(timer);
        resolve(false);
      },
    );
  });
}

/**
 * The decision of a DELETE, in this order: the caller's own conversation (erased or pending), else the caller's own
 * erased marker (answered 200 again), else an ownerless legacy entry (409, nothing touched), else not found. The id
 * is only ever a key into the caller's own maps; it never reaches the file system.
 */
export async function deleteConversation(clientId: string, label: string | undefined): Promise<DeleteOutcome> {
  if (label !== undefined) {
    if (ownedConversation(label, clientId)) {
      markErasePending(label, clientId);
      return (await withinBound(eraseOwnedConversation(label, clientId))) ? "deleted" : "pending";
    }
    if (hasErasedMarker(label, clientId)) return "deleted";
  }
  return hasLegacyEntry(clientId) ? "legacy" : "not_found";
}

export async function deleteSessionRoute(req: Request, res: Response): Promise<void> {
  const outcome = await deleteConversation(String(req.params.id), req.clientLabel);
  switch (outcome) {
    case "deleted":
      res.json({ deleted: true });
      return;
    case "pending":
      res.status(503).json({ error: "erasure_pending" });
      return;
    case "legacy":
      res.status(409).json({ error: "legacy_not_erased" });
      return;
    default:
      res.status(404).json({ error: "Session not found" });
  }
}

/* ------------------------------------------------------------------ */
/*  Gateway-driven completion                                           */
/* ------------------------------------------------------------------ */

export const DEFAULT_SESSION_ERASURE_RETRY_MS = 60_000;

/** An invalid `SESSION_ERASURE_RETRY_MS`: startup stops with one fixed line, like the other configuration keys. */
export class ErasureConfigError extends Error {
  readonly key = "SESSION_ERASURE_RETRY_MS";

  constructor() {
    super("invalid value for SESSION_ERASURE_RETRY_MS");
  }

  get logLine(): string {
    return `FATAL config key=${this.key} reason=must be a positive whole number of milliseconds`;
  }
}

/** The sweep interval: unset or empty = 60 s; anything but a positive whole number of milliseconds is an error. */
export function loadErasureRetryMs(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env.SESSION_ERASURE_RETRY_MS;
  if (raw === undefined || raw.trim() === "") return DEFAULT_SESSION_ERASURE_RETRY_MS;
  if (!/^[0-9]+$/.test(raw.trim())) throw new ErasureConfigError();
  const value = Number(raw.trim());
  if (!Number.isSafeInteger(value) || value <= 0) throw new ErasureConfigError();
  return value;
}

let sweeping: Promise<void> | null = null;

/**
 * One sweep: save a tombstone whose first save failed, take the idle conversations (when an idle timeout is set),
 * then try every tombstone once, one after the other. A sweep that finds the previous one still running does
 * nothing, so sweeps never overlap and a slow removal never queues work up.
 */
export function runErasureSweep(): Promise<void> {
  if (sweeping) return Promise.resolve();
  const sweep = (async (): Promise<void> => {
    reflushPending();
    expireIdleSessions();
    for (const { label, clientId } of pendingConversations()) {
      try {
        await eraseOwnedConversation(label, clientId);
      } catch {
        // An attempt reports its own failures; the next sweep tries again.
      }
    }
  })().finally(() => {
    sweeping = null;
  });
  sweeping = sweep;
  return sweep;
}

let sweepTimer: ReturnType<typeof setInterval> | null = null;
let stopReleaseListener: (() => void) | null = null;

/**
 * Starts the gateway-driven completion: a tombstone is retried when the run that held its conversation releases it,
 * on every sweep tick (also with the idle timeout 0), and once now (after a restart). Returns the startup sweep, which
 * the caller does not wait for. Calling it again restarts the timer.
 */
export function startErasureSweeper(options: { retryMs?: number } = {}): Promise<void> {
  stopErasureSweeper();
  // A run's release only schedules the attempt (never inside `release`); the eraser's own release is not announced.
  stopReleaseListener = onConversationRunReleased((dirId) => {
    const pending = pendingConversationForDir(dirId);
    if (pending) setImmediate(() => void eraseOwnedConversation(pending.label, pending.clientId).catch(() => undefined));
  });
  sweepTimer = setInterval(() => void runErasureSweep(), options.retryMs ?? loadErasureRetryMs());
  sweepTimer.unref();
  return runErasureSweep();
}

export function stopErasureSweeper(): void {
  if (sweepTimer) clearInterval(sweepTimer);
  sweepTimer = null;
  stopReleaseListener?.();
  stopReleaseListener = null;
}
