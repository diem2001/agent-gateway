import { randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

/* ------------------------------------------------------------------ */
/*  Types                                                               */
/* ------------------------------------------------------------------ */

export type PersistenceArea = "sessions" | "tools" | "mcpServers";

export type PersistenceProblem =
  | "corrupt-preserved"
  | "unreadable-not-preserved"
  | "write-failed";

/** One entry of `persistenceIssues` in GET /health. */
export interface PersistenceIssue {
  area: PersistenceArea;
  problem: PersistenceProblem;
  file: string;
  preservedAs?: string[];
}

export interface PersistenceReport {
  persistence: "ok" | "degraded";
  persistenceIssues: PersistenceIssue[];
}

/* ------------------------------------------------------------------ */
/*  ERROR lines                                                         */
/* ------------------------------------------------------------------ */

/**
 * One searchable ERROR line, written regardless of the /v1/logging level:
 * `ERROR persistence area=… problem=… file=… [preservedAs=…] reason=… [code=…] (see /health)`.
 * `reason` is always a fixed text and `code` an errno name. Never pass an
 * error message or file content: a JSON.parse message quotes part of the
 * input, and mcp-servers.json holds MCP credentials.
 */
export function logPersistenceError(fields: {
  area: PersistenceArea;
  problem: PersistenceProblem | "final-save-failed";
  file: string;
  preservedAs?: string;
  reason: string;
  code?: string;
}): void {
  const parts = [
    "ERROR persistence",
    `area=${fields.area}`,
    `problem=${fields.problem}`,
    `file=${fields.file}`,
  ];
  if (fields.preservedAs) parts.push(`preservedAs=${fields.preservedAs}`);
  parts.push(`reason=${fields.reason}`);
  if (fields.code) parts.push(`code=${fields.code}`);
  parts.push("(see /health)");
  console.error(parts.join(" "));
}

/** The errno name of an error (`EACCES`, `ENOSPC`, …), never its message. */
export function errnoCode(e: unknown): string | undefined {
  const code = (e as { code?: unknown } | null)?.code;
  return typeof code === "string" && /^[A-Z0-9_]+$/.test(code) ? code : undefined;
}

/* ------------------------------------------------------------------ */
/*  Atomic write                                                        */
/* ------------------------------------------------------------------ */

const DIR_FSYNC_UNSUPPORTED = new Set(["EISDIR", "EINVAL", "EPERM"]);

/**
 * Replace `file` with `content` so that a kill, crash or write error at any
 * point leaves either the complete old file or the complete new one.
 *
 * The temp file is created next to the target (same filesystem, so the rename
 * is atomic) with O_EXCL and mode 0600: it never follows a symlink, and a temp
 * file a kill leaves behind is never readable by anyone but the owner. Only
 * after the rename does the new file get the target's previous mode, through
 * the still-open descriptor. On any error before the rename the temp file is
 * removed and the target is untouched.
 */
export function atomicWriteFileSync(file: string, content: string): void {
  const dir = path.dirname(file);
  fs.mkdirSync(dir, { recursive: true });

  let mode: number;
  try {
    mode = fs.statSync(file).mode & 0o7777;
  } catch {
    mode = 0o666 & ~process.umask();
  }

  const temp = `${file}.tmp-${process.pid}-${randomBytes(6).toString("hex")}`;
  const fd = fs.openSync(temp, "wx", 0o600);
  try {
    fs.writeFileSync(fd, content);
    fs.fsyncSync(fd);
    fs.renameSync(temp, file);
  } catch (e) {
    try {
      fs.closeSync(fd);
    } catch {
      // already closed
    }
    try {
      fs.unlinkSync(temp);
    } catch {
      // nothing left to remove
    }
    throw e;
  }
  try {
    fs.fchmodSync(fd, mode);
  } finally {
    fs.closeSync(fd);
  }

  // Make the rename itself durable where the platform allows a directory fsync.
  try {
    const dirFd = fs.openSync(dir, "r");
    try {
      fs.fsyncSync(dirFd);
    } finally {
      fs.closeSync(dirFd);
    }
  } catch (e) {
    if (!DIR_FSYNC_UNSUPPORTED.has(errnoCode(e) ?? "")) throw e;
  }
}

/* ------------------------------------------------------------------ */
/*  Persistent store                                                    */
/* ------------------------------------------------------------------ */

function corruptStamp(date: Date): string {
  return date.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
}

export interface PersistentStoreOptions {
  area: PersistenceArea;
  /** State file path as configured (env or default). */
  file: string;
  /** The current in-memory state, serialized as `JSON.stringify(data, null, 2)`. */
  snapshot: () => unknown;
  /** Shape check for loaded data; false is handled like invalid JSON. */
  isValid: (data: unknown) => boolean;
}

/**
 * One state file: atomic, debounced saves, a load that never lets an
 * unreadable file be overwritten, and the issue state reported by /health.
 */
export class PersistentStore {
  readonly area: PersistenceArea;
  readonly file: string;
  private readonly snapshot: () => unknown;
  private readonly isValid: (data: unknown) => boolean;
  private timer: ReturnType<typeof setTimeout> | null = null;
  /** The file could not be read and could not be moved aside: never write it. */
  private suppressed = false;
  /** The most recent save failed; cleared by a later successful save. */
  private writeFailed = false;

  constructor(options: PersistentStoreOptions) {
    this.area = options.area;
    this.file = path.resolve(options.file);
    this.snapshot = options.snapshot;
    this.isValid = options.isValid;
  }

  /**
   * Read the state file. Returns the parsed data, or undefined for an empty
   * start: the file is missing, or it could not be read or parsed. An
   * unreadable file is moved aside to `<file>.corrupt-<UTC stamp>`; if that
   * fails, the file stays in place and every later save of this area is
   * suppressed for the lifetime of the process.
   */
  load(): unknown {
    this.suppressed = false;
    this.removeTempLeftovers();

    let raw: string;
    try {
      raw = fs.readFileSync(this.file, "utf-8");
    } catch (e) {
      if (errnoCode(e) === "ENOENT") return undefined;
      this.setAside("read error", errnoCode(e));
      return undefined;
    }

    let data: unknown;
    try {
      data = JSON.parse(raw);
    } catch {
      this.setAside("invalid JSON");
      return undefined;
    }
    if (!this.isValid(data)) {
      this.setAside("unexpected content");
      return undefined;
    }
    return data;
  }

  /** Debounced save (100 ms), as before. */
  schedule(): void {
    if (this.timer) return;
    this.timer = setTimeout(() => {
      this.timer = null;
      this.flush();
    }, 100);
  }

  /**
   * Save now, synchronously, cancelling a pending debounced save. Returns
   * false when the save failed or is suppressed for this area.
   */
  flush(): boolean {
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    if (this.suppressed) {
      logPersistenceError({
        area: this.area,
        problem: "unreadable-not-preserved",
        file: this.file,
        reason: "save suppressed, unreadable file was not moved aside",
      });
      return false;
    }
    try {
      atomicWriteFileSync(this.file, JSON.stringify(this.snapshot(), null, 2));
      this.writeFailed = false;
      return true;
    } catch (e) {
      this.writeFailed = true;
      logPersistenceError({
        area: this.area,
        problem: "write-failed",
        file: this.file,
        reason: "save failed, previous file kept",
        code: errnoCode(e),
      });
      return false;
    }
  }

  /** This area's outstanding problems; `corrupt-preserved` is read from disk each call. */
  issues(): PersistenceIssue[] {
    const issues: PersistenceIssue[] = [];
    const preserved = this.preservedCopies();
    if (preserved.length > 0) {
      issues.push({ area: this.area, problem: "corrupt-preserved", file: this.file, preservedAs: preserved });
    }
    if (this.suppressed) {
      issues.push({ area: this.area, problem: "unreadable-not-preserved", file: this.file });
    }
    if (this.writeFailed) {
      issues.push({ area: this.area, problem: "write-failed", file: this.file });
    }
    return issues;
  }

  private setAside(reason: string, code?: string): void {
    const stamp = corruptStamp(new Date());
    let target = `${this.file}.corrupt-${stamp}`;
    for (let n = 1; fs.existsSync(target); n++) {
      target = `${this.file}.corrupt-${stamp}-${n}`;
    }
    try {
      fs.renameSync(this.file, target);
    } catch (e) {
      this.suppressed = true;
      logPersistenceError({
        area: this.area,
        problem: "unreadable-not-preserved",
        file: this.file,
        reason: `${reason}, move aside failed, saves suppressed`,
        code: errnoCode(e) ?? code,
      });
      return;
    }
    logPersistenceError({
      area: this.area,
      problem: "corrupt-preserved",
      file: this.file,
      preservedAs: target,
      reason: `${reason}, starting empty`,
      code,
    });
  }

  private siblings(): string[] {
    try {
      return fs.readdirSync(path.dirname(this.file));
    } catch {
      return [];
    }
  }

  private preservedCopies(): string[] {
    const prefix = `${path.basename(this.file)}.corrupt-`;
    const dir = path.dirname(this.file);
    return this.siblings()
      .filter((name) => name.startsWith(prefix))
      .sort()
      .map((name) => path.join(dir, name));
  }

  /** Temp files a killed save left behind; only this area's, never a `.corrupt-*` copy. */
  private removeTempLeftovers(): void {
    const prefix = `${path.basename(this.file)}.tmp-`;
    const dir = path.dirname(this.file);
    for (const name of this.siblings()) {
      if (!name.startsWith(prefix)) continue;
      try {
        fs.unlinkSync(path.join(dir, name));
      } catch {
        // left for the next start
      }
    }
  }
}

/* ------------------------------------------------------------------ */
/*  Registry of the gateway's stores                                    */
/* ------------------------------------------------------------------ */

const AREA_ORDER: PersistenceArea[] = ["sessions", "tools", "mcpServers"];
const stores = new Map<PersistenceArea, PersistentStore>();

/** Create the store for an area and register it for /health and shutdown. */
export function createPersistentStore(options: PersistentStoreOptions): PersistentStore {
  const store = new PersistentStore(options);
  stores.set(store.area, store);
  return store;
}

export function registeredStores(): PersistentStore[] {
  return AREA_ORDER.map((area) => stores.get(area)).filter((s): s is PersistentStore => s !== undefined);
}

/** The two additive /health fields. */
export function persistenceReport(): PersistenceReport {
  const persistenceIssues = registeredStores().flatMap((store) => store.issues());
  return { persistence: persistenceIssues.length === 0 ? "ok" : "degraded", persistenceIssues };
}
