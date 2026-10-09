/**
 * Erasure of a deleted conversation (MVP-7402, session-erasure.ts, sessions.ts, query.ts): the erase helper on real
 * folders (deep trees, unreadable directories, links, special files, mount and type checks), the DELETE contract
 * (200 / 404 / 409 / 503) through the real route handler, the persisted erasure-pending entries and erased markers,
 * the admission refusal of a pending conversation, the log line rules and the persisted-field validation.
 * The agent run is mocked where a query is needed; the real-runtime rows are in session-erasure-process.test.ts.
 * Fixtures live under `/tmp/mvp7402-*` only and are removed by the code under test or by literal absolute path.
 */
import { execFileSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

type SessionsModule = typeof import("../sessions.js");
type ErasureModule = typeof import("../session-erasure.js");

const runQuery = vi.fn();
const roots: string[] = [];
const started: ErasureModule[] = [];
let tmp: string;
let root: string;
let logs: string[];
let errors: string[];

const A = { label: "reqlift", userId: "user-1" };
const B = { label: "diemai", userId: null };
const IMAGE_B64 = randomBytes(2048).toString("base64");

function makeRoot(): string {
  const dir = fs.mkdtempSync("/tmp/mvp7402-");
  fs.chmodSync(dir, 0o700);
  roots.push(dir);
  return dir;
}

beforeEach(() => {
  tmp = makeRoot();
  root = path.join(tmp, "store");
  fs.mkdirSync(path.join(root, "sessions"), { recursive: true, mode: 0o700 });
  fs.chmodSync(root, 0o700);
  fs.chmodSync(path.join(root, "sessions"), 0o700);
  process.env.AGENT_SANDBOX_ROOT = root;
  process.env.SESSION_PERSIST_PATH = path.join(tmp, "sessions.json");
  process.env.TOOLS_PERSIST_PATH = path.join(tmp, "tools.json");
  process.env.MCP_SERVERS_PERSIST_PATH = path.join(tmp, "mcp-servers.json");
  logs = [];
  errors = [];
  vi.spyOn(console, "log").mockImplementation((...args) => {
    logs.push(args.map(String).join(" "));
  });
  vi.spyOn(console, "error").mockImplementation((...args) => {
    errors.push(args.map(String).join(" "));
  });
  runQuery.mockReset();
  vi.resetModules();
});

afterEach(() => {
  for (const m of started.splice(0)) (m as Partial<ErasureModule>).stopErasureSweeper?.();
  vi.restoreAllMocks();
  for (const key of ["AGENT_SANDBOX_ROOT", "SESSION_PERSIST_PATH", "TOOLS_PERSIST_PATH", "MCP_SERVERS_PERSIST_PATH", "LOG_LEVEL"]) delete process.env[key];
  // Whatever a failed assertion left unreadable is made readable first, then the fixture root goes (literal /tmp/mvp7402-* roots only).
  for (const dir of roots.splice(0)) {
    try {
      execFileSync("/usr/bin/chmod", ["-R", "u+rwx", "--", dir], { stdio: "ignore" });
    } catch {
      // Nothing to repair.
    }
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

async function load(): Promise<{ sessions: SessionsModule; erasure: ErasureModule; sandbox: typeof import("../sandbox.js") }> {
  const sessions = await import("../sessions.js");
  const erasure = await import("../session-erasure.js");
  const sandbox = await import("../sandbox.js");
  started.push(erasure);
  return { sessions, erasure, sandbox };
}

async function rig(): Promise<{ app: express.Express; sessions: SessionsModule; erasure: ErasureModule; sandbox: typeof import("../sandbox.js") }> {
  const loaded = await load();
  const app = express();
  app.use((req, _res, next) => {
    req.clientLabel = (req.headers["x-test-label"] as string | undefined) ?? "reqlift";
    next();
  });
  app.delete("/v1/sessions/:id", loaded.erasure.deleteSessionRoute);
  return { app, ...loaded };
}

const del = (app: express.Express, id: string, label = "reqlift") => request(app).delete(`/v1/sessions/${encodeURIComponent(id)}`).set("x-test-label", label);

function folder(dirId: string): string {
  return path.join(root, "sessions", dirId);
}

/** A conversation folder with a transcript that holds a base64 image, a tool result and a work file. */
function makeFolder(dirId: string): void {
  const projects = path.join(folder(dirId), "home", ".claude", "projects", "-work");
  fs.mkdirSync(projects, { recursive: true });
  fs.mkdirSync(path.join(folder(dirId), "work"), { recursive: true });
  fs.writeFileSync(path.join(projects, "t.jsonl"), JSON.stringify({ type: "user", message: { content: [{ type: "image", source: { type: "base64", data: IMAGE_B64 } }] } }) + "\n");
  fs.writeFileSync(path.join(folder(dirId), "work", "note.txt"), "work area file\n");
}

function conversation(sessions: SessionsModule, caller: { label: string; userId: string | null }, id: string): string {
  const created = sessions.getSession(id, "sys", "model", true, caller);
  sessions.updateSessionSdkId(id, `sdk-${randomBytes(4).toString("hex")}`, caller.label);
  makeFolder(created.sandboxDirId!);
  return created.sandboxDirId!;
}

function readStore(): { sessions: Record<string, Record<string, unknown>>; sessionsByLabel: Record<string, Record<string, Record<string, unknown>>>; erasedByLabel?: Record<string, Record<string, Record<string, unknown>>> } {
  return JSON.parse(fs.readFileSync(process.env.SESSION_PERSIST_PATH!, "utf8"));
}

function sha(file: string): string {
  return createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

/** Every path below `dir` with its type and the SHA-256 of regular files; links are not followed. */
function snapshot(dir: string): string[] {
  const out: string[] = [];
  const walk = (p: string): void => {
    const st = fs.lstatSync(p);
    const rel = path.relative(dir, p) || ".";
    if (st.isSymbolicLink()) out.push(`${rel} -> ${fs.readlinkSync(p)}`);
    else if (st.isDirectory()) {
      out.push(`${rel}/ ${(st.mode & 0o777).toString(8)}`);
      for (const name of fs.readdirSync(p).sort()) walk(path.join(p, name));
    } else if (st.isFile()) out.push(`${rel} ${(st.mode & 0o777).toString(8)} ${sha(p)}`);
    else out.push(`${rel} special`);
  };
  walk(dir);
  return out;
}

const gone = (p: string): boolean => {
  try {
    fs.lstatSync(p);
    return false;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "ENOENT";
  }
};

/** Bytes of the image anywhere below `dir` (positive control: the search is live). */
function imageHits(dir: string): number {
  let hits = 0;
  const walk = (p: string): void => {
    const st = fs.lstatSync(p);
    if (st.isDirectory()) for (const name of fs.readdirSync(p)) walk(path.join(p, name));
    else if (st.isFile() && fs.readFileSync(p, "utf8").includes(IMAGE_B64)) hits++;
  };
  if (!gone(dir)) walk(dir);
  return hits;
}

describe("the erase helper (eraseConversationDir)", () => {
  it("removes the whole folder, transcripts and work area included, and reports success", async () => {
    const { erasure } = await load();
    const dirId = "0123456789abcdef01234567";
    makeFolder(dirId);
    expect(imageHits(folder(dirId))).toBe(1);
    expect(await erasure.eraseConversationDir(root, dirId)).toEqual({ ok: true });
    expect(gone(folder(dirId))).toBe(true);
    expect(imageHits(path.join(root, "sessions"))).toBe(0);
  });

  it("an absent folder below a valid sessions directory is success, and nothing is created", async () => {
    const { erasure } = await load();
    expect(await erasure.eraseConversationDir(root, "0123456789abcdef01234567")).toEqual({ ok: true });
    expect(fs.readdirSync(path.join(root, "sessions"))).toEqual([]);
  });

  it.each(["..", "../x", "0123456789ABCDEF01234567", "0123456789abcdef0123456", "0123456789abcdef012345678", "", "a/b"])("refuses the directory id %j without touching the file system", async (dirId) => {
    const { erasure } = await load();
    const before = snapshot(root);
    expect(await erasure.eraseConversationDir(root, dirId)).toEqual({ ok: false, code: "invalid_dir_id" });
    expect(snapshot(root)).toEqual(before);
  });

  it("S3: a missing sessions directory is never success, and nothing is created", async () => {
    const { erasure } = await load();
    fs.rmdirSync(path.join(root, "sessions"));
    expect(await erasure.eraseConversationDir(root, "0123456789abcdef01234567")).toEqual({ ok: false, code: "root_invalid" });
    expect(gone(path.join(root, "sessions"))).toBe(true);
  });

  it("S3: a sessions directory that is a link is never followed, its target is untouched", async () => {
    const { erasure } = await load();
    const real = path.join(tmp, "elsewhere");
    const dirId = "0123456789abcdef01234567";
    fs.mkdirSync(real, { mode: 0o700 });
    fs.mkdirSync(path.join(real, dirId));
    fs.writeFileSync(path.join(real, dirId, "keep.txt"), "keep");
    fs.rmdirSync(path.join(root, "sessions"));
    fs.symlinkSync(real, path.join(root, "sessions"));
    const before = snapshot(real);
    expect(await erasure.eraseConversationDir(root, dirId)).toEqual({ ok: false, code: "root_invalid" });
    expect(snapshot(real)).toEqual(before);
  });

  it("S3: a root with a link in its path, a root that is not private and a sessions directory that is group-writable are root_invalid", async () => {
    const { erasure } = await load();
    const dirId = "0123456789abcdef01234567";
    makeFolder(dirId);
    const viaLink = path.join(tmp, "link-to-store");
    fs.symlinkSync(root, viaLink);
    expect(await erasure.eraseConversationDir(viaLink, dirId)).toEqual({ ok: false, code: "root_invalid" });
    fs.chmodSync(path.join(root, "sessions"), 0o770);
    expect(await erasure.eraseConversationDir(root, dirId)).toEqual({ ok: false, code: "root_invalid" });
    fs.chmodSync(path.join(root, "sessions"), 0o700);
    fs.chmodSync(root, 0o777);
    expect(await erasure.eraseConversationDir(root, dirId)).toEqual({ ok: false, code: "root_invalid" });
    expect(fs.existsSync(folder(dirId))).toBe(true);
  });

  it("a link or a regular file at the folder's place is unexpected_type: never followed, never removed", async () => {
    const { erasure } = await load();
    const target = path.join(tmp, "target");
    fs.mkdirSync(target, { mode: 0o700 });
    fs.writeFileSync(path.join(target, "f"), "x");
    const linkId = "aaaaaaaaaaaaaaaaaaaaaaaa";
    const fileId = "bbbbbbbbbbbbbbbbbbbbbbbb";
    fs.symlinkSync(target, folder(linkId));
    fs.writeFileSync(folder(fileId), "not a folder");
    const before = snapshot(target);
    expect(await erasure.eraseConversationDir(root, linkId)).toEqual({ ok: false, code: "unexpected_type" });
    expect(await erasure.eraseConversationDir(root, fileId)).toEqual({ ok: false, code: "unexpected_type" });
    expect(snapshot(target)).toEqual(before);
    expect(fs.lstatSync(folder(linkId)).isSymbolicLink()).toBe(true);
    expect(fs.readFileSync(folder(fileId), "utf8")).toBe("not a folder");
  });

  it("S4: links inside the folder are removed, their targets (a 0500 directory, a 0400 file, a sibling folder, the sessions directory) keep content and mode", async () => {
    const { erasure } = await load();
    const dirId = "0123456789abcdef01234567";
    const orphan = "ffffffffffffffffffffffff";
    makeFolder(dirId);
    makeFolder(orphan);
    const outside = path.join(tmp, "outside");
    fs.mkdirSync(path.join(outside, "dir"), { recursive: true });
    fs.writeFileSync(path.join(outside, "dir", "inner.txt"), "inner");
    fs.writeFileSync(path.join(outside, "file.txt"), "outside file");
    fs.chmodSync(path.join(outside, "file.txt"), 0o400);
    fs.chmodSync(path.join(outside, "dir"), 0o500);
    const work = path.join(folder(dirId), "work");
    fs.symlinkSync(path.join(outside, "dir"), path.join(work, "to-dir"));
    fs.symlinkSync(path.join(outside, "file.txt"), path.join(work, "to-file"));
    fs.symlinkSync(folder(orphan), path.join(work, "to-sibling"));
    fs.symlinkSync(path.join(root, "sessions"), path.join(work, "to-sessions"));
    fs.symlinkSync("/nonexistent/dangling", path.join(work, "dangling"));
    const beforeOutside = snapshot(outside);
    const beforeOrphan = snapshot(folder(orphan));
    expect(await erasure.eraseConversationDir(root, dirId)).toEqual({ ok: true });
    expect(gone(folder(dirId))).toBe(true);
    expect(snapshot(outside)).toEqual(beforeOutside);
    expect(snapshot(folder(orphan))).toEqual(beforeOrphan);
    // The mode check is part of the snapshot ("dir/ 500", "file.txt 400"); restore for the cleanup.
    expect(beforeOutside.some((l) => l.startsWith("dir/ 500"))).toBe(true);
    expect(beforeOutside.some((l) => l.startsWith("file.txt 400"))).toBe(true);
  });

  it("S4: a FIFO, a socket and a hard-link pair inside are removed, and an unreadable nested tree does not stop the removal", async () => {
    const { erasure } = await load();
    const dirId = "0123456789abcdef01234567";
    makeFolder(dirId);
    const work = path.join(folder(dirId), "work");
    execFileSync("/usr/bin/mkfifo", [path.join(work, "pipe")]);
    const server = net.createServer();
    await new Promise<void>((resolve) => server.listen(path.join(work, "s.sock"), resolve));
    server.close();
    fs.writeFileSync(path.join(work, "one"), "linked");
    fs.linkSync(path.join(work, "one"), path.join(work, "two"));
    fs.mkdirSync(path.join(work, "locked", "inner", "deepest"), { recursive: true });
    fs.writeFileSync(path.join(work, "locked", "inner", "deepest", "secret"), "s");
    fs.chmodSync(path.join(work, "locked", "inner", "deepest"), 0o000);
    fs.chmodSync(path.join(work, "locked", "inner"), 0o500);
    fs.chmodSync(path.join(work, "locked"), 0o000);
    expect(await erasure.eraseConversationDir(root, dirId)).toEqual({ ok: true });
    expect(gone(folder(dirId))).toBe(true);
  });

  it("S2: a tree deeper than PATH_MAX with a 0000 directory at the bottom is removed", async () => {
    const { erasure } = await load();
    const dirId = "0123456789abcdef01234567";
    makeFolder(dirId);
    const work = path.join(folder(dirId), "work");
    // 30 levels of 200 characters: far above PATH_MAX (4096), built one relative step at a time.
    execFileSync("/bin/bash", ["-c", `cd "$1" && for i in $(seq 1 30); do n=$(printf 'd%.0s' $(seq 1 200)); mkdir "$n" && cd "$n"; done; echo deep > file.txt; mkdir bottom; echo b > bottom/f; chmod 000 bottom`, "bash", work]);
    let probe = work;
    const level = "d".repeat(200);
    for (let i = 0; i < 22; i++) probe = path.join(probe, level);
    expect(probe.length).toBeGreaterThan(4096);
    expect(() => fs.lstatSync(probe)).toThrow(/ENAMETOOLONG/);
    expect(await erasure.eraseConversationDir(root, dirId)).toEqual({ ok: true });
    expect(gone(folder(dirId))).toBe(true);
  });

  it("S4: a mount below the folder is never crossed: the removal refuses before any tool runs, and the mounted directory keeps content and mode", async () => {
    const dirId = "0123456789abcdef01234567";
    makeFolder(dirId);
    const outside = path.join(tmp, "mounted-outside");
    fs.mkdirSync(outside, { mode: 0o700 });
    fs.writeFileSync(path.join(outside, "canary.txt"), "canary");
    fs.chmodSync(path.join(outside, "canary.txt"), 0o400);
    fs.mkdirSync(path.join(folder(dirId), "work", "m"));
    const before = snapshot(outside);
    // A user and mount namespace of its own: the bind mount exists only inside it (no privilege needed).
    const script = `mount --bind "$1" "$2" && exec "$3" --eval 'import("${path.resolve("src/session-erasure.ts")}").then(async (m) => { console.log(JSON.stringify(await m.eraseConversationDir(process.argv[1], process.argv[2]))); })' "$4" "$5"`;
    let out: string;
    try {
      out = execFileSync("/usr/bin/unshare", ["-Urm", "/bin/sh", "-c", script, "sh", outside, path.join(folder(dirId), "work", "m"), path.resolve("node_modules/.bin/tsx"), root, dirId], { encoding: "utf8", env: { ...process.env, AGENT_SANDBOX_ROOT: root } });
    } catch (e) {
      throw new Error(`host prerequisite missing: user and mount namespaces for the mount row (${(e as Error).message.split("\n")[0]})`);
    }
    expect(JSON.parse(out.trim().split("\n").at(-1)!)).toEqual({ ok: false, code: "mount_boundary" });
    expect(snapshot(outside)).toEqual(before);
    expect(fs.existsSync(folder(dirId))).toBe(true);
  });

  it("a failing removal reports a fixed code, never a path or a message", async () => {
    const { erasure } = await load();
    const dirId = "0123456789abcdef01234567";
    makeFolder(dirId);
    fs.chmodSync(path.join(root, "sessions"), 0o500);
    const result = await erasure.eraseConversationDir(root, dirId);
    fs.chmodSync(path.join(root, "sessions"), 0o700);
    expect(result).toEqual({ ok: false, code: "rm_failed" });
    expect(await erasure.eraseConversationDir(root, dirId)).toEqual({ ok: true });
    expect(gone(folder(dirId))).toBe(true);
  });
});

describe("DELETE /v1/sessions/:id (the contract table)", () => {
  it("the owner's delete answers 200, removes entry and folder, leaves a content-free marker, and every repeat answers 200", async () => {
    const { app, sessions } = await rig();
    const dirId = conversation(sessions, A, "c1");
    expect(imageHits(folder(dirId))).toBe(1);
    const first = await del(app, "c1");
    expect(first.status).toBe(200);
    expect(first.body).toEqual({ deleted: true });
    expect(gone(folder(dirId))).toBe(true);
    expect(imageHits(path.join(root, "sessions"))).toBe(0);
    expect(sessions.getSessionCount()).toBe(0);
    expect(sessions.listSessions("reqlift")).toEqual([]);
    const saved = readStore();
    expect(saved.sessionsByLabel.reqlift?.c1).toBeUndefined();
    expect(Object.keys(saved.erasedByLabel!.reqlift.c1)).toEqual(["erasedAt"]);
    expect(typeof saved.erasedByLabel!.reqlift.c1.erasedAt).toBe("number");
    expect(JSON.stringify(saved)).not.toContain(dirId);
    for (let n = 0; n < 2; n++) {
      const again = await del(app, "c1");
      expect([again.status, again.body]).toEqual([200, { deleted: true }]);
    }
  });

  it("a restart keeps the marker: the owner's late retry still answers 200, another label and a never-used id answer 404", async () => {
    const first = await rig();
    conversation(first.sessions, A, "c1");
    expect((await del(first.app, "c1")).status).toBe(200);
    expect(first.sessions.flushSessions()).toBe(true);
    vi.resetModules();
    const second = await rig();
    second.sessions.loadSessions();
    const again = await del(second.app, "c1");
    expect([again.status, again.body]).toEqual([200, { deleted: true }]);
    for (const [id, label] of [["c1", "diemai"], ["never-used", "reqlift"]] as const) {
      const res = await del(second.app, id, label);
      expect([res.status, res.body]).toEqual([404, { error: "Session not found" }]);
    }
  });

  it("an erased id is new again: the next conversation drops the marker, gets a new empty folder, and a later delete erases that one", async () => {
    const { app, sessions } = await rig();
    const old = conversation(sessions, A, "c1");
    await del(app, "c1");
    expect(sessions.admitSession("c1", A)).toEqual({ kind: "new" });
    const fresh = sessions.getSession("c1", "sys", "model", true, A);
    expect(fresh.isNew).toBe(true);
    expect(fresh.sandboxDirId).not.toBe(old);
    sessions.flushSessions();
    expect(readStore().erasedByLabel?.reqlift?.c1).toBeUndefined();
    expect(gone(folder(old))).toBe(true);
    makeFolder(fresh.sandboxDirId!);
    expect((await del(app, "c1")).status).toBe(200);
    expect(gone(folder(fresh.sandboxDirId!))).toBe(true);
  });

  it.each([
    ["label B", "c1", "diemai"],
    ["label A, an id with no entry", "no-such-id", "reqlift"],
    ["label A, `..`", "..", "reqlift"],
    ["label A, an encoded path", "..%2F..%2Fetc", "reqlift"],
    ["label A, an absolute path", "/etc/passwd", "reqlift"],
  ])("only the owner erases: %s answers 404 and leaves C and the orphan O unchanged", async (_name, id, label) => {
    const { app, sessions } = await rig();
    const dirId = conversation(sessions, A, "c1");
    const orphan = "eeeeeeeeeeeeeeeeeeeeeeee";
    makeFolder(orphan);
    sessions.flushSessions();
    const entryBefore = readStore().sessionsByLabel.reqlift.c1;
    const folderBefore = snapshot(folder(dirId));
    const orphanBefore = snapshot(folder(orphan));
    // An HTTP client normalizes `..` away before it is sent, so that id goes straight to the route's decision.
    if (id === "..") expect(await (await import("../session-erasure.js")).deleteConversation(id, label)).toBe("not_found");
    else {
      const res = await del(app, id, label);
      expect([res.status, res.body]).toEqual([404, { error: "Session not found" }]);
    }
    sessions.flushSessions();
    expect(readStore().sessionsByLabel.reqlift.c1).toEqual(entryBefore);
    expect(snapshot(folder(dirId))).toEqual(folderBefore);
    expect(snapshot(folder(orphan))).toEqual(orphanBefore);
  });

  it.each([["A", "reqlift"], ["B", "diemai"]])("a legacy entry answers 409 legacy_not_erased for label %s, twice; entry, old store, C and its folder are unchanged", async (_name, label) => {
    fs.writeFileSync(
      process.env.SESSION_PERSIST_PATH!,
      JSON.stringify({ sessions: { P: { sessionId: "gw", sdkSessionId: "sdk-old", systemPrompt: "", model: "m", lastUsed: Date.now() } }, settings: { sessionIdleTimeoutMs: 0 } }),
    );
    const oldStore = path.join(tmp, "old-shared-store");
    fs.mkdirSync(oldStore, { mode: 0o700 });
    fs.writeFileSync(path.join(oldStore, "T.jsonl"), "legacy transcript");
    const { app, sessions } = await rig();
    sessions.loadSessions();
    const dirId = conversation(sessions, A, "C");
    const storeBefore = snapshot(oldStore);
    const folderBefore = snapshot(folder(dirId));
    for (let n = 0; n < 2; n++) {
      const res = await del(app, "P", label);
      expect([res.status, res.body]).toEqual([409, { error: "legacy_not_erased" }]);
    }
    expect(snapshot(oldStore)).toEqual(storeBefore);
    expect(snapshot(folder(dirId))).toEqual(folderBefore);
    expect(sessions.admitSession("P", A)).toEqual({ kind: "refused", reason: "legacy" });
    expect(sessions.admitSession("C", A).kind).toBe("resume");
    sessions.flushSessions();
    expect(readStore().sessions.P).toBeDefined();
  });

  it("a run that holds the conversation answers 503 erasure_pending, keeps the entry as a persisted tombstone and the folder", async () => {
    const { app, sessions, sandbox } = await rig();
    const dirId = conversation(sessions, A, "c1");
    const lock = sandbox.tryLockConversation(dirId)!;
    const res = await del(app, "c1");
    expect([res.status, res.body]).toEqual([503, { error: "erasure_pending" }]);
    expect(fs.existsSync(folder(dirId))).toBe(true);
    const saved = readStore();
    expect(typeof saved.sessionsByLabel.reqlift.c1.erasePendingSince).toBe("number");
    expect(saved.sessionsByLabel.reqlift.c1.sandboxDirId).toBe(dirId);
    // A pending conversation is blocked, hidden from the list and the live count, and still counted as pending.
    expect(sessions.admitSession("c1", A)).toEqual({ kind: "refused", reason: "erasing" });
    expect(sessions.listSessions("reqlift")).toEqual([]);
    expect(sessions.getSessionCount()).toBe(0);
    expect(sessions.erasurePendingCount()).toBe(1);
    // The caller's repeat completes the erasure once the run is over.
    lock.release();
    const again = await del(app, "c1");
    expect([again.status, again.body]).toEqual([200, { deleted: true }]);
    expect(gone(folder(dirId))).toBe(true);
    expect(sessions.erasurePendingCount()).toBe(0);
  });

  it("a file system error answers 503 with one warning (id and code only), the entry stays pending, and a repeat after the error is gone answers 200", async () => {
    const { app, sessions } = await rig();
    const dirId = conversation(sessions, A, "c1");
    fs.chmodSync(path.join(root, "sessions"), 0o500);
    const res = await del(app, "c1");
    fs.chmodSync(path.join(root, "sessions"), 0o700);
    expect([res.status, res.body]).toEqual([503, { error: "erasure_pending" }]);
    expect(sessions.admitSession("c1", A)).toEqual({ kind: "refused", reason: "erasing" });
    const warnings = logs.filter((l) => l.includes("sessions.erasure.failed"));
    expect(warnings).toEqual(['[sessions] sessions.erasure.failed id="c1" code=rm_failed']);
    const again = await del(app, "c1");
    expect([again.status, again.body]).toEqual([200, { deleted: true }]);
    expect(gone(folder(dirId))).toBe(true);
  });

  it("S10: two entries that share one directory id: the delete answers 503, folder and the other entry are unchanged", async () => {
    const dirId = "0123456789abcdef01234567";
    const entry = (label: string) => ({ sessionId: "gw", sdkSessionId: "sdk", systemPrompt: "", model: "m", lastUsed: Date.now(), owner: { label, userId: null }, sandboxDirId: dirId });
    fs.writeFileSync(process.env.SESSION_PERSIST_PATH!, JSON.stringify({ sessions: {}, sessionsByLabel: { reqlift: { c1: entry("reqlift") }, diemai: { c9: entry("diemai") } }, settings: { sessionIdleTimeoutMs: 0 } }));
    const { app, sessions } = await rig();
    sessions.loadSessions();
    makeFolder(dirId);
    const before = snapshot(folder(dirId));
    const res = await del(app, "c1");
    expect([res.status, res.body]).toEqual([503, { error: "erasure_pending" }]);
    expect(snapshot(folder(dirId))).toEqual(before);
    expect(sessions.admitSession("c9", B).kind).toBe("resume");
    expect(logs.filter((l) => l.includes("sessions.erasure.failed"))).toEqual(['[sessions] sessions.erasure.failed id="c1" code=dir_shared']);
  });

  it("S8: the ids __proto__, constructor and a 10 kB id are erased like any other: 200 twice, and the file stays valid after a restart", async () => {
    const first = await rig();
    const ids = ["__proto__", "constructor", "x".repeat(10_000)];
    for (const id of ids) conversation(first.sessions, A, id);
    for (const id of ids) {
      for (let n = 0; n < 2; n++) expect((await del(first.app, id)).status, id.slice(0, 20)).toBe(200);
    }
    expect(first.sessions.flushSessions()).toBe(true);
    vi.resetModules();
    const second = await rig();
    second.sessions.loadSessions();
    expect(fs.readdirSync(tmp).some((f) => f.startsWith("sessions.json.corrupt"))).toBe(false);
    for (const id of ids) expect((await del(second.app, id)).status, id.slice(0, 20)).toBe(200);
    expect(({} as Record<string, unknown>).erasedAt).toBeUndefined();
  });
});

describe("log lines carry the conversation id escaped and bounded (S6)", () => {
  it.each([[undefined], ["info"]])("a hostile id gives one escaped, bounded erasure line (LOG_LEVEL %s)", async (level) => {
    if (level) process.env.LOG_LEVEL = level;
    const { app, sessions } = await rig();
    const hostile = ["c\n[audit] x forged line", "y".repeat(10_000)];
    for (const id of hostile) conversation(sessions, A, id);
    fs.chmodSync(path.join(root, "sessions"), 0o500);
    for (const id of hostile) expect((await del(app, id)).status).toBe(503);
    fs.chmodSync(path.join(root, "sessions"), 0o700);
    for (const id of hostile) expect((await del(app, id)).status).toBe(200);
    // No log message of this run contains a line break followed by a forged prefix, and none is longer than a bounded line.
    const lines = logs.join("\n").split("\n");
    expect(lines.filter((l) => l.startsWith("[audit] x"))).toEqual([]);
    expect(logs.filter((l) => l.includes("[audit] x")).every((l) => !l.includes("\n"))).toBe(true);
    const failed = logs.filter((l) => l.includes("sessions.erasure.failed"));
    expect(failed).toHaveLength(2);
    expect(failed[0]).toBe('[sessions] sessions.erasure.failed id="c\\n[audit] x forged line" code=rm_failed');
    for (const l of logs.filter((m) => m.includes("sessions.erasure"))) expect(l.length).toBeLessThan(400);
    expect(failed[1]).toBe(`[sessions] sessions.erasure.failed id="${"y".repeat(128)}" code=rm_failed`);
  });
});

describe("persisted fields (additive, validated at load)", () => {
  const now = Date.now();
  const dirId = "0123456789abcdef01234567";
  const entry = (extra: Record<string, unknown> = {}) => ({ sessionId: "gw", sdkSessionId: "sdk", systemPrompt: "", model: "m", lastUsed: now, owner: { label: "reqlift", userId: null }, sandboxDirId: dirId, ...extra });

  it("a valid pending entry and valid markers load; the pending one is blocked and counted, the markers answer 200 to their label", async () => {
    fs.writeFileSync(
      process.env.SESSION_PERSIST_PATH!,
      JSON.stringify({ sessions: {}, sessionsByLabel: { reqlift: { c1: entry({ erasePendingSince: now }) } }, erasedByLabel: { reqlift: { gone1: { erasedAt: now } }, diemai: { gone2: { erasedAt: now } } }, settings: { sessionIdleTimeoutMs: 0 } }),
    );
    const { app, sessions } = await rig();
    sessions.loadSessions();
    expect(fs.readdirSync(tmp).some((f) => f.startsWith("sessions.json.corrupt"))).toBe(false);
    expect(sessions.admitSession("c1", A)).toEqual({ kind: "refused", reason: "erasing" });
    expect(sessions.erasurePendingCount()).toBe(1);
    expect((await del(app, "gone1")).status).toBe(200);
    expect((await del(app, "gone2")).status).toBe(404);
    expect((await del(app, "gone2", "diemai")).status).toBe(200);
  });

  it.each([
    ["erasedAt is not a number", { erasedByLabel: { reqlift: { c1: { erasedAt: "yesterday" } } } }],
    ["a marker under an empty label", { erasedByLabel: { "": { c1: { erasedAt: now } } } }],
    ["a marker that carries a directory id", { erasedByLabel: { reqlift: { c1: { erasedAt: now, sandboxDirId: dirId } } } }],
    ["a label map that is not an object", { erasedByLabel: { reqlift: [] } }],
    ["erasedByLabel that is not an object", { erasedByLabel: [] }],
    ["erasePendingSince that is not a number", { sessionsByLabel: { reqlift: { c1: entry({ erasePendingSince: "now" }) } } }],
    ["erasePendingSince on a legacy entry", { sessions: { old: { sessionId: "gw", systemPrompt: "", model: "m", lastUsed: now, erasePendingSince: now } } }],
  ])("%s sets the whole file aside instead of loading it", async (_name, extra) => {
    fs.writeFileSync(process.env.SESSION_PERSIST_PATH!, JSON.stringify({ sessions: {}, settings: { sessionIdleTimeoutMs: 0 }, ...extra }));
    const { sessions } = await load();
    sessions.loadSessions();
    expect(sessions.getSessionCount()).toBe(0);
    expect(fs.readdirSync(tmp).some((f) => f.startsWith("sessions.json.corrupt"))).toBe(true);
  });
});

describe("the query route refuses a pending conversation before any run", () => {
  it("answers one fixed session_erasing error event, starts no run, and leaves the legacy text unchanged", async () => {
    vi.doMock("../agent.js", () => ({ runQuery: (...args: unknown[]) => runQuery(...args), DEFAULT_TOOLS: [] }));
    const { sessions, sandbox, erasure } = await load();
    const failure = await import("../run-failure.js");
    const { queryRouter } = await import("../query.js");
    const server = express();
    server.use(express.json());
    server.use((req, _res, next) => {
      req.clientLabel = "reqlift";
      next();
    });
    server.use(queryRouter);
    const dirId = conversation(sessions, A, "c1");
    // The run's lock stays held: the conversation is pending and the query is refused at admission.
    expect(sandbox.tryLockConversation(dirId)).not.toBeNull();
    expect(await erasure.deleteConversation("c1", "reqlift")).toBe("pending");
    const res = await request(server).post("/v1/query").send({ model: "m", prompt: "hi", queryId: "q1", sessionId: "c1" });
    const events = res.text.split("\n").filter((l) => l.startsWith("{")).map((l) => JSON.parse(l) as { type: string; content?: string });
    expect(events).toEqual([{ seq: 0, type: "error", content: failure.SESSION_ERASING_MESSAGE }]);
    expect(runQuery).not.toHaveBeenCalled();
    expect(failure.SESSION_ERASING_MESSAGE).toBe("This conversation is being deleted. Its content is erased as soon as the gateway can finish, so it cannot be used any more. Please start a new conversation.");
    expect(failure.SESSION_ERASING_MESSAGE).not.toBe(failure.SESSION_LEGACY_MESSAGE);
    expect(failure.SESSION_ERASING_MESSAGE).not.toBe(failure.SESSION_BUSY_MESSAGE);
  });
});

/* ------------------------------------------------------------------ */
/*  Gate B: gateway-driven completion                                   */
/* ------------------------------------------------------------------ */

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));
const failedLines = (): string[] => logs.filter((l) => l.includes("sessions.erasure.failed"));

describe("the gateway finishes a pending erasure itself", () => {
  it("S1: the run's release triggers the erasure; the eraser's own release does not: a persistent error gives one attempt, not a loop", async () => {
    const { app, sessions, erasure, sandbox } = await rig();
    await erasure.startErasureSweeper({ retryMs: 60_000 });
    const dirId = conversation(sessions, A, "c1");
    // A run holds the conversation: 503, no attempt and no warning while it runs.
    const lock = sandbox.tryLockConversation(dirId)!;
    expect((await del(app, "c1")).status).toBe(503);
    expect(failedLines()).toEqual([]);
    // The file system is in error when the run releases: exactly one attempt follows, from the run's release.
    fs.chmodSync(path.join(root, "sessions"), 0o500);
    lock.release();
    await vi.waitFor(() => expect(failedLines()).toHaveLength(1));
    // The eraser took and released the same lock on the way: nothing re-triggers it, whatever the time.
    await sleep(1500);
    expect(failedLines()).toHaveLength(1);
    fs.chmodSync(path.join(root, "sessions"), 0o700);
    expect(sessions.erasurePendingCount()).toBe(1);
    expect(fs.existsSync(folder(dirId))).toBe(true);
  });

  it("a run's release finishes a pending erasure with no further request and far inside the sweep interval", async () => {
    const { app, sessions, erasure, sandbox } = await rig();
    await erasure.startErasureSweeper({ retryMs: 60_000 });
    const dirId = conversation(sessions, A, "c1");
    const orphan = "eeeeeeeeeeeeeeeeeeeeeeee";
    makeFolder(orphan);
    const other = conversation(sessions, B, "c1");
    const orphanBefore = snapshot(folder(orphan));
    const otherBefore = snapshot(folder(other));
    const lock = sandbox.tryLockConversation(dirId)!;
    expect((await del(app, "c1")).status).toBe(503);
    expect(fs.existsSync(folder(dirId))).toBe(true);
    lock.release();
    await vi.waitFor(() => expect(sessions.erasurePendingCount()).toBe(0));
    expect(gone(folder(dirId))).toBe(true);
    // The late retry answers: A 200 (twice), B 404 for the id it never used, a never-used id 404.
    for (let n = 0; n < 2; n++) expect((await del(app, "c1")).body).toEqual({ deleted: true });
    expect(sessions.admitSession("c1", B).kind).toBe("resume");
    expect(snapshot(folder(orphan))).toEqual(orphanBefore);
    expect(snapshot(folder(other))).toEqual(otherBefore);
    expect((await del(app, "never-used")).status).toBe(404);
  });

  it("the sweep finishes a pending erasure after a file system error is gone, without any request and with the idle timeout 0", async () => {
    const { app, sessions, erasure } = await rig();
    const dirId = conversation(sessions, A, "c1");
    fs.chmodSync(path.join(root, "sessions"), 0o500);
    expect((await del(app, "c1")).status).toBe(503);
    expect(sessions.getSettings().sessionIdleTimeoutMs).toBe(0);
    await erasure.startErasureSweeper({ retryMs: 100 });
    await sleep(350);
    expect(sessions.erasurePendingCount()).toBe(1);
    fs.chmodSync(path.join(root, "sessions"), 0o700);
    await vi.waitFor(() => expect(sessions.erasurePendingCount()).toBe(0), { timeout: 3000 });
    expect(gone(folder(dirId))).toBe(true);
    expect(sessions.admitSession("c1", A)).toEqual({ kind: "new" });
    expect((await del(app, "c1")).status).toBe(200);
  });

  it("a restart while pending: the tombstone survives, blocks the conversation, and the startup sweep erases it", async () => {
    const first = await rig();
    const dirId = conversation(first.sessions, A, "c1");
    const lock = first.sandbox.tryLockConversation(dirId)!;
    expect((await del(first.app, "c1")).status).toBe(503);
    expect(first.sessions.flushSessions()).toBe(true);
    lock.release();
    vi.resetModules();
    const second = await rig();
    second.sessions.loadSessions();
    expect(second.sessions.admitSession("c1", A)).toEqual({ kind: "refused", reason: "erasing" });
    expect(second.sessions.erasurePendingCount()).toBe(1);
    await second.erasure.startErasureSweeper({ retryMs: 60_000 });
    expect(second.sessions.erasurePendingCount()).toBe(0);
    expect(gone(folder(dirId))).toBe(true);
    const again = await del(second.app, "c1");
    expect([again.status, again.body]).toEqual([200, { deleted: true }]);
    // And after one more restart the marker still answers.
    expect(second.sessions.flushSessions()).toBe(true);
    vi.resetModules();
    const third = await rig();
    third.sessions.loadSessions();
    expect((await del(third.app, "c1")).status).toBe(200);
    expect((await del(third.app, "c1", "diemai")).status).toBe(404);
  });

  it("an error plus a restart: the startup sweep retries and the entry stays pending while the error lasts", async () => {
    const first = await rig();
    const dirId = conversation(first.sessions, A, "c1");
    fs.chmodSync(path.join(root, "sessions"), 0o500);
    expect((await del(first.app, "c1")).status).toBe(503);
    expect(first.sessions.flushSessions()).toBe(true);
    vi.resetModules();
    const second = await rig();
    second.sessions.loadSessions();
    await second.erasure.startErasureSweeper({ retryMs: 60_000 });
    expect(second.sessions.erasurePendingCount()).toBe(1);
    expect(failedLines().length).toBeGreaterThanOrEqual(2);
    fs.chmodSync(path.join(root, "sessions"), 0o700);
    await second.erasure.runErasureSweep();
    expect(second.sessions.erasurePendingCount()).toBe(0);
    expect(gone(folder(dirId))).toBe(true);
  });

  it("S4: a lock held until a deadline stop's exit is observed: DELETE answers 503 and makes no attempt until the hold resolves, then the folder is gone", async () => {
    vi.doMock("../agent.js", () => ({ runQuery: (...args: unknown[]) => runQuery(...args), DEFAULT_TOOLS: [] }));
    const { sessions, erasure } = await load();
    await erasure.startErasureSweeper({ retryMs: 60_000 });
    const { queryRouter } = await import("../query.js");
    const server = express();
    server.use(express.json());
    server.use((req, _res, next) => {
      req.clientLabel = "reqlift";
      next();
    });
    server.use(queryRouter);
    server.delete("/v1/sessions/:id", erasure.deleteSessionRoute);
    let releaseHold: () => void = () => undefined;
    const hold = new Promise<void>((resolve) => (releaseHold = resolve));
    let dirId = "";
    runQuery.mockImplementationOnce(async (options: { sandboxDirId?: string; holdConversation?: (until: Promise<unknown>) => void }) => {
      dirId = options.sandboxDirId!;
      makeFolder(dirId);
      options.holdConversation?.(hold);
      return { response: "answer", resultData: { session_id: "sdk-1", usage: {}, modelUsage: {} } };
    });
    const attempts = vi.fn();
    erasure.erasureSeams.remove = async (r, d) => {
      attempts();
      return erasure.eraseConversationDir(r, d);
    };
    const res = await request(server).post("/v1/query").send({ model: "m", prompt: "hi", queryId: "q1", sessionId: "c1" });
    expect(res.text).toContain('"type":"done"');
    // The request is over, but the sandbox exit was not observed: the conversation stays locked.
    const first = await request(server).delete("/v1/sessions/c1");
    expect([first.status, first.body]).toEqual([503, { error: "erasure_pending" }]);
    await sleep(200);
    expect(attempts).not.toHaveBeenCalled();
    expect(fs.existsSync(folder(dirId))).toBe(true);
    releaseHold();
    await vi.waitFor(() => expect(gone(folder(dirId))).toBe(true));
    expect(attempts).toHaveBeenCalledTimes(1);
    expect(sessions.erasurePendingCount()).toBe(0);
  });

  it("a delete during a running request: 503, the run is unaffected, and the folder is gone right after the request ends", async () => {
    vi.doMock("../agent.js", () => ({ runQuery: (...args: unknown[]) => runQuery(...args), DEFAULT_TOOLS: [] }));
    const { sessions, erasure } = await load();
    await erasure.startErasureSweeper({ retryMs: 60_000 });
    const { queryRouter } = await import("../query.js");
    const server = express();
    server.use(express.json());
    server.use((req, _res, next) => {
      req.clientLabel = "reqlift";
      next();
    });
    server.use(queryRouter);
    server.delete("/v1/sessions/:id", erasure.deleteSessionRoute);
    let finish: (v: unknown) => void = () => undefined;
    let dirId = "";
    runQuery.mockImplementationOnce((options: { sandboxDirId?: string }) => {
      dirId = options.sandboxDirId!;
      makeFolder(dirId);
      return new Promise((resolve) => (finish = resolve));
    });
    const running = request(server).post("/v1/query").send({ model: "m", prompt: "hi", queryId: "q1", sessionId: "c1" }).then((r) => r);
    await vi.waitFor(() => expect(dirId).not.toBe(""));
    expect((await request(server).delete("/v1/sessions/c1")).status).toBe(503);
    finish({ response: "answer", resultData: { session_id: "sdk-1", usage: {}, modelUsage: {} } });
    const result = await running;
    expect(result.text).toContain('"type":"done"');
    await vi.waitFor(() => expect(gone(folder(dirId))).toBe(true));
    expect(sessions.erasurePendingCount()).toBe(0);
    expect((await request(server).delete("/v1/sessions/c1")).status).toBe(200);
  });
});

describe("expiry goes through the erase path", () => {
  const old = Date.now() - 60_000;
  const owned = (dirId: string, extra: Record<string, unknown> = {}) => ({ sessionId: "gw", sdkSessionId: "sdk", systemPrompt: "", model: "m", lastUsed: old, owner: { label: "reqlift", userId: null }, sandboxDirId: dirId, ...extra });

  it("idle expiry erases the folder and leaves a marker: the owner's late delete answers 200, label B 404", async () => {
    const { app, sessions, erasure } = await rig();
    sessions.updateSettings({ sessionIdleTimeoutMs: 100 });
    const dirId = conversation(sessions, A, "c1");
    await sleep(150);
    const legacy = { sessionId: "gw", systemPrompt: "", model: "m", lastUsed: Date.now() - 10_000 };
    await erasure.startErasureSweeper({ retryMs: 100 });
    await vi.waitFor(() => expect(gone(folder(dirId))).toBe(true), { timeout: 3000 });
    expect(sessions.getSessionCount()).toBe(0);
    for (let n = 0; n < 2; n++) expect((await del(app, "c1")).body).toEqual({ deleted: true });
    expect((await del(app, "c1", "diemai")).status).toBe(404);
    expect(legacy.lastUsed).toBeLessThan(Date.now());
  });

  it("idle expiry takes an idle legacy entry the old way: dropped, no file touched", async () => {
    fs.writeFileSync(process.env.SESSION_PERSIST_PATH!, JSON.stringify({ sessions: { old: { sessionId: "gw", systemPrompt: "", model: "m", lastUsed: Date.now() } }, settings: { sessionIdleTimeoutMs: 100 } }));
    const { sessions, erasure } = await rig();
    sessions.loadSessions();
    const store = path.join(tmp, "legacy-store");
    fs.mkdirSync(store, { mode: 0o700 });
    fs.writeFileSync(path.join(store, "T.jsonl"), "legacy transcript");
    const before = snapshot(store);
    await sleep(150);
    await erasure.runErasureSweep();
    expect(sessions.admitSession("old", A)).toEqual({ kind: "new" });
    expect(snapshot(store)).toEqual(before);
    expect(sessions.erasurePendingCount()).toBe(0);
  });

  it("load-time expiry keeps the conversation as a tombstone and the startup sweep erases its folder", async () => {
    const dirId = "0123456789abcdef01234567";
    fs.writeFileSync(process.env.SESSION_PERSIST_PATH!, JSON.stringify({ sessions: {}, sessionsByLabel: { reqlift: { c1: owned(dirId) } }, settings: { sessionIdleTimeoutMs: 1000 } }));
    const { app, sessions, erasure } = await rig();
    makeFolder(dirId);
    sessions.loadSessions();
    expect(sessions.getSessionCount()).toBe(0);
    expect(sessions.erasurePendingCount()).toBe(1);
    expect(sessions.admitSession("c1", A)).toEqual({ kind: "refused", reason: "erasing" });
    await erasure.startErasureSweeper({ retryMs: 60_000 });
    expect(gone(folder(dirId))).toBe(true);
    expect((await del(app, "c1")).status).toBe(200);
  });

  it("with the idle timeout 0 nothing expires, however old the entry", async () => {
    const dirId = "0123456789abcdef01234567";
    fs.writeFileSync(process.env.SESSION_PERSIST_PATH!, JSON.stringify({ sessions: {}, sessionsByLabel: { reqlift: { c1: owned(dirId, { lastUsed: 1 }) } }, settings: { sessionIdleTimeoutMs: 0 } }));
    const { sessions, erasure } = await rig();
    makeFolder(dirId);
    sessions.loadSessions();
    await erasure.startErasureSweeper({ retryMs: 50 });
    await sleep(300);
    expect(sessions.getSessionCount()).toBe(1);
    expect(fs.existsSync(folder(dirId))).toBe(true);
  });
});

describe("bounds and persistence of the erase path", () => {
  it("S9: a slow removal makes the DELETE answer 503 within its bound while the removal continues; a later DELETE answers 200", async () => {
    const { app, sessions, erasure } = await rig();
    const dirId = conversation(sessions, A, "c1");
    erasure.erasureSeams.deleteWaitMs = 100;
    erasure.erasureSeams.remove = async (r, d) => {
      await sleep(600);
      return erasure.eraseConversationDir(r, d);
    };
    const started = Date.now();
    const slow = await del(app, "c1");
    expect([slow.status, slow.body]).toEqual([503, { error: "erasure_pending" }]);
    expect(Date.now() - started).toBeLessThan(450);
    expect(fs.existsSync(folder(dirId))).toBe(true);
    await vi.waitFor(() => expect(sessions.erasurePendingCount()).toBe(0), { timeout: 3000 });
    expect(gone(folder(dirId))).toBe(true);
    expect((await del(app, "c1")).status).toBe(200);
  });

  it("S9: with three pending entries the sweeps never overlap and no two removals run at once", async () => {
    const { sessions, erasure, sandbox } = await rig();
    const dirs = ["c1", "c2", "c3"].map((id) => conversation(sessions, A, id));
    const locks = dirs.map((d) => sandbox.tryLockConversation(d)!);
    for (const id of ["c1", "c2", "c3"]) sessions.markErasePending("reqlift", id);
    locks.forEach((l) => l.release());
    let active = 0;
    let peak = 0;
    let calls = 0;
    erasure.erasureSeams.remove = async (r, d) => {
      calls++;
      active++;
      peak = Math.max(peak, active);
      await sleep(80);
      const result = await erasure.eraseConversationDir(r, d);
      active--;
      return result;
    };
    const first = erasure.runErasureSweep();
    const overlapping = erasure.runErasureSweep();
    await Promise.all([first, overlapping]);
    expect(peak).toBe(1);
    expect(calls).toBe(3);
    expect(sessions.erasurePendingCount()).toBe(0);
    dirs.forEach((d) => expect(gone(folder(d))).toBe(true));
  });

  it("S5: a failed save of a new tombstone keeps it pending in memory and the next sweep saves it", async () => {
    const persistDir = path.join(tmp, "persist");
    fs.mkdirSync(persistDir, { mode: 0o700 });
    process.env.SESSION_PERSIST_PATH = path.join(persistDir, "sessions.json");
    const { app, sessions, erasure, sandbox } = await rig();
    const dirId = conversation(sessions, A, "c1");
    expect(sessions.flushSessions()).toBe(true);
    const lock = sandbox.tryLockConversation(dirId)!;
    fs.chmodSync(persistDir, 0o500);
    expect((await del(app, "c1")).status).toBe(503);
    fs.chmodSync(persistDir, 0o700);
    expect(readStore().sessionsByLabel.reqlift.c1.erasePendingSince).toBeUndefined();
    expect(sessions.erasurePendingCount()).toBe(1);
    await erasure.runErasureSweep();
    expect(typeof readStore().sessionsByLabel.reqlift.c1.erasePendingSince).toBe("number");
    lock.release();
  });
});

describe("SESSION_ERASURE_RETRY_MS", () => {
  it.each([
    [undefined, 60_000],
    ["", 60_000],
    ["250", 250],
    [" 1500 ", 1500],
  ])("%j is accepted as %i ms", async (raw, expected) => {
    const { erasure } = await load();
    expect(erasure.loadErasureRetryMs(raw === undefined ? {} : { SESSION_ERASURE_RETRY_MS: raw })).toBe(expected);
  });

  it.each(["0", "-5", "1.5", "abc", "1e3", "9007199254740993", "10 000"])("%j stops startup with the fixed line", async (raw) => {
    const { erasure } = await load();
    try {
      erasure.loadErasureRetryMs({ SESSION_ERASURE_RETRY_MS: raw });
      throw new Error("accepted");
    } catch (e) {
      expect(e).toBeInstanceOf(erasure.ErasureConfigError);
      expect((e as InstanceType<typeof erasure.ErasureConfigError>).logLine).toBe("FATAL config key=SESSION_ERASURE_RETRY_MS reason=must be a positive whole number of milliseconds");
    }
  });
});
