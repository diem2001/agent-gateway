/**
 * Unit tests for the shared persistence helper (MVP-7616): atomic writes, the
 * load classification of an unreadable state file, suppressed and failed
 * saves, the /health issue list, and the three stores built on it.
 * Every test uses its own temp directory, never the real home folder.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PersistentStore, atomicWriteFileSync, type PersistenceArea } from "../persistence.js";

const IS_ROOT = process.getuid?.() === 0;

let dir: string;
let errors: string[];

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "mvp7616-unit-"));
  errors = [];
  vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
    errors.push(args.map(String).join(" "));
  });
  vi.spyOn(console, "log").mockImplementation(() => undefined);
});

afterEach(() => {
  vi.restoreAllMocks();
  fs.chmodSync(dir, 0o755);
  fs.rmSync(dir, { recursive: true, force: true });
});

function enospc(): NodeJS.ErrnoException {
  const e: NodeJS.ErrnoException = new Error("ENOSPC: no space left on device, write");
  e.code = "ENOSPC";
  return e;
}

function tempLeftovers(file: string): string[] {
  return fs.readdirSync(path.dirname(file)).filter((n) => n.startsWith(`${path.basename(file)}.tmp-`));
}

describe("atomicWriteFileSync", () => {
  it("writes the exact content and leaves no temp file", () => {
    const file = path.join(dir, "state.json");
    atomicWriteFileSync(file, '{\n  "a": 1\n}');
    expect(fs.readFileSync(file, "utf8")).toBe('{\n  "a": 1\n}');
    expect(tempLeftovers(file)).toEqual([]);
  });

  it("creates a missing directory", () => {
    const file = path.join(dir, "nested", "deeper", "state.json");
    atomicWriteFileSync(file, "[]");
    expect(fs.readFileSync(file, "utf8")).toBe("[]");
  });

  it("keeps the target byte-identical and removes the temp file when the write fails", () => {
    const file = path.join(dir, "state.json");
    fs.writeFileSync(file, "previous complete state");
    const original = fs.readFileSync(file);
    vi.spyOn(fs, "fsyncSync").mockImplementationOnce(() => {
      throw enospc();
    });
    expect(() => atomicWriteFileSync(file, "new state")).toThrow(/ENOSPC/);
    expect(fs.readFileSync(file).equals(original)).toBe(true);
    expect(tempLeftovers(file)).toEqual([]);
  });

  it("keeps the target byte-identical when the rename fails", () => {
    const file = path.join(dir, "state.json");
    fs.writeFileSync(file, "previous complete state");
    vi.spyOn(fs, "renameSync").mockImplementationOnce(() => {
      throw Object.assign(new Error("EXDEV"), { code: "EXDEV" });
    });
    expect(() => atomicWriteFileSync(file, "new state")).toThrow();
    expect(fs.readFileSync(file, "utf8")).toBe("previous complete state");
    expect(tempLeftovers(file)).toEqual([]);
  });

  it("keeps the target's mode (0600 stays 0600)", () => {
    const file = path.join(dir, "mcp-servers.json");
    fs.writeFileSync(file, "[]", { mode: 0o600 });
    fs.chmodSync(file, 0o600);
    atomicWriteFileSync(file, '[{"name":"x"}]');
    expect(fs.statSync(file).mode & 0o777).toBe(0o600);
  });

  it("gives a new file the umask default, as the previous in-place write did", () => {
    const file = path.join(dir, "fresh.json");
    atomicWriteFileSync(file, "[]");
    const mask = process.umask();
    expect(fs.statSync(file).mode & 0o777).toBe(0o666 & ~mask);
  });

  it("creates the temp file exclusively with mode 0600 in the target's directory", () => {
    const file = path.join(dir, "state.json");
    const open = vi.spyOn(fs, "openSync");
    atomicWriteFileSync(file, "[]");
    const tempCall = open.mock.calls.find(([p]) => String(p).includes(".tmp-"));
    expect(tempCall).toBeDefined();
    expect(path.dirname(String(tempCall![0]))).toBe(dir);
    expect(path.basename(String(tempCall![0]))).toMatch(/^state\.json\.tmp-\d+-[0-9a-f]{12}$/);
    expect(tempCall![1]).toBe("wx");
    expect(tempCall![2]).toBe(0o600);
  });

  it("refuses to write through an existing temp name (wx never follows a symlink)", () => {
    const target = path.join(dir, "elsewhere.txt");
    fs.writeFileSync(target, "untouched");
    const link = path.join(dir, "state.json.tmp-link");
    fs.symlinkSync(target, link);
    expect(() => fs.openSync(link, "wx", 0o600)).toThrow(/EEXIST/);
    expect(fs.readFileSync(target, "utf8")).toBe("untouched");
  });
});

function makeStore(file: string, data: () => unknown = () => ({ v: 1 }), area: PersistenceArea = "tools"): PersistentStore {
  return new PersistentStore({
    area,
    file,
    snapshot: data,
    isValid: (d) => typeof d === "object" && d !== null,
  });
}

function corruptCopies(file: string): string[] {
  return fs.readdirSync(path.dirname(file)).filter((n) => n.startsWith(`${path.basename(file)}.corrupt-`));
}

describe("PersistentStore.load", () => {
  it("returns the parsed data of a valid file and reports no issue", () => {
    const file = path.join(dir, "tools.json");
    fs.writeFileSync(file, JSON.stringify([{ name: "a" }], null, 2));
    const store = makeStore(file);
    expect(store.load()).toEqual([{ name: "a" }]);
    expect(store.issues()).toEqual([]);
    expect(errors).toEqual([]);
  });

  it("starts empty without an issue when the file is missing", () => {
    const store = makeStore(path.join(dir, "tools.json"));
    expect(store.load()).toBeUndefined();
    expect(store.issues()).toEqual([]);
    expect(errors).toEqual([]);
  });

  it("moves invalid JSON aside with the original bytes and reports corrupt-preserved", () => {
    const file = path.join(dir, "tools.json");
    const bytes = Buffer.from('[{"name": "half-writ');
    fs.writeFileSync(file, bytes);
    const store = makeStore(file);
    expect(store.load()).toBeUndefined();
    expect(fs.existsSync(file)).toBe(false);
    const copies = corruptCopies(file);
    expect(copies).toHaveLength(1);
    expect(copies[0]).toMatch(/^tools\.json\.corrupt-\d{8}T\d{6}Z$/);
    expect(fs.readFileSync(path.join(dir, copies[0])).equals(bytes)).toBe(true);
    expect(store.issues()).toEqual([
      { area: "tools", problem: "corrupt-preserved", file, preservedAs: [path.join(dir, copies[0])] },
    ]);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toBe(
      `ERROR persistence area=tools problem=corrupt-preserved file=${file} preservedAs=${path.join(dir, copies[0])} reason=invalid JSON, starting empty (see /health)`,
    );
  });

  it("treats valid JSON of the wrong shape like invalid JSON", () => {
    const file = path.join(dir, "tools.json");
    fs.writeFileSync(file, "null");
    const store = makeStore(file);
    expect(store.load()).toBeUndefined();
    expect(corruptCopies(file)).toHaveLength(1);
    expect(errors[0]).toContain("reason=unexpected content");
  });

  it("adds a counter when a copy with the same stamp already exists", () => {
    const file = path.join(dir, "tools.json");
    const store = makeStore(file);
    fs.writeFileSync(file, "{");
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      vi.setSystemTime(new Date("2026-09-25T10:15:00.123Z"));
      store.load();
      fs.writeFileSync(file, "{{");
      store.load();
    } finally {
      vi.useRealTimers();
    }
    expect(corruptCopies(file).sort()).toEqual(["tools.json.corrupt-20260925T101500Z", "tools.json.corrupt-20260925T101500Z-1"]);
    expect(fs.readFileSync(path.join(dir, "tools.json.corrupt-20260925T101500Z"), "utf8")).toBe("{");
    expect(fs.readFileSync(path.join(dir, "tools.json.corrupt-20260925T101500Z-1"), "utf8")).toBe("{{");
  });

  it("moves an unreadable path aside on a read error other than ENOENT (EISDIR)", () => {
    const file = path.join(dir, "tools.json");
    fs.mkdirSync(file);
    fs.writeFileSync(path.join(file, "inside"), "kept");
    const store = makeStore(file);
    expect(store.load()).toBeUndefined();
    const copies = corruptCopies(file);
    expect(copies).toHaveLength(1);
    expect(fs.readFileSync(path.join(dir, copies[0], "inside"), "utf8")).toBe("kept");
    expect(errors[0]).toMatch(/problem=corrupt-preserved .* reason=read error, starting empty code=EISDIR \(see \/health\)$/);
  });

  it.skipIf(IS_ROOT)("moves an unreadable file aside on EACCES and keeps its bytes and mode", () => {
    const file = path.join(dir, "tools.json");
    fs.writeFileSync(file, "[]");
    fs.chmodSync(file, 0o000);
    const store = makeStore(file);
    expect(store.load()).toBeUndefined();
    const copy = path.join(dir, corruptCopies(file)[0]);
    expect(fs.statSync(copy).mode & 0o777).toBe(0o000);
    fs.chmodSync(copy, 0o600);
    expect(fs.readFileSync(copy, "utf8")).toBe("[]");
    expect(errors[0]).toContain("code=EACCES");
  });

  it.skipIf(IS_ROOT)("leaves the file in place, suppresses saves and reports unreadable-not-preserved when it cannot be moved aside", () => {
    const file = path.join(dir, "tools.json");
    fs.writeFileSync(file, "{broken");
    fs.chmodSync(dir, 0o555);
    const store = makeStore(file);
    expect(store.load()).toBeUndefined();
    expect(errors[0]).toBe(
      `ERROR persistence area=tools problem=unreadable-not-preserved file=${file} reason=invalid JSON, move aside failed, saves suppressed code=EACCES (see /health)`,
    );
    expect(store.issues()).toEqual([{ area: "tools", problem: "unreadable-not-preserved", file }]);

    // Even with a writable directory again, this process never writes the file.
    fs.chmodSync(dir, 0o755);
    expect(store.flush()).toBe(false);
    expect(fs.readFileSync(file, "utf8")).toBe("{broken");
    expect(corruptCopies(file)).toEqual([]);
    expect(errors[1]).toContain("problem=unreadable-not-preserved");
    expect(errors[1]).toContain("reason=save suppressed");
  });

  it("removes only its own temp leftovers at start, never other files or corrupt copies", () => {
    const file = path.join(dir, "tools.json");
    fs.writeFileSync(file, "[]");
    for (const name of ["tools.json.tmp-1-aaaaaaaaaaaa", "sessions.json.tmp-1-bbbbbbbbbbbb", "tools.json.corrupt-20260101T000000Z"]) {
      fs.writeFileSync(path.join(dir, name), "x");
    }
    makeStore(file).load();
    expect(fs.readdirSync(dir).sort()).toEqual(["sessions.json.tmp-1-bbbbbbbbbbbb", "tools.json", "tools.json.corrupt-20260101T000000Z"]);
  });
});

describe("PersistentStore saves and issues", () => {
  it("writes JSON.stringify(data, null, 2) byte for byte", () => {
    const file = path.join(dir, "tools.json");
    const data = [{ name: "a", input_schema: { type: "object" } }];
    expect(makeStore(file, () => data).flush()).toBe(true);
    expect(fs.readFileSync(file, "utf8")).toBe(JSON.stringify(data, null, 2));
  });

  it("reports write-failed until a later save succeeds, keeping the previous file", () => {
    const file = path.join(dir, "tools.json");
    let value = 1;
    const store = makeStore(file, () => ({ value }));
    expect(store.flush()).toBe(true);
    const before = fs.readFileSync(file);

    value = 2;
    vi.spyOn(fs, "writeFileSync").mockImplementationOnce(() => {
      throw enospc();
    });
    expect(store.flush()).toBe(false);
    expect(fs.readFileSync(file).equals(before)).toBe(true);
    expect(store.issues()).toEqual([{ area: "tools", problem: "write-failed", file }]);
    expect(errors).toEqual([
      `ERROR persistence area=tools problem=write-failed file=${file} reason=save failed, previous file kept code=ENOSPC (see /health)`,
    ]);

    expect(store.flush()).toBe(true);
    expect(JSON.parse(fs.readFileSync(file, "utf8"))).toEqual({ value: 2 });
    expect(store.issues()).toEqual([]);
  });

  it("recomputes corrupt-preserved on every call: it clears once the copy is gone", () => {
    const file = path.join(dir, "tools.json");
    fs.writeFileSync(file, "{");
    const store = makeStore(file);
    store.load();
    expect(store.issues().map((i) => i.problem)).toEqual(["corrupt-preserved"]);
    store.flush();
    // A valid file next to the copy is still degraded.
    expect(store.issues().map((i) => i.problem)).toEqual(["corrupt-preserved"]);
    for (const name of corruptCopies(file)) fs.rmSync(path.join(dir, name));
    expect(store.issues()).toEqual([]);
  });

  it("debounces saves to one write per 100 ms burst and flush cancels the pending one", async () => {
    const file = path.join(dir, "tools.json");
    let value = 0;
    const store = makeStore(file, () => ({ value }));
    const write = vi.spyOn(fs, "renameSync");
    value = 1;
    store.schedule();
    value = 2;
    store.schedule();
    await new Promise((resolve) => setTimeout(resolve, 250));
    expect(write).toHaveBeenCalledTimes(1);
    expect(JSON.parse(fs.readFileSync(file, "utf8"))).toEqual({ value: 2 });

    value = 3;
    store.schedule();
    expect(store.flush()).toBe(true);
    await new Promise((resolve) => setTimeout(resolve, 250));
    expect(write).toHaveBeenCalledTimes(2);
    expect(JSON.parse(fs.readFileSync(file, "utf8"))).toEqual({ value: 3 });
  });
});

/* ------------------------------------------------------------------ */
/*  The three stores                                                    */
/* ------------------------------------------------------------------ */

interface StoreCase {
  area: PersistenceArea;
  envKey: string;
  fileName: string;
  valid: unknown;
  /** Valid JSON with at least one entry the store cannot restore; each is set aside like invalid JSON. */
  unrestorable: [label: string, content: unknown][];
  /** Files the pre-MVP-7616 load accepted; they still load, with the listed names. */
  tolerated: [label: string, content: unknown, names: string[]][];
  /** Load, change one entry, flush; returns the flush result. */
  loadAndChange: (dirOfFile: string) => Promise<{ loadedNames: string[]; flushed: boolean }>;
}

async function freshImport<T>(specifier: string): Promise<T> {
  vi.resetModules();
  return (await import(specifier)) as T;
}

const session = (fields: Record<string, unknown> = {}) => ({ sessionId: "sdk-1", systemPrompt: "", model: "m", lastUsed: Date.now(), ...fields });
const tool = (fields: Record<string, unknown> = {}) => ({ name: "t1", description: "d", input_schema: { type: "object" }, webhook_url: "http://127.0.0.1/x", ...fields });
const mcpServer = (fields: Record<string, unknown> = {}) => ({ name: "m1", description: "", enabled: true, type: "http", url: "http://127.0.0.1/mcp", createdAt: "x", updatedAt: "x", ...fields });

function withoutKey(entry: Record<string, unknown>, key: string): Record<string, unknown> {
  const { [key]: _removed, ...rest } = entry;
  return rest;
}

const CASES: StoreCase[] = [
  {
    area: "sessions",
    envKey: "SESSION_PERSIST_PATH",
    fileName: "sessions.json",
    valid: { sessions: { s1: session() }, settings: { sessionIdleTimeoutMs: 0 } },
    unrestorable: [
      ["null session, idle timeout on", { sessions: { s1: null }, settings: { sessionIdleTimeoutMs: 60_000 } }],
      ["null session, idle timeout off", { sessions: { s1: null }, settings: { sessionIdleTimeoutMs: 0 } }],
      ["wrong-typed session", { sessions: { s1: "text" }, settings: { sessionIdleTimeoutMs: 0 } }],
      ["session without lastUsed, idle timeout on", { sessions: { s1: withoutKey(session(), "lastUsed") }, settings: { sessionIdleTimeoutMs: 60_000 } }],
      ["session without lastUsed, idle timeout off", { sessions: { s1: withoutKey(session(), "lastUsed") }, settings: { sessionIdleTimeoutMs: 0 } }],
      ["session with a non-numeric lastUsed", { sessions: { s1: session({ lastUsed: "yesterday" }) }, settings: { sessionIdleTimeoutMs: 0 } }],
      ["one good and one null session", { sessions: { s1: session(), s2: null }, settings: { sessionIdleTimeoutMs: 0 } }],
      ["sessions is an array", { sessions: [session()], settings: { sessionIdleTimeoutMs: 0 } }],
      // The fields added by the isolation update (MVP-7678) are optional, but a present one must be usable.
      ["an owner that is not an object", { sessions: { s1: session({ owner: "reqlift" }) } }],
      ["an owner without a label", { sessions: { s1: session({ owner: { userId: null } }) } }],
      ["an owner with an empty label", { sessions: { s1: session({ owner: { label: "", userId: null } }) } }],
      ["an owner with a numeric user id", { sessions: { s1: session({ owner: { label: "a", userId: 7 } }) } }],
      ["an owner without a user id field", { sessions: { s1: session({ owner: { label: "a" } }) } }],
      ["a sandboxDirId with a path in it", { sessions: { s1: session({ sandboxDirId: "../../etc/passwd000000000" }) } }],
      ["a sandboxDirId in upper case", { sessions: { s1: session({ sandboxDirId: "ABCDEF0123456789ABCDEF01" }) } }],
      ["a sandboxDirId that is too short", { sessions: { s1: session({ sandboxDirId: "abcdef" }) } }],
      ["a numeric sandboxDirId", { sessions: { s1: session({ sandboxDirId: 123456789012345678901234 }) } }],
    ],
    tolerated: [
      ["a legacy entry without owner and sandboxDirId (loads; refused on resume)", { sessions: { s1: session() } }, ["s1"]],
      ["entries with an owner with and without a user id and a recorded sandboxDirId", { sessions: { s1: session({ owner: { label: "a", userId: "u-1" }, sandboxDirId: "0123456789abcdef01234567" }), s2: session({ owner: { label: "a", userId: null }, sandboxDirId: "fedcba9876543210fedcba98" }) } }, ["s1", "s2"]],
      ["no settings", { sessions: { s1: session() } }, ["s1"]],
      ["no sessions", { settings: { sessionIdleTimeoutMs: 0 } }, []],
      ["settings of the wrong type", { sessions: { s1: session() }, settings: "x" }, ["s1"]],
      ["session without sdkSessionId and with an extra field", { sessions: { s1: withoutKey(session({ extra: 1 }), "sdkSessionId") } }, ["s1"]],
      [
        "an expired session is dropped as before",
        { sessions: { s1: session(), old: session({ lastUsed: 1 }) }, settings: { sessionIdleTimeoutMs: 60_000 } },
        ["s1"],
      ],
    ],
    loadAndChange: async () => {
      const m = await freshImport<typeof import("../sessions.js")>("../sessions.js");
      m.loadSessions();
      const loadedNames = m.listSessions().map((s) => s.id);
      m.updateSettings({ sessionIdleTimeoutMs: 4321 });
      return { loadedNames, flushed: m.flushSessions() };
    },
  },
  {
    area: "tools",
    envKey: "TOOLS_PERSIST_PATH",
    fileName: "tools.json",
    valid: [tool()],
    unrestorable: [
      ["null entry", [null]],
      ["wrong-typed entry", ["t1"]],
      ["entry without name", [withoutKey(tool(), "name")]],
      ["entry with a non-string name", [tool({ name: 7 })]],
      ["one good entry and one null entry", [tool(), null]],
    ],
    tolerated: [
      ["entries without optional fields and with an extra field", [tool({ extra: 1 }), withoutKey(tool({ name: "t2" }), "description")], ["t1", "t2"]],
      ["no entries", [], []],
    ],
    loadAndChange: async () => {
      const m = await freshImport<typeof import("../tools.js")>("../tools.js");
      m.loadTools();
      const loadedNames = m.getAllTools().map((t) => t.name);
      m.registerTool({ name: "t2", description: "d", input_schema: { type: "object" }, webhook_url: "http://127.0.0.1/y" });
      return { loadedNames, flushed: m.flushTools() };
    },
  },
  {
    area: "mcpServers",
    envKey: "MCP_SERVERS_PERSIST_PATH",
    fileName: "mcp-servers.json",
    valid: [mcpServer()],
    unrestorable: [
      ["null entry", [null]],
      ["wrong-typed entry", [["m1"]]],
      ["entry without name", [withoutKey(mcpServer(), "name")]],
      ["entry with a non-string name", [mcpServer({ name: { first: "m1" } })]],
      ["one good entry and one null entry", [mcpServer(), null]],
    ],
    tolerated: [
      ["entries without optional fields and with an extra field", [mcpServer({ extra: 1 }), withoutKey(mcpServer({ name: "m2" }), "url")], ["m1", "m2"]],
      ["no entries", [], []],
    ],
    loadAndChange: async () => {
      const m = await freshImport<typeof import("../mcp-registry.js")>("../mcp-registry.js");
      m.loadMcpServers();
      const loadedNames = m.getAllMcpServers().map((s) => s.name);
      m.registerMcpServer({ name: "m2", description: "", enabled: true, type: "http", url: "http://127.0.0.1/m2", createdAt: "x", updatedAt: "x" });
      return { loadedNames, flushed: m.flushMcpServers() };
    },
  },
];

describe.each(CASES)("$area store", (c) => {
  let file: string;
  beforeEach(() => {
    file = path.join(dir, c.fileName);
    process.env[c.envKey] = file;
  });
  afterEach(() => {
    delete process.env[c.envKey];
  });

  async function report() {
    const { persistenceReport } = await import("../persistence.js");
    return persistenceReport().persistenceIssues.filter((i) => i.area === c.area);
  }

  it("valid: loads the file, saves byte-compatible JSON and reports no issue", async () => {
    fs.writeFileSync(file, JSON.stringify(c.valid, null, 2));
    const { loadedNames, flushed } = await c.loadAndChange(dir);
    expect(loadedNames.length).toBe(1);
    expect(flushed).toBe(true);
    const saved = fs.readFileSync(file, "utf8");
    expect(saved).toBe(JSON.stringify(JSON.parse(saved), null, 2));
    expect(await report()).toEqual([]);
  });

  it("missing: starts empty and creates the file on save", async () => {
    const { loadedNames, flushed } = await c.loadAndChange(dir);
    expect(loadedNames).toEqual([]);
    expect(flushed).toBe(true);
    expect(fs.existsSync(file)).toBe(true);
    expect(await report()).toEqual([]);
  });

  it("invalid JSON: preserves the bytes aside, saves a new file, reports corrupt-preserved", async () => {
    const bytes = JSON.stringify(c.valid, null, 2).slice(0, 30);
    fs.writeFileSync(file, bytes);
    const { loadedNames, flushed } = await c.loadAndChange(dir);
    expect(loadedNames).toEqual([]);
    expect(flushed).toBe(true);
    const [copy] = corruptCopies(file);
    expect(fs.readFileSync(path.join(dir, copy), "utf8")).toBe(bytes);
    expect(JSON.parse(fs.readFileSync(file, "utf8"))).toBeTruthy();
    expect((await report()).map((i) => i.problem)).toEqual(["corrupt-preserved"]);
    expect(errors.some((l) => l.startsWith(`ERROR persistence area=${c.area} problem=corrupt-preserved`))).toBe(true);
  });

  it.each(c.unrestorable)("unrestorable entry (%s): preserves the bytes aside, starts empty, reports corrupt-preserved", async (_label, content) => {
    const bytes = JSON.stringify(content, null, 2);
    fs.writeFileSync(file, bytes);
    const { loadedNames, flushed } = await c.loadAndChange(dir);
    // Nothing of the file is restored, not even the entries before the bad one.
    expect(loadedNames).toEqual([]);
    expect(flushed).toBe(true);
    const copies = corruptCopies(file);
    expect(copies).toHaveLength(1);
    expect(fs.readFileSync(path.join(dir, copies[0]), "utf8")).toBe(bytes);
    expect((await report()).map((i) => i.problem)).toEqual(["corrupt-preserved"]);
    expect(errors).toEqual([
      `ERROR persistence area=${c.area} problem=corrupt-preserved file=${file} preservedAs=${path.join(dir, copies[0])} reason=unexpected content, starting empty (see /health)`,
    ]);
  });

  it.each(c.tolerated)("existing file loads as before (%s)", async (_label, content, names) => {
    fs.writeFileSync(file, JSON.stringify(content, null, 2));
    const { loadedNames, flushed } = await c.loadAndChange(dir);
    expect(loadedNames.sort()).toEqual(names);
    expect(flushed).toBe(true);
    expect(corruptCopies(file)).toEqual([]);
    expect(await report()).toEqual([]);
    expect(errors).toEqual([]);
  });

  it("read error (EISDIR): moves the path aside and reports corrupt-preserved", async () => {
    fs.mkdirSync(file);
    const { loadedNames, flushed } = await c.loadAndChange(dir);
    expect(loadedNames).toEqual([]);
    expect(flushed).toBe(true);
    expect(corruptCopies(file)).toHaveLength(1);
    expect(errors.some((l) => l.includes(`area=${c.area} problem=corrupt-preserved`) && l.includes("code=EISDIR"))).toBe(true);
  });

  it.skipIf(IS_ROOT)("failed move-aside: never writes the file and reports unreadable-not-preserved", async () => {
    fs.writeFileSync(file, "{not json");
    fs.chmodSync(dir, 0o555);
    const { flushed } = await c.loadAndChange(dir);
    fs.chmodSync(dir, 0o755);
    expect(flushed).toBe(false);
    expect(fs.readFileSync(file, "utf8")).toBe("{not json");
    expect(corruptCopies(file)).toEqual([]);
    expect((await report()).map((i) => i.problem)).toEqual(["unreadable-not-preserved"]);
  });
});
