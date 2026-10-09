/**
 * Conversation admission and legacy refusal (MVP-7678, MVP-8044, sessions.ts, query.ts): conversations are keyed by
 * (API-key label, client id) (MVP-7679) and belong to the label (DEC-ISO-007): within a label any `user_id`, null or
 * present, continues the conversation; admission without any change to the entry, legacy entries, caller-scoped list
 * and delete, the recorded sandbox home name, persistence across a restart, and the query route's refusals (fixed
 * texts, 0 runs, no session change). The agent run is mocked here; the real-runtime rows are in
 * session-isolation-process.test.ts and shared-conversation-process.test.ts.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

let dir: string;
let logs: string[];
const runQuery = vi.fn();

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "session-ownership-"));
  process.env.SESSION_PERSIST_PATH = path.join(dir, "sessions.json");
  process.env.TOOLS_PERSIST_PATH = path.join(dir, "tools.json");
  process.env.MCP_SERVERS_PERSIST_PATH = path.join(dir, "mcp-servers.json");
  // A trusted storage root with its sessions directory: a delete of an owned conversation checks it (MVP-7402).
  process.env.AGENT_SANDBOX_ROOT = path.join(dir, "store");
  fs.mkdirSync(path.join(dir, "store", "sessions"), { recursive: true, mode: 0o700 });
  logs = [];
  vi.spyOn(console, "log").mockImplementation((...args) => {
    logs.push(args.map(String).join(" "));
  });
  runQuery.mockReset();
  vi.resetModules();
});

afterEach(() => {
  vi.restoreAllMocks();
  delete process.env.SESSION_PERSIST_PATH;
  delete process.env.TOOLS_PERSIST_PATH;
  delete process.env.MCP_SERVERS_PERSIST_PATH;
  delete process.env.AGENT_SANDBOX_ROOT;
  fs.rmSync(dir, { recursive: true, force: true });
});

async function sessionsModule(): Promise<typeof import("../sessions.js")> {
  return await import("../sessions.js");
}

/** The route's decision for a delete of `id` by `label` (MVP-7402): "deleted", "pending", "legacy" or "not_found". */
async function remove(id: string, label: string): Promise<string> {
  return (await import("../session-erasure.js")).deleteConversation(id, label);
}

const A = { label: "reqlift", userId: "user-1" };
const B = { label: "diemai", userId: "user-1" };

describe("the owner rule", () => {
  it("a new conversation records its owner and a random sandbox home name", async () => {
    const m = await sessionsModule();
    expect(m.admitSession("c1", A)).toEqual({ kind: "new" });
    const created = m.getSession("c1", "sys", "model", true, A);
    expect(created.isNew).toBe(true);
    expect(created.sandboxDirId).toMatch(/^[0-9a-f]{24}$/);
    const other = m.getSession("c2", "sys", "model", true, A);
    expect(other.sandboxDirId).not.toBe(created.sandboxDirId);
    expect(m.flushSessions()).toBe(true);
    const saved = JSON.parse(fs.readFileSync(process.env.SESSION_PERSIST_PATH!, "utf8")) as {
      sessions: Record<string, unknown>;
      sessionsByLabel: Record<string, Record<string, { owner: unknown; sandboxDirId: string }>>;
    };
    // MVP-7679: the conversation lives below its label; the raw-id map holds only legacy entries.
    expect(saved.sessions).toEqual({});
    expect(saved.sessionsByLabel.reqlift.c1.owner).toEqual(A);
    expect(saved.sessionsByLabel.reqlift.c1.sandboxDirId).toBe(created.sandboxDirId);
  });

  it("the creator resumes, with the same sandbox home", async () => {
    const m = await sessionsModule();
    const created = m.getSession("c1", "sys", "model", true, A);
    m.updateSessionSdkId("c1", "sdk-1", A.label);
    expect(m.admitSession("c1", { ...A })).toEqual({ kind: "resume", sandboxDirId: created.sandboxDirId });
    const resumed = m.getSession("c1", "sys", "model", true, A);
    expect(resumed).toEqual({ sessionId: "sdk-1", isNew: false, sandboxDirId: created.sandboxDirId });
  });

  it.each([
    ["A", "B", "user-A", "user-B"],
    ["none", "B", null, "user-B"],
    ["B", "none", "user-B", null],
    ["A", "A", "user-A", "user-A"],
  ])("creator %s, writer %s: the same label resumes the conversation in the same home (the label decides, not the user id)", async (_c, _w, creatorId, writerId) => {
    const m = await sessionsModule();
    const created = m.getSession("c1", "sys", "model", true, { label: "reqlift", userId: creatorId });
    m.updateSessionSdkId("c1", "sdk-1", "reqlift");
    const writer = { label: "reqlift", userId: writerId };
    expect(m.admitSession("c1", writer)).toEqual({ kind: "resume", sandboxDirId: created.sandboxDirId });
    const resumed = m.getSession("c1", "sys", "model", true, writer);
    expect(resumed).toEqual({ sessionId: "sdk-1", isNew: false, sandboxDirId: created.sandboxDirId });
  });

  it("the creator's user id stays on the entry as metadata and a later writer does not replace it", async () => {
    const m = await sessionsModule();
    m.getSession("c1", "sys", "model", true, A);
    m.updateSessionSdkId("c1", "sdk-1", "reqlift");
    m.getSession("c1", "sys", "model", true, { label: "reqlift", userId: "user-2" });
    m.flushSessions();
    const saved = JSON.parse(fs.readFileSync(process.env.SESSION_PERSIST_PATH!, "utf8")) as { sessionsByLabel: Record<string, Record<string, { owner: unknown }>> };
    expect(saved.sessionsByLabel.reqlift.c1.owner).toEqual(A);
  });

  it.each([
    ["another API-key label with the same user id", { label: "diemai", userId: "user-1" }],
    ["another label without a user id", { label: "diemai", userId: null }],
  ])("%s does not see the conversation: it starts its own", async (_label, caller) => {
    const m = await sessionsModule();
    const mine = m.getSession("c1", "sys", "model", true, A);
    m.updateSessionSdkId("c1", "sdk-1", A.label);
    // No refusal: nothing tells the other label that this id exists.
    expect(m.admitSession("c1", caller)).toEqual({ kind: "new" });
    const theirs = m.getSession("c1", "sys", "model", true, caller);
    expect(theirs.isNew).toBe(true);
    expect(theirs.sandboxDirId).not.toBe(mine.sandboxDirId);
    // Each label resumes its own.
    m.updateSessionSdkId("c1", "sdk-2", caller.label);
    expect(m.admitSession("c1", A)).toEqual({ kind: "resume", sandboxDirId: mine.sandboxDirId });
    expect(m.getSession("c1", "sys", "model", true, A).sessionId).toBe("sdk-1");
    expect(m.getSession("c1", "sys", "model", true, caller).sessionId).toBe("sdk-2");
  });

  it("an id that looks like another label's key (`reqlift:abc`) is just an id: label B learns nothing about reqlift's conversation `abc`", async () => {
    const m = await sessionsModule();
    const abc = m.getSession("abc", "sys", "model", true, A);
    m.updateSessionSdkId("abc", "sdk-abc", A.label);
    expect(m.admitSession("reqlift:abc", B)).toEqual({ kind: "new" });
    const b = m.getSession("reqlift:abc", "sys", "model", true, B);
    expect(b.isNew).toBe(true);
    expect(b.sandboxDirId).not.toBe(abc.sandboxDirId);
    expect(m.listSessions("reqlift").map((x) => x.id)).toEqual(["abc"]);
    expect(m.listSessions("diemai").map((x) => x.id)).toEqual(["reqlift:abc"]);
  });

  it("a conversation created without a user id is continued with one, and the reverse", async () => {
    const m = await sessionsModule();
    m.getSession("c1", "sys", "model", true, { label: "reqlift", userId: null });
    expect(m.admitSession("c1", { label: "reqlift", userId: null }).kind).toBe("resume");
    expect(m.admitSession("c1", { label: "reqlift", userId: "user-1" }).kind).toBe("resume");
    m.getSession("c2", "sys", "model", true, A);
    expect(m.admitSession("c2", { label: "reqlift", userId: null }).kind).toBe("resume");
  });

  it("admission changes nothing: an admission of another writer or another label leaves the entry exactly as it was", async () => {
    const m = await sessionsModule();
    m.getSession("c1", "original system prompt", "model-a", true, A);
    m.updateSessionSdkId("c1", "sdk-1", A.label);
    m.flushSessions();
    const before = fs.readFileSync(process.env.SESSION_PERSIST_PATH!, "utf8");
    await new Promise((r) => setTimeout(r, 20));
    expect(m.admitSession("c1", { label: A.label, userId: "user-2" }).kind).toBe("resume");
    expect(m.admitSession("c1", B)).toEqual({ kind: "new" });
    m.flushSessions();
    expect(fs.readFileSync(process.env.SESSION_PERSIST_PATH!, "utf8")).toBe(before);
  });

  it("a request without a session (useSession false) has no owner and no home", async () => {
    const m = await sessionsModule();
    const result = m.getSession("ignored", "sys", "model", false, A);
    expect(result.isNew).toBe(true);
    expect(result.sandboxDirId).toBeUndefined();
    expect(m.getSessionCount()).toBe(0);
  });
});

describe("legacy conversations (created before the update)", () => {
  function seed(file: string): void {
    fs.writeFileSync(
      file,
      JSON.stringify({
        sessions: {
          legacyConfirmed: { sessionId: "gw-1", sdkSessionId: "sdk-old", systemPrompt: "", model: "m", lastUsed: Date.now() },
          legacyUnconfirmed: { sessionId: "gw-2", systemPrompt: "", model: "m", lastUsed: Date.now() },
          ownerOnly: { sessionId: "gw-3", systemPrompt: "", model: "m", lastUsed: Date.now(), owner: { label: "reqlift", userId: null } },
          dirOnly: { sessionId: "gw-4", systemPrompt: "", model: "m", lastUsed: Date.now(), sandboxDirId: "0123456789abcdef01234567" },
        },
        settings: { sessionIdleTimeoutMs: 0 },
      }),
    );
  }

  it("every entry without a recorded owner and home is refused for every caller, confirmed or not, with a count-only audit line", async () => {
    seed(process.env.SESSION_PERSIST_PATH!);
    const m = await sessionsModule();
    m.loadSessions();
    expect(m.getSessionCount()).toBe(4);
    let total = 0;
    for (const id of ["legacyConfirmed", "legacyUnconfirmed", "ownerOnly", "dirOnly"]) {
      for (const caller of [A, B, { label: "reqlift", userId: null }]) {
        expect(m.admitSession(id, caller), `${id} / ${JSON.stringify(caller)}`).toEqual({ kind: "refused", reason: "legacy" });
        total++;
      }
    }
    const audit = logs.filter((l) => l.includes("sessions.legacy.refused"));
    expect(audit).toHaveLength(total);
    expect(audit.at(-1)).toBe(`[audit] sessions.legacy.refused total=${total}`);
    // Counts only: no conversation id, no label.
    expect(audit.join("\n")).not.toMatch(/legacy[A-Z]|ownerOnly|dirOnly|reqlift|diemai/);
  });

  it("legacy entries stay listable for every label; a delete answers legacy_not_erased and changes nothing (MVP-7402)", async () => {
    seed(process.env.SESSION_PERSIST_PATH!);
    const m = await sessionsModule();
    m.loadSessions();
    // An entry without a complete owner and home (`ownerOnly` lacks the home) stays a legacy entry under its raw id,
    // visible to every label (MVP-7679: only complete entries move into their label's map).
    expect(m.listSessions("anyone").map((s) => s.id).sort()).toEqual(["dirOnly", "legacyConfirmed", "legacyUnconfirmed", "ownerOnly"]);
    expect(m.listSessions("reqlift").map((s) => s.id).sort()).toEqual(["dirOnly", "legacyConfirmed", "legacyUnconfirmed", "ownerOnly"]);
    // Comment 40659 (option B): the old shared store is not erased here, so a delete never reports success for it.
    expect(await remove("legacyConfirmed", "anyone")).toBe("legacy");
    expect(await remove("legacyConfirmed", "anyone")).toBe("legacy");
    expect(m.getSessionCount()).toBe(4);
  });

  it("a legacy id stays refused after a delete; only expiry drops it, and then the id is new", async () => {
    seed(process.env.SESSION_PERSIST_PATH!);
    const m = await sessionsModule();
    m.loadSessions();
    expect(m.admitSession("legacyConfirmed", A).kind).toBe("refused");
    expect(await remove("legacyConfirmed", A.label)).toBe("legacy");
    expect(m.admitSession("legacyConfirmed", A).kind).toBe("refused");
    // Expiry keeps today's behavior for a legacy entry: dropped without any file being touched.
    vi.resetModules();
    fs.writeFileSync(
      process.env.SESSION_PERSIST_PATH!,
      JSON.stringify({ sessions: { legacyConfirmed: { sessionId: "gw-1", sdkSessionId: "sdk-old", systemPrompt: "", model: "m", lastUsed: 1_700_000_000_000 } }, settings: { sessionIdleTimeoutMs: 1000 } }),
    );
    const later = await sessionsModule();
    later.loadSessions();
    expect(later.admitSession("legacyConfirmed", A)).toEqual({ kind: "new" });
    const fresh = later.getSession("legacyConfirmed", "", "m", true, A);
    expect(fresh.isNew).toBe(true);
    // A fresh random home: nothing of the old conversation is reused.
    expect(fresh.sandboxDirId).not.toBe("0123456789abcdef01234567");
  });
});

describe("list and delete are scoped to the caller's label", () => {
  it("a label lists only its own conversations; another label's delete answers not found and changes nothing", async () => {
    const m = await sessionsModule();
    m.getSession("mine", "", "m", true, A);
    m.getSession("theirs", "", "m", true, B);
    m.getSession("mine-without-user", "", "m", true, { label: "reqlift", userId: null });
    expect(m.listSessions("reqlift").map((s) => s.id).sort()).toEqual(["mine", "mine-without-user"]);
    expect(m.listSessions("diemai").map((s) => s.id)).toEqual(["theirs"]);
    expect(m.listSessions("nobody")).toEqual([]);
    expect(await remove("theirs", "reqlift")).toBe("not_found");
    expect(m.getSessionCount()).toBe(3);
    expect(await remove("theirs", "diemai")).toBe("deleted");
    expect(m.getSessionCount()).toBe(2);
    // Unscoped (no label) keeps the old behavior for internal callers.
    expect(m.listSessions()).toHaveLength(2);
  });
});

describe("restart", () => {
  it("owner and sandbox home name survive a restart, and any writer of the label resumes", async () => {
    const m1 = await sessionsModule();
    const created = m1.getSession("c1", "sys", "model", true, A);
    m1.updateSessionSdkId("c1", "sdk-1", A.label);
    expect(m1.flushSessions()).toBe(true);
    vi.resetModules();
    const m2 = await sessionsModule();
    m2.loadSessions();
    expect(m2.admitSession("c1", A)).toEqual({ kind: "resume", sandboxDirId: created.sandboxDirId });
    expect(m2.admitSession("c1", { label: A.label, userId: "user-2" })).toEqual({ kind: "resume", sandboxDirId: created.sandboxDirId });
    expect(m2.admitSession("c1", { label: A.label, userId: null })).toEqual({ kind: "resume", sandboxDirId: created.sandboxDirId });
    expect(m2.admitSession("c1", B)).toEqual({ kind: "new" });
  });
});

describe("the query route", () => {
  async function app(): Promise<{ app: express.Express; sessions: typeof import("../sessions.js") }> {
    vi.doMock("../agent.js", () => ({ runQuery: (...args: unknown[]) => runQuery(...args), DEFAULT_TOOLS: [] }));
    const sessions = await sessionsModule();
    const { queryRouter } = await import("../query.js");
    const server = express();
    server.use(express.json());
    server.use((req, _res, next) => {
      req.clientLabel = (req.headers["x-test-label"] as string) ?? "reqlift";
      next();
    });
    server.use(queryRouter);
    return { app: server, sessions };
  }

  const ok = { response: "answer", resultData: { session_id: "sdk-new", usage: {}, modelUsage: {} } };

  async function ask(server: express.Express, body: Record<string, unknown>, label = "reqlift") {
    const res = await request(server).post("/v1/query").set("x-test-label", label).send({ model: "m", prompt: "hi", ...body });
    const events = res.text.split("\n").filter((l) => l.startsWith("{")).map((l) => JSON.parse(l) as { type: string; content?: string });
    return { res, events };
  }

  it("a new conversation runs with its recorded sandbox home name, any writer of the label resumes with it, another label gets its own", async () => {
    runQuery.mockResolvedValue(ok);
    const { app: server, sessions } = await app();
    const first = await ask(server, { queryId: "q1", sessionId: "c1", user_id: "user-1" });
    expect(first.events.at(-1)?.type).toBe("done");
    expect(runQuery).toHaveBeenCalledTimes(1);
    const firstDir = (runQuery.mock.calls[0][0] as { sandboxDirId?: string }).sandboxDirId;
    expect(firstDir).toMatch(/^[0-9a-f]{24}$/);

    const again = await ask(server, { queryId: "q2", sessionId: "c1", user_id: "user-1" });
    expect(again.events.at(-1)?.type).toBe("done");
    expect(runQuery).toHaveBeenCalledTimes(2);
    expect((runQuery.mock.calls[1][0] as { sandboxDirId?: string; isResume?: boolean })).toMatchObject({ sandboxDirId: firstDir, isResume: true });

    // Another person of the same label (another user id, none) continues the conversation in the same home: one run
    // each, no refusal text (MVP-8044).
    for (const [n, body] of [
      [3, { user_id: "user-2" }],
      [4, {}],
    ] as const) {
      const writer = await ask(server, { queryId: `q-writer-${n}`, sessionId: "c1", ...body });
      expect(writer.events.at(-1)?.type).toBe("done");
      expect(writer.events.some((e) => e.type === "error")).toBe(false);
      expect(runQuery).toHaveBeenCalledTimes(n);
      expect(runQuery.mock.calls[n - 1][0]).toMatchObject({ sandboxDirId: firstDir, isResume: true });
    }

    // Another label using the same id is not refused and learns nothing: it gets its own new conversation
    // (MVP-7679), with its own home, and reqlift's conversation is untouched.
    const other = await ask(server, { queryId: "q-other-label", sessionId: "c1", user_id: "user-1" }, "diemai");
    expect(other.events.at(-1)?.type).toBe("done");
    expect(runQuery).toHaveBeenCalledTimes(5);
    const otherCall = runQuery.mock.calls[4][0] as { sandboxDirId?: string; isResume?: boolean };
    expect(otherCall.isResume).toBe(false);
    expect(otherCall.sandboxDirId).toMatch(/^[0-9a-f]{24}$/);
    expect(otherCall.sandboxDirId).not.toBe(firstDir);
    expect(sessions.listSessions("reqlift").map((x) => x.id)).toEqual(["c1"]);
    expect(sessions.listSessions("diemai").map((x) => x.id)).toEqual(["c1"]);
    // reqlift resumes its own conversation, not the other label's.
    const resumed = await ask(server, { queryId: "q-again", sessionId: "c1", user_id: "user-1" });
    expect(resumed.events.at(-1)?.type).toBe("done");
    expect(runQuery.mock.calls[5][0]).toMatchObject({ sandboxDirId: firstDir, isResume: true });
  });

  it("a legacy conversation is refused with the fixed text, no run, no change; with the exact NDJSON shape (one error event, no done)", async () => {
    fs.writeFileSync(process.env.SESSION_PERSIST_PATH!, JSON.stringify({ sessions: { old: { sessionId: "gw", sdkSessionId: "sdk-old", systemPrompt: "", model: "m", lastUsed: 1_700_000_000_000 } } }));
    const { app: server, sessions } = await app();
    sessions.loadSessions();
    const refused = await ask(server, { queryId: "q-legacy", sessionId: "old", user_id: "user-1" });
    expect(refused.res.status).toBe(200);
    expect(refused.events).toEqual([
      { seq: 0, type: "error", content: "This conversation was started before a gateway security update and cannot be continued safely. Please start a new conversation. Retrying will not help." },
    ]);
    // Refused for every caller alike (another user id, none, another label), each with exactly one error and no done.
    for (const [label, body] of [
      ["reqlift", { user_id: "user-2" }],
      ["reqlift", {}],
      ["diemai", { user_id: "user-1" }],
    ] as const) {
      const again = await ask(server, { queryId: `q-legacy-${label}-${JSON.stringify(body)}`, sessionId: "old", ...body }, label);
      expect(again.events).toEqual(refused.events);
    }
    expect(runQuery).not.toHaveBeenCalled();
    expect(sessions.getSessionCount()).toBe(1);
  });

  it("the refusal texts of the legacy and busy cases are pinned verbatim, and the other-owner text no longer exists", async () => {
    const failure = await import("../run-failure.js");
    expect(failure.SESSION_LEGACY_MESSAGE).toBe("This conversation was started before a gateway security update and cannot be continued safely. Please start a new conversation. Retrying will not help.");
    expect(failure.SESSION_BUSY_MESSAGE).toBe("This conversation is still answering an earlier request. Please wait until it has finished, then try again.");
    expect(Object.keys(failure).filter((name) => /OTHER_OWNER/i.test(name))).toEqual([]);
  });

  it("a second request for a conversation that is still answering is refused as busy with no run, and the first request is unaffected", async () => {
    let finish: (v: unknown) => void = () => {};
    runQuery.mockImplementationOnce(() => new Promise((resolve) => (finish = resolve)));
    const { app: server } = await app();
    const firstDone = ask(server, { queryId: "q1", sessionId: "busy", user_id: "user-1" });
    await vi.waitFor(() => expect(runQuery).toHaveBeenCalledTimes(1));
    // The lock is per conversation: a request of another user id or without one is refused as busy too.
    for (const [n, body] of [
      [2, { user_id: "user-1" }],
      [3, { user_id: "user-2" }],
      [4, {}],
    ] as const) {
      const second = await ask(server, { queryId: `q${n}`, sessionId: "busy", ...body });
      expect(second.events).toEqual([{ seq: 0, type: "error", content: "This conversation is still answering an earlier request. Please wait until it has finished, then try again." }]);
    }
    expect(runQuery).toHaveBeenCalledTimes(1);
    // Another conversation of the same owner is not blocked.
    runQuery.mockResolvedValueOnce(ok);
    const other = await ask(server, { queryId: "q5", sessionId: "other", user_id: "user-1" });
    expect(other.events.at(-1)?.type).toBe("done");
    finish(ok);
    expect((await firstDone).events.at(-1)?.type).toBe("done");
    // Free again once the run ended: the next request is accepted.
    runQuery.mockResolvedValueOnce(ok);
    const third = await ask(server, { queryId: "q6", sessionId: "busy", user_id: "user-2" });
    expect(third.events.at(-1)?.type).toBe("done");
  });

  it("the lock is released when the run fails, and before the error reaches the client", async () => {
    runQuery.mockRejectedValueOnce(new Error("boom"));
    const { app: server } = await app();
    const failed = await ask(server, { queryId: "q1", sessionId: "c-fail", user_id: "user-1" });
    expect(failed.events.at(-1)?.type).toBe("error");
    runQuery.mockResolvedValueOnce(ok);
    const next = await ask(server, { queryId: "q2", sessionId: "c-fail", user_id: "user-1" });
    expect(next.events.at(-1)?.type).toBe("done");
  });

  it("a request without a session id or with useSession false needs no admission and starts a private run", async () => {
    runQuery.mockResolvedValue(ok);
    const { app: server, sessions } = await app();
    const a = await ask(server, { queryId: "q1" });
    const b = await ask(server, { queryId: "q2", sessionId: "c1", useSession: false, user_id: "user-1" });
    expect(a.events.at(-1)?.type).toBe("done");
    expect(b.events.at(-1)?.type).toBe("done");
    for (const call of runQuery.mock.calls) expect((call[0] as { sandboxDirId?: string }).sandboxDirId).toBeUndefined();
    expect(sessions.getSessionCount()).toBe(0);
  });
});

describe("conversations per label (MVP-7679)", () => {
  const now = Date.now();
  const entry = (label: string, extra: Record<string, unknown> = {}) => ({
    sessionId: "gw",
    sdkSessionId: "sdk",
    systemPrompt: "",
    model: "m",
    lastUsed: now,
    owner: { label, userId: null },
    sandboxDirId: "0123456789abcdef01234567",
    ...extra,
  });

  it("an entry written by the isolation update (owner and home, raw id) moves into its label's map on load and is still resumed", async () => {
    fs.writeFileSync(
      process.env.SESSION_PERSIST_PATH!,
      JSON.stringify({ sessions: { c1: entry("reqlift"), "diemcrm:123": { sessionId: "gw", systemPrompt: "", model: "m", lastUsed: now } }, settings: { sessionIdleTimeoutMs: 0 } }),
    );
    const m = await sessionsModule();
    m.loadSessions();
    expect(m.admitSession("c1", { label: "reqlift", userId: null })).toEqual({ kind: "resume", sandboxDirId: "0123456789abcdef01234567" });
    // Another label's id c1 is a new conversation for it.
    expect(m.admitSession("c1", B)).toEqual({ kind: "new" });
    // A legacy ownerless id that looks like `<label>:<id>` stays refused for every label.
    expect(m.admitSession("diemcrm:123", { label: "diemcrm", userId: null })).toEqual({ kind: "refused", reason: "legacy" });
    expect(m.admitSession("diemcrm:123", A)).toEqual({ kind: "refused", reason: "legacy" });
    m.flushSessions();
    const saved = JSON.parse(fs.readFileSync(process.env.SESSION_PERSIST_PATH!, "utf8")) as { sessions: Record<string, unknown>; sessionsByLabel: Record<string, Record<string, unknown>> };
    expect(Object.keys(saved.sessions)).toEqual(["diemcrm:123"]);
    expect(Object.keys(saved.sessionsByLabel.reqlift)).toEqual(["c1"]);
  });

  it("the public routes keep raw ids: list shows the caller's ids, delete removes the caller's own entry first", async () => {
    const m = await sessionsModule();
    m.getSession("same", "", "m", true, A);
    m.getSession("same", "", "m", true, B);
    expect(m.listSessions("reqlift").map((x) => x.id)).toEqual(["same"]);
    expect(await remove("same", "reqlift")).toBe("deleted");
    expect(m.listSessions("reqlift")).toEqual([]);
    expect(m.listSessions("diemai").map((x) => x.id)).toEqual(["same"]);
    // The owner's repeat is answered from the erased marker, another label's never-used id is not found.
    expect(await remove("same", "reqlift")).toBe("deleted");
    expect(await remove("same", "third")).toBe("not_found");
  });

  it.each([
    ["a per-label entry without an owner", { sessionsByLabel: { reqlift: { c1: { sessionId: "gw", systemPrompt: "", model: "m", lastUsed: now } } } }],
    ["a per-label entry under another label", { sessionsByLabel: { reqlift: { c1: entry("diemai") } } }],
    ["a per-label map that is not an object", { sessionsByLabel: { reqlift: [] } }],
    ["a per-label entry without a home", { sessionsByLabel: { reqlift: { c1: entry("reqlift", { sandboxDirId: undefined }) } } }],
  ])("%s sets the whole file aside instead of loading it (MVP-7616)", async (_label, extra) => {
    fs.writeFileSync(process.env.SESSION_PERSIST_PATH!, JSON.stringify({ sessions: {}, settings: { sessionIdleTimeoutMs: 0 }, ...extra }));
    const m = await sessionsModule();
    m.loadSessions();
    expect(m.getSessionCount()).toBe(0);
    expect(fs.readdirSync(dir).some((f) => f.startsWith("sessions.json.corrupt"))).toBe(true);
  });
});
