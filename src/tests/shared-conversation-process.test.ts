/**
 * Outcome Probe for MVP-8044 (DEC-ISO-007): a conversation belongs to the API-key label, not to a person. The compiled
 * gateway (`dist/server.js`) with the production Claude Agent SDK, its bundled runtime, real `bwrap`, a scripted model
 * double and recording upstream, webhook and skill fixtures, on the security rig (labels `reqlift` and `diemcrm`).
 * Every secret is a synthetic marker; only names, booleans and counts are printed (`SHARED-CONVERSATION-EVIDENCE`).
 *
 * - S1 (the Outcome): A starts conversation C through label `reqlift`; B sends the follow-up and gets an answer that
 *   uses C's earlier context, in C's own home, with no refusal text.
 * - S2: creator and writer user ids A to B, none to B, B to none, A to A; each resumes with the earlier context.
 * - S3: the same after a gateway restart.
 * - S4: a `sessions.json` whose entries have and lack `owner.userId`, next to a second label's entry and a legacy
 *   entry, loads; B continues both; the legacy entry stays refused; no other entry is dropped or changed.
 * - S5: another label sending C's id gets its own conversation and sees nothing of C.
 * - S6: a pre-update conversation is refused for every caller with the legacy text and no model request.
 * - S7-S9: the writer's skills (read on per-run surfaces only: `skills_loaded`, the bundle mounted in the run, the text
 *   the writer's own skill adds, a call to the creator's skill failing) and webhook identity; the writer's credential
 *   at the upstream double, never the creator's (the creator's own turn is the live control); a writer without a
 *   credential gets the fixed no-credential text, or the server is left out.
 * - S10: one active run per conversation across two people.
 * The `AD.*` security rows and their negative controls are in `security-regression-process.test.ts`.
 *
 * Needs `npm run build`, `bwrap`, user namespaces, `git` and `python3`. Linux only.
 */
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { Cleanup } from "./helpers/git-process-gateway.js";
import {
  BUSY_TEXT,
  CREATOR_USER,
  LEGACY_TEXT,
  WRITER_USER,
  bashStep,
  conversationDir,
  emitEvidence,
  entryOf,
  eventsSayDone,
  observe,
  otherLabelProblems,
  readSessionsFile,
  runOtherLabelScenario,
  runWriterScenario,
  scenarioSurfaces,
  setupWriterFixtures,
  sleep,
  verdictProblems,
  writerProblems,
  type SavedEntry,
} from "./helpers/shared-conversation.js";
import { TURN_DEADLINE_MS, createMarkers, createRig, detect, emit, evidenceLine, pinnedProblems, requestsFor, requireHost, shellQuote, turnProblems, waitForIsolation, type SecurityRig } from "./helpers/security-matrix.js";

vi.setConfig({ testTimeout: 600_000 });

const markers = createMarkers();
const cleanups: Cleanup[] = [];
afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()!();
});

beforeAll(() => {
  requireHost(["bwrap", "userns", "git", "python3", "build"]);
  emit(
    evidenceLine({
      suite: "shared-conversation-process",
      config: { API_KEYS: "reqlift+diemcrm", ANTHROPIC_BASE_URL: "local-double", CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1" },
      deadlines: { turn_ms: TURN_DEADLINE_MS, busy_answer_ms: 2000 },
      offline: false,
      logLevel: "info",
    }),
  );
});

async function newRig(seed?: Parameters<typeof createRig>[1] extends infer O ? (O extends { seed?: infer F } ? F : never) : never): Promise<SecurityRig> {
  const rig = await createRig(cleanups, { markers, rootPrefix: "mvp8044-shared-", seed });
  expect(pinnedProblems(rig)).toEqual([]);
  return rig;
}

/** No refusal of any kind: the legacy, busy and the former other-owner text all contain one of these phrases. */
const refusalIn = (events: unknown): boolean => /cannot be continued|still answering an earlier request/.test(JSON.stringify(events));

describe("a conversation belongs to the API-key label", () => {
  it("S1 (Outcome): B continues the conversation A started through the same label, in the same home, with A's earlier context and no refusal", async () => {
    const rig = await newRig();
    const first = await observe(rig, { prompt: "SC-S1-1", session: "c-s1", user: CREATOR_USER, steps: [bashStep("echo A-WORK-S1 > /work/a.txt; echo wrote")] });
    const before = entryOf(rig.gateway, "reqlift", "c-s1");
    const second = await observe(rig, { prompt: "SC-S1-2", session: "c-s1", user: WRITER_USER, steps: [bashStep("echo SEEN=$(cat /work/a.txt)")] });
    const after = entryOf(rig.gateway, "reqlift", "c-s1");
    expect(turnProblems(first.turn)).toEqual([]);
    expect(turnProblems(second.turn)).toEqual([]);
    expect(eventsSayDone(second.events), "B's stream ends in done with no error event").toBe(true);
    expect(refusalIn(second.events), "no refusal text").toBe(false);
    expect(second.requests.some((request) => request.userTexts.some((text) => text.includes("SC-S1-1"))), "the turn-2 request carries the turn-1 prompt").toBe(true);
    expect(second.results[0]?.text).toContain("SEEN=A-WORK-S1");
    expect(before?.sandboxDirId).toMatch(/^[0-9a-f]{24}$/);
    expect(after?.sandboxDirId, "same sandboxDirId before and after").toBe(before?.sandboxDirId);
    expect(after?.owner, "the creator's identity stays on the entry as metadata").toEqual({ label: "reqlift", userId: CREATOR_USER });
    emitEvidence("S1", { done: true, refusal_text: false, turn1_prompt_in_turn2_request: true, same_home: true, turns: 2 });
  });

  it("S2: creator A to writer B, none to B, B to none and A to A each resume with the earlier context in the same home", async () => {
    const rig = await newRig();
    const combos: [string, string | null, string | null][] = [
      ["A-to-B", CREATOR_USER, WRITER_USER],
      ["none-to-B", null, WRITER_USER],
      ["B-to-none", WRITER_USER, null],
      ["A-to-A", CREATOR_USER, CREATOR_USER],
    ];
    for (const [index, [name, creatorUser, writerUser]] of combos.entries()) {
      const session = `c-s2-${index}`;
      const first = await observe(rig, { prompt: `SC-S2-${index}-1`, session, user: creatorUser, steps: [bashStep(`echo FILE-${index} > /work/f.txt; echo wrote`)] });
      const home = entryOf(rig.gateway, "reqlift", session)?.sandboxDirId;
      const second = await observe(rig, { prompt: `SC-S2-${index}-2`, session, user: writerUser, steps: [bashStep("echo SEEN=$(cat /work/f.txt)")] });
      expect(turnProblems(first.turn), name).toEqual([]);
      expect(turnProblems(second.turn), name).toEqual([]);
      expect(eventsSayDone(second.events) && !refusalIn(second.events), `${name}: done, no refusal`).toBe(true);
      expect(second.requests.some((request) => request.userTexts.some((text) => text.includes(`SC-S2-${index}-1`))), `${name}: earlier context`).toBe(true);
      expect(second.results[0]?.text, name).toContain(`SEEN=FILE-${index}`);
      expect(entryOf(rig.gateway, "reqlift", session)?.sandboxDirId, `${name}: same home`).toBe(home);
      expect(entryOf(rig.gateway, "reqlift", session)?.owner?.userId ?? null, `${name}: creator metadata unchanged`).toBe(creatorUser);
    }
    emitEvidence("S2", { rows: combos.length, all_resumed_with_context: true, refusal_text: false, turns: combos.length * 2 });
  });

  it("S3: a shared conversation survives a gateway restart and B continues it with A's earlier context in the same home", async () => {
    const rig = await newRig();
    const first = await observe(rig, { prompt: "SC-S3-1", session: "c-s3", user: CREATOR_USER, steps: [bashStep("echo A-WORK-S3 > /work/a.txt; echo wrote")] });
    const home = entryOf(rig.gateway, "reqlift", "c-s3")?.sandboxDirId;
    await rig.restart();
    expect(await waitForIsolation(rig), "/health isolation after the restart").toBe("ok");
    const second = await observe(rig, { prompt: "SC-S3-2", session: "c-s3", user: WRITER_USER, steps: [bashStep("echo SEEN=$(cat /work/a.txt)")] });
    expect(turnProblems(first.turn)).toEqual([]);
    expect(turnProblems(second.turn)).toEqual([]);
    expect(eventsSayDone(second.events) && !refusalIn(second.events)).toBe(true);
    expect(second.requests.some((request) => request.userTexts.some((text) => text.includes("SC-S3-1")))).toBe(true);
    expect(second.results[0]?.text).toContain("SEEN=A-WORK-S3");
    expect(entryOf(rig.gateway, "reqlift", "c-s3")?.sandboxDirId).toBe(home);
    emitEvidence("S3", { restarts: 1, done: true, earlier_context: true, same_home: true });
  });

  it("S4: sessions.json with and without owner.userId loads, B continues both, the legacy entry stays refused and no other entry is dropped or changed", async () => {
    const rig = await newRig();
    await observe(rig, { prompt: "SC-S4-C1", session: "s4-has", user: CREATOR_USER, steps: [bashStep("echo W1 > /work/w.txt; echo wrote")] });
    await observe(rig, { prompt: "SC-S4-C2", session: "s4-lacks", user: null, steps: [bashStep("echo W2 > /work/w.txt; echo wrote")] });
    await observe(rig, { prompt: "SC-S4-D1", session: "s4-other", user: CREATOR_USER, label: "diemcrm", steps: [bashStep("echo W3 > /work/w.txt; echo wrote")] });
    const file = path.join(rig.gateway.dirs.persist, "sessions.json");
    let snapshot: ReturnType<typeof readSessionsFile> = {};
    await rig.restart("SIGTERM", () => {
      // The old process is gone and wrote its final state: this is the file a new process starts from.
      const saved = readSessionsFile(rig.gateway);
      snapshot = JSON.parse(JSON.stringify(saved)) as typeof snapshot;
      const lacking = saved.sessionsByLabel?.reqlift?.["s4-lacks"];
      expect(lacking?.owner, "the entry that lacks the key has an owner").toBeDefined();
      delete lacking!.owner!.userId;
      fs.writeFileSync(file, JSON.stringify(saved, null, 2));
    });
    expect(await waitForIsolation(rig)).toBe("ok");
    expect(fs.readdirSync(rig.gateway.dirs.persist).filter((name) => name.startsWith("sessions.json.corrupt")), "the file is not set aside").toEqual([]);
    const homes = ["s4-has", "s4-lacks"].map((id) => entryOf(rig.gateway, "reqlift", id)?.sandboxDirId);
    expect(homes.every((home) => typeof home === "string")).toBe(true);

    const writerTurns = [];
    for (const [index, id] of ["s4-has", "s4-lacks"].entries()) {
      writerTurns.push(await observe(rig, { prompt: `SC-S4-W${index}`, session: id, user: WRITER_USER, steps: [bashStep("echo SEEN=$(cat /work/w.txt)")] }));
    }
    for (const [index, observed] of writerTurns.entries()) {
      expect(turnProblems(observed.turn)).toEqual([]);
      expect(eventsSayDone(observed.events) && !refusalIn(observed.events)).toBe(true);
      expect(observed.results[0]?.text).toContain(`SEEN=W${index + 1}`);
      expect(observed.requests.some((request) => request.userTexts.some((text) => text.includes(index === 0 ? "SC-S4-C1" : "SC-S4-C2")))).toBe(true);
    }
    // The legacy entry (seeded by the rig) is still refused after the reload, for the same person who just continued C.
    const modelBefore = rig.api.requests.length;
    const legacy = await rig.ask("reqlift", { queryId: "q-s4-legacy", sessionId: "legacy-conv", prompt: "SC-S4-LEGACY", user_id: WRITER_USER, useSession: true });
    expect(legacy.events).toEqual([{ seq: 0, type: "error", content: LEGACY_TEXT }]);
    expect(rig.api.requests.length).toBe(modelBefore);

    // Re-persisted file: every other entry present and unchanged; the continued entries keep owner and home, and the missing key stays missing.
    await sleep(600);
    const saved = readSessionsFile(rig.gateway);
    const unchanged = (entry: SavedEntry | undefined): unknown => {
      const copy = { ...(entry ?? {}) };
      delete copy.lastUsed;
      return copy;
    };
    expect(unchanged(saved.sessions?.["legacy-conv"])).toEqual(unchanged(snapshot.sessions?.["legacy-conv"]));
    expect(saved.sessionsByLabel?.diemcrm?.["s4-other"]).toEqual(snapshot.sessionsByLabel?.diemcrm?.["s4-other"]);
    expect(saved.sessionsByLabel?.reqlift?.["s4-has"]?.owner).toEqual({ label: "reqlift", userId: CREATOR_USER });
    expect(saved.sessionsByLabel?.reqlift?.["s4-lacks"]?.owner).toEqual({ label: "reqlift" });
    expect(saved.sessionsByLabel?.reqlift?.["s4-has"]?.sandboxDirId).toBe(homes[0]);
    expect(saved.sessionsByLabel?.reqlift?.["s4-lacks"]?.sandboxDirId).toBe(homes[1]);
    expect(Object.keys(saved.sessionsByLabel ?? {}).sort()).toEqual(["diemcrm", "reqlift"]);
    emitEvidence("S4", { entries_with_user_id: 1, entries_without_user_id: 1, other_label_entries: 1, legacy_entries: 1, file_set_aside: false, other_entries_unchanged: true, legacy_refused_after_reload: true });
  });

  it("S5: another label sending the conversation's id gets its own conversation and sees nothing of the first one", async () => {
    const rig = await newRig();
    const scenario = await runOtherLabelScenario(rig, "SC-S5");
    const verdict = otherLabelProblems(rig, scenario);
    expect(turnProblems(scenario.other.turn)).toEqual([]);
    expect(verdict.problems).toEqual([]);
    const v = rig.markers.values;
    expect(detect(scenarioSurfaces(rig, [scenario.other]).filter((surface) => surface.name !== "transcripts"), { sessionBFile: v.sessionBFile, sessionBTurn: v.sessionBTurn })).toEqual([]);
    emitEvidence("S5", { ...verdict.evidence, controls: verdict.controls.length });
  });

  it("S6: a pre-update conversation is refused for every caller with the legacy text, no model request and no transcript in any request", async () => {
    const rig = await newRig();
    const callers: ["reqlift" | "diemcrm", string | undefined][] = [["reqlift", CREATOR_USER], ["reqlift", WRITER_USER], ["reqlift", undefined], ["diemcrm", CREATOR_USER]];
    const modelBefore = rig.api.requests.length;
    for (const [index, [label, user]] of callers.entries()) {
      const outcome = await rig.ask(label, { queryId: `q-s6-${index}`, sessionId: "legacy-conv", prompt: "SC-S6", ...(user ? { user_id: user } : {}), useSession: true }, 10_000);
      expect(outcome.events, `${label} / ${user ?? "none"}`).toEqual([{ seq: 0, type: "error", content: LEGACY_TEXT }]);
      expect(outcome.ms).toBeLessThan(2000);
    }
    expect(rig.api.requests.length, "no model request").toBe(modelBefore);
    expect(JSON.stringify(rig.api.requests)).not.toContain(rig.markers.values.legacyTranscript);
    emitEvidence("S6", { callers: callers.length, refused_with_legacy_text: callers.length, model_requests: 0 });
  });

  it("S7-S9: the writer's skills and webhook identity, the writer's credential and a writer without a credential, never the creator's", async () => {
    const rig = await newRig();
    const fixture = await setupWriterFixtures(rig, cleanups);
    const scenario = await runWriterScenario(rig, fixture, "SC-S789");
    const verdict = writerProblems(rig, scenario);
    for (const observed of [scenario.creator, scenario.writer, scenario.replay, scenario.third]) expect(turnProblems(observed.turn)).toEqual([]);
    expect(verdict.general, "streams and the shared home").toEqual([]);
    expect(verdict.skills, "S7: skills and webhook identity").toEqual([]);
    expect(verdict.credentials, "S8: credentials").toEqual([]);
    expect(verdict.noCredential, "S9: no credential").toEqual([]);
    const v = rig.markers.values;
    expect(detect(scenarioSurfaces(rig, [scenario.writer, scenario.replay, scenario.third]), { creatorSkill: v.creatorSkill, creatorCredential: v.creatorCredential }), "no creator marker on a later writer's surfaces").toEqual([]);
    emitEvidence("S7-S9", { controls: verdict.controls.length, problems: verdictProblems(verdict).length, turns: 4, upstream_requests: fixture.upstream.requests.length });
  });

  it("S10: while A's run holds the conversation, B and a person without a user id get the busy text within 2 s, no model request and no second runtime; the conversation is free afterwards", async () => {
    const rig = await newRig();
    const session = "c-s10";
    const tag = `HELD-S10-${randomBytes(3).toString("hex")}`;
    const held = `python3 -c ${shellQuote("import os, time\nopen('/work/held', 'w').write('x')\nend = time.time() + 120\nwhile time.time() < end and not os.path.exists('/work/stop'):\n    time.sleep(0.2)")} ${tag}`;
    const first = observe(rig, { prompt: "SC-S10-1", session, user: CREATOR_USER, steps: [bashStep(`${held}; echo A-DONE`)] });
    const workDir = (): string | null => {
      const id = entryOf(rig.gateway, "reqlift", session)?.sandboxDirId;
      return id ? path.join(conversationDir(rig.gateway, id), "work") : null;
    };
    for (const end = Date.now() + 90_000; !(workDir() && fs.existsSync(path.join(workDir()!, "held"))); await sleep(100)) if (Date.now() > end) throw new Error("A's run never reached its held command");
    const startsBefore = (rig.log().match(/SDK options:/g) ?? []).length;
    const modelBefore = rig.api.requests.length;
    const busy: { user: string | null; ms: number; events: unknown }[] = [];
    for (const [index, user] of [WRITER_USER, null].entries()) {
      const outcome = await rig.ask("reqlift", { queryId: `q-s10-${index}`, sessionId: session, prompt: `SC-S10-B${index}`, ...(user ? { user_id: user } : {}), useSession: true }, 10_000);
      busy.push({ user, ms: outcome.ms, events: outcome.events });
    }
    for (const entry of busy) {
      expect(entry.events, `user ${entry.user ?? "none"}`).toEqual([{ seq: 0, type: "error", content: BUSY_TEXT }]);
      expect(entry.ms).toBeLessThan(2000);
    }
    expect(rig.api.requests.length, "no model request for B").toBe(modelBefore);
    expect(requestsFor(rig.api, "SC-S10-B0")).toEqual([]);
    expect((rig.log().match(/SDK options:/g) ?? []).length, "no second runtime start").toBe(startsBefore);
    fs.writeFileSync(path.join(workDir()!, "stop"), "x");
    const done = await first;
    expect(eventsSayDone(done.events), "A's run was not disturbed").toBe(true);
    expect(done.results[0]?.text).toContain("A-DONE");
    // Free again: B's next request runs in the same conversation.
    const after = await observe(rig, { prompt: "SC-S10-2", session, user: WRITER_USER, steps: [bashStep("echo AFTER-OK")] });
    expect(eventsSayDone(after.events) && !refusalIn(after.events)).toBe(true);
    expect(after.results[0]?.text).toContain("AFTER-OK");
    emitEvidence("S10", { busy_answers: busy.length, max_busy_ms: Math.max(...busy.map((entry) => entry.ms)), model_requests_for_b: 0, runtime_starts_for_b: 0, free_afterwards: true });
  });
});
