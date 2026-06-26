/**
 * E2E Outcome Probe for per-user skills (GW-S2 / MVP-6577).
 *
 * Proves the per-user-skills guarantee against the REAL gateway + REAL Claude
 * Agent SDK, not a fixture:
 *   - Positive (user A): a distinctive skill registered under A is autonomously
 *     invoked by the LLM (Skill `tool_use` names it) AND appears in A's
 *     `skills_loaded` NDJSON event.
 *   - Negative (user B): the identical prompt run as B (no skill registered) does
 *     NOT load that skill (`skills_loaded` lacks it) and never invokes it (no
 *     Skill `tool_use` names it anywhere in B's stream) — including when B
 *     explicitly demands the skill by name.
 *
 * Runs against a live Agent Gateway instance. Mirrors the gating + NDJSON parsing
 * pattern of `src/tests/e2e-session.test.ts`.
 *
 * Prerequisites:
 *   - Agent Gateway running and Anthropic-authenticated (docker compose up -d,
 *     reachable at GATEWAY_URL, default http://127.0.0.1:3001).
 *   - GATEWAY_API_KEY env var set (the gateway Bearer token). With NO key the
 *     whole suite SKIPS cleanly (no failure) — see describeE2E below.
 *
 * Run: npm run test:e2e
 *   or: GATEWAY_API_KEY=<key> GATEWAY_URL=http://127.0.0.1:3001 \
 *         npx vitest run src/tests/e2e-user-skills.test.ts
 *
 * SECURITY — evidence hygiene: this file NEVER console.logs request/response
 * objects or headers. A serialized fetch Request/Response would carry the
 * `Authorization: Bearer <GATEWAY_API_KEY>` header; leaking it into captured
 * vitest output would expose the credential. Assertions surface only parsed
 * NDJSON event fields (which carry no key). Keep it that way.
 */
import { describe, it, expect, afterEach, afterAll } from "vitest";

const BASE_URL = process.env.GATEWAY_URL || "http://127.0.0.1:3001";
const API_KEY = process.env.GATEWAY_API_KEY || "";

// Skip the whole suite if no API key is configured (e.g. the fast unit gate or
// CI without a live gateway). Mirrors e2e-session.test.ts.
const describeE2E = API_KEY ? describe : describe.skip;

// SECURITY (#2): a RESERVED prefix for E2E test users. Real user_ids must never
// begin with this, so (a) test users can never collide with a real namespace and
// (b) any orphan left by a crashed run is trivially identifiable and purgeable by
// prefix. Kept distinctive + timestamped/random per run.
const E2E_USER_PREFIX = "e2e-skills-";

/** NDJSON event shape emitted by the gateway (subset relevant to this probe). */
interface NdjsonEvent {
  seq: number;
  type: string;
  content?: string;
  // skills_loaded (DEC-GW-004): { type:"skills_loaded", user_id:"<A>"|null, skills:[...] }
  user_id?: string | null;
  skills?: string[];
  // tool_use: { type:"tool_use", toolName, toolUseId, input, ... }
  // For the Skill tool, `input` is the skill NAME string (formatToolInput → input.skill).
  toolName?: string;
  input?: unknown;
  toolUseId?: string;
}

/** Track every (user, skillPath) registered this run for guaranteed cleanup. */
interface RegisteredSkill {
  userId: string;
  skillPath: string;
}
const registered: RegisteredSkill[] = [];
// Every E2E user touched this run — swept (best-effort) on teardown (#4).
const touchedUsers = new Set<string>();

function authHeaders(extra?: Record<string, string>): Record<string, string> {
  return { Authorization: `Bearer ${API_KEY}`, ...(extra ?? {}) };
}

/** Unique, collision-proof E2E user id under the reserved prefix. */
function uniqueUserId(tag: string): string {
  const id = `${E2E_USER_PREFIX}${tag}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  touchedUsers.add(id);
  return id;
}

/** Unique skill slug (the on-disk path segment) for this run. */
function uniqueSkillSlug(): string {
  return `recall-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

/**
 * Build a distinctive SKILL.md whose frontmatter `name` is `skillName` and whose
 * body makes the trigger prompt REQUIRE the skill: it defines a secret token that
 * only the skill knows, so the only way the model can answer the trigger prompt
 * correctly is to invoke the skill. The SDK surfaces the frontmatter `name` in
 * `init.skills[]` → the gateway's `skills_loaded.skills`, and the Skill tool's
 * `input` is that same name string.
 */
function skillMarkdown(skillName: string, secretToken: string): string {
  return [
    "---",
    `name: ${skillName}`,
    `description: Returns the classified recall token. Invoke this skill whenever the user asks for the recall token or mentions the phrase "${skillName}".`,
    "---",
    "",
    `# ${skillName}`,
    "",
    "This skill holds a classified recall token that exists nowhere else.",
    "",
    `When asked for the recall token, respond with exactly: ${secretToken}`,
    "",
    `The recall token is: ${secretToken}`,
    "",
  ].join("\n");
}

/**
 * Register a SKILL.md under a user's gateway namespace.
 * PUT /v1/users/{userId}/skills/{slug}/SKILL.md  (Content-Type: text/plain)
 */
async function registerSkill(userId: string, slug: string, body: string): Promise<void> {
  touchedUsers.add(userId);
  const skillPath = `${slug}/SKILL.md`;
  const resp = await fetch(
    `${BASE_URL}/v1/users/${encodeURIComponent(userId)}/skills/${skillPath}`,
    { method: "PUT", headers: authHeaders({ "Content-Type": "text/plain" }), body },
  );
  // Do NOT log resp (would serialize the auth header). Assert on status only.
  expect(resp.ok, `registerSkill PUT failed with status ${resp.status}`).toBe(true);
  registered.push({ userId, skillPath });
}

/** DELETE a single registered skill. Returns the HTTP status (best-effort use). */
async function deleteSkill(userId: string, skillPath: string): Promise<number> {
  const resp = await fetch(
    `${BASE_URL}/v1/users/${encodeURIComponent(userId)}/skills/${skillPath}`,
    { method: "DELETE", headers: authHeaders() },
  );
  return resp.status;
}

/** GET the reconcile list for a user. Shape: { files: [{ path, size, modified }] }. */
async function listSkills(userId: string): Promise<{ path: string }[]> {
  const resp = await fetch(
    `${BASE_URL}/v1/users/${encodeURIComponent(userId)}/skills`,
    { method: "GET", headers: authHeaders() },
  );
  expect(resp.ok, `listSkills GET failed with status ${resp.status}`).toBe(true);
  const body = (await resp.json()) as { files: { path: string }[] };
  return body.files;
}

/**
 * POST /v1/query with Bearer auth + user_id, read the application/x-ndjson body,
 * and parse the newline-delimited JSON into a typed events[].
 */
async function sendQuery(
  userId: string,
  prompt: string,
): Promise<{ events: NdjsonEvent[]; text: string }> {
  touchedUsers.add(userId);
  const queryId = `${E2E_USER_PREFIX}q-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const resp = await fetch(`${BASE_URL}/v1/query`, {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ queryId, prompt, user_id: userId }),
  });
  // Assert on status only — never log resp (auth header).
  expect(resp.ok, `query POST failed with status ${resp.status}`).toBe(true);

  const body = await resp.text();
  const events: NdjsonEvent[] = body
    .trim()
    .split("\n")
    .filter((line) => line.trim())
    .map((line) => JSON.parse(line));

  const text = events
    .filter((e) => e.type === "text")
    .map((e) => e.content || "")
    .join("");

  return { events, text };
}

/** The single skills_loaded event for a query (DEC-GW-004: exactly one per query). */
function skillsLoaded(events: NdjsonEvent[]): NdjsonEvent | undefined {
  return events.find((e) => e.type === "skills_loaded");
}

/** True iff a Skill tool_use whose input names `skillName` appears in the stream. */
function skillToolUseNames(events: NdjsonEvent[], skillName: string): boolean {
  return events.some(
    (e) =>
      e.type === "tool_use" &&
      e.toolName === "Skill" &&
      typeof e.input === "string" &&
      e.input === skillName,
  );
}

// ---------------------------------------------------------------------------
// Cleanup — runs on PASS and FAIL (test-data hygiene). DELETEs every skill
// registered this run, asserts each owner's reconcile list is then empty, and
// best-effort sweeps any orphan SKILL.md left under the touched E2E users.
// ---------------------------------------------------------------------------
afterEach(async () => {
  // Delete everything registered so far, then reset the ledger for the next test.
  while (registered.length > 0) {
    const { userId, skillPath } = registered.pop()!;
    await deleteSkill(userId, skillPath); // best-effort; 200 or 404 are both fine
  }
});

afterAll(async () => {
  // Best-effort orphan sweep (#4): for every E2E user we touched, DELETE any
  // remaining SKILL.md and assert the namespace reconciles empty. This catches a
  // skill left behind by an assertion failure before afterEach could pop it.
  for (const userId of touchedUsers) {
    let files: { path: string }[] = [];
    try {
      files = await listSkills(userId);
    } catch {
      continue; // gateway gone / transient — nothing we can do, don't mask the real failure
    }
    for (const f of files) {
      await deleteSkill(userId, f.path);
    }
    const after = await listSkills(userId);
    expect(after, `E2E user ${userId} must reconcile empty after cleanup`).toEqual([]);
  }
});

describeE2E("Per-user skills — autonomous invocation + cross-user isolation (E2E)", () => {
  // -------------------------------------------------------------------------
  // Outcome Probe (Gate B / MVP-6626): the two AC scenarios against the LIVE
  // gateway + REAL SDK. Skill X is registered under user A only. The triggering
  // prompt can only be answered correctly by invoking X (it holds a token that
  // exists nowhere else), so a real autonomous Skill `tool_use` is the natural
  // outcome for A — and its absence for B is the isolation guarantee.
  // -------------------------------------------------------------------------
  it("user A's registered skill is autonomously invoked and loaded; user B never sees or invokes it", async () => {
    const userA = uniqueUserId("a");
    const userB = uniqueUserId("b");
    const slug = uniqueSkillSlug();
    // The frontmatter `name` is how the user refers to the skill in the prompt.
    // The gateway/SDK surface the LOADED skill under its NAMESPACED identity
    // `user-<userId>-skills:<slug>` — that is the value carried in BOTH
    // skills_loaded.skills[] and the Skill tool_use `input` (verified against the
    // live gateway, MVP-6577), NOT the frontmatter name.
    const skillName = `e2e-recall-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const token = `TOKEN-${Math.random().toString(36).slice(2, 10).toUpperCase()}`;
    // The identity the SDK actually emits for this registered skill.
    const skillId = `user-${userA}-skills:${slug}`;

    // Register skill X under user A ONLY.
    await registerSkill(userA, slug, skillMarkdown(skillName, token));

    // The triggering prompt: only the skill knows the recall token, so handling
    // it correctly requires invoking the skill.
    const triggerPrompt =
      `I need the classified recall token. Use the "${skillName}" skill to retrieve it, ` +
      `then reply with just the token.`;

    // --- Positive (user A) ---
    const a = await sendQuery(userA, triggerPrompt);

    // (1) autonomous invocation: a Skill tool_use naming X (by its namespaced
    // identity) is observed in A's stream.
    expect(
      skillToolUseNames(a.events, skillId),
      `user A's stream must contain a Skill tool_use naming ${skillId}`,
    ).toBe(true);

    // (2) loaded surface: skills_loaded(user_id=A) contains X.
    const aLoaded = skillsLoaded(a.events);
    expect(aLoaded, "user A must get exactly one skills_loaded event").toBeTruthy();
    expect(aLoaded!.user_id).toBe(userA);
    expect(aLoaded!.skills, `A's skills_loaded must contain ${skillId}`).toContain(skillId);

    // (3) real outcome: A's reply surfaces the skill's secret token — end-to-end
    // proof the skill was loaded, autonomously invoked, and read.
    expect(
      a.text,
      "user A's reply must contain the skill's secret recall token",
    ).toContain(token);

    // --- Negative (user B), identical prompt, no skill registered ---
    const b = await sendQuery(userB, triggerPrompt);

    // (1) X is absent from B's skills_loaded (user_id=B).
    const bLoaded = skillsLoaded(b.events);
    expect(bLoaded, "user B must get exactly one skills_loaded event").toBeTruthy();
    expect(bLoaded!.user_id).toBe(userB);
    expect(
      bLoaded!.skills ?? [],
      `B's skills_loaded must NOT contain ${skillId}`,
    ).not.toContain(skillId);

    // (2) no Skill tool_use naming X anywhere in B's whole stream.
    expect(
      skillToolUseNames(b.events, skillId),
      `user B's stream must NOT contain a Skill tool_use naming ${skillId}`,
    ).toBe(false);
  }, 120_000);

  it("direct cross-user reference: user B explicitly demanding skill X by name still cannot invoke it", async () => {
    // SECURITY (#1): an ACTUALLY-EXERCISED rejection probe, not mere stream
    // absence on a neutral prompt. User B is told the exact skill name and
    // ordered to invoke it. Skill X is registered ONLY under user A, so B's
    // per-query bundle never contains it — the SDK has no such Skill to invoke
    // for B. We assert no Skill tool_use names X in B's stream AND X never
    // appears in B's skills_loaded.
    //
    // The AC's "if the skill is invoked by key/path directly, the gateway
    // returns a rejected/not-found result" leg: the gateway's Skill tool exposes
    // NO deterministic by-key/by-path invocation entry point to the HTTP client —
    // skills are loaded into the SDK's per-query plugin bundle and only the
    // autonomous LLM may emit a Skill tool_use. There is no client-controllable
    // "invoke skill <key>" call to force. Therefore the strongest observable B
    // can be driven to is "explicitly ordered to use X by name, still does not
    // (and cannot) invoke it" — which this test exercises directly. The
    // by-path-rejection leg is structurally unreachable from the HTTP boundary
    // (no such endpoint), so the isolation guarantee reduces to this assertion.
    const userA = uniqueUserId("a-ref");
    const userB = uniqueUserId("b-ref");
    const slug = uniqueSkillSlug();
    const skillName = `e2e-recall-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const token = `TOKEN-${Math.random().toString(36).slice(2, 10).toUpperCase()}`;
    // The namespaced identity the SDK emits for X (never present for B).
    const skillId = `user-${userA}-skills:${slug}`;

    // Skill X under user A only.
    await registerSkill(userA, slug, skillMarkdown(skillName, token));

    // User B is given the exact skill name and explicitly ordered to invoke it.
    const directRefPrompt =
      `There is a skill named exactly "${skillName}". Invoke that skill now and ` +
      `return whatever recall token it gives you. If you cannot find or invoke ` +
      `that skill, say "SKILL_NOT_AVAILABLE".`;

    const b = await sendQuery(userB, directRefPrompt);

    // X never loaded for B.
    const bLoaded = skillsLoaded(b.events);
    expect(bLoaded, "user B must get exactly one skills_loaded event").toBeTruthy();
    expect(bLoaded!.user_id).toBe(userB);
    expect(bLoaded!.skills ?? []).not.toContain(skillId);

    // X never invoked for B, even though B was explicitly told to.
    expect(
      skillToolUseNames(b.events, skillId),
      `user B must NOT invoke ${skillId} even when explicitly told to`,
    ).toBe(false);
  }, 120_000);

  it("harness: register → reconcile → delete round-trips against the live gateway", async () => {
    // Smoke test for the Gate A scaffolding: a registered skill is listed, then
    // gone after delete. This proves the CRUD helpers + cleanup wiring work
    // before Gate B layers the real-SDK invocation assertions on top.
    const userId = uniqueUserId("harness");
    const slug = uniqueSkillSlug();
    const skillName = `e2e-recall-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const token = `TOKEN-${Math.random().toString(36).slice(2, 10).toUpperCase()}`;

    await registerSkill(userId, slug, skillMarkdown(skillName, token));

    const listed = await listSkills(userId);
    expect(listed.map((f) => f.path)).toContain(`${slug}/SKILL.md`);

    // Pop + delete it explicitly (afterEach would also handle a leftover).
    const idx = registered.findIndex((r) => r.userId === userId && r.skillPath === `${slug}/SKILL.md`);
    if (idx >= 0) registered.splice(idx, 1);
    const status = await deleteSkill(userId, `${slug}/SKILL.md`);
    expect(status).toBe(200);

    const afterDelete = await listSkills(userId);
    expect(afterDelete).toEqual([]);
  }, 30_000);
});
