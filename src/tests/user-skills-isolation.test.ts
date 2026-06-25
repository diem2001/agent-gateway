import { beforeEach, afterEach, describe, expect, it, vi } from "vitest";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import type { StreamEvent } from "../event-cache.js";

/**
 * Outcome Probe for GW-S1 (MVP-6578 / Gate D) — the Epic cross-user isolation
 * invariant proven WITHOUT live SDK credentials.
 *
 * Pattern mirrors src/tests/concurrent-isolation.test.ts: mock the Claude Agent
 * SDK `query()`, capture `options` per call, and synthesize an `init` system
 * message. The synthetic init's `skills[]` is derived from the bundle the gateway
 * materialized at `options.plugins[].path` (the SDK loads `skills/<slug>/SKILL.md`
 * and surfaces each skill's frontmatter `name`) PLUS a fixed set of global skills,
 * exactly as the real SDK would. The gateway then emits `skills_loaded` from that
 * init message — the durable black-box surface this probe asserts.
 */

const TEST_WORKSPACE = fs.mkdtempSync(path.join(os.tmpdir(), "agw-isolation-test-"));
process.env.WORKSPACE_ROOT = TEST_WORKSPACE;

// Global skills that always load (independent of any user) — proves the per-user
// bundle is ADDITIVE, not a replacement.
const GLOBAL_SKILLS = ["global-skill-a", "global-skill-b"];

let sdkOptions: Array<Record<string, unknown>> = [];

/** Read the frontmatter `name:` of every SKILL.md in a materialized plugin bundle. */
function skillNamesFromBundle(pluginRoot: string | undefined): string[] {
  if (!pluginRoot) return [];
  const skillsDir = path.join(pluginRoot, "skills");
  if (!fs.existsSync(skillsDir)) return [];
  const names: string[] = [];
  for (const slug of fs.readdirSync(skillsDir)) {
    const file = path.join(skillsDir, slug, "SKILL.md");
    if (!fs.existsSync(file)) continue;
    const content = fs.readFileSync(file, "utf-8");
    const m = content.match(/^name:\s*(.+)$/m);
    names.push(m ? m[1].trim() : slug);
  }
  return names;
}

beforeEach(() => {
  vi.resetModules();
  sdkOptions = [];
  fs.rmSync(path.join(TEST_WORKSPACE, "users"), { recursive: true, force: true });
  delete process.env.USER_SKILLS_MAX_COUNT;
  delete process.env.USER_SKILLS_MAX_BYTES;

  vi.doMock("@anthropic-ai/claude-agent-sdk", () => ({
    createSdkMcpServer: vi.fn((options) => ({ type: "sdk", name: options.name })),
    query: vi.fn(({ options }) => {
      sdkOptions.push(options as Record<string, unknown>);
      // Resolve this call's per-user bundle path (if any) and derive loaded skills.
      const plugins = (options as { plugins?: Array<{ type: string; path: string }> }).plugins;
      const userBundleRoot = plugins && plugins[0] ? plugins[0].path : undefined;
      const loaded = [...GLOBAL_SKILLS, ...skillNamesFromBundle(userBundleRoot)];
      return (async function* () {
        // Synthetic init system message carrying the authoritative loaded skill set.
        yield { type: "system", subtype: "init", skills: loaded, session_id: "sdk-session" };
        yield { type: "result", usage: {}, total_cost_usd: 0, sessionId: "sdk-session" };
      })();
    }),
  }));
});

afterEach(() => {
  vi.doUnmock("@anthropic-ai/claude-agent-sdk");
});

function writeUserSkill(userId: string, subpath: string, name: string): void {
  const base = path.join(TEST_WORKSPACE, "users", userId, "skills");
  const full = path.join(base, subpath);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, `---\nname: ${name}\ndescription: test skill\n---\n\nbody for ${name}\n`);
}

async function runFor(userId: string | undefined): Promise<{ events: StreamEvent[]; options: Record<string, unknown> }> {
  const { runQuery } = await import("../agent.js");
  const events: StreamEvent[] = [];
  const before = sdkOptions.length;
  await runQuery({
    prompt: "do the thing",
    abortController: new AbortController(),
    onEvent: (e) => events.push(e as StreamEvent),
    userId,
  });
  return { events, options: sdkOptions[before] };
}

function skillsLoaded(events: StreamEvent[]): StreamEvent | undefined {
  return events.find((e) => e.type === "skills_loaded");
}

describe("GW-S1 Outcome Probe — cross-user skill isolation (mocked SDK)", () => {
  it("user A sees skill X; user B does not; both retain global skills", async () => {
    // reqlift PUTs skill X to users/A/skills
    writeUserSkill("A", "x/SKILL.md", "skill-x");

    const a = await runFor("A");
    const b = await runFor("B");

    // A's query: plugins point at A's namespace, skills_loaded includes X, user_id=A
    const aPlugins = a.options.plugins as Array<{ type: string; path: string }> | undefined;
    expect(aPlugins, "A's query must set plugins").toBeTruthy();
    expect(aPlugins![0].type).toBe("local");
    expect(aPlugins![0].path).toContain("agw-userskills-");
    const aLoaded = skillsLoaded(a.events);
    expect(aLoaded, "A must get a skills_loaded event").toBeTruthy();
    expect(aLoaded!.user_id).toBe("A");
    expect(aLoaded!.skills).toContain("skill-x");
    // Global skills present (additive)
    for (const g of GLOBAL_SKILLS) expect(aLoaded!.skills).toContain(g);

    // B's query: skill X absent, user_id=B, global skills still present.
    const bLoaded = skillsLoaded(b.events);
    expect(bLoaded, "B must get a skills_loaded event").toBeTruthy();
    expect(bLoaded!.user_id).toBe("B");
    expect(bLoaded!.skills).not.toContain("skill-x");
    for (const g of GLOBAL_SKILLS) expect(bLoaded!.skills).toContain(g);
    // B has no skills → no plugins set (global-only).
    expect(b.options.plugins).toBeUndefined();
  });

  it("a query carrying no user_id loads global-only and emits user_id=null", async () => {
    const r = await runFor(undefined);
    expect(r.options.plugins).toBeUndefined();
    const loaded = skillsLoaded(r.events);
    expect(loaded!.user_id).toBeNull();
    expect(loaded!.skills).toEqual(GLOBAL_SKILLS);
  });

  it("exactly one skills_loaded event is emitted per query", async () => {
    writeUserSkill("A", "x/SKILL.md", "skill-x");
    const a = await runFor("A");
    expect(a.events.filter((e) => e.type === "skills_loaded")).toHaveLength(1);
  });

  it("caps overflow emits skills_truncated and the query still completes", async () => {
    process.env.USER_SKILLS_MAX_COUNT = "1";
    writeUserSkill("A", "a/SKILL.md", "skill-a");
    writeUserSkill("A", "b/SKILL.md", "skill-b");

    const a = await runFor("A");

    const truncated = a.events.find((e) => e.type === "skills_truncated");
    expect(truncated, "must emit skills_truncated on overflow").toBeTruthy();
    expect(truncated!.reason).toBe("count_cap");
    expect(truncated!.dropped).toEqual(["b/SKILL.md"]);
    // Query still completed → it emitted skills_loaded with the surviving skill.
    const loaded = skillsLoaded(a.events);
    expect(loaded, "query must still run and load the remaining skill").toBeTruthy();
    expect(loaded!.skills).toContain("skill-a");
    expect(loaded!.skills).not.toContain("skill-b");
  });

  it("after DELETE, user A's next query no longer lists the skill", async () => {
    writeUserSkill("A", "x/SKILL.md", "skill-x");
    const before = await runFor("A");
    expect(skillsLoaded(before.events)!.skills).toContain("skill-x");

    // reqlift DELETEs the skill.
    fs.rmSync(path.join(TEST_WORKSPACE, "users", "A", "skills", "x"), { recursive: true, force: true });

    const after = await runFor("A");
    const loaded = skillsLoaded(after.events);
    expect(loaded!.skills).not.toContain("skill-x");
    // Namespace now empty → no plugins set.
    expect(after.options.plugins).toBeUndefined();
  });
});
