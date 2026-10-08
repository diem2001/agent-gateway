import { describe, it, beforeEach, afterEach, vi } from "vitest";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

// WORKSPACE_ROOT is read at import time by the workspace module; set it first.
const TEST_WORKSPACE = fs.mkdtempSync(path.join(os.tmpdir(), "agw-mat-test-"));
process.env.WORKSPACE_ROOT = TEST_WORKSPACE;

const { getUserSkillsDir } = await import("../workspace.js");
const { materializeUserSkills, cleanupUserSkillBundle } = await import("../user-skills.js");

function writeUserSkill(userId: string, subpath: string, content: string): void {
  const base = getUserSkillsDir(userId)!;
  const full = path.join(base, subpath);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content);
}

const SKILL = "---\nname: x\ndescription: y\n---\nbody\n";

describe("materializeUserSkills (Gate B bundle + Gate C caps)", () => {
  const roots: string[] = [];

  beforeEach(() => {
    fs.rmSync(path.join(TEST_WORKSPACE, "users"), { recursive: true, force: true });
    delete process.env.USER_SKILLS_MAX_COUNT;
    delete process.env.USER_SKILLS_MAX_BYTES;
  });

  afterEach(() => {
    for (const r of roots) cleanupUserSkillBundle(r);
    roots.length = 0;
  });

  it("returns null pluginRoot when userId is undefined (global-only load)", () => {
    const res = materializeUserSkills(undefined);
    assert.equal(res.pluginRoot, null);
    assert.deepEqual(res.dropped, []);
  });

  it("returns null pluginRoot when the namespace is empty", () => {
    const res = materializeUserSkills("nobody");
    assert.equal(res.pluginRoot, null);
  });

  it("materializes a valid local-plugin bundle for a user's skill", () => {
    writeUserSkill("alice", "deploy/SKILL.md", SKILL);
    const res = materializeUserSkills("alice");
    assert.ok(res.pluginRoot, "expected a plugin root");
    roots.push(res.pluginRoot!);

    // plugin.json contract
    const meta = JSON.parse(fs.readFileSync(path.join(res.pluginRoot!, ".claude-plugin", "plugin.json"), "utf-8"));
    assert.equal(meta.name, "user-alice-skills");
    assert.equal(meta.version, "0.0.0");

    // skills/<slug>/SKILL.md exists with the stored bytes
    const skillsDir = path.join(res.pluginRoot!, "skills");
    const slugs = fs.readdirSync(skillsDir);
    assert.equal(slugs.length, 1);
    const skillMd = path.join(skillsDir, slugs[0], "SKILL.md");
    assert.ok(fs.existsSync(skillMd));
    assert.equal(fs.readFileSync(skillMd, "utf-8"), SKILL);
    assert.deepEqual(res.dropped, []);
    assert.equal(res.reason, null);
  });

  it("enforces the count cap deterministically and reports count_cap", () => {
    process.env.USER_SKILLS_MAX_COUNT = "2";
    writeUserSkill("bob", "a/SKILL.md", SKILL);
    writeUserSkill("bob", "b/SKILL.md", SKILL);
    writeUserSkill("bob", "c/SKILL.md", SKILL);
    const res = materializeUserSkills("bob");
    roots.push(res.pluginRoot!);
    // Path-sorted: a, b kept; c dropped.
    assert.deepEqual(res.dropped, ["c/SKILL.md"]);
    assert.equal(res.reason, "count_cap");
    assert.equal(fs.readdirSync(path.join(res.pluginRoot!, "skills")).length, 2);
  });

  it("enforces the byte cap and reports size_cap", () => {
    // Cap small enough that only the first skill fits.
    process.env.USER_SKILLS_MAX_BYTES = String(SKILL.length + 1);
    writeUserSkill("carol", "a/SKILL.md", SKILL);
    writeUserSkill("carol", "b/SKILL.md", SKILL);
    const res = materializeUserSkills("carol");
    if (res.pluginRoot) roots.push(res.pluginRoot);
    assert.deepEqual(res.dropped, ["b/SKILL.md"]);
    assert.equal(res.reason, "size_cap");
  });
});

describe("materializeUserSkills for a run without Bash (MVP-8106)", () => {
  const roots: string[] = [];
  const HOOKED = "---\nname: probe\ndescription: d\nhooks:\n  Stop:\n    - hooks:\n        - type: command\n          command: touch /work/m-USERHOOK\n---\nUSER-INSTRUCTION\n";
  const NEUTRAL = '---\nname: "probe"\ndescription: "d"\n---\nUSER-INSTRUCTION\n';
  let logs: string[] = [];

  beforeEach(() => {
    fs.rmSync(path.join(TEST_WORKSPACE, "users"), { recursive: true, force: true });
    delete process.env.USER_SKILLS_MAX_COUNT;
    delete process.env.USER_SKILLS_MAX_BYTES;
    logs = [];
    vi.spyOn(console, "log").mockImplementation((...args) => {
      logs.push(args.map(String).join(" "));
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    for (const r of roots) cleanupUserSkillBundle(r);
    roots.length = 0;
  });

  const skillOf = (root: string | null): string => {
    assert.ok(root, "expected a plugin root");
    roots.push(root!);
    const slugs = fs.readdirSync(path.join(root!, "skills"));
    return fs.readFileSync(path.join(root!, "skills", slugs[0], "SKILL.md"), "utf-8");
  };

  it("writes the rewritten text into the bundle and leaves the stored file as it was", () => {
    writeUserSkill("dave", "probe/SKILL.md", HOOKED);
    const res = materializeUserSkills("dave", { neutralizeCommands: true, label: "reqlift" });
    assert.equal(skillOf(res.pluginRoot), NEUTRAL);
    assert.equal(fs.readFileSync(path.join(getUserSkillsDir("dave")!, "probe", "SKILL.md"), "utf-8"), HOOKED);
    assert.deepEqual(res.dropped, []);
  });

  it("copies the text verbatim without the option or with it false", () => {
    writeUserSkill("erin", "probe/SKILL.md", HOOKED);
    assert.equal(skillOf(materializeUserSkills("erin").pluginRoot), HOOKED);
    assert.equal(skillOf(materializeUserSkills("erin", { neutralizeCommands: false }).pluginRoot), HOOKED);
    assert.ok(!logs.join("\n").includes("command-settings"));
  });

  it("keeps the caps on the stored bytes, so the same skills are loaded and dropped as without the option", () => {
    process.env.USER_SKILLS_MAX_COUNT = "2";
    for (const name of ["a", "b", "c"]) writeUserSkill("frank", `${name}/SKILL.md`, HOOKED);
    const plain = materializeUserSkills("frank");
    roots.push(plain.pluginRoot!);
    const neutral = materializeUserSkills("frank", { neutralizeCommands: true, label: "reqlift" });
    roots.push(neutral.pluginRoot!);
    assert.deepEqual(neutral.dropped, plain.dropped);
    assert.equal(neutral.reason, plain.reason);
    assert.deepEqual(fs.readdirSync(path.join(neutral.pluginRoot!, "skills")), fs.readdirSync(path.join(plain.pluginRoot!, "skills")));
    // A skill whose rewrite is shorter than the stored file still counts its stored size against the byte cap.
    process.env.USER_SKILLS_MAX_COUNT = "50";
    process.env.USER_SKILLS_MAX_BYTES = String(HOOKED.length + 1);
    const capped = materializeUserSkills("frank", { neutralizeCommands: true });
    roots.push(capped.pluginRoot!);
    assert.equal(capped.reason, "size_cap");
    assert.equal(capped.dropped.length, 2);
  });

  it("logs one content-free line per rewritten file: label, source, name and the kind of setting", () => {
    writeUserSkill("gina", "probe/SKILL.md", HOOKED);
    writeUserSkill("gina", "clean/SKILL.md", "---\nname: clean\n---\nbody\n");
    const res = materializeUserSkills("gina", { neutralizeCommands: true, label: "reqlift" });
    roots.push(res.pluginRoot!);
    const lines = logs.filter((line) => line.includes("command-settings"));
    assert.deepEqual(lines, ["[audit] command-settings.ignored label=reqlift source=user-skills name=probe setting=hooks"]);
    assert.ok(!logs.join("\n").includes("USERHOOK"));
    assert.ok(!logs.join("\n").includes(TEST_WORKSPACE));
  });

  it("rewrites a file whose frontmatter cannot be read to an empty gateway block above the original text", () => {
    const odd = "---\nname: a\nname: b\nhooks: x\n---\nbody\n";
    writeUserSkill("hank", "odd/SKILL.md", odd);
    const res = materializeUserSkills("hank", { neutralizeCommands: true, label: "reqlift" });
    assert.equal(skillOf(res.pluginRoot), `---\n---\n${odd}`);
    assert.ok(logs.some((line) => line.endsWith("name=odd setting=unparseable")));
  });
});
