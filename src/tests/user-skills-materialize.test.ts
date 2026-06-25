import { describe, it, beforeEach, afterEach } from "vitest";
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
