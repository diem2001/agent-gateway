/**
 * The mount plan of the extension directories (MVP-7679, QA rework 2): the sandbox sees the workspace entry read-only,
 * or a trusted EMPTY one when the workspace has none or the entry fails the no-follow checks, never the agent-writable
 * directory underneath. The clean home that removes everything else the agent wrote is in sandbox-home.test.ts; the
 * real runtime rows are in tool-grant-process.test.ts.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { planTrustedContent } from "../sandbox-content.js";

let outside: string;

beforeEach(() => {
  outside = fs.mkdtempSync(path.join(os.tmpdir(), "sandbox-runtime-config-outside-"));
});

afterEach(() => {
  fs.rmSync(outside, { recursive: true, force: true });
});

describe("the mount plan binds trusted EMPTY content wherever the workspace has no trusted entry", () => {
  const EXTENSION_ENTRIES = ["commands", "agents", "skills", "output-styles", "plugins", "hooks", "CLAUDE.md"];
  const planFor = (workspace: string) => {
    const trustedDir = fs.mkdtempSync(path.join(os.tmpdir(), "sandbox-runtime-config-trusted-"));
    return { plan: planTrustedContent({ workspaceRoot: workspace, trustedDir, needles: [] }), trustedDir };
  };

  it("an empty workspace: every extension entry is mounted from an empty source", () => {
    const { plan, trustedDir } = planFor(outside);
    try {
      for (const name of EXTENSION_ENTRIES) {
        const mount = plan.mounts.find((m) => m.dest === `/home/node/.claude/${name}`);
        expect(mount, name).toBeDefined();
        const stat = fs.lstatSync(mount!.src);
        if (name === "CLAUDE.md") expect(stat.isFile() && stat.size === 0, name).toBe(true);
        else expect(stat.isDirectory() && fs.readdirSync(mount!.src).length === 0, name).toBe(true);
        expect(mount!.src.startsWith(outside), `${name}: not a workspace path`).toBe(false);
      }
    } finally {
      fs.rmSync(trustedDir, { recursive: true, force: true });
    }
  });

  it("an entry that is a link in the workspace is replaced by an empty source, not skipped", () => {
    fs.mkdirSync(path.join(outside, "elsewhere"));
    fs.symlinkSync(path.join(outside, "elsewhere"), path.join(outside, "commands"));
    const { plan, trustedDir } = planFor(outside);
    try {
      const mount = plan.mounts.find((m) => m.dest === "/home/node/.claude/commands");
      expect(mount).toBeDefined();
      expect(fs.readdirSync(mount!.src)).toEqual([]);
    } finally {
      fs.rmSync(trustedDir, { recursive: true, force: true });
    }
  });

  it("a trusted workspace entry is still the source when it exists", () => {
    fs.mkdirSync(path.join(outside, "commands"));
    fs.writeFileSync(path.join(outside, "commands", "c.md"), "x");
    const { plan, trustedDir } = planFor(outside);
    try {
      const mount = plan.mounts.find((m) => m.dest === "/home/node/.claude/commands");
      expect(fs.realpathSync(mount!.src)).toBe(fs.realpathSync(path.join(outside, "commands")));
    } finally {
      fs.rmSync(trustedDir, { recursive: true, force: true });
    }
  });
});
