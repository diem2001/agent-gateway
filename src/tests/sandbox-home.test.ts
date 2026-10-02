/**
 * The clean home and the work area of a conversation (MVP-7679, operator decision A2 of comment 38300,
 * sandbox-content.ts `prepareSandboxHome` and `prepareWorkArea`).
 *
 * Before every sandbox start the trusted side rebuilds the agent's home from nothing: only the runtime's data
 * directories carry over (transcripts, todos, plans, memory), every other home entry is removed without following
 * links, because the runtime and its children (`bash -l` for the shell snapshot, `git`) read the home by name at start.
 * The inventory below is written down here, independent of the production lookup; it is the set of paths measured at
 * start with a libc interposer inside the real sandbox (rework 3, step 1) plus the shell and git names no runtime
 * reads in the production image today. The real runtime rows are in tool-grant-process.test.ts.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { RUNTIME_WRITABLE_DIRS, SANDBOX_WORK, prepareSandboxHome, prepareWorkArea } from "../sandbox-content.js";

let home: string;
let work: string;
let outside: string;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), "sandbox-home-home-"));
  work = fs.mkdtempSync(path.join(os.tmpdir(), "sandbox-home-work-"));
  outside = fs.mkdtempSync(path.join(os.tmpdir(), "sandbox-home-outside-"));
  fs.writeFileSync(path.join(outside, "keep.txt"), "keep");
});

afterEach(() => {
  for (const dir of [home, work, outside]) fs.rmSync(dir, { recursive: true, force: true });
});

const dotClaude = () => path.join(home, ".claude");
const kept = () => fs.readFileSync(path.join(outside, "keep.txt"), "utf8");

/** Names the shell, git and the runtime read from the home root at start (measured), plus the sibling names of the same classes. */
const HOME_ROOT_INVENTORY = [
  ".bashrc", ".bash_profile", ".bash_login", ".profile", ".bash_logout",
  ".zshenv", ".zshrc", ".zprofile", ".zlogin", ".zlogout",
  ".gitconfig", ".config", ".git",
  ".claude.json", ".claude.json.backup", ".claude.json.tmp.2.1790929766730",
  ".mcp.json", "CLAUDE.md", ".ssh", ".npmrc", ".local", ".cache", "notes.txt", "future-dotfile-7679",
];

describe("the clean home", () => {
  it("the data allow-list is exactly the runtime's data directories", () => {
    expect([...RUNTIME_WRITABLE_DIRS]).toEqual(["memory", "plans", "projects", "todos"]);
  });

  it("every home-root entry except .claude is removed (files, directories, links), links are never followed", () => {
    for (const name of HOME_ROOT_INVENTORY) {
      if (name.startsWith(".config") || name === ".git" || name === ".ssh" || name === ".local" || name === ".cache") fs.mkdirSync(path.join(home, name, "nested"), { recursive: true });
      else fs.writeFileSync(path.join(home, name), "touch /home/node/m-evil\n");
    }
    fs.symlinkSync(outside, path.join(home, "linked-dir"));
    fs.symlinkSync(path.join(outside, "keep.txt"), path.join(home, ".bash_aliases"));
    fs.mkdirSync(dotClaude());
    prepareSandboxHome(home);
    expect(fs.readdirSync(home)).toEqual([".claude"]);
    expect(kept()).toBe("keep");
    expect(fs.readdirSync(outside)).toEqual(["keep.txt"]);
  });

  it("inventory: no agent-writable path the shell, git or the runtime read at start is left in place, the data survives", () => {
    for (const name of HOME_ROOT_INVENTORY.filter((n) => !n.startsWith(".config") && n !== ".git" && n !== ".ssh" && n !== ".local" && n !== ".cache")) fs.writeFileSync(path.join(home, name), "x");
    fs.mkdirSync(path.join(home, ".config", "git"), { recursive: true });
    fs.writeFileSync(path.join(home, ".config", "git", "config"), "[core]\n\tfsmonitor = touch /home/node/m-evil\n");
    fs.mkdirSync(path.join(home, ".git"));
    const data: Record<string, string> = {
      "projects/-work/s1.jsonl": "transcript",
      "projects/-work/agent-a1.jsonl": "sub-agent transcript",
      "todos/s1-agent-s1.json": "[]",
      "plans/p.md": "plan",
      "memory/m.md": "memory",
    };
    for (const [rel, text] of Object.entries(data)) {
      fs.mkdirSync(path.dirname(path.join(dotClaude(), rel)), { recursive: true });
      fs.writeFileSync(path.join(dotClaude(), rel), text);
    }
    // What the runtime reads under ~/.claude at start (measured): all of it goes, whatever it is.
    for (const name of [".config.json", ".credentials.json", "CLAUDE.md", "settings.local.json", "stats-cache.json", "rules", "ide", "image-cache", "file-history", "session-env", "shell-snapshots", "cache", "plugins"]) {
      fs.mkdirSync(path.join(dotClaude(), name, "nested"), { recursive: true });
    }
    prepareSandboxHome(home);
    const present: string[] = [];
    const walk = (dir: string, rel: string) => {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const next = rel ? `${rel}/${entry.name}` : entry.name;
        if (entry.isDirectory()) walk(path.join(dir, entry.name), next);
        else present.push(next);
      }
    };
    walk(home, "");
    expect(present.sort()).toEqual(Object.keys(data).map((rel) => `.claude/${rel}`).sort());
    for (const [rel, text] of Object.entries(data)) expect(fs.readFileSync(path.join(dotClaude(), rel), "utf8")).toBe(text);
  });

  it("under ~/.claude only the data directories stay; a data name that is a link or a file is removed, never followed", () => {
    fs.mkdirSync(dotClaude());
    fs.symlinkSync(outside, path.join(dotClaude(), "projects"));
    fs.writeFileSync(path.join(dotClaude(), "todos"), "x");
    fs.mkdirSync(path.join(dotClaude(), "plans"));
    fs.mkdirSync(path.join(dotClaude(), "memory"));
    fs.mkdirSync(path.join(dotClaude(), "commands", "nested"), { recursive: true });
    prepareSandboxHome(home);
    expect(fs.readdirSync(dotClaude()).sort()).toEqual(["memory", "plans"]);
    expect(kept()).toBe("keep");
  });

  it("under projects only the runtime's own transcript directories stay (names starting with -, real directories)", () => {
    const projects = path.join(dotClaude(), "projects");
    fs.mkdirSync(path.join(projects, "-work"), { recursive: true });
    fs.writeFileSync(path.join(projects, "-work", "s.jsonl"), "x");
    fs.mkdirSync(path.join(projects, "-home-node"));
    fs.mkdirSync(path.join(projects, "repo", ".git"), { recursive: true });
    fs.writeFileSync(path.join(projects, "-file"), "x");
    fs.writeFileSync(path.join(projects, "planted.json"), "x");
    fs.symlinkSync(outside, path.join(projects, "-link"));
    prepareSandboxHome(home);
    expect(fs.readdirSync(projects).sort()).toEqual(["-home-node", "-work"]);
    expect(fs.readFileSync(path.join(projects, "-work", "s.jsonl"), "utf8")).toBe("x");
    expect(kept()).toBe("keep");
  });

  it("a .claude that is a link is removed, never followed", () => {
    fs.writeFileSync(path.join(outside, ".config.json"), "{}");
    fs.symlinkSync(outside, dotClaude());
    prepareSandboxHome(home);
    expect(fs.readdirSync(home)).toEqual([]);
    expect(fs.existsSync(path.join(outside, ".config.json"))).toBe(true);
  });

  it("an empty or missing .claude, and a second pass, change nothing", () => {
    prepareSandboxHome(home);
    expect(fs.readdirSync(home)).toEqual([]);
    fs.mkdirSync(path.join(dotClaude(), "todos"), { recursive: true });
    fs.writeFileSync(path.join(dotClaude(), "todos", "t.json"), "[]");
    prepareSandboxHome(home);
    prepareSandboxHome(home);
    expect(fs.readFileSync(path.join(dotClaude(), "todos", "t.json"), "utf8")).toBe("[]");
  });
});

describe("the work area", () => {
  it("is /work inside the sandbox", () => {
    expect(SANDBOX_WORK).toBe("/work");
  });

  it("the agent's files stay, and project settings in it are left alone (they are inert: the runtime reads the user source only)", () => {
    fs.mkdirSync(path.join(work, ".claude", "agents"), { recursive: true });
    fs.writeFileSync(path.join(work, ".mcp.json"), "{}");
    fs.writeFileSync(path.join(work, "CLAUDE.md"), "x");
    fs.writeFileSync(path.join(work, "notes.txt"), "notes");
    prepareWorkArea(work);
    expect(fs.readdirSync(work).sort()).toEqual([".claude", ".mcp.json", "CLAUDE.md", "notes.txt"]);
  });

  it("a .git that is a file (a gitdir pointer) or a link is removed without being followed", () => {
    fs.writeFileSync(path.join(work, ".git"), "gitdir: /home/node/elsewhere\n");
    prepareWorkArea(work);
    expect(fs.existsSync(path.join(work, ".git"))).toBe(false);
    fs.mkdirSync(path.join(outside, "bare"));
    fs.writeFileSync(path.join(outside, "bare", "config"), "[core]\n\tfsmonitor = touch /x\n");
    fs.symlinkSync(path.join(outside, "bare"), path.join(work, ".git"));
    prepareWorkArea(work);
    expect(fs.existsSync(path.join(work, ".git"))).toBe(false);
    expect(fs.readFileSync(path.join(outside, "bare", "config"), "utf8")).toContain("fsmonitor");
  });

  it("any .git at the work root is removed at every start (a real directory, a commondir pointer, a worktree config): no repository is a supported scenario there", () => {
    const git = path.join(work, ".git");
    fs.mkdirSync(path.join(git, "objects"), { recursive: true });
    fs.writeFileSync(path.join(git, "HEAD"), "ref: refs/heads/main\n");
    fs.writeFileSync(path.join(git, "config"), "[core]\n\trepositoryformatversion = 1\n\tfsmonitor = touch /work/m-fsmonitor\n[extensions]\n\tworktreeConfig = true\n");
    fs.writeFileSync(path.join(git, "config.worktree"), "[core]\n\tfsmonitor = touch /work/m-worktreecfg\n");
    fs.writeFileSync(path.join(git, "commondir"), "../evil\n");
    fs.mkdirSync(path.join(work, "evil"));
    fs.writeFileSync(path.join(work, "evil", "config"), "[core]\n\tfsmonitor = touch /work/m-commondir\n");
    prepareWorkArea(work);
    expect(fs.existsSync(git)).toBe(false);
    // Only the .git entry goes: the agent's other files stay.
    expect(fs.existsSync(path.join(work, "evil", "config"))).toBe(true);
  });

  it("a .git directory that holds a link or a directory named config is removed whole, nothing outside is followed", () => {
    const git = path.join(work, ".git");
    fs.mkdirSync(git);
    fs.symlinkSync(path.join(outside, "keep.txt"), path.join(git, "config"));
    prepareWorkArea(work);
    expect(fs.existsSync(git)).toBe(false);
    expect(kept()).toBe("keep");
  });

  it("repositories below the work area are not touched", () => {
    fs.mkdirSync(path.join(work, "sub", ".git"), { recursive: true });
    fs.writeFileSync(path.join(work, "sub", ".git", "config"), "[core]\n\tfsmonitor = x\n");
    prepareWorkArea(work);
    expect(fs.readFileSync(path.join(work, "sub", ".git", "config"), "utf8")).toContain("fsmonitor");
  });
});
