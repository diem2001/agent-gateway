/**
 * What an agent sandbox may see of the trusted workspace (src/sandbox-content.ts): no-follow
 * validation of every bind source and trusted read, planted symlinks in every position, the
 * allowlist-generated git configuration, the known-value scan and the mount plan.
 * All secret values are synthetic.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  KnownValueScanner,
  allowlistGitConfig,
  assertNoSymlinkComponents,
  checkTrusted,
  copyFileNoFollow,
  knownSecretValues,
  listRegularFilesNoFollow,
  planTrustedContent,
  prepareMountPoints,
  readFileNoFollow,
  stripUrlUserInfo,
} from "../sandbox-content.js";

const SECRET = "SYNTH-CRED-ACCESS-TOKEN-7678-abcdef";
const TOKEN_URL_SECRET = "SYNTH-CLONE-TOKEN-7678-xyz";

let root: string;
let logs: string[];

beforeEach(() => {
  root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "sandbox-content-")));
  logs = [];
  vi.spyOn(console, "log").mockImplementation((...args) => {
    logs.push(args.map(String).join(" "));
  });
});

afterEach(() => {
  vi.restoreAllMocks();
  fs.rmSync(root, { recursive: true, force: true });
});

function write(rel: string, content: string): string {
  const file = path.join(root, rel);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content);
  return file;
}

describe("checkTrusted", () => {
  it("accepts a regular file and a directory inside the root", () => {
    write("ws/CLAUDE.md", "x");
    fs.mkdirSync(path.join(root, "ws", "skills"));
    expect(checkTrusted(path.join(root, "ws", "CLAUDE.md"), "file", root).ok).toBe(true);
    expect(checkTrusted(path.join(root, "ws", "skills"), "dir", root).ok).toBe(true);
  });

  it("refuses a symlink (to a file, a directory, a dangling target), a missing path and the wrong type", () => {
    write("secret/creds.json", "x");
    fs.mkdirSync(path.join(root, "ws"));
    fs.symlinkSync(path.join(root, "secret", "creds.json"), path.join(root, "ws", "link-file"));
    fs.symlinkSync(path.join(root, "secret"), path.join(root, "ws", "link-dir"));
    fs.symlinkSync(path.join(root, "nowhere"), path.join(root, "ws", "dangling"));
    fs.mkdirSync(path.join(root, "ws", "dir"));
    write("ws/file", "x");
    const reason = (p: string, kind: "file" | "dir") => {
      const check = checkTrusted(path.join(root, "ws", p), kind, root);
      return check.ok ? "ok" : check.reason;
    };
    expect(reason("link-file", "file")).toBe("symlink");
    expect(reason("link-dir", "dir")).toBe("symlink");
    expect(reason("dangling", "file")).toBe("symlink");
    expect(reason("missing", "file")).toBe("missing");
    expect(reason("dir", "file")).toBe("wrong_type");
    expect(reason("file", "dir")).toBe("wrong_type");
  });

  it("refuses a path with a symlink in a parent component and a path outside the root", () => {
    write("secret/inner/file", "x");
    fs.mkdirSync(path.join(root, "ws"));
    fs.symlinkSync(path.join(root, "secret"), path.join(root, "ws", "parent"));
    expect((checkTrusted(path.join(root, "ws", "parent", "inner", "file"), "file", root) as { reason: string }).reason).toBe("symlink");
    expect((checkTrusted(path.join(root, "secret", "inner", "file"), "file", path.join(root, "ws")) as { reason: string }).reason).toBe("outside_root");
  });
});

describe("no-follow reads, listings and copies", () => {
  it("reads a regular file and refuses a final symlink, a directory and an oversized file", () => {
    const real = write("a/real.txt", "hello");
    fs.symlinkSync(real, path.join(root, "a", "link.txt"));
    expect(readFileNoFollow(real)?.toString()).toBe("hello");
    expect(readFileNoFollow(path.join(root, "a", "link.txt"))).toBeNull();
    expect(readFileNoFollow(path.join(root, "a"))).toBeNull();
    expect(readFileNoFollow(real, 3)).toBeNull();
    expect(readFileNoFollow(path.join(root, "nope"))).toBeNull();
  });

  it("lists regular files only: symlinks to files and directories are neither listed nor entered", () => {
    write("skills/a.md", "a");
    write("skills/sub/b.md", "b");
    write("outside/secret.md", "s");
    fs.symlinkSync(path.join(root, "outside", "secret.md"), path.join(root, "skills", "link.md"));
    fs.symlinkSync(path.join(root, "outside"), path.join(root, "skills", "linkdir"));
    fs.symlinkSync(path.join(root, "outside"), path.join(root, "skills", "sub", "deeper"));
    expect(listRegularFilesNoFollow(path.join(root, "skills")).map((f) => f.path).sort()).toEqual(["a.md", "sub/b.md"]);
  });

  it("lists nothing for a base that is a symlink or missing", () => {
    write("outside/x.md", "x");
    fs.symlinkSync(path.join(root, "outside"), path.join(root, "base"));
    expect(listRegularFilesNoFollow(path.join(root, "base"))).toEqual([]);
    expect(listRegularFilesNoFollow(path.join(root, "missing"))).toEqual([]);
  });

  it("copies a regular file and refuses a symlink source", () => {
    const real = write("s/real.md", "content");
    fs.symlinkSync(real, path.join(root, "s", "link.md"));
    expect(copyFileNoFollow(real, path.join(root, "copy1"))).toBe(true);
    expect(fs.readFileSync(path.join(root, "copy1"), "utf8")).toBe("content");
    expect(copyFileNoFollow(path.join(root, "s", "link.md"), path.join(root, "copy2"))).toBe(false);
    expect(fs.existsSync(path.join(root, "copy2"))).toBe(false);
  });

  it("finds a symlink component below a base", () => {
    fs.mkdirSync(path.join(root, "home", ".claude"), { recursive: true });
    fs.mkdirSync(path.join(root, "elsewhere"));
    fs.symlinkSync(path.join(root, "elsewhere"), path.join(root, "home", ".claude", "skills"));
    expect(assertNoSymlinkComponents(path.join(root, "home"), ".claude/skills/x")).toBe(false);
    expect(assertNoSymlinkComponents(path.join(root, "home"), ".claude/agents/x")).toBe(true);
  });
});

describe("mount points in an agent-writable home", () => {
  it("removes a planted symlink parent and a wrong-typed destination, never touching what a link pointed to", () => {
    const home = path.join(root, "home");
    fs.mkdirSync(path.join(home, ".claude", "projects"), { recursive: true });
    const victim = write("victim/keep.txt", "keep");
    // `.claude/skills` is a link to a directory outside; `.claude/CLAUDE.md` is a directory (a file is mounted);
    // `.claude/agents` is a file (a directory is mounted); `.claude/projects/repo` is a link.
    fs.symlinkSync(path.join(root, "victim"), path.join(home, ".claude", "skills"));
    fs.mkdirSync(path.join(home, ".claude", "CLAUDE.md"));
    fs.writeFileSync(path.join(home, ".claude", "agents"), "file");
    fs.symlinkSync(path.join(root, "victim"), path.join(home, ".claude", "projects", "repo"));
    write("ws/CLAUDE.md", "x");
    fs.mkdirSync(path.join(root, "ws", "skills"));
    fs.mkdirSync(path.join(root, "ws", "agents"));
    fs.mkdirSync(path.join(root, "ws", "repo"));
    prepareMountPoints(
      home,
      [
        { src: path.join(root, "ws", "CLAUDE.md"), dest: "/home/node/.claude/CLAUDE.md" },
        { src: path.join(root, "ws", "skills"), dest: "/home/node/.claude/skills/deep" },
        { src: path.join(root, "ws", "agents"), dest: "/home/node/.claude/agents" },
        { src: path.join(root, "ws", "repo"), dest: "/home/node/.claude/projects/repo" },
      ],
      [],
    );
    for (const p of ["skills", "CLAUDE.md", "agents", "projects/repo"]) expect(fs.existsSync(path.join(home, ".claude", p)), p).toBe(false);
    expect(fs.readFileSync(victim, "utf8")).toBe("keep");
  });

  it("leaves a matching existing directory mount point alone", () => {
    const home = path.join(root, "home");
    fs.mkdirSync(path.join(home, ".claude", "skills"), { recursive: true });
    fs.writeFileSync(path.join(home, ".claude", "skills", "note"), "mine");
    fs.mkdirSync(path.join(root, "ws", "skills"), { recursive: true });
    prepareMountPoints(home, [{ src: path.join(root, "ws", "skills"), dest: "/home/node/.claude/skills" }], []);
    expect(fs.readFileSync(path.join(home, ".claude", "skills", "note"), "utf8")).toBe("mine");
  });
});

describe("git configuration allowlist", () => {
  const RAW = `
[core]
	repositoryformatversion = 0
	filemode = true
	sshCommand = ssh -i /home/node/.ssh/id_rsa
	askpass = /usr/bin/leak-askpass
	fsmonitor = /usr/bin/leak-monitor
	hooksPath = /tmp/evil-hooks
[remote "origin"]
	url = https://x-access-token:${TOKEN_URL_SECRET}@github.com/acme/repo.git
	fetch = +refs/heads/*:refs/remotes/origin/*
	pushurl = https://x:${TOKEN_URL_SECRET}@github.com/acme/repo.git
	mirror = true
[branch "main"]
	remote = origin
	merge = refs/heads/main
[url "https://${TOKEN_URL_SECRET}@github.com/"]
	insteadOf = https://github.com/
[http "https://github.com/"]
	extraheader = AUTHORIZATION: bearer ${TOKEN_URL_SECRET}
[credential]
	helper = store --file /home/node/.git-credentials
[alias]
	leak = !cat /home/node/.ssh/id_rsa
[include]
	path = /home/node/.claude/.credentials.json
[user]
	name = Synthetic
	email = synthetic@example.test
[extensions]
	objectformat = sha256
`;

  it("keeps only remote url (user info stripped) and fetch, branch, core without the four keys, and extensions", () => {
    const out = allowlistGitConfig(RAW);
    expect(out).toContain('[remote "origin"]');
    expect(out).toContain('url = "https://github.com/acme/repo.git"');
    expect(out).toContain('fetch = "+refs/heads/*:refs/remotes/origin/*"');
    expect(out).toContain('[branch "main"]');
    expect(out).toContain('remote = "origin"');
    expect(out).toContain('merge = "refs/heads/main"');
    expect(out).toContain("[core]");
    expect(out).toContain('repositoryformatversion = "0"');
    expect(out).toContain('filemode = "true"');
    expect(out).toContain("[extensions]");
    expect(out).toContain('objectformat = "sha256"');
  });

  it("drops everything else, and no secret or dangerous key survives", () => {
    const out = allowlistGitConfig(RAW);
    for (const absent of [TOKEN_URL_SECRET, "sshcommand", "sshCommand", "askpass", "fsmonitor", "hookspath", "hooksPath", "pushurl", "mirror", "insteadOf", "insteadof", "extraheader", "credential", "helper", "alias", "leak", "[include]", "[user]", "synthetic@example.test", ".git-credentials", ".credentials.json", "id_rsa"]) {
      expect(out, absent).not.toContain(absent);
    }
  });

  it("handles quoting, comments, continuation lines, inline section values, legacy subsection headers and CRLF", () => {
    const text = [
      "[remote.origin]\r",
      '\turl = "https://user:pw@host.example/a b.git" ; comment\r',
      "\tfetch = +refs/heads/*:\\",
      "refs/remotes/origin/*",
      "[core] bare = false",
      "[branch \"feat/x\"] remote = origin",
      "# [remote \"evil\"]",
      "[remote \"other\"]",
      "\tURL = git@github.com:acme/other.git",
    ].join("\n");
    const out = allowlistGitConfig(text);
    expect(out).toContain('url = "https://host.example/a b.git"');
    expect(out).toContain('fetch = "+refs/heads/*:refs/remotes/origin/*"');
    expect(out).toContain('bare = "false"');
    expect(out).toContain('[branch "feat/x"]');
    expect(out).toContain('url = "git@github.com:acme/other.git"');
    expect(out).not.toContain("pw");
    expect(out).not.toContain("evil");
  });

  it("emits a value with a quote or a newline escaped so it cannot add a key", () => {
    const out = allowlistGitConfig('[branch "x"]\n\tdescription = "a\\"\\n[remote \\"evil\\"] url = http://leak"\n');
    expect(out.split("\n").filter((l) => l.startsWith("["))).toEqual(['[branch "x"]']);
  });

  it("strips user info from any scheme and leaves other urls unchanged", () => {
    expect(stripUrlUserInfo("https://a:b@host/x")).toBe("https://host/x");
    expect(stripUrlUserInfo("ssh://git@host:22/x")).toBe("ssh://host:22/x");
    expect(stripUrlUserInfo("https://h/x@y")).toBe("https://h/x@y");
    expect(stripUrlUserInfo("git@github.com:a/b.git")).toBe("git@github.com:a/b.git");
    expect(stripUrlUserInfo("/srv/git/repo")).toBe("/srv/git/repo");
    expect(stripUrlUserInfo("https://a:b@c:d@host/x")).toBe("https://host/x");
  });
});

describe("known-value scan", () => {
  it("collects secret-looking environment values, every API_KEYS key, OAuth tokens and extra values, never short ones", () => {
    const creds = write("home/.claude/.credentials.json", JSON.stringify({ claudeAiOauth: { accessToken: "SYNTH-ACCESS-7678", refreshToken: "SYNTH-REFRESH-7678" } }));
    const needles = knownSecretValues(
      { ANTHROPIC_API_KEY: "SYNTH-PROVIDER-KEY", API_KEYS: "a:SYNTH-GW-KEY-ONE,b:SYNTH-GW-KEY-TWO,c:short", OTHER: "SYNTH-NOT-SECRET-NAME", GH_TOKEN: "tiny", DB_PASSWORD: "SYNTH-DB-PASSWORD" },
      creds,
      ["SYNTH-REGISTRY-HEADER", "short"],
    ).map((b) => b.toString());
    expect(needles.sort()).toEqual(["SYNTH-ACCESS-7678", "SYNTH-DB-PASSWORD", "SYNTH-GW-KEY-ONE", "SYNTH-GW-KEY-TWO", "SYNTH-PROVIDER-KEY", "SYNTH-REFRESH-7678", "SYNTH-REGISTRY-HEADER"].sort());
  });

  it("finds a file holding a value (a planted copy or hardlink), ignores symlinks, skips git object stores, and caches by mtime", () => {
    const needles = [Buffer.from(SECRET)];
    write("tree/clean.txt", "nothing here");
    write("tree/dir/copy.txt", `prefix ${SECRET} suffix`);
    const creds = write("home/creds.json", JSON.stringify({ t: SECRET }));
    fs.linkSync(creds, path.join(root, "tree", "hardlink.json"));
    fs.symlinkSync(creds, path.join(root, "tree", "symlink.json"));
    write("tree/repo/.git/objects/ab/cdef", SECRET);
    write("tree/repo/.git/modules/m/objects/ab/cdef", SECRET);
    write("tree/repo/.git/HEAD", "ref: refs/heads/main");
    const scanner = new KnownValueScanner();
    const rel = (hits: string[]) => hits.map((h) => path.relative(path.join(root, "tree"), h)).sort();
    expect(rel(scanner.scan(path.join(root, "tree"), needles))).toEqual(["dir/copy.txt", "hardlink.json"]);
    // Changing a file by content and mtime is seen on the next scan; an untouched file keeps its cached result.
    const clean = path.join(root, "tree", "clean.txt");
    fs.writeFileSync(clean, `now ${SECRET}`);
    fs.utimesSync(clean, new Date(Date.now() + 5000), new Date(Date.now() + 5000));
    expect(rel(scanner.scan(path.join(root, "tree"), needles))).toEqual(["clean.txt", "dir/copy.txt", "hardlink.json"]);
    // A different set of values rescans everything.
    expect(scanner.scan(path.join(root, "tree"), [Buffer.from("never-present-value")])).toEqual([]);
  });

  it("drops cached results below a path after a trusted write", () => {
    const needles = [Buffer.from(SECRET)];
    const file = write("tree/repo/file.txt", "clean");
    const scanner = new KnownValueScanner();
    expect(scanner.scan(path.join(root, "tree"), needles)).toEqual([]);
    // Same size and mtime: only invalidation makes the scanner look again.
    const stat = fs.statSync(file);
    fs.writeFileSync(file, SECRET.padEnd(5, "x").slice(0, 5));
    fs.utimesSync(file, stat.atime, stat.mtime);
    fs.writeFileSync(file, `${SECRET}`.slice(0, stat.size).padEnd(stat.size, "x"));
    fs.utimesSync(file, stat.atime, stat.mtime);
    scanner.invalidate(path.join(root, "tree", "repo"));
    expect(scanner.scan(path.join(root, "tree"), [Buffer.from(SECRET.slice(0, Math.min(SECRET.length, stat.size)))])).toHaveLength(1);
  });

  it("scans nothing without values and skips files over the size limit", () => {
    write("tree/a.txt", SECRET);
    const scanner = new KnownValueScanner();
    expect(scanner.scan(path.join(root, "tree"), [])).toEqual([]);
    fs.writeFileSync(path.join(root, "tree", "big.bin"), Buffer.concat([Buffer.from(SECRET), Buffer.alloc(1024 * 1024 + 10)]));
    expect(scanner.scan(path.join(root, "tree"), [Buffer.from(SECRET)]).map((h) => path.basename(h))).toEqual(["a.txt"]);
  });
});

describe("mount plan", () => {
  function plan(needles: Buffer[] = []) {
    const trustedDir = path.join(root, "trusted");
    return planTrustedContent({ workspaceRoot: path.join(root, "ws"), trustedDir, needles, scanner: new KnownValueScanner() });
  }
  const dests = (p: ReturnType<typeof plan>) => p.mounts.map((m) => m.dest);

  it("mounts the global entries, repositories and a settings file that keeps only permissions", () => {
    write("ws/CLAUDE.md", "global memory");
    write("ws/skills/s/SKILL.md", "skill");
    write("ws/agents/a.md", "agent");
    write("ws/memory/m.md", "memory");
    write("ws/commands/c.md", "command");
    write("ws/settings.json", JSON.stringify({ permissions: { allow: ["Bash(*)"] }, env: { LEAK: SECRET }, hooks: { PreToolUse: [{ hooks: [{ type: "command", command: "evil" }] }] }, mcpServers: { x: { command: "evil" } } }));
    write("ws/.credentials.json", SECRET);
    write("ws/sessions.json", "{}");
    write("ws/projects/knowledge-base/doc.md", "kb");
    write("ws/projects/-home-node/transcript.jsonl", "transcript");
    const p = plan();
    expect(dests(p)).toEqual([
      "/home/node/.claude/CLAUDE.md",
      "/home/node/.claude/skills",
      "/home/node/.claude/agents",
      "/home/node/.claude/memory",
      "/home/node/.claude/commands",
      "/home/node/.claude/output-styles",
      "/home/node/.claude/plugins",
      "/home/node/.claude/hooks",
      "/home/node/.claude/settings.json",
      "/home/node/.claude/projects/knowledge-base",
    ]);
    const settings = p.mounts.find((m) => m.dest.endsWith("settings.json"))!;
    expect(JSON.parse(fs.readFileSync(settings.src, "utf8"))).toEqual({ permissions: { allow: ["Bash(*)"] } });
    expect(fs.readFileSync(settings.src, "utf8")).not.toContain(SECRET);
    // Nothing trusted (credentials, state files, transcripts) is among the mounts.
    expect(JSON.stringify(p.mounts)).not.toMatch(/credentials|sessions\.json|-home-node/);
    expect(p.skipped).toBe(0);
  });

  it("writes an empty settings file when the trusted one is missing or unusable", () => {
    write("ws/skills/s.md", "x");
    let p = plan();
    expect(JSON.parse(fs.readFileSync(p.mounts.find((m) => m.dest.endsWith("settings.json"))!.src, "utf8"))).toEqual({});
    fs.rmSync(path.join(root, "trusted"), { recursive: true });
    write("ws/settings.json", "not json");
    p = plan();
    expect(JSON.parse(fs.readFileSync(p.mounts.find((m) => m.dest.endsWith("settings.json"))!.src, "utf8"))).toEqual({});
  });

  it("leaves out a planted symlink in every position, each with an audit line and no mount of the linked content", () => {
    write("outside/secret.txt", SECRET);
    fs.mkdirSync(path.join(root, "outside", "dir"));
    fs.mkdirSync(path.join(root, "ws", "projects"), { recursive: true });
    // A global entry that is a link to a directory and one that is a link to a file.
    fs.symlinkSync(path.join(root, "outside"), path.join(root, "ws", "skills"));
    fs.symlinkSync(path.join(root, "outside", "secret.txt"), path.join(root, "ws", "CLAUDE.md"));
    // A repository that is a link, and one whose .git is a link.
    fs.symlinkSync(path.join(root, "outside"), path.join(root, "ws", "projects", "linked-repo"));
    write("ws/projects/gitlink/file.txt", "x");
    fs.symlinkSync(path.join(root, "outside", "dir"), path.join(root, "ws", "projects", "gitlink", ".git"));
    // A repository whose .git/config and a module config are links.
    write("ws/projects/cfglink/.git/HEAD", "ref");
    fs.symlinkSync(path.join(root, "outside", "secret.txt"), path.join(root, "ws", "projects", "cfglink", ".git", "config"));
    write("ws/projects/modlink/.git/config", "[core]\n");
    write("ws/projects/modlink/.git/modules/m/HEAD", "ref");
    fs.symlinkSync(path.join(root, "outside", "secret.txt"), path.join(root, "ws", "projects", "modlink", ".git", "modules", "m", "config"));
    // The settings file and the projects directory.
    fs.symlinkSync(path.join(root, "outside", "secret.txt"), path.join(root, "ws", "settings.json"));
    const p = plan();
    // Nothing from the workspace is mounted; the trusted entries a link replaced are empty stand-ins below the trusted directory.
    const rest = p.mounts.filter((m) => !m.dest.endsWith("settings.json"));
    expect(rest.map((m) => m.dest).sort()).toEqual(["agents", "commands", "hooks", "output-styles", "plugins", "skills", "CLAUDE.md"].map((n) => `/home/node/.claude/${n}`).sort());
    for (const m of rest) expect(m.src.startsWith(path.join(root, "trusted")), m.dest).toBe(true);
    for (const m of rest) {
      const stat = fs.lstatSync(m.src);
      expect(stat.isDirectory() ? fs.readdirSync(m.src).length : stat.size, m.dest).toBe(0);
    }
    expect(p.skipped).toBe(6);
    expect(logs.join("\n")).toMatch(/kind=settings name=settings.json reason=symlink/);
    expect(logs.filter((l) => l.includes("sandbox.content.skipped")).join("\n")).toMatch(/kind=global name=skills reason=symlink/);
    expect(logs.join("\n")).toMatch(/kind=repo name=linked-repo reason=symlink/);
    expect(logs.join("\n")).toMatch(/kind=repo name=gitlink reason=unsafe_git/);
    expect(logs.join("\n")).toMatch(/kind=repo name=cfglink reason=unsafe_git/);
    expect(logs.join("\n")).toMatch(/kind=repo name=modlink reason=unsafe_git/);
    // The settings file the sandbox sees carries nothing of the linked one.
    expect(fs.readFileSync(p.mounts.find((m) => m.dest.endsWith("settings.json"))!.src, "utf8")).not.toContain(SECRET);
    // No audit line carries a secret value or a path below the workspace.
    expect(logs.join("\n")).not.toContain(SECRET);
    expect(logs.join("\n")).not.toContain(root);
  });

  it("leaves out a projects directory that is a link and repositories with an unsafe name", () => {
    write("outside/r/file.txt", "x");
    fs.mkdirSync(path.join(root, "ws"), { recursive: true });
    fs.symlinkSync(path.join(root, "outside"), path.join(root, "ws", "projects"));
    expect(dests(plan()).some((d) => d.includes("/projects/"))).toBe(false);
    fs.rmSync(path.join(root, "ws", "projects"));
    write("ws/projects/ok/file.txt", "x");
    write("ws/projects/with space/file.txt", "x");
    write("ws/projects/.hidden/file.txt", "x");
    fs.rmSync(path.join(root, "trusted"), { recursive: true });
    const p = plan();
    expect(dests(p).filter((d) => d.includes("/projects/"))).toEqual(["/home/node/.claude/projects/ok"]);
    expect(logs.join("\n")).toMatch(/kind=repo name=invalid reason=unsafe_name/);
  });

  it("covers every git configuration of a repository with a generated copy and never mounts the original", () => {
    const tokenUrl = `https://x-access-token:${TOKEN_URL_SECRET}@github.com/acme/repo.git`;
    write("ws/projects/repo/file.txt", "x");
    write("ws/projects/repo/.git/config", `[remote "origin"]\n\turl = ${tokenUrl}\n[core]\n\tfsmonitor = /evil\n`);
    write("ws/projects/repo/.git/modules/sub/config", `[remote "origin"]\n\turl = ${tokenUrl}\n`);
    write("ws/projects/repo/.git/modules/sub/modules/inner/config", `[remote "origin"]\n\turl = ${tokenUrl}\n`);
    write("ws/projects/repo/.git/worktrees/wt1/config", `[remote "origin"]\n\turl = ${tokenUrl}\n`);
    write("ws/projects/repo/.git/modules/sub/objects/ab/cd", "object");
    const p = plan();
    const masks = p.mounts.filter((m) => m.dest.includes("/.git/"));
    expect(masks.map((m) => m.dest).sort()).toEqual(
      [
        "/home/node/.claude/projects/repo/.git/config",
        "/home/node/.claude/projects/repo/.git/modules/sub/config",
        "/home/node/.claude/projects/repo/.git/modules/sub/modules/inner/config",
        "/home/node/.claude/projects/repo/.git/worktrees/wt1/config",
      ].sort(),
    );
    for (const mask of masks) {
      expect(mask.src.startsWith(path.join(root, "trusted"))).toBe(true);
      const text = fs.readFileSync(mask.src, "utf8");
      expect(text).not.toContain(TOKEN_URL_SECRET);
      expect(text).toContain("https://github.com/acme/repo.git");
      expect(text).not.toContain("fsmonitor");
    }
    // The repository itself is mounted before its masks, which sit on top of it.
    const order = dests(p);
    expect(order.indexOf("/home/node/.claude/projects/repo")).toBeLessThan(order.indexOf("/home/node/.claude/projects/repo/.git/config"));
  });

  it("accepts a .git file (a submodule or worktree checkout) and a non-git directory without masks", () => {
    write("ws/projects/sub/.git", "gitdir: ../.git/modules/sub");
    write("ws/projects/docs/readme.md", "x");
    const p = plan();
    expect(dests(p).filter((d) => d.includes("/projects/"))).toEqual(["/home/node/.claude/projects/docs", "/home/node/.claude/projects/sub"]);
  });

  it("hides a file that holds a known value behind an empty file, in a global directory and a repository, with an audit line without the value", () => {
    write("ws/skills/ok.md", "fine");
    write("ws/skills/planted-copy.md", `token ${SECRET}`);
    write("ws/CLAUDE.md", `my key is ${SECRET}`);
    write("ws/projects/repo/src/leak.txt", SECRET);
    write("ws/projects/repo/src/fine.txt", "fine");
    const p = plan([Buffer.from(SECRET)]);
    expect(p.hidden.sort()).toEqual(
      ["/home/node/.claude/CLAUDE.md", "/home/node/.claude/projects/repo/src/leak.txt", "/home/node/.claude/skills/planted-copy.md"].sort(),
    );
    expect(p.hiddenCount).toBe(3);
    const audit = logs.filter((l) => l.includes("known_value")).join("\n");
    expect(audit).toMatch(/kind=global name=skills reason=known_value/);
    expect(audit).toMatch(/kind=repo name=repo reason=known_value/);
    expect(logs.join("\n")).not.toContain(SECRET);
  });
});
