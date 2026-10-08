/**
 * What an agent sandbox may see of the trusted workspace (src/sandbox-content.ts): no-follow
 * validation of every bind source and trusted read, planted symlinks in every position, the
 * allowlist-generated git configuration, the known-value scan and the mount plan.
 * All secret values are synthetic.
 */
import { execFileSync } from "node:child_process";
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
  sshPrivateKeyValues,
  stripUrlUserInfo,
  webhookUrlValues,
} from "../sandbox-content.js";
import { neutralizeCommandSettings } from "../command-settings.js";
import { SandboxRun, loadIsolationConfig } from "../sandbox.js";

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

  it("scans nothing without values", () => {
    write("tree/a.txt", SECRET);
    expect(new KnownValueScanner().scan(path.join(root, "tree"), [])).toEqual([]);
  });

  it("finds a value at the end of a 2 MiB file and leaves a clean 2 MiB file alone", () => {
    const MiB = 1024 * 1024;
    fs.mkdirSync(path.join(root, "tree"), { recursive: true });
    fs.writeFileSync(path.join(root, "tree", "big-planted.bin"), Buffer.concat([Buffer.alloc(2 * MiB, "x"), Buffer.from(SECRET)]));
    fs.writeFileSync(path.join(root, "tree", "big-clean.bin"), Buffer.alloc(2 * MiB, "x"));
    write("tree/small-clean.txt", "fine");
    expect(new KnownValueScanner().scan(path.join(root, "tree"), [Buffer.from(SECRET)]).map((h) => path.basename(h))).toEqual(["big-planted.bin"]);
  });

  it("finds a value that straddles a chunk boundary, at every offset around it", () => {
    const MiB = 1024 * 1024;
    const needle = Buffer.from(SECRET);
    fs.mkdirSync(path.join(root, "tree"), { recursive: true });
    for (let shift = 0; shift < needle.length; shift++) {
      const body = Buffer.alloc(3 * MiB, "x");
      needle.copy(body, MiB - shift);
      fs.writeFileSync(path.join(root, "tree", `straddle-${shift}.bin`), body);
    }
    const hits = new KnownValueScanner().scan(path.join(root, "tree"), [needle]);
    expect(hits).toHaveLength(needle.length);
  });

  it("finds a straddling value with a tiny chunk size and a value longer than the chunk", () => {
    const needle = Buffer.from(SECRET);
    for (const chunkBytes of [1, 7, needle.length - 1, needle.length, needle.length + 3]) {
      const dir = path.join(root, `tiny-${chunkBytes}`);
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(path.join(dir, "planted.bin"), Buffer.concat([Buffer.alloc(chunkBytes * 3 + 5, "x"), needle, Buffer.alloc(chunkBytes * 2 + 1, "y")]));
      fs.writeFileSync(path.join(dir, "clean.bin"), Buffer.alloc(chunkBytes * 6 + needle.length, "x"));
      const hits = new KnownValueScanner({ chunkBytes }).scan(dir, [needle]).map((h) => path.basename(h));
      expect(hits, `chunk ${chunkBytes}`).toEqual(["planted.bin"]);
    }
  });

  it("hides a file above the ceiling without reading it, and a file exactly at the ceiling is scanned", () => {
    const ceiling = 4096;
    fs.mkdirSync(path.join(root, "tree"), { recursive: true });
    fs.writeFileSync(path.join(root, "tree", "over.bin"), Buffer.alloc(ceiling + 1, "x"));
    fs.writeFileSync(path.join(root, "tree", "at-planted.bin"), Buffer.concat([Buffer.alloc(ceiling - SECRET.length, "x"), Buffer.from(SECRET)]));
    fs.writeFileSync(path.join(root, "tree", "at-clean.bin"), Buffer.alloc(ceiling, "x"));
    const scanner = new KnownValueScanner({ maxFileBytes: ceiling });
    const result = scanner.scanDetailed(path.join(root, "tree"), [Buffer.from(SECRET)]);
    expect(result.tooLarge.map((h) => path.basename(h))).toEqual(["over.bin"]);
    expect(result.hits.map((h) => path.basename(h))).toEqual(["at-planted.bin"]);
    expect(scanner.scan(path.join(root, "tree"), [Buffer.from(SECRET)]).map((h) => path.basename(h)).sort()).toEqual(["at-planted.bin", "over.bin"]);
  });

  it("scans a single file and refuses a link, a missing file and a directory as a hit", () => {
    const scanner = new KnownValueScanner();
    const needles = [Buffer.from(SECRET)];
    const clean = write("one/clean.txt", "fine");
    const planted = write("one/planted.txt", SECRET);
    const link = path.join(root, "one", "link.txt");
    fs.symlinkSync(clean, link);
    expect(scanner.scanFile(clean, needles)).toBe("clean");
    expect(scanner.scanFile(planted, needles)).toBe("hit");
    expect(scanner.scanFile(link, needles)).toBe("hit");
    expect(scanner.scanFile(path.join(root, "one", "missing.txt"), needles)).toBe("hit");
    expect(scanner.scanFile(path.join(root, "one"), needles)).toBe("hit");
  });
});

describe("SSH private-key values", () => {
  const BODY_ONE = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW";
  const BODY_TWO = "QyNTUxOQAAACBSYNTH7919FAKEKEYBODYLINETWOabcdefghijklmnopqrstuvwxyz0";
  const BODY_SHORT = "short=";
  const key = (eol: string) =>
    ["-----BEGIN OPENSSH PRIVATE KEY-----", BODY_ONE, BODY_TWO, BODY_SHORT, "-----END OPENSSH PRIVATE KEY-----", ""].join(eol);

  it("takes every body line of 16 or more characters of an armored private key, nothing else", () => {
    write("ssh/id_ed25519", key("\n"));
    const values = sshPrivateKeyValues(path.join(root, "ssh"));
    expect(values).toHaveLength(2);
    expect(values.includes(BODY_ONE)).toBe(true);
    expect(values.includes(BODY_TWO)).toBe(true);
    expect(values.some((v) => v.includes("BEGIN") || v.includes("END") || v === BODY_SHORT)).toBe(false);
  });

  it("reads a CRLF-stored key as the same lines, so an LF or CRLF copy contains them", () => {
    write("ssh/id_crlf", key("\r\n"));
    const values = sshPrivateKeyValues(path.join(root, "ssh"));
    expect(values.sort()).toEqual([BODY_ONE, BODY_TWO].sort());
    expect(values.every((v) => !v.includes("\r"))).toBe(true);
  });

  it("skips the headers of an encrypted legacy key", () => {
    write("ssh/id_rsa", ["-----BEGIN RSA PRIVATE KEY-----", "Proc-Type: 4,ENCRYPTED", "DEK-Info: AES-128-CBC,0123456789ABCDEF0123456789ABCDEF", "", BODY_ONE, "-----END RSA PRIVATE KEY-----", ""].join("\n"));
    expect(sshPrivateKeyValues(path.join(root, "ssh"))).toEqual([BODY_ONE]);
  });

  it("ignores public keys, known_hosts, authorized_keys and config", () => {
    write("ssh/id_ed25519.pub", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFSYNTH7919PUBLICKEYBLOBabcdefghijkl comment\n");
    write("ssh/known_hosts", "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n");
    write("ssh/authorized_keys", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFSYNTH7919AUTHORIZEDKEYabcdefghijklm x\n");
    write("ssh/config", "# Managed by agent-gateway\nHost *\n  StrictHostKeyChecking accept-new\n  IdentityFile /home/node/.ssh/id_ed25519\n");
    expect(sshPrivateKeyValues(path.join(root, "ssh"))).toEqual([]);
  });

  it("ignores a symlink, an oversized file and a subdirectory, and a missing directory gives nothing", () => {
    const real = write("elsewhere/real-key", key("\n"));
    fs.mkdirSync(path.join(root, "ssh"), { recursive: true });
    fs.symlinkSync(real, path.join(root, "ssh", "linked-key"));
    write("ssh/huge", `${key("\n")}${"x".repeat(300 * 1024)}`);
    write("ssh/sub/nested-key", key("\n"));
    expect(sshPrivateKeyValues(path.join(root, "ssh"))).toEqual([]);
    expect(sshPrivateKeyValues(path.join(root, "missing"))).toEqual([]);
  });

  it("logs nothing", () => {
    write("ssh/id_ed25519", key("\n"));
    sshPrivateKeyValues(path.join(root, "ssh"));
    expect(logs).toEqual([]);
  });
});

describe("webhook URL values", () => {
  const has = (values: string[], value: string) => values.includes(value);
  const tool = (webhook_url: string) => [{ webhook_url }];

  it("takes the full URL, a path token and the path onward", () => {
    const values = webhookUrlValues(tool("https://hooks.example.test/services/T0SYNTH7919/B0SYNTH7919/XYZsynth7919PATHTOKEN"));
    expect(has(values, "https://hooks.example.test/services/T0SYNTH7919/B0SYNTH7919/XYZsynth7919PATHTOKEN")).toBe(true);
    expect(has(values, "XYZsynth7919PATHTOKEN")).toBe(true);
    expect(has(values, "/services/T0SYNTH7919/B0SYNTH7919/XYZsynth7919PATHTOKEN")).toBe(true);
    expect(has(values, "services")).toBe(false);
  });

  it("takes query and fragment values: unnamed ones of 16+ characters, secret-named ones of 8+", () => {
    const values = webhookUrlValues(tool("https://hooks.example.test/h?code=ABC12345&token=SYNTHqueryTOKEN7919&mode=fast&opaque=OPAQUEvalue7919xx#access_token=FRAGsynth7919&view=list"));
    expect(has(values, "ABC12345")).toBe(true);
    expect(has(values, "SYNTHqueryTOKEN7919")).toBe(true);
    expect(has(values, "OPAQUEvalue7919xx")).toBe(true);
    expect(has(values, "FRAGsynth7919")).toBe(true);
    expect(has(values, "fast")).toBe(false);
    expect(has(values, "list")).toBe(false);
  });

  it("takes user info and the percent-decoded form of an encoded token", () => {
    const values = webhookUrlValues(tool("https://synthuser7919:synth%2Fpass7919@hooks.example.test/h?api_key=a%2Bb%2Fc7919KEY"));
    expect(has(values, "synthuser7919")).toBe(true);
    expect(has(values, "synth%2Fpass7919")).toBe(true);
    expect(has(values, "synth/pass7919")).toBe(true);
    expect(has(values, "a%2Bb%2Fc7919KEY")).toBe(true);
    expect(has(values, "a+b/c7919KEY")).toBe(true);
  });

  it("gives nothing for a URL that does not parse, a non-string and a tool without a URL, and logs nothing", () => {
    expect(webhookUrlValues([{ webhook_url: "not a url SYNTH7919SECRETVALUE" }, { webhook_url: 42 }, {}])).toEqual([]);
    expect(logs).toEqual([]);
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

  it("hides a global CLAUDE.md over 1 MiB that holds a known value", () => {
    const MiB = 1024 * 1024;
    fs.mkdirSync(path.join(root, "ws"), { recursive: true });
    fs.writeFileSync(path.join(root, "ws", "CLAUDE.md"), Buffer.concat([Buffer.alloc(2 * MiB, "x"), Buffer.from(SECRET)]));
    const planted = plan([Buffer.from(SECRET)]);
    expect(planted.hidden).toEqual(["/home/node/.claude/CLAUDE.md"]);
    expect(logs.join("\n")).toMatch(/kind=global name=CLAUDE.md reason=known_value/);
  });

  it("keeps a clean global CLAUDE.md and a clean file over 1 MiB mounted", () => {
    const MiB = 1024 * 1024;
    fs.mkdirSync(path.join(root, "ws", "projects", "repo"), { recursive: true });
    fs.writeFileSync(path.join(root, "ws", "CLAUDE.md"), Buffer.alloc(2 * MiB, "x"));
    fs.writeFileSync(path.join(root, "ws", "projects", "repo", "big-clean.bin"), Buffer.alloc(2 * MiB, "x"));
    const p = plan([Buffer.from(SECRET)]);
    expect(p.hidden).toEqual([]);
    expect(p.hiddenCount).toBe(0);
    expect(p.mounts.some((m) => m.dest === "/home/node/.claude/CLAUDE.md" && m.src === path.join(root, "ws", "CLAUDE.md"))).toBe(true);
  });

  it("hides an oversized global CLAUDE.md but leaves repository files outside the scan", () => {
    const ceiling = 2048;
    fs.mkdirSync(path.join(root, "ws", "projects", "repo"), { recursive: true });
    fs.writeFileSync(path.join(root, "ws", "projects", "repo", "huge.bin"), Buffer.alloc(ceiling + 1, "x"));
    fs.writeFileSync(path.join(root, "ws", "projects", "repo", "fine.txt"), "fine");
    fs.writeFileSync(path.join(root, "ws", "CLAUDE.md"), Buffer.alloc(ceiling + 1, "x"));
    const trustedDir = path.join(root, "trusted");
    const p = planTrustedContent({ workspaceRoot: path.join(root, "ws"), trustedDir, needles: [Buffer.from(SECRET)], scanner: new KnownValueScanner({ maxFileBytes: ceiling }) });
    expect(p.hidden).toEqual(["/home/node/.claude/CLAUDE.md"]);
    expect(p.hiddenCount).toBe(1);
    expect(p.mounts).toContainEqual({ src: path.join(root, "ws", "projects", "repo"), dest: "/home/node/.claude/projects/repo" });
    const audit = logs.filter((l) => l.includes("sandbox.content.skipped")).join("\n");
    expect(audit).not.toMatch(/kind=repo name=repo reason=too_large/);
    expect(audit).toMatch(/kind=global name=CLAUDE.md reason=too_large/);
    expect(audit).not.toMatch(/known_value/);
  });

  it("hides known values in global entries without scanning repository contents", () => {
    write("ws/skills/ok.md", "fine");
    write("ws/skills/planted-copy.md", `token ${SECRET}`);
    write("ws/CLAUDE.md", `my key is ${SECRET}`);
    write("ws/projects/repo/src/leak.txt", SECRET);
    write("ws/projects/repo/src/fine.txt", "fine");
    const p = plan([Buffer.from(SECRET)]);
    expect(p.hidden.sort()).toEqual(
      ["/home/node/.claude/CLAUDE.md", "/home/node/.claude/skills/planted-copy.md"].sort(),
    );
    expect(p.hiddenCount).toBe(2);
    expect(p.mounts).toContainEqual({ src: path.join(root, "ws", "projects", "repo"), dest: "/home/node/.claude/projects/repo" });
    const audit = logs.filter((l) => l.includes("known_value")).join("\n");
    expect(audit).toMatch(/kind=global name=skills reason=known_value/);
    expect(audit).not.toMatch(/kind=repo name=repo reason=known_value/);
    expect(logs.join("\n")).not.toContain(SECRET);
  });
});

describe("a snapshot of skills, agents and commands for a run without Bash (MVP-8106)", () => {
  const HOOK_SKILL = "---\nname: probe\ndescription: probe skill\nhooks:\n  PreToolUse:\n    - matcher: Read\n      hooks:\n        - type: command\n          command: touch /work/m-HOOKCMD\n---\nINSTRUCTION-TOKEN\n";
  const NEUTRAL_SKILL = '---\nname: "probe"\ndescription: "probe skill"\n---\nINSTRUCTION-TOKEN\n';
  const HOOK_AGENT = "---\nname: a\ndescription: agent\ntools: Read\nmcpServers:\n  - p:\n      type: stdio\n      command: sh\n---\nAGENT-TOKEN\n";
  const NEUTRAL_AGENT = '---\nname: "a"\ndescription: "agent"\ntools: "Read"\n---\nAGENT-TOKEN\n';
  const trusted = () => path.join(root, "trusted");

  function plan(options: { neutralize?: boolean; needles?: Buffer[]; scanner?: KnownValueScanner; limits?: Record<string, number>; trustedDir?: string; ws?: string } = {}) {
    return planTrustedContent({
      workspaceRoot: options.ws ?? path.join(root, "ws"),
      trustedDir: options.trustedDir ?? trusted(),
      needles: options.needles ?? [],
      scanner: options.scanner ?? new KnownValueScanner(),
      ...(options.neutralize === undefined ? {} : { neutralizeCommands: options.neutralize }),
      label: "reqlift",
      // Loosely typed on purpose: a row passes only the limit it exercises, whatever the option's declared type is.
      ...(options.limits ? { snapshotLimits: options.limits as unknown as { maxFiles: number; maxBytes: number } } : {}),
    });
  }
  const mountOf = (p: ReturnType<typeof plan>, entry: string) => p.mounts.find((m) => m.dest === `/home/node/.claude/${entry}`);
  const audits = () => logs.filter((l) => l.includes("[audit]")).join("\n");

  function seed(): void {
    write("ws/skills/probe/SKILL.md", HOOK_SKILL);
    write("ws/skills/probe/reference.txt", "reference text");
    write("ws/skills/probe/deep/NOTES.MD", HOOK_SKILL);
    write("ws/agents/a.md", HOOK_AGENT);
    write("ws/agents/team/b.md", HOOK_AGENT);
    write("ws/commands/c.md", HOOK_SKILL);
    write("ws/memory/note.md", HOOK_SKILL);
    write("ws/CLAUDE.md", HOOK_SKILL);
  }

  it("binds a copy instead of the live entry for skills, agents and commands only, in the same mount order and at the same paths", () => {
    seed();
    const off = plan({ neutralize: false, trustedDir: path.join(root, "trusted-off") });
    const on = plan({ neutralize: true });
    expect(on.mounts.map((m) => m.dest)).toEqual(off.mounts.map((m) => m.dest));
    for (const entry of ["skills", "agents", "commands"]) {
      expect(mountOf(off, entry)!.src).toBe(path.join(root, "ws", entry));
      expect(mountOf(on, entry)!.src).toBe(path.join(trusted(), "neutralized", entry));
    }
    for (const entry of ["CLAUDE.md", "memory", "output-styles", "plugins", "hooks", "settings.json"]) {
      expect(mountOf(on, entry)!.src.startsWith(path.join(trusted(), "neutralized"))).toBe(false);
    }
    expect(mountOf(on, "memory")!.src).toBe(path.join(root, "ws", "memory"));
    expect(mountOf(on, "CLAUDE.md")!.src).toBe(path.join(root, "ws", "CLAUDE.md"));
  });

  it("changes nothing without the flag: the plan with the option absent or false is the plan of before, and no copy is made", () => {
    seed();
    const absent = plan();
    const explicitFalse = plan({ neutralize: false, trustedDir: path.join(root, "trusted-false") });
    const strip = (p: ReturnType<typeof plan>, dir: string) => JSON.parse(JSON.stringify(p).replaceAll(dir, "<trusted>"));
    expect(strip(explicitFalse, path.join(root, "trusted-false"))).toEqual(strip(absent, trusted()));
    expect(mountOf(absent, "skills")!.src).toBe(path.join(root, "ws", "skills"));
    expect(fs.existsSync(path.join(trusted(), "neutralized"))).toBe(false);
    expect(audits()).not.toContain("command-settings");
  });

  it("rewrites every markdown file (any case, any depth) and copies everything else as it is", () => {
    seed();
    write("ws/skills/probe/script.sh", "#!/bin/sh\necho x\n");
    fs.chmodSync(path.join(root, "ws", "skills", "probe", "script.sh"), 0o755);
    plan({ neutralize: true });
    const snap = (rel: string) => fs.readFileSync(path.join(trusted(), "neutralized", rel), "utf8");
    expect(snap("skills/probe/SKILL.md")).toBe(NEUTRAL_SKILL);
    expect(snap("skills/probe/deep/NOTES.MD")).toBe(NEUTRAL_SKILL);
    expect(snap("agents/a.md")).toBe(NEUTRAL_AGENT);
    expect(snap("agents/team/b.md")).toBe(NEUTRAL_AGENT);
    expect(snap("commands/c.md")).toBe(NEUTRAL_SKILL);
    expect(snap("skills/probe/reference.txt")).toBe("reference text");
    expect(snap("skills/probe/script.sh")).toBe("#!/bin/sh\necho x\n");
    expect(fs.statSync(path.join(trusted(), "neutralized", "skills", "probe", "script.sh")).mode & 0o100).toBe(0o100);
    expect(fs.statSync(path.join(trusted(), "neutralized", "skills", "probe", "reference.txt")).mode & 0o100).toBe(0);
    // The stored files are untouched, and so are the entries the runtime does not load as skills or agents.
    expect(fs.readFileSync(path.join(root, "ws", "skills", "probe", "SKILL.md"), "utf8")).toBe(HOOK_SKILL);
    expect(fs.readFileSync(path.join(root, "ws", "agents", "a.md"), "utf8")).toBe(HOOK_AGENT);
  });

  it("is a copy of the moment of the plan: a file saved, changed or deleted afterwards does not reach it", () => {
    seed();
    plan({ neutralize: true });
    write("ws/skills/late/SKILL.md", HOOK_SKILL);
    write("ws/skills/probe/SKILL.md", "---\nname: probe\nhooks: {}\n---\nCHANGED\n");
    fs.rmSync(path.join(root, "ws", "agents", "a.md"));
    const snapshot = path.join(trusted(), "neutralized");
    expect(fs.existsSync(path.join(snapshot, "skills", "late"))).toBe(false);
    expect(fs.readFileSync(path.join(snapshot, "skills", "probe", "SKILL.md"), "utf8")).toBe(NEUTRAL_SKILL);
    expect(fs.readFileSync(path.join(snapshot, "agents", "a.md"), "utf8")).toBe(NEUTRAL_AGENT);
  });

  it("leaves a symlink (to a file or a directory) and a non-regular file out, each with an audit line, and never follows them", () => {
    seed();
    write("outside/secret.md", `---\nname: x\n---\n${SECRET}\n`);
    fs.mkdirSync(path.join(root, "outside", "dir"));
    write("outside/dir/inner.md", "inner");
    fs.symlinkSync(path.join(root, "outside", "secret.md"), path.join(root, "ws", "skills", "probe", "link.md"));
    fs.symlinkSync(path.join(root, "outside", "dir"), path.join(root, "ws", "agents", "linked-dir"));
    fs.symlinkSync(path.join(root, "nowhere"), path.join(root, "ws", "commands", "dangling.md"));
    execFifo(path.join(root, "ws", "skills", "probe", "pipe.md"));
    plan({ neutralize: true });
    const snapshot = path.join(trusted(), "neutralized");
    expect(fs.existsSync(path.join(snapshot, "skills", "probe", "link.md"))).toBe(false);
    expect(fs.existsSync(path.join(snapshot, "skills", "probe", "pipe.md"))).toBe(false);
    expect(fs.existsSync(path.join(snapshot, "agents", "linked-dir"))).toBe(false);
    expect(fs.existsSync(path.join(snapshot, "commands", "dangling.md"))).toBe(false);
    expect(fs.readFileSync(path.join(snapshot, "skills", "probe", "SKILL.md"), "utf8")).toBe(NEUTRAL_SKILL);
    const text = audits();
    expect(text).toMatch(/kind=snapshot-skills name=link reason=symlink/);
    expect(text).toMatch(/kind=snapshot-skills name=pipe reason=wrong_type/);
    expect(text).toMatch(/kind=snapshot-agents name=linked-dir reason=symlink/);
    expect(text).toMatch(/kind=snapshot-commands name=dangling reason=symlink/);
    expect(logs.join("\n")).not.toContain(SECRET);
  });

  it("leaves a file the gateway user does not own out, with the audit reason not_owned", () => {
    seed();
    write("ws/skills/probe/foreign.md", HOOK_SKILL);
    const foreign = path.join(root, "ws", "skills", "probe", "foreign.md");
    const real = fs.lstatSync;
    vi.spyOn(fs, "lstatSync").mockImplementation(((target: fs.PathLike, ...rest: unknown[]) => {
      const stat = (real as (...args: unknown[]) => fs.Stats)(target, ...rest);
      if (String(target) !== foreign) return stat;
      return Object.assign(Object.create(Object.getPrototypeOf(stat)), stat, { uid: (stat.uid + 1) % 65536 }) as fs.Stats;
    }) as typeof fs.lstatSync);
    plan({ neutralize: true });
    vi.restoreAllMocks();
    expect(fs.existsSync(path.join(trusted(), "neutralized", "skills", "probe", "foreign.md"))).toBe(false);
    expect(fs.existsSync(path.join(trusted(), "neutralized", "skills", "probe", "SKILL.md"))).toBe(true);
  });

  it("stops at the file limit and leaves a file above the byte limit out, each only counted in the one summary line, never as a too_large line per file", () => {
    for (let i = 0; i < 5; i++) write(`ws/skills/s${i}/SKILL.md`, `---\nname: s${i}\n---\nbody\n`);
    plan({ neutralize: true, limits: { maxFiles: 3, maxBytes: 1_000_000 } });
    const snapshot = path.join(trusted(), "neutralized", "skills");
    const folders = fs.readdirSync(snapshot);
    const copied = folders.filter((name) => fs.existsSync(path.join(snapshot, name, "SKILL.md")));
    // The walk creates the folder of the fourth file and stops at that file: the order of the folders is the filesystem's.
    expect(folders.length).toBe(4);
    expect(copied.length).toBe(3);
    for (const name of copied) expect(fs.existsSync(path.join(root, "ws", "skills", name, "SKILL.md"))).toBe(true);
    const limited = logs.filter((l) => l.includes("sandbox.content.limited"));
    expect(limited).toHaveLength(1);
    expect(limited[0]).toMatch(/kind=snapshot-skills files=3 folders=4 examined=\d+ bytes=\d+ left_out=1 stopped=true$/);
    expect(audits()).not.toMatch(/reason=too_large/);
    fs.rmSync(trusted(), { recursive: true, force: true });
    fs.rmSync(path.join(root, "ws"), { recursive: true, force: true });
    logs.length = 0;
    write("ws/skills/big/SKILL.md", `---\nname: big\n---\n${"x".repeat(600)}\n`);
    plan({ neutralize: true, limits: { maxFiles: 100, maxBytes: 100 } });
    expect(fs.existsSync(path.join(trusted(), "neutralized", "skills", "big", "SKILL.md"))).toBe(false);
    const afterBig = logs.filter((l) => l.includes("sandbox.content.limited"));
    expect(afterBig).toHaveLength(1);
    expect(afterBig[0]).toMatch(/kind=snapshot-skills files=0 folders=1 examined=2 bytes=0 left_out=1 stopped=false$/);
    expect(audits()).not.toMatch(/reason=too_large/);
  });

  it("fails closed when an entry cannot be copied: it is seen as empty, nothing of it is left in the copy and the live entry is not bound", () => {
    seed();
    const real = fs.readdirSync;
    vi.spyOn(fs, "readdirSync").mockImplementation(((target: fs.PathLike, ...rest: unknown[]) => {
      if (String(target) === path.join(root, "ws", "skills", "probe")) throw new Error("EACCES");
      return (real as (...args: unknown[]) => unknown)(target, ...rest);
    }) as typeof fs.readdirSync);
    // The walk lists a folder through either call; the row fails the same folder through both.
    const realOpendir = fs.opendirSync;
    vi.spyOn(fs, "opendirSync").mockImplementation(((target: fs.PathLike, ...rest: unknown[]) => {
      if (String(target) === path.join(root, "ws", "skills", "probe")) throw new Error("EACCES");
      return (realOpendir as (...args: unknown[]) => unknown)(target, ...rest);
    }) as typeof fs.opendirSync);
    const p = plan({ neutralize: true });
    vi.restoreAllMocks();
    expect(mountOf(p, "skills")!.src).toBe(path.join(trusted(), "empty-dir"));
    expect(fs.existsSync(path.join(trusted(), "neutralized", "skills"))).toBe(false);
    expect(mountOf(p, "agents")!.src).toBe(path.join(trusted(), "neutralized", "agents"));
    expect(p.mounts.some((m) => m.src === path.join(root, "ws", "skills"))).toBe(false);
  });

  it("scans the copy for known values and hides the file, without keeping the single-use snapshot paths in the scanner cache", () => {
    seed();
    write("ws/skills/probe/planted.md", `---\nname: planted\n---\ntoken ${SECRET}\n`);
    const scanner = new KnownValueScanner();
    const p = plan({ neutralize: true, needles: [Buffer.from(SECRET)], scanner });
    expect(p.hidden).toEqual(["/home/node/.claude/skills/probe/planted.md"]);
    expect(audits()).toMatch(/kind=global name=skills reason=known_value/);
    const cached = [...(scanner as unknown as { cache: Map<string, unknown> }).cache.keys()];
    expect(cached.some((key) => key.includes("neutralized"))).toBe(false);
    expect(logs.join("\n")).not.toContain(SECRET);
  });

  it("writes one content-free audit line per rewritten file: label, source, name and the kinds, never a path, a value or a command", () => {
    seed();
    write("ws/skills/odd name/SKILL.md", HOOK_SKILL);
    write("ws/agents/clean.md", "---\nname: clean\ndescription: nothing to drop\n---\nbody\n");
    plan({ neutralize: true });
    const lines = logs.filter((l) => l.includes("command-settings.ignored"));
    expect(lines).toContain("[audit] command-settings.ignored label=reqlift source=skills name=probe setting=hooks");
    expect(lines).toContain("[audit] command-settings.ignored label=reqlift source=agents name=a setting=mcpServers");
    expect(lines).toContain("[audit] command-settings.ignored label=reqlift source=agents name=b setting=mcpServers");
    expect(lines).toContain("[audit] command-settings.ignored label=reqlift source=commands name=c setting=hooks");
    expect(lines).toContain("[audit] command-settings.ignored label=reqlift source=skills name=invalid setting=hooks");
    expect(lines.some((l) => l.includes("clean"))).toBe(false);
    const text = lines.join("\n");
    expect(text).not.toContain(root);
    expect(text).not.toContain("HOOKCMD");
    expect(text).not.toContain("touch");
  });

  it("leaves nothing behind after a start that fails once the content was planned: the run directory, with the copy, is removed", async () => {
    seed();
    const proxy = { isListening: () => true } as never;
    const config = { ...loadIsolationConfig({ HOME: root, AGENT_SANDBOX_ROOT: path.join(root, "sandbox") }), bwrapPath: "/usr/bin/true" };
    const run = new SandboxRun({ queryId: "q-8106", runLogDir: path.join(root, "no-log-dir"), runLogEnv: {}, neutralizeCommands: true, label: "reqlift", workspaceRoot: path.join(root, "ws"), config, proxy });
    expect(() => run.spawnHook({ command: "/bin/sh", args: ["-c", "true"], env: {}, signal: new AbortController().signal })).toThrow();
    const runs = path.join(root, "sandbox", "runs");
    const [name] = fs.readdirSync(runs);
    expect(fs.existsSync(path.join(runs, name, "trusted", "neutralized", "skills", "probe", "SKILL.md"))).toBe(true);
    await run.dispose();
    expect(fs.readdirSync(runs)).toEqual([]);
  });

  describe("a bounded walk and a bounded read (MVP-8126)", () => {
    const K = Buffer.byteLength(HOOK_SKILL);
    const wsRoot = () => path.join(root, "ws");
    const limitedLines = () => logs.filter((l) => l.includes("sandbox.content.limited"));
    const tooLargeLines = () => logs.filter((l) => l.includes("reason=too_large"));
    const symlinkLines = () => logs.filter((l) => l.includes("reason=symlink"));
    const LIMITED = /^\[audit\] sandbox\.content\.limited kind=snapshot-(skills|agents|commands) files=\d+ folders=\d+ examined=\d+ bytes=\d+ left_out=\d+ stopped=(true|false)$/;
    const fieldsOf = (line: string): Record<string, string> => Object.fromEntries([...line.matchAll(/(\w+)=(\S+)/g)].map((m) => [m[1], m[2]]));
    const snapOf = (entry: string, trustedDir = trusted()) => path.join(trustedDir, "neutralized", entry);

    /** Exactly one summary line, of the content-free shape, for `kind`, with these counts. */
    function expectOneLimited(kind: string, counts: Record<string, number | boolean>): void {
      const lines = limitedLines();
      expect(lines.length, "summary lines").toBe(1);
      expect(lines[0]).toMatch(LIMITED);
      const fields = fieldsOf(lines[0]);
      expect(fields.kind).toBe(`snapshot-${kind}`);
      for (const [key, value] of Object.entries(counts)) expect(fields[key], key).toBe(String(value));
    }

    /** Every file and folder of the copy, relative to its root (`/` separated), with a stack so a deep chain needs no recursion. */
    function treeOf(base: string): { files: string[]; folders: string[] } {
      const out = { files: [] as string[], folders: [] as string[] };
      const stack = [""];
      while (stack.length > 0) {
        const rel = stack.pop()!;
        for (const name of fs.readdirSync(rel ? path.join(base, rel) : base)) {
          const childRel = rel ? `${rel}/${name}` : name;
          if (fs.lstatSync(path.join(base, childRel)).isDirectory()) {
            out.folders.push(childRel);
            stack.push(childRel);
          } else out.files.push(childRel);
        }
      }
      return out;
    }

    /**
     * What every snapshot must be: a subset of the store in which every `.md` equals its rewritten source, every other
     * file is byte-identical, and nothing is a link or a special file.
     */
    function expectSnapshotInvariant(entry: string, where: { ws?: string; trustedDir?: string } = {}): { files: number; folders: number } {
      const source = path.join(where.ws ?? wsRoot(), entry);
      const copy = snapOf(entry, where.trustedDir);
      const problems: string[] = [];
      const counts = { files: 0, folders: 0 };
      const tree = treeOf(copy);
      for (const rel of tree.folders) {
        const stat = fs.lstatSync(path.join(copy, rel));
        const original = fs.lstatSync(path.join(source, rel), { throwIfNoEntry: false });
        if (!stat.isDirectory() || !original?.isDirectory()) problems.push(`folder ${rel}`);
        counts.folders++;
      }
      for (const rel of tree.files) {
        const stat = fs.lstatSync(path.join(copy, rel));
        const original = fs.lstatSync(path.join(source, rel), { throwIfNoEntry: false });
        if (!stat.isFile() || !original?.isFile()) {
          problems.push(`file ${rel}`);
          continue;
        }
        const input = fs.readFileSync(path.join(source, rel));
        const expected = /\.md$/i.test(rel) ? neutralizeCommandSettings(input).data : input;
        if (!fs.readFileSync(path.join(copy, rel)).equals(expected)) problems.push(`content ${rel}`);
        counts.files++;
      }
      expect(problems.slice(0, 5)).toEqual([]);
      return counts;
    }

    /** Counts the directory handles opened below `prefix`, the entries read through them and the handles closed. */
    function trackDirs(prefix: string, failAt?: string) {
      const state = { opened: 0, closed: 0, reads: 0 };
      const real = fs.opendirSync;
      vi.spyOn(fs, "opendirSync").mockImplementation(((target: fs.PathLike, ...rest: unknown[]) => {
        if (failAt !== undefined && String(target) === failAt) throw new Error("EMFILE");
        const dir = (real as (...args: unknown[]) => fs.Dir)(target, ...rest);
        if (String(target) === prefix || String(target).startsWith(prefix + path.sep)) {
          state.opened++;
          const read = dir.readSync.bind(dir);
          const close = dir.closeSync.bind(dir);
          dir.readSync = () => {
            state.reads++;
            return read();
          };
          dir.closeSync = () => {
            state.closed++;
            return close();
          };
        }
        return dir;
      }) as typeof fs.opendirSync);
      return state;
    }

    /** Runs `fn` with `fs.fstatSync` of the descriptor opened for `target` growing the file by `grow` bytes (real growth, once, after the real fstat). */
    function growAtFstat(target: string, grow: number) {
      const realOpen = fs.openSync;
      const realFstat = fs.fstatSync;
      const realRead = fs.readSync;
      const pathOf = new Map<number, string>();
      const state = { targetFd: -1, grown: false, targetBytes: 0, bytesBeforeTarget: 0, acceptedBefore: -1, otherBytes: 0 };
      vi.spyOn(fs, "openSync").mockImplementation(((p: fs.PathLike, ...rest: unknown[]) => {
        const fd = (realOpen as (...args: unknown[]) => number)(p, ...rest);
        pathOf.set(fd, String(p));
        if (String(p) === target) {
          state.targetFd = fd;
          state.acceptedBefore = state.otherBytes;
        }
        return fd;
      }) as typeof fs.openSync);
      vi.spyOn(fs, "fstatSync").mockImplementation(((fd: number, ...rest: unknown[]) => {
        const stat = (realFstat as (...args: unknown[]) => fs.Stats)(fd, ...rest);
        if (fd === state.targetFd && !state.grown) {
          state.grown = true;
          const extra = realOpen(target, "a");
          fs.writeSync(extra, Buffer.alloc(grow, 0x78));
          realClose(extra);
        }
        return stat;
      }) as typeof fs.fstatSync);
      const realClose = fs.closeSync;
      vi.spyOn(fs, "closeSync").mockImplementation(((fd: number) => {
        // A closed descriptor number is handed out again to the next file.
        if (fd === state.targetFd) state.targetFd = -1;
        return realClose(fd);
      }) as typeof fs.closeSync);
      vi.spyOn(fs, "readSync").mockImplementation(((fd: number, ...rest: unknown[]) => {
        const n = (realRead as (...args: unknown[]) => number)(fd, ...rest);
        if (fd === state.targetFd) state.targetBytes += n;
        else if ((pathOf.get(fd) ?? "").startsWith(path.join(wsRoot(), "skills"))) state.otherBytes += n;
        return n;
      }) as typeof fs.readSync);
      return state;
    }

    /* ---- A1: one row per boundary: exactly at the limit, and one over ---- */

    it("B1 file limit, exactly at it: maxFiles hooked markdown files of one length are complete, with no summary line", () => {
      for (let i = 0; i < 3; i++) write(`ws/skills/f${i}.md`, HOOK_SKILL);
      plan({ neutralize: true, limits: { maxFiles: 3 } });
      expect(limitedLines()).toEqual([]);
      expect(tooLargeLines()).toEqual([]);
      expect(expectSnapshotInvariant("skills")).toEqual({ files: 3, folders: 0 });
    });

    it("B2 file limit, one over: the walk stops at the extra file, with one content-free summary line and no too_large line", () => {
      for (let i = 0; i < 4; i++) write(`ws/skills/f${i}.md`, HOOK_SKILL);
      plan({ neutralize: true, limits: { maxFiles: 3 } });
      expectOneLimited("skills", { files: 3, folders: 0, left_out: 1, stopped: true });
      expect(tooLargeLines()).toEqual([]);
      expect(expectSnapshotInvariant("skills")).toEqual({ files: 3, folders: 0 });
    });

    it("B3 folder limit, exactly at it: maxFolders empty folders are complete, with no summary line", () => {
      for (let i = 0; i < 3; i++) fs.mkdirSync(path.join(wsRoot(), "skills", `d${i}`), { recursive: true });
      plan({ neutralize: true, limits: { maxFolders: 3 } });
      expect(limitedLines()).toEqual([]);
      expect(expectSnapshotInvariant("skills")).toEqual({ files: 0, folders: 3 });
    });

    it("B4 folder limit, one over: the extra folder is not created and the walk stops, with one summary line", () => {
      for (let i = 0; i < 4; i++) fs.mkdirSync(path.join(wsRoot(), "skills", `d${i}`), { recursive: true });
      plan({ neutralize: true, limits: { maxFolders: 3 } });
      expectOneLimited("skills", { files: 0, folders: 3, left_out: 1, stopped: true });
      expect(expectSnapshotInvariant("skills")).toEqual({ files: 0, folders: 3 });
    });

    function linkStore(count: number): void {
      fs.mkdirSync(path.join(wsRoot(), "skills"), { recursive: true });
      for (let i = 0; i < count; i++) fs.symlinkSync("nowhere", path.join(wsRoot(), "skills", `l${i}`));
    }

    it("B5 examined-entry limit, exactly at it: maxExamined symlinks each get their line and there is no summary line", () => {
      linkStore(6);
      plan({ neutralize: true, limits: { maxExamined: 6 } });
      expect(symlinkLines().length).toBe(6);
      expect(limitedLines()).toEqual([]);
      expect(expectSnapshotInvariant("skills")).toEqual({ files: 0, folders: 0 });
    });

    it("B6 examined-entry limit, one over: still six symlink lines, and one summary line with stopped=true and nothing left out", () => {
      linkStore(7);
      plan({ neutralize: true, limits: { maxExamined: 6 } });
      expect(symlinkLines().length).toBe(6);
      expectOneLimited("skills", { files: 0, folders: 0, examined: 6, left_out: 0, stopped: true });
      expect(expectSnapshotInvariant("skills")).toEqual({ files: 0, folders: 0 });
    });

    it("B7 byte limit, exactly at it: files of one length k with maxBytes 6k are complete, with no summary line", () => {
      for (let i = 0; i < 6; i++) write(`ws/skills/b${i}.md`, HOOK_SKILL);
      plan({ neutralize: true, limits: { maxBytes: 6 * K } });
      expect(limitedLines()).toEqual([]);
      expect(tooLargeLines()).toEqual([]);
      expect(expectSnapshotInvariant("skills")).toEqual({ files: 6, folders: 0 });
    });

    it("B8 byte limit, one over: six files are copied and the seventh is left out, with one summary line that does not stop the walk", () => {
      for (let i = 0; i < 7; i++) write(`ws/skills/b${i}.md`, HOOK_SKILL);
      plan({ neutralize: true, limits: { maxBytes: 6 * K } });
      expectOneLimited("skills", { files: 6, folders: 0, bytes: 6 * K, left_out: 1, stopped: false });
      expect(tooLargeLines()).toEqual([]);
      expect(expectSnapshotInvariant("skills")).toEqual({ files: 6, folders: 0 });
    });

    /* ---- A2: the cost of the 40,000-folder store is bounded by operation counts ---- */

    it("B9 a flat store of 40,000 empty folders (default limits): 2000 folders are copied, 2001 entries are examined, and one summary line says so", () => {
      const big = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "mvp8126-bound-")));
      try {
        const entry = path.join(big, "ws", "skills");
        fs.mkdirSync(entry, { recursive: true });
        for (let i = 0; i < 40_000; i++) fs.mkdirSync(path.join(entry, `d${i}`));
        const copy = path.join(big, "trusted", "neutralized", "skills");
        const handles = trackDirs(entry);
        const realMkdir = fs.mkdirSync;
        const realLstat = fs.lstatSync;
        const counts = { mkdirBelow: 0, lstatBelow: 0 };
        vi.spyOn(fs, "mkdirSync").mockImplementation(((target: fs.PathLike, ...rest: unknown[]) => {
          if (String(target).startsWith(copy + path.sep)) counts.mkdirBelow++;
          return (realMkdir as (...args: unknown[]) => unknown)(target, ...rest);
        }) as typeof fs.mkdirSync);
        vi.spyOn(fs, "lstatSync").mockImplementation(((target: fs.PathLike, ...rest: unknown[]) => {
          if (String(target).startsWith(entry + path.sep)) counts.lstatBelow++;
          return (realLstat as (...args: unknown[]) => unknown)(target, ...rest);
        }) as typeof fs.lstatSync);
        const started = Date.now();
        plan({ neutralize: true, ws: path.join(big, "ws"), trustedDir: path.join(big, "trusted") });
        const planMs = Date.now() - started;
        vi.restoreAllMocks();
        const copied = fs.readdirSync(copy).length;
        const examined = Number(fieldsOf(limitedLines()[0] ?? "").examined ?? 0);
        process.stderr.write(`MVP8126-BOUND dirsStored=40000 dirsCopied=${copied} examined=${examined} planMs=${planMs} opendir=${handles.opened} lstat=${counts.lstatBelow} mkdir=${counts.mkdirBelow} listReads=${handles.reads}\n`);
        expect(handles.opened, "directory handles opened (the entry and 2000 folders)").toBe(2001);
        expect(counts.lstatBelow, "lstat calls below the entry").toBe(2001);
        expect(counts.mkdirBelow, "mkdir calls below the copy").toBe(2000);
        expect(handles.reads, "listing reads").toBeLessThanOrEqual(2001 + 2000 + 1);
        expect(handles.closed, "handles closed").toBe(handles.opened);
        expectOneLimited("skills", { files: 0, folders: 2000, examined: 2001, left_out: 1, stopped: true });
        expect(copied).toBe(2000);
      } finally {
        fs.rmSync(big, { recursive: true, force: true });
      }
    }, 60_000);

    /* ---- A3: the acceptance scenarios at their own numbers ---- */

    it("B10 2500 hooked markdown files in 50 folders: exactly 2000 are copied and rewritten, with one summary line that holds no file name", () => {
      for (let d = 0; d < 50; d++) {
        write(`ws/skills/s${d}/SKILL.md`, HOOK_SKILL);
        for (let f = 1; f < 50; f++) write(`ws/skills/s${d}/r${f}.md`, HOOK_SKILL);
      }
      plan({ neutralize: true });
      expectOneLimited("skills", { files: 2000, left_out: 1, stopped: true });
      expect(tooLargeLines()).toEqual([]);
      expect(expectSnapshotInvariant("skills").files).toBe(2000);
    }, 60_000);

    it("B11 2000 files in 2000 folders (far below the byte limit): the copy is complete, with no summary line", () => {
      for (let d = 0; d < 2000; d++) write(`ws/skills/f${d}/SKILL.md`, HOOK_SKILL);
      plan({ neutralize: true });
      expect(limitedLines()).toEqual([]);
      expect(tooLargeLines()).toEqual([]);
      expect(expectSnapshotInvariant("skills")).toEqual({ files: 2000, folders: 2000 });
    }, 60_000);

    it("B12 15,000 symlinks: at most 10,000 symlink lines, one summary line with stopped=true", () => {
      linkStore(15_000);
      plan({ neutralize: true });
      expect(symlinkLines().length).toBeLessThanOrEqual(10_000);
      expectOneLimited("skills", { files: 0, folders: 0, examined: 10_000, left_out: 0, stopped: true });
      expect(expectSnapshotInvariant("skills")).toEqual({ files: 0, folders: 0 });
    }, 60_000);

    /* ---- A4: a file behind the folder limit ---- */

    it("B13 a file inside the folder the walk leaves out (2001 sibling folders) is never copied, and the same store gives the same copy every run", () => {
      for (let i = 0; i < 2001; i++) fs.mkdirSync(path.join(wsRoot(), "skills", `d${i}`), { recursive: true });
      const listing = fs.opendirSync(path.join(wsRoot(), "skills"));
      let leftOut = "";
      for (let i = 0; i < 2001; i++) leftOut = listing.readSync()!.name;
      listing.closeSync();
      write(`ws/skills/${leftOut}/late.md`, HOOK_SKILL);
      const shapes: string[][] = [];
      for (const run of ["one", "two", "three"]) {
        logs.length = 0;
        const trustedDir = path.join(root, `trusted-${run}`);
        plan({ neutralize: true, trustedDir });
        expectOneLimited("skills", { files: 0, folders: 2000, examined: 2001, left_out: 1, stopped: true });
        expect(fs.existsSync(path.join(snapOf("skills", trustedDir), leftOut))).toBe(false);
        expect(expectSnapshotInvariant("skills", { trustedDir })).toEqual({ files: 0, folders: 2000 });
        const tree = treeOf(snapOf("skills", trustedDir));
        shapes.push([...tree.folders, ...tree.files].sort());
      }
      expect(shapes[1]).toEqual(shapes[0]);
      expect(shapes[2]).toEqual(shapes[0]);
    }, 60_000);

    /* ---- A5: a file that grows between fstat and read ---- */

    it("B14 a file that grows past the remaining budget between fstat and read is left out whole, never truncated, and is read for at most the remaining budget plus one byte", () => {
      for (const name of ["a.md", "b.md", "grow.md"]) write(`ws/skills/g/${name}`, HOOK_SKILL);
      const maxBytes = 3 * K + 10;
      const state = growAtFstat(path.join(wsRoot(), "skills", "g", "grow.md"), maxBytes);
      plan({ neutralize: true, limits: { maxBytes } });
      vi.restoreAllMocks();
      expect(state.grown, "the file grew while it was being read").toBe(true);
      expect(fs.existsSync(path.join(snapOf("skills"), "g", "grow.md"))).toBe(false);
      expect(fs.existsSync(path.join(snapOf("skills"), "g", "a.md"))).toBe(true);
      expect(fs.existsSync(path.join(snapOf("skills"), "g", "b.md"))).toBe(true);
      expectOneLimited("skills", { files: 2, bytes: 2 * K, left_out: 1, stopped: false });
      expect(tooLargeLines()).toEqual([]);
      expect(state.targetBytes, "bytes read from the growing file").toBeLessThanOrEqual(maxBytes - state.acceptedBefore + 1);
      expect(expectSnapshotInvariant("skills")).toEqual({ files: 2, folders: 1 });
    });

    it("B15 readFileNoFollow with a limit returns null for a file that grows past it between fstat and read, and the whole content for one that stays within it", () => {
      const grower = write("grow.txt", "0123456789");
      const state = growAtFstat(grower, 100);
      expect(readFileNoFollow(grower, 20)?.length ?? null).toBeNull();
      vi.restoreAllMocks();
      expect(state.grown).toBe(true);
      const steady = write("steady.txt", "0123456789");
      expect(readFileNoFollow(steady, 20)?.toString("utf8")).toBe("0123456789");
      expect(readFileNoFollow(steady, 10)?.toString("utf8")).toBe("0123456789");
      expect(readFileNoFollow(steady, 9)).toBeNull();
    });

    it("B16 an unlimited read and a copy still succeed for a small file", () => {
      const file = write("small.txt", "small content");
      expect(readFileNoFollow(file, Number.MAX_SAFE_INTEGER)?.toString("utf8")).toBe("small content");
      const dest = path.join(root, "copy.txt");
      expect(copyFileNoFollow(file, dest)).toBe(true);
      expect(fs.readFileSync(dest, "utf8")).toBe("small content");
    });

    /* ---- A6: limits are per entry ---- */

    it("B17 skills over the folder limit: agents with three entries stay complete and only the skills entry names a limit", () => {
      for (let i = 0; i < 4; i++) write(`ws/skills/s${i}/SKILL.md`, HOOK_SKILL);
      for (let i = 0; i < 3; i++) write(`ws/agents/a${i}.md`, HOOK_AGENT);
      plan({ neutralize: true, limits: { maxFolders: 3 } });
      expectOneLimited("skills", { folders: 3, left_out: 1, stopped: true });
      expect(expectSnapshotInvariant("agents")).toEqual({ files: 3, folders: 0 });
    });

    it("B18 agents over the file limit: commands with three entries stay complete and only the agents entry names a limit", () => {
      for (let i = 0; i < 4; i++) write(`ws/agents/a${i}.md`, HOOK_AGENT);
      for (let i = 0; i < 3; i++) write(`ws/commands/c${i}.md`, HOOK_SKILL);
      plan({ neutralize: true, limits: { maxFiles: 3 } });
      expectOneLimited("agents", { files: 3, left_out: 1, stopped: true });
      expect(expectSnapshotInvariant("commands")).toEqual({ files: 3, folders: 0 });
    });

    /* ---- A7: a run with the Bash grant is unchanged ---- */

    it("B19 a run with the Bash grant binds the live entry whatever its size: no copy, no summary line", () => {
      for (let i = 0; i < 5; i++) fs.mkdirSync(path.join(wsRoot(), "skills", `d${i}`), { recursive: true });
      const p = plan({ neutralize: false, limits: { maxFolders: 3, maxFiles: 1, maxExamined: 2 } });
      expect(mountOf(p, "skills")!.src).toBe(path.join(wsRoot(), "skills"));
      expect(fs.existsSync(path.join(trusted(), "neutralized"))).toBe(false);
      expect(limitedLines()).toEqual([]);
    });

    /* ---- A8: fail closed, and no handle stays open ---- */

    it("B20 a listing that fails part-way gives the empty stand-in and closes every handle it opened", () => {
      write("ws/skills/a/SKILL.md", HOOK_SKILL);
      write("ws/skills/probe/SKILL.md", HOOK_SKILL);
      // Node loads its recursive remover on first use and keeps the `readdirSync` it finds then: load it before the spies.
      fs.rmSync(path.join(root, "warm-up"), { recursive: true, force: true });
      const handles = trackDirs(path.join(wsRoot(), "skills"), path.join(wsRoot(), "skills", "probe"));
      const realReaddir = fs.readdirSync;
      vi.spyOn(fs, "readdirSync").mockImplementation(((target: fs.PathLike, ...rest: unknown[]) => {
        if (String(target) === path.join(wsRoot(), "skills", "probe")) throw new Error("EMFILE");
        return (realReaddir as (...args: unknown[]) => unknown)(target, ...rest);
      }) as typeof fs.readdirSync);
      const p = plan({ neutralize: true });
      vi.restoreAllMocks();
      expect(mountOf(p, "skills")!.src).toBe(path.join(trusted(), "empty-dir"));
      expect(fs.existsSync(path.join(trusted(), "neutralized", "skills"))).toBe(false);
      expect(limitedLines()).toEqual([]);
      expect(handles.closed).toBe(handles.opened);
    });

    it("B21 a chain of 60 folders under maxFolders 50 stops at 50 folders, with every handle closed", () => {
      let chain = path.join(wsRoot(), "skills");
      for (let i = 0; i < 60; i++) chain = path.join(chain, "d");
      fs.mkdirSync(chain, { recursive: true });
      write("ws/skills/top.md", HOOK_SKILL);
      const handles = trackDirs(path.join(wsRoot(), "skills"));
      plan({ neutralize: true, limits: { maxFolders: 50 } });
      vi.restoreAllMocks();
      expectOneLimited("skills", { folders: 50, left_out: 1, stopped: true });
      expect(expectSnapshotInvariant("skills")).toEqual({ files: 1, folders: 50 });
      expect(handles.closed).toBe(handles.opened);
    });

    it("B22 the deepest chain the path length allows, at default limits: the copy ends at the folder limit or fails closed, never live or unrewritten, with every handle closed", () => {
      const sourceBase = path.join(wsRoot(), "skills");
      const depth = Math.floor((4095 - sourceBase.length) / 2);
      let chain = sourceBase;
      for (let i = 0; i < depth; i++) chain = path.join(chain, "d");
      fs.mkdirSync(chain, { recursive: true });
      write("ws/skills/top.md", HOOK_SKILL);
      const handles = trackDirs(sourceBase);
      try {
        const p = plan({ neutralize: true });
        vi.restoreAllMocks();
        const src = mountOf(p, "skills")!.src;
        expect([snapOf("skills"), path.join(trusted(), "empty-dir")]).toContain(src);
        expect(p.mounts.some((m) => m.src === sourceBase)).toBe(false);
        if (src === snapOf("skills")) {
          expect(expectSnapshotInvariant("skills").folders).toBeLessThanOrEqual(2000);
        } else {
          expect(fs.existsSync(snapOf("skills"))).toBe(false);
        }
        expect(handles.closed).toBe(handles.opened);
      } finally {
        // The recursive remover of the test's own cleanup overflows its stack on a chain this deep: remove it from the bottom up.
        for (const base of [sourceBase, snapOf("skills")]) {
          let deepest = base;
          while (fs.existsSync(deepest + "/d")) deepest += "/d";
          for (let at = deepest; at !== base; at = path.dirname(at)) fs.rmdirSync(at);
        }
      }
    }, 60_000);
  });
});

function execFifo(file: string): void {
  execFileSync("mkfifo", [file]);
}
