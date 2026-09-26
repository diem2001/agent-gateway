/**
 * MVP-7614 — contract, queue and injection rows for the git routes, run
 * in-process against the real router with a fake `git` wrapper first on PATH
 * (it logs every invocation and can sleep before running the real git).
 *
 * Everything lives under one test-owned temp root: WORKSPACE_ROOT, HOME, TMPDIR,
 * the bare remotes, the loopback dumb-HTTP remote and the injection markers.
 * Global and system git config are switched off for the router's git and for
 * the fixtures, so no credential helper of the host ever sees a test token.
 */
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import express from "express";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { createFakeGit, type FakeGitInvocation } from "./helpers/fake-git.js";
import {
  closedPort,
  createBareRepo,
  fixtureGit,
  pushFixtureCommit,
  startDumbHttpGitRemote,
  type DumbHttpGitRemote,
} from "./helpers/dumb-http-git-remote.js";

const ROOT = fs.mkdtempSync(path.join(os.tmpdir(), "mvp7614-contract-"));
const WORKSPACE = path.join(ROOT, "workspace");
const PROJECTS = path.join(WORKSPACE, "projects");
const TMP = path.join(ROOT, "tmp");
const REMOTES = path.join(ROOT, "remotes");
const PWN = path.join(ROOT, "pwn");
for (const dir of [PROJECTS, TMP, REMOTES, PWN, path.join(ROOT, "home")]) fs.mkdirSync(dir, { recursive: true });

const fake = createFakeGit(ROOT);
const REAL_GIT = fake.realGit;

/** Test timeout seam: production keeps 120 s. */
const TIMEOUT_MS = 3000;

process.env.WORKSPACE_ROOT = WORKSPACE;
process.env.HOME = path.join(ROOT, "home");
process.env.TMPDIR = TMP;
process.env.GIT_CONFIG_NOSYSTEM = "1";
process.env.GIT_CONFIG_GLOBAL = "/dev/null";
process.env.GIT_TIMEOUT_MS = String(TIMEOUT_MS);
process.env.PATH = `${fake.binDir}${path.delimiter}${process.env.PATH ?? ""}`;
for (const key of ["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"]) delete process.env[key];

interface LoadedApp {
  port: number;
  server: Server;
  /** The queue module instance the router of this app uses. */
  gitExec: typeof import("../git-exec.js");
}

async function loadApp(maxConcurrency?: string): Promise<LoadedApp> {
  if (maxConcurrency === undefined) delete process.env.GIT_MAX_CONCURRENCY;
  else process.env.GIT_MAX_CONCURRENCY = maxConcurrency;
  vi.resetModules();
  const { default: gitRoutes } = await import("../routes/git.js");
  const gitExec = await import("../git-exec.js");
  const app = express();
  app.use(express.json());
  app.use(gitRoutes);
  const server = await new Promise<Server>((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  return { port: (server.address() as AddressInfo).port, server, gitExec };
}

async function closeApp(app: LoadedApp): Promise<void> {
  await new Promise<void>((resolve) => app.server.close(() => resolve()));
}

interface Reply {
  status: number;
  body: Record<string, unknown>;
}

async function call(app: LoadedApp, method: "GET" | "POST", urlPath: string, body?: Record<string, unknown>): Promise<Reply> {
  const res = await fetch(`http://127.0.0.1:${app.port}${urlPath}`, {
    method,
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

const clone = (app: LoadedApp, body: Record<string, unknown>) => call(app, "POST", "/v1/workspace/git/clone", body);
const pull = (app: LoadedApp, body: Record<string, unknown>) => call(app, "POST", "/v1/workspace/git/pull", body);
const status = (app: LoadedApp, userPath: string) => call(app, "GET", `/v1/workspace/git/status?path=${encodeURIComponent(userPath)}`);

let remoteSeq = 0;
/** A new bare remote with one commit on main. */
function bareRemote(label: string): string {
  const bare = path.join(REMOTES, `${label}-${++remoteSeq}.git`);
  createBareRepo(REAL_GIT, bare);
  return bare;
}

/** A checkout under PROJECTS, cloned by the fixture (not through the router). */
function fixtureCheckout(bare: string, userPath: string): string {
  const target = path.join(PROJECTS, userPath);
  fixtureGit(REAL_GIT, ["clone", "-b", "main", "--", bare, target], ROOT);
  return target;
}

function shortSha(bare: string, ref = "main"): string {
  return fixtureGit(REAL_GIT, ["rev-parse", "--short", ref], bare);
}

/** Every invocation that ran in or on `target` (its cwd, or an argument naming it). */
function touching(target: string): (inv: FakeGitInvocation) => boolean {
  return (inv) => inv.cwd === target || inv.cwd.startsWith(target + path.sep) || inv.argv.includes(target);
}

/** A 500 whose body is exactly `{ error: <string> }` without credentials or Node's command line. */
function expectCleanGitError(reply: Reply, secrets: string[] = []): string {
  expect(reply.status).toBe(500);
  expect(Object.keys(reply.body)).toEqual(["error"]);
  const text = reply.body.error;
  expect(typeof text).toBe("string");
  expect(text as string).not.toMatch(/^Command failed/);
  expect(text as string).not.toMatch(/[a-z][a-z0-9+.-]*:\/\/[^/\s'"@]*:[^/\s'"@]*@/i);
  for (const secret of secrets) expect(text as string).not.toContain(secret);
  return text as string;
}

function keyFilesInTmp(): string[] {
  return fs.readdirSync(TMP).filter((name) => name.startsWith("agw-ssh-"));
}

const FAKE_SSH_KEY = [
  "-----BEGIN OPENSSH PRIVATE KEY-----",
  "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW",
  "QyNTUxOQAAACBmYWtlLWtleS1mb3ItbXZwNzYxNC10ZXN0cy1vbmx5AAAAAAAAAAAAAAAA",
  "-----END OPENSSH PRIVATE KEY-----",
].join("\n");

/** Resolves once `n` requests wait for a global slot. */
async function waitForWaiting(app: LoadedApp, n: number): Promise<void> {
  const started = Date.now();
  while (app.gitExec.gitQueueSnapshot().waiting < n) {
    if (Date.now() - started > 10_000) throw new Error(`fewer than ${n} requests waiting after 10 s`);
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

let httpRemote: DumbHttpGitRemote;

beforeAll(async () => {
  httpRemote = await startDumbHttpGitRemote(ROOT, REAL_GIT);
});

afterAll(async () => {
  await httpRemote?.close();
  fs.rmSync(ROOT, { recursive: true, force: true });
});

/* ------------------------------------------------------------------ */
/*  Contract table (default GIT_MAX_CONCURRENCY)                        */
/* ------------------------------------------------------------------ */

describe("git endpoints keep their contract", () => {
  let app: LoadedApp;
  beforeAll(async () => {
    app = await loadApp(undefined);
  });
  afterAll(async () => {
    fake.setSlow(null);
    await closeApp(app);
  });

  it("clone of a new repository: 200 cloned with exactly path, branch, commit", async () => {
    const bare = bareRemote("new");
    const reply = await clone(app, { url: bare, path: "contract-new" });
    expect(reply.status).toBe(200);
    expect(reply.body).toEqual({ status: "cloned", path: "contract-new", branch: "main", commit: shortSha(bare) });
  });

  it("clone onto an existing checkout: 200 pulled with exactly path, branch, commit", async () => {
    const bare = bareRemote("exists");
    fixtureCheckout(bare, "contract-exists");
    const reply = await clone(app, { url: bare, path: "contract-exists" });
    expect(reply.status).toBe(200);
    expect(reply.body).toEqual({ status: "pulled", path: "contract-exists", branch: "main", commit: shortSha(bare) });
  });

  it("pull with nothing new: 200 up-to-date; with new commits: 200 updated", async () => {
    const bare = bareRemote("pull");
    fixtureCheckout(bare, "contract-pull");
    const first = await pull(app, { path: "contract-pull" });
    expect(first.status).toBe(200);
    expect(first.body).toEqual({ status: "up-to-date", branch: "main", commit: shortSha(bare) });

    pushFixtureCommit(REAL_GIT, bare, "second commit");
    const second = await pull(app, { path: "contract-pull", branch: "main" });
    expect(second.status).toBe(200);
    expect(second.body).toEqual({ status: "updated", branch: "main", commit: shortSha(bare) });
  });

  it("status of an existing, a dirty and a missing repository", async () => {
    const bare = bareRemote("status");
    const target = fixtureCheckout(bare, "contract-status");
    const clean = await status(app, "contract-status");
    expect(clean.status).toBe(200);
    expect(Object.keys(clean.body).sort()).toEqual(["branch", "commit", "dirty", "exists", "lastCommitDate"]);
    expect(clean.body).toMatchObject({ exists: true, branch: "main", commit: shortSha(bare), dirty: false });
    expect(typeof clean.body.lastCommitDate).toBe("string");

    fs.writeFileSync(path.join(target, "untracked.txt"), "dirty");
    expect((await status(app, "contract-status")).body).toMatchObject({ exists: true, dirty: true });

    const missing = await status(app, "contract-missing");
    expect(missing.status).toBe(200);
    expect(missing.body).toEqual({ exists: false });
  });

  it("400 rows keep their text: missing url, missing path, traversal", async () => {
    expect(await clone(app, { path: "x" })).toEqual({ status: 400, body: { error: "url is required" } });
    expect(await clone(app, { url: "https://example.invalid/r.git" })).toEqual({ status: 400, body: { error: "path is required" } });
    const invalid = { status: 400, body: { error: "Invalid path (must be relative, no traversal)" } };
    expect(await clone(app, { url: "https://example.invalid/r.git", path: "../x" })).toEqual(invalid);
    expect(await pull(app, {})).toEqual({ status: 400, body: { error: "path is required" } });
    expect(await pull(app, { path: "../../etc" })).toEqual(invalid);
    expect(await call(app, "GET", "/v1/workspace/git/status")).toEqual({ status: 400, body: { error: "path query parameter is required" } });
    expect(await status(app, "../../etc")).toEqual(invalid);
  });

  it("404 for a folder that is not a git repository", async () => {
    fs.mkdirSync(path.join(PROJECTS, "contract-not-a-repo"), { recursive: true });
    expect(await pull(app, { path: "contract-not-a-repo" })).toEqual({
      status: 404,
      body: { error: "Not a git repository: contract-not-a-repo" },
    });
  });

  it("a branch that starts with '-' is 400 Invalid branch on clone and pull, and no git process starts", async () => {
    const bare = bareRemote("dash");
    fixtureCheckout(bare, "contract-dash");
    fake.clearLog();
    expect(await clone(app, { url: bare, path: "contract-dash-new", branch: "-b" })).toEqual({ status: 400, body: { error: "Invalid branch" } });
    expect(await pull(app, { path: "contract-dash", branch: "--orphan=x" })).toEqual({ status: 400, body: { error: "Invalid branch" } });
    expect(fake.invocations()).toEqual([]);
  });

  it("wrong credentials: 500 with git's message and no credentials (clone and pull)", async () => {
    const wrongPassword = httpRemote.wrongAuthUrl.split("@")[0].split(":").pop()!;
    const cloneReply = await clone(app, { url: httpRemote.wrongAuthUrl, path: "contract-wrong-auth" });
    const cloneText = expectCleanGitError(cloneReply, [httpRemote.token, wrongPassword]);
    expect(cloneText).toMatch(/Authentication failed/);

    // Cloned from the bare path (a synchronous fixture clone over HTTP would block the
    // in-process remote), then pointed at the token-bearing URL.
    const authCheckout = fixtureCheckout(httpRemote.barePath, "contract-auth-pull");
    fixtureGit(REAL_GIT, ["remote", "set-url", "origin", httpRemote.authUrl], authCheckout);
    httpRemote.setReject(true);
    try {
      const pullReply = await pull(app, { path: "contract-auth-pull" });
      expect(expectCleanGitError(pullReply, [httpRemote.token])).toMatch(/Authentication failed/);
    } finally {
      httpRemote.setReject(false);
    }
  });

  it("a remote that does not exist: 500 with git's message and no credentials", async () => {
    const token = "SECRET-TOKEN-missing-remote-7614";
    const port = await closedPort();
    const refused = await clone(app, { url: `http://user:${token}@127.0.0.1:${port}/missing.git`, path: "contract-refused" });
    expect(expectCleanGitError(refused, [token])).toMatch(/unable to access|Failed to connect|Could not connect/i);

    const missing = await clone(app, { url: path.join(REMOTES, "does-not-exist.git"), path: "contract-no-remote" });
    expect(expectCleanGitError(missing)).toMatch(/does not exist/);
  });

  it("git exceeding the time limit: 500 'git <subcommand> timed out after <n> s' (clone and pull)", async () => {
    const seconds = TIMEOUT_MS / 1000;
    const bare = bareRemote("slow");
    fake.setSlow({ sleepMs: TIMEOUT_MS + 3000, on: ["clone"], match: "contract-timeout-clone" });
    const started = Date.now();
    const cloneReply = await clone(app, { url: bare, path: "contract-timeout-clone" });
    expect(cloneReply).toEqual({ status: 500, body: { error: `git clone timed out after ${seconds} s` } });
    expect(Date.now() - started).toBeLessThan(TIMEOUT_MS + 3000);

    fixtureCheckout(bare, "contract-timeout-pull");
    fake.setSlow({ sleepMs: TIMEOUT_MS + 3000, on: ["pull"], match: "contract-timeout-pull" });
    const pullReply = await pull(app, { path: "contract-timeout-pull" });
    expect(pullReply).toEqual({ status: 500, body: { error: `git pull timed out after ${seconds} s` } });
    fake.setSlow(null);
  }, 30_000);
});

/* ------------------------------------------------------------------ */
/*  Queues with the default limit                                       */
/* ------------------------------------------------------------------ */

describe("git queues (default GIT_MAX_CONCURRENCY = 3)", () => {
  let app: LoadedApp;
  beforeAll(async () => {
    app = await loadApp(undefined);
  });
  afterAll(async () => {
    fake.setSlow(null);
    await closeApp(app);
  });

  it("a burst of 10 clones for 10 repositories: all succeed, a few at a time, never more than 3 git processes", async () => {
    const bares = Array.from({ length: 10 }, (_, i) => bareRemote(`burst-${i}`));
    fake.clearLog();
    fake.setSlow({ sleepMs: 800, on: ["clone"], match: "burst-target-" });
    const replies = await Promise.all(bares.map((bare, i) => clone(app, { url: bare, path: `burst-target-${i}` })));
    fake.setSlow(null);
    for (const [i, reply] of replies.entries()) {
      expect(reply.status).toBe(200);
      expect(reply.body).toMatchObject({ status: "cloned", path: `burst-target-${i}` });
    }
    const overlap = fake.maxOverlap();
    expect(overlap).toBeLessThanOrEqual(3);
    // "A few at a time": the burst really ran concurrently.
    expect(overlap).toBeGreaterThanOrEqual(2);
  }, 60_000);

  it("an existing valid checkout: a pull and then a clone run one after the other; the clone sees the pull's result", async () => {
    const bare = bareRemote("same-pull");
    const target = fixtureCheckout(bare, "same-pull-clone");
    pushFixtureCommit(REAL_GIT, bare, "new upstream commit");
    const newCommit = shortSha(bare);
    fake.clearLog();
    fake.setSlow({ sleepMs: 1500, on: ["pull"], match: "same-pull-clone" });
    const first = pull(app, { path: "same-pull-clone" });
    await fake.waitForStart((inv) => inv.subcommand === "pull" && inv.cwd === target);
    const second = clone(app, { url: bare, path: "same-pull-clone" });
    const [a, b] = await Promise.all([first, second]);
    fake.setSlow(null);
    expect(a).toEqual({ status: 200, body: { status: "updated", branch: "main", commit: newCommit } });
    expect(b).toEqual({ status: 200, body: { status: "pulled", path: "same-pull-clone", branch: "main", commit: newCommit } });
    expect(fake.maxOverlap(touching(target))).toBe(1);
  }, 30_000);

  it("no checkout yet: two first clones run one after the other; the second pulls what the first cloned", async () => {
    const bare = bareRemote("same-clone");
    const target = path.join(PROJECTS, "same-two-clones");
    fake.clearLog();
    fake.setSlow({ sleepMs: 1500, on: ["clone"], match: "same-two-clones" });
    const first = clone(app, { url: bare, path: "same-two-clones" });
    await fake.waitForStart((inv) => inv.subcommand === "clone" && inv.argv.includes(target));
    const second = clone(app, { url: bare, path: "same-two-clones" });
    const [a, b] = await Promise.all([first, second]);
    fake.setSlow(null);
    expect(a).toEqual({ status: 200, body: { status: "cloned", path: "same-two-clones", branch: "main", commit: shortSha(bare) } });
    expect(b).toEqual({ status: 200, body: { status: "pulled", path: "same-two-clones", branch: "main", commit: shortSha(bare) } });
    expect(fake.maxOverlap(touching(target))).toBe(1);
  }, 30_000);

  it("no checkout yet: a status behind a first clone reports the cloned repository", async () => {
    const bare = bareRemote("same-status");
    const target = path.join(PROJECTS, "same-clone-status");
    fake.clearLog();
    fake.setSlow({ sleepMs: 1500, on: ["clone"], match: "same-clone-status" });
    const first = clone(app, { url: bare, path: "same-clone-status" });
    await fake.waitForStart((inv) => inv.subcommand === "clone" && inv.argv.includes(target));
    const second = status(app, "same-clone-status");
    const [a, b] = await Promise.all([first, second]);
    fake.setSlow(null);
    expect(a.body).toMatchObject({ status: "cloned", commit: shortSha(bare) });
    expect(b.status).toBe(200);
    expect(b.body).toMatchObject({ exists: true, branch: "main", commit: shortSha(bare), dirty: false });
    expect(fake.maxOverlap(touching(target))).toBe(1);
  }, 30_000);
});

/* ------------------------------------------------------------------ */
/*  Queues with a limit of one                                          */
/* ------------------------------------------------------------------ */

describe("git queues (GIT_MAX_CONCURRENCY = 1)", () => {
  let app: LoadedApp;
  beforeAll(async () => {
    app = await loadApp("1");
  });
  afterAll(async () => {
    fake.setSlow(null);
    await closeApp(app);
  });

  it("waiting requests start in arrival order A, B, C", async () => {
    const [ba, bb, bc] = ["fifo-a", "fifo-b", "fifo-c"].map((label) => bareRemote(label));
    const targets = ["fifo-target-a", "fifo-target-b", "fifo-target-c"].map((p) => path.join(PROJECTS, p));
    fake.clearLog();
    fake.setSlow({ sleepMs: 1500, on: ["clone"], match: "fifo-target-a" });
    const a = clone(app, { url: ba, path: "fifo-target-a" });
    await fake.waitForStart((inv) => inv.argv.includes(targets[0]));
    const b = clone(app, { url: bb, path: "fifo-target-b" });
    await waitForWaiting(app, 1);
    const c = clone(app, { url: bc, path: "fifo-target-c" });
    await waitForWaiting(app, 2);
    const replies = await Promise.all([a, b, c]);
    fake.setSlow(null);
    for (const reply of replies) expect(reply.body).toMatchObject({ status: "cloned" });

    const firstStart = targets.map((target) => Math.min(...fake.invocations().filter(touching(target)).map((inv) => inv.start)));
    const lastEnd = targets.map((target) => Math.max(...fake.invocations().filter(touching(target)).map((inv) => inv.end ?? Infinity)));
    expect(firstStart[0]).toBeLessThan(firstStart[1]);
    expect(firstStart[1]).toBeLessThan(firstStart[2]);
    expect(firstStart[1]).toBeGreaterThanOrEqual(lastEnd[0]);
    expect(firstStart[2]).toBeGreaterThanOrEqual(lastEnd[1]);
    expect(fake.maxOverlap()).toBe(1);
  }, 30_000);

  for (const outcome of ["fail", "timeout"] as const) {
    it(`an operation that ends with ${outcome} frees its place: the waiting operations on R and S complete, and no key file exists while they wait`, async () => {
      const token = `SECRET-TOKEN-queue-${outcome}-7614`;
      const bareR = bareRemote(`queue-${outcome}-r`);
      const bareS = bareRemote(`queue-${outcome}-s`);
      const userR = `queue-${outcome}-repo-r`;
      const userS = `queue-${outcome}-repo-s`;
      const firstUrl =
        outcome === "fail" ? `http://user:${token}@127.0.0.1:${await closedPort()}/queue-first.git` : bareR;
      fake.clearLog();
      // The first operation is slow either way, so the others arrive while it runs.
      fake.setSlow({ sleepMs: outcome === "fail" ? 1500 : TIMEOUT_MS + 3000, on: ["clone"], match: outcome === "fail" ? "queue-first" : bareR });
      const first = clone(app, { url: firstUrl, path: userR });
      await fake.waitForStart((inv) => inv.subcommand === "clone" && inv.argv.includes(path.join(PROJECTS, userR)));
      fake.setSlow(null);

      const keySightings: string[] = [];
      let firstDone = false;
      const sampler = setInterval(() => {
        if (!firstDone) keySightings.push(...keyFilesInTmp());
      }, 5);
      // The second operation on R waits for R's turn, the one on S for the only slot.
      const secondR = clone(app, { url: bareR, path: userR, sshKey: FAKE_SSH_KEY });
      const onS = clone(app, { url: bareS, path: userS, sshKey: FAKE_SSH_KEY });
      await waitForWaiting(app, 1);
      await new Promise((resolve) => setTimeout(resolve, 200));
      // Only the first operation's git has started.
      expect(fake.invocations()).toHaveLength(1);
      keySightings.push(...keyFilesInTmp());

      const firstReply = await first;
      firstDone = true;
      clearInterval(sampler);
      if (outcome === "fail") expectCleanGitError(firstReply, [token]);
      else expect(firstReply).toEqual({ status: 500, body: { error: `git clone timed out after ${TIMEOUT_MS / 1000} s` } });

      const [r2, s] = await Promise.all([secondR, onS]);
      expect(r2).toEqual({ status: 200, body: { status: "cloned", path: userR, branch: "main", commit: shortSha(bareR) } });
      expect(s).toEqual({ status: 200, body: { status: "cloned", path: userS, branch: "main", commit: shortSha(bareS) } });
      expect(keySightings).toEqual([]);
      expect(keyFilesInTmp()).toEqual([]);
    }, 30_000);
  }
});

/* ------------------------------------------------------------------ */
/*  Request values cannot run commands                                  */
/* ------------------------------------------------------------------ */

describe("request values cannot run commands", () => {
  let app: LoadedApp;
  let bare: string;
  beforeAll(async () => {
    app = await loadApp(undefined);
    bare = bareRemote("inject");
    // Branches that the positive rows use.
    const work = `${bare}.work`;
    for (const branch of ["feature/MVP-1-x", "sprint/2026-09-26-27"]) {
      fixtureGit(REAL_GIT, ["branch", branch], work);
      fixtureGit(REAL_GIT, ["push", bare, branch], work);
    }
  });
  afterAll(async () => {
    await closeApp(app);
  });

  const marker = (name: string) => path.join(PWN, name);

  it("clone, branch 'main;touch <marker>': 500 with git's error, no command runs", async () => {
    const reply = await clone(app, { url: bare, path: "inj-branch", branch: `main;touch ${marker("m1")}` });
    expectCleanGitError(reply);
    expect(fs.existsSync(marker("m1"))).toBe(false);
  });

  it("clone, url 'https://example.invalid/r.git;touch <marker>': 500 with git's error, no command runs", async () => {
    const reply = await clone(app, { url: `https://example.invalid/r.git;touch ${marker("m2")}`, path: "inj-url" });
    expectCleanGitError(reply);
    expect(fs.existsSync(marker("m2"))).toBe(false);
  });

  it("clone, url '--upload-pack=touch <marker>': 500, read as a repository after '--', not as an option (guard)", async () => {
    const value = `--upload-pack=touch ${marker("m3")}`;
    const target = path.join(PROJECTS, "inj-upload-pack");
    fake.clearLog();
    expectCleanGitError(await clone(app, { url: value, path: "inj-upload-pack" }));
    expect(fs.existsSync(marker("m3"))).toBe(false);
    const cloneCall = fake.invocations().find((inv) => inv.subcommand === "clone" || inv.argv.includes(target));
    expect(cloneCall).toBeDefined();
    const argv = cloneCall!.argv;
    expect(argv[argv.indexOf(value) - 1]).toBe("--");
    expect(argv.slice(argv.indexOf(value) + 1)).toEqual([target]);
  });

  it("clone, url '--upload-pack=<script> file://<bare>': the script never runs (red on the shell baseline)", async () => {
    const script = path.join(ROOT, "upload-pack-probe.sh");
    fs.writeFileSync(script, `#!/bin/sh\ntouch '${marker("m3b")}'\nexec git-upload-pack "$@"\n`, { mode: 0o755 });
    const value = `--upload-pack=${script} file://${bare}`;
    const reply = await clone(app, { url: value, path: "inj-upload-pack-script" });
    expect(fs.existsSync(marker("m3b"))).toBe(false);
    expectCleanGitError(reply);
  });

  it("clone, path 'repo;touch <marker>': 200 cloned into a folder literally named so, no command runs", async () => {
    // The marker is relative to the clone's working directory (WORKSPACE_ROOT).
    const userPath = "repo;touch pwn-m4";
    const reply = await clone(app, { url: bare, path: userPath });
    expect(reply).toEqual({ status: 200, body: { status: "cloned", path: userPath, branch: "main", commit: shortSha(bare) } });
    expect(fs.existsSync(path.join(PROJECTS, userPath, ".git"))).toBe(true);
    expect(fs.existsSync(path.join(WORKSPACE, "pwn-m4"))).toBe(false);
    expect(fs.existsSync(path.join(PROJECTS, "repo"))).toBe(false);
  });

  it("pull, branch 'main$(touch <marker>)': 500 with git's error, no command runs", async () => {
    fixtureCheckout(bare, "inj-pull");
    const reply = await pull(app, { path: "inj-pull", branch: `main$(touch ${marker("m5")})` });
    expectCleanGitError(reply);
    expect(fs.existsSync(marker("m5"))).toBe(false);
  });

  it("clone, branch '--upload-pack=touch <marker>': 400 Invalid branch, no git process starts", async () => {
    fake.clearLog();
    const reply = await clone(app, { url: bare, path: "inj-dash-branch", branch: `--upload-pack=touch ${marker("m6")}` });
    expect(reply).toEqual({ status: 400, body: { error: "Invalid branch" } });
    expect(fake.invocations()).toEqual([]);
    expect(fs.existsSync(marker("m6"))).toBe(false);
  });

  it("clone, url 'ext::sh -c touch% <marker>': the ext transport stays disabled (guard)", async () => {
    const reply = await clone(app, { url: `ext::sh -c touch% ${marker("m7")}`, path: "inj-ext" });
    expectCleanGitError(reply);
    expect(fs.existsSync(marker("m7"))).toBe(false);
  });

  it("pull, branch values that are refspecs do not create or move local refs", async () => {
    const target = fixtureCheckout(bare, "inj-refspec");
    const refsBefore = fixtureGit(REAL_GIT, ["for-each-ref", "--format=%(refname) %(objectname)"], target);
    for (const branch of ["main:refs/heads/injected", "+main:injected2", "a:refs/heads/x"]) {
      expectCleanGitError(await pull(app, { path: "inj-refspec", branch }));
    }
    const refsAfter = fixtureGit(REAL_GIT, ["for-each-ref", "--format=%(refname) %(objectname)"], target);
    expect(refsAfter).toBe(refsBefore);
  });

  it("pull fetches with '--' and an explicit refspec for the branch", async () => {
    const target = fixtureCheckout(bare, "inj-fetch-argv");
    fake.clearLog();
    const reply = await pull(app, { path: "inj-fetch-argv", branch: "main" });
    expect(reply.status).toBe(200);
    const fetchCall = fake.invocations().find((inv) => inv.subcommand === "fetch" && inv.cwd === target);
    expect(fetchCall?.argv).toEqual(["fetch", "origin", "--", "+refs/heads/main:refs/remotes/origin/main"]);
  });

  it("ordinary branch names with slashes still clone and pull", async () => {
    for (const branch of ["feature/MVP-1-x", "sprint/2026-09-26-27"]) {
      const userPath = `inj-ok-${branch.replace(/\//g, "-")}`;
      const cloned = await clone(app, { url: bare, path: userPath, branch });
      expect(cloned).toEqual({ status: 200, body: { status: "cloned", path: userPath, branch, commit: shortSha(bare, branch) } });
      const pulled = await pull(app, { path: userPath, branch });
      expect(pulled).toEqual({ status: 200, body: { status: "up-to-date", branch, commit: shortSha(bare, branch) } });
    }
  });
});
