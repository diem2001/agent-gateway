/**
 * MVP-7614 Gate B — unit rows for src/git-exec.ts: the global FIFO slot limit,
 * the per-repository turn, runGit's process-group timeout, output cap, child
 * environment and error-text redaction.
 *
 * Module-level settings (GIT_TIMEOUT_MS, GIT_MAX_CONCURRENCY) are read at
 * import, so each row that needs other settings re-imports the module.
 * Scripted `git` stand-ins live in test-owned bin directories on the PATH of
 * the environment passed to runGit.
 */
import { afterAll, describe, expect, it, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createFakeGit } from "./helpers/fake-git.js";

type GitExec = typeof import("../git-exec.js");

const ROOT = fs.mkdtempSync(path.join(os.tmpdir(), "mvp7614-gitexec-"));

afterAll(() => {
  fs.rmSync(ROOT, { recursive: true, force: true });
});

async function loadGitExec(env: Record<string, string | undefined>): Promise<GitExec> {
  for (const [key, value] of Object.entries(env)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  vi.resetModules();
  return import("../git-exec.js");
}

let binSeq = 0;
/** A bin directory whose `git` is the given shell script body. */
function scriptedGit(body: string): string {
  const dir = path.join(ROOT, `bin-${++binSeq}`);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "git"), `#!/bin/sh\n${body}\n`, { mode: 0o755 });
  return dir;
}

function envWithPath(binDir: string, extra: Record<string, string> = {}): NodeJS.ProcessEnv {
  return { ...process.env, PATH: `${binDir}${path.delimiter}${process.env.PATH ?? ""}`, ...extra };
}

/** Process ids whose process group is `pgid` (Linux /proc). */
function processesInGroup(pgid: number): number[] {
  const found: number[] = [];
  for (const entry of fs.readdirSync("/proc")) {
    if (!/^\d+$/.test(entry)) continue;
    try {
      const stat = fs.readFileSync(`/proc/${entry}/stat`, "utf8");
      // Fields after the parenthesized command: state ppid pgrp ...
      const fields = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
      if (Number(fields[2]) === pgid) found.push(Number(entry));
    } catch {
      // Process ended while reading.
    }
  }
  return found;
}

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => (resolve = r));
  return { promise, resolve };
}

describe("settings", () => {
  it("defaults to 120 s and 3 slots; invalid values fall back to the defaults", async () => {
    let mod = await loadGitExec({ GIT_TIMEOUT_MS: undefined, GIT_MAX_CONCURRENCY: undefined });
    expect(mod.GIT_TIMEOUT_MS).toBe(120_000);
    expect(mod.GIT_MAX_CONCURRENCY).toBe(3);
    for (const bad of ["0", "-1", "abc", "1.5"]) {
      mod = await loadGitExec({ GIT_TIMEOUT_MS: bad, GIT_MAX_CONCURRENCY: bad });
      expect(mod.GIT_TIMEOUT_MS).toBe(120_000);
      expect(mod.GIT_MAX_CONCURRENCY).toBe(3);
    }
    mod = await loadGitExec({ GIT_TIMEOUT_MS: "2500", GIT_MAX_CONCURRENCY: "5" });
    expect(mod.GIT_TIMEOUT_MS).toBe(2500);
    expect(mod.GIT_MAX_CONCURRENCY).toBe(5);
  });
});

describe("global slots", () => {
  it("with a limit of 1, waiting operations start in arrival order A, B, C", async () => {
    const mod = await loadGitExec({ GIT_MAX_CONCURRENCY: "1" });
    const order: string[] = [];
    const gate = deferred();
    const a = mod.withGitSlot(async () => {
      order.push("A");
      await gate.promise;
    });
    const b = mod.withGitSlot(async () => void order.push("B"));
    const c = mod.withGitSlot(async () => void order.push("C"));
    expect(mod.gitQueueSnapshot()).toEqual({ running: 1, waiting: 2 });
    gate.resolve();
    await Promise.all([a, b, c]);
    expect(order).toEqual(["A", "B", "C"]);
    expect(mod.gitQueueSnapshot()).toEqual({ running: 0, waiting: 0 });
  });

  it("10 operations never overlap more than the limit, and all complete", async () => {
    const mod = await loadGitExec({ GIT_MAX_CONCURRENCY: "3" });
    let active = 0;
    let maxActive = 0;
    const results = await Promise.all(
      Array.from({ length: 10 }, (_, i) =>
        mod.withGitSlot(async () => {
          active++;
          maxActive = Math.max(maxActive, active);
          await new Promise((resolve) => setTimeout(resolve, 20 + (i % 3) * 15));
          active--;
          return i;
        }),
      ),
    );
    expect(results).toEqual([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    expect(maxActive).toBe(3);
  });

  it("a rejected operation releases its slot to the next waiter", async () => {
    const mod = await loadGitExec({ GIT_MAX_CONCURRENCY: "1" });
    const failing = mod.withGitSlot(async () => {
      await new Promise((resolve) => setTimeout(resolve, 20));
      throw new Error("boom");
    });
    const next = mod.withGitSlot(async () => "ran");
    await expect(failing).rejects.toThrow("boom");
    await expect(next).resolves.toBe("ran");
    expect(mod.gitQueueSnapshot()).toEqual({ running: 0, waiting: 0 });
  });
});

describe("per-repository turns", () => {
  it("operations on the same repository never overlap and run in arrival order; other repositories are not held up", async () => {
    const mod = await loadGitExec({});
    const events: string[] = [];
    const gate = deferred();
    const first = mod.withRepoTurn("/r", async () => {
      events.push("r1 start");
      await gate.promise;
      events.push("r1 end");
    });
    const second = mod.withRepoTurn("/r", async () => {
      events.push("r2 start");
      events.push("r2 end");
    });
    const other = mod.withRepoTurn("/s", async () => void events.push("s"));
    await other;
    expect(events).toEqual(["r1 start", "s"]);
    gate.resolve();
    await Promise.all([first, second]);
    expect(events).toEqual(["r1 start", "s", "r1 end", "r2 start", "r2 end"]);
  });

  it("a rejected operation releases the turn", async () => {
    const mod = await loadGitExec({});
    const failing = mod.withRepoTurn("/r", async () => {
      throw new Error("boom");
    });
    const next = mod.withRepoTurn("/r", async () => "ran");
    await expect(failing).rejects.toThrow("boom");
    await expect(next).resolves.toBe("ran");
  });
});

describe("runGit", () => {
  it("resolves with trimmed stdout; runs without a shell (arguments stay literal)", async () => {
    const mod = await loadGitExec({});
    const bin = scriptedGit('for a in "$@"; do printf "<%s>\\n" "$a"; done');
    const out = await mod.runGit(["log", "a b", "$(touch x)", ";id"], ROOT, envWithPath(bin));
    expect(out).toBe("<log>\n<a b>\n<$(touch x)>\n<;id>");
    expect(fs.existsSync(path.join(ROOT, "x"))).toBe(false);
  });

  it("child environment: prompts off, ext:: transport disabled, git/curl tracing removed", async () => {
    const mod = await loadGitExec({});
    const bin = scriptedGit("env");
    const out = await mod.runGit(["status"], ROOT, envWithPath(bin, { GIT_TRACE: "1", GIT_TRACE_CURL: "1", GIT_CURL_VERBOSE: "1", KEEP_ME: "yes" }));
    const env = Object.fromEntries(out.split("\n").map((line) => [line.slice(0, line.indexOf("=")), line.slice(line.indexOf("=") + 1)]));
    expect(env.GIT_TERMINAL_PROMPT).toBe("0");
    expect(env.GIT_CONFIG_COUNT).toBe("1");
    expect(env.GIT_CONFIG_KEY_0).toBe("protocol.ext.allow");
    expect(env.GIT_CONFIG_VALUE_0).toBe("never");
    expect(env.GIT_TRACE).toBeUndefined();
    expect(env.GIT_TRACE_CURL).toBeUndefined();
    expect(env.GIT_CURL_VERBOSE).toBeUndefined();
    expect(env.KEEP_ME).toBe("yes");
  });

  it("the real git refuses the ext:: transport", async () => {
    const mod = await loadGitExec({});
    const marker = path.join(ROOT, "ext-marker");
    await expect(mod.runGit(["clone", "--", `ext::sh -c touch% ${marker}`, path.join(ROOT, "ext-target")], ROOT)).rejects.toThrow(/ext/);
    expect(fs.existsSync(marker)).toBe(false);
  });

  it("a failure carries git's stderr with URL credentials removed, never Node's command line", async () => {
    const mod = await loadGitExec({});
    const bin = scriptedGit('echo "fatal: could not read from https://user:SECRET-7614@example.invalid/r.git" >&2; exit 128');
    const error = await mod.runGit(["clone", "--", "https://user:SECRET-7614@example.invalid/r.git", "x"], ROOT, envWithPath(bin)).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(mod.GitError);
    expect((error as Error).message).toBe("fatal: could not read from https://***@example.invalid/r.git");
  });

  it("a failure without stderr names the subcommand and exit code", async () => {
    const mod = await loadGitExec({});
    const bin = scriptedGit("exit 3");
    await expect(mod.runGit(["fetch", "origin"], ROOT, envWithPath(bin))).rejects.toThrow("git fetch failed with exit code 3");
  });

  it("a git that cannot be started rejects with a GitError", async () => {
    const mod = await loadGitExec({});
    const empty = path.join(ROOT, "empty-bin");
    fs.mkdirSync(empty, { recursive: true });
    const error = await mod.runGit(["status"], ROOT, { ...process.env, PATH: empty }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(mod.GitError);
    expect((error as Error).message).toMatch(/^git status could not be started/);
  });

  it("output over 10 MiB fails instead of growing without bound", async () => {
    const mod = await loadGitExec({});
    const bin = scriptedGit("head -c 11000000 /dev/zero");
    await expect(mod.runGit(["show"], ROOT, envWithPath(bin))).rejects.toThrow("git show output exceeded 10 MiB");
  });

  it("timeout: a pipe-holding grandchild does not keep the call open; the whole process group is gone", async () => {
    const mod = await loadGitExec({ GIT_TIMEOUT_MS: "1000" });
    const fake = createFakeGit(path.join(ROOT, "fake-timeout"));
    fake.setSlow({ sleepMs: 20_000, on: ["clone"] });
    const started = Date.now();
    const error = await mod.runGit(["clone", "--", "/nonexistent", path.join(ROOT, "t1")], ROOT, envWithPath(fake.binDir)).catch((e: unknown) => e);
    const elapsed = Date.now() - started;
    expect((error as Error).message).toBe("git clone timed out after 1 s");
    expect(elapsed).toBeLessThan(1000 + 3000);
    const wrapperPid = fake.invocations()[0].pid;
    // The killed grandchild is reaped asynchronously by its new parent.
    for (let i = 0; i < 50 && processesInGroup(wrapperPid).length > 0; i++) await new Promise((resolve) => setTimeout(resolve, 20));
    expect(processesInGroup(wrapperPid)).toEqual([]);
  });

  it("timeout: a group that ignores SIGTERM is SIGKILLed after the grace", async () => {
    const mod = await loadGitExec({ GIT_TIMEOUT_MS: "1000" });
    const pidFile = path.join(ROOT, "stubborn.pid");
    const bin = scriptedGit(`trap '' TERM\necho $$ > '${pidFile}'\nsleep 20 &\nwait $!\nwait $!`);
    const started = Date.now();
    await expect(mod.runGit(["pull"], ROOT, envWithPath(bin))).rejects.toThrow("git pull timed out after 1 s");
    const elapsed = Date.now() - started;
    expect(elapsed).toBeGreaterThanOrEqual(1000 + 1900);
    expect(elapsed).toBeLessThan(1000 + 2000 + 1500);
    const pgid = Number(fs.readFileSync(pidFile, "utf8").trim());
    // SIGKILL delivery is asynchronous; give the kernel a moment to reap.
    for (let i = 0; i < 50 && processesInGroup(pgid).length > 0; i++) await new Promise((resolve) => setTimeout(resolve, 20));
    expect(processesInGroup(pgid)).toEqual([]);
  });

  it("a timed-out operation releases both its turn and its slot", async () => {
    const mod = await loadGitExec({ GIT_TIMEOUT_MS: "500", GIT_MAX_CONCURRENCY: "1" });
    const bin = scriptedGit("sleep 20 & wait $!");
    const env = envWithPath(bin);
    const slow = mod.withRepoTurn("/r", () => mod.withGitSlot(() => mod.runGit(["fetch"], ROOT, env)));
    const sameRepo = mod.withRepoTurn("/r", () => mod.withGitSlot(async () => "same"));
    const otherRepo = mod.withRepoTurn("/s", () => mod.withGitSlot(async () => "other"));
    await expect(slow).rejects.toThrow("git fetch timed out after 0.5 s");
    await expect(Promise.all([sameRepo, otherRepo])).resolves.toEqual(["same", "other"]);
    expect(mod.gitQueueSnapshot()).toEqual({ running: 0, waiting: 0 });
  });
});

describe("redactUrlCredentials", () => {
  it("removes every userinfo, including passwords that contain '@'", async () => {
    const { redactUrlCredentials } = await loadGitExec({});
    expect(redactUrlCredentials("a https://u:p@h/x and ssh://git:t@k@host:22/y 'http://x:y@z'")).toBe(
      "a https://***@h/x and ssh://***@host:22/y 'http://***@z'",
    );
    expect(redactUrlCredentials("no credentials: https://host/x git@host:repo")).toBe("no credentials: https://host/x git@host:repo");
  });

  it("redacts before shortening a long error text; other errors get the same treatment", async () => {
    const mod = await loadGitExec({});
    const secret = "SECRET-LONG-7614";
    const text = "x".repeat(4090) + `https://user:${secret}@host/r.git`;
    const error = new mod.GitError(text);
    expect(error.message.length).toBe(4096);
    expect(error.message).not.toContain(secret.slice(0, 4));
    expect(error.message.endsWith("https:")).toBe(true);
    expect(mod.gitErrorText(new Error(`EACCES https://u:${secret}@h/x`))).toBe("EACCES https://***@h/x");
    expect(mod.gitErrorText(error)).toBe(error.message);
  });
});
