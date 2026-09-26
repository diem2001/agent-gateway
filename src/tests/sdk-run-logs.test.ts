/**
 * Per-run runtime log directory (src/sdk-run-logs.ts): creation, deletion after
 * the child exits, the bounded wait that kills a hung child, the startup sweep
 * and the DEBUG_CLAUDE_AGENT_SDK strip. TMPDIR points at a test directory, so
 * nothing outside it is touched.
 */
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

let tmp = "";
let previousTmpdir: string | undefined;
let logs: string[] = [];

beforeEach(() => {
  vi.resetModules();
  logs = [];
  vi.spyOn(console, "log").mockImplementation((...args) => {
    logs.push(args.map(String).join(" "));
  });
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "mvp7667-runlogs-"));
  previousTmpdir = process.env.TMPDIR;
  process.env.TMPDIR = tmp;
});

afterEach(() => {
  if (previousTmpdir === undefined) delete process.env.TMPDIR;
  else process.env.TMPDIR = previousTmpdir;
  delete process.env.DEBUG_CLAUDE_AGENT_SDK;
  vi.restoreAllMocks();
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe("per-run runtime log directory", () => {
  it("is private (0700) under the OS temp directory; the child environment points the runtime's logs into it", async () => {
    const { createRunLogDir } = await import("../sdk-run-logs.js");

    const run = createRunLogDir();

    expect(path.dirname(run.dir)).toBe(tmp);
    expect(path.basename(run.dir).startsWith("agent-gateway-run-")).toBe(true);
    expect(fs.statSync(run.dir).mode & 0o777).toBe(0o700);
    expect(run.env).toEqual({ CLAUDE_CODE_DEBUG_LOGS_DIR: path.join(run.dir, "debug", "run.txt"), XDG_CACHE_HOME: path.join(run.dir, "cache") });
  });

  it("without a child it is deleted at once; with one, only after the child has exited", async () => {
    const { createRunLogDir, removeRunLogDirAfterExit } = await import("../sdk-run-logs.js");
    const noChild = createRunLogDir();
    await removeRunLogDirAfterExit(noChild.dir, null);
    expect(fs.existsSync(noChild.dir)).toBe(false);

    const run = createRunLogDir();
    const child = spawn(process.execPath, ["-e", "setTimeout(() => {}, 400)"], { stdio: "ignore" });
    const removal = removeRunLogDirAfterExit(run.dir, child, 10_000);
    await new Promise((resolve) => setTimeout(resolve, 150));
    expect(fs.existsSync(run.dir)).toBe(true);
    await removal;
    expect(child.exitCode).toBe(0);
    expect(fs.existsSync(run.dir)).toBe(false);
  });

  it("a child that does not exit in time is killed, then its directory is deleted", async () => {
    const { createRunLogDir, removeRunLogDirAfterExit } = await import("../sdk-run-logs.js");
    const run = createRunLogDir();
    const child = spawn(process.execPath, ["-e", "process.on('SIGTERM', () => {}); setInterval(() => {}, 1000)"], { stdio: "ignore" });

    const started = Date.now();
    await removeRunLogDirAfterExit(run.dir, child, 300);

    expect(Date.now() - started).toBeGreaterThanOrEqual(250);
    expect(child.signalCode).toBe("SIGKILL");
    expect(fs.existsSync(run.dir)).toBe(false);
    expect(logs.join("\n")).toContain("runtime child did not exit in time");
  });

  it("the startup sweep removes leftover run directories and nothing else", async () => {
    const { sweepRunLogDirs } = await import("../sdk-run-logs.js");
    fs.mkdirSync(path.join(tmp, "agent-gateway-run-left1", "debug"), { recursive: true });
    fs.writeFileSync(path.join(tmp, "agent-gateway-run-left1", "debug", "run.txt"), "x");
    fs.mkdirSync(path.join(tmp, "agent-gateway-run-left2"));
    fs.mkdirSync(path.join(tmp, "unrelated"));

    sweepRunLogDirs();

    expect(fs.readdirSync(tmp)).toEqual(["unrelated"]);
    expect(logs.join("\n")).toContain("Removed 2 leftover run log directories");
  });
});

describe("DEBUG_CLAUDE_AGENT_SDK", () => {
  it("is removed from the environment with a warning; unset, nothing is logged", async () => {
    const { stripSdkDebugEnv } = await import("../sdk-run-logs.js");

    stripSdkDebugEnv();
    expect(logs).toEqual([]);

    process.env.DEBUG_CLAUDE_AGENT_SDK = "1";
    stripSdkDebugEnv();
    expect(process.env.DEBUG_CLAUDE_AGENT_SDK).toBeUndefined();
    expect(logs.join("\n")).toContain("DEBUG_CLAUDE_AGENT_SDK is ignored");
  });
});
