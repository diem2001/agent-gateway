import { spawn, type ChildProcess } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { SpawnOptions, SpawnedProcess } from "@anthropic-ai/claude-agent-sdk";
import { log } from "./logging.js";

/**
 * Per-run log files of the Claude runtime (MVP-7667, plan supplement PS-1).
 *
 * The runtime writes every MCP connection's options, including header and env
 * values, to its debug log (`~/.claude/debug/<session>.txt`) and its MCP logs
 * (`~/.cache/claude-cli-nodejs/<cwd>/mcp-logs-<server>/`). Each run therefore
 * gets a private directory under the OS temp directory: the SDK child
 * environment points `CLAUDE_CODE_DEBUG_LOGS_DIR` (a file path) and
 * `XDG_CACHE_HOME` into it, and the directory is deleted once the runtime child
 * has exited (it flushes buffered log lines on exit). A child that does not
 * exit in time is killed first. Leftovers of a crashed gateway are swept at
 * startup.
 */

export const RUN_DIR_PREFIX = "agent-gateway-run-";
/** Bounded wait for the runtime child to exit before it is killed and its directory deleted. */
export const RUNTIME_EXIT_WAIT_MS = 10_000;

export interface RunLogDir {
  dir: string;
  /** Additions to the SDK child environment. */
  env: { CLAUDE_CODE_DEBUG_LOGS_DIR: string; XDG_CACHE_HOME: string };
}

/** Creates the run's private directory (0700). */
export function createRunLogDir(): RunLogDir {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), RUN_DIR_PREFIX));
  fs.chmodSync(dir, 0o700);
  return {
    dir,
    env: {
      // A file path; the extra "debug" level keeps the runtime's own log directory inside the run directory.
      CLAUDE_CODE_DEBUG_LOGS_DIR: path.join(dir, "debug", "run.txt"),
      XDG_CACHE_HOME: path.join(dir, "cache"),
    },
  };
}

function removeDir(dir: string): void {
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch (e: unknown) {
    log("query", `run log directory cleanup failed: ${e instanceof Error ? e.message : String(e)}`);
  }
}

/**
 * Deletes the run directory after the runtime child has exited. Without a child
 * (the SDK never spawned one) it is deleted at once. After `waitMs` the child is
 * killed, then the directory is deleted.
 */
export function removeRunLogDirAfterExit(dir: string, child: ChildProcess | null, waitMs = RUNTIME_EXIT_WAIT_MS): Promise<void> {
  if (!child || child.exitCode !== null || child.signalCode !== null) {
    removeDir(dir);
    return Promise.resolve();
  }
  return new Promise((resolve) => {
    const done = (): void => {
      clearTimeout(timer);
      removeDir(dir);
      resolve();
    };
    const timer = setTimeout(() => {
      log("query", "runtime child did not exit in time; killing it before deleting its log directory");
      child.kill("SIGKILL");
    }, waitMs);
    child.once("exit", done);
  });
}

/**
 * An SDK `spawnClaudeCodeProcess` hook that spawns the runtime like the SDK's
 * default (stdin/stdout piped, stderr ignored) and reports the child, so the run
 * can wait for its exit.
 */
export function spawnRuntimeWithHandle(onSpawn: (child: ChildProcess) => void): (options: SpawnOptions) => SpawnedProcess {
  return ({ command, args, cwd, env, signal }) => {
    const child = spawn(command, args, { cwd, env, signal, stdio: ["pipe", "pipe", "ignore"], windowsHide: true });
    onSpawn(child);
    return child as unknown as SpawnedProcess;
  };
}

/** Removes run directories left by an earlier gateway process (crash, kill). */
export function sweepRunLogDirs(): void {
  let entries: string[] = [];
  try {
    entries = fs.readdirSync(os.tmpdir());
  } catch {
    return;
  }
  let removed = 0;
  for (const name of entries) {
    if (!name.startsWith(RUN_DIR_PREFIX)) continue;
    removeDir(path.join(os.tmpdir(), name));
    removed++;
  }
  if (removed > 0) log("server", `Removed ${removed} leftover run log director${removed === 1 ? "y" : "ies"}`);
}

/**
 * `DEBUG_CLAUDE_AGENT_SDK` makes the SDK write its full runtime arguments,
 * including `--mcp-config` with header values, to `~/.claude/debug/sdk-*.txt`
 * and turns on the runtime's debug output. The SDK reads it lazily, so removing
 * it before the first query prevents both.
 */
export function stripSdkDebugEnv(): void {
  if (process.env.DEBUG_CLAUDE_AGENT_SDK === undefined) return;
  delete process.env.DEBUG_CLAUDE_AGENT_SDK;
  log("server", "WARNING: DEBUG_CLAUDE_AGENT_SDK is ignored: it would write MCP credentials to the SDK debug log");
}
