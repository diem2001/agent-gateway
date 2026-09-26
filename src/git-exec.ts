import { spawn } from "node:child_process";
import { log } from "./logging.js";

/* ------------------------------------------------------------------ */
/*  Non-blocking git execution with per-repository and global queues    */
/* ------------------------------------------------------------------ */

const DEFAULT_TIMEOUT_MS = 120_000;
const DEFAULT_MAX_CONCURRENCY = 3;
const MAX_OUTPUT_BYTES = 10 * 1024 * 1024;
/** After a timeout, SIGTERM first (git removes its lock files), SIGKILL after this grace. */
const KILL_GRACE_MS = 2_000;
const MAX_ERROR_CHARS = 4096;

function positiveIntFromEnv(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  const value = Number(raw);
  if (Number.isInteger(value) && value > 0) return value;
  log("git", `Ignoring invalid ${name}=${JSON.stringify(raw)}; using ${fallback}`);
  return fallback;
}

/** Per-command deadline. Read once at startup. */
export const GIT_TIMEOUT_MS = positiveIntFromEnv("GIT_TIMEOUT_MS", DEFAULT_TIMEOUT_MS);
/** Git operations that may run at the same time across all repositories. Read once at startup. */
export const GIT_MAX_CONCURRENCY = positiveIntFromEnv("GIT_MAX_CONCURRENCY", DEFAULT_MAX_CONCURRENCY);

/**
 * Replace the userinfo of every `scheme://user:password@` in `text` with `***`.
 * The match runs to the last `@` of the authority, so a password that itself
 * contains `@` leaves no tail behind.
 */
export function redactUrlCredentials(text: string): string {
  return text.replace(/([a-z][a-z0-9+.-]*:\/\/)[^/\s'"]*@/gi, "$1***@");
}

/** Redacted first, then shortened: no prefix of a credential can survive the cut. */
function safeErrorText(text: string): string {
  const redacted = redactUrlCredentials(text);
  return redacted.length > MAX_ERROR_CHARS ? redacted.slice(0, MAX_ERROR_CHARS) : redacted;
}

/**
 * A failed git command. The message is git's own error output (or a fixed text
 * for a timeout, an output overflow or a start failure), with URL credentials
 * removed. Node's "Command failed: <command line>" text is never used: the
 * command line can hold a token-bearing URL.
 */
export class GitError extends Error {
  constructor(message: string) {
    super(safeErrorText(message));
    this.name = "GitError";
  }
}

/** Response/log text for any failure of a git operation: GitError as is, anything else redacted and capped. */
export function gitErrorText(error: unknown): string {
  if (error instanceof GitError) return error.message;
  return safeErrorText(error instanceof Error ? error.message : String(error));
}

function formatSeconds(ms: number): string {
  return String(Number((ms / 1000).toFixed(3)));
}

/**
 * Environment for a git child: the caller's (or the gateway's) environment
 * without git/curl tracing (stderr becomes error text, and curl tracing prints
 * Authorization headers), with terminal prompts off (a missing credential fails
 * instead of waiting for input) and the `ext::` transport disabled whatever the
 * system or global git config says.
 */
function gitChildEnv(env?: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const childEnv: NodeJS.ProcessEnv = { ...(env ?? process.env) };
  for (const key of Object.keys(childEnv)) {
    if (key.startsWith("GIT_TRACE") || key === "GIT_CURL_VERBOSE") delete childEnv[key];
  }
  childEnv.GIT_TERMINAL_PROMPT = "0";
  childEnv.GIT_CONFIG_COUNT = "1";
  childEnv.GIT_CONFIG_KEY_0 = "protocol.ext.allow";
  childEnv.GIT_CONFIG_VALUE_0 = "never";
  return childEnv;
}

/**
 * Run git with an argument array (no shell) and resolve with its trimmed
 * stdout. Git runs in its own process group: on timeout or output overflow the
 * whole group gets SIGTERM, then SIGKILL after a short grace, so a helper that
 * still holds git's pipes (git-remote-https, ssh) cannot keep the call open.
 */
export function runGit(args: string[], cwd: string, env?: NodeJS.ProcessEnv): Promise<string> {
  const subcommand = args.find((arg) => !arg.startsWith("-")) ?? "";
  return new Promise<string>((resolve, reject) => {
    let settled = false;
    let exited = false;
    let failure: string | null = null;
    let outputBytes = 0;
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let graceTimer: NodeJS.Timeout | undefined;

    const child = spawn("git", args, { cwd, env: gitChildEnv(env), detached: true, stdio: ["ignore", "pipe", "pipe"] });

    const settle = (error: GitError | null, output?: string): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timeoutTimer);
      clearTimeout(graceTimer);
      if (error) reject(error);
      else resolve(output ?? "");
    };

    const killGroup = (signal: NodeJS.Signals): void => {
      if (child.pid === undefined || exited) return;
      try {
        process.kill(-child.pid, signal);
      } catch {
        // ESRCH: the group is already gone.
      }
    };

    /** Stop the command; settle once it has closed, or after the grace at the latest. */
    const abort = (message: string): void => {
      if (failure !== null) return;
      failure = message;
      killGroup("SIGTERM");
      graceTimer = setTimeout(() => {
        killGroup("SIGKILL");
        settle(new GitError(message));
      }, KILL_GRACE_MS);
    };

    const timeoutTimer = setTimeout(() => {
      abort(`git ${subcommand} timed out after ${formatSeconds(GIT_TIMEOUT_MS)} s`);
    }, GIT_TIMEOUT_MS);

    const collect = (target: Buffer[]) => (chunk: Buffer) => {
      if (failure !== null) return;
      outputBytes += chunk.length;
      if (outputBytes > MAX_OUTPUT_BYTES) {
        abort(`git ${subcommand} output exceeded ${MAX_OUTPUT_BYTES / (1024 * 1024)} MiB`);
        return;
      }
      target.push(chunk);
    };
    child.stdout.on("data", collect(stdout));
    child.stderr.on("data", collect(stderr));

    child.on("exit", () => {
      exited = true;
    });
    child.on("error", (err) => {
      exited = true;
      settle(new GitError(`git ${subcommand} could not be started: ${err.message}`));
    });
    child.on("close", (code, signal) => {
      exited = true;
      if (failure !== null) {
        settle(new GitError(failure));
        return;
      }
      if (code === 0) {
        settle(null, Buffer.concat(stdout).toString("utf8").trim());
        return;
      }
      const message = Buffer.concat(stderr).toString("utf8").trim();
      settle(new GitError(message || `git ${subcommand} failed with ${code !== null ? `exit code ${code}` : `signal ${signal}`}`));
    });
  });
}

/* ------------------------------------------------------------------ */
/*  Queues                                                              */
/* ------------------------------------------------------------------ */

/** Per repository: the promise the next arrival waits for. Idle repositories have no entry. */
const repoTails = new Map<string, Promise<void>>();

/**
 * Run `fn` when every earlier operation on the same repository (same resolved
 * path) has finished, in arrival order. The turn is released however `fn` ends.
 */
export async function withRepoTurn<T>(repoKey: string, fn: () => Promise<T>): Promise<T> {
  const previous = repoTails.get(repoKey) ?? Promise.resolve();
  let release!: () => void;
  const turn = new Promise<void>((resolve) => (release = resolve));
  const tail = previous.then(() => turn);
  repoTails.set(repoKey, tail);
  await previous;
  try {
    return await fn();
  } finally {
    release();
    if (repoTails.get(repoKey) === tail) repoTails.delete(repoKey);
  }
}

let runningOperations = 0;
const slotWaiters: (() => void)[] = [];

/**
 * Run `fn` in one of GIT_MAX_CONCURRENCY global slots. Requests beyond the
 * limit wait in arrival order and are never rejected; a finished operation
 * hands its slot straight to the oldest waiter, however it ended.
 */
export async function withGitSlot<T>(fn: () => Promise<T>): Promise<T> {
  if (runningOperations < GIT_MAX_CONCURRENCY) runningOperations++;
  else await new Promise<void>((resolve) => slotWaiters.push(resolve));
  try {
    return await fn();
  } finally {
    const next = slotWaiters.shift();
    if (next) next();
    else runningOperations--;
  }
}

/** Current global queue state (read-only, for tests and diagnostics). */
export function gitQueueSnapshot(): { running: number; waiting: number } {
  return { running: runningOperations, waiting: slotWaiters.length };
}
