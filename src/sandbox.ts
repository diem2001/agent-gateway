import { spawn, type ChildProcess } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { SpawnOptions, SpawnedProcess } from "@anthropic-ai/claude-agent-sdk";
import { log, logAlways, logDebug } from "./logging.js";
import { gatewayModelProxy, type ModelProxy } from "./model-proxy.js";
import { fixedFailure, isolationTimeoutMessage, isolationUnavailableMessage, RunFailure } from "./run-failure.js";
import {
  SANDBOX_HOME,
  SANDBOX_WORK,
  checkTrusted,
  contentScanner,
  lstatOrNull,
  planTrustedContent,
  prepareMountPoints,
  prepareSandboxHome,
  prepareWorkArea,
  randomDirName,
  type MountPlan,
  type SandboxMount,
} from "./sandbox-content.js";
import { gatewayKnownValues } from "./tool-mediation.js";
import { getWorkspaceRoot } from "./workspace.js";
import { bundledCliPath } from "./runtime-cli.js";

/**
 * Per-run process isolation (MVP-7678, TD-1 to TD-7).
 *
 * Every agent run's Claude runtime (and so every Bash command, interpreter,
 * Read/Write/Edit/Glob/Grep call, runtime-spawned stdio MCP server and subagent) runs
 * inside a bubblewrap sandbox: new user, PID, IPC, UTS and cgroup namespaces, the
 * network namespace shared (the credential relay and the model proxy stay reachable),
 * all capabilities dropped, nested user namespaces disabled, and only an allowlist of
 * paths visible. The sandbox environment is an allowlist too; the only provider
 * credential it gets is a per-run token for the trusted model proxy.
 *
 * Nothing runs unsandboxed: every problem on the way (missing binary, namespace
 * failure, nested user namespaces not blocked, invalid storage root, unusable mount
 * source, startup timeout) fails the run with a fixed public text and is never retried.
 */

/* ------------------------------------------------------------------ */
/*  Configuration (TD-6)                                                */
/* ------------------------------------------------------------------ */

export interface IsolationConfig {
  startupTimeoutMs: number;
  runTimeoutMs: number;
  sandboxRoot: string;
  bwrapPath: string;
}

export const DEFAULT_ISOLATION_STARTUP_TIMEOUT_MS = 10_000;
export const DEFAULT_AGENT_RUN_TIMEOUT_MS = 7_200_000;
export const DEFAULT_SANDBOX_BWRAP = "/usr/bin/bwrap";

/** An invalid new configuration key: startup stops (nothing falls back silently). */
export class IsolationConfigError extends Error {
  constructor(
    readonly key: string,
    readonly reason: "positive_number" | "absolute_path",
  ) {
    super(`invalid value for ${key}`);
  }

  /** The fixed fatal log line. */
  get logLine(): string {
    const text = this.reason === "positive_number" ? "must be a positive whole number of milliseconds" : "must be an absolute path";
    return `FATAL config key=${this.key} reason=${text}`;
  }
}

function positiveNumber(env: NodeJS.ProcessEnv, key: string, fallback: number): number {
  const raw = env[key];
  if (raw === undefined) return fallback;
  if (!/^[0-9]+$/.test(raw.trim())) throw new IsolationConfigError(key, "positive_number");
  const value = Number(raw.trim());
  if (!Number.isSafeInteger(value) || value <= 0) throw new IsolationConfigError(key, "positive_number");
  return value;
}

function absolutePath(env: NodeJS.ProcessEnv, key: string, fallback: string): string {
  const raw = env[key];
  if (raw === undefined) return fallback;
  if (raw.length === 0 || raw.includes("\0") || !path.isAbsolute(raw)) throw new IsolationConfigError(key, "absolute_path");
  return path.resolve(raw);
}

/** The isolation keys of the environment; throws `IsolationConfigError` for an invalid value. */
export function loadIsolationConfig(env: NodeJS.ProcessEnv = process.env): IsolationConfig {
  return {
    startupTimeoutMs: positiveNumber(env, "ISOLATION_STARTUP_TIMEOUT_MS", DEFAULT_ISOLATION_STARTUP_TIMEOUT_MS),
    runTimeoutMs: positiveNumber(env, "AGENT_RUN_TIMEOUT_MS", DEFAULT_AGENT_RUN_TIMEOUT_MS),
    sandboxRoot: absolutePath(env, "AGENT_SANDBOX_ROOT", path.join(env.HOME || "/home/node", ".agent-sandbox")),
    bwrapPath: absolutePath(env, "AGENT_SANDBOX_BWRAP", DEFAULT_SANDBOX_BWRAP),
  };
}

/* ------------------------------------------------------------------ */
/*  Isolation state for /health and the operator log                    */
/* ------------------------------------------------------------------ */

export type IsolationStatus = "starting" | "ok" | "unavailable";

/** Problem words and their fixed operator texts; nothing else ever appears in the log line. */
const PROBLEMS = {
  binary_missing: "the isolation runtime is not installed or not executable",
  invalid_root: "the isolation storage directory is missing or not safe to use",
  namespace_denied: "the container does not allow the isolation namespaces",
  proc_denied: "the container does not allow a private process view",
  userns_not_blocked: "nested isolation is not blocked inside the sandbox",
  canary_visible: "a trusted file is visible inside the sandbox",
  pid_namespace_shared: "the sandbox shares the gateway's process view",
  mount_failed: "the sandbox could not mount its allowed content",
  content_invalid: "a directory the sandbox needs is not safe to use",
  proxy_unavailable: "the trusted model proxy is not running",
  start_failed: "the sandbox did not start",
} as const;

export type IsolationProblem = keyof typeof PROBLEMS;

let isolationState: IsolationStatus = "starting";

export function isolationStatus(): IsolationStatus {
  return isolationState;
}

function markIsolationOk(): void {
  if (isolationState !== "ok") log("isolation", "status=ok");
  isolationState = "ok";
}

function markIsolationUnavailable(problem: IsolationProblem): void {
  isolationState = "unavailable";
  // One fixed line; the same operator action applies to every problem.
  logAlways("isolation", `ERROR isolation problem=${problem} reason=${PROBLEMS[problem]} (see /health)`);
}

/** Tests only: the state a fresh gateway starts in. */
export function resetIsolationStatusForTests(): void {
  isolationState = "starting";
}

/** A failed or slow sandbox start, with a fixed public text. Never retried. */
export class IsolationFailure extends RunFailure {
  readonly problem: IsolationProblem | "timeout";

  constructor(problem: IsolationProblem | "timeout", queryId?: string) {
    const timeout = problem === "timeout";
    const failure = fixedFailure(timeout ? "isolation_timeout" : "isolation_unavailable", timeout ? isolationTimeoutMessage(queryId) : isolationUnavailableMessage(queryId));
    super(failure.kind, failure.message, failure.logFields, null);
    this.name = "IsolationFailure";
    this.problem = problem;
  }
}

/** A problem found while preparing a start, before any process exists. */
class SandboxPrepError extends Error {
  constructor(readonly problem: IsolationProblem) {
    super(problem);
  }
}

/** Records the outcome of a start attempt: a permanent problem marks isolation unavailable, a slow start changes nothing. */
function noteStartFailure(failure: IsolationFailure): void {
  if (failure.problem === "timeout") {
    log("isolation", "start timed out; isolation status unchanged");
    return;
  }
  markIsolationUnavailable(failure.problem);
}

/* ------------------------------------------------------------------ */
/*  bwrap argument builder (exact-argv tested)                          */
/* ------------------------------------------------------------------ */

/** Exit code the launch wrapper uses when a nested user namespace can still be created. */
export const EXIT_USERNS_NOT_BLOCKED = 97;
/** Exit code the launch wrapper uses when it cannot list its own descriptors (no `/proc`), so it cannot prove it closed them. */
export const EXIT_FDS_NOT_LISTABLE = 96;
/** Exit code the launch wrapper uses when a descriptor above 2 is still open after the close step. */
export const EXIT_FDS_NOT_CLOSED = 94;
/** Exit code the launch wrapper uses when a tool of its own start check (`unshare`, `true`) is not a regular executable file, or `unshare` could not run. */
export const EXIT_CHECK_TOOL_MISSING = 95;
/** The line the launch wrapper writes to stderr once the sandbox has passed its start check. */
export const SANDBOX_CHECK_LINE = "SANDBOX-CHECK-OK";
/**
 * The interpreter of the launch wrapper: bash, because dash cannot close descriptors above 9. `-p` (privileged mode)
 * ignores `BASH_ENV`, exported functions and `SHELLOPTS`; `--norc` is needed on top of it: the launcher's stdio are
 * sockets, and bash then behaves as if started by sshd and sources `/etc/bash.bashrc` and `$HOME/.bashrc` even under
 * `-p` (observed, Debian build).
 */
export const LAUNCH_INTERPRETER = ["/bin/bash", "--norc", "-p", "-c"] as const;
/**
 * Launch wrapper, first process inside the sandbox: close every descriptor above 2 (bwrap passes on whatever its
 * parent left open without close-on-exec, and the runtime inherits nothing but stdin, stdout and stderr), list the
 * descriptors again and refuse if one survived, refuse unless the tools of its own start check are regular executable
 * files, refuse to start unless a nested user namespace fails, report the passed check on stderr (which belongs to the
 * launcher until that line arrives) and exec the runtime.
 *
 * It runs under `bash --norc -p` so neither the caller-controlled environment of a stdio tool server (`BASH_ENV`,
 * `BASH_FUNC_*`, `SHELLOPTS`) nor a start file can change it; the close loop uses builtins only and does not look at
 * `PATH`; `unshare` and the program it runs are called by absolute path (`unshare -U true` would look `true` up in
 * `PATH`, fail under a poisoned `PATH` and read as "blocked"); and it refuses (its own exit code) when it cannot list
 * its descriptors, because an unmatched glob would otherwise close nothing.
 *
 * A start check that cannot run is never a passed check: `[ -f ] && [ -x ]` rejects a missing tool, a directory and a
 * file that is not executable (95), and only exit status 1 of `unshare` counts as "blocked" (126 or 127 mean it could
 * not run, 95). The re-listed glob's own directory descriptor is closed again when the test runs, so it needs no
 * exception.
 */
export const LAUNCH_WRAPPER = `[ -e /proc/self/fd/0 ] || exit ${EXIT_FDS_NOT_LISTABLE}; for f in /proc/self/fd/*; do n=\${f##*/}; if [ "$n" -gt 2 ]; then eval "exec $n>&-"; fi; done; for f in /proc/self/fd/*; do n=\${f##*/}; if [ "$n" -gt 2 ] && [ -L "$f" ]; then exit ${EXIT_FDS_NOT_CLOSED}; fi; done; [ -f /usr/bin/unshare ] && [ -x /usr/bin/unshare ] && [ -f /usr/bin/true ] && [ -x /usr/bin/true ] || exit ${EXIT_CHECK_TOOL_MISSING}; /usr/bin/unshare -U /usr/bin/true >/dev/null 2>&1; r=$?; [ $r -eq 0 ] && exit ${EXIT_USERNS_NOT_BLOCKED}; [ $r -eq 1 ] || exit ${EXIT_CHECK_TOOL_MISSING}; echo ${SANDBOX_CHECK_LINE} >&2; exec "$@"`;

export interface RootLayout {
  /** `--symlink <target> <link>` entries (merged-usr layouts). */
  symlinks: { link: string; target: string }[];
  /** Real directories bound read-only at their own path. */
  binds: string[];
}

export interface ProcMasks {
  /** Files under /proc hidden behind /dev/null. */
  files: string[];
  /** Directories under /proc replaced by an empty tmpfs. */
  dirs: string[];
}

export interface BwrapSpec {
  layout: RootLayout;
  procMasks: ProcMasks;
  /** Host session home, bound read-write at `/home/node`. */
  homeDir: string;
  /** Host work area of the conversation, bound read-write at `/work`, the working directory; without one the home is the working directory (tool sandboxes). */
  workDir?: string;
  /** Read-only binds of trusted content (applied after the home bind, in order). */
  mounts: SandboxMount[];
  /** Destination paths hidden behind an empty file. */
  hidden: string[];
  /** A trusted empty regular file, the source of every hidden path (a bound device node is unreadable, not empty). */
  emptyFile: string;
  /** Host paths bound read-only at the same path. */
  roBinds: string[];
  /** Host paths bound read-write at the same path. */
  rwBinds: string[];
  command: string;
  args: string[];
}

/** The bwrap arguments (without the binary): the allowlist and nothing else. */
export function buildBwrapArgv(spec: BwrapSpec): string[] {
  const argv: string[] = [
    "--unshare-user",
    "--disable-userns",
    "--unshare-pid",
    "--unshare-ipc",
    "--unshare-uts",
    "--unshare-cgroup",
    "--die-with-parent",
    "--new-session",
    "--cap-drop",
    "ALL",
    "--ro-bind",
    "/usr",
    "/usr",
  ];
  for (const { link, target } of spec.layout.symlinks) argv.push("--symlink", target, link);
  for (const dir of spec.layout.binds) argv.push("--ro-bind", dir, dir);
  argv.push("--ro-bind", "/etc", "/etc", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp");
  for (const file of spec.procMasks.files) argv.push("--ro-bind", "/dev/null", `/proc/${file}`);
  for (const dir of spec.procMasks.dirs) argv.push("--tmpfs", `/proc/${dir}`);
  argv.push("--ro-bind", "/proc/sys", "/proc/sys");
  argv.push("--bind", spec.homeDir, SANDBOX_HOME);
  if (spec.workDir) argv.push("--bind", spec.workDir, SANDBOX_WORK);
  for (const mount of spec.mounts) argv.push("--ro-bind", mount.src, mount.dest);
  for (const dest of spec.hidden) argv.push("--ro-bind", spec.emptyFile, dest);
  for (const p of spec.roBinds) argv.push("--ro-bind", p, p);
  for (const p of spec.rwBinds) argv.push("--bind", p, p);
  argv.push("--chdir", spec.workDir ? SANDBOX_WORK : SANDBOX_HOME, "--", ...LAUNCH_INTERPRETER, LAUNCH_WRAPPER, "sandbox", spec.command, ...spec.args);
  return argv;
}

let cachedLayout: RootLayout | null = null;

/** How `/bin`, `/sbin`, `/lib`, `/lib64` look on this host: symlinks into /usr (merged) or real directories. */
export function detectRootLayout(): RootLayout {
  if (cachedLayout) return cachedLayout;
  const layout: RootLayout = { symlinks: [], binds: [] };
  for (const dir of ["/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32"]) {
    const stat = lstatOrNull(dir);
    if (!stat) continue;
    if (stat.isSymbolicLink()) {
      const target = fs.readlinkSync(dir);
      // Only links into /usr are reproduced; anything else would point outside the allowlist.
      const relative = path.isAbsolute(target) ? path.relative("/", target) : target;
      if (relative.startsWith("usr/")) layout.symlinks.push({ link: dir, target: relative });
    } else if (stat.isDirectory()) {
      layout.binds.push(dir);
    }
  }
  cachedLayout = layout;
  return layout;
}

let cachedMasks: ProcMasks | null = null;

/** The /proc entries Docker normally masks, limited to the ones this kernel has (bwrap cannot create a missing /proc entry). */
export function detectProcMasks(): ProcMasks {
  if (cachedMasks) return cachedMasks;
  const masks: ProcMasks = { files: [], dirs: [] };
  for (const file of ["kcore", "keys", "timer_list", "sysrq-trigger"]) if (lstatOrNull(`/proc/${file}`)) masks.files.push(file);
  for (const dir of ["acpi", "scsi"]) if (lstatOrNull(`/proc/${dir}`)) masks.dirs.push(dir);
  cachedMasks = masks;
  return masks;
}

/* ------------------------------------------------------------------ */
/*  Sandbox environment (TD-7)                                          */
/* ------------------------------------------------------------------ */

const RUNTIME_KEY = /^(CLAUDE_CODE|CLAUDE_AGENT_SDK)_[A-Z0-9_]+$/;
const SECRET_KEY = /(TOKEN|KEY|SECRET|PASSWORD|CREDENTIAL)/;
const SAFE_VALUE = /^[A-Za-z0-9_.@:/=,+-]{0,200}$/;

/**
 * The non-secret `CLAUDE_CODE_*` and `CLAUDE_AGENT_SDK_*` keys of `source` (the SDK
 * sets a few): never one that looks like a credential, never `CLAUDE_CODE_OAUTH_TOKEN`.
 */
export function runtimeEnvFrom(source: { [key: string]: string | undefined }): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(source)) {
    if (typeof value !== "string" || !RUNTIME_KEY.test(key) || SECRET_KEY.test(key) || !SAFE_VALUE.test(value)) continue;
    result[key] = value;
  }
  return result;
}

export interface SandboxEnvInput {
  /** The environment the SDK passes to the spawn hook (only its non-secret runtime keys are used). */
  sdkEnv: { [key: string]: string | undefined };
  /** The gateway's own environment (only locale values are read). */
  gatewayEnv: NodeJS.ProcessEnv;
  proxyBaseUrl: string;
  runToken: string;
  runLogEnv: Record<string, string>;
}

/**
 * Trusted git configuration, injected at command scope (git 2.31+, highest precedence, above any repository file the
 * agent writes). The runtime runs `git status` in `/work` at every start and the agent writes that directory, so git
 * must find no repository there that it would read: `.git` is removed before the start and an implicit bare layout
 * (HEAD, objects, refs, config in the working directory itself) is refused (`safe.bareRepository`, 2.38+; a protected
 * key, honored only from the system, global and command scope). With no repository discovered, no repository file is
 * read at all. fsmonitor and hooks are switched off as a second layer for the repositories git is still told to use.
 */
const GIT_TRUSTED_CONFIG: ReadonlyArray<readonly [string, string]> = [
  ["safe.bareRepository", "explicit"],
  ["core.fsmonitor", "false"],
  ["core.hooksPath", "/dev/null"],
];

/** The complete sandbox environment: an allowlist, built from nothing. */
export function buildSandboxEnv(input: SandboxEnvInput): Record<string, string> {
  const env: Record<string, string> = {
    HOME: SANDBOX_HOME,
    USER: "node",
    PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    LANG: "C.UTF-8",
    TERM: "xterm",
    TMPDIR: "/tmp",
    // The gateway promises MCP tools are available on the first turn. New SDK runtimes connect in the background unless disabled.
    MCP_CONNECTION_NONBLOCKING: "0",
  };
  for (const [key, value] of Object.entries(input.gatewayEnv)) {
    if ((key === "LANG" || /^LC_[A-Z_]+$/.test(key)) && typeof value === "string" && /^[A-Za-z0-9_.@-]{1,64}$/.test(value)) env[key] = value;
  }
  Object.assign(env, runtimeEnvFrom(input.sdkEnv));
  Object.assign(env, input.runLogEnv, {
    ANTHROPIC_BASE_URL: input.proxyBaseUrl,
    ANTHROPIC_API_KEY: input.runToken,
    DISABLE_AUTOUPDATER: "1",
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
    GIT_CONFIG_COUNT: String(GIT_TRUSTED_CONFIG.length),
  });
  GIT_TRUSTED_CONFIG.forEach(([key, value], i) => {
    env[`GIT_CONFIG_KEY_${i}`] = key;
    env[`GIT_CONFIG_VALUE_${i}`] = value;
  });
  return env;
}

/* ------------------------------------------------------------------ */
/*  Storage root                                                        */
/* ------------------------------------------------------------------ */

function ownedAndPrivate(stat: import("node:fs").Stats): boolean {
  const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
  return (uid === undefined || stat.uid === uid) && (stat.mode & 0o022) === 0;
}

/** Creates `dir` (0700) when it is missing; it must be a real directory owned by the gateway user and not group or world writable. */
function ensurePrivateDir(dir: string): void {
  let stat = lstatOrNull(dir);
  if (!stat) {
    try {
      fs.mkdirSync(dir, { mode: 0o700 });
    } catch {
      throw new SandboxPrepError("invalid_root");
    }
    stat = lstatOrNull(dir);
  }
  if (!stat || stat.isSymbolicLink() || !stat.isDirectory() || !ownedAndPrivate(stat)) throw new SandboxPrepError("invalid_root");
}

/**
 * Validates the trusted storage root (no symlink in its path, a private directory owned by
 * the gateway user) and returns its `runs` directory. Throws `SandboxPrepError`.
 */
export function prepareRunsRoot(root: string): string {
  ensurePrivateDir(root);
  let real: string;
  try {
    real = fs.realpathSync(root);
  } catch {
    throw new SandboxPrepError("invalid_root");
  }
  if (real !== path.resolve(root)) throw new SandboxPrepError("invalid_root");
  const runs = path.join(root, "runs");
  ensurePrivateDir(runs);
  return runs;
}

/** A directory the agent writes: a real directory owned by the gateway user (never a link), private to it. */
function ensureAgentDir(dir: string): void {
  let stat = lstatOrNull(dir);
  if (!stat) {
    fs.mkdirSync(dir, { mode: 0o700 });
    stat = lstatOrNull(dir);
  }
  const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
  if (!stat || stat.isSymbolicLink() || !stat.isDirectory() || (uid !== undefined && stat.uid !== uid)) throw new SandboxPrepError("invalid_root");
  fs.chmodSync(dir, 0o700);
}

/**
 * The persistent directories of a conversation: `<root>/sessions/<name>/home` (rebuilt at every start, only the
 * runtime's data carries over) and `<root>/sessions/<name>/work` (the agent's work area, bound at `/work`), both
 * created on first use. The name is the random id recorded with the conversation; the directories above are
 * private to the gateway, the two below are the agent's. Deleting a conversation leaves both in place: cleanup and
 * retention belong to MVP-7402.
 */
function sessionDirs(root: string, dirId: string): { home: string; work: string } {
  if (!/^[0-9a-f]{24}$/.test(dirId)) throw new SandboxPrepError("content_invalid");
  const sessions = path.join(root, "sessions");
  ensurePrivateDir(sessions);
  const dir = path.join(sessions, dirId);
  ensurePrivateDir(dir);
  const home = path.join(dir, "home");
  const work = path.join(dir, "work");
  ensureAgentDir(home);
  ensureAgentDir(work);
  return { home, work };
}

/** Removes every run directory a crashed gateway left behind. Called once at start. */
export function sweepSandboxRuns(root: string = loadIsolationConfig().sandboxRoot): void {
  const runs = path.join(root, "runs");
  const stat = lstatOrNull(runs);
  if (!stat || !stat.isDirectory() || stat.isSymbolicLink()) return;
  let removed = 0;
  for (const name of fs.readdirSync(runs)) {
    if (!name.startsWith("run-")) continue;
    fs.rmSync(path.join(runs, name), { recursive: true, force: true });
    removed++;
  }
  if (removed > 0) log("server", `Removed ${removed} leftover sandbox run director${removed === 1 ? "y" : "ies"}`);
}

/* ------------------------------------------------------------------ */
/*  Launching bwrap                                                     */
/* ------------------------------------------------------------------ */

export interface Launch {
  child: ChildProcess;
  /** Resolves when the sandbox has started and passed its check line, rejects with the start failure. */
  ready: Promise<void>;
  failure: () => IsolationFailure | null;
}

/** The isolation runtime's own exec failure for the launch wrapper's interpreter: missing, or not executable. */
const INTERPRETER_EXEC_FAILURE = new RegExp(`execvp ${LAUNCH_INTERPRETER[0].replace(/[.*+?^${}()|[\]\\/]/g, "\\$&")}: (No such file or directory|Permission denied)`);

function classifyEarlyExit(code: number | null, stderr: string): IsolationProblem {
  if (code === EXIT_USERNS_NOT_BLOCKED) return "userns_not_blocked";
  if (code === EXIT_FDS_NOT_LISTABLE) return "proc_denied";
  if (code === EXIT_CHECK_TOOL_MISSING) return "binary_missing";
  if (code === EXIT_FDS_NOT_CLOSED) return "start_failed";
  if (INTERPRETER_EXEC_FAILURE.test(stderr)) return "binary_missing";
  if (/No permissions to create new namespace|Creating new namespace failed/.test(stderr)) return "namespace_denied";
  if (/Can't mount proc|mount proc/.test(stderr)) return "proc_denied";
  if (/Can't (mount|bind|make|create|mkdir|find source|open)|Failed to make|pivot_root|No such file or directory/.test(stderr)) return "mount_failed";
  return "start_failed";
}

export function launchBwrap(
  config: IsolationConfig,
  argv: string[],
  env: Record<string, string>,
  options: { signal?: AbortSignal; queryId?: string; markOk?: boolean },
): Launch {
  let failure: IsolationFailure | null = null;
  let settled = false;
  let resolveReady: () => void = () => {};
  let rejectReady: (f: IsolationFailure) => void = () => {};
  const ready = new Promise<void>((resolve, reject) => {
    resolveReady = resolve;
    rejectReady = reject;
  });

  // The options travel through a pipe (`--args 3`), only the command stays on the command line: the
  // sandbox's process 1 is a copy of bwrap and its /proc/1/cmdline would otherwise show every host path
  // it mounts. bwrap reads and closes the descriptor before it starts the sandbox's first process.
  const split = argv.indexOf("--");
  const child = spawn(config.bwrapPath, ["--args", "3", ...argv.slice(split)], { env, signal: options.signal, stdio: ["pipe", "pipe", "pipe", "pipe"], windowsHide: true });
  const argsPipe = child.stdio[3] as import("node:stream").Writable | null;
  argsPipe?.on("error", () => {});
  argsPipe?.end(Buffer.from(`${argv.slice(0, split).join("\0")}\0`, "utf8"));
  let stderrText = "";
  const timer = setTimeout(() => {
    fail(new IsolationFailure("timeout", options.queryId));
  }, config.startupTimeoutMs);

  function fail(f: IsolationFailure): void {
    if (failure || settled) return;
    // A client that went away during the start is not an isolation problem.
    if (options.signal?.aborted) {
      settled = true;
      clearTimeout(timer);
      rejectReady(f);
      return;
    }
    failure = f;
    settled = true;
    clearTimeout(timer);
    noteStartFailure(f);
    try {
      child.kill("SIGKILL");
    } catch {
      // Already gone.
    }
    rejectReady(f);
  }

  // stderr is the launcher's own until the wrapper's check line arrives; after that the runtime owns it
  // and it is only drained.
  child.stderr?.on("data", (chunk: Buffer) => {
    if (settled) return;
    stderrText += chunk.toString("utf8");
    if (stderrText.split("\n").includes(SANDBOX_CHECK_LINE)) {
      settled = true;
      clearTimeout(timer);
      if (options.markOk !== false) markIsolationOk();
      resolveReady();
    } else if (stderrText.length > 4096) {
      stderrText = stderrText.slice(-2048);
    }
  });
  child.stdin?.on("error", () => {});
  child.once("error", (error: NodeJS.ErrnoException) => {
    if (options.signal?.aborted) return;
    fail(new IsolationFailure(error.code === "ENOENT" || error.code === "EACCES" ? "binary_missing" : "start_failed", options.queryId));
  });
  child.once("exit", (code) => {
    if (!settled) {
      logDebug("isolation", `sandbox exited before it was ready: code=${code}`);
      fail(new IsolationFailure(classifyEarlyExit(code, stderrText), options.queryId));
    }
  });
  return { child, ready, failure: () => failure };
}

/* ------------------------------------------------------------------ */
/*  The launcher's end as the SDK and the gateway see it (MVP-7964)     */
/* ------------------------------------------------------------------ */

/** How the launcher ended: Node's own exit code and signal, never decoded. */
export interface LauncherExit {
  exitCode: number | null;
  signalCode: NodeJS.Signals | null;
}

/**
 * Resolves when the launcher ended by a signal nobody on the gateway side sent, and never otherwise (a normal
 * end, an exit code, any `kill()` from this process, the gateway's own cleanup, an abort). `child.killed` is true
 * after every `kill()` this process issued, including the abort signal of `spawn`, so it separates the gateway's
 * own endings from an outside one. `owned` names the endings `killed` cannot see (the cleanup kill, an abort).
 */
export function watchUnownedExit(child: ChildProcess, owned: () => boolean): Promise<LauncherExit> {
  return new Promise<LauncherExit>((resolve) => {
    child.once("exit", (exitCode, signalCode) => {
      if (signalCode !== null && !child.killed && !owned()) resolve({ exitCode, signalCode });
    });
  });
}

type ExitListener = (code: number | null, signal: NodeJS.Signals | null) => void;

/**
 * The process object the SDK gets. SDK 0.1.77 looks at `exitCode`/`killed` when it starts waiting for the end of
 * the runtime and otherwise registers a one-time `exit` listener; a launcher ended by an outside signal has
 * `exitCode` null and `killed` false, so that listener arrives after the event and is never called. This object
 * calls an `exit` listener that is registered after the end once, with the recorded code and signal, so the
 * SDK's wait ends with its own error instead of hanging. Everything else is the launcher itself.
 */
export function sdkProcessOf(child: ChildProcess): SpawnedProcess {
  const replays = new Map<ExitListener, NodeJS.Immediate>();
  const ended = (): boolean => child.exitCode !== null || child.signalCode !== null;
  const add = (once: boolean) => (event: "exit" | "error", listener: ExitListener | ((error: Error) => void)): void => {
    if (event === "exit" && ended()) {
      const exitListener = listener as ExitListener;
      replays.set(
        exitListener,
        setImmediate(() => {
          replays.delete(exitListener);
          exitListener(child.exitCode, child.signalCode);
        }),
      );
      return;
    }
    if (once) child.once(event, listener as (...args: unknown[]) => void);
    else child.on(event, listener as (...args: unknown[]) => void);
  };
  return {
    stdin: child.stdin,
    stdout: child.stdout,
    get killed(): boolean {
      return child.killed;
    },
    get exitCode(): number | null {
      return child.exitCode;
    },
    kill: (signal: NodeJS.Signals): boolean => child.kill(signal),
    on: add(false),
    once: add(true),
    off: (event: "exit" | "error", listener: ExitListener | ((error: Error) => void)): void => {
      const pending = event === "exit" ? replays.get(listener as ExitListener) : undefined;
      if (pending !== undefined) {
        clearImmediate(pending);
        replays.delete(listener as ExitListener);
      } else {
        child.off(event, listener as (...args: unknown[]) => void);
      }
    },
  } as unknown as SpawnedProcess;
}

/* ------------------------------------------------------------------ */
/*  One active request per conversation                                 */
/* ------------------------------------------------------------------ */

const lockedConversations = new Set<string>();

export interface ConversationLock {
  release: () => void;
}

/**
 * The trusted-side lock of one conversation home: a second request for a conversation that is still
 * answering gets null (and is refused with 0 runtime starts). Held for the whole request, retries
 * included; `SandboxRun.dispose` has waited for the sandbox process to exit before it is released (after a
 * deadline stop whose exit was not observed in time, query.ts keeps the lock until that exit), so two sandboxes
 * never share one home at the same time.
 */
export function tryLockConversation(dirId: string): ConversationLock | null {
  if (lockedConversations.has(dirId)) return null;
  lockedConversations.add(dirId);
  let released = false;
  return {
    release: () => {
      if (released) return;
      released = true;
      lockedConversations.delete(dirId);
    },
  };
}

/* ------------------------------------------------------------------ */
/*  One run's sandbox                                                   */
/* ------------------------------------------------------------------ */

export interface SandboxRunOptions {
  queryId?: string;
  /** This run's log directory (MVP-7667), writable in the sandbox at its own path. */
  runLogDir: string;
  runLogEnv: Record<string, string>;
  /** This run's user-skill bundle (read-only at its own path), or null. */
  userSkillsDir?: string | null;
  /**
   * The run has no `Bash` grant (MVP-8106): the skill, agent and command files it sees are a run-scoped copy without
   * command settings. `label` is the caller's API-key label, for the audit line of a rewritten file.
   */
  neutralizeCommands?: boolean;
  label?: string;
  /**
   * The conversation's recorded sandbox home name: its home persists under `<root>/sessions/<name>/home`
   * between requests. Without one, the home is private to this run and removed with it.
   */
  sessionDirId?: string;
  signal?: AbortSignal;
  /** Tests: a workspace root other than the gateway's own. */
  workspaceRoot?: string;
  /** Tests: fixed configuration and proxy. */
  config?: IsolationConfig;
  proxy?: ModelProxy;
}

const RUNTIME_EXIT_WAIT_MS = 10_000;

/** How long a deadline stop waits to observe the launcher's exit after it sent SIGKILL (MVP-8000). */
export const DEADLINE_KILL_CONFIRM_MS = 500;

function runtimeSdkDir(cliPath: string): string {
  let trustedCli: string;
  let resolvedCli: string;
  try {
    trustedCli = fs.realpathSync(bundledCliPath());
    resolvedCli = fs.realpathSync(cliPath);
  } catch {
    throw new SandboxPrepError("content_invalid");
  }
  if (resolvedCli !== trustedCli) throw new SandboxPrepError("content_invalid");
  return path.dirname(cliPath);
}

/**
 * The sandbox of one agent run. `spawnHook` is the SDK's `spawnClaudeCodeProcess`: it
 * prepares the run's private directories, plans the allowed content, registers a model
 * proxy token and starts the runtime through bwrap. A problem on the way throws an
 * `IsolationFailure` (nothing runs); a failure after the process exists is kept in
 * `startFailure` for the caller to report instead of the SDK's generic exit error.
 * `dispose` revokes the token and removes the run's directories once the process is gone.
 */
export class SandboxRun {
  private readonly options: SandboxRunOptions;
  private proxyToken: string | null = null;
  private runDir: string | null = null;
  private launch: Launch | null = null;
  private prepFailure: IsolationFailure | null = null;
  /** Set when `dispose` itself killed the launcher: that end is the gateway's own cleanup, not a cause to report. */
  private killedByGateway = false;
  private readonly unowned: Promise<LauncherExit>;
  private resolveUnowned: (exit: LauncherExit) => void = () => {};
  readonly spawnHook: (spawnOptions: SpawnOptions) => SpawnedProcess;

  constructor(options: SandboxRunOptions) {
    this.options = options;
    this.spawnHook = (spawnOptions) => this.start(spawnOptions);
    this.unowned = new Promise<LauncherExit>((resolve) => {
      this.resolveUnowned = resolve;
    });
  }

  /**
   * Resolves when the launcher ended by a signal the gateway did not send (MVP-7964), and never otherwise: not
   * for a normal end, an exit code, the SDK's or the gateway's own kill, an abort or a start failure.
   */
  unownedExit(): Promise<LauncherExit> {
    return this.unowned;
  }

  /** Watches a started launcher for an outside signal; `start` calls it for every launch. */
  watchLaunch(launch: Launch, spawnSignal?: AbortSignal): void {
    void watchUnownedExit(launch.child, () => this.killedByGateway || spawnSignal?.aborted === true || this.options.signal?.aborted === true).then((exit) =>
      this.resolveUnowned(exit),
    );
  }

  /** Closes the launcher's output stream so an SDK reader blocked on it stops; stdin stays, so a late SDK write cannot throw. */
  releaseOutput(): void {
    this.launch?.child.stdout?.destroy();
  }

  /** The runtime's process group leader (the bwrap process), once started. */
  get child(): ChildProcess | null {
    return this.launch?.child ?? null;
  }

  /**
   * The runtime process's own exit metadata for the failure log (MVP-7852): the exit code and signal of
   * the launcher (bwrap) process as Node observed them, never decoded. Null without a launch and after
   * the gateway's own cleanup kill; both fields are null while the launcher has not exited.
   */
  get runtimeExit(): { exitCode: number | null; signalCode: NodeJS.Signals | null } | null {
    const child = this.launch?.child;
    if (!child || this.killedByGateway) return null;
    return { exitCode: child.exitCode, signalCode: child.signalCode };
  }

  /** The isolation failure of this run, if its start failed. */
  get startFailure(): IsolationFailure | null {
    return this.prepFailure ?? this.launch?.failure() ?? null;
  }

  private proxy(): ModelProxy {
    return this.options.proxy ?? gatewayModelProxy();
  }

  private start(spawnOptions: SpawnOptions): SpawnedProcess {
    const queryId = this.options.queryId;
    let config: IsolationConfig;
    try {
      config = this.options.config ?? loadIsolationConfig();
    } catch {
      return this.refuse("start_failed");
    }
    try {
      const launch = this.prepareAndLaunch(config, spawnOptions);
      this.launch = launch;
      launch.ready.catch(() => {});
      this.watchLaunch(launch, spawnOptions.signal);
      return sdkProcessOf(launch.child);
    } catch (error) {
      if (error instanceof IsolationFailure) throw error;
      if (error instanceof SandboxPrepError) return this.refuse(error.problem);
      logDebug("isolation", `unexpected error while preparing a sandbox: ${error instanceof Error ? error.name : "unknown"}`);
      void queryId;
      return this.refuse("start_failed");
    }
  }

  private refuse(problem: IsolationProblem): never {
    const failure = new IsolationFailure(problem, this.options.queryId);
    this.prepFailure = failure;
    noteStartFailure(failure);
    throw failure;
  }

  private prepareAndLaunch(config: IsolationConfig, spawnOptions: SpawnOptions): Launch {
    try {
      fs.accessSync(config.bwrapPath, fs.constants.X_OK);
    } catch {
      throw new SandboxPrepError("binary_missing");
    }
    const runs = prepareRunsRoot(config.sandboxRoot);
    const proxy = this.proxy();
    if (!proxy.isListening()) throw new SandboxPrepError("proxy_unavailable");

    const runDir = fs.mkdtempSync(path.join(runs, "run-"));
    this.runDir = runDir;
    fs.chmodSync(runDir, 0o700);
    const trustedDir = path.join(runDir, "trusted");
    fs.mkdirSync(trustedDir, { mode: 0o700 });
    let homeDir: string;
    let workDir: string;
    if (this.options.sessionDirId) {
      ({ home: homeDir, work: workDir } = sessionDirs(config.sandboxRoot, this.options.sessionDirId));
    } else {
      homeDir = path.join(runDir, "home");
      workDir = path.join(runDir, "work");
      fs.mkdirSync(homeDir, { mode: 0o700 });
      fs.mkdirSync(workDir, { mode: 0o700 });
    }

    const workspaceRoot = this.options.workspaceRoot ?? getWorkspaceRoot();
    const needles = gatewayKnownValues(workspaceRoot);
    const plan: MountPlan = planTrustedContent({ workspaceRoot, trustedDir, needles, scanner: contentScanner, neutralizeCommands: this.options.neutralizeCommands === true, label: this.options.label });
    if (plan.skipped > 0 || plan.hiddenCount > 0) log("audit", `sandbox.content skipped=${plan.skipped} hidden=${plan.hiddenCount}`);

    // The runtime and the trusted directories it needs, each validated without following links.
    const cliPath = [spawnOptions.command, ...spawnOptions.args].find((arg) => arg === bundledCliPath());
    if (!cliPath) throw new SandboxPrepError("content_invalid");
    const sdkDir = runtimeSdkDir(cliPath);
    const roBinds = [sdkDir];
    const command = spawnOptions.command === "node" ? process.execPath : spawnOptions.command;
    if (!path.isAbsolute(command)) throw new SandboxPrepError("content_invalid");
    if (!command.startsWith("/usr/") && !roBinds.includes(command) && !command.startsWith(`${sdkDir}/`)) roBinds.push(command);
    const tmpRoot = fs.realpathSync(os.tmpdir());
    const rwBinds: string[] = [];
    const logCheck = checkTrusted(path.join(tmpRoot, path.basename(this.options.runLogDir)), "dir", tmpRoot);
    if (!logCheck.ok || path.dirname(fs.realpathSync(this.options.runLogDir)) !== tmpRoot) throw new SandboxPrepError("content_invalid");
    rwBinds.push(this.options.runLogDir);
    if (this.options.userSkillsDir) {
      const skillsCheck = checkTrusted(path.join(tmpRoot, path.basename(this.options.userSkillsDir)), "dir", tmpRoot);
      if (!skillsCheck.ok || path.dirname(fs.realpathSync(this.options.userSkillsDir)) !== tmpRoot) throw new SandboxPrepError("content_invalid");
      roBinds.push(this.options.userSkillsDir);
    }

    try {
      prepareSandboxHome(homeDir);
      prepareWorkArea(workDir);
    } catch {
      throw new SandboxPrepError("content_invalid");
    }
    prepareMountPoints(homeDir, plan.mounts, plan.hidden);
    const emptyFile = path.join(trustedDir, "empty");
    fs.writeFileSync(emptyFile, "", { mode: 0o444 });

    const registration = proxy.register();
    this.proxyToken = registration.token;
    const env = buildSandboxEnv({
      sdkEnv: spawnOptions.env,
      gatewayEnv: process.env,
      proxyBaseUrl: registration.baseUrl,
      runToken: registration.token,
      runLogEnv: this.options.runLogEnv,
    });
    const argv = buildBwrapArgv({
      layout: detectRootLayout(),
      procMasks: detectProcMasks(),
      homeDir,
      workDir,
      mounts: plan.mounts,
      hidden: plan.hidden,
      emptyFile,
      roBinds,
      rwBinds,
      command,
      args: spawnOptions.args,
    });
    return launchBwrap(config, argv, env, { signal: spawnOptions.signal, queryId: this.options.queryId });
  }

  /** Revokes the run token now; removes the run's directories once the process has exited (killed after a bounded wait). */
  async dispose(waitMs: number = RUNTIME_EXIT_WAIT_MS): Promise<void> {
    this.revokeProxyToken();
    const child = this.child;
    if (child && child.exitCode === null && child.signalCode === null) {
      await new Promise<void>((resolve) => {
        const timer = setTimeout(() => {
          log("query", "sandbox did not exit in time; killing it");
          this.killedByGateway = true;
          child.kill("SIGKILL");
        }, waitMs);
        child.once("exit", () => {
          clearTimeout(timer);
          resolve();
        });
      });
    }
    this.removeRunDir();
  }

  /**
   * The stop of a run whose deadline expired (MVP-8000): the run token is revoked and the launcher is killed at once
   * (`--unshare-pid` and `--die-with-parent` take the sandbox tree with it), and its exit is awaited at most
   * `confirmMs`. Resolves null when the exit was observed (the run directory is then removed, as `dispose` does).
   * Otherwise it logs one line and resolves with the launcher's exit promise (wrapped, so awaiting this call does not await the exit) without blocking the request; the run
   * directory is removed when that exit is eventually observed, and the caller keeps the conversation locked until then.
   */
  async disposeAfterDeadline(confirmMs: number = DEADLINE_KILL_CONFIRM_MS): Promise<{ exited: Promise<void> } | null> {
    this.revokeProxyToken();
    const child = this.child;
    if (child && child.exitCode === null && child.signalCode === null) {
      const exited = new Promise<void>((resolve) => child.once("exit", () => resolve()));
      this.killedByGateway = true;
      child.kill("SIGKILL");
      const startedAt = Date.now();
      let timer: NodeJS.Timeout | undefined;
      const confirmed = await Promise.race([
        exited.then(() => true),
        new Promise<boolean>((resolve) => { timer = setTimeout(() => resolve(false), confirmMs); }),
      ]);
      clearTimeout(timer);
      if (!confirmed) {
        log("query", `sandbox exit not confirmed after deadline stop queryId=${this.options.queryId ?? "none"} waitedMs=${Date.now() - startedAt}`);
        void exited.then(() => this.removeRunDir());
        return { exited };
      }
    }
    this.removeRunDir();
    return null;
  }

  private revokeProxyToken(): void {
    if (this.proxyToken) {
      this.proxy().revoke(this.proxyToken);
      this.proxyToken = null;
    }
  }

  private removeRunDir(): void {
    if (!this.runDir) return;
    try {
      fs.rmSync(this.runDir, { recursive: true, force: true });
    } catch (e: unknown) {
      log("query", `sandbox run directory cleanup failed: ${e instanceof Error ? e.name : "error"}`);
    }
    this.runDir = null;
  }
}

/* ------------------------------------------------------------------ */
/*  Boot self-check                                                     */
/* ------------------------------------------------------------------ */

/** The checks of the boot self-check, run inside a sandbox: exit codes name the problem. */
const SELF_CHECK_SCRIPT = `[ -e "$1" ] && exit 98; [ "$(cat /proc/1/comm)" = "bwrap" ] || exit 99; exit 0`;

/**
 * Starts a real sandbox and checks what must hold: a trusted canary file next to the session
 * homes is invisible, the sandbox has its own process view, and a nested user namespace is
 * refused (by the launch wrapper). Sets the `/health` isolation state.
 */
export async function runIsolationSelfCheck(configOverride?: IsolationConfig): Promise<void> {
  let config: IsolationConfig;
  try {
    config = configOverride ?? loadIsolationConfig();
  } catch {
    markIsolationUnavailable("start_failed");
    return;
  }
  let runDir: string | null = null;
  try {
    try {
      fs.accessSync(config.bwrapPath, fs.constants.X_OK);
    } catch {
      throw new SandboxPrepError("binary_missing");
    }
    const runs = prepareRunsRoot(config.sandboxRoot);
    runDir = fs.mkdtempSync(path.join(runs, "run-"));
    fs.chmodSync(runDir, 0o700);
    const homeDir = path.join(runDir, "home");
    const workDir = path.join(runDir, "work");
    fs.mkdirSync(homeDir, { mode: 0o700 });
    fs.mkdirSync(workDir, { mode: 0o700 });
    const canary = path.join(runDir, `canary-${randomDirName()}`);
    fs.writeFileSync(canary, "canary", { mode: 0o600 });
    const argv = buildBwrapArgv({
      layout: detectRootLayout(),
      procMasks: detectProcMasks(),
      homeDir,
      workDir,
      mounts: [],
      hidden: [],
      emptyFile: "/dev/null",
      roBinds: [],
      rwBinds: [],
      command: "/bin/sh",
      args: ["-c", SELF_CHECK_SCRIPT, "selfcheck", canary],
    });
    const launch = launchBwrap(config, argv, { PATH: "/usr/bin:/bin", HOME: SANDBOX_HOME }, { markOk: false });
    launch.child.stdout?.resume();
    const outcome = await new Promise<"ok" | IsolationFailure | number>((resolve) => {
      launch.ready.catch((f: IsolationFailure) => resolve(f));
      launch.child.once("exit", (code) => resolve(code === 0 ? "ok" : (code ?? -1)));
    });
    if (outcome === "ok") {
      markIsolationOk();
      return;
    }
    if (outcome instanceof IsolationFailure) {
      // A slow start during boot is unavailable until a later start succeeds.
      markIsolationUnavailable(outcome.problem === "timeout" ? "start_failed" : outcome.problem);
      return;
    }
    // The launcher ended before its check line: `launchBwrap` already classified the exit, logged it and marked the state once.
    if (launch.failure()) return;
    if (outcome === 98) markIsolationUnavailable("canary_visible");
    else if (outcome === 99) markIsolationUnavailable("pid_namespace_shared");
    else markIsolationUnavailable("start_failed");
  } catch (error) {
    markIsolationUnavailable(error instanceof SandboxPrepError ? error.problem : "start_failed");
  } finally {
    if (runDir) fs.rmSync(runDir, { recursive: true, force: true });
  }
}
