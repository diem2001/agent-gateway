import { spawn, type ChildProcess } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import type { SpawnOptions, SpawnedProcess } from "@anthropic-ai/claude-agent-sdk";
import { log, logAlways, logDebug } from "./logging.js";
import { getEnabledMcpServers } from "./mcp-registry.js";
import { gatewayModelProxy, type ModelProxy } from "./model-proxy.js";
import { fixedFailure, isolationTimeoutMessage, isolationUnavailableMessage, RunFailure } from "./run-failure.js";
import {
  SANDBOX_HOME,
  checkTrusted,
  contentScanner,
  knownSecretValues,
  lstatOrNull,
  planTrustedContent,
  prepareMountPoints,
  sanitizeRuntimeConfig,
  randomDirName,
  type MountPlan,
  type SandboxMount,
} from "./sandbox-content.js";
import { getWorkspaceRoot } from "./workspace.js";

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
/** The line the launch wrapper writes to stderr once the sandbox has passed its start check. */
export const SANDBOX_CHECK_LINE = "SANDBOX-CHECK-OK";
/**
 * Launch wrapper, first process inside the sandbox: refuse to start unless a nested user
 * namespace fails, close the launcher's argument descriptor (the runtime inherits nothing but
 * stdin, stdout and stderr), report the passed check on stderr (which belongs to the launcher
 * until that line arrives) and exec the runtime.
 */
export const LAUNCH_WRAPPER = `if unshare -U true >/dev/null 2>&1; then exit ${EXIT_USERNS_NOT_BLOCKED}; fi; exec 3>&-; echo ${SANDBOX_CHECK_LINE} >&2; exec "$@"`;

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
  for (const mount of spec.mounts) argv.push("--ro-bind", mount.src, mount.dest);
  for (const dest of spec.hidden) argv.push("--ro-bind", spec.emptyFile, dest);
  for (const p of spec.roBinds) argv.push("--ro-bind", p, p);
  for (const p of spec.rwBinds) argv.push("--bind", p, p);
  argv.push("--chdir", SANDBOX_HOME, "--", "/bin/sh", "-c", LAUNCH_WRAPPER, "sandbox", spec.command, ...spec.args);
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

/** The complete sandbox environment: an allowlist, built from nothing. */
export function buildSandboxEnv(input: SandboxEnvInput): Record<string, string> {
  const env: Record<string, string> = {
    HOME: SANDBOX_HOME,
    USER: "node",
    PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    LANG: "C.UTF-8",
    TERM: "xterm",
    TMPDIR: "/tmp",
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

/**
 * The persistent home of a conversation: `<root>/sessions/<name>/home`, created on first use. The name
 * is the random id recorded with the conversation; the directories above the home are private to the
 * gateway, the home itself is the agent's (it must stay a real directory owned by the gateway user).
 * Deleting a conversation leaves its home in place: cleanup and retention belong to MVP-7402.
 */
function sessionHome(root: string, dirId: string): string {
  if (!/^[0-9a-f]{24}$/.test(dirId)) throw new SandboxPrepError("content_invalid");
  const sessions = path.join(root, "sessions");
  ensurePrivateDir(sessions);
  const dir = path.join(sessions, dirId);
  ensurePrivateDir(dir);
  const home = path.join(dir, "home");
  let stat = lstatOrNull(home);
  if (!stat) {
    fs.mkdirSync(home, { mode: 0o700 });
    stat = lstatOrNull(home);
  }
  const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
  if (!stat || stat.isSymbolicLink() || !stat.isDirectory() || (uid !== undefined && stat.uid !== uid)) throw new SandboxPrepError("invalid_root");
  fs.chmodSync(home, 0o700);
  return home;
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

function classifyEarlyExit(code: number | null, stderr: string): IsolationProblem {
  if (code === EXIT_USERNS_NOT_BLOCKED) return "userns_not_blocked";
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
/*  One active request per conversation                                 */
/* ------------------------------------------------------------------ */

const lockedConversations = new Set<string>();

export interface ConversationLock {
  release: () => void;
}

/**
 * The trusted-side lock of one conversation home: a second request for a conversation that is still
 * answering gets null (and is refused with 0 runtime starts). Held for the whole request, retries
 * included; `SandboxRun.dispose` has waited for the sandbox process to exit before it is released, so
 * two sandboxes never share one home at the same time.
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

function runtimeSdkDir(cliPath: string): string {
  const sdkEntry = createRequire(import.meta.url).resolve("@anthropic-ai/claude-agent-sdk");
  const sdkDir = path.dirname(fs.realpathSync(sdkEntry));
  let cliDir: string;
  try {
    cliDir = path.dirname(fs.realpathSync(cliPath));
  } catch {
    throw new SandboxPrepError("content_invalid");
  }
  if (cliDir !== sdkDir) throw new SandboxPrepError("content_invalid");
  return path.dirname(cliPath);
}

function registryExtraSecrets(): string[] {
  const values: string[] = [];
  for (const def of getEnabledMcpServers()) {
    for (const value of Object.values(def.headers ?? {})) values.push(value);
    for (const value of Object.values(def.env ?? {})) values.push(value);
  }
  return values;
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
  readonly spawnHook: (spawnOptions: SpawnOptions) => SpawnedProcess;

  constructor(options: SandboxRunOptions) {
    this.options = options;
    this.spawnHook = (spawnOptions) => this.start(spawnOptions);
  }

  /** The runtime's process group leader (the bwrap process), once started. */
  get child(): ChildProcess | null {
    return this.launch?.child ?? null;
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
      return launch.child as unknown as SpawnedProcess;
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
    const homeDir = this.options.sessionDirId ? sessionHome(config.sandboxRoot, this.options.sessionDirId) : path.join(runDir, "home");
    if (!this.options.sessionDirId) fs.mkdirSync(homeDir, { mode: 0o700 });

    const workspaceRoot = this.options.workspaceRoot ?? getWorkspaceRoot();
    const needles = knownSecretValues(process.env, path.join(workspaceRoot, ".credentials.json"), registryExtraSecrets());
    const plan: MountPlan = planTrustedContent({ workspaceRoot, trustedDir, needles, scanner: contentScanner });
    if (plan.skipped > 0 || plan.hiddenCount > 0) log("audit", `sandbox.content skipped=${plan.skipped} hidden=${plan.hiddenCount}`);

    // The runtime and the trusted directories it needs, each validated without following links.
    const cliPath = spawnOptions.args.find((arg) => arg.endsWith("cli.js"));
    if (!cliPath) throw new SandboxPrepError("content_invalid");
    const sdkDir = runtimeSdkDir(cliPath);
    const roBinds = [sdkDir];
    const command = spawnOptions.command === "node" ? process.execPath : spawnOptions.command;
    if (!path.isAbsolute(command)) throw new SandboxPrepError("content_invalid");
    if (!command.startsWith("/usr/")) roBinds.push(command);
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
      sanitizeRuntimeConfig(homeDir);
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
    if (this.proxyToken) {
      this.proxy().revoke(this.proxyToken);
      this.proxyToken = null;
    }
    const child = this.child;
    if (child && child.exitCode === null && child.signalCode === null) {
      await new Promise<void>((resolve) => {
        const timer = setTimeout(() => {
          log("query", "sandbox did not exit in time; killing it");
          child.kill("SIGKILL");
        }, waitMs);
        child.once("exit", () => {
          clearTimeout(timer);
          resolve();
        });
      });
    }
    if (this.runDir) {
      try {
        fs.rmSync(this.runDir, { recursive: true, force: true });
      } catch (e: unknown) {
        log("query", `sandbox run directory cleanup failed: ${e instanceof Error ? e.name : "error"}`);
      }
      this.runDir = null;
    }
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
    fs.mkdirSync(homeDir, { mode: 0o700 });
    const canary = path.join(runDir, `canary-${randomDirName()}`);
    fs.writeFileSync(canary, "canary", { mode: 0o600 });
    const argv = buildBwrapArgv({
      layout: detectRootLayout(),
      procMasks: detectProcMasks(),
      homeDir,
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
    if (outcome === 98) markIsolationUnavailable("canary_visible");
    else if (outcome === 99) markIsolationUnavailable("pid_namespace_shared");
    else markIsolationUnavailable(outcome === EXIT_USERNS_NOT_BLOCKED ? "userns_not_blocked" : "start_failed");
  } catch (error) {
    markIsolationUnavailable(error instanceof SandboxPrepError ? error.problem : "start_failed");
  } finally {
    if (runDir) fs.rmSync(runDir, { recursive: true, force: true });
  }
}
