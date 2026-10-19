import fs from "node:fs";
import path from "node:path";
import type { ChildProcess } from "node:child_process";
import { log } from "./logging.js";
import { BRIDGE_MAX_BUFFER_BYTES, BRIDGE_MAX_PENDING, type BridgeResult, type JsonRpcObject, type McpBridge } from "./mcp-bridge.js";
import { SANDBOX_HOME } from "./sandbox-content.js";
import { buildBwrapArgv, detectProcMasks, detectRootLayout, launchBwrap, loadIsolationConfig, prepareRunsRoot, type IsolationConfig } from "./sandbox.js";
import type { ToolFailure } from "./tool-mediation.js";

/**
 * Trusted stdio MCP servers in their own sandbox (MVP-7679).
 *
 * A registered stdio server (and a request stdio server that carries `env`) never runs next to the agent: it runs
 * in a separate bubblewrap sandbox built with the isolation module's own argv builder and launcher, so the agent
 * sandbox cannot see its process, command line, environment or files (own user, PID, IPC, UTS and cgroup namespaces,
 * a private empty home, a private `/tmp`, read-only system directories, no gateway content). Its environment is the
 * base allowlist plus the server's own `env` after overrides: never the model proxy token or URL, never a run-log
 * path. The runtime only talks to the relay (`mcp-credential-relay.ts`), which hands each already-checked JSON-RPC
 * message to the bridge below: one JSON message per line on stdin and stdout.
 *
 * The sandbox starts with the first message (`initialize`), within the isolation startup timeout, and is killed with
 * everything in it when the relay binding is revoked (run end, cancel) and with the gateway (`--die-with-parent`).
 * Nothing in here may end the gateway process: every stream has an error listener, lines are capped, and a failure
 * answers with a `ToolFailure`.
 */

const BASE_ENV_KEYS = ["LANG"] as const;

/** The environment of a tool sandbox: a base allowlist built from nothing, then the server's own `env` without loader settings. */
export function buildToolSandboxEnv(gatewayEnv: NodeJS.ProcessEnv, serverEnv: Record<string, string>): Record<string, string> {
  const env: Record<string, string> = {
    HOME: SANDBOX_HOME,
    USER: "node",
    PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    LANG: "C.UTF-8",
    TERM: "xterm",
    TMPDIR: "/tmp",
  };
  for (const [key, value] of Object.entries(gatewayEnv)) {
    if ((BASE_ENV_KEYS.includes(key as (typeof BASE_ENV_KEYS)[number]) || /^LC_[A-Z_]+$/.test(key)) && typeof value === "string" && /^[A-Za-z0-9_.@-]{1,64}$/.test(value)) env[key] = value;
  }
  Object.assign(env, serverEnv);
  // A loader setting (`LD_PRELOAD`, `LD_AUDIT`, `LD_LIBRARY_PATH`, any other `LD_*`, `GLIBC_TUNABLES`) would load a library into the
  // launch wrapper and into the launcher process before the wrapper closes the inherited descriptors (MVP-8020): never delivered.
  let removed = 0;
  for (const key of Object.keys(env)) {
    if (key.startsWith("LD_") || key === "GLIBC_TUNABLES") {
      delete env[key];
      removed++;
    }
  }
  if (removed > 0) log("mcp", `mcp.stdio.loader_settings_removed count=${removed}`);
  return env;
}

export interface StdioBridgeOptions {
  serverName: string;
  command: string;
  args: string[];
  /** The server's env after overrides. */
  env: Record<string, string>;
  /** Tests: another isolation configuration. */
  config?: IsolationConfig;
  maxLineBytes?: number;
  /** Server stderr is drained and discarded; this bounds nothing in memory. */
  queryId?: string;
}

interface Pending {
  message: JsonRpcObject;
  resolve: (result: BridgeResult) => void;
  timer: NodeJS.Timeout;
  isInitialize: boolean;
}

/** A tool sandbox for one stdio server of one run. */
export class StdioBridge implements McpBridge {
  private readonly config: IsolationConfig;
  private readonly maxLineBytes: number;
  private child: ChildProcess | null = null;
  private runDir: string | null = null;
  private starting: Promise<ToolFailure | null> | null = null;
  private closed = false;
  /** The sandbox ended and will not be started again: a new process would not hold the runtime's initialized session. */
  private dead = false;
  private initialized = false;
  private restarted = false;
  private readonly pending = new Map<string, Pending>();

  constructor(private readonly options: StdioBridgeOptions) {
    this.config = options.config ?? loadIsolationConfig();
    this.maxLineBytes = options.maxLineBytes ?? BRIDGE_MAX_BUFFER_BYTES;
  }

  async request(message: JsonRpcObject, deadlineMs: number): Promise<BridgeResult> {
    const { serverName } = this.options;
    if (this.closed || this.dead) return { kind: "failure", failure: { kind: "unreachable", name: serverName } };
    const failure = await this.ensureStarted();
    if (failure) return { kind: "failure", failure };
    const child = this.child;
    if (!child || this.closed) return { kind: "failure", failure: { kind: "unreachable", name: serverName } };

    const hasId = message.id !== undefined && message.id !== null;
    if (!hasId) {
      return this.write(message) ? { kind: "accepted" } : { kind: "failure", failure: { kind: "unreachable", name: serverName } };
    }
    const key = JSON.stringify(message.id);
    // A request id that is still waiting, or too many waiting requests, is refused: the map stays consistent.
    if (this.pending.has(key)) return { kind: "failure", failure: { kind: "denied" } };
    if (this.pending.size >= BRIDGE_MAX_PENDING) return { kind: "failure", failure: { kind: "unreachable", name: serverName } };
    return new Promise<BridgeResult>((resolve) => {
      const entry: Pending = {
        message,
        resolve,
        isInitialize: message.method === "initialize",
        timer: setTimeout(() => {
          if (this.pending.get(key) === entry) this.pending.delete(key);
          resolve({ kind: "failure", failure: { kind: "timeout", name: serverName, timeoutMs: deadlineMs } });
        }, deadlineMs),
      };
      this.pending.set(key, entry);
      if (!this.write(message)) this.settle(key, { kind: "failure", failure: { kind: "unreachable", name: serverName } });
    });
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.failAll({ kind: "unreachable", name: this.options.serverName });
    this.killSandbox();
  }

  private settle(key: string, result: BridgeResult): void {
    const entry = this.pending.get(key);
    if (!entry) return;
    clearTimeout(entry.timer);
    this.pending.delete(key);
    entry.resolve(result);
  }

  private failAll(failure: ToolFailure): void {
    for (const key of [...this.pending.keys()]) this.settle(key, { kind: "failure", failure });
  }

  /** Kills the sandbox (the bwrap process is process 1 of its PID namespace, so everything in it dies) and removes its directory once it exited. */
  private killSandbox(): void {
    this.dead = true;
    const child = this.child;
    const runDir = this.runDir;
    this.child = null;
    this.runDir = null;
    this.starting = null;
    const remove = (): void => {
      if (!runDir) return;
      try {
        fs.rmSync(runDir, { recursive: true, force: true });
      } catch {
        log("isolation", "tool sandbox directory cleanup failed");
      }
    };
    if (!child || child.exitCode !== null || child.signalCode !== null) {
      remove();
      return;
    }
    child.once("exit", remove);
    try {
      child.kill("SIGKILL");
    } catch {
      remove();
    }
  }

  private write(message: JsonRpcObject): boolean {
    const stdin = this.child?.stdin;
    if (!stdin || stdin.destroyed || !stdin.writable) return false;
    try {
      stdin.write(`${JSON.stringify(message)}\n`);
      return true;
    } catch {
      return false;
    }
  }

  private ensureStarted(): Promise<ToolFailure | null> {
    if (this.child) return Promise.resolve(null);
    if (!this.starting) this.starting = this.start();
    return this.starting;
  }

  /** Starts the sandbox with its own private home; resolves with a failure or null once the sandbox passed its start check. */
  private async start(): Promise<ToolFailure | null> {
    const { serverName, command, args, env } = this.options;
    const unavailable: ToolFailure = { kind: "unreachable", name: serverName };
    try {
      fs.accessSync(this.config.bwrapPath, fs.constants.X_OK);
      const runs = prepareRunsRoot(this.config.sandboxRoot);
      const runDir = fs.mkdtempSync(path.join(runs, "run-"));
      this.runDir = runDir;
      fs.chmodSync(runDir, 0o700);
      const homeDir = path.join(runDir, "home");
      fs.mkdirSync(homeDir, { mode: 0o700 });
      const argv = buildBwrapArgv({
        layout: detectRootLayout(),
        procMasks: detectProcMasks(),
        homeDir,
        mounts: [],
        hidden: [],
        emptyFile: "/dev/null",
        roBinds: [],
        rwBinds: [],
        command,
        args,
      });
      const launch = launchBwrap(this.config, argv, buildToolSandboxEnv(process.env, env), { queryId: this.options.queryId });
      this.child = launch.child;
      this.watch(launch.child);
      await launch.ready;
      return null;
    } catch {
      log("audit", `mcp.stdio.start_failed serverName=${serverName}`);
      this.killSandbox();
      this.starting = null;
      return unavailable;
    }
  }

  private watch(child: ChildProcess): void {
    let buffer = "";
    child.stdin?.on("error", () => undefined);
    child.stderr?.on("error", () => undefined);
    // The server's own stderr is discarded: it may hold anything the server was given.
    child.stderr?.on("data", () => undefined);
    child.stdout?.on("error", () => undefined);
    child.stdout?.setEncoding("utf8");
    child.stdout?.on("data", (chunk: string) => {
      try {
        buffer += chunk;
        for (;;) {
          const newline = buffer.indexOf("\n");
          if (newline === -1) break;
          const line = buffer.slice(0, newline).trim();
          buffer = buffer.slice(newline + 1);
          if (line.length > 0) this.onLine(line);
        }
        if (buffer.length > this.maxLineBytes) {
          // A line that never ends: the server is dropped, nothing waits for it.
          log("audit", `mcp.bridge.refused serverName=${this.options.serverName} reason=line_too_large`);
          buffer = "";
          this.failAll({ kind: "invalid_response", name: this.options.serverName });
          this.killSandbox();
        }
      } catch {
        this.failAll({ kind: "invalid_response", name: this.options.serverName });
        this.killSandbox();
      }
    });
    child.once("exit", () => this.onExit(child));
    child.once("error", () => this.onExit(child));
  }

  private onExit(child: ChildProcess): void {
    if (this.child !== child) return;
    if (this.closed) return;
    // A server that dies before it answered `initialize` gets one restart per run; anything else is unreachable.
    const waitingInit = [...this.pending.values()].filter((entry) => entry.isInitialize);
    this.child = null;
    this.starting = null;
    const runDir = this.runDir;
    this.runDir = null;
    if (runDir) {
      try {
        fs.rmSync(runDir, { recursive: true, force: true });
      } catch {
        // Best effort.
      }
    }
    if (!this.initialized && !this.restarted && waitingInit.length > 0) {
      this.restarted = true;
      const entry = waitingInit[0];
      const key = JSON.stringify(entry.message.id);
      void this.ensureStarted().then((failure) => {
        if (failure || this.closed || !this.child) {
          this.failAll({ kind: "unreachable", name: this.options.serverName });
          return;
        }
        if (!this.pending.has(key) || !this.write(entry.message)) this.failAll({ kind: "unreachable", name: this.options.serverName });
      });
      return;
    }
    this.dead = true;
    this.failAll({ kind: "unreachable", name: this.options.serverName });
  }

  private onLine(line: string): void {
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      // Not a message (a banner or log line on stdout): ignored.
      return;
    }
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return;
    const message = parsed as JsonRpcObject;
    if (typeof message.method === "string") {
      if (message.id !== undefined && message.id !== null) this.answerServerRequest(message);
      return;
    }
    if (message.id !== undefined && message.id !== null && ("result" in message || "error" in message)) {
      const key = JSON.stringify(message.id);
      const entry = this.pending.get(key);
      if (entry?.isInitialize && "result" in message) this.initialized = true;
      this.settle(key, { kind: "answer", message });
    }
  }

  /** A request from the server: answered locally, never forwarded to the runtime. */
  private answerServerRequest(request: JsonRpcObject): void {
    if (request.method === "ping") this.write({ jsonrpc: "2.0", id: request.id, result: {} });
    else if (request.method === "roots/list") this.write({ jsonrpc: "2.0", id: request.id, result: { roots: [] } });
    else this.write({ jsonrpc: "2.0", id: request.id, error: { code: -32601, message: "Method not found" } });
  }
}
