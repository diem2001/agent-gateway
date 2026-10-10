/**
 * Spawned-gateway harness for the git process tests: the compiled gateway
 * (`dist/server.js`, built by `npm run build`) runs as a child process with an
 * environment ALLOWLIST (never the parent's API or Jira secrets) and fresh temp
 * directories for HOME, TMPDIR, cwd, every persist path and WORKSPACE_ROOT.
 * An optional fake-git bin directory goes first on the child's PATH.
 *
 * Every started gateway is registered with the caller's cleanup list; cleanup
 * SIGKILLs the gateway and every process below it, then removes its root.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { randomInt } from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = path.resolve(here, "..", "..", "..");
const DIST_SERVER = path.join(REPO_ROOT, "dist", "server.js");

export const GATEWAY_API_KEY = "git-proc-gateway-key-7614";

/** Environment ALLOWLIST for the spawned gateway. Never turn this into a denylist. */
const ALLOWED_ENV_KEYS = ["PATH", "LANG"] as const;

/** Fails loudly when dist/ is missing or older than src/ (run `npm run build`). */
export function assertFreshBuild(): void {
  const srcRoot = path.join(REPO_ROOT, "src");
  for (const entry of fs.readdirSync(srcRoot, { withFileTypes: true, recursive: true })) {
    if (!entry.isFile() || !entry.name.endsWith(".ts") || entry.name.endsWith(".test.ts")) continue;
    const source = path.join(entry.parentPath, entry.name);
    const relative = path.relative(srcRoot, source);
    if (relative.startsWith("tests") || relative.startsWith("__tests__")) continue;
    const compiled = path.join(REPO_ROOT, "dist", relative.replace(/\.ts$/, ".js"));
    if (!fs.existsSync(compiled) || fs.statSync(compiled).mtimeMs < fs.statSync(source).mtimeMs) {
      throw new Error(`dist is missing or older than src for ${relative}; run \`npm run build\` first`);
    }
  }
}

export interface SpawnedGateway {
  child: ChildProcess;
  port: number;
  root: string;
  dirs: { home: string; tmp: string; cwd: string; persist: string; workspace: string; projects: string };
  /** Everything the gateway wrote to stdout and stderr so far. */
  output: () => string;
  /** True when the gateway was spawned as the leader of its own process group (`detached`), the only case `killGatewayGroup` accepts. */
  detached: boolean;
}

/**
 * SIGKILL for the whole process group of a gateway that was spawned `detached` (a hard stop of the gateway together
 * with its children, the way a container kill does it). Guarded: it refuses a gateway that is not a group leader by
 * construction, one that already exited, and one whose process group is not its own pid; it never signals by name or
 * pattern.
 */
export function killGatewayGroup(gateway: Pick<SpawnedGateway, "child" | "detached">): void {
  const { child } = gateway;
  if (!gateway.detached) throw new Error("refusing a group kill: this gateway was not spawned detached");
  if (child.pid === undefined || child.exitCode !== null || child.signalCode !== null) throw new Error("refusing a group kill: the gateway process is not running");
  const stat = fs.readFileSync(`/proc/${child.pid}/stat`, "utf8");
  const pgrp = Number(stat.slice(stat.lastIndexOf(")") + 2).split(" ")[2]);
  if (pgrp !== child.pid) throw new Error(`refusing a group kill: process group ${pgrp} is not the gateway pid ${child.pid}`);
  process.kill(-child.pid, "SIGKILL");
}

export type Cleanup = () => Promise<void> | void;

/* ------------------------------------------------------------------ */
/*  Reserved ports (MVP-8129)                                           */
/* ------------------------------------------------------------------ */

/**
 * A `listen(0)` + `close()` pick is not a reservation: any other `listen(0)` on the host (fakes, a gateway's model proxy
 * and credential relay, other test files) can take the number before the gateway binds it. Gateway ports and "nothing
 * listens here" ports therefore come from the 8192 ports below the kernel's ephemeral range, which the kernel hands out
 * to neither `listen(0)` nor outgoing connections. The range is cut into slots of 256 ports, one per vitest pool id (the
 * process id when absent); inside a slot a port is claimed by an exclusive lock file holding the claiming pid (so
 * concurrent vitest runs on one host never share a port) and then checked with a bind.
 */
const GATEWAY_PORT_SLOT_SIZE = 256;
const GATEWAY_PORT_RANGE_SIZE = 8192;
const GATEWAY_PORT_MIN_RANGE = 1024;
const GATEWAY_PORT_LOCK_DIR = path.join(os.tmpdir(), "agent-gateway-test-ports");

/** Default bound of the readiness wait, in ms. A test or hook budget must cover this plus 15 s for each gateway start. */
export const GATEWAY_READY_TIMEOUT_MS = 45_000;

const heldPortLocks = new Map<string, string>();
let releaseOnExitRegistered = false;

function reservedRange(): [number, number] {
  let low = 32_768;
  try {
    low = Number(fs.readFileSync("/proc/sys/net/ipv4/ip_local_port_range", "utf8").trim().split(/\s+/)[0]);
  } catch {
    // Not Linux, or /proc unreadable: the Linux default applies.
  }
  return [Math.max(1024, low - GATEWAY_PORT_RANGE_SIZE), low];
}

function pidAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

/** Claims `<lockDir>/<port>.lock` for this process; a lock of a dead pid is stale and replaced. */
function claimPortLock(lockDir: string, port: number): string | null {
  fs.mkdirSync(lockDir, { recursive: true });
  const file = path.join(lockDir, `${port}.lock`);
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      fs.writeFileSync(file, String(process.pid), { flag: "wx" });
      return file;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }
    let holder = NaN;
    try {
      holder = Number(fs.readFileSync(file, "utf8").trim());
    } catch {
      continue;
    }
    if (pidAlive(holder)) return null;
    try {
      fs.unlinkSync(file);
    } catch {
      // Another process replaced it first; the next attempt sees its lock.
    }
  }
  return null;
}

function bindable(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const probe = net.createServer();
    probe.once("error", () => resolve(false));
    probe.listen(port, "127.0.0.1", () => probe.close(() => resolve(true)));
  });
}

function removePortLock(key: string): void {
  const file = heldPortLocks.get(key);
  heldPortLocks.delete(key);
  if (!file) return;
  try {
    fs.unlinkSync(file);
  } catch {
    // Already gone.
  }
}

/**
 * A loopback port that no `listen(0)` can receive and no other test process has claimed. It is held (lock file) until
 * `releaseGatewayPort` or the end of this process. Used for gateway ports and for "nothing listens here" ports.
 * `range` (a half-open port interval), `slot` and `lockDir` are injectable for the allocator's own rows.
 */
export async function reserveGatewayPort(options: { range?: [number, number]; slot?: number; lockDir?: string } = {}): Promise<number> {
  const [from, to] = options.range ?? reservedRange();
  if (to - from < GATEWAY_PORT_MIN_RANGE) {
    throw new Error(`the reserved port range [${from}, ${to}) has fewer than ${GATEWAY_PORT_MIN_RANGE} usable ports; refusing to fall back to listen(0)`);
  }
  const slots = Math.floor((to - from) / GATEWAY_PORT_SLOT_SIZE);
  const slot = (options.slot ?? (Number(process.env.VITEST_POOL_ID) || process.pid)) % slots;
  const lockDir = options.lockDir ?? GATEWAY_PORT_LOCK_DIR;
  const base = from + slot * GATEWAY_PORT_SLOT_SIZE;
  const offset = randomInt(GATEWAY_PORT_SLOT_SIZE);
  for (let i = 0; i < GATEWAY_PORT_SLOT_SIZE; i++) {
    const port = base + ((offset + i) % GATEWAY_PORT_SLOT_SIZE);
    const lock = claimPortLock(lockDir, port);
    if (!lock) continue;
    const key = `${lockDir}\u0000${port}`;
    heldPortLocks.set(key, lock);
    if (!releaseOnExitRegistered) {
      releaseOnExitRegistered = true;
      process.on("exit", () => {
        for (const held of [...heldPortLocks.keys()]) removePortLock(held);
      });
    }
    if (await bindable(port)) return port;
    removePortLock(key);
  }
  throw new Error(`no free gateway port in slot ${slot} (${base}-${base + GATEWAY_PORT_SLOT_SIZE - 1}) of the reserved range`);
}

/** Gives a reserved port back (its lock file is removed); a port never reserved by this process is ignored. */
export function releaseGatewayPort(port: number, options: { lockDir?: string } = {}): void {
  removePortLock(`${options.lockDir ?? GATEWAY_PORT_LOCK_DIR}\u0000${port}`);
}

/* ------------------------------------------------------------------ */
/*  Readiness (MVP-8129)                                                */
/* ------------------------------------------------------------------ */

/** The inode of every LISTEN socket on `port` (any address), from /proc/net/tcp{,6}. */
function listenInodesOnPort(port: number): Set<string> {
  const inodes = new Set<string>();
  for (const file of ["/proc/net/tcp", "/proc/net/tcp6"]) {
    let text = "";
    try {
      text = fs.readFileSync(file, "utf8");
    } catch {
      continue;
    }
    for (const line of text.split("\n").slice(1)) {
      const cols = line.trim().split(/\s+/);
      // cols[1] is "<hex address>:<hex port>", cols[3] the state (0A = LISTEN), cols[9] the socket inode.
      if (cols.length > 9 && cols[3] === "0A" && parseInt(cols[1].split(":")[1] ?? "", 16) === port) inodes.add(cols[9]);
    }
  }
  return inodes;
}

/** Whether `pid` itself (not a process below it) holds a LISTEN socket on `port`. */
function pidOwnsListener(pid: number, port: number): boolean {
  const inodes = listenInodesOnPort(port);
  if (inodes.size === 0) return false;
  let fds: string[] = [];
  try {
    fds = fs.readdirSync(`/proc/${pid}/fd`);
  } catch {
    return false;
  }
  for (const fd of fds) {
    try {
      const match = /^socket:\[(\d+)\]$/.exec(fs.readlinkSync(`/proc/${pid}/fd/${fd}`));
      if (match && inodes.has(match[1])) return true;
    } catch {
      // Descriptor closed while reading.
    }
  }
  return false;
}

/** GET /health with a probe timeout: the status, or the error code / "timeout". */
function probeHealth(port: number, timeoutMs: number): Promise<{ status: number; detail: string }> {
  return new Promise((resolve) => {
    const probe = http.get({ host: "127.0.0.1", port, path: "/health", agent: false, timeout: timeoutMs }, (res) => {
      res.resume();
      res.on("end", () => resolve({ status: res.statusCode ?? 0, detail: String(res.statusCode ?? 0) }));
    });
    probe.on("timeout", () => {
      probe.destroy();
      resolve({ status: 0, detail: "timeout" });
    });
    probe.on("error", (error: NodeJS.ErrnoException) => resolve({ status: 0, detail: error.code ?? "error" }));
  });
}

/** Secret values to hide in a start-up failure message: the final child environment plus the caller's own list. */
function startupSecrets(env: NodeJS.ProcessEnv | undefined, extra: readonly string[] | undefined): string[] {
  const values = new Set<string>(extra ?? []);
  for (const [key, value] of Object.entries(env ?? {})) {
    if (!value) continue;
    if (key === "API_KEYS") {
      for (const entry of value.split(",")) {
        values.add(entry.trim());
        values.add(entry.slice(entry.indexOf(":") + 1).trim());
      }
    } else if (/(_API_KEY|_TOKEN|SECRET|PASSWORD)$/.test(key)) {
      values.add(value);
    }
  }
  return [...values].filter((value) => value.length >= 4).sort((a, b) => b.length - a.length);
}

function lastLines(text: string, secrets: readonly string[]): string {
  let tail = text.replace(/\n+$/, "").split("\n").slice(-20).join("\n");
  for (const secret of secrets) tail = tail.split(secret).join("[redacted]");
  return tail;
}

function appendStartupLog(line: string): void {
  const file = process.env.GATEWAY_STARTUP_LOG;
  if (file) fs.appendFileSync(file, `${line}\n`);
}

/**
 * Waits until the spawned gateway serves its port: `/health` answers 200 (2 s per probe) AND `child` itself holds the
 * LISTEN socket on `port`, so a foreign listener on the port never counts. An exit rejects at once with the exit code,
 * the signal and the last 20 log lines (secrets redacted); a live process that is still not ready at `readyTimeoutMs`
 * (default `GATEWAY_READY_TIMEOUT_MS`) rejects with a distinct message. Returns the time to readiness in ms.
 */
export async function waitForGatewayReady(options: {
  child: ChildProcess;
  port: number;
  output: () => string;
  readyTimeoutMs?: number;
  /** The final environment of the child: its API keys and `*_API_KEY`/`*_TOKEN`/`*SECRET`/`*PASSWORD` values are redacted. */
  env?: NodeJS.ProcessEnv;
  /** More values to redact. */
  secrets?: string[];
}): Promise<number> {
  const { child, port } = options;
  const bound = options.readyTimeoutMs ?? GATEWAY_READY_TIMEOUT_MS;
  const secrets = startupSecrets(options.env, options.secrets);
  const started = Date.now();
  const hasExited = (): boolean => child.exitCode !== null || child.signalCode !== null;
  const exited = new Promise<"exit">((resolve) => {
    if (hasExited()) resolve("exit");
    else child.once("exit", () => resolve("exit"));
  });
  const closed = new Promise<void>((resolve) => {
    if (child.stdout?.destroyed && child.stderr?.destroyed) resolve();
    else child.once("close", () => resolve());
  });
  const fail = async (kind: "exited" | "not-ready", message: () => string): Promise<never> => {
    if (kind === "exited") await Promise.race([closed, new Promise((resolve) => setTimeout(resolve, 1000))]);
    const text = message();
    appendStartupLog(`failed pid=${child.pid} port=${port} ms=${Date.now() - started} ${kind}`);
    throw new Error(text);
  };

  let lastProbe = "none";
  let owns = false;
  let foreign = false;
  let milestone = false;
  for (;;) {
    const probe = await Promise.race([probeHealth(port, 2000), exited]);
    if (probe === "exit" || hasExited()) {
      return fail("exited", () => `gateway exited during startup: code=${child.exitCode ?? "null"} signal=${child.signalCode ?? "null"}; last 20 log lines:\n${lastLines(options.output(), secrets)}`);
    }
    lastProbe = probe.detail;
    if (probe.status === 200) {
      if (child.pid !== undefined && pidOwnsListener(child.pid, port)) {
        const ms = Date.now() - started;
        appendStartupLog(`ready pid=${child.pid} port=${port} ms=${ms}`);
        return ms;
      }
      foreign = true;
      owns = false;
    }
    const elapsed = Date.now() - started;
    if (!milestone && elapsed >= 15_000) {
      milestone = true;
      const line = `[gateway-startup] pid=${child.pid} port=${port} not ready after 15 s, still waiting (owns port: ${owns ? "yes" : "no"}, last probe: ${lastProbe})`;
      process.stderr.write(`${line}\n`);
      appendStartupLog(`milestone pid=${child.pid} port=${port} ms=${elapsed}`);
    }
    if (elapsed >= bound) {
      return fail(
        "not-ready",
        () =>
          `gateway still running but not ready after ${bound} ms (owns port: ${owns ? "yes" : "no"}, last probe: ${lastProbe}, foreign responder: ${foreign ? "yes" : "no"}); last 20 log lines:\n${lastLines(options.output(), secrets)}`,
      );
    }
    await Promise.race([new Promise((resolve) => setTimeout(resolve, 50)), exited]);
  }
}

function childPids(pid: number): number[] {
  const result: number[] = [];
  let tasks: string[] = [];
  try {
    tasks = fs.readdirSync(`/proc/${pid}/task`);
  } catch {
    return result;
  }
  for (const tid of tasks) {
    try {
      const text = fs.readFileSync(`/proc/${pid}/task/${tid}/children`, "utf8").trim();
      if (text) result.push(...text.split(/\s+/).map(Number));
    } catch {
      // Thread ended while reading.
    }
  }
  return result;
}

/** Every process below `pid` (not `pid` itself). Linux /proc only. */
export function descendants(pid: number): number[] {
  const found: number[] = [];
  const queue = [pid];
  while (queue.length > 0) {
    for (const child of childPids(queue.shift()!)) {
      found.push(child);
      queue.push(child);
    }
  }
  return found;
}

export async function spawnGateway(
  cleanups: Cleanup[],
  options: {
    fakeGitBin?: string;
    env?: Record<string, string>;
    rootPrefix?: string;
    distServer?: string;
    /** Called with the directories before the gateway starts (state files, planted content). */
    seed?: (dirs: SpawnedGateway["dirs"]) => void;
    /** A restart: the directories of an earlier gateway (its cleanup removes them), with a new process and port. */
    reuse?: SpawnedGateway;
    /**
     * Descriptors of this process the gateway inherits WITHOUT close-on-exec, as its descriptors 20, 21, ... (MVP-7991).
     * They start at 20 because libuv's `uv_disable_stdio_inheritance` marks the first 16 descriptors and every contiguous
     * one after them close-on-exec when a Node process starts, so only a descriptor behind a gap survives in the gateway.
     * Absent: stdio unchanged.
     */
    inheritedFds?: number[];
    /** Bound of the readiness wait in ms (default `GATEWAY_READY_TIMEOUT_MS`). */
    readyTimeoutMs?: number;
    /** Spawn the gateway as the leader of its own process group, so `killGatewayGroup` can stop it with all its children. */
    detached?: boolean;
  } = {},
): Promise<SpawnedGateway> {
  assertFreshBuild();
  const port = await reserveGatewayPort();
  const root = options.reuse?.root ?? fs.mkdtempSync(path.join(os.tmpdir(), options.rootPrefix ?? "mvp7614-gw-"));
  const base = { home: path.join(root, "home"), tmp: path.join(root, "tmp"), cwd: path.join(root, "cwd"), persist: path.join(root, "persist") };
  const workspace = path.join(base.home, ".claude");
  const dirs = options.reuse?.dirs ?? { ...base, workspace, projects: path.join(workspace, "projects") };
  if (!options.reuse) {
    for (const dir of Object.values(base)) fs.mkdirSync(dir);
    fs.mkdirSync(dirs.projects, { recursive: true });
    options.seed?.(dirs);
  }

  const childEnv: NodeJS.ProcessEnv = {};
  for (const key of ALLOWED_ENV_KEYS) {
    if (process.env[key] !== undefined) childEnv[key] = process.env[key];
  }
  if (options.fakeGitBin) childEnv.PATH = `${options.fakeGitBin}${path.delimiter}${childEnv.PATH ?? ""}`;
  Object.assign(childEnv, {
    HOME: dirs.home,
    TMPDIR: dirs.tmp,
    PORT: String(port),
    HOST: "127.0.0.1",
    API_KEYS: `proc:${GATEWAY_API_KEY}`,
    SESSION_PERSIST_PATH: path.join(dirs.persist, "sessions.json"),
    TOOLS_PERSIST_PATH: path.join(dirs.persist, "tools.json"),
    MCP_SERVERS_PERSIST_PATH: path.join(dirs.persist, "mcp-servers.json"),
    WORKSPACE_ROOT: workspace,
    ...options.env,
  });

  const child = spawn(process.execPath, ["--expose-gc", options.distServer ?? DIST_SERVER], {
    cwd: dirs.cwd,
    env: childEnv,
    detached: options.detached === true,
    stdio: options.inheritedFds ? ["ignore", "pipe", "pipe", ...Array<"ignore">(17).fill("ignore"), ...options.inheritedFds] : ["ignore", "pipe", "pipe"],
  });
  let output = "";
  child.stdout!.on("data", (data: Buffer) => (output += data.toString("utf8")));
  child.stderr!.on("data", (data: Buffer) => (output += data.toString("utf8")));
  cleanups.push(async () => {
    for (const pid of descendants(child.pid!)) {
      try {
        process.kill(pid, "SIGKILL");
      } catch {
        // Already gone.
      }
    }
    if (options.detached && child.exitCode === null && child.signalCode === null) {
      // The guarded group kill: only the recorded group of a gateway that really leads its own group.
      try {
        killGatewayGroup({ child, detached: true });
      } catch {
        // The per-process kill below still applies.
      }
    }
    if (child.exitCode === null && child.signalCode === null) {
      const exited = new Promise<void>((resolve) => child.once("exit", () => resolve()));
      child.kill("SIGKILL");
      await exited;
    }
    releaseGatewayPort(port);
    if (!options.reuse) fs.rmSync(root, { recursive: true, force: true });
  });

  await waitForGatewayReady({ child, port, output: () => output, readyTimeoutMs: options.readyTimeoutMs, env: childEnv });
  return { child, port, root, dirs, output: () => output, detached: options.detached === true };
}

/** GET /health; status 0 when the connection failed. */
export function getHealth(port: number): Promise<{ status: number; ms: number }> {
  const started = performance.now();
  return new Promise((resolve) => {
    const probe = http.get({ host: "127.0.0.1", port, path: "/health", agent: false }, (res) => {
      res.resume();
      res.on("end", () => resolve({ status: res.statusCode ?? 0, ms: performance.now() - started }));
    });
    probe.on("error", () => resolve({ status: 0, ms: performance.now() - started }));
  });
}

/** An authenticated JSON request to the spawned gateway. */
export function gatewayRequest(
  port: number,
  method: string,
  urlPath: string,
  body?: unknown,
  /** The API key to authenticate with (default: the harness's own key). */
  apiKey: string = GATEWAY_API_KEY,
  /** The gateway's address (default 127.0.0.1; the Docker integration probe uses a container address). */
  host = "127.0.0.1",
): Promise<{ status: number; text: string; json: Record<string, unknown> | null }> {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body), "utf8");
    const req = http.request(
      {
        host,
        port,
        method,
        path: urlPath,
        agent: false,
        headers: {
          Authorization: `Bearer ${apiKey}`,
          ...(payload ? { "Content-Type": "application/json", "Content-Length": payload.length } : {}),
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          let json: Record<string, unknown> | null = null;
          try {
            json = JSON.parse(text) as Record<string, unknown>;
          } catch {
            // Not JSON.
          }
          resolve({ status: res.statusCode ?? 0, text, json });
        });
      },
    );
    req.on("error", reject);
    req.end(payload);
  });
}
