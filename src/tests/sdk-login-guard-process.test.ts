/**
 * Login guard for SDK upgrades: the compiled gateway (`dist/server.js`, built by
 * `npm run build`) runs as a child process with the production Claude Agent SDK
 * and its bundled Claude runtime. The runtime talks to a loopback MCP stub that
 * publishes OAuth metadata with a registration endpoint, and to a scripted
 * stand-in for the Anthropic Messages API (no real model is involved).
 *
 * The child gets an environment ALLOWLIST (never the parent's API or Jira
 * secrets) and fresh temp directories for HOME, TMPDIR, cwd and every persist
 * path. Linux only: the listening-socket check reads /proc.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import net, { type AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { FINAL_ANSWER, startFakeAnthropicApi, type FakeAnthropicApi } from "./helpers/fake-anthropic-api.js";
import { STUB_TOOL_NAME, startOAuthMcpStub, type OAuthMcpStub, type OAuthStubOptions } from "./helpers/oauth-mcp-stub.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(here, "..", "..");
const DIST_SERVER = path.join(REPO_ROOT, "dist", "server.js");

const API_KEY = "login-guard-gateway-key-7667";
/** Wait after the runtime child exits before scanning files: it flushes buffered log lines on exit. */
const SCAN_DELAY_MS = 2000;

/** Fails loudly when dist/ is missing or older than src/ (run `npm run build`). */
function assertFreshBuild(): void {
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

/** A distinct random alphanumeric test credential. */
function sentinel(label: string): string {
  return `${label}${randomBytes(18).toString("hex")}`;
}

/** Environment ALLOWLIST for the spawned gateway. Never turn this into a denylist. */
const ALLOWED_ENV_KEYS = ["PATH", "LANG"] as const;

interface SpawnedGateway {
  child: ChildProcess;
  port: number;
  /** HOME, TMPDIR, cwd and persist directories of the child. */
  dirs: { home: string; tmp: string; cwd: string; persist: string };
  output: () => string;
}

const cleanups: (() => Promise<void> | void)[] = [];

afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()!();
});

async function freePort(): Promise<number> {
  const server = net.createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const { port } = server.address() as AddressInfo;
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
}

async function mcpStub(options: OAuthStubOptions): Promise<OAuthMcpStub> {
  const created = await startOAuthMcpStub(options);
  cleanups.push(() => created.close());
  return created;
}

async function fakeApi(): Promise<FakeAnthropicApi> {
  const created = await startFakeAnthropicApi({ toolName: STUB_TOOL_NAME });
  cleanups.push(() => created.close());
  return created;
}

function request(port: number, method: string, urlPath: string, body?: unknown): Promise<{ status: number; text: string }> {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body), "utf8");
    const req = http.request(
      {
        host: "127.0.0.1",
        port,
        method,
        path: urlPath,
        agent: false,
        headers: {
          Authorization: `Bearer ${API_KEY}`,
          ...(payload ? { "Content-Type": "application/json", "Content-Length": payload.length } : {}),
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString("utf8") }));
      },
    );
    req.on("error", reject);
    req.end(payload);
  });
}

async function spawnGateway(api: FakeAnthropicApi, env: Record<string, string> = {}): Promise<SpawnedGateway> {
  assertFreshBuild();
  const port = await freePort();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "mvp7667-login-"));
  const dirs = { home: path.join(root, "home"), tmp: path.join(root, "tmp"), cwd: path.join(root, "cwd"), persist: path.join(root, "persist") };
  for (const dir of Object.values(dirs)) fs.mkdirSync(dir);

  const childEnv: NodeJS.ProcessEnv = {};
  for (const key of ALLOWED_ENV_KEYS) {
    if (process.env[key] !== undefined) childEnv[key] = process.env[key];
  }
  Object.assign(childEnv, {
    HOME: dirs.home,
    TMPDIR: dirs.tmp,
    PORT: String(port),
    HOST: "127.0.0.1",
    API_KEYS: `probe:${API_KEY}`,
    LOG_LEVEL: "debug",
    ANTHROPIC_BASE_URL: api.baseUrl,
    ANTHROPIC_API_KEY: "sk-ant-fake-login-guard-7667",
    DISABLE_TELEMETRY: "1",
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
    SESSION_PERSIST_PATH: path.join(dirs.persist, "sessions.json"),
    TOOLS_PERSIST_PATH: path.join(dirs.persist, "tools.json"),
    MCP_SERVERS_PERSIST_PATH: path.join(dirs.persist, "mcp-servers.json"),
    WORKSPACE_ROOT: path.join(dirs.home, ".claude"),
    ...env,
  });

  const child = spawn(process.execPath, ["--expose-gc", DIST_SERVER], {
    cwd: dirs.cwd,
    env: childEnv,
    stdio: ["ignore", "pipe", "pipe"],
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
    if (child.exitCode === null && child.signalCode === null) {
      const exited = new Promise<void>((resolve) => child.once("exit", () => resolve()));
      child.kill("SIGKILL");
      await exited;
    }
    fs.rmSync(root, { recursive: true, force: true });
  });

  const started = Date.now();
  for (;;) {
    if (child.exitCode !== null) throw new Error(`gateway exited early: ${output}`);
    const healthy = await new Promise<boolean>((resolve) => {
      const probe = http.get({ host: "127.0.0.1", port, path: "/health", agent: false }, (res) => {
        res.resume();
        resolve(res.statusCode === 200);
      });
      probe.on("error", () => resolve(false));
    });
    if (healthy) break;
    if (Date.now() - started > 15_000) throw new Error(`gateway not ready: ${output}`);
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  return { child, port, dirs, output: () => output };
}

/* ------------------------------------------------------------------ */
/*  Process tree, listening sockets, file scan                          */
/* ------------------------------------------------------------------ */

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

/** Every process below `pid` (not `pid` itself). */
function descendants(pid: number): number[] {
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

function listeningInodes(): Set<string> {
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
      // cols[3] is the state (0A = LISTEN), cols[9] the socket inode.
      if (cols.length > 9 && cols[3] === "0A") inodes.add(cols[9]);
    }
  }
  return inodes;
}

/** "pid:inode" for every listening TCP socket held by `pid` or a process below it. */
function listeningSocketsOfTree(pid: number): Set<string> {
  const listening = listeningInodes();
  const held = new Set<string>();
  for (const p of [pid, ...descendants(pid)]) {
    let fds: string[] = [];
    try {
      fds = fs.readdirSync(`/proc/${p}/fd`);
    } catch {
      continue;
    }
    for (const fd of fds) {
      try {
        const match = /^socket:\[(\d+)\]$/.exec(fs.readlinkSync(`/proc/${p}/fd/${fd}`));
        if (match && listening.has(match[1])) held.add(`inode:${match[1]}`);
      } catch {
        // fd closed while reading.
      }
    }
  }
  return held;
}

/** Polls the tree's listening sockets until stopped; returns every socket seen that was not there at start. */
function watchNewListeners(pid: number): { stop: () => string[] } {
  const initial = listeningSocketsOfTree(pid);
  const seen = new Set<string>();
  const timer = setInterval(() => {
    for (const socket of listeningSocketsOfTree(pid)) if (!initial.has(socket)) seen.add(socket);
  }, 25);
  return {
    stop: () => {
      clearInterval(timer);
      for (const socket of listeningSocketsOfTree(pid)) if (!initial.has(socket)) seen.add(socket);
      return [...seen];
    },
  };
}

async function waitForNoDescendants(pid: number, timeoutMs = 20_000): Promise<void> {
  const started = Date.now();
  while (descendants(pid).length > 0) {
    if (Date.now() - started > timeoutMs) throw new Error(`runtime processes still alive after ${timeoutMs} ms: ${descendants(pid).join(",")}`);
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
}

/** Files under the given roots whose content contains any needle, as "<file>: <needle>". */
function filesContaining(roots: string[], needles: string[]): string[] {
  const hits: string[] = [];
  const walk = (dir: string): void => {
    let entries: fs.Dirent[] = [];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile()) {
        const content = fs.readFileSync(full, "latin1");
        for (const needle of needles) if (content.includes(needle)) hits.push(`${full}: ${needle.slice(0, 8)}…`);
      }
    }
  };
  for (const root of roots) walk(root);
  return hits;
}

/* ------------------------------------------------------------------ */
/*  One run                                                             */
/* ------------------------------------------------------------------ */

interface NdjsonEvent {
  type: string;
  [key: string]: unknown;
}

interface RunOutcome {
  status: number;
  events: NdjsonEvent[];
  finalText: string;
  newListeners: string[];
  /** Files that hold a needle, scanned SCAN_DELAY_MS after the runtime child exited. */
  fileHits: string[];
}

async function runAgent(gateway: SpawnedGateway, body: Record<string, unknown>, needles: string[]): Promise<RunOutcome> {
  const watcher = watchNewListeners(gateway.child.pid!);
  let response: { status: number; text: string };
  let newListeners: string[] = [];
  try {
    response = await request(gateway.port, "POST", "/v1/query", {
      queryId: `q-${randomBytes(4).toString("hex")}`,
      prompt: `Look up record R-1 with ${STUB_TOOL_NAME}.`,
      model: "claude-sonnet-4-5",
      useSession: false,
      ...body,
    });
    await waitForNoDescendants(gateway.child.pid!);
  } finally {
    // Collected after the runtime is gone, so a listener it opened late is still seen.
    newListeners = watcher.stop();
  }
  await new Promise((resolve) => setTimeout(resolve, SCAN_DELAY_MS));
  const events = response.text
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as NdjsonEvent);
  const finalText = events
    .filter((e) => e.type === "text")
    .map((e) => String(e.content))
    .join("");
  const { home, tmp, cwd, persist } = gateway.dirs;
  return {
    status: response.status,
    events,
    finalText,
    newListeners,
    fileHits: filesContaining([home, tmp, cwd, persist], needles),
  };
}

async function registerHttpServer(gateway: SpawnedGateway, name: string, stub: OAuthMcpStub, extra: Record<string, unknown> = {}): Promise<void> {
  const put = await request(gateway.port, "PUT", `/v1/mcp-servers/${name}`, { type: "http", url: stub.url, ...extra });
  expect(put.status).toBe(201);
}

/* ------------------------------------------------------------------ */
/*  Rows                                                                */
/* ------------------------------------------------------------------ */

const SERVER = "records";
const TOOL = `mcp__${SERVER}__${STUB_TOOL_NAME}`;

interface LoginRow {
  name: string;
  refuse: OAuthStubOptions["refuse"];
  /** What the model must see from the refusing server. */
  modelSees: "tool-error" | "no-tools" | "tool-result";
}

const LOGIN_ROWS: LoginRow[] = [
  { name: "401 only for tools/call (token expired mid-run): the model sees a tool error result", refuse: "tools-call", modelSees: "tool-error" },
  { name: "401 already for initialize: the model sees none of the server's tools", refuse: "initialize", modelSees: "no-tools" },
  { name: "401 on the GET event stream: tool calls still work", refuse: "get-stream", modelSees: "tool-result" },
];

describe("login guard controls", () => {
  it("the listening-socket check sees a port opened by a grandchild process", async () => {
    // A child that starts a grandchild, which opens a listening port after a short delay.
    const script = `const { spawn } = require("node:child_process");
      spawn(process.execPath, ["-e", "setTimeout(() => require('node:net').createServer().listen(0, '127.0.0.1'), 300); setTimeout(() => {}, 5000)"], { stdio: "ignore" });
      setTimeout(() => {}, 5000);`;
    const child = spawn(process.execPath, ["-e", script], { stdio: "ignore" });
    cleanups.push(() => {
      for (const pid of descendants(child.pid!)) process.kill(pid, "SIGKILL");
      child.kill("SIGKILL");
    });
    const watcher = watchNewListeners(child.pid!);
    await new Promise((resolve) => setTimeout(resolve, 1500));
    expect(watcher.stop().length).toBe(1);
  }, 10_000);
});

describe("a refused MCP token never starts a login inside the gateway (real runtime)", () => {
  for (const row of LOGIN_ROWS) {
    it(row.name, async () => {
      const stub = await mcpStub({ refuse: row.refuse });
      const api = await fakeApi();
      const gateway = await spawnGateway(api);
      await registerHttpServer(gateway, SERVER, stub);
      const credential = sentinel("LoginGuardCred");

      const outcome = await runAgent(
        gateway,
        { mcpCredentialOverrides: { [SERVER]: { headers: { Authorization: `Bearer ${credential}` } } } },
        [credential, "mcpOAuth"],
      );

      // Soft assertions: a failing run reports every outcome that does not hold, not only the first.
      // The run ends with a normal answer.
      expect.soft(outcome.status).toBe(200);
      expect.soft(outcome.events.some((e) => e.type === "error")).toBe(false);
      expect.soft(outcome.events.at(-1)?.type).toBe("done");
      expect.soft(outcome.finalText).toContain(FINAL_ANSWER);

      // What the model sees.
      const agentRequests = api.agentRequests();
      expect.soft(agentRequests.length).toBeGreaterThan(0);
      const offeredTool = agentRequests.some((r) => r.tools.includes(TOOL));
      const results = agentRequests.flatMap((r) => r.toolResults);
      if (row.modelSees === "no-tools") {
        expect.soft(offeredTool).toBe(false);
      } else {
        expect.soft(offeredTool).toBe(true);
        expect.soft(results.length).toBeGreaterThan(0);
        expect.soft(results.every((r) => r.isError === (row.modelSees === "tool-error"))).toBe(true);
        if (row.modelSees === "tool-result") expect.soft(results[0].text).toContain(stub.toolResultPrefix);
      }

      // No authentication tool is offered to the model, in any request.
      const authTools = api.requests.flatMap((r) => r.tools).filter((name) => /auth/i.test(name));
      expect.soft(authTools).toEqual([]);

      // The server receives no client-registration, authorize or token request (primary check).
      expect.soft({ registration: stub.counters.registration, authorize: stub.counters.authorize, token: stub.counters.token }).toEqual({
        registration: 0,
        authorize: 0,
        token: 0,
      });

      // No OAuth credential (and no copy of the run's credential) is written under the gateway's directories.
      expect.soft(outcome.fileHits).toEqual([]);

      // No process in the gateway opens a local port for an OAuth redirect (secondary check).
      expect.soft(outcome.newListeners).toEqual([]);
    }, 90_000);
  }
});
