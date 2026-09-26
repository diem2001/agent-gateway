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
  /** True when the client aborted the run. */
  aborted: boolean;
  newListeners: string[];
  /** Every `--mcp-config` value seen on a runtime process's command line during the run. */
  runtimeMcpConfigs: string[];
  /** Files that hold a needle, scanned SCAN_DELAY_MS after the runtime child exited. */
  fileHits: string[];
  /** Run log directories of the gateway left in the child's TMPDIR. */
  leftoverRunDirs: string[];
}

function collectRuntimeMcpConfigs(pid: number, seen: Set<string>): void {
  for (const p of descendants(pid)) {
    try {
      const args = fs.readFileSync(`/proc/${p}/cmdline`, "utf8").split("\0");
      const index = args.indexOf("--mcp-config");
      if (index >= 0 && args[index + 1]) seen.add(args[index + 1]);
    } catch {
      // Process ended while reading.
    }
  }
}

interface RunOptions {
  /** Abort the run (close the client connection) once the NDJSON stream contains this event type. */
  abortAfterEvent?: string;
}

async function runAgent(gateway: SpawnedGateway, body: Record<string, unknown>, needles: string[], options: RunOptions = {}): Promise<RunOutcome> {
  const pid = gateway.child.pid!;
  const watcher = watchNewListeners(pid);
  const configs = new Set<string>();
  const configTimer = setInterval(() => collectRuntimeMcpConfigs(pid, configs), 25);
  let status = 0;
  let text = "";
  let aborted = false;
  let newListeners: string[] = [];
  try {
    await new Promise<void>((resolve, reject) => {
      const payload = Buffer.from(
        JSON.stringify({
          queryId: `q-${randomBytes(4).toString("hex")}`,
          prompt: `Look up record R-1 with ${STUB_TOOL_NAME}.`,
          model: "claude-sonnet-4-5",
          useSession: false,
          ...body,
        }),
      );
      const req = http.request(
        {
          host: "127.0.0.1",
          port: gateway.port,
          method: "POST",
          path: "/v1/query",
          agent: false,
          headers: { Authorization: `Bearer ${API_KEY}`, "Content-Type": "application/json", "Content-Length": payload.length },
        },
        (res) => {
          status = res.statusCode ?? 0;
          res.on("data", (chunk: Buffer) => {
            text += chunk.toString("utf8");
            if (options.abortAfterEvent && !aborted && text.includes(`"type":"${options.abortAfterEvent}"`)) {
              aborted = true;
              req.destroy();
              resolve();
            }
          });
          res.on("end", () => resolve());
          res.on("error", () => resolve());
        },
      );
      req.on("error", (err) => (aborted ? resolve() : reject(err)));
      req.end(payload);
    });
    await waitForNoDescendants(pid);
  } finally {
    clearInterval(configTimer);
    // Collected after the runtime is gone, so a listener it opened late is still seen.
    newListeners = watcher.stop();
  }
  await new Promise((resolve) => setTimeout(resolve, SCAN_DELAY_MS));
  const events = text
    .split("\n")
    .filter((line) => line.trim().startsWith("{") && line.trim().endsWith("}"))
    .map((line) => JSON.parse(line) as NdjsonEvent);
  const finalText = events
    .filter((e) => e.type === "text")
    .map((e) => String(e.content))
    .join("");
  const { home, tmp, cwd, persist } = gateway.dirs;
  return {
    status,
    events,
    finalText,
    aborted,
    newListeners,
    runtimeMcpConfigs: [...configs],
    fileHits: filesContaining([home, tmp, cwd, persist], needles),
    leftoverRunDirs: fs.readdirSync(tmp).filter((name) => name.startsWith("agent-gateway-run-")),
  };
}

async function registerServer(gateway: SpawnedGateway, name: string, body: Record<string, unknown>): Promise<void> {
  const put = await request(gateway.port, "PUT", `/v1/mcp-servers/${name}`, body);
  expect(put.status).toBe(201);
}

async function registerHttpServer(gateway: SpawnedGateway, name: string, stub: OAuthMcpStub, extra: Record<string, unknown> = {}): Promise<void> {
  await registerServer(gateway, name, { type: "http", url: stub.url, ...extra });
}

/** The relay URL a runtime got for `name`, read from its `--mcp-config` argument. */
function relayUrlFor(outcome: RunOutcome, name: string): string | undefined {
  for (const config of outcome.runtimeMcpConfigs) {
    const url = (JSON.parse(config) as { mcpServers?: Record<string, { url?: string }> }).mcpServers?.[name]?.url;
    if (url) return url;
  }
  return undefined;
}

/** A minimal stdio MCP server: initialize, tools/list and tools/call over newline-delimited JSON. */
const STDIO_SERVER_SOURCE = [
  'const readline = require("node:readline");',
  "const rl = readline.createInterface({ input: process.stdin });",
  'const send = (m) => process.stdout.write(JSON.stringify(m) + "\\n");',
  'rl.on("line", (line) => {',
  "  let m; try { m = JSON.parse(line); } catch { return; }",
  "  if (m.id === undefined) return;",
  '  if (m.method === "initialize") send({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: m.params.protocolVersion, capabilities: { tools: {} }, serverInfo: { name: "stdio-stub", version: "1" } } });',
  '  else if (m.method === "tools/list") send({ jsonrpc: "2.0", id: m.id, result: { tools: [{ name: "local_lookup", description: "Local lookup.", inputSchema: { type: "object", properties: {} } }] } });',
  '  else if (m.method === "tools/call") send({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: "LOCAL-OK" }] } });',
  '  else send({ jsonrpc: "2.0", id: m.id, error: { code: -32601, message: "Method not found" } });',
  "});",
].join("\n");

function postInitialize(url: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
    const req = http.request(url, { method: "POST", agent: false, headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) } }, (res) => {
      res.resume();
      res.on("end", () => resolve(res.statusCode ?? 0));
    });
    req.on("error", reject);
    req.end(body);
  });
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
  for (const flagged of [false, true]) {
    for (const row of LOGIN_ROWS) {
      it(`${flagged ? "flagged (requireUserCredentials)" : "unflagged"} server, ${row.name}`, async () => {
        const stub = await mcpStub({ refuse: row.refuse });
        const api = await fakeApi();
        const gateway = await spawnGateway(api);
        await registerHttpServer(gateway, SERVER, stub, flagged ? { requireUserCredentials: true } : {});
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

        // The credential still reached the MCP server, and never appeared on the runtime's command line.
        expect.soft(stub.authorizations().length).toBeGreaterThan(0);
        expect.soft(stub.authorizations().every((a) => a === `Bearer ${credential}`)).toBe(true);
        expect.soft(outcome.runtimeMcpConfigs.length).toBeGreaterThan(0);
        expect.soft(outcome.runtimeMcpConfigs.some((c) => c.includes(credential))).toBe(false);
      }, 90_000);
    }
  }
});

describe("a server that needs a user credential is left out of runs without one (real runtime)", () => {
  it("without an aida entry the AIDA server receives no request; with one it receives the overridden Authorization", async () => {
    const aida = await mcpStub({});
    const api = await fakeApi();
    const gateway = await spawnGateway(api);
    await registerHttpServer(gateway, "aida", aida, { requireUserCredentials: true });
    const credential = sentinel("AidaCred");

    const without = await runAgent(gateway, {}, [credential]);

    expect(without.finalText).toContain(FINAL_ANSWER);
    expect(aida.requests).toEqual([]);
    expect(api.agentRequests().some((r) => r.tools.some((t) => t.startsWith("mcp__aida__")))).toBe(false);
    expect(without.runtimeMcpConfigs.some((c) => c.includes('"aida"'))).toBe(false);
    expect(gateway.output()).toContain("mcp.server.omitted serverName=aida reason=missing_user_credential");

    const withEntry = await runAgent(gateway, { mcpCredentialOverrides: { aida: { headers: { Authorization: `Bearer ${credential}` } } } }, [credential]);

    expect(withEntry.finalText).toContain(FINAL_ANSWER);
    expect(aida.authorizations().length).toBeGreaterThan(0);
    expect(aida.authorizations().every((a) => a === `Bearer ${credential}`)).toBe(true);
    expect(api.agentRequests().some((r) => r.toolResults.some((t) => t.text.includes(aida.toolResultPrefix)))).toBe(true);
    expect(withEntry.fileHits).toEqual([]);
  }, 90_000);
});

describe("a run's credentials do not remain in the Claude runtime's own log files (PS-1, real runtime)", () => {
  const ENDS = [
    { name: "with a normal answer", mode: "normal" as const },
    { name: "with an error", mode: "error" as const },
    { name: "because it is aborted", mode: "hang-after-tool" as const },
  ];

  for (const end of ENDS) {
    it(`the run ends ${end.name}: no file holds the http header or the stdio env value`, async () => {
      const stub = await mcpStub({});
      // A request-supplied http server keeps the direct path: its header reaches the runtime and its logs.
      const direct = await mcpStub({});
      const api = await startFakeAnthropicApi({ toolName: STUB_TOOL_NAME, mode: end.mode });
      cleanups.push(() => api.close());
      const gateway = await spawnGateway(api);
      const stdioScript = path.join(os.tmpdir(), `mvp7667-stdio-${randomBytes(4).toString("hex")}.cjs`);
      fs.writeFileSync(stdioScript, STDIO_SERVER_SOURCE);
      cleanups.push(() => fs.rmSync(stdioScript, { force: true }));
      await registerHttpServer(gateway, SERVER, stub);
      await registerServer(gateway, "local", { type: "stdio", command: process.execPath, args: [stdioScript] });
      const header = sentinel("Ps1Header");
      const envValue = sentinel("Ps1Env");
      const directHeader = sentinel("Ps1Direct");

      const outcome = await runAgent(
        gateway,
        {
          mcpCredentialOverrides: {
            [SERVER]: { headers: { Authorization: `Bearer ${header}` } },
            local: { env: { TOKEN: envValue } },
          },
          mcpServers: { direct: { type: "http", url: direct.url, headers: { Authorization: `Bearer ${directHeader}` } } },
        },
        [header, envValue, directHeader],
        end.mode === "hang-after-tool" ? { abortAfterEvent: "tool_result" } : {},
      );

      // The runtime had the stdio env value and the direct header during the run.
      expect.soft(outcome.runtimeMcpConfigs.some((c) => c.includes(envValue))).toBe(true);
      expect.soft(outcome.runtimeMcpConfigs.some((c) => c.includes(directHeader))).toBe(true);
      expect.soft(direct.authorizations().length).toBeGreaterThan(0);
      if (end.mode !== "error") expect.soft(stub.authorizations().length).toBeGreaterThan(0);
      if (end.mode === "normal") {
        expect.soft(outcome.finalText).toContain(FINAL_ANSWER);
        expect.soft(outcome.events.at(-1)?.type).toBe("done");
      }
      // The scripted API answers 400; the runtime exits and the client receives an error event.
      if (end.mode === "error") expect.soft(outcome.events.some((e) => e.type === "error")).toBe(true);
      if (end.mode === "hang-after-tool") expect.soft(outcome.aborted).toBe(true);

      expect.soft(outcome.fileHits).toEqual([]);
      expect.soft(outcome.leftoverRunDirs).toEqual([]);
      expect.soft([header, envValue, directHeader].some((needle) => gateway.output().includes(needle))).toBe(false);
    }, 90_000);
  }
});

describe("the relay carries a working MCP server (real runtime)", () => {
  it("SSE answers, the Mcp-Session-Id round trip and a multi-MB tool result reach the model", async () => {
    const stub = await mcpStub({ responseMode: "sse", toolResultBytes: 3 * 1024 * 1024 });
    const api = await fakeApi();
    const gateway = await spawnGateway(api);
    await registerHttpServer(gateway, SERVER, stub);

    const outcome = await runAgent(gateway, {}, []);

    expect(outcome.finalText).toContain(FINAL_ANSWER);
    const results = api.agentRequests().flatMap((r) => r.toolResults);
    expect(results).toHaveLength(1);
    expect(results[0].isError).toBe(false);
    expect(results[0].text).toContain(stub.toolResultPrefix);
    const afterInitialize = stub.requests.filter((r) => r.path === "/mcp" && r.method === "POST" && !r.rpcMethods.includes("initialize"));
    expect(afterInitialize.length).toBeGreaterThan(0);
    expect(afterInitialize.every((r) => r.headers["mcp-session-id"] === "stub-session-1")).toBe(true);
  }, 90_000);

  it("a lost upstream session (404) reaches the runtime as a plain 404: a tool error, as with a direct connection, and no login", async () => {
    // Claude Code 2.0.77 does not initialize a new session after the 404; it reports the call as failed.
    // A direct connection (before the relay) gives the same tool result.
    const stub = await mcpStub({ loseSessionOn: "tools/call" });
    const api = await fakeApi();
    const gateway = await spawnGateway(api);
    await registerHttpServer(gateway, SERVER, stub);

    const outcome = await runAgent(gateway, {}, []);

    expect(outcome.finalText).toContain(FINAL_ANSWER);
    expect(outcome.events.at(-1)?.type).toBe("done");
    expect(stub.requests.find((r) => r.rpcMethods.includes("tools/call"))?.status).toBe(404);
    const results = api.agentRequests().flatMap((r) => r.toolResults);
    expect(results).toHaveLength(1);
    expect(results[0].isError).toBe(true);
    expect(results[0].text).toBe("Streamable HTTP error: Error POSTing to endpoint:");
    expect({ metadata: stub.counters.metadata, registration: stub.counters.registration }).toEqual({ metadata: 0, registration: 0 });
  }, 90_000);

  it("a finished run's relay URL answers 404", async () => {
    const stub = await mcpStub({});
    const api = await fakeApi();
    const gateway = await spawnGateway(api);
    await registerHttpServer(gateway, SERVER, stub);

    const outcome = await runAgent(gateway, {}, []);
    const relayUrl = relayUrlFor(outcome, SERVER);

    expect(relayUrl).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/mcp\/[A-Za-z0-9_-]{22}$/);
    const before = stub.requests.length;
    expect(await postInitialize(relayUrl!)).toBe(404);
    expect(stub.requests.length).toBe(before);
  }, 90_000);

  it("an unreachable upstream still ends the run with a normal answer", async () => {
    const api = await fakeApi();
    const gateway = await spawnGateway(api);
    const closedPort = await freePort();
    await registerServer(gateway, SERVER, { type: "http", url: `http://127.0.0.1:${closedPort}/mcp` });

    const outcome = await runAgent(gateway, {}, []);

    expect(outcome.status).toBe(200);
    expect(outcome.events.at(-1)?.type).toBe("done");
    expect(outcome.finalText).toContain(FINAL_ANSWER);
  }, 90_000);
});

describe("DEBUG_CLAUDE_AGENT_SDK (real runtime)", () => {
  it("a gateway started with it set warns, writes no sdk-*.txt and no credential copy", async () => {
    const stub = await mcpStub({});
    const api = await fakeApi();
    const gateway = await spawnGateway(api, { DEBUG_CLAUDE_AGENT_SDK: "1" });
    await registerHttpServer(gateway, SERVER, stub);
    const credential = sentinel("SdkDebugCred");

    const outcome = await runAgent(gateway, { mcpCredentialOverrides: { [SERVER]: { headers: { Authorization: `Bearer ${credential}` } } } }, [credential]);

    expect(outcome.finalText).toContain(FINAL_ANSWER);
    const sdkFiles: string[] = [];
    const walk = (dir: string): void => {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        if (entry.isDirectory()) walk(path.join(dir, entry.name));
        else if (/^sdk-.*\.txt$/.test(entry.name)) sdkFiles.push(entry.name);
      }
    };
    for (const dir of Object.values(gateway.dirs)) walk(dir);
    expect.soft(sdkFiles).toEqual([]);
    expect.soft(outcome.fileHits).toEqual([]);
    expect.soft(gateway.output()).toContain("DEBUG_CLAUDE_AGENT_SDK is ignored");
  }, 90_000);
});
