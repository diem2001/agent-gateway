/**
 * Process-level proofs for MVP-7616 Gate B: the compiled gateway
 * (`dist/server.js`, built by `npm run build`) runs as a child process with an
 * environment ALLOWLIST and fresh temp directories (one per persistence area)
 * and receives real SIGTERM/SIGINT signals. Streaming chat answers use the real
 * Claude runtime against the scripted Anthropic API in mode "hang".
 *
 * Covers the ticket's outlines "Every pending change in every area survives a
 * stop signal", "A second signal ends the drain at once", "A stop whose final
 * save fails for one area exits with failure and keeps that area's file", "A
 * stop during a slow git operation never damages saved state", an idle stop,
 * and the deadline with an open stream (the process-level half of the Outcome).
 */
import { spawn, type ChildProcess } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { startFakeAnthropicApi, type FakeAnthropicApi } from "./helpers/fake-anthropic-api.js";
import { releaseGatewayPort, reserveGatewayPort, waitForGatewayReady } from "./helpers/git-process-gateway.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(here, "..", "..");
const DIST_SERVER = path.join(REPO_ROOT, "dist", "server.js");

const API_KEY = "proc-gateway-key-7616-stop";
const IS_ROOT = process.getuid?.() === 0;
const skipAsRoot = IS_ROOT ? "skipped: tests run as root, permission-based rows need a non-root user" : "";
const TIMEOUT = { timeout: 90_000 };

type Area = "sessions" | "tools" | "mcpServers";
const AREAS: Area[] = ["sessions", "tools", "mcpServers"];
const FILE_NAME: Record<Area, string> = { sessions: "sessions.json", tools: "tools.json", mcpServers: "mcp-servers.json" };
const ENV_KEY: Record<Area, string> = {
  sessions: "SESSION_PERSIST_PATH",
  tools: "TOOLS_PERSIST_PATH",
  mcpServers: "MCP_SERVERS_PERSIST_PATH",
};

function earlierState(area: Area): unknown {
  const now = Date.now();
  switch (area) {
    case "sessions":
      // Conversations of the key's label `proc` with a folder name (MVP-7402: a delete erases the folder; a pre-update
      // entry answers 409 and stays, so it could not stand for "a session deleted just before the stop").
      return {
        sessions: {},
        sessionsByLabel: {
          proc: {
            "earlier-1": { sessionId: "sdk-1", systemPrompt: "", model: "m", lastUsed: now, owner: { label: "proc", userId: null }, sandboxDirId: "1a1a1a1a1a1a1a1a1a1a1a1a" },
            "earlier-2": { sessionId: "sdk-2", systemPrompt: "", model: "m", lastUsed: now, owner: { label: "proc", userId: null }, sandboxDirId: "2b2b2b2b2b2b2b2b2b2b2b2b" },
          },
        },
        settings: { sessionIdleTimeoutMs: 0 },
      };
    case "tools":
      return [{ name: "earlier-tool", description: "d", input_schema: { type: "object" }, webhook_url: "http://127.0.0.1:9/hook" }];
    case "mcpServers":
      return [{ name: "earlier-mcp", description: "", enabled: true, type: "http", url: "http://127.0.0.1:9/mcp", createdAt: "x", updatedAt: "x" }];
  }
}

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

/** Environment ALLOWLIST for the spawned gateway. Never turn this into a denylist. */
const ALLOWED_ENV_KEYS = ["PATH", "LANG"] as const;

interface Fixture {
  root: string;
  home: string;
  dirs: Record<Area, string>;
  file: (area: Area) => string;
}

interface Gateway {
  child: ChildProcess;
  port: number;
  output: () => string;
  exited: Promise<{ code: number | null; signal: NodeJS.Signals | null; at: number }>;
}

const cleanups: (() => Promise<void> | void)[] = [];

afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()!();
});

function fixture(): Fixture {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "mvp7616-stop-"));
  const home = path.join(root, "home");
  fs.mkdirSync(home);
  fs.mkdirSync(path.join(root, "tmp"));
  // The trusted storage root with its sessions directory: the delete of a conversation checks it (MVP-7402).
  fs.mkdirSync(path.join(home, ".agent-sandbox", "sessions"), { recursive: true, mode: 0o700 });
  fs.chmodSync(path.join(home, ".agent-sandbox"), 0o700);
  fs.chmodSync(path.join(home, ".agent-sandbox", "sessions"), 0o700);
  const dirs = {} as Record<Area, string>;
  for (const area of AREAS) {
    dirs[area] = path.join(root, `persist-${area}`);
    fs.mkdirSync(dirs[area]);
  }
  const file = (area: Area) => path.join(dirs[area], FILE_NAME[area]);
  for (const area of AREAS) fs.writeFileSync(file(area), JSON.stringify(earlierState(area), null, 2));
  cleanups.push(() => {
    for (const dir of Object.values(dirs)) fs.chmodSync(dir, 0o755);
    fs.rmSync(root, { recursive: true, force: true });
  });
  return { root, home, dirs, file };
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

/** Kill processes the gateway started (runtime, git) that outlive it. */
function reapLater(pids: number[]): void {
  cleanups.push(() => {
    for (const pid of pids) {
      try {
        process.kill(pid, "SIGKILL");
      } catch {
        // Already gone.
      }
    }
  });
}

async function startGateway(fx: Fixture, extraEnv: Record<string, string> = {}): Promise<Gateway> {
  assertFreshBuild();
  const port = await reserveGatewayPort();
  const childEnv: NodeJS.ProcessEnv = {};
  for (const key of ALLOWED_ENV_KEYS) {
    if (process.env[key] !== undefined) childEnv[key] = process.env[key];
  }
  Object.assign(childEnv, {
    HOME: fx.home,
    TMPDIR: path.join(fx.root, "tmp"),
    PORT: String(port),
    HOST: "127.0.0.1",
    API_KEYS: `proc:${API_KEY}`,
    WORKSPACE_ROOT: path.join(fx.home, ".claude"),
    DISABLE_TELEMETRY: "1",
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
    ...extraEnv,
  });
  for (const area of AREAS) childEnv[ENV_KEY[area]] = fx.file(area);

  const child = spawn(process.execPath, ["--expose-gc", DIST_SERVER], {
    cwd: fx.root,
    env: childEnv,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  child.stdout!.on("data", (data: Buffer) => (output += data.toString("utf8")));
  child.stderr!.on("data", (data: Buffer) => (output += data.toString("utf8")));
  const exited = new Promise<{ code: number | null; signal: NodeJS.Signals | null; at: number }>((resolve) =>
    child.once("exit", (code, signal) => resolve({ code, signal, at: Date.now() })),
  );
  const gateway: Gateway = { child, port, output: () => output, exited };
  cleanups.push(async () => {
    reapLater(descendants(child.pid!));
    if (child.exitCode === null && child.signalCode === null) {
      child.kill("SIGKILL");
      await exited;
    }
    releaseGatewayPort(port);
  });

  await waitForGatewayReady({ child, port, output: () => output, env: childEnv });
  return gateway;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function request(port: number, method: string, urlPath: string, body?: unknown): Promise<{ status: number; text: string; json: () => any }> {
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
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          resolve({ status: res.statusCode ?? 0, text, json: () => JSON.parse(text) });
        });
      },
    );
    req.on("error", reject);
    req.end(payload);
  });
}

/**
 * A request whose headers and half of its JSON body are sent now; `finish`
 * sends the rest. Node parses the headers at once, so the request counts as
 * received and is drained, while its route handler (and state change) only
 * runs once the body is complete.
 */
async function partialRequest(port: number, method: string, urlPath: string, body: unknown) {
  const payload = Buffer.from(JSON.stringify(body), "utf8");
  const half = Math.floor(payload.length / 2);
  let resolveReply: (r: { status: number; text: string; connection?: string }) => void;
  let rejectReply: (e: Error) => void;
  const reply = new Promise<{ status: number; text: string; connection?: string }>((resolve, reject) => {
    resolveReply = resolve;
    rejectReply = reject;
  });
  const req = http.request(
    {
      host: "127.0.0.1",
      port,
      method,
      path: urlPath,
      agent: false,
      headers: { Authorization: `Bearer ${API_KEY}`, "Content-Type": "application/json", "Content-Length": payload.length },
    },
    (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (chunk: Buffer) => chunks.push(chunk));
      res.on("end", () =>
        resolveReply({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString("utf8"), connection: res.headers.connection }),
      );
    },
  );
  req.on("error", (e) => rejectReply(e));
  req.write(payload.subarray(0, half));
  return {
    finish: () => {
      req.end(payload.subarray(half));
      return reply;
    },
  };
}

function connectRefused(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = net.connect(port, "127.0.0.1");
    socket.once("connect", () => {
      socket.destroy();
      resolve(false);
    });
    socket.once("error", () => resolve(true));
  });
}

function readState(fx: Fixture) {
  return {
    sessions: JSON.parse(fs.readFileSync(fx.file("sessions"), "utf8")) as {
      sessions: Record<string, unknown>;
      sessionsByLabel?: Record<string, Record<string, unknown>>;
      settings: { sessionIdleTimeoutMs: number };
    },
    tools: (JSON.parse(fs.readFileSync(fx.file("tools"), "utf8")) as { name: string }[]).map((t) => t.name),
    mcpServers: (JSON.parse(fs.readFileSync(fx.file("mcpServers"), "utf8")) as { name: string }[]).map((s) => s.name),
  };
}

const toolBody = { description: "d", input_schema: { type: "object" }, webhook_url: "http://127.0.0.1:9/hook" };
const mcpBody = { type: "http", url: "http://127.0.0.1:9/mcp" };

/**
 * Pending, not yet saved changes in all three areas (inside the 100 ms
 * debounce). Without earlier sessions (an unreadable sessions file) the
 * sessions change is the idle-timeout setting alone.
 */
async function pendingChanges(gateway: Gateway, tag: string, withSessionDelete = true): Promise<void> {
  const replies = await Promise.all([
    request(gateway.port, "PUT", "/v1/settings", { sessionIdleTimeoutMs: 111_000 }),
    ...(withSessionDelete ? [request(gateway.port, "DELETE", "/v1/sessions/earlier-1")] : []),
    request(gateway.port, "PUT", `/v1/tools/tool-${tag}`, toolBody),
    request(gateway.port, "PUT", `/v1/mcp-servers/mcp-${tag}`, mcpBody),
  ]);
  for (const r of replies) expect([200, 201]).toContain(r.status);
}

function errorLines(output: string): string[] {
  return output.split("\n").filter((l) => l.startsWith("ERROR persistence "));
}

/* ------------------------------------------------------------------ */
/*  Every pending change in every area survives a stop signal           */
/* ------------------------------------------------------------------ */

describe("Every pending change in every area survives a stop signal", () => {
  it.each(["SIGTERM", "SIGINT"] as const)(
    "%s: pending and drain-time changes are all present after a restart",
    async (signal) => {
      const fx = fixture();
      const gateway = await startGateway(fx);

      // Requests received before the signal, whose bodies (and state changes) arrive while draining.
      const drainSettings = await partialRequest(gateway.port, "PUT", "/v1/settings", { sessionIdleTimeoutMs: 222_000 });
      const drainSession = await partialRequest(gateway.port, "DELETE", "/v1/sessions/earlier-2", {});
      const drainTool = await partialRequest(gateway.port, "PUT", "/v1/tools/tool-drain", toolBody);
      const drainMcp = await partialRequest(gateway.port, "PUT", "/v1/mcp-servers/mcp-drain", mcpBody);
      await delay(150);

      await pendingChanges(gateway, "pending");
      // Still inside the debounce window: nothing of it is on disk yet.
      const onDisk = readState(fx);
      expect(onDisk.tools).not.toContain("tool-pending");
      expect(onDisk.mcpServers).not.toContain("mcp-pending");

      const signalledAt = Date.now();
      gateway.child.kill(signal);
      await delay(100);
      expect(await connectRefused(gateway.port)).toBe(true);
      expect(gateway.child.exitCode).toBeNull();

      const replies = await Promise.all([drainSettings.finish(), drainSession.finish(), drainTool.finish(), drainMcp.finish()]);
      for (const r of replies) expect([200, 201]).toContain(r.status);
      for (const r of replies) expect(r.connection).toBe("close");

      const exit = await gateway.exited;
      expect(exit.code, gateway.output()).toBe(0);
      expect(exit.at - signalledAt).toBeLessThan(9000);
      expect(errorLines(gateway.output())).toEqual([]);

      const restarted = await startGateway(fx);
      const sessions = (await request(restarted.port, "GET", "/v1/sessions")).json().sessions.map((s: { id: string }) => s.id);
      expect(sessions).not.toContain("earlier-1");
      expect(sessions).not.toContain("earlier-2");
      expect((await request(restarted.port, "GET", "/v1/settings")).json()).toEqual({ sessionIdleTimeoutMs: 222_000 });
      const tools = (await request(restarted.port, "GET", "/v1/tools")).json().tools.map((t: { name: string }) => t.name);
      expect(tools).toEqual(expect.arrayContaining(["earlier-tool", "tool-pending", "tool-drain"]));
      const mcp = (await request(restarted.port, "GET", "/v1/mcp-servers")).json().servers.map((s: { name: string }) => s.name);
      expect(mcp).toEqual(expect.arrayContaining(["earlier-mcp", "mcp-pending", "mcp-drain"]));
    },
    TIMEOUT.timeout,
  );
});

/* ------------------------------------------------------------------ */
/*  Idle stop                                                           */
/* ------------------------------------------------------------------ */

describe("An idle stop is quick and keeps a change made just before it", () => {
  it.each(["SIGTERM", "SIGINT"] as const)(
    "%s: exit 0 within 2 s, the session deleted less than 100 ms earlier stays deleted",
    async (signal) => {
      const fx = fixture();
      const gateway = await startGateway(fx);
      expect((await request(gateway.port, "DELETE", "/v1/sessions/earlier-1")).status).toBe(200);
      const signalledAt = Date.now();
      gateway.child.kill(signal);
      const exit = await gateway.exited;
      expect(exit.code, gateway.output()).toBe(0);
      expect(exit.at - signalledAt).toBeLessThan(2000);

      const restarted = await startGateway(fx);
      const sessions = (await request(restarted.port, "GET", "/v1/sessions")).json().sessions.map((s: { id: string }) => s.id);
      expect(sessions).toEqual(["earlier-2"]);
    },
    TIMEOUT.timeout,
  );
});

/* ------------------------------------------------------------------ */
/*  Streaming chat answer: deadline and second signal                   */
/* ------------------------------------------------------------------ */

async function api(): Promise<FakeAnthropicApi> {
  const created = await startFakeAnthropicApi({ toolName: "none", mode: "hang" });
  cleanups.push(() => created.close());
  return created;
}

/** Starts a streaming chat answer for a new session and waits until the session exists. */
async function openStream(gateway: Gateway, sessionId: string): Promise<{ ended: () => boolean }> {
  let ended = false;
  const payload = Buffer.from(JSON.stringify({ queryId: `q-${sessionId}`, prompt: "Say hello.", sessionId, model: "claude-sonnet-4-5" }));
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
      res.resume();
      res.on("close", () => (ended = true));
    },
  );
  req.on("error", () => (ended = true));
  req.end(payload);

  const started = Date.now();
  for (;;) {
    const sessions = (await request(gateway.port, "GET", "/v1/sessions")).json().sessions.map((s: { id: string }) => s.id);
    if (sessions.includes(sessionId)) break;
    if (Date.now() - started > 10_000) throw new Error(`stream did not start: ${gateway.output()}`);
    await delay(20);
  }
  return { ended: () => ended };
}

describe("A streaming chat answer during a stop", () => {
  it(
    "deadline: with an answer that never finishes, exit 0 within 9 s and the new session is present",
    async () => {
      const fx = fixture();
      const scripted = await api();
      const gateway = await startGateway(fx, { ANTHROPIC_BASE_URL: scripted.baseUrl, ANTHROPIC_API_KEY: "sk-ant-fake-7616" });
      const stream = await openStream(gateway, "stream-deadline");
      await delay(500);
      expect(stream.ended()).toBe(false);

      reapLater(descendants(gateway.child.pid!));
      const signalledAt = Date.now();
      gateway.child.kill("SIGTERM");
      await delay(7000);
      // Still draining: the stream is held open until the deadline.
      expect(gateway.child.exitCode).toBeNull();
      expect(stream.ended()).toBe(false);
      const exit = await gateway.exited;
      expect(exit.code, gateway.output()).toBe(0);
      expect(exit.at - signalledAt).toBeGreaterThanOrEqual(7900);
      expect(exit.at - signalledAt).toBeLessThan(9000);

      const restarted = await startGateway(fx);
      const sessions = (await request(restarted.port, "GET", "/v1/sessions")).json().sessions.map((s: { id: string }) => s.id);
      expect(sessions).toContain("stream-deadline");
    },
    TIMEOUT.timeout,
  );

  it.each([
    ["SIGTERM", "SIGTERM"],
    ["SIGTERM", "SIGINT"],
  ] as const)(
    "second signal: %s then %s ends the drain and exits 0 within 1 s",
    async (first, second) => {
      const fx = fixture();
      const scripted = await api();
      const gateway = await startGateway(fx, { ANTHROPIC_BASE_URL: scripted.baseUrl, ANTHROPIC_API_KEY: "sk-ant-fake-7616" });
      const stream = await openStream(gateway, "stream-second");
      expect((await request(gateway.port, "PUT", "/v1/tools/tool-before-stop", toolBody)).status).toBe(201);

      reapLater(descendants(gateway.child.pid!));
      gateway.child.kill(first);
      await delay(500);
      expect(gateway.child.exitCode).toBeNull();
      expect(stream.ended()).toBe(false);

      const secondAt = Date.now();
      gateway.child.kill(second);
      const exit = await gateway.exited;
      expect(exit.code, gateway.output()).toBe(0);
      expect(exit.at - secondAt).toBeLessThan(1000);

      const restarted = await startGateway(fx);
      const sessions = (await request(restarted.port, "GET", "/v1/sessions")).json().sessions.map((s: { id: string }) => s.id);
      expect(sessions).toContain("stream-second");
      const tools = (await request(restarted.port, "GET", "/v1/tools")).json().tools.map((t: { name: string }) => t.name);
      expect(tools).toContain("tool-before-stop");
    },
    TIMEOUT.timeout,
  );
});

/* ------------------------------------------------------------------ */
/*  A stop whose final save fails for one area                          */
/* ------------------------------------------------------------------ */

type Condition = "injected write error" | "suppressed";
const FINAL_SAVE_ROWS: [Area, Condition, "SIGTERM" | "SIGINT"][] = [
  ["sessions", "injected write error", "SIGTERM"],
  ["sessions", "suppressed", "SIGINT"],
  ["tools", "injected write error", "SIGINT"],
  ["tools", "suppressed", "SIGTERM"],
  ["mcpServers", "injected write error", "SIGTERM"],
  ["mcpServers", "suppressed", "SIGINT"],
];

describe.skipIf(IS_ROOT)(`A stop whose final save fails for one area exits with failure and keeps that area's file ${skipAsRoot}`, () => {
  it.each(FINAL_SAVE_ROWS)(
    "%s, %s, %s",
    async (area, condition, signal) => {
      const fx = fixture();
      if (condition === "suppressed") {
        fs.writeFileSync(fx.file(area), "{ not json at all");
        fs.chmodSync(fx.dirs[area], 0o555);
      }
      const kept = fs.readFileSync(fx.file(area));
      const gateway = await startGateway(fx);
      if (condition === "suppressed") {
        expect(errorLines(gateway.output())[0]).toContain(`area=${area} problem=unreadable-not-preserved`);
      }

      await pendingChanges(gateway, "pending", !(area === "sessions" && condition === "suppressed"));
      if (condition === "injected write error") fs.chmodSync(fx.dirs[area], 0o555);

      const signalledAt = Date.now();
      gateway.child.kill(signal);
      const exit = await gateway.exited;
      expect(exit.code, gateway.output()).toBe(1);
      expect(exit.at - signalledAt).toBeLessThan(2000);

      const finalLines = errorLines(gateway.output()).filter((l) => l.includes("problem=final-save-failed"));
      expect(finalLines).toHaveLength(1);
      expect(finalLines[0]).toMatch(new RegExp(`^ERROR persistence area=${area} problem=final-save-failed file=${fx.file(area).replace(/[.]/g, "\\.")} reason=`));
      if (condition === "injected write error") expect(finalLines[0]).toContain("code=EACCES");

      fs.chmodSync(fx.dirs[area], 0o755);
      expect(fs.readFileSync(fx.file(area)).equals(kept)).toBe(true);

      // The other two areas' pending changes were saved.
      const others = AREAS.filter((a) => a !== area);
      const restarted = await startGateway(fx);
      if (others.includes("sessions")) {
        expect((await request(restarted.port, "GET", "/v1/settings")).json()).toEqual({ sessionIdleTimeoutMs: 111_000 });
        const sessions = (await request(restarted.port, "GET", "/v1/sessions")).json().sessions.map((s: { id: string }) => s.id);
        expect(sessions).not.toContain("earlier-1");
      }
      if (others.includes("tools")) {
        const tools = (await request(restarted.port, "GET", "/v1/tools")).json().tools.map((t: { name: string }) => t.name);
        expect(tools).toContain("tool-pending");
      }
      if (others.includes("mcpServers")) {
        const mcp = (await request(restarted.port, "GET", "/v1/mcp-servers")).json().servers.map((s: { name: string }) => s.name);
        expect(mcp).toContain("mcp-pending");
      }
    },
    TIMEOUT.timeout,
  );
});

/* ------------------------------------------------------------------ */
/*  A stop during a slow git operation never damages saved state        */
/* ------------------------------------------------------------------ */

/** True while src/routes/git.ts runs git synchronously (before MVP-7614). */
function gitBlocksEventLoop(): boolean {
  return /\bexecSync\s*\(/.test(fs.readFileSync(path.join(REPO_ROOT, "src", "routes", "git.ts"), "utf8"));
}

const GIT_LEVEL = gitBlocksEventLoop()
  ? "level integrity-only: bounded stop during git awaits MVP-7614"
  : "level bounded: exit 0 within 9 s";

describe("A stop during a slow git operation never damages saved state", () => {
  it(
    `every state file loads and holds at least its last completed save (${GIT_LEVEL})`,
    async () => {
      const fx = fixture();
      const bin = path.join(fx.root, "fake-bin");
      fs.mkdirSync(bin);
      fs.writeFileSync(path.join(bin, "git"), "#!/bin/sh\nexec sleep 30\n", { mode: 0o755 });
      fs.mkdirSync(path.join(fx.home, ".claude", "projects", "repo", ".git"), { recursive: true });
      const gateway = await startGateway(fx, { PATH: `${bin}:${process.env.PATH ?? ""}` });

      // A completed save in every area.
      await pendingChanges(gateway, "completed");
      await delay(300);
      const completed = readState(fx);
      expect(completed.tools).toContain("tool-completed");

      const gitRequest = request(gateway.port, "GET", "/v1/workspace/git/status?path=repo").catch(() => null);
      await delay(300);
      reapLater(descendants(gateway.child.pid!));
      const signalledAt = Date.now();
      gateway.child.kill("SIGTERM");

      // Docker's behaviour: SIGKILL when the process has not ended after 10 s.
      const exit = await Promise.race([gateway.exited, delay(10_000).then(() => null)]);
      const result = exit ?? (gateway.child.kill("SIGKILL"), await gateway.exited);
      await gitRequest;

      const after = readState(fx);
      expect(after.sessions.settings.sessionIdleTimeoutMs).toBe(111_000);
      expect(Object.keys(after.sessions.sessionsByLabel?.proc ?? {})).not.toContain("earlier-1");
      expect(after.tools).toContain("tool-completed");
      expect(after.mcpServers).toContain("mcp-completed");

      // While execSync blocks, the signal handler cannot run and the process
      // ends by the SIGKILL above: integrity is the whole guarantee then.
      if (!gitBlocksEventLoop()) {
        expect(result.code, gateway.output()).toBe(0);
        expect(result.at - signalledAt).toBeLessThan(9000);
      }
    },
    TIMEOUT.timeout,
  );
});
