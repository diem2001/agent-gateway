/**
 * Start-up of a test-started gateway (MVP-8129): how the shared test harness picks a port and decides that a spawned
 * gateway is ready, and how the gateway itself reacts when its port is taken.
 *
 * Why: under full-suite load a harness start failed with "gateway not ready" although the gateway's log said it was
 * listening. Two causes were found. The harness picked a port with `listen(0)` + `close()` and the gateway bound it
 * seconds later, so any other `listen(0)` on the host could take it in between; and the gateway ignored the listen
 * callback's error, so it logged "listening" and stayed up without serving its port. Rows S1-S4 drive the harness with
 * stand-in processes started through `spawnGateway({ distServer })`; S5 starts the real `dist/server.js` on a taken
 * port; S6/S6b exercise the port allocator; S7 is the inventory guard; S8 pins the start-up log line.
 *
 * Needs `npm run build` (S5 and S6b run compiled code). Linux only (`/proc`). Every secret is synthetic.
 */
import { spawn, type ChildProcess } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import net, { type AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import * as harness from "./helpers/git-process-gateway.js";
import type { Cleanup, SpawnedGateway } from "./helpers/git-process-gateway.js";

vi.setConfig({ testTimeout: 90_000 });

const { REPO_ROOT, GATEWAY_API_KEY, gatewayRequest, descendants } = harness;

/** The harness API this file pins; the new members are loosely typed so the file compiles (and fails) on a harness without them. */
interface StartupHarness {
  spawnGateway(cleanups: Cleanup[], options?: Parameters<typeof harness.spawnGateway>[1] & { readyTimeoutMs?: number }): Promise<SpawnedGateway>;
  reserveGatewayPort(options?: { range?: [number, number]; slot?: number; lockDir?: string }): Promise<number>;
  releaseGatewayPort(port: number, options?: { lockDir?: string }): void;
  GATEWAY_READY_TIMEOUT_MS: number;
}
const api = harness as unknown as StartupHarness;

const cleanups: Cleanup[] = [];
const savedStartupLog = process.env.GATEWAY_STARTUP_LOG;
afterEach(async () => {
  if (savedStartupLog === undefined) delete process.env.GATEWAY_STARTUP_LOG;
  else process.env.GATEWAY_STARTUP_LOG = savedStartupLog;
  while (cleanups.length > 0) await cleanups.pop()!();
});

function scratchDir(prefix: string): string {
  const dir = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), prefix));
  cleanups.push(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

/* ------------------------------------------------------------------ */
/*  Stand-in gateways                                                   */
/* ------------------------------------------------------------------ */

/** A health-and-echo server on PORT; `delayMs` is how long the stand-in takes before it listens. */
function listeningScript(delayMs: number): string {
  return `
const http = require("node:http");
const key = String(process.env.API_KEYS).split(":")[1];
setTimeout(() => {
  http.createServer((req, res) => {
    if (req.url === "/health") { res.end("ok"); return; }
    if (req.headers.authorization !== "Bearer " + key) { res.statusCode = 401; res.end(); return; }
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ echo: true }));
  }).listen(Number(process.env.PORT), "127.0.0.1", () => console.log("stand-in listening"));
}, ${delayMs});
`;
}

const EXIT_SCRIPT = `
for (let i = 1; i <= 30; i++) {
  const n = String(i).padStart(3, "0");
  console.log(i === 12 ? "numbered-line-" + n + " key=" + process.env.API_KEYS : "numbered-line-" + n);
}
process.exit(3);
`;

const SIGNAL_SCRIPT = `
console.log("about to be killed");
setTimeout(() => process.kill(process.pid, "SIGKILL"), 50);
setInterval(() => {}, 1000);
`;

const NEVER_LISTENS_SCRIPT = `
console.log("stand-in alive, never listens");
setInterval(() => {}, 1000);
`;

/** A separate process answers 200 on PORT; the stand-in itself never listens. */
const FOREIGN_RESPONDER_SCRIPT = `
const { spawn } = require("node:child_process");
const port = Number(process.env.PORT);
spawn(process.execPath, ["-e", "require('node:http').createServer((q, r) => r.end('ok')).listen(" + port + ", '127.0.0.1')"], { stdio: "ignore" });
console.log("stand-in alive, a foreign process answers on the port");
setInterval(() => {}, 1000);
`;

function standIn(script: string): string {
  const file = path.join(scratchDir("mvp8129-standin-"), "server.cjs");
  fs.writeFileSync(file, script);
  return file;
}

async function startFailure(distServer: string, options: { readyTimeoutMs?: number } = {}): Promise<{ message: string; ms: number }> {
  const started = Date.now();
  try {
    await api.spawnGateway(cleanups, { distServer, ...options });
  } catch (error) {
    return { message: (error as Error).message, ms: Date.now() - started };
  }
  throw new Error("the start was reported ready, a failure was expected");
}

/* ------------------------------------------------------------------ */
/*  S1-S4: the readiness wait                                           */
/* ------------------------------------------------------------------ */

describe("readiness wait", () => {
  it("S1 a slow but healthy start (listens after 16 s, past the old 15 s deadline) is waited for and then used", async () => {
    const gateway = await api.spawnGateway(cleanups, { distServer: standIn(listeningScript(16_000)) });
    const answer = await gatewayRequest(gateway.port, "GET", "/v1/echo");
    expect(answer.status).toBe(200);
    expect(answer.json).toEqual({ echo: true });
  });

  it("S2a a start that exits reports code, signal and the last 20 lines at once, without the key", async () => {
    const { message, ms } = await startFailure(standIn(EXIT_SCRIPT));
    expect(message).toContain("gateway exited during startup: code=3 signal=null");
    expect(message).toContain("numbered-line-030");
    expect(message).toContain("numbered-line-011");
    expect(message).not.toContain("numbered-line-001");
    expect(message).not.toContain(GATEWAY_API_KEY);
    expect(message).toContain("[redacted]");
    // The exit caused the rejection, not a deadline: well before the old 15 s.
    expect(ms).toBeLessThan(10_000);
  });

  it("S2b a start that is killed by a signal reports the signal", async () => {
    const { message, ms } = await startFailure(standIn(SIGNAL_SCRIPT));
    expect(message).toContain("gateway exited during startup: code=null signal=SIGKILL");
    expect(message).toContain("about to be killed");
    expect(ms).toBeLessThan(10_000);
  });

  it("S3 a live process that never listens fails at the given bound and says it is still running", async () => {
    const { message, ms } = await startFailure(standIn(NEVER_LISTENS_SCRIPT), { readyTimeoutMs: 3_000 });
    expect(message).toContain("gateway still running but not ready after");
    expect(message).toContain("stand-in alive, never listens");
    expect(message).not.toContain("exited");
    expect(ms).toBeGreaterThanOrEqual(3_000);
    expect(ms).toBeLessThan(15_000);
  });

  it("S4 a 200 from a process the gateway does not own is never ready", async () => {
    const { message, ms } = await startFailure(standIn(FOREIGN_RESPONDER_SCRIPT), { readyTimeoutMs: 3_000 });
    expect(message).toContain("gateway still running but not ready after");
    expect(message).toContain("foreign responder: yes");
    expect(message).toContain("owns port: no");
    expect(ms).toBeGreaterThanOrEqual(3_000);
    expect(ms).toBeLessThan(15_000);
  });
});

/* ------------------------------------------------------------------ */
/*  S5: the real gateway on a taken port                                */
/* ------------------------------------------------------------------ */

describe("real gateway on a taken port", () => {
  it("S5 exits 1 with one FATAL listen line and never logs that it is listening", async () => {
    const squatter = http.createServer((_req, res) => {
      res.statusCode = 404;
      res.end();
    });
    await new Promise<void>((resolve) => squatter.listen(0, "127.0.0.1", () => resolve()));
    cleanups.push(() => new Promise<void>((resolve) => squatter.close(() => resolve())));
    const { port } = squatter.address() as AddressInfo;

    const root = scratchDir("mvp8129-s5-");
    for (const dir of ["home", "tmp", "persist"]) fs.mkdirSync(path.join(root, dir));
    const child = spawn(process.execPath, [path.join(REPO_ROOT, "dist", "server.js")], {
      cwd: path.join(root, "home"),
      env: {
        PATH: process.env.PATH ?? "",
        HOME: path.join(root, "home"),
        TMPDIR: path.join(root, "tmp"),
        PORT: String(port),
        HOST: "127.0.0.1",
        API_KEYS: `proc:${GATEWAY_API_KEY}`,
        SESSION_PERSIST_PATH: path.join(root, "persist", "sessions.json"),
        TOOLS_PERSIST_PATH: path.join(root, "persist", "tools.json"),
        MCP_SERVERS_PERSIST_PATH: path.join(root, "persist", "mcp-servers.json"),
        WORKSPACE_ROOT: path.join(root, "home", ".claude"),
      },
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
    });

    const deadline = Date.now() + 45_000;
    while (child.exitCode === null && child.signalCode === null && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    const state = child.exitCode === null && child.signalCode === null ? "still running" : `code=${child.exitCode} signal=${child.signalCode}`;
    expect(state, `gateway on a taken port; log:\n${output}`).toBe("code=1 signal=null");
    expect(output).toMatch(new RegExp(`FATAL listen host=127\\.0\\.0\\.1 port=${port} code=EADDRINUSE reason=the listen port could not be opened`));
    expect(output).not.toContain("listening on");
    expect(output.match(/FATAL listen/g)).toHaveLength(1);
  });
});

/* ------------------------------------------------------------------ */
/*  S6, S6b: the port allocator                                         */
/* ------------------------------------------------------------------ */

/** Lower bound of the kernel's ephemeral range: the allocator hands out ports below it, so `listen(0)` can never collide. */
function ephemeralLow(): number {
  return Number(fs.readFileSync("/proc/sys/net/ipv4/ip_local_port_range", "utf8").trim().split(/\s+/)[0]);
}

/** Slot layout of the allocator, written out here and not read from it: 256 ports per slot in the 8192 ports below the ephemeral range. */
function slotWindow(slot: number): [number, number] {
  const start = ephemeralLow() - 8192 + slot * 256;
  return [start, start + 256];
}

describe("reserved gateway ports", () => {
  it("S6 ports come from below the ephemeral range, are distinct, and a port someone holds is skipped", async () => {
    const lockDir = scratchDir("mvp8129-s6-");
    const [start, end] = slotWindow(30);
    const held = start + 100;
    const squatter = net.createServer();
    await new Promise<void>((resolve, reject) => squatter.once("error", reject).listen(held, "127.0.0.1", () => resolve()));
    cleanups.push(() => new Promise<void>((resolve) => squatter.close(() => resolve())));

    const first = await Promise.all(Array.from({ length: 5 }, () => api.reserveGatewayPort({ lockDir, slot: 30 })));
    expect(new Set(first).size).toBe(5);

    const ports = [...first];
    for (let i = 0; i < 300; i++) {
      try {
        ports.push(await api.reserveGatewayPort({ lockDir, slot: 30 }));
      } catch {
        break;
      }
    }
    expect(ports.length).toBeGreaterThanOrEqual(200);
    expect(new Set(ports).size).toBe(ports.length);
    for (const port of ports) {
      expect(port).toBeGreaterThanOrEqual(start);
      expect(port).toBeLessThan(end);
      expect(port).toBeLessThan(ephemeralLow());
    }
    expect(ports).not.toContain(held);
  });

  it("S6b two processes never receive the same port; slots are disjoint; stale locks are replaced; a too-small range is refused", async () => {
    const lockDir = scratchDir("mvp8129-s6b-");
    const helperUrl = pathToFileURL(path.join(REPO_ROOT, "dist", "tests", "helpers", "git-process-gateway.js")).href;
    const program = `
      const m = await import(${JSON.stringify(helperUrl)});
      const ports = [];
      for (let i = 0; i < 100; i++) ports.push(await m.reserveGatewayPort({ lockDir: ${JSON.stringify(lockDir)}, slot: 29 }));
      console.log(JSON.stringify(ports));
      process.stdin.resume();
      process.stdin.on("end", () => process.exit(0));
    `;
    const children: ChildProcess[] = [];
    const lists = await Promise.all(
      [0, 1].map(
        () =>
          new Promise<number[]>((resolve, reject) => {
            const child = spawn(process.execPath, ["--input-type=module", "-e", program], { stdio: ["pipe", "pipe", "pipe"] });
            children.push(child);
            let out = "";
            let err = "";
            child.stdout!.on("data", (data: Buffer) => {
              out += data.toString("utf8");
              if (out.includes("\n")) resolve(JSON.parse(out) as number[]);
            });
            child.stderr!.on("data", (data: Buffer) => (err += data.toString("utf8")));
            child.once("exit", (code) => reject(new Error(`allocator process ended with code ${code}: ${err}`)));
          }),
      ),
    ).finally(() => {
      for (const child of children) child.stdin!.end();
    });
    expect(lists[0]).toHaveLength(100);
    expect(lists[1]).toHaveLength(100);
    expect(new Set([...lists[0], ...lists[1]]).size).toBe(200);

    // Slots are disjoint windows.
    const bySlot = new Map<number, Set<number>>();
    for (const slot of [26, 27, 28]) {
      const taken = new Set<number>();
      for (let i = 0; i < 20; i++) taken.add(await api.reserveGatewayPort({ lockDir, slot }));
      const [start, end] = slotWindow(slot);
      for (const port of taken) {
        expect(port).toBeGreaterThanOrEqual(start);
        expect(port).toBeLessThan(end);
      }
      bySlot.set(slot, taken);
    }
    expect(new Set([...bySlot.values()].flatMap((set) => [...set])).size).toBe(60);

    // A lock of a live process keeps its port; the lock of a dead process is replaced.
    const staleDir = scratchDir("mvp8129-s6b-stale-");
    const dead = spawn(process.execPath, ["-e", ""]);
    await new Promise((resolve) => dead.once("exit", resolve));
    const [start, end] = slotWindow(25);
    const free = start + 77;
    for (let port = start; port < end; port++) fs.writeFileSync(path.join(staleDir, `${port}.lock`), port === free ? String(dead.pid) : "1");
    expect(await api.reserveGatewayPort({ lockDir: staleDir, slot: 25 })).toBe(free);
    await expect(api.reserveGatewayPort({ lockDir: staleDir, slot: 25 })).rejects.toThrow(/no free gateway port/);

    // A range below 1024 usable ports is an error, never a silent fallback.
    await expect(api.reserveGatewayPort({ lockDir, range: [40_000, 40_500] })).rejects.toThrow(/fewer than 1024/);
    expect(api.GATEWAY_READY_TIMEOUT_MS).toBe(45_000);
  });
});

/* ------------------------------------------------------------------ */
/*  S7: inventory guard                                                 */
/* ------------------------------------------------------------------ */

describe("inventory", () => {
  it("S7 no test file keeps its own readiness loop or picks a gateway port outside the allocator", () => {
    const testsRoot = path.dirname(fileURLToPath(import.meta.url));
    const self = path.basename(fileURLToPath(import.meta.url));
    const files: string[] = [];
    const walk = (dir: string): void => {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) walk(full);
        else if (entry.name.endsWith(".ts") && entry.name !== self) files.push(full);
      }
    };
    walk(testsRoot);

    const violations: string[] = [];
    for (const file of files) {
      const text = fs.readFileSync(file, "utf8");
      const name = path.relative(testsRoot, file);
      for (const phrase of ["gateway not ready", "gateway exited early"]) {
        if (text.includes(phrase)) violations.push(`${name}: its own readiness loop (\`${phrase}\`)`);
      }
      if (/\bPORT: String\(/.test(text) && !text.includes("reserveGatewayPort")) violations.push(`${name}: sets PORT for a spawned gateway without reserveGatewayPort`);
      // A "free port" pick: listen(0), read the port, close the socket, use the number later.
      const pick = /[^\n]*\.address\(\)[^\n]*\n(?:[^\n]*\n)?[^\n]*\.close\(/g;
      for (let match = pick.exec(text); match; match = pick.exec(text)) {
        if (/port|AddressInfo/.test(match[0].split("\n")[0])) violations.push(`${name}:${text.slice(0, match.index).split("\n").length}: listen(0) then close() to pick a port`);
      }
    }
    expect(violations).toEqual([]);
  });
});

/* ------------------------------------------------------------------ */
/*  S8: start-up log                                                    */
/* ------------------------------------------------------------------ */

describe("start-up log", () => {
  it("S8 every start appends one line to the file named by GATEWAY_STARTUP_LOG, ready and failed alike", async () => {
    const logFile = path.join(scratchDir("mvp8129-s8-"), "startup.log");
    process.env.GATEWAY_STARTUP_LOG = logFile;

    const gateway = await api.spawnGateway(cleanups, { distServer: standIn(listeningScript(0)) });
    await startFailure(standIn(NEVER_LISTENS_SCRIPT), { readyTimeoutMs: 2_000 });

    const lines = fs.readFileSync(logFile, "utf8").trim().split("\n");
    expect(lines).toHaveLength(2);
    expect(lines[0]).toMatch(new RegExp(`^ready pid=${gateway.child.pid} port=${gateway.port} ms=\\d+$`));
    expect(lines[1]).toMatch(/^failed pid=\d+ port=\d+ ms=\d+ /);
  });
});
