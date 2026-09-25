/**
 * Real-process proofs for the upload relay: the compiled gateway
 * (`dist/server.js`, built by `npm run build`) runs as a child process with the
 * node flags of the production start line (the exec line of entrypoint.sh), an
 * environment ALLOWLIST (never the parent's API or Jira secrets), and fresh
 * temp directories for HOME, TMPDIR, cwd and every persist path. The MCP server
 * is a loopback stub in this process.
 *
 * Memory is read from Linux /proc: writing 5 to /proc/<pid>/clear_refs resets
 * the peak (VmHWM) to the current RSS, so VmHWM after a relay minus VmRSS before
 * it is the peak growth that relay caused. `--expose-gc` lets the relay force a
 * minor collection every 2 MiB (src/gc-budget.ts); without it the received
 * chunks pile up as garbage and the "< 10 MB" assertions below fail.
 */
import { spawn, type ChildProcess } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import net, { type AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import {
  MiB,
  answerCreated,
  sendUpload,
  startUploadStub,
  type SendOptions,
  type StubHandler,
  type UploadStub,
} from "./helpers/upload-relay-stub.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(here, "..", "..");
const DIST_SERVER = path.join(REPO_ROOT, "dist", "server.js");

const FIFTY_MB = 50 * MiB;
/** The Story's bound: peak resident memory grows by less than 10 MB. */
const TEN_MB = 10 * 1000 * 1000;

const API_KEY = "proc-gateway-key-7564";
const TOKEN = "proc-user-token-7564";
const EMAIL_TOKEN = `user-a@example.com:${TOKEN}`;
const BASIC_B64 = Buffer.from(EMAIL_TOKEN, "utf8").toString("base64");
const BASIC = `Basic ${BASIC_B64}`;
const OVERRIDE = Buffer.from(JSON.stringify({ Authorization: BASIC }), "utf8").toString("base64");
const MARKER = Buffer.from("BYTES-MARKER-7564-q8zv", "utf8");
/** Every form of the test credential, the gateway key and a marker inside the relayed bytes. */
const MUST_NOT_BE_LOGGED = [TOKEN, EMAIL_TOKEN, BASIC_B64, BASIC, OVERRIDE, API_KEY, MARKER.toString("utf8")];

const TARGET = "/v1/mcp-servers/jira/uploads/jira/issue/MVP-1?filename=shot.png";

/**
 * The node flags between `node` and `/app/dist/server.js` on the exec line of
 * entrypoint.sh. Throws when the line has another shape, so the tests cannot
 * silently fall back to a start line the image does not use.
 */
function entrypointNodeFlags(): string[] {
  const script = fs.readFileSync(path.join(REPO_ROOT, "entrypoint.sh"), "utf8");
  const lines = [...script.matchAll(/^exec gosu node node (.*?)\s*\/app\/dist\/server\.js\s*$/gm)];
  if (lines.length !== 1) {
    throw new Error("entrypoint.sh must have exactly one `exec gosu node node [flags] /app/dist/server.js` line");
  }
  return lines[0][1].split(/\s+/).filter(Boolean);
}

const NODE_FLAGS = entrypointNodeFlags();

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

/** Environment ALLOWLIST for the spawned gateway. Never turn this into a denylist. */
const ALLOWED_ENV_KEYS = ["PATH", "LANG"] as const;

interface SpawnedGateway {
  child: ChildProcess;
  port: number;
  root: string;
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

async function stub(handler?: StubHandler): Promise<UploadStub> {
  const created = await startUploadStub(handler);
  cleanups.push(() => created.close());
  return created;
}

function request(
  port: number,
  method: string,
  urlPath: string,
  body?: unknown,
): Promise<{ status: number; text: string }> {
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

async function spawnGateway(env: Record<string, string>): Promise<SpawnedGateway> {
  assertFreshBuild();
  const port = await freePort();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "mvp7564-relay-"));
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
    API_KEYS: `proc:${API_KEY}`,
    SESSION_PERSIST_PATH: path.join(dirs.persist, "sessions.json"),
    TOOLS_PERSIST_PATH: path.join(dirs.persist, "tools.json"),
    MCP_SERVERS_PERSIST_PATH: path.join(dirs.persist, "mcp-servers.json"),
    WORKSPACE_ROOT: path.join(dirs.home, ".claude"),
    ...env,
  });

  const child = spawn(process.execPath, [...NODE_FLAGS, DIST_SERVER], {
    cwd: dirs.cwd,
    env: childEnv,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  child.stdout!.on("data", (data: Buffer) => (output += data.toString("utf8")));
  child.stderr!.on("data", (data: Buffer) => (output += data.toString("utf8")));
  cleanups.push(async () => {
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
  return { child, port, root, output: () => output };
}

async function registerJira(gateway: SpawnedGateway, upstream: Pick<UploadStub, "url">): Promise<void> {
  const reply = await request(gateway.port, "PUT", "/v1/mcp-servers/jira", {
    type: "http",
    url: upstream.url,
    headers: { "X-Static": "1" },
  });
  // 201 on the first registration, 200 when it replaces an earlier one.
  expect([200, 201]).toContain(reply.status);
  // The registry persists after a 100 ms debounce; let that write land before
  // any file snapshot is taken.
  await new Promise((resolve) => setTimeout(resolve, 300));
}

interface RawStatusStub {
  url: string;
  /** Connections accepted and connections the gateway has closed again. */
  accepted: () => number;
  closed: () => number;
}

/**
 * A raw TCP upstream that reads the whole request, then answers with the given
 * status line and a small JSON body and keeps its socket open. Node's HTTP
 * client accepts any three digits as a status (`000` to `999`), which an
 * `http.Server` stub cannot send.
 */
async function rawStatusStub(status: string): Promise<RawStatusStub> {
  let accepted = 0;
  let closed = 0;
  const sockets = new Set<net.Socket>();
  const server = net.createServer((socket) => {
    accepted += 1;
    sockets.add(socket);
    socket.on("close", () => {
      closed += 1;
      sockets.delete(socket);
    });
    socket.on("error", () => undefined);
    let received = Buffer.alloc(0);
    let answered = false;
    socket.on("data", (data: Buffer) => {
      if (answered) return;
      received = Buffer.concat([received, data]);
      const headEnd = received.indexOf("\r\n\r\n");
      if (headEnd === -1) return;
      const length = Number(/^content-length:\s*(\d+)/im.exec(received.subarray(0, headEnd).toString("latin1"))?.[1] ?? 0);
      if (received.length - headEnd - 4 < length) return;
      answered = true;
      socket.write(`HTTP/1.1 ${status} Odd\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}`);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const { port } = server.address() as AddressInfo;
  cleanups.push(
    () =>
      new Promise<void>((resolve) => {
        for (const socket of sockets) socket.destroy();
        server.close(() => resolve());
      }),
  );
  return { url: `http://127.0.0.1:${port}/mcp`, accepted: () => accepted, closed: () => closed };
}

function relay(gateway: SpawnedGateway, options: Omit<SendOptions, "port" | "path"> & { path?: string }) {
  return sendUpload({
    port: gateway.port,
    path: TARGET,
    ...options,
    headers: { Authorization: `Bearer ${API_KEY}`, "X-MCP-Credential-Headers": OVERRIDE, "Content-Type": "image/png", ...options.headers },
  });
}

function procStatusKb(pid: number, field: "VmRSS" | "VmHWM"): number {
  const status = fs.readFileSync(`/proc/${pid}/status`, "utf8");
  const match = status.match(new RegExp(`^${field}:\\s+(\\d+) kB$`, "m"));
  if (!match) throw new Error(`${field} not found in /proc/${pid}/status`);
  return Number(match[1]);
}

/** Resets the peak and returns the current RSS in bytes. */
function resetPeak(pid: number): number {
  fs.writeFileSync(`/proc/${pid}/clear_refs`, "5");
  return procStatusKb(pid, "VmRSS") * 1024;
}

function peakBytes(pid: number): number {
  return procStatusKb(pid, "VmHWM") * 1024;
}

/** Every path under `dir` with its size and mtime. */
function snapshot(dir: string): string[] {
  const out: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true, recursive: true })) {
    const full = path.join(entry.parentPath, entry.name);
    const stat = fs.statSync(full);
    out.push(`${path.relative(dir, full)} ${entry.isDirectory() ? "dir" : stat.size} ${stat.mtimeMs}`);
  }
  return out.sort();
}

function report(line: string): void {
  process.stderr.write(`[upload-relay-process] ${line}\n`);
}

describe("upload relay in a real gateway process", () => {
  it("the production start lines run the gateway with --expose-gc", () => {
    expect(NODE_FLAGS).toContain("--expose-gc");
    const pkg = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "package.json"), "utf8"));
    expect(pkg.scripts.start).toBe(`node ${NODE_FLAGS.join(" ")} dist/server.js`);
  });

  it("50 MB: peak grows by less than 10 MB, no new file, no bytes or credential in logs at debug, info and off", async () => {
    const upstream = await stub();
    const gateway = await spawnGateway({ LOG_LEVEL: "debug" });
    await registerJira(gateway, upstream);
    const pid = gateway.child.pid!;

    // Warm-up relay so one-time allocations (modules, first sockets) are not
    // attributed to the measured relay.
    const warm = await relay(gateway, { total: 4 * MiB, prefix: MARKER });
    expect(warm.status).toBe(201);
    const filesBefore = snapshot(gateway.root);

    const rssBefore = resetPeak(pid);
    const result = await relay(gateway, { total: FIFTY_MB, prefix: MARKER });
    const growth = peakBytes(pid) - rssBefore;
    report(`50 MB relay at LOG_LEVEL=debug: peak RSS growth ${growth} bytes (${(growth / MiB).toFixed(2)} MiB)`);

    expect(result.status).toBe(201);
    expect(JSON.parse(result.text).size).toBe(FIFTY_MB);
    const seen = upstream.requests.at(-1)!;
    expect(seen.sha256).toBe(result.sentSha256);
    expect(seen.headers.authorization).toBe(BASIC);
    expect(growth).toBeLessThan(TEN_MB);

    for (const level of ["info", "off"]) {
      expect((await request(gateway.port, "PUT", "/v1/logging", { level })).status).toBe(200);
      const leveled = await relay(gateway, { total: 2 * MiB, prefix: MARKER });
      expect(leveled.status).toBe(201);
    }

    expect(snapshot(gateway.root)).toEqual(filesBefore);
    const output = gateway.output();
    expect(output).toContain("mcp.upload.relayed serverName=jira status=201");
    for (const secret of MUST_NOT_BE_LOGGED) expect(output).not.toContain(secret);
  }, 60_000);

  it("a stub reading at 1 MB/s holds the sender to its rate, memory stays flat", async () => {
    const upstream = await stub(async ({ res, record, consume }) => {
      if (!(await consume({ bytesPerSecond: MiB }))) return;
      const body = JSON.stringify({ size: record.bytes });
      res.writeHead(201, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) });
      res.end(body);
    });
    const gateway = await spawnGateway({ LOG_LEVEL: "info" });
    await registerJira(gateway, upstream);
    const pid = gateway.child.pid!;
    expect((await relay(gateway, { total: MiB })).status).toBe(201);

    const measuredIndex = upstream.requests.length;
    const rssBefore = resetPeak(pid);
    let written = 0;
    let worstLead = 0;
    const sampler = setInterval(() => {
      const current = upstream.requests[measuredIndex];
      if (current) worstLead = Math.max(worstLead, written - current.bytes);
    }, 250);
    const result = await relay(gateway, { total: FIFTY_MB, onWritten: (n) => (written = n) });
    clearInterval(sampler);
    const growth = peakBytes(pid) - rssBefore;
    const elapsed = result.finishedAt - result.startedAt;
    report(
      `50 MB relay to a 1 MiB/s stub: sender elapsed ${elapsed} ms, worst sender lead ${(worstLead / MiB).toFixed(2)} MiB, ` +
        `peak RSS growth ${growth} bytes (${(growth / MiB).toFixed(2)} MiB)`,
    );

    expect(result.status).toBe(201);
    expect(JSON.parse(result.text).size).toBe(FIFTY_MB);
    expect(elapsed).toBeGreaterThanOrEqual(40_000);
    expect(growth).toBeLessThan(TEN_MB);
  }, 120_000);

  it("slow progress completes and a stall answers 504 UPLOAD_TIMEOUT with the upstream aborted (MCP_UPLOAD_IDLE_TIMEOUT_MS=2000)", async () => {
    const upstream = await stub(answerCreated);
    const gateway = await spawnGateway({ LOG_LEVEL: "info", MCP_UPLOAD_IDLE_TIMEOUT_MS: "2000" });
    await registerJira(gateway, upstream);

    const slow = await relay(gateway, { total: 10 * 16 * 1024, chunkSize: 16 * 1024, intervalMs: 1000 });
    expect(slow.status).toBe(201);
    expect(slow.finishedAt - slow.startedAt).toBeGreaterThanOrEqual(9000);

    const stalled = await relay(gateway, { total: MiB, stallAfter: 64 * 1024 });
    expect(stalled.status).toBe(504);
    expect(JSON.parse(stalled.text).error.code).toBe("UPLOAD_TIMEOUT");
    const deadline = Date.now() + 1000;
    while (!upstream.requests.at(-1)!.aborted && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    expect(upstream.requests.at(-1)!.aborted).toBe(true);
    expect(gateway.output()).toContain("result=timeout");
  }, 30_000);

  it.each([5 * MiB, 20 * MiB])(
    "an mcp-jira style refusal (answer at once, read at most 1 MiB, then close) reaches a fast %i-byte sender verbatim",
    async (total) => {
      // mcp-jira refuses a missing credential before it reads the body, then
      // discards at most 1 MiB and closes the socket with the rest unread, so the
      // kernel resets the connection. A fast sender (one write, like curl) fills
      // the gateway with MBs at once; the relay must still read the early
      // answer before that reset, and the sender must get it unchanged, not a
      // 502. Found by the Outcome Probe against the real mcp-jira.
      const refusal = JSON.stringify({ error: { code: "UPLOAD_UNAUTHENTICATED", message: "An Authorization header is required." } });
      const upstream = await stub(({ req, res }) => {
        res.writeHead(401, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(refusal), Connection: "close" });
        res.write(refusal);
        let drained = 0;
        let closed = false;
        const close = () => {
          if (closed) return;
          closed = true;
          res.end(() => req.destroy());
        };
        req.on("data", (chunk: Buffer) => {
          drained += chunk.length;
          if (drained >= MiB) {
            req.pause();
            close();
          }
        });
        req.on("end", close);
      });
      const gateway = await spawnGateway({ LOG_LEVEL: "info" });
      await registerJira(gateway, upstream);

      const statuses: number[] = [];
      for (let attempt = 0; attempt < 10; attempt++) {
        const result = await relay(gateway, { total, oneWrite: true });
        statuses.push(result.status);
        if (result.status !== 401) report(`attempt ${attempt}: HTTP ${result.status} ${result.text}`);
        else expect(result.text).toBe(refusal);
      }
      report(`mcp-jira style refusal, ${total} bytes: statuses ${statuses.join(",")}`);
      expect(statuses).toEqual(Array(10).fill(401));
    },
    60_000,
  );

  it.each(["099", "000", "101", "600", "999"])(
    "an upstream answer with status %s becomes 502 UPLOAD_UPSTREAM_FAILED and the gateway keeps serving",
    async (status) => {
      // A registered MCP server is untrusted: a status the relay cannot pass on
      // (Node's client accepts any three digits; writeHead throws below 100) must
      // not crash the shared gateway, and must not be relayed as an answer.
      const upstream = await rawStatusStub(status);
      const gateway = await spawnGateway({ LOG_LEVEL: "info" });
      await registerJira(gateway, upstream);

      const result = await relay(gateway, { total: 1000 });
      expect(result.status).toBe(502);
      const body = JSON.parse(result.text);
      expect(body.error.code).toBe("UPLOAD_UPSTREAM_FAILED");
      expect(body.error.message).toContain("the outcome is unconfirmed");

      // The upstream request was destroyed.
      const deadline = Date.now() + 2000;
      while (upstream.closed() < upstream.accepted() && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
      expect(upstream.accepted()).toBe(1);
      expect(upstream.closed()).toBe(1);

      // The same process still serves: health, and a follow-up relay.
      expect(gateway.child.exitCode).toBeNull();
      expect((await request(gateway.port, "GET", "/health")).status).toBe(200);
      await registerJira(gateway, await stub());
      expect((await relay(gateway, { total: 1000 })).status).toBe(201);
      expect(gateway.child.exitCode).toBeNull();
      expect(gateway.output()).toContain("mcp.upload.relayed serverName=jira status=502 bytes=1000 result=upstream_failed");
      expect(gateway.output()).not.toContain("ERR_HTTP_INVALID_STATUS_CODE");
    },
    20_000,
  );

  it("a 50 MB sender without an API key gets a readable 401 and the socket closes within about 5 s", async () => {
    const upstream = await stub();
    const gateway = await spawnGateway({ LOG_LEVEL: "info" });
    await registerJira(gateway, upstream);

    const result = await sendUpload({ port: gateway.port, path: TARGET, total: FIFTY_MB });

    expect(result.status).toBe(401);
    expect(JSON.parse(result.text)).toEqual({ error: "Missing or malformed Authorization header" });
    expect(result.headers.connection).toBe("close");
    const deadline = Date.now() + 6000;
    while (result.socketClosedAt() === null && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    expect(result.socketClosedAt()).not.toBeNull();
    expect(result.socketClosedAt()! - result.finishedAt).toBeLessThan(5500);
    expect(result.written()).toBeLessThan(FIFTY_MB);
    expect(upstream.connections()).toBe(0);
  }, 20_000);
});
