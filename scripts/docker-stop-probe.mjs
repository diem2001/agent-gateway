#!/usr/bin/env node
/**
 * Outcome Probe for MVP-7616: "A stop saves everything and is quick".
 *
 * Builds the image from this checkout, runs one task-owned container on a
 * fresh temp directory mounted at /home/node, and measures `docker stop`:
 *
 *   row 1 (idle):   a session is deleted, `docker stop` follows within 100 ms;
 *                   expect exit 0 within 2 s and the session still deleted
 *                   after `docker start`.
 *   row 2 (stream): a streaming chat answer is opened against a scripted
 *                   Anthropic API that never answers; `docker stop` follows
 *                   within 100 ms of the new session; expect exit 0 within
 *                   9 s and the new session present after `docker start`.
 *
 * Also checks that process 1 in the container is tini and that the gateway
 * listens on 127.0.0.1 only. Writes one evidence JSON (exit codes, durations,
 * session checks, image tag, commit; no environment, no state files).
 *
 * Isolation: never touches the shared agent-gateway container, agent_home or
 * port 3001. Uses `sudo -n docker`, a random image tag and container name, a
 * random API key passed through a 0600 env file, host networking with a free
 * loopback port, and removes only the container ID and image tag it created
 * plus its own temp directories. Exits non-zero at once on a failed check.
 *
 * Usage: npm run probe:docker-stop [-- --evidence <file>]
 */
import { execFile, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { composeRunArgs } from "./lib/compose-security.mjs";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PREFIX = "agw-mvp7616-probe-";
const RAND = randomBytes(4).toString("hex");
const IMAGE = `agw-mvp7616-probe:${RAND}`;
const CONTAINER_NAME = `${PREFIX}${RAND}`;
const API_KEY = randomBytes(24).toString("hex");
const LIMITS = { idle: 2000, stream: 9000 };

const evidenceArg = process.argv.indexOf("--evidence");
const EVIDENCE = evidenceArg > 0 ? path.resolve(process.argv[evidenceArg + 1]) : path.join(os.tmpdir(), `${PREFIX}evidence-${RAND}.json`);

const evidence = { probe: "MVP-7616 docker stop Outcome Probe", image: IMAGE, commit: null, dirty: null, pid1: null, loopbackOnly: null, rows: [] };
let containerId = null;
let imageBuilt = false;
const tempDirs = [];

function log(message) {
  console.log(`[probe] ${message}`);
}

function fail(message) {
  throw new Error(`FAILED: ${message}`);
}

function run(file, args, options = {}) {
  return new Promise((resolve, reject) => {
    execFile(file, args, { maxBuffer: 64 * 1024 * 1024, ...options }, (error, stdout, stderr) => {
      if (error) {
        error.message = `${file} ${args.join(" ")} failed: ${stderr || error.message}`;
        reject(error);
        return;
      }
      resolve(stdout.trim());
    });
  });
}

const docker = (...args) => run("sudo", ["-n", "docker", ...args]);

/** `docker build`, streamed, so a long build is visibly alive. */
function dockerBuild() {
  return new Promise((resolve, reject) => {
    const child = spawn("sudo", ["-n", "docker", "build", "--progress=plain", "-t", IMAGE, REPO_ROOT], { stdio: ["ignore", "inherit", "inherit"] });
    child.on("error", reject);
    child.on("exit", (code) => (code === 0 ? resolve() : reject(new Error(`docker build exited ${code}`))));
  });
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  await new Promise((resolve) => server.close(resolve));
  return port;
}

function request(port, method, urlPath, body) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
    const req = http.request(
      {
        host: "127.0.0.1",
        port,
        method,
        path: urlPath,
        agent: false,
        headers: { Authorization: `Bearer ${API_KEY}`, ...(payload ? { "Content-Type": "application/json", "Content-Length": payload.length } : {}) },
      },
      (res) => {
        let text = "";
        res.on("data", (d) => (text += d));
        res.on("end", () => resolve({ status: res.statusCode, text }));
      },
    );
    req.on("error", reject);
    req.end(payload);
  });
}

async function sessionIds(port) {
  const reply = await request(port, "GET", "/v1/sessions");
  if (reply.status !== 200) fail(`GET /v1/sessions answered ${reply.status}`);
  return JSON.parse(reply.text).sessions.map((s) => s.id);
}

async function waitHealthy(port) {
  const started = Date.now();
  for (;;) {
    const ok = await request(port, "GET", "/health").then((r) => r.status === 200).catch(() => false);
    if (ok) return;
    if (Date.now() - started > 60_000) fail("gateway did not become healthy within 60 s");
    await delay(100);
  }
}

/** A scripted Anthropic API that never answers a message request: the chat answer stays open. */
async function hangingApi() {
  const sockets = new Set();
  let messageRequests = 0;
  const server = http.createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      const pathname = new URL(req.url ?? "/", "http://x").pathname;
      if (pathname === "/v1/messages/count_tokens") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ input_tokens: 10 }));
        return;
      }
      if (pathname.startsWith("/v1/messages")) {
        messageRequests += 1;
        return;
      }
      res.writeHead(404);
      res.end();
    });
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    messageRequests: () => messageRequests,
    close: () =>
      new Promise((resolve) => {
        for (const socket of sockets) socket.destroy();
        server.close(resolve);
      }),
  };
}

/** Opens a streaming POST /v1/query; resolves to its end time once the response closes. */
function openStream(port, sessionId) {
  const payload = Buffer.from(JSON.stringify({ queryId: `q-${RAND}`, prompt: "Say hello.", sessionId, model: "claude-sonnet-4-5" }));
  return new Promise((resolve) => {
    const req = http.request(
      {
        host: "127.0.0.1",
        port,
        method: "POST",
        path: "/v1/query",
        agent: false,
        headers: { Authorization: `Bearer ${API_KEY}`, "Content-Type": "application/json", "Content-Length": payload.length },
      },
      (res) => {
        res.resume();
        res.on("close", () => resolve(Date.now()));
      },
    );
    req.on("error", () => resolve(Date.now()));
    req.end(payload);
  });
}

async function stopContainer() {
  const started = Date.now();
  await docker("stop", containerId);
  const stopMs = Date.now() - started;
  const exitCode = Number(await docker("inspect", "-f", "{{.State.ExitCode}}", containerId));
  return { started, stopMs, exitCode };
}

function nonLoopbackAddress() {
  for (const list of Object.values(os.networkInterfaces())) {
    for (const addr of list ?? []) {
      if (addr.family === "IPv4" && !addr.internal) return addr.address;
    }
  }
  return null;
}

function refused(host, port) {
  return new Promise((resolve) => {
    const socket = net.connect(port, host);
    socket.setTimeout(2000, () => {
      socket.destroy();
      resolve(true);
    });
    socket.once("connect", () => {
      socket.destroy();
      resolve(false);
    });
    socket.once("error", () => resolve(true));
  });
}

function seedHome(home) {
  // The container runs as the node user (uid 1000) like the compose file's `user: node`: the mounted
  // directory must belong to that uid, and the gateway runs the runtime bundled with the Agent SDK.
  fs.mkdirSync(path.join(home, ".claude"), { recursive: true });
  fs.writeFileSync(path.join(home, ".claude", "settings.json"), JSON.stringify({ permissions: { allow: [] } }, null, 2));
  const now = Date.now();
  const sessions = {
    sessions: {
      "probe-idle": { sessionId: "sdk-probe-idle", systemPrompt: "", model: "m", lastUsed: now },
      "probe-keep": { sessionId: "sdk-probe-keep", systemPrompt: "", model: "m", lastUsed: now },
    },
    settings: { sessionIdleTimeoutMs: 0 },
  };
  fs.writeFileSync(path.join(home, ".claude", "sessions.json"), JSON.stringify(sessions, null, 2));
}

function removeOwnTempDir(dir) {
  const real = fs.realpathSync(dir);
  const tmpRoot = fs.realpathSync(os.tmpdir());
  if (path.dirname(real) !== tmpRoot || !path.basename(real).startsWith(PREFIX)) {
    log(`not removing ${real}: outside ${tmpRoot} or without the probe prefix`);
    return;
  }
  fs.rmSync(real, { recursive: true, force: true });
}

async function main() {
  if (typeof process.getuid === "function" && process.getuid() !== 1000) fail("run this probe as uid 1000: the container's node user must own the mounted home");
  evidence.commit = await run("git", ["-C", REPO_ROOT, "rev-parse", "HEAD"]);
  evidence.dirty = (await run("git", ["-C", REPO_ROOT, "status", "--porcelain", "--untracked-files=no"])) !== "";
  await docker("version", "--format", "{{.Server.Version}}");

  log(`building ${IMAGE} from ${REPO_ROOT} at ${evidence.commit}`);
  imageBuilt = true;
  await dockerBuild();

  const home = fs.mkdtempSync(path.join(os.tmpdir(), PREFIX));
  tempDirs.push(home);
  seedHome(home);
  const secrets = fs.mkdtempSync(path.join(os.tmpdir(), `${PREFIX}env-`));
  tempDirs.push(secrets);
  const api = await hangingApi();
  const port = await freePort();
  const envFile = path.join(secrets, "env");
  fs.writeFileSync(
    envFile,
    [
      `API_KEYS=probe:${API_KEY}`,
      `PORT=${port}`,
      "HOST=127.0.0.1",
      `ANTHROPIC_BASE_URL=${api.url}`,
      `ANTHROPIC_API_KEY=sk-ant-probe-${RAND}`,
      "DISABLE_TELEMETRY=1",
      "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1",
      "SESSION_PERSIST_PATH=/home/node/.claude/sessions.json",
      "TOOLS_PERSIST_PATH=/home/node/.claude/tools.json",
      "MCP_SERVERS_PERSIST_PATH=/home/node/.claude/mcp-servers.json",
    ].join("\n") + "\n",
    { mode: 0o600 },
  );

  try {
    // The security profile of the committed compose file (user, capabilities, seccomp, AppArmor, systempaths, pids): agent runs need it.
    containerId = await docker("run", "-d", "--name", CONTAINER_NAME, "--network", "host", ...composeRunArgs(REPO_ROOT), "--env-file", envFile, "-v", `${home}:/home/node`, IMAGE);
    log(`container ${containerId.slice(0, 12)} on 127.0.0.1:${port}`);
    await waitHealthy(port);

    evidence.pid1 = await docker("exec", containerId, "cat", "/proc/1/comm");
    if (evidence.pid1 !== "tini") fail(`process 1 is ${evidence.pid1}, expected tini`);
    const external = nonLoopbackAddress();
    evidence.loopbackOnly = external ? { checkedAddress: "non-loopback IPv4 of this host", refused: await refused(external, port) } : { checkedAddress: "none available", refused: null };
    if (evidence.loopbackOnly.refused === false) fail("the gateway accepts connections on a non-loopback address");

    // Row 1: idle, a session deleted less than 100 ms before the stop.
    if (!(await sessionIds(port)).includes("probe-idle")) fail("seeded session probe-idle is missing");
    const deleted = await request(port, "DELETE", "/v1/sessions/probe-idle");
    if (deleted.status !== 200) fail(`DELETE answered ${deleted.status}`);
    const changedAt = Date.now();
    const idle = await stopContainer();
    await docker("start", containerId);
    await waitHealthy(port);
    const afterIdle = await sessionIds(port);
    const row1 = {
      row: "idle",
      changeToStopMs: idle.started - changedAt,
      exitCode: idle.exitCode,
      stopMs: idle.stopMs,
      limitMs: LIMITS.idle,
      sessionDeletedBeforeStopIsAbsentAfterRestart: !afterIdle.includes("probe-idle"),
      otherSessionPresent: afterIdle.includes("probe-keep"),
    };
    evidence.rows.push(row1);
    log(`row 1: ${JSON.stringify(row1)}`);

    // Row 2: a streaming chat answer that never finishes, a new session less than 100 ms before the stop.
    const streamEnded = openStream(port, "probe-stream");
    const started = Date.now();
    while (!(await sessionIds(port)).includes("probe-stream")) {
      if (Date.now() - started > 10_000) fail("the streaming query did not create its session");
      await delay(5);
    }
    const acceptedAt = Date.now();
    const stream = await stopContainer();
    const streamEndedAt = await streamEnded;
    const apiRequestsBeforeRestart = api.messageRequests();
    await docker("start", containerId);
    await waitHealthy(port);
    const afterStream = await sessionIds(port);
    const row2 = {
      row: "stream open",
      changeToStopMs: stream.started - acceptedAt,
      exitCode: stream.exitCode,
      stopMs: stream.stopMs,
      limitMs: LIMITS.stream,
      streamOpenForMsAfterStop: streamEndedAt - stream.started,
      scriptedApiMessageRequests: apiRequestsBeforeRestart,
      newSessionPresentAfterRestart: afterStream.includes("probe-stream"),
    };
    evidence.rows.push(row2);
    log(`row 2: ${JSON.stringify(row2)}`);

    // Stop the restarted container the same way, for the record (not a scenario row).
    await docker("stop", containerId);
    await api.close();

    const failures = [];
    for (const row of evidence.rows) {
      if (row.changeToStopMs >= 100) failures.push(`${row.row}: change to stop took ${row.changeToStopMs} ms (>= 100)`);
      if (row.exitCode !== 0) failures.push(`${row.row}: exit code ${row.exitCode}`);
      if (row.stopMs >= row.limitMs) failures.push(`${row.row}: stop took ${row.stopMs} ms (limit ${row.limitMs})`);
    }
    if (!row1.sessionDeletedBeforeStopIsAbsentAfterRestart) failures.push("idle: the deleted session is back after restart");
    if (!row1.otherSessionPresent) failures.push("idle: the kept session is missing after restart");
    if (!row2.newSessionPresentAfterRestart) failures.push("stream open: the new session is missing after restart");
    if (row2.streamOpenForMsAfterStop < 7000) failures.push(`stream open: the answer ended ${row2.streamOpenForMsAfterStop} ms after the stop began, not held until the deadline`);
    evidence.result = failures.length === 0 ? "PASS" : "FAIL";
    evidence.failures = failures;
    if (failures.length > 0) fail(failures.join("; "));
  } finally {
    fs.writeFileSync(EVIDENCE, JSON.stringify(evidence, null, 2) + "\n");
    log(`evidence written to ${EVIDENCE}`);
  }
}

async function cleanup() {
  if (containerId) {
    await docker("rm", "-f", containerId).then(() => log(`removed container ${containerId.slice(0, 12)}`), (e) => log(`container cleanup failed: ${e.message}`));
  }
  for (const dir of tempDirs) {
    try {
      removeOwnTempDir(dir);
    } catch (e) {
      log(`temp cleanup failed for ${dir}: ${e.code ?? e.message}`);
    }
  }
  if (imageBuilt) {
    await docker("image", "rm", IMAGE).then(() => log(`removed image ${IMAGE}`), (e) => log(`image cleanup failed: ${e.message}`));
  }
}

let exitCode = 0;
try {
  await main();
  log("PASS");
} catch (e) {
  exitCode = 1;
  console.error(`[probe] ${e.message}`);
} finally {
  await cleanup();
}
process.exit(exitCode);
