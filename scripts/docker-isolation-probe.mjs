#!/usr/bin/env node
/**
 * Docker Outcome Probe for MVP-7678: "the built image, under the committed compose security profile,
 * isolates agent runs".
 *
 * Builds the image from this checkout (bookworm `bubblewrap`) and runs task-owned containers with
 * exactly the `user`, `cap_drop`, `security_opt` and `pids_limit` of the committed docker-compose.yml
 * (read from the file, scripts/lib/compose-security.mjs), synthetic credentials and a scripted model.
 * No shared gateway, no real provider call, no real credential, no shared port or volume.
 *
 *   profile   docker inspect shows the compose options; the gateway process has `NoNewPrivs: 1`,
 *             `CapEff: 0` and a seccomp filter; the compose health command succeeds;
 *   chat      an ordinary chat runs `env | sort` and writes a fixture file; after `docker restart`
 *             the conversation resumes and reads it;
 *   sandbox   from inside a run: process 1 is bwrap, a nested user namespace is refused, `CapEff` 0,
 *             no trusted file, key, clone token or Docker socket, no host path on any command line;
 *   closed    a second container with Docker's default profile reports `isolation: unavailable`,
 *             fails the compose health command, and answers a query with the permanent text and
 *             0 provider requests.
 *
 * Writes one evidence JSON (case names, booleans and counts; never a secret value). Removes only the
 * containers, image tag and temp directories it created.
 *
 * Usage: npm run probe:docker-isolation [-- --evidence <file>]   (run as uid 1000, with `sudo -n docker`)
 */
import { execFile, execFileSync, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { composeRunArgs, readComposeSecurity } from "./lib/compose-security.mjs";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PREFIX = "agw-mvp7678-probe-";
const RAND = randomBytes(4).toString("hex");
const IMAGE = `agw-mvp7678-probe:${RAND}`;
const API_KEY = `SYNTH-GW-KEY-${randomBytes(12).toString("hex")}`;
const PROVIDER_KEY = `SYNTH-PROVIDER-KEY-${randomBytes(12).toString("hex")}`;
const MARKERS = {
  apiKey: API_KEY,
  providerKey: PROVIDER_KEY,
  githubToken: `SYNTH-GITHUB-TOKEN-${randomBytes(12).toString("hex")}`,
  oauthAccess: `SYNTH-OAUTH-ACCESS-${randomBytes(12).toString("hex")}`,
  oauthRefresh: `SYNTH-OAUTH-REFRESH-${randomBytes(12).toString("hex")}`,
  sshKey: `SYNTH-SSH-KEY-${randomBytes(12).toString("hex")}`,
  cloneToken: `SYNTH-CLONE-TOKEN-${randomBytes(12).toString("hex")}`,
};

const evidenceArg = process.argv.indexOf("--evidence");
const EVIDENCE = evidenceArg > 0 ? path.resolve(process.argv[evidenceArg + 1]) : path.join(os.tmpdir(), `${PREFIX}evidence-${RAND}.json`);
const evidence = { probe: "MVP-7678 docker isolation Outcome Probe", image: IMAGE, commit: null, dirty: null, compose: null, rows: [], result: null, failures: [] };
const containers = [];
const tempDirs = [];
let imageBuilt = false;

const log = (message) => console.log(`[probe] ${message}`);
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function run(file, args, options = {}) {
  return new Promise((resolve, reject) => {
    execFile(file, args, { maxBuffer: 64 * 1024 * 1024, ...options }, (error, stdout, stderr) => {
      if (error) {
        error.message = `${file} ${args.join(" ")} failed: ${stderr || error.message}`;
        error.stdout = stdout;
        reject(error);
        return;
      }
      resolve(stdout.trim());
    });
  });
}
const docker = (...args) => run("sudo", ["-n", "docker", ...args]);

function dockerBuild() {
  return new Promise((resolve, reject) => {
    const child = spawn("sudo", ["-n", "docker", "build", "--progress=plain", "-t", IMAGE, REPO_ROOT], { stdio: ["ignore", "inherit", "inherit"] });
    child.on("error", reject);
    child.on("exit", (code) => (code === 0 ? resolve() : reject(new Error(`docker build exited ${code}`))));
  });
}

function row(name, ok, details = {}) {
  evidence.rows.push({ row: name, ok, ...details });
  log(`${ok ? "ok  " : "FAIL"} ${name} ${JSON.stringify(details)}`);
  if (!ok) evidence.failures.push(name);
}

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  await new Promise((resolve) => server.close(resolve));
  return port;
}

function httpRequest(port, method, urlPath, body) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
    const req = http.request(
      { host: "127.0.0.1", port, method, path: urlPath, agent: false, headers: { Authorization: `Bearer ${API_KEY}`, ...(payload ? { "Content-Type": "application/json", "Content-Length": payload.length } : {}) } },
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

async function query(port, body) {
  const reply = await httpRequest(port, "POST", "/v1/query", { model: "claude-sonnet-4-5", useSession: true, ...body });
  return reply.text
    .split("\n")
    .filter((l) => l.trim().startsWith("{"))
    .map((l) => JSON.parse(l));
}

async function health(port) {
  const reply = await httpRequest(port, "GET", "/health").catch(() => null);
  if (!reply || reply.status !== 200) return null;
  return JSON.parse(reply.text);
}

async function waitHealth(port, want) {
  const started = Date.now();
  for (;;) {
    const h = await health(port);
    if (h && (want === undefined || h.isolation === want)) return h;
    if (Date.now() - started > 90_000) throw new Error(`gateway did not reach isolation=${want ?? "any"} within 90 s`);
    await delay(200);
  }
}

/* ------------------------------------------------------------------ */
/*  A scripted Messages API: one Bash or Read call per prompt tag       */
/* ------------------------------------------------------------------ */

async function scriptedApi() {
  const sockets = new Set();
  const results = new Map();
  let messageRequests = 0;
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const pathname = new URL(req.url ?? "/", "http://x").pathname;
      if (pathname === "/v1/messages/count_tokens") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ input_tokens: 10 }));
        return;
      }
      if (!pathname.startsWith("/v1/messages")) {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end("{}");
        return;
      }
      let body = {};
      try {
        body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      } catch {
        // Treated as an empty request.
      }
      const messages = body.messages ?? [];
      const textOf = (m) => (typeof m.content === "string" ? m.content : (m.content ?? []).filter((b) => b.type === "text").map((b) => b.text).join("\n"));
      let lastPromptAt = -1;
      messages.forEach((m, i) => {
        if (m.role === "user" && textOf(m)) lastPromptAt = i;
      });
      const prompt = lastPromptAt >= 0 ? textOf(messages[lastPromptAt]) : "";
      const warmup = prompt.trim() === "Warmup";
      const toolResultsAfter = messages.slice(lastPromptAt + 1).flatMap((m) => (Array.isArray(m.content) ? m.content.filter((b) => b.type === "tool_result") : []));
      const tag = /\[\[(BASH|READ):([A-Za-z0-9+/=_-]+)\]\]/.exec(prompt);
      const model = body.model ?? "claude-sonnet-4-5";
      const usage = { input_tokens: 10, output_tokens: 5, cache_creation_input_tokens: 0, cache_read_input_tokens: 0 };
      let content;
      if (!warmup && tag) messageRequests += 1;
      if (!warmup && tag && toolResultsAfter.length === 0) {
        const value = Buffer.from(tag[2], "base64").toString("utf8");
        content = [{ type: "tool_use", id: `toolu_${randomBytes(6).toString("hex")}`, name: tag[1] === "BASH" ? "Bash" : "Read", input: tag[1] === "BASH" ? { command: value, description: "probe" } : { file_path: value } }];
      } else {
        if (!warmup && tag && toolResultsAfter.length > 0) {
          const r = toolResultsAfter[0];
          const text = typeof r.content === "string" ? r.content : (r.content ?? []).map((b) => b.text ?? "").join("\n");
          results.set(tag[0], { isError: r.is_error === true, text });
        }
        content = [{ type: "text", text: "PROBE-DONE" }];
      }
      const stopReason = content[0].type === "tool_use" ? "tool_use" : "end_turn";
      const messageId = `msg_${randomBytes(6).toString("hex")}`;
      if (body.stream !== true) {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ id: messageId, type: "message", role: "assistant", model, content, stop_reason: stopReason, stop_sequence: null, usage }));
        return;
      }
      res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache" });
      const send = (event, data) => res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
      send("message_start", { type: "message_start", message: { id: messageId, type: "message", role: "assistant", model, content: [], stop_reason: null, stop_sequence: null, usage } });
      content.forEach((block, index) => {
        if (block.type === "tool_use") {
          send("content_block_start", { type: "content_block_start", index, content_block: { ...block, input: {} } });
          send("content_block_delta", { type: "content_block_delta", index, delta: { type: "input_json_delta", partial_json: JSON.stringify(block.input) } });
        } else {
          send("content_block_start", { type: "content_block_start", index, content_block: { type: "text", text: "" } });
          send("content_block_delta", { type: "content_block_delta", index, delta: { type: "text_delta", text: block.text } });
        }
        send("content_block_stop", { type: "content_block_stop", index });
      });
      send("message_delta", { type: "message_delta", delta: { stop_reason: stopReason, stop_sequence: null }, usage: { output_tokens: 5 } });
      send("message_stop", { type: "message_stop" });
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
    results,
    messageRequests: () => messageRequests,
    close: () =>
      new Promise((resolve) => {
        for (const socket of sockets) socket.destroy();
        server.close(resolve);
      }),
  };
}

const bash = (script) => `[[BASH:${Buffer.from(script).toString("base64")}]]`;
const readTool = (file) => `[[READ:${Buffer.from(file).toString("base64")}]]`;

/* ------------------------------------------------------------------ */
/*  Fixture                                                             */
/* ------------------------------------------------------------------ */

function seedHome(home) {
  const claude = path.join(home, ".claude");
  fs.mkdirSync(path.join(claude, "skills", "ok"), { recursive: true });
  fs.writeFileSync(path.join(claude, "settings.json"), JSON.stringify({ permissions: { allow: ["Bash(*)", "Read(*)"] } }));
  fs.writeFileSync(path.join(claude, "CLAUDE.md"), "GLOBAL-MEMORY-OK");
  fs.writeFileSync(path.join(claude, "skills", "ok", "SKILL.md"), "SKILL-OK");
  fs.writeFileSync(path.join(claude, ".credentials.json"), JSON.stringify({ claudeAiOauth: { accessToken: MARKERS.oauthAccess, refreshToken: MARKERS.oauthRefresh, expiresAt: Date.now() + 3_600_000 } }));
  fs.mkdirSync(path.join(home, ".ssh"), { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(home, ".ssh", "id_rsa"), MARKERS.sshKey, { mode: 0o600 });
  // Links planted before the update.
  fs.symlinkSync(path.join(claude, ".credentials.json"), path.join(claude, "skills", "to-credentials"));
  fs.linkSync(path.join(claude, ".credentials.json"), path.join(claude, "skills", "hardlinked-credentials"));
  // A repository with a token clone URL.
  const repo = path.join(claude, "projects", "repo");
  fs.mkdirSync(path.join(repo, "src"), { recursive: true });
  fs.writeFileSync(path.join(repo, "src", "main.txt"), "REPO-OK");
  const git = (...args) => execFileSync("git", ["-C", repo, ...args], { env: { PATH: process.env.PATH, HOME: home, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@example.test", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@example.test" }, stdio: "ignore" });
  git("init", "-q", "-b", "main");
  git("add", ".");
  git("commit", "-q", "-m", "init");
  git("remote", "add", "origin", `https://x-access-token:${MARKERS.cloneToken}@github.com/acme/repo.git`);
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

async function startContainer(name, port, apiUrl, profileArgs) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), `${PREFIX}home-`));
  tempDirs.push(home);
  seedHome(home);
  const secrets = fs.mkdtempSync(path.join(os.tmpdir(), `${PREFIX}env-`));
  tempDirs.push(secrets);
  const envFile = path.join(secrets, "env");
  fs.writeFileSync(
    envFile,
    [
      `API_KEYS=probe:${API_KEY}`,
      `PORT=${port}`,
      "HOST=127.0.0.1",
      `ANTHROPIC_BASE_URL=${apiUrl}`,
      `ANTHROPIC_API_KEY=${PROVIDER_KEY}`,
      `GITHUB_TOKEN=${MARKERS.githubToken}`,
      "DISABLE_TELEMETRY=1",
      "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1",
      "SESSION_PERSIST_PATH=/home/node/.claude/sessions.json",
      "TOOLS_PERSIST_PATH=/home/node/.claude/tools.json",
      "MCP_SERVERS_PERSIST_PATH=/home/node/.claude/mcp-servers.json",
    ].join("\n") + "\n",
    { mode: 0o600 },
  );
  const id = await docker("run", "-d", "--name", name, "--network", "host", ...profileArgs, "--env-file", envFile, "-v", `${home}:/home/node`, IMAGE);
  containers.push(id);
  return { id, home };
}

function inSandbox(text, key) {
  return new RegExp(`${key}=(.*)`).exec(text)?.[1]?.trim();
}

/* ------------------------------------------------------------------ */
/*  Probe                                                               */
/* ------------------------------------------------------------------ */

async function main() {
  if (typeof process.getuid === "function" && process.getuid() !== 1000) throw new Error("run this probe as uid 1000: the container's node user must own the mounted home");
  evidence.commit = await run("git", ["-C", REPO_ROOT, "rev-parse", "HEAD"]);
  evidence.dirty = (await run("git", ["-C", REPO_ROOT, "status", "--porcelain", "--untracked-files=no"])) !== "";
  const compose = readComposeSecurity(REPO_ROOT);
  evidence.compose = { user: compose.user, capDrop: compose.capDrop, securityOpt: compose.securityOpt.map((o) => o.replace(REPO_ROOT, "<repo>")), pidsLimit: compose.pidsLimit };
  evidence.dockerVersion = await docker("version", "--format", "{{.Server.Version}}");

  log(`building ${IMAGE} from ${REPO_ROOT} at ${evidence.commit}`);
  imageBuilt = true;
  await dockerBuild();

  const api = await scriptedApi();
  const port = await freePort();
  const name = `${PREFIX}${RAND}`;
  const { id } = await startContainer(name, port, api.url, composeRunArgs(REPO_ROOT));
  const h = await waitHealth(port, "ok");
  row("gateway reports isolation ok under the committed profile", h.isolation === "ok", { isolation: h.isolation });
  evidence.bwrap = await docker("exec", id, "bwrap", "--version");
  row("the image carries Debian bookworm bubblewrap 0.8", /bubblewrap 0\.8\./.test(evidence.bwrap), { version: evidence.bwrap });

  // Profile as Docker sees it, and as the gateway process lives in it.
  const inspect = JSON.parse(await docker("inspect", id))[0];
  // The Docker CLI reads a seccomp profile file and sends its content: compare the content with the committed file.
  const seccompEntry = compose.securityOpt.find((o) => o.startsWith("seccomp="));
  const committedProfile = JSON.parse(fs.readFileSync(seccompEntry.slice("seccomp=".length), "utf8"));
  const appliedSeccomp = inspect.HostConfig.SecurityOpt.find((o) => o.startsWith("seccomp="));
  const seccompSame = !!appliedSeccomp && JSON.stringify(JSON.parse(appliedSeccomp.slice("seccomp=".length))) === JSON.stringify(committedProfile);
  // Docker stores `systempaths=unconfined` as empty masked and read-only path lists, not as a security option.
  const otherOpts = (list) => list.filter((o) => !o.startsWith("seccomp=") && o !== "systempaths=unconfined").sort();
  const systempathsUnconfined = compose.securityOpt.includes("systempaths=unconfined") ? (inspect.HostConfig.MaskedPaths ?? []).length === 0 && (inspect.HostConfig.ReadonlyPaths ?? []).length === 0 : true;
  const optsSame = JSON.stringify(otherOpts(inspect.HostConfig.SecurityOpt)) === JSON.stringify(otherOpts(compose.securityOpt)) && systempathsUnconfined;
  row("docker inspect: the committed security options, caps dropped, not privileged, pids limit, user", seccompSame && optsSame && JSON.stringify(inspect.HostConfig.CapDrop) === JSON.stringify(compose.capDrop) && inspect.HostConfig.Privileged === false && String(inspect.HostConfig.PidsLimit) === compose.pidsLimit && inspect.Config.User === compose.user, {
    seccompProfileEqualsCommittedFile: seccompSame,
    otherSecurityOpt: otherOpts(inspect.HostConfig.SecurityOpt),
    systempathsUnconfined,
    capDrop: inspect.HostConfig.CapDrop,
    privileged: inspect.HostConfig.Privileged,
    pidsLimit: inspect.HostConfig.PidsLimit,
    user: inspect.Config.User,
  });
  const gatewayPid = (await docker("exec", id, "sh", "-c", "pgrep -f 'node --expose-gc /app/dist/server.js' | head -1")).trim();
  const status = await docker("exec", id, "cat", `/proc/${gatewayPid}/status`);
  const field = (key) => new RegExp(`^${key}:\\s*(.*)$`, "m").exec(status)?.[1];
  row("the gateway process: NoNewPrivs 1, CapEff 0, seccomp filter on, uid 1000", field("NoNewPrivs") === "1" && /^0+$/.test(field("CapEff")) && field("Seccomp") === "2" && /^1000\b/.test(field("Uid")), { NoNewPrivs: field("NoNewPrivs"), CapEff: field("CapEff"), Seccomp: field("Seccomp"), Uid: field("Uid")?.split(/\s+/)[0] });
  const pid1 = await docker("exec", id, "cat", "/proc/1/comm");
  row("process 1 of the container is tini", pid1 === "tini", { pid1 });
  const healthCmd = compose.healthcheck.replace("localhost:3001", `localhost:${port}`);
  const healthOk = await docker("exec", id, "sh", "-c", `${healthCmd} && echo HEALTHY || echo UNHEALTHY`);
  row("the compose health command succeeds while isolation is ok", healthOk === "HEALTHY", { command: "compose healthcheck (port substituted)" });

  // An ordinary chat: `env | sort`, a fixture file, and (after a container restart) a resumed turn.
  const first = await query(port, { queryId: "q-env", sessionId: "conv-docker", prompt: `PROBE-ENV ${bash("env | sort; echo FIXTURE-7678 > /home/node/fixture.txt; echo WROTE")}`, user_id: "user-1" });
  const envResult = api.results.get(bash("env | sort; echo FIXTURE-7678 > /home/node/fixture.txt; echo WROTE"));
  row("an ordinary chat answers and shows its environment", first.at(-1)?.type === "done" && !!envResult && envResult.text.includes("HOME=/home/node") && /ANTHROPIC_API_KEY=mpt_/.test(envResult.text), { done: first.at(-1)?.type === "done" });
  const leaked = Object.entries(MARKERS).filter(([, v]) => (envResult?.text ?? "").includes(v)).map(([k]) => k);
  const surfaces = [JSON.stringify(first), await docker("logs", id).catch(() => "")].join("\n");
  const leakedElsewhere = Object.entries(MARKERS).filter(([k, v]) => k !== "apiKey" && surfaces.includes(v)).map(([k]) => k);
  row("`env | sort` and the events and the gateway log hold no synthetic credential", leaked.length === 0 && leakedElsewhere.length === 0, { markers: Object.keys(MARKERS).length, hitsInResult: leaked.length, hitsInEventsAndLog: leakedElsewhere.length });

  // From inside a run: process, namespace, capability and file rows with their controls.
  const rowsScript = [
    "echo PID1=$(cat /proc/1/comm)",
    "echo UNSHARE_USER=$(unshare -U true >/dev/null 2>&1; echo $?)",
    "echo CAPEFF=$(grep CapEff /proc/self/status | awk '{print $2}')",
    "echo CREDS_FILE=$(test -e /home/node/.claude/.credentials.json && echo yes || echo no)",
    "echo SSH_DIR=$(test -e /home/node/.ssh && echo yes || echo no)",
    "echo SESSIONS_JSON=$(test -e /home/node/.claude/sessions.json && echo yes || echo no)",
    "echo DOCKER_SOCK=$(test -e /var/run/docker.sock && echo yes || echo no)",
    "echo MARKER_FILES=$(grep -rIl --exclude-dir=proc --exclude-dir=sys 'SYNTH-[A-Z]*-[A-Z]*' /home /etc /tmp /var /opt /srv 2>/dev/null | wc -l)",
    "echo PLANTED_LINK=$(cat /home/node/.claude/skills/to-credentials 2>&1 | grep -c SYNTH)",
    "echo PLANTED_HARDLINK_SIZE=$(wc -c < /home/node/.claude/skills/hardlinked-credentials)",
    "echo REMOTE=$(git -C /home/node/.claude/projects/repo remote -v | head -1 | awk '{print $2}')",
    "echo RESOLV=$(test -s /etc/resolv.conf && echo present || echo missing)",
    "echo CMDLINE_HOST_PATHS=$(cat /proc/[0-9]*/cmdline | tr '\\0' ' ' | grep -c '/home/node/.agent-sandbo[x]')",
    "echo CONTROL_MEMORY=$(cat /home/node/.claude/CLAUDE.md)",
    "echo CONTROL_REPO=$(cat /home/node/.claude/projects/repo/src/main.txt)",
    "echo WRITE_REPO=$(touch /home/node/.claude/projects/repo/new 2>/dev/null; echo $?)",
    "echo WRITE_HOME=$(touch /home/node/ok 2>/dev/null; echo $?)",
  ].join("\n");
  const rowsTag = bash(rowsScript);
  const second = await query(port, { queryId: "q-rows", sessionId: "conv-rows", prompt: `PROBE-ROWS ${rowsTag}`, user_id: "user-1" });
  const rows = api.results.get(rowsTag)?.text ?? "";
  const v = (key) => inSandbox(rows, key);
  row("inside a run: process 1 is bwrap, nested user namespaces refused, no capability", second.at(-1)?.type === "done" && v("PID1") === "bwrap" && v("UNSHARE_USER") !== "0" && /^0+$/.test(v("CAPEFF") ?? "x"), { PID1: v("PID1"), UNSHARE_USER: v("UNSHARE_USER"), CAPEFF: v("CAPEFF") });
  row("inside a run: no credential file, SSH directory, state file, Docker socket or marker file; planted link and hardlink reach nothing", v("CREDS_FILE") === "no" && v("SSH_DIR") === "no" && v("SESSIONS_JSON") === "no" && v("DOCKER_SOCK") === "no" && v("MARKER_FILES") === "0" && v("PLANTED_LINK") === "0" && v("PLANTED_HARDLINK_SIZE") === "0", {
    CREDS_FILE: v("CREDS_FILE"),
    SSH_DIR: v("SSH_DIR"),
    SESSIONS_JSON: v("SESSIONS_JSON"),
    DOCKER_SOCK: v("DOCKER_SOCK"),
    MARKER_FILES: v("MARKER_FILES"),
    PLANTED_LINK: v("PLANTED_LINK"),
    PLANTED_HARDLINK_SIZE: v("PLANTED_HARDLINK_SIZE"),
  });
  row("inside a run: the git view shows the URL without the token", v("REMOTE") === "https://github.com/acme/repo.git", { REMOTE: v("REMOTE") });
  row("controls: allowed content readable, repositories read-only, home writable, DNS config present, no host path on a command line", v("CONTROL_MEMORY") === "GLOBAL-MEMORY-OK" && v("CONTROL_REPO") === "REPO-OK" && v("WRITE_REPO") !== "0" && v("WRITE_HOME") === "0" && v("RESOLV") === "present" && v("CMDLINE_HOST_PATHS") === "0", {
    CONTROL_MEMORY: v("CONTROL_MEMORY"),
    CONTROL_REPO: v("CONTROL_REPO"),
    WRITE_REPO: v("WRITE_REPO"),
    WRITE_HOME: v("WRITE_HOME"),
    RESOLV: v("RESOLV"),
    CMDLINE_HOST_PATHS: v("CMDLINE_HOST_PATHS"),
  });
  const rowMarkers = Object.entries(MARKERS).filter(([, val]) => rows.includes(val)).map(([k]) => k);
  row("the rows' own output holds no synthetic credential", rowMarkers.length === 0, { hits: rowMarkers.length });

  // The conversation resumes after a container restart, in its own home.
  await docker("restart", "-t", "10", id);
  await waitHealth(port, "ok");
  const readTag = readTool("/home/node/fixture.txt");
  const resumed = await query(port, { queryId: "q-resume", sessionId: "conv-docker", prompt: `PROBE-RESUME ${readTag}`, user_id: "user-1" });
  const resumedResult = api.results.get(readTag);
  row("after a container restart the conversation resumes and finds its file", resumed.at(-1)?.type === "done" && !!resumedResult && resumedResult.text.includes("FIXTURE-7678"), { done: resumed.at(-1)?.type === "done" });
  const requestsBefore = api.messageRequests();
  const other = await query(port, { queryId: "q-other", sessionId: "conv-docker", prompt: `PROBE-OTHER ${bash("echo should-not-run")}`, user_id: "someone-else" });
  row("another user id is refused with the fixed text and no provider request", other.length === 1 && other[0].type === "error" && other[0].content === "This conversation cannot be continued from your account. Please start a new conversation." && api.messageRequests() === requestsBefore, { events: other.length, providerRequests: api.messageRequests() - requestsBefore });

  // Fail closed: Docker's default profile (same image, same user, no seccomp/AppArmor/systempaths change).
  const closedPort = await freePort();
  const apiClosed = await scriptedApi();
  const closed = await startContainer(`${PREFIX}${RAND}-closed`, closedPort, apiClosed.url, ["--user", compose.user]);
  const hc = await waitHealth(closedPort, "unavailable");
  row("under Docker's default profile the gateway reports isolation unavailable", hc.isolation === "unavailable", { isolation: hc.isolation });
  const closedHealth = await docker("exec", closed.id, "sh", "-c", `${healthCmd.replace(`localhost:${port}`, `localhost:${closedPort}`)} && echo HEALTHY || echo UNHEALTHY`);
  row("and the compose health command fails", closedHealth === "UNHEALTHY", {});
  const refused = await query(closedPort, { queryId: "q-closed", sessionId: "conv-closed", prompt: `PROBE-CLOSED ${bash("echo started")}`, user_id: "user-1" });
  row("and a query gets the permanent text with 0 provider requests and no runtime", refused.length === 1 && refused[0].type === "error" && refused[0].content.startsWith("The gateway cannot start a protected workspace, so this request did not run.") && apiClosed.messageRequests() === 0, { providerRequests: apiClosed.messageRequests() });
  await apiClosed.close();
  await api.close();

  evidence.result = evidence.failures.length === 0 ? "PASS" : "FAIL";
  if (evidence.failures.length > 0) throw new Error(`FAILED rows: ${evidence.failures.join("; ")}`);
}

async function cleanup() {
  for (const id of containers) {
    await docker("rm", "-f", id).then(() => log(`removed container ${id.slice(0, 12)}`), (e) => log(`container cleanup failed: ${e.message}`));
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
  evidence.result = "FAIL";
  console.error(`[probe] ${e.message}`);
} finally {
  fs.writeFileSync(EVIDENCE, JSON.stringify(evidence, null, 2) + "\n");
  log(`evidence written to ${EVIDENCE}`);
  await cleanup();
}
process.exit(exitCode);
