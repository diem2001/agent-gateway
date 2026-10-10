#!/usr/bin/env node
/**
 * Epic Integration Gate (MVP-7677, `npm run probe:epic-integration`): the headline outcome of the Epic MVP-7676, shown on
 * the built image under the committed compose security profile, with representative reqlift and diemcrm callers.
 *
 * One task-owned container on a task-owned `--internal` bridge network (no route out; the container's own loopback is its
 * own, so the live gateway's host port is unreachable from it), home mounted from a task-owned temp directory, synthetic
 * credentials only, OAuth mode like production (no `ANTHROPIC_API_KEY`: the access token is about to expire so the first
 * model call refreshes against a local token double), `MCP_SERVER_OWNERS=jira:reqlift` over a seeded ownerless `jira` entry
 * (the MVP-7925 deploy step), a short upload idle timeout and a finite tool timeout. Every double (scripted model, http MCP
 * servers, webhooks, upload server, token endpoint, an "other origin") is a host process bound to the bridge's gateway
 * address, never `0.0.0.0`; they are the compiled helpers of the vitest suites (`dist/tests/helpers`).
 *
 * Rows (stable ids `EI.*`, printed as `SECURITY-MATRIX` lines and written to the evidence JSON):
 *   profile      docker inspect shows the committed options, `/health` isolation ok, the compose health command succeeds;
 *   auth         query / direct MCP call / upload relay x no key / unknown key / valid key (401 rows count 0 runs, 0 upstream);
 *   registration both labels register their webhook tools; the deploy read-back shows zero ownerless tools and servers;
 *   reqlift      chat with its webhook tool and `jira` under a per-user override, an enforcedTools run refusing Bash, a
 *                credential-free request stdio server, resume; /v1/auth/status; /health as the admin page reads it;
 *   diemcrm      the website-builder shape (no user_id, system_prompt, variant, gatewayMode) with its webhook tool, resume;
 *   skills       the global skill and CLAUDE.md are available to a run;
 *   routes       the eight secret routes from an ordinary chat, before and after `docker restart` (the same probes as the
 *                vitest suites, `dist/tests/helpers/security-routes.js`), request-scoped credentials live in every run;
 *   direct       an authenticated direct MCP call; upload progressing past the idle timeout, upload stalled (504);
 *   legacy       a legacy conversation is refused, then reqlift's delete-and-replay path succeeds;
 *   restart      `docker restart`; both callers resume;
 *   surfaces     zero markers on model-bound bodies, NDJSON, `docker logs`, transcripts and /work; every double received only
 *                its bound credential; the token double saw exactly the refresh token;
 *   cleanup      the probe's own containers, network, image and temp directories are gone.
 *
 * Writes one evidence JSON (case names, booleans and counts; never a secret value) with the revision, the image digest and
 * an overall verdict. Removes only what it created (every docker command is name-guarded, scripts/lib/docker-probe.mjs).
 * The live shared gateway is never touched.
 *
 * Usage: npm run build && npm run probe:epic-integration [-- --evidence <file>]   (uid 1000, `sudo -n docker`)
 */
import { execFileSync } from "node:child_process";
import http from "node:http";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { composeRunArgs, readComposeSecurity } from "./lib/compose-security.mjs";
import { createDockerSession, delay, freePortOn, requireProbeHost } from "./lib/docker-probe.mjs";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const helpers = (name) => import(path.join(REPO_ROOT, "dist", "tests", "helpers", `${name}.js`));
const [matrix, routes, fakeApi, oauthStub, uploadStub, gw] = await Promise.all(["security-matrix", "security-routes", "fake-anthropic-api", "oauth-mcp-stub", "upload-relay-stub", "git-process-gateway"].map(helpers));

const PORT = 3001;
const IDLE_TIMEOUT_MS = 1500;
const TOOL_TIMEOUT_MS = 15_000;
const TURN_MS = 120_000;
/** Read-only references the caller request shapes were taken from (plan part 1). */
const CALLERS = {
  reqlift: { revision: "origin/sprint/2026-09-30@5ff02a9fd78f479d69d206eb8a9861e1fd349182", file: "crates/reqlift-server/src/api/gateway.rs", fields: "queryId, prompt, sessionId, model, user_id, conversation_id, systemPrompt, mcpServers, mcpCredentialOverrides, enforcedTools" },
  diemcrm: { revision: "origin/master@4366204fa7c25cca9e4aade91a321162e186cf68", file: "services/customer-portal/app/Http/Controllers/WebsiteBuilderController.php:256-269,602-615; services/crm/app/Console/Commands/RegisterGatewayToolsCommand.php", fields: "queryId, prompt, sessionId, variant, gatewayMode, system_prompt, model (no user_id); tools registered with PUT /v1/tools/{name}" },
};

const session = createDockerSession({ prefix: "agw-mvp7677-probe-", tagBase: "agw-mvp7677-probe" });
const { names } = session;
const markers = matrix.createMarkers();
markers.values.cloneToken = `SYNTH-CLONETOKEN-${randomBytes(8).toString("hex")}`;
// What the local token endpoint hands out on the one refresh: markers too (a planted copy of the refreshed file must stay invisible).
markers.values.refreshedAccess = `SYNTH-REFRESHEDACCESS-${markers.seed}`;
markers.values.refreshedRefresh = `SYNTH-REFRESHEDREFRESH-${markers.seed}`;
const K = { reqlift: markers.values.gatewayKeyReqlift, diemcrm: markers.values.gatewayKeyDiemcrm };
const UNKNOWN_KEY = `SYNTH-UNKNOWN-KEY-${randomBytes(6).toString("hex")}`;

const evidenceArg = process.argv.indexOf("--evidence");
const EVIDENCE = evidenceArg > 0 ? path.resolve(process.argv[evidenceArg + 1]) : path.join(os.tmpdir(), `${names.ownPrefix}-evidence.json`);
const recorder = new matrix.MatrixRecorder("epic-integration-probe", []);
const evidence = { probe: "MVP-7677 Epic Integration Gate", commit: null, tree: null, trackedChanges: null, image: { tag: names.image, id: null }, runtime: null, callers: CALLERS, configuration: null, deviations: [], rows: [], summary: null, verdict: null, failures: [] };
const say = (message) => console.log(`[probe] ${message}`);

/* ------------------------------------------------------------------ */
/*  Row bookkeeping                                                     */
/* ------------------------------------------------------------------ */

const allTurns = [];
const conversations = new Set();
let model;
const scripts = [];
let ip = null;

function addRow(id, { problems = [], controls = [], surfaces = [], durationMs = 0, deadlineMs = TURN_MS, allowedOn, floors } = {}) {
  const hits = surfaces.flatMap((surface) => {
    const allowed = allowedOn && allowedOn.surface === surface.name ? new Set(allowedOn.markers) : new Set();
    return matrix.detect([surface], Object.fromEntries(Object.entries(markers.values).filter(([name]) => !allowed.has(name))));
  });
  const merged = { ...matrix.SURFACE_FLOORS, ...floors };
  const thin = surfaces.filter((surface) => surface.text.length < (merged[surface.name] ?? 1)).map((surface) => surface.name);
  const all = [...problems, ...(thin.length > 0 ? [`below the byte floor: [${thin.join(", ")}]`] : [])];
  const observed = hits.length === 0 && all.length === 0 ? "pass" : "fail";
  recorder.record({ id, expected: "pass", observed, hits: hits.length, durationMs, deadlineMs, surfaces, controls });
  evidence.rows.push({ id, ok: observed === "pass", hits: hits.length, controls, problems: all, surfaces: surfaces.map((s) => ({ name: s.name, bytes: s.text.length })) });
  if (observed === "fail") evidence.failures.push(`${id}: ${hits.length > 0 ? `hits=${hits.length} [${hits.join(", ")}]` : ""}${all.length > 0 ? ` ${all.join("; ")}` : ""}`.trim());
}

const dockerLogs = () => session.logs(names.container);

/** The sandbox homes of the named conversations in the mounted home (transcripts, `/work`, home). */
function conversationText(home, ids) {
  let saved = {};
  try {
    saved = JSON.parse(fs.readFileSync(path.join(home, ".claude", "sessions.json"), "utf8"));
  } catch {
    return "";
  }
  const dirs = ids.flatMap((id) => [...Object.values(saved.sessionsByLabel ?? {}).map((entries) => entries[id]?.sandboxDirId), saved.sessions?.[id]?.sandboxDirId].filter(Boolean));
  return dirs.map((dirId) => matrix.treeText(path.join(home, ".agent-sandbox", "sessions", dirId)).text).join("\n");
}

/* ------------------------------------------------------------------ */
/*  Fixture                                                             */
/* ------------------------------------------------------------------ */

const put = (file, content, mode) => {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content, mode ? { mode } : undefined);
};

function seedHome(home, doubles) {
  const v = markers.values;
  const ws = path.join(home, ".claude");
  put(path.join(ws, ".credentials.json"), JSON.stringify({ claudeAiOauth: { accessToken: v.oauthAccess, refreshToken: v.oauthRefresh, expiresAt: Date.now() + 1000 } }), 0o600);
  put(path.join(home, ".ssh", "id_rsa"), `-----BEGIN RSA PRIVATE KEY-----\n${v.sshKey}\n-----END RSA PRIVATE KEY-----\n`, 0o600);
  put(path.join(home, ".config", "gh", "hosts.yml"), `github.com:\n  oauth_token: ${v.githubToken}\n`);
  put(path.join(ws, "notes-state.json"), JSON.stringify({ note: v.stateFile }));
  put(path.join(ws, "settings.json"), JSON.stringify({ permissions: { allow: ["Bash(*)", "Read(*)", "Write(*)", "Edit(*)", "Glob(*)", "Grep(*)"] } }));
  put(path.join(ws, "CLAUDE.md"), "GLOBAL-MEMORY-OK");
  put(path.join(ws, "skills", "ok", "SKILL.md"), "---\nname: ok\ndescription: a harmless global skill\n---\nSKILL-OK");
  put(path.join(ws, "agents", "reviewer.md"), "---\nname: reviewer\ndescription: a harmless configured agent\n---\nYou review things. AGENT-OK");
  put(path.join(ws, "projects", "repo", "src", "main.txt"), "REPO-OK");
  const git = (...args) => execFileSync("git", ["-C", path.join(ws, "projects", "repo"), ...args], { env: { PATH: process.env.PATH, HOME: home, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@example.test", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@example.test" }, stdio: "ignore" });
  git("init", "-q", "-b", "main");
  git("add", ".");
  git("commit", "-q", "-m", "init");
  git("remote", "add", "origin", `https://x-access-token:${v.cloneToken}@github.com/acme/repo.git`);
  fs.symlinkSync(path.join(ws, ".credentials.json"), path.join(ws, "skills", "to-credentials"));
  fs.symlinkSync("../.credentials.json", path.join(ws, "skills", "to-credentials-relative"));
  fs.symlinkSync(home, path.join(ws, "projects", "linked-home"));
  // A hardlink and a copy of the credentials file are planted after the one OAuth refresh (plantCopies), when the file holds the values the gateway knows.
  put(path.join(ws, "projects", "-home-node", "sdk-legacy.jsonl"), JSON.stringify({ note: v.legacyTranscript }));
  put(path.join(ws, "sessions.json"), JSON.stringify({ sessions: { "legacy-conv": { sessionId: "gw-legacy", sdkSessionId: "sdk-legacy", systemPrompt: "", model: "m", lastUsed: Date.now() } }, settings: { sessionIdleTimeoutMs: 0 } }));
  // The registry as it was before ownership: an `jira` entry without an owner (the MVP-7925 deploy step assigns it).
  const now = new Date().toISOString();
  put(path.join(ws, "mcp-servers.json"), JSON.stringify([{ name: "jira", description: "", enabled: true, type: "http", url: doubles.jira.url, headers: { Authorization: `Basic ${v.registryHttpHeader}` }, createdAt: now, updatedAt: now }]));
}

/** After the refresh the credentials file holds the refreshed tokens: plant a hardlink and a copy of it where the content plan looks. */
function plantCopies(home) {
  const ws = path.join(home, ".claude");
  fs.linkSync(path.join(ws, ".credentials.json"), path.join(ws, "skills", "hardlinked-credentials"));
  put(path.join(ws, "memory", "copy.md"), `copied ${markers.values.refreshedAccess}`);
}

/* ------------------------------------------------------------------ */
/*  Calls to the container                                              */
/* ------------------------------------------------------------------ */

const call = (method, urlPath, body, key = K.reqlift) => gw.gatewayRequest(PORT, method, urlPath, body, key, ip);

async function health() {
  const res = await call("GET", "/health").catch(() => null);
  return res && res.status === 200 ? res.json : null;
}

async function waitHealth() {
  for (const end = Date.now() + 90_000; Date.now() < end; await delay(200)) {
    ip = await session.containerIp(names.container).catch(() => ip);
    const h = ip ? await health() : null;
    if (h && h.isolation === "ok") return h;
  }
  throw new Error("the gateway did not reach isolation ok within 90 s");
}

/** One chat turn as `label`: the scripted steps run through the real runtime in the container. */
async function turn({ label, prompt, session: sessionId, steps, body = {}, extraPrompts = [], deadlineMs = TURN_MS }) {
  if (steps.length > 0) model.scripts.push(matrix.scriptOf(prompt, steps));
  conversations.add(sessionId);
  const started = Date.now();
  const outcome = await matrix.queryAs(PORT, K[label], { queryId: `q-${sessionId}-${randomBytes(3).toString("hex")}`, prompt, sessionId, useSession: true, ...body }, deadlineMs, undefined, ip);
  const record = { label, prompt, extraPrompts, sessionId, outcome, results: steps.length > 0 ? matrix.resultsFor(model.api, prompt).slice(-steps.length) : [], ms: Date.now() - started };
  allTurns.push(record);
  return record;
}

const done = (t) => t.outcome.events.at(-1)?.type === "done";
const turnSurfaces = (turns, logText) => {
  const prompts = [...new Set(turns.flatMap((t) => [t.prompt, ...t.extraPrompts]))];
  const requests = [...new Set(prompts.flatMap((p) => matrix.requestsFor(model.api, p)))];
  return [
    { name: "tool-results", text: requests.flatMap((r) => r.toolResults.map((x) => x.text)).join("\n") },
    { name: "model-requests", text: requests.map((r) => r.body).join("\n") },
    { name: "events", text: JSON.stringify(turns.map((t) => t.outcome.events)) },
    { name: "gateway-log", text: logText },
    { name: "transcripts", text: conversationText(HOME, [...new Set(turns.map((t) => t.sessionId))]) },
  ];
};

let HOME = null;
let doublesRef = null;
const roleTags = [];

/* ------------------------------------------------------------------ */
/*  Main                                                                */
/* ------------------------------------------------------------------ */

async function main() {
  requireProbeHost(["uid1000", "docker", "space", "build"]);
  const v = markers.values;
  evidence.commit = execFileSync("git", ["-C", REPO_ROOT, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  evidence.tree = execFileSync("git", ["-C", REPO_ROOT, "rev-parse", "HEAD^{tree}"], { encoding: "utf8" }).trim();
  evidence.trackedChanges = execFileSync("git", ["-C", REPO_ROOT, "status", "--porcelain", "--untracked-files=no"], { encoding: "utf8" }).split("\n").filter(Boolean).length;
  evidence.runtime = { ...matrix.runtimeFacts(), docker: await session.docker("version", "--format", "{{.Server.Version}}") };
  const compose = readComposeSecurity(REPO_ROOT);

  say(`building ${names.image} from ${REPO_ROOT} at ${evidence.commit}`);
  await session.build(REPO_ROOT);
  evidence.image.id = await session.docker("image", "inspect", names.image, "--format", "{{.Id}}");

  // The task-owned network and the doubles on its gateway address.
  const gwIp = await session.createNetwork();
  const bind = gwIp;
  const other = await matrix.startCountingDouble({ host: bind });
  const doubles = {
    jira: await oauthStub.startOAuthMcpStub({ toolNames: ["get_page", "update_page"], host: bind }),
    reqHttp: await oauthStub.startOAuthMcpStub({ toolNames: ["get_page"], host: bind }),
    upload: await uploadStub.startUploadStub(undefined, bind),
    webhookReqlift: await matrix.startCountingDouble({ host: bind }),
    webhookDiemcrm: await matrix.startCountingDouble({ host: bind }),
    token: await matrix.startTokenDouble(bind, { access: markers.values.refreshedAccess, refresh: markers.values.refreshedRefresh }),
    feed: await oauthStub.startOAuthMcpStub({ toolNames: ["lookup_record", "delete_record"], host: bind }),
    other,
    redirectMcp: await matrix.startRedirectMcp(other.base, bind),
    redirectHook: await matrix.startCountingDouble({ host: bind, redirectTo: `${other.base}/collected` }),
  };
  doublesRef = doubles;
  const modelApi = await fakeApi.startFakeAnthropicApi({ toolName: "unused-7677", exactTool: scripts, host: bind });
  model = { api: modelApi, scripts };
  const closers = [() => modelApi.close(), ...Object.values(doubles).map((d) => () => d.close())];

  HOME = session.tempDir("home");
  seedHome(HOME, doubles);
  const secrets = session.tempDir("env");
  const envFile = path.join(secrets, "env");
  const envLines = {
    API_KEYS: `reqlift:${K.reqlift},diemcrm:${K.diemcrm}`,
    PORT: String(PORT),
    HOST: "0.0.0.0",
    LOG_LEVEL: "info",
    ANTHROPIC_BASE_URL: modelApi.baseUrl,
    MODEL_PROXY_OAUTH_TOKEN_URL: doubles.token.url,
    DISABLE_TELEMETRY: "1",
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
    SESSION_PERSIST_PATH: "/home/node/.claude/sessions.json",
    TOOLS_PERSIST_PATH: "/home/node/.claude/tools.json",
    MCP_SERVERS_PERSIST_PATH: "/home/node/.claude/mcp-servers.json",
    MCP_SERVER_OWNERS: "jira:reqlift",
    MCP_UPLOAD_IDLE_TIMEOUT_MS: String(IDLE_TIMEOUT_MS),
    AGENT_MCP_TOOL_TIMEOUT_MS: String(TOOL_TIMEOUT_MS),
  };
  fs.writeFileSync(envFile, `${Object.entries(envLines).map(([k, val]) => `${k}=${val}`).join("\n")}\n`, { mode: 0o600 });
  evidence.configuration = { ...Object.fromEntries(Object.entries(envLines).filter(([k]) => !["API_KEYS"].includes(k)).map(([k, val]) => [k, k.endsWith("_URL") ? "<bridge double>" : val])), API_KEYS: "reqlift+diemcrm", mode: "OAuth (no ANTHROPIC_API_KEY)", network: "task-owned --internal bridge, doubles on the bridge gateway address", profile: { ...compose, securityOpt: compose.securityOpt.map((o) => o.replace(REPO_ROOT, "<repo>")) } };
  evidence.deviations.push("the port is not published on 127.0.0.1: an --internal network has no NAT, so the probe reaches the container on its bridge address (the host's loopback services stay unreachable from the container)");

  const id = await session.docker("run", "-d", "--name", names.container, "--network", names.network, ...composeRunArgs(REPO_ROOT), "--env-file", envFile, "-v", `${HOME}:/home/node`, names.image);
  session.ownContainer(id);
  const first = await waitHealth();
  const startedLogs = await dockerLogs();

  /* profile */
  {
    const inspect = JSON.parse(await session.docker("inspect", id))[0];
    const seccompEntry = compose.securityOpt.find((o) => o.startsWith("seccomp="));
    const committed = JSON.parse(fs.readFileSync(seccompEntry.slice("seccomp=".length), "utf8"));
    const applied = inspect.HostConfig.SecurityOpt.find((o) => o.startsWith("seccomp="));
    const seccompSame = !!applied && JSON.stringify(JSON.parse(applied.slice("seccomp=".length))) === JSON.stringify(committed);
    const problems = [];
    if (!seccompSame) problems.push("the applied seccomp profile is not the committed file");
    if (JSON.stringify(inspect.HostConfig.CapDrop) !== JSON.stringify(compose.capDrop) || inspect.HostConfig.Privileged !== false || String(inspect.HostConfig.PidsLimit) !== compose.pidsLimit || inspect.Config.User !== compose.user) problems.push("docker inspect does not show the committed options");
    if (first.isolation !== "ok") problems.push("/health isolation is not ok");
    const healthOk = await session.docker("exec", id, "sh", "-c", `${compose.healthcheck.replace("localhost:3001", `localhost:${PORT}`)} && echo HEALTHY || echo UNHEALTHY`);
    if (healthOk !== "HEALTHY") problems.push("the compose health command failed");
    addRow("EI.profile", { problems, controls: ["committed_security_options_applied", "isolation_ok", "compose_health_command_succeeds"], surfaces: [{ name: "gateway-log", text: startedLogs }] });
  }

  /* registration and the deploy read-back */
  const tools = {
    reqlift: await call("PUT", "/v1/tools/rl_tool", { description: "reqlift webhook tool", input_schema: { type: "object", properties: {} }, webhook_url: `${doubles.webhookReqlift.base}/rl_tool` }, K.reqlift),
    diemcrm: await call("PUT", "/v1/tools/wsb_tool", { description: "diemcrm webhook tool", input_schema: { type: "object", properties: {} }, webhook_url: `${doubles.webhookDiemcrm.base}/wsb_tool` }, K.diemcrm),
    moved: await call("PUT", "/v1/tools/moved_hook", { description: "redirecting hook", input_schema: { type: "object", properties: {} }, webhook_url: `${doubles.redirectHook.base}/moved_hook` }, K.reqlift),
  };
  const register = (label, name, body) => call("PUT", `/v1/mcp-servers/${name}`, body, K[label]);
  const registered = [
    await register("diemcrm", "feed", { type: "http", url: doubles.feed.url, headers: { "X-Api-Key": v.sseHeader } }),
    await register("reqlift", "store", { type: "http", url: doubles.upload.url, headers: { "X-Upload-Credential": v.registryHttpHeader } }),
    await register("diemcrm", "moved", { type: "http", url: doubles.redirectMcp.url, headers: { Authorization: `Basic ${v.registryHttpHeader}` } }),
  ];
  await delay(400);
  {
    const problems = [];
    for (const [name, res] of Object.entries(tools)) if (res.status >= 300) problems.push(`registering the ${name} webhook tool answered ${res.status}`);
    for (const res of registered) if (res.status >= 300) problems.push(`a registry write answered ${res.status}`);
    const logs = await dockerLogs();
    const controls = [];
    if (/mcp\.registry\.owner_assigned serverName=jira/.test(logs)) controls.push("owner_assigned_line_for_jira");
    else problems.push("no owner_assigned line for jira");
    if (/mcp\.registry\.ownerless count=0 /.test(logs)) controls.push("ownerless_mcp_count_0");
    else problems.push("the deploy read-back did not show zero ownerless MCP servers");
    if (!/tools\.legacy\.ownerless count=[1-9]/.test(logs)) controls.push("zero_ownerless_tools");
    else problems.push("the gateway reported ownerless tools");
    const listed = await call("GET", "/v1/tools", undefined, K.reqlift);
    if (listed.status === 200 && ["rl_tool", "wsb_tool", "moved_hook"].every((name) => listed.text.includes(name))) controls.push("both_labels_tools_listed");
    else problems.push("a registered tool is not listed");
    addRow("EI.registration", { problems, controls, surfaces: [{ name: "gateway-log", text: logs }, { name: "caller-body", text: `${listed.text}\n${tools.reqlift.text}\n${tools.diemcrm.text}` }] });
  }

  /* authentication rows */
  {
    const problems = [];
    const controls = [];
    const stub = doubles.jira;
    const upload = doubles.upload;
    const authQuery = { queryId: "q-auth", prompt: "AUTH-PROMPT", model: "claude-sonnet-4-5", useSession: false, enforcedTools: [] };
    const runs = () => new Set(model.api.requests.filter((r) => r.userTexts.some((t) => t.includes("AUTH-PROMPT")) && !r.warmup).map((r) => r.session)).size;
    const rows = [
      ["query", "no key", undefined, 401, 0, 0],
      ["query", "an unknown key", UNKNOWN_KEY, 401, 0, 0],
      ["query", "the valid key", K.reqlift, 200, 1, 0],
      ["direct", "no key", undefined, 401, 0, 0],
      ["direct", "an unknown key", UNKNOWN_KEY, 401, 0, 0],
      ["direct", "the valid key", K.reqlift, 200, 0, 1],
      ["upload", "no key", undefined, 401, 0, 0],
      ["upload", "an unknown key", UNKNOWN_KEY, 401, 0, 0],
      ["upload", "the valid key", K.reqlift, 201, 0, 1],
    ];
    for (const [operation, credential, key, status, expectedRuns, expectedUpstream] of rows) {
      const runsBefore = runs();
      const upBefore = operation === "upload" ? upload.requests.length : stub.requests.filter((r) => r.path === "/mcp").length;
      let result;
      if (operation === "query") result = key === undefined ? await rawJson("POST", "/v1/query", authQuery, undefined) : await rawJson("POST", "/v1/query", authQuery, key);
      else if (operation === "direct") result = await rawJson("POST", "/v1/mcp-servers/jira/call", { tool: "get_page", arguments: { id: "P-1" } }, key);
      else result = await rawUpload(key);
      const upAfter = operation === "upload" ? upload.requests.length : stub.requests.filter((r) => r.path === "/mcp").length;
      const label = `${operation} with ${credential}`;
      if (result.status !== status) problems.push(`${label}: status ${result.status}, expected ${status}`);
      if (runs() - runsBefore !== expectedRuns) problems.push(`${label}: ${runs() - runsBefore} agent run(s), expected ${expectedRuns}`);
      if (upAfter - upBefore !== expectedUpstream) problems.push(`${label}: ${upAfter - upBefore} upstream request(s), expected ${expectedUpstream}`);
      if (result.status === status && runs() - runsBefore === expectedRuns && upAfter - upBefore === expectedUpstream) controls.push(`${operation}_${credential.replace(/\s+/g, "_")}`);
    }
    addRow("EI.auth", { problems, controls, surfaces: [{ name: "gateway-log", text: await dockerLogs() }], floors: {} });
  }

  /* OAuth mode: the first model call refreshed the near-expiry token against the local token endpoint (exactly once) */
  {
    const problems = [];
    const refreshes = doubles.token.refreshTokens;
    const file = fs.readFileSync(path.join(HOME, ".claude", ".credentials.json"), "utf8");
    if (refreshes.length === 1 && refreshes[0] === v.oauthRefresh) {
      // ok
    } else problems.push(`the token endpoint saw ${refreshes.length} refresh(es), expected exactly one with the stored refresh token`);
    if (!file.includes(v.refreshedAccess)) problems.push("the credentials file does not hold the refreshed access token");
    plantCopies(HOME);
    addRow("EI.oauth", { problems, controls: ["one_refresh_against_the_local_token_endpoint", "credentials_file_holds_the_refreshed_token", "hardlink_and_copy_planted_after_the_refresh"], surfaces: [{ name: "gateway-log", text: await dockerLogs() }] });
  }

  /* the callers */
  const credBody = () => ({
    mcpCredentialOverrides: { jira: { headers: { authorization: `Bearer ${v.userOverrideHeader}` } } },
    mcpServers: {
      reqhttp: { type: "http", url: doubles.reqHttp.url, headers: { Authorization: `Bearer ${v.requestHttpHeader}` } },
      reqlocal: { command: "node", args: ["-e", matrix.STDIO_SOURCE], env: { SERVER_TOKEN: v.requestStdioEnv } },
    },
  });
  const bash = (command) => ({ name: "Bash", input: { command, description: "probe" } });
  const logMark = async () => (await dockerLogs()).length;
  const sinceMark = async (mark) => (await dockerLogs()).slice(mark);

  /* reqlift */
  {
    const mark = await logMark();
    const webhookBefore = doubles.webhookReqlift.hits.length;
    const base = { model: "claude-sonnet-4-5", conversation_id: "ui-conv-1", systemPrompt: "You are the reqlift assistant." };
    const jiraBefore = doubles.jira.authorizations().length;
    const chat = await turn({
      label: "reqlift",
      prompt: "RL-CHAT",
      session: "rl-conv",
      steps: [{ name: "mcp__agent-gateway-tools__rl_tool", input: {} }, { name: "mcp__jira__get_page", input: { id: "P-1" } }, bash("env | sort; echo RL-FIXTURE > /work/rl.txt; echo WROTE")],
      body: { ...base, user_id: "user-1", mcpCredentialOverrides: credBody().mcpCredentialOverrides },
    });
    const jiraNow = doubles.jira.authorizations().slice(jiraBefore);
    const enforced = await turn({
      label: "reqlift",
      prompt: "RL-ENFORCED",
      session: "rl-enforced",
      steps: [bash("touch /work/m-enforced; echo RAN"), { name: "mcp__agent-gateway-tools__rl_tool", input: {} }],
      body: { ...base, user_id: "user-1", enforcedTools: ["mcp__agent-gateway-tools__rl_tool"] },
    });
    const chrome = await turn({
      label: "reqlift",
      prompt: "RL-CHROME",
      session: "rl-chrome",
      steps: [{ name: "mcp__chrome-devtools__echo", input: {} }],
      body: { ...base, user_id: "user-1", allowedTools: ["mcp__chrome-devtools__*"], mcpServers: { "chrome-devtools": { command: "node", args: ["-e", matrix.STDIO_SOURCE] } } },
    });
    const resumed = await turn({ label: "reqlift", prompt: "RL-RESUME", session: "rl-conv", steps: [{ name: "Read", input: { file_path: "/work/rl.txt" } }], body: { ...base, user_id: "user-1" } });
    const problems = [];
    for (const t of [chat, enforced, chrome, resumed]) if (!done(t)) problems.push(`${t.prompt}: the stream did not end in done`);
    if (!/RECORD-7667-OK/.test(chat.results[1]?.text ?? "")) problems.push("the per-user jira call did not return its fixture");
    if (!(chat.results[0]?.text ?? "").includes("WEBHOOK-RESULT /rl_tool")) problems.push("the webhook tool did not return its fixture");
    if (!(chat.results[2]?.text ?? "").includes("WROTE") || !/ANTHROPIC_API_KEY=mpt_/.test(chat.results[2]?.text ?? "")) problems.push("Bash did not show the sandbox environment");
    if (!(enforced.results[0]?.isError && enforced.results[0].text.includes("No such tool available: Bash"))) problems.push("the enforcedTools run did not refuse Bash");
    if (!(enforced.results[1]?.text ?? "").includes("WEBHOOK-RESULT")) problems.push("the enforced run's allowed webhook tool did not run");
    if (chrome.results[0]?.text !== "STDIO-RESULT:0") problems.push("the credential-free request stdio server did not answer");
    if (!(resumed.results[0]?.text ?? "").includes("RL-FIXTURE")) problems.push("the resumed conversation did not find its file");
    if (jiraNow.length === 0 || !jiraNow.every((a) => a === `Bearer ${v.userOverrideHeader}`)) problems.push("the jira double did not receive exactly the user's override from the reqlift runs");
    const hooks = doubles.webhookReqlift.hits.slice(webhookBefore);
    if (hooks.length < 2 || !hooks.every((h) => h.authorization === `Bearer ${K.reqlift}`)) problems.push("the reqlift webhook did not receive exactly the caller's own key");
    const status = await call("GET", "/v1/auth/status", undefined, K.reqlift);
    const h = await health();
    const controls = ["chat_with_webhook_tool_and_per_user_jira_override", "enforcedTools_run_refused_bash", "credential_free_request_stdio_server", "resume_found_the_earlier_file"];
    if (status.status === 200 && !status.text.includes(v.oauthAccess) && !status.text.includes(v.oauthRefresh)) controls.push("auth_status_holds_no_oauth_marker");
    else problems.push("/v1/auth/status failed or held an OAuth marker");
    if (h?.isolation === "ok") controls.push("health_isolation_ok_as_the_admin_page_reads_it");
    else problems.push("/health isolation is not ok");
    addRow("EI.reqlift", { problems, controls, surfaces: [...turnSurfaces([chat, enforced, chrome, resumed], await sinceMark(mark)), { name: "caller-body", text: status.text }], floors: { "tool-results": 50 } });
  }

  /* diemcrm */
  {
    const mark = await logMark();
    const hooksBefore = doubles.webhookDiemcrm.hits.length;
    const shape = { model: "claude-sonnet-4-5", variant: "A", gatewayMode: "website-builder", system_prompt: "You build websites." };
    const chat = await turn({ label: "diemcrm", prompt: "DC-CHAT", session: "dc-website-uuid", steps: [{ name: "mcp__agent-gateway-tools__wsb_tool", input: {} }, bash("echo DC-FIXTURE > /work/dc.txt; echo WROTE")], body: shape });
    const resumed = await turn({ label: "diemcrm", prompt: "DC-RESUME", session: "dc-website-uuid", steps: [{ name: "Read", input: { file_path: "/work/dc.txt" } }], body: shape });
    const problems = [];
    for (const t of [chat, resumed]) if (!done(t)) problems.push(`${t.prompt}: the stream did not end in done`);
    if (!(chat.results[0]?.text ?? "").includes("WEBHOOK-RESULT /wsb_tool")) problems.push("the website-builder webhook tool did not return its fixture");
    if (!(resumed.results[0]?.text ?? "").includes("DC-FIXTURE")) problems.push("the resumed website conversation did not find its file");
    const hooks = doubles.webhookDiemcrm.hits.slice(hooksBefore);
    if (hooks.length < 1 || !hooks.every((h) => h.authorization === `Bearer ${K.diemcrm}`)) problems.push("the diemcrm webhook did not receive exactly the caller's own key");
    addRow("EI.diemcrm", { problems, controls: ["website_builder_shape_without_user_id", "webhook_tool_result", "resume_found_the_earlier_file"], surfaces: turnSurfaces([chat, resumed], await sinceMark(mark)), floors: { "tool-results": 50 } });
  }

  /* skills and global memory */
  {
    const mark = await logMark();
    const t = await turn({ label: "reqlift", prompt: "SKILLS-CHAT", session: "skills-conv", steps: [{ name: "Skill", input: { skill: "ok" } }], body: { user_id: "user-1" } });
    const loaded = t.outcome.events.find((e) => e.type === "skills_loaded");
    const requests = matrix.requestsFor(model.api, "SKILLS-CHAT").filter((r) => !r.warmup);
    const problems = [];
    if (!done(t)) problems.push("the stream did not end in done");
    if (!loaded?.skills?.includes("ok")) problems.push("skills_loaded did not list the global skill");
    if (!requests.some((r) => r.userTexts.some((x) => x.includes("SKILL-OK")))) problems.push("the skill's content did not reach the model");
    if (!requests.some((r) => r.body.includes("GLOBAL-MEMORY-OK"))) problems.push("the global CLAUDE.md did not reach the model");
    addRow("EI.skills", { problems, controls: ["global_skill_loaded_and_used", "global_claude_md_in_the_request"], surfaces: turnSurfaces([t], await sinceMark(mark)), floors: { "tool-results": 10 } });
  }

  /* the routes, before the restart */
  const routeRows = {};
  await runRoutes("fresh", routeRows, { phaseFor: () => "probe" });

  /* direct call and the two upload rows */
  {
    const jiraBefore = doubles.jira.authorizations().length;
    const t0 = Date.now();
    const direct = await call("POST", "/v1/mcp-servers/jira/call", { tool: "get_page", arguments: { id: "P-7" }, credentials: { headers: { authorization: `Bearer ${v.userOverrideHeader}` } } }, K.reqlift);
    const problems = [];
    if (direct.status !== 200 || !direct.text.includes("RECORD-7667-OK")) problems.push("the direct call did not return its fixture");
    const seen = doubles.jira.authorizations().slice(jiraBefore);
    if (seen.length === 0 || !seen.every((a) => a === `Bearer ${v.userOverrideHeader}`)) problems.push("the upstream did not receive exactly the user's credential");
    addRow("EI.direct", { problems, controls: ["fixture_returned", "upstream_got_only_the_bound_credential"], surfaces: [{ name: "caller-body", text: direct.text }, { name: "gateway-log", text: (await dockerLogs()).slice(-4000) }], durationMs: Date.now() - t0 });

    const upload = doubles.upload;
    const path1 = "/v1/mcp-servers/store/uploads/jira/issue/MVP-1";
    const t1 = Date.now();
    const progressing = await uploadStub.sendUpload({ host: ip, port: PORT, path: `${path1}?filename=slow.png`, headers: { Authorization: `Bearer ${K.reqlift}` }, total: 8 * 8192, chunkSize: 8192, intervalMs: 500 });
    const problems2 = [];
    if (progressing.status !== 201 || Date.now() - t1 < 2 * IDLE_TIMEOUT_MS) problems2.push("an upload that keeps progressing did not outlast the idle timeout and succeed");
    if (!upload.requests.at(-1)?.complete) problems2.push("the upload server did not receive the whole body");
    addRow("EI.upload.progressing", { problems: problems2, controls: ["upload_outlasted_the_idle_timeout_and_returned_the_servers_answer"], surfaces: [{ name: "caller-body", text: progressing.text }, { name: "gateway-log", text: (await dockerLogs()).slice(-4000) }], durationMs: Date.now() - t1, deadlineMs: 60_000 });
    const t2 = Date.now();
    const stalled = await uploadStub.sendUpload({ host: ip, port: PORT, path: `${path1}?filename=stall.png`, headers: { Authorization: `Bearer ${K.reqlift}` }, total: 1024 * 1024, stallAfter: 64 * 1024 });
    const problems3 = [];
    if (stalled.status !== 504 || !/UPLOAD_TIMEOUT/.test(stalled.text)) problems3.push("a stalled upload was not answered 504 UPLOAD_TIMEOUT");
    for (const end = Date.now() + 5000; !upload.requests.at(-1)?.aborted && Date.now() < end; await delay(100));
    if (!upload.requests.at(-1)?.aborted) problems3.push("the upstream upload request was not aborted");
    addRow("EI.upload.stalled", { problems: problems3, controls: ["504_UPLOAD_TIMEOUT", "upstream_upload_aborted"], surfaces: [{ name: "caller-body", text: stalled.text }, { name: "gateway-log", text: (await dockerLogs()).slice(-4000) }], durationMs: Date.now() - t2, deadlineMs: 60_000 });
  }

  /* legacy refusal, then reqlift's delete-and-replay path */
  {
    const mark = await logMark();
    const before = model.api.requests.length;
    const refused = await matrix.queryAs(PORT, K.reqlift, { queryId: "q-legacy", sessionId: "legacy-conv", prompt: "LEGACY-RESUME", user_id: "user-1", useSession: true }, 15_000, undefined, ip);
    const problems = [];
    const text = "This conversation was started before a gateway security update and cannot be continued safely. Please start a new conversation. Retrying will not help.";
    if (!(refused.events.length === 1 && refused.events[0].type === "error" && refused.events[0].content === text)) problems.push("the legacy conversation was not refused with its exact text");
    if (model.api.requests.length !== before) problems.push("the legacy resume made a model request");
    // MVP-7402: a delete of a conversation from before the isolation update answers 409 legacy_not_erased and keeps the
    // entry, so it is still refused; the caller (reqlift) then rotates to a new conversation id, which runs.
    const deleted = await call("DELETE", "/v1/sessions/legacy-conv", undefined, K.reqlift);
    if (deleted.status !== 409) problems.push(`the delete of the legacy conversation answered ${deleted.status}, expected 409 legacy_not_erased`);
    const replay = await turn({ label: "reqlift", prompt: "LEGACY-REPLAY", session: "legacy-conv-rotated", steps: [bash("echo REPLAYED")], body: { user_id: "user-1" } });
    if (!done(replay) || !(replay.results[0]?.text ?? "").includes("REPLAYED")) problems.push("the replay under a new conversation id did not run");
    addRow("EI.legacy", { problems, controls: ["legacy_refused_with_exact_text_and_no_model_request", "legacy_delete_answered_409", "rotated_replay_succeeded"], surfaces: [{ name: "events", text: JSON.stringify([refused.events, replay.outcome.events]) }, { name: "gateway-log", text: await sinceMark(mark) }, { name: "caller-body", text: refused.raw }] });
  }

  /* docker restart: both callers resume, the routes run again (resumed in their old conversations and in new ones) */
  {
    const t0 = Date.now();
    const mark = await logMark();
    await session.docker("restart", "-t", "10", names.container);
    const after = await waitHealth();
    const problems = [];
    if (after.isolation !== "ok") problems.push("/health isolation is not ok after the restart");
    const rl = await turn({ label: "reqlift", prompt: "RL-AFTER-RESTART", session: "rl-conv", steps: [{ name: "Read", input: { file_path: "/work/rl.txt" } }, { name: "mcp__agent-gateway-tools__rl_tool", input: {} }], body: { user_id: "user-1", model: "claude-sonnet-4-5", conversation_id: "ui-conv-1", systemPrompt: "You are the reqlift assistant." } });
    const dc = await turn({ label: "diemcrm", prompt: "DC-AFTER-RESTART", session: "dc-website-uuid", steps: [{ name: "Read", input: { file_path: "/work/dc.txt" } }, { name: "mcp__agent-gateway-tools__wsb_tool", input: {} }], body: { model: "claude-sonnet-4-5", variant: "A", gatewayMode: "website-builder", system_prompt: "You build websites." } });
    if (!done(rl) || !(rl.results[0]?.text ?? "").includes("RL-FIXTURE") || !(rl.results[1]?.text ?? "").includes("WEBHOOK-RESULT")) problems.push("the reqlift conversation did not resume after the restart");
    if (!done(dc) || !(dc.results[0]?.text ?? "").includes("DC-FIXTURE") || !(dc.results[1]?.text ?? "").includes("WEBHOOK-RESULT")) problems.push("the diemcrm conversation did not resume after the restart");
    const stateKept = await call("GET", "/v1/tools", undefined, K.reqlift);
    if (!stateKept.text.includes("rl_tool")) problems.push("a registered tool did not survive the restart");
    addRow("EI.restart", { problems, controls: ["docker_restart_isolation_ok", "reqlift_resumed", "diemcrm_resumed", "registered_tools_kept"], surfaces: turnSurfaces([rl, dc], await sinceMark(mark)), floors: { "tool-results": 50 }, durationMs: Date.now() - t0 });
    await runRoutes("restarted", routeRows, { phaseFor: (route) => (route === "routing" ? "replay" : "probe") });
  }

  /* the final row: every double's credentials, every agent-side surface */
  {
    const problems = [];
    const controls = [];
    const refreshes = doubles.token.refreshTokens;
    if (refreshes.length === 1 && refreshes[0] === v.oauthRefresh) controls.push("token_double_saw_exactly_one_refresh_with_the_stored_refresh_token");
    else problems.push(`the token double saw ${refreshes.length} refresh(es), not exactly one with the stored refresh token`);
    const providerAuth = model.api.requests.map((r) => r.authorization ?? r.apiKey ?? "");
    if (providerAuth.length > 0 && providerAuth.every((a) => a === `Bearer ${v.refreshedAccess}`)) controls.push("provider_double_received_only_the_refreshed_access_token");
    else problems.push("the provider double received a credential other than the refreshed access token");
    const only = (list, allowed) => list.length > 0 && list.every((a) => allowed.includes(a));
    if (only(doubles.jira.authorizations(), [`Basic ${v.registryHttpHeader}`, `Bearer ${v.userOverrideHeader}`])) controls.push("jira_double_received_only_its_bound_credentials");
    else problems.push("the jira double received an unexpected credential");
    if (only(doubles.reqHttp.authorizations(), [`Bearer ${v.requestHttpHeader}`])) controls.push("request_http_double_received_only_its_credential");
    else problems.push("the request-body http double received an unexpected credential");
    const feedHeaders = doubles.feed.requests.filter((r) => r.path === "/mcp").map((r) => r.headers["x-api-key"]);
    if (only(feedHeaders, [v.sseHeader]) && doubles.feed.toolCalls.every((name) => name === "lookup_record")) controls.push("feed_double_received_only_its_key_and_only_the_granted_tool");
    else problems.push("the feed double received an unexpected credential or an ungranted tool call");
    if (only(doubles.webhookReqlift.hits.map((h) => h.authorization), [`Bearer ${K.reqlift}`]) && only(doubles.webhookDiemcrm.hits.map((h) => h.authorization), [`Bearer ${K.diemcrm}`])) controls.push("each_webhook_received_only_its_callers_own_key");
    else problems.push("a webhook received a key that is not its caller's");
    if (doubles.upload.requests.length > 0 && doubles.upload.requests.every((r) => r.headers["x-upload-credential"] === v.registryHttpHeader)) controls.push("upload_server_received_only_its_stored_credential");
    else problems.push("the upload server received an unexpected credential");
    if (doubles.other.hits.length === 0) controls.push("other_origin_received_nothing");
    else problems.push(`the other origin received ${doubles.other.hits.length} request(s)`);
    if (doubles.redirectHook.hits.length > 0 && doubles.redirectMcp.methods.includes("tools/call")) controls.push("redirecting_servers_were_called_and_their_redirects_not_followed");
    else problems.push("the redirecting MCP server or webhook was never called");
    // The agent-side surfaces of every conversation the callers drove (not the concurrent role conversations: they hold their own marker by design).
    // The runtime also sends side requests that quote a tool command (a command-safety check): those of a role conversation carry its tag.
    const agentRequests = model.api.requests.filter((r) => !r.userTexts.some((t) => t.startsWith("ROLE ")) && !roleTags.some((tag) => r.body.includes(tag)));
    const logs = await dockerLogs();
    for (const r of agentRequests.filter((x) => x.body.includes(v.sessionBFile))) problems.push(`a model request whose first user text starts "${(r.userTexts[0] ?? "").slice(0, 8)}" holds the second-session file marker (${r.userTexts.length} user texts, tools ${r.tools.length})`);
    const surfaces = [
      { name: "tool-results", text: agentRequests.flatMap((r) => r.toolResults.map((x) => x.text)).join("\n") },
      { name: "model-requests", text: agentRequests.map((r) => r.body).join("\n") },
      { name: "events", text: JSON.stringify(allTurns.map((t) => t.outcome.events)) },
      { name: "gateway-log", text: logs },
      { name: "transcripts", text: conversationText(HOME, [...conversations]) },
    ];
    addRow("EI.surfaces", { problems, controls, surfaces, deadlineMs: 0 });
  }

  // The summary rows are those of the routes: every route ran before and after the restart.
  const expected = [...ROUTE_IDS_LIST.flatMap((route) => [`EI.route.${route}.fresh`, `EI.route.${route}.restarted`]), "EI.profile", "EI.registration", "EI.auth", "EI.oauth", "EI.reqlift", "EI.diemcrm", "EI.skills", "EI.direct", "EI.upload.progressing", "EI.upload.stalled", "EI.legacy", "EI.restart", "EI.surfaces"];
  const observed = new Set(recorder.observedIds());
  const missing = expected.filter((rowId) => !observed.has(rowId));
  for (const rowId of missing) evidence.failures.push(`${rowId}: the row never ran`);
  for (const close of closers) await close().catch(() => {});
}

const ROUTE_IDS_LIST = routes.ROUTE_IDS;

function rawJson(method, urlPath, body, key) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
    const req = http.request({ host: ip, port: PORT, method, path: urlPath, agent: false, headers: { ...(key ? { Authorization: `Bearer ${key}` } : {}), ...(payload ? { "Content-Type": "application/json", "Content-Length": payload.length } : {}) } }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode, text: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("error", reject);
    req.end(payload);
  });
}

async function rawUpload(key) {
  return uploadStub.sendUpload({ host: ip, port: PORT, path: "/v1/mcp-servers/store/uploads/jira/issue/MVP-1?filename=shot.png", headers: key ? { Authorization: `Bearer ${key}` } : {}, total: 64 * 1024 });
}

/** The eight routes from an ordinary chat in the container, with the request-scoped credentials live; proc and session run beside concurrent conversations. */
async function runRoutes(mode, rows, { phaseFor }) {
  const v = markers.values;
  const credentialBody = () => ({
    allowedTools: matrix.ROUTE_ALLOWED_TOOLS,
    mcpCredentialOverrides: { jira: { headers: { authorization: `Bearer ${v.userOverrideHeader}` } } },
    mcpServers: {
      reqhttp: { type: "http", url: modelHostDoubles().reqHttp.url, headers: { Authorization: `Bearer ${v.requestHttpHeader}` } },
      reqlocal: { command: "node", args: ["-e", matrix.STDIO_SOURCE], env: { SERVER_TOKEN: v.requestStdioEnv } },
    },
  });
  const ctxFor = (phase) => ({ markers, host: { workspace: "/home/node/.claude", home: "/home/node", persist: "/home/node/.claude" }, gatewayPort: PORT, canary: `SYNTH-CANARY-${markers.seed}`, phase, afterRestart: mode === "restarted" });
  const countProcs = async (tag) => Number(await session.docker("exec", names.container, "sh", "-c", `pgrep -fc '[${tag[0]}]${tag.slice(1)}' || true`).catch(() => "0")) || 0;
  for (const route of routes.ROUTE_IDS) {
    const started = Date.now();
    const mark = (await dockerLogs()).length;
    const phase = phaseFor(route);
    const ctx = ctxFor(phase);
    // The restarted mode resumes the conversation of the fresh mode (the routing replay needs the files its probe left in /work).
    const sessionId = `route-${route}-fresh`;
    const prompt = `ROUTE-${route}-${mode}`;
    let role = null;
    if (route === "proc" || route === "session") role = await startRole(route);
    const steps = [...routes.credentialSteps(), ...routes.routeSteps(route, ctx)];
    const before = role ? await countProcs(role.tag) : 0;
    const turnRecord = await turn({ label: "reqlift", prompt, session: sessionId, steps, body: { user_id: "user-1", ...credentialBody() } });
    const after = role ? await countProcs(role.tag) : 0;
    if (role) await stopRole(role);
    const probe = turnRecord.results[routes.credentialSteps().length];
    const verdict = routes.verifyRoute(route, probe?.text ?? "", ctx);
    const problems = [...verdict.failures];
    if (!done(turnRecord)) problems.push("the stream did not end in done");
    const jira = turnRecord.results[0];
    if (!jira || jira.isError || !jira.text.includes("RECORD-7667-OK")) problems.push("the per-user override fixture did not answer");
    if (turnRecord.results[2]?.text !== `STDIO-RESULT:${v.requestStdioEnv.length}`) problems.push("the request-body stdio fixture did not answer");
    if (role && !(before > 0 && after > 0)) problems.push("the concurrent conversation did not overlap the scan");
    const controls = [...verdict.controls, ...(role && before > 0 && after > 0 ? ["concurrent_conversation_overlapped_the_scan"] : [])];
    addRow(`EI.route.${route}.${mode}`, { problems, controls, surfaces: turnSurfaces([turnRecord], (await dockerLogs()).slice(mark)), durationMs: Date.now() - started });
    rows[`${route}.${mode}`] = verdict;
  }
}

/** A concurrent conversation of the other label that holds its marker in `/work` until stopped. */
async function startRole(route) {
  const v = markers.values;
  const tag = `ROLE-${route}-${randomBytes(3).toString("hex")}`;
  roleTags.push(tag);
  const file = route === "session" ? "b-secret.txt" : "b-proc.txt";
  const sessionId = `role-${tag}`;
  const command = `python3 -c ${matrix.shellQuote(`import os, sys, time\nopen('/work/${file}', 'w').write(sys.argv[1])\nend = time.time() + 150\nwhile time.time() < end and not os.path.exists('/work/stop'):\n    time.sleep(0.2)`)} ${matrix.shellQuote(v.sessionBFile)} ${tag}`;
  const prompt = `ROLE ${v.sessionBTurn} ${tag}`;
  model.scripts.push(matrix.scriptOf(prompt, [{ name: "Bash", input: { command, description: "role" } }]));
  const outcome = matrix.queryAs(PORT, K.diemcrm, { queryId: `q-${tag}`, sessionId, prompt, user_id: "user-b", useSession: true, enforcedTools: ["Bash"], model: "claude-sonnet-4-5" }, 200_000, undefined, ip);
  for (const end = Date.now() + 60_000; ; await delay(200)) {
    if ((Number(await session.docker("exec", names.container, "sh", "-c", `pgrep -fc '[${tag[0]}]${tag.slice(1)}' || true`).catch(() => "0")) || 0) > 0) break;
    if (Date.now() > end) throw new Error("the concurrent conversation did not start");
  }
  return { tag, sessionId, outcome };
}

async function stopRole(role) {
  let saved = {};
  try {
    saved = JSON.parse(fs.readFileSync(path.join(HOME, ".claude", "sessions.json"), "utf8"));
  } catch {
    // Not persisted yet.
  }
  const dirId = Object.values(saved.sessionsByLabel ?? {}).map((entries) => entries[role.sessionId]?.sandboxDirId).find(Boolean);
  if (dirId) fs.writeFileSync(path.join(HOME, ".agent-sandbox", "sessions", dirId, "work", "stop"), "stop");
  await role.outcome;
}

function modelHostDoubles() {
  return doublesRef;
}

/* ------------------------------------------------------------------ */
/*  Run                                                                 */
/* ------------------------------------------------------------------ */

let exitCode = 0;
try {
  await main();
  evidence.summary = recorder.summary();
  if (evidence.failures.length > 0) throw new Error(`${evidence.failures.length} failure(s): ${evidence.failures.join(" | ")}`);
  evidence.verdict = "PASS";
} catch (error) {
  exitCode = 1;
  evidence.verdict = "FAIL";
  evidence.summary ??= recorder.summary();
  console.error(`[probe] ${error.message}`);
} finally {
  const left = await session.cleanup(say).catch((error) => ({ error: error.message }));
  const clean = left && left.containers === 0 && left.networks === 0 && left.images === 0 && left.tempDirs === 0;
  evidence.cleanup = left;
  evidence.rows.push({ id: "EI.cleanup", ok: clean, controls: ["own_containers_networks_images_and_temp_directories_removed"], problems: clean ? [] : [`left behind: ${JSON.stringify(left)}`] });
  say(`EI.cleanup ${clean ? "ok" : "FAIL"} ${JSON.stringify(left)}`);
  if (!clean) {
    exitCode = 1;
    evidence.verdict = "FAIL";
    evidence.failures.push("EI.cleanup: resources of the probe remain");
  }
  fs.writeFileSync(EVIDENCE, `${JSON.stringify(evidence, null, 2)}\n`);
  matrix.emit(`EPIC-INTEGRATION-RESULT verdict=${evidence.verdict} commit=${evidence.commit} image=${evidence.image.id} rows=${evidence.rows.length} failures=${evidence.failures.length} evidence=${EVIDENCE}`);
}
process.exit(exitCode);
