/**
 * Outcome Probe for MVP-7678: "an ordinary chat running `env | sort`, and resuming, gets its result
 * while no synthetic credential reaches any output".
 *
 * The compiled gateway runs as a child process with the production Claude runtime and real bwrap.
 * A fixture holds a synthetic marker in every place the Story names: both API keys, the provider
 * key (API-key mode) or the OAuth file's access and refresh tokens (OAuth mode), a registered http
 * MCP server's header, `~/.ssh`, a token clone URL, symlinks planted before the update, another
 * conversation's home, a legacy transcript and the state files. A scripted model drives an ordinary
 * chat with no agent and no skill: turn 1 runs `env | sort` and writes a fixture file, turn 2
 * resumes the conversation and reads the file. A route matrix then tries every way an agent can
 * reach a secret. Observation: the raw Bash and Read outputs, the model-bound request bodies, the
 * NDJSON events, the gateway log and the conversation's own home (transcripts). Assertion: the
 * fixture result arrives and the resumed turn has the prior context; every marker has 0 matches on
 * every surface; a deliberately leaking negative control is caught by the same detector; the
 * fail-closed rows end with the exact text within their deadline and 0 runtime starts.
 *
 * The two S2 residual rows (a stdio server's env value and an SSE server's header, which the SDK
 * puts on the runtime's command line) are reported separately and are NOT counted as passes.
 *
 * Needs `npm run build`, `bwrap` and user namespaces. Linux only. Only case names and counts are
 * printed (`OUTCOME-MATRIX ...`); never a marker value.
 */
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { afterEach, describe, expect, it, vi } from "vitest";
import { startFakeAnthropicApi, type ExactToolScript, type FakeAnthropicApi } from "./helpers/fake-anthropic-api.js";
import { descendants, gatewayRequest, spawnGateway, type Cleanup, type SpawnedGateway } from "./helpers/git-process-gateway.js";
import { startOAuthMcpStub, type OAuthMcpStub } from "./helpers/oauth-mcp-stub.js";

vi.setConfig({ testTimeout: 180_000 });

const KEY_ALPHA = "SYNTH-API-KEY-ALPHA-7678";
const KEY_BETA = "SYNTH-API-KEY-BETA-7678";
const PROVIDER_KEY = "SYNTH-PROVIDER-KEY-7678-outcome";
const OAUTH_ACCESS = "SYNTH-OAUTH-ACCESS-7678-outcome";
const OAUTH_REFRESH = "SYNTH-OAUTH-REFRESH-7678-outcome";
const REGISTRY_HEADER = "SYNTH-REGISTRY-HEADER-7678";
const SSH_KEY = "SYNTH-SSH-PRIVATE-KEY-7678-outcome";
const CLONE_TOKEN = "SYNTH-CLONE-TOKEN-7678-outcome";
const STATE_MARKER = "SYNTH-STATE-FILE-7678-outcome";
const LEGACY_MARKER = "SYNTH-LEGACY-TRANSCRIPT-7678-outcome";
const OTHER_SESSION_MARKER = "SYNTH-OTHER-SESSION-7678-outcome";
const STDIO_ENV = "SYNTH-STDIO-ENV-7678";
const SSE_HEADER = "SYNTH-SSE-HEADER-7678";

/** The S1 markers: every one must have 0 matches on every agent-side surface. */
const MARKERS: Record<string, string> = {
  apiKeyAlpha: KEY_ALPHA,
  apiKeyBeta: KEY_BETA,
  providerKey: PROVIDER_KEY,
  oauthAccess: OAUTH_ACCESS,
  oauthRefresh: OAUTH_REFRESH,
  registryHeader: REGISTRY_HEADER,
  sshKey: SSH_KEY,
  cloneToken: CLONE_TOKEN,
  stateFile: STATE_MARKER,
  legacyTranscript: LEGACY_MARKER,
  otherSession: OTHER_SESSION_MARKER,
};

const cleanups: Cleanup[] = [];
afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()!();
});

/** One evidence line (case names and counts only). Written to stderr, which the runner log keeps for passing tests. */
function report(line: string): void {
  process.stderr.write(`${line}\n`);
}

interface Surface {
  name: string;
  text: string;
}

/** The detector: which (surface, marker) pairs match. Used for the matrix and for the negative control. */
export function detect(surfaces: Surface[], markers: Record<string, string> = MARKERS): string[] {
  const hits: string[] = [];
  for (const surface of surfaces) {
    for (const [name, value] of Object.entries(markers)) if (surface.text.includes(value)) hits.push(`${surface.name}:${name}`);
  }
  return hits;
}

interface Ndjson {
  type: string;
  content?: string;
  [key: string]: unknown;
}

function queryAs(port: number, key: string, body: Record<string, unknown>): Promise<Ndjson[]> {
  return new Promise((resolve, reject) => {
    const payload = Buffer.from(JSON.stringify({ model: "claude-sonnet-4-5", ...body }), "utf8");
    const req = http.request(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/query", agent: false, headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json", "Content-Length": payload.length } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve(
            Buffer.concat(chunks)
              .toString("utf8")
              .split("\n")
              .filter((l) => l.trim().startsWith("{"))
              .map((l) => JSON.parse(l) as Ndjson),
          ),
        );
      },
    );
    req.on("error", reject);
    req.end(payload);
  });
}

function write(file: string, content: string): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content);
}

function requestsFor(api: FakeAnthropicApi, prompt: string) {
  return api.requests.filter((r) => r.userTexts.some((t) => t.includes(prompt)));
}

/** The tool results of the latest turn of the conversation whose latest prompt is `prompt`. */
function lastResults(api: FakeAnthropicApi, prompt: string): string[] {
  const matching = api.requests.filter((r) => r.userTexts.at(-1)?.includes(prompt) && !r.warmup);
  return (matching.at(-1)?.toolResults ?? []).map((r) => r.text);
}

function conversationHomes(gateway: SpawnedGateway, onlyFor: string[]): string[] {
  const saved = JSON.parse(fs.readFileSync(path.join(gateway.dirs.persist, "sessions.json"), "utf8")) as { sessions: Record<string, { sandboxDirId?: string }> };
  return onlyFor.flatMap((id) => (saved.sessions[id]?.sandboxDirId ? [path.join(gateway.dirs.home, ".agent-sandbox", "sessions", saved.sessions[id].sandboxDirId!, "home")] : []));
}

function homeText(home: string): string {
  let text = "";
  const walk = (dir: string): void => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile() && fs.statSync(full).size < 4 * 1024 * 1024) text += `\n${fs.readFileSync(full, "utf8")}`;
    }
  };
  walk(home);
  return text;
}

const bash = (prompt: string, command: string): ExactToolScript => ({ name: "Bash", prompt, input: { command, description: "probe" } });
const read = (prompt: string, file: string): ExactToolScript => ({ name: "Read", prompt, input: { file_path: file } });

interface Fixture {
  api: FakeAnthropicApi;
  gateway: SpawnedGateway;
  mcp: OAuthMcpStub;
  scripts: ExactToolScript[];
}

/** The fixture gateway: markers in every named place. `mode` picks the provider credential source. */
async function fixture(mode: "api-key" | "oauth", routeScripts: (gateway: SpawnedGateway) => ExactToolScript[], extraEnv: Record<string, string> = {}): Promise<Fixture> {
  const scripts: ExactToolScript[] = [];
  const api = await startFakeAnthropicApi({ toolName: "unused-7678", exactTool: scripts });
  cleanups.push(() => api.close());
  const mcp = await startOAuthMcpStub({ toolNames: ["get_page"] });
  cleanups.push(() => mcp.close());
  const gateway = await spawnGateway(cleanups, {
    rootPrefix: "mvp7678-outcome-",
    env: {
      API_KEYS: `alpha:${KEY_ALPHA},beta:${KEY_BETA}`,
      ANTHROPIC_BASE_URL: api.baseUrl,
      ...(mode === "api-key" ? { ANTHROPIC_API_KEY: PROVIDER_KEY } : {}),
      DISABLE_TELEMETRY: "1",
      CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
      ...extraEnv,
    },
    seed: (dirs) => {
      // The OAuth file exists in both modes; in API-key mode the gateway's key is used and the file stays unused.
      write(path.join(dirs.workspace, ".credentials.json"), JSON.stringify({ claudeAiOauth: { accessToken: OAUTH_ACCESS, refreshToken: OAUTH_REFRESH, expiresAt: Date.now() + 3_600_000 } }));
      write(path.join(dirs.home, ".ssh", "id_rsa"), SSH_KEY);
      write(path.join(dirs.workspace, "tools.json"), "[]");
      write(path.join(dirs.workspace, "notes-state.json"), JSON.stringify({ note: STATE_MARKER }));
      write(path.join(dirs.workspace, "CLAUDE.md"), "GLOBAL-MEMORY-OK");
      write(path.join(dirs.workspace, "skills", "ok", "SKILL.md"), "SKILL-OK");
      // A repository whose configuration holds a token clone URL.
      write(path.join(dirs.workspace, "projects", "repo", "src", "main.txt"), "REPO-OK");
      const git = (...args: string[]) =>
        execFileSync("git", ["-C", path.join(dirs.workspace, "projects", "repo"), ...args], { env: { PATH: process.env.PATH ?? "", HOME: dirs.home, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@example.test", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@example.test" }, stdio: "ignore" });
      git("init", "-q", "-b", "main");
      git("add", ".");
      git("commit", "-q", "-m", "init");
      git("remote", "add", "origin", `https://x-access-token:${CLONE_TOKEN}@github.com/acme/repo.git`);
      // Links and copies planted before the update.
      fs.symlinkSync(path.join(dirs.workspace, ".credentials.json"), path.join(dirs.workspace, "skills", "to-credentials"));
      fs.symlinkSync("../.credentials.json", path.join(dirs.workspace, "skills", "to-credentials-relative"));
      fs.symlinkSync(dirs.home, path.join(dirs.workspace, "projects", "linked-home"));
      fs.linkSync(path.join(dirs.workspace, ".credentials.json"), path.join(dirs.workspace, "skills", "hardlinked-credentials"));
      write(path.join(dirs.workspace, "memory", "copy.md"), `copied ${OAUTH_ACCESS}`);
      // A legacy conversation and its transcript.
      write(path.join(dirs.workspace, "projects", "-home-node", "sdk-legacy.jsonl"), JSON.stringify({ note: LEGACY_MARKER }));
      write(path.join(dirs.persist, "sessions.json"), JSON.stringify({ sessions: { "legacy-conv": { sessionId: "gw-legacy", sdkSessionId: "sdk-legacy", systemPrompt: "", model: "m", lastUsed: Date.now() } }, settings: { sessionIdleTimeoutMs: 0 } }));
    },
  });
  scripts.push(...routeScripts(gateway));
  return { api, gateway, mcp, scripts };
}

/** A registered http MCP server whose header is a marker: reached through the credential relay only. */
async function registerWithAlpha(f: Fixture): Promise<void> {
  const res = await new Promise<number>((resolve, reject) => {
    const payload = Buffer.from(JSON.stringify({ type: "http", url: f.mcp.url, headers: { Authorization: `Bearer ${REGISTRY_HEADER}` } }));
    const req = http.request({ host: "127.0.0.1", port: f.gateway.port, method: "PUT", path: "/v1/mcp-servers/jira", agent: false, headers: { Authorization: `Bearer ${KEY_ALPHA}`, "Content-Type": "application/json", "Content-Length": payload.length } }, (r) => {
      r.resume();
      r.on("end", () => resolve(r.statusCode ?? 0));
    });
    req.on("error", reject);
    req.end(payload);
  });
  expect([200, 201]).toContain(res);
}

const PROMPTS = {
  turn1: "OUTCOME-TURN1",
  turn2: "OUTCOME-TURN2",
  interpreters: "OUTCOME-INTERPRETERS",
  readCreds: "OUTCOME-READ-CREDS",
  readHostCreds: "OUTCOME-READ-HOSTCREDS",
  readSsh: "OUTCOME-READ-SSH",
  readState: "OUTCOME-READ-STATE",
  grep: "OUTCOME-GREP",
  glob: "OUTCOME-GLOB",
  planted: "OUTCOME-PLANTED",
  mcp: "OUTCOME-MCP",
  other: "OUTCOME-OTHER-SESSION",
};

/** The scripted conversation and route matrix for one gateway. */
function scriptsFor(gateway: SpawnedGateway): ExactToolScript[] {
  const ws = gateway.dirs.workspace;
  return [
    // The Scenario: an ordinary chat, no agent, no skill. Turn 1 shows the environment and writes a fixture; turn 2 resumes and reads it.
    bash(PROMPTS.turn1, "env | sort; echo FIXTURE-RESULT-7678 > /home/node/fixture.txt; echo WROTE-FIXTURE"),
    read(PROMPTS.turn2, "/home/node/fixture.txt"),
    // The route matrix.
    bash(PROMPTS.interpreters, `python3 -c "import os; print(dict(os.environ))"; node -e "console.log(JSON.stringify(process.env))"; perl -e 'print join(",", %ENV)'; sh -c env; cat /proc/self/environ | tr '\\0' '\\n'; cat /proc/[0-9]*/environ 2>/dev/null | tr '\\0' '\\n'`),
    read(PROMPTS.readCreds, "/home/node/.claude/.credentials.json"),
    read(PROMPTS.readHostCreds, path.join(ws, ".credentials.json")),
    read(PROMPTS.readSsh, path.join(gateway.dirs.home, ".ssh", "id_rsa")),
    read(PROMPTS.readState, path.join(gateway.dirs.persist, "sessions.json")),
    { name: "Grep", prompt: PROMPTS.grep, input: { pattern: "SYNTH-[A-Z]+-", path: "/home", output_mode: "content" } },
    { name: "Glob", prompt: PROMPTS.glob, input: { pattern: "**/*credentials*", path: "/home" } },
    bash(PROMPTS.planted, "cd /home/node/.claude; cat skills/to-credentials skills/to-credentials-relative skills/hardlinked-credentials memory/copy.md 2>&1; ls projects; cat projects/linked-home/.ssh/id_rsa 2>&1; grep -rh 'x-access-token' projects 2>&1; git -C projects/repo remote -v; ln -s /home/node/.claude/.credentials.json /home/node/plant; cat /home/node/plant 2>&1"),
    { name: "mcp__jira__get_page", prompt: PROMPTS.mcp, input: {} },
    bash(PROMPTS.other, "grep -rl --exclude-dir=proc --exclude-dir=sys 'SYNTH-OTHER-SESSIO[N]' / 2>/dev/null | wc -l; find / -xdev -name 'b-secret.tx[t]' 2>/dev/null | wc -l"),
  ];
}

const FIXED_TEXTS = {
  unavailable: (id: string) =>
    `The gateway cannot start a protected workspace, so this request did not run. Ask your gateway administrator to check the gateway's isolation status. Retrying will not help until the administrator has done this. (reference: ${id})`,
  otherOwner: "This conversation cannot be continued from your account. Please start a new conversation.",
  legacy: "This conversation was started before a gateway security update and cannot be continued safely. Please start a new conversation. Retrying will not help.",
  busy: "This conversation is still answering an earlier request. Please wait until it has finished, then try again.",
};

describe.each([["api-key" as const], ["oauth" as const]])("the Outcome Probe, provider credential in %s mode", (mode) => {
  it("an ordinary chat shows its environment and resumes, and no synthetic credential reaches any surface", async () => {
    const f = await fixture(mode, scriptsFor);
    await registerWithAlpha(f);
    // Another conversation's home holds its own marker (created by another owner, at the same time as nothing else runs).
    f.scripts.push(bash("OUTCOME-SESSION-B", "echo SYNTH-OTHER-SESSION-7678-outcome > /home/node/b-secret.txt; echo B-WROTE"));
    const port = f.gateway.port;
    const events: Record<string, Ndjson[]> = {};
    const t = async (id: string, prompt: string, sessionId: string, key = KEY_ALPHA, user = "user-1"): Promise<Ndjson[]> => {
      const result = await queryAs(port, key, { queryId: `q-${id}`, sessionId, prompt, user_id: user, useSession: true });
      events[id] = result;
      return result;
    };

    const b = await t("B", "OUTCOME-SESSION-B", "conv-B", KEY_BETA, "user-b");
    expect(b.at(-1)?.type, JSON.stringify(b.at(-1))).toBe("done");

    // Scenario: turn 1 (`env | sort` and a fixture file) then turn 2 resumes the conversation and reads the file.
    const started = Date.now();
    const turn1 = await t("turn1", PROMPTS.turn1, "conv-outcome");
    expect(turn1.at(-1)?.type, JSON.stringify(turn1.at(-1))).toBe("done");
    const env = lastResults(f.api, PROMPTS.turn1)[0] ?? "";
    expect(env).toContain("HOME=/home/node");
    expect(env).toMatch(/ANTHROPIC_API_KEY=mpt_/);
    expect(env).toContain("WROTE-FIXTURE");
    const turn2 = await t("turn2", PROMPTS.turn2, "conv-outcome");
    expect(turn2.at(-1)?.type, JSON.stringify(turn2.at(-1))).toBe("done");
    expect(Date.now() - started).toBeLessThan(120_000);
    expect(lastResults(f.api, PROMPTS.turn2).at(-1)).toContain("FIXTURE-RESULT-7678");
    // The resumed turn has the prior context.
    const resumed = requestsFor(f.api, PROMPTS.turn2).filter((q) => !q.warmup);
    expect(resumed[0].userTexts.join(" ")).toContain(PROMPTS.turn1);

    // The route matrix, each in its own conversation of the same owner.
    const routes: [string, string][] = [
      ["interpreters", PROMPTS.interpreters],
      ["readCreds", PROMPTS.readCreds],
      ["readHostCreds", PROMPTS.readHostCreds],
      ["readSsh", PROMPTS.readSsh],
      ["readState", PROMPTS.readState],
      ["grep", PROMPTS.grep],
      ["glob", PROMPTS.glob],
      ["planted", PROMPTS.planted],
      ["mcp", PROMPTS.mcp],
      ["other", PROMPTS.other],
    ];
    for (const [id, prompt] of routes) {
      const result = await t(id, prompt, `conv-${id}`);
      expect(result.at(-1)?.type, `${id}: ${JSON.stringify(result.at(-1))}`).toBe("done");
    }
    // Controls inside the routes: the tools ran and returned something.
    expect(lastResults(f.api, PROMPTS.interpreters)[0]).toContain("HOME");
    expect(lastResults(f.api, PROMPTS.planted)[0]).toContain("https://github.com/acme/repo.git");
    expect(lastResults(f.api, PROMPTS.other)[0]).toMatch(/^0\n0/);
    // The registered MCP server was reached through the relay with its own header; the agent never held it.
    expect(f.mcp.toolCalls).toContain("get_page");
    expect(f.mcp.authorizations()).toContain(`Bearer ${REGISTRY_HEADER}`);

    // Surfaces: everything the agent side produced or saw. Another conversation's own home and the trusted state files are not agent surfaces.
    const agentIds = ["conv-outcome", ...routes.map(([id]) => `conv-${id}`)];
    const agentPrompts = [PROMPTS.turn1, PROMPTS.turn2, ...routes.map(([, p]) => p)];
    const agentRequests = f.api.requests.filter((q) => q.userTexts.some((text) => agentPrompts.some((p) => text.includes(p))));
    const surfaces: Surface[] = [
      { name: "tool-results", text: agentRequests.flatMap((q) => q.toolResults.map((r) => r.text)).join("\n") },
      { name: "model-requests", text: agentRequests.map((q) => q.body).join("\n") },
      { name: "events", text: JSON.stringify(Object.entries(events).filter(([id]) => id !== "B")) },
      { name: "gateway-log", text: f.gateway.output() },
      { name: "transcripts", text: conversationHomes(f.gateway, agentIds).map(homeText).join("\n") },
    ];
    const hits = detect(surfaces);
    // The matrix: case names and counts only.
    const matrix = { mode, surfaces: surfaces.map((s) => ({ surface: s.name, bytes: s.text.length })), markers: Object.keys(MARKERS).length, routes: routes.length + 2, hits: hits.length };
    report(`OUTCOME-MATRIX ${JSON.stringify(matrix)}`);
    expect(hits).toEqual([]);
    // Every surface is non-trivial (the detector looked at something).
    for (const surface of surfaces) expect(surface.text.length, surface.name).toBeGreaterThan(200);
    // Control inside the transcripts: they do hold the conversation's own content.
    expect(surfaces.find((s) => s.name === "transcripts")!.text).toContain("FIXTURE-RESULT-7678");
  });
});

describe("the detector", () => {
  it("catches a marker on any surface, and only that marker", () => {
    expect(detect([{ name: "x", text: "clean" }])).toEqual([]);
    expect(detect([{ name: "x", text: `prefix ${REGISTRY_HEADER} suffix` }, { name: "y", text: "clean" }])).toEqual(["x:registryHeader"]);
  });

  it("negative control: a run that deliberately prints a marker is caught by the same detector, on the surfaces the marker reached", async () => {
    const f = await fixture("api-key", () => [bash("OUTCOME-LEAK", `echo ${KEY_ALPHA}; echo ${OAUTH_ACCESS}`)]);
    const events = await queryAs(f.gateway.port, KEY_ALPHA, { queryId: "q-leak", sessionId: "conv-leak", prompt: "OUTCOME-LEAK", user_id: "user-1", useSession: true });
    expect(events.at(-1)?.type, JSON.stringify(events.at(-1))).toBe("done");
    const requests = requestsFor(f.api, "OUTCOME-LEAK");
    const surfaces: Surface[] = [
      { name: "tool-results", text: requests.flatMap((q) => q.toolResults.map((r) => r.text)).join("\n") },
      { name: "model-requests", text: requests.map((q) => q.body).join("\n") },
      { name: "events", text: JSON.stringify(events) },
      { name: "transcripts", text: conversationHomes(f.gateway, ["conv-leak"]).map(homeText).join("\n") },
    ];
    const hits = detect(surfaces);
    expect(hits).toContain("tool-results:apiKeyAlpha");
    expect(hits).toContain("model-requests:apiKeyAlpha");
    expect(hits).toContain("transcripts:apiKeyAlpha");
    expect(hits).toContain("tool-results:oauthAccess");
    report(`OUTCOME-NEGATIVE-CONTROL ${JSON.stringify({ hits: hits.length })}`);
  });
});

describe("the fail-closed rows end with the exact text within their deadline and 0 runtime starts", () => {
  async function ends(f: { api: FakeAnthropicApi; gateway: SpawnedGateway }, body: Record<string, unknown>, key: string, expectedText: string, deadlineMs: number): Promise<void> {
    const before = f.api.requests.length;
    const started = Date.now();
    const events = await queryAs(f.gateway.port, key, { useSession: true, ...body });
    expect(Date.now() - started).toBeLessThan(deadlineMs);
    expect(events).toEqual([{ seq: 0, type: "error", content: expectedText }]);
    expect(f.api.requests.length).toBe(before);
    expect(descendants(f.gateway.child.pid!)).toEqual([]);
  }

  it("isolation unavailable (no isolation binary): the permanent text, /health unavailable", async () => {
    const f = await fixture("api-key", () => [bash("OUTCOME-CLOSED", "echo started")], { AGENT_SANDBOX_BWRAP: "/nonexistent/bwrap" });
    const end = Date.now() + 10_000;
    for (;;) {
      const health = await gatewayRequest(f.gateway.port, "GET", "/health");
      if (health.json?.isolation === "unavailable") break;
      if (Date.now() > end) throw new Error(`never unavailable: ${health.text}`);
      await new Promise((r) => setTimeout(r, 100));
    }
    await ends(f, { queryId: "q-closed", sessionId: "conv-closed", prompt: "OUTCOME-CLOSED", user_id: "user-1" }, KEY_ALPHA, FIXED_TEXTS.unavailable("q-closed"), 3000);
  });

  it("another owner, a legacy conversation and a busy conversation", async () => {
    const f = await fixture("api-key", (gateway) => scriptsFor(gateway));
    f.scripts.push(bash("OUTCOME-LONG", "sleep 6; echo LONG-DONE"));
    const first = await queryAs(f.gateway.port, KEY_ALPHA, { queryId: "q-own", sessionId: "conv-own", prompt: PROMPTS.turn1, user_id: "user-1", useSession: true });
    expect(first.at(-1)?.type).toBe("done");
    await ends(f, { queryId: "q-steal", sessionId: "conv-own", prompt: PROMPTS.turn2, user_id: "user-1" }, KEY_BETA, FIXED_TEXTS.otherOwner, 2000);
    await ends(f, { queryId: "q-legacy", sessionId: "legacy-conv", prompt: PROMPTS.turn2, user_id: "user-1" }, KEY_ALPHA, FIXED_TEXTS.legacy, 2000);
    const long = queryAs(f.gateway.port, KEY_ALPHA, { queryId: "q-long", sessionId: "conv-long", prompt: "OUTCOME-LONG", user_id: "user-1", useSession: true });
    const end = Date.now() + 30_000;
    while (requestsFor(f.api, "OUTCOME-LONG").filter((q) => !q.warmup).length === 0 && Date.now() < end) await new Promise((r) => setTimeout(r, 50));
    await new Promise((r) => setTimeout(r, 500));
    const before = f.api.requests.length;
    const started = Date.now();
    const busy = await queryAs(f.gateway.port, KEY_ALPHA, { queryId: "q-busy", sessionId: "conv-long", prompt: PROMPTS.turn2, user_id: "user-1", useSession: true });
    expect(Date.now() - started).toBeLessThan(2000);
    expect(busy).toEqual([{ seq: 0, type: "error", content: FIXED_TEXTS.busy }]);
    expect(f.api.requests.length).toBe(before);
    expect((await long).at(-1)?.type).toBe("done");
  });

  it("a run over its deadline: the deadline text, nothing saved, no process left", async () => {
    const api = await startFakeAnthropicApi({ toolName: "unused-7678", mode: "hang" });
    cleanups.push(() => api.close());
    const gateway = await spawnGateway(cleanups, { rootPrefix: "mvp7678-deadline-", env: { API_KEYS: `alpha:${KEY_ALPHA}`, ANTHROPIC_BASE_URL: api.baseUrl, ANTHROPIC_API_KEY: PROVIDER_KEY, AGENT_RUN_TIMEOUT_MS: "3000", CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1" } });
    const started = Date.now();
    const events = await queryAs(gateway.port, KEY_ALPHA, { queryId: "q-deadline", sessionId: "conv-deadline", prompt: "OUTCOME-DEADLINE", useSession: true });
    expect(Date.now() - started).toBeLessThan(15_000);
    expect(events.at(-1)).toEqual({ seq: events.at(-1)!.seq, type: "error", content: "The request was stopped because it ran longer than the gateway's limit of 1 minute. Its results were not saved. Try again with a smaller task, or ask your gateway administrator to raise the limit. (reference: q-deadline)" });
    expect(events.map((e) => e.type)).not.toContain("done");
    await new Promise((r) => setTimeout(r, 1500));
    expect(descendants(gateway.child.pid!)).toEqual([]);
  });
});

describe("former S2 residuals, closed by MVP-7679 (credential-bearing MCP servers run behind the trusted relay)", () => {
  it("an MCP server given in the request body with an env value or a header: the value is on no process's command line or environment inside the run's sandbox, and no audit line reports it", async () => {
    const f = await fixture("api-key", () => [
      bash("OUTCOME-RESIDUAL", "echo STDIO_ENV_VISIBLE=$(cat /proc/[0-9]*/cmdline 2>/dev/null | tr '\\0' ' ' | grep -c 'SYNTH-STDIO-ENV-7[6]78'); echo SSE_HEADER_VISIBLE=$(cat /proc/[0-9]*/cmdline 2>/dev/null | tr '\\0' ' ' | grep -c 'SYNTH-SSE-HEADER-7[6]78'); echo RELAYED_HEADER_VISIBLE=$(cat /proc/[0-9]*/cmdline /proc/[0-9]*/environ 2>/dev/null | tr '\\0' ' ' | grep -c 'SYNTH-REGISTRY-HEADE[R]-7678')"),
    ]);
    const events = await queryAs(f.gateway.port, KEY_ALPHA, {
      queryId: "q-residual",
      sessionId: "conv-residual",
      prompt: "OUTCOME-RESIDUAL",
      user_id: "user-1",
      useSession: true,
      mcpServers: {
        stdiosrv: { command: "node", args: ["-e", "setInterval(() => {}, 1e6)"], env: { PROBE_TOKEN: STDIO_ENV } },
        ssesrv: { type: "sse", url: "http://127.0.0.1:9/sse", headers: { Authorization: `Bearer ${SSE_HEADER}` } },
      },
    });
    expect(events.at(-1)?.type, JSON.stringify(events.at(-1))).toBe("done");
    const result = lastResults(f.api, "OUTCOME-RESIDUAL")[0] ?? "";
    const residual = { stdioEnvVisibleInsideOwnSandbox: /STDIO_ENV_VISIBLE=([1-9])/.test(result), sseHeaderVisibleInsideOwnSandbox: /SSE_HEADER_VISIBLE=([1-9])/.test(result) };
    report(`OUTCOME-RESIDUAL-S2 ${JSON.stringify(residual)}`);
    // Closed: the stdio server runs in its own tool sandbox and the SSE server is reached through the relay, so
    // neither value is anywhere the agent's processes can read; the relayed registry header never was.
    expect(residual).toEqual({ stdioEnvVisibleInsideOwnSandbox: false, sseHeaderVisibleInsideOwnSandbox: false });
    expect(result).toContain("RELAYED_HEADER_VISIBLE=0");
    expect(f.gateway.output()).not.toContain("credential_in_runtime_args");
    expect(f.gateway.output()).not.toContain(STDIO_ENV);
    expect(f.gateway.output()).not.toContain(SSE_HEADER);
  });
});

