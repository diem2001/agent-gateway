/**
 * A Bash denial also covers the commands that skill and agent files start (MVP-8106): the compiled gateway
 * (`dist/server.js`, built by `npm run build`) runs as a child process with its real bwrap sandbox, the bundled
 * Claude runtime and a scripted stand-in for the Anthropic Messages API. The "model" calls exactly the tools a row
 * scripts. The runtime starts commands from the frontmatter of skill, agent and command files on its own (`hooks`,
 * a stdio `mcpServers` entry); whether one ran is measured on the host, as a marker file in the conversation's own
 * work area (`sessions/<id>/work`, the sandbox's `/work`), which only a command that ran inside that sandbox can create.
 *
 * Rows (the Story's acceptance criteria): seven negative rows with the label `reqlift` denied `Bash`, the rest of each
 * file still applying (the unique instruction token reaches the model; an agent's own `tools` list still narrows),
 * a file saved by a label that may run commands, a skill saved while a run is open, a skill replaced while a run is
 * open, the Bash-granted controls and the unchanged save response. The negative controls run three of the rows in a
 * child vitest against a deliberately vulnerable copy of `dist/`: each must exit nonzero, name its row and print no
 * marker value. Evidence prints names and counts only (`COMMAND-SETTINGS`).
 *
 * Needs `npm run build`, `bwrap` and user namespaces. Linux only. Every secret is synthetic.
 */
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { afterAll, describe, expect, it, vi } from "vitest";
import { startFakeAnthropicApi, type ExactToolScript, type FakeAnthropicApi } from "./helpers/fake-anthropic-api.js";
import { REPO_ROOT, spawnGateway, type Cleanup, type SpawnedGateway } from "./helpers/git-process-gateway.js";

vi.setConfig({ testTimeout: 240_000 });

/** Set for a child run of a negative control: the vulnerable copy of the compiled server, and the parent's seed. */
const VULNERABLE_SERVER = process.env.COMMAND_SETTINGS_DIST;
const SEED = process.env.COMMAND_SETTINGS_SEED ?? randomBytes(4).toString("hex");

const KEY_REQLIFT = "SYNTH-KEY-REQLIFT-8106";
const KEY_DIEMCRM = "SYNTH-KEY-DIEMCRM-8106";
const DENY_BASH_FOR_REQLIFT = JSON.stringify({ labels: { reqlift: { deny: ["Bash"] } } });
const SETTINGS_FILE = "/home/node/.claude/settings.json";
/** How long a held run waits between the change and the next turn: the runtime's skill watcher needs several seconds (Gate A, MVP-8116). */
const WATCHER_HOLD_MS = 10_000;

const cleanups: Cleanup[] = [];
afterAll(async () => {
  while (cleanups.length > 0) await cleanups.pop()!();
});

/* ------------------------------------------------------------------ */
/*  Files                                                               */
/* ------------------------------------------------------------------ */

const marker = (row: string, event: string): string => `marker-${SEED}-${row}-${event}`;
const token = (row: string): string => `TOKEN-${row.toUpperCase()}-${SEED}`;

/** PreToolUse and PostToolUse on `Read`, and Stop: each creates a marker in the sandbox's `/work`. */
function hooksOf(row: string): string {
  const command = (event: string) => `        - type: command\n          command: "touch /work/${marker(row, event)}"\n`;
  return `hooks:\n  PreToolUse:\n    - matcher: "Read"\n      hooks:\n${command("pre")}  PostToolUse:\n    - matcher: "Read"\n      hooks:\n${command("post")}  Stop:\n    - hooks:\n${command("stop")}`;
}

/** A stdio server entry (list form, the shape the runtime accepts) whose command creates a marker. */
function stdioOf(row: string): string {
  return `mcpServers:\n  - ${row}:\n      type: stdio\n      command: sh\n      args: ["-c", "touch /work/${marker(row, "mcp")}; sleep 1"]\n`;
}

/** A skill: the body holds the unique instruction token and, as its last line, the prompt that makes the "model" read a file. */
function skillOf(row: string, settings: string, nextPrompt: string, name = `${row}skill`): string {
  return `---\nname: ${name}\ndescription: probe skill of row ${row}\n${settings}---\n${token(row)}\n${nextPrompt}\n`;
}

function agentOf(row: string, settings: string, extra = ""): string {
  return `---\nname: ${row}agent\ndescription: probe agent of row ${row}\n${extra}${settings}---\n${token(row)}\n`;
}

const read = (prompt: string): ExactToolScript => ({ name: "Read", prompt, input: { file_path: SETTINGS_FILE } });
const useSkill = (prompt: string, skill: string): ExactToolScript => ({ name: "Skill", prompt, input: { skill } });
const delegate = (prompt: string, subPrompt: string, agent: string): ExactToolScript => ({ name: "Agent", prompt, input: { description: "probe", prompt: subPrompt, subagent_type: agent, run_in_background: false } });

/* ------------------------------------------------------------------ */
/*  Rig                                                                 */
/* ------------------------------------------------------------------ */

interface Reply {
  status: number;
  text: string;
  json: Record<string, unknown> | null;
}

function send(port: number, key: string, method: string, urlPath: string, body?: { text?: string; json?: unknown }): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const payload = body?.text !== undefined ? Buffer.from(body.text, "utf8") : body?.json !== undefined ? Buffer.from(JSON.stringify(body.json), "utf8") : undefined;
    const contentType = body?.text !== undefined ? "text/plain" : "application/json";
    const req = http.request(
      { host: "127.0.0.1", port, method, path: urlPath, agent: false, headers: { Authorization: `Bearer ${key}`, ...(payload ? { "Content-Type": contentType, "Content-Length": payload.length } : {}) } },
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

interface Rig {
  api: FakeAnthropicApi;
  gateway: SpawnedGateway;
}

interface RigOptions {
  scripts: ExactToolScript[];
  policy: string;
  /** Operator-owned files: written into the workspace before the gateway starts, not through the API. */
  seed?: (workspace: string) => void;
  beforeAnswer?: (info: { prompt: string; resultsAfterLatestPrompt: number }, rig: () => Rig) => Promise<void> | void;
}

async function rig(options: RigOptions): Promise<Rig> {
  let self: Rig | undefined;
  const api = await startFakeAnthropicApi({
    toolName: "unused-8106",
    exactTool: options.scripts,
    ...(options.beforeAnswer ? { beforeScriptedAnswer: (info) => options.beforeAnswer!(info, () => self!) } : {}),
  });
  cleanups.push(() => api.close());
  const gateway = await spawnGateway(cleanups, {
    rootPrefix: "mvp8106-cs-",
    ...(VULNERABLE_SERVER ? { distServer: VULNERABLE_SERVER } : {}),
    seed: (dirs) => options.seed?.(dirs.workspace),
    env: {
      ANTHROPIC_BASE_URL: api.baseUrl,
      ANTHROPIC_API_KEY: "sk-ant-fake-8106",
      DISABLE_TELEMETRY: "1",
      CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
      API_KEYS: `reqlift:${KEY_REQLIFT},diemcrm:${KEY_DIEMCRM}`,
      AGENT_TOOL_POLICY: options.policy,
    },
  });
  self = { api, gateway };
  return self;
}

/** An operator-owned read-only file: placed on disk, mode 0444, never through the API. */
function operatorFile(workspace: string, rel: string, text: string): void {
  const file = path.join(workspace, rel);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text, { mode: 0o444 });
}

const keyOf = (label: string): string => (label === "reqlift" ? KEY_REQLIFT : KEY_DIEMCRM);

interface Ndjson {
  type: string;
  [key: string]: unknown;
}

async function ask(r: Rig, label: string, body: Record<string, unknown>): Promise<Ndjson[]> {
  const res = await send(r.gateway.port, keyOf(label), "POST", "/v1/query", { json: { queryId: `q-8106-${Date.now()}-${Math.floor(Math.random() * 1e6)}`, model: "claude-sonnet-4-5", useSession: true, ...body } });
  expect(res.status, "query status").toBe(200);
  return res.text
    .split("\n")
    .filter((line) => line.trim().startsWith("{"))
    .map((line) => JSON.parse(line) as Ndjson);
}

async function put(r: Rig, label: string, urlPath: string, text: string): Promise<Reply> {
  const reply = await send(r.gateway.port, keyOf(label), "PUT", urlPath, { text });
  expect(reply.status, `PUT ${urlPath.split("/")[2]}`).toBe(200);
  return reply;
}

/** The conversation's work area on the host: the sandbox's `/work`. */
async function workArea(r: Rig, label: string, clientId: string): Promise<string> {
  const end = Date.now() + 15_000;
  for (;;) {
    try {
      const saved = JSON.parse(fs.readFileSync(path.join(r.gateway.dirs.persist, "sessions.json"), "utf8")) as { sessionsByLabel: Record<string, Record<string, { sandboxDirId?: string }>> };
      const id = saved.sessionsByLabel[label]?.[clientId]?.sandboxDirId;
      if (id) return path.join(r.gateway.dirs.home, ".agent-sandbox", "sessions", id, "work");
    } catch {
      // Not written yet.
    }
    if (Date.now() > end) throw new Error(`no work area recorded for ${label}/${clientId}`);
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
}

async function markersOf(r: Rig, label: string, clientId: string, rowPrefix: string): Promise<number> {
  const dir = await workArea(r, label, clientId);
  return fs.readdirSync(dir).filter((name) => name.startsWith(`marker-${SEED}-${rowPrefix}`)).length;
}

/** The log line of one rewritten file; the same line is written by every run that sees the file. */
const ignoredLine = (label: string, source: string, name: string, setting: string): string => `[audit] command-settings.ignored label=${label} source=${source} name=${name} setting=${setting}`;

function evidence(row: string, fields: Record<string, number | string | boolean>, ok: boolean): void {
  process.stderr.write(`COMMAND-SETTINGS row=${row} ${Object.entries(fields).map(([k, v]) => `${k}=${String(v)}`).join(" ")} observed=${ok ? "pass" : "fail"}\n`);
}

/** The recorded model requests whose body carries `needle` (names and counts only leave this function). */
function requestsWith(r: Rig, needle: string): number {
  return r.api.requests.filter((q) => q.body.includes(needle)).length;
}

interface Verdict {
  completed: boolean;
  markers: number;
  ignored: boolean;
  tokenSeen: boolean;
  logClean: boolean;
}

/** Observations of one negative row, printed as one evidence line, asserted as booleans and counts only. */
function conclude(row: string, r: Rig, events: Ndjson[], markers: number, expectedLine: string, tokenOf: string): Verdict {
  const log = r.gateway.output();
  const verdict: Verdict = {
    completed: events.at(-1)?.type === "done" && !events.some((e) => e.type === "error"),
    markers,
    ignored: log.split("\n").some((line) => line.includes(expectedLine)),
    tokenSeen: requestsWith(r, tokenOf) > 0,
    logClean: !log.includes(SEED),
  };
  const ok = verdict.completed && verdict.markers === 0 && verdict.ignored && verdict.tokenSeen && verdict.logClean;
  evidence(row, { markers: verdict.markers, completed: verdict.completed, ignoredLine: verdict.ignored, tokenSeen: verdict.tokenSeen, logClean: verdict.logClean }, ok);
  return verdict;
}

function expectNegative(row: string, verdict: Verdict): void {
  expect(verdict.completed, `${row}: the run completes with its normal response`).toBe(true);
  expect(verdict.markers, `${row}: markers after the run`).toBe(0);
  expect(verdict.ignored, `${row}: the gateway logged the ignored setting`).toBe(true);
  expect(verdict.tokenSeen, `${row}: the rest of the file reached the model`).toBe(true);
  expect(verdict.logClean, `${row}: the gateway log holds no command text`).toBe(true);
}

/* ------------------------------------------------------------------ */
/*  One gateway for the rows of label reqlift (Bash denied) and diemcrm */
/* ------------------------------------------------------------------ */

const PROMPTS = {
  n1: "N1GO",
  n2: "N2GO",
  n3: "N3GO",
  n4: "N4GO",
  n5: "N5GO",
  n6: "N6GO",
  n7a: "N7ONE hello",
  n7: "N7GO",
  n8a: "N8AGO",
  n8b: "/n8bcmd N8BREAD",
  x1: "X1GO",
  g1: "G1GO",
  g2: "G2GO",
};

let shared: Promise<Rig> | undefined;
function sharedRig(): Promise<Rig> {
  shared ??= rig({
    policy: DENY_BASH_FOR_REQLIFT,
    scripts: [
      useSkill(PROMPTS.n1, "n1skill"),
      read("N1READ"),
      useSkill(PROMPTS.n2, "user-u-n2-skills:n2skill"),
      read("N2READ"),
      delegate(PROMPTS.n3, "N3SUB go", "n3agent"),
      read("N3SUB"),
      delegate(PROMPTS.n4, "N4SUB go", "n4agent"),
      read("N4SUB"),
      useSkill(PROMPTS.n5, "n5skill"),
      read("N5READ"),
      delegate(PROMPTS.n6, "N6SUB go", "n6agent"),
      read("N6SUB"),
      useSkill(PROMPTS.n7, "n7skill"),
      read("N7READ"),
      useSkill(PROMPTS.n8a, "n8acmd"),
      read("N8AREAD"),
      read("N8BREAD"),
      useSkill(PROMPTS.x1, "x1skill"),
      read("X1READ"),
      useSkill(PROMPTS.g1, "g1skill"),
      read("G1READ"),
      delegate(PROMPTS.g2, "G2SUB go", "g2agent"),
      read("G2SUB"),
    ],
    seed: (workspace) => {
      operatorFile(workspace, "skills/n5skill/SKILL.md", skillOf("n5", hooksOf("n5"), "N5READ"));
      operatorFile(workspace, "agents/n6agent.md", agentOf("n6", hooksOf("n6") + stdioOf("n6")));
      operatorFile(workspace, "commands/n8acmd.md", skillOf("n8a", hooksOf("n8a"), "N8AREAD", "n8acmd"));
      operatorFile(workspace, "commands/n8bcmd.md", skillOf("n8b", hooksOf("n8b"), "N8BREAD", "n8bcmd"));
    },
  });
  return shared;
}

describe("a Bash denial also covers commands started by skill, agent and command files (real runtime)", () => {
  it("N1 stored global skill with hooks, used by the denied label: no command runs, the skill's instruction still applies", async () => {
    const r = await sharedRig();
    await put(r, "reqlift", "/v1/skills/n1skill/SKILL.md", skillOf("n1", hooksOf("n1"), "N1READ"));
    const events = await ask(r, "reqlift", { prompt: PROMPTS.n1, sessionId: "n1" });
    expectNegative("N1", conclude("N1", r, events, await markersOf(r, "reqlift", "n1", "n1-"), ignoredLine("reqlift", "skills", "n1skill", "hooks"), token("n1")));
  });

  it("N2 per-user skill with hooks, used with that user_id: no command runs, the skill's instruction still applies", async () => {
    const r = await sharedRig();
    await put(r, "reqlift", "/v1/users/u-n2/skills/n2skill/SKILL.md", skillOf("n2", hooksOf("n2"), "N2READ"));
    const events = await ask(r, "reqlift", { prompt: PROMPTS.n2, sessionId: "n2", user_id: "u-n2" });
    expectNegative("N2", conclude("N2", r, events, await markersOf(r, "reqlift", "n2", "n2-"), ignoredLine("reqlift", "user-skills", "n2skill", "hooks"), token("n2")));
  });

  it("N3 stored global agent with hooks, delegated to by the denied label: no command runs, the agent's instruction still applies", async () => {
    const r = await sharedRig();
    await put(r, "reqlift", "/v1/agents/n3agent.md", agentOf("n3", hooksOf("n3")));
    const events = await ask(r, "reqlift", { prompt: PROMPTS.n3, sessionId: "n3" });
    expectNegative("N3", conclude("N3", r, events, await markersOf(r, "reqlift", "n3", "n3-"), ignoredLine("reqlift", "agents", "n3agent", "hooks"), token("n3")));
  });

  it("N4 stored global agent with a stdio mcpServers command, delegated to by the denied label: no command starts, the agent's instruction still applies", async () => {
    const r = await sharedRig();
    await put(r, "reqlift", "/v1/agents/n4agent.md", agentOf("n4", stdioOf("n4")));
    const events = await ask(r, "reqlift", { prompt: PROMPTS.n4, sessionId: "n4" });
    expectNegative("N4", conclude("N4", r, events, await markersOf(r, "reqlift", "n4", "n4-"), ignoredLine("reqlift", "agents", "n4agent", "mcpServers"), token("n4")));
  });

  it("N5 operator-owned read-only skill with hooks: the same rule, no exemption for its source", async () => {
    const r = await sharedRig();
    const events = await ask(r, "reqlift", { prompt: PROMPTS.n5, sessionId: "n5" });
    expectNegative("N5", conclude("N5", r, events, await markersOf(r, "reqlift", "n5", "n5-"), ignoredLine("reqlift", "skills", "n5skill", "hooks"), token("n5")));
  });

  it("N6 operator-owned read-only agent with hooks and a stdio mcpServers command: nothing runs, the agent's instruction still applies", async () => {
    const r = await sharedRig();
    const events = await ask(r, "reqlift", { prompt: PROMPTS.n6, sessionId: "n6" });
    expectNegative("N6", conclude("N6", r, events, await markersOf(r, "reqlift", "n6", "n6-"), ignoredLine("reqlift", "agents", "n6agent", "hooks,mcpServers"), token("n6")));
  });

  it("N7 resumed conversation that uses a stored global skill: no command runs", async () => {
    const r = await sharedRig();
    await put(r, "reqlift", "/v1/skills/n7skill/SKILL.md", skillOf("n7", hooksOf("n7"), "N7READ"));
    await ask(r, "reqlift", { prompt: PROMPTS.n7a, sessionId: "n7" });
    const events = await ask(r, "reqlift", { prompt: PROMPTS.n7, sessionId: "n7" });
    expectNegative("N7", conclude("N7", r, events, await markersOf(r, "reqlift", "n7", "n7-"), ignoredLine("reqlift", "skills", "n7skill", "hooks"), token("n7")));
  });

  it("N8a operator command file with hooks, used through the Skill tool: no command runs", async () => {
    const r = await sharedRig();
    const events = await ask(r, "reqlift", { prompt: PROMPTS.n8a, sessionId: "n8a" });
    expectNegative("N8a", conclude("N8a", r, events, await markersOf(r, "reqlift", "n8a", "n8a-"), ignoredLine("reqlift", "commands", "n8acmd", "hooks"), token("n8a")));
  });

  it("N8b operator command file with hooks, started by a slash prompt: no command runs", async () => {
    const r = await sharedRig();
    const events = await ask(r, "reqlift", { prompt: PROMPTS.n8b, sessionId: "n8b" });
    expectNegative("N8b", conclude("N8b", r, events, await markersOf(r, "reqlift", "n8b", "n8b-"), ignoredLine("reqlift", "commands", "n8bcmd", "hooks"), token("n8b")));
  });

  it("X1 a skill saved by the label that may run commands does not run them for the denied label", async () => {
    const r = await sharedRig();
    await put(r, "diemcrm", "/v1/skills/x1skill/SKILL.md", skillOf("x1", hooksOf("x1"), "X1READ"));
    const events = await ask(r, "reqlift", { prompt: PROMPTS.x1, sessionId: "x1" });
    expectNegative("X1", conclude("X1", r, events, await markersOf(r, "reqlift", "x1", "x1-"), ignoredLine("reqlift", "skills", "x1skill", "hooks"), token("x1")));
  });

  it("G1 control: the label granted Bash keeps a stored skill's hooks, and they run inside the sandbox", async () => {
    const r = await sharedRig();
    await put(r, "diemcrm", "/v1/skills/g1skill/SKILL.md", skillOf("g1", hooksOf("g1"), "G1READ"));
    const events = await ask(r, "diemcrm", { prompt: PROMPTS.g1, sessionId: "g1" });
    const markers = await markersOf(r, "diemcrm", "g1", "g1-");
    const rewritten = r.gateway.output().split("\n").some((line) => line.includes("command-settings.ignored label=diemcrm"));
    const ok = events.at(-1)?.type === "done" && markers > 0 && !rewritten;
    evidence("G1", { markers, ignoredLine: rewritten }, ok);
    expect(events.at(-1)?.type, "G1: the run completes").toBe("done");
    // `/work` exists only inside the sandbox, so a marker there was created by a command that ran in it.
    expect(markers, "G1: markers after the run").toBeGreaterThan(0);
    expect(rewritten, "G1: nothing was rewritten for the granted label").toBe(false);
  });

  it("G2 control: the label granted Bash keeps a stored agent's stdio mcpServers command, and it starts inside the sandbox", async () => {
    const r = await sharedRig();
    await put(r, "diemcrm", "/v1/agents/g2agent.md", agentOf("g2", stdioOf("g2")));
    const events = await ask(r, "diemcrm", { prompt: PROMPTS.g2, sessionId: "g2" });
    const markers = await markersOf(r, "diemcrm", "g2", "g2-");
    const rewritten = r.gateway.output().split("\n").some((line) => line.includes("command-settings.ignored label=diemcrm"));
    const ok = events.at(-1)?.type === "done" && markers > 0 && !rewritten;
    evidence("G2", { markers, ignoredLine: rewritten }, ok);
    expect(events.at(-1)?.type, "G2: the run completes").toBe("done");
    expect(markers, "G2: markers after the run").toBeGreaterThan(0);
    expect(rewritten, "G2: nothing was rewritten for the granted label").toBe(false);
  });

  it("S1 saving a file with command settings still succeeds for the denied label, with the existing reply and the stored text unchanged", async () => {
    const r = await sharedRig();
    const text = skillOf("s1", hooksOf("s1"), "S1READ");
    const reply = await send(r.gateway.port, KEY_REQLIFT, "PUT", "/v1/skills/s1skill/SKILL.md", { text });
    const stored = fs.readFileSync(path.join(r.gateway.dirs.workspace, "skills", "s1skill", "SKILL.md"), "utf8");
    const ok = reply.status === 200 && stored === text;
    evidence("S1", { status: reply.status, storedUnchanged: stored === text, reply: JSON.stringify(reply.json) === JSON.stringify({ status: "ok", path: "skills/s1skill/SKILL.md" }) }, ok);
    expect(reply.status, "S1: status").toBe(200);
    expect(reply.json, "S1: the existing reply").toEqual({ status: "ok", path: "skills/s1skill/SKILL.md" });
    expect(stored === text, "S1: the stored text is the sent text").toBe(true);
  });
});

/* ------------------------------------------------------------------ */
/*  An agent's own tool list still applies                              */
/* ------------------------------------------------------------------ */

describe("an agent file's tool restriction still applies when its command settings are ignored (real runtime)", () => {
  it("T1 an agent with tools: Read and hooks, under a policy that grants Read and Grep but not Bash, is offered Read and not Grep", async () => {
    const r = await rig({
      policy: JSON.stringify({ labels: { reqlift: { allow: ["Read", "Grep", "Agent", "Task", "Skill"] } } }),
      scripts: [delegate("T1GO", "T1SUB go", "t1agent"), read("T1SUB")],
      seed: (workspace) => operatorFile(workspace, "agents/t1agent.md", agentOf("t1", hooksOf("t1"), "tools: Read\n")),
    });
    const events = await ask(r, "reqlift", { prompt: "T1GO", sessionId: "t1" });
    const sub = r.api.requests.find((q) => q.userTexts.at(-1)?.includes("T1SUB") && !q.warmup);
    const offered = sub?.tools ?? [];
    const markers = await markersOf(r, "reqlift", "t1", "t1-");
    const ok = events.at(-1)?.type === "done" && offered.includes("Read") && !offered.includes("Grep") && markers === 0;
    evidence("T1", { offered: offered.length, readOffered: offered.includes("Read"), grepOffered: offered.includes("Grep"), markers }, ok);
    expect(events.at(-1)?.type, "T1: the run completes").toBe("done");
    expect(offered.includes("Read"), "T1: the delegated agent is offered Read").toBe(true);
    expect(offered.includes("Grep"), "T1: the delegated agent is not offered Grep").toBe(false);
    expect(markers, "T1: markers after the run").toBe(0);
    expect(requestsWith(r, token("t1")) > 0, "T1: the agent's instruction reached the model").toBe(true);
  });
});

/* ------------------------------------------------------------------ */
/*  Files that change while a run is open                               */
/* ------------------------------------------------------------------ */

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

describe("a file saved or replaced while a run is open does not reach it (real runtime)", () => {
  async function heldRig(): Promise<Rig> {
    return rig({
      policy: DENY_BASH_FOR_REQLIFT,
      scripts: [
        { name: "Read", prompt: "M1GO", input: { file_path: SETTINGS_FILE }, then: [{ name: "Skill", input: { skill: "m1late" } }] },
        read("M1READ"),
        { name: "Read", prompt: "R1GO", input: { file_path: SETTINGS_FILE }, then: [{ name: "Skill", input: { skill: "r1skill" } }] },
        read("R1READ"),
      ],
      // A skills directory that exists when the run starts is one the runtime's watcher can watch (Gate A).
      seed: (workspace) => {
        operatorFile(workspace, "skills/early/SKILL.md", `---\nname: early\ndescription: present when the run starts\n---\nEARLY\n`);
        operatorFile(workspace, "skills/r1skill/SKILL.md", skillOf("r1a", hooksOf("r1a"), "R1READ", "r1skill"));
      },
      beforeAnswer: async (info, self) => {
        if (info.resultsAfterLatestPrompt !== 1) return;
        const r = self();
        if (info.prompt === "M1GO") {
          await put(r, "diemcrm", "/v1/skills/m1late/SKILL.md", skillOf("m1", hooksOf("m1"), "M1READ", "m1late"));
          await sleep(WATCHER_HOLD_MS);
        } else if (info.prompt === "R1GO") {
          const deleted = await send(r.gateway.port, KEY_DIEMCRM, "DELETE", "/v1/skills/r1skill/SKILL.md");
          expect(deleted.status, "R1: delete").toBe(200);
          await put(r, "diemcrm", "/v1/skills/r1skill/SKILL.md", skillOf("r1b", hooksOf("r1b"), "R1READ", "r1skill"));
          await sleep(WATCHER_HOLD_MS);
        }
      },
    });
  }

  it("M1 a skill with hooks saved by another label between two turns of a denied run: the run cannot use it to run a command, and completes", async () => {
    const r = await heldRig();
    const events = await ask(r, "reqlift", { prompt: "M1GO", sessionId: "m1" });
    const markers = await markersOf(r, "reqlift", "m1", "m1-");
    const completed = events.at(-1)?.type === "done" && !events.some((e) => e.type === "error");
    evidence("M1", { markers, completed }, completed && markers === 0);
    expect(completed, "M1: the run completes").toBe(true);
    expect(markers, "M1: markers after the run").toBe(0);
  });

  it("R1 a skill deleted and saved again while a denied run is open: no command runs, and the run does not fail", async () => {
    const r = await heldRig();
    const events = await ask(r, "reqlift", { prompt: "R1GO", sessionId: "r1" });
    // Either version of the skill (r1a was stored before the run, r1b replaced it) may leave markers.
    const markers = await markersOf(r, "reqlift", "r1", "r1");
    const completed = events.at(-1)?.type === "done" && !events.some((e) => e.type === "error");
    evidence("R1", { markers, completed }, completed && markers === 0);
    expect(completed, "R1: the run completes").toBe(true);
    expect(markers, "R1: markers after the run").toBe(0);
  });
});

/* ------------------------------------------------------------------ */
/*  A store of thousands of empty folders (MVP-8126)                    */
/* ------------------------------------------------------------------ */

/** One query, timed to its first stream event (evidence only, never asserted). */
function askTimed(r: Rig, label: string, body: Record<string, unknown>): Promise<{ events: Ndjson[]; firstEventMs: number }> {
  const payload = Buffer.from(JSON.stringify({ queryId: `q-8126-${Date.now()}-${Math.floor(Math.random() * 1e6)}`, model: "claude-sonnet-4-5", useSession: true, ...body }), "utf8");
  const started = Date.now();
  return new Promise((resolve, reject) => {
    let firstEventMs = -1;
    const req = http.request(
      { host: "127.0.0.1", port: r.gateway.port, method: "POST", path: "/v1/query", agent: false, headers: { Authorization: `Bearer ${keyOf(label)}`, "Content-Type": "application/json", "Content-Length": payload.length } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => {
          if (firstEventMs < 0) firstEventMs = Date.now() - started;
          chunks.push(chunk);
        });
        res.on("end", () => {
          const events = Buffer.concat(chunks)
            .toString("utf8")
            .split("\n")
            .filter((line) => line.trim().startsWith("{"))
            .map((line) => JSON.parse(line) as Ndjson);
          resolve({ events, firstEventMs });
        });
      },
    );
    req.on("error", reject);
    req.end(payload);
  });
}

describe("a very large skills store does not stop or slow a denied run (real runtime)", () => {
  it("L1 a Bash-denied run with 2500 empty skill folders and a stdio-command agent completes, binds a copy of 2000 folders and logs one summary line", async () => {
    const folders = 2500;
    const seen = { runDirs: -1, folders: -1, files: -1 };
    const r = await rig({
      policy: DENY_BASH_FOR_REQLIFT,
      scripts: [delegate("L1GO", "L1SUB go", "l1agent"), read("L1SUB")],
      seed: (workspace) => {
        for (let i = 0; i < folders; i++) fs.mkdirSync(path.join(workspace, "skills", `f${String(i).padStart(4, "0")}`), { recursive: true });
        operatorFile(workspace, "agents/l1agent.md", agentOf("l1", stdioOf("l1")));
      },
      // The run is open here: count the copy the sandbox is bound to, on the host.
      beforeAnswer: (info, self) => {
        if (info.prompt !== "L1GO" || info.resultsAfterLatestPrompt !== 0 || seen.runDirs >= 0) return;
        const runs = path.join(self().gateway.dirs.home, ".agent-sandbox", "runs");
        const matching = fs.readdirSync(runs).filter((name) => name.startsWith("run-"));
        seen.runDirs = matching.length;
        if (matching.length !== 1) return;
        const copy = path.join(runs, matching[0], "trusted", "neutralized", "skills");
        const entries = fs.readdirSync(copy, { withFileTypes: true });
        seen.folders = entries.filter((e) => e.isDirectory()).length;
        seen.files = entries.filter((e) => !e.isDirectory()).length;
      },
    });
    const { events, firstEventMs } = await askTimed(r, "reqlift", { prompt: "L1GO", sessionId: "l1" });
    const lines = r.gateway.output().split("\n");
    const limited = lines.filter((line) => line.includes("sandbox.content.limited"));
    const skillsLimited = limited.filter((line) => line.includes("kind=snapshot-skills") && line.includes(" folders=2000 ") && line.includes(" stopped=true"));
    const tooLarge = lines.filter((line) => line.includes("reason=too_large")).length;
    const markers = await markersOf(r, "reqlift", "l1", "l1-");
    const completed = events.at(-1)?.type === "done" && !events.some((e) => e.type === "error");
    const tokenSeen = requestsWith(r, token("l1")) > 0;
    const ok = completed && markers === 0 && tokenSeen && seen.runDirs === 1 && seen.folders === 2000 && seen.files === 0 && limited.length === 1 && skillsLimited.length === 1 && tooLarge === 0;
    evidence("L1", { runDirs: seen.runDirs, copiedFolders: seen.folders, copiedFiles: seen.files, limitedLines: limited.length, skillsLimitedLines: skillsLimited.length, tooLargeLines: tooLarge, markers, completed, tokenSeen, runStartMs: firstEventMs }, ok);
    expect(completed, "L1: the run completes").toBe(true);
    expect(markers, "L1: markers after the run").toBe(0);
    expect(tokenSeen, "L1: the agent's instruction reached the model").toBe(true);
    expect(seen.runDirs, "L1: run folders on the host while the run was open").toBe(1);
    expect(seen.folders, "L1: folders in the copy the sandbox sees").toBe(2000);
    expect(seen.files, "L1: files in the copy the sandbox sees").toBe(0);
    expect(limited.length, "L1: summary lines in the gateway output").toBe(1);
    expect(skillsLimited.length, "L1: the summary line names the skills entry with folders=2000 and stopped=true").toBe(1);
    expect(tooLarge, "L1: too_large lines").toBe(0);
  });
});

/* ------------------------------------------------------------------ */
/*  Negative controls                                                   */
/* ------------------------------------------------------------------ */

/** A copy of `dist/` under the temp directory whose `file` has `from` replaced by `to`; the patch must match exactly once. */
function vulnerableServer(file: string, from: string, to: string): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "mvp8106-vulnerable-"));
  cleanups.push(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.cpSync(path.join(REPO_ROOT, "dist"), path.join(root, "dist"), { recursive: true, filter: (source) => !source.startsWith(path.join(REPO_ROOT, "dist", "tests")) });
  fs.copyFileSync(path.join(REPO_ROOT, "package.json"), path.join(root, "package.json"));
  fs.symlinkSync(path.join(REPO_ROOT, "node_modules"), path.join(root, "node_modules"));
  const target = path.join(root, "dist", file);
  const source = fs.readFileSync(target, "utf8");
  expect(source.split(from).length - 1, `the patch of ${file} must match exactly once`).toBe(1);
  fs.writeFileSync(target, source.replace(from, () => to));
  expect(fs.readFileSync(target, "utf8")).not.toBe(source);
  return path.join(root, "dist", "server.js");
}

interface ChildResult {
  failed: boolean;
  namesTheRow: boolean;
  markers: number;
  printsAMarkerValue: boolean;
  timedOut: boolean;
}

/** Runs the rows `selector` selects in a child vitest against `server`; only these booleans and a count leave this function. */
async function runChildRow(selector: string, rowId: string, server: string, seed: string): Promise<ChildResult> {
  const child = spawn(process.execPath, [path.join(REPO_ROOT, "node_modules", "vitest", "vitest.mjs"), "run", "src/tests/command-settings-process.test.ts", "-t", selector], {
    cwd: REPO_ROOT,
    env: { PATH: process.env.PATH, HOME: process.env.HOME, LANG: process.env.LANG, TMPDIR: os.tmpdir(), COMMAND_SETTINGS_DIST: server, COMMAND_SETTINGS_SEED: seed },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  child.stdout!.on("data", (data: Buffer) => (output += data.toString("utf8")));
  child.stderr!.on("data", (data: Buffer) => (output += data.toString("utf8")));
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    child.kill("SIGKILL");
  }, 230_000);
  const code = await new Promise<number | null>((resolve) => child.on("exit", (exitCode) => resolve(exitCode)));
  clearTimeout(timer);
  const line = new RegExp(`COMMAND-SETTINGS row=${rowId} [^\\n]*`).exec(output)?.[0] ?? "";
  return {
    failed: code !== 0 && code !== null,
    namesTheRow: line.includes("observed=fail"),
    markers: Number(/ markers=(\d+)/.exec(line)?.[1] ?? 0),
    printsAMarkerValue: output.includes(seed),
    timedOut,
  };
}

if (!VULNERABLE_SERVER) {
  describe("negative controls: each row is red against a gateway that does not neutralize, and the child prints no marker value", () => {
    const REWRITE_OFF = { file: "agent.js", from: "const neutralizeCommands = !commandsGranted;", to: "const neutralizeCommands = false;" };
    const LIVE_BIND = { file: "sandbox-content.js", from: "plan.mounts.push({ src: snapshot, dest });", to: "plan.mounts.push({ src: source, dest });" };

    it("NC1 the stored-skill row fails against a gateway with the rewrite disabled", async () => {
      const seed = randomBytes(4).toString("hex");
      const result = await runChildRow("N1 stored global skill", "N1", vulnerableServer(REWRITE_OFF.file, REWRITE_OFF.from, REWRITE_OFF.to), seed);
      expect(result.timedOut, "NC1: timed out").toBe(false);
      expect(result.failed, "NC1: the child exits nonzero").toBe(true);
      expect(result.namesTheRow, "NC1: the child names the row").toBe(true);
      expect(result.markers, "NC1: markers the child saw").toBeGreaterThan(0);
      expect(result.printsAMarkerValue, "NC1: the child prints a marker value").toBe(false);
    });

    it("NC2 the agent stdio-command row fails against a gateway with the rewrite disabled", async () => {
      const seed = randomBytes(4).toString("hex");
      const result = await runChildRow("N4 stored global agent with a stdio", "N4", vulnerableServer(REWRITE_OFF.file, REWRITE_OFF.from, REWRITE_OFF.to), seed);
      expect(result.timedOut, "NC2: timed out").toBe(false);
      expect(result.failed, "NC2: the child exits nonzero").toBe(true);
      expect(result.namesTheRow, "NC2: the child names the row").toBe(true);
      expect(result.markers, "NC2: markers the child saw").toBeGreaterThan(0);
      expect(result.printsAMarkerValue, "NC2: the child prints a marker value").toBe(false);
    });

    it("NC3 the saved-while-open row fails against a gateway that rewrites but binds the live directory instead of the snapshot", async () => {
      const seed = randomBytes(4).toString("hex");
      const result = await runChildRow("M1 a skill with hooks saved", "M1", vulnerableServer(LIVE_BIND.file, LIVE_BIND.from, LIVE_BIND.to), seed);
      expect(result.timedOut, "NC3: timed out").toBe(false);
      expect(result.failed, "NC3: the child exits nonzero").toBe(true);
      expect(result.namesTheRow, "NC3: the child names the row").toBe(true);
      expect(result.markers, "NC3: markers the child saw").toBeGreaterThan(0);
      expect(result.printsAMarkerValue, "NC3: the child prints a marker value").toBe(false);
    });
  });
}
