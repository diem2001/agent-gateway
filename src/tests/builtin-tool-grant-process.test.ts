/**
 * The built-in tools the gateway offers, observed at the real runtime (MVP-8088, DEC-ISO-008): the compiled gateway
 * (`dist/server.js`, built by `npm run build`) runs as a child process with the production Claude Agent SDK, its
 * bundled native runtime, real `bwrap` and a recording stand-in for the Anthropic Messages API. Every row compares the
 * tool names of the model requests (`tools[].name`) with an expected set that is written out in this file, never
 * computed from the gateway's own tables. A "recorded built-in" is every recorded name that does not start with `mcp__`;
 * rows without MCP servers or webhook tools compare the whole `tools[]`.
 *
 * What the rows cover: the reproduction (no policy), every run type, delegated subagents (exact sets plus the parent
 * grant boundary, also for every advertised subagent type), the progress checklist event reqlift reads, the
 * subscription-login path, the policy naming every tool the runtime offers one at a time, the names it rejects, the
 * startup audit line, the committed inventory of the bundled runtime and its drift detection.
 *
 * Needs `npm run build`, `bwrap` and user namespaces. Linux only. Every secret is synthetic; evidence lines print names
 * and counts only (`TOOL-GRANT-EVIDENCE`).
 */
import { spawn } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { query } from "@anthropic-ai/claude-agent-sdk";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { buildSandboxEnv } from "../sandbox.js";
import * as toolGrant from "../tool-grant.js";
import { startFakeAnthropicApi, type ExactToolScript, type FakeAnthropicApi, type RecordedMessagesRequest } from "./helpers/fake-anthropic-api.js";
import { REPO_ROOT, gatewayRequest, releaseGatewayPort, reserveGatewayPort, spawnGateway, type Cleanup, type SpawnedGateway } from "./helpers/git-process-gateway.js";

vi.setConfig({ testTimeout: 240_000 });

const cleanups: Cleanup[] = [];
afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()!();
});

/* ------------------------------------------------------------------ */
/*  The reviewed sets, written out (DEC-ISO-008, Gate A of MVP-8088)     */
/* ------------------------------------------------------------------ */

const APPROVED_DEFAULT_SET = ["Agent", "Bash", "Edit", "Glob", "Grep", "NotebookEdit", "Read", "Skill", "TodoWrite", "WebFetch", "WebSearch", "Write"];
/** Measured on the bundled runtime (Gate A): a general-purpose subagent is offered the parent's whole set, `Agent` included. */
const DELEGATED_DEFAULT_SET = [...APPROVED_DEFAULT_SET];
/** Every built-in name the runtime offers when the gateway starts it (`CLAUDE_CODE_ENABLE_TASKS=false`, nonessential traffic off). */
const INVENTORY = [
  "Agent", "Bash", "CronCreate", "CronDelete", "CronList", "Edit", "EnterWorktree", "ExitWorktree", "Glob", "Grep", "ListAgents", "NotebookEdit", "Read",
  "ReportFindings", "ScheduleWakeup", "SendMessage", "Skill", "TaskStop", "TodoWrite", "WebFetch", "WebSearch", "Workflow", "Write",
];
const UNREVIEWED_TOOLS = [
  "CronCreate", "CronDelete", "CronList", "DesignSync", "EnterWorktree", "ExitWorktree", "ListAgents", "Monitor", "PushNotification", "ReportFindings",
  "ScheduleWakeup", "SendMessage", "TaskStop", "Workflow", "Artifact", "SendUserFile", "ShareOnboardingGuide", "TaskCreate", "TaskGet", "TaskList", "TaskUpdate",
];
const ALIASES: Readonly<Record<string, string>> = { Task: "Agent" };

const sorted = (names: readonly string[]): string[] => [...names].sort();
const without = (names: readonly string[], ...drop: string[]): string[] => names.filter((name) => !drop.includes(name));

/* ------------------------------------------------------------------ */
/*  Rig                                                                 */
/* ------------------------------------------------------------------ */

const keyFor = (label: string): string => `SYNTH-8088-KEY-${label}`;

interface Rig {
  api: FakeAnthropicApi;
  gateway: SpawnedGateway;
  /** Scripts the model double answers with; more can be added while the rig runs. */
  scripts: ExactToolScript[];
  labels: string[];
}

interface RigOptions {
  labels?: string[];
  policy?: unknown;
  seed?: (workspace: string) => void;
  /** Gateway environment on top of the defaults. `ANTHROPIC_API_KEY: null` starts the gateway without a provider key. */
  env?: Record<string, string | null>;
  scripts?: ExactToolScript[];
  /** Records the argument vector of every sandbox launch (`AGENT_SANDBOX_BWRAP` wrapper) and returns its directory. */
  recordLaunches?: boolean;
  /** Where the rig registers its cleanup (default: the per-test list); a describe that shares one rig passes its own. */
  cleanupList?: Cleanup[];
}

async function startRig(options: RigOptions = {}): Promise<Rig & { launchDir?: string }> {
  const labels = options.labels ?? ["reqlift", "diemcrm"];
  const scripts = options.scripts ?? [];
  const into = options.cleanupList ?? cleanups;
  const api = await startFakeAnthropicApi({ toolName: "unused-8088", exactTool: scripts });
  into.push(() => api.close());
  let launchDir: string | undefined;
  const extraEnv: Record<string, string> = {};
  if (options.recordLaunches) {
    launchDir = fs.mkdtempSync(path.join(os.tmpdir(), "mvp8088-launch-"));
    into.push(() => fs.rmSync(launchDir!, { recursive: true, force: true }));
    const wrapper = path.join(launchDir, "bwrap");
    fs.writeFileSync(wrapper, `#!/bin/bash\nprintf '%s\\0' "$@" > "${launchDir}/argv.$$.$RANDOM"\nexec /usr/bin/bwrap "$@"\n`, { mode: 0o755 });
    extraEnv.AGENT_SANDBOX_BWRAP = wrapper;
  }
  const env: Record<string, string> = {
    API_KEYS: labels.map((label) => `${label}:${keyFor(label)}`).join(","),
    ANTHROPIC_BASE_URL: api.baseUrl,
    ANTHROPIC_API_KEY: "sk-ant-fake-grant-8088",
    DISABLE_TELEMETRY: "1",
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
    ...(options.policy !== undefined ? { AGENT_TOOL_POLICY: JSON.stringify(options.policy) } : {}),
    ...extraEnv,
  };
  for (const [key, value] of Object.entries(options.env ?? {})) {
    if (value === null) delete env[key];
    else env[key] = value;
  }
  const gateway = await spawnGateway(into, { rootPrefix: "mvp8088-grant-", seed: (dirs) => options.seed?.(dirs.workspace), env });
  return { api, gateway, scripts, labels, launchDir };
}

interface Ndjson {
  type: string;
  [key: string]: unknown;
}

interface Chat {
  status: number;
  events: Ndjson[];
  /** Every model request the double received while this chat ran. */
  requests: RecordedMessagesRequest[];
}

let queryCounter = 0;

async function chat(r: Rig, label: string, body: Record<string, unknown>): Promise<Chat> {
  const before = r.api.requests.length;
  const res = await gatewayRequest(
    r.gateway.port,
    "POST",
    "/v1/query",
    { queryId: `q-8088-${Date.now()}-${++queryCounter}`, model: "claude-sonnet-4-5", useSession: false, ...body },
    keyFor(label),
  );
  const events = res.text
    .split("\n")
    .filter((line) => line.trim().startsWith("{"))
    .map((line) => JSON.parse(line) as Ndjson);
  return { status: res.status, events, requests: r.api.requests.slice(before) };
}

/** The tool names of every conversation request (not a warmup, offering tools) whose user text carries `marker`. */
function offeredSets(requests: readonly RecordedMessagesRequest[], marker: string): string[][] {
  return requests.filter((q) => !q.warmup && q.tools.length > 0 && q.userTexts.some((text) => text.includes(marker))).map((q) => sorted(q.tools));
}

function evidence(row: string, names: readonly string[]): void {
  process.stderr.write(`TOOL-GRANT-EVIDENCE row=${row} count=${names.length} names=${names.join(",") || "-"}\n`);
}

/** Every request carrying `marker` offers exactly `expected` (and at least one was recorded). */
function expectOffered(requests: readonly RecordedMessagesRequest[], marker: string, expected: readonly string[], row: string): void {
  const sets = offeredSets(requests, marker);
  expect(sets.length, `${row}: no request recorded for ${marker}`).toBeGreaterThan(0);
  for (const set of sets) {
    evidence(row, set);
    expect(set, row).toEqual(sorted(expected));
  }
}

function expectNoUnreviewed(requests: readonly RecordedMessagesRequest[], row: string): void {
  for (const request of requests) {
    expect(request.tools.filter((name) => UNREVIEWED_TOOLS.includes(name)), `${row}: unreviewed tool offered`).toEqual([]);
  }
}

function resultOf(requests: readonly RecordedMessagesRequest[], marker: string): { isError: boolean; text: string } | undefined {
  const matching = requests.filter((q) => q.userTexts.at(-1)?.includes(marker) && !q.warmup);
  return matching.at(-1)?.toolResults.at(-1);
}

const bash = (prompt: string, command: string): ExactToolScript => ({ name: "Bash", prompt, input: { command, description: "probe" } });
const agentCall = (prompt: string, subPrompt: string, subagent: string): ExactToolScript => ({
  name: "Agent",
  prompt,
  input: { description: "probe", prompt: subPrompt, subagent_type: subagent, run_in_background: false },
});

function seedConfigured(workspace: string): void {
  fs.writeFileSync(path.join(workspace, "settings.json"), JSON.stringify({ permissions: { allow: ["Bash(*)", "Read(*)", "Write(*)", "Edit(*)", "Glob(*)", "Grep(*)", "WebSearch(*)", "WebFetch(*)"] } }));
  fs.mkdirSync(path.join(workspace, "skills", "bashskill"), { recursive: true });
  fs.writeFileSync(path.join(workspace, "skills", "bashskill", "SKILL.md"), "---\nname: bashskill\ndescription: runs a shell command\nallowed-tools: Bash\n---\n\nRun the command the user names.\n");
  fs.mkdirSync(path.join(workspace, "agents"), { recursive: true });
  fs.writeFileSync(path.join(workspace, "agents", "probe-agent.md"), "---\nname: probe-agent\ndescription: lists an unreviewed tool\ntools: Read, Bash, CronCreate\n---\n\nYou are a probe.\n");
}

/** The `--tools` value of every runtime launch the recording wrapper saw. */
function launchedToolLists(launchDir: string): string[] {
  const lists: string[] = [];
  for (const name of fs.readdirSync(launchDir).filter((n) => n.startsWith("argv."))) {
    const args = fs.readFileSync(path.join(launchDir, name), "utf8").split("\0");
    if (!args.includes("--output-format")) continue;
    const at = args.indexOf("--tools");
    lists.push(at >= 0 ? args[at + 1] : "(absent)");
  }
  return lists;
}

/* ------------------------------------------------------------------ */
/*  No policy: the reproduction and every run type                       */
/* ------------------------------------------------------------------ */

const TODOS = [{ content: "Check logs", status: "in_progress", activeForm: "Checking logs" }];

describe("without a tool policy (real runtime)", () => {
  const scripts: ExactToolScript[] = [
    { name: "CronCreate", prompt: "R0-ORDINARY", input: { cron: "* * * * *", prompt: "tick" } },
    { name: "Skill", prompt: "R3-SKILL", input: { skill: "bashskill" } },
    { name: "TodoWrite", prompt: "T1-TODO", input: { todos: TODOS } },
    agentCall("D1-GENERAL", "SUB-D1 go", "general-purpose"),
    agentCall("D2-CONFIGURED", "SUB-D2 go", "probe-agent"),
  ];

  async function g0(): Promise<Rig & { launchDir?: string }> {
    // The gateway's own environment asks for the task tools; the sandbox environment must not honor it.
    return startRig({ scripts, seed: seedConfigured, recordLaunches: true, env: { CLAUDE_CODE_ENABLE_TASKS: "true" } });
  }

  it("an ordinary chat is offered exactly the approved default set, with an explicit tools list; a call to an unreviewed tool is refused", async () => {
    const r = await g0();
    const { status, events, requests } = await chat(r, "reqlift", { prompt: "R0-ORDINARY say hello" });
    expect(status).toBe(200);
    expect(events.at(-1)?.type).toBe("done");
    expectOffered(requests, "R0-ORDINARY", APPROVED_DEFAULT_SET, "R0 ordinary chat");
    expectNoUnreviewed(requests, "R0");
    // The runtime was started with an explicit list: the approved names, not the runtime default.
    expect(launchedToolLists(r.launchDir!).map((list) => sorted(list.split(","))), "launched --tools list").toEqual([sorted(APPROVED_DEFAULT_SET)]);
    // SC-5: a tool that is not offered returns the runtime's explicit error.
    const refused = resultOf(requests, "R0-ORDINARY");
    expect(refused?.isError).toBe(true);
    expect(refused?.text).toContain("No such tool available: CronCreate");
  });

  it("the run types are bound to the same grant: resumed conversation, configured agent and skill, enforced list", async () => {
    const r = await g0();
    const first = await chat(r, "reqlift", { prompt: "R2-RESUME-1 hello", sessionId: "res-1", useSession: true });
    expectOffered(first.requests, "R2-RESUME-1", APPROVED_DEFAULT_SET, "R2 resumed conversation, first turn");
    const second = await chat(r, "reqlift", { prompt: "R2-RESUME-2 again", sessionId: "res-1", useSession: true });
    expectOffered(second.requests, "R2-RESUME-2", APPROVED_DEFAULT_SET, "R2 resumed conversation, second turn");
    const skill = await chat(r, "reqlift", { prompt: "R3-SKILL use the skill" });
    expect(skill.events.find((e) => e.type === "skills_loaded")).toMatchObject({ skills: expect.arrayContaining(["bashskill"]) });
    expectOffered(skill.requests, "R3-SKILL", APPROVED_DEFAULT_SET, "R3 configured agent and skill");
    const enforced = await chat(r, "reqlift", { prompt: "R6-ENFORCED hello", enforcedTools: ["Read"] });
    expectOffered(enforced.requests, "R6-ENFORCED", ["Read"], "R6 caller enforcedTools [Read]");
    expectNoUnreviewed([...first.requests, ...second.requests, ...skill.requests], "run types");
  });

  it("reqlift's progress checklist still works: the raw TodoWrite input reaches the caller and no task tool is recorded", async () => {
    const r = await g0();
    const { events, requests } = await chat(r, "reqlift", { prompt: "T1-TODO plan the work" });
    expect(events.at(-1)?.type).toBe("done");
    const toolUse = events.filter((e) => e.type === "tool_use" && e.toolName === "TodoWrite");
    expect(toolUse).toHaveLength(1);
    expect(toolUse[0].input).toEqual({ todos: TODOS });
    expect(resultOf(requests, "T1-TODO")?.isError).toBe(false);
    for (const request of requests) {
      expect(request.tools.filter((name) => ["TaskCreate", "TaskGet", "TaskList", "TaskUpdate"].includes(name)), "task tools recorded").toEqual([]);
    }
    expectOffered(requests, "T1-TODO", APPROVED_DEFAULT_SET, "T1 TodoWrite chat");
  });

  it("a delegated subagent gets the measured default set; a configured agent listing an unreviewed tool gets only the reviewed ones", async () => {
    const r = await g0();
    const general = await chat(r, "reqlift", { prompt: "D1-GENERAL delegate" });
    const parent = offeredSets(general.requests, "D1-GENERAL");
    expectOffered(general.requests, "D1-GENERAL", APPROVED_DEFAULT_SET, "D1 parent");
    expectOffered(general.requests, "SUB-D1", DELEGATED_DEFAULT_SET, "D1 general-purpose subagent");
    for (const sub of offeredSets(general.requests, "SUB-D1")) expect(sub.every((name) => parent[0].includes(name)), "D1 subagent within parent").toBe(true);
    expectNoUnreviewed(general.requests, "D1");

    const configured = await chat(r, "reqlift", { prompt: "D2-CONFIGURED delegate" });
    expectOffered(configured.requests, "SUB-D2", ["Read", "Bash"], "D2 configured agent listing Read, Bash, CronCreate");
    expectNoUnreviewed(configured.requests, "D2");
  });

  it("the startup audit line names the effective built-ins of every label instead of all", async () => {
    const r = await g0();
    const names = APPROVED_DEFAULT_SET.join(",");
    for (const label of ["reqlift", "diemcrm"]) expect(r.gateway.output()).toContain(`[audit] tool.policy label=${label} builtIns=${names} servers=all`);
    expect(r.gateway.output()).not.toContain("builtIns=all");
  });
});

/* ------------------------------------------------------------------ */
/*  Policies                                                            */
/* ------------------------------------------------------------------ */

describe("policies bind the offered set (real runtime)", () => {
  it("default deny Bash, a label that allows one new tool, and a delegated subagent under the denial", async () => {
    const scripts: ExactToolScript[] = [agentCall("D3-GENERAL", "SUB-D3 go", "general-purpose")];
    const r = await startRig({ policy: { default: { deny: ["Bash"] }, labels: { reqlift: { allow: ["CronCreate"] } } }, scripts });
    const denied = await chat(r, "diemcrm", { prompt: "P1-DENY-BASH hello" });
    expectOffered(denied.requests, "P1-DENY-BASH", without(APPROVED_DEFAULT_SET, "Bash"), "default deny [Bash]");
    const allowed = await chat(r, "reqlift", { prompt: "P2-ALLOW-CRON hello" });
    expectOffered(allowed.requests, "P2-ALLOW-CRON", ["CronCreate"], "label reqlift allow [CronCreate]");
    const delegated = await chat(r, "diemcrm", { prompt: "D3-GENERAL delegate" });
    expectOffered(delegated.requests, "D3-GENERAL", without(APPROVED_DEFAULT_SET, "Bash"), "D3 parent");
    expectOffered(delegated.requests, "SUB-D3", without(DELEGATED_DEFAULT_SET, "Bash"), "D3 general-purpose subagent under default deny [Bash]");
    expectNoUnreviewed(delegated.requests, "D3");
  });

  it("no subagent type the runtime advertises is offered a tool its parent was not granted (Bash denied)", async () => {
    const scripts: ExactToolScript[] = [];
    const r = await startRig({ policy: { default: { deny: ["Bash"] } }, scripts, seed: seedConfigured });
    const discovery = await chat(r, "diemcrm", { prompt: "A0-DISCOVER hello" });
    const parent = offeredSets(discovery.requests, "A0-DISCOVER")[0];
    expect(parent, "parent set").toEqual(sorted(without(APPROVED_DEFAULT_SET, "Bash")));
    const advertised = discovery.requests
      .flatMap((q) => q.userTexts)
      .flatMap((text) => {
        const at = text.indexOf("Available agent types for the Agent tool:");
        if (at < 0) return [];
        const block = text.slice(at).split("\n\n")[0];
        return block.split("\n").flatMap((line) => /^- ([A-Za-z0-9_-]+):/.exec(line)?.[1] ?? []);
      });
    const types = [...new Set(advertised)];
    expect(types, "advertised subagent types").toEqual(expect.arrayContaining(["general-purpose", "probe-agent"]));
    for (const [index, type] of types.entries()) {
      scripts.push(agentCall(`A${index + 1}-TYPE`, `SUB-A${index + 1} go`, type));
      const run = await chat(r, "diemcrm", { prompt: `A${index + 1}-TYPE delegate to ${type}` });
      const subs = offeredSets(run.requests, `SUB-A${index + 1}`);
      expect(subs.length, `${type}: subagent request recorded`).toBeGreaterThan(0);
      for (const sub of subs) {
        evidence(`subagent ${type} under deny [Bash]`, sub);
        expect(sub.filter((name) => !parent.includes(name)), `${type}: tool outside the parent's grant`).toEqual([]);
        expect(sub, `${type}: Bash`).not.toContain("Bash");
      }
      expectNoUnreviewed(run.requests, type);
    }
  }, 600_000);
});

describe("the policy can name every tool the runtime offers, one at a time (real runtime)", () => {
  const names = [...INVENTORY, "Task"];
  const policy = {
    default: { allow: ["Read"] },
    labels: Object.fromEntries(names.flatMap((name) => [[`allow-${name}`, { allow: [name] }], [`deny-${name}`, { deny: [name] }]])),
  };
  const labels = ["reqlift", "diemcrm", ...names.flatMap((name) => [`allow-${name}`, `deny-${name}`])];
  const own: Cleanup[] = [];
  let shared: Rig;
  beforeAll(async () => {
    shared = await startRig({ policy, labels, cleanupList: own });
  }, 120_000);
  afterAll(async () => {
    while (own.length > 0) await own.pop()!();
  });

  it("a label without an entry falls back to the default entry", async () => {
    const fallback = await chat(shared, "reqlift", { prompt: "N0-DEFAULT hello" });
    expectOffered(fallback.requests, "N0-DEFAULT", ["Read"], "default allow [Read]");
  });

  it.each(names.map((name, index) => [name, index] as const))("%s: allowed alone it is the only tool offered; denied alone it is the only tool missing from the default set", async (name, index) => {
    const offered = ALIASES[name] ?? name;
    const only = await chat(shared, `allow-${name}`, { prompt: `N${index}-ALLOW-${name} hello` });
    expectOffered(only.requests, `N${index}-ALLOW-${name}`, [offered], `allow only ${name}`);
    const rest = await chat(shared, `deny-${name}`, { prompt: `N${index}-DENY-${name} hello` });
    expectOffered(rest.requests, `N${index}-DENY-${name}`, without(APPROVED_DEFAULT_SET, offered), `deny only ${name}`);
  });

  it("the policy accepts TodoWrite: the gateway started with it and its denial removes exactly the checklist tool", async () => {
    expect(shared.gateway.output()).not.toContain("FATAL");
    const rest = await chat(shared, "deny-TodoWrite", { prompt: "N-TODO-DENY hello" });
    expectOffered(rest.requests, "N-TODO-DENY", without(APPROVED_DEFAULT_SET, "TodoWrite"), "deny TodoWrite for one label");
  });
});

/* ------------------------------------------------------------------ */
/*  Subscription login                                                  */
/* ------------------------------------------------------------------ */

describe("a gateway that authenticates with a subscription login (real runtime)", () => {
  const ACCESS = "SYNTH-OAUTH-ACCESS-8088";

  it("offers exactly the approved default set, no claude.ai publishing tool, and the sandbox holds no login material", async () => {
    const scripts: ExactToolScript[] = [
      bash("O1-ENV", "env | sed 's/=.*//' | sort; echo ---; printenv ANTHROPIC_API_KEY | cut -c1-4; echo ---; ls -A /home/node /home/node/.claude"),
    ];
    const r = await startRig({
      scripts,
      env: { ANTHROPIC_API_KEY: null },
      seed: (workspace) => {
        fs.writeFileSync(
          path.join(workspace, ".credentials.json"),
          JSON.stringify({ claudeAiOauth: { accessToken: ACCESS, refreshToken: "SYNTH-OAUTH-REFRESH-8088", expiresAt: Date.now() + 3_600_000, scopes: ["user:inference"], subscriptionType: "max" } }),
          { mode: 0o600 },
        );
      },
    });
    const { status, requests } = await chat(r, "reqlift", { prompt: "O1-ENV show the environment" });
    expect(status).toBe(200);
    expectOffered(requests, "O1-ENV", APPROVED_DEFAULT_SET, "O1 subscription login");
    for (const name of ["Artifact", "SendUserFile", "ShareOnboardingGuide"]) {
      expect(requests.flatMap((q) => q.tools), name).not.toContain(name);
    }
    // The provider saw the subscription credential, the runtime only ever held the run token (simulated: the provider is the double).
    const main = requests.find((q) => q.userTexts.some((t) => t.includes("O1-ENV")) && q.tools.length > 0);
    expect(main?.authorization).toBe(`Bearer ${ACCESS}`);
    expect(main?.anthropicBeta ?? "").toContain("oauth-2025-04-20");
    expect(main?.body ?? "").not.toContain(ACCESS);
    const output = resultOf(requests, "O1-ENV")?.text ?? "";
    const [keys, token, listing] = output.split("---\n");
    expect(keys.split("\n").filter((key) => /OAUTH|AUTH_TOKEN|ACCESS_TOKEN|REFRESH|CREDENTIAL/i.test(key))).toEqual([]);
    expect(keys.split("\n")).toContain("ANTHROPIC_API_KEY");
    expect(token.trim()).toBe("mpt_");
    expect(listing).not.toContain(".credentials.json");
    expect(output).not.toContain(ACCESS);
  });
});

/* ------------------------------------------------------------------ */
/*  Names the runtime does not offer                                    */
/* ------------------------------------------------------------------ */

async function startOnly(policy: unknown): Promise<{ code: number | null; output: string; port: number }> {
  const root = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), "mvp8088-start-"));
  cleanups.push(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const dir of ["home", "tmp", "persist"]) fs.mkdirSync(path.join(root, dir));
  const port = await reserveGatewayPort();
  const child = spawn(process.execPath, [path.join(REPO_ROOT, "dist", "server.js")], {
    cwd: path.join(root, "home"),
    env: {
      PATH: process.env.PATH ?? "",
      HOME: path.join(root, "home"),
      TMPDIR: path.join(root, "tmp"),
      PORT: String(port),
      HOST: "127.0.0.1",
      API_KEYS: `reqlift:${keyFor("reqlift")}`,
      SESSION_PERSIST_PATH: path.join(root, "persist", "sessions.json"),
      TOOLS_PERSIST_PATH: path.join(root, "persist", "tools.json"),
      MCP_SERVERS_PERSIST_PATH: path.join(root, "persist", "mcp-servers.json"),
      WORKSPACE_ROOT: path.join(root, "home", ".claude"),
      AGENT_TOOL_POLICY: JSON.stringify(policy),
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  child.stdout.on("data", (d: Buffer) => (output += d.toString("utf8")));
  child.stderr.on("data", (d: Buffer) => (output += d.toString("utf8")));
  cleanups.push(() => {
    if (child.exitCode === null) child.kill("SIGKILL");
    releaseGatewayPort(port);
  });
  const code = await new Promise<number | null>((resolve) => {
    const timer = setTimeout(() => resolve(null), 20_000);
    child.once("exit", (exitCode) => {
      clearTimeout(timer);
      resolve(exitCode);
    });
  });
  return { code, output, port };
}

function listening(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = net.connect({ host: "127.0.0.1", port }, () => {
      socket.destroy();
      resolve(true);
    });
    socket.on("error", () => resolve(false));
  });
}

describe("a policy naming a tool the configured runtime does not offer", () => {
  it.each([["TaskOutput"], ["LSP"], ["AskUserQuestion"], ["TaskCreate"], ["Artifact"]])("%s stops the gateway at startup and no run is served", async (name) => {
    const { code, output, port } = await startOnly({ default: { deny: [name] } });
    expect(code).toBe(1);
    expect(output).toContain("FATAL config key=AGENT_TOOL_POLICY reason=unknown built-in tool name");
    expect(output).not.toContain(name);
    expect(await listening(port)).toBe(false);
  });
});

/* ------------------------------------------------------------------ */
/*  The committed inventory of the bundled runtime                      */
/* ------------------------------------------------------------------ */

interface Observation {
  /** The built-ins the runtime offers started the way the gateway starts it, without a `--tools` list. */
  offered: string[];
  /** What `--tools <alias>` offers, per alias. */
  aliasOffers: Record<string, string[]>;
}

/** The runtime keys the gateway's sandbox environment sets (never HOME, PATH or credentials). */
function gatewayRuntimeEnv(): Record<string, string> {
  const full = buildSandboxEnv({ sdkEnv: {}, gatewayEnv: {}, proxyBaseUrl: "http://127.0.0.1:1", runToken: "mpt_inventory", runLogEnv: {} });
  return Object.fromEntries(Object.entries(full).filter(([key]) => /^(CLAUDE_|DISABLE_AUTOUPDATER$|MCP_CONNECTION_NONBLOCKING$)/.test(key)));
}

async function observeRuntime(tools?: string[]): Promise<string[]> {
  const api = await startFakeAnthropicApi({ toolName: "unused-8088" });
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "mvp8088-inventory-"));
  try {
    const abort = new AbortController();
    const timer = setTimeout(() => abort.abort(), 90_000);
    const stream = query({
      prompt: "INVENTORY-PROBE say hello",
      options: {
        cwd: home,
        abortController: abort,
        permissionMode: "bypassPermissions",
        settingSources: ["user"],
        // The gateway's default model: the runtime's default set depends on the model (without one it offers no TodoWrite).
        model: "claude-opus-4-6",
        systemPrompt: { type: "preset", preset: "claude_code" },
        // Measured (Gate A): the runtime leaves Glob and Grep out of its default set unless the run pre-approves them, as the
        // gateway's runs do; an explicit `tools` list offers them either way.
        allowedTools: ["Glob", "Grep"],
        ...(tools ? { tools } : {}),
        env: { ...gatewayRuntimeEnv(), HOME: home, TMPDIR: home, PATH: process.env.PATH ?? "", ANTHROPIC_BASE_URL: api.baseUrl, ANTHROPIC_API_KEY: "sk-ant-fake-inventory-8088" },
      },
    });
    for await (const message of stream) if (message.type === "result") break;
    clearTimeout(timer);
    const offered = offeredSets(api.requests, "INVENTORY-PROBE");
    expect(offered.length, "inventory probe request recorded").toBeGreaterThan(0);
    return offered[0];
  } finally {
    await api.close();
    fs.rmSync(home, { recursive: true, force: true });
  }
}

let observation: Promise<Observation> | undefined;
function observed(): Promise<Observation> {
  observation ??= (async () => ({ offered: await observeRuntime(), aliasOffers: { Task: await observeRuntime(["Task"]) } }))();
  return observation;
}

/** What differs between the reviewed inventory (names, aliases) and what the runtime offers; empty when they agree. */
function inventoryProblems(reviewed: readonly string[], aliases: Readonly<Record<string, string>>, seen: Observation): string[] {
  const problems: string[] = [];
  const canonical = reviewed.filter((name) => !(name in aliases));
  for (const name of seen.offered) if (!canonical.includes(name)) problems.push(`the runtime offers ${name}, which is not listed`);
  for (const name of canonical) if (!seen.offered.includes(name)) problems.push(`${name} is listed, but the runtime no longer offers it`);
  for (const [alias, target] of Object.entries(aliases)) {
    if (!reviewed.includes(alias)) problems.push(`the alias ${alias} is not in the reviewed list`);
    const got = seen.aliasOffers[alias] ?? [];
    if (got.length !== 1 || got[0] !== target) problems.push(`the alias ${alias} resolves to ${got.join(",") || "nothing"}, reviewed as ${target}`);
  }
  return problems;
}

describe("the reviewed inventory against the bundled runtime", () => {
  const reviewedNames = [...toolGrant.RUNTIME_BUILT_IN_TOOLS];
  const reviewedAliases: Record<string, string> = (toolGrant as { BUILT_IN_ALIASES?: Record<string, string> }).BUILT_IN_ALIASES ?? {};

  it("the gateway's inventory is exactly what the runtime offers when started as the gateway starts it, plus the Task alias", async () => {
    const seen = await observed();
    evidence("runtime inventory", seen.offered);
    expect(sorted(seen.offered), "runtime offers (written-out expectation)").toEqual(sorted(INVENTORY));
    expect(sorted(reviewedNames), "reviewed inventory").toEqual(sorted([...INVENTORY, "Task"]));
    expect(reviewedAliases).toEqual(ALIASES);
    expect(inventoryProblems(reviewedNames, reviewedAliases, seen)).toEqual([]);
  });

  it.each([
    ["a tool the runtime offers but is not listed", () => ({ names: without(reviewedNames, "Workflow"), aliases: reviewedAliases }), "the runtime offers Workflow"],
    ["a listed tool the runtime no longer offers", () => ({ names: [...reviewedNames, "TaskOutput"], aliases: reviewedAliases }), "TaskOutput is listed, but the runtime no longer offers it"],
    ["an alias that resolves to a different tool", () => ({ names: reviewedNames, aliases: { Task: "Bash" } }), "the alias Task resolves to Agent, reviewed as Bash"],
  ])("a drift is caught and names the tool: %s", async (_label, mutate, expected) => {
    const seen = await observed();
    const { names, aliases } = mutate();
    const problems = inventoryProblems(names, aliases, seen);
    expect(problems.length, "the comparator must fail on this drift").toBeGreaterThan(0);
    expect(problems.join("\n")).toContain(expected);
  });
});
