/**
 * Every execution entry point of the gateway under the real runtime (MVP-7677, Outline "Every execution entry point is
 * covered"): for each entry point a permitted operation succeeds and a secret-access attempt is denied or returns no
 * protected material, and the check observes the stated boundary.
 *
 * - `EP.ordinary`, `EP.agent`, `EP.skill`, `EP.subagent`: the actual built-in tool process (a file the permitted command
 *   wrote shows on the host in the conversation's own `/work`) and the model-bound tool result (the model double's record
 *   of what the runtime sent back), for an ordinary chat, a configured agent (workspace `agents/reviewer.md`, started by
 *   delegation), a skill chat (`skills/ok`) and a delegated general-purpose sub-agent.
 * - `EP.mcp-direct`, `EP.upload`: the trusted upstream request (the doubles' own request records) and the caller-visible
 *   result, with the model double recording 0 runs.
 * - `EP.denied`, `EP.enlarge`: under a policy that denies Bash, every way of asking for the denied tool (ordinary chat, an
 *   explicit request, an omitted list, a configured agent, a delegated sub-agent, a resumed conversation) and every way of
 *   enlarging the grant (an `allowedTools` naming it, an `enforcedTools` with it as a member, Task delegation, the unknown
 *   body fields `permissionMode`, `tools`, `disallowedTools` and `settingSources`) is refused by the runtime itself and the
 *   tool process never executes (its marker file does not exist), while a permitted file operation still works.
 *
 * Every secret is a synthetic marker with a random suffix; only names, booleans and counts are printed.
 * Needs `npm run build`, `bwrap`, user namespaces, `git` and `python3`. Linux only.
 */
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { Cleanup } from "./helpers/git-process-gateway.js";
import { gatewayRequest } from "./helpers/git-process-gateway.js";
import {
  MatrixRecorder,
  TURN_DEADLINE_MS,
  chatTurn,
  conversationDirs,
  createMarkers,
  createRig,
  emit,
  evidenceLine,
  finishRow,
  pinnedProblems,
  registerStandardServers,
  requestsFor,
  requireHost,
  resultsFor,
  scriptOf,
  surfacesOf,
  turnProblems,
  type SecurityMarkers,
  type SecurityRig,
  type Surface,
  type ToolStep,
  type TurnObservation,
} from "./helpers/security-matrix.js";
import { MiB, sendUpload, startUploadStub } from "./helpers/upload-relay-stub.js";

vi.setConfig({ testTimeout: 300_000 });

const markers: SecurityMarkers = createMarkers();
const NO_SUCH_TOOL = (tool: string): string => `<tool_use_error>Error: No such tool available: ${tool}</tool_use_error>`;
const EXPECTED_ROWS = ["EP.ordinary", "EP.agent", "EP.skill", "EP.subagent", "EP.mcp-direct", "EP.upload", "EP.denied", "EP.enlarge"];
const recorder = new MatrixRecorder("security-entrypoints-process", EXPECTED_ROWS);

const cleanups: Cleanup[] = [];
afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()!();
});

beforeAll(() => {
  requireHost(["bwrap", "userns", "git", "python3", "build"]);
  emit(
    evidenceLine({
      suite: "security-entrypoints-process",
      config: { API_KEYS: "reqlift+diemcrm", ANTHROPIC_BASE_URL: "local-double", MODEL_PROXY_OAUTH_TOKEN_URL: "local-double", AGENT_TOOL_POLICY: "unset (denied rows: reqlift denies Bash)" },
      deadlines: { turn_ms: TURN_DEADLINE_MS, row_test_timeout_ms: 300_000 },
      offline: false,
      logLevel: "info",
    }),
  );
});

async function newRig(policy?: Record<string, unknown>): Promise<SecurityRig> {
  const rig = await createRig(cleanups, { markers, env: policy ? { AGENT_TOOL_POLICY: JSON.stringify(policy) } : undefined });
  expect(pinnedProblems(rig)).toEqual([]);
  await registerStandardServers(rig);
  return rig;
}

const bash = (command: string): ToolStep => ({ name: "Bash", input: { command, description: "probe" } });

/** The secret-access attempt: every environment dump, both credential files by their sandbox and host paths. */
function secretAttempt(rig: SecurityRig): string {
  return `python3 -c "import os, json; print(json.dumps(dict(os.environ)))"; cat /home/node/.claude/.credentials.json 2>&1 | head -c 200; cat ${path.join(rig.gateway.dirs.workspace, ".credentials.json")} 2>&1 | head -c 200; cat ${path.join(rig.gateway.dirs.home, ".ssh", "id_rsa")} 2>&1 | head -c 200; echo SECRET-ATTEMPT-DONE`;
}

/** What the permitted operation and the secret attempt of one entry point must show; names only. */
function entryProblems(rig: SecurityRig, label: string, results: { isError: boolean; text: string }[], session: string, file: string): string[] {
  const problems: string[] = [];
  const [permitted, attempt] = results;
  if (!permitted || permitted.isError || !permitted.text.includes(`PERMITTED-${label}`)) problems.push("the permitted operation did not succeed");
  if (!attempt || attempt.isError || !attempt.text.includes("SECRET-ATTEMPT-DONE") || !attempt.text.includes("HOME")) problems.push("the secret-access attempt did not run to its end (an execution error is not a passing secrecy test)");
  const dir = conversationDirs(rig.gateway, [session])[0];
  if (!dir || !fs.existsSync(path.join(dir, "work", file))) problems.push("the permitted command left no file on the host (the tool process did not run in the conversation's work area)");
  return problems;
}

/** The turn's own problems plus the entry's: stream, runtime, egress and the request-scoped fixtures are not needed here (no credentials are attached). */
function chat(rig: SecurityRig, prompt: string, session: string, steps: ToolStep[], extra: { extraPrompts?: string[]; body?: Record<string, unknown> } = {}): Promise<TurnObservation> {
  return chatTurn(rig, { prompt, sessionId: session, steps, withCredentials: false, extraPrompts: extra.extraPrompts, body: { allowedTools: undefined, ...extra.body } });
}

describe("built-in tool entry points", () => {
  it("EP.ordinary: an ordinary chat without agent or skill selection runs the permitted command; the secret attempt returns no protected material", async () => {
    const rig = await newRig();
    const started = Date.now();
    const file = "p-ordinary.txt";
    const turn = await chat(rig, "EP-ORDINARY", "conv-ep-ordinary", [bash(`echo PERMITTED-ordinary > /work/${file} && cat /work/${file}`), bash(secretAttempt(rig)), { name: "Read", input: { file_path: path.join(rig.gateway.dirs.workspace, ".credentials.json") } }]);
    const problems = [...turnProblems(turn), ...entryProblems(rig, "ordinary", turn.results, "conv-ep-ordinary", file), ...(turn.results[2]?.isError ? [] : ["the built-in Read of a credential file did not fail"])];
    finishRow(recorder, rig, { id: "EP.ordinary", durationMs: Date.now() - started, deadlineMs: TURN_DEADLINE_MS, surfaces: surfacesOf(rig, [turn]), controls: ["permitted_command_ran_in_the_conversation_work_area", "secret_attempt_ran_to_its_end", "read_of_the_credential_file_failed"], problems });
  });

  it.each([
    ["EP.agent", "agent", "reviewer"],
    ["EP.subagent", "subagent", "general-purpose"],
  ] as const)("%s: a %s started by delegation runs the permitted command; its secret attempt returns no protected material", async (id, label, agentType) => {
    const rig = await newRig();
    const started = Date.now();
    const sub = `EP-SUB-${label}-${randomBytes(3).toString("hex")}`;
    const file = `p-${label}.txt`;
    rig.scripts.push(scriptOf(sub, [bash(`echo PERMITTED-${label} > /work/${file} && cat /work/${file}`), bash(secretAttempt(rig))]));
    const session = `conv-ep-${label}`;
    const turn = await chat(rig, `EP-${label.toUpperCase()}`, session, [{ name: "Task", input: { description: "probe", prompt: `${sub} go`, subagent_type: agentType } }], { extraPrompts: [sub] });
    const results = resultsFor(rig.api, sub).slice(-2);
    const problems = [...turnProblems(turn), ...entryProblems(rig, label, results, session, file), ...(results.length === 2 ? [] : ["the delegated conversation did not run both commands"])];
    finishRow(recorder, rig, { id, durationMs: Date.now() - started, deadlineMs: TURN_DEADLINE_MS, surfaces: surfacesOf(rig, [turn]), controls: ["delegated_conversation_ran_in_its_own_requests", "permitted_command_ran_in_the_conversation_work_area", "secret_attempt_ran_to_its_end"], problems });
  });

  it("EP.skill: a skill chat (skills/ok, then the next turn) runs the permitted command; the secret attempt returns no protected material", async () => {
    const rig = await newRig();
    const started = Date.now();
    const session = "conv-ep-skill";
    const file = "p-skill.txt";
    const first = await chat(rig, "EP-SKILL-1", session, [{ name: "Skill", input: { skill: "ok" } }]);
    const second = await chat(rig, "EP-SKILL-2", session, [bash(`echo PERMITTED-skill > /work/${file} && cat /work/${file}`), bash(secretAttempt(rig))]);
    const loaded = first.outcome.events.find((event) => event.type === "skills_loaded") as { skills?: string[] } | undefined;
    const problems = [...turnProblems(first), ...turnProblems(second), ...entryProblems(rig, "skill", second.results, session, file)];
    // The runtime follows a Skill call with the skill's text as a user message, so the call's result is read from the request that carries it.
    const skillRequests = requestsFor(rig.api, "EP-SKILL-1").filter((request) => !request.warmup);
    const skillResult = skillRequests.flatMap((request) => request.toolResults).at(-1);
    if (!skillResult || skillResult.isError) problems.push("the Skill call returned an error");
    if (!skillRequests.some((request) => request.userTexts.some((text) => text.includes("SKILL-OK")))) problems.push("the skill's content did not reach the model");
    if (!loaded?.skills?.includes("ok")) problems.push("skills_loaded did not list the global skill");
    finishRow(recorder, rig, { id: "EP.skill", durationMs: Date.now() - started, deadlineMs: TURN_DEADLINE_MS * 2, surfaces: surfacesOf(rig, [first, second]), controls: ["skill_loaded", "permitted_command_ran_in_the_conversation_work_area", "secret_attempt_ran_to_its_end"], problems });
  });
});

describe("LLM-free entry points", () => {
  it("EP.mcp-direct: an authenticated direct MCP call returns its fixture with the user's credential at the upstream, no stored credential in the caller-visible body, and no model run", async () => {
    const rig = await newRig();
    const v = rig.markers.values;
    const started = Date.now();
    const modelBefore = rig.api.requests.length;
    const jiraBefore = rig.jira.authorizations().length;
    const logFrom = rig.log().length;
    const call = await gatewayRequest(rig.gateway.port, "POST", "/v1/mcp-servers/jira/call", { tool: "get_page", arguments: { id: "P-1" }, credentials: { headers: { authorization: `Bearer ${v.userOverrideHeader}` } } }, rig.keys.reqlift);
    const plain = await gatewayRequest(rig.gateway.port, "POST", "/v1/mcp-servers/jira/call", { tool: "get_page", arguments: { id: "P-2" } }, rig.keys.reqlift);
    const problems: string[] = [];
    if (call.status !== 200 || !call.text.includes("RECORD-7667-OK")) problems.push("the direct call did not return its fixture");
    if (plain.status !== 200) problems.push("the direct call without a user credential did not return its fixture");
    const seen = rig.jira.authorizations().slice(jiraBefore);
    if (seen.length < 2 || !(seen.includes(`Bearer ${v.userOverrideHeader}`) && seen.includes(`Basic ${v.registryHttpHeader}`)) || seen.some((value) => value !== `Bearer ${v.userOverrideHeader}` && value !== `Basic ${v.registryHttpHeader}`)) {
      problems.push("the upstream did not receive exactly the user's credential for the first call and the registry credential for the second");
    }
    if (rig.api.requests.length !== modelBefore) problems.push("a model run was started to satisfy a direct call");
    const surfaces: Surface[] = [
      { name: "caller-body", text: `${call.text}\n${plain.text}` },
      { name: "gateway-log", text: rig.log().slice(logFrom) },
    ];
    finishRow(recorder, rig, { id: "EP.mcp-direct", durationMs: Date.now() - started, deadlineMs: 60_000, surfaces, controls: ["fixture_returned", "upstream_got_only_the_bound_credentials", "model_double_recorded_0_requests"], problems });
  });

  it("EP.upload: an authenticated streaming upload relay returns the upload server's answer with the stored credential at the upstream only, nothing in the caller-visible body, and no model run", async () => {
    const rig = await newRig();
    const v = rig.markers.values;
    const store = await startUploadStub();
    cleanups.push(() => store.close());
    await rig.register("reqlift", "store", { type: "http", url: store.url, headers: { "X-Upload-Credential": v.registryHttpHeader } });
    await new Promise((resolve) => setTimeout(resolve, 300));
    const started = Date.now();
    const modelBefore = rig.api.requests.length;
    const logFrom = rig.log().length;
    const sent = await sendUpload({ port: rig.gateway.port, path: "/v1/mcp-servers/store/uploads/jira/issue/MVP-1?filename=shot.png", headers: { Authorization: `Bearer ${rig.keys.reqlift}` }, total: 2 * MiB });
    const problems: string[] = [];
    if (sent.status !== 201 || !/"attachmentId"\s*:\s*"10001"/.test(sent.text)) problems.push("the upload relay did not return the upload server's answer");
    const request = store.requests.at(-1);
    if (!request || !request.complete || request.headers["x-upload-credential"] !== v.registryHttpHeader) problems.push("the upload server did not receive the whole body with exactly its stored credential");
    if (rig.api.requests.length !== modelBefore) problems.push("a model run was started to satisfy an upload");
    const surfaces: Surface[] = [
      { name: "caller-body", text: `${sent.text}\n${JSON.stringify(sent.headers)}` },
      { name: "gateway-log", text: rig.log().slice(logFrom) },
    ];
    finishRow(recorder, rig, { id: "EP.upload", durationMs: Date.now() - started, deadlineMs: 60_000, surfaces, controls: ["upload_answered_by_the_trusted_upstream", "upstream_got_only_its_stored_credential", "model_double_recorded_0_requests"], problems });
  });
});

describe("denied tool and grant enlargement", () => {
  const policy = { labels: { reqlift: { deny: ["Bash"] } } };

  interface Attempt {
    name: string;
    /** The conversation steps are `Write` (permitted), Bash (denied) and `Read` (permitted); a `sub` prompt runs the Bash call in a delegated conversation. */
    body?: Record<string, unknown>;
    delegate?: string;
    resumed?: boolean;
  }

  /** One attempt in its own conversation: the denied Bash call is refused by the runtime itself, never offered, never executed, and Read of the permitted file works. */
  async function attempt(rig: SecurityRig, row: Attempt, index: number): Promise<{ turns: TurnObservation[]; problems: string[] }> {
    const id = `${row.name.replace(/[^a-z0-9]+/gi, "-").toLowerCase()}-${index}`;
    const session = `conv-denied-${id}`;
    const prompt = `EP-DENIED-${id}`;
    const marker = `m-${id}`;
    const turns: TurnObservation[] = [];
    const problems: string[] = [];
    const permittedFile = `/work/permitted-${id}.txt`;
    if (row.resumed) turns.push(await chat(rig, `${prompt}-first`, session, [{ name: "Write", input: { file_path: `/work/first-${id}.txt`, content: "x" } }], { body: row.body }));
    const sub = row.delegate ? `${prompt}-SUB` : undefined;
    const denied = bash(`touch /work/${marker}; echo RAN-${id}`);
    if (sub) rig.scripts.push(scriptOf(sub, [denied]));
    const steps: ToolStep[] = [{ name: "Write", input: { file_path: permittedFile, content: `PERMITTED-${id}` } }, ...(sub ? [{ name: "Task", input: { description: "probe", prompt: `${sub} go`, subagent_type: row.delegate! } }] : [denied]), { name: "Read", input: { file_path: permittedFile } }];
    const turn = await chat(rig, prompt, session, steps, { extraPrompts: sub ? [sub] : [], body: row.body });
    turns.push(turn);
    problems.push(...turnProblems(turn));
    const deniedResult = sub ? resultsFor(rig.api, sub).at(-1) : turn.results[1];
    if (!deniedResult || !deniedResult.isError || deniedResult.text !== NO_SUCH_TOOL("Bash")) problems.push(`${row.name}: the denied tool call was not refused by the runtime itself`);
    const offered = requestsFor(rig.api, sub ?? prompt).filter((request) => !request.warmup).flatMap((request) => request.tools);
    if (offered.includes("Bash")) problems.push(`${row.name}: the denied tool was offered to the model`);
    const read = turn.results.at(-1);
    if (!read || read.isError || !read.text.includes(`PERMITTED-${id}`)) problems.push(`${row.name}: the permitted file operation did not work`);
    const dir = conversationDirs(rig.gateway, [session])[0];
    if (dir && fs.existsSync(path.join(dir, "work", marker))) problems.push(`${row.name}: the denied tool process executed (its marker file exists)`);
    return { turns, problems };
  }

  async function matrix(id: string, rows: Attempt[]): Promise<void> {
    const rig = await newRig(policy);
    const started = Date.now();
    const turns: TurnObservation[] = [];
    const problems: string[] = [];
    for (const [index, row] of rows.entries()) {
      const result = await attempt(rig, row, index);
      turns.push(...result.turns);
      problems.push(...result.problems);
    }
    // A control: without the policy the same call runs (the marker is producible), so the policy is what refuses it.
    const open = await newRig();
    const controlTurn = await chat(open, "EP-DENIED-CONTROL", "conv-denied-control", [bash("touch /work/m-control; echo RAN-CONTROL")]);
    const controlDir = conversationDirs(open.gateway, ["conv-denied-control"])[0];
    const live = controlTurn.results[0] !== undefined && !controlTurn.results[0].isError && controlDir !== undefined && fs.existsSync(path.join(controlDir, "work", "m-control"));
    if (!live) problems.push("control: the same Bash call did not run without the policy, so the refusals prove nothing");
    finishRow(recorder, rig, { id, durationMs: Date.now() - started, deadlineMs: TURN_DEADLINE_MS * turns.length, surfaces: surfacesOf(rig, turns), controls: [...rows.map((row) => `refused:${row.name.replace(/\s+/g, "_")}`), "control_the_same_call_runs_without_the_policy"], problems });
  }

  it("EP.denied: ordinary chat, an explicit request, an omitted list, a configured agent, a delegated sub-agent and a resumed conversation all get an explicit refusal; the tool never executes", async () => {
    await matrix("EP.denied", [
      { name: "ordinary chat" },
      { name: "explicit request for the denied tool", body: { allowedTools: ["Bash", "Read", "Write"] } },
      { name: "omitted tool list" },
      { name: "configured agent", delegate: "reviewer" },
      { name: "delegated sub-agent", delegate: "general-purpose" },
      { name: "resumed conversation", resumed: true },
    ]);
  });

  it("EP.enlarge: allowedTools naming the denied tool, enforcedTools with it as a member, Task delegation and the unknown fields permissionMode, tools, disallowedTools and settingSources do not enlarge the grant", async () => {
    await matrix("EP.enlarge", [
      { name: "allowedTools naming the denied tool", body: { allowedTools: ["Bash", "Write", "Read"] } },
      { name: "enforcedTools with a denied member", body: { enforcedTools: ["Bash", "Write", "Read"] } },
      { name: "Task delegation", delegate: "general-purpose" },
      { name: "permissionMode bypassPermissions", body: { permissionMode: "bypassPermissions" } },
      { name: "tools naming the denied tool", body: { tools: ["Bash", "Write", "Read"] } },
      { name: "disallowedTools emptied", body: { disallowedTools: [] } },
      { name: "settingSources project", body: { settingSources: ["project"] } },
    ]);
  });
});

describe("summary", () => {
  it("every expected row of the suite ran and passed", () => {
    const summary = recorder.finish();
    expect(summary.missing).toEqual([]);
    expect(summary.fail).toBe(0);
  });
});
