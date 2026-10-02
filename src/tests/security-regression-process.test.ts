/**
 * The real-process security regression suite (MVP-7677): the compiled gateway (`dist/server.js`) with the production
 * Claude Agent SDK, its bundled runtime, real `bwrap`, a scripted model double and recording MCP, webhook and git
 * doubles. Every credential in it is a synthetic marker with a random suffix; the observation surfaces are the raw
 * tool outputs, the model-bound request bodies, the NDJSON events, the gateway log and the conversation's own
 * transcripts, `/work`, home and per-run leftovers. Only case names, booleans and counts are printed
 * (`SECURITY-MATRIX` lines, one per row, with a stable AC row id).
 *
 * - `RP.regression`: the Real-process regression scenario (an ordinary chat shows its environment and resumes; the
 *   authorized operations of the request-scoped credentials still work; no marker on any surface).
 * - `RT.<route>.<mode>`: the eight secret routes of the outline in fresh, resumed and restarted execution. Every
 *   route run carries the request-scoped credentials live, and the doubles confirm they received them in that run.
 *   Concurrent roles overlap the process and session scans: a conversation of another label and one of the same
 *   label with another user (each holding its marker in `/work`), a stdio tool sandbox and a slow trusted git clone.
 * - `NC.*.<mode>`: the exact normal-chat route: three turns of `env | sort` in one ordinary conversation, then an
 *   allowed workspace command, an alternate interpreter environment read and a built-in Read of a credential file.
 * - `X.*`: rows for leftovers of an earlier version in a conversation home, writes into the read-only extension
 *   directories and the trusted git configuration.
 * - The negative controls prove the detector end to end: a child vitest run of the same row against a deliberately
 *   vulnerable copy of `dist/` (offline, in a loopback-only namespace) must exit nonzero, name the row and report
 *   hits, and print no marker value.
 *
 * The child run selects rows with `-t`, so a row's test name carries its selector: `regression row` for the regression
 * scenario, `route config probe` for the file detector. No other test name may contain either phrase.
 *
 * Needs `npm run build`, `bwrap`, user namespaces, `unshare`, `git` and `python3`; a missing prerequisite fails with
 * `host prerequisite missing: <name>`. Linux only.
 */
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { createFakeGit, type FakeGit } from "./helpers/fake-git.js";
import { REPO_ROOT, gatewayRequest, type Cleanup } from "./helpers/git-process-gateway.js";
import {
  MatrixRecorder,
  STDIO_SOURCE,
  TURN_DEADLINE_MS,
  chatTurn,
  conversationDirs,
  createMarkers,
  createRig,
  emit,
  evidenceLine,
  finishRow,
  offlineAvailable,
  offlinePrefix,
  pinnedProblems,
  registerStandardServers,
  requestsFor,
  requireHost,
  resultsFor,
  runChild,
  runLeftoversText,
  scriptOf,
  shellQuote,
  startProcessSampler,
  surfacesOf,
  turnProblems,
  credentialProblems,
  waitForIsolation,
  type RowInput,
  type SecurityMarkers,
  type SecurityRig,
  type ToolStep,
  type TurnObservation,
} from "./helpers/security-matrix.js";
import { ROUTE_IDS, credentialSteps, routeTurn, type RouteId, type RouteTurn } from "./helpers/security-routes.js";

const ROW_TEST_TIMEOUT_MS = 600_000;
vi.setConfig({ testTimeout: ROW_TEST_TIMEOUT_MS });

/** A child run of this file (the negative control) shares the parent's marker seed and runs offline. */
const IS_CHILD = process.env.SECURITY_CHILD === "1";
const NEGATIVE_CONTROL_DIST = process.env.SECURITY_NEGATIVE_CONTROL;
const markers: SecurityMarkers = createMarkers();

type Mode = "fresh" | "resumed" | "restarted";
const MODES: Mode[] = ["fresh", "resumed", "restarted"];

const EXPECTED_ROWS = [
  "RP.regression",
  ...MODES.flatMap((mode) => ROUTE_IDS.map((route) => `RT.${route}.${mode}`)),
  ...MODES.flatMap((mode) => [`NC.chat.${mode}`, `NC.interpreter.${mode}`, `NC.read.${mode}`]),
  "X.gitconfig",
  "X.leftovers",
  "X.extension-writes",
  "X.run-leftovers",
  "RP.negative-control",
  "RP.negative-control.file-detector",
];
const recorder = new MatrixRecorder("security-regression-process", EXPECTED_ROWS);

const cleanups: Cleanup[] = [];
afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()!();
});

beforeAll(() => {
  requireHost(["bwrap", "userns", "unshare", "git", "python3", "build"]);
  emit(
    evidenceLine({
      suite: "security-regression-process",
      config: { API_KEYS: "reqlift+diemcrm", ANTHROPIC_BASE_URL: "local-double", MODEL_PROXY_OAUTH_TOKEN_URL: "local-double", CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1", AGENT_TOOL_POLICY: "unset", LOG_LEVEL: "info (debug in the restarted modes)" },
      deadlines: { turn_ms: TURN_DEADLINE_MS, row_test_timeout_ms: ROW_TEST_TIMEOUT_MS, negative_control_child_ms: 240_000 },
      offline: process.env.SECURITY_OFFLINE === "1",
      logLevel: "info",
    }),
  );
});

/* ------------------------------------------------------------------ */
/*  Shared row machinery                                                */
/* ------------------------------------------------------------------ */

async function newRig(options: { logLevel?: "info" | "debug"; fake?: FakeGit } = {}): Promise<SecurityRig> {
  const rig = await createRig(cleanups, { markers, distServer: NEGATIVE_CONTROL_DIST, logLevel: options.logLevel, fakeGitBin: options.fake?.binDir });
  expect(pinnedProblems(rig)).toEqual([]);
  await registerStandardServers(rig);
  return rig;
}

function newFakeGit(): FakeGit {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "mvp7677-fakegit-"));
  cleanups.push(() => fs.rmSync(root, { recursive: true, force: true }));
  return createFakeGit(root);
}

interface WarmTurn {
  turn: TurnObservation;
  /** Judged right after the turn: the doubles' records keep growing with later runs. */
  problems: string[];
}

/** A trivial ordinary-chat turn that only shows the conversation is alive (and carries the request-scoped credentials). */
async function warmTurn(rig: SecurityRig, prompt: string, sessionId: string): Promise<WarmTurn> {
  const turn = await chatTurn(rig, { prompt, sessionId, steps: [...credentialSteps(), { name: "Bash", input: { command: "echo FIRST-TURN > /work/first.txt; echo ok", description: "probe" } }] });
  return { turn, problems: [...turnProblems(turn), ...credentialProblems(rig, turn), ...(turn.results.at(-1)?.text.includes("ok") ? [] : ["the warm-up command did not run"])] };
}

/* ------------------------------------------------------------------ */
/*  Concurrent roles                                                    */
/* ------------------------------------------------------------------ */

interface Roles {
  tags: { b1: string; b2: string; stdio: string; git: string };
  b1Session: string;
  b2Session: string;
  sampler: ReturnType<typeof startProcessSampler>;
  fake: FakeGit;
  stop: () => Promise<void>;
}

const waiterCommand = (marker: string, file: string, tag: string): string =>
  `python3 -c ${shellQuote(`import os, sys, time\nopen('/work/${file}', 'w').write(sys.argv[1])\nend = time.time() + 150\nwhile time.time() < end and not os.path.exists('/work/stop'):\n    time.sleep(0.2)`)} ${shellQuote(marker)} ${tag}`;

/**
 * Starts the concurrent roles: a conversation of another label (and user) holding its marker in `/work` with a stdio tool
 * sandbox attached, a conversation of the same label with another user, and a slow trusted git clone carrying a token
 * URL and an ssh key. They run until `stop()`; the process sampler records when each existed.
 */
async function startRoles(rig: SecurityRig, fake: FakeGit): Promise<Roles> {
  const v = rig.markers.values;
  const id = randomBytes(3).toString("hex");
  const tags = { b1: `ROLE-B1-${id}`, b2: `ROLE-B2-${id}`, stdio: `ROLE-STDIO-${id}`, git: `slow-clone-${id}` };
  const b1Session = `conv-B1-${id}`;
  const b2Session = `conv-B2-${id}`;
  const sampler = startProcessSampler(() => rig.gateway.child.pid!, [tags.b1, tags.b2, tags.stdio, tags.git]);
  rig.scripts.push(scriptOf(`ROLE-B1 ${v.sessionBTurn}`, [{ name: "mcp__bstdio__echo", input: {} }, { name: "Bash", input: { command: waiterCommand(v.sessionBFile, "b-secret.txt", tags.b1), description: "role" } }]));
  rig.scripts.push(scriptOf(`ROLE-B2 ${v.sessionBTurn}`, [{ name: "Bash", input: { command: waiterCommand(v.sessionB2File, "b2-secret.txt", tags.b2), description: "role" } }]));
  const b1 = rig.ask(
    "diemcrm",
    {
      queryId: `q-b1-${id}`,
      sessionId: b1Session,
      prompt: `ROLE-B1 ${v.sessionBTurn}`,
      user_id: "user-b",
      useSession: true,
      enforcedTools: ["Bash", "mcp__bstdio__echo"],
      mcpServers: { bstdio: { command: "node", args: ["-e", STDIO_SOURCE, tags.stdio], env: { SERVER_TOKEN: v.requestStdioEnv } } },
    },
    200_000,
  );
  const b2 = rig.ask("reqlift", { queryId: `q-b2-${id}`, sessionId: b2Session, prompt: `ROLE-B2 ${v.sessionBTurn}`, user_id: "user-b2", useSession: true, enforcedTools: ["Bash"] }, 200_000);
  const workFile = (session: string, name: string): string => path.join(conversationDirs(rig.gateway, [session])[0] ?? "/nonexistent", "work", name);
  const end = Date.now() + 60_000;
  while (!(fs.existsSync(workFile(b1Session, "b-secret.txt")) && fs.existsSync(workFile(b2Session, "b2-secret.txt")))) {
    if (Date.now() > end) throw new Error("the concurrent conversations did not start in time");
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  // The trusted git clone: slow (so it is running during the scans), with a token URL and an ssh key in its request.
  fake.setSlow({ sleepMs: 25_000, on: ["clone"] });
  const clone = gatewayRequest(rig.gateway.port, "POST", "/v1/workspace/git/clone", { url: rig.remote.authUrl, path: tags.git, sshKey: v.sshKey }, rig.keys.diemcrm);
  await fake.waitForStart((inv) => inv.subcommand === "clone" && inv.argv.some((arg) => arg.includes(tags.git)), 20_000);
  const seen = Date.now() + 20_000;
  while (!([tags.b1, tags.b2, tags.stdio].every((tag) => sampler.peek().windows[tag]))) {
    if (Date.now() > seen) throw new Error(`a concurrent role was not seen by the process sampler: ${[tags.b1, tags.b2, tags.stdio].filter((tag) => !sampler.peek().windows[tag]).join(", ")}`);
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  return {
    tags,
    b1Session,
    b2Session,
    sampler,
    fake,
    stop: async () => {
      for (const session of [b1Session, b2Session]) {
        const dir = conversationDirs(rig.gateway, [session])[0];
        if (dir) fs.writeFileSync(path.join(dir, "work", "stop"), "stop");
      }
      await Promise.all([b1, b2, clone]);
      sampler.stop();
    },
  };
}

/** Host-side proof that every concurrent role existed for the whole scan of the probe (R2-4). */
function overlapProblems(roles: Roles, report: { t0: number; t1: number }): string[] {
  const windows = roles.sampler.peek().windows;
  const problems: string[] = [];
  for (const [role, tag] of Object.entries({ "another-label conversation": roles.tags.b1, "same-label conversation": roles.tags.b2, "stdio tool sandbox": roles.tags.stdio })) {
    const window = windows[tag];
    if (!window || window.first > report.t0 || window.last < report.t1) problems.push(`the ${role} did not overlap the scan`);
  }
  const clone = roles.fake.invocations().find((inv) => inv.subcommand === "clone" && inv.argv.some((arg) => arg.includes(roles.tags.git)));
  if (!clone || clone.start > report.t0 || (clone.end !== undefined && clone.end < report.t1)) problems.push("the trusted git clone did not overlap the scan");
  return problems;
}

/* ------------------------------------------------------------------ */
/*  Route rows                                                          */
/* ------------------------------------------------------------------ */

const LEGACY_TEXT = "This conversation was started before a gateway security update and cannot be continued safely. Please start a new conversation. Retrying will not help.";

interface Checked {
  problems: string[];
  controls: string[];
}

/** Checks of one route turn that only the host can make: concurrent roles, the other session's files, legacy refusal, redirects, identities. */
async function hostChecks(rig: SecurityRig, route: RouteId, turn: RouteTurn, roles: Roles | null): Promise<Checked> {
  const v = rig.markers.values;
  const problems: string[] = [];
  const controls: string[] = [];
  const report = turn.verdict.report;
  if ((route === "proc" || route === "session") && roles && report) {
    const overlap = overlapProblems(roles, report);
    problems.push(...overlap);
    if (overlap.length === 0) controls.push("concurrent_roles_overlapped_the_scan");
  }
  if (route === "session" && roles) {
    const present = (session: string, file: string, marker: string): boolean => {
      const dir = conversationDirs(rig.gateway, [session])[0];
      return dir !== undefined && fs.existsSync(path.join(dir, "work", file)) && fs.readFileSync(path.join(dir, "work", file), "utf8") === marker;
    };
    if (present(roles.b1Session, "b-secret.txt", v.sessionBFile) && present(roles.b2Session, "b2-secret.txt", v.sessionB2File)) controls.push("other_sessions_held_their_markers_on_the_host");
    else problems.push("the other sessions' markers were not on the host during the scan");
  }
  if (route === "legacy") {
    const count = (pattern: RegExp): number => [...rig.log().matchAll(pattern)].length;
    const refusals = (): number => Number([...rig.log().matchAll(/sessions\.legacy\.refused total=(\d+)/g)].at(-1)?.[1] ?? 0);
    const before = { requests: rig.api.requests.length, starts: count(/SDK options:/g), refusals: refusals() };
    const resumed = await rig.ask("reqlift", { queryId: `q-legacy-${randomBytes(3).toString("hex")}`, sessionId: "legacy-conv", prompt: "ROUTE-LEGACY-RESUME", user_id: "user-1", useSession: true }, 10_000);
    // The audit line travels through the gateway's output pipe: give it a moment to arrive.
    for (const end = Date.now() + 3000; refusals() < before.refusals + 1 && Date.now() < end; ) await new Promise((resolve) => setTimeout(resolve, 50));
    const after = { requests: rig.api.requests.length, starts: count(/SDK options:/g), refusals: refusals() };
    const exact = resumed.events.length === 1 && resumed.events[0].type === "error" && resumed.events[0].content === LEGACY_TEXT;
    if (!exact || resumed.ms > 2000) problems.push("the legacy conversation was not refused with its exact text within 2 s");
    if (after.requests !== before.requests) problems.push("the legacy resume made a model request");
    if (after.starts !== before.starts) problems.push("the legacy resume started a runtime");
    if (after.refusals !== before.refusals + 1) problems.push("the legacy refusal audit count did not rise by one");
    if (exact && after.requests === before.requests && after.starts === before.starts && after.refusals === before.refusals + 1) controls.push("legacy_resume_refused_before_any_run");
    if (resumed.raw.includes(v.legacyTranscript)) problems.push("the legacy refusal carried the legacy marker");
  }
  if (route === "routing" && turn.phase === "probe") {
    const [moved, hook] = turn.extraResults;
    if (moved && moved.isError && /TOOL_UNAVAILABLE/.test(moved.text) && hook && hook.isError && /TOOL_UNAVAILABLE/.test(hook.text)) controls.push("redirecting_mcp_and_webhook_refused");
    else problems.push("a credential-bearing call to a redirecting MCP server or webhook was not refused with TOOL_UNAVAILABLE");
    if (rig.otherOrigin.hits.length > 0) problems.push(`the other origin received ${rig.otherOrigin.hits.length} request(s)`);
    else controls.push("other_origin_received_nothing");
    // Another label cannot read this run's events, and another label's request with this conversation's id is a new conversation.
    const events = await gatewayRequest(rig.gateway.port, "GET", `/v1/query/${turn.turn.queryId}/events`, undefined, rig.keys.diemcrm);
    if (events.status !== 404) problems.push(`another label read the events of the run (status ${events.status})`);
    else controls.push("other_label_cannot_read_events");
    const probe = `ROUTING-OTHER-LABEL-${randomBytes(3).toString("hex")}`;
    const other = await rig.ask("diemcrm", { queryId: `q-other-${probe}`, sessionId: turn.turn.sessionId, prompt: probe, user_id: "user-1", useSession: true }, 60_000);
    const seen = requestsFor(rig.api, probe).filter((request) => !request.warmup);
    if (other.events.at(-1)?.type !== "done" || seen.length === 0 || seen.some((request) => request.userTexts.some((text) => text.includes(turn.turn.prompt)))) problems.push("another label with this conversation's id saw this conversation's content");
    else controls.push("other_label_got_a_new_conversation");
  }
  if ((route === "env" || route === "repo") && report) {
    const count = report.facts.git_config_env_vars;
    controls.push(`git_config_env_vars_${String(count)}`);
  }
  return { problems, controls };
}

/** Records one route row from its turns and the host checks. */
async function routeRow(rig: SecurityRig, route: RouteId, mode: Mode, started: number, parts: { turns: RouteTurn[]; warm?: WarmTurn[]; problems?: string[]; roles?: Roles | null; deadlineMs?: number }): Promise<void> {
  const problems: string[] = [...(parts.problems ?? [])];
  const controls = new Set<string>();
  for (const warm of parts.warm ?? []) problems.push(...warm.problems.map((problem) => `warm-up turn: ${problem}`));
  for (const [index, turn] of parts.turns.entries()) {
    problems.push(...turn.problems.map((problem) => `turn ${index + 1}: ${problem}`));
    for (const control of turn.verdict.controls) controls.add(control);
    const checked = await hostChecks(rig, route, turn, parts.roles ?? null);
    problems.push(...checked.problems);
    for (const control of checked.controls) controls.add(control);
  }
  const observations = [...(parts.warm ?? []).map((warm) => warm.turn), ...parts.turns.map((turn) => turn.turn)];
  // At debug level the gateway log carries the request text of every conversation: a concurrent conversation's own content may be in it.
  const debugLog = (parts.roles ?? null) !== null && rig.logLevel === "debug";
  if (debugLog) controls.add("debug_log_holds_concurrent_conversations_own_requests");
  finishRow(recorder, rig, {
    id: `RT.${route}.${mode}`,
    mode,
    durationMs: Date.now() - started,
    deadlineMs: parts.deadlineMs ?? TURN_DEADLINE_MS * observations.length,
    surfaces: surfacesOf(rig, observations),
    controls: [...controls],
    problems,
    ...(debugLog ? { allowedOn: { surface: "gateway-log", markers: ["sessionBTurn", "sessionBFile", "sessionB2File"] } } : {}),
  });
}

/** Runs `body` for every route; the process and session routes run inside the concurrent roles. */
async function forEachRoute(rig: SecurityRig, fake: FakeGit, body: (route: RouteId, roles: Roles | null) => Promise<void>): Promise<void> {
  for (const route of ROUTE_IDS.filter((r) => r !== "proc" && r !== "session")) await body(route, null);
  const roles = await startRoles(rig, fake);
  try {
    await body("proc", roles);
    await body("session", roles);
  } finally {
    await roles.stop();
  }
}

describe("route matrix", () => {
  it("route matrix, fresh: all eight secret routes in new conversations", async () => {
    const fake = newFakeGit();
    const rig = await newRig({ fake });
    await forEachRoute(rig, fake, async (route, roles) => {
      const started = Date.now();
      const turn = await routeTurn(rig, route, { prompt: `ROUTE-${route}-fresh`, sessionId: `conv-${route}-fresh` });
      await routeRow(rig, route, "fresh", started, { turns: [turn], roles });
    });
  });

  it("route matrix, resumed: each route as turn 2 of a conversation (routing: the saved relay URL and proxy token of turn 1 are dead)", async () => {
    const fake = newFakeGit();
    const rig = await newRig({ fake });
    await forEachRoute(rig, fake, async (route, roles) => {
      const started = Date.now();
      const session = `conv-${route}-resumed`;
      if (route === "routing") {
        const first = await routeTurn(rig, route, { prompt: `ROUTE-${route}-resumed-1`, sessionId: session });
        const second = await routeTurn(rig, route, { prompt: `ROUTE-${route}-resumed-2`, sessionId: session, phase: "replay" });
        await routeRow(rig, route, "resumed", started, { turns: [first, second], roles });
        return;
      }
      const warm = await warmTurn(rig, `ROUTE-${route}-resumed-1`, session);
      const turn = await routeTurn(rig, route, { prompt: `ROUTE-${route}-resumed-2`, sessionId: session });
      await routeRow(rig, route, "resumed", started, { turns: [turn], warm: [warm], roles });
    });
  });

  it("route matrix, restarted: SIGTERM and a new process on the same directories; each route in a pre-restart conversation and in a new one (LOG_LEVEL=debug)", async () => {
    const fake = newFakeGit();
    const rig = await newRig({ fake, logLevel: "debug" });
    // Conversations created before the restart: a trivial turn each (routing: the probe, so its URL and token are saved).
    const pre: Record<string, { warm?: WarmTurn; probe?: RouteTurn }> = {};
    for (const route of ROUTE_IDS) {
      const session = `conv-${route}-pre`;
      if (route === "routing") pre[route] = { probe: await routeTurn(rig, route, { prompt: `ROUTE-${route}-pre`, sessionId: session }) };
      else pre[route] = { warm: await warmTurn(rig, `ROUTE-${route}-pre`, session) };
    }
    const started = Date.now();
    await rig.restart();
    expect(await waitForIsolation(rig), "/health isolation after the restart").toBe("ok");
    await forEachRoute(rig, fake, async (route, roles) => {
      const rowStarted = Date.now();
      const session = `conv-${route}-pre`;
      const resumedTurn = await routeTurn(rig, route, { prompt: `ROUTE-${route}-restarted-1`, sessionId: session, phase: route === "routing" ? "replay" : "probe", afterRestart: true });
      const freshTurn = await routeTurn(rig, route, { prompt: `ROUTE-${route}-restarted-2`, sessionId: `conv-${route}-post` });
      // The pre-restart probe of the routing route is a row turn too: its host checks ran in the fresh mode; here its problems and surfaces count.
      const warm: WarmTurn[] = route === "routing" ? [{ turn: pre.routing.probe!.turn, problems: pre.routing.probe!.problems }] : [pre[route].warm!];
      await routeRow(rig, route, "restarted", rowStarted, { turns: [resumedTurn, freshTurn], warm, roles });
    });
    void started;
  });
});

/* ------------------------------------------------------------------ */
/*  Normal chat                                                         */
/* ------------------------------------------------------------------ */

interface NormalChat {
  env: TurnObservation[];
  command: TurnObservation;
  interpreter: TurnObservation;
  credentialRead: TurnObservation;
}

/** A normal chat turn the way reqlift sends it: no agent, no skill, no tool list, no request-scoped MCP configuration. */
function normalTurn(rig: SecurityRig, prompt: string, sessionId: string, step: ToolStep): Promise<TurnObservation> {
  return chatTurn(rig, { prompt, sessionId, steps: [step], withCredentials: false, body: { allowedTools: undefined, conversation_id: `${sessionId}-ui`, systemPrompt: "You are a helpful assistant." } });
}

/** The exact normal-chat route: three `env | sort` turns in one conversation, an allowed workspace command, an alternate interpreter read and a built-in Read of a credential file. */
async function normalChat(rig: SecurityRig, session: string, tag: string, full = true): Promise<NormalChat> {
  const bash = (command: string): ToolStep => ({ name: "Bash", input: { command, description: "probe" } });
  const env: TurnObservation[] = [];
  for (const n of [1, 2, 3]) env.push(await normalTurn(rig, `NC-ENV-${tag}-${n}`, session, bash("env | sort")));
  const command = await normalTurn(rig, `NC-CMD-${tag}`, session, bash("echo NC-WORKSPACE-OK > /work/nc.txt && cat /work/nc.txt && ls /work"));
  if (!full) return { env, command, interpreter: command, credentialRead: command };
  const interpreter = await normalTurn(rig, `NC-INTERP-${tag}`, session, bash(`python3 -c "import os, json; print(json.dumps(dict(os.environ)))"; node -e "console.log(JSON.stringify(process.env))"; perl -e 'print join(",", %ENV)'; sh -c env`));
  const credentialRead = await normalTurn(rig, `NC-READ-${tag}`, session, { name: "Read", input: { file_path: path.join(rig.gateway.dirs.workspace, ".credentials.json") } });
  return { env, command, interpreter, credentialRead };
}

function normalChatRows(rig: SecurityRig, mode: Mode, started: number, chats: NormalChat[], extraProblems: string[] = []): void {
  const chatTurns = chats.flatMap((chat) => [...chat.env, chat.command]);
  const problems = [...extraProblems];
  const controls: string[] = [];
  for (const turn of chatTurns) problems.push(...turnProblems(turn));
  for (const turn of chats.flatMap((chat) => chat.env)) {
    const text = turn.results[0]?.text ?? "";
    if (!(text.includes("HOME=/home/node") && /ANTHROPIC_API_KEY=mpt_/.test(text) && text.length > 200)) problems.push("a Bash output was not the sandbox's actual environment");
    const main = requestsFor(rig.api, turn.prompt).find((request) => !request.warmup);
    if (!main?.tools.includes("Bash")) problems.push("Bash was not offered to the model (the trusted grant must enable it)");
  }
  for (const chat of chats) if (!(chat.command.results[0]?.text ?? "").includes("NC-WORKSPACE-OK")) problems.push("the allowed workspace command did not run in the same conversation");
  if (problems.length === extraProblems.length) controls.push("three_env_turns_showed_the_sandbox_environment", "bash_offered_by_the_trusted_grant", "allowed_workspace_command_ran");
  finishRow(recorder, rig, { id: `NC.chat.${mode}`, mode, durationMs: Date.now() - started, deadlineMs: TURN_DEADLINE_MS * chatTurns.length, surfaces: surfacesOf(rig, chatTurns), controls, problems });

  const interpreterTurns = chats.filter((chat) => chat.interpreter !== chat.command).map((chat) => chat.interpreter);
  const interpreterProblems = interpreterTurns.flatMap((turn) => [...turnProblems(turn), ...((turn.results[0]?.text ?? "").includes("HOME") ? [] : ["the interpreter dump was empty"])]);
  finishRow(recorder, rig, { id: `NC.interpreter.${mode}`, mode, durationMs: Date.now() - started, deadlineMs: TURN_DEADLINE_MS, surfaces: surfacesOf(rig, interpreterTurns), controls: ["python_node_perl_sh_environment_dumps_ran"], problems: interpreterProblems });

  const readTurns = chats.filter((chat) => chat.credentialRead !== chat.command).map((chat) => chat.credentialRead);
  const readProblems = readTurns.flatMap((turn) => [...turnProblems(turn), ...(turn.results[0]?.isError ? [] : ["the built-in Read of the credential file did not fail"])]);
  finishRow(recorder, rig, { id: `NC.read.${mode}`, mode, durationMs: Date.now() - started, deadlineMs: TURN_DEADLINE_MS, surfaces: surfacesOf(rig, readTurns), controls: ["read_of_the_credential_file_failed"], problems: readProblems });
}

describe("normal chat", () => {
  it("normal chat, fresh: three env | sort turns, an allowed workspace command, an alternate interpreter read and a Read of a credential file", async () => {
    const rig = await newRig();
    const started = Date.now();
    normalChatRows(rig, "fresh", started, [await normalChat(rig, "conv-nc-fresh", "fresh")]);
  });

  it("normal chat, resumed: the same in a conversation that already had a turn", async () => {
    const rig = await newRig();
    const started = Date.now();
    const warm = await warmTurn(rig, "NC-WARM-resumed", "conv-nc-resumed");
    normalChatRows(rig, "resumed", started, [await normalChat(rig, "conv-nc-resumed", "resumed")], warm.problems);
  });

  it("normal chat, restarted: the same in a conversation created before a gateway restart, and the three turns in a new one", async () => {
    const rig = await newRig({ logLevel: "debug" });
    const started = Date.now();
    const warm = await warmTurn(rig, "NC-WARM-restarted", "conv-nc-pre");
    await rig.restart();
    expect(await waitForIsolation(rig), "/health isolation after the restart").toBe("ok");
    const pre = await normalChat(rig, "conv-nc-pre", "restarted-pre");
    const post = await normalChat(rig, "conv-nc-post", "restarted-post", false);
    normalChatRows(rig, "restarted", started, [pre, post], warm.problems);
  });
});

/* ------------------------------------------------------------------ */
/*  Trusted git configuration (the open question of the S2 QA)          */
/* ------------------------------------------------------------------ */

describe("trusted git configuration", () => {
  it("X.gitconfig: the trusted configuration reaches the runtime's own git and the agent's git as command-scope environment, and the start-time git runs nothing an earlier turn planted", async () => {
    const rig = await newRig();
    const started = Date.now();
    const lines = (turn: TurnObservation): Map<string, string> => new Map((turn.results[0]?.text ?? "").split("\n").flatMap((line) => (/^[A-Z0-9_]+=/.test(line) ? [[line.slice(0, line.indexOf("=")), line.slice(line.indexOf("=") + 1)] as [string, string]] : [])));
    const plant = String.raw`echo SHELL_GIT_ENV_VARS=$(env | grep -c '^GIT_CONFIG')
echo SHELL_GIT_ENV_NAMES=$(env | grep '^GIT_CONFIG' | cut -d= -f1 | sort | tr '\n' ',')
echo AGENT_GIT_SCOPES=$(git config --show-scope --get-regexp '^(safe\.barerepository|core\.fsmonitor|core\.hookspath)$' | tr '\t\n' '  ')
python3 - <<'PY'
import os
found = 'none'
for pid in os.listdir('/proc'):
    if not pid.isdigit():
        continue
    try:
        cmd = open('/proc/%s/cmdline' % pid, 'rb').read().replace(b'\0', b' ')
        env = open('/proc/%s/environ' % pid, 'rb').read().split(b'\0')
    except Exception:
        continue
    if cmd.startswith(b'claude'):
        found = str(len([e for e in env if e.startswith(b'GIT_CONFIG_COUNT=3')]))
print('RUNTIME_GIT_CONFIG_COUNT_3=' + found)
PY
export GIT_CONFIG_COUNT=0
git init -q --bare /work && git -C /work config core.bare false && git -C /work config core.worktree /work && git -C /work config core.fsmonitor 'touch /work/m-ran'
rm -f /work/m-ran
echo PLANTED=1`;
    const turn1 = await chatTurn(rig, { prompt: "GITCFG-PLANT", sessionId: "conv-gitconfig", steps: [{ name: "Bash", input: { command: plant, description: "probe" } }], withCredentials: false });
    const check = String.raw`echo START_TIME_GIT_RAN=$(ls /work/m-ran 2>/dev/null | wc -l)
env -u GIT_CONFIG_COUNT git -C /work status >/dev/null 2>&1
echo CONTROL_GIT_WITHOUT_TRUSTED_CONFIG_RAN=$(ls /work/m-ran 2>/dev/null | wc -l)
echo DONE=1`;
    const turn2 = await chatTurn(rig, { prompt: "GITCFG-CHECK", sessionId: "conv-gitconfig", steps: [{ name: "Bash", input: { command: check, description: "probe" } }], withCredentials: false });
    const one = lines(turn1);
    const two = lines(turn2);
    const problems = [...turnProblems(turn1), ...turnProblems(turn2)];
    const controls: string[] = [];
    const expectLine = (name: string, ok: boolean): void => {
      if (ok) controls.push(name);
      else problems.push(`control did not hold: ${name}`);
    };
    expectLine("shell_environment_holds_the_seven_trusted_git_variables", one.get("SHELL_GIT_ENV_VARS") === "7");
    expectLine("agent_git_reports_the_three_values_at_command_scope", ["command safe.barerepository explicit", "command core.fsmonitor false", "command core.hookspath /dev/null"].every((entry) => (one.get("AGENT_GIT_SCOPES") ?? "").toLowerCase().includes(entry)));
    expectLine("runtime_process_environment_holds_the_trusted_git_count", one.get("RUNTIME_GIT_CONFIG_COUNT_3") === "1");
    expectLine("agent_planted_the_implicit_bare_layout", one.get("PLANTED") === "1");
    expectLine("start_time_git_ran_nothing_the_agent_planted", two.get("START_TIME_GIT_RAN") === "0");
    expectLine("planted_vector_is_live_without_the_trusted_configuration", two.get("CONTROL_GIT_WITHOUT_TRUSTED_CONFIG_RAN") === "1");
    finishRow(recorder, rig, { id: "X.gitconfig", durationMs: Date.now() - started, deadlineMs: TURN_DEADLINE_MS * 2, surfaces: surfacesOf(rig, [turn1, turn2]), controls, problems });
  });
});

/* ------------------------------------------------------------------ */
/*  The regression row                                                  */
/* ------------------------------------------------------------------ */

describe("real-process regression", () => {
  it("regression row: an ordinary chat shows its environment and resumes, the authorized operations work, and no marker reaches any surface", async () => {
    const rig = await newRig();
    const started = Date.now();
    const turn1 = await chatTurn(rig, {
      prompt: "REGRESSION-TURN1",
      sessionId: "conv-regression",
      steps: [...credentialSteps(), { name: "Bash", input: { command: "env | sort; echo FIXTURE-RESULT-7677 > /work/fixture.txt; echo WROTE-FIXTURE", description: "probe" } }],
    });
    const turn2 = await chatTurn(rig, { prompt: "REGRESSION-TURN2", sessionId: "conv-regression", steps: [{ name: "Read", input: { file_path: "/work/fixture.txt" } }] });
    const problems = [...turnProblems(turn1), ...turnProblems(turn2), ...credentialProblems(rig, turn1)];

    // Controls: the actual Bash output is the sandbox's environment, and the permitted workspace operation worked.
    const envText = turn1.results[credentialSteps().length]?.text ?? "";
    const controls: string[] = [];
    const check = (name: string, ok: boolean): void => {
      if (ok) controls.push(name);
      else problems.push(`control did not hold: ${name}`);
    };
    check("bash_showed_the_sandbox_environment", envText.includes("HOME=/home/node") && /ANTHROPIC_API_KEY=mpt_/.test(envText));
    check("authorized_workspace_operation_worked", envText.includes("WROTE-FIXTURE"));
    check("resumed_turn_read_the_fixture", (turn2.results.at(-1)?.text ?? "").includes("FIXTURE-RESULT-7677"));
    const resumed = requestsFor(rig.api, "REGRESSION-TURN2").filter((request) => !request.warmup);
    check("resumed_turn_has_the_prior_context", (resumed[0]?.userTexts.join(" ") ?? "").includes("REGRESSION-TURN1"));
    check("gateway_still_running", rig.gateway.child.exitCode === null);

    finishRow(recorder, rig, { id: "RP.regression", durationMs: Date.now() - started, deadlineMs: TURN_DEADLINE_MS * 2, surfaces: surfacesOf(rig, [turn1, turn2]), controls, problems });
  });
});

describe("route probes", () => {
  it("route config probe, fresh: trusted files, OAuth state and MCP configuration are unreachable from the sandbox (the file detector's subject)", async () => {
    const rig = await newRig();
    const started = Date.now();
    const turn = await routeTurn(rig, "config", { prompt: "ROUTE-CONFIG-SUBJECT", sessionId: "conv-config-subject" });
    finishRow(recorder, rig, { id: "RT.config.subject", mode: "fresh", durationMs: Date.now() - started, deadlineMs: TURN_DEADLINE_MS, surfaces: surfacesOf(rig, [turn.turn]), controls: turn.verdict.controls, problems: turn.problems });
  });
});

/* ------------------------------------------------------------------ */
/*  Negative controls                                                   */
/* ------------------------------------------------------------------ */

/** A copy of `dist/` under the temp directory whose `file` has `from` replaced by `to`; the patch must apply exactly once. */
function vulnerableDist(file: string, from: string, to: string): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "mvp7677-vulnerable-"));
  cleanups.push(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.cpSync(path.join(REPO_ROOT, "dist"), path.join(root, "dist"), { recursive: true, filter: (source) => !source.startsWith(path.join(REPO_ROOT, "dist", "tests")) });
  fs.copyFileSync(path.join(REPO_ROOT, "package.json"), path.join(root, "package.json"));
  fs.symlinkSync(path.join(REPO_ROOT, "node_modules"), path.join(root, "node_modules"));
  const target = path.join(root, "dist", file);
  const source = fs.readFileSync(target, "utf8");
  expect(source.split(from).length - 1, `the patch of ${file} must match exactly once`).toBe(1);
  fs.writeFileSync(target, source.replace(from, to));
  expect(fs.readFileSync(target, "utf8")).not.toBe(source);
  return path.join(root, "dist", "server.js");
}

interface ChildResult {
  failed: boolean;
  namesTheRow: boolean;
  hits: number;
  printsAMarkerValue: boolean;
  reportsExpectedFailure: boolean;
  timedOut: boolean;
}

/**
 * Runs `-t <selector>` of this file in a child vitest against `dist`, offline, with the parent's marker seed. The child's
 * output is never printed or asserted as text: only these booleans and the hit count leave this function.
 */
async function runChildRow(selector: string, rowId: string, dist: string, childSeed: string): Promise<ChildResult> {
  const childMarkers = createMarkers(childSeed);
  const { code, output, timedOut } = await runChild(
    [...offlinePrefix(), process.execPath, path.join(REPO_ROOT, "node_modules", "vitest", "vitest.mjs"), "run", "src/tests/security-regression-process.test.ts", "-t", selector],
    {
      PATH: process.env.PATH,
      HOME: process.env.HOME,
      LANG: process.env.LANG,
      TMPDIR: os.tmpdir(),
      SECURITY_CHILD: "1",
      SECURITY_OFFLINE: "1",
      SECURITY_MARKER_SEED: childSeed,
      SECURITY_NEGATIVE_CONTROL: dist,
    },
    REPO_ROOT,
    240_000,
  );
  const line = new RegExp(`SECURITY-MATRIX id=${rowId.replace(/\./g, "\\.")}[^\\n]*`).exec(output)?.[0] ?? "";
  return {
    failed: code !== 0 && code !== null,
    namesTheRow: line.length > 0 && /observed=fail/.test(line),
    hits: Number(/ hits=(\d+)/.exec(line)?.[1] ?? 0),
    printsAMarkerValue: Object.values(childMarkers.values).some((value) => output.includes(value)),
    reportsExpectedFailure: output.includes(`security row ${rowId}: hits=`),
    timedOut,
  };
}

describe("negative control", () => {
  it("negative control: the ordinary-chat row exits nonzero against a gateway that passes API_KEYS into the sandbox, names the row, reports hits and prints no value", async () => {
    expect(offlineAvailable(), "the offline execution mode (a loopback-only network namespace) is required").toBe(true);
    const dist = vulnerableDist("sandbox.js", "Object.assign(env, input.runLogEnv, {", 'env.API_KEYS = String(input.gatewayEnv.API_KEYS ?? "");\n    Object.assign(env, input.runLogEnv, {');
    const started = Date.now();
    const result = await runChildRow("regression row", "RP.regression", dist, randomBytes(4).toString("hex"));
    expect(result.timedOut, "the child run hit its deadline").toBe(false);
    expect(result.failed, "the suite must exit nonzero on a deliberately exposed credential").toBe(true);
    expect(result.namesTheRow, "the child output must name the row with observed=fail").toBe(true);
    expect(result.hits, "the child must report hits above 0").toBeGreaterThan(0);
    expect(result.reportsExpectedFailure, "the failure must be the detector's").toBe(true);
    expect(result.printsAMarkerValue, "the child output must contain no marker value").toBe(false);
    recorder.record({ id: "RP.negative-control", expected: "fail", observed: result.failed && result.namesTheRow && result.hits > 0 ? "fail" : "pass", hits: result.hits, durationMs: Date.now() - started, deadlineMs: 240_000, surfaces: [], controls: ["child_exited_nonzero", "row_named", "no_marker_value_printed"] });
  });

  it("negative control: a credential file bound into the sandbox by a vulnerable launcher is found by the config route in a child run", async () => {
    expect(offlineAvailable()).toBe(true);
    const dist = vulnerableDist(
      "sandbox.js",
      'argv.push("--bind", spec.homeDir, SANDBOX_HOME);',
      'argv.push("--bind", spec.homeDir, SANDBOX_HOME);\n    argv.push("--ro-bind", `${process.env.HOME}/.claude/.credentials.json`, `${SANDBOX_HOME}/.claude/.credentials.json`);',
    );
    const started = Date.now();
    const result = await runChildRow("route config probe", "RT.config.subject", dist, randomBytes(4).toString("hex"));
    expect(result.timedOut).toBe(false);
    expect(result.failed).toBe(true);
    expect(result.namesTheRow).toBe(true);
    expect(result.hits).toBeGreaterThan(0);
    expect(result.printsAMarkerValue).toBe(false);
    recorder.record({ id: "RP.negative-control.file-detector", expected: "fail", observed: result.failed && result.namesTheRow && result.hits > 0 ? "fail" : "pass", hits: result.hits, durationMs: Date.now() - started, deadlineMs: 240_000, surfaces: [], controls: ["child_exited_nonzero", "row_named", "no_marker_value_printed"] });
  });
});

/* ------------------------------------------------------------------ */
/*  Summary (the last test of a full run)                               */
/* ------------------------------------------------------------------ */

describe("summary", () => {
  it("every expected row of the suite ran and passed", () => {
    const summary = recorder.finish();
    expect(summary.missing).toEqual([]);
    expect(summary.fail).toBe(0);
  });
});

// Kept for the rows added next to the route matrix (X.*), which read the same helpers.
void ([] as ToolStep[]);
void resultsFor;
void runLeftoversText;
void (null as unknown as RowInput);
