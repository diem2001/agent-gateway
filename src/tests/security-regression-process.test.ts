/**
 * The real-process security regression suite (MVP-7677): the compiled gateway (`dist/server.js`) with the production
 * Claude Agent SDK, its bundled runtime, real `bwrap`, a scripted model double and recording MCP, webhook and git
 * doubles. Every credential in it is a synthetic marker with a random suffix; the observation surfaces are the raw
 * tool outputs, the model-bound request bodies, the NDJSON events, the gateway log and the conversation's own
 * transcripts, `/work` and home. Only case names, booleans and counts are printed (`SECURITY-MATRIX` lines).
 *
 * - `RP.regression` is the Real-process regression scenario: an ordinary chat (no agent, no skill) shows its
 *   environment with `env | sort` and resumes; the authorized operations of the three request-scoped credentials still
 *   produce their fixtures; no marker is on any surface; the runtime never runs outside the sandbox.
 * - The route rows run the probes of `helpers/security-routes.ts` in fresh, resumed and restarted execution.
 * - The negative controls prove the detector end to end: a child vitest run of the same row against a deliberately
 *   vulnerable copy of `dist/` (offline, in a loopback-only namespace) must exit nonzero, name the row and report
 *   hits, and print no marker value.
 *
 * The child run selects rows with `-t`, so a row's test name carries its selector: `regression row` for the regression
 * scenario, `route config probe` for the file detector.
 *
 * Needs `npm run build`, `bwrap`, user namespaces, `unshare`, `git` and `python3`; a missing prerequisite fails with
 * `host prerequisite missing: <name>`. Linux only.
 */
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { REPO_ROOT, type Cleanup } from "./helpers/git-process-gateway.js";
import {
  MatrixRecorder,
  SURFACE_FLOORS,
  conversationText,
  createMarkers,
  createRig,
  detect,
  emit,
  evidenceLine,
  offlineAvailable,
  offlinePrefix,
  requestCredentials,
  requestsFor,
  registerStandardServers,
  requireHost,
  resultsFor,
  runChild,
  runLeftoversText,
  startEgressSampler,
  startProcessSampler,
  type MatrixRow,
  type QueryOutcome,
  type SecurityMarkers,
  type SecurityRig,
  type Surface,
} from "./helpers/security-matrix.js";
import { ROUTE_ALLOWED_TOOLS, credentialSteps, routeSteps, verifyRoute, type RouteContext, type RouteId, type RouteStep } from "./helpers/security-routes.js";

const TURN_DEADLINE_MS = 120_000;
const ROW_TEST_TIMEOUT_MS = 300_000;
vi.setConfig({ testTimeout: ROW_TEST_TIMEOUT_MS });

/** A child run of this file (the negative control) shares the parent's marker seed and runs offline. */
const IS_CHILD = process.env.SECURITY_CHILD === "1";
const NEGATIVE_CONTROL_DIST = process.env.SECURITY_NEGATIVE_CONTROL;
const markers: SecurityMarkers = createMarkers();

const EXPECTED_ROWS = ["RP.regression", "RT.config.fresh", "RP.negative-control", "RP.negative-control.file-detector"];
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
      config: { API_KEYS: "reqlift+diemcrm", ANTHROPIC_BASE_URL: "local-double", MODEL_PROXY_OAUTH_TOKEN_URL: "local-double", CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1", AGENT_TOOL_POLICY: "unset" },
      deadlines: { turn_ms: TURN_DEADLINE_MS, row_test_timeout_ms: ROW_TEST_TIMEOUT_MS },
      offline: process.env.SECURITY_OFFLINE === "1",
      logLevel: "info",
    }),
  );
});

/* ------------------------------------------------------------------ */
/*  Shared row machinery                                                */
/* ------------------------------------------------------------------ */

function rigOptions(extra: { distServer?: string } = {}): Parameters<typeof createRig>[1] {
  return { markers, distServer: extra.distServer ?? NEGATIVE_CONTROL_DIST };
}

/** The pinned provider and OAuth endpoints are local doubles: nothing of a row can reach a real provider. */
function assertPinned(rig: SecurityRig): void {
  expect(rig.baseEnv.ANTHROPIC_BASE_URL.startsWith("http://127.0.0.1:")).toBe(true);
  expect(rig.baseEnv.MODEL_PROXY_OAUTH_TOKEN_URL.startsWith("http://127.0.0.1:")).toBe(true);
}

function routeContext(rig: SecurityRig, phase?: "probe" | "replay"): RouteContext {
  return {
    markers: rig.markers,
    host: { workspace: rig.gateway.dirs.workspace, home: rig.gateway.dirs.home, persist: rig.gateway.dirs.persist },
    gatewayPort: rig.gateway.port,
    canary: `SYNTH-CANARY-${rig.markers.seed}`,
    phase,
  };
}

/** The scripted turn: the first step is the exact call, the rest follow after each result. */
function scriptOf(prompt: string, steps: RouteStep[]) {
  return { name: steps[0].name, prompt, input: steps[0].input, then: steps.slice(1) };
}

interface TurnObservation {
  outcome: QueryOutcome;
  results: { isError: boolean; text: string }[];
  prompt: string;
  sessionId: string;
  logFrom: number;
  unsandboxedRuntimes: number[];
  runtimesSeen: number;
  egress: string[];
  jiraBefore: number;
  reqHttpBefore: number;
}

/** One chat turn of an ordinary conversation with every request-scoped credential, observed from the host. */
async function chatTurn(rig: SecurityRig, options: { prompt: string; sessionId: string; steps: RouteStep[]; label?: "reqlift" | "diemcrm"; user?: string; withCredentials?: boolean }): Promise<TurnObservation> {
  rig.scripts.push(scriptOf(options.prompt, options.steps));
  const logFrom = rig.log().length;
  const jiraBefore = rig.jira.authorizations().length;
  const reqHttpBefore = rig.reqHttp.authorizations().length;
  const processes = startProcessSampler(() => rig.gateway.child.pid!);
  const egress = startEgressSampler(() => rig.gateway.child.pid!);
  const outcome = await rig.ask(
    options.label ?? "reqlift",
    {
      queryId: `q-${options.sessionId}-${randomBytes(3).toString("hex")}`,
      sessionId: options.sessionId,
      prompt: options.prompt,
      user_id: options.user ?? "user-1",
      useSession: true,
      allowedTools: ROUTE_ALLOWED_TOOLS,
      ...(options.withCredentials === false ? {} : requestCredentials(rig)),
    },
    TURN_DEADLINE_MS,
  );
  const sample = processes.stop();
  return {
    outcome,
    results: resultsFor(rig.api, options.prompt).slice(-options.steps.length),
    prompt: options.prompt,
    sessionId: options.sessionId,
    logFrom,
    unsandboxedRuntimes: sample.unsandboxedRuntimes,
    runtimesSeen: sample.runtimesSeen,
    egress: egress.stop(),
    jiraBefore,
    reqHttpBefore,
  };
}

/** The five observation surfaces of the given turns (and the runtime's per-run leftovers inside `transcripts`). */
function surfacesOf(rig: SecurityRig, turns: TurnObservation[]): Surface[] {
  const prompts = [...new Set(turns.map((turn) => turn.prompt))];
  const requests = prompts.flatMap((prompt) => requestsFor(rig.api, prompt));
  const unique = [...new Set(requests)];
  const sessions = [...new Set(turns.map((turn) => turn.sessionId))];
  const home = conversationText(rig.gateway, sessions);
  const leftovers = runLeftoversText(rig.gateway);
  const earliest = Math.min(...turns.map((turn) => turn.logFrom));
  return [
    { name: "tool-results", text: unique.flatMap((request) => request.toolResults.map((result) => result.text)).join("\n") },
    { name: "model-requests", text: unique.map((request) => request.body).join("\n") },
    { name: "events", text: JSON.stringify(turns.map((turn) => turn.outcome.events)) },
    { name: "gateway-log", text: rig.log().slice(earliest) },
    { name: "transcripts", text: `${home.text}\n${leftovers.text}` },
  ];
}

/** Records the row, and throws with names and counts when anything but a clean pass was observed. */
function finishRow(row: Omit<MatrixRow, "observed" | "hits" | "expected"> & { expected?: MatrixRow["expected"]; problems: string[] }, rig: SecurityRig): "pass" | "fail" {
  const hits = detect(row.surfaces, rig.markers.values);
  const thin = row.surfaces.filter((surface) => surface.text.length < (SURFACE_FLOORS[surface.name] ?? 1)).map((surface) => surface.name);
  const problems = [...row.problems, ...(thin.length > 0 ? [`below the byte floor: [${thin.join(", ")}]`] : [])];
  const observed = hits.length === 0 && problems.length === 0 ? "pass" : "fail";
  recorder.record({ id: row.id, mode: row.mode, expected: row.expected ?? "pass", observed, hits: hits.length, durationMs: row.durationMs, deadlineMs: row.deadlineMs, surfaces: row.surfaces, controls: row.controls });
  if (observed === "fail" && (row.expected ?? "pass") === "pass") {
    throw new Error(`security row ${row.id}: ${hits.length > 0 ? `hits=${hits.length} [${hits.join(", ")}]` : "hits=0"}${problems.length > 0 ? `; ${problems.join("; ")}` : ""}`);
  }
  return observed;
}

/** What every turn of every row must show: the stream ended in `done`, no runtime outside the sandbox, no external destination. */
function turnProblems(turn: TurnObservation): string[] {
  const problems: string[] = [];
  if (turn.outcome.events.at(-1)?.type !== "done") problems.push(`the stream did not end in done (${turn.outcome.events.at(-1)?.type ?? "no event"})`);
  if (turn.outcome.ms > TURN_DEADLINE_MS) problems.push("the turn missed its deadline");
  if (turn.unsandboxedRuntimes.length > 0) problems.push(`${turn.unsandboxedRuntimes.length} agent runtime(s) ran without a sandbox ancestor`);
  if (turn.runtimesSeen < 1) problems.push("the process sampler saw no runtime");
  if (turn.egress.length > 0) problems.push(`${turn.egress.length} non-loopback destination(s) in the gateway's network namespace`);
  return problems;
}

/** The three request-scoped fixtures at the start of every route turn: each double saw its own bound credential in this run. */
function credentialProblems(rig: SecurityRig, turn: TurnObservation): string[] {
  const v = rig.markers.values;
  const problems: string[] = [];
  const [jira, reqHttp, reqLocal] = turn.results;
  if (!jira || jira.isError || !jira.text.includes("RECORD-7667-OK")) problems.push("the per-user override fixture did not answer");
  if (!reqHttp || reqHttp.isError || !reqHttp.text.includes("RECORD-7667-OK")) problems.push("the request-body http fixture did not answer");
  if (!reqLocal || reqLocal.isError || reqLocal.text !== `STDIO-RESULT:${v.requestStdioEnv.length}`) problems.push("the request-body stdio fixture did not answer with its env value");
  const jiraNow = rig.jira.authorizations().slice(turn.jiraBefore);
  const reqNow = rig.reqHttp.authorizations().slice(turn.reqHttpBefore);
  if (jiraNow.length === 0 || !jiraNow.every((value) => value === `Bearer ${v.userOverrideHeader}`)) problems.push("the per-user MCP double did not receive exactly the user's credential in this run");
  if (reqNow.length === 0 || !reqNow.every((value) => value === `Bearer ${v.requestHttpHeader}`)) problems.push("the request-body http double did not receive exactly its credential in this run");
  return problems;
}

/** Runs one route probe as an ordinary chat turn and returns the observation with the route's verdict problems. */
async function routeTurn(rig: SecurityRig, route: RouteId, options: { prompt: string; sessionId: string; phase?: "probe" | "replay" }): Promise<{ turn: TurnObservation; problems: string[]; controls: string[]; hits: number }> {
  const ctx = routeContext(rig, options.phase);
  const steps = [...credentialSteps(), ...routeSteps(route, ctx)];
  const turn = await chatTurn(rig, { prompt: options.prompt, sessionId: options.sessionId, steps });
  const probe = turn.results[credentialSteps().length];
  const verdict = verifyRoute(route, probe?.text ?? "", ctx);
  return { turn, problems: [...turnProblems(turn), ...credentialProblems(rig, turn), ...verdict.failures], controls: verdict.controls, hits: verdict.hits };
}

/* ------------------------------------------------------------------ */
/*  The regression row                                                  */
/* ------------------------------------------------------------------ */

describe("real-process regression", () => {
  it("regression row: an ordinary chat shows its environment and resumes, the authorized operations work, and no marker reaches any surface", async () => {
    const rig = await createRig(cleanups, rigOptions());
    assertPinned(rig);
    await registerStandardServers(rig);
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

    finishRow(
      { id: "RP.regression", durationMs: Date.now() - started, deadlineMs: TURN_DEADLINE_MS * 2, surfaces: surfacesOf(rig, [turn1, turn2]), controls, problems },
      rig,
    );
  });
});

/* ------------------------------------------------------------------ */
/*  Route rows                                                          */
/* ------------------------------------------------------------------ */

describe("route probes", () => {
  it("route config probe, fresh: trusted files, OAuth state and MCP configuration are unreachable from the sandbox", async () => {
    const rig = await createRig(cleanups, rigOptions());
    assertPinned(rig);
    await registerStandardServers(rig);
    const started = Date.now();
    const row = await routeTurn(rig, "config", { prompt: "ROUTE-CONFIG-FRESH", sessionId: "conv-config-fresh" });
    finishRow(
      { id: "RT.config.fresh", mode: "fresh", durationMs: Date.now() - started, deadlineMs: TURN_DEADLINE_MS, surfaces: surfacesOf(rig, [row.turn]), controls: row.controls, problems: row.problems },
      rig,
    );
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
    const result = await runChildRow("route config probe", "RT.config.fresh", dist, randomBytes(4).toString("hex"));
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

afterAll(() => {
  // Child runs and filtered runs print the summary too; only the last test of a full run asserts it.
  if (IS_CHILD) recorder.finish();
});

