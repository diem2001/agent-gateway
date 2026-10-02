/**
 * Isolation failures are safe and visible (MVP-7677, Outline "Isolation failures are safe and visible"): seven injected
 * failures, each with its precondition, an injection, a fixture-side confirmation that the run reached the named boundary
 * before the failure took effect, a bounded explicit caller-visible failure without credentials within its deadline, and
 * no unrestricted fallback or unauthorized side effect.
 *
 * - `IF.startup-exit`, `IF.startup-hang`, `IF.policy`: a recording `AGENT_SANDBOX_BWRAP` wrapper passes through for the boot
 *   self-check (isolation `ok`), then a mode file makes it exit, hang or drop `--disable-userns` for the next launch. The
 *   wrapper logs every launch with the run's unique log path from its environment (the arguments travel on fd 3, so the
 *   query id is not visible to it): that line is the boundary proof.
 * - `IF.cancel`, `IF.restart-term`, `IF.restart-kill`: a Bash tool with a tagged child; the host sees the child below the
 *   gateway and the model double recorded the call before the caller closes the connection, or the gateway is stopped.
 * - `IF.cred-missing`, `IF.cred-refused`, `IF.timeout`, `IF.unavailable`: registered MCP server doubles behind the relay; the
 *   relay's own audit line shows the trusted mediation step was reached.
 * - `IF.legacy`: resume of a stored conversation with a credential-bearing legacy transcript.
 *
 * Every row also asserts, for the whole failure window, that no agent runtime ran without a `bwrap` ancestor (a process
 * sampler, because a runtime outside the sandbox would not reach the model double), counts the runtime starts, and checks
 * the gateway's own socket destinations. The fixed texts are asserted verbatim. Needs `npm run build`, `bwrap`, user
 * namespaces, `perl`, `git`, `python3`. Linux only. Every secret is synthetic; only names, booleans and counts are printed.
 */
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { descendants, gatewayRequest, type Cleanup } from "./helpers/git-process-gateway.js";
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
  requireHost,
  runLeftoversText,
  scriptOf,
  shellQuote,
  startEgressSampler,
  startFaultMcp,
  startProcessSampler,
  surfacesOf,
  turnProblems,
  waitForIsolation,
  type Ndjson,
  type QueryOutcome,
  type SecurityMarkers,
  type SecurityRig,
  type Surface,
  type ToolStep,
} from "./helpers/security-matrix.js";
import { failureRowIds } from "./helpers/security-routes.js";
import { startOAuthMcpStub } from "./helpers/oauth-mcp-stub.js";

vi.setConfig({ testTimeout: 300_000 });

const markers: SecurityMarkers = createMarkers();
const recorder = new MatrixRecorder("security-failure-process", failureRowIds());
const STARTUP_TIMEOUT_MS = 1500;
const TOOL_TIMEOUT_MS = 3000;
/** The runtime's exit wait (`RUNTIME_EXIT_WAIT_MS`) plus the plan's margin: nothing of a cancelled or stopped run may outlive it. */
const NOTHING_LEFT_WITHIN_MS = 15_000;
const SHUTDOWN_DRAIN_MS = 8000;

const cleanups: Cleanup[] = [];
afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()!();
});

beforeAll(() => {
  requireHost(["bwrap", "userns", "git", "python3", "build"]);
  emit(
    evidenceLine({
      suite: "security-failure-process",
      config: { API_KEYS: "reqlift+diemcrm", ISOLATION_STARTUP_TIMEOUT_MS: String(STARTUP_TIMEOUT_MS), AGENT_MCP_TOOL_TIMEOUT_MS: String(TOOL_TIMEOUT_MS), SHUTDOWN_DEADLINE_MS: String(SHUTDOWN_DRAIN_MS), ANTHROPIC_BASE_URL: "local-double" },
      deadlines: { startup_bound_ms: STARTUP_TIMEOUT_MS + 2000, tool_timeout_ms: TOOL_TIMEOUT_MS, nothing_left_within_ms: NOTHING_LEFT_WITHIN_MS, shutdown_drain_ms: SHUTDOWN_DRAIN_MS },
      offline: false,
      logLevel: "info",
    }),
  );
});

const UNAVAILABLE = (id: string): string =>
  `The gateway cannot start a protected workspace, so this request did not run. Ask your gateway administrator to check the gateway's isolation status. Retrying will not help until the administrator has done this. (reference: ${id})`;
const IN_TIME = (id: string): string =>
  `The gateway could not start a protected workspace in time, so this request did not run. Please try again in a few minutes. If it keeps happening, tell your gateway administrator. (reference: ${id})`;
const LEGACY = "This conversation was started before a gateway security update and cannot be continued safely. Please start a new conversation. Retrying will not help.";

/* ------------------------------------------------------------------ */
/*  The recording launcher                                              */
/* ------------------------------------------------------------------ */

type WrapperMode = "pass" | "startup-exit" | "startup-hang" | "no-userns";

interface Wrapper {
  path: string;
  setMode: (mode: WrapperMode) => void;
  /** Every launch the wrapper saw, in order: epoch ms, the mode it acted on and the run's unique log path (`none` for the boot check). */
  launches: () => { ms: number; mode: string; run: string }[];
}

function makeWrapper(): Wrapper {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mvp7677-launcher-"));
  cleanups.push(() => fs.rmSync(dir, { recursive: true, force: true }));
  const script = path.join(dir, "bwrap");
  fs.writeFileSync(path.join(dir, "mode"), "pass");
  fs.writeFileSync(
    script,
    String.raw`#!/bin/bash
DIR=${shellQuote(dir)}
MODE=$(cat "$DIR/mode" 2>/dev/null || echo pass)
printf '%s\t%s\t%s\n' "$(date +%s%3N)" "$MODE" "${"$"}{CLAUDE_CODE_DEBUG_LOGS_DIR:-none}" >> "$DIR/launches.log"
case "$MODE" in
  startup-exit) exit 3 ;;
  startup-hang) exec sleep 120 ;;
  no-userns) exec /usr/bin/bwrap --args 4 "${"$"}{@:3}" 4< <(perl -0777 -pe 's/--disable-userns\0//' <&3) ;;
  *) exec /usr/bin/bwrap "$@" ;;
esac
`,
    { mode: 0o755 },
  );
  return {
    path: script,
    setMode: (mode) => fs.writeFileSync(path.join(dir, "mode"), mode),
    launches: () => {
      try {
        return fs
          .readFileSync(path.join(dir, "launches.log"), "utf8")
          .split("\n")
          .filter(Boolean)
          .map((line) => {
            const [ms, mode, run] = line.split("\t");
            return { ms: Number(ms), mode, run };
          });
      } catch {
        return [];
      }
    },
  };
}

async function newRig(env: Record<string, string> = {}): Promise<SecurityRig> {
  const rig = await createRig(cleanups, { markers, env: { AGENT_MCP_TOOL_TIMEOUT_MS: String(TOOL_TIMEOUT_MS), ...env } });
  expect(pinnedProblems(rig)).toEqual([]);
  await registerStandardServers(rig);
  return rig;
}

async function wrapperRig(): Promise<{ rig: SecurityRig; wrapper: Wrapper }> {
  const wrapper = makeWrapper();
  const rig = await createRig(cleanups, { markers, env: { AGENT_SANDBOX_BWRAP: wrapper.path, ISOLATION_STARTUP_TIMEOUT_MS: String(STARTUP_TIMEOUT_MS), AGENT_MCP_TOOL_TIMEOUT_MS: String(TOOL_TIMEOUT_MS) } });
  expect(pinnedProblems(rig)).toEqual([]);
  expect(await waitForIsolation(rig), "the boot self-check passes through the wrapper").toBe("ok");
  await registerStandardServers(rig);
  return { rig, wrapper };
}

/* ------------------------------------------------------------------ */
/*  Shared checks                                                       */
/* ------------------------------------------------------------------ */

/** The failure window: a process sampler, an egress sampler and the counters every row compares afterwards. */
function windowOf(rig: SecurityRig, tags: string[] = []) {
  const processes = startProcessSampler(() => rig.gateway.child.pid!, tags);
  const egress = startEgressSampler(() => rig.gateway.child.pid!);
  return {
    logFrom: rig.log().length,
    requestsBefore: rig.api.requests.length,
    startsBefore: (rig.log().match(/SDK options:/g) ?? []).length,
    peek: () => processes.peek(),
    close: () => ({ sample: processes.stop(), egress: egress.stop() }),
  };
}

type Window = ReturnType<typeof windowOf>;

/** Nothing in the window ran outside the sandbox or reached a non-loopback destination; `runtimes` says how many runtimes the window may have started. */
function fallbackProblems(rig: SecurityRig, window: Window, expectation: { runtimes: "none" | "some"; modelRequests: "none" | "some" }): string[] {
  const { sample, egress } = window.close();
  const problems: string[] = [];
  if (sample.unsandboxedRuntimes.length > 0) problems.push(`${sample.unsandboxedRuntimes.length} agent runtime(s) ran without a sandbox ancestor`);
  if (expectation.runtimes === "none" && sample.runtimesSeen > 0) problems.push(`${sample.runtimesSeen} runtime process(es) started in a window that must start none`);
  if (expectation.runtimes === "some" && sample.runtimesSeen === 0) problems.push("the process sampler saw no runtime in a window that ran one");
  const modelRequests = rig.api.requests.length - window.requestsBefore;
  if (expectation.modelRequests === "none" && modelRequests > 0) problems.push(`${modelRequests} model request(s) in a window that must make none`);
  if (egress.length > 0) problems.push(`${egress.length} non-loopback destination(s) held by the gateway's processes`);
  return problems;
}

/** The gateway log since the window opened and what the caller saw: the surfaces of a row that makes no model request. */
function noRunSurfaces(rig: SecurityRig, window: Window, outcome: QueryOutcome, extra: string[] = []): Surface[] {
  return [
    { name: "events", text: JSON.stringify(outcome.events) },
    { name: "gateway-log", text: rig.log().slice(window.logFrom) },
    { name: "caller-body", text: `${outcome.raw}\n${extra.join("\n")}` },
  ];
}

function exactError(outcome: QueryOutcome, text: string): boolean {
  return outcome.events.length === 1 && outcome.events[0].type === "error" && outcome.events[0].content === text && !outcome.events.some((event) => event.type === "done");
}

const bashStep = (command: string): ToolStep => ({ name: "Bash", input: { command, description: "probe" } });

/** A held tool: a tagged Python child that holds until `/work/stop` appears (or two minutes), after writing `/work/held`. */
const heldCommand = (tag: string): string => `python3 -c ${shellQuote("import os, time\nopen('/work/held', 'w').write('x')\nend = time.time() + 120\nwhile time.time() < end and not os.path.exists('/work/stop'):\n    time.sleep(0.2)")} ${tag}`;

async function waitFor(condition: () => boolean, timeoutMs: number, what: string): Promise<void> {
  for (const end = Date.now() + timeoutMs; !condition(); await new Promise((resolve) => setTimeout(resolve, 50))) if (Date.now() > end) throw new Error(`timed out waiting for ${what}`);
}

const taggedProcesses = (rig: SecurityRig, tag: string): number =>
  descendants(rig.gateway.child.pid!).filter((pid) => {
    try {
      return fs.readFileSync(`/proc/${pid}/cmdline`).toString("latin1").includes(tag);
    } catch {
      return false;
    }
  }).length;

/* ------------------------------------------------------------------ */
/*  Startup and policy failures                                         */
/* ------------------------------------------------------------------ */

describe("sandbox startup and policy-check failures", () => {
  /** Runs one query against a wrapper mode and returns what the caller saw plus the wrapper's launch log for the window. */
  async function injected(rig: SecurityRig, wrapper: Wrapper, mode: WrapperMode, id: string, scriptSteps: ToolStep[]) {
    const prompt = `IF-${id}`;
    rig.scripts.push(scriptOf(prompt, scriptSteps));
    const before = wrapper.launches().length;
    wrapper.setMode(mode);
    const window = windowOf(rig);
    const queryId = `q-${id}`;
    const outcome = await rig.ask("reqlift", { queryId, sessionId: `conv-${id}`, prompt, user_id: "user-1", useSession: true, allowedTools: ["Bash"] }, 30_000);
    const launches = wrapper.launches().slice(before);
    return { outcome, launches, window, queryId, prompt };
  }

  it("IF.startup-exit: a sandbox that exits at start is refused with the permanent text within the startup bound; nothing ran; the next start works", async () => {
    const { rig, wrapper } = await wrapperRig();
    const started = Date.now();
    const { outcome, launches, window, queryId } = await injected(rig, wrapper, "startup-exit", "startup-exit", [bashStep("touch /work/m-startup; echo RAN")]);
    const problems = fallbackProblems(rig, window, { runtimes: "none", modelRequests: "none" });
    const controls: string[] = [];
    if (launches.some((launch) => launch.mode === "startup-exit" && launch.run !== "none")) controls.push("launcher_saw_this_runs_start_before_it_failed");
    else problems.push("the launcher did not see a launch of this run (the failure may have happened before the isolation startup step)");
    if (exactError(outcome, UNAVAILABLE(queryId))) controls.push("exact_permanent_text_without_done");
    else problems.push("the caller did not receive exactly the permanent isolation text");
    if (outcome.ms > STARTUP_TIMEOUT_MS + 2000) problems.push("the failure took longer than the startup bound plus 2 s");
    expect((await gatewayRequest(rig.gateway.port, "GET", "/health")).json?.isolation, "/health isolation").toBe("unavailable");
    const dir = conversationDirs(rig.gateway, ["conv-startup-exit"])[0];
    if (dir && fs.existsSync(path.join(dir, "work", "m-startup"))) problems.push("the scripted tool ran");
    // Recovery: with the fault removed the next start works and the state returns to ok.
    wrapper.setMode("pass");
    const recovered = await chatTurn(rig, { prompt: "IF-startup-exit-recover", sessionId: "conv-startup-exit", steps: [bashStep("echo RECOVERED")], withCredentials: false });
    problems.push(...turnProblems(recovered));
    if ((await waitForIsolation(rig)) === "ok") controls.push("next_start_recovered_and_health_returned_to_ok");
    else problems.push("/health isolation did not return to ok");
    finishRow(recorder, rig, { id: "IF.startup-exit", durationMs: outcome.ms, deadlineMs: STARTUP_TIMEOUT_MS + 2000, surfaces: noRunSurfaces(rig, window, outcome), controls, problems });
  });

  it("IF.startup-hang: a sandbox that never reports ready is killed and refused with the transient text within the startup bound; nothing ran", async () => {
    const { rig, wrapper } = await wrapperRig();
    const started = Date.now();
    const { outcome, launches, window, queryId } = await injected(rig, wrapper, "startup-hang", "startup-hang", [bashStep("touch /work/m-hang; echo RAN")]);
    const problems = fallbackProblems(rig, window, { runtimes: "none", modelRequests: "none" });
    const controls: string[] = [];
    if (launches.some((launch) => launch.mode === "startup-hang" && launch.run !== "none")) controls.push("launcher_saw_this_runs_start_before_it_hung");
    else problems.push("the launcher did not see a launch of this run");
    if (exactError(outcome, IN_TIME(queryId))) controls.push("exact_transient_text_without_done");
    else problems.push("the caller did not receive exactly the transient isolation text");
    if (outcome.ms < STARTUP_TIMEOUT_MS - 200 || outcome.ms > STARTUP_TIMEOUT_MS + 2000) problems.push("the failure did not arrive at the startup bound");
    const hungLauncher = (): number => descendants(rig.gateway.child.pid!).length;
    await waitFor(() => hungLauncher() === 0, 5000, "the hung launcher to be killed").catch(() => problems.push("the hung launcher was not killed"));
    const dir = conversationDirs(rig.gateway, ["conv-startup-hang"])[0];
    if (dir && fs.existsSync(path.join(dir, "work", "m-hang"))) problems.push("the scripted tool ran");
    finishRow(recorder, rig, { id: "IF.startup-hang", durationMs: outcome.ms, deadlineMs: STARTUP_TIMEOUT_MS + 2000, surfaces: noRunSurfaces(rig, window, outcome), controls, problems });
  });

  it("IF.policy: a sandbox that can still create nested user namespaces fails the in-sandbox restriction check before the first tool; nothing ran", async () => {
    const { rig, wrapper } = await wrapperRig();
    const started = Date.now();
    const { outcome, launches, window, queryId } = await injected(rig, wrapper, "no-userns", "policy", [bashStep("touch /work/m-policy; echo RAN")]);
    const problems = fallbackProblems(rig, window, { runtimes: "none", modelRequests: "none" });
    const controls: string[] = [];
    if (launches.some((launch) => launch.mode === "no-userns" && launch.run !== "none")) controls.push("sandbox_started_with_the_restriction_dropped");
    else problems.push("the launcher did not see a launch of this run");
    if (/problem=userns_not_blocked/.test(rig.log().slice(window.logFrom))) controls.push("gateway_log_names_the_failed_policy_check");
    else problems.push("the gateway log did not name the failed restriction check");
    if (exactError(outcome, UNAVAILABLE(queryId))) controls.push("exact_permanent_text_without_done");
    else problems.push("the caller did not receive exactly the permanent isolation text");
    if (outcome.ms > STARTUP_TIMEOUT_MS + 2000) problems.push("the failure took longer than the startup bound plus 2 s");
    const dir = conversationDirs(rig.gateway, ["conv-policy"])[0];
    if (dir && fs.existsSync(path.join(dir, "work", "m-policy"))) problems.push("the scripted tool's marker exists");
    finishRow(recorder, rig, { id: "IF.policy", durationMs: outcome.ms, deadlineMs: STARTUP_TIMEOUT_MS + 2000, surfaces: noRunSurfaces(rig, window, outcome), controls, problems });
  });
});

/* ------------------------------------------------------------------ */
/*  Cancellation and restart during a tool call                         */
/* ------------------------------------------------------------------ */

interface HeldRun {
  rig: SecurityRig;
  tag: string;
  session: string;
  queryId: string;
  prompt: string;
  window: Window;
  outcome: Promise<QueryOutcome>;
  control: { abort?: () => void };
}

/** Starts a run whose Bash tool holds a tagged child, and waits until the host sees the child and the model double recorded the call. */
async function startHeldRun(rig: SecurityRig, id: string): Promise<HeldRun> {
  const tag = `HELD-${id}-${randomBytes(3).toString("hex")}`;
  const prompt = `IF-${id}`;
  const session = `conv-${id}`;
  const queryId = `q-${id}-${randomBytes(2).toString("hex")}`;
  rig.scripts.push(scriptOf(prompt, [bashStep(heldCommand(tag))]));
  const window = windowOf(rig, [tag]);
  const control: { abort?: () => void } = {};
  const outcome = rig.ask("reqlift", { queryId, sessionId: session, prompt, user_id: "user-1", useSession: true, allowedTools: ["Bash"] }, 90_000, control);
  await waitFor(() => window.peek().windows[tag] !== undefined && rig.api.requests.some((request) => request.userTexts.some((text) => text.includes(prompt)) && !request.warmup), 60_000, "the tagged child below the gateway and the model's tool call");
  return { rig, tag, session, queryId, prompt, window, outcome, control };
}

/** The NDJSON events the gateway replays for a query id. */
async function replay(rig: SecurityRig, queryId: string): Promise<{ status: number; events: Ndjson[]; text: string }> {
  const res = await gatewayRequest(rig.gateway.port, "GET", `/v1/query/${queryId}/events`, undefined, rig.keys.reqlift);
  const events = res.text.split("\n").filter((line) => line.trim().startsWith("{")).flatMap((line) => {
    try {
      return [JSON.parse(line) as Ndjson];
    } catch {
      return [];
    }
  });
  return { status: res.status, events, text: res.text };
}

describe("cancellation and restart during a tool call with a child process", () => {
  it("IF.cancel: closing the caller's connection ends the run, the abort error is replayed without done, no tagged process or run directory is left, and the conversation is free", async () => {
    const rig = await newRig();
    const started = Date.now();
    const held = await startHeldRun(rig, "cancel");
    const problems: string[] = [];
    const controls = ["tagged_child_below_the_gateway_and_tool_call_recorded_before_the_cancel"];
    const cancelledAt = Date.now();
    held.control.abort!();
    const outcome = await held.outcome;
    await waitFor(() => taggedProcesses(rig, held.tag) === 0, NOTHING_LEFT_WITHIN_MS, "the tagged child to end").catch(() => problems.push("a tagged process survived the cancellation"));
    await waitFor(() => descendants(rig.gateway.child.pid!).length === 0 && runLeftoversText(rig.gateway).files === 0, NOTHING_LEFT_WITHIN_MS, "the runtime and the run directory to go").catch(() => problems.push("a runtime process or a run directory survived the cancellation"));
    if (problems.length === 0) controls.push("no_tagged_process_no_runtime_no_run_directory_within_the_bound");
    const replayed = await replay(rig, held.queryId);
    if (replayed.status === 200 && replayed.events.at(-1)?.type === "error" && !replayed.events.some((event) => event.type === "done")) controls.push("replay_ends_with_the_abort_error_and_no_done");
    else problems.push(`the replayed events did not end with an error and no done (status ${replayed.status}, last ${replayed.events.at(-1)?.type ?? "none"})`);
    if (outcome.events.some((event) => event.type === "done")) problems.push("the cancelled stream reported done");
    // The conversation is free again: the next turn on it works inside a fresh sandbox.
    const next = await chatTurn(rig, { prompt: "AFTER-cancel-next", sessionId: held.session, steps: [bashStep("echo NEXT-OK; cat /work/held")], withCredentials: false });
    problems.push(...turnProblems(next), ...(next.results[0]?.text.includes("NEXT-OK") ? [] : ["the conversation was not free for the next turn"]));
    problems.push(...fallbackProblems(rig, held.window, { runtimes: "some", modelRequests: "some" }));
    finishRow(recorder, rig, {
      id: "IF.cancel",
      durationMs: Date.now() - cancelledAt,
      deadlineMs: NOTHING_LEFT_WITHIN_MS,
      surfaces: [...surfacesOf(rig, [{ ...next, prompt: held.prompt, extraPrompts: [next.prompt] }]), { name: "caller-body", text: outcome.raw }, { name: "replayed-events", text: replayed.text }],
      controls,
      problems,
      floors: { "tool-results": 5 },
    });
  });

  it.each([
    ["IF.restart-term", "SIGTERM"],
    ["IF.restart-kill", "SIGKILL"],
  ] as const)("%s: stopping the gateway with %s during the tool call ends the caller's stream without done, leaves no tagged process, and the conversation resumes inside a sandbox", async (id, signal) => {
    const rig = await newRig();
    const started = Date.now();
    const held = await startHeldRun(rig, id.toLowerCase().replace(/[^a-z]/g, ""));
    const problems: string[] = [];
    const controls = ["tagged_child_below_the_gateway_and_tool_call_recorded_before_the_stop"];
    const stoppedAt = Date.now();
    const old = rig.gateway.child;
    old.kill(signal);
    await new Promise<void>((resolve) => (old.exitCode !== null || old.signalCode !== null ? resolve() : old.once("exit", () => resolve())));
    const exitMs = Date.now() - stoppedAt;
    const outcome = await held.outcome;
    const streamEndMs = Date.now() - stoppedAt;
    const bound = signal === "SIGTERM" ? SHUTDOWN_DRAIN_MS + 5000 : 5000;
    if (exitMs > bound) problems.push(`the gateway took ${exitMs} ms to exit`);
    if (streamEndMs > bound) problems.push(`the caller's stream ended ${streamEndMs} ms after the stop`);
    if (outcome.events.some((event) => event.type === "done")) problems.push("the stream ended with done");
    else if (outcome.aborted) controls.push("stream_ended_abnormally_without_done");
    else problems.push("the stream was not cut (it ended normally)");
    // No tagged process survives the gateway: the sandbox dies with its parent.
    await waitFor(() => !fs.readdirSync("/proc").some((entry) => /^\d+$/.test(entry) && (() => { try { return fs.readFileSync(`/proc/${entry}/cmdline`).toString("latin1").includes(held.tag); } catch { return false; } })()), 10_000, "the tagged child to end").then(() => controls.push("no_tagged_process_survived_the_gateway")).catch(() => problems.push("a tagged process survived the gateway"));
    const sample = held.window.close();
    if (sample.sample.unsandboxedRuntimes.length > 0) problems.push("an agent runtime ran without a sandbox ancestor");
    const leftovers = runLeftoversText(rig.gateway).files;
    await rig.restart();
    expect(await waitForIsolation(rig), "/health isolation after the restart").toBe("ok");
    const afterSweep = runLeftoversText(rig.gateway).files;
    if (afterSweep !== 0) problems.push(`${afterSweep} run file(s) survived the restart`);
    else controls.push(leftovers > 0 ? "restart_swept_what_the_stop_left_behind" : "no_run_files_after_the_restart");
    const replayed = await replay(rig, held.queryId);
    if (replayed.status === 404 && /Query not found or expired/.test(replayed.text)) controls.push("replay_after_the_restart_says_query_not_found");
    else problems.push(`the replay after the restart answered ${replayed.status}`);
    // The conversation resumes inside a sandbox: its environment shows only the run token as credential.
    const resumed = await chatTurn(rig, { prompt: `AFTER-${held.session}-resume`, sessionId: held.session, steps: [bashStep("env | sort; cat /work/held")], withCredentials: false });
    problems.push(...turnProblems(resumed));
    const envText = resumed.results[0]?.text ?? "";
    if (envText.includes("HOME=/home/node") && /ANTHROPIC_API_KEY=mpt_/.test(envText)) controls.push("resumed_conversation_runs_inside_a_sandbox");
    else problems.push("the resumed conversation did not run inside a sandbox");
    finishRow(recorder, rig, {
      id,
      // The failure's own time (the stop to the end of the caller's stream); the resume afterwards is not part of the deadline.
      durationMs: streamEndMs,
      deadlineMs: bound,
      surfaces: [...surfacesOf(rig, [{ ...resumed, prompt: held.prompt, extraPrompts: [resumed.prompt] }]), { name: "caller-body", text: outcome.raw }, { name: "replayed-events", text: replayed.text }],
      controls,
      problems,
    });
  });
});

/* ------------------------------------------------------------------ */
/*  Upstream credential, timeout and unavailability                     */
/* ------------------------------------------------------------------ */

const PER_USER_SCHEMA = {
  fields: [{ key: "token", label: "Token", type: "password", required: true }],
  outputs: [{ outputKey: "Authorization", target: "headers", template: "Bearer {token}" }],
};

describe("trusted mediation failures", () => {
  /** One model call of `mcp__<server>__get_page`, returning the model-bound result, the NDJSON tool_result event and the relay's audit lines. */
  async function mediated(rig: SecurityRig, server: string, prompt: string, session: string, body: Record<string, unknown> = {}) {
    const window = windowOf(rig);
    const turn = await chatTurn(rig, { prompt, sessionId: session, steps: [{ name: `mcp__${server}__get_page`, input: { id: "P-1" } }], withCredentials: false, body: { allowedTools: [`mcp__${server}__*`], ...body } });
    const toolResult = turn.outcome.events.find((event) => event.type === "tool_result") as { output?: string; success?: boolean } | undefined;
    const audit = rig.log().slice(window.logFrom).split("\n").filter((line) => line.includes("mcp.relay.refused") && line.includes(`serverName=${server}`));
    return { turn, result: turn.results[0], toolResult, audit, window };
  }

  it("IF.cred-missing: a run without the user's credential gets the fixed no-credential text at the relay, success:false, no upstream tools/call, no shared fallback and no login", async () => {
    const rig = await newRig();
    const started = Date.now();
    const upstream = await startOAuthMcpStub({ toolNames: ["get_page"] });
    cleanups.push(() => upstream.close());
    await rig.register("reqlift", "peruser", { type: "http", url: upstream.url, userCredentialSchema: PER_USER_SCHEMA });
    await new Promise((resolve) => setTimeout(resolve, 300));
    const callsBefore = upstream.toolCalls.length;
    const authBefore = upstream.authorizations().length;
    const oauth = (counters: typeof upstream.counters): string => JSON.stringify([counters.registration, counters.authorize, counters.token, counters.metadata]);
    const countersBefore = oauth(upstream.counters);
    const { turn, result, toolResult, audit, window } = await mediated(rig, "peruser", "IF-CRED-MISSING", "conv-cred-missing");
    const problems = [...turnProblems(turn), ...fallbackProblems(rig, window, { runtimes: "some", modelRequests: "some" })];
    const controls: string[] = [];
    const text = `TOOL_AUTH_UNAVAILABLE: No credential for "peruser" was provided with this request. Ask the user to connect their account; retrying will not help.`;
    if (result?.isError && result.text === text && toolResult?.success === false && toolResult.output === text) controls.push("exact_no_credential_text_with_success_false");
    else problems.push("the model-bound result and the stream event were not the exact no-credential failure");
    if (audit.some((line) => line.includes("reason=no_credential"))) controls.push("relay_audit_line_shows_the_mediation_step_was_reached");
    else problems.push("the relay's audit line for the refusal is missing");
    if (upstream.toolCalls.length === callsBefore) controls.push("upstream_received_no_tools_call");
    else problems.push("a tools/call reached the upstream");
    const sharedTried = upstream.authorizations().slice(authBefore).filter((value) => value !== undefined);
    if (sharedTried.length > 0) problems.push("a credential was sent to the upstream although the run had none");
    if (oauth(upstream.counters) !== countersBefore) problems.push("an OAuth discovery, registration or token request reached the upstream");
    else controls.push("no_oauth_login_attempted");
    // The other shape: a server that requires the user's credential is left out of the run, so the call is refused by the runtime itself and nothing reaches the upstream.
    await rig.register("reqlift", "needsuser", { type: "http", url: upstream.url, userCredentialSchema: PER_USER_SCHEMA, requireUserCredentials: true });
    await new Promise((resolve) => setTimeout(resolve, 300));
    const omitted = await mediated(rig, "needsuser", "IF-CRED-OMITTED", "conv-cred-omitted");
    if (omitted.result?.isError && omitted.result.text.includes("No such tool available") && /mcp\.server\.omitted serverName=needsuser reason=missing_user_credential/.test(rig.log())) controls.push("required_credential_server_left_out_and_call_refused");
    else problems.push("the server that requires the user's credential was not left out of the run");
    if (upstream.toolCalls.length !== callsBefore) problems.push("a tools/call reached the upstream through the omitted server");
    problems.push(...turnProblems(omitted.turn));
    finishRow(recorder, rig, { id: "IF.cred-missing", durationMs: Date.now() - started, deadlineMs: TURN_DEADLINE_MS, surfaces: surfacesOf(rig, [turn, omitted.turn]), controls, problems, floors: { "tool-results": 50 } });
  });

  it("IF.cred-refused: an upstream that answers 401 to the user's credential, and to the gateway's own, gets the fixed refusal text, success:false, one call with that credential only, no shared fallback and no login", async () => {
    const rig = await newRig();
    const v = rig.markers.values;
    const started = Date.now();
    const user = await startOAuthMcpStub({ toolNames: ["get_page"], refuse: "tools-call" });
    cleanups.push(() => user.close());
    const shared = await startOAuthMcpStub({ toolNames: ["get_page"], refuse: "tools-call" });
    cleanups.push(() => shared.close());
    await rig.register("reqlift", "refuseduser", { type: "http", url: user.url, userCredentialSchema: PER_USER_SCHEMA });
    await rig.register("reqlift", "refusedshared", { type: "http", url: shared.url, headers: { Authorization: `Basic ${v.registryHttpHeader}` } });
    await new Promise((resolve) => setTimeout(resolve, 300));
    const oauth = (counters: typeof user.counters): string => JSON.stringify([counters.registration, counters.authorize, counters.token, counters.metadata]);
    const countersBefore = [oauth(user.counters), oauth(shared.counters)];
    const toolCallRequests = (stub: typeof user) => stub.requests.filter((request) => request.rpcMethods.includes("tools/call"));
    const withUser = await mediated(rig, "refuseduser", "IF-CRED-REFUSED-USER", "conv-cred-refused-user", { mcpCredentialOverrides: { refuseduser: { headers: { Authorization: `Bearer ${v.userOverrideHeader}` } } } });
    const withShared = await mediated(rig, "refusedshared", "IF-CRED-REFUSED-SHARED", "conv-cred-refused-shared");
    const problems = [...turnProblems(withUser.turn), ...turnProblems(withShared.turn), ...fallbackProblems(rig, withUser.window, { runtimes: "some", modelRequests: "some" })];
    const controls: string[] = [];
    const userText = `TOOL_AUTH_UNAVAILABLE: "refuseduser" did not accept the user's credential. Ask the user to reconnect their account; retrying will not help.`;
    const sharedText = `TOOL_AUTH_UNAVAILABLE: "refusedshared" did not accept the gateway's credential. Ask your gateway administrator to check this tool's credential; retrying will not help.`;
    if (withUser.result?.isError && withUser.result.text === userText && withUser.toolResult?.success === false) controls.push("exact_user_credential_refused_text_with_success_false");
    else problems.push("the user-credential refusal was not the exact fixed failure");
    if (withShared.result?.isError && withShared.result.text === sharedText && withShared.toolResult?.success === false) controls.push("exact_gateway_credential_refused_text_with_success_false");
    else problems.push("the gateway-credential refusal was not the exact fixed failure");
    if (toolCallRequests(user).length === 1 && toolCallRequests(user).every((request) => request.headers.authorization === `Bearer ${v.userOverrideHeader}`) && user.authorizations().every((value) => value === `Bearer ${v.userOverrideHeader}`)) controls.push("one_tools_call_with_the_user_credential_only");
    else problems.push("the user-credential upstream did not receive exactly one call with exactly the user's credential");
    if (toolCallRequests(shared).length === 1 && shared.authorizations().every((value) => value === `Basic ${v.registryHttpHeader}`)) controls.push("one_tools_call_with_the_registry_credential_only");
    else problems.push("the registry-credential upstream did not receive exactly one call with exactly its credential");
    if (withUser.audit.some((line) => line.includes("status=401")) && withShared.audit.some((line) => line.includes("status=401"))) controls.push("relay_audit_lines_show_the_refusals");
    else problems.push("the relay's audit lines for the refusals are missing");
    if (oauth(user.counters) !== countersBefore[0] || oauth(shared.counters) !== countersBefore[1]) problems.push("an OAuth discovery, registration or token request reached an upstream");
    else controls.push("no_oauth_login_attempted");
    const credentialsFile = path.join(rig.gateway.dirs.workspace, ".credentials.json");
    if (/mcpOAuth/.test(fs.readFileSync(credentialsFile, "utf8"))) problems.push("an mcpOAuth record was written");
    finishRow(recorder, rig, { id: "IF.cred-refused", durationMs: Date.now() - started, deadlineMs: TURN_DEADLINE_MS * 2, surfaces: surfacesOf(rig, [withUser.turn, withShared.turn]), controls, problems, floors: { "tool-results": 50 } });
  });

  it.each([
    ["IF.timeout", "hang", "TOOL_TIMEOUT", `TOOL_TIMEOUT: "faulty" did not answer within 3 seconds. Try again later or with a smaller request; if it keeps happening, tell your gateway administrator.`],
    ["IF.unavailable", "reset", "TOOL_UNAVAILABLE", `TOOL_UNAVAILABLE: "faulty" could not be reached or failed. Try again later; if it keeps happening, tell your gateway administrator.`],
  ] as const)("%s: an upstream that %ss on tools/call gets the fixed %s text with success:false inside the deadline, and the gateway stays up", async (id, mode, code, text) => {
    const rig = await newRig();
    const started = Date.now();
    const upstream = await startFaultMcp(mode);
    cleanups.push(() => upstream.close());
    await rig.register("reqlift", "faulty", { type: "http", url: upstream.url });
    await new Promise((resolve) => setTimeout(resolve, 300));
    const { turn, result, toolResult, audit, window } = await mediated(rig, "faulty", `IF-${code}`, `conv-${id.toLowerCase()}`);
    const problems = [...turnProblems(turn), ...fallbackProblems(rig, window, { runtimes: "some", modelRequests: "some" })];
    const controls: string[] = [];
    if (upstream.calls() === 1) controls.push("upstream_recorded_the_tools_call");
    else problems.push(`the upstream recorded ${upstream.calls()} tools/call request(s)`);
    if (result?.isError && result.text === text && toolResult?.success === false && toolResult.output === text) controls.push(`exact_${code.toLowerCase()}_text_with_success_false`);
    else problems.push("the model-bound result and the stream event were not the exact fixed failure");
    if (audit.length > 0 || rig.log().includes("faulty")) controls.push("relay_audit_shows_the_mediation_step_was_reached");
    const bound = (mode === "hang" ? TOOL_TIMEOUT_MS : 0) + 30_000;
    if (turn.outcome.ms > bound) problems.push("the turn took longer than the tool deadline plus the run's own work");
    if (rig.gateway.child.exitCode !== null) problems.push("the gateway stopped");
    else controls.push("gateway_still_up");
    if ((await gatewayRequest(rig.gateway.port, "GET", "/health")).status !== 200) problems.push("/health did not answer");
    finishRow(recorder, rig, { id, durationMs: Date.now() - started, deadlineMs: bound, surfaces: surfacesOf(rig, [turn]), controls, problems, floors: { "tool-results": 50 } });
  });
});

/* ------------------------------------------------------------------ */
/*  Legacy session                                                      */
/* ------------------------------------------------------------------ */

describe("legacy session admission", () => {
  it("IF.legacy: resuming a stored conversation that holds a credential-bearing legacy transcript is refused with the legacy text, raises the audit count, makes no model request and starts no runtime", async () => {
    const rig = await newRig();
    const started = Date.now();
    const count = (pattern: RegExp): number => [...rig.log().matchAll(pattern)].length;
    const refusals = (): number => Number([...rig.log().matchAll(/sessions\.legacy\.refused total=(\d+)/g)].at(-1)?.[1] ?? 0);
    const before = { refusals: refusals(), starts: count(/SDK options:/g), requests: rig.api.requests.length };
    const window = windowOf(rig);
    const queryId = `q-legacy-${randomBytes(2).toString("hex")}`;
    const outcome = await rig.ask("reqlift", { queryId, sessionId: "legacy-conv", prompt: "IF-LEGACY-RESUME", user_id: "user-1", useSession: true }, 10_000);
    await waitFor(() => refusals() === before.refusals + 1, 3000, "the audit line").catch(() => undefined);
    const problems = fallbackProblems(rig, window, { runtimes: "none", modelRequests: "none" });
    const controls: string[] = [];
    if (exactError(outcome, LEGACY) && outcome.ms <= 2000) controls.push("exact_legacy_text_within_2_s");
    else problems.push("the caller did not receive exactly the legacy text within 2 s");
    if (refusals() === before.refusals + 1) controls.push("audit_count_rose_by_one_at_the_admission_check");
    else problems.push("the legacy refusal audit count did not rise by exactly one");
    if (count(/SDK options:/g) === before.starts) controls.push("zero_runtime_starts");
    else problems.push("a runtime attempt was logged");
    // The legacy transcript is where the fixture put it, and its marker is on no surface.
    const transcript = path.join(rig.gateway.dirs.workspace, "projects", "-home-node", "sdk-legacy.jsonl");
    if (fs.existsSync(transcript) && fs.readFileSync(transcript, "utf8").includes(rig.markers.values.legacyTranscript)) controls.push("the_legacy_transcript_exists_and_holds_its_marker_on_the_host");
    else problems.push("the legacy transcript fixture was not on the host");
    finishRow(recorder, rig, { id: "IF.legacy", durationMs: Date.now() - started, deadlineMs: 2000, surfaces: noRunSurfaces(rig, window, outcome), controls, problems });
  });
});

describe("summary", () => {
  it("every expected row of the suite ran and passed", () => {
    const summary = recorder.finish();
    expect(summary.missing).toEqual([]);
    expect(summary.fail).toBe(0);
  });
});
