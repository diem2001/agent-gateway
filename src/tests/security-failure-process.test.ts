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
 * - `IF.check-tool-unshare`, `IF.check-tool-true` (MVP-8020): the same wrapper binds an empty non-executable file over one tool of the
 *   launch wrapper's own start check; the gateway log names `binary_missing`, the caller gets the permanent text, nothing ran and the next
 *   start with the tool back returns `/health` to `ok`.
 * - `IF.cancel`, `IF.restart-term`, `IF.restart-kill`: a Bash tool with a tagged child; the host sees the child below the
 *   gateway and the model double recorded the call before the caller closes the connection, or the gateway is stopped.
 * - `IF.detached-complete`, `IF.detached-cancel`, `IF.detached-kill` (MVP-7977): the same, with a tool child that left its session
 *   (`setsid nohup`). Host-side proof that it is detached inside the run's sandbox before the termination; afterwards the whole run is
 *   absent from the host (no process in its PID namespace, launcher and init gone, no process carrying the tag). A completed or
 *   cancelled run's relay URL and run token, saved from inside the sandbox, are refused. Only these three terminations are probed
 *   for detached children here; the startup timings are probed at `SandboxRun` level (`sandbox-process.test.ts`).
 * - `IF.cred-missing`, `IF.cred-refused`, `IF.timeout`, `IF.unavailable`: registered MCP server doubles behind the relay; the
 *   relay's own audit line shows the trusted mediation step was reached.
 * - `IF.legacy`: resume of a stored conversation with a credential-bearing legacy transcript.
 *
 * Every row also asserts, for the whole failure window, that no agent runtime ran without a `bwrap` ancestor (a process
 * sampler, because a runtime outside the sandbox would not reach the model double), counts the runtime starts, and checks
 * the gateway's own socket destinations. The fixed texts are asserted verbatim. Needs `npm run build`, `bwrap`, user
 * namespaces, `perl`, `git`, `python3`. Linux only. Every secret is synthetic; only names, booleans and counts are printed.
 */
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { SANDBOX_CHECK_LINE } from "../sandbox.js";
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
  DETACHED_MAX_AGE_S,
  describeRecords,
  endedNow,
  detachedAgeS,
  detachedCommand,
  detachedEvidence,
  detachedProof,
  detachedTag,
  killRun,
  sampleProblems,
  surfacesOf,
  turnProblems,
  waitForIsolation,
  waitRunGone,
  type DetachedRecord,
  type Ndjson,
  type QueryOutcome,
  type SecurityMarkers,
  type SecurityRig,
  type Surface,
  type ToolStep,
  type TurnObservation,
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
/** How long a relay audit line that must exist may trail the answer that was already seen (the log arrives through a pipe). */
const AUDIT_WAIT_MS = 5000;

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

/**
 * `bypass` and `bypass-ready` are the negative controls of the process sampler: the launcher drops the sandbox and runs
 * the runtime command (`bypass`: a stand-in Node with the same executable and `cli.js` argument, so nothing real runs
 * outside the sandbox; `bypass-ready`: after printing the sandbox check line, the real runtime in a scratch home) in the
 * gateway's own namespaces. `bypass-fork` is `bypass-ready` with the runtime as a child of this script (named `bwrap`) instead of
 * an exec, the shape of the exit-rule control (MVP-8090): a real runtime outside the sandbox below a process named `bwrap`. A mode that must start no runtime (`pass`, `startup-exit`, `startup-hang`, `no-userns`,
 * `mask-unshare`, `mask-true`) forks
 * nothing before it execs or exits: the sampler cannot tell a fork of this script, whose command line carries `cli.js`, from
 * a runtime, so the mode file, the time stamp and the `--disable-userns` strip use shell builtins only. `startup-exit` holds
 * 0.4 s on a FIFO (`read -t` on a builtin, no fork) before it exits: a process that ends before the sampler can read its
 * executable cannot be classified by it (a stated blind spot), so the double stays alive for several sampler ticks. `keep-inner`
 * (MVP-8125) removes only `--die-with-parent` from the arguments and execs the real bwrap: the sandbox is otherwise unchanged,
 * but its inner bwrap survives the end of the outer one, which makes the launcher-ended window deterministic.
 */
type WrapperMode = "pass" | "startup-exit" | "startup-hang" | "no-userns" | "mask-unshare" | "mask-true" | "bypass" | "bypass-ready" | "bypass-fork" | "keep-inner";

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
  fs.writeFileSync(path.join(dir, "mode"), "pass\n");
  // The stand-in of a missing start-check tool: an empty regular file that is not executable (`mask-*` binds it over the tool).
  fs.writeFileSync(path.join(dir, "empty"), "", { mode: 0o644 });
  execFileSync("mkfifo", [path.join(dir, "hold")]);
  fs.writeFileSync(
    script,
    String.raw`#!/bin/bash
DIR=${shellQuote(dir)}
{ read -r MODE < "$DIR/mode"; } 2>/dev/null
MODE=${"$"}{MODE:-pass}
NOW=${"$"}{EPOCHREALTIME/./}
printf '%s\t%s\t%s\n' "${"$"}{NOW%???}" "$MODE" "${"$"}{CLAUDE_CODE_DEBUG_LOGS_DIR:-none}" >> "$DIR/launches.log"
case "$MODE" in
  startup-exit) exec 5<> "$DIR/hold"; read -r -t 0.4 -u 5; exit 3 ;;
  startup-hang) exec sleep 120 ;;
  no-userns)
    ARGS="$DIR/args.$$"
    while IFS= read -r -d '' ARG; do [ "$ARG" = --disable-userns ] || printf '%s\0' "$ARG"; done <&3 > "$ARGS"
    exec /usr/bin/bwrap --args 4 "${"$"}{@:3}" 4< "$ARGS" ;;
  keep-inner)
    ARGS="$DIR/args.$$"
    while IFS= read -r -d '' ARG; do [ "$ARG" = --die-with-parent ] || printf '%s\0' "$ARG"; done <&3 > "$ARGS"
    exec /usr/bin/bwrap --args 4 "${"$"}{@:3}" 4< "$ARGS" ;;
  mask-unshare|mask-true)
    ARGS="$DIR/args.$$"
    while IFS= read -r -d '' ARG; do printf '%s\0' "$ARG"; done <&3 > "$ARGS"
    printf '%s\0%s\0%s\0' --ro-bind "$DIR/empty" "/usr/bin/${"$"}{MODE#mask-}" >> "$ARGS"
    exec /usr/bin/bwrap --args 4 "${"$"}{@:3}" 4< "$ARGS" ;;
  bypass)
    for ((i = 1; i <= $#; i++)); do [ "${"$"}{!i}" = sandbox ] && break; done
    exec "${"$"}{@:i+1:1}" -e 'setInterval(() => {}, 1000)' "${"$"}{@:i+2:1}" ;;
  bypass-ready)
    for ((i = 1; i <= $#; i++)); do [ "${"$"}{!i}" = sandbox ] && break; done
    echo ${SANDBOX_CHECK_LINE} >&2
    export HOME="$DIR/home"; mkdir -p "$HOME"; cd "$DIR"
    exec "${"$"}{@:i+1}" ;;
  bypass-fork)
    for ((i = 1; i <= $#; i++)); do [ "${"$"}{!i}" = sandbox ] && break; done
    echo ${SANDBOX_CHECK_LINE} >&2
    export HOME="$DIR/home"; mkdir -p "$HOME"; cd "$DIR"
    "${"$"}{@:i+1}"; exit $? ;;
  *) exec /usr/bin/bwrap "$@" ;;
esac
`,
    { mode: 0o755 },
  );
  return {
    path: script,
    setMode: (mode) => fs.writeFileSync(path.join(dir, "mode"), `${mode}\n`),
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

async function wrapperRig(startupTimeoutMs: number = STARTUP_TIMEOUT_MS): Promise<{ rig: SecurityRig; wrapper: Wrapper }> {
  const wrapper = makeWrapper();
  const rig = await createRig(cleanups, { markers, env: { AGENT_SANDBOX_BWRAP: wrapper.path, ISOLATION_STARTUP_TIMEOUT_MS: String(startupTimeoutMs), AGENT_MCP_TOOL_TIMEOUT_MS: String(TOOL_TIMEOUT_MS) } });
  expect(pinnedProblems(rig)).toEqual([]);
  expect(await waitForIsolation(rig), "the boot self-check passes through the wrapper").toBe("ok");
  await registerStandardServers(rig);
  return { rig, wrapper };
}

/* ------------------------------------------------------------------ */
/*  Shared checks                                                       */
/* ------------------------------------------------------------------ */

/** The failure window: a process sampler, an egress sampler and the counters every row compares afterwards. */
function windowOf(rig: SecurityRig, tags: string[] = [], seam: { afterStableReading?: (pid: number) => void } = {}) {
  const processes = startProcessSampler(() => rig.gateway.child.pid!, tags, 20, seam);
  const egress = startEgressSampler(() => rig.gateway.child.pid!);
  return {
    logFrom: rig.log().length,
    requestsBefore: rig.api.requests.length,
    startsBefore: (rig.log().match(/SDK options:/g) ?? []).length,
    peek: () => processes.peek(),
    close: () => ({ sample: processes.stop(rig.markers.values), egress: egress.stop() }),
  };
}

type Window = ReturnType<typeof windowOf>;

/** Nothing in the window ran outside the sandbox or reached a non-loopback destination; `runtimes` says how many runtimes the window may have started. */
function fallbackProblems(rig: SecurityRig, window: Window, expectation: { runtimes: "none" | "some"; modelRequests: "none" | "some" }): string[] {
  const { sample, egress } = window.close();
  const problems: string[] = [];
  problems.push(...sampleProblems(sample, rig.markers.values));
  if (expectation.runtimes === "none" && sample.runtimesSeen > 0) problems.push(`${sample.runtimesSeen} runtime process(es) started in a window that must start none [${describeRecords(sample.records.filter((record) => record.verdict === "runtime" || record.verdict === "unresolved"), rig.markers.values)}]`);
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

  it.each([
    ["IF.check-tool-unshare", "mask-unshare"],
    ["IF.check-tool-true", "mask-true"],
  ] as const)("%s: a sandbox whose start-check tool is not executable is refused as binary_missing before the first tool; nothing ran; the next start works", async (id, mode) => {
    const { rig, wrapper } = await wrapperRig();
    const slug = id.slice(3).toLowerCase();
    const { outcome, launches, window, queryId } = await injected(rig, wrapper, mode, slug, [bashStep(`touch /work/m-${slug}; echo RAN`)]);
    const problems = fallbackProblems(rig, window, { runtimes: "none", modelRequests: "none" });
    const controls: string[] = [];
    if (launches.some((launch) => launch.mode === mode && launch.run !== "none")) controls.push("sandbox_started_with_the_tool_masked");
    else problems.push("the launcher did not see a launch of this run");
    if (/problem=binary_missing/.test(rig.log().slice(window.logFrom))) controls.push("gateway_log_names_binary_missing");
    else problems.push("the gateway log did not name binary_missing");
    if (exactError(outcome, UNAVAILABLE(queryId))) controls.push("exact_permanent_text_without_done");
    else problems.push("the caller did not receive exactly the permanent isolation text");
    if (outcome.ms > STARTUP_TIMEOUT_MS + 2000) problems.push("the failure took longer than the startup bound plus 2 s");
    expect((await gatewayRequest(rig.gateway.port, "GET", "/health")).json?.isolation, "/health isolation").toBe("unavailable");
    const dir = conversationDirs(rig.gateway, [`conv-${slug}`])[0];
    if (dir && fs.existsSync(path.join(dir, "work", `m-${slug}`))) problems.push("the scripted tool's marker exists");
    // Recovery: with the tool back the next start works and the state returns to ok.
    wrapper.setMode("pass");
    const recovered = await chatTurn(rig, { prompt: `IF-${slug}-recover`, sessionId: `conv-${slug}`, steps: [bashStep("echo RECOVERED")], withCredentials: false });
    problems.push(...turnProblems(recovered));
    if ((await waitForIsolation(rig)) === "ok") controls.push("next_start_recovered_and_health_returned_to_ok");
    else problems.push("/health isolation did not return to ok");
    finishRow(recorder, rig, { id, durationMs: outcome.ms, deadlineMs: STARTUP_TIMEOUT_MS + 2000, surfaces: noRunSurfaces(rig, window, outcome), controls, problems });
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
    if (sample.sample.unsandboxedRuntimes.length > 0) problems.push(`an agent runtime ran without a sandbox ancestor [${describeRecords(sample.sample.records.filter((record) => record.unsandboxed), rig.markers.values)}]`);
    problems.push(...sampleProblems(sample.sample, rig.markers.values).filter((problem) => problem.includes("cleared")));
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
/*  A detached tool child (setsid nohup) at the three terminations       */
/* ------------------------------------------------------------------ */

/**
 * Runs inside the sandbox as part of the tool command: saves the run's relay URL(s), model proxy base URL and run token to
 * `/work/replay.json` (never to the tool output), so the host can replay them after the run ended. Prints nothing.
 */
const SAVE_RUN_FACTS = String.raw`python3 - <<'PY'
import json, os, re
pattern = re.compile(rb'http://127\.0\.0\.1:\d+/mcp/[A-Za-z0-9_-]+')
urls, token, base = [], None, None
me = str(os.getpid())
def add(data):
    for m in pattern.finditer(data):
        u = m.group(0).decode()
        if u not in urls:
            urls.append(u)
for pid in os.listdir('/proc'):
    if not pid.isdigit() or pid == me:
        continue
    for name in ('cmdline', 'environ'):
        try:
            data = open('/proc/%s/%s' % (pid, name), 'rb').read()
        except Exception:
            continue
        add(data)
        if name == 'environ':
            for item in data.split(b'\0'):
                if item.startswith(b'ANTHROPIC_API_KEY=mpt_'):
                    token = item.split(b'=', 1)[1].decode()
                if item.startswith(b'ANTHROPIC_BASE_URL='):
                    base = item.split(b'=', 1)[1].decode()
for root in ('/tmp', '/home/node'):
    for dirpath, dirs, files in os.walk(root):
        for f in files:
            try:
                p = os.path.join(dirpath, f)
                if os.path.getsize(p) > 5000000:
                    continue
                add(open(p, 'rb').read())
            except Exception:
                continue
json.dump({'relay': urls, 'token': token, 'base': base}, open('/work/replay.json', 'w'))
PY`;

interface DetachedHeld {
  rig: SecurityRig;
  session: string;
  queryId: string;
  prompt: string;
  heldTag: string;
  window: Window;
  outcome: Promise<QueryOutcome>;
  control: { abort?: () => void };
  record: DetachedRecord;
  /** The conversation's work area on the host (`/work` inside the sandbox). */
  workDir: string;
}

/**
 * Starts a run whose Bash tool leaves a `setsid nohup` child, saves the run's relay URL and run token, then holds; waits until the
 * host proves the child is detached inside the run's sandbox and the model double recorded the call. A missing proof fails the row.
 */
async function startDetachedRun(rig: SecurityRig, id: string): Promise<DetachedHeld> {
  const heldTag = `HELD-${id}-${randomBytes(3).toString("hex")}`;
  const tag = detachedTag();
  const prompt = `IF-${id}`;
  const session = `conv-${id}`;
  const queryId = `q-${id}-${randomBytes(2).toString("hex")}`;
  const owned: { tag: string; outer?: DetachedRecord["outer"]; init?: DetachedRecord["init"] } = { tag };
  cleanups.push(async () => {
    killRun(owned);
    killRun({ tag: heldTag });
  });
  rig.scripts.push(scriptOf(prompt, [bashStep([detachedCommand(tag), SAVE_RUN_FACTS, heldCommand(heldTag), "echo DETACHED-TOOL-DONE"].join("\n"))]));
  const window = windowOf(rig, [heldTag, tag]);
  const control: { abort?: () => void } = {};
  const outcome = rig.ask("reqlift", { queryId, sessionId: session, prompt, user_id: "user-1", useSession: true, allowedTools: ["Bash", "mcp__jira__*"] }, 90_000, control);
  await waitFor(() => window.peek().windows[heldTag] !== undefined && rig.api.requests.some((request) => request.userTexts.some((text) => text.includes(prompt)) && !request.warmup), 60_000, "the held child below the gateway and the model's tool call");
  let proof = detachedProof(tag);
  await waitFor(() => (proof = detachedProof(tag)).record !== null, 30_000, "the proof of the detached child").catch(() => {
    throw new Error(`precondition not reached: held=[${proof.held.join(",")}] missing=[${proof.missing.join(",")}]`);
  });
  const record = proof.record!;
  owned.outer = record.outer;
  owned.init = record.init;
  const workDir = path.join(conversationDirs(rig.gateway, [session])[0], "work");
  return { rig, session, queryId, prompt, heldTag, window, outcome, control, record, workDir };
}

interface SavedRunFacts {
  relay: string[];
  token: string | null;
  base: string | null;
}

const savedFacts = (held: DetachedHeld): SavedRunFacts | null => {
  try {
    return JSON.parse(fs.readFileSync(path.join(held.workDir, "replay.json"), "utf8")) as SavedRunFacts;
  } catch {
    return null;
  }
};

const relayListCall = (url: string): Promise<Response> =>
  fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }), signal: AbortSignal.timeout(10_000) });

/** While the run lives, the saved relay URL answers (a permitted control: the replay after the run proves something only if it could have worked). */
async function relayLiveControl(held: DetachedHeld): Promise<string | null> {
  const facts = savedFacts(held);
  if (!facts || facts.relay.length === 0 || !facts.token || !facts.base) return "the run's relay URL and run token could not be saved from inside the sandbox";
  const status = (await relayListCall(facts.relay[0])).status;
  return status === 200 ? null : `the saved relay URL answered ${status} while the run was alive (the replay control is not live)`;
}

/** After the run ended: the saved relay URL and run token are refused and nothing reaches the MCP or model doubles. */
async function replayRefusals(held: DetachedHeld): Promise<{ problems: string[]; controls: string[] }> {
  const { rig } = held;
  const facts = savedFacts(held);
  const problems: string[] = [];
  const controls: string[] = [];
  if (!facts || facts.relay.length === 0 || !facts.token || !facts.base) return { problems: ["the run's relay URL and run token could not be saved from inside the sandbox"], controls };
  const jiraBefore = rig.jira.requests.length;
  const apiBefore = rig.api.requests.length;
  for (const url of facts.relay) {
    const status = (await relayListCall(url)).status;
    if (status !== 404) problems.push(`a saved relay URL answered ${status} after the run ended`);
  }
  const model = await fetch(`${facts.base}/v1/messages`, { method: "POST", headers: { "x-api-key": facts.token, "content-type": "application/json", "anthropic-version": "2023-06-01" }, body: "{}", signal: AbortSignal.timeout(10_000) });
  if (model.status !== 401) problems.push(`the saved run token answered ${model.status} after the run ended`);
  if (rig.jira.requests.length !== jiraBefore || rig.api.requests.length !== apiBefore) problems.push("a replay reached an upstream double");
  if (problems.length === 0) controls.push("saved_relay_url_refused_404_and_saved_run_token_refused_401_nothing_reached_a_double");
  return { problems, controls };
}

/** The checks every detached row makes of the end of the run: nothing of it is left on the host, and the child did not simply expire. */
async function detachedEndProblems(id: string, held: DetachedHeld, bound: number): Promise<{ problems: string[]; controls: string[]; elapsedMs: number }> {
  const presence = await waitRunGone(held.record, bound);
  const age = detachedAgeS(held.record);
  detachedEvidence(id, { absent_after_ms: presence.elapsedMs, child_age_s: Math.round(age), survivors: presence.survivors.length, proof: true });
  const problems: string[] = [];
  const controls = ["detached_child_proven_inside_the_sandbox_before_the_end"];
  if (!presence.gone) problems.push(`the run was not gone within ${bound} ms: ${presence.survivors.join(" | ")}`);
  else if (age >= DETACHED_MAX_AGE_S) problems.push(`the detached child could have expired by itself (age ${Math.round(age)} s)`);
  else controls.push("no_process_in_the_sandbox_namespace_no_launcher_no_tagged_process_before_the_child_could_expire");
  return { problems, controls, elapsedMs: presence.elapsedMs };
}

const turnOf = (held: DetachedHeld, outcome: QueryOutcome): TurnObservation => ({ outcome, prompt: held.prompt, extraPrompts: [], sessionId: held.session, queryId: held.queryId, logFrom: held.window.logFrom }) as unknown as TurnObservation;

describe("a detached tool child (setsid nohup) at completion, cancellation and gateway SIGKILL", () => {
  it("IF.detached-complete: the run's normal end leaves no process of the sandbox, and the run's relay URL and token are refused afterwards", async () => {
    const rig = await newRig();
    const held = await startDetachedRun(rig, "dcomplete");
    const live = await relayLiveControl(held);
    const problems: string[] = live ? [live] : [];
    fs.writeFileSync(path.join(held.workDir, "stop"), "");
    const outcome = await held.outcome;
    if (outcome.events.at(-1)?.type !== "done") problems.push(`the stream did not end in done (${outcome.events.at(-1)?.type ?? "none"})`);
    const end = await detachedEndProblems("IF.detached-complete", held, NOTHING_LEFT_WITHIN_MS);
    problems.push(...end.problems);
    await waitFor(() => descendants(rig.gateway.child.pid!).length === 0 && runLeftoversText(rig.gateway).files === 0, NOTHING_LEFT_WITHIN_MS, "the runtime and the run directory to go").catch(() => problems.push("a runtime process or a run directory survived the normal end"));
    const replayed = await replayRefusals(held);
    problems.push(...replayed.problems, ...fallbackProblems(rig, held.window, { runtimes: "some", modelRequests: "some" }));
    finishRow(recorder, rig, { id: "IF.detached-complete", durationMs: end.elapsedMs, deadlineMs: NOTHING_LEFT_WITHIN_MS, surfaces: surfacesOf(rig, [turnOf(held, outcome)]), controls: [...end.controls, ...(live ? [] : ["saved_relay_url_answered_while_the_run_was_alive"]), ...replayed.controls], problems, floors: { "tool-results": 5 } });
  });

  it("IF.detached-cancel: closing the caller's connection leaves no process of the sandbox, and the run's relay URL and token are refused afterwards", async () => {
    const rig = await newRig();
    const held = await startDetachedRun(rig, "dcancel");
    const live = await relayLiveControl(held);
    const problems: string[] = live ? [live] : [];
    held.control.abort!();
    const outcome = await held.outcome;
    if (outcome.events.some((event) => event.type === "done")) problems.push("the cancelled stream reported done");
    const end = await detachedEndProblems("IF.detached-cancel", held, NOTHING_LEFT_WITHIN_MS);
    problems.push(...end.problems);
    await waitFor(() => descendants(rig.gateway.child.pid!).length === 0 && runLeftoversText(rig.gateway).files === 0, NOTHING_LEFT_WITHIN_MS, "the runtime and the run directory to go").catch(() => problems.push("a runtime process or a run directory survived the cancellation"));
    const replayed = await replayRefusals(held);
    problems.push(...replayed.problems, ...fallbackProblems(rig, held.window, { runtimes: "some", modelRequests: "some" }));
    finishRow(recorder, rig, { id: "IF.detached-cancel", durationMs: end.elapsedMs, deadlineMs: NOTHING_LEFT_WITHIN_MS, surfaces: surfacesOf(rig, [turnOf(held, outcome)]), controls: [...end.controls, ...(live ? [] : ["saved_relay_url_answered_while_the_run_was_alive"]), ...replayed.controls], problems, floors: { "tool-results": 0 } });
  });

  it("IF.detached-kill: SIGKILL of the gateway leaves no process of the sandbox, the stream ends without done, and the restart sweeps the run files (the in-memory relay and proxy grants end with the process: no replay claim)", async () => {
    const rig = await newRig();
    const held = await startDetachedRun(rig, "dkill");
    const problems: string[] = [];
    const stoppedAt = Date.now();
    const old = rig.gateway.child;
    old.kill("SIGKILL");
    await new Promise<void>((resolve) => (old.exitCode !== null || old.signalCode !== null ? resolve() : old.once("exit", () => resolve())));
    const exitMs = Date.now() - stoppedAt;
    const outcome = await held.outcome;
    const streamEndMs = Date.now() - stoppedAt;
    if (exitMs > 5000) problems.push(`the gateway took ${exitMs} ms to exit`);
    if (streamEndMs > 5000) problems.push(`the caller's stream ended ${streamEndMs} ms after the stop`);
    if (outcome.events.some((event) => event.type === "done")) problems.push("the stream ended with done");
    const end = await detachedEndProblems("IF.detached-kill", held, 10_000);
    problems.push(...end.problems);
    const sample = held.window.close();
    if (sample.sample.unsandboxedRuntimes.length > 0) problems.push(`an agent runtime ran without a sandbox ancestor [${describeRecords(sample.sample.records.filter((record) => record.unsandboxed), rig.markers.values)}]`);
    problems.push(...sampleProblems(sample.sample, rig.markers.values).filter((problem) => problem.includes("cleared")));
    const controls = [...end.controls, ...(outcome.aborted ? ["stream_ended_abnormally_without_done"] : [])];
    if (!outcome.aborted) problems.push("the stream was not cut (it ended normally)");
    await rig.restart();
    expect(await waitForIsolation(rig), "/health isolation after the restart").toBe("ok");
    const afterSweep = runLeftoversText(rig.gateway).files;
    if (afterSweep !== 0) problems.push(`${afterSweep} run file(s) survived the restart`);
    else controls.push("no_run_files_after_the_restart");
    finishRow(recorder, rig, { id: "IF.detached-kill", durationMs: streamEndMs, deadlineMs: 5000, surfaces: surfacesOf(rig, [turnOf(held, outcome)]), controls, problems, floors: { "tool-results": 0 } });
  });
});

/* ------------------------------------------------------------------ */
/*  Upstream credential, timeout and unavailability                     */
/* ------------------------------------------------------------------ */

const PER_USER_SCHEMA = {
  fields: [{ key: "token", label: "Token", type: "password", required: true }],
  outputs: [{ outputKey: "Authorization", target: "headers", template: "Bearer {token}" }],
};

/**
 * One model call of `mcp__<server>__get_page`, returning the model-bound result, the NDJSON tool_result event and the
 * relay's audit lines. The runtime's answer can reach this process before the gateway's log line does, so a line that
 * must exist (`audit`) is waited for, bounded; checks that something did NOT happen run after that wait, never before.
 */
async function mediated(rig: SecurityRig, server: string, prompt: string, session: string, body: Record<string, unknown> = {}, audit: string | null = null) {
  const window = windowOf(rig);
  const turn = await chatTurn(rig, { prompt, sessionId: session, steps: [{ name: `mcp__${server}__get_page`, input: { id: "P-1" } }], withCredentials: false, body: { allowedTools: [`mcp__${server}__*`], ...body } });
  const toolResult = turn.outcome.events.find((event) => event.type === "tool_result") as { output?: string; success?: boolean } | undefined;
  const auditLines = (): string[] => rig.log().slice(window.logFrom).split("\n").filter((line) => line.includes("mcp.relay.refused") && line.includes(`serverName=${server}`));
  if (audit !== null) await waitFor(() => auditLines().some((line) => line.includes(audit)), AUDIT_WAIT_MS, "the relay audit line").catch(() => undefined);
  return { turn, result: turn.results[0], toolResult, audit: auditLines(), window };
}

type Mediated = Awaited<ReturnType<typeof mediated>>;

/* ------------------------------------------------------------------ */
/*  The refused-credential check, shared by the row and its control    */
/* ------------------------------------------------------------------ */

type OAuthStub = Awaited<ReturnType<typeof startOAuthMcpStub>>;

interface RefusalObservation {
  user: OAuthStub;
  shared: OAuthStub;
  countersBefore: string[];
  withUser: Mediated;
  withShared: Mediated;
}

const oauthCounters = (stub: OAuthStub): string => JSON.stringify([stub.counters.registration, stub.counters.authorize, stub.counters.token, stub.counters.metadata]);

/** Two registered servers, one per credential kind, whose upstreams `refuse` (401 to tools/call) or `accept` it, and one model call through each. */
async function refusalObservation(rig: SecurityRig, upstream: "refuse" | "accept"): Promise<RefusalObservation> {
  const v = rig.markers.values;
  const user = await startOAuthMcpStub({ toolNames: ["get_page"], ...(upstream === "refuse" ? { refuse: "tools-call" as const } : {}) });
  cleanups.push(() => user.close());
  const shared = await startOAuthMcpStub({ toolNames: ["get_page"], ...(upstream === "refuse" ? { refuse: "tools-call" as const } : {}) });
  cleanups.push(() => shared.close());
  await rig.register("reqlift", "refuseduser", { type: "http", url: user.url, userCredentialSchema: PER_USER_SCHEMA });
  await rig.register("reqlift", "refusedshared", { type: "http", url: shared.url, headers: { Authorization: `Basic ${v.registryHttpHeader}` } });
  await new Promise((resolve) => setTimeout(resolve, 300));
  const countersBefore = [oauthCounters(user), oauthCounters(shared)];
  const withUser = await mediated(rig, "refuseduser", "IF-CRED-REFUSED-USER", "conv-cred-refused-user", { mcpCredentialOverrides: { refuseduser: { headers: { Authorization: `Bearer ${v.userOverrideHeader}` } } } }, "status=401");
  const withShared = await mediated(rig, "refusedshared", "IF-CRED-REFUSED-SHARED", "conv-cred-refused-shared", {}, "status=401");
  return { user, shared, countersBefore, withUser, withShared };
}

/** What the IF.cred-refused row requires of an observation; the negative control feeds it an upstream that accepts the credential. */
function refusalProblems(rig: SecurityRig, observed: RefusalObservation): { problems: string[]; controls: string[]; withUser: Mediated; withShared: Mediated } {
  const v = rig.markers.values;
  const { user, shared, countersBefore, withUser, withShared } = observed;
  const toolCallRequests = (stub: OAuthStub) => stub.requests.filter((request) => request.rpcMethods.includes("tools/call"));
  const problems = [
    ...turnProblems(withUser.turn),
    ...turnProblems(withShared.turn),
    ...fallbackProblems(rig, withUser.window, { runtimes: "some", modelRequests: "some" }),
    ...fallbackProblems(rig, withShared.window, { runtimes: "some", modelRequests: "some" }),
  ];
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
  if (oauthCounters(user) !== countersBefore[0] || oauthCounters(shared) !== countersBefore[1]) problems.push("an OAuth discovery, registration or token request reached an upstream");
  else controls.push("no_oauth_login_attempted");
  const credentialsFile = path.join(rig.gateway.dirs.workspace, ".credentials.json");
  if (/mcpOAuth/.test(fs.readFileSync(credentialsFile, "utf8"))) problems.push("an mcpOAuth record was written");
  return { problems, controls, withUser, withShared };
}

describe("trusted mediation failures", () => {
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
    const { turn, result, toolResult, audit, window } = await mediated(rig, "peruser", "IF-CRED-MISSING", "conv-cred-missing", {}, "reason=no_credential");
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
    problems.push(...turnProblems(omitted.turn), ...fallbackProblems(rig, omitted.window, { runtimes: "some", modelRequests: "some" }));
    finishRow(recorder, rig, { id: "IF.cred-missing", durationMs: Date.now() - started, deadlineMs: TURN_DEADLINE_MS, surfaces: surfacesOf(rig, [turn, omitted.turn]), controls, problems, floors: { "tool-results": 50 } });
  });

  it("IF.cred-refused: an upstream that answers 401 to the user's credential, and to the gateway's own, gets the fixed refusal text, success:false, one call with that credential only, no shared fallback and no login", async () => {
    const rig = await newRig();
    const started = Date.now();
    const observed = await refusalObservation(rig, "refuse");
    const { problems, controls, withUser, withShared } = refusalProblems(rig, observed);
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


/* ------------------------------------------------------------------ */
/*  Negative controls: a genuine violation still fails                  */
/* ------------------------------------------------------------------ */

/**
 * The sampler's rule may only ever get stricter about a real runtime. These controls run the same windows as the rows
 * (`windowOf`, `fallbackProblems`, `chatTurn`, `turnProblems`) with real processes against a launcher that breaks the
 * sandbox, and against an upstream that accepts the credential the row says is refused. They are not matrix rows.
 */
describe("sampler and refusal-check controls", () => {
  it("control: a runtime outside the sandbox in a window that must start none is reported by both problems, with its pid and a Node executable", async () => {
    const { rig, wrapper } = await wrapperRig(30_000);
    const prompt = "IF-CONTROL-BYPASS-NONE";
    rig.scripts.push(scriptOf(prompt, [bashStep("echo CONTROL")]));
    wrapper.setMode("bypass");
    const window = windowOf(rig);
    const asked = rig.ask("reqlift", { queryId: "q-control-bypass-none", sessionId: "conv-control-bypass-none", prompt, user_id: "user-1", useSession: true, allowedTools: ["Bash"] }, 60_000).catch(() => undefined);
    await waitFor(() => window.peek().unsandboxedRuntimes.length > 0, 30_000, "the runtime started outside the sandbox");
    const seen = window.peek();
    const problems = fallbackProblems(rig, window, { runtimes: "none", modelRequests: "none" });
    expect(problems.filter((problem) => problem.includes("agent runtime(s) ran without a sandbox ancestor")).length).toBe(1);
    expect(problems.filter((problem) => problem.includes("runtime process(es) started in a window that must start none")).length).toBe(1);
    const flagged = seen.records.filter((record) => record.unsandboxed);
    expect(flagged.map((record) => record.pid)).toEqual(expect.arrayContaining(seen.unsandboxedRuntimes));
    expect(flagged.some((record) => record.exe === "claude" && record.verdict === "runtime")).toBe(true);
    expect(problems.join(" ")).not.toContain(rig.markers.values.providerApiKey);
    void asked;
  });

  it("control: a turn that completes with the runtime outside the sandbox is reported as a runtime without a sandbox ancestor", async () => {
    const { rig, wrapper } = await wrapperRig();
    wrapper.setMode("bypass-ready");
    const turn = await chatTurn(rig, { prompt: "IF-CONTROL-BYPASS-READY", sessionId: "conv-control-bypass-ready", steps: [bashStep("echo CONTROL")], withCredentials: false });
    const problems = turnProblems(turn);
    expect(problems.filter((problem) => problem.includes("agent runtime(s) ran without a sandbox ancestor")).length).toBe(1);
    expect(turn.sample.records.some((record) => record.unsandboxed && record.exe === "claude" && record.verdict === "runtime")).toBe(true);
  });

  it("control: a sandboxed runtime in a window that must start none is reported as a started runtime, and not as one outside the sandbox", async () => {
    const { rig } = await wrapperRig();
    const window = windowOf(rig);
    const turn = await chatTurn(rig, { prompt: "IF-CONTROL-PASS-NONE", sessionId: "conv-control-pass-none", steps: [bashStep("echo CONTROL")], withCredentials: false });
    const problems = fallbackProblems(rig, window, { runtimes: "none", modelRequests: "none" });
    expect(problems.some((problem) => problem.includes("runtime process(es) started in a window that must start none"))).toBe(true);
    expect(problems.some((problem) => problem.includes("ran without a sandbox ancestor"))).toBe(false);
    expect(turnProblems(turn)).toEqual([]);
  });

  /**
   * The exit-rule seam for a gateway-level control (MVP-8090): on the `atReading`-th stable reading of the native runtime
   * (the executable `claude`) it stops the runtime's parent, kills the runtime and holds the sampler tick until the runtime is
   * a zombie (bound 2 s; a missed bound leaves `reached` false and the control fails as a precondition). Only the runtime the
   * gateway started is signalled, and the stopped parent is continued by `release` once the window is closed.
   */
  function runtimeExit(atReading: number) {
    const state = { pid: 0, readings: 0, forced: false, reached: false, stopped: [] as number[] };
    const statOf = (pid: number): { state: string; ppid: number } | null => {
      try {
        const text = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
        const rest = text.slice(text.lastIndexOf(")") + 2).split(" ");
        return { state: rest[0], ppid: Number(rest[1]) };
      } catch {
        return null;
      }
    };
    const threads = (pid: number): number => Number(/^Threads:\s*(\d+)/m.exec(fs.readFileSync(`/proc/${pid}/status`, "utf8"))?.[1] ?? 1);
    const isZombie = (pid: number): boolean => {
      try {
        return statOf(pid)?.state === "Z" && threads(pid) <= 1;
      } catch {
        return false;
      }
    };
    const seam = (pid: number): void => {
      let exe = "";
      try {
        exe = path.basename(fs.readlinkSync(`/proc/${pid}/exe`));
      } catch {
        return;
      }
      if (exe !== "claude" || state.forced || (state.pid !== 0 && state.pid !== pid)) return;
      state.pid = pid;
      state.readings += 1;
      if (state.readings < atReading) return;
      state.forced = true;
      const parent = statOf(pid)?.ppid ?? 0;
      process.kill(parent, "SIGSTOP");
      state.stopped.push(parent);
      // SIGSTOP is delivered asynchronously: a parent that has not stopped yet would reap the runtime at once and leave no zombie.
      for (const end = Date.now() + 2000; statOf(parent)?.state !== "T" && Date.now() < end; Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 2));
      process.kill(pid, "SIGKILL");
      for (const end = Date.now() + 2000; !(state.reached = isZombie(pid)) && Date.now() < end; Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 2));
    };
    const release = (): void => {
      for (const pid of state.stopped.splice(0)) {
        try {
          process.kill(pid, "SIGCONT");
        } catch {
          // Already gone.
        }
      }
    };
    return { state, seam, release };
  }

  /**
   * The seam of a gateway-end control (MVP-8090 rev 3): on the `atReading`-th stable reading of the native runtime (the executable
   * `claude`) it SIGKILLs the gateway and holds the sampler tick until the gateway is a zombie (or gone) and the process `hops`
   * parents above the runtime, the gateway's own child, is gone or has a new parent. The tick is synchronous, so the test worker
   * cannot reap the gateway before the proof runs. With `endRuntime` the runtime is also killed from the event loop 100 ms later,
   * so the row can assert its exit before the window closes.
   */
  function gatewayEnd(gatewayPid: number, atReading: number, hops: number, endRuntime: boolean) {
    const state = { pid: 0, startTicks: "", readings: 0, forced: false, reached: false };
    const statOf = (pid: number): { state: string; ppid: number; startTicks: string } | null => {
      try {
        const text = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
        const rest = text.slice(text.lastIndexOf(")") + 2).split(" ");
        return { state: rest[0], ppid: Number(rest[1]), startTicks: rest[19] };
      } catch {
        return null;
      }
    };
    const threads = (pid: number): number => {
      try {
        return Number(/^Threads:\s*(\d+)/m.exec(fs.readFileSync(`/proc/${pid}/status`, "utf8"))?.[1] ?? 1);
      } catch {
        return 0;
      }
    };
    const ended = (pid: number): boolean => statOf(pid) === null || (statOf(pid)?.state === "Z" && threads(pid) <= 1);
    const seam = (pid: number): void => {
      let exe = "";
      try {
        exe = path.basename(fs.readlinkSync(`/proc/${pid}/exe`));
      } catch {
        return;
      }
      if (exe !== "claude" || state.forced || (state.pid !== 0 && state.pid !== pid)) return;
      state.pid = pid;
      state.readings += 1;
      if (state.readings < atReading) return;
      state.forced = true;
      state.startTicks = statOf(pid)?.startTicks ?? "";
      let top = pid;
      for (let hop = 0; hop < hops; hop++) top = statOf(top)?.ppid ?? 0;
      process.kill(gatewayPid, "SIGKILL");
      for (const end = Date.now() + 2000; !(state.reached = ended(gatewayPid) && (statOf(top) === null || statOf(top)!.ppid !== gatewayPid)) && Date.now() < end; Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 2));
      if (endRuntime) setTimeout(() => {
        try {
          process.kill(pid, "SIGKILL");
        } catch {
          // Already gone.
        }
      }, 100);
    };
    return { state, seam };
  }

  it("control G3 (smoke): the gateway is SIGKILLed after the sandboxed native runtime's own proof; the runtime is not reported, whichever of the two clear routes applies", async () => {
    const { rig } = await wrapperRig();
    const end = gatewayEnd(rig.gateway.child.pid!, 3, 2, false);
    const prompt = "IF-CONTROL-GATEWAY-END";
    rig.scripts.push(scriptOf(prompt, [bashStep("echo CONTROL")]));
    const window = windowOf(rig, [], { afterStableReading: end.seam });
    const asked = rig.ask("reqlift", { queryId: "q-control-gateway-end", sessionId: "conv-control-gateway-end", prompt, user_id: "user-1", useSession: true, allowedTools: ["Bash"] }, 90_000).catch(() => undefined);
    await waitFor(() => end.state.forced, 60_000, "the sampler to end the gateway");
    await waitFor(() => endedNow(end.state.pid, end.state.startTicks).ended, 15_000, "the runtime to end after its gateway");
    await waitFor(() => window.peek().records.every((record) => record.pending?.state !== "waiting"), 10_000, "pending records to settle");
    const { sample } = window.close();
    expect(end.state.reached, "precondition not reached: the gateway was not a zombie within its bound").toBe(true);
    const record = sample.records.find((candidate) => candidate.pid === end.state.pid);
    expect(record, "precondition not reached: the sampler did not record the runtime").toBeDefined();
    expect(record!.unsandboxed).toBe(false);
    expect(["own", "reference-ended"]).toContain(record!.clearedBy);
    expect(sample.unsandboxedRuntimes).toEqual([]);
    expect(sample.referenceChanged).toBe(0);
    expect(sampleProblems(sample, rig.markers.values)).toEqual([]);
    void asked;
  });

  it("control G4: the real native runtime outside the sandbox below a script named bwrap, whose gateway is SIGKILLed on the first reading, is reported", async () => {
    const { rig, wrapper } = await wrapperRig();
    wrapper.setMode("bypass-fork");
    const end = gatewayEnd(rig.gateway.child.pid!, 1, 1, true);
    const prompt = "IF-CONTROL-GATEWAY-END-BYPASS";
    rig.scripts.push(scriptOf(prompt, [bashStep("echo CONTROL")]));
    const window = windowOf(rig, [], { afterStableReading: end.seam });
    const asked = rig.ask("reqlift", { queryId: "q-control-gateway-end-bypass", sessionId: "conv-control-gateway-end-bypass", prompt, user_id: "user-1", useSession: true, allowedTools: ["Bash"] }, 90_000).catch(() => undefined);
    await waitFor(() => end.state.forced, 60_000, "the sampler to end the gateway");
    await waitFor(() => endedNow(end.state.pid, end.state.startTicks).ended, 15_000, "the runtime to end");
    const { sample } = window.close();
    expect(end.state.reached, "precondition not reached: the gateway was not a zombie within its bound").toBe(true);
    const record = sample.records.find((candidate) => candidate.pid === end.state.pid);
    expect(record, "precondition not reached: the sampler did not record the runtime").toBeDefined();
    expect(endedNow(end.state.pid, end.state.startTicks).ended, "the runtime's exit was not confirmed before the window closed").toBe(true);
    expect(record!.clearedBy).toBeUndefined();
    expect(record!.pending).toBeUndefined();
    expect(record!.proofFailure).toMatchObject({ ownProof: false, escapeEvidence: true, pending: "none" });
    expect(sample.unsandboxedRuntimes).toContain(record!.pid);
    const text = sampleProblems(sample, rig.markers.values).join("\n");
    expect(text).toContain("ran without a sandbox ancestor");
    expect(text).toContain(`pid ${record!.pid}`);
    void asked;
  });

  it("control G1: a sandboxed native runtime that exits after its own proof, with its parent stopped, is cleared by that proof and audited, not reported", async () => {
    const { rig } = await wrapperRig();
    const exit = runtimeExit(3);
    const prompt = "IF-CONTROL-EXIT-SANDBOXED";
    rig.scripts.push(scriptOf(prompt, [bashStep("echo CONTROL")]));
    const window = windowOf(rig, [], { afterStableReading: exit.seam });
    const asked = rig.ask("reqlift", { queryId: "q-control-exit-sandboxed", sessionId: "conv-control-exit-sandboxed", prompt, user_id: "user-1", useSession: true, allowedTools: ["Bash"] }, 90_000).catch(() => undefined);
    try {
      await waitFor(() => exit.state.forced, 60_000, "the sampler to force the runtime's exit");
      const { sample } = window.close();
      expect(exit.state.reached, "precondition not reached: the runtime was not a zombie within its bound").toBe(true);
      const record = sample.records.find((candidate) => candidate.pid === exit.state.pid);
      expect(record, "precondition not reached: the sampler did not record the runtime").toBeDefined();
      expect(record!.exe).toBe("claude");
      expect(record!.proofFailure).toMatchObject({ failedWhile: "exiting", ownProof: true, escapeEvidence: false });
      expect(record!.clearedBy).toBe("own");
      expect(sample.unsandboxedRuntimes).toEqual([]);
      expect(sampleProblems(sample, rig.markers.values)).toEqual([]);
      expect(sample.clears.some((clear) => clear.record.pid === record!.pid && clear.explanation === "exiting after a proof read while alive (own)")).toBe(true);
    } finally {
      exit.release();
    }
    void asked;
  });

  it("control G2: the real native runtime started outside the sandbox below a script named bwrap is reported when its exit is forced at the first reading", async () => {
    const { rig, wrapper } = await wrapperRig();
    wrapper.setMode("bypass-fork");
    const exit = runtimeExit(1);
    const prompt = "IF-CONTROL-EXIT-BYPASS";
    rig.scripts.push(scriptOf(prompt, [bashStep("echo CONTROL")]));
    const window = windowOf(rig, [], { afterStableReading: exit.seam });
    const asked = rig.ask("reqlift", { queryId: "q-control-exit-bypass", sessionId: "conv-control-exit-bypass", prompt, user_id: "user-1", useSession: true, allowedTools: ["Bash"] }, 90_000).catch(() => undefined);
    try {
      await waitFor(() => exit.state.forced, 60_000, "the sampler to force the runtime's exit");
      const { sample } = window.close();
      expect(exit.state.reached, "precondition not reached: the runtime was not a zombie within its bound").toBe(true);
      const record = sample.records.find((candidate) => candidate.pid === exit.state.pid);
      expect(record, "precondition not reached: the sampler did not record the runtime").toBeDefined();
      // The seam acted on the executable `claude`; a record created on a zombie reading has no readable executable name.
      expect(record!.clearedBy).toBeUndefined();
      expect(sample.unsandboxedRuntimes).toContain(record!.pid);
      const text = sampleProblems(sample, rig.markers.values).join("\n");
      expect(text).toContain("ran without a sandbox ancestor");
      expect(text).toContain(`pid ${record!.pid}`);
    } finally {
      exit.release();
    }
    void asked;
  });

  /**
   * The seam of a launcher-stop control (MVP-8125): on the `atReading`-th stable reading of the native runtime (the executable
   * `claude`) it records the runtime, its direct parent (the inner bwrap, pid 1 of the sandbox) and the gateway's own child that is
   * the real outer bwrap, SIGTERMs only that outer bwrap and holds the sampler tick until the inner bwrap has a new parent, so the
   * proof runs after the reparenting. The gateway stays alive. Everything it records carries its start time; only a recorded process
   * whose start time still matches is ever signalled again.
   */
  function launcherStop(gatewayPid: number, atReading: number) {
    interface Recorded {
      pid: number;
      startTicks: string;
    }
    const state = { pid: 0, readings: 0, forced: false, reached: false, outerIsRealBwrap: false, runtime: undefined as Recorded | undefined, inner: undefined as Recorded | undefined, outer: undefined as Recorded | undefined };
    const statOf = (pid: number): { ppid: number; startTicks: string } | null => {
      try {
        const text = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
        const rest = text.slice(text.lastIndexOf(")") + 2).split(" ");
        return { ppid: Number(rest[1]), startTicks: rest[19] };
      } catch {
        return null;
      }
    };
    const recordedAs = (pid: number): Recorded => ({ pid, startTicks: statOf(pid)?.startTicks ?? "" });
    const sameProcess = (item: Recorded | undefined): boolean => item !== undefined && statOf(item.pid)?.startTicks === item.startTicks;
    const identityOf = (file: string): string | null => {
      try {
        const identity = fs.statSync(file, { bigint: true });
        return `${identity.dev}:${identity.ino}`;
      } catch {
        return null;
      }
    };
    const seam = (pid: number): void => {
      let exe = "";
      try {
        exe = path.basename(fs.readlinkSync(`/proc/${pid}/exe`));
      } catch {
        return;
      }
      if (exe !== "claude" || state.forced || (state.pid !== 0 && state.pid !== pid)) return;
      state.pid = pid;
      state.readings += 1;
      if (state.readings < atReading) return;
      state.forced = true;
      state.runtime = recordedAs(pid);
      state.inner = recordedAs(statOf(pid)?.ppid ?? 0);
      let top = state.inner.pid;
      for (let hop = 0; hop < 8 && (statOf(top)?.ppid ?? 0) !== gatewayPid && (statOf(top)?.ppid ?? 0) > 1; hop++) top = statOf(top)?.ppid ?? 0;
      state.outer = recordedAs(top);
      const innerParent = statOf(state.inner.pid)?.ppid ?? 0;
      state.outerIsRealBwrap = statOf(top)?.ppid === gatewayPid && identityOf(`/proc/${top}/exe`) === identityOf("/usr/bin/bwrap");
      if (!state.outerIsRealBwrap) return;
      process.kill(top, "SIGTERM");
      for (const end = Date.now() + 3000; !(state.reached = (statOf(state.inner.pid)?.ppid ?? 0) !== innerParent) && Date.now() < end; Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 2));
    };
    /** Ends the sandbox's inner bwrap (its namespace teardown ends the runtime); a recorded process that is not the same one any more is left alone. */
    const endInner = (): void => {
      if (sameProcess(state.inner)) process.kill(state.inner!.pid, "SIGKILL");
    };
    const endAll = (): void => {
      for (const item of [state.inner, state.runtime, state.outer]) {
        if (!sameProcess(item)) continue;
        try {
          process.kill(item!.pid, "SIGKILL");
        } catch {
          // Already gone.
        }
      }
    };
    return { state, seam, endInner, endAll };
  }

  it("control G5: the outer bwrap is stopped while the gateway lives (its sandbox keeps the inner bwrap): the native runtime is cleared by the launcher-ended route once its exit is confirmed, and audited, not reported", async () => {
    const { rig, wrapper } = await wrapperRig();
    wrapper.setMode("keep-inner");
    const stop = launcherStop(rig.gateway.child.pid!, 3);
    const prompt = "IF-CONTROL-LAUNCHER-ENDED";
    rig.scripts.push(scriptOf(prompt, [bashStep("echo CONTROL")]));
    const window = windowOf(rig, [], { afterStableReading: stop.seam });
    const asked = rig.ask("reqlift", { queryId: "q-control-launcher-ended", sessionId: "conv-control-launcher-ended", prompt, user_id: "user-1", useSession: true, allowedTools: ["Bash"] }, 90_000).catch(() => undefined);
    let closed: ReturnType<Window["close"]> | undefined;
    try {
      await waitFor(() => stop.state.forced, 60_000, "the sampler to stop the launcher");
      expect(stop.state.outerIsRealBwrap, "precondition not reached: the gateway's own child above the runtime is not the real bwrap").toBe(true);
      expect(stop.state.reached, "precondition not reached: the inner bwrap was not reparented within its bound").toBe(true);
      await waitFor(() => window.peek().records.some((candidate) => candidate.pid === stop.state.runtime?.pid && candidate.proofFailure !== undefined), 10_000, "the failing tick");
      const waiting = window.peek().records.find((candidate) => candidate.pid === stop.state.runtime?.pid)!;
      expect(waiting.proofFailure).toMatchObject({ failedWhile: "alive", ownProof: true, escapeEvidence: false, ownUnreadable: "none", referenceExit: "alive", runtimeExit: "alive", launcherIdentity: "verified", launcherExe: "real-bwrap", reparented: true, pending: "waiting" });
      expect(waiting.pending?.route).toBe("launcher-ended");
      stop.endInner();
      await waitFor(() => endedNow(stop.state.runtime!.pid, stop.state.runtime!.startTicks).ended, 15_000, "the runtime to end after its inner bwrap");
      await waitFor(() => window.peek().records.every((candidate) => candidate.pending?.state !== "waiting"), 10_000, "pending records to settle");
      closed = window.close();
      const { sample } = closed;
      const record = sample.records.find((candidate) => candidate.pid === stop.state.runtime!.pid);
      expect(record, "precondition not reached: the sampler did not record the runtime").toBeDefined();
      expect(record!.exe).toBe("claude");
      expect(record!.clearedBy).toBe("launcher-ended");
      expect(record!.unsandboxed).toBe(false);
      expect(sample.unsandboxedRuntimes).toEqual([]);
      expect(sample.referenceChanged).toBe(0);
      expect(sampleProblems(sample, rig.markers.values)).toEqual([]);
      expect(sample.clears.filter((clear) => clear.record.pid === record!.pid && clear.explanation === "runtime exit confirmed after its own proof read while alive (launcher ended first, gateway alive)")).toHaveLength(1);
    } finally {
      // A failed row must not leave a real runtime under the user's subreaper.
      stop.endAll();
      if (stop.state.runtime) await waitFor(() => endedNow(stop.state.runtime!.pid, stop.state.runtime!.startTicks).ended, 15_000, "the runtime to end").catch(() => undefined);
      closed ??= window.close();
    }
    void asked;
  });

  it("control: an upstream that accepts the credential fails both refusal texts and the missing audit lines after the bounded wait", async () => {
    const rig = await newRig();
    const started = Date.now();
    const observed = await refusalObservation(rig, "accept");
    const { problems } = refusalProblems(rig, observed);
    expect(problems).toEqual(expect.arrayContaining(["the user-credential refusal was not the exact fixed failure", "the gateway-credential refusal was not the exact fixed failure", "the relay's audit lines for the refusals are missing"]));
    // Two calls each waited the bound for a line that never came, so the poll ended and the absence was reported.
    expect(Date.now() - started).toBeGreaterThanOrEqual(AUDIT_WAIT_MS);
  });
});

describe("summary", () => {
  it("every expected row of the suite ran and passed", () => {
    const summary = recorder.finish();
    expect(summary.missing).toEqual([]);
    expect(summary.fail).toBe(0);
  });
});
