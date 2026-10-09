/**
 * T1 for the security matrix harness (MVP-7677 Gate A): the detector, the evidence lines, the route probes and the
 * host-side samplers behave as the acceptance suites rely on. Nothing here starts a gateway; the rows that need one
 * are in `security-regression-process.test.ts`.
 *
 * Every value is synthetic. The assertions on printed text are boolean: no failure message of this file embeds a
 * marker value.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  AC_ROWS,
  MatrixRecorder,
  ROUTE_ALLOWED_TOOLS,
  SURFACE_FLOORS,
  assertNoLeak,
  createMarkers,
  destinationsFromTable,
  detect,
  emit,
  evidenceLine,
  killRun,
  matrixLine,
  offlineAvailable,
  offlinePrefix,
  requireHost,
  runChild,
  sandboxFixtureRecord,
  scrub,
  splitNeedle,
  splitNeedles,
  startProcessSampler,
  waitRunGone,
  type PresenceKey,
  type ProcessSample,
  redactArgv,
  PENDING_BOUND_MS,
  pendingBoundOrigin,
  createReferenceTracker,
  readExitReadingOf,
  runtimeEndingPending,
  runtimeLeaderExited,
  currentRowId,
  deriveRowId,
  describeRecords,
  endedNow,
  exitConfirmed,
  exitKind,
  exitProofClears,
  exitBracket,
  exitFaultAllowed,
  exitReadOutcome,
  exeReaderOver,
  isConfirmedExit,
  isReferenceEnding,
  leaderExitSign,
  procMountHidesProcesses,
  readExitReadingFrom,
  EXIT_PAIRS,
  type ExitKind,
  type ExitReadFault,
  type ExitSource,
  flagAfterProofFailure,
  referenceEndedPending,
  referenceSymptom,
  resolvePending,
  sameNamespace,
  sampleProblems,
  taggedProcessProof,
  type ExitReading,
  type ReferenceIo,
  type ProcessRecord,
  type TickProcess,
  type MatrixRow,
  type Surface,
} from "./helpers/security-matrix.js";
import { launcherEndedPending, launcherEvidenceOf, launcherExeOf, launcherIdentityOf, launcherLeftTree, ownProofHeld, type LauncherEvidence, type LauncherExeRead } from "./helpers/security-matrix.js";
import { descendants } from "./helpers/git-process-gateway.js";
import { ROUTE_IDS, credentialSteps, entrypointRowIds, failureRowIds, registryRowIds, regressionRowIds, parseReport, routeSource, routeSteps, verifyRoute, type RouteContext, type RouteReport } from "./helpers/security-routes.js";

vi.setConfig({ testTimeout: 60_000 });

const markers = createMarkers("t1fixed");
const context: RouteContext = {
  markers,
  host: { workspace: "/h/home/.claude", home: "/h/home", persist: "/h/persist" },
  gatewayPort: 4321,
  canary: "SYNTH-CANARY-t1fixed",
};

/** Surfaces long enough to clear every byte floor. */
function clean(): Surface[] {
  return Object.entries(SURFACE_FLOORS).map(([name, floor]) => ({ name, text: "x".repeat(floor + 10) }));
}

describe("markers", () => {
  it("every marker has its own value, carries the seed and is distinct from the others", () => {
    const values = Object.values(markers.values);
    expect(new Set(values).size).toBe(values.length);
    expect(values.every((value) => value.includes("t1fixed"))).toBe(true);
    expect(Object.keys(markers.values)).toEqual(expect.arrayContaining(["gatewayKeyReqlift", "gatewayKeyDiemcrm", "providerApiKey", "oauthAccess", "oauthRefresh", "sshKey", "cloneToken", "sessionBFile", "legacyTranscript", "stateFile"]));
  });

  it("the same seed gives the same values (a parent can recognize a child's markers), a new seed gives other values", () => {
    expect(createMarkers("t1fixed").values).toEqual(markers.values);
    expect(createMarkers("other").values.providerApiKey).not.toBe(markers.values.providerApiKey);
  });

  it("split needles never contain a whole marker, and their halves rejoin to it", () => {
    for (const value of Object.values(markers.values)) {
      const [first, second] = splitNeedle(value);
      expect(first.length).toBeGreaterThan(0);
      expect(second.length).toBeGreaterThan(0);
      expect(first.includes(value) || second.includes(value)).toBe(false);
      expect(first + second).toBe(value);
    }
    const json = splitNeedles(markers.values);
    expect(Object.values(markers.values).some((value) => json.includes(value))).toBe(false);
  });
});

describe("the detector", () => {
  const surfaceNames = Object.keys(SURFACE_FLOORS);

  it.each(surfaceNames)("a marker planted on the %s surface is flagged on exactly that surface and no other", (planted) => {
    const surfaces = clean().map((surface) => (surface.name === planted ? { ...surface, text: `${surface.text} ${markers.values.providerApiKey} ` } : surface));
    expect(detect(surfaces, markers.values)).toEqual([`${planted}:providerApiKey`]);
  });

  it("flags every marker name that is present and only those", () => {
    const text = `a ${markers.values.gatewayKeyReqlift} b ${markers.values.sshKey} c`;
    expect(detect([{ name: "events", text }], markers.values).sort()).toEqual(["events:gatewayKeyReqlift", "events:sshKey"]);
    expect(detect(clean(), markers.values)).toEqual([]);
  });

  it("assertNoLeak passes clean surfaces, and fails with names and counts only, never a value", () => {
    expect(() => assertNoLeak("RP.regression", clean(), markers.values)).not.toThrow();
    const leaking = clean().map((surface) => (surface.name === "tool-results" ? { ...surface, text: `${surface.text}${markers.values.oauthAccess}` } : surface));
    let message = "";
    try {
      assertNoLeak("RP.regression", leaking, markers.values);
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).toContain("RP.regression");
    expect(message).toContain("hits=1");
    expect(message).toContain("tool-results:oauthAccess");
    expect(Object.values(markers.values).some((value) => message.includes(value))).toBe(false);
  });

  it("assertNoLeak fails a surface below its byte floor: an empty capture cannot pass", () => {
    const thin = clean().map((surface) => (surface.name === "model-requests" ? { ...surface, text: "tiny" } : surface));
    expect(() => assertNoLeak("RP.regression", thin, markers.values)).toThrow(/below the byte floor: \[model-requests\]/);
  });

  it("scrub replaces every value with its name", () => {
    const scrubbed = scrub(`x ${markers.values.sshKey} y ${markers.values.stateFile}`, markers.values);
    expect(scrubbed).toBe("x [sshKey] y [stateFile]");
  });
});

describe("evidence lines", () => {
  const row = (overrides: Partial<MatrixRow> = {}): MatrixRow => ({
    id: "RT.env.fresh",
    mode: "fresh",
    expected: "pass",
    observed: "pass",
    hits: 0,
    durationMs: 1234.4,
    deadlineMs: 120_000,
    surfaces: [{ name: "tool-results", text: "abc" }],
    controls: ["scanner_found_canary"],
    ...overrides,
  });

  it("a security row reads expected=pass observed=pass result=pass, with the id, the deadline and the surface sizes", () => {
    const line = matrixLine(row());
    expect(line).toBe("SECURITY-MATRIX id=RT.env.fresh mode=fresh expected=pass observed=pass result=pass hits=0 duration_ms=1234 deadline_ms=120000 controls=scanner_found_canary surfaces=tool-results:3");
  });

  it("a negative control reads expected=fail observed=fail result=pass; an unexpected observation reads result=fail", () => {
    expect(matrixLine(row({ id: "RP.negative-control", expected: "fail", observed: "fail", hits: 3 }))).toContain("expected=fail observed=fail result=pass");
    expect(matrixLine(row({ expected: "pass", observed: "fail", hits: 1 }))).toContain("expected=pass observed=fail result=fail");
    expect(matrixLine(row({ expected: "fail", observed: "pass" }))).toContain("expected=fail observed=pass result=fail");
  });

  it("no evidence line holds a marker value, even for a row whose surfaces hold one", () => {
    const leaking = row({ hits: 1, observed: "fail", surfaces: [{ name: "events", text: markers.values.providerApiKey }] });
    const lines = [matrixLine(leaking), evidenceLine({ suite: "t1", config: { LOG_LEVEL: "info" }, deadlines: { row: 1 }, offline: false, logLevel: "info" })];
    expect(lines.some((line) => Object.values(markers.values).some((value) => line.includes(value)))).toBe(false);
  });

  it("the evidence line names commit, tree, versions, log level and deadlines", () => {
    const line = evidenceLine({ suite: "t1", config: { LOG_LEVEL: "debug" }, deadlines: { turn: 120000 }, offline: true, logLevel: "debug" });
    expect(line).toMatch(/^SECURITY-EVIDENCE suite=t1 commit=[0-9a-f]{40} tree=[0-9a-f]{40} tracked_changes=\d+ claude_code_version=2\.1\.292 sdk=0\.3\.292 bwrap=\S+ node=v\d+/);
    expect(line).toContain("log_level=debug offline=true config=LOG_LEVEL:debug deadlines=turn:120000");
  });

  it("the summary lists the expected ids that no row covered", () => {
    const recorder = new MatrixRecorder("t1", ["A", "B", "C"], () => undefined);
    recorder.record(row({ id: "A" }));
    recorder.record(row({ id: "B", observed: "fail" }));
    expect(recorder.summary()).toEqual({ expected: 3, observed: 2, pass: 1, fail: 1, hits: 0, missing: ["C"] });
  });

  it("every row id a suite requires has an AC description (the map is the single list of stable ids), and no id is listed twice", () => {
    const all = [...regressionRowIds(), ...entrypointRowIds(), ...failureRowIds(), ...registryRowIds()];
    expect(new Set(all).size).toBe(all.length);
    const base = (id: string): string => (AC_ROWS[id] !== undefined ? id : id.replace(/\.(fresh|resumed|restarted)$/, ""));
    expect(all.filter((id) => AC_ROWS[base(id)] === undefined)).toEqual([]);
  });

  it("every AC row id of the map has a description", () => {
    expect(Object.keys(AC_ROWS).length).toBeGreaterThanOrEqual(30);
    expect(Object.values(AC_ROWS).every((text) => text.length > 10)).toBe(true);
  });
});

describe("host prerequisites", () => {
  it("a present prerequisite passes and a missing one fails with the fixed line (the suite never skips)", () => {
    expect(() => requireHost(["bwrap", "git", "python3"])).not.toThrow();
    // uid 1000 is only needed by the Docker probe; on any other uid the fixed line names it.
    if (process.getuid?.() !== 1000) expect(() => requireHost(["uid1000"])).toThrow("host prerequisite missing: uid1000");
  });
});

describe("route probes", () => {
  it("every route has Python source that holds no marker value and no whole canary, and runs through Bash first", () => {
    for (const route of ROUTE_IDS) {
      const source = routeSource(route, context);
      expect(Object.values(markers.values).some((value) => source.includes(value)), route).toBe(false);
      expect(source.includes(context.canary), route).toBe(false);
      const steps = routeSteps(route, context);
      expect(steps[0].name, route).toBe("Bash");
      expect(JSON.stringify(steps).includes(markers.values.providerApiKey), route).toBe(false);
    }
    expect(ROUTE_IDS).toHaveLength(8);
  });

  it("the python of each route compiles", async () => {
    for (const route of ROUTE_IDS) {
      const source = routeSource(route, context).replace(/^python3 - <<'PY'\n/, "").replace(/\nPY$/, "");
      const child = spawn("python3", ["-c", "import sys; compile(sys.stdin.read(), 'route', 'exec')"], { stdio: ["pipe", "ignore", "pipe"] });
      let stderr = "";
      child.stderr.on("data", (chunk: Buffer) => (stderr += chunk.toString()));
      child.stdin.end(source);
      const code = await new Promise<number | null>((resolve) => child.on("exit", resolve));
      expect(code, `${route}: ${stderr.slice(0, 300)}`).toBe(0);
    }
  });

  it("the scanner finds a planted needle through the split halves and reports names and counts only", async () => {
    // The env probe's own scanner run on the host: plant a marker in the dump directory, run the real prelude against it.
    const source = routeSource("legacy", context).replace(/^python3 - <<'PY'\n/, "").replace(/\nPY$/, "");
    const probe = source.replace("D = '/work/route-legacy'", "D = '/tmp/t1-route-legacy'").replace(/os\.walk\('\/'/, "os.walk('/tmp/t1-nothing'").replace("scan_tree('/home/node/.claude/projects')", "0");
    const child = spawn("python3", ["-c", probe], { stdio: ["ignore", "pipe", "pipe"] });
    let output = "";
    child.stdout.on("data", (chunk: Buffer) => (output += chunk.toString()));
    await new Promise((resolve) => child.on("exit", resolve));
    const report = parseReport(output);
    expect(report).not.toBeNull();
    expect(report!.controls.scanner_found_canary).toBe(true);
    expect(report!.hits).toEqual({});
    expect(Object.values(markers.values).some((value) => output.includes(value))).toBe(false);
  });

  const report = (overrides: Partial<RouteReport> = {}): string =>
    `noise\nSEC-REPORT ${JSON.stringify({ route: "env", rc: { "python-env": 0, env: 0, "sh-env": 0, printenv: 0, "node-env": 0, "perl-env": 0 }, hits: {}, controls: { scanner_found_canary: true, env_nonempty: true }, facts: {}, t0: 1, t1: 2, ...overrides })}\nmore`;

  it("verifyRoute passes a clean report whose controls held", () => {
    const verdict = verifyRoute("env", report(), context);
    expect(verdict.failures).toEqual([]);
    expect(verdict.controls).toEqual(["scanner_found_canary", "env_nonempty"]);
  });

  it.each([
    ["no report at all", "nothing here", /no SEC-REPORT/],
    ["a marker hit", report({ hits: { oauthAccess: 2 } }), /marker hits: oauthAccessx2/],
    ["a sub-command that failed", report({ rc: { "python-env": 0, env: 1, "sh-env": 0, printenv: 0, "node-env": 0, "perl-env": 0 } }), /sub-command env exited 1/],
    ["a sub-command that never ran", report({ rc: { "python-env": 0 } }), /sub-command env exited never ran/],
    ["a scanner whose canary control failed", report({ controls: { scanner_found_canary: false } }), /control did not hold: scanner_found_canary/],
  ])("verifyRoute fails %s", (_label, text, pattern) => {
    expect(verifyRoute("env", text, context).failures.join("; ")).toMatch(pattern);
  });

  it("the routing route requires every attack to be refused, and a replay requires the old tokens to be dead", () => {
    const refused = Object.fromEntries(
      ["relay-token", "proxy-token"].flatMap((who) => [...["/v1/tools", "/v1/mcp-servers", "/v1/auth/status", "/v1/sessions"].map((r) => [`${who} GET ${r}`, 401]), ...["/v1/auth/login", "/v1/query"].map((r) => [`${who} POST ${r}`, 401])]),
    );
    const bodies = Object.fromEntries(["ungranted", "unparsable", "batch", "methodless", "resources"].map((l) => [`body_${l}`, "TOOL_DENIED: not allowed"]));
    const probe = report({ rc: {}, controls: { scanner_found_canary: true, relay_url_found_where_an_agent_can_read: true }, facts: { cases: refused, ...bodies } });
    expect(verifyRoute("routing", probe, context).failures).toEqual([]);
    const open = report({ rc: {}, controls: { scanner_found_canary: true }, facts: { cases: { ...refused, "proxy-token GET /v1/tools": 200 }, ...bodies } });
    expect(verifyRoute("routing", open, context).failures.join(";")).toContain("proxy-token GET /v1/tools answered 200");
    const replay = report({ rc: {}, controls: { earlier_run_saved_its_urls: true, scanner_found_canary: false }, facts: { cases: { "old-relay-url": 404, "old-proxy-token-model-proxy": 401, "old-proxy-token GET /v1/tools": 401 } } });
    expect(verifyRoute("routing", replay, { ...context, phase: "replay" }).failures).toEqual([]);
    const refused0 = report({ rc: {}, controls: { earlier_run_saved_its_urls: true }, facts: { cases: { "old-relay-url": 0, "old-proxy-token-model-proxy": 401 } } });
    expect(verifyRoute("routing", refused0, { ...context, phase: "replay" }).failures.join(";")).toContain("old relay URL answered 0");
    expect(verifyRoute("routing", refused0, { ...context, phase: "replay", afterRestart: true }).failures).toEqual([]);
    const live = report({ rc: {}, controls: { earlier_run_saved_its_urls: true }, facts: { cases: { "old-relay-url": 200, "old-proxy-token-model-proxy": 401 } } });
    expect(verifyRoute("routing", live, { ...context, phase: "replay" }).failures.join(";")).toContain("old relay URL answered 200");
  });

  it("credential steps cover a per-user override, a request http server and a request stdio server; the grant keeps delete_record out", () => {
    expect(credentialSteps().map((step) => step.name)).toEqual(["mcp__jira__get_page", "mcp__reqhttp__get_page", "mcp__reqlocal__echo"]);
    expect(ROUTE_ALLOWED_TOOLS).not.toContain("mcp__feed__delete_record");
    expect(ROUTE_ALLOWED_TOOLS).toContain("mcp__feed__lookup_record");
  });
});

describe("host-side samplers", () => {
  it("the egress parser reports the non-loopback destinations of the given sockets only, and ignores listeners", () => {
    const header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
    const loopback = "   0: 0100007F:1F90 0100007F:C350 01 00000000:00000000 00:00000000 00000000  1000        0 1\n";
    const external = "   1: 0100007F:1F91 0100A8C0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 2\n";
    const foreign = "   2: 0100007F:1F93 0200A8C0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 4\n";
    const listener = "   3: 00000000:1F92 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 3\n";
    expect(destinationsFromTable("tcp", header + loopback + listener, new Set(["1", "3"]))).toEqual([]);
    expect(destinationsFromTable("tcp", header + loopback + external + listener, new Set(["1", "2", "3"]))).toEqual(["192.168.0.1"]);
    // A socket of another process in the same namespace is not this tree's destination.
    expect(destinationsFromTable("tcp", header + external + foreign, new Set(["2"]))).toEqual(["192.168.0.1"]);
    expect(destinationsFromTable("tcp", header + external + foreign, new Set(["4"]))).toEqual(["192.168.0.2"]);
    expect(destinationsFromTable("tcp", header + external + foreign)).toEqual(["192.168.0.1", "192.168.0.2"]);
  });

  // Each run tags its fixtures uniquely: the absence check and the cleanup then see only this run's processes, never an older
  // leftover or another session's fixture, and no kill path ever matches a shared literal tag. Cleanup runs after every test,
  // passed or failed: it ends the launchers, waits for the whole run to be gone, kills by the unique tag what is left, and
  // fails the test when anything had to be killed.
  interface Fixture {
    tag: string;
    children: ChildProcess[];
    record: PresenceKey | null;
  }
  const fixtures: Fixture[] = [];
  const registerFixture = (tag: string): Fixture => {
    const fixture: Fixture = { tag, children: [], record: null };
    fixtures.push(fixture);
    return fixture;
  };
  afterEach(async () => {
    const leaks: string[] = [];
    for (const fixture of fixtures.splice(0)) {
      for (const child of fixture.children) child.kill("SIGKILL");
      const key = fixture.record ?? { tag: fixture.tag, pidNs: "none", outer: { pid: -1, startTicks: -1 }, init: { pid: -1, startTicks: -1 } };
      const presence = await waitRunGone(key, 5000);
      emit(`SECURITY-FIXTURE-CLEANUP row=after-each tagLength=${fixture.tag.length} gone=${presence.gone} elapsedMs=${presence.elapsedMs} survivors=${presence.survivors.length}`);
      if (presence.gone) continue;
      killRun({ tag: fixture.tag, outer: key.outer, init: key.init });
      leaks.push(...presence.survivors);
    }
    expect(leaks, "a sandboxed fixture outlived its test").toEqual([]);
  });

  it("the process sampler flags an agent runtime without a bwrap ancestor, and not one inside bwrap, and times a tag", async () => {
    requireHost(["bwrap"]);
    const idle = "setInterval(() => {}, 1000)";
    const suffix = randomBytes(6).toString("hex");
    const [bareTag, wrappedTag, absentTag] = [`T1-BARE-${suffix}`, `T1-WRAPPED-${suffix}`, `T1-ABSENT-${suffix}`];
    const bareFixture = registerFixture(bareTag);
    const wrappedFixture = registerFixture(wrappedTag);
    const bare = spawn("node", ["-e", idle, "cli.js", bareTag], { stdio: "ignore" });
    bareFixture.children.push(bare);
    const wrapped = spawn("bwrap", ["--die-with-parent", "--ro-bind", "/", "/", "--unshare-user", "--unshare-pid", "--dev", "/dev", "--proc", "/proc", "node", "-e", idle, "cli.js", wrappedTag], { stdio: "ignore" });
    wrappedFixture.children.push(wrapped);
    const sampler = startProcessSampler(() => process.pid, [bareTag, wrappedTag, absentTag]);
    await new Promise((resolve) => setTimeout(resolve, 600));
    const sample = sampler.stop({});
    const record = (wrappedFixture.record = sandboxFixtureRecord(wrappedTag));
    bare.kill("SIGKILL");
    wrapped.kill("SIGKILL");
    expect(record, "precondition not reached: the sandboxed fixture was not recorded while it ran").not.toBeNull();
    expect(sample.unsandboxedRuntimes).toEqual([bare.pid]);
    expect(sample.runtimesSeen).toBeGreaterThanOrEqual(2);
    expect(sample.windows[bareTag]).toBeDefined();
    expect(sample.windows[wrappedTag]).toBeDefined();
    expect(sample.windows[absentTag]).toBeUndefined();
    expect(sample.windows[bareTag]!.last).toBeGreaterThanOrEqual(sample.windows[bareTag]!.first);
    const gone = await waitRunGone(record!, 5000);
    emit(`SECURITY-FIXTURE-CLEANUP row=T1 gone=${gone.gone} elapsedMs=${gone.elapsedMs} survivors=${gone.survivors.length}`);
    expect(gone.survivors, "the sandboxed fixture left a process behind after its launcher ended").toEqual([]);
  });

  it("the absence check fails for a sandboxed fixture that outlives its launcher, and passes once the run is killed by its tag", async () => {
    requireHost(["bwrap"]);
    const tag = `T1-SURVIVOR-${randomBytes(6).toString("hex")}`;
    const fixture = registerFixture(tag);
    // The defect shape: no --die-with-parent, so ending the launcher leaves the sandbox init and its Node child running.
    const launcher = spawn("bwrap", ["--ro-bind", "/", "/", "--unshare-user", "--unshare-pid", "--dev", "/dev", "--proc", "/proc", "node", "-e", "setInterval(() => {}, 1000)", "cli.js", tag], { stdio: "ignore" });
    fixture.children.push(launcher);
    const deadline = Date.now() + 10_000;
    while (!(fixture.record = sandboxFixtureRecord(tag)) && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 25));
    expect(fixture.record, "precondition not reached: the sandboxed fixture was not recorded while it ran").not.toBeNull();
    launcher.kill("SIGKILL");
    const survived = await waitRunGone(fixture.record!, 1500);
    emit(`SECURITY-FIXTURE-CLEANUP row=T1-control gone=${survived.gone} elapsedMs=${survived.elapsedMs} survivors=${survived.survivors.length}`);
    expect(survived.gone).toBe(false);
    expect(survived.survivors.some((line) => line.includes("carries_the_tag"))).toBe(true);
    killRun({ tag, outer: fixture.record!.outer, init: fixture.record!.init });
    expect((await waitRunGone(fixture.record!, 5000)).survivors).toEqual([]);
  });

  it("a process record shows names, booleans and lengths only: no relay token, flag value, MCP config or marker", () => {
    const token = "tok-7950-per-run-relay-token";
    const marker = "SYNTHETIC-7950-MARKER-value";
    const argv = [
      "/usr/local/bin/node",
      `/opt/app/node_modules/sdk/cli.js`,
      "--mcp-config",
      JSON.stringify({ mcpServers: { jira: { type: "http", url: `http://127.0.0.1:41234/mcp/${token}`, headers: { Authorization: `Bearer ${marker}` } } } }),
      `--x=${marker}`,
      `http://127.0.0.1:41234/mcp/${token}`,
      marker,
      "/bin/sh",
    ];
    const shape = redactArgv(argv);
    expect(shape).toMatch(/^node cli\.js --mcp-config <len \d+> <flag len 3>=<len \d+> <len \d+> <len \d+> sh$/);
    for (const forbidden of [token, marker, "127.0.0.1", "jira", "Bearer"]) expect(shape).not.toContain(forbidden);
    // A flag name that is not on the allowlist can itself be a secret (`--<marker>`): it is printed as its length.
    expect(redactArgv(["/usr/bin/node", "cli.js", `--${marker}`, "--verbose"])).toMatch(/^node cli\.js <flag len \d+> --verbose$/);
    const record: ProcessRecord = {
      pid: 1,
      startTicks: "9",
      comms: ["sh"],
      argvShape: shape,
      exe: "sh",
      ancestors: ["bwrap", "gateway"],
      sameNamespaces: { pid: false, user: false, mnt: false },
      firstMs: 10,
      lastMs: 40,
      oldCounted: true,
      oldUnsandboxed: false,
      verdict: "launcher",
      unsandboxed: false,
      inconsistentReads: 0,
      fate: "exited",
    };
    expect(describeRecords([record], { marker })).toContain("pid 1 comm sh exe sh");
    const failed = describeRecords([{ ...record, proofFailure: { failedWhile: "exiting", ownProof: false, launcherProof: true, escapeEvidence: false, ownUnreadable: "mnt", reference: "cached", chain: "broken", referenceEnded: true, referenceExit: "Z1", runtimeExit: "Z1", pending: "waiting" }, clearedBy: "reference-ended", provedReferenceCached: 2 }], { marker });
    expect(failed).toContain("proof-failure [failed-while=exiting own-proof=false launcher-proof=true escape-evidence=false own-unreadable=mnt reference=cached chain=broken reference-ended=true reference-exit=Z1 runtime-exit=Z1 pending=waiting] cleared-by=reference-ended proved-reference-cached=2");
    expect(describeRecords([{ ...record, argvShape: `leak ${marker}` }], { marker })).toBe("[process records withheld: a marker was detected]");
    // A process name that is not on the allowlist (a comm or an ancestor) is printed as `other`, with or without markers.
    const named = describeRecords([{ ...record, comms: [marker.slice(0, 15)], ancestors: [marker.slice(0, 15), "gateway"] }], {});
    expect(named.includes(marker.slice(0, 15))).toBe(false);
    expect(named).toContain("comm other exe sh");
    expect(named).toContain("ancestors [other,gateway]");
  });

  it("the offline mode gives a command a loopback-only network under the caller's own uid", async () => {
    requireHost(["unshare"]);
    expect(offlineAvailable()).toBe(true);
    const { code, output } = await runChild([...offlinePrefix(), "sh", "-c", "id -u; ip -br addr | grep -c 127.0.0.1; ip -br addr | grep -v '^lo ' | wc -l"], process.env, "/tmp", 20_000);
    expect(code).toBe(0);
    const [uid, up, others] = output.trim().split("\n");
    expect(Number(uid)).toBe(process.getuid?.());
    expect(Number(up)).toBeGreaterThanOrEqual(1);
    expect(Number(others)).toBe(0);
  });
});

/**
 * Stand-ins for what the sampler sees below a gateway (MVP-7950). Every stand-in is a real process tree below this
 * test worker; the sampler runs until its own observation proves the stand-in was seen in the state under test, so a
 * slow host delays a row but never makes it pass without having looked.
 */
describe("process sampler classification", () => {
  const IDLE = "setInterval(() => {}, 1000)";
  const BWRAP = ["bwrap", "--die-with-parent", "--ro-bind", "/", "/", "--unshare-user", "--unshare-pid", "--dev", "/dev", "--proc", "/proc"];
  const children: ChildProcess[] = [];
  const dirs: string[] = [];
  afterEach(() => {
    for (const child of children.splice(0)) child.kill("SIGKILL");
    for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
  });

  async function observe(start: () => ChildProcess, until: (sample: ProcessSample, pid: number) => boolean): Promise<{ sample: ProcessSample; pid: number }> {
    const sampler = startProcessSampler(() => process.pid, []);
    const child = start();
    children.push(child);
    const pid = child.pid!;
    const deadline = Date.now() + 30_000;
    while (!until(sampler.peek(), pid) && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 25));
    await new Promise((resolve) => setTimeout(resolve, 150));
    const sample = sampler.stop({});
    child.kill("SIGKILL");
    return { sample, pid };
  }

  const recordFor = (sample: ProcessSample, predicate: (comms: string[]) => boolean) => sample.records.find((record) => predicate(record.comms));
  const sawComm = (comm: string) => (sample: ProcessSample) => sample.records.some((record) => record.comms.includes(comm));

  it("(c) the in-sandbox launch wrapper (sh, cli.js in its argv, below bwrap) is not counted as a runtime", async () => {
    requireHost(["bwrap"]);
    const { sample } = await observe(() => spawn(BWRAP[0], [...BWRAP.slice(1), "/bin/sh", "-c", "sleep 30", "sandbox", "node", "cli.js"], { stdio: "ignore" }), sawComm("sh"));
    const wrapper = recordFor(sample, (comms) => comms[0] === "sh");
    expect(wrapper, "the sampler saw the wrapper").toBeDefined();
    expect(wrapper!.ancestors).toContain("bwrap");
    expect(sample.runtimesSeen).toBe(0);
    expect(sample.unsandboxedRuntimes).toEqual([]);
  });

  it("(d) a launcher (sh, cli.js in its argv) that is outside bwrap for a while and then execs bwrap is not flagged as an unsandboxed runtime", async () => {
    requireHost(["bwrap"]);
    const { sample } = await observe(
      () => spawn("/bin/sh", ["-c", 'sleep 1; exec "$@"', "launcher", ...BWRAP, "/bin/sh", "-c", "sleep 30", "sandbox", "node", "cli.js"], { stdio: "ignore" }),
      (seen) => seen.records.some((record) => record.comms[0] === "sh" && record.comms.includes("bwrap")),
    );
    const launcher = recordFor(sample, (comms) => comms[0] === "sh" && comms.includes("bwrap"));
    expect(launcher, "the sampler saw the launcher before and after the exec").toBeDefined();
    expect(sample.unsandboxedRuntimes).toEqual([]);
    expect(sample.runtimesSeen).toBe(0);
  });

  it("(e) a Node runtime below bwrap that shares the gateway's pid namespace is flagged as unsandboxed", async () => {
    requireHost(["bwrap"]);
    const { sample } = await observe(
      () => spawn("bwrap", ["--die-with-parent", "--ro-bind", "/", "/", "--unshare-user", "--dev", "/dev", "--proc", "/proc", "node", "-e", IDLE, "cli.js"], { stdio: "ignore" }),
      (seen) => seen.runtimesSeen > 0,
    );
    expect(sample.unsandboxedRuntimes.length).toBeGreaterThanOrEqual(1);
  });

  it("(f) an unsandboxed runtime whose command line does not name cli.js but whose process title is claude is flagged", async () => {
    const { sample } = await observe(() => spawn("bash", ["-c", `exec -a claude node -e ${JSON.stringify(IDLE)}`], { stdio: "ignore" }), (_, pid) => {
      try {
        return path.basename(fs.readlinkSync(`/proc/${pid}/exe`)) === "node";
      } catch {
        return false;
      }
    });
    expect(sample.unsandboxedRuntimes.length).toBeGreaterThanOrEqual(1);
    expect(sample.runtimesSeen).toBeGreaterThanOrEqual(1);
  });

  it("(g) a copied Node binary running cli.js outside any sandbox is flagged", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mvp7950-copy-"));
    dirs.push(dir);
    const copy = path.join(dir, "not-node");
    fs.copyFileSync(process.execPath, copy);
    fs.chmodSync(copy, 0o755);
    const { sample, pid } = await observe(() => spawn(copy, ["-e", IDLE, "cli.js"], { stdio: "ignore" }), (seen) => seen.runtimesSeen > 0);
    expect(sample.unsandboxedRuntimes).toEqual([pid]);
  });

  it("(h) a launcher (sh, cli.js in its argv) outside bwrap that then execs node under the same pid is flagged unsandboxed", async () => {
    const { sample, pid } = await observe(
      () => spawn("/bin/sh", ["-c", 'sleep 0.5; exec "$@"', "sandbox", process.execPath, "-e", IDLE, "cli.js"], { stdio: "ignore" }),
      (seen) => seen.records.some((record) => record.comms[0] === "sh" && record.comms.includes("node")),
    );
    expect(sample.unsandboxedRuntimes).toEqual([pid]);
  });

  it("(i) a runtime below a process whose comm is bwrap but which is not the real bwrap is flagged", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mvp7950-fake-"));
    dirs.push(dir);
    const fake = path.join(dir, "bwrap");
    fs.writeFileSync(fake, '#!/bin/sh\n"$@"\n', { mode: 0o755 });
    const { sample } = await observe(() => spawn(fake, [process.execPath, "-e", IDLE, "cli.js"], { stdio: "ignore" }), (seen) => seen.runtimesSeen > 0);
    expect(sample.unsandboxedRuntimes.length).toBeGreaterThanOrEqual(1);
  });
});

/**
 * The launcher exemption of the process sampler (MVP-7992). Every control is a real process tree below this test worker,
 * and every row first asserts that the sampler recorded the candidate in the state under test (a process that ends
 * between two ticks can never decide a row). Rows that need an executable the sampler cannot read use an
 * execute-only copy of the shell: the kernel makes such a process non-dumpable, so `/proc/<pid>/exe` and `ns/*` fail with
 * EACCES for the same user while it lives (needs a non-root euid and `fs.suid_dumpable` 0 or 2; a host without that
 * fails the row, never skips it).
 */
describe("process sampler launcher exemption", () => {
  const IDLE = "setInterval(() => {}, 1000)";
  const SHELL = fs.realpathSync("/bin/sh");
  const BWRAP = ["bwrap", "--die-with-parent", "--ro-bind", "/", "/", "--unshare-user", "--unshare-pid", "--dev", "/dev", "--proc", "/proc"];
  const children: ChildProcess[] = [];
  const dirs: string[] = [];
  const stoppedPids: number[] = [];
  /** Processes a row recorded to be killed at the end, besides the descendants of its children (the reference's whole thread group). */
  const recordedPids: number[] = [];
  /**
   * The runtime, its bwrap processes and the holder of a reference-end control, with their start times. The control kills the
   * reference, so the holder is reparented to the user's init and `--die-with-parent` only ties bwrap to the holder: nothing
   * would end the idle stand-in. `afterEach` ends each recorded tree, but only a process whose start time still matches.
   */
  const reapRoots: { pid: number; startTicks: string }[] = [];
  afterEach(() => {
    // A holder the exit seam stopped is continued first, then every recorded process and every process of the fixture is killed.
    for (const pid of recordedPids.splice(0)) {
      try {
        process.kill(pid, "SIGKILL");
      } catch {
        // Already gone.
      }
    }
    // A holder the exit seam stopped is continued first, then every process of the fixture is killed.
    for (const pid of stoppedPids.splice(0)) {
      try {
        process.kill(pid, "SIGCONT");
      } catch {
        // Already gone.
      }
    }
    for (const root of reapRoots.splice(0)) {
      if (root.startTicks === "" || startOf(root.pid) !== root.startTicks) continue;
      for (const pid of [...descendants(root.pid), root.pid]) {
        try {
          process.kill(pid, "SIGKILL");
        } catch {
          // Already gone.
        }
      }
    }
    for (const child of children.splice(0)) {
      for (const pid of [...descendants(child.pid!), child.pid!]) {
        try {
          process.kill(pid, "SIGKILL");
        } catch {
          // Already gone.
        }
      }
    }
    for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
  });

  const quote = (value: string): string => `'${value.replace(/'/g, `'\\''`)}'`;

  /** Links named `bwrap` to the real shell, to an execute-only copy of it and to this Node, plus a `bwrap` script that runs a fixed command. */
  function standIns(): { dir: string; executeOnly: string; shell: string; node: string; script: (command: string) => string } {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mvp7992-"));
    dirs.push(dir);
    const copy = path.join(dir, "execute-only");
    fs.copyFileSync(SHELL, copy);
    fs.chmodSync(copy, 0o111);
    const link = (sub: string, target: string): string => {
      fs.mkdirSync(path.join(dir, sub));
      const named = path.join(dir, sub, "bwrap");
      fs.symlinkSync(target, named);
      return named;
    };
    return {
      dir,
      executeOnly: link("x", copy),
      shell: link("s", SHELL),
      node: link("n", process.execPath),
      script: (command) => {
        fs.mkdirSync(path.join(dir, "w"));
        const file = path.join(dir, "w", "bwrap");
        fs.writeFileSync(file, `#!/bin/sh\n${command}\n:\n`, { mode: 0o755 });
        return file;
      },
    };
  }

  type Stage = { name: string; until: (sample: ProcessSample) => boolean; settleMs?: number };

  /** Runs the sampler beside `start()`, takes a snapshot when each stage is reached (undefined when it never was), and returns the final sample and the audit lines `stop(markers)` printed. */
  async function stages(
    start: () => ChildProcess,
    steps: Stage[],
    markers: Record<string, string> = {},
    seam: (pid: number) => void = () => {},
    referencePid: () => number = () => process.pid,
  ): Promise<{ snapshots: (ProcessSample | undefined)[]; final: ProcessSample; audit: string[]; summary: string[] }> {
    const sampler = startProcessSampler(referencePid, [], 20, { afterStableReading: seam });
    const child = start();
    children.push(child);
    const snapshots: (ProcessSample | undefined)[] = [];
    for (const step of steps) {
      const deadline = Date.now() + 20_000;
      while (!step.until(sampler.peek()) && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 25));
      if (!step.until(sampler.peek())) break;
      await new Promise((resolve) => setTimeout(resolve, step.settleMs ?? 150));
      snapshots.push(sampler.peek());
    }
    const lines: string[] = [];
    const spy = vi.spyOn(process.stderr, "write").mockImplementation((chunk: string | Uint8Array) => {
      lines.push(String(chunk));
      return true;
    });
    let final: ProcessSample;
    try {
      final = sampler.stop(markers);
    } finally {
      spy.mockRestore();
    }
    const printed = lines.join("").split("\n");
    return { snapshots, final, audit: printed.filter((line) => line.startsWith("SECURITY-PROCESS-AUDIT")), summary: printed.filter((line) => line.startsWith("SECURITY-PROCESS-SUMMARY")) };
  }

  const exeUnreadable = (pid: number): boolean => {
    try {
      fs.readlinkSync(`/proc/${pid}/exe`);
      return false;
    } catch (error) {
      return (error as NodeJS.ErrnoException).code === "EACCES";
    }
  };
  const hostFacts = (): string => `euid ${process.geteuid?.()}, fs.suid_dumpable ${fs.readFileSync("/proc/sys/fs/suid_dumpable", "utf8").trim()}`;
  const unreadable = (record: ProcessRecord): void => expect(record.exe, `the execute-only executable was readable (${hostFacts()}): the technique needs a non-root user and fs.suid_dumpable 0 or 2`).toBe("unreadable");
  const recorded = (sample: ProcessSample | undefined, what: string): ProcessRecord => {
    expect(sample, `precondition not reached: ${what}`).toBeDefined();
    expect(sample!.records.length, `precondition not reached: ${what}`).toBeGreaterThan(0);
    return sample!.records[0];
  };

  it("J: a runtime started through a link named bwrap below a script named bwrap, outside any sandbox, is flagged by the window", async () => {
    const s = standIns();
    const script = s.script(`${quote(s.node)} -e ${quote(IDLE)} cli.js`);
    const { snapshots, final } = await stages(() => spawn(script, [], { stdio: "ignore" }), [{ name: "runtime recorded", until: (seen) => seen.runtimesSeen > 0 }]);
    const record = recorded(snapshots[0], "the renamed runtime was not recorded");
    expect(record.comms).toEqual(["bwrap"]);
    expect(record.ancestors).toEqual(["bwrap", "gateway"]);
    expect(record.verdict).toBe("runtime");
    expect(final.unsandboxedRuntimes).toContain(record.pid);
    expect(sampleProblems(final, {}).join("\n")).toContain(`pid ${record.pid}`);
  });

  it("K: an executable that cannot be read is never excused by the name bwrap alone (first tick)", async () => {
    const s = standIns();
    const script = s.script(`${quote(s.executeOnly)} -c 'sleep 3; :' sh cli.js`);
    const { snapshots, final } = await stages(() => spawn(script, [], { stdio: "ignore" }), [{ name: "candidate recorded", until: (seen) => seen.records.length > 0 }]);
    const record = recorded(snapshots[0], "the unreadable candidate was not recorded");
    unreadable(record);
    expect(record.comms).toEqual(["bwrap"]);
    expect(record.ancestors).toEqual(["bwrap", "gateway"]);
    expect(record.verdict).toBe("unresolved");
    expect(final.unsandboxedRuntimes).toContain(record.pid);
    expect(sampleProblems(final, {}).join("\n")).toContain(`pid ${record.pid}`);
  });

  it("L1: an unreadable candidate that execs a readable runtime is re-checked on the next tick and flagged as a runtime", async () => {
    const s = standIns();
    const script = s.script(`${quote(s.executeOnly)} -c 'sleep 2; exec "$1" -e "$2" "$3"' sh ${quote(s.node)} ${quote(IDLE)} cli.js`);
    let pid = 0;
    const { snapshots, final } = await stages(
      () => spawn(script, [], { stdio: "ignore" }),
      [
        { name: "unreadable phase", until: (seen) => seen.records.length > 0 },
        { name: "readable runtime phase", until: (seen) => seen.records.some((record) => record.exe === "node") },
      ],
    );
    const first = recorded(snapshots[0], "the unreadable phase was not recorded");
    pid = first.pid;
    unreadable(first);
    expect(first.verdict).toBe("unresolved");
    expect(snapshots[1], "precondition not reached: the exec into the readable runtime was not recorded").toBeDefined();
    const later = final.records.find((record) => record.pid === pid)!;
    expect(later.verdict).toBe("runtime");
    expect(final.unsandboxedRuntimes).toContain(pid);
  });

  it("L2: an unreadable candidate that execs a readable launcher is reclassified by that executable and stays counted", async () => {
    const s = standIns();
    const script = s.script(`${quote(s.executeOnly)} -c 'sleep 2; exec "$1" -c "$2" sh "$3"' sh ${quote(s.shell)} 'sleep 3; :' cli.js`);
    const { snapshots, final } = await stages(
      () => spawn(script, [], { stdio: "ignore" }),
      [
        { name: "unreadable phase", until: (seen) => seen.records.length > 0 },
        { name: "readable launcher phase", until: (seen) => seen.records.some((record) => record.exe === "dash") },
      ],
    );
    const first = recorded(snapshots[0], "the unreadable phase was not recorded");
    unreadable(first);
    expect(first.verdict).toBe("unresolved");
    expect(snapshots[1], "precondition not reached: the exec into the readable launcher was not recorded").toBeDefined();
    const later = final.records.find((record) => record.pid === first.pid)!;
    expect(later.verdict).toBe("launcher");
    expect(final.unsandboxedRuntimes, "the process was unreadable while it lived: it stays counted").toContain(first.pid);
  });

  it("M: the real bwrap and a link named bwrap to the real shell are launchers: not counted, also when they end during the window", async () => {
    requireHost(["bwrap"]);
    const real = await stages(
      () => spawn(BWRAP[0], [...BWRAP.slice(1), "/bin/sh", "-c", "sleep 0.5", "sandbox", "node", "cli.js"], { stdio: "ignore" }),
      [
        { name: "launcher recorded", until: (seen) => seen.records.some((record) => record.exe === "bwrap") },
        { name: "launcher ended", until: (seen) => seen.records.some((record) => record.exe === "bwrap" && record.fate === "exited") },
      ],
    );
    const launcher = recorded(real.snapshots[0], "the real launcher was not recorded");
    expect(real.snapshots[1], "precondition not reached: the real launcher did not end during the window").toBeDefined();
    const ended = real.final.records.find((record) => record.pid === launcher.pid)!;
    expect(ended.verdict).toBe("launcher");
    expect(ended.unsandboxed).toBe(false);
    expect(real.final.unsandboxedRuntimes).toEqual([]);
    expect(real.final.runtimesSeen).toBe(0);

    const s = standIns();
    const script = s.script(`${quote(s.shell)} -c 'sleep 2; :' sh cli.js`);
    const renamed = await stages(() => spawn(script, [], { stdio: "ignore" }), [{ name: "candidate recorded", until: (seen) => seen.records.length > 0 }]);
    const record = recorded(renamed.snapshots[0], "the renamed shell was not recorded");
    expect(record.comms).toEqual(["bwrap"]);
    expect(record.exe).toBe("dash");
    expect(record.verdict).toBe("launcher");
    expect(renamed.final.unsandboxedRuntimes).toEqual([]);
  });

  it("N: a launcher that execs an executable that cannot be read loses its launcher verdict and is counted", async () => {
    const s = standIns();
    const script = s.script(`${quote(s.shell)} -c 'sleep 2; exec "$1" -c "sleep 3; :" sh "$2"' sh ${quote(s.executeOnly)} cli.js`);
    let pid = 0;
    const { snapshots, final } = await stages(
      () => spawn(script, [], { stdio: "ignore" }),
      [
        { name: "launcher phase", until: (seen) => seen.records.some((record) => record.verdict === "launcher") },
        {
          name: "unreadable phase",
          until: (seen) => {
            pid = seen.records[0]?.pid ?? 0;
            return pid > 0 && exeUnreadable(pid);
          },
          settleMs: 400,
        },
      ],
    );
    const first = recorded(snapshots[0], "the launcher phase was not recorded");
    expect(first.verdict).toBe("launcher");
    expect(snapshots[1], "precondition not reached: the exec into the unreadable executable was not seen").toBeDefined();
    const during = snapshots[1]!.records.find((record) => record.pid === first.pid)!;
    unreadable(during);
    expect(during.verdict, "the launcher verdict must be withdrawn while the process is alive and unreadable").toBe("unresolved");
    expect(final.unsandboxedRuntimes).toContain(first.pid);
  });

  it("O: the audit lines hold no unsafe process name, flag or marker, and keep the detail of allowlisted processes", async () => {
    for (const withMarkers of [true, false]) {
      const marker = `SY7992${randomBytes(3).toString("hex")}`;
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mvp7992-"));
      dirs.push(dir);
      const named = path.join(dir, marker);
      fs.symlinkSync(SHELL, named);
      const { snapshots, audit, summary } = await stages(
        () => spawn(named, ["-c", `/bin/sh -c 'sleep 3; :' sh cli.js --${marker}; :`, "sh", "cli.js", `--${marker}`], { stdio: "ignore" }),
        [{ name: "both candidates recorded", until: (seen) => seen.records.length >= 2 }],
        withMarkers ? { synthetic: marker } : {},
      );
      expect(snapshots[0], "precondition not reached: the marker-named launcher and its child were not both recorded").toBeDefined();
      expect(audit.length, "precondition not reached: no audit line was printed").toBeGreaterThanOrEqual(2);
      for (const line of audit) expect(line.includes(marker), "an audit line carried the synthetic name").toBe(false);
      expect(audit.some((line) => line.includes("comm sh exe") && line.includes("verdict=launcher")), "the allowlisted process lost its detail").toBe(true);
      expect(summary, "one summary line of counts per window").toHaveLength(1);
      expect(summary[0]).toMatch(/^SECURITY-PROCESS-SUMMARY records=\d+ runtime=\d+ launcher=\d+ other=\d+ descendant=\d+ unresolved=\d+ unresolved_unreadable=\d+ unresolved_torn=\d+ unresolved_unread=\d+ flagged_unreadable=\d+ failed_exiting=\d+ failed_alive=\d+ failed_own_proof=\d+ failed_launcher_proof=\d+ failed_escape_evidence=\d+ exit_cleared_own=\d+ exit_cleared_launcher=\d+ exit_cleared_reference=\d+ exit_cleared_runtime_ending=\d+ exit_cleared_launcher_ended=\d+ failed_launcher_reparented=\d+ pending_expired=\d+ proved_reference_cached=\d+ failed_reference_cached=\d+ failed_reference_missing=\d+ failed_own_unreadable=\d+ failed_chain_broken=\d+ reference_changed=\d+ row=(none|withheld|[A-Za-z0-9().,_-]+-[0-9a-f]{10}) flagged=\d+$/);
    }
  });

  /*  The exit rule (MVP-8090): real processes whose exit is forced between the stable reading and the proof  */

  /** What the exit seam did for the one candidate under test: every flag is read back by the row before it asserts anything else. */
  interface ExitState {
    pid?: number;
    readings: number;
    forced: boolean;
    reached: boolean;
  }
  const newExitState = (): ExitState => ({ readings: 0, forced: false, reached: false });

  /** Sleeps without releasing the event loop: the seam runs inside a sampler tick and must hold it until the exit shape is reached. */
  const sleepSync = (ms: number): void => void Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
  const waitSync = (condition: () => boolean, boundMs = 2000): boolean => {
    for (const end = Date.now() + boundMs; !condition(); sleepSync(2)) if (Date.now() > end) return false;
    return true;
  };
  const statOf = (pid: number): { state: string; ppid: number } | null => {
    try {
      const fields = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
      const rest = fields.slice(fields.lastIndexOf(")") + 2).split(" ");
      return { state: rest[0], ppid: Number(rest[1]) };
    } catch {
      return null;
    }
  };
  const threadsOf = (pid: number): number => {
    try {
      return Number(/^Threads:\s*(\d+)/m.exec(fs.readFileSync(`/proc/${pid}/status`, "utf8"))?.[1] ?? 1);
    } catch {
      return 0;
    }
  };
  const isGone = (pid: number): boolean => statOf(pid) === null;
  const isZombie = (pid: number): boolean => statOf(pid)?.state === "Z" && threadsOf(pid) <= 1;

  /**
   * The seam of one control: on the `atReading`-th stable reading of its candidate it kills the candidate and holds the tick
   * until the exit shape exists (bound 2 s; a missed bound leaves `reached` false and the row fails as a precondition).
   * `zombie` stops the parent first, so the candidate stays a zombie whose namespaces still read (pid and user, not mnt);
   * `reaped` waits until the parent has reaped it; `reaped-with-launcher` also waits until the candidate's parent is gone.
   * Only a pid the test itself spawned below the worker is ever signalled.
   */
  const forceExit =
    (state: ExitState, shape: "zombie" | "reaped" | "reaped-with-launcher", atReading = 1) =>
    (pid: number): void => {
      state.pid ??= pid;
      if (pid !== state.pid || state.forced) return;
      state.readings += 1;
      if (state.readings < atReading) return;
      state.forced = true;
      const parent = statOf(pid)?.ppid ?? 0;
      if (shape === "zombie") {
        process.kill(parent, "SIGSTOP");
        stoppedPids.push(parent);
        // SIGSTOP is delivered asynchronously: a parent that has not stopped yet would reap the runtime at once and leave no zombie.
        waitSync(() => statOf(parent)?.state === "T");
      }
      process.kill(pid, "SIGKILL");
      state.reached = waitSync(() => (shape === "zombie" ? isZombie(pid) : isGone(pid) && (shape === "reaped" || isGone(parent))));
    };

  const standIn = `exec -a claude ${quote(process.execPath)} -e ${quote(IDLE)}`;
  /** A `bwrap`-named bash script (outside any sandbox) that runs `body`. */
  function renamedLauncher(body: string): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mvp8090-"));
    dirs.push(dir);
    fs.mkdirSync(path.join(dir, "w"));
    const file = path.join(dir, "w", "bwrap");
    fs.writeFileSync(file, `#!/bin/bash\n${body}\n:\n`, { mode: 0o755 });
    return file;
  }
  const sandboxed = (args: string[]): ChildProcess => spawn(BWRAP[0], [...BWRAP.slice(1), ...args], { stdio: "ignore" });
  const unshared = `unshare --user --map-root-user --pid --mount --fork /bin/bash -c ${quote(`(${standIn}) & wait`)}`;

  const forcedStages = (state: ExitState): Stage[] => [
    { name: "runtime recorded", until: (seen) => seen.runtimesSeen > 0 },
    { name: "exit forced", until: () => state.forced, settleMs: 100 },
  ];
  const outcomeOf = (state: ExitState, snapshots: (ProcessSample | undefined)[], what: string): ProcessRecord => {
    expect(state.forced && state.reached, `precondition not reached: the exit shape of ${what} was not reached within its bound`).toBe(true);
    return recorded(snapshots[1], `${what} was not recorded`);
  };
  const reported = (final: ProcessSample, record: ProcessRecord): void => {
    expect(final.unsandboxedRuntimes).toContain(record.pid);
    expect(record.clearedBy).toBeUndefined();
    const text = sampleProblems(final, {}).join("\n");
    expect(text).toContain("ran without a sandbox ancestor");
    expect(text).toContain(`pid ${record.pid}`);
  };

  it("E1: a sandboxed runtime that exits after two proven ticks, with its launchers gone (reaped), is cleared by its own proof and audited", async () => {
    requireHost(["bwrap"]);
    const state = newExitState();
    const { snapshots, final, audit } = await stages(() => sandboxed(["/bin/bash", "-c", standIn]), forcedStages(state), {}, forceExit(state, "reaped-with-launcher", 3));
    const record = outcomeOf(state, snapshots, "the sandboxed runtime");
    expect(record.verdict).toBe("runtime");
    expect(record.proofFailure).toMatchObject({ failedWhile: "exiting", ownProof: true, launcherProof: false, escapeEvidence: false });
    expect(record.clearedBy).toBe("own");
    expect(record.unsandboxed).toBe(false);
    expect(final.unsandboxedRuntimes).toEqual([]);
    expect(sampleProblems(final, {})).toEqual([]);
    expect(audit.filter((line) => line.includes("exiting after a proof read while alive (own)"))).toHaveLength(1);
  });

  it("E2: a sandboxed runtime that is a zombie at its first reading is cleared by the live real bwrap above it, which has the full proof itself", async () => {
    requireHost(["bwrap"]);
    const state = newExitState();
    const { snapshots, final, audit, summary } = await stages(() => sandboxed(["/bin/bash", "-c", `(${standIn}) & wait`]), forcedStages(state), {}, forceExit(state, "zombie"));
    const record = outcomeOf(state, snapshots, "the sandboxed runtime");
    expect(record.proofFailure).toMatchObject({ failedWhile: "exiting", ownProof: false, launcherProof: true, escapeEvidence: false });
    expect(record.clearedBy).toBe("launcher");
    expect(record.unsandboxed).toBe(false);
    expect(final.unsandboxedRuntimes).toEqual([]);
    expect(sampleProblems(final, {})).toEqual([]);
    expect(audit.filter((line) => line.includes("exiting after a proof read while alive (launcher)"))).toHaveLength(1);
    expect(summary[0]).toContain("exit_cleared_launcher=1");
  });

  it.each(["zombie", "reaped"] as const)("E3 (%s): a runtime titled claude below a script named bwrap, outside any sandbox, is reported when its exit is forced at the first reading", async (shape) => {
    const launcher = renamedLauncher(`(${standIn})`);
    const state = newExitState();
    const { snapshots, final } = await stages(() => spawn(launcher, [], { stdio: "ignore" }), forcedStages(state), {}, forceExit(state, shape));
    const record = outcomeOf(state, snapshots, "the renamed runtime");
    expect(record.verdict).toBe("runtime");
    // A zombie still reads the gateway's pid and user namespaces (positive evidence of no sandbox); a reaped one reads nothing.
    expect(record.proofFailure).toMatchObject({ failedWhile: "exiting", ownProof: false, launcherProof: false, escapeEvidence: shape === "zombie" });
    reported(final, record);
  });

  it("E4a: a runtime in new pid, user and mount namespaces without the real bwrap, a zombie at its first reading, is reported", async () => {
    const launcher = renamedLauncher(unshared);
    const state = newExitState();
    const { snapshots, final } = await stages(() => spawn(launcher, [], { stdio: "ignore" }), forcedStages(state), {}, forceExit(state, "zombie"));
    const record = outcomeOf(state, snapshots, "the runtime in new namespaces");
    expect(record.sameNamespaces.pid, "precondition not reached: the namespaces did not differ").toBe(false);
    expect(record.sameNamespaces.user, "precondition not reached: the namespaces did not differ").toBe(false);
    expect(record.proofFailure).toMatchObject({ failedWhile: "exiting", ownProof: false, launcherProof: false, escapeEvidence: false });
    reported(final, record);
  });

  it("E4b: the same tree held for two stable ticks before its exit is forced is reported: namespaces that differ never become an own proof", async () => {
    const launcher = renamedLauncher(unshared);
    const state = newExitState();
    const { snapshots, final } = await stages(() => spawn(launcher, [], { stdio: "ignore" }), forcedStages(state), {}, forceExit(state, "zombie", 3));
    const record = outcomeOf(state, snapshots, "the runtime in new namespaces");
    expect(state.readings, "precondition not reached: fewer than three stable readings").toBeGreaterThanOrEqual(3);
    expect(record.firstMissingProof, "the first proof attempt had a real bwrap").toContain("chain-complete real-bwrap=false");
    expect(record.proofFailure?.ownProof).toBe(false);
    reported(final, record);
  });

  // E5 keeps its holder (and so the real bwrap above it) alive after it reaped the runtime: the control is the launcher route, so the launcher must still be there.
  it("E5: a runtime below a real bwrap that has no pid namespace of its own (so no full proof) and is reaped at its first reading is reported", async () => {
    requireHost(["bwrap"]);
    const state = newExitState();
    const withoutPidNamespace = BWRAP.slice(1).filter((argument) => argument !== "--unshare-pid");
    const { snapshots, final } = await stages(() => spawn(BWRAP[0], [...withoutPidNamespace, "/bin/bash", "-c", `(${standIn}) & wait; sleep 5`], { stdio: "ignore" }), forcedStages(state), {}, forceExit(state, "reaped"));
    const record = outcomeOf(state, snapshots, "the runtime below the real bwrap");
    expect(record.proofFailure).toMatchObject({ failedWhile: "exiting", ownProof: false, launcherProof: false, escapeEvidence: false });
    reported(final, record);
  });

  /*  The reference ends (MVP-8090 rev 3): the gateway stand-in is killed while the runtime below it is still alive  */

  interface ChainState extends ExitState {
    runtime?: { pid: number; startTicks: string };
    holder?: number;
  }
  const ppidOf = (pid: number): number => statOf(pid)?.ppid ?? 0;
  /** Records the processes from `runtime` up to `holder` (the bwrap processes between them included) for `afterEach` to end. */
  const recordTree = (runtime: number, holder: number): void => {
    const seen = new Set<number>();
    for (let pid = runtime; pid > 1 && !seen.has(pid); pid = ppidOf(pid)) {
      seen.add(pid);
      reapRoots.push({ pid, startTicks: startOf(pid) ?? "" });
      if (pid === holder) break;
    }
  };
  const startOf = (pid: number): string | null => {
    try {
      const text = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
      return text.slice(text.lastIndexOf(")") + 2).split(" ")[19];
    } catch {
      return null;
    }
  };
  const mntLinkDenied = (pid: number): boolean => {
    try {
      fs.readlinkSync(`/proc/${pid}/ns/mnt`);
      return false;
    } catch (error) {
      return (error as NodeJS.ErrnoException).code === "EACCES";
    }
  };
  const safeKill = (pid: number | undefined, signal: NodeJS.Signals): void => {
    if (pid === undefined) return;
    try {
      process.kill(pid, signal);
    } catch {
      // Already gone.
    }
  };
  /** A reference stand-in that keeps running (so it never ends by itself) and makes itself non-dumpable on SIGUSR1: its namespace links then fail with EACCES while it lives. */
  const NON_DUMPABLE_REFERENCE = "import ctypes, signal, subprocess, sys, time\nlibc = ctypes.CDLL(None)\nsignal.signal(signal.SIGUSR1, lambda *_: libc.prctl(4, 0, 0, 0, 0))\nchild = subprocess.Popen(sys.argv[1:])\nwhile True:\n    time.sleep(0.05)";
  const pythonReference = (argv: string[]): ChildProcess => spawn("python3", ["-c", NON_DUMPABLE_REFERENCE, ...argv], { stdio: "ignore" });
  /** H: the process that holds the real bwrap around the stand-in runtime; R: the bash reference above H. */
  const holderScript = `${BWRAP.map(quote).join(" ")} /bin/bash -c ${quote(standIn)}; :`;
  const referenceScript = `/bin/bash -c ${quote(holderScript)}; :`;

  /**
   * The seam of a reference-end control. On the `atReading`-th stable reading of the runtime it records the runtime, finds the holder
   * `holderHops` parents above it and kills the holder's parent (the reference, or a middle process below a live reference), then
   * holds the tick until that process is a zombie or gone and the holder has a new parent. `before` runs first. The holder or the
   * runtime is then ended from the event loop, `endAfterMs` later, when the row needs the runtime to end within the bound.
   */
  const chainSeam =
    (state: ChainState, options: { atReading: number; holderHops: number; before?: () => boolean; end?: "holder" | "runtime"; endAfterMs?: number }) =>
    (pid: number): void => {
      state.pid ??= pid;
      if (pid !== state.pid || state.forced) return;
      state.readings += 1;
      if (state.readings < options.atReading) return;
      state.forced = true;
      state.runtime = { pid, startTicks: startOf(pid) ?? "" };
      let holder = pid;
      for (let hop = 0; hop < options.holderHops; hop++) holder = ppidOf(holder);
      state.holder = holder;
      recordTree(pid, holder);
      const victim = ppidOf(holder);
      const prepared = options.before?.() ?? true;
      process.kill(victim, "SIGKILL");
      state.reached = prepared && waitSync(() => (isZombie(victim) || isGone(victim)) && ppidOf(holder) !== victim);
      if (options.end) setTimeout(() => safeKill(options.end === "holder" ? holder : pid, "SIGKILL"), options.endAfterMs ?? 100);
    };
  const runtimeEnded = (state: ChainState): boolean => state.runtime !== undefined && endedNow(state.runtime.pid, state.runtime.startTicks).ended;
  const referenceStages = (state: ChainState, last: Stage): Stage[] => [...forcedStages(state), last];
  const flaggedNever = (final: ProcessSample, record: ProcessRecord, what: string): void => {
    reported(final, record);
    expect(record.pending, `${what} was never pending`).toBeUndefined();
    expect(record.proofFailure?.pending, `${what} was never pending`).toBe("none");
  };

  it("R0: a reference that turns non-dumpable while alive (its namespace links fail with EACCES) is read from the cache: the proof holds, nothing is flagged or cleared", async () => {
    requireHost(["bwrap", "python3"]);
    const state: ChainState = newExitState();
    let reference: ChildProcess | undefined;
    const seam = (pid: number): void => {
      state.pid ??= pid;
      if (pid !== state.pid || state.forced) return;
      state.readings += 1;
      if (state.readings < 3) return;
      state.forced = true;
      process.kill(reference!.pid!, "SIGUSR1");
      state.reached = waitSync(() => mntLinkDenied(reference!.pid!));
    };
    const { snapshots, final } = await stages(
      () => (reference = pythonReference([BWRAP[0], ...BWRAP.slice(1), "/bin/bash", "-c", standIn])),
      [...forcedStages(state), { name: "proofs on the cache", until: (seen) => seen.records.some((record) => (record.provedReferenceCached ?? 0) > 0) }],
      {},
      seam,
      () => reference?.pid ?? 0,
    );
    const record = outcomeOf(state, snapshots, "the runtime below the non-dumpable reference");
    expect(record.proofFailure, "the proof failed").toBeUndefined();
    expect(record.unsandboxed).toBe(false);
    expect(record.clearedBy).toBeUndefined();
    expect(record.provedReferenceCached ?? 0).toBeGreaterThan(0);
    expect(final.referenceChanged).toBe(0);
    expect(final.unsandboxedRuntimes).toEqual([]);
    expect(endedNow(reference!.pid!, startOf(reference!.pid!)!).ended, "a live non-dumpable reference is not an ended one").toBe(false);
  });

  it("R1: the reference ends (a zombie, chain broken) after the runtime's own proof: the record waits, the runtime ends within the bound, and it is cleared and audited", async () => {
    requireHost(["bwrap"]);
    const state: ChainState = newExitState();
    let reference: ChildProcess | undefined;
    const { snapshots, final, audit, summary } = await stages(
      () => (reference = spawn("/bin/bash", ["-c", referenceScript], { stdio: "ignore" })),
      referenceStages(state, { name: "cleared", until: (seen) => seen.records.some((record) => record.pending?.state === "cleared") }),
      {},
      chainSeam(state, { atReading: 3, holderHops: 3, end: "holder" }),
      () => reference?.pid ?? 0,
    );
    const record = snapshots.at(-1)?.records[0];
    expect(state.forced && state.reached, "precondition not reached: the reference did not end as a zombie within its bound").toBe(true);
    expect(record, "precondition not reached: the runtime was not recorded").toBeDefined();
    expect(record!.proofFailure).toMatchObject({ failedWhile: "alive", ownProof: true, referenceEnded: true, chain: "broken", reference: "cached", runtimeExit: "alive", pending: "cleared" });
    expect(record!.clearedBy).toBe("reference-ended");
    expect(record!.unsandboxed).toBe(false);
    expect(final.unsandboxedRuntimes).toEqual([]);
    expect(sampleProblems(final, {})).toEqual([]);
    expect(audit.filter((line) => line.includes("reference ended after the runtime's own proof read while alive; runtime exit confirmed"))).toHaveLength(1);
    expect(summary[0]).toContain("exit_cleared_reference=1");
  });

  it("R1-alive: the same record whose runtime outlives the bound is flagged for good (pending expired)", async () => {
    requireHost(["bwrap"]);
    const state: ChainState = newExitState();
    let reference: ChildProcess | undefined;
    const { snapshots, final, summary } = await stages(
      () => (reference = spawn("/bin/bash", ["-c", referenceScript], { stdio: "ignore" })),
      referenceStages(state, { name: "expired", until: (seen) => seen.records.some((record) => record.pending?.state === "expired") }),
      {},
      chainSeam(state, { atReading: 3, holderHops: 3 }),
      () => reference?.pid ?? 0,
    );
    const record = snapshots.at(-1)?.records[0];
    expect(state.forced && state.reached, "precondition not reached: the reference did not end as a zombie within its bound").toBe(true);
    expect(record, "precondition not reached: the runtime was not recorded").toBeDefined();
    expect(record!.proofFailure).toMatchObject({ referenceEnded: true, chain: "broken", runtimeExit: "alive", pending: "expired" });
    expect(endedNow(record!.pid, record!.startTicks).ended, "the runtime outlived the bound by construction").toBe(false);
    reported(final, record!);
    expect(summary[0]).toContain("pending_expired=1");
  });

  it("R2: a runtime below a script named bwrap, in the reference's namespaces, whose reference ends is reported (escape evidence against the cache), and its exit is confirmed before the window closes", async () => {
    const launcher = renamedLauncher(`(${standIn})`);
    const state: ChainState = newExitState();
    let reference: ChildProcess | undefined;
    const { snapshots, final } = await stages(
      () => (reference = spawn("/bin/bash", ["-c", `${launcher}; :`], { stdio: "ignore" })),
      referenceStages(state, { name: "runtime ended", until: () => runtimeEnded(state) }),
      {},
      chainSeam(state, { atReading: 1, holderHops: 1, end: "runtime" }),
      () => reference?.pid ?? 0,
    );
    const record = outcomeOf(state, snapshots, "the renamed runtime");
    expect(record.proofFailure).toMatchObject({ ownProof: false, escapeEvidence: true, referenceEnded: true });
    expect(runtimeEnded(state), "the runtime's exit was not confirmed before the window closed").toBe(true);
    flaggedNever(final, record, "the renamed runtime");
  });

  it("R3: the reference ends on the runtime's first stable reading, before any own proof: reported, never pending", async () => {
    requireHost(["bwrap"]);
    const state: ChainState = newExitState();
    let reference: ChildProcess | undefined;
    const { snapshots, final } = await stages(
      () => (reference = spawn("/bin/bash", ["-c", referenceScript], { stdio: "ignore" })),
      referenceStages(state, { name: "runtime ended", until: () => runtimeEnded(state) }),
      {},
      chainSeam(state, { atReading: 1, holderHops: 3, end: "holder" }),
      () => reference?.pid ?? 0,
    );
    const record = outcomeOf(state, snapshots, "the runtime on its first reading");
    expect(record.proofFailure).toMatchObject({ ownProof: false, referenceEnded: true });
    expect(runtimeEnded(state), "the runtime's exit was not confirmed before the window closed").toBe(true);
    flaggedNever(final, record, "the runtime on its first reading");
  });

  it("R4: a middle process dies below a reference that is still alive (non-dumpable, read from the cache): the chain breaks, the runtime is reported, never pending", async () => {
    requireHost(["bwrap", "python3"]);
    const state: ChainState = newExitState();
    let reference: ChildProcess | undefined;
    const { snapshots, final } = await stages(
      () => (reference = pythonReference(["/bin/bash", "-c", referenceScript])),
      referenceStages(state, { name: "runtime ended", until: () => runtimeEnded(state) }),
      {},
      chainSeam(state, {
        atReading: 3,
        holderHops: 3,
        end: "holder",
        before: () => {
          process.kill(reference!.pid!, "SIGUSR1");
          return waitSync(() => mntLinkDenied(reference!.pid!));
        },
      }),
      () => reference?.pid ?? 0,
    );
    const record = outcomeOf(state, snapshots, "the runtime below the live reference");
    expect(record.proofFailure).toMatchObject({ ownProof: true, chain: "broken", reference: "cached", referenceEnded: false, runtimeExit: "alive" });
    expect(runtimeEnded(state), "the runtime's exit was not confirmed before the window closed").toBe(true);
    flaggedNever(final, record, "the runtime below the live reference");
  });

  /*  The reference ends in two steps (MVP-8090 rev 3.1): its main thread first, its other thread later or never  */

  /** A reference whose main thread ends alone with the raw `exit` syscall on SIGUSR1 (one thread, unlike exit_group) while a background thread keeps it a zombie that still counts threads. */
  const LEADER_ONLY_REFERENCE =
    "import ctypes, platform, signal, subprocess, sys, threading, time\nlibc = ctypes.CDLL(None)\nexit_thread = 60 if platform.machine() == 'x86_64' else 93\nsignal.signal(signal.SIGUSR1, lambda *_: libc.syscall(exit_thread, 0))\nchild = subprocess.Popen(sys.argv[1:])\ndef spin():\n    while True:\n        time.sleep(0.05)\nthreading.Thread(target=spin).start()\nwhile True:\n    time.sleep(0.05)";
  /** P (sh, stopped before the reference ends) -> reference R (python, a background thread) -> M -> H -> real bwrap -> stand-in runtime. */
  const leaderOnlyTree = (): ChildProcess => spawn("/bin/sh", ["-c", `python3 -c ${quote(LEADER_ONLY_REFERENCE)} /bin/bash -c ${quote(referenceScript)}; :`], { stdio: "ignore" });
  const firstChildOf = (parent: ChildProcess): number => {
    try {
      return Number(fs.readFileSync(`/proc/${parent.pid}/task/${parent.pid}/children`, "utf8").trim().split(" ")[0]) || 0;
    } catch {
      return 0;
    }
  };
  const threadsNow = (pid: number): number => threadsOf(pid);

  interface LeaderOnlyState extends ChainState {
    reference?: number;
  }
  /**
   * On the `atReading`-th stable reading: stops P, ends R's main thread (R becomes `Z` with threads still showing), kills M so the
   * chain breaks and holds the tick until both are done; then ends H after 100 ms (the runtime's exit is confirmed inside the bound)
   * and, with `endReferenceAfterMs`, kills R's whole thread group (a group exit: `Z` with one thread behind the stopped P).
   */
  const leaderOnlySeam =
    (state: LeaderOnlyState, parent: ChildProcess, endReferenceAfterMs?: number) =>
    (pid: number): void => {
      state.pid ??= pid;
      if (pid !== state.pid || state.forced) return;
      state.readings += 1;
      if (state.readings < 3) return;
      state.forced = true;
      state.runtime = { pid, startTicks: startOf(pid) ?? "" };
      let holder = pid;
      for (let hop = 0; hop < 3; hop++) holder = ppidOf(holder);
      state.holder = holder;
      recordTree(pid, holder);
      const middle = ppidOf(holder);
      const reference = ppidOf(middle);
      state.reference = reference;
      recordedPids.push(reference);
      process.kill(parent.pid!, "SIGSTOP");
      stoppedPids.push(parent.pid!);
      waitSync(() => statOf(parent.pid!)?.state === "T");
      process.kill(reference, "SIGUSR1");
      const zombieWithThreads = waitSync(() => statOf(reference)?.state === "Z" && threadsNow(reference) >= 2);
      process.kill(middle, "SIGKILL");
      state.reached = zombieWithThreads && waitSync(() => (isZombie(middle) || isGone(middle)) && ppidOf(holder) !== middle);
      setTimeout(() => safeKill(holder, "SIGKILL"), 100);
      if (endReferenceAfterMs !== undefined) setTimeout(() => safeKill(reference, "SIGKILL"), endReferenceAfterMs);
    };

  it("R5: a reference that is a zombie leader whose other thread keeps running past the bound (Zn) is pending at first, then flagged for good (expired on the reference), although the runtime's exit is confirmed", async () => {
    requireHost(["bwrap", "python3"]);
    const state: LeaderOnlyState = newExitState();
    let parent: ChildProcess | undefined;
    const { snapshots, final, summary } = await stages(
      () => (parent = leaderOnlyTree()),
      referenceStages(state, { name: "expired on the reference", until: (seen) => seen.records.some((record) => record.pending?.state === "expired-reference") }),
      {},
      (pid) => leaderOnlySeam(state, parent!)(pid),
      () => (parent ? firstChildOf(parent) : 0),
    );
    const record = snapshots.at(-1)?.records[0];
    expect(state.forced && state.reached, "precondition not reached: the reference did not become a zombie leader with threads, or the chain did not break, within its bound").toBe(true);
    expect(record, "precondition not reached: the runtime was not recorded").toBeDefined();
    expect(record!.proofFailure).toMatchObject({ ownProof: true, chain: "broken", reference: "cached", referenceEnded: false, referenceExit: "Zn", pending: "expired-reference" });
    expect(runtimeEnded(state), "the runtime's exit was not confirmed before the window closed").toBe(true);
    expect(statOf(state.reference!)?.state, "the reference stayed a zombie leader").toBe("Z");
    expect(threadsNow(state.reference!), "the reference still counted threads").toBeGreaterThanOrEqual(2);
    reported(final, record!);
    expect(summary[0]).toContain("pending_expired=1");
  });

  it("R5-ends: the same reference whose last thread ends inside the bound (Zn, then Z1) is cleared, and the failing tick was pending with the reference still Zn", async () => {
    requireHost(["bwrap", "python3"]);
    const state: LeaderOnlyState = newExitState();
    let parent: ChildProcess | undefined;
    const { snapshots, final, audit, summary } = await stages(
      () => (parent = leaderOnlyTree()),
      referenceStages(state, { name: "cleared", until: (seen) => seen.records.some((record) => record.pending?.state === "cleared") }),
      {},
      (pid) => leaderOnlySeam(state, parent!, 600)(pid),
      () => (parent ? firstChildOf(parent) : 0),
    );
    const record = snapshots.at(-1)?.records[0];
    expect(state.forced && state.reached, "precondition not reached: the reference did not become a zombie leader with threads, or the chain did not break, within its bound").toBe(true);
    expect(record, "precondition not reached: the runtime was not recorded").toBeDefined();
    // On the failing tick the reference was still Zn and the record went pending; it can only have been cleared from that state.
    expect(record!.proofFailure).toMatchObject({ ownProof: true, chain: "broken", reference: "cached", referenceExit: "Zn", pending: "cleared" });
    expect(record!.clearedBy).toBe("reference-ended");
    expect(record!.unsandboxed).toBe(false);
    expect(final.unsandboxedRuntimes).toEqual([]);
    expect(sampleProblems(final, {})).toEqual([]);
    expect(audit.filter((line) => line.includes("reference ended after the runtime's own proof read while alive; runtime exit confirmed"))).toHaveLength(1);
    expect(summary[0]).toContain("exit_cleared_reference=1");
  });

  /*  The runtime's leader exits first (MVP-8090 rev 3.2): a multi-threaded runtime is a zombie leader while its other threads finish  */

  /**
   * A runtime stand-in (started with `exec -a claude`) whose main thread ends alone with the raw `exit` syscall on SIGUSR1 (one
   * thread, unlike exit_group) while another thread keeps the process a zombie that still counts threads. `LEAVE=timed`: a 300 ms
   * thread, so the process ends by itself; `LEAVE=stdin`: the thread blocks reading stdin and the process ends when the write end
   * is closed. Handlers run on the main thread only, so the thread is started in the handler and never ended by a signal.
   */
  const LEADER_FIRST_RUNTIME =
    "import ctypes, os, platform, signal, sys, threading, time\nlibc = ctypes.CDLL(None)\nexit_thread = 60 if platform.machine() == 'x86_64' else 93\ndef leave(*_):\n    if os.environ.get('LEAVE') == 'stdin':\n        threading.Thread(target=lambda: sys.stdin.buffer.read(1)).start()\n    else:\n        threading.Thread(target=lambda: time.sleep(0.3)).start()\n    libc.syscall(exit_thread, 0)\nsignal.signal(signal.SIGUSR1, leave)\nwhile True:\n    time.sleep(0.05)";
  const leaderFirst = (leave: "timed" | "stdin"): string => `LEAVE=${leave} exec -a claude python3 -c ${quote(LEADER_FIRST_RUNTIME)}`;
  const sandboxedLeaderFirst = (leave: "timed" | "stdin"): ChildProcess => spawn(BWRAP[0], [...BWRAP.slice(1), "/bin/bash", "-c", leaderFirst(leave)], { stdio: [leave === "stdin" ? "pipe" : "ignore", "ignore", "ignore"] });

  /**
   * The seam of a leader-first control: on the `atReading`-th stable reading it sends SIGUSR1 to the runtime and holds the tick
   * until the runtime is a zombie leader that still counts threads (bound 2 s); the proof then runs on that state.
   */
  const leaderFirstSeam =
    (state: ChainState, atReading: number) =>
    (pid: number): void => {
      state.pid ??= pid;
      if (pid !== state.pid || state.forced) return;
      state.readings += 1;
      if (state.readings < atReading) return;
      state.forced = true;
      state.runtime = { pid, startTicks: startOf(pid) ?? "" };
      // The stand-in installs its handler a moment after it starts: SIGUSR1 before that would kill it instead of ending its leader.
      const handlerInstalled = (): boolean => {
        try {
          return (BigInt("0x" + /^SigCgt:\s*([0-9a-f]+)/m.exec(fs.readFileSync(`/proc/${pid}/status`, "utf8"))![1]) & 0x200n) !== 0n;
        } catch {
          return false;
        }
      };
      if (!waitSync(handlerInstalled)) return;
      process.kill(pid, "SIGUSR1");
      state.reached = waitSync(() => statOf(pid)?.state === "Z" && threadsOf(pid) >= 2);
    };
  const neverPending = (record: ProcessRecord, what: string): void => {
    expect(record.pending, `${what} was never pending`).toBeUndefined();
    expect(record.proofFailure?.pending, `${what} was never pending`).toBe("none");
  };

  it("R6: a sandboxed runtime whose leader exits first (a zombie that still counts threads, mount link unreadable) after its own proof waits, and is cleared and audited once the last thread ends", async () => {
    requireHost(["bwrap", "python3"]);
    const state: ChainState = newExitState();
    const { snapshots, final, audit, summary } = await stages(
      () => sandboxedLeaderFirst("timed"),
      referenceStages(state, { name: "cleared", until: (seen) => seen.records.some((record) => record.pending?.state === "cleared") }),
      {},
      leaderFirstSeam(state, 3),
    );
    const record = snapshots.at(-1)?.records[0];
    expect(state.forced && state.reached, "precondition not reached: the runtime did not become a zombie leader that counts threads within its bound").toBe(true);
    expect(record, "precondition not reached: the runtime was not recorded").toBeDefined();
    expect(record!.proofFailure).toMatchObject({ failedWhile: "alive", ownProof: true, escapeEvidence: false, runtimeExit: "Zn", pending: "cleared" });
    expect(record!.proofFailure!.ownUnreadable).toContain("mnt");
    expect(record!.pending?.route).toBe("runtime-ending");
    expect(record!.clearedBy).toBe("runtime-ending");
    expect(record!.unsandboxed).toBe(false);
    expect(final.unsandboxedRuntimes).toEqual([]);
    expect(sampleProblems(final, {})).toEqual([]);
    expect(audit.filter((line) => line.includes("runtime exit confirmed after its own proof read while alive (leader exited first)"))).toHaveLength(1);
    expect(summary[0]).toContain("exit_cleared_runtime_ending=1");
  });

  it("R6-never: the same runtime whose last thread outlives the bound is flagged for good, although it fully ends before the window closes", async () => {
    requireHost(["bwrap", "python3"]);
    const state: ChainState = newExitState();
    let child: ChildProcess | undefined;
    const { snapshots, final, summary } = await stages(
      () => (child = sandboxedLeaderFirst("stdin")),
      [
        ...forcedStages(state),
        { name: "expired", until: (seen) => seen.records.some((record) => record.pending?.state === "expired") },
        // The write end is held by this test only; closing it lets the thread read EOF and the process end.
        { name: "last thread ended", until: () => (child!.stdin!.end(), runtimeEnded(state)) },
      ],
      {},
      leaderFirstSeam(state, 3),
    );
    const record = snapshots.at(-1)?.records[0];
    expect(state.forced && state.reached, "precondition not reached: the runtime did not become a zombie leader that counts threads within its bound").toBe(true);
    expect(record, "precondition not reached: the runtime was not recorded").toBeDefined();
    expect(record!.proofFailure).toMatchObject({ ownProof: true, runtimeExit: "Zn", pending: "expired" });
    expect(record!.pending?.route).toBe("runtime-ending");
    expect(runtimeEnded(state), "the runtime did not fully end before the window closed").toBe(true);
    reported(final, record!);
    expect(summary[0]).toContain("pending_expired=1");
  });

  it("R7: a leader-first runtime outside any sandbox, below a script named bwrap, is reported at once (no own proof, the gateway's namespaces) and never pending", async () => {
    requireHost(["python3"]);
    const launcher = renamedLauncher(`(${leaderFirst("timed")})`);
    const state: ChainState = newExitState();
    const { snapshots, final } = await stages(
      () => spawn(launcher, [], { stdio: "ignore" }),
      referenceStages(state, { name: "runtime ended", until: () => runtimeEnded(state) }),
      {},
      leaderFirstSeam(state, 1),
    );
    const record = outcomeOf(state, snapshots, "the leader-first runtime outside the sandbox");
    expect(record.proofFailure).toMatchObject({ ownProof: false, escapeEvidence: true, runtimeExit: "Zn" });
    expect(runtimeEnded(state), "the runtime did not fully end before the window closed").toBe(true);
    neverPending(record, "the runtime outside the sandbox");
    reported(final, record);
  });

  it("R8: a sandboxed leader-first runtime on its first stable reading (no own proof yet) is reported and never pending", async () => {
    requireHost(["bwrap", "python3"]);
    const state: ChainState = newExitState();
    const { snapshots, final } = await stages(() => sandboxedLeaderFirst("timed"), referenceStages(state, { name: "runtime ended", until: () => runtimeEnded(state) }), {}, leaderFirstSeam(state, 1));
    const record = outcomeOf(state, snapshots, "the sandboxed leader-first runtime");
    expect(record.proofFailure).toMatchObject({ ownProof: false, escapeEvidence: false, runtimeExit: "Zn" });
    expect(runtimeEnded(state), "the runtime did not fully end before the window closed").toBe(true);
    neverPending(record, "the runtime without an own proof");
    reported(final, record);
  });

  it("R9: a live sandboxed runtime with its own proof is never read as ending by the sampler's condition-2 classifier, has no pending and no clear, and fully ends when killed", async () => {
    requireHost(["bwrap"]);
    const state: ChainState = newExitState();
    let classified: boolean | undefined;
    const { snapshots, final } = await stages(
      () => sandboxed(["/bin/bash", "-c", standIn]),
      [
        { name: "runtime recorded", until: (seen) => seen.runtimesSeen > 0 },
        {
          name: "classified while alive",
          settleMs: 150,
          until: (seen) => {
            const live = seen.records[0];
            state.runtime = { pid: live.pid, startTicks: live.startTicks };
            classified = runtimeLeaderExited(readExitReadingOf(live.pid, live.startTicks));
            return true;
          },
        },
        { name: "killed and ended", until: () => (safeKill(state.runtime!.pid, "SIGKILL"), runtimeEnded(state)) },
      ],
    );
    const record = snapshots[1]?.records[0];
    expect(record, "precondition not reached: the runtime was not recorded while alive").toBeDefined();
    expect(classified, "the exact exported classifier read a live process as a zombie leader").toBe(false);
    expect(record!.pending).toBeUndefined();
    expect(record!.clearedBy).toBeUndefined();
    expect(record!.proofFailure, "the proof of a live sandboxed runtime failed").toBeUndefined();
    expect(record!.unsandboxed).toBe(false);
    expect(runtimeEnded(state), "the runtime did not fully end").toBe(true);
    expect(final.unsandboxedRuntimes).toEqual([]);
  });
});

/**
 * The launcher ends first while the gateway lives (MVP-8125): the gateway stops the outer bwrap, the inner bwrap (pid 1 of the
 * sandbox) is reparented to the user's subreaper and the runtime below it leaves the gateway's process tree, so the tick whose
 * snapshot predates that reparenting proves a runtime through a broken chain. Real processes: a Node reference stand-in
 * (`gatewayPid`) starts a real bwrap WITHOUT `--die-with-parent`, so the inner bwrap and the stand-in runtime survive the end of
 * the outer one, as they do in the gateway's window. The row ids start with `LE` (apart from the `L1`/`L2` rows of the launcher
 * exemption). Every negative row first asserts that the sampler recorded the candidate and then that every predicate other than
 * the row's own one still holds, so a row isolates exactly one predicate, and it ends the runtime within the bound so that an
 * expiry cannot mask a widening (MVP-8090 finding A). A missing host prerequisite fails the row.
 */
describe("process sampler launcher ended (MVP-8125)", () => {
  const KEEP_INNER = ["bwrap", "--ro-bind", "/", "/", "--unshare-user", "--unshare-pid", "--dev", "/dev", "--proc", "/proc"];
  const STAND_IN = "exec -a claude sleep 30";
  const STAND_IN_FORK = `(${STAND_IN}) & wait`;
  const REFERENCE_SOURCE = `
    const { spawn } = require("node:child_process");
    const [mode, argv] = [process.argv[1], JSON.parse(process.argv[2])];
    const controller = new AbortController();
    const m = spawn(argv[0], argv.slice(1), { stdio: [process.argv[3] === "inherit" ? "inherit" : "ignore", "ignore", "ignore"], ...(mode === "abort" ? { signal: controller.signal } : {}) });
    m.on("error", () => {});
    if (mode === "exit") {
      process.on("SIGUSR2", () => process.exit(0));
      // The SDK's exit handler: SIGTERM to the launcher, then the gateway stays alive in its exit sequence.
      process.on("exit", () => { m.kill("SIGTERM"); Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 4000); });
    }
    if (mode === "abort") process.on("SIGUSR2", () => controller.abort());
    if (mode === "kill") process.on("SIGUSR2", () => m.kill("SIGKILL"));
    setInterval(() => {}, 1000);
  `;
  type Trigger = "exit" | "abort" | "kill" | "none";
  interface Tracked {
    pid: number;
    startTicks: string;
  }
  const tracked: Tracked[] = [];
  const references: ChildProcess[] = [];
  const dirs: string[] = [];
  const quote = (value: string): string => `'${value.replace(/'/g, `'\\''`)}'`;

  const sleepSync = (ms: number): void => void Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
  /** The seam runs inside a sampler tick and must hold it until the shape exists: this waits without releasing the event loop. */
  const waitSync = (condition: () => boolean, boundMs = 3000): boolean => {
    for (const end = Date.now() + boundMs; !condition(); sleepSync(2)) if (Date.now() > end) return false;
    return true;
  };
  const stat = (pid: number): { state: string; ppid: number; startTicks: string } | null => {
    try {
      const text = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
      const rest = text.slice(text.lastIndexOf(")") + 2).split(" ");
      return { state: rest[0], ppid: Number(rest[1]), startTicks: rest[19] };
    } catch {
      return null;
    }
  };
  const ppidOf = (pid: number): number => stat(pid)?.ppid ?? 0;
  const signal = (pid: number, name: NodeJS.Signals): void => {
    try {
      process.kill(pid, name);
    } catch {
      // Already gone.
    }
  };
  const exeId = (pid: number): string | null => {
    try {
      const identity = fs.statSync(`/proc/${pid}/exe`, { bigint: true });
      return `${identity.dev}:${identity.ino}`;
    } catch {
      return null;
    }
  };
  const REAL_BWRAP = ((): string => {
    const identity = fs.statSync("/usr/bin/bwrap", { bigint: true });
    return `${identity.dev}:${identity.ino}`;
  })();
  const isRealBwrap = (pid: number): boolean => exeId(pid) === REAL_BWRAP;
  /** Records a process the row depends on with its start time, so that cleanup only ever kills the process it recorded. */
  const track = (pid: number): Tracked => {
    const item = { pid, startTicks: stat(pid)?.startTicks ?? "" };
    tracked.push(item);
    return item;
  };
  const sameProcess = (item: Tracked): boolean => stat(item.pid)?.startTicks === item.startTicks;
  const endTracked = (item: Tracked): void => {
    if (sameProcess(item)) signal(item.pid, "SIGKILL");
  };
  afterEach(() => {
    for (const item of tracked.splice(0)) endTracked(item);
    for (const reference of references.splice(0)) for (const pid of [...descendants(reference.pid!), reference.pid!]) signal(pid, "SIGKILL");
    for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
  });

  /** With `stdinPipe` the test holds the write end of a pipe whose read end the reference passes down to the launcher tree (`reference.stdin.end()` closes it). */
  const startReference = (trigger: Trigger, argv: string[], stdinPipe = false): ChildProcess => {
    const reference = spawn(process.execPath, ["-e", REFERENCE_SOURCE, trigger, JSON.stringify(argv), stdinPipe ? "inherit" : "ignore"], { stdio: [stdinPipe ? "pipe" : "ignore", "ignore", "ignore"] });
    references.push(reference);
    return reference;
  };
  const scratch = (): string => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mvp8125-"));
    dirs.push(dir);
    return dir;
  };

  /** What the seam did for the one candidate under test: the row reads every flag back before it asserts anything else. */
  interface SeamState {
    pid?: number;
    readings: number;
    forced: boolean;
    reached: boolean;
    runtime?: Tracked;
  }
  const newState = (): SeamState => ({ readings: 0, forced: false, reached: false });
  /** On the `atReading`-th stable reading of the one candidate it runs `act`, which returns whether the shape was reached within its bound. */
  const seamOf =
    (state: SeamState, atReading: number, act: (pid: number) => boolean) =>
    (pid: number): void => {
      state.pid ??= pid;
      if (pid !== state.pid || state.forced) return;
      state.readings += 1;
      if (state.readings < atReading) return;
      state.forced = true;
      state.runtime = track(pid);
      state.reached = act(pid);
    };

  const until = async (condition: () => boolean, what: string, boundMs = 20_000): Promise<void> => {
    for (const end = Date.now() + boundMs; !condition() && Date.now() < end; ) await new Promise((resolve) => setTimeout(resolve, 25));
    expect(condition(), `precondition not reached: ${what}`).toBe(true);
  };
  const pause = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));
  const ended = (item: Tracked): boolean => endedNow(item.pid, item.startTicks).ended;
  /** Reaped: a zombie still reads as `running` in a snapshot's `fate`, so a row that asserts `exited` waits for its parent to reap the runtime. */
  const reaped = (item: Tracked): boolean => !sameProcess(item);

  /** Closes the window and returns the final sample with the audit and summary lines `stop(markers)` printed. */
  function closeWindow(sampler: { stop: (markers: Record<string, string>) => ProcessSample }): { final: ProcessSample; audit: string[]; summary: string[] } {
    const lines: string[] = [];
    const spy = vi.spyOn(process.stderr, "write").mockImplementation((chunk: string | Uint8Array) => {
      lines.push(String(chunk));
      return true;
    });
    let final: ProcessSample;
    try {
      final = sampler.stop({});
    } finally {
      spy.mockRestore();
    }
    const printed = lines.join("").split("\n");
    return { final, audit: printed.filter((line) => line.startsWith("SECURITY-PROCESS-AUDIT")), summary: printed.filter((line) => line.startsWith("SECURITY-PROCESS-SUMMARY")) };
  }

  /** The failing tick has run for the runtime under test: the record holds a proof failure. */
  const failureRecorded = (sampler: { peek: () => ProcessSample }): boolean => sampler.peek().records.some((record) => record.proofFailure !== undefined);
  const recordOf = (sample: ProcessSample, runtime: Tracked | undefined): ProcessRecord => {
    const record = sample.records.find((candidate) => candidate.pid === runtime?.pid);
    expect(record, "precondition not reached: the sampler did not record the runtime").toBeDefined();
    return record!;
  };

  /** Every predicate holds; a negative row overrides exactly its own one. */
  const ALL_HOLD = { failedWhile: "alive", ownProof: true, escapeEvidence: false, ownUnreadable: "none", referenceExit: "alive", runtimeExit: "alive", chain: "broken", launcherIdentity: "verified", launcherExe: "real-bwrap", reparented: true } as const;
  /** A negative row: the record was flagged, never pending, and every predicate but the row's own one is as in `ALL_HOLD`. */
  const flaggedWith = (final: ProcessSample, record: ProcessRecord, own: Partial<Record<keyof typeof ALL_HOLD, string | boolean>>): void => {
    // The outcome first, so that a widened rule fails here and not on a field it changed on the way.
    expect(record.pending, "the record was never pending").toBeUndefined();
    expect(record.clearedBy, "the record was never cleared").toBeUndefined();
    expect(final.unsandboxedRuntimes, "the record stays flagged").toContain(record.pid);
    expect(record.proofFailure?.pending, "the record was never pending").toBe("none");
    expect(record.proofFailure).toMatchObject({ ...ALL_HOLD, ...own });
    expect(record.fate, "the runtime ended within the bound").toBe("exited");
    const text = sampleProblems(final, {}).join("\n");
    expect(text).toContain("ran without a sandbox ancestor");
    expect(text).toContain(`pid ${record.pid}`);
  };

  /** Reference -> M (no `--die-with-parent`) -> I (inner bwrap, pid 1 of the sandbox) -> C (stand-in titled claude). */
  const launcherTree = [...KEEP_INNER, "/bin/bash", "-c", STAND_IN];
  /** The seam of the rows that stop the launcher through the reference: on the third reading it triggers the stop and holds the tick until I's parent is no longer M. */
  const stopThroughReference = (state: SeamState, reference: () => ChildProcess | undefined, record: (inner: Tracked) => void) =>
    seamOf(state, 3, (pid) => {
      const inner = track(ppidOf(pid));
      const monitor = track(ppidOf(inner.pid));
      record(inner);
      signal(reference()!.pid!, "SIGUSR2");
      return waitSync(() => ppidOf(inner.pid) !== monitor.pid);
    });

  it.each([
    ["LE1-exit", "SIGTERM from the gateway's exit handler (restart-term path)", "exit"],
    ["LE1-abort", "SIGTERM from the spawn abort signal (cancel path)", "abort"],
    ["LE1-kill", "SIGKILL (deadline stop, dispose timeout)", "kill"],
  ] as const)("%s: the launcher is stopped by %s while the gateway lives; the runtime is pending, counts as flagged, and is cleared when its exit is confirmed", async (_id, _by, trigger) => {
    requireHost(["bwrap", "unshare"]);
    const state = newState();
    let inner: Tracked | undefined;
    let reference: ChildProcess | undefined;
    const sampler = startProcessSampler(() => reference?.pid ?? 0, [], 20, {
      afterStableReading: stopThroughReference(state, () => reference, (found) => (inner = found)),
    });
    reference = startReference(trigger, launcherTree);
    await until(() => state.forced, "the seam did not run");
    expect(state.reached, "precondition not reached: the inner bwrap was not reparented within its bound").toBe(true);
    await until(() => failureRecorded(sampler), "the failing tick did not run");
    const waiting = sampler.peek();
    const record = recordOf(waiting, state.runtime);
    expect(record.proofFailure).toMatchObject({ ...ALL_HOLD, pending: "waiting" });
    expect(record.pending).toMatchObject({ state: "waiting", route: "launcher-ended" });
    expect(describeRecords([record])).toContain("launcher-identity=verified launcher-exe=real-bwrap reparented=true");
    // A waiting record counts as flagged (closes MVP-8090 QA note Q6); only after that is the sandbox ended.
    expect(waiting.unsandboxedRuntimes).toContain(record.pid);
    expect(inner && sameProcess(inner) && isRealBwrap(inner.pid), "precondition not reached: the inner bwrap was not alive with the real executable").toBe(true);
    endTracked(inner!);
    await until(() => ended(state.runtime!), "the runtime did not end after the inner bwrap");
    await until(() => sampler.peek().records.every((candidate) => candidate.pending?.state !== "waiting"), "the pending record did not settle");
    const { final, audit, summary } = closeWindow(sampler);
    const cleared = recordOf(final, state.runtime);
    expect(cleared.pending?.state).toBe("cleared");
    expect(cleared.clearedBy).toBe("launcher-ended");
    expect(cleared.unsandboxed).toBe(false);
    expect(final.unsandboxedRuntimes).toEqual([]);
    expect(sampleProblems(final, {})).toEqual([]);
    expect(audit.filter((line) => line.includes("runtime exit confirmed after its own proof read while alive (launcher ended first, gateway alive)"))).toHaveLength(1);
    expect(summary[0]).toContain("exit_cleared_launcher_ended=1");
    for (const other of ["exit_cleared_own", "exit_cleared_launcher", "exit_cleared_reference", "exit_cleared_runtime_ending"]) expect(summary[0], `only the new route cleared (${other})`).toContain(`${other}=0`);
  });

  it("LE2-alive: a runtime still alive 2.5 s after the break is flagged for good (the pending record expires), although it ends before the window closes", async () => {
    requireHost(["bwrap", "unshare"]);
    const state = newState();
    let inner: Tracked | undefined;
    let reference: ChildProcess | undefined;
    const sampler = startProcessSampler(() => reference?.pid ?? 0, [], 20, {
      afterStableReading: stopThroughReference(state, () => reference, (found) => (inner = found)),
    });
    reference = startReference("kill", launcherTree);
    await until(() => state.forced, "the seam did not run");
    expect(state.reached, "precondition not reached: the inner bwrap was not reparented within its bound").toBe(true);
    await until(() => failureRecorded(sampler), "the failing tick did not run");
    // A fixed wait, never a stage: the bound is 2 s, and the runtime and its inner bwrap stay alive through it.
    await pause(2500);
    expect(ended(state.runtime!), "precondition not reached: the runtime ended before the bound passed").toBe(false);
    const expired = recordOf(sampler.peek(), state.runtime);
    expect(expired.pending?.state, "the record expired at the bound").toBe("expired");
    expect(expired.proofFailure).toMatchObject({ ...ALL_HOLD, pending: "expired" });
    expect(expired.unsandboxed).toBe(true);
    endTracked(inner!);
    await until(() => ended(state.runtime!), "the runtime did not end after the inner bwrap");
    await until(() => reaped(state.runtime!), "the runtime was not reaped");
    const { final, summary } = closeWindow(sampler);
    const record = recordOf(final, state.runtime);
    expect(record.fate).toBe("exited");
    expect(record.pending?.state).toBe("expired");
    expect(record.clearedBy).toBeUndefined();
    expect(final.unsandboxedRuntimes).toContain(record.pid);
    expect(sampleProblems(final, {}).join("\n")).toContain(`pid ${record.pid}`);
    expect(summary[0]).toContain("pending_expired=1");
    expect(summary[0]).toContain("exit_cleared_launcher_ended=0");
  });

  it("LE3-noproof: a runtime whose first stable reading falls on the break (no own proof, the start-failure shape) is flagged and never pending", async () => {
    requireHost(["bwrap", "unshare"]);
    const state = newState();
    let inner: Tracked | undefined;
    let reference: ChildProcess | undefined;
    const sampler = startProcessSampler(() => reference?.pid ?? 0, [], 20, {
      afterStableReading: seamOf(state, 1, (pid) => {
        inner = track(ppidOf(pid));
        const monitor = track(ppidOf(inner.pid));
        signal(monitor.pid, "SIGKILL");
        return waitSync(() => ppidOf(inner!.pid) !== monitor.pid);
      }),
    });
    reference = startReference("none", launcherTree);
    await until(() => state.forced, "the seam did not run");
    expect(state.reached, "precondition not reached: the inner bwrap was not reparented within its bound").toBe(true);
    await until(() => failureRecorded(sampler), "the failing tick did not run");
    endTracked(inner!);
    await until(() => ended(state.runtime!), "the runtime did not end within the bound");
    await until(() => reaped(state.runtime!), "the runtime was not reaped");
    const { final } = closeWindow(sampler);
    flaggedWith(final, recordOf(final, state.runtime), { ownProof: false, launcherIdentity: "none" });
  });

  // LE4: a copy of `unshare` named `bwrap` sits directly above the runtime, in new pid, user and mount namespaces below a real bwrap.
  it("LE4-forged: a forged bwrap (not the real executable) directly above the break is no launcher: the identity stays none and the runtime is flagged", async () => {
    requireHost(["bwrap", "unshare"]);
    const forged = path.join(scratch(), "bwrap");
    fs.copyFileSync("/usr/bin/unshare", forged);
    fs.chmodSync(forged, 0o755);
    const state = newState();
    let reference: ChildProcess | undefined;
    const sampler = startProcessSampler(() => reference?.pid ?? 0, [], 20, {
      afterStableReading: seamOf(state, 3, (pid) => {
        const forgedParent = track(ppidOf(pid));
        const holder = track(ppidOf(forgedParent.pid));
        signal(holder.pid, "SIGKILL");
        return waitSync(() => ppidOf(forgedParent.pid) !== holder.pid);
      }),
    });
    reference = startReference("none", [
      "bwrap", "--unshare-user", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc",
      "/bin/sh", "-c", `${quote(forged)} --user --map-root-user --pid --fork /bin/bash -c ${quote(STAND_IN)} & wait`,
    ]);
    await until(() => state.forced, "the seam did not run");
    expect(state.reached, "precondition not reached: the forged bwrap was not reparented within its bound").toBe(true);
    await until(() => failureRecorded(sampler), "the failing tick did not run");
    signal(state.runtime!.pid, "SIGKILL");
    await until(() => ended(state.runtime!), "the runtime did not end within the bound");
    await until(() => reaped(state.runtime!), "the runtime was not reaped");
    const { final } = closeWindow(sampler);
    flaggedWith(final, recordOf(final, state.runtime), { launcherIdentity: "none", launcherExe: "other" });
  });

  // LE5: nothing is sandboxed; a copy of bash named `bwrap` sits above the runtime in the reference's namespaces (escape evidence).
  it("LE5-combined: an unsandboxed runtime below a forged bwrap whose holder is killed is flagged on its escape evidence, never pending", async () => {
    requireHost(["bwrap", "unshare"]);
    const forged = path.join(scratch(), "bwrap");
    fs.copyFileSync("/bin/bash", forged);
    fs.chmodSync(forged, 0o755);
    const forgedStat = fs.statSync(forged, { bigint: true });
    const state = newState();
    let directParentIsForged = false;
    let reference: ChildProcess | undefined;
    const sampler = startProcessSampler(() => reference?.pid ?? 0, [], 20, {
      afterStableReading: seamOf(state, 1, (pid) => {
        const forgedParent = track(ppidOf(pid));
        const holder = track(ppidOf(forgedParent.pid));
        directParentIsForged = exeId(forgedParent.pid) === `${forgedStat.dev}:${forgedStat.ino}` && !isRealBwrap(forgedParent.pid);
        signal(holder.pid, "SIGKILL");
        return waitSync(() => ppidOf(forgedParent.pid) !== holder.pid);
      }),
    });
    reference = startReference("none", ["/bin/sh", "-c", `${quote(forged)} -c ${quote(STAND_IN_FORK)} & wait`]);
    await until(() => state.forced, "the seam did not run");
    expect(directParentIsForged, "precondition not reached: the runtime's direct parent is not the forged bwrap").toBe(true);
    expect(state.reached, "precondition not reached: the forged bwrap was not reparented within its bound").toBe(true);
    await until(() => failureRecorded(sampler), "the failing tick did not run");
    signal(state.runtime!.pid, "SIGKILL");
    await until(() => ended(state.runtime!), "the runtime did not end within the bound");
    await until(() => reaped(state.runtime!), "the runtime was not reaped");
    const { final } = closeWindow(sampler);
    flaggedWith(final, recordOf(final, state.runtime), { ownProof: false, escapeEvidence: true, launcherIdentity: "none", launcherExe: "other" });
  });

  // LE6: M -> I -> holder X (bash) -> C. The proven ticks record no identity (the direct parent is the holder); once X dies C is I's child.
  it("LE6-identity-none: a real bwrap that became the runtime's parent only after the proven ticks is no recorded launcher: flagged, never pending", async () => {
    requireHost(["bwrap", "unshare"]);
    const state = newState();
    let reference: ChildProcess | undefined;
    let innerIsRealBwrap = false;
    const sampler = startProcessSampler(() => reference?.pid ?? 0, [], 20, {
      afterStableReading: seamOf(state, 3, (pid) => {
        const holder = track(ppidOf(pid));
        const inner = track(ppidOf(holder.pid));
        const monitor = track(ppidOf(inner.pid));
        signal(holder.pid, "SIGKILL");
        if (!waitSync(() => ppidOf(pid) === inner.pid)) return false;
        innerIsRealBwrap = sameProcess(inner) && isRealBwrap(inner.pid);
        signal(monitor.pid, "SIGKILL");
        return waitSync(() => ppidOf(inner.pid) !== monitor.pid);
      }),
    });
    reference = startReference("none", [...KEEP_INNER, "/bin/bash", "-c", STAND_IN_FORK]);
    await until(() => state.forced, "the seam did not run");
    expect(state.reached, "precondition not reached: the runtime did not become the inner bwrap's child, or the inner bwrap was not reparented, within the bounds").toBe(true);
    expect(innerIsRealBwrap, "precondition not reached: the inner bwrap was not alive with the real executable").toBe(true);
    await until(() => failureRecorded(sampler), "the failing tick did not run");
    endTracked(tracked.find((item) => item.pid === ppidOf(state.runtime!.pid))!);
    await until(() => ended(state.runtime!), "the runtime did not end within the bound");
    await until(() => reaped(state.runtime!), "the runtime was not reaped");
    const { final } = closeWindow(sampler);
    flaggedWith(final, recordOf(final, state.runtime), { launcherIdentity: "none", launcherExe: "real-bwrap" });
  });

  // LE7: X (sh) -> M -> I -> C. X dies: M leaves the gateway's line, but I keeps its parent M, which is still a snapshot process.
  it("LE7-not-reparented: a launcher whose parent is still on the gateway's line (a snapshot process) is not reparented: flagged, never pending", async () => {
    requireHost(["bwrap", "unshare"]);
    const state = newState();
    let reference: ChildProcess | undefined;
    const sampler = startProcessSampler(() => reference?.pid ?? 0, [], 20, {
      afterStableReading: seamOf(state, 3, (pid) => {
        const inner = track(ppidOf(pid));
        const monitor = track(ppidOf(inner.pid));
        const holder = track(ppidOf(monitor.pid));
        signal(holder.pid, "SIGKILL");
        return waitSync(() => ppidOf(monitor.pid) !== holder.pid);
      }),
    });
    reference = startReference("none", ["/bin/sh", "-c", `${KEEP_INNER.map(quote).join(" ")} /bin/bash -c ${quote(STAND_IN)} & wait`]);
    await until(() => state.forced, "the seam did not run");
    expect(state.reached, "precondition not reached: the monitor was not reparented within its bound").toBe(true);
    await until(() => failureRecorded(sampler), "the failing tick did not run");
    endTracked(tracked.find((item) => item.pid === ppidOf(state.runtime!.pid))!);
    await until(() => ended(state.runtime!), "the runtime did not end within the bound");
    await until(() => reaped(state.runtime!), "the runtime was not reaped");
    const { final } = closeWindow(sampler);
    flaggedWith(final, recordOf(final, state.runtime), { reparented: false });
  });

  // LE8 (rev 2): fixture LZ is fixture LA with a multi-threaded stand-in. On SIGUSR1 the python3 stand-in (titled claude, under bash) starts one
  // thread that blocks reading stdin and ends its main thread with the raw exit syscall, so it is a zombie leader whose thread still runs (`Zn`).
  // The leader's exit is placed between the proof (all own links readable) and the exit read that follows it by the `afterFailedProof` seam.
  // The leader never ends from a Python signal handler of the thread; the test holds the only write end of the pipe, the stand-in the read end.
  const ZN_RUNTIME =
    "import ctypes, platform, signal, sys, threading, time\nlibc = ctypes.CDLL(None)\nexit_thread = 60 if platform.machine() == 'x86_64' else 93\ndef leave(*_):\n    threading.Thread(target=lambda: sys.stdin.buffer.read(1)).start()\n    libc.syscall(exit_thread, 0)\nsignal.signal(signal.SIGUSR1, leave)\nwhile True:\n    time.sleep(0.05)";
  const znTree = [...KEEP_INNER, "/bin/bash", "-c", `exec -a claude python3 -c ${quote(ZN_RUNTIME)}`];
  const threadsOf = (pid: number): number => {
    try {
      return Number(/^Threads:\s*(\d+)/m.exec(fs.readFileSync(`/proc/${pid}/status`, "utf8"))?.[1] ?? 1);
    } catch {
      return 0;
    }
  };
  /** The stand-in installs its handler a moment after it starts: SIGUSR1 before that would kill it instead of ending its leader. */
  const handlerInstalled = (pid: number): boolean => {
    try {
      return (BigInt("0x" + /^SigCgt:\s*([0-9a-f]+)/m.exec(fs.readFileSync(`/proc/${pid}/status`, "utf8"))![1]) & 0x200n) !== 0n;
    } catch {
      return false;
    }
  };
  /** After the failed proof of the runtime under test: ends its leader (SIGUSR1) and holds the tick until it is `Z` with threads still counted. */
  const leaderEndsAfterProof = (state: SeamState, outcome: { done: boolean; reached: boolean }) => (pid: number): void => {
    if (!state.forced || pid !== state.pid || outcome.done) return;
    outcome.done = true;
    if (!waitSync(() => handlerInstalled(pid))) return;
    signal(pid, "SIGUSR1");
    outcome.reached = waitSync(() => stat(pid)?.state === "Z" && threadsOf(pid) >= 2);
  };

  /** Starts the LZ window: reference, tree and seams; returns once the proof failed on a runtime that is a zombie leader at the exit read. */
  async function zombieLeaderWindow(): Promise<{ state: SeamState; reference: ChildProcess; sampler: ReturnType<typeof startProcessSampler> }> {
    requireHost(["bwrap", "unshare", "python3"]);
    const state = newState();
    const outcome = { done: false, reached: false };
    let reference: ChildProcess | undefined;
    const sampler = startProcessSampler(() => reference?.pid ?? 0, [], 20, {
      afterStableReading: stopThroughReference(state, () => reference, () => undefined),
      afterFailedProof: leaderEndsAfterProof(state, outcome),
    });
    reference = startReference("kill", znTree, true);
    await until(() => state.forced, "the seam did not run");
    expect(state.reached, "precondition not reached: the inner bwrap was not reparented within its bound").toBe(true);
    await until(() => outcome.done, "the failed proof did not reach the leader seam");
    expect(outcome.reached, "precondition not reached: the runtime did not become a zombie leader that counts threads within its bound").toBe(true);
    await until(() => failureRecorded(sampler), "the failing tick did not run");
    return { state, reference, sampler };
  }

  it("LE8-zn: a runtime that is alive at the proof and a zombie leader with a running thread at the exit read is pending (counts as flagged) and is cleared when its last thread ends", async () => {
    const { state, reference, sampler } = await zombieLeaderWindow();
    const waiting = sampler.peek();
    const record = recordOf(waiting, state.runtime);
    expect(record.pending, "the record is pending, not flagged").toBeDefined();
    expect(record.proofFailure).toMatchObject({ ...ALL_HOLD, runtimeExit: "Zn", pending: "waiting" });
    expect(record.pending).toMatchObject({ state: "waiting", route: "launcher-ended" });
    expect(waiting.unsandboxedRuntimes, "a waiting record counts as flagged").toContain(record.pid);
    expect(ended(state.runtime!), "a runtime in Zn is not a confirmed exit").toBe(false);
    reference.stdin!.end();
    await until(() => ended(state.runtime!), "the runtime did not fully end after its last thread");
    await until(() => sampler.peek().records.every((candidate) => candidate.pending?.state !== "waiting"), "the pending record did not settle");
    const { final, audit, summary } = closeWindow(sampler);
    const cleared = recordOf(final, state.runtime);
    expect(cleared.pending?.state).toBe("cleared");
    expect(cleared.clearedBy).toBe("launcher-ended");
    expect(cleared.unsandboxed).toBe(false);
    expect(final.unsandboxedRuntimes).toEqual([]);
    expect(sampleProblems(final, {})).toEqual([]);
    expect(audit.filter((line) => line.includes("runtime exit confirmed after its own proof read while alive (launcher ended first, gateway alive)"))).toHaveLength(1);
    expect(summary[0]).toContain("exit_cleared_launcher_ended=1");
    for (const other of ["exit_cleared_own", "exit_cleared_launcher", "exit_cleared_reference", "exit_cleared_runtime_ending"]) expect(summary[0], `only the new route cleared (${other})`).toContain(`${other}=0`);
  });

  it("LE8-zn-never: the same runtime whose last thread outlives the bound is flagged for good, although it fully ends before the window closes", async () => {
    const { state, reference, sampler } = await zombieLeaderWindow();
    // A fixed wait, never a stage: the bound is 2 s and the write end of the pipe stays open through it.
    await pause(2500);
    expect(ended(state.runtime!), "precondition not reached: the runtime ended before the bound passed").toBe(false);
    const expired = recordOf(sampler.peek(), state.runtime);
    expect(expired.pending?.state, "the record expired at the bound").toBe("expired");
    expect(expired.proofFailure).toMatchObject({ ...ALL_HOLD, runtimeExit: "Zn", pending: "expired" });
    expect(expired.unsandboxed).toBe(true);
    reference.stdin!.end();
    await until(() => ended(state.runtime!), "the runtime did not fully end after its last thread");
    await until(() => reaped(state.runtime!), "the runtime was not reaped");
    const { final, summary } = closeWindow(sampler);
    const record = recordOf(final, state.runtime);
    expect(record.fate).toBe("exited");
    expect(record.pending?.state).toBe("expired");
    expect(record.clearedBy).toBeUndefined();
    expect(final.unsandboxedRuntimes).toContain(record.pid);
    expect(sampleProblems(final, {}).join("\n")).toContain(`pid ${record.pid}`);
    expect(summary[0]).toContain("pending_expired=1");
    expect(summary[0]).toContain("exit_cleared_launcher_ended=0");
  });
});

/**
 * The decision table of the launcher-ended route: the same exported functions the sampler runs, with expected values written out
 * here. Stated exceptions to the real-process rule (MVP-7992), each with its reason in `docs/architecture.md`: pid reuse (an
 * unprivileged test cannot force it), escape together with an own proof (no real process can have both), the inner bwrap in its own
 * exit (microseconds to milliseconds, cannot be held), EACCES on the launcher (a real bwrap never execs and EACCES would need a
 * setuid bwrap), an unreadable own link while alive (measured unreachable in MVP-8090), and the reference ending (rows R1 to R5).
 */
describe("process sampler launcher ended: decision table (MVP-8125)", () => {
  const holds = (partial: Partial<Parameters<typeof launcherEndedPending>[0]> = {}): Parameters<typeof launcherEndedPending>[0] => ({
    ownProof: true,
    identity: "verified",
    exe: "real-bwrap",
    reparented: true,
    referenceExit: "alive",
    cacheExists: true,
    runtimeExit: "alive",
    ownUnreadable: false,
    escapeEvidence: false,
    ...partial,
  });

  it.each([
    ["T-le: every condition holds (the inner bwrap alive with its executable)", holds(), true],
    ["T-le: every condition holds (the inner bwrap in its own exit: ENOENT with an empty command line)", holds({ exe: "gone" }), true],
    ["T-le: ownProof=false with the identity verified", holds({ ownProof: false }), false],
    ["T-le: launcher identity changed (the pid was reused)", holds({ identity: "changed" }), false],
    ["T-le: no recorded launcher identity", holds({ identity: "none" }), false],
    ["T-le: the launcher's executable is another one", holds({ exe: "other" }), false],
    ["T-le: EACCES on the launcher is no identity", holds({ exe: "denied" }), false],
    ["T-le: ESRCH or any other error on the launcher", holds({ exe: "none" }), false],
    ["T-le: not reparented (the launcher's parent is on the gateway's line)", holds({ reparented: false }), false],
    ["T-le: no cache for the reference", holds({ cacheExists: false }), false],
    ["T-le: an own link unreadable while alive", holds({ ownUnreadable: true }), false],
    ["T-le: escape evidence on pid, user or mnt", holds({ escapeEvidence: true }), false],
  ])("%s", (_name, given, expected) => {
    expect(launcherEndedPending(given)).toBe(expected);
  });

  it.each(["Zn", "Z1", "X", "vanished", "start-changed", "empty-gone", "empty-n", "unknown"] as const)("T-le: reference %s / ended is no route (the reference-ended route takes it)", (kind) => {
    expect(launcherEndedPending(holds({ referenceExit: kind }))).toBe(false);
  });

  it.each(["Z1", "X", "vanished", "start-changed", "empty-gone", "unknown"] as const)("T-le: runtime %s at the exit read is no launcher-ended entry (a confirmed exit is cleared by the own route, an unknown one is flagged)", (kind) => {
    expect(launcherEndedPending(holds({ runtimeExit: kind }))).toBe(false);
  });

  it("T-le: a runtime that is a zombie leader whose threads still run (Zn) at the exit read is an entry, when every link read at the proof", () => {
    expect(launcherEndedPending(holds({ runtimeExit: "Zn" }))).toBe(true);
    expect(launcherEndedPending(holds({ runtimeExit: "empty-n" })), "empty-n is handled exactly like Zn").toBe(true);
    expect(launcherEndedPending(holds({ runtimeExit: "empty-n", ownUnreadable: true }))).toBe(false);
    expect(launcherEndedPending(holds({ runtimeExit: "Zn", ownUnreadable: true })), "an unreadable own link at the proof is the runtime-ending route").toBe(false);
  });

  it("T-le: Zn at settle is not a confirmed exit: a Zn runtime waits inside the bound and expires at it", () => {
    const leaderOnly: ExitReading = { vanished: false, startChanged: false, state: "Z", threads: 3, cmdline: "", exe: "gone" };
    expect(exitConfirmed({ ...leaderOnly, state: "S" }), "an empty leader with other threads is not ending either").toBe(false);
    expect(exitConfirmed(leaderOnly)).toBe(false);
    expect(resolvePending({ elapsedMs: 100, exitConfirmed: exitConfirmed(leaderOnly), referenceEnded: true, final: false })).toBe("waiting");
    expect(resolvePending({ elapsedMs: PENDING_BOUND_MS + 1, exitConfirmed: exitConfirmed(leaderOnly), referenceEnded: true, final: false })).toBe("expired");
  });

  it.each([
    ["in the snapshot with the same start time, its parent off the snapshot and not the gateway", { pid: 7, startTicks: "9", ppid: 2606 }, true],
    ["the same pid with another start time (a reused pid) is not in the snapshot", { pid: 7, startTicks: "10", ppid: 2606 }, false],
    ["its parent is the gateway itself (ppid equals root)", { pid: 7, startTicks: "9", ppid: 100 }, false],
    ["its parent is a snapshot process (still on the gateway's line)", { pid: 7, startTicks: "9", ppid: 8 }, false],
    ["not in the snapshot", { pid: 9, startTicks: "9", ppid: 2606 }, false],
    ["unreadable", null, false],
  ] as const)("T-le: launcher left the tree: %s", (_name, parent, expected) => {
    const snapshot = new Map([[7, { startTicks: "9" }], [8, { startTicks: "5" }]]);
    expect(launcherLeftTree(snapshot, 100, parent)).toBe(expected);
  });

  /** Real-shaped inputs of the one builder of the route's input (the sampler passes exactly these). */
  const wiring = (partial: Partial<Parameters<typeof launcherEvidenceOf>[0]> = {}): Parameters<typeof launcherEvidenceOf>[0] => ({
    ownProof: true,
    recorded: { pid: 7, startTicks: "9" },
    parent: { pid: 7, startTicks: "9", ppid: 2606, exe: { error: null, realBwrap: true, cmdline: "bwrap" } },
    namespaces: { pid: false, user: false, mnt: false },
    ownUnreadable: false,
    referenceExit: "alive",
    cacheExists: true,
    runtimeExit: "alive",
    snapshot: new Map([[7, { startTicks: "9" }], [8, { startTicks: "5" }]]),
    root: 100,
    ...partial,
  });
  const ALL_TRUE: LauncherEvidence = { ownProof: true, identity: "verified", exe: "real-bwrap", reparented: true, referenceExit: "alive", cacheExists: true, runtimeExit: "alive", ownUnreadable: false, escapeEvidence: false };

  it("T-le: wiring: real-shaped inputs build the exact evidence the route receives, and the route holds", () => {
    const evidence = launcherEvidenceOf(wiring());
    expect(evidence).toEqual(ALL_TRUE);
    expect(launcherEndedPending(evidence)).toBe(true);
  });

  it.each(["pid", "user", "mnt"] as const)("T-le: wiring: a proof that read the %s namespace equal to the gateway's is escape evidence and no route", (kind) => {
    const evidence = launcherEvidenceOf(wiring({ namespaces: { pid: false, user: false, mnt: false, [kind]: true } }));
    expect(evidence.escapeEvidence).toBe(true);
    expect(launcherEndedPending(evidence)).toBe(false);
  });

  it.each(["Zn", "Z1", "vanished"] as const)("T-le: wiring: a gateway re-read as %s is carried and is no route", (kind) => {
    const evidence = launcherEvidenceOf(wiring({ referenceExit: kind }));
    expect(evidence.referenceExit).toBe(kind);
    expect(launcherEndedPending(evidence)).toBe(false);
  });

  it("T-le: wiring: a gateway that could not be re-read counts as vanished and is no route", () => {
    const evidence = launcherEvidenceOf(wiring({ referenceExit: null }));
    expect(evidence.referenceExit).toBe("vanished");
    expect(launcherEndedPending(evidence)).toBe(false);
  });

  it("T-le: wiring: a tracker without a cache for the gateway is carried and is no route", () => {
    const evidence = launcherEvidenceOf(wiring({ cacheExists: false }));
    expect(evidence.cacheExists).toBe(false);
    expect(launcherEndedPending(evidence)).toBe(false);
  });

  it("T-le: wiring: the exit read's state is carried (Zn and empty-n are an entry, Z1 and unknown are not)", () => {
    expect(launcherEvidenceOf(wiring({ runtimeExit: "Zn" })).runtimeExit).toBe("Zn");
    expect(launcherEndedPending(launcherEvidenceOf(wiring({ runtimeExit: "Zn" })))).toBe(true);
    expect(launcherEndedPending(launcherEvidenceOf(wiring({ runtimeExit: "empty-n" })))).toBe(true);
    expect(launcherEndedPending(launcherEvidenceOf(wiring({ runtimeExit: "Z1" })))).toBe(false);
    expect(launcherEndedPending(launcherEvidenceOf(wiring({ runtimeExit: "unknown" })))).toBe(false);
  });

  it("T-le: wiring: an unreadable own link, a missing own proof, a parent that cannot be read and a parent that moved on are carried and are no route", () => {
    expect(launcherEndedPending(launcherEvidenceOf(wiring({ ownUnreadable: true })))).toBe(false);
    expect(launcherEndedPending(launcherEvidenceOf(wiring({ ownProof: false })))).toBe(false);
    expect(launcherEvidenceOf(wiring({ parent: null }))).toMatchObject({ identity: "none", exe: "none", reparented: false });
    expect(launcherEvidenceOf(wiring({ parent: { pid: 7, startTicks: "10", ppid: 2606, exe: { error: null, realBwrap: true, cmdline: "bwrap" } } }))).toMatchObject({ identity: "changed", reparented: false });
    expect(launcherEvidenceOf(wiring({ parent: { pid: 7, startTicks: "9", ppid: 8, exe: { error: null, realBwrap: true, cmdline: "bwrap" } } })).reparented).toBe(false);
  });

  // The reference and runtime routes already share ticks (the sampler resolves them by precedence); the launcher route shares none with either.
  it("T-le: the launcher-ended route never applies to a tick where the reference-ended or the runtime-ending route applies", () => {
    const kinds = ["alive", "Zn", "Z1", "X", "vanished", "start-changed", "empty-gone", "empty-n", "unknown"] as const;
    for (const referenceExit of kinds) for (const runtimeExit of kinds) for (const ownUnreadable of [false, true]) {
      const reference = referenceEndedPending({ ownProof: true, launcherProof: false, referenceEnding: isReferenceEnding(referenceExit), symptom: true, escapeEvidence: false, cacheExists: true });
      const runtime = runtimeEndingPending({ ownProof: true, zombieLeader: runtimeExit === "Zn" || runtimeExit === "empty-n", ownUnreadable, escapeEvidence: false });
      const launcher = launcherEndedPending(holds({ referenceExit, runtimeExit, ownUnreadable }));
      expect(launcher && (reference || runtime), `reference=${referenceExit} runtime=${runtimeExit} own-unreadable=${ownUnreadable}`).toBe(false);
    }
  });

  it.each([
    ["own proof, same pid and start time", 100, "55", true],
    ["own proof, other start time (a reused pid)", 100, "56", false],
    ["own proof, other pid", 101, "55", false],
  ])("T-le: %s", (_name, pid, startTicks, expected) => {
    expect(ownProofHeld(new Set(["100:55"]), pid, startTicks)).toBe(expected);
  });

  it.each([
    ["verified: the same pid and start time", { pid: 7, startTicks: "9" }, { pid: 7, startTicks: "9" }, "verified"],
    ["launcher identity changed: the same pid, another start time", { pid: 7, startTicks: "9" }, { pid: 7, startTicks: "10" }, "changed"],
    ["another pid", { pid: 7, startTicks: "9" }, { pid: 8, startTicks: "9" }, "none"],
    ["nothing recorded", undefined, { pid: 7, startTicks: "9" }, "none"],
    ["the recorded parent was not the real bwrap", "none", { pid: 7, startTicks: "9" }, "none"],
    ["the parent cannot be read now", { pid: 7, startTicks: "9" }, null, "none"],
  ] as const)("T-le: %s", (_name, recorded, current, expected) => {
    expect(launcherIdentityOf(recorded, current)).toBe(expected);
  });

  const exeRead = (partial: Partial<LauncherExeRead>): LauncherExeRead => ({ error: null, realBwrap: true, cmdline: "bwrap --unshare-user", ...partial });
  it.each([
    ["the real bwrap executable", exeRead({}), "real-bwrap"],
    ["another executable", exeRead({ realBwrap: false }), "other"],
    ["ENOENT with an empty command line (the inner bwrap in its own exit)", exeRead({ error: "ENOENT", realBwrap: false, cmdline: "" }), "gone"],
    ["ENOENT with a command line", exeRead({ error: "ENOENT", realBwrap: false }), "none"],
    ["EACCES", exeRead({ error: "EACCES", realBwrap: false, cmdline: "" }), "denied"],
    ["ESRCH", exeRead({ error: "ESRCH", realBwrap: false, cmdline: "" }), "none"],
    ["any other error", exeRead({ error: "EIO", realBwrap: false, cmdline: "" }), "none"],
  ] as const)("T-le: launcher executable: %s", (_name, given, expected) => {
    expect(launcherExeOf(given)).toBe(expected);
  });

  it("T-le: the record shape prints names, booleans and the route only, never the launcher's pid or start time", () => {
    const record: ProcessRecord = {
      pid: 4242,
      startTicks: "1111",
      comms: ["claude"],
      argvShape: "claude",
      exe: "other",
      ancestors: ["bwrap", "other"],
      sameNamespaces: { pid: false, user: false, mnt: false },
      firstMs: 0,
      lastMs: 10,
      oldCounted: false,
      oldUnsandboxed: false,
      verdict: "runtime",
      unsandboxed: false,
      inconsistentReads: 0,
      proofFailure: { failedWhile: "alive", ownProof: true, launcherProof: false, escapeEvidence: false, ownUnreadable: "none", reference: "live", chain: "broken", referenceEnded: false, referenceExit: "alive", runtimeExit: "alive", pending: "cleared", launcherIdentity: "verified", launcherExe: "real-bwrap", reparented: true },
      pending: { state: "cleared", sinceMs: 5, route: "launcher-ended" },
      clearedBy: "launcher-ended",
      launcherIdentity: { pid: 424242, startTicks: "987654321" },
      fate: "exited",
    };
    const text = describeRecords([record]);
    expect(text).toContain("launcher-identity=verified launcher-exe=real-bwrap reparented=true");
    expect(text).toContain("pending-route=launcher-ended");
    expect(text).toContain("cleared-by=launcher-ended");
    expect(text.includes("424242") || text.includes("987654321")).toBe(false);
  });
});

/**
 * The decision table of the exit rule: the same functions the sampler runs. Expected values are written out here and do not
 * come from the production table. Rows that no real process can produce (a runtime that loses its proof while alive) live here
 * and nowhere else (MVP-8090: a stated exception to the real-process control rule of MVP-7992).
 */
describe("process sampler exit rule: decision table", () => {
  const evidence = (exitConfirmed: boolean, escapeEvidence: boolean, ownProof: boolean, launcherProof: boolean) => ({ exitConfirmed, escapeEvidence, ownProof, launcherProof });

  it.each([
    ["own full proof at an earlier tick", evidence(true, false, true, false), "own"],
    ["live real-bwrap ancestor with full proof in the same tick", evidence(true, false, false, true), "launcher"],
    ["chain complete, real bwrap, pid and user differ, mnt unreadable, no other proof", evidence(true, false, false, false), null],
    ["chain broken, all namespaces unreadable, names show bwrap (no proof of either kind)", evidence(true, false, false, false), null],
    ["ancestor named bwrap whose executable is not the real bwrap (no launcher proof)", evidence(true, false, false, false), null],
    ["T-live: alive with an earlier own proof, proof fails now", evidence(false, false, true, false), null],
    ["T-live: alive with a live launcher proof", evidence(false, false, false, true), null],
    ["alive without any proof", evidence(false, false, false, false), null],
    ["T-escape: exiting, own proof, but the pid or user namespace read as the gateway's", evidence(true, true, true, false), null],
    ["T-escape: exiting, launcher proof, but the pid or user namespace read as the gateway's", evidence(true, true, false, true), null],
  ])("%s", (_name, given, expected) => {
    expect(exitProofClears(given)).toBe(expected);
  });

  it("an own proof wins over a launcher proof when both exist", () => {
    expect(exitProofClears(evidence(true, false, true, true))).toBe("own");
  });

  it.each([
    ["a first failure that clears does not flag", false, "own", false],
    ["a first failure that clears by the launcher does not flag", false, "launcher", false],
    ["a first failure with no route flags", false, null, true],
    ["T-reset: flagged on an alive tick, then exiting with an own proof, still flagged", true, "own", true],
    ["T-reset: flagged on an alive tick, then exiting with a launcher proof, still flagged", true, "launcher", true],
    ["a later failure with no route keeps the flag", true, null, true],
  ] as const)("%s", (_name, prior, clearedBy, expected) => {
    expect(flagAfterProofFailure(prior, clearedBy)).toBe(expected);
  });

  const reading = (partial: Partial<ExitReading>): ExitReading => ({ vanished: false, startChanged: false, state: "S", threads: 1, cmdline: "claude --print", exe: "readable", ...partial });

  it.each([
    ["alive and reading normally", reading({}), false],
    ["a live process that blanked its command line keeps a readable executable", reading({ cmdline: "" }), false],
    ["a live process whose executable cannot be read (EACCES) is not ending", reading({ cmdline: "", exe: "denied" }), false],
    ["a live process with a missing executable but a command line", reading({ exe: "gone" }), false],
    ["a thread-group leader that exited while other threads run", reading({ state: "Z", threads: 3, cmdline: "", exe: "gone" }), false],
    ["a zombie with one thread", reading({ state: "Z", threads: 1, cmdline: "", exe: "gone" }), true],
    ["state X (dead)", reading({ state: "X" }), true],
    ["vanished", reading({ vanished: true }), true],
    ["the pid now has another start time", reading({ startChanged: true }), true],
    ["empty command line and missing executable together", reading({ cmdline: "", exe: "gone" }), true],
    ["an empty leader that finished while other threads run (empty-n)", reading({ threads: 3, cmdline: "", exe: "gone" }), false],
    ["a read that proved nothing (unknown)", reading({ unknown: { file: "stat", errno: "EIO" } }), false],
  ])("exit classifier: %s", (_name, given, expected) => {
    expect(exitConfirmed(given)).toBe(expected);
  });

  const reference = (partial: Partial<Parameters<typeof referenceEndedPending>[0]> = {}) => ({ ownProof: true, launcherProof: false, referenceEnding: true, symptom: true, escapeEvidence: false, cacheExists: true, ...partial });
  const ending = (partial: Partial<ExitReading>): boolean => isReferenceEnding(exitKind({ vanished: false, startChanged: false, state: "S", threads: 1, cmdline: "gateway", exe: "readable", ...partial }));

  it.each([
    ["T-ref: all four conditions hold", reference(), true],
    ["T-ref: no own proof (first tick)", reference({ ownProof: false }), false],
    ["T-ref: launcher proof only, no own proof", reference({ ownProof: false, launcherProof: true }), false],
    ["T-ref: reference alive (S with a command line, not ending)", reference({ referenceEnding: ending({}) }), false],
    ["T-ref: reference alive but non-dumpable (command line readable, exe denied)", reference({ referenceEnding: ending({ exe: "denied" }) }), false],
    ["T-ref: reference a zombie leader whose threads still show (Zn) is ending, so the record is pending", reference({ referenceEnding: ending({ state: "Z", threads: 3, cmdline: "", exe: "gone" }) }), true],
    ["T-ref: reference ended (Z1) is ending", reference({ referenceEnding: ending({ state: "Z", threads: 1, cmdline: "", exe: "gone" }) }), true],
    ["T-ref: reference held in empty-n (leader finished, threads still run) is ending", reference({ referenceEnding: ending({ threads: 3, cmdline: "", exe: "gone" }) }), true],
    ["T-ref: reference whose read proved nothing (unknown) is not ending", reference({ referenceEnding: ending({ unknown: { file: "stat", errno: "EIO" } }) }), false],
    ["T-ref: reference vanished is ending", reference({ referenceEnding: ending({ vanished: true }) }), true],
    ["T-ref: no reference symptom (live readable reference, complete chain)", reference({ symptom: referenceSymptom("live", "complete") }), false],
    ["T-ref-escape: the runtime's pid link equals the reference's", reference({ escapeEvidence: true }), false],
    ["T-ref: no cache for the reference identity", reference({ cacheExists: false }), false],
  ])("%s", (_name, given, expected) => {
    expect(referenceEndedPending(given)).toBe(expected);
  });

  it.each([
    ["live and complete: no symptom", "live", "complete", false],
    ["cached reference: symptom", "cached", "complete", true],
    ["missing reference: symptom", "missing", "complete", true],
    ["broken chain: symptom", "live", "broken", true],
  ] as const)("reference symptom: %s", (_name, source, chain, expected) => {
    expect(referenceSymptom(source, chain)).toBe(expected);
  });

  it.each([
    ["both confirmed within the bound clears", { elapsedMs: 100, exitConfirmed: true, referenceEnded: true, final: false }, "cleared"],
    ["no exit yet inside the bound waits", { elapsedMs: 100, exitConfirmed: false, referenceEnded: true, final: false }, "waiting"],
    ["the runtime's exit confirmed but the reference still Zn inside the bound waits", { elapsedMs: 100, exitConfirmed: true, referenceEnded: false, final: false }, "waiting"],
    ["the runtime's exit confirmed and the reference still Zn at the bound expires on the reference", { elapsedMs: PENDING_BOUND_MS + 1, exitConfirmed: true, referenceEnded: false, final: false }, "expired-reference"],
    ["the runtime's exit confirmed and the reference still Zn at stop() expires on the reference", { elapsedMs: 100, exitConfirmed: true, referenceEnded: false, final: true }, "expired-reference"],
    ["no exit at the bound expires", { elapsedMs: PENDING_BOUND_MS + 1, exitConfirmed: false, referenceEnded: true, final: false }, "expired"],
    ["an exit seen only after the bound does not clear", { elapsedMs: PENDING_BOUND_MS + 1, exitConfirmed: true, referenceEnded: true, final: false }, "expired"],
    ["no exit at stop() expires", { elapsedMs: 100, exitConfirmed: false, referenceEnded: true, final: true }, "expired"],
    ["neither confirmed at the bound expires", { elapsedMs: PENDING_BOUND_MS + 1, exitConfirmed: false, referenceEnded: false, final: false }, "expired"],
  ] as const)("pending: %s", (_name, given, expected) => {
    expect(resolvePending(given)).toBe(expected);
  });


  const runtimeRow = (partial: Partial<Parameters<typeof runtimeEndingPending>[0]> = {}) => ({ ownProof: true, zombieLeader: true, ownUnreadable: true, escapeEvidence: false, ...partial });
  const zombieLeader = (partial: Partial<ExitReading>): boolean => runtimeLeaderExited({ vanished: false, startChanged: false, state: "S", threads: 1, cmdline: "claude", exe: "readable", ...partial });

  it.each([
    ["T-rt: a zombie leader that still counts threads, own proof, own link unreadable, no escape evidence", runtimeRow(), true],
    ["T-rt: no own proof (first tick)", runtimeRow({ ownProof: false }), false],
    ["T-rt-escape: the runtime's pid, user or mount link equals the reference's", runtimeRow({ escapeEvidence: true }), false],
    ["T-rt: no runtime-side symptom (all own links readable)", runtimeRow({ ownUnreadable: false }), false],
    ["T-rt: sleeping with its command line (T-live: alive stays flagged)", runtimeRow({ zombieLeader: zombieLeader({ state: "S" }) }), false],
    ["T-rt: running with its command line (T-live: alive stays flagged)", runtimeRow({ zombieLeader: zombieLeader({ state: "R" }) }), false],
    ["T-rt: a zombie with one thread is a confirmed exit, cleared by the own route, not pending", runtimeRow({ zombieLeader: zombieLeader({ state: "Z", threads: 1, cmdline: "", exe: "gone" }) }), false],
    ["T-rt: a zombie with several threads is the leader-first shape", runtimeRow({ zombieLeader: zombieLeader({ state: "Z", threads: 4, cmdline: "", exe: "gone" }) }), true],
    ["T-rt: vanished is a confirmed exit, not pending", runtimeRow({ zombieLeader: zombieLeader({ vanished: true }) }), false],
  ])("%s", (_name, given, expected) => {
    expect(runtimeEndingPending(given)).toBe(expected);
  });

  it.each([
    ["the last thread ended inside the bound clears", { elapsedMs: 100, exitConfirmed: true, final: false }, "cleared"],
    ["still Zn inside the bound waits", { elapsedMs: 100, exitConfirmed: false, final: false }, "waiting"],
    ["still Zn at the bound expires", { elapsedMs: PENDING_BOUND_MS + 1, exitConfirmed: false, final: false }, "expired"],
    ["still Zn at stop() expires", { elapsedMs: 100, exitConfirmed: false, final: true }, "expired"],
  ] as const)("runtime-ending resolution: %s", (_name, given, expected) => {
    expect(resolvePending({ ...given, referenceEnded: true })).toBe(expected);
  });

  it("exit kinds name how a process looked on the re-read", () => {
    const base: ExitReading = { vanished: false, startChanged: false, state: "S", threads: 1, cmdline: "x", exe: "readable" };
    expect(exitKind(base)).toBe("alive");
    expect(exitKind({ ...base, vanished: true })).toBe("vanished");
    expect(exitKind({ ...base, startChanged: true })).toBe("start-changed");
    expect(exitKind({ ...base, state: "X" })).toBe("X");
    expect(exitKind({ ...base, state: "Z" })).toBe("Z1");
    expect(exitKind({ ...base, state: "Z", threads: 2 })).toBe("Zn");
    expect(exitKind({ ...base, cmdline: "", exe: "gone" })).toBe("empty-gone");
    expect(exitKind({ ...base, cmdline: "", exe: "gone", threads: 2 })).toBe("empty-n");
    expect(exitKind({ ...base, unknown: { file: "exe", errno: "EIO" } })).toBe("unknown");
    for (const state of ["X", "Z", "S"]) {
      const withCmdline = state === "S" ? { cmdline: "", exe: "gone" as const } : {};
      expect(exitKind({ ...base, ...withCmdline, state, threads: 0 }), `${state} with a count of 0`).toBe("unknown");
    }
    expect(exitKind({ ...base, state: "X", threads: 2 }), "X with a count of 2 is an old leader of an exec, not an exit").toBe("unknown");
  });
});

/**
 * The thread-safe exit rule (MVP-8130): the same exported functions the sampler runs. Expected values are written out here and do
 * not come from the production tables. Rows that no real process can produce (an unreadable `/proc` file, a torn read, a count of 0
 * that persists) live here and in the RE-* rows, which inject the error codes through the restricted exit read seam.
 */
describe("process sampler thread-safe exit: decision table (MVP-8130)", () => {
  const reading = (partial: Partial<ExitReading>): ExitReading => ({ vanished: false, startChanged: false, state: "S", threads: 1, cmdline: "claude", exe: "readable", ...partial });
  const READ = {
    alive: reading({}),
    Z1: reading({ state: "Z", cmdline: "", exe: "gone" }),
    Z0: reading({ state: "Z", threads: 0, cmdline: "", exe: "gone" }),
    Zn: reading({ state: "Z", threads: 3, cmdline: "", exe: "gone" }),
    X1: reading({ state: "X", cmdline: "", exe: "gone" }),
    X0: reading({ state: "X", threads: 0, cmdline: "", exe: "gone" }),
    X2: reading({ state: "X", threads: 2, cmdline: "", exe: "gone" }),
    emptyGone: reading({ cmdline: "", exe: "gone" }),
    emptyN: reading({ threads: 3, cmdline: "", exe: "gone" }),
    empty0: reading({ threads: 0, cmdline: "", exe: "gone" }),
    vanished: reading({ vanished: true, threads: 0, cmdline: "", exe: "gone" }),
    startChanged: reading({ startChanged: true }),
    unknownStat: reading({ unknown: { file: "stat", errno: "EIO" } }),
    raceCmdline: reading({ unknown: { file: "cmdline", errno: "ENOENT" } }),
  } as const;
  type Shorthand = keyof typeof READ;

  /** Feeds the bracket the listed readings in order and reports the decision and how many readings it consumed. */
  const decide = (list: Shorthand[]): { kind: ExitKind; used: number } => {
    let used = 0;
    const { kind } = exitBracket(() => {
      if (used >= list.length) throw new Error("the row supplied too few readings");
      return READ[list[used++]];
    });
    return { kind, used };
  };

  it.each([
    ["T-th1: alive and reading normally", reading({}), "alive"],
    ["T-th1: a live process that blanked its command line keeps a readable executable", reading({ cmdline: "" }), "alive"],
    ["T-th1: a live process whose executable cannot be read (EACCES) is alive", reading({ cmdline: "", exe: "denied" }), "alive"],
    ["T-th1: a live process with a missing executable but a command line", reading({ exe: "gone" }), "alive"],
    ["T-th1: empty-gone: empty command line, missing executable, exactly one thread", READ.emptyGone, "empty-gone"],
    ["T-th1: empty-n: empty command line, missing executable, two or more threads (a leader that finished while other threads run)", READ.emptyN, "empty-n"],
    ["T-th1: empty command line and missing executable with a count of 0 proves nothing", READ.empty0, "unknown"],
    ["T-th1: Z1: a zombie with exactly one thread", READ.Z1, "Z1"],
    ["T-th1: Zn: a zombie leader whose other threads still run", READ.Zn, "Zn"],
    ["T-th1: a zombie with a count of 0 proves nothing", READ.Z0, "unknown"],
    ["T-th1: X with exactly one thread", READ.X1, "X"],
    ["T-th1: X with a count of 0 proves nothing", READ.X0, "unknown"],
    ["T-th1: X with a count of 2 is the old leader of an exec, not an exit", READ.X2, "unknown"],
    ["T-th1: vanished", READ.vanished, "vanished"],
    ["T-th1: the pid now has another start time", READ.startChanged, "start-changed"],
    ["T-th1: a read that failed with an error other than ENOENT/ESRCH", READ.unknownStat, "unknown"],
  ] as const)("%s", (_name, given, expected) => {
    expect(exitKind(given)).toBe(expected);
    expect(isConfirmedExit(exitKind(given)), "only the five kinds with a kernel fact are confirmed").toBe(["vanished", "start-changed", "X", "Z1", "empty-gone"].includes(expected));
  });

  it("T-th1: consumers: only the five confirmed kinds end a process, only alive and unknown never open the reference route", () => {
    const kinds: ExitKind[] = ["vanished", "start-changed", "X", "Z1", "Zn", "empty-gone", "empty-n", "alive", "unknown"];
    expect(kinds.filter(isConfirmedExit)).toEqual(["vanished", "start-changed", "X", "Z1", "empty-gone"]);
    expect(kinds.filter(isReferenceEnding)).toEqual(["vanished", "start-changed", "X", "Z1", "Zn", "empty-gone", "empty-n"]);
    expect(runtimeLeaderExited(READ.emptyN), "empty-n is a leader that finished").toBe(true);
    expect(runtimeLeaderExited(READ.Zn)).toBe(true);
    for (const shorthand of ["alive", "Z1", "emptyGone", "unknownStat", "Z0"] as const) expect(runtimeLeaderExited(READ[shorthand]), shorthand).toBe(false);
  });

  it.each([
    ["T-th2: two agreeing readings decide", ["Z1", "Z1"], "Z1", 2],
    ["T-th2: two agreeing empty-gone readings decide", ["emptyGone", "emptyGone"], "empty-gone", 2],
    ["T-th2: two agreeing empty-n readings decide", ["emptyN", "emptyN"], "empty-n", 2],
    ["T-th2: (alive, Z1) is read again and an alive pair decides alive", ["alive", "Z1", "alive", "alive"], "alive", 4],
    ["T-th2: (Z1, alive) is read again and an alive pair decides alive", ["Z1", "alive", "alive", "alive"], "alive", 4],
    ["T-th2: the measured torn read (a zombie state with a count of 0 or 1, then alive) is never a confirmed exit", ["Z0", "alive", "alive", "alive"], "alive", 4],
    ["T-th2: a disagreement that persists to the end is not a confirmed exit: (alive, Z1) three times decides alive", ["alive", "Z1", "alive", "Z1", "alive", "Z1"], "alive", 6],
    ["T-th2: a disagreement that persists, the other order: (Z1, alive) three times decides alive", ["Z1", "alive", "Z1", "alive", "Z1", "alive"], "alive", 6],
    ["T-th2: two confirmed kinds that persist take the later one", ["Z1", "emptyGone", "Z1", "emptyGone", "Z1", "emptyGone"], "empty-gone", 6],
    ["T-th2: a confirmed kind against Zn that persists is the non-confirmed Zn", ["Z1", "Zn", "Z1", "Zn", "Z1", "Zn"], "Zn", 6],
    ["T-th2: two non-confirmed kinds that persist take the later one", ["Zn", "emptyN", "Zn", "emptyN", "Zn", "emptyN"], "empty-n", 6],
    ["T-th2: a vanished stat decides at once, also as the first reading", ["vanished"], "vanished", 1],
    ["T-th2: (alive, vanished) is vanished", ["alive", "vanished"], "vanished", 2],
    ["T-th2: another start time decides at once", ["alive", "startChanged"], "start-changed", 2],
    ["T-th2: an unknown reading decides unknown without a re-read", ["Z1", "unknownStat"], "unknown", 2],
    ["T-th2: unknown first, the pair is complete and decides unknown", ["unknownStat", "Z1"], "unknown", 2],
    ["T-th2: a stat that fails with ENOENT after an unknown one is vanished (both facts are monotone)", ["unknownStat", "vanished"], "vanished", 2],
    ["T-th2: S-C1: [Z1, Z0, ENOENT] is vanished (a count of 0 is read again before any unknown rule)", ["Z1", "Z0", "vanished"], "vanished", 3],
    ["T-th2: S-C1: [X0, ENOENT] is vanished", ["X0", "vanished"], "vanished", 2],
    ["T-th2: S-C1: [Z1, Z0, Z1, Z1] decides Z1 once the zero is gone", ["Z1", "Z0", "Z1", "Z1"], "Z1", 4],
    ["T-th2: S-C1: a count of 0 that persists to the end of the budget is unknown", ["Z1", "Z0", "Z1", "Z0", "Z1", "Z0"], "unknown", 6],
    ["T-th2: S-C1: (empty, 0) that persists is unknown", ["empty0", "empty0", "empty0", "empty0", "empty0", "empty0"], "unknown", 6],
    ["T-th2: a command line read that failed with ENOENT/ESRCH (released between the reads) is read again and the next stat decides: vanished", ["raceCmdline", "Z1", "vanished"], "vanished", 3],
    ["T-th2: the same race, then two agreeing readings", ["raceCmdline", "Z1", "Z1", "Z1"], "Z1", 4],
    ["T-th2: a race that persists to the end is unknown", ["raceCmdline", "Z1", "raceCmdline", "Z1", "raceCmdline", "Z1"], "unknown", 6],
  ] as const)("%s", (_name, list, expected, used) => {
    const result = decide([...list]);
    expect(result.kind).toBe(expected);
    expect(result.used, "readings consumed").toBe(used);
    if (!["vanished", "start-changed"].includes(expected) && expected !== "Z1" && expected !== "empty-gone") expect(isConfirmedExit(result.kind)).toBe(false);
  });

  it("T-th2: the budget is three pairs", () => {
    expect(EXIT_PAIRS).toBe(3);
  });

  /** The text of `/proc/<pid>/stat` with the given state, thread count and start time (fields 3, 20 and 22); a comm may hold `)`. */
  const statText = (state: string, threads: number | string, start: string, comm = "claude"): string => `1234 (${comm}) ${state} 1 ${Array.from({ length: 15 }, () => "0").join(" ")} ${threads} 0 ${start} 0 0`;
  interface Double {
    source: ExitSource;
    calls: string[];
  }
  const doubleOf = (parts: { stat?: () => string; cmdline?: () => string; status?: () => string; exe?: () => "readable" | "denied" | "gone" }): Double => {
    const calls: string[] = [];
    const call = <T>(name: string, read: (() => T) | undefined, fallback: T): T => {
      calls.push(name);
      return read ? read() : fallback;
    };
    return {
      calls,
      source: {
        stat: () => call("stat", parts.stat, statText("S", 1, "500")),
        cmdline: () => call("cmdline", parts.cmdline, "claude\0--print\0"),
        status: () => call("status", parts.status, "Name:\tclaude\nThreads:\t1\n"),
        exe: () => call("exe", parts.exe, "readable" as const),
      },
    };
  };
  function errno(code: string): never {
    throw Object.assign(new Error(code), { code });
  }

  it("T-th2: the reader: a command line read failing with ENOENT after a readable stat is a race (unknown, read again) and the next stat decides vanished, after exactly two readings", () => {
    let statReads = 0;
    const given = doubleOf({
      stat: () => (++statReads === 1 ? statText("Z", 1, "500") : errno("ENOENT")),
      cmdline: () => errno("ENOENT"),
      exe: () => "gone",
    });
    const { kind, readings } = exitBracket(() => readExitReadingFrom(given.source, 4242, "500"));
    expect(kind).toBe("vanished");
    expect(readings.length, "the race reading is read again, it does not decide").toBe(2);
    expect(readings[0].unknown).toEqual({ file: "cmdline", errno: "ENOENT" });
    // The same race that persists is unknown, never vanished by itself.
    const persistent = doubleOf({ stat: () => statText("Z", 1, "500"), cmdline: () => errno("ESRCH"), exe: () => "gone" });
    expect(exitBracket(() => readExitReadingFrom(persistent.source, 4242, "500")).kind).toBe("unknown");
  });

  it.each([
    ["Zn: a zombie leader whose threads still run", READ.Zn, true],
    ["empty-n: a leader that finished while other threads run", READ.emptyN, true],
    ["X with a count of 2: the old leader of an exec", READ.X2, true],
    ["Z with a count of 0: a task being released", READ.Z0, true],
    ["X with a count of 0", READ.X0, true],
    ["Z1: a single-thread zombie", READ.Z1, false],
    ["X with a count of 1", READ.X1, false],
    ["empty-gone", READ.emptyGone, false],
    ["alive", READ.alive, false],
    ["vanished", READ.vanished, false],
    ["unknown", READ.unknownStat, false],
  ] as const)("T-th2: the leader-exit signature (it sets the revival flag): %s", (_name, given, expected) => {
    expect(leaderExitSign(given)).toBe(expected);
  });

  it("T-th2: the thread count comes from the same stat text as the state: stat says Z with 3 threads and status says 1, the reading is Zn and status is never read", () => {
    const given = doubleOf({ stat: () => statText("Z", 3, "500"), cmdline: () => "", exe: () => "gone", status: () => "Name:\tclaude\nThreads:\t1\n" });
    const read = readExitReadingFrom(given.source, 4242, "500");
    expect(exitKind(read)).toBe("Zn");
    expect(given.calls, "the status file is not part of an exit reading").not.toContain("status");
    expect(given.calls[0], "the stat text is read first").toBe("stat");
  });

  it("T-th2: a comm that contains ')' does not move the thread count or the start time", () => {
    const given = doubleOf({ stat: () => statText("Z", 1, "500", "a) b (c)"), cmdline: () => "", exe: () => "gone" });
    expect(exitKind(readExitReadingFrom(given.source, 4242, "500"))).toBe("Z1");
    const other = doubleOf({ stat: () => statText("Z", 1, "501", "a) b (c)") });
    expect(exitKind(readExitReadingFrom(other.source, 4242, "500")), "another start time behind a comm with ')'").toBe("start-changed");
  });

  it("T-th2: the stat text is read once per reading, then the command line, then the executable", () => {
    const given = doubleOf({});
    readExitReadingFrom(given.source, 4242, "500");
    expect(given.calls).toEqual(["stat", "cmdline", "exe"]);
  });

  it.each([
    ["RE1: a stat text cut before the start time is unknown", statText("Z", 1, "500").split(" ").slice(0, 20).join(" "), "start-field"],
    ["RE1: a non-numeric thread field is unknown", statText("Z", "x", "500"), "thread-field"],
    ["RE1: a non-numeric start field is unknown", statText("Z", 1, "later"), "start-field"],
    ["RE1: a stat text without a command name is unknown", "garbage", "stat"],
    ["RE1: an empty stat text is unknown", "", "stat"],
  ] as const)("%s", (_name, text, file) => {
    const read = readExitReadingFrom(doubleOf({ stat: () => text, cmdline: () => "", exe: () => "gone" }).source, 4242, "500");
    expect(read.unknown?.file).toBe(file);
    expect(exitKind(read)).toBe("unknown");
    expect(exitConfirmed(read)).toBe(false);
  });

  // The read-error decision row, every file against every error code. Written out here, not read from the production function.
  const CODES = ["ENOENT", "ESRCH", "EACCES", "EIO", "EMFILE", "ENFILE", "ENOMEM", "EPERM", "ELOOP", "EINTR", "OTHER"] as const;
  const EXPECTED: Record<"stat" | "cmdline" | "exe", Record<(typeof CODES)[number], string>> = {
    stat: { ENOENT: "vanished", ESRCH: "vanished", EACCES: "unknown", EIO: "unknown", EMFILE: "unknown", ENFILE: "unknown", ENOMEM: "unknown", EPERM: "unknown", ELOOP: "unknown", EINTR: "unknown", OTHER: "unknown" },
    cmdline: { ENOENT: "unknown", ESRCH: "unknown", EACCES: "unknown", EIO: "unknown", EMFILE: "unknown", ENFILE: "unknown", ENOMEM: "unknown", EPERM: "unknown", ELOOP: "unknown", EINTR: "unknown", OTHER: "unknown" },
    exe: { ENOENT: "gone", ESRCH: "gone", EACCES: "denied", EIO: "unknown", EMFILE: "unknown", ENFILE: "unknown", ENOMEM: "unknown", EPERM: "unknown", ELOOP: "unknown", EINTR: "unknown", OTHER: "unknown" },
  };
  for (const file of ["stat", "cmdline", "exe"] as const) {
    it.each(CODES)(`RE1: ${file} read failing with %s`, (code) => {
      expect(exitReadOutcome(file, code)).toBe(EXPECTED[file][code]);
      // The same row through the reader: what the sampler's reading says for a double that throws.
      const given = doubleOf({
        stat: file === "stat" ? () => errno(code) : () => statText("S", 1, "500"),
        cmdline: file === "cmdline" ? () => errno(code) : () => "",
        exe: file === "exe" ? exeReaderOver({ readlink: () => errno(code), stat: () => ({}) }).bind(null, 4242) : () => "gone",
      });
      const read = readExitReadingFrom(given.source, 4242, "500");
      const expectedOutcome = EXPECTED[file][code];
      if (expectedOutcome === "vanished") expect(exitKind(read)).toBe("vanished");
      else if (expectedOutcome === "unknown") {
        expect(exitKind(read)).toBe("unknown");
        expect(read.unknown?.file).toBe(file);
      } else if (expectedOutcome === "gone") expect(exitKind(read), "an executable that is gone next to an empty command line").toBe("empty-gone");
      else expect(exitKind(read), "an executable that is denied is alive").toBe("alive");
    });
  }

  const EXE_ROWS: [string, { readlink: () => string; stat: () => unknown }, "readable" | "denied" | "gone"][] = [
    ["the link is readable and its identity too", { readlink: () => "/usr/bin/x", stat: () => ({}) }, "readable"],
    ["the link fails with ENOENT", { readlink: () => errno("ENOENT"), stat: () => ({}) }, "gone"],
    ["the link fails with EACCES", { readlink: () => errno("EACCES"), stat: () => ({}) }, "denied"],
    ["the identity of a readable link fails with ENOENT", { readlink: () => "/usr/bin/x (deleted)", stat: () => errno("ENOENT") }, "gone"],
    ["the identity of a readable link fails with ESRCH", { readlink: () => "/usr/bin/x", stat: () => errno("ESRCH") }, "gone"],
  ];
  it.each(EXE_ROWS)("RE1: executable: %s", (_name, io, expected) => {
    expect(exeReaderOver(io)(1)).toBe(expected);
  });

  it.each(["EACCES", "EIO", "EMFILE", "ELOOP"])("RE1: executable: the identity of a readable link fails with %s: unknown, never gone or denied", (code) => {
    const given = doubleOf({ stat: () => statText("S", 1, "500"), cmdline: () => "", exe: exeReaderOver({ readlink: () => "/usr/bin/x", stat: () => errno(code) }).bind(null, 4242) });
    const read = readExitReadingFrom(given.source, 4242, "500");
    expect(exitKind(read)).toBe("unknown");
    expect(read.unknown?.file).toBe("exe");
  });

  it.each([
    ["EIO", "stat", true],
    ["EMFILE", "cmdline", true],
    ["ENFILE", "exe", true],
    ["ENOMEM", "stat", true],
    ["EPERM", "exe", true],
    ["EACCES", "stat", true],
    ["EACCES", "cmdline", true],
    ["EACCES", "exe", false],
    ["ENOENT", "stat", false],
    ["ESRCH", "stat", false],
    ["ENOENT", "exe", false],
    ["EINTR", "stat", false],
    ["", "stat", false],
  ] as const)("TH-seam: the exit read seam accepts %s on %s: %s", (code, file, allowed) => {
    expect(exitFaultAllowed(file, code)).toBe(allowed);
  });

  it("TH-seam: a real process read through the seam: an accepted code reads unknown with its code, a refused code and a throwing seam read unknown too, none reads as no fault or as vanished", () => {
    const start = (): string => {
      const text = fs.readFileSync("/proc/self/stat", "utf8");
      return text.slice(text.lastIndexOf(")") + 2).split(" ")[19];
    };
    const ticks = start();
    const plain = endedNow(process.pid, ticks);
    expect(plain.kind, "this very process is alive").toBe("alive");
    expect(plain.injected).toBe(false);
    const run = (fault: ExitReadFault) => endedNow(process.pid, ticks, fault);
    expect(run(() => undefined)).toMatchObject({ kind: "alive", injected: false });
    expect(run((pid, file) => (pid === process.pid && file === "stat" ? "EIO" : undefined))).toMatchObject({ kind: "unknown", unknownRead: "stat:EIO", injected: true, ended: false });
    expect(run((pid, file) => (pid === process.pid && file === "cmdline" ? "EMFILE" : undefined))).toMatchObject({ kind: "unknown", unknownRead: "cmdline:EMFILE", injected: true });
    expect(run((pid, file) => (pid === process.pid && file === "exe" ? "EPERM" : undefined))).toMatchObject({ kind: "unknown", unknownRead: "exe:EPERM", injected: true });
    let statReads = 0;
    expect(
      run((pid, file) => (pid === process.pid && file === "stat" ? (++statReads === 2 ? "EIO" : undefined) : undefined)),
      "a fault on the second full reading only: the decision takes two readings",
    ).toMatchObject({ kind: "unknown", unknownRead: "stat:EIO", injected: true });
    expect(run(() => "ENOENT"), "ENOENT is refused: a test error, read as unknown").toMatchObject({ kind: "unknown", unknownRead: "stat:SEAM-INVALID", injected: true, ended: false });
    expect(run(() => "ESRCH")).toMatchObject({ kind: "unknown", unknownRead: "stat:SEAM-INVALID" });
    expect(run((_pid, file) => (file === "exe" ? "EACCES" : undefined)), "EACCES on exe would read as denied, which is alive: refused").toMatchObject({ kind: "unknown", unknownRead: "exe:SEAM-INVALID" });
    expect(
      run(() => {
        throw new Error("a seam that throws");
      }),
      "a throwing seam is never read as no fault",
    ).toMatchObject({ kind: "unknown", unknownRead: "stat:SEAM-THREW", injected: true });
  });

  it("TH-seam: static: only the declared RE-rows, TH-bracket and this row pass the exit read seam", () => {
    const ALLOWED = ["RE-own", "RE-exe", "RE-rt", "RE-ref", "RE-le", "RE-launcher", "R1-RE", "TH-bracket", "TH-seam"];
    const dir = path.dirname(fileURLToPath(import.meta.url));
    const files = fs.readdirSync(dir, { recursive: true, encoding: "utf8" }).filter((name) => name.endsWith(".ts") && !name.startsWith("helpers"));
    // The plumbing that forwards the seam into the sampler windows sits between two markers; every other use belongs to a row.
    const open = "<exit-read-fault" + "-plumbing>";
    const close = "</exit-read-fault" + "-plumbing>";
    const offenders: string[] = [];
    let uses = 0;
    for (const name of files) {
      const text = fs.readFileSync(path.join(dir, name), "utf8");
      const titles = [...text.matchAll(/^\s*it\(\s*[`"']([^`"'$%]*)/gm)].map((match) => ({ at: match.index!, title: match[1] }));
      const plumbing: [number, number][] = [];
      for (let at = text.indexOf(open); at >= 0; at = text.indexOf(open, at + 1)) plumbing.push([at, text.indexOf(close, at)]);
      for (const use of text.matchAll(/exitReadFault\b/g)) {
        if (plumbing.some(([from, to]) => use.index! >= from && use.index! < to)) continue;
        uses += 1;
        const owner = [...titles].reverse().find((title) => title.at < use.index!);
        const id = owner?.title.split(":")[0].trim() ?? "";
        if (!ALLOWED.includes(id)) offenders.push(`${name}:${owner?.title.slice(0, 40) ?? "outside a row"}`);
      }
    }
    expect(uses, "the rows that use the seam were found").toBeGreaterThanOrEqual(ALLOWED.length - 1);
    expect(offenders).toEqual([]);
  });

  it("PB-origin: the pending bound starts at the tick's start; only a test seam's return moves it", () => {
    expect(pendingBoundOrigin(1000, null), "no seam ran (every real run): the tick's start").toBe(1000);
    expect(pendingBoundOrigin(1000, 4200), "a seam held the tick and returned later: its return").toBe(4200);
    expect(pendingBoundOrigin(1000, 1000)).toBe(1000);
    expect(PENDING_BOUND_MS, "the bound itself is unchanged").toBe(2000);
  });

  it("T-th2: the hidepid precondition reads the /proc mount options and refuses a mount that hides processes", () => {
    const line = (options: string, superOptions: string): string => `25 29 0:23 / /proc ${options} shared:12 - proc proc ${superOptions}`;
    expect(procMountHidesProcesses(line("rw,nosuid,nodev,noexec,relatime", "rw"))).toBe(false);
    expect(procMountHidesProcesses(line("rw,nosuid,nodev,noexec,relatime", "rw,hidepid=2"))).toBe(true);
    expect(procMountHidesProcesses(line("rw,nosuid,nodev,noexec,relatime,hidepid=invisible", "rw"))).toBe(true);
    expect(procMountHidesProcesses(line("rw,hidepid=1", "rw"))).toBe(true);
    expect(procMountHidesProcesses(line("rw,hidepid=0", "rw,hidepid=off"))).toBe(false);
    expect(procMountHidesProcesses(`${line("rw", "rw")}\n30 29 0:30 / /sys rw - sysfs sysfs rw,hidepid=2`), "another mount").toBe(false);
    expect(procMountHidesProcesses("")).toBe(false);
    expect(procMountHidesProcesses(fs.readFileSync("/proc/self/mountinfo", "utf8")), "this host can run a window").toBe(false);
  });

  it("T-th2: the record shape prints names, codes and booleans only: the failed read, the injection, the revival and the confirming kinds", () => {
    const record: ProcessRecord = {
      pid: 4242,
      startTicks: "1111",
      comms: ["claude"],
      argvShape: "claude",
      exe: "other",
      ancestors: ["bwrap", "other"],
      sameNamespaces: { pid: false, user: false, mnt: false },
      firstMs: 0,
      lastMs: 10,
      oldCounted: false,
      oldUnsandboxed: false,
      verdict: "runtime",
      unsandboxed: true,
      inconsistentReads: 0,
      proofFailure: { failedWhile: "alive", ownProof: true, launcherProof: false, escapeEvidence: false, ownUnreadable: "mnt", reference: "live", chain: "complete", referenceEnded: false, referenceExit: "alive", runtimeExit: "unknown", exitRead: "stat:EIO", exitReadInjected: true, pending: "expired" },
      pending: { state: "expired", sinceMs: 5, route: "runtime-ending", sawLeaderExit: true, revived: true },
      provenExeId: "64769:123456789",
      fate: "exited",
    };
    const text = describeRecords([record]);
    expect(text).toContain("runtime-exit=unknown exit-read=stat:EIO exit-read-injected=true pending=expired");
    expect(text).toContain("pending-route=runtime-ending revived=true");
    expect(text.includes("123456789"), "the executable identity is never printed").toBe(false);
    const hostile = describeRecords([{ ...record, proofFailure: { ...record.proofFailure!, exitRead: "stat:eio /etc/passwd", referenceExitRead: "cmdline:EMFILE" } }]);
    expect(hostile).toContain("exit-read=other");
    expect(hostile).toContain("reference-exit-read=cmdline:EMFILE");
    expect(hostile.includes("passwd")).toBe(false);
    const cleared = describeRecords([{ ...record, unsandboxed: false, pending: { state: "cleared", sinceMs: 5, route: "reference-ended" }, clearedBy: "reference-ended", exitConfirmed: { runtime: "Z1", reference: "vanished" } }]);
    expect(cleared).toContain("cleared-by=reference-ended exit-confirmed=Z1 reference-exit-confirmed=vanished");
    expect(describeRecords([{ ...record, unsandboxed: false, clearedBy: "own", exitConfirmed: { runtime: "empty-gone" } }])).toContain("cleared-by=own exit-confirmed=empty-gone");
  });
});

/**
 * Real processes for the thread-safe exit rule (MVP-8130). A python3 stand-in titled `claude` (or a reference) has a second
 * thread that polls a trigger directory; on SIGUSR1 its leader opens `FRESH` files in a private descriptor table and then ends
 * alone with the raw `exit` syscall, so the leader stays in its exit for a measured while after its memory (command line,
 * executable) is gone and the other thread keeps the process alive: the state `empty-n`, then `Zn`. The trigger files `end` and
 * `exec` make the surviving thread return (the process then ends) or execute a new program (the process is revived under the
 * same pid and start time). The sampler windows place the leader exit between the proof and the exit read with its own seams, so
 * a missed hold is a precondition failure of the row (INVALID), never a pass. Every fixture reaps its trees: a recorded pid is
 * only ever signalled while its start time still matches.
 */
describe("process sampler thread-safe exit: real processes (MVP-8130)", () => {
  const BWRAP_DIE = ["bwrap", "--die-with-parent", "--ro-bind", "/", "/", "--unshare-user", "--unshare-pid", "--dev", "/dev", "--proc", "/proc"];
  const KEEP_INNER = ["bwrap", "--ro-bind", "/", "/", "--unshare-user", "--unshare-pid", "--dev", "/dev", "--proc", "/proc"];
  /**
   * Fresh files the leader opens before it ends: its exit releases each one itself, after its namespaces are gone, so the leader stays
   * in `empty-n` for about as long as the release takes (measured at A0: about 126 ms for 300000 files and 247 ms for 600000, the
   * mount link going after about a quarter of it, also under load). The count is the largest the descriptor limit allows, so that a
   * poll that is starved of CPU under load still finds the held state; it costs seconds of open phase per row.
   */
  const HOLD_FILES = 1_000_000;
  /** The same for a reference stand-in, whose hold must outlast the runtime's end that follows the seam. */
  const REFERENCE_HOLD_FILES = HOLD_FILES;
  const IDLE = "setInterval(() => {}, 1000)";
  const quote = (value: string): string => `'${value.replace(/'/g, `'\\''`)}'`;
  const standIn = `exec -a claude ${quote(process.execPath)} -e ${quote(IDLE)}`;

  const THREAD_FIXTURE = [
    "import ctypes, os, platform, resource, signal, subprocess, sys, threading, time",
    "libc = ctypes.CDLL(None)",
    "exit_thread = 60 if platform.machine() == 'x86_64' else 93",
    "trig, fresh, secs, title = os.environ['TRIG'], int(os.environ.get('FRESH', '0')), os.environ.get('SECS', '6'), os.environ.get('TITLE', 'claude')",
    "limit = resource.getrlimit(resource.RLIMIT_NOFILE)[1]",
    "resource.setrlimit(resource.RLIMIT_NOFILE, (limit, limit))",
    "def worker():",
    "    while True:",
    "        if os.path.exists(trig + '/exec'):",
    "            os.execv('/bin/sleep', [title, secs])",
    "        if os.path.exists(trig + '/end'):",
    "            return",
    "        time.sleep(0.001)",
    "def leave(*_):",
    "    sys.stderr.write('leave: start\\n')",
    "    sys.stderr.flush()",
    "    try:",
    "        if fresh > 0:",
    "            os.unshare(os.CLONE_FILES)",
    "            for _ in range(fresh):",
    "                os.open('/dev/null', os.O_RDONLY)",
    "    except BaseException as error:",
    "        sys.stderr.write('leave: failed %r\\n' % (error,))",
    "        sys.stderr.flush()",
    "        raise",
    "    sys.stderr.write('leave: opened\\n')",
    "    sys.stderr.flush()",
    "    libc.syscall(exit_thread, 0)",
    "signal.signal(signal.SIGUSR1, leave)",
    "child = subprocess.Popen(sys.argv[1:]) if len(sys.argv) > 1 else None",
    "threading.Thread(target=worker).start()",
    "while True:",
    "    time.sleep(0.05)",
  ].join("\n");
  const fixtureCommand = (trig: string, env: Record<string, string | number>, title = "claude", args = ""): string =>
    `${Object.entries({ TRIG: trig, TITLE: title, ...env }).map(([key, value]) => `${key}=${quote(String(value))}`).join(" ")} ${title === "claude" ? `exec -a claude ` : ""}python3 -c ${quote(THREAD_FIXTURE)}${args}`;

  interface Tracked {
    pid: number;
    startTicks: string;
  }
  const tracked: Tracked[] = [];
  const spawned: ChildProcess[] = [];
  const stopped: number[] = [];
  const dirs: string[] = [];

  const sleepSync = (ms: number): void => void Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
  /** The seam runs inside a sampler tick and must hold it until the shape exists: this waits without releasing the event loop. */
  const waitSync = (condition: () => boolean, boundMs = 3000, stepMs = 2): boolean => {
    for (const end = Date.now() + boundMs; !condition(); sleepSync(stepMs)) if (Date.now() > end) return false;
    return true;
  };
  const pause = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));
  const until = async (condition: () => boolean, what: string, boundMs = 30_000): Promise<void> => {
    for (const end = Date.now() + boundMs; !condition() && Date.now() < end; ) await pause(25);
    expect(condition(), `precondition not reached: ${what}`).toBe(true);
  };

  const statOf = (pid: number): { state: string; ppid: number; threads: number; startTicks: string } | null => {
    try {
      const text = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
      const rest = text.slice(text.lastIndexOf(")") + 2).split(" ");
      return { state: rest[0], ppid: Number(rest[1]), threads: Number(rest[17]), startTicks: rest[19] };
    } catch {
      return null;
    }
  };
  const ppidOf = (pid: number): number => statOf(pid)?.ppid ?? 0;
  const signal = (pid: number, name: NodeJS.Signals): void => {
    try {
      process.kill(pid, name);
    } catch {
      // Already gone.
    }
  };
  const track = (pid: number): Tracked => {
    const item = { pid, startTicks: statOf(pid)?.startTicks ?? "" };
    tracked.push(item);
    return item;
  };
  const sameProcess = (item: Tracked): boolean => item.startTicks !== "" && statOf(item.pid)?.startTicks === item.startTicks;
  const endTracked = (item: Tracked): void => {
    if (sameProcess(item)) signal(item.pid, "SIGKILL");
  };
  afterEach(() => {
    for (const pid of stopped.splice(0)) signal(pid, "SIGCONT");
    for (const item of tracked.splice(0)) endTracked(item);
    for (const child of spawned.splice(0)) for (const pid of [...descendants(child.pid!), child.pid!]) signal(pid, "SIGKILL");
    for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
  });
  const scratch = (): string => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mvp8130-"));
    dirs.push(dir);
    return dir;
  };
  const touch = (dir: string, name: "end" | "exec"): void => fs.writeFileSync(path.join(dir, name), "");

  const linkGone = (pid: number, kind: "exe" | "ns/mnt"): boolean => {
    try {
      fs.readlinkSync(`/proc/${pid}/${kind}`);
      return false;
    } catch (error) {
      return (error as NodeJS.ErrnoException).code === "ENOENT";
    }
  };
  const cmdlineEmpty = (pid: number): boolean => {
    try {
      return fs.readFileSync(`/proc/${pid}/cmdline`).length === 0;
    } catch {
      return false;
    }
  };
  /** The shape `empty-n` stands for, read by the fixture itself: the leader finished its memory release while other threads run. */
  const held = (pid: number): boolean => {
    const stat = statOf(pid);
    return stat !== null && stat.state !== "Z" && stat.state !== "X" && stat.threads >= 2 && cmdlineEmpty(pid) && linkGone(pid, "exe");
  };
  const zombieLeader = (pid: number): boolean => {
    const stat = statOf(pid);
    return stat !== null && stat.state === "Z" && stat.threads >= 2;
  };
  const zombieSingle = (pid: number): boolean => {
    const stat = statOf(pid);
    return stat !== null && stat.state === "Z" && stat.threads === 1;
  };
  /** The stand-in installs its SIGUSR1 handler a moment after it starts: the signal before that would kill it instead of ending its leader. */
  const handlerInstalled = (pid: number): boolean => {
    try {
      return (BigInt("0x" + /^SigCgt:\s*([0-9a-f]+)/m.exec(fs.readFileSync(`/proc/${pid}/status`, "utf8"))![1]) & 0x200n) !== 0n;
    } catch {
      return false;
    }
  };
  /** The new program the surviving thread executed runs under the same pid (its command line is the title and the seconds only). */
  const imageRuns = (pid: number, secs: string, title = "claude"): boolean => {
    try {
      return fs.readFileSync(`/proc/${pid}/cmdline`).toString("latin1") === `${title}\0${secs}\0`;
    } catch {
      return false;
    }
  };
  const ended = (item: Tracked): boolean => endedNow(item.pid, item.startTicks).ended;

  /** What the seams did for the one candidate under test; the row reads every flag back before it asserts anything else. */
  interface Seam {
    pid?: number;
    readings: number;
    forced: boolean;
    reached: boolean;
    runtime?: Tracked;
    /** The process whose held leader exit the row relies on (the runtime, or the reference), and whether it still showed that shape right before and right after the exit read. */
    holdPid?: number;
    preHold?: boolean;
    postHold?: boolean;
    reference?: Tracked;
    holder?: Tracked;
  }
  const newSeam = (): Seam => ({ readings: 0, forced: false, reached: false });
  /** On the `atReading`-th stable reading of the one candidate: records it and runs `act`, which returns whether the shape was reached within its bound. */
  const seamAt =
    (state: Seam, atReading: number, act: (pid: number) => boolean) =>
    (pid: number): void => {
      state.pid ??= pid;
      if (pid !== state.pid || state.forced) return;
      state.readings += 1;
      if (state.readings < atReading) return;
      state.forced = true;
      state.runtime = track(pid);
      state.holdPid ??= pid;
      state.reached = act(pid);
    };
  /** Sends SIGUSR1 once the handler is installed and waits for `shape`; false when the handler never appeared or the shape was not reached. */
  const endLeader = (pid: number, shape: () => boolean, boundMs = 40_000): boolean => {
    if (!waitSync(() => handlerInstalled(pid), 30_000)) return false;
    signal(pid, "SIGUSR1");
    // Fails at once when the process is gone or the leader already is a plain zombie leader (the held state was missed): nothing more can happen.
    let reached = false;
    waitSync(() => (reached = shape()) || statOf(pid) === null || zombieSingle(pid) || zombieLeader(pid), boundMs, 0.5);
    return reached;
  };
  /** What a precondition failure of a held leader exit reports: the process state and the fixture's stderr (names and counts only). */
  const heldDiag = (pid: number | undefined, trig: string): string => {
    const stat = pid === undefined ? null : statOf(pid);
    let stderr = "";
    try {
      stderr = fs.readFileSync(path.join(trig, "stderr"), "utf8").replace(/\s+/g, " ").slice(-300);
    } catch {
      stderr = "no stderr file";
    }
    return `process ${stat === null ? "gone" : `state=${stat.state} threads=${stat.threads} cmdline-empty=${cmdlineEmpty(pid!)} exe-gone=${linkGone(pid!, "exe")} mnt-gone=${linkGone(pid!, "ns/mnt")} handler=${handlerInstalled(pid!)}`}; fixture stderr: ${stderr}`;
  };
  /** Spawns a fixture tree with its stderr in the trigger directory, for \`heldDiag\`. */
  const spawnLogged = (file: string, args: string[], trig: string): ChildProcess => spawn(file, args, { stdio: ["ignore", "ignore", fs.openSync(path.join(trig, "stderr"), "w")] });
  /** The fixture's own reads right before the exit read (the failed proof's seam) and right after the tick that did it. */
  const holdChecks = (state: Seam) => ({
    before: (): void => {
      if (state.forced && state.holdPid !== undefined && state.preHold === undefined) state.preHold = held(state.holdPid);
    },
    afterTick: (): void => {
      if (state.preHold !== undefined && state.postHold === undefined && state.holdPid !== undefined) state.postHold = held(state.holdPid);
    },
  });
  /** A kind the row expects from the exit read of a held leader: a missed hold (the fixture's own reads show it ended) is INVALID, a classifier that read the intact hold differently is a failure. */
  const expectHeldKind = (state: Seam, actual: ExitKind | undefined, expected: ExitKind): void => {
    if (actual !== expected) expect(state.preHold === true && state.postHold === true, `precondition not reached: the held leader exit ended before the exit read finished (read ${actual})`).toBe(true);
    expect(actual).toBe(expected);
  };

  // <exit-read-fault-plumbing>
  interface Plumbed {
    exitReadFault?: ExitReadFault;
  }
  const plumb = (options: Plumbed): Plumbed => ({ exitReadFault: options.exitReadFault });
  // </exit-read-fault-plumbing>

  function closeWindow(sampler: { stop: (markers: Record<string, string>) => ProcessSample }): { final: ProcessSample; audit: string[]; summary: string[] } {
    const lines: string[] = [];
    const spy = vi.spyOn(process.stderr, "write").mockImplementation((chunk: string | Uint8Array) => {
      lines.push(String(chunk));
      return true;
    });
    let final: ProcessSample;
    try {
      final = sampler.stop({});
    } finally {
      spy.mockRestore();
    }
    const printed = lines.join("").split("\n");
    return { final, audit: printed.filter((line) => line.startsWith("SECURITY-PROCESS-AUDIT")), summary: printed.filter((line) => line.startsWith("SECURITY-PROCESS-SUMMARY")) };
  }
  const failureRecorded = (sampler: { peek: () => ProcessSample }): boolean => sampler.peek().records.some((record) => record.proofFailure !== undefined);
  const recordOf = (sample: ProcessSample, runtime: Tracked | undefined): ProcessRecord => {
    const record = sample.records.find((candidate) => candidate.pid === runtime?.pid);
    expect(record, "precondition not reached: the sampler did not record the runtime").toBeDefined();
    return record!;
  };
  const flagged = (final: ProcessSample, record: ProcessRecord): void => {
    expect(final.unsandboxedRuntimes, "the record stays flagged").toContain(record.pid);
    expect(record.clearedBy, "the record was never cleared").toBeUndefined();
    const text = sampleProblems(final, {}).join("\n");
    expect(text).toContain("ran without a sandbox ancestor");
    expect(text).toContain(`pid ${record.pid}`);
  };
  const noClears = (summary: string[]): void => {
    for (const route of ["own", "launcher", "reference", "runtime_ending", "launcher_ended"]) expect(summary[0], `no clear by ${route}`).toContain(`exit_cleared_${route}=0`);
  };
  /** The runtime's whole life from the exit read to the end of a pending wait: bound seconds plus a margin. */
  const pastBound = (): Promise<void> => pause(PENDING_BOUND_MS + 500);

  /*  Own route: the leader finishes after the runtime's own proof, below the real bwrap (the R6 shape)  */

  async function ownWindow(state: Seam, options: Plumbed & { secs?: string; fresh?: number } = {}): Promise<{ trig: string; sampler: ReturnType<typeof startProcessSampler>; child: ChildProcess }> {
    requireHost(["bwrap", "python3"]);
    const trig = scratch();
    const checks = holdChecks(state);
    const sampler = startProcessSampler(() => process.pid, [], 20, {
      // The third reading: two proven ticks first. The proof then fails on the released mount namespace and the exit read follows at once.
      afterStableReading: seamAt(state, 3, (pid) => endLeader(pid, () => held(pid) && linkGone(pid, "ns/mnt"))),
      afterFailedProof: checks.before,
      afterTick: checks.afterTick,
      ...plumb(options),
    });
    const command = fixtureCommand(trig, { FRESH: options.fresh ?? HOLD_FILES, SECS: options.secs ?? "6" });
    const child = spawnLogged(BWRAP_DIE[0], [...BWRAP_DIE.slice(1), "/bin/bash", "-c", command], trig);
    spawned.push(child);
    await until(() => state.forced, "the seam did not run");
    expect(state.reached, `precondition not reached: the leader exit was not held within its bound (${heldDiag(state.runtime?.pid, trig)})`).toBe(true);
    await until(() => failureRecorded(sampler), "the failing tick did not run");
    return { trig, sampler, child };
  }

  /** The leader finished, its thread outlives the bound: pending, then flagged for good although the process fully ends before the window closes. */
  async function ownNever(state: Seam) {
    const window = await ownWindow(state);
    await pastBound();
    touch(window.trig, "end");
    await until(() => ended(state.runtime!), "the runtime did not fully end after its last thread");
    const closed = closeWindow(window.sampler);
    return { ...closed, record: recordOf(closed.final, state.runtime) };
  }
  const assertOwnNever = (state: Seam, run: Awaited<ReturnType<typeof ownNever>>): void => {
    expectHeldKind(state, run.record.proofFailure?.runtimeExit, "empty-n");
    expect(run.record.proofFailure).toMatchObject({ failedWhile: "alive", ownProof: true, escapeEvidence: false });
    expect(run.record.pending).toMatchObject({ state: "expired", route: "runtime-ending", sawLeaderExit: true });
    flagged(run.final, run.record);
    expect(run.summary[0]).toContain("pending_expired=1");
  };

  it("TH-own-live: a runtime whose leader finished while a thread runs (empty-n at the exit read) is never cleared by its own proof, it waits and is flagged when the thread outlives the bound", async () => {
    const state = newSeam();
    const run = await ownNever(state);
    assertOwnNever(state, run);
    expect(run.record.proofFailure!.failedWhile, "not read as exiting").toBe("alive");
    expect(run.summary[0]).toContain("exit_cleared_own=0");
    expect(run.audit.filter((line) => line.includes("(own)"))).toEqual([]);
  });

  it("R6-emptyn-never: the same runtime, route verdict: the runtime-ending record expires flagged and no route clears it", async () => {
    const state = newSeam();
    const run = await ownNever(state);
    assertOwnNever(state, run);
    noClears(run.summary);
    expect(run.audit, "nothing was cleared, so nothing is audited").toEqual([]);
  });

  it("R6-emptyn: the same runtime whose last thread ends inside the bound is cleared by the runtime-ending route and audited with the confirming kind (no new false alarm)", async () => {
    const state = newSeam();
    const window = await ownWindow(state);
    touch(window.trig, "end");
    await until(() => ended(state.runtime!), "the runtime did not fully end after its last thread");
    await pause(300);
    const { final, audit, summary } = closeWindow(window.sampler);
    const record = recordOf(final, state.runtime);
    expectHeldKind(state, record.proofFailure?.runtimeExit, "empty-n");
    expect(record.pending).toMatchObject({ state: "cleared", route: "runtime-ending" });
    expect(record.clearedBy).toBe("runtime-ending");
    expect(record.unsandboxed).toBe(false);
    expect(final.unsandboxedRuntimes).toEqual([]);
    expect(sampleProblems(final, {})).toEqual([]);
    expect(audit.filter((line) => line.includes("runtime exit confirmed after its own proof read while alive (leader exited first)"))).toHaveLength(1);
    expect(audit.join("\n")).toMatch(/exit-confirmed=(Z1|vanished|empty-gone)\b/);
    expect(summary[0]).toContain("exit_cleared_runtime_ending=1");
  });

  /** The surviving thread executes a new program after the leader finished; `exitsInside` lets that program end inside the bound. */
  async function ownRevive(state: Seam, secs: string, exitsInside: boolean) {
    // A program that must end inside the bound gets the shorter hold: the whole chain (hold, exec, program) has to fit into 2 s under load.
    const window = await ownWindow(state, { secs, fresh: exitsInside ? 300_000 : undefined });
    touch(window.trig, "exec");
    await until(() => imageRuns(state.runtime!.pid, secs), "the surviving thread did not execute the new program");
    let insideBound = true;
    if (exitsInside) {
      await until(() => ended(state.runtime!), "the new program did not end");
      insideBound = Date.now() - recordOf(window.sampler.peek(), state.runtime).pending!.sinceMs < PENDING_BOUND_MS - 300;
    } else await pause(400);
    const proof = exitsInside ? undefined : taggedProcessProof(process.pid, `claude ${secs}`);
    const closed = closeWindow(window.sampler);
    return { ...closed, proof, insideBound, exitsInside, record: recordOf(closed.final, state.runtime) };
  }
  const assertRevived = (state: Seam, run: Awaited<ReturnType<typeof ownRevive>>): void => {
    expect(run.insideBound, "precondition not reached: the new program ended after the bound").toBe(true);
    // The rows that must fit the whole chain into the bound use the shorter hold: a leader that is already a zombie leader at the exit read is as good for them.
    expectHeldKind(state, run.record.proofFailure?.runtimeExit, run.exitsInside && run.record.proofFailure?.runtimeExit === "Zn" ? "Zn" : "empty-n");
    expect(run.record.pending).toMatchObject({ state: "expired", route: "runtime-ending", revived: true });
    expect(describeRecords([run.record])).toContain("revived=true");
    flagged(run.final, run.record);
    noClears(run.summary);
  };

  it("TH-own-revive: a surviving thread executes a new program after the leader finished: the record is flagged at once (revived), the new image is judged by its own proof and the record stays flagged", async () => {
    const state = newSeam();
    const run = await ownRevive(state, "6", false);
    assertRevived(state, run);
    expect(run.record.comms, "the record saw the new program").toContain("sleep");
    expect(run.proof, "the new program is a holder with the full sandbox proof").toMatchObject({ holders: 1, proven: 1 });
  });

  it("R6-revive: the same revival, route verdict: pending, then revived and expired although the process is alive and the new program outlives the bound", async () => {
    const state = newSeam();
    const run = await ownRevive(state, "6", false);
    assertRevived(state, run);
    expect(run.summary[0]).toContain("pending_expired=1");
  });

  it("TH-own-revive-exit: the new program ends inside the bound: the record is still flagged, never cleared (the process was never ended in between)", async () => {
    const state = newSeam();
    const run = await ownRevive(state, "0.1", true);
    assertRevived(state, run);
  });

  it("R6-revive-exit: the same, route verdict: no route clears a revived record whose new program fully ended", async () => {
    const state = newSeam();
    const run = await ownRevive(state, "0.1", true);
    assertRevived(state, run);
    expect(run.audit, "nothing was cleared, so nothing is audited").toEqual([]);
    expect(run.summary[0]).toContain("pending_expired=1");
  });

  /*  A single-thread zombie held by its stopped parent: own route (E1 shape) and live-launcher route (E2 shape)  */

  async function zombieWindow(state: Seam, options: Plumbed & { atReading: number }): Promise<{ sampler: ReturnType<typeof startProcessSampler> }> {
    requireHost(["bwrap"]);
    const sampler = startProcessSampler(() => process.pid, [], 20, {
      afterStableReading: seamAt(state, options.atReading, (pid) => {
        const parent = ppidOf(pid);
        signal(parent, "SIGSTOP");
        stopped.push(parent);
        waitSync(() => statOf(parent)?.state === "T");
        signal(pid, "SIGKILL");
        return waitSync(() => zombieSingle(pid));
      }),
      ...plumb(options),
    });
    const child = spawn(BWRAP_DIE[0], [...BWRAP_DIE.slice(1), "/bin/bash", "-c", `(${standIn}) & wait`], { stdio: "ignore" });
    spawned.push(child);
    await until(() => state.forced, "the seam did not run");
    expect(state.reached, "precondition not reached: the runtime was not a single-thread zombie within its bound").toBe(true);
    await until(() => failureRecorded(sampler), "the failing tick did not run");
    return { sampler };
  }

  it("RE-own-control: the same held single-thread zombie without an injected fault is Z1 and cleared by the runtime's own proof, audited with the confirming kind", async () => {
    const state = newSeam();
    const window = await zombieWindow(state, { atReading: 3 });
    const { final, audit, summary } = closeWindow(window.sampler);
    const record = recordOf(final, state.runtime);
    expect(record.proofFailure).toMatchObject({ failedWhile: "exiting", ownProof: true, runtimeExit: "Z1" });
    expect(record.clearedBy).toBe("own");
    expect(record.exitConfirmed).toEqual({ runtime: "Z1" });
    expect(record.unsandboxed).toBe(false);
    expect(sampleProblems(final, {})).toEqual([]);
    expect(audit.filter((line) => line.includes("exiting after a proof read while alive (own)") && line.includes("exit-confirmed=Z1"))).toHaveLength(1);
    expect(summary[0]).toContain("exit_cleared_own=1");
  });

  const reportedUnknown = (final: ProcessSample, record: ProcessRecord, read: string, summary: string[]): void => {
    expect(record.proofFailure).toMatchObject({ runtimeExit: "unknown", exitRead: read, exitReadInjected: true });
    expect(record.pending, "never pending").toBeUndefined();
    expect(record.proofFailure!.pending).toBe("none");
    flagged(final, record);
    noClears(summary);
    expect(describeRecords([record])).toContain(`exit-read=${read} exit-read-injected=true`);
  };

  it("RE-own: an injected EIO on the stat read of the held zombie reads unknown: not cleared by the own proof, flagged", async () => {
    const state = newSeam();
    const window = await zombieWindow(state, { atReading: 3, exitReadFault: (pid, file) => (pid === state.pid && state.forced && file === "stat" ? "EIO" : undefined) });
    const { final, summary } = closeWindow(window.sampler);
    reportedUnknown(final, recordOf(final, state.runtime), "stat:EIO", summary);
  });

  it("RE-exe: an injected EIO on the executable read of the held zombie (empty command line) reads unknown, flagged", async () => {
    const state = newSeam();
    const window = await zombieWindow(state, { atReading: 3, exitReadFault: (pid, file) => (pid === state.pid && state.forced && file === "exe" ? "EIO" : undefined) });
    const { final, summary } = closeWindow(window.sampler);
    reportedUnknown(final, recordOf(final, state.runtime), "exe:EIO", summary);
  });

  it("TH-bracket: a fault on the second full reading only (the first says Z1) reads unknown: the sampler decides on two readings, not one", async () => {
    const state = newSeam();
    let statReads = 0;
    const window = await zombieWindow(state, {
      atReading: 3,
      exitReadFault: (pid, file) => (pid === state.pid && state.forced && file === "stat" ? (++statReads === 2 ? "EIO" : undefined) : undefined),
    });
    const { final, summary } = closeWindow(window.sampler);
    reportedUnknown(final, recordOf(final, state.runtime), "stat:EIO", summary);
    expect(statReads, "precondition not reached: the exit read took two readings").toBeGreaterThanOrEqual(2);
  });

  it("E2-kind: a runtime that is a zombie at its first reading is cleared by the live real bwrap above it, audited with the confirming kind", async () => {
    const state = newSeam();
    const window = await zombieWindow(state, { atReading: 1 });
    const { final, audit, summary } = closeWindow(window.sampler);
    const record = recordOf(final, state.runtime);
    expect(record.proofFailure).toMatchObject({ failedWhile: "exiting", ownProof: false, launcherProof: true, runtimeExit: "Z1" });
    expect(record.clearedBy).toBe("launcher");
    expect(record.exitConfirmed).toEqual({ runtime: "Z1" });
    expect(sampleProblems(final, {})).toEqual([]);
    expect(audit.filter((line) => line.includes("exiting after a proof read while alive (launcher)") && line.includes("exit-confirmed=Z1"))).toHaveLength(1);
    expect(summary[0]).toContain("exit_cleared_launcher=1");
  });

  it("RE-launcher: the same live-launcher shape with an injected EIO at the first reading reads unknown: not cleared by the launcher, flagged", async () => {
    const state = newSeam();
    const window = await zombieWindow(state, { atReading: 1, exitReadFault: (pid, file) => (pid === state.pid && state.forced && file === "stat" ? "EIO" : undefined) });
    const { final, summary } = closeWindow(window.sampler);
    const record = recordOf(final, state.runtime);
    expect(record.proofFailure).toMatchObject({ ownProof: false, launcherProof: true });
    reportedUnknown(final, record, "stat:EIO", summary);
  });

  it("R8-emptyn: a runtime held in empty-n at its first reading below the live inner bwrap that has the full proof is not cleared (the thread still runs) and is flagged", async () => {
    requireHost(["bwrap", "python3"]);
    const state = newSeam();
    const trig = scratch();
    const checks = holdChecks(state);
    const sampler = startProcessSampler(() => process.pid, [], 20, {
      afterStableReading: seamAt(state, 1, (pid) => endLeader(pid, () => held(pid) && linkGone(pid, "ns/mnt"))),
      afterFailedProof: checks.before,
      afterTick: checks.afterTick,
    });
    const child = spawnLogged(BWRAP_DIE[0], [...BWRAP_DIE.slice(1), "/bin/bash", "-c", `(${fixtureCommand(trig, { FRESH: HOLD_FILES })}) & wait`], trig);
    spawned.push(child);
    await until(() => state.forced, "the seam did not run");
    expect(state.reached, `precondition not reached: the leader exit was not held within its bound (${heldDiag(state.runtime?.pid, trig)})`).toBe(true);
    await until(() => failureRecorded(sampler), "the failing tick did not run");
    touch(trig, "end");
    await until(() => ended(state.runtime!), "the runtime did not fully end after its last thread");
    const { final, summary } = closeWindow(sampler);
    const record = recordOf(final, state.runtime);
    expectHeldKind(state, record.proofFailure?.runtimeExit, "empty-n");
    expect(record.proofFailure).toMatchObject({ failedWhile: "alive", ownProof: false, launcherProof: true, escapeEvidence: false });
    expect(record.pending, "never pending").toBeUndefined();
    flagged(final, record);
    noClears(summary);
  });

  /*  Launcher-ended route (MVP-8125 shape): the launcher is stopped through the reference while the gateway lives  */

  const REFERENCE_SOURCE = `
    const { spawn } = require("node:child_process");
    const argv = JSON.parse(process.argv[1]);
    const m = spawn(argv[0], argv.slice(1), { stdio: "ignore" });
    m.on("error", () => {});
    process.on("SIGUSR2", () => m.kill("SIGKILL"));
    setInterval(() => {}, 1000);
  `;

  async function launcherWindow(state: Seam, options: Plumbed & { leaderAfterProof?: boolean; secs?: string; fresh?: number; runtime?: "python" | "node" }) {
    requireHost(["bwrap", "unshare", "python3"]);
    const trig = scratch();
    const outcome = { done: false, reached: false };
    let reference: ChildProcess | undefined;
    const checks = holdChecks(state);
    const sampler = startProcessSampler(() => reference?.pid ?? 0, [], 20, {
      // The third reading stops the launcher through the reference and holds the tick until the inner bwrap is reparented.
      afterStableReading: seamAt(state, 3, (pid) => {
        const inner = track(ppidOf(pid));
        const monitor = track(ppidOf(inner.pid));
        signal(reference!.pid!, "SIGUSR2");
        return waitSync(() => ppidOf(inner.pid) !== monitor.pid);
      }),
      afterFailedProof: (pid) => {
        // The leader finishes between the proof (all own links readable) and the exit read that follows it.
        if (options.leaderAfterProof && state.forced && pid === state.pid && !outcome.done) {
          outcome.done = true;
          outcome.reached = endLeader(pid, () => held(pid));
        }
        checks.before();
      },
      afterTick: checks.afterTick,
      ...plumb(options),
    });
    const command = options.runtime === "node" ? standIn : fixtureCommand(trig, { FRESH: options.fresh ?? HOLD_FILES, SECS: options.secs ?? "6" });
    reference = spawn(process.execPath, ["-e", REFERENCE_SOURCE, JSON.stringify([...KEEP_INNER, "/bin/bash", "-c", command])], { stdio: "ignore" });
    spawned.push(reference);
    await until(() => state.forced, "the seam did not run");
    expect(state.reached, "precondition not reached: the inner bwrap was not reparented within its bound").toBe(true);
    if (options.leaderAfterProof) {
      await until(() => outcome.done, "the failed proof did not reach the leader seam");
      expect(outcome.reached, `precondition not reached: the leader exit was not held within its bound (${heldDiag(state.runtime?.pid, trig)})`).toBe(true);
    }
    await until(() => failureRecorded(sampler), "the failing tick did not run");
    return { trig, sampler, reference };
  }
  const assertLauncherWaiting = (state: Seam, sample: ProcessSample, kind: ExitKind): ProcessRecord => {
    const record = recordOf(sample, state.runtime);
    expectHeldKind(state, record.proofFailure?.runtimeExit, kind);
    expect(record.proofFailure).toMatchObject({ failedWhile: "alive", ownProof: true, escapeEvidence: false, ownUnreadable: "none", launcherIdentity: "verified" });
    expect(record.pending, "pending, not flagged").toMatchObject({ route: "launcher-ended" });
    return record;
  };

  it("LE8-emptyn: a runtime that is alive at the proof and held in empty-n at the exit read is pending and is cleared when its last thread ends, audited with the confirming kind", async () => {
    const state = newSeam();
    const window = await launcherWindow(state, { leaderAfterProof: true });
    const waiting = window.sampler.peek();
    const record = assertLauncherWaiting(state, waiting, "empty-n");
    expect(waiting.unsandboxedRuntimes, "a waiting record counts as flagged").toContain(record.pid);
    touch(window.trig, "end");
    await until(() => ended(state.runtime!), "the runtime did not fully end after its last thread");
    await pause(300);
    const { final, audit, summary } = closeWindow(window.sampler);
    const cleared = recordOf(final, state.runtime);
    expect(cleared.pending?.state).toBe("cleared");
    expect(cleared.clearedBy).toBe("launcher-ended");
    expect(cleared.unsandboxed).toBe(false);
    expect(sampleProblems(final, {})).toEqual([]);
    expect(audit.filter((line) => line.includes("launcher ended first, gateway alive") && /exit-confirmed=(Z1|vanished|empty-gone)\b/.test(line))).toHaveLength(1);
    expect(summary[0]).toContain("exit_cleared_launcher_ended=1");
  });

  it("LE8-emptyn-never: the same runtime whose last thread outlives the bound is flagged for good, although it fully ends before the window closes", async () => {
    const state = newSeam();
    const window = await launcherWindow(state, { leaderAfterProof: true });
    await pastBound();
    touch(window.trig, "end");
    await until(() => ended(state.runtime!), "the runtime did not fully end after its last thread");
    const { final, summary } = closeWindow(window.sampler);
    const record = assertLauncherWaiting(state, final, "empty-n");
    expect(record.pending?.state).toBe("expired");
    flagged(final, record);
    expect(summary[0]).toContain("pending_expired=1");
    noClears(summary);
  });

  async function launcherRevive(state: Seam, secs: string, options: { leaderAfterProof: boolean; exitsInside: boolean }) {
    const window = await launcherWindow(state, { leaderAfterProof: options.leaderAfterProof, secs, fresh: options.exitsInside ? 300_000 : undefined });
    touch(window.trig, "exec");
    await until(() => imageRuns(state.runtime!.pid, secs), "the surviving thread did not execute the new program");
    let insideBound = true;
    if (options.exitsInside) {
      await until(() => ended(state.runtime!), "the new program did not end");
      insideBound = Date.now() - recordOf(window.sampler.peek(), state.runtime).pending!.sinceMs < PENDING_BOUND_MS - 300;
    } else await pause(400);
    const closed = closeWindow(window.sampler);
    return { ...closed, insideBound, record: recordOf(closed.final, state.runtime) };
  }

  it("LE8-revive: the surviving thread executes a new program after the leader finished: the pending record is expired at once (revived) and flagged", async () => {
    const state = newSeam();
    const run = await launcherRevive(state, "6", { leaderAfterProof: true, exitsInside: false });
    expectHeldKind(state, run.record.proofFailure?.runtimeExit, "empty-n");
    expect(run.record.pending).toMatchObject({ state: "expired", route: "launcher-ended", revived: true });
    flagged(run.final, run.record);
    noClears(run.summary);
  });

  it("LE8-revive-exit: the new program ends inside the bound: the record is still flagged, never cleared", async () => {
    const state = newSeam();
    const run = await launcherRevive(state, "0.1", { leaderAfterProof: true, exitsInside: true });
    expect(run.insideBound, "precondition not reached: the new program ended after the bound").toBe(true);
    expectHeldKind(state, run.record.proofFailure?.runtimeExit, run.record.proofFailure?.runtimeExit === "Zn" ? "Zn" : "empty-n");
    expect(run.record.pending).toMatchObject({ state: "expired", route: "launcher-ended", revived: true });
    flagged(run.final, run.record);
    noClears(run.summary);
  });

  it("LE8-revive-alive-entry: a record that entered alive and whose thread executes a different executable that then ends inside the bound is flagged (executable identity), never cleared", async () => {
    const state = newSeam();
    const run = await launcherRevive(state, "0.1", { leaderAfterProof: false, exitsInside: true });
    expect(run.insideBound, "precondition not reached: the new program ended after the bound").toBe(true);
    expect(run.record.pending?.sawLeaderExit, "precondition not reached: a leader exit was seen, so the executable-identity check is not what revived the record").not.toBe(true);
    expect(run.record.proofFailure).toMatchObject({ failedWhile: "alive", ownProof: true, runtimeExit: "alive" });
    expect(run.record.pending).toMatchObject({ state: "expired", route: "launcher-ended", revived: true });
    flagged(run.final, run.record);
    noClears(run.summary);
  });

  it("RE-le: an injected error on the runtime's exit read reads unknown: no launcher-ended entry and flagged at the failing tick; on the settle reads the pending record expires flagged", async () => {
    // Entry: the fault is on from the first read of the runtime's exit.
    const first = newSeam();
    const entry = await launcherWindow(first, { runtime: "node", exitReadFault: (pid, file) => (pid === first.pid && first.forced && file === "stat" ? "EIO" : undefined) });
    signal(first.runtime!.pid, "SIGKILL");
    await until(() => ended(first.runtime!), "the runtime did not end");
    const entered = closeWindow(entry.sampler);
    const record = recordOf(entered.final, first.runtime);
    expect(record.proofFailure).toMatchObject({ failedWhile: "alive", ownProof: true, runtimeExit: "unknown", exitRead: "stat:EIO", exitReadInjected: true, launcherIdentity: "verified", pending: "none" });
    expect(record.pending, "never pending").toBeUndefined();
    flagged(entered.final, record);
    noClears(entered.summary);

    // Settle: a normal entry, then the fault.
    const second = newSeam();
    const flags = { on: false };
    const settle = await launcherWindow(second, { runtime: "node", exitReadFault: (pid, file) => (flags.on && pid === second.pid && file === "stat" ? "EIO" : undefined) });
    expect(settle.sampler.peek().records[0].pending, "precondition not reached: a normal entry is pending").toMatchObject({ state: "waiting", route: "launcher-ended" });
    flags.on = true;
    signal(second.runtime!.pid, "SIGKILL");
    await until(() => ended(second.runtime!), "the runtime did not end");
    await pastBound();
    const settled = closeWindow(settle.sampler);
    const waited = recordOf(settled.final, second.runtime);
    expect(waited.pending?.state).toBe("expired");
    flagged(settled.final, waited);
    noClears(settled.summary);
  });

  it("RE-rt: injected errors on every settle read of a pending runtime-ending record: it never clears and is flagged at the bound although the runtime fully ended", async () => {
    const state = newSeam();
    const flags = { on: false };
    const window = await ownWindow(state, { exitReadFault: (pid) => (flags.on && pid === state.pid ? "EMFILE" : undefined) });
    flags.on = true;
    touch(window.trig, "end");
    await until(() => ended(state.runtime!), "the runtime did not fully end after its last thread");
    await pastBound();
    const { final, summary } = closeWindow(window.sampler);
    const record = recordOf(final, state.runtime);
    expect(record.pending).toMatchObject({ state: "expired", route: "runtime-ending" });
    flagged(final, record);
    noClears(summary);
    expect(summary[0]).toContain("pending_expired=1");
  });

  /*  Reference-ended route: the gateway ends after the runtime's own proof (R1 and R5 shapes)  */

  const holderScriptOf = (runtimeCommand: string): string => `${BWRAP_DIE.map(quote).join(" ")} /bin/bash -c ${quote(runtimeCommand)}; :`;
  const referenceScriptOf = (runtimeCommand: string): string => `/bin/bash -c ${quote(holderScriptOf(runtimeCommand))}; :`;

  /**
   * R -> H -> real bwrap -> runtime (R1 shape): on the third reading the seam optionally ends the runtime's leader (held) and then
   * kills R, so the chain breaks while the runtime lives; with `endHolderAfterMs` the holder is killed later and the runtime ends.
   */
  async function runtimeWindow(state: Seam, options: Plumbed & { runtime: "python" | "node"; heldLeader?: boolean; endHolderAfterMs?: number; secs?: string }) {
    requireHost(["bwrap", "python3"]);
    const trig = scratch();
    const checks = holdChecks(state);
    let reference: ChildProcess | undefined;
    const sampler = startProcessSampler(() => reference?.pid ?? 0, [], 20, {
      afterStableReading: seamAt(state, 3, (pid) => {
        let holder = pid;
        for (let hop = 0; hop < 3; hop++) holder = ppidOf(holder);
        state.holder = track(holder);
        const victim = ppidOf(holder);
        if (options.heldLeader && !endLeader(pid, () => held(pid))) return false;
        signal(victim, "SIGKILL");
        const reached = waitSync(() => (zombieSingle(victim) || statOf(victim) === null) && ppidOf(holder) !== victim);
        if (options.endHolderAfterMs !== undefined) setTimeout(() => endTracked(state.holder!), options.endHolderAfterMs);
        return reached;
      }),
      afterFailedProof: checks.before,
      afterTick: checks.afterTick,
      ...plumb(options),
    });
    const command = options.runtime === "node" ? standIn : fixtureCommand(trig, { FRESH: options.heldLeader ? HOLD_FILES : 0, SECS: options.secs ?? "6" });
    reference = spawnLogged("/bin/bash", ["-c", referenceScriptOf(command)], trig);
    spawned.push(reference);
    await until(() => state.forced, "the seam did not run");
    expect(state.reached, `precondition not reached: the reference did not end as a zombie within its bound, or the leader exit was not held (${heldDiag(state.runtime?.pid, trig)})`).toBe(true);
    await until(() => failureRecorded(sampler), "the failing tick did not run");
    return { trig, sampler };
  }

  it("R1-kind: the reference ends after the runtime's own proof and the runtime ends within the bound: cleared, audited with the confirming kinds of both", async () => {
    const state = newSeam();
    const window = await runtimeWindow(state, { runtime: "node", endHolderAfterMs: 100 });
    await until(() => ended(state.runtime!), "the runtime did not end");
    await pause(300);
    const { final, audit, summary } = closeWindow(window.sampler);
    const record = recordOf(final, state.runtime);
    expect(record.pending).toMatchObject({ state: "cleared", route: "reference-ended" });
    expect(record.clearedBy).toBe("reference-ended");
    expect(record.exitConfirmed?.runtime).toMatch(/^(Z1|X|vanished|empty-gone)$/);
    expect(record.exitConfirmed?.reference).toMatch(/^(Z1|X|vanished|empty-gone)$/);
    expect(sampleProblems(final, {})).toEqual([]);
    expect(audit.filter((line) => line.includes("reference ended after the runtime's own proof") && /exit-confirmed=\w+(-\w+)? reference-exit-confirmed=\w+(-\w+)?/.test(line))).toHaveLength(1);
    expect(summary[0]).toContain("exit_cleared_reference=1");
  });

  it("R1-emptyn-never: the gateway ended and the runtime is held in empty-n with a live thread past the bound: the record expires flagged", async () => {
    const state = newSeam();
    const window = await runtimeWindow(state, { runtime: "python", heldLeader: true });
    await pastBound();
    touch(window.trig, "end");
    await until(() => ended(state.runtime!), "the runtime did not fully end after its last thread");
    const { final, summary } = closeWindow(window.sampler);
    const record = recordOf(final, state.runtime);
    expectHeldKind(state, record.proofFailure?.runtimeExit, "empty-n");
    expect(record.proofFailure).toMatchObject({ failedWhile: "alive", ownProof: true, referenceEnded: true, chain: "broken" });
    expect(record.pending).toMatchObject({ state: "expired", route: "reference-ended" });
    flagged(final, record);
    noClears(summary);
    expect(summary[0]).toContain("pending_expired=1");
  });

  it("R1-revive-exit: the runtime's leader finishes after the entry, its thread executes a new program that ends inside the bound: flagged (revival), never cleared", async () => {
    const state = newSeam();
    const window = await runtimeWindow(state, { runtime: "python", secs: "0.1" });
    const pid = state.runtime!.pid;
    expect(endLeader(pid, () => zombieLeader(pid) || held(pid)), `precondition not reached: the leader did not finish (${heldDiag(pid, window.trig)})`).toBe(true);
    // The sampler's settle reads register the leader exit before the thread executes the new program (the zombie leader persists until then).
    await pause(250);
    touch(window.trig, "exec");
    await until(() => imageRuns(pid, "0.1"), "the surviving thread did not execute the new program");
    await until(() => ended(state.runtime!), "the new program did not end");
    const insideBound = Date.now() - recordOf(window.sampler.peek(), state.runtime).pending!.sinceMs < PENDING_BOUND_MS - 300;
    const { final, summary } = closeWindow(window.sampler);
    expect(insideBound, "precondition not reached: the new program ended after the bound").toBe(true);
    const record = recordOf(final, state.runtime);
    expect(record.pending).toMatchObject({ state: "expired", route: "reference-ended", revived: true });
    flagged(final, record);
    noClears(summary);
  });

  it("R1-RE: injected errors on the runtime's settle reads after the gateway ended: the record never clears and is flagged at the bound although the runtime ended", async () => {
    const state = newSeam();
    const flags = { on: false };
    const window = await runtimeWindow(state, { runtime: "node", exitReadFault: (pid) => (flags.on && pid === state.pid ? "EMFILE" : undefined) });
    flags.on = true;
    endTracked(state.holder!);
    await until(() => ended(state.runtime!), "the runtime did not end");
    await pastBound();
    const { final, summary } = closeWindow(window.sampler);
    const record = recordOf(final, state.runtime);
    expect(record.pending?.route).toBe("reference-ended");
    expect(record.pending?.state).toMatch(/^expired/);
    flagged(final, record);
    noClears(summary);
  });

  /**
   * P (sh, stopped) -> R (python reference with the thread fixture) -> M -> H -> real bwrap -> runtime (R5 shape). On the third
   * reading of the runtime the seam ends R's leader (`held`: held in its exit; else a plain zombie leader), kills M so the chain breaks
   * and ends the holder shortly after, so the runtime's own exit is confirmed while R's thread still runs.
   */
  async function referenceWindow(state: Seam, options: Plumbed & { held: boolean; secs?: string; execAtOnce?: boolean }) {
    requireHost(["bwrap", "python3"]);
    const trig = scratch();
    const checks = holdChecks(state);
    let parent: ChildProcess | undefined;
    const firstChild = (): number => {
      try {
        return Number(fs.readFileSync(`/proc/${parent?.pid}/task/${parent?.pid}/children`, "utf8").trim().split(" ")[0]) || 0;
      } catch {
        return 0;
      }
    };
    const sampler = startProcessSampler(firstChild, [], 20, {
      afterStableReading: seamAt(state, 3, (pid) => {
        let holder = pid;
        for (let hop = 0; hop < 3; hop++) holder = ppidOf(holder);
        state.holder = track(holder);
        const middle = ppidOf(holder);
        const reference = ppidOf(middle);
        state.reference = track(reference);
        state.holdPid = reference;
        signal(parent!.pid!, "SIGSTOP");
        stopped.push(parent!.pid!);
        waitSync(() => statOf(parent!.pid!)?.state === "T");
        // A held reference is read from the cache only once its mount namespace link is gone too (the hold outlasts that by far).
        if (!endLeader(reference, () => (options.held ? held(reference) && linkGone(reference, "ns/mnt") : zombieLeader(reference)))) return false;
        if (options.execAtOnce) touch(trig, "exec");
        signal(middle, "SIGKILL");
        const reached = waitSync(() => (statOf(middle)?.state === "Z" || statOf(middle) === null) && ppidOf(holder) !== middle);
        setTimeout(() => endTracked(state.holder!), 30);
        return reached;
      }),
      afterFailedProof: checks.before,
      afterTick: checks.afterTick,
      ...plumb(options),
    });
    const env = { FRESH: options.held ? REFERENCE_HOLD_FILES : 0, SECS: options.secs ?? "6" };
    parent = spawnLogged("/bin/sh", ["-c", `${fixtureCommand(trig, env, "gateway", ` /bin/bash -c ${quote(referenceScriptOf(standIn))}`)}; :`], trig);
    spawned.push(parent);
    await until(() => state.forced, "the seam did not run");
    expect(state.reached, `precondition not reached: the reference did not reach its leader-exit shape, or the chain did not break, within its bound (${heldDiag(state.holdPid, trig)})`).toBe(true);
    await until(() => failureRecorded(sampler), "the failing tick did not run");
    return { trig, sampler };
  }
  const assertReferenceExpired = (final: ProcessSample, record: ProcessRecord, summary: string[]): void => {
    expect(record.proofFailure).toMatchObject({ ownProof: true, chain: "broken", reference: "cached", referenceEnded: false, pending: "expired-reference" });
    expect(record.pending).toMatchObject({ state: "expired-reference", route: "reference-ended" });
    flagged(final, record);
    noClears(summary);
    expect(summary[0]).toContain("pending_expired=1");
  };

  it("R5-emptyn: a reference held in empty-n (its thread still runs) while the runtime's own exit is confirmed is pending and expires on the reference, flagged", async () => {
    const state = newSeam();
    const window = await referenceWindow(state, { held: true });
    await until(() => ended(state.runtime!), "the runtime did not end");
    await pastBound();
    touch(window.trig, "end");
    const { final, summary } = closeWindow(window.sampler);
    const record = recordOf(final, state.runtime);
    expectHeldKind(state, record.proofFailure?.referenceExit, "empty-n");
    assertReferenceExpired(final, record, summary);
  });

  it("R5-revive: the reference's thread executes a new program after the leader finished: the reference was never ended, the record expires on the reference, flagged", async () => {
    const state = newSeam();
    const window = await referenceWindow(state, { held: true, execAtOnce: true, secs: "6" });
    await until(() => ended(state.runtime!), "the runtime did not end");
    await until(() => imageRuns(state.reference!.pid, "6", "gateway"), "the reference's thread did not execute the new program");
    await pastBound();
    const { final, summary } = closeWindow(window.sampler);
    const record = recordOf(final, state.runtime);
    expectHeldKind(state, record.proofFailure?.referenceExit, "empty-n");
    assertReferenceExpired(final, record, summary);
  });

  it("RE-ref: an injected error on the reference's exit read reads unknown: it is no reference ending at the failing tick (flagged, never pending), and on the settle reads the record expires on the reference", async () => {
    // Entry: the fault is on from the reference's first exit read.
    const first = newSeam();
    const entry = await referenceWindow(first, { held: false, exitReadFault: (pid, file) => (first.holdPid !== undefined && pid === first.holdPid && file === "stat" ? "EIO" : undefined) });
    await until(() => ended(first.runtime!), "the runtime did not end");
    const entered = closeWindow(entry.sampler);
    const record = recordOf(entered.final, first.runtime);
    expect(record.proofFailure).toMatchObject({ ownProof: true, chain: "broken", referenceEnded: false, referenceExit: "unknown", referenceExitRead: "stat:EIO", exitReadInjected: true, pending: "none" });
    expect(record.pending, "never pending").toBeUndefined();
    flagged(entered.final, record);
    noClears(entered.summary);

    // Settle: a normal entry (the reference is a zombie leader whose thread runs), then the fault on the reference's reads.
    const second = newSeam();
    const flags = { on: false };
    const settle = await referenceWindow(second, { held: false, exitReadFault: (pid, file) => (flags.on && second.holdPid !== undefined && pid === second.holdPid && file === "stat" ? "EIO" : undefined) });
    flags.on = true;
    await until(() => ended(second.runtime!), "the runtime did not end");
    await pastBound();
    const settled = closeWindow(settle.sampler);
    assertReferenceExpired(settled.final, recordOf(settled.final, second.runtime), settled.summary);
  });

  /*  Classification of real processes, no sampler: the exit decision the sampler takes, read in a tight loop against raw thread counts  */

  interface Trace {
    kinds: ExitKind[];
    /** Confirmed decisions read while the raw thread count was 2 or more on both sides of the read. */
    violations: ExitKind[];
    confirmed: ExitKind[];
  }
  const observe = (item: Tracked, done: (trace: Trace, kind: ExitKind) => boolean, boundMs: number): Trace => {
    const trace: Trace = { kinds: [], violations: [], confirmed: [] };
    for (const end = Date.now() + boundMs; Date.now() < end; sleepSync(1)) {
      const before = statOf(item.pid);
      const now = endedNow(item.pid, item.startTicks);
      const after = statOf(item.pid);
      if (trace.kinds.at(-1) !== now.kind) trace.kinds.push(now.kind);
      if (now.ended) trace.confirmed.push(now.kind);
      if (now.ended && before !== null && after !== null && before.threads >= 2 && after.threads >= 2) trace.violations.push(now.kind);
      if (done(trace, now.kind)) break;
    }
    return trace;
  };
  async function startFixture(secs = "6"): Promise<{ trig: string; item: Tracked }> {
    requireHost(["python3"]);
    const trig = scratch();
    const child = spawn("/bin/bash", ["-c", fixtureCommand(trig, { FRESH: HOLD_FILES, SECS: secs })], { stdio: "ignore" });
    spawned.push(child);
    const item = track(child.pid!);
    await until(() => handlerInstalled(item.pid), "the stand-in did not install its handler");
    return { trig, item };
  }

  it("TH1: a real process whose leader ends alone reads empty-n, then Zn, and only Z1 or vanished once its last thread ended: never a confirmed exit while a thread runs", async () => {
    const { trig, item } = await startFixture();
    signal(item.pid, "SIGUSR1");
    let leaderSeen = 0;
    const trace = observe(
      item,
      (seen, kind) => {
        if (kind === "Zn") leaderSeen += 1;
        if (leaderSeen === 3) touch(trig, "end");
        return seen.confirmed.length >= 3;
      },
      30_000,
    );
    expect(trace.violations, "a confirmed exit was read while a thread ran").toEqual([]);
    expect(trace.kinds, "precondition not reached: the held leader exit was not read (empty-n)").toContain("empty-n");
    expect(trace.kinds).toContain("Zn");
    expect(trace.confirmed.length, "the process was read as ended once its last thread ended").toBeGreaterThanOrEqual(3);
    expect(["Z1", "vanished"], "the confirming kind").toContain(trace.confirmed[0]);
    expect(trace.kinds.indexOf("empty-n")).toBeLessThan(trace.kinds.indexOf("Zn"));
  });

  it("TH2: a surviving thread that executes a new program after the leader ended revives the process under the same pid and start time: from the leader exit to the revival no reading is a confirmed exit", async () => {
    const { trig, item } = await startFixture("6");
    signal(item.pid, "SIGUSR1");
    let leaderSeen = 0;
    let revived = false;
    const trace = observe(
      item,
      (seen, kind) => {
        if (kind === "Zn") leaderSeen += 1;
        if (leaderSeen === 3) touch(trig, "exec");
        revived = imageRuns(item.pid, "6");
        return revived && seen.kinds.at(-1) === "alive";
      },
      30_000,
    );
    expect(trace.confirmed, "a confirmed exit was read between the leader exit and the revival").toEqual([]);
    expect(revived, "precondition not reached: the surviving thread did not execute the new program").toBe(true);
    expect(trace.kinds, "precondition not reached: the held leader exit was not read (empty-n)").toContain("empty-n");
    expect(sameProcess(item), "the same pid and start time run the new program").toBe(true);
  });

  it("TH3: the native runtime killed by SIGKILL (a group exit): no reading is a confirmed exit while a thread of it runs, and it ends in a confirmed kind (observation)", async () => {
    const binary = path.resolve("node_modules/@anthropic-ai/claude-agent-sdk-linux-x64/claude");
    if (!fs.existsSync(binary)) throw new Error("host prerequisite missing: native runtime");
    const home = scratch();
    const child = spawn(binary, ["--print", "--input-format", "stream-json", "--output-format", "stream-json", "--verbose"], { stdio: ["pipe", "ignore", "ignore"], env: { PATH: process.env.PATH ?? "/usr/bin:/bin", HOME: home } });
    spawned.push(child);
    await pause(1500);
    const item = track(child.pid!);
    expect(statOf(item.pid), "precondition not reached: the native runtime did not start").not.toBeNull();
    signal(item.pid, "SIGKILL");
    const trace = observe(item, (seen) => seen.confirmed.length >= 3, 15_000);
    expect(trace.violations, "a confirmed exit was read while a thread ran").toEqual([]);
    expect(trace.confirmed.length, "the runtime ended in a confirmed kind").toBeGreaterThanOrEqual(1);
    process.stderr.write(`SECURITY-THREAD-EXIT row=TH3 kinds=${trace.kinds.join(">")} violations=${trace.violations.length}\n`);
  });
});

/**
 * The reference resolver (MVP-8090 rev 3) over a fake `/proc`: the cache of the reference's namespace links per identity,
 * live-first comparison and the start-time bracket. The fake stands in for a reference that no unprivileged real process can
 * be made to leave at a chosen moment; R0 and R1 run the same tracker against real processes.
 */
describe("process sampler reference resolver", () => {
  const LINKS = { pid: "pid:[1]", user: "user:[2]", mnt: "mnt:[3]" };
  function fake(initial: { startTicks?: string; state?: string; cmdline?: string; links?: Partial<Record<"pid" | "user" | "mnt", string | null>> } = {}) {
    const proc = { startTicks: initial.startTicks ?? "100", state: initial.state ?? "S", cmdline: initial.cmdline ?? "gateway", links: { ...LINKS, ...initial.links } as Record<"pid" | "user" | "mnt", string | null>, gone: false, changeStartAfterInfoCalls: Infinity, infoCalls: 0 };
    const io: ReferenceIo = {
      info: () => {
        proc.infoCalls += 1;
        return proc.gone ? null : { startTicks: proc.infoCalls > proc.changeStartAfterInfoCalls ? "999" : proc.startTicks, state: proc.state, cmdline: proc.cmdline };
      },
      link: (_pid, kind) => (proc.gone ? null : proc.links[kind]),
    };
    return { proc, io };
  }

  it("a readable live link equal to the cache is used live, and nothing changed", () => {
    const { io } = fake();
    const tracker = createReferenceTracker(io);
    const reference = tracker.begin(10);
    expect(reference.hasCache).toBe(true);
    expect(reference.link("mnt")).toEqual({ value: LINKS.mnt, source: "live" });
    expect(tracker.changed()).toBe(0);
  });

  it("an unreadable live link falls back to the cache taken while the reference was healthy", () => {
    const { proc, io } = fake();
    const tracker = createReferenceTracker(io);
    tracker.begin(10);
    proc.links.mnt = null;
    proc.state = "Z";
    expect(tracker.begin(10).link("mnt")).toEqual({ value: LINKS.mnt, source: "cached" });
    expect(tracker.begin(10).link("pid")).toEqual({ value: LINKS.pid, source: "live" });
  });

  it("without a cache an unreadable link stays unreadable", () => {
    const { io } = fake({ state: "Z", links: { mnt: null } });
    const tracker = createReferenceTracker(io);
    const reference = tracker.begin(10);
    expect(reference.hasCache).toBe(false);
    expect(reference.link("mnt")).toEqual({ value: null, source: "missing" });
  });

  it("a readable live link that differs from the cache is counted and the live value is returned", () => {
    const { proc, io } = fake();
    const tracker = createReferenceTracker(io);
    tracker.begin(10);
    proc.links.mnt = "mnt:[99]";
    expect(tracker.begin(10).link("mnt")).toEqual({ value: "mnt:[99]", source: "live" });
    expect(tracker.changed()).toBe(1);
  });

  it("a new identity (another start time) gets no cache from the old one, and the old cache is not used for it", () => {
    const { proc, io } = fake();
    const tracker = createReferenceTracker(io);
    tracker.begin(10);
    proc.startTicks = "200";
    proc.state = "Z";
    proc.links.mnt = null;
    const reference = tracker.begin(10);
    expect(reference.hasCache).toBe(false);
    expect(reference.link("mnt")).toEqual({ value: null, source: "missing" });
  });

  it.each([
    ["a zombie", { state: "Z" }],
    ["a dead process (X)", { state: "X" }],
    ["an empty command line", { cmdline: "" }],
  ])("no cache is captured while the reference is ending: %s", (_name, partial) => {
    const { io } = fake(partial);
    expect(createReferenceTracker(io).begin(10).hasCache).toBe(false);
  });

  it("no cache is captured when a link cannot be read, or when the start time changes during the capture", () => {
    expect(createReferenceTracker(fake({ links: { user: null } }).io).begin(10).hasCache).toBe(false);
    const { proc, io } = fake();
    proc.changeStartAfterInfoCalls = 1;
    expect(createReferenceTracker(io).begin(10).hasCache).toBe(false);
  });

  it("a live link read across a start-time change is not used", () => {
    const { proc, io } = fake();
    const tracker = createReferenceTracker(io);
    const reference = tracker.begin(10);
    proc.changeStartAfterInfoCalls = proc.infoCalls;
    expect(reference.link("mnt")).toEqual({ value: LINKS.mnt, source: "cached" });
  });

  it("an unreadable reference has no identity, no cache and reads nothing", () => {
    const { proc, io } = fake();
    proc.gone = true;
    const reference = createReferenceTracker(io).begin(10);
    expect(reference.id).toBeNull();
    expect(reference.link("pid")).toEqual({ value: null, source: "missing" });
  });

  it("the runtime's own side is never cached: a link that was readable once and is gone now is unreadable", async () => {
    const { io } = fake();
    const reference = createReferenceTracker(io).begin(10);
    const child = spawn("sleep", ["5"], { stdio: "ignore" });
    const exited = new Promise((resolve) => child.once("exit", resolve));
    expect(sameNamespace(child.pid!, reference, "pid").result, "precondition not reached: the child's link was not readable").not.toBe("unreadable");
    child.kill("SIGKILL");
    await exited;
    expect(sameNamespace(child.pid!, reference, "pid")).toMatchObject({ result: "unreadable", ownUnreadable: true });
  });
});

/** Row attribution (MVP-8090 rev 3): every summary line names its row by an id derived from the test's file and full name. */
describe("process sampler row attribution", () => {
  const FILE = "src/tests/example.test.ts";

  it("the id is the plain leading token of the last segment plus a hash of file and full name; any other leading text gives the prefix t", () => {
    expect(deriveRowId(`/work/tree/${FILE}`, "d > E1: a runtime")).toMatch(/^E1-[0-9a-f]{10}$/);
    expect(deriveRowId(FILE, "d > control G1: a runtime")).toMatch(/^t-[0-9a-f]{10}$/);
    expect(deriveRowId(FILE, `d > ${"x".repeat(60)}: long`)).toMatch(/^t-[0-9a-f]{10}$/);
    expect(deriveRowId(FILE, "d > IF.detached-kill: SIGKILL of the gateway")).toMatch(/^IF\.detached-kill-[0-9a-f]{10}$/);
  });

  it("two names with the same prefix get different ids, and the same name in another file does too", () => {
    expect(deriveRowId(FILE, "control: first")).not.toBe(deriveRowId(FILE, "control: second"));
    expect(deriveRowId(FILE, "d > E1: same")).not.toBe(deriveRowId("src/tests/other.test.ts", "d > E1: same"));
    expect(deriveRowId(`/a/${FILE}`, "d > E1: same")).toBe(deriveRowId(`/b/${FILE}`, "d > E1: same"));
  });

  it("the running test reads its own id through the global state, with the real describe nesting", () => {
    const state = (globalThis as Record<symbol, { getState: () => { testPath: string } }>)[Symbol.for("expect-global")].getState();
    expect(currentRowId()).toBe(deriveRowId(state.testPath, "process sampler row attribution > the running test reads its own id through the global state, with the real describe nesting"));
  });

  it("a window's summary line carries the row id of the test that started it and the number of flagged records", async () => {
    const child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)", "cli.js"], { stdio: "ignore" });
    const sampler = startProcessSampler(() => process.pid, []);
    const deadline = Date.now() + 10_000;
    while (sampler.peek().runtimesSeen === 0 && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 25));
    const lines: string[] = [];
    const spy = vi.spyOn(process.stderr, "write").mockImplementation((chunk: string | Uint8Array) => {
      lines.push(String(chunk));
      return true;
    });
    try {
      sampler.stop({});
    } finally {
      spy.mockRestore();
      child.kill("SIGKILL");
    }
    const summary = lines.join("").split("\n").filter((line) => line.startsWith("SECURITY-PROCESS-SUMMARY"));
    expect(summary, "precondition not reached: the runtime stand-in was not recorded").toHaveLength(1);
    expect(summary[0]).toContain(`row=${currentRowId()} flagged=1`);
  });

  it("a row id that matches a run marker is withheld", async () => {
    const sampler = startProcessSampler(() => process.pid, []);
    const child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)", "cli.js"], { stdio: "ignore" });
    const deadline = Date.now() + 10_000;
    while (sampler.peek().runtimesSeen === 0 && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 25));
    const lines: string[] = [];
    const spy = vi.spyOn(process.stderr, "write").mockImplementation((chunk: string | Uint8Array) => {
      lines.push(String(chunk));
      return true;
    });
    try {
      sampler.stop({ synthetic: currentRowId() });
    } finally {
      spy.mockRestore();
      child.kill("SIGKILL");
    }
    expect(lines.join("")).toContain("row=withheld");
    expect(lines.join("").includes(currentRowId())).toBe(false);
  });
});

/**
 * The pieces the concurrent roles of the route matrix rest on (MVP-8118): the sandbox proof of the processes that carry a
 * run-owned tag, the observer a caller can hang on a sampler tick, and the reference-changed mapping every window verdict
 * now consumes. Every stand-in is a real process tree below this test worker (the reference); a row waits until its own
 * observation shows the state under test.
 */
describe("tagged role processes and the sampler observer", () => {
  const IDLE = "setInterval(() => {}, 1000)";
  const BWRAP = ["bwrap", "--die-with-parent", "--ro-bind", "/", "/", "--unshare-user", "--unshare-pid", "--dev", "/dev", "--proc", "/proc"];
  const children: ChildProcess[] = [];
  afterEach(() => {
    for (const child of children.splice(0)) {
      for (const pid of [...descendants(child.pid!), child.pid!]) {
        try {
          process.kill(pid, "SIGKILL");
        } catch {
          // Already gone.
        }
      }
    }
  });

  const newTag = (): string => `ROLE-T1-${randomBytes(4).toString("hex")}`;
  const start = (command: string, args: string[]): ChildProcess => {
    const child = spawn(command, args, { stdio: "ignore" });
    children.push(child);
    return child;
  };
  /** Polls until `done` holds (bounded); a slow host delays a row but never lets it pass without having looked. */
  async function until(done: () => boolean, what: string): Promise<void> {
    const deadline = Date.now() + 30_000;
    while (!done() && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 25));
    expect(done(), `precondition not reached: ${what}`).toBe(true);
  }

  it("TP1: a tagged process below the real bwrap, in pid, user and mount namespaces of its own, is proven, and the real bwrap holding the tag is no holder", async () => {
    requireHost(["bwrap"]);
    const tag = newTag();
    start(BWRAP[0], [...BWRAP.slice(1), process.execPath, "-e", IDLE, tag]);
    await until(() => taggedProcessProof(process.pid, tag).holders >= 1, "the tagged process was not seen");
    // The proof of a live holder is stable: read again until it is proven (a process in the middle of its start is read once more).
    let proof = taggedProcessProof(process.pid, tag);
    await until(() => (proof = taggedProcessProof(process.pid, tag)).proven >= 1, "the tagged process was never proven");
    expect(proof.holders).toBe(1);
    expect(proof.proven).toBe(1);
    expect(proof.unproven).toEqual([]);
    expect(proof.provenIds).toEqual(proof.holderIds);
  });

  it("TP2: a tagged process outside any sandbox is unproven with its pid; the result holds no tag, command line or marker", async () => {
    requireHost(["bwrap"]);
    const tag = newTag();
    const child = start(process.execPath, ["-e", IDLE, tag]);
    await until(() => taggedProcessProof(process.pid, tag).holders >= 1, "the tagged process was not seen");
    const proof = taggedProcessProof(process.pid, tag);
    expect(proof.proven).toBe(0);
    expect(proof.unproven.map((failed) => failed.pid)).toEqual([child.pid]);
    expect(proof.unproven[0].detail).toMatch(/real-bwrap=false same-ns pid=true user=true mnt=true/);
    const printed = JSON.stringify(proof);
    expect(printed.includes(tag) || printed.includes("setInterval")).toBe(false);
    expect(detect([{ name: "proof", text: printed }], markers.values)).toEqual([]);
  });

  it("TP3: without a tagged process there is no holder and nothing is proven", async () => {
    requireHost(["bwrap"]);
    const proof = taggedProcessProof(process.pid, newTag());
    expect(proof).toEqual({ holders: 0, proven: 0, unproven: [], holderIds: [], provenIds: [] });
  });

  it("TP4: only the real bwrap holds the tag (the process below it no longer does): no holder, nothing proven", async () => {
    requireHost(["bwrap"]);
    const tag = newTag();
    // The shell holds the tag only until it execs `sleep`; the bwrap and its pid-1 copy keep it in their arguments.
    const outer = start(BWRAP[0], [...BWRAP.slice(1), "/bin/bash", "-c", "exec sleep 60", "bash", tag]);
    const commsBelow = (): string[] =>
      descendants(outer.pid!).map((pid) => {
        try {
          return fs.readFileSync(`/proc/${pid}/comm`, "utf8").trim();
        } catch {
          return "";
        }
      });
    await until(() => commsBelow().includes("sleep"), "the tagged shell did not exec sleep");
    const bwrapsHoldingTheTag = descendants(outer.pid!).concat(outer.pid!).filter((pid) => {
      try {
        return fs.readFileSync(`/proc/${pid}/cmdline`).toString("latin1").includes(tag) && fs.readFileSync(`/proc/${pid}/comm`, "utf8").trim() === "bwrap";
      } catch {
        return false;
      }
    });
    expect(bwrapsHoldingTheTag.length, "precondition not reached: no bwrap holds the tag").toBeGreaterThanOrEqual(1);
    const proof = taggedProcessProof(process.pid, tag);
    expect(proof).toEqual({ holders: 0, proven: 0, unproven: [], holderIds: [], provenIds: [] });
  });

  it("AT1: afterTick delivers the tick's processes after the sampler has written their records and windows", async () => {
    requireHost(["bwrap"]);
    const tag = newTag();
    let sampler: ReturnType<typeof startProcessSampler> | undefined;
    let child: ChildProcess | undefined;
    const firstSight: { record?: boolean; window?: boolean; fields?: boolean } = {};
    sampler = startProcessSampler(() => process.pid, [tag], 20, {
      afterTick: (processes) => {
        const info = processes.find((candidate) => candidate.pid === child?.pid);
        if (!info || firstSight.record !== undefined) return;
        const seen = sampler!.peek();
        firstSight.record = seen.records.some((record) => record.pid === info.pid);
        firstSight.window = seen.windows[tag] !== undefined;
        firstSight.fields = info.ppid === process.pid && info.cmdline.includes(tag) && info.comm.length > 0 && info.startTicks.length > 0;
      },
    });
    child = start(process.execPath, ["-e", IDLE, "cli.js", tag]);
    await until(() => firstSight.record !== undefined, "the observer never saw the stand-in");
    const sample = sampler.stop({});
    expect(firstSight).toEqual({ record: true, window: true, fields: true });
    expect(sample.unsandboxedRuntimes).toContain(child.pid);
  });

  it("AT2: an observer that throws ends nothing and changes no verdict", async () => {
    requireHost(["bwrap"]);
    const tag = newTag();
    let calls = 0;
    const sampler = startProcessSampler(() => process.pid, [tag], 20, {
      afterTick: () => {
        calls += 1;
        throw new Error("observer failure");
      },
    });
    const child = start(process.execPath, ["-e", IDLE, "cli.js", tag]);
    await until(() => sampler.peek().records.some((record) => record.pid === child.pid), "the stand-in was not recorded");
    await until(() => calls >= 3, "the observer was not called on later ticks");
    const sample = sampler.stop({});
    expect(sample.unsandboxedRuntimes).toContain(child.pid);
    expect(sample.windows[tag]).toBeDefined();
  });

  it("AT3: what the observer receives is frozen: a write to it throws, and the sampler's records are unchanged", async () => {
    requireHost(["bwrap"]);
    const tag = newTag();
    const outcome: { frozen?: boolean; writeThrew?: boolean; pushThrew?: boolean; argvThrew?: boolean } = {};
    const sampler = startProcessSampler(() => process.pid, [tag], 20, {
      afterTick: (processes: readonly TickProcess[]) => {
        if (outcome.frozen !== undefined || processes.length === 0) return;
        const first = processes[0];
        outcome.frozen = Object.isFrozen(processes) && Object.isFrozen(first) && Object.isFrozen(first.argv);
        const attempt = (write: () => void): boolean => {
          try {
            write();
            return false;
          } catch {
            return true;
          }
        };
        outcome.writeThrew = attempt(() => {
          (first as { cmdline: string }).cmdline = "changed";
        });
        outcome.pushThrew = attempt(() => {
          (processes as TickProcess[]).push(first);
        });
        outcome.argvThrew = attempt(() => {
          (first.argv as string[]).push("changed");
        });
        throw new Error("observer failure after mutating");
      },
    });
    const child = start(process.execPath, ["-e", IDLE, "cli.js", tag]);
    await until(() => outcome.frozen !== undefined && sampler.peek().records.some((record) => record.pid === child.pid), "the observer or the record was missing");
    const sample = sampler.stop({});
    expect(outcome).toEqual({ frozen: true, writeThrew: true, pushThrew: true, argvThrew: true });
    const record = sample.records.find((candidate) => candidate.pid === child.pid)!;
    expect(record.argvShape.includes("changed")).toBe(false);
    expect(sample.unsandboxedRuntimes).toContain(child.pid);
  });

  it("Q8: a sample whose reference changed reports it, with the number of reads, and a sample without a change does not", () => {
    requireHost(["bwrap"]);
    const sample = (referenceChanged: number): ProcessSample => ({ referenceChanged, unsandboxedRuntimes: [], runtimesSeen: 0, windows: {}, records: [], clears: [] });
    expect(sampleProblems(sample(1), {})).toEqual(["the reference process's namespaces changed during the window (1 read(s) differed from the cache)"]);
    expect(sampleProblems(sample(3), {})).toEqual(["the reference process's namespaces changed during the window (3 read(s) differed from the cache)"]);
    expect(sampleProblems(sample(0), {})).toEqual([]);
  });
});
