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
  createReferenceTracker,
  currentRowId,
  deriveRowId,
  describeRecords,
  endedNow,
  exitConfirmed,
  exitKind,
  exitProofClears,
  flagAfterProofFailure,
  referenceEndedPending,
  referenceSymptom,
  resolvePending,
  sameNamespace,
  sampleProblems,
  type ExitReading,
  type ReferenceIo,
  type ProcessRecord,
  type MatrixRow,
  type Surface,
} from "./helpers/security-matrix.js";
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
    const failed = describeRecords([{ ...record, proofFailure: { failedWhile: "exiting", ownProof: false, launcherProof: true, escapeEvidence: false, ownUnreadable: "mnt", reference: "cached", chain: "broken", referenceEnded: true, runtimeExit: "Z1", pending: "waiting" }, clearedBy: "reference-ended", provedReferenceCached: 2 }], { marker });
    expect(failed).toContain("proof-failure [failed-while=exiting own-proof=false launcher-proof=true escape-evidence=false own-unreadable=mnt reference=cached chain=broken reference-ended=true runtime-exit=Z1 pending=waiting] cleared-by=reference-ended proved-reference-cached=2");
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
  afterEach(() => {
    // A holder the exit seam stopped is continued first, then every process of the fixture is killed.
    for (const pid of stoppedPids.splice(0)) {
      try {
        process.kill(pid, "SIGCONT");
      } catch {
        // Already gone.
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
      expect(summary[0]).toMatch(/^SECURITY-PROCESS-SUMMARY records=\d+ runtime=\d+ launcher=\d+ other=\d+ descendant=\d+ unresolved=\d+ unresolved_unreadable=\d+ unresolved_torn=\d+ unresolved_unread=\d+ flagged_unreadable=\d+ failed_exiting=\d+ failed_alive=\d+ failed_own_proof=\d+ failed_launcher_proof=\d+ failed_escape_evidence=\d+ exit_cleared_own=\d+ exit_cleared_launcher=\d+ exit_cleared_reference=\d+ pending_expired=\d+ proved_reference_cached=\d+ failed_reference_cached=\d+ failed_reference_missing=\d+ failed_own_unreadable=\d+ failed_chain_broken=\d+ reference_changed=\d+ row=(none|withheld|[A-Za-z0-9().,_-]+-[0-9a-f]{10}) flagged=\d+$/);
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
  ])("exit classifier: %s", (_name, given, expected) => {
    expect(exitConfirmed(given)).toBe(expected);
  });

  const reference = (partial: Partial<Parameters<typeof referenceEndedPending>[0]> = {}) => ({ ownProof: true, launcherProof: false, referenceEnded: true, symptom: true, escapeEvidence: false, cacheExists: true, ...partial });

  it.each([
    ["T-ref: all four conditions hold", reference(), true],
    ["T-ref: no own proof (first tick)", reference({ ownProof: false }), false],
    ["T-ref: launcher proof only, no own proof", reference({ ownProof: false, launcherProof: true }), false],
    ["T-ref: reference alive (not ended)", reference({ referenceEnded: false }), false],
    ["T-ref: reference not confirmed ended (a zombie leader whose threads run)", reference({ referenceEnded: exitConfirmed({ vanished: false, startChanged: false, state: "Z", threads: 3, cmdline: "", exe: "gone" }) }), false],
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
    ["exit confirmed within the bound clears", { elapsedMs: 100, exitConfirmed: true, final: false }, "cleared"],
    ["no exit yet inside the bound waits", { elapsedMs: 100, exitConfirmed: false, final: false }, "waiting"],
    ["no exit at the bound expires", { elapsedMs: PENDING_BOUND_MS + 1, exitConfirmed: false, final: false }, "expired"],
    ["an exit seen only after the bound does not clear", { elapsedMs: PENDING_BOUND_MS + 1, exitConfirmed: true, final: false }, "expired"],
    ["no exit at stop() expires", { elapsedMs: 100, exitConfirmed: false, final: true }, "expired"],
  ] as const)("pending: %s", (_name, given, expected) => {
    expect(resolvePending(given)).toBe(expected);
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
