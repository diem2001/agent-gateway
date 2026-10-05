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
  describeRecords,
  sampleProblems,
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
    expect(line).toMatch(/^SECURITY-EVIDENCE suite=t1 commit=[0-9a-f]{40} tree=[0-9a-f]{40} tracked_changes=\d+ claude_code_version=2\.0\.\d+ sdk=0\.1\.\d+ bwrap=\S+ node=v\d+/);
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
    const sample = sampler.stop();
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
    expect(shape).toMatch(/^node cli\.js --mcp-config <len \d+> --x=<len \d+> <len \d+> <len \d+> sh$/);
    for (const forbidden of [token, marker, "127.0.0.1", "jira", "Bearer"]) expect(shape).not.toContain(forbidden);
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
    expect(describeRecords([{ ...record, argvShape: `leak ${marker}` }], { marker })).toBe("[process records withheld: a marker was detected]");
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
    const sample = sampler.stop();
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
  async function stages(start: () => ChildProcess, steps: Stage[], markers: Record<string, string> = {}): Promise<{ snapshots: (ProcessSample | undefined)[]; final: ProcessSample; audit: string[] }> {
    const sampler = startProcessSampler(() => process.pid, []);
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
    return { snapshots, final, audit: lines.join("").split("\n").filter((line) => line.startsWith("SECURITY-PROCESS-AUDIT")) };
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
      const { snapshots, audit } = await stages(
        () => spawn(named, ["-c", `/bin/sh -c 'sleep 3; :' sh cli.js --${marker}; :`, "sh", "cli.js", `--${marker}`], { stdio: "ignore" }),
        [{ name: "both candidates recorded", until: (seen) => seen.records.length >= 2 }],
        withMarkers ? { synthetic: marker } : {},
      );
      expect(snapshots[0], "precondition not reached: the marker-named launcher and its child were not both recorded").toBeDefined();
      expect(audit.length, "precondition not reached: no audit line was printed").toBeGreaterThanOrEqual(2);
      for (const line of audit) expect(line.includes(marker), "an audit line carried the synthetic name").toBe(false);
      expect(audit.some((line) => line.includes("comm sh exe") && line.includes("verdict=launcher")), "the allowlisted process lost its detail").toBe(true);
    }
  });
});
