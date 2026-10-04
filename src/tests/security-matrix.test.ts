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
  type ProcessRecord,
  type MatrixRow,
  type Surface,
} from "./helpers/security-matrix.js";
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
  // leftover or another session's fixture, and no kill path ever matches a shared literal tag.
  const fixtureTags: string[] = [];
  afterEach(() => {
    for (const tag of fixtureTags.splice(0)) killRun({ tag });
  });

  it("the process sampler flags an agent runtime without a bwrap ancestor, and not one inside bwrap, and times a tag", async () => {
    requireHost(["bwrap"]);
    const idle = "setInterval(() => {}, 1000)";
    const suffix = randomBytes(6).toString("hex");
    const [bareTag, wrappedTag, absentTag] = [`T1-BARE-${suffix}`, `T1-WRAPPED-${suffix}`, `T1-ABSENT-${suffix}`];
    fixtureTags.push(bareTag, wrappedTag);
    const bare = spawn("node", ["-e", idle, "cli.js", bareTag], { stdio: "ignore" });
    const wrapped = spawn("bwrap", ["--die-with-parent", "--ro-bind", "/", "/", "--unshare-user", "--unshare-pid", "--dev", "/dev", "--proc", "/proc", "node", "-e", idle, "cli.js", wrappedTag], { stdio: "ignore" });
    const sampler = startProcessSampler(() => process.pid, [bareTag, wrappedTag, absentTag]);
    await new Promise((resolve) => setTimeout(resolve, 600));
    const sample = sampler.stop();
    const record: PresenceKey | null = sandboxFixtureRecord(wrappedTag);
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
