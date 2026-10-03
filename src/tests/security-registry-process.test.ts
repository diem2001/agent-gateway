/**
 * The registry's stored `headers`, `env` and stdio `args` are write-only and its failure texts are fixed, under the
 * real gateway (MVP-7936, MVP-7957): the compiled gateway (`dist/server.js`), the production Claude Agent SDK and its
 * runtime, real `bwrap`, recording MCP doubles and a scripted model, with two real API-key labels (reqlift owns `jira`
 * and `local`, diemcrm owns `feed` and `moved`), one entry registered before ownership (no owner label) that carries its
 * own header marker, and legacy entries in the persisted file: three whose URL breaks the public-URL rule (user info,
 * query, fragment) and one whose stored header cannot be sent.
 *
 * - `RG.read`: list and detail as the owner, as another label and for the ownerless entry carry no `headers`, `env`
 *   or `args` property and no stored value.
 * - `RG.write`: the replies of an owner update and of a new registration carry neither property nor value.
 * - `RG.refused`: another label's PUT and every label's PUT on the ownerless entry are 403, the stored maps (compared
 *   by hash of the persisted file) do not change and nothing is disclosed.
 * - `RG.preserve-run`: a reqlift-style toggle (GET, spread, PUT) of `jira` and `local` keeps both stored maps (hash)
 *   and an authorized chat run still delivers the registry header to the http upstream and the env value to the stdio
 *   server (both compared, never printed), with no marker on any client surface.
 *
 * - `RG.args-url`: a compliant URL is returned verbatim, a legacy URL with user info, query or fragment is withheld
 *   with `urlMigrationRequired`, an unsafe URL on a write is refused without being echoed, a metadata edit of a legacy
 *   entry leaves its stored values unchanged (hash), a toggle keeps the stored args and an authorized run still
 *   receives them.
 * - `RG.failure-text`: health, test and call answer fixed texts for the unsendable stored header, the unusable stored
 *   address and an unreachable upstream, with no stored value in any answer or log line; an authorized /test still
 *   sends the stored header.
 *
 * Every secret is a synthetic marker with a random suffix; only names, booleans and counts are printed.
 * Needs `npm run build`, `bwrap`, user namespaces, `git` and `python3`. Linux only.
 */
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { Cleanup } from "./helpers/git-process-gateway.js";
import { gatewayRequest } from "./helpers/git-process-gateway.js";
import {
  MatrixRecorder,
  TURN_DEADLINE_MS,
  chatTurn,
  createMarkers,
  createRig,
  emit,
  evidenceLine,
  finishRow,
  pinnedProblems,
  registerStandardServers,
  requireHost,
  surfacesOf,
  turnProblems,
  type SecurityMarkers,
  type SecurityRig,
  type Surface,
} from "./helpers/security-matrix.js";
import { registryRowIds } from "./helpers/security-routes.js";

vi.setConfig({ testTimeout: 300_000 });

const markers: SecurityMarkers = createMarkers();
const recorder = new MatrixRecorder("security-registry-process", registryRowIds());

const cleanups: Cleanup[] = [];
afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()!();
});

beforeAll(() => {
  requireHost(["bwrap", "userns", "git", "python3", "build"]);
  emit(
    evidenceLine({
      suite: "security-registry-process",
      config: { API_KEYS: "reqlift+diemcrm", ANTHROPIC_BASE_URL: "local-double", MODEL_PROXY_OAUTH_TOKEN_URL: "local-double", MCP_SERVERS: "standard servers + one ownerless entry" },
      deadlines: { turn_ms: TURN_DEADLINE_MS, row_test_timeout_ms: 300_000 },
      offline: false,
      logLevel: "info",
    }),
  );
});

const LEGACY = "legacy";
const LEGACY_USER = "legacy-user";
const LEGACY_QUERY = "legacy-query";
const LEGACY_FRAGMENT = "legacy-fragment";
const LEGACY_HEADER = "legacy-header";
const LEGACY_URL_ENTRIES = [LEGACY_USER, LEGACY_QUERY, LEGACY_FRAGMENT];
const PERSIST_WAIT_MS = 400;

/** The rig with the standard servers and one ownerless entry in the registry file before the first start. */
async function newRig(): Promise<SecurityRig> {
  const rig = await createRig(cleanups, {
    markers,
    seed: (dirs, seeded) => {
      const now = "2026-09-01T00:00:00.000Z";
      const v = seeded.values;
      const entry = { name: LEGACY, description: "registered before ownership", enabled: true, type: "http", url: "http://127.0.0.1:9/mcp", headers: { Authorization: `Basic ${v.legacyRegistryHeader}` }, createdAt: now, updatedAt: now };
      const legacyEntry = (name: string, url: string, extra: Record<string, unknown> = {}) => ({ name, description: "legacy", enabled: true, type: "http", url, owner: "reqlift", headers: { Authorization: `Basic ${v.legacyRegistryHeader}` }, createdAt: now, updatedAt: now, ...extra });
      const entries = [
        entry,
        legacyEntry(LEGACY_USER, `http://${v.urlUserInfo}:pw@127.0.0.1:9/mcp`),
        legacyEntry(LEGACY_QUERY, `http://127.0.0.1:9/mcp?token=${v.urlQuery}`),
        legacyEntry(LEGACY_FRAGMENT, `http://127.0.0.1:9/mcp#${v.urlFragment}`),
        legacyEntry(LEGACY_HEADER, "http://127.0.0.1:9/mcp", { headers: { [`X-Bad Name ${v.legacyHeader}`]: "value", Authorization: `Bearer ${v.legacyHeader}\r\nX-Injected: 1` } }),
      ];
      fs.writeFileSync(path.join(dirs.persist, "mcp-servers.json"), JSON.stringify(entries, null, 2));
    },
  });
  expect(pinnedProblems(rig)).toEqual([]);
  await registerStandardServers(rig);
  return rig;
}

interface StoredEntry {
  name: string;
  owner?: string;
  url?: string;
  headers?: Record<string, string>;
  args?: string[];
  env?: Record<string, string>;
}

/** The persisted registry, after the debounced save. */
async function persisted(rig: SecurityRig): Promise<StoredEntry[]> {
  await new Promise((resolve) => setTimeout(resolve, PERSIST_WAIT_MS));
  return JSON.parse(fs.readFileSync(path.join(rig.gateway.dirs.persist, "mcp-servers.json"), "utf8")) as StoredEntry[];
}

/** One hash per entry over its write-only fields and URL, so "unchanged" is compared without a value ever being held in an assertion. */
function mapHashes(entries: StoredEntry[]): Record<string, string> {
  return Object.fromEntries(entries.map((entry) => [entry.name, createHash("sha256").update(JSON.stringify([entry.url ?? null, entry.headers ?? null, entry.args ?? null, entry.env ?? null])).digest("hex")]));
}

const request = (rig: SecurityRig, label: "reqlift" | "diemcrm", method: string, route: string, body?: Record<string, unknown>) => gatewayRequest(rig.gateway.port, method, route, body, rig.keys[label]);

/** The text of every answer, as the caller-visible surface. */
const callerBody = (answers: { status: number; text: string }[]): Surface => ({ name: "caller-body", text: answers.map((answer) => `${answer.status} ${answer.text}`).join("\n") });

/** Names of the write-only properties an answer carries (`headers`, `env` or `args`, at any depth of a list). */
function mapProperties(text: string): string[] {
  const found: string[] = [];
  const visit = (value: unknown): void => {
    if (Array.isArray(value)) value.forEach(visit);
    else if (value && typeof value === "object") {
      for (const [key, inner] of Object.entries(value)) {
        if (key === "headers" || key === "env" || key === "args") found.push(key);
        visit(inner);
      }
    }
  };
  try {
    visit(JSON.parse(text));
  } catch {
    // Not JSON: nothing to inspect.
  }
  return found;
}

/** The registry holds the marker values the rows claim stay hidden, so absence is not an empty registry. */
function storedControl(entries: StoredEntry[], v: Record<string, string>): string[] {
  const text = JSON.stringify(entries);
  return [v.registryHttpHeader, v.stdioEnv, v.stdioArgs, v.sseHeader, v.legacyRegistryHeader, v.legacyHeader, v.urlUserInfo, v.urlQuery, v.urlFragment].every((value) => text.includes(value)) ? [] : ["control: the persisted registry does not hold every stored marker, so the absence rows prove nothing"];
}

describe("registry write-only rows", () => {
  it("RG.read: list and detail for the owner, another label and an ownerless entry carry no headers or env property and no stored value", async () => {
    const rig = await newRig();
    const started = Date.now();
    const problems = storedControl(await persisted(rig), rig.markers.values);
    const answers: { status: number; text: string }[] = [];
    for (const label of ["reqlift", "diemcrm"] as const) {
      const list = await request(rig, label, "GET", "/v1/mcp-servers");
      answers.push(list);
      const names = ((list.json?.servers ?? []) as { name: string }[]).map((server) => server.name).sort();
      if (list.status !== 200 || names.join(",") !== ["feed", LEGACY, ...LEGACY_URL_ENTRIES, LEGACY_HEADER, "jira", "local", "moved"].sort().join(",")) problems.push(`${label}: the list did not answer with every server`);
      for (const name of ["jira", "local", "feed", LEGACY, ...LEGACY_URL_ENTRIES, LEGACY_HEADER]) {
        const detail = await request(rig, label, "GET", `/v1/mcp-servers/${name}`);
        answers.push(detail);
        if (detail.status !== 200 || detail.json?.name !== name) problems.push(`${label}: the detail of ${name} did not answer`);
      }
    }
    const missing = await request(rig, "diemcrm", "GET", "/v1/mcp-servers/nope");
    if (missing.status !== 404) problems.push("a missing server's detail is not 404");
    for (const answer of answers) if (mapProperties(answer.text).length > 0) problems.push("an answer carries a headers, env or args property");
    for (const answer of answers) if (answer.text.includes('"owner"')) problems.push("an answer carries an owner property");
    const surfaces = [callerBody(answers), { name: "gateway-log", text: rig.log() }];
    finishRow(recorder, rig, {
      id: "RG.read",
      durationMs: Date.now() - started,
      deadlineMs: 60_000,
      surfaces,
      controls: ["persisted_registry_holds_every_stored_marker", "list_and_detail_answered_for_both_labels", "ownerless_entry_listed", "legacy_url_entries_listed", "missing_detail_is_404"],
      problems,
    });
  });

  it("RG.write: the replies of an owner update and a new registration carry neither property nor value", async () => {
    const rig = await newRig();
    const v = rig.markers.values;
    const started = Date.now();
    const problems: string[] = [];
    const update = await request(rig, "reqlift", "PUT", "/v1/mcp-servers/jira", { type: "http", url: rig.jira.url, headers: { Authorization: `Basic ${v.registryHttpHeader}` }, env: { DORMANT: v.stdioEnv } });
    const created = await request(rig, "reqlift", "PUT", "/v1/mcp-servers/fresh", { type: "stdio", command: "node", args: ["-e", "0"], env: { SERVER_TOKEN: v.stdioEnv }, headers: { "X-Dormant": v.sseHeader } });
    if (update.status !== 200) problems.push("the owner update was not 200");
    if (created.status !== 201) problems.push("the new registration was not 201");
    for (const answer of [update, created]) if (mapProperties(answer.text).length > 0) problems.push("a reply carries a headers, env or args property");
    const stored = await persisted(rig);
    const fresh = stored.find((entry) => entry.name === "fresh");
    if (fresh?.env?.SERVER_TOKEN !== v.stdioEnv || fresh?.headers?.["X-Dormant"] !== v.sseHeader || fresh?.args?.[1] !== "0") problems.push("the registry did not store the submitted maps of the new registration");
    finishRow(recorder, rig, {
      id: "RG.write",
      durationMs: Date.now() - started,
      deadlineMs: 60_000,
      surfaces: [callerBody([update, created]), { name: "gateway-log", text: rig.log() }],
      controls: ["owner_update_200", "new_registration_201", "submitted_maps_and_args_stored_internally"],
      problems,
    });
  });

  it("RG.refused: another label's PUT and a PUT on the ownerless entry are 403, change no stored map and disclose nothing", async () => {
    const rig = await newRig();
    const v = rig.markers.values;
    const started = Date.now();
    const problems = storedControl(await persisted(rig), v);
    const before = mapHashes(await persisted(rig));
    const body = { type: "http", url: "http://127.0.0.1:9/mcp", headers: { Authorization: "Bearer replacement" }, env: {} };
    const attempts = [
      await request(rig, "diemcrm", "PUT", "/v1/mcp-servers/jira", body),
      await request(rig, "diemcrm", "PUT", `/v1/mcp-servers/${LEGACY}`, body),
      await request(rig, "reqlift", "PUT", `/v1/mcp-servers/${LEGACY}`, { type: "http", url: "http://127.0.0.1:9/mcp" }),
    ];
    for (const [index, attempt] of attempts.entries()) if (attempt.status !== 403) problems.push(`refused attempt ${index + 1} was not 403`);
    const after = mapHashes(await persisted(rig));
    for (const name of ["jira", LEGACY, "feed", "moved", "local"]) if (before[name] !== after[name]) problems.push(`the stored maps of ${name} changed`);
    // Control: the owner's own clear of its env does change its entry, so the hash comparison can see a change.
    const clear = await request(rig, "reqlift", "PUT", "/v1/mcp-servers/local", { type: "stdio", command: "node", env: {} });
    if (clear.status !== 200 || mapHashes(await persisted(rig)).local === before.local) problems.push("control: an owner's clear of its own map did not change the hash, so the comparison cannot detect a change");
    finishRow(recorder, rig, {
      id: "RG.refused",
      durationMs: Date.now() - started,
      deadlineMs: 60_000,
      surfaces: [callerBody(attempts), { name: "gateway-log", text: rig.log() }],
      controls: ["persisted_registry_holds_every_stored_marker", "three_refusals_403", "stored_map_hashes_unchanged", "control_an_owner_clear_changes_the_hash"],
      problems,
    });
  });

  it("RG.preserve-run: a reqlift-style toggle keeps both stored maps and an authorized run still delivers the stored header and env value", async () => {
    const rig = await newRig();
    const v = rig.markers.values;
    const started = Date.now();
    const problems = storedControl(await persisted(rig), v);
    const before = mapHashes(await persisted(rig));
    const answers: { status: number; text: string }[] = [];
    for (const name of ["jira", "local"]) {
      for (const enabled of [false, true]) {
        const detail = await request(rig, "reqlift", "GET", `/v1/mcp-servers/${name}`);
        const put = await request(rig, "reqlift", "PUT", `/v1/mcp-servers/${name}`, { ...detail.json, enabled });
        answers.push(detail, put);
        if (put.status !== 200) problems.push(`the toggle of ${name} to ${enabled} was not 200`);
      }
    }
    const after = mapHashes(await persisted(rig));
    for (const name of ["jira", "local"]) if (before[name] !== after[name]) problems.push(`the toggle changed the stored maps of ${name}`);

    const jiraBefore = rig.jira.authorizations().length;
    const turn = await chatTurn(rig, { prompt: "RG-PRESERVE-RUN", sessionId: "conv-rg-preserve", withCredentials: false, steps: [{ name: "mcp__jira__get_page", input: { id: "P-1" } }, { name: "mcp__local__echo", input: {} }, { name: "mcp__local__argv", input: {} }] });
    problems.push(...turnProblems(turn));
    const [jira, local, argv] = turn.results;
    if (!jira || jira.isError || !jira.text.includes("RECORD-7667-OK")) problems.push("the registered http server did not answer the run's call");
    const sent = rig.jira.authorizations().slice(jiraBefore);
    if (sent.length === 0 || !sent.every((value) => value === `Basic ${v.registryHttpHeader}`)) problems.push("the http upstream did not receive exactly the stored header after the toggle");
    if (!local || local.isError || local.text !== `STDIO-RESULT:${v.stdioEnv.length}`) problems.push("the stdio server did not receive the stored env value after the toggle");
    if (!argv || argv.isError || argv.text !== `STDIO-ARGV:${v.stdioArgs.length}`) problems.push("the stdio server did not receive the stored args after the toggle");
    finishRow(recorder, rig, {
      id: "RG.preserve-run",
      durationMs: Date.now() - started,
      deadlineMs: TURN_DEADLINE_MS * 2,
      surfaces: [...surfacesOf(rig, [turn]), callerBody(answers)],
      // The two tool answers of this run are short fixed texts.
      floors: { "tool-results": 20 },
      controls: ["persisted_registry_holds_every_stored_marker", "toggle_off_and_on_200_for_http_and_stdio", "stored_map_hashes_unchanged", "upstream_received_exactly_the_stored_header", "stdio_server_received_the_stored_env_value_length_match", "stdio_server_received_the_stored_args_length_match"],
      problems,
    });
  });

  it("RG.args-url: a compliant URL is returned verbatim, a legacy URL is withheld with a flag, unsafe URL writes are refused, a toggle keeps the args and the run still receives them", async () => {
    const rig = await newRig();
    const v = rig.markers.values;
    const started = Date.now();
    const problems = storedControl(await persisted(rig), v);
    const before = mapHashes(await persisted(rig));
    const answers: { status: number; text: string }[] = [];

    // Reads: both labels, list and detail. A compliant URL (reqlift's OAuth precondition) is the registered string; a legacy one is withheld.
    for (const label of ["reqlift", "diemcrm"] as const) {
      const list = await request(rig, label, "GET", "/v1/mcp-servers");
      answers.push(list);
      const byName = new Map(((list.json?.servers ?? []) as { name: string; url?: string; urlMigrationRequired?: boolean }[]).map((server) => [server.name, server]));
      if (byName.get("jira")?.url !== rig.jira.url) problems.push(`${label}: the list did not return the compliant URL of jira verbatim`);
      for (const name of LEGACY_URL_ENTRIES) {
        const detail = await request(rig, label, "GET", `/v1/mcp-servers/${name}`);
        answers.push(detail);
        if (detail.json?.url !== undefined || detail.json?.urlMigrationRequired !== true) problems.push(`${label}: the detail of ${name} did not withhold the URL with the migration flag`);
        const inList = byName.get(name);
        if (inList?.url !== undefined || inList?.urlMigrationRequired !== true) problems.push(`${label}: the list did not withhold the URL of ${name} with the migration flag`);
      }
      const jiraDetail = await request(rig, label, "GET", "/v1/mcp-servers/jira");
      answers.push(jiraDetail);
      if (jiraDetail.json?.url !== rig.jira.url || jiraDetail.json?.urlMigrationRequired !== undefined) problems.push(`${label}: the detail of jira did not return the compliant URL without a flag`);
    }

    // Unsafe URLs on a write: a new name and an owner update, every part, refused with the fixed code and nothing changed.
    const unsafe = [`http://${v.urlUserInfo}:pw@127.0.0.1:9/mcp`, `http://127.0.0.1:9/mcp?token=${v.urlQuery}`, `http://127.0.0.1:9/mcp#${v.urlFragment}`];
    for (const url of unsafe) {
      for (const name of ["bad-new", "jira"]) {
        const refused = await request(rig, "reqlift", "PUT", `/v1/mcp-servers/${name}`, { type: "http", url });
        answers.push(refused);
        if (refused.status !== 400 || (refused.json?.error as { code?: string } | undefined)?.code !== "MCP_SERVER_URL_INVALID") problems.push(`an unsafe URL on ${name} was not refused with MCP_SERVER_URL_INVALID`);
      }
    }
    const afterRefused = await persisted(rig);
    if (afterRefused.some((entry) => entry.name === "bad-new")) problems.push("a refused registration was stored");
    if (mapHashes(afterRefused).jira !== before.jira) problems.push("a refused update changed the jira entry");

    // A metadata edit of a legacy entry by its owner keeps every stored value (hash) and still withholds the URL; another label is refused.
    for (const name of LEGACY_URL_ENTRIES) {
      const edit = await request(rig, "reqlift", "PUT", `/v1/mcp-servers/${name}`, { type: "http", description: "edited" });
      answers.push(edit);
      if (edit.status !== 200 || edit.json?.url !== undefined || edit.json?.urlMigrationRequired !== true || edit.json?.description !== "edited") problems.push(`the metadata edit of ${name} did not answer 200 with the URL withheld`);
      const other = await request(rig, "diemcrm", "PUT", `/v1/mcp-servers/${name}`, { type: "http", description: "taken" });
      answers.push(other);
      if (other.status !== 403) problems.push(`another label's PUT on ${name} was not 403`);
    }
    const afterEdit = mapHashes(await persisted(rig));
    for (const name of LEGACY_URL_ENTRIES) if (afterEdit[name] !== before[name]) problems.push(`the metadata edit changed the stored url, args, headers or env of ${name}`);

    // A reqlift-style toggle keeps the stored args (hash); an explicit [] clears them (control: the hash can change), on a separate entry.
    for (const enabled of [false, true]) {
      const detail = await request(rig, "reqlift", "GET", "/v1/mcp-servers/local");
      const put = await request(rig, "reqlift", "PUT", "/v1/mcp-servers/local", { ...detail.json, enabled });
      answers.push(detail, put);
      if (put.status !== 200) problems.push(`the toggle of local to ${enabled} was not 200`);
    }
    if (mapHashes(await persisted(rig)).local !== before.local) problems.push("the toggle changed the stored args of local");
    const made = await request(rig, "reqlift", "PUT", "/v1/mcp-servers/clearme", { type: "stdio", command: "node", args: ["-e", "0", v.stdioArgs] });
    const kept = await request(rig, "reqlift", "PUT", "/v1/mcp-servers/clearme", { type: "stdio", command: "node", description: "edited" });
    const keptArgs = (await persisted(rig)).find((entry) => entry.name === "clearme")?.args;
    const cleared = await request(rig, "reqlift", "PUT", "/v1/mcp-servers/clearme", { type: "stdio", command: "node", args: [] });
    const clearedArgs = (await persisted(rig)).find((entry) => entry.name === "clearme")?.args;
    answers.push(made, kept, cleared);
    if (keptArgs?.[2] !== v.stdioArgs) problems.push("an edit that omitted args did not keep them");
    if (clearedArgs !== undefined) problems.push("args: [] did not clear the stored args");

    // The authorized run still receives the stored args.
    const turn = await chatTurn(rig, { prompt: "RG-ARGS-URL", sessionId: "conv-rg-args-url", withCredentials: false, steps: [{ name: "mcp__local__argv", input: {} }] });
    problems.push(...turnProblems(turn));
    const [argv] = turn.results;
    if (!argv || argv.isError || argv.text !== `STDIO-ARGV:${v.stdioArgs.length}`) problems.push("the stdio server did not receive the stored args");

    for (const answer of answers) if (mapProperties(answer.text).length > 0) problems.push("an answer carries a headers, env or args property");
    finishRow(recorder, rig, {
      id: "RG.args-url",
      durationMs: Date.now() - started,
      deadlineMs: TURN_DEADLINE_MS * 2,
      surfaces: [...surfacesOf(rig, [turn]), callerBody(answers)],
      floors: { "tool-results": 10 },
      controls: ["persisted_registry_holds_every_stored_marker", "compliant_url_returned_verbatim_to_both_labels", "legacy_url_withheld_with_flag_in_list_and_detail", "unsafe_urls_refused_for_new_and_existing_name", "refused_writes_store_nothing", "metadata_edit_keeps_every_stored_value_hash", "toggle_keeps_args_hash", "omitted_args_keep_and_empty_args_clear", "stdio_server_received_the_stored_args_length_match"],
      problems,
    });
  });

  it("RG.failure-text: health, test and call answer fixed texts for an unsendable header, an unusable address and an unreachable upstream", async () => {
    const rig = await newRig();
    const v = rig.markers.values;
    const started = Date.now();
    const problems = storedControl(await persisted(rig), v);
    const answers: { status: number; text: string }[] = [];
    const TEXT = { header: "a stored header of this server cannot be sent", address: "the stored server address cannot be used", unreachable: "the MCP server could not be reached" };

    const dead = await request(rig, "reqlift", "PUT", "/v1/mcp-servers/dead", { type: "http", url: "http://127.0.0.1:9/mcp", headers: { Authorization: `Basic ${v.registryHttpHeader}` } });
    if (dead.status !== 201) problems.push("the unreachable entry was not registered");
    const expectations: Array<[string, string]> = [[LEGACY_HEADER, TEXT.header], [LEGACY_USER, TEXT.address], ["dead", TEXT.unreachable]];
    for (const [name, text] of expectations) {
      const health = await request(rig, "reqlift", "GET", `/v1/mcp-servers/${name}/health`);
      const test = await request(rig, "reqlift", "POST", `/v1/mcp-servers/${name}/test`, {});
      const call = await request(rig, "reqlift", "POST", `/v1/mcp-servers/${name}/call`, { tool: "get_page", arguments: {} });
      answers.push(health, test, call);
      if (health.status !== 200 || health.json?.status !== "error" || health.json?.detail !== text) problems.push(`health of ${name} did not answer the fixed text`);
      for (const [route, answer] of [["test", test], ["call", call]] as const) {
        const error = answer.json?.error as { code?: string; message?: string } | undefined;
        if (answer.status !== 502 || error?.code !== "MCP_NETWORK_ERROR" || error?.message !== text) problems.push(`${route} of ${name} did not answer the fixed text`);
      }
    }
    const log = rig.log();
    if (!log.includes(`mcp.test.called serverName=${LEGACY_HEADER} result=network_error reason=header`)) problems.push("the audit line of the header failure is missing or has no reason");
    if (!log.includes(`mcp.call.called serverName=${LEGACY_USER} tool=get_page result=network_error reason=address`)) problems.push("the audit line of the address failure is missing or has no reason");

    // Control: an authorized /test of a healthy entry still sends the stored header and answers the upstream's tool list.
    const sentBefore = rig.jira.authorizations().length;
    const control = await request(rig, "reqlift", "POST", "/v1/mcp-servers/jira/test", {});
    answers.push(control);
    if (control.status !== 200 || control.json?.ok !== true) problems.push("control: the authorized test of jira did not answer ok");
    const sent = rig.jira.authorizations().slice(sentBefore);
    if (sent.length === 0 || !sent.every((value) => value === `Basic ${v.registryHttpHeader}`)) problems.push("control: the authorized test did not send exactly the stored header");

    finishRow(recorder, rig, {
      id: "RG.failure-text",
      durationMs: Date.now() - started,
      deadlineMs: 120_000,
      surfaces: [callerBody(answers), { name: "gateway-log", text: log }],
      controls: ["persisted_registry_holds_every_stored_marker", "header_address_and_unreachable_fixed_on_health_test_call", "audit_lines_carry_a_reason", "authorized_test_still_sends_the_stored_header"],
      problems,
    });
  });
});

describe("summary", () => {
  it("every expected row of the suite ran and passed", () => {
    const summary = recorder.finish();
    expect(summary.missing).toEqual([]);
    expect(summary.fail).toBe(0);
  });
});
