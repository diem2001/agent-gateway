/**
 * The registry's stored `headers` and `env` are write-only, under the real gateway (MVP-7936): the compiled gateway
 * (`dist/server.js`), the production Claude Agent SDK and its runtime, real `bwrap`, recording MCP doubles and a
 * scripted model, with two real API-key labels (reqlift owns `jira` and `local`, diemcrm owns `feed` and `moved`) and
 * one entry registered before ownership (no owner label) that carries its own header marker.
 *
 * - `RG.read`: list and detail as the owner, as another label and for the ownerless entry carry no `headers`/`env`
 *   property and no stored value (the stdio `args` of `local` are public by the approved contract, so their marker is
 *   the one listed exclusion).
 * - `RG.write`: the replies of an owner update and of a new registration carry neither property nor value.
 * - `RG.refused`: another label's PUT and every label's PUT on the ownerless entry are 403, the stored maps (compared
 *   by hash of the persisted file) do not change and nothing is disclosed.
 * - `RG.preserve-run`: a reqlift-style toggle (GET, spread, PUT) of `jira` and `local` keeps both stored maps (hash)
 *   and an authorized chat run still delivers the registry header to the http upstream and the env value to the stdio
 *   server (both compared, never printed), with no marker on any client surface.
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
const PERSIST_WAIT_MS = 400;

/** The rig with the standard servers and one ownerless entry in the registry file before the first start. */
async function newRig(): Promise<SecurityRig> {
  const rig = await createRig(cleanups, {
    markers,
    seed: (dirs, seeded) => {
      const now = "2026-09-01T00:00:00.000Z";
      const entry = { name: LEGACY, description: "registered before ownership", enabled: true, type: "http", url: "http://127.0.0.1:9/mcp", headers: { Authorization: `Basic ${seeded.values.legacyRegistryHeader}` }, createdAt: now, updatedAt: now };
      fs.writeFileSync(path.join(dirs.persist, "mcp-servers.json"), JSON.stringify([entry], null, 2));
    },
  });
  expect(pinnedProblems(rig)).toEqual([]);
  await registerStandardServers(rig);
  return rig;
}

interface StoredEntry {
  name: string;
  owner?: string;
  headers?: Record<string, string>;
  env?: Record<string, string>;
}

/** The persisted registry, after the debounced save. */
async function persisted(rig: SecurityRig): Promise<StoredEntry[]> {
  await new Promise((resolve) => setTimeout(resolve, PERSIST_WAIT_MS));
  return JSON.parse(fs.readFileSync(path.join(rig.gateway.dirs.persist, "mcp-servers.json"), "utf8")) as StoredEntry[];
}

/** One hash per entry over its two maps, so "unchanged" is compared without a value ever being held in an assertion. */
function mapHashes(entries: StoredEntry[]): Record<string, string> {
  return Object.fromEntries(entries.map((entry) => [entry.name, createHash("sha256").update(JSON.stringify([entry.headers ?? null, entry.env ?? null])).digest("hex")]));
}

const request = (rig: SecurityRig, label: "reqlift" | "diemcrm", method: string, route: string, body?: Record<string, unknown>) => gatewayRequest(rig.gateway.port, method, route, body, rig.keys[label]);

/** The text of every answer, as the caller-visible surface. */
const callerBody = (answers: { status: number; text: string }[]): Surface => ({ name: "caller-body", text: answers.map((answer) => `${answer.status} ${answer.text}`).join("\n") });

/** Names of the stored-map properties an answer carries (`headers` or `env`, at any depth of a list). */
function mapProperties(text: string): string[] {
  const found: string[] = [];
  const visit = (value: unknown): void => {
    if (Array.isArray(value)) value.forEach(visit);
    else if (value && typeof value === "object") {
      for (const [key, inner] of Object.entries(value)) {
        if (key === "headers" || key === "env") found.push(key);
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
  return [v.registryHttpHeader, v.stdioEnv, v.sseHeader, v.legacyRegistryHeader].every((value) => text.includes(value)) ? [] : ["control: the persisted registry does not hold every stored marker, so the absence rows prove nothing"];
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
      if (list.status !== 200 || names.join(",") !== ["feed", LEGACY, "jira", "local", "moved"].sort().join(",")) problems.push(`${label}: the list did not answer with every server`);
      for (const name of ["jira", "local", "feed", LEGACY]) {
        const detail = await request(rig, label, "GET", `/v1/mcp-servers/${name}`);
        answers.push(detail);
        if (detail.status !== 200 || detail.json?.name !== name) problems.push(`${label}: the detail of ${name} did not answer`);
      }
    }
    const missing = await request(rig, "diemcrm", "GET", "/v1/mcp-servers/nope");
    if (missing.status !== 404) problems.push("a missing server's detail is not 404");
    for (const answer of answers) if (mapProperties(answer.text).length > 0) problems.push("an answer carries a headers or env property");
    for (const answer of answers) if (answer.text.includes('"owner"')) problems.push("an answer carries an owner property");
    const surfaces = [callerBody(answers), { name: "gateway-log", text: rig.log() }];
    finishRow(recorder, rig, {
      id: "RG.read",
      durationMs: Date.now() - started,
      deadlineMs: 60_000,
      surfaces,
      allowedOn: { surface: "caller-body", markers: ["stdioArgs"] },
      controls: ["persisted_registry_holds_every_stored_marker", "list_and_detail_answered_for_both_labels", "ownerless_entry_listed", "missing_detail_is_404", "stdio_args_are_public_by_contract_so_their_marker_is_excluded_on_caller_body"],
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
    for (const answer of [update, created]) if (mapProperties(answer.text).length > 0) problems.push("a reply carries a headers or env property");
    const stored = await persisted(rig);
    const fresh = stored.find((entry) => entry.name === "fresh");
    if (fresh?.env?.SERVER_TOKEN !== v.stdioEnv || fresh?.headers?.["X-Dormant"] !== v.sseHeader) problems.push("the registry did not store the submitted maps of the new registration");
    finishRow(recorder, rig, {
      id: "RG.write",
      durationMs: Date.now() - started,
      deadlineMs: 60_000,
      surfaces: [callerBody([update, created]), { name: "gateway-log", text: rig.log() }],
      allowedOn: { surface: "caller-body", markers: ["stdioArgs"] },
      controls: ["owner_update_200", "new_registration_201", "submitted_maps_stored_internally"],
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
      allowedOn: { surface: "caller-body", markers: ["stdioArgs"] },
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
    const turn = await chatTurn(rig, { prompt: "RG-PRESERVE-RUN", sessionId: "conv-rg-preserve", withCredentials: false, steps: [{ name: "mcp__jira__get_page", input: { id: "P-1" } }, { name: "mcp__local__echo", input: {} }] });
    problems.push(...turnProblems(turn));
    const [jira, local] = turn.results;
    if (!jira || jira.isError || !jira.text.includes("RECORD-7667-OK")) problems.push("the registered http server did not answer the run's call");
    const sent = rig.jira.authorizations().slice(jiraBefore);
    if (sent.length === 0 || !sent.every((value) => value === `Basic ${v.registryHttpHeader}`)) problems.push("the http upstream did not receive exactly the stored header after the toggle");
    if (!local || local.isError || local.text !== `STDIO-RESULT:${v.stdioEnv.length}`) problems.push("the stdio server did not receive the stored env value after the toggle");
    finishRow(recorder, rig, {
      id: "RG.preserve-run",
      durationMs: Date.now() - started,
      deadlineMs: TURN_DEADLINE_MS * 2,
      surfaces: [...surfacesOf(rig, [turn]), callerBody(answers)],
      // The two tool answers of this run are short fixed texts.
      floors: { "tool-results": 20 },
      allowedOn: { surface: "caller-body", markers: ["stdioArgs"] },
      controls: ["persisted_registry_holds_every_stored_marker", "toggle_off_and_on_200_for_http_and_stdio", "stored_map_hashes_unchanged", "upstream_received_exactly_the_stored_header", "stdio_server_received_the_stored_env_value_length_match"],
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
