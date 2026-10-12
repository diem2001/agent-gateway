/**
 * A raw tool's structured `tool_use` input never carries a secret value the gateway holds (MVP-8096, Gate C): the
 * compiled gateway (`dist/server.js`), the production Claude Agent SDK and its runtime, real `bwrap`, recording doubles
 * and a scripted model, with two real API-key labels, a registered http server with a stored header, a per-user
 * credential override and request-body servers with a header and an env value.
 *
 * - `SI.stream-input-secret`: a webhook tool registered `stream_input: "raw"` is called by the scripted model with an
 *   input that holds, one value per call, a registry server's stored header value, the per-user override value, the
 *   caller's own gateway key (the webhook bearer), a request-body server's header value and a request-body stdio env
 *   value. None of them appears on the stream, on the `GET /v1/query/:queryId/events` replay or in the gateway log at
 *   `LOG_LEVEL=debug` (which prints every emitted event); each event input is a summary string that shows
 *   `[REDACTED]`. The permitted control is the same call without a known value, which streams the object, and the
 *   webhook received every call.
 *
 * - `SI.mask-overlap` (MVP-8207): a stored registry server holds a value V1 (header) and V2 = V1 + `:` + a password part
 *   (env), so the sorted known-value list holds V1 first. A raw tool called with `login <V2> now` shows
 *   `login [REDACTED] now`; neither V2 nor the password part is on the stream, the replay or the debug log.
 * - `SI.mask-scheme`: the bare token of a `Bearer`/`Basic` header from a stored registry server, a per-request MCP
 *   server and a per-user override is withheld and masked on the same surfaces; a 7-character token is shown unchanged.
 * - `SI.refusal-mask`: a webhook tool refuses with a message that holds V2, the registry token, a per-request server's
 *   `Basic` token and the per-user override's `Basic` token (one call each): the `tool_result` text in the stream and
 *   the tool result the scripted model received hold none of them and show `[REDACTED]`.
 * - `SI.credentials-bound` (MVP-8207): a request whose credential values (per-user overrides, or a request server's headers)
 *   total 8 MB is refused at validation with 400 `MCP_CREDENTIALS_TOO_LARGE` and a fixed text that holds no value, fast, while
 *   `/health` stays responsive and no run starts; a request within the limits on the same route, with a refusing webhook
 *   tool, still runs and masks its value.
 * - `SI.refusal-cost`: a caller with about 100 per-user override values whose webhook tool refuses with an 8 MiB body gets
 *   the refusal within the budget, and `/health` of the same gateway, pinged from this process while the turn runs, never
 *   waits longer than the health budget.
 *
 * The model's own tool call is the one place a value is expected (it is the scripted input), so this row does not use
 * the model-request or transcript surfaces: they hold what the "model" said, not what the gateway streamed.
 * Every secret is a synthetic marker with a random suffix; only names, booleans and counts are printed.
 * Needs `npm run build`, `bwrap`, user namespaces, `git` and `python3`. Linux only.
 */
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { Cleanup } from "./helpers/git-process-gateway.js";
import { REPO_ROOT, gatewayRequest } from "./helpers/git-process-gateway.js";
import { startRefusingDouble } from "./helpers/refusing-webhook.js";
import {
  AC_ROWS,
  MatrixRecorder,
  ROUTE_ALLOWED_TOOLS,
  STDIO_SOURCE,
  TURN_DEADLINE_MS,
  chatTurn,
  createMarkers,
  createRig,
  detect,
  emit,
  evidenceLine,
  finishRow,
  pinnedProblems,
  registerStandardServers,
  requestCredentials,
  requireHost,
  runChild,
  turnProblems,
  type SecurityMarkers,
  type SecurityRig,
  type Surface,
} from "./helpers/security-matrix.js";

vi.setConfig({ testTimeout: 300_000 });

const ROW_IDS = ["SI.stream-input-secret", "SI.mask-overlap", "SI.mask-scheme", "SI.refusal-mask", "SI.refusal-cost", "SI.credentials-bound", "SI.stored-registry-budget", "SI.stored-url-budget", "SI.stored-write-caps"];
const TOOL = "stream_probe";
const FULL = `mcp__agent-gateway-tools__${TOOL}`;
/** The budgets of `SI.refusal-cost`: the turn (measured about 1.5 s) and the longest wait of one `/health` ping (measured about 0.2 s). */
const REFUSAL_COST_TURN_MS = 10_000;
const REFUSAL_COST_HEALTH_MS = 1_000;
/** The budget of one refused 8 MB request of `SI.credentials-bound`: parsing and validating it, measured well under a second. */
const BOUND_REFUSAL_MS = 3_000;
/** The fixed text a refusal shows once the run's known values are over the masking budget (no upstream detail). */
const WITHHELD_REFUSAL = `TOOL_UNAVAILABLE: "refuse_probe" refused the request, and the gateway cannot show its answer safely. Tell your gateway administrator; retrying will not help.`;
const WITHHELD_INPUT = "[input withheld]";
const CONTROL_TEXT = "harmless control text without any known value";
const REFUSE_TOOL = "refuse_probe";
const REFUSE_FULL = `mcp__agent-gateway-tools__${REFUSE_TOOL}`;

/**
 * The gateway build the negative controls start instead of `dist/server.js`. It is honored only in a child run
 * (`SECURITY_MASK_CHILD=1`); anywhere else a set variable throws, so a leaked variable can never make an ordinary run
 * green against another build.
 */
function negativeControlServer(): string | undefined {
  const dist = process.env.SECURITY_MASK_DIST;
  if (dist === undefined || dist === "") return undefined;
  if (process.env.SECURITY_MASK_CHILD !== "1") throw new Error("SECURITY_MASK_DIST is set outside a negative-control child run");
  return dist;
}

const markers: SecurityMarkers = createMarkers();
const recorder = new MatrixRecorder("security-stream-input-process", ROW_IDS);

const cleanups: Cleanup[] = [];
afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()!();
});

beforeAll(() => {
  requireHost(["bwrap", "userns", "git", "python3", "build"]);
  emit(
    evidenceLine({
      suite: "security-stream-input-process",
      config: { API_KEYS: "reqlift+diemcrm", ANTHROPIC_BASE_URL: "local-double", MODEL_PROXY_OAUTH_TOKEN_URL: "local-double", WEBHOOK_TOOL: "stream_input raw" },
      deadlines: { turn_ms: TURN_DEADLINE_MS, row_test_timeout_ms: 300_000 },
      offline: false,
      logLevel: "debug",
    }),
  );
});


/** The synthetic values of the MVP-8207 rows. Not rig markers: each row checks them itself, by name only. */
function maskValues(seed: string): Record<string, string> {
  const dbUser = `SYNTH-DBUSER-${seed}`;
  const dbPass = `SYNTH-DBPASS-${seed}`;
  return {
    dbUser,
    dbPass,
    dbLogin: `${dbUser}:${dbPass}`,
    regToken: `SYNTH-REGTOKEN-${seed}`,
    reqBasicToken: `SYNTH-REQBASIC-${seed}`,
    ovrToken: `SYNTH-OVRTOKEN-${seed}`,
  };
}

/** A token of exactly 7 characters, under the 8-character threshold for a known value. */
const shortToken = (seed: string): string => `s${seed}000000`.slice(0, 7);

/** The stored servers of the MVP-8207 rows: V1 as a header, V2 as an env value, a `Bearer` registry token, a 7-character `Bearer` token. */
async function registerMaskServers(rig: SecurityRig, values: Record<string, string>, short: string): Promise<void> {
  await rig.register("reqlift", "dbhttp", { type: "http", url: rig.jira.url, headers: { "X-Db-User": values.dbUser, Authorization: `Bearer ${values.regToken}` } });
  await rig.register("reqlift", "dbstdio", { type: "stdio", command: "node", args: ["-e", STDIO_SOURCE, "mask-args"], env: { DB_LOGIN: values.dbLogin } });
  await rig.register("reqlift", "dbshort", { type: "http", url: rig.jira.url, headers: { Authorization: `Bearer ${short}` } });
}

async function registerRawProbe(rig: SecurityRig): Promise<string[]> {
  const put = await gatewayRequest(
    rig.gateway.port,
    "PUT",
    `/v1/tools/${TOOL}`,
    { description: "Probe tool whose input is streamed as an object.", input_schema: { type: "object", properties: { question: { type: "string" } }, required: ["question"] }, webhook_url: `${rig.webhook.base}/${TOOL}`, stream_input: "raw" },
    rig.keys.reqlift,
  );
  return put.status !== 201 || put.json?.stream_input !== "raw" ? ["the raw tool was not registered"] : [];
}

type StreamEvent = { type: string; toolName?: string; input?: unknown; output?: string; success?: boolean };

async function replayOf(rig: SecurityRig, queryId: string): Promise<{ status: number; text: string; events: StreamEvent[] }> {
  const replay = await gatewayRequest(rig.gateway.port, "GET", `/v1/query/${queryId}/events`, undefined, rig.keys.reqlift);
  const events = replay.text.split("\n").filter((line) => line.trim().startsWith("{")).map((line) => JSON.parse(line) as StreamEvent);
  return { status: replay.status, text: replay.text, events };
}

/** Names and counts only: the (surface, value) pairs of the row's own values found on a surface. */
function leakProblems(surfaces: Surface[], values: Record<string, string>): string[] {
  const hits = detect(surfaces, values);
  return hits.length > 0 ? [`hits=${hits.length} [${hits.join(", ")}]`] : [];
}

const ROW_PREFIX = "secrets the gateway holds ";

describe("a raw tool's structured input and the secrets the gateway holds", () => {
  it("every row id has an AC description in the single map", () => {
    expect(ROW_IDS.filter((id) => AC_ROWS[id] === undefined)).toEqual([]);
  });

  it("SI.stream-input-secret: no known secret value reaches the stream, the replay or the debug log, and the permitted call streams the object", async () => {
    const rig = await createRig(cleanups, { markers, logLevel: "debug", rootPrefix: "mvp8096-sec-" });
    expect(pinnedProblems(rig)).toEqual([]);
    await registerStandardServers(rig);
    const v = rig.markers.values;
    const started = Date.now();

    const put = await gatewayRequest(
      rig.gateway.port,
      "PUT",
      `/v1/tools/${TOOL}`,
      { description: "Probe tool whose input is streamed as an object.", input_schema: { type: "object", properties: { question: { type: "string" } }, required: ["question"] }, webhook_url: `${rig.webhook.base}/${TOOL}`, stream_input: "raw" },
      rig.keys.reqlift,
    );
    const problems: string[] = [];
    if (put.status !== 201 || put.json?.stream_input !== "raw") problems.push("the raw tool was not registered");

    // One known value per call: a registry header value (as stored), the per-user override value (as sent), the caller's own key,
    // a request-body server's header value and a request-body stdio env value; then the permitted control.
    const known: { name: string; value: string }[] = [
      { name: "registry_header", value: `Basic ${v.registryHttpHeader}` },
      { name: "user_override_header", value: `Bearer ${v.userOverrideHeader}` },
      { name: "caller_gateway_key", value: v.gatewayKeyReqlift },
      { name: "request_server_header", value: `Bearer ${v.requestHttpHeader}` },
      { name: "request_server_env", value: v.requestStdioEnv },
    ];
    const hitsBefore = rig.webhook.hits.length;
    const turn = await chatTurn(rig, {
      prompt: "SI-SECRET",
      sessionId: "conv-si-secret",
      steps: [...known.map((entry) => ({ name: FULL, input: { question: entry.value } })), { name: FULL, input: { question: CONTROL_TEXT } }],
      body: { allowedTools: [...ROUTE_ALLOWED_TOOLS, FULL] },
    });
    problems.push(...turnProblems(turn));

    const events = turn.outcome.events as { type: string; toolName?: string; input?: unknown }[];
    const probeEvents = events.filter((event) => event.type === "tool_use" && event.toolName === FULL);
    if (probeEvents.length !== known.length + 1) problems.push(`the stream held ${probeEvents.length} probe tool_use events, expected ${known.length + 1}`);
    for (const [index, entry] of known.entries()) {
      const input = probeEvents[index]?.input;
      if (typeof input !== "string") problems.push(`${entry.name}: the event input is not a summary string`);
      else if (!input.includes("[REDACTED]")) problems.push(`${entry.name}: the summary does not show [REDACTED]`);
    }
    // The permitted control: no known value, so the object is streamed.
    const control = probeEvents[known.length]?.input as { question?: string } | string | undefined;
    if (typeof control !== "object" || control === null || control.question !== CONTROL_TEXT) problems.push("control: the call without a known value did not stream the object");
    // The webhook received every call, so the withheld input is only about what is streamed.
    const webhookHits = rig.webhook.hits.slice(hitsBefore).filter((hit) => hit.path === `/${TOOL}`).length;
    if (webhookHits !== known.length + 1) problems.push(`control: the webhook received ${webhookHits} calls, expected ${known.length + 1}`);

    // The replay of the same run.
    const replay = await gatewayRequest(rig.gateway.port, "GET", `/v1/query/${turn.queryId}/events`, undefined, rig.keys.reqlift);
    if (replay.status !== 200) problems.push("the replay did not answer 200");
    const replayed = replay.text.split("\n").filter((line) => line.trim().startsWith("{")).map((line) => JSON.parse(line) as { type: string; toolName?: string; input?: unknown });
    const replayedProbe = replayed.filter((event) => event.type === "tool_use" && event.toolName === FULL);
    if (JSON.stringify(replayedProbe.map((event) => event.input)) !== JSON.stringify(probeEvents.map((event) => event.input))) problems.push("the replay's inputs differ from the stream's");

    // The debug log is live (it carries the emitted events and the withheld lines) and holds no value.
    const log = rig.log().slice(turn.logFrom);
    const withheld = log.split("\n").filter((line) => line.includes("tool.stream_input.withheld") && line.includes("reason=secret")).length;
    if (withheld !== known.length) problems.push(`the gateway log holds ${withheld} secret-withheld lines, expected ${known.length}`);
    if (!log.includes('"type":"tool_use"') && !log.includes("tool_use")) problems.push("control: the debug log does not show emitted events, so its absence rows prove nothing");

    const surfaces: Surface[] = [
      { name: "events", text: JSON.stringify(turn.outcome.events) },
      { name: "replay", text: replay.text },
      { name: "gateway-log", text: log },
    ];
    finishRow(recorder, rig, {
      id: "SI.stream-input-secret",
      durationMs: Date.now() - started,
      deadlineMs: TURN_DEADLINE_MS,
      surfaces,
      floors: { events: 100, replay: 100, "gateway-log": 100 },
      controls: ["raw_tool_registered", "five_known_values_each_in_a_summary_with_redacted", "permitted_call_streams_the_object", "webhook_received_every_call", "replay_equals_stream", "debug_log_shows_the_withheld_lines"],
      problems,
    });
  });

  it("SI.mask-overlap: a known value that starts a longer one leaves no fragment of the longer one on the stream, the replay or the debug log", async () => {
    const rig = await createRig(cleanups, { markers, logLevel: "debug", rootPrefix: "mvp8207-ovl-", distServer: negativeControlServer() });
    expect(pinnedProblems(rig)).toEqual([]);
    await registerStandardServers(rig);
    const values = maskValues(rig.markers.seed);
    await registerMaskServers(rig, values, shortToken(rig.markers.seed));
    const started = Date.now();
    const problems = await registerRawProbe(rig);
    // The known-value list is sorted: the shorter value comes first, which is the order that leaked before the fix.
    if (!(values.dbUser < values.dbLogin && values.dbLogin.startsWith(values.dbUser))) problems.push("precondition: the shorter value does not sort before the longer one");

    const hitsBefore = rig.webhook.hits.length;
    const turn = await chatTurn(rig, {
      prompt: "SI-MASK-OVERLAP",
      sessionId: "conv-si-mask-overlap",
      steps: [
        { name: FULL, input: { question: `login ${values.dbLogin} now` } },
        { name: FULL, input: { question: CONTROL_TEXT } },
      ],
      body: { allowedTools: [...ROUTE_ALLOWED_TOOLS, FULL] },
    });
    problems.push(...turnProblems(turn));

    const probeEvents = (turn.outcome.events as StreamEvent[]).filter((event) => event.type === "tool_use" && event.toolName === FULL);
    if (probeEvents.length !== 2) problems.push(`the stream held ${probeEvents.length} probe tool_use events, expected 2`);
    const masked = probeEvents[0]?.input;
    if (typeof masked !== "string") problems.push("the event input of the overlapping value is not a summary string");
    else if (!masked.includes("login [REDACTED] now")) problems.push("the summary does not show `login [REDACTED] now`");
    const control = probeEvents[1]?.input as { question?: string } | string | undefined;
    if (typeof control !== "object" || control === null || control.question !== CONTROL_TEXT) problems.push("control: the call without a known value did not stream the object");
    const webhookHits = rig.webhook.hits.slice(hitsBefore).filter((hit) => hit.path === `/${TOOL}`).length;
    if (webhookHits !== 2) problems.push(`control: the webhook received ${webhookHits} calls, expected 2`);

    const replay = await replayOf(rig, turn.queryId);
    if (replay.status !== 200) problems.push("the replay did not answer 200");
    const replayedInputs = replay.events.filter((event) => event.type === "tool_use" && event.toolName === FULL).map((event) => event.input);
    if (JSON.stringify(replayedInputs) !== JSON.stringify(probeEvents.map((event) => event.input))) problems.push("the replay's inputs differ from the stream's");
    const log = rig.log().slice(turn.logFrom);
    if (!log.includes("tool.stream_input.withheld")) problems.push("control: the debug log does not show the withheld line, so its absence rows prove nothing");

    const surfaces: Surface[] = [
      { name: "events", text: JSON.stringify(turn.outcome.events) },
      { name: "replay", text: replay.text },
      { name: "gateway-log", text: log },
    ];
    problems.push(...leakProblems(surfaces, { dbUser: values.dbUser, dbPass: values.dbPass, dbLogin: values.dbLogin }));
    finishRow(recorder, rig, {
      id: "SI.mask-overlap",
      durationMs: Date.now() - started,
      deadlineMs: TURN_DEADLINE_MS,
      surfaces,
      floors: { events: 100, replay: 100, "gateway-log": 100 },
      controls: ["raw_tool_registered", "shorter_value_sorts_first", "longer_value_fully_redacted", "permitted_call_streams_the_object", "webhook_received_every_call", "replay_equals_stream", "debug_log_shows_the_withheld_line"],
      problems,
    });
  });

  it("SI.mask-scheme: the bare token of a Bearer or Basic header is masked whatever its source, and a 7-character token is not", async () => {
    const rig = await createRig(cleanups, { markers, logLevel: "debug", rootPrefix: "mvp8207-sch-", distServer: negativeControlServer() });
    expect(pinnedProblems(rig)).toEqual([]);
    await registerStandardServers(rig);
    const values = maskValues(rig.markers.seed);
    const short = shortToken(rig.markers.seed);
    await registerMaskServers(rig, values, short);
    const started = Date.now();
    const problems = await registerRawProbe(rig);
    const v = rig.markers.values;

    // One bare token per call: (a) a stored registry server, (b) a per-request MCP server (`Bearer`), (c) a per-user override (`Basic`).
    const known: { name: string; value: string }[] = [
      { name: "registry_bearer", value: values.regToken },
      { name: "request_server_bearer", value: v.requestHttpHeader },
      { name: "user_override_basic", value: values.ovrToken },
    ];
    const hitsBefore = rig.webhook.hits.length;
    const turn = await chatTurn(rig, {
      prompt: "SI-MASK-SCHEME",
      sessionId: "conv-si-mask-scheme",
      steps: [...known.map((entry) => ({ name: FULL, input: { question: entry.value } })), { name: FULL, input: { question: short } }, { name: FULL, input: { question: CONTROL_TEXT } }],
      body: { allowedTools: [...ROUTE_ALLOWED_TOOLS, FULL], mcpCredentialOverrides: { jira: { headers: { authorization: `Basic ${values.ovrToken}` } } } },
    });
    problems.push(...turnProblems(turn));

    const probeEvents = (turn.outcome.events as StreamEvent[]).filter((event) => event.type === "tool_use" && event.toolName === FULL);
    if (probeEvents.length !== known.length + 2) problems.push(`the stream held ${probeEvents.length} probe tool_use events, expected ${known.length + 2}`);
    for (const [index, entry] of known.entries()) {
      const input = probeEvents[index]?.input;
      if (typeof input !== "string") problems.push(`${entry.name}: the event input is not a summary string`);
      else if (!input.includes("[REDACTED]")) problems.push(`${entry.name}: the summary does not show [REDACTED]`);
    }
    // The threshold control: a 7-character token is no known value, so the object streams unchanged.
    const thresholdInput = probeEvents[known.length]?.input as { question?: string } | string | undefined;
    if (typeof thresholdInput !== "object" || thresholdInput === null || thresholdInput.question !== short) problems.push("threshold control: the 7-character token was not streamed unchanged");
    const control = probeEvents[known.length + 1]?.input as { question?: string } | string | undefined;
    if (typeof control !== "object" || control === null || control.question !== CONTROL_TEXT) problems.push("control: the call without a known value did not stream the object");
    const webhookHits = rig.webhook.hits.slice(hitsBefore).filter((hit) => hit.path === `/${TOOL}`).length;
    if (webhookHits !== known.length + 2) problems.push(`control: the webhook received ${webhookHits} calls, expected ${known.length + 2}`);

    const replay = await replayOf(rig, turn.queryId);
    if (replay.status !== 200) problems.push("the replay did not answer 200");
    const replayedInputs = replay.events.filter((event) => event.type === "tool_use" && event.toolName === FULL).map((event) => event.input);
    if (JSON.stringify(replayedInputs) !== JSON.stringify(probeEvents.map((event) => event.input))) problems.push("the replay's inputs differ from the stream's");
    const log = rig.log().slice(turn.logFrom);
    const withheld = log.split("\n").filter((line) => line.includes("tool.stream_input.withheld") && line.includes("reason=secret")).length;
    if (withheld !== known.length) problems.push(`the gateway log holds ${withheld} secret-withheld lines, expected ${known.length}`);

    // The 7-character token is expected on the surfaces (control); every other value is not.
    const surfaces: Surface[] = [
      { name: "events", text: JSON.stringify(turn.outcome.events) },
      { name: "replay", text: replay.text },
      { name: "gateway-log", text: log },
    ];
    problems.push(...leakProblems(surfaces, { regToken: values.regToken, ovrToken: values.ovrToken }));
    finishRow(recorder, rig, {
      id: "SI.mask-scheme",
      durationMs: Date.now() - started,
      deadlineMs: TURN_DEADLINE_MS,
      surfaces,
      floors: { events: 100, replay: 100, "gateway-log": 100 },
      controls: ["raw_tool_registered", "three_bare_tokens_each_in_a_summary_with_redacted", "seven_character_token_streams_the_object", "permitted_call_streams_the_object", "webhook_received_every_call", "replay_equals_stream", "debug_log_shows_the_withheld_lines"],
      problems,
    });
  });

  it("SI.refusal-mask: a webhook refusal text masks an overlapping value and the bare token of a registry, request-server or override header", async () => {
    const rig = await createRig(cleanups, { markers, logLevel: "debug", rootPrefix: "mvp8207-ref-", distServer: negativeControlServer() });
    expect(pinnedProblems(rig)).toEqual([]);
    await registerStandardServers(rig);
    const values = maskValues(rig.markers.seed);
    await registerMaskServers(rig, values, shortToken(rig.markers.seed));
    const started = Date.now();
    const problems: string[] = [];

    const refusals = [
      { name: "overlap", message: `bad login ${values.dbLogin} end` },
      { name: "registry_bearer", message: `bad token ${values.regToken} end` },
      { name: "request_server_basic", message: `bad token ${values.reqBasicToken} end` },
      { name: "user_override_basic", message: `bad token ${values.ovrToken} end` },
    ];
    const plain = "bad request without any known value";
    const refuser = await startRefusingDouble([...refusals.map((entry) => entry.message), plain]);
    cleanups.push(() => refuser.close());
    const put = await gatewayRequest(
      rig.gateway.port,
      "PUT",
      `/v1/tools/${REFUSE_TOOL}`,
      { description: "Probe tool that always refuses.", input_schema: { type: "object", properties: {} }, webhook_url: `${refuser.base}/${REFUSE_TOOL}` },
      rig.keys.reqlift,
    );
    if (put.status !== 201) problems.push("the refusing tool was not registered");

    const base = requestCredentials(rig);
    const turn = await chatTurn(rig, {
      prompt: "SI-REFUSAL-MASK",
      sessionId: "conv-si-refusal-mask",
      steps: Array.from({ length: refusals.length + 1 }, () => ({ name: REFUSE_FULL, input: {} })),
      body: {
        // A request server with no granted tool is not attached, and its credential never becomes a known value of the run.
        allowedTools: [...ROUTE_ALLOWED_TOOLS, REFUSE_FULL, "mcp__reqbasic__*"],
        mcpServers: { ...(base.mcpServers as Record<string, unknown>), reqbasic: { type: "http", url: rig.reqHttp.url, headers: { Authorization: `Basic ${values.reqBasicToken}` } } },
        mcpCredentialOverrides: { jira: { headers: { authorization: `Basic ${values.ovrToken}` } } },
      },
    });
    problems.push(...turnProblems(turn));
    if (refuser.hits.length !== refusals.length + 1) problems.push(`control: the webhook received ${refuser.hits.length} calls, expected ${refusals.length + 1}`);

    const streamed = (turn.outcome.events as StreamEvent[]).filter((event) => event.type === "tool_result" && event.toolName === REFUSE_FULL);
    if (streamed.length !== refusals.length + 1) problems.push(`the stream held ${streamed.length} refusal tool_result events, expected ${refusals.length + 1}`);
    if (turn.results.length !== refusals.length + 1) problems.push(`the model received ${turn.results.length} tool results, expected ${refusals.length + 1}`);
    for (const [index, entry] of refusals.entries()) {
      for (const [surface, text] of [["stream", streamed[index]?.output], ["model", turn.results[index]?.text]] as const) {
        if (typeof text !== "string" || !text.includes("[REDACTED]")) problems.push(`${entry.name}: the ${surface} refusal text does not show [REDACTED]`);
        else if (!text.startsWith("The tool rejected the request (HTTP 422): ")) problems.push(`${entry.name}: the ${surface} refusal text lost its prefix`);
      }
    }
    // The permitted control: a refusal without a known value is shown unchanged.
    const expectedPlain = `The tool rejected the request (HTTP 422): ${plain}`;
    if (streamed[refusals.length]?.output !== expectedPlain) problems.push("control: the stream's refusal without a known value was not shown unchanged");
    if (turn.results[refusals.length]?.text !== expectedPlain) problems.push("control: the model's refusal without a known value was not shown unchanged");

    const replay = await replayOf(rig, turn.queryId);
    if (replay.status !== 200) problems.push("the replay did not answer 200");
    const surfaces: Surface[] = [
      { name: "stream-results", text: streamed.map((event) => event.output ?? "").join("\n") },
      { name: "replay-results", text: replay.events.filter((event) => event.type === "tool_result" && event.toolName === REFUSE_FULL).map((event) => event.output ?? "").join("\n") },
      { name: "model-results", text: turn.results.map((result) => result.text).join("\n") },
    ];
    problems.push(...leakProblems(surfaces, values));
    finishRow(recorder, rig, {
      id: "SI.refusal-mask",
      durationMs: Date.now() - started,
      deadlineMs: TURN_DEADLINE_MS,
      surfaces,
      floors: { "stream-results": 100, "replay-results": 100, "model-results": 100 },
      controls: ["refusing_tool_registered", "four_refusals_each_with_redacted_on_stream_and_model_result", "refusal_without_known_value_unchanged", "webhook_received_every_call"],
      problems,
    });
  });

  it("SI.refusal-cost: about 100 override values and an 8 MiB refusal body neither delay the refusal nor stall /health", async () => {
    const rig = await createRig(cleanups, { markers, logLevel: "debug", rootPrefix: "mvp8207-cost-", distServer: negativeControlServer() });
    expect(pinnedProblems(rig)).toEqual([]);
    await registerStandardServers(rig);
    const started = Date.now();
    const problems: string[] = [];

    const body = "a".repeat(8 * 1024 * 1024 - 64);
    const refuser = await startRefusingDouble([body]);
    cleanups.push(() => refuser.close());
    const put = await gatewayRequest(
      rig.gateway.port,
      "PUT",
      `/v1/tools/${REFUSE_TOOL}`,
      { description: "Probe tool that always refuses.", input_schema: { type: "object", properties: {} }, webhook_url: `${refuser.base}/${REFUSE_TOOL}` },
      rig.keys.reqlift,
    );
    if (put.status !== 201) problems.push("the refusing tool was not registered");

    const headers = Object.fromEntries(Array.from({ length: 100 }, (_, i) => [`x-cost-${i}`, `${"a".repeat(10 + i)}b`]));
    let pinging = true;
    let worstHealthMs = 0;
    let pings = 0;
    const healthErrors: string[] = [];
    const pinger = (async () => {
      while (pinging) {
        const pingStarted = Date.now();
        try {
          await fetch(`http://127.0.0.1:${rig.gateway.port}/health`, { signal: AbortSignal.timeout(60_000) });
        } catch (error) {
          healthErrors.push(`${(error as Error).name}:${((error as { cause?: { code?: string } }).cause?.code) ?? "none"}`);
          worstHealthMs = Number.POSITIVE_INFINITY;
        }
        worstHealthMs = Math.max(worstHealthMs, Date.now() - pingStarted);
        pings++;
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
    })();
    const turn = await chatTurn(rig, {
      prompt: "SI-REFUSAL-COST",
      sessionId: "conv-si-refusal-cost",
      steps: [{ name: REFUSE_FULL, input: {} }],
      withCredentials: false,
      body: {
        allowedTools: [...ROUTE_ALLOWED_TOOLS, REFUSE_FULL],
        mcpCredentialOverrides: { jira: { headers } },
      },
    });
    pinging = false;
    await pinger;

    problems.push(...turnProblems(turn));
    if (refuser.hits.length !== 1) problems.push(`control: the webhook received ${refuser.hits.length} calls, expected 1`);
    if (turn.outcome.ms > REFUSAL_COST_TURN_MS) problems.push(`the turn took ${turn.outcome.ms} ms, budget ${REFUSAL_COST_TURN_MS} ms`);
    if (pings < 3) problems.push(`control: only ${pings} health pings were answered during the turn`);
    if (worstHealthMs > REFUSAL_COST_HEALTH_MS) problems.push(`/health waited ${worstHealthMs} ms during the turn, budget ${REFUSAL_COST_HEALTH_MS} ms`);
    // The permitted control: the refusal text is the tool's own message, cut to 500 characters, and nothing in it is masked.
    const expected = `The tool rejected the request (HTTP 422): ${"a".repeat(500)}`;
    if (turn.results[0]?.text !== expected) problems.push("control: the model's refusal text was not the unmasked message cut to 500 characters");
    emit(`SECURITY-MASK-EVIDENCE refusal-cost override_values=100 body_bytes=${body.length + 14} turn_ms=${turn.outcome.ms} health_pings=${pings} health_max_ms=${worstHealthMs} health_errors=${healthErrors.join("+") || "none"}`);
    finishRow(recorder, rig, {
      id: "SI.refusal-cost",
      durationMs: Date.now() - started,
      deadlineMs: TURN_DEADLINE_MS,
      surfaces: [{ name: "model-results", text: turn.results.map((result) => result.text).join("\n") }],
      floors: { "model-results": 100 },
      controls: ["refusing_tool_registered", "webhook_received_the_call", "health_answered_during_the_turn", "refusal_text_unmasked_and_cut"],
      problems,
    });
  });

  it("SI.credentials-bound: an 8 MB request of credential values is refused at validation, /health stays responsive, and a request within the limits still runs", async () => {
    const rig = await createRig(cleanups, { markers, logLevel: "debug", rootPrefix: "mvp8207-bound-", distServer: negativeControlServer() });
    expect(pinnedProblems(rig)).toEqual([]);
    await registerStandardServers(rig);
    const started = Date.now();
    const problems: string[] = [];

    const refuser = await startRefusingDouble(["refused with a plain message"]);
    cleanups.push(() => refuser.close());
    const put = await gatewayRequest(
      rig.gateway.port,
      "PUT",
      `/v1/tools/${REFUSE_TOOL}`,
      { description: "Probe tool that always refuses.", input_schema: { type: "object", properties: {} }, webhook_url: `${refuser.base}/${REFUSE_TOOL}` },
      rig.keys.reqlift,
    );
    if (put.status !== 201) problems.push("the refusing tool was not registered");

    let pinging = true;
    let worstHealthMs = 0;
    let pings = 0;
    const pinger = (async () => {
      while (pinging) {
        const pingStarted = Date.now();
        try {
          await fetch(`http://127.0.0.1:${rig.gateway.port}/health`, { signal: AbortSignal.timeout(60_000) });
        } catch {
          worstHealthMs = Number.POSITIVE_INFINITY;
        }
        worstHealthMs = Math.max(worstHealthMs, Date.now() - pingStarted);
        pings++;
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
    })();

    // 1600 values of `Bearer ` + 5000 characters, a synthetic marker in the first: 8 MB in total, once as per-user overrides
    // and once as the headers of a request server.
    const marker = `SYNTH-BOUND-${rig.markers.seed}`;
    const values = Array.from({ length: 1600 }, (_, i) => `Bearer ${i === 0 ? marker : ""}${"a".repeat(5000)}`);
    const asHeaders = Object.fromEntries(values.map((value, i) => [`x-big-${i}`, value]));
    const attempts: { name: string; status: number; text: string; ms: number }[] = [];
    // Four rounds of both shapes, so the health pings overlap the refusals.
    const shapes = [
      ["overrides", { mcpCredentialOverrides: { jira: { headers: asHeaders } } }],
      ["request-server", { mcpServers: { bigsrv: { url: "http://127.0.0.1:9/mcp", headers: asHeaders } } }],
    ] as const;
    for (const [name, extra] of [0, 1, 2, 3].flatMap(() => shapes)) {
      const sent = Date.now();
      const res = await gatewayRequest(
        rig.gateway.port,
        "POST",
        "/v1/query",
        { queryId: `q-bound-${name}-${randomBytes(3).toString("hex")}`, prompt: "SI-CREDENTIALS-BOUND", user_id: "user-1", ...extra },
        rig.keys.reqlift,
      );
      attempts.push({ name, status: res.status, text: res.text, ms: Date.now() - sent });
    }
    pinging = false;
    await pinger;

    for (const attempt of attempts) {
      let error: { code?: string } | undefined;
      try {
        error = (JSON.parse(attempt.text) as { error?: { code?: string } }).error;
      } catch {
        error = undefined; // a stream of events, not a refusal
      }
      if (attempt.status !== 400 || error?.code !== "MCP_CREDENTIALS_TOO_LARGE") problems.push(`${attempt.name}: answered ${attempt.status} ${error?.code ?? "no code"}, expected 400 MCP_CREDENTIALS_TOO_LARGE`);
      if (attempt.text.length > 400) problems.push(`${attempt.name}: the refusal body is ${attempt.text.length} characters, expected a short fixed text`);
      if (attempt.text.includes(marker)) problems.push(`${attempt.name}: the refusal body holds a request value`);
      if (attempt.ms > BOUND_REFUSAL_MS) problems.push(`${attempt.name}: the refusal took ${attempt.ms} ms, budget ${BOUND_REFUSAL_MS} ms`);
    }
    if (refuser.hits.length !== 0) problems.push(`no run may start, but the webhook received ${refuser.hits.length} calls`);
    if (pings < 3) problems.push(`control: only ${pings} health pings were answered during the refusals`);
    if (worstHealthMs > REFUSAL_COST_HEALTH_MS) problems.push(`/health waited ${worstHealthMs} ms during the refusals, budget ${REFUSAL_COST_HEALTH_MS} ms`);

    // The permitted control: the same route with a request within the limits runs, the refusing tool is called and its text is masked.
    const small = `Bearer SYNTH-BOUND-OK-${rig.markers.seed}`;
    const turn = await chatTurn(rig, {
      prompt: "SI-CREDENTIALS-BOUND-OK",
      sessionId: "conv-si-credentials-bound",
      steps: [{ name: REFUSE_FULL, input: {} }],
      withCredentials: false,
      body: { allowedTools: [...ROUTE_ALLOWED_TOOLS, REFUSE_FULL], mcpCredentialOverrides: { jira: { headers: { "x-small": small } } } },
    });
    problems.push(...turnProblems(turn));
    if (refuser.hits.length !== 1) problems.push(`control: the webhook received ${refuser.hits.length} calls after the in-limit request, expected 1`);
    emit(
      `SECURITY-MASK-EVIDENCE credentials-bound request_bytes=${JSON.stringify({ x: asHeaders }).length} ${attempts.map((a) => `${a.name}_status=${a.status} ${a.name}_ms=${a.ms}`).join(" ")} health_pings=${pings} health_max_ms=${worstHealthMs} control_turn_ms=${turn.outcome.ms}`,
    );
    finishRow(recorder, rig, {
      id: "SI.credentials-bound",
      durationMs: Date.now() - started,
      deadlineMs: TURN_DEADLINE_MS,
      surfaces: [
        { name: "refusal-bodies", text: attempts.map((a) => a.text).join("\n") },
        { name: "model-results", text: turn.results.map((result) => result.text).join("\n") },
      ],
      floors: { "refusal-bodies": 50, "model-results": 20 },
      controls: ["refusing_tool_registered", "both_oversize_requests_answered_400_with_the_code", "no_value_in_the_refusal_body", "webhook_not_called_by_the_refused_requests", "health_answered_during_the_refusals", "in_limit_request_on_the_same_route_ran"],
      problems,
    });
  });


  /**
   * Hand-written state files model an entry stored before the write caps existed: the gateway must load it, and the masking
   * budget (not the cap) is what keeps a refusal cheap and closed.
   */
  const storedBudgetRow = (id: string, plant: "registry" | "url") => async (): Promise<void> => {
    const huge = randomBytes(4_000_000).toString("hex");
    const now = new Date().toISOString();
    const rig = await createRig(cleanups, {
      markers,
      logLevel: "debug",
      rootPrefix: `mvp8207-${plant}-`,
      distServer: negativeControlServer(),
      seed: (dirs) => {
        if (plant === "registry") {
          fs.writeFileSync(path.join(dirs.persist, "mcp-servers.json"), JSON.stringify([{ name: "qabig", type: "http", url: "http://127.0.0.1:9/mcp", description: "", enabled: true, headers: { Authorization: `Bearer ${huge}` }, owner: "reqlift", createdAt: now, updatedAt: now }]));
        } else {
          fs.writeFileSync(path.join(dirs.persist, "tools.json"), JSON.stringify([{ name: "qabigurl", description: "stored before the cap", input_schema: { type: "object", properties: {} }, webhook_url: `http://127.0.0.1:9/${huge}`, timeout_ms: 1000, owner: "reqlift", stream_input: "summary" }]));
        }
      },
    });
    expect(pinnedProblems(rig)).toEqual([]);
    const started = Date.now();
    const problems: string[] = [];

    const refuser = await startRefusingDouble(["a".repeat(8 * 1024 * 1024 - 64)]);
    cleanups.push(() => refuser.close());
    const put = await gatewayRequest(
      rig.gateway.port,
      "PUT",
      `/v1/tools/${REFUSE_TOOL}`,
      { description: "Probe tool that always refuses.", input_schema: { type: "object", properties: {} }, webhook_url: `${refuser.base}/${REFUSE_TOOL}` },
      rig.keys.reqlift,
    );
    if (put.status !== 201) problems.push("the refusing tool was not registered");
    problems.push(...(await registerRawProbe(rig)));
    const listed = await gatewayRequest(rig.gateway.port, "GET", plant === "registry" ? "/v1/mcp-servers/qabig" : "/v1/tools/qabigurl", undefined, rig.keys.reqlift);
    if (listed.status !== 200) problems.push(`control: the stored oversized entry did not load (GET answered ${listed.status})`);

    let pinging = true;
    let worstHealthMs = 0;
    let pings = 0;
    const pinger = (async () => {
      while (pinging) {
        const pingStarted = Date.now();
        try {
          await fetch(`http://127.0.0.1:${rig.gateway.port}/health`, { signal: AbortSignal.timeout(60_000) });
        } catch {
          worstHealthMs = Number.POSITIVE_INFINITY;
        }
        worstHealthMs = Math.max(worstHealthMs, Date.now() - pingStarted);
        pings++;
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
    })();
    const turn = await chatTurn(rig, {
      prompt: `SI-STORED-${plant.toUpperCase()}`,
      sessionId: `conv-si-stored-${plant}`,
      steps: [{ name: FULL, input: { question: "plain question" } }, { name: REFUSE_FULL, input: {} }, { name: REFUSE_FULL, input: {} }],
      withCredentials: false,
      body: { allowedTools: [...ROUTE_ALLOWED_TOOLS, FULL, REFUSE_FULL] },
    });
    pinging = false;
    await pinger;

    problems.push(...turnProblems(turn));
    if (refuser.hits.length !== 2) problems.push(`control: the webhook received ${refuser.hits.length} refusing calls, expected 2`);
    if (turn.outcome.ms > REFUSAL_COST_TURN_MS) problems.push(`the turn took ${turn.outcome.ms} ms, budget ${REFUSAL_COST_TURN_MS} ms`);
    if (pings < 3) problems.push(`control: only ${pings} health pings were answered during the turn`);
    if (worstHealthMs > REFUSAL_COST_HEALTH_MS) problems.push(`/health waited ${worstHealthMs} ms during the turn, budget ${REFUSAL_COST_HEALTH_MS} ms`);
    const refusals = turn.results.filter((result) => result.text.startsWith("The tool rejected") || result.text.startsWith("TOOL_"));
    if (refusals.length !== 2) problems.push(`the model received ${refusals.length} refusal results, expected 2`);
    for (const result of refusals) if (result.text !== WITHHELD_REFUSAL) problems.push("a refusal result is not the fixed withheld text");
    const streamedRefusals = (turn.outcome.events as StreamEvent[]).filter((event) => event.type === "tool_result" && event.toolName === REFUSE_FULL);
    for (const event of streamedRefusals) if (event.output !== WITHHELD_REFUSAL) problems.push("a streamed refusal is not the fixed withheld text");
    const toolUse = (turn.outcome.events as StreamEvent[]).find((event) => event.type === "tool_use" && event.toolName === FULL);
    if (toolUse?.input !== WITHHELD_INPUT) problems.push("the raw tool's tool_use input is not the fixed placeholder");
    if (!rig.log().includes("masking.budget_exceeded")) problems.push("the budget log line is missing");
    // A webhook address is returned by GET /v1/tools (and so echoed by the response log at debug level); a registry header is write-only.
    if (plant === "registry" && rig.log().includes(huge.slice(0, 64))) problems.push("the gateway log holds a stored value");
    emit(`SECURITY-MASK-EVIDENCE ${id} stored_bytes=${huge.length} turn_ms=${turn.outcome.ms} health_pings=${pings} health_max_ms=${worstHealthMs}`);
    finishRow(recorder, rig, {
      id,
      durationMs: Date.now() - started,
      deadlineMs: TURN_DEADLINE_MS,
      surfaces: [
        { name: "model-results", text: turn.results.map((result) => result.text).join("\n") },
        { name: "stream-events", text: JSON.stringify(turn.outcome.events) },
      ],
      floors: { "model-results": 50, "stream-events": 100 },
      controls: ["refusing_tool_registered", "stored_oversized_entry_loaded", "webhook_received_both_calls", "health_answered_during_the_turn", "both_refusals_are_the_fixed_text", "raw_tool_input_is_the_placeholder", "budget_line_logged"],
      problems,
    });
  };

  it("SI.stored-registry-budget: a stored registry value of 8 MB neither stalls /health nor lets a refusal text through", storedBudgetRow("SI.stored-registry-budget", "registry"));
  it("SI.stored-url-budget: a stored webhook URL of 8 MB neither stalls /health nor lets a refusal text through", storedBudgetRow("SI.stored-url-budget", "url"));

  it("SI.stored-write-caps: an 8 MB header value or webhook URL is refused at the write route, fast, nothing is stored and /health stays responsive", async () => {
    const rig = await createRig(cleanups, { markers, logLevel: "debug", rootPrefix: "mvp8207-caps-", distServer: negativeControlServer() });
    expect(pinnedProblems(rig)).toEqual([]);
    const started = Date.now();
    const problems: string[] = [];
    const huge = randomBytes(4_000_000).toString("hex");
    const attempts: { name: string; status: number; code?: string; text: string; ms: number }[] = [];
    const send = async (name: string, route: string, body: Record<string, unknown>): Promise<void> => {
      const sent = Date.now();
      const res = await gatewayRequest(rig.gateway.port, "PUT", route, body, rig.keys.reqlift);
      attempts.push({ name, status: res.status, code: (res.json?.error as { code?: string } | undefined)?.code, text: res.text, ms: Date.now() - sent });
    };
    await send("header", "/v1/mcp-servers/qabig", { type: "http", url: rig.jira.url, headers: { Authorization: `Bearer ${huge}` } });
    await send("env", "/v1/mcp-servers/qabigenv", { type: "stdio", command: "node", env: { TOKEN: huge } });
    await send("args", "/v1/mcp-servers/qabigargs", { type: "stdio", command: "node", args: [huge] });
    await send("webhook_url", "/v1/tools/qabigurl", { description: "big", input_schema: { type: "object", properties: {} }, webhook_url: `http://127.0.0.1:9/${huge}` });
    const expectedCodes: Record<string, string> = { header: "MCP_SERVER_VALUE_TOO_LARGE", env: "MCP_SERVER_VALUE_TOO_LARGE", args: "MCP_SERVER_VALUE_TOO_LARGE", webhook_url: "TOOL_WEBHOOK_URL_TOO_LONG" };
    for (const attempt of attempts) {
      if (attempt.status !== 400 || attempt.code !== expectedCodes[attempt.name]) problems.push(`${attempt.name}: answered ${attempt.status} ${attempt.code ?? "no code"}, expected 400 ${expectedCodes[attempt.name]}`);
      if (attempt.text.length > 400) problems.push(`${attempt.name}: the refusal body is ${attempt.text.length} characters, expected a short fixed text`);
      if (attempt.text.includes(huge.slice(0, 64))) problems.push(`${attempt.name}: the refusal body holds a submitted value`);
    }
    for (const route of ["/v1/mcp-servers/qabig", "/v1/mcp-servers/qabigenv", "/v1/mcp-servers/qabigargs", "/v1/tools/qabigurl"]) {
      const stored = await gatewayRequest(rig.gateway.port, "GET", route, undefined, rig.keys.reqlift);
      if (stored.status !== 404) problems.push(`${route}: something was stored (GET answered ${stored.status})`);
    }
    const health = Date.now();
    const ping = await fetch(`http://127.0.0.1:${rig.gateway.port}/health`);
    const healthMs = Date.now() - health;
    if (ping.status !== 200 || healthMs > REFUSAL_COST_HEALTH_MS) problems.push(`/health answered ${ping.status} in ${healthMs} ms after the refused writes`);
    // The permitted control: a value at the cap is accepted.
    const atCap = await gatewayRequest(rig.gateway.port, "PUT", "/v1/mcp-servers/qaatcap", { type: "http", url: rig.jira.url, headers: { Authorization: `Bearer ${"b".repeat(65_536 - 7)}` } }, rig.keys.reqlift);
    if (atCap.status !== 201) problems.push(`control: a header value of exactly 65,536 bytes answered ${atCap.status}, expected 201`);
    emit(`SECURITY-MASK-EVIDENCE stored-write-caps ${attempts.map((a) => `${a.name}_status=${a.status} ${a.name}_ms=${a.ms}`).join(" ")} health_ms=${healthMs}`);
    finishRow(recorder, rig, {
      id: "SI.stored-write-caps",
      durationMs: Date.now() - started,
      deadlineMs: TURN_DEADLINE_MS,
      surfaces: [{ name: "refusal-bodies", text: attempts.map((a) => a.text).join("\n") }],
      floors: { "refusal-bodies": 50 },
      controls: ["four_oversize_writes_answered_400_with_the_code", "no_value_in_the_refusal_body", "nothing_stored", "health_answered_after_the_writes", "value_at_the_cap_accepted"],
      problems,
    });
  });
});

/* ------------------------------------------------------------------ */
/*  Negative controls                                                   */
/* ------------------------------------------------------------------ */

/**
 * A copy of `dist/` with exactly one protection taken out (the patch changes its compiled file once, asserted). The child
 * run executes this very file against it, for the named rows only, with a known marker seed, and must exit nonzero naming
 * those rows. It prints names and counts only; the parent checks that no marker value is in its output.
 */
async function negativeControl(options: { file: string; anchor: string; patch: (source: string) => string; rows: string; mustName: string[] }): Promise<void> {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "mvp8207-vulnerable-"));
  cleanups.push(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.cpSync(path.join(REPO_ROOT, "dist"), path.join(root, "dist"), { recursive: true, filter: (source) => !source.startsWith(path.join(REPO_ROOT, "dist", "tests")) });
  fs.copyFileSync(path.join(REPO_ROOT, "package.json"), path.join(root, "package.json"));
  fs.symlinkSync(path.join(REPO_ROOT, "node_modules"), path.join(root, "node_modules"));
  const target = path.join(root, "dist", options.file);
  const source = fs.readFileSync(target, "utf8");
  expect(source.split(options.anchor).length - 1, "the anchor must occur in the compiled file").toBeGreaterThanOrEqual(1);
  const patched = options.patch(source);
  expect(patched, "the patch must change the compiled file").not.toBe(source);
  fs.writeFileSync(target, patched);
  const seed = `nc${Date.now().toString(16)}`;
  const child = await runChild(
    [process.execPath, path.join(REPO_ROOT, "node_modules", "vitest", "vitest.mjs"), "run", "src/tests/security-stream-input-process.test.ts", "-t", options.rows],
    { PATH: process.env.PATH, HOME: process.env.HOME, LANG: process.env.LANG, TMPDIR: os.tmpdir(), NO_COLOR: "1", SECURITY_MARKER_SEED: seed, SECURITY_MASK_CHILD: "1", SECURITY_MASK_DIST: path.join(root, "dist", "server.js") },
    REPO_ROOT,
    280_000,
  );
  expect(child.timedOut, "the child run hit its deadline").toBe(false);
  expect(child.code !== 0 && child.code !== null, "the rows must exit nonzero against the vulnerable build").toBe(true);
  const failed = [...child.output.matchAll(/FAIL .*? > (.*)/g)].map((match) => match[1]);
  process.stderr.write(`SECURITY-MASK-EVIDENCE negative-control file=${options.file} rows=${JSON.stringify(options.rows)} exit=${child.code} failed_rows=${failed.length} marker_in_output=${child.output.includes(seed)}\n`);
  for (const name of options.mustName) expect(failed.some((title) => title.includes(name)), `the child run must fail ${name}`).toBe(true);
  expect(child.output.includes(seed), "the child output must hold no marker value").toBe(false);
}

// A child run never starts a negative control itself: its `-t` filter names rows, and this guard makes a recursion impossible.
describe.skipIf(process.env.SECURITY_MASK_CHILD === "1")("negative controls (child runs against patched copies of dist/)", () => {
  it("NC1: against a build that masks one value after another in input order, SI.mask-overlap and SI.refusal-mask fail", async () => {
    await negativeControl({
      file: "tool-mediation.js",
      anchor: "export function maskSecrets(text, secrets) {",
      patch: (source) =>
        source.replace(
          "export function maskSecrets(text, secrets) {",
          () => 'export function maskSecrets(text, secrets) {\n    let out = text;\n    for (const secret of secrets) {\n        if (secret.length >= 8)\n            out = out.split(secret).join("[REDACTED]");\n    }\n    return out;\n}\nfunction maskSecretsByRanges(text, secrets) {',
        ),
      rows: `${ROW_PREFIX}SI\\.mask-overlap:|${ROW_PREFIX}SI\\.refusal-mask:`,
      mustName: ["SI.mask-overlap", "SI.refusal-mask"],
    });
  }, 300_000);

  it("NC2: against a build without the token after Bearer or Basic, SI.mask-scheme fails", async () => {
    await negativeControl({
      file: "tool-mediation.js",
      anchor: "function withSchemeTokens(values) {",
      patch: (source) => source.replace("function withSchemeTokens(values) {", () => "function withSchemeTokens(values) {\n    return [...values];\n}\nfunction withSchemeTokensExpanded(values) {"),
      rows: `${ROW_PREFIX}SI\\.mask-scheme:`,
      mustName: ["SI.mask-scheme"],
    });
  }, 300_000);

  it("NC3: against a build whose refusal text holds no request-server or override value, SI.refusal-mask fails", async () => {
    await negativeControl({
      file: "agent.js",
      anchor: "const maskingValues = runMaskingValues(() => [",
      patch: (source) => source.replace(/const maskingValues = runMaskingValues\(\(\) => \[[\s\S]*?\n\s*\]\);/, () => "const maskingValues = runMaskingValues(() => (clientAuthToken ? [clientAuthToken] : []));"),
      rows: `${ROW_PREFIX}SI\\.refusal-mask:`,
      mustName: ["SI.refusal-mask"],
    });
  }, 300_000);

  it("NC4: against a build whose masking has no budget, SI.stored-registry-budget fails", async () => {
    await negativeControl({
      file: "tool-mediation.js",
      anchor: "if (bytes > MASKING_BUDGET_BYTES)",
      patch: (source) => source.replace("if (bytes > MASKING_BUDGET_BYTES)", () => "if (false)"),
      rows: `${ROW_PREFIX}SI\\.stored-registry-budget:`,
      mustName: ["SI.stored-registry-budget"],
    });
  }, 300_000);

  it("NC5: against a build without the registry and tool write caps, SI.stored-write-caps fails", async () => {
    await negativeControl({
      file: "routes/mcp.js",
      anchor: "if (storedValueTooLarge(body.headers, body.env, body.args))",
      patch: (source) => source.replace("if (storedValueTooLarge(body.headers, body.env, body.args))", () => "if (false)"),
      rows: `${ROW_PREFIX}SI\\.stored-write-caps:`,
      mustName: ["SI.stored-write-caps"],
    });
  }, 300_000);
});

describe("summary", () => {
  it("every expected row of the suite ran and passed", () => {
    const summary = recorder.finish();
    expect(summary.missing).toEqual([]);
    expect(summary.fail).toBe(0);
  });
});
