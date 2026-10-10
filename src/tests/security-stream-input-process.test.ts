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
 *
 * The model's own tool call is the one place a value is expected (it is the scripted input), so this row does not use
 * the model-request or transcript surfaces: they hold what the "model" said, not what the gateway streamed.
 * Every secret is a synthetic marker with a random suffix; only names, booleans and counts are printed.
 * Needs `npm run build`, `bwrap`, user namespaces, `git` and `python3`. Linux only.
 */
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

const ROW_IDS = ["SI.stream-input-secret", "SI.mask-overlap", "SI.mask-scheme", "SI.refusal-mask"];
const TOOL = "stream_probe";
const FULL = `mcp__agent-gateway-tools__${TOOL}`;
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

describe("negative controls (child runs against patched copies of dist/)", () => {
  it("NC1: against a build that masks one value after another in input order, SI.mask-overlap and SI.refusal-mask fail", async () => {
    await negativeControl({
      file: "tool-mediation.js",
      anchor: "export function maskSecrets(text, secrets) {",
      patch: (source) =>
        source.replace(
          "export function maskSecrets(text, secrets) {",
          () => 'export function maskSecrets(text, secrets) {\n    let out = text;\n    for (const secret of secrets) {\n        if (secret.length >= 8)\n            out = out.split(secret).join("[REDACTED]");\n    }\n    return out;\n}\nfunction maskSecretsByRanges(text, secrets) {',
        ),
      rows: "SI.mask-overlap|SI.refusal-mask",
      mustName: ["SI.mask-overlap", "SI.refusal-mask"],
    });
  }, 300_000);

  it("NC2: against a build without the token after Bearer or Basic, SI.mask-scheme fails", async () => {
    await negativeControl({
      file: "tool-mediation.js",
      anchor: "function withSchemeTokens(values) {",
      patch: (source) => source.replace("function withSchemeTokens(values) {", () => "function withSchemeTokens(values) {\n    return [...values];\n}\nfunction withSchemeTokensExpanded(values) {"),
      rows: "SI.mask-scheme",
      mustName: ["SI.mask-scheme"],
    });
  }, 300_000);

  it("NC3: against a build whose refusal text holds no request-server or override value, SI.refusal-mask fails", async () => {
    await negativeControl({
      file: "agent.js",
      anchor: "secrets: () => secretValuesForMasking([",
      patch: (source) => source.replace(/secrets: \(\) => secretValuesForMasking\(\[[\s\S]*?\n\s*\]\),/, () => "secrets: () => secretValuesForMasking(clientAuthToken ? [clientAuthToken] : []),"),
      rows: "SI.refusal-mask",
      mustName: ["SI.refusal-mask"],
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
