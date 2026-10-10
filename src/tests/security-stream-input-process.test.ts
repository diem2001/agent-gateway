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
 * The model's own tool call is the one place a value is expected (it is the scripted input), so this row does not use
 * the model-request or transcript surfaces: they hold what the "model" said, not what the gateway streamed.
 * Every secret is a synthetic marker with a random suffix; only names, booleans and counts are printed.
 * Needs `npm run build`, `bwrap`, user namespaces, `git` and `python3`. Linux only.
 */
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { Cleanup } from "./helpers/git-process-gateway.js";
import { gatewayRequest } from "./helpers/git-process-gateway.js";
import {
  AC_ROWS,
  MatrixRecorder,
  ROUTE_ALLOWED_TOOLS,
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
  turnProblems,
  type SecurityMarkers,
  type Surface,
} from "./helpers/security-matrix.js";

vi.setConfig({ testTimeout: 300_000 });

const ROW_IDS = ["SI.stream-input-secret"];
const TOOL = "stream_probe";
const FULL = `mcp__agent-gateway-tools__${TOOL}`;
const CONTROL_TEXT = "harmless control text without any known value";

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
});

describe("summary", () => {
  it("every expected row of the suite ran and passed", () => {
    const summary = recorder.finish();
    expect(summary.missing).toEqual([]);
    expect(summary.fail).toBe(0);
  });
});
