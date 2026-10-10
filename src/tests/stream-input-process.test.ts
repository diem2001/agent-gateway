/**
 * The structured `tool_use` input of a `stream_input: "raw"` webhook tool through the real gateway (MVP-8096, Gate C,
 * Outcome Probe): the compiled gateway (`dist/server.js`, built by `npm run build`) runs as a child process with the
 * production Claude Agent SDK, its bundled runtime in the real bubblewrap sandbox, and a scripted stand-in for the
 * Messages API. A recording webhook stub is the registered tool's webhook, so the NDJSON stream, the
 * `GET /v1/query/:queryId/events` replay and the body the webhook received can be compared with the object the
 * "model" sent.
 *
 * Rows: P1 the Story's example; P2 to P7 the six size and registration Examples (each on the stream and the replay);
 * P8 a restart keeps the registration; P9 a file written before the field loads as summary; P10 the flag grants
 * nothing; P11 a legacy ownerless entry that stores raw streams a summary; P12 another label neither replays the
 * query nor is offered the tool; P13 filtering at the real boundary; P14 U+0000 in a value; registry rows for the
 * accepted and refused values. NC1 and NC2 run this file's rows against patched copies of `dist/` and must fail.
 *
 * Needs `npm run build`, `bwrap` and user namespaces. Linux only. Every value is synthetic.
 */
import fs from "node:fs";
import http from "node:http";
import net, { type AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { startFakeAnthropicApi, type FakeAnthropicApi } from "./helpers/fake-anthropic-api.js";
import { REPO_ROOT, gatewayRequest, spawnGateway, type Cleanup, type SpawnedGateway } from "./helpers/git-process-gateway.js";
import { runChild } from "./helpers/security-matrix.js";
import { SCHEMA_FINAL_ANSWER, startToolSchemaApi, type ScriptStep, type ToolSchemaApi } from "./helpers/tool-schema-api.js";

vi.setConfig({ testTimeout: 180_000, hookTimeout: 180_000 });

const KEY_REQLIFT = "stream-input-key-reqlift-8096";
const KEY_DIEMCRM = "stream-input-key-diemcrm-8096";
const PREFIX = "mcp__agent-gateway-tools__";
const TOOL = "reqlift_present_choices";
const FULL = `${PREFIX}${TOOL}`;

/**
 * The gateway build the negative controls start instead of `dist/server.js`. It is honored only in a child run
 * (`STREAM_INPUT_CHILD=1`); anywhere else a set variable throws, so a leaked variable can never make an ordinary run
 * green against another build.
 */
function negativeControlServer(): string | undefined {
  const dist = process.env.STREAM_INPUT_DIST;
  if (dist === undefined || dist === "") return undefined;
  if (process.env.STREAM_INPUT_CHILD !== "1") throw new Error("STREAM_INPUT_DIST is set outside a negative-control child run");
  return dist;
}

const cleanups: Cleanup[] = [];
afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()!();
});
afterAll(async () => {
  while (cleanups.length > 0) await cleanups.pop()!();
});

/* ------------------------------------------------------------------ */
/*  Rig                                                                 */
/* ------------------------------------------------------------------ */

interface WebhookRequest {
  path: string;
  body: unknown;
}

interface WebhookStub {
  base: string;
  requests: WebhookRequest[];
}

async function webhookStub(into: Cleanup[]): Promise<WebhookStub> {
  const requests: WebhookRequest[] = [];
  const sockets = new Set<net.Socket>();
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      let body: unknown = null;
      try {
        body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      } catch {
        body = Buffer.concat(chunks).toString("utf8");
      }
      requests.push({ path: req.url ?? "/", body });
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ output: `WEBHOOK-OK ${req.url}` }));
    });
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  into.push(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
  return { base: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, requests };
}

interface Ndjson {
  type: string;
  [key: string]: unknown;
}

const lines = (text: string): Ndjson[] =>
  text
    .split("\n")
    .filter((line) => line.trim().startsWith("{"))
    .map((line) => JSON.parse(line) as Ndjson);

const toolUses = (events: Ndjson[]): Ndjson[] => events.filter((event) => event.type === "tool_use");

interface Rig {
  gateway: SpawnedGateway;
  webhook: WebhookStub;
  env: Record<string, string>;
  into: Cleanup[];
}

interface RigOptions {
  api: { baseUrl: string };
  env?: Record<string, string>;
  seed?: (dirs: SpawnedGateway["dirs"], webhookBase: string) => void;
  /** Where the rig's cleanup goes: the per-test list (default) or a suite's own list. */
  into?: Cleanup[];
}

async function startRig(options: RigOptions): Promise<Rig> {
  const into = options.into ?? cleanups;
  const webhook = await webhookStub(into);
  const distServer = negativeControlServer();
  const env = {
    API_KEYS: `reqlift:${KEY_REQLIFT},diemcrm:${KEY_DIEMCRM}`,
    ANTHROPIC_BASE_URL: options.api.baseUrl,
    ANTHROPIC_API_KEY: "sk-ant-fake-stream-input-8096",
    DISABLE_TELEMETRY: "1",
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
    ...options.env,
  };
  const gateway = await spawnGateway(into, {
    rootPrefix: "mvp8096-stream-",
    ...(distServer ? { distServer } : {}),
    env,
    seed: (dirs) => options.seed?.(dirs, webhook.base),
  });
  return { gateway, webhook, env, into };
}

/** SIGTERM, wait for the exit, and start a new process on the same directories (the persisted registry survives). */
async function restart(rig: Rig): Promise<Rig> {
  const old = rig.gateway;
  old.child.kill("SIGTERM");
  await new Promise<void>((resolve) => (old.child.exitCode !== null || old.child.signalCode !== null ? resolve() : old.child.once("exit", () => resolve())));
  const distServer = negativeControlServer();
  const gateway = await spawnGateway(rig.into, { reuse: old, env: rig.env, ...(distServer ? { distServer } : {}) });
  return { ...rig, gateway };
}

const put = (rig: Rig, key: string, name: string, body: Record<string, unknown>) => gatewayRequest(rig.gateway.port, "PUT", `/v1/tools/${name}`, body, key);

const SCHEMA = {
  type: "object",
  properties: { question: { type: "string" }, options: { type: "array", items: { type: "object", properties: { label: { type: "string" } } } } },
  required: ["question"],
};

const definition = (rig: Rig, name: string, extra: Record<string, unknown> = {}) => ({ description: `Probe tool ${name}.`, input_schema: SCHEMA, webhook_url: `${rig.webhook.base}/${name}`, ...extra });

async function persistedStreamInput(rig: Rig, name: string): Promise<unknown> {
  const file = path.join(rig.gateway.dirs.persist, "tools.json");
  const end = Date.now() + 8000;
  for (;;) {
    try {
      const entry = (JSON.parse(fs.readFileSync(file, "utf8")) as { name: string; stream_input?: unknown }[]).find((tool) => tool.name === name);
      if (entry) return entry.stream_input;
    } catch {
      // Not written yet.
    }
    if (Date.now() > end) throw new Error(`the registry file did not hold ${name} in time`);
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
}

let queryCounter = 0;

/** One scripted run as `key`; returns the stream's and the replay's `tool_use` events. */
async function run(rig: Rig, key: string, prompt = "Run the scripted tool calls."): Promise<{ queryId: string; status: number; stream: Ndjson[]; all: Ndjson[]; replayStatus: number; replayed: Ndjson[] }> {
  const queryId = `q-8096-${process.pid}-${++queryCounter}`;
  const res = await gatewayRequest(rig.gateway.port, "POST", "/v1/query", { queryId, prompt, model: "claude-sonnet-4-5", useSession: false }, key);
  const all = lines(res.text);
  const replay = await gatewayRequest(rig.gateway.port, "GET", `/v1/query/${queryId}/events`, undefined, key);
  return { queryId, status: res.status, stream: toolUses(all), all, replayStatus: replay.status, replayed: toolUses(lines(replay.text)) };
}

/** An input whose compact serialization is exactly `bytes` UTF-8 bytes. */
function inputOfBytes(bytes: number, filler = "a"): { question: string } {
  const wrapper = Buffer.byteLength(JSON.stringify({ question: "" }), "utf8");
  const count = (bytes - wrapper) / Buffer.byteLength(filler, "utf8");
  if (!Number.isInteger(count)) throw new Error(`cannot reach ${bytes} bytes with ${filler}`);
  const input = { question: filler.repeat(count) };
  if (Buffer.byteLength(JSON.stringify(input), "utf8") !== bytes) throw new Error("size construction is off");
  return input;
}

/* ------------------------------------------------------------------ */
/*  The main rig: P1 to P7, P13, P14, P12 and the registry rows          */
/* ------------------------------------------------------------------ */

const AC_INPUT = { question: "Which environment?", options: [{ label: "Test" }, { label: "Stage" }] };
const UTF8_OVER = inputOfBytes(16385, "ä");
const FILTERED_CALL = { question: "q", extraTop: "dropped", options: [{ label: "A", hiddenNested: 1 }] };
const FILTERED_BODY = { question: "q", options: [{ label: "A", hiddenNested: 1 }] };

const SCRIPT: ScriptStep[] = [
  { tool: TOOL, input: AC_INPUT },
  { tool: TOOL, input: inputOfBytes(200) },
  { tool: TOOL, input: inputOfBytes(16384) },
  { tool: TOOL, input: inputOfBytes(16385) },
  { tool: TOOL, input: UTF8_OVER },
  { tool: "summary_tool", input: inputOfBytes(200) },
  { tool: "plain_tool", input: inputOfBytes(200) },
  { tool: TOOL, input: FILTERED_CALL },
  { tool: TOOL, input: { question: "has a nul \u0000 inside" } },
];

describe("the structured tool_use input through a spawned gateway and the real runtime", () => {
  let api: ToolSchemaApi;
  let rig: Rig;
  const suiteCleanups: Cleanup[] = [];
  let first: Awaited<ReturnType<typeof run>>;
  let other: { status: number; replayStatus: number; offered: string[][] };
  const registry: Record<string, { status: number; text: string }> = {};

  beforeAll(async () => {
    api = await startToolSchemaApi(SCRIPT);
    suiteCleanups.push(() => api.close());
    rig = await startRig({ api, env: { LOG_LEVEL: "info" }, into: suiteCleanups });
    registry.raw = await put(rig, KEY_REQLIFT, TOOL, definition(rig, TOOL, { stream_input: "raw" }));
    registry.rawUpdate = await put(rig, KEY_REQLIFT, TOOL, definition(rig, TOOL, { stream_input: "raw" }));
    registry.summary = await put(rig, KEY_REQLIFT, "summary_tool", definition(rig, "summary_tool", { stream_input: "summary" }));
    registry.summaryUpdate = await put(rig, KEY_REQLIFT, "summary_tool", definition(rig, "summary_tool", { stream_input: "summary" }));
    registry.omitted = await put(rig, KEY_REQLIFT, "plain_tool", definition(rig, "plain_tool"));
    registry.full = await put(rig, KEY_REQLIFT, "bad_full", definition(rig, "bad_full", { stream_input: "full" }));
    registry.five = await put(rig, KEY_REQLIFT, "bad_five", definition(rig, "bad_five", { stream_input: 5 }));
    registry.upper = await put(rig, KEY_REQLIFT, "bad_upper", definition(rig, "bad_upper", { stream_input: "RAW" }));
    first = await run(rig, KEY_REQLIFT);

    // Another label: it neither replays the first query nor is offered the first label's tool.
    const requestsBefore = api.requests.length;
    const theirs = await run(rig, KEY_DIEMCRM);
    const stranger = await gatewayRequest(rig.gateway.port, "GET", `/v1/query/${first.queryId}/events`, undefined, KEY_DIEMCRM);
    other = { status: theirs.status, replayStatus: stranger.status, offered: api.requests.slice(requestsBefore).map((r) => r.tools.map((t) => t.name)) };
  }, 300_000);

  afterAll(async () => {
    while (suiteCleanups.length > 0) await suiteCleanups.pop()!();
  });

  /** The call i (script index): the stream event, the replayed event and the webhook body. */
  const row = (index: number) => ({
    event: first.stream[index],
    replayed: first.replayed[index],
    webhook: rig.webhook.requests[index],
    result: api.stepResults()[index],
  });

  it("the run completes, every scripted call reached the model, and the stream and the replay hold one tool_use per call", () => {
    expect.soft(first.status).toBe(200);
    expect.soft(first.all.at(-1)?.type).toBe("done");
    expect.soft(first.all.filter((e) => e.type === "text").map((e) => String(e.content)).join("")).toContain(SCHEMA_FINAL_ANSWER);
    expect.soft(api.stepResults().map((r) => r !== undefined)).toEqual(SCRIPT.map(() => true));
    expect.soft(first.stream).toHaveLength(SCRIPT.length);
    expect.soft(first.replayStatus).toBe(200);
    expect.soft(first.replayed).toEqual(first.stream);
    expect.soft(rig.webhook.requests).toHaveLength(SCRIPT.length);
  });

  it("P1: the Story's example arrives as exactly that object on the stream, on the replay and at the webhook", () => {
    const { event, replayed, webhook } = row(0);
    expect(event).toMatchObject({ type: "tool_use", toolName: FULL, toolUseId: "toolu_7697_1", input: AC_INPUT, parentToolUseId: null });
    expect(typeof event.seq).toBe("number");
    expect(typeof event.startedAt).toBe("number");
    expect(replayed).toEqual(event);
    expect(webhook.body).toEqual(AC_INPUT);
    expect(event.input).toEqual(webhook.body);
  });

  it.each([
    ["P2: raw, 200 bytes", 1],
    ["P3: raw, 16384 bytes", 2],
  ])("%s: the original object on the stream, the replay and at the webhook", (_label, index) => {
    const { event, replayed, webhook } = row(index);
    expect(event.input).toEqual(SCRIPT[index].input);
    expect(replayed.input).toEqual(SCRIPT[index].input);
    expect(webhook.body).toEqual(SCRIPT[index].input);
  });

  it.each([
    ["P4: raw, 16385 bytes", 3],
    ["P5: raw, UTF-8 bytes above 16384 with at most 16384 characters", 4],
  ])("%s: a summary string of at most 1000 characters on the stream and the replay", (_label, index) => {
    const { event, replayed, webhook } = row(index);
    expect(typeof event.input).toBe("string");
    expect((event.input as string).length).toBeLessThanOrEqual(1000);
    expect(replayed.input).toBe(event.input);
    // The call itself is unchanged: the webhook still received the whole input.
    expect(webhook.body).toEqual(SCRIPT[index].input);
  });

  it("P5 premise: the input has at most 16384 characters and more than 16384 UTF-8 bytes", () => {
    expect(UTF8_OVER.question.length).toBeLessThanOrEqual(16384);
    expect(JSON.stringify(UTF8_OVER).length).toBeLessThanOrEqual(16384);
    expect(Buffer.byteLength(JSON.stringify(UTF8_OVER), "utf8")).toBeGreaterThan(16384);
  });

  it.each([
    ["P6: summary, 200 bytes", 5],
    ["P7: flag not sent, 200 bytes", 6],
  ])("%s: a summary string on the stream and the replay", (_label, index) => {
    const { event, replayed } = row(index);
    expect(typeof event.input).toBe("string");
    expect((event.input as string).length).toBeLessThanOrEqual(1000);
    expect(event.input).toBe(JSON.stringify(SCRIPT[index].input, null, 2));
    expect(replayed.input).toBe(event.input);
  });

  it("P13: the streamed object is the body the webhook received: the undeclared top-level key is stripped, the nested one stays", () => {
    const { event, replayed, webhook } = row(7);
    expect(webhook.body).toEqual(FILTERED_BODY);
    expect(event.input).toEqual(FILTERED_BODY);
    expect(replayed.input).toEqual(FILTERED_BODY);
  });

  it("P14: a U+0000 inside a value gives a summary string on the stream and the replay", () => {
    const { event, replayed, result } = row(8);
    expect(typeof event.input).toBe("string");
    expect(replayed.input).toBe(event.input);
    expect(result?.isError).toBe(false);
  });

  it("P12: another label cannot replay the query and is not offered the first label's tool", () => {
    expect(other.status).toBe(200);
    expect(other.replayStatus).toBe(404);
    expect(other.offered.length).toBeGreaterThan(0);
    expect(other.offered.some((names) => names.length > 0)).toBe(true);
    for (const names of other.offered) expect(names).not.toContain(FULL);
  });

  it("registry: raw and summary answer 201 for a new tool and 200 for an update, and GET shows the value", async () => {
    expect.soft(registry.raw.status).toBe(201);
    expect.soft(registry.rawUpdate.status).toBe(200);
    expect.soft(registry.summary.status).toBe(201);
    expect.soft(registry.summaryUpdate.status).toBe(200);
    expect.soft(registry.omitted.status).toBe(201);
    const list = await gatewayRequest(rig.gateway.port, "GET", "/v1/tools", undefined, KEY_REQLIFT);
    const byName = new Map(((list.json?.tools ?? []) as { name: string; stream_input: string }[]).map((tool) => [tool.name, tool.stream_input]));
    expect.soft(byName.get(TOOL)).toBe("raw");
    expect.soft(byName.get("summary_tool")).toBe("summary");
    expect.soft(byName.get("plain_tool")).toBe("summary");
    expect.soft(byName.has("bad_full")).toBe(false);
  });

  it("registry: \"full\", 5 and \"RAW\" answer 400 with the registry's error envelope and store nothing", async () => {
    for (const key of ["full", "five", "upper"]) {
      expect.soft(registry[key].status, key).toBe(400);
      expect.soft(JSON.parse(registry[key].text), key).toEqual({ error: 'stream_input must be "summary" or "raw"' });
    }
    for (const name of ["bad_full", "bad_five", "bad_upper"]) expect.soft((await gatewayRequest(rig.gateway.port, "GET", `/v1/tools/${name}`, undefined, KEY_REQLIFT)).status, name).toBe(404);
  });
});

/* ------------------------------------------------------------------ */
/*  P8: a restart keeps the registration                                */
/* ------------------------------------------------------------------ */

describe("a raw registration survives a gateway restart", () => {
  it("P8: GET still shows raw after the restart, and a later run streams and replays the object", async () => {
    const api = await startToolSchemaApi([{ tool: TOOL, input: AC_INPUT }]);
    cleanups.push(() => api.close());
    let rig = await startRig({ api, env: { LOG_LEVEL: "info" } });
    expect((await put(rig, KEY_REQLIFT, TOOL, definition(rig, TOOL, { stream_input: "raw" }))).status).toBe(201);
    // The registry is saved a moment after the PUT; the file must hold the field before the process stops.
    expect(await persistedStreamInput(rig, TOOL)).toBe("raw");
    const portBefore = rig.gateway.port;
    rig = await restart(rig);
    expect(rig.gateway.port).not.toBe(portBefore);
    const got = await gatewayRequest(rig.gateway.port, "GET", "/v1/tools", undefined, KEY_REQLIFT);
    expect(((got.json?.tools ?? []) as { name: string; stream_input: string }[]).find((tool) => tool.name === TOOL)?.stream_input).toBe("raw");
    const after = await run(rig, KEY_REQLIFT);
    expect(after.status).toBe(200);
    expect(after.stream).toHaveLength(1);
    expect(after.stream[0].input).toEqual(AC_INPUT);
    expect(after.replayed).toEqual(after.stream);
    expect(rig.webhook.requests.map((r) => r.body)).toEqual([AC_INPUT]);
  });
});

/* ------------------------------------------------------------------ */
/*  P9, P11: files written before the field / without an owner          */
/* ------------------------------------------------------------------ */

describe("registry files that predate the field or the owner", () => {
  it("P9 and P11: an owned entry without stream_input loads as summary, and an ownerless entry that stores raw streams a summary string", async () => {
    const api = await startToolSchemaApi([
      { tool: "old_owned", input: AC_INPUT },
      { tool: "legacy_raw", input: AC_INPUT },
    ]);
    cleanups.push(() => api.close());
    const rig = await startRig({
      api,
      env: { LOG_LEVEL: "info" },
      seed: (dirs, base) => {
        const entry = (name: string, extra: Record<string, unknown>) => ({ name, description: `Probe ${name}.`, input_schema: SCHEMA, webhook_url: `${base}/${name}`, timeout_ms: 30000, ...extra });
        fs.writeFileSync(path.join(dirs.persist, "tools.json"), JSON.stringify([entry("old_owned", { owner: "reqlift" }), entry("legacy_raw", { stream_input: "raw" })]));
      },
    });
    const list = await gatewayRequest(rig.gateway.port, "GET", "/v1/tools", undefined, KEY_REQLIFT);
    const byName = new Map(((list.json?.tools ?? []) as { name: string; stream_input: string; owner?: string }[]).map((tool) => [tool.name, tool]));
    // P9
    expect(byName.get("old_owned")?.stream_input).toBe("summary");
    // P11: stored raw, no owner.
    expect(byName.get("legacy_raw")?.stream_input).toBe("raw");
    expect(byName.get("legacy_raw")?.owner).toBeUndefined();
    const outcome = await run(rig, KEY_REQLIFT);
    expect(outcome.status).toBe(200);
    expect(api.stepResults().map((r) => r !== undefined)).toEqual([true, true]);
    expect(outcome.stream).toHaveLength(2);
    for (const event of outcome.stream) {
      expect(typeof event.input).toBe("string");
      expect(event.input).toBe(JSON.stringify(AC_INPUT, null, 2));
    }
    expect(outcome.replayed).toEqual(outcome.stream);
    // Both calls reached their webhooks: only what is streamed differs.
    expect(rig.webhook.requests.map((r) => r.body)).toEqual([AC_INPUT, AC_INPUT]);
  });
});

/* ------------------------------------------------------------------ */
/*  P10: the flag grants nothing                                        */
/* ------------------------------------------------------------------ */

describe("the flag grants nothing", () => {
  it("P10: with the tool denied by AGENT_TOOL_POLICY, it is not offered, a call to it is refused by the runtime, the webhook gets no request and the event input is a string", async () => {
    const api: FakeAnthropicApi = await startFakeAnthropicApi({ toolName: "unused-8096", exactTool: [{ name: FULL, prompt: "SI-P10", input: AC_INPUT }] });
    cleanups.push(() => api.close());
    const rig = await startRig({
      api,
      env: { LOG_LEVEL: "info", AGENT_TOOL_POLICY: JSON.stringify({ labels: { reqlift: { deny: [FULL] } } }) },
    });
    expect((await put(rig, KEY_REQLIFT, TOOL, definition(rig, TOOL, { stream_input: "raw" }))).status).toBe(201);
    const outcome = await run(rig, KEY_REQLIFT, "SI-P10");
    expect(outcome.status).toBe(200);
    const main = api.requests.filter((r) => r.userTexts.at(-1)?.includes("SI-P10") && !r.warmup);
    expect(main.length).toBeGreaterThan(0);
    expect(main[0].tools).not.toContain(FULL);
    const refused = main.at(-1)?.toolResults.at(-1);
    expect(refused?.isError).toBe(true);
    expect(refused?.text).toContain(`No such tool available: ${FULL}`);
    expect(rig.webhook.requests).toEqual([]);
    expect(outcome.stream).toHaveLength(1);
    expect(typeof outcome.stream[0].input).toBe("string");
    expect(outcome.replayed).toEqual(outcome.stream);
  });
});

/* ------------------------------------------------------------------ */
/*  Negative controls                                                   */
/* ------------------------------------------------------------------ */

/**
 * A copy of `dist/` with exactly one protection taken out. The child run executes this very file against it, for the
 * named rows only, and must exit nonzero naming those rows. It prints names and counts only.
 */
async function negativeControl(options: { patch: (source: string) => string; file: string; rows: string; mustName: string[] }): Promise<void> {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "mvp8096-vulnerable-"));
  cleanups.push(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.cpSync(path.join(REPO_ROOT, "dist"), path.join(root, "dist"), { recursive: true, filter: (source) => !source.startsWith(path.join(REPO_ROOT, "dist", "tests")) });
  fs.copyFileSync(path.join(REPO_ROOT, "package.json"), path.join(root, "package.json"));
  fs.symlinkSync(path.join(REPO_ROOT, "node_modules"), path.join(root, "node_modules"));
  const target = path.join(root, "dist", options.file);
  const source = fs.readFileSync(target, "utf8");
  const patched = options.patch(source);
  expect(patched, "the patch must change the compiled file").not.toBe(source);
  fs.writeFileSync(target, patched);
  const child = await runChild(
    [process.execPath, path.join(REPO_ROOT, "node_modules", "vitest", "vitest.mjs"), "run", "src/tests/stream-input-process.test.ts", "-t", options.rows],
    { PATH: process.env.PATH, HOME: process.env.HOME, LANG: process.env.LANG, TMPDIR: os.tmpdir(), NO_COLOR: "1", STREAM_INPUT_CHILD: "1", STREAM_INPUT_DIST: path.join(root, "dist", "server.js") },
    REPO_ROOT,
    280_000,
  );
  expect(child.timedOut, "the child run hit its deadline").toBe(false);
  expect(child.code !== 0 && child.code !== null, "the rows must exit nonzero against the vulnerable build").toBe(true);
  const failed = [...child.output.matchAll(/FAIL .*? > (.*)/g)].map((match) => match[1]);
  // Each entry is the rest of the title path ("describe > row title").
  process.stderr.write(`STREAM-INPUT-EVIDENCE negative-control file=${options.file} rows=${JSON.stringify(options.rows)} exit=${child.code} failed_rows=${failed.length}\n`);
  for (const name of options.mustName) expect(failed.some((title) => title.includes(name)), `the child run must fail ${name}`).toBe(true);
}

describe("negative controls (child runs against patched copies of dist/)", () => {
  it("NC1: against a build whose size bound is raised, P4 and P5 fail", async () => {
    await negativeControl({
      file: "tool-use-input.js",
      patch: (source) => source.replace("export const MAX_INPUT_BYTES = 16384;", () => "export const MAX_INPUT_BYTES = 1048576;"),
      rows: "P4: |P5: ",
      mustName: ["P4: ", "P5: "],
    });
  }, 300_000);

  it("NC2: against a build that treats an ownerless tool as owned, P11 fails", async () => {
    await negativeControl({
      file: "tool-use-input.js",
      patch: (source) => source.replace("if (def.owner === undefined || def.owner !== callerLabel)", () => "if (def.owner !== undefined && def.owner !== callerLabel)"),
      rows: "P9 and P11",
      mustName: ["P9 and P11"],
    });
  }, 300_000);
});
