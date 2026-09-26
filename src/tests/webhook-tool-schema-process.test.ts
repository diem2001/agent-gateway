/**
 * Webhook tool schemas at the real model boundary (MVP-7697): the compiled
 * gateway (`dist/server.js`, built by `npm run build`) runs as a child process
 * with the production Claude Agent SDK and its bundled Claude runtime, against
 * a scripted stand-in for the Messages API that records the tool definitions
 * the runtime sends to the model and the tool results it returns. Registered
 * tools point at a loopback webhook stub that records every request body.
 *
 * The child gets an environment ALLOWLIST (never the parent's API or Jira
 * secrets) and fresh temp directories for HOME, TMPDIR, cwd and every persist
 * path. No real model and no shared gateway are involved.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import net, { type AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { SCHEMA_FINAL_ANSWER, startToolSchemaApi, type RecordedToolDefinition, type ScriptStep, type ToolSchemaApi } from "./helpers/tool-schema-api.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(here, "..", "..");
const DIST_SERVER = path.join(REPO_ROOT, "dist", "server.js");
const FIXTURES = path.join(here, "fixtures", "webhook-tool-schemas.json");

const API_KEY = "tool-schema-gateway-key-7697";
const SERVER_PREFIX = "mcp__agent-gateway-tools__";

/** Fails loudly when dist/ is missing or older than src/ (run `npm run build`). */
function assertFreshBuild(): void {
  const srcRoot = path.join(REPO_ROOT, "src");
  for (const entry of fs.readdirSync(srcRoot, { withFileTypes: true, recursive: true })) {
    if (!entry.isFile() || !entry.name.endsWith(".ts") || entry.name.endsWith(".test.ts")) continue;
    const source = path.join(entry.parentPath, entry.name);
    const relative = path.relative(srcRoot, source);
    if (relative.startsWith("tests") || relative.startsWith("__tests__")) continue;
    const compiled = path.join(REPO_ROOT, "dist", relative.replace(/\.ts$/, ".js"));
    if (!fs.existsSync(compiled) || fs.statSync(compiled).mtimeMs < fs.statSync(source).mtimeMs) {
      throw new Error(`dist is missing or older than src for ${relative}; run \`npm run build\` first`);
    }
  }
}

/** Environment ALLOWLIST for the spawned gateway. Never turn this into a denylist. */
const ALLOWED_ENV_KEYS = ["PATH", "LANG"] as const;

async function freePort(): Promise<number> {
  const server = net.createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const { port } = server.address() as AddressInfo;
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
}

function request(port: number, method: string, urlPath: string, body?: unknown): Promise<{ status: number; text: string }> {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body), "utf8");
    const req = http.request(
      {
        host: "127.0.0.1",
        port,
        method,
        path: urlPath,
        agent: false,
        headers: {
          Authorization: `Bearer ${API_KEY}`,
          ...(payload ? { "Content-Type": "application/json", "Content-Length": payload.length } : {}),
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString("utf8") }));
      },
    );
    req.on("error", reject);
    req.end(payload);
  });
}

/* ------------------------------------------------------------------ */
/*  Loopback webhook stub                                               */
/* ------------------------------------------------------------------ */

const WEBHOOK_ERROR_PATH = "/probe/fail";
const WEBHOOK_ERROR_BODY = "PROBE-7697-WEBHOOK-REJECTED";

interface WebhookRequest {
  path: string;
  body: unknown;
}

interface WebhookStub {
  base: string;
  requests: WebhookRequest[];
  close: () => Promise<void>;
}

async function startWebhookStub(): Promise<WebhookStub> {
  const requests: WebhookRequest[] = [];
  const sockets = new Set<net.Socket>();
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const urlPath = req.url ?? "/";
      let body: unknown = null;
      try {
        body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      } catch {
        body = Buffer.concat(chunks).toString("utf8");
      }
      requests.push({ path: urlPath, body });
      if (urlPath === WEBHOOK_ERROR_PATH) {
        res.writeHead(422, { "Content-Type": "text/plain" });
        res.end(WEBHOOK_ERROR_BODY);
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ output: `WEBHOOK-OK ${urlPath}` }));
    });
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const { port } = server.address() as AddressInfo;
  return {
    base: `http://127.0.0.1:${port}`,
    requests,
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

/* ------------------------------------------------------------------ */
/*  Spawned gateway                                                     */
/* ------------------------------------------------------------------ */

interface SpawnedGateway {
  child: ChildProcess;
  port: number;
  output: () => string;
  stop: () => Promise<void>;
}

function childPids(pid: number): number[] {
  const result: number[] = [];
  let tasks: string[] = [];
  try {
    tasks = fs.readdirSync(`/proc/${pid}/task`);
  } catch {
    return result;
  }
  for (const tid of tasks) {
    try {
      const text = fs.readFileSync(`/proc/${pid}/task/${tid}/children`, "utf8").trim();
      if (text) result.push(...text.split(/\s+/).map(Number));
    } catch {
      // Thread ended while reading.
    }
  }
  return result;
}

/** Every process below `pid` (not `pid` itself). */
function descendants(pid: number): number[] {
  const found: number[] = [];
  const queue = [pid];
  while (queue.length > 0) {
    for (const child of childPids(queue.shift()!)) {
      found.push(child);
      queue.push(child);
    }
  }
  return found;
}

async function spawnGateway(apiBaseUrl: string): Promise<SpawnedGateway> {
  assertFreshBuild();
  const port = await freePort();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "mvp7697-schema-"));
  const dirs = { home: path.join(root, "home"), tmp: path.join(root, "tmp"), cwd: path.join(root, "cwd"), persist: path.join(root, "persist") };
  for (const dir of Object.values(dirs)) fs.mkdirSync(dir);

  const childEnv: NodeJS.ProcessEnv = {};
  for (const key of ALLOWED_ENV_KEYS) {
    if (process.env[key] !== undefined) childEnv[key] = process.env[key];
  }
  Object.assign(childEnv, {
    HOME: dirs.home,
    TMPDIR: dirs.tmp,
    PORT: String(port),
    HOST: "127.0.0.1",
    API_KEYS: `probe:${API_KEY}`,
    LOG_LEVEL: "debug",
    ANTHROPIC_BASE_URL: apiBaseUrl,
    ANTHROPIC_API_KEY: "sk-ant-fake-tool-schema-7697",
    DISABLE_TELEMETRY: "1",
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
    SESSION_PERSIST_PATH: path.join(dirs.persist, "sessions.json"),
    TOOLS_PERSIST_PATH: path.join(dirs.persist, "tools.json"),
    MCP_SERVERS_PERSIST_PATH: path.join(dirs.persist, "mcp-servers.json"),
    WORKSPACE_ROOT: path.join(dirs.home, ".claude"),
  });

  const child = spawn(process.execPath, ["--expose-gc", DIST_SERVER], {
    cwd: dirs.cwd,
    env: childEnv,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  child.stdout!.on("data", (data: Buffer) => (output += data.toString("utf8")));
  child.stderr!.on("data", (data: Buffer) => (output += data.toString("utf8")));
  const stop = async (): Promise<void> => {
    for (const pid of descendants(child.pid!)) {
      try {
        process.kill(pid, "SIGKILL");
      } catch {
        // Already gone.
      }
    }
    if (child.exitCode === null && child.signalCode === null) {
      const exited = new Promise<void>((resolve) => child.once("exit", () => resolve()));
      child.kill("SIGKILL");
      await exited;
    }
    fs.rmSync(root, { recursive: true, force: true });
  };

  const started = Date.now();
  for (;;) {
    if (child.exitCode !== null) {
      await stop();
      throw new Error(`gateway exited early: ${output}`);
    }
    const healthy = await new Promise<boolean>((resolve) => {
      const probe = http.get({ host: "127.0.0.1", port, path: "/health", agent: false }, (res) => {
        res.resume();
        resolve(res.statusCode === 200);
      });
      probe.on("error", () => resolve(false));
    });
    if (healthy) break;
    if (Date.now() - started > 15_000) {
      await stop();
      throw new Error(`gateway not ready: ${output}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  return { child, port, output: () => output, stop };
}

interface NdjsonEvent {
  type: string;
  [key: string]: unknown;
}

async function runQuery(gateway: SpawnedGateway): Promise<{ status: number; events: NdjsonEvent[] }> {
  let status = 0;
  let text = "";
  await new Promise<void>((resolve, reject) => {
    const payload = Buffer.from(
      JSON.stringify({ queryId: `q-${randomBytes(4).toString("hex")}`, prompt: "Run the scripted tool calls.", model: "claude-sonnet-4-5", useSession: false }),
    );
    const req = http.request(
      {
        host: "127.0.0.1",
        port: gateway.port,
        method: "POST",
        path: "/v1/query",
        agent: false,
        headers: { Authorization: `Bearer ${API_KEY}`, "Content-Type": "application/json", "Content-Length": payload.length },
      },
      (res) => {
        status = res.statusCode ?? 0;
        res.on("data", (chunk: Buffer) => (text += chunk.toString("utf8")));
        res.on("end", () => resolve());
        res.on("error", () => resolve());
      },
    );
    req.on("error", reject);
    req.end(payload);
  });
  const events = text
    .split("\n")
    .filter((line) => line.trim().startsWith("{") && line.trim().endsWith("}"))
    .map((line) => JSON.parse(line) as NdjsonEvent);
  return { status, events };
}

/* ------------------------------------------------------------------ */
/*  Registered tools and script                                         */
/* ------------------------------------------------------------------ */

const PAGE_ID_DESCRIPTION = "Confluence page id as text";

/** One tool whose schema covers every AC-3 construct. */
const PROBE_SCHEMA = {
  type: "object",
  properties: {
    pageId: { type: "string", description: PAGE_ID_DESCRIPTION },
    amount: { type: "number", description: "An amount with decimals" },
    count: { type: "integer", description: "A whole number" },
    enabled: { type: "boolean" },
    mode: { type: "string", enum: ["a", "b"], description: "Either a or b" },
    target: {
      type: "object",
      description: "A nested object",
      properties: {
        id: { type: "string", description: "Target id" },
        label: { type: "string" },
      },
      required: ["id"],
    },
    lines: {
      type: "array",
      description: "An array of objects",
      items: {
        type: "object",
        properties: {
          sku: { type: "string" },
          qty: { type: "integer", description: "Quantity" },
        },
        required: ["sku"],
      },
    },
    choice: { oneOf: [{ type: "string" }, { type: "number" }], description: "A name or a number" },
    ref: { type: "string", format: "uuid", description: "A reference id" },
    note: { type: "string", description: "Optional note" },
  },
  required: ["pageId", "count", "mode", "target", "choice"],
};

/** What the model must receive for each probe property (AC-1/AC-3 rows). */
const EXPECTED_PROBE_PROPERTIES: Record<string, unknown> = {
  pageId: { type: "string", description: PAGE_ID_DESCRIPTION },
  amount: { type: "number", description: "An amount with decimals" },
  count: { type: "integer", description: "A whole number" },
  enabled: { type: "boolean" },
  mode: { type: "string", enum: ["a", "b"], description: "Either a or b" },
  target: {
    type: "object",
    description: "A nested object",
    properties: { id: { type: "string", description: "Target id" }, label: { type: "string" } },
    required: ["id"],
  },
  lines: {
    type: "array",
    description: "An array of objects",
    items: { type: "object", properties: { sku: { type: "string" }, qty: { type: "integer", description: "Quantity" } }, required: ["sku"] },
  },
  // Unsupported constructs fall back to "any value", keeping the description.
  choice: { description: "A name or a number" },
  ref: { description: "A reference id" },
  note: { type: "string", description: "Optional note" },
};

const PROBE_DESCRIPTION = "Probe tool covering every supported schema construct (MVP-7697).";

interface Fixtures {
  tools: { name: string; description: string; input_schema: Record<string, unknown>; webhook_url: string; timeout_ms?: number }[];
}

const fixtures = JSON.parse(fs.readFileSync(FIXTURES, "utf8")) as Fixtures;

const VALID_PROBE_INPUT = {
  pageId: "118784054",
  amount: 12.5,
  count: 3,
  enabled: true,
  mode: "a",
  target: { id: "T-1", label: "first", extraNested: 1 },
  lines: [{ sku: "S-1", qty: 2, color: "red" }],
  choice: 7,
  ref: "not-a-uuid",
  note: "step-valid",
};

const UPSERT_INPUT = {
  analysisId: "0b0f3f8e-7a51-4c55-9a8f-5d0f6f1d2a01",
  pageId: "118784054",
  regionKey: "/billing",
  snapshotContent: "<p>managed</p>",
};

const RATE_IMAGES_INPUT = { images: ["https://images.example/1.jpg", "https://images.example/2.jpg"], context: "hero" };

const SCRIPT: ScriptStep[] = [
  // 0: valid call plus an undeclared top-level key.
  { tool: "probe_schema", input: { ...VALID_PROBE_INPUT, undeclaredTop: "dropped" } },
  // 1: Missing Scenario 2 — pageId as a number.
  { tool: "probe_schema", input: { pageId: 118784054, count: 3, mode: "a", target: { id: "T-1" }, choice: "x", note: "step-wrong-type" } },
  // 2: a required field missing.
  { tool: "probe_schema", input: { count: 3, mode: "a", target: { id: "T-1" }, choice: "x", note: "step-missing-required" } },
  // 3: a value outside the enum.
  { tool: "probe_schema", input: { pageId: "p", count: 3, mode: "c", target: { id: "T-1" }, choice: "x", note: "step-out-of-enum" } },
  // 4: any value in the fallback properties.
  { tool: "probe_schema", input: { pageId: "p", count: 3, mode: "b", target: { id: "T-1" }, choice: { any: ["shape", 1] }, ref: 12345, note: "step-fallback" } },
  // 5: the webhook answers with an error.
  { tool: "probe_webhook_error", input: { pageId: "p" } },
  // 6, 7: existing registrants (AC-4).
  { tool: "reqlift_confluence_upsert_section", input: UPSERT_INPUT },
  { tool: "wsb_rate_images", input: RATE_IMAGES_INPUT },
];

/* ------------------------------------------------------------------ */
/*  Run once, assert per row                                            */
/* ------------------------------------------------------------------ */

let api: ToolSchemaApi;
let webhook: WebhookStub;
let gateway: SpawnedGateway;
const registrations: Record<string, number> = {};
let outcome: { status: number; events: NdjsonEvent[] };

function offered(name: string): RecordedToolDefinition | undefined {
  return api.agentRequests()[0]?.tools.find((t) => t.name === `${SERVER_PREFIX}${name}`);
}

function webhookBodiesWithNote(note: string): unknown[] {
  return webhook.requests.filter((r) => (r.body as { note?: unknown } | null)?.note === note).map((r) => r.body);
}

beforeAll(async () => {
  api = await startToolSchemaApi(SCRIPT);
  webhook = await startWebhookStub();
  gateway = await spawnGateway(api.baseUrl);

  const definitions = [
    { name: "probe_schema", description: PROBE_DESCRIPTION, input_schema: PROBE_SCHEMA, webhook_url: `${webhook.base}/probe/schema` },
    {
      name: "probe_webhook_error",
      description: "Probe tool whose webhook rejects every call.",
      input_schema: { type: "object", properties: { pageId: { type: "string" } }, required: ["pageId"] },
      webhook_url: `${webhook.base}${WEBHOOK_ERROR_PATH}`,
    },
    ...fixtures.tools.map((t) => ({ ...t, webhook_url: t.webhook_url.replace("WEBHOOK_BASE", webhook.base) })),
  ];
  for (const def of definitions) {
    const { name, ...body } = def;
    registrations[name] = (await request(gateway.port, "PUT", `/v1/tools/${name}`, body)).status;
  }

  outcome = await runQuery(gateway);

  // Evidence: set TOOL_SCHEMA_CAPTURE_FILE to keep what the model received.
  const captureFile = process.env.TOOL_SCHEMA_CAPTURE_FILE;
  if (captureFile) {
    const capture = {
      tools: ["probe_schema", "reqlift_confluence_upsert_section", "wsb_rate_images"].map((name) => offered(name) ?? { name, missing: true }),
      steps: SCRIPT.map((step, index) => ({ ...step, result: api.stepResults()[index] })),
      webhookRequests: webhook.requests,
    };
    fs.writeFileSync(captureFile, JSON.stringify(capture, null, 2) + "\n");
  }
}, 120_000);

afterAll(async () => {
  await gateway?.stop();
  await webhook?.close();
  await api?.close();
});

describe("webhook tool schemas at the real model boundary (spawned gateway + real runtime)", () => {
  it("the run completes and every scripted tool call reaches the model", () => {
    expect.soft(outcome.status).toBe(200);
    expect.soft(outcome.events.at(-1)?.type).toBe("done");
    expect.soft(outcome.events.filter((e) => e.type === "text").map((e) => String(e.content)).join("")).toContain(SCHEMA_FINAL_ANSWER);
    expect.soft(api.stepResults().map((r) => r !== undefined)).toEqual(SCRIPT.map(() => true));
  });

  describe("tools/list: what the model receives (AC-1, AC-3)", () => {
    for (const [property, expected] of Object.entries(EXPECTED_PROBE_PROPERTIES)) {
      it(`property "${property}" is advertised as ${JSON.stringify(expected)}`, () => {
        const schema = offered("probe_schema")?.input_schema as { properties?: Record<string, unknown> } | undefined;
        expect(schema?.properties?.[property]).toEqual(expected);
      });
    }

    it("required membership is exactly the registered list", () => {
      const schema = offered("probe_schema")?.input_schema as { required?: string[] } | undefined;
      expect([...(schema?.required ?? [])].sort()).toEqual([...PROBE_SCHEMA.required].sort());
    });

    it("no property is added and the tool-level description is unchanged", () => {
      const tool = offered("probe_schema");
      const schema = tool?.input_schema as { type?: string; properties?: Record<string, unknown> } | undefined;
      expect.soft(schema?.type).toBe("object");
      expect.soft(Object.keys(schema?.properties ?? {}).sort()).toEqual(Object.keys(PROBE_SCHEMA.properties).sort());
      expect.soft(tool?.description).toBe(PROBE_DESCRIPTION);
    });
  });

  describe("tools/call: what reaches the webhook and what the model gets back (AC-2, AC-3)", () => {
    it("a valid call reaches the webhook with the declared values unchanged; the undeclared top-level key is dropped (current behavior)", () => {
      expect.soft(webhookBodiesWithNote("step-valid")).toEqual([VALID_PROBE_INPUT]);
      const result = api.stepResults()[0];
      expect.soft(result?.isError).toBe(false);
      expect.soft(result?.text).toContain("WEBHOOK-OK /probe/schema");
    });

    it("pageId sent as a number: the model gets a tool error naming pageId and a string expectation; the webhook gets no request", () => {
      const result = api.stepResults()[1];
      expect.soft(result?.isError).toBe(true);
      expect.soft(result?.text).toContain('"pageId"');
      expect.soft(result?.text).toMatch(/expected string, received number/);
      expect.soft(webhookBodiesWithNote("step-wrong-type")).toEqual([]);
    });

    it("a missing required field: the model gets a tool error naming the field; the webhook gets no request", () => {
      const result = api.stepResults()[2];
      expect.soft(result?.isError).toBe(true);
      expect.soft(result?.text).toContain('"pageId"');
      expect.soft(result?.text).toMatch(/received undefined/);
      expect.soft(webhookBodiesWithNote("step-missing-required")).toEqual([]);
    });

    it("a value outside the enum: the model gets a tool error naming the field and the allowed values; the webhook gets no request", () => {
      const result = api.stepResults()[3];
      expect.soft(result?.isError).toBe(true);
      expect.soft(result?.text).toContain('"mode"');
      expect.soft(result?.text).toMatch(/expected one of "a"\|"b"/);
      expect.soft(webhookBodiesWithNote("step-out-of-enum")).toEqual([]);
    });

    it("any value in an unsupported-construct property is accepted and delivered unchanged", () => {
      expect.soft(webhookBodiesWithNote("step-fallback")).toEqual([
        { pageId: "p", count: 3, mode: "b", target: { id: "T-1" }, choice: { any: ["shape", 1] }, ref: 12345, note: "step-fallback" },
      ]);
      expect.soft(api.stepResults()[4]?.isError).toBe(false);
    });

    it("a webhook error is relayed to the model as today", () => {
      const result = api.stepResults()[5];
      expect.soft(result?.isError).toBe(true);
      expect.soft(result?.text).toBe(`Tool webhook returned error: 422 ${WEBHOOK_ERROR_BODY}`);
      expect.soft(webhook.requests.filter((r) => r.path === WEBHOOK_ERROR_PATH).map((r) => r.body)).toEqual([{ pageId: "p" }]);
    });
  });

  describe("existing registrants keep working (AC-4)", () => {
    it("every fixture tool registers and is offered to the model", () => {
      for (const tool of fixtures.tools) {
        expect.soft(registrations[tool.name], tool.name).toBe(201);
        expect.soft(offered(tool.name), tool.name).toBeDefined();
      }
    });

    it("reqlift's pageId is advertised as a required, described string; the uuid-format field falls back to any value", () => {
      const schema = offered("reqlift_confluence_upsert_section")?.input_schema as { properties?: Record<string, unknown>; required?: string[] } | undefined;
      const registered = fixtures.tools.find((t) => t.name === "reqlift_confluence_upsert_section")!.input_schema as {
        properties: Record<string, { description: string }>;
      };
      expect.soft(schema?.properties?.pageId).toEqual({ type: "string", description: registered.properties.pageId.description });
      expect.soft(schema?.properties?.analysisId).toEqual({ description: registered.properties.analysisId.description });
      expect.soft([...(schema?.required ?? [])].sort()).toEqual(["analysisId", "pageId", "regionKey", "snapshotContent"]);
    });

    it("valid calls to reqlift_confluence_upsert_section and wsb_rate_images (array with items) reach their webhooks unchanged", () => {
      expect.soft(webhook.requests.filter((r) => r.path === "/confluence_upsert_section").map((r) => r.body)).toEqual([UPSERT_INPUT]);
      expect.soft(api.stepResults()[6]?.isError).toBe(false);
      expect.soft(webhook.requests.filter((r) => r.path === "/api/webhooks/wsb/rate-images").map((r) => r.body)).toEqual([RATE_IMAGES_INPUT]);
      expect.soft(api.stepResults()[7]?.isError).toBe(false);
    });
  });
});
