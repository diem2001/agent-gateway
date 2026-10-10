/**
 * The structured `tool_use` input of a `stream_input: "raw"` webhook tool through the REAL query.ts + agent.ts +
 * retry.ts path (MVP-8096), with ONLY the Claude Agent SDK boundary (`query()`) mocked. The mocked SDK plays the
 * model: for every scripted call it sends the same input to the REAL in-process MCP server (JSON-RPC `tools/call`
 * over an in-memory transport, a recording stub as the webhook) and then yields the assistant message that carries
 * the `tool_use` block. The contract check is therefore not circular: the event is compared with the body the
 * webhook actually received, produced by the SDK server's own parsing.
 *
 * The same event must come back on `GET /v1/query/:queryId/events`. The real runtime is proven in
 * stream-input-process.test.ts. One SDK mock per file.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const PREFIX = "mcp__agent-gateway-tools__";
const CHOICES = { question: "Which environment?", options: [{ label: "Test" }, { label: "Stage" }] };
const TOOL_SCHEMA = {
  type: "object",
  properties: { question: { type: "string" }, options: { type: "array", items: { type: "object", properties: { label: { type: "string" } } } } },
  required: ["question"],
};

interface Step {
  /** The full tool name as the model calls it. */
  tool: string;
  /** The raw JSON text of the input, so an own `__proto__` key survives. */
  json: string;
  id?: string;
  parent?: string | null;
}

interface JsonRpcMessage {
  jsonrpc: "2.0";
  id?: number;
  method?: string;
  params?: unknown;
  result?: unknown;
  error?: { code: number; message: string };
}

const INIT = { type: "system", subtype: "init", claude_code_version: "2.0.77", skills: [] };
const RESULT = { type: "result", subtype: "success", is_error: false, result: "fine", session_id: "sdk-s", usage: { input_tokens: 1, output_tokens: 1 }, total_cost_usd: 0 };

let steps: Step[] = [];
let capturedOptions: Record<string, unknown>[] = [];
let webhookBodies: { url: string; body: unknown }[] = [];
let tempDir: string;
let logs: string[];

/** Sends `tools/call` to the real MCP server instance, as the runtime would. */
const clients = new WeakMap<object, (name: string, argumentsJson: string) => Promise<unknown>>();

async function callServer(instance: { connect: (t: unknown) => Promise<void> }, name: string, argumentsJson: string): Promise<void> {
  const known = clients.get(instance);
  if (known) {
    await known(name, argumentsJson);
    return;
  }
  const pending = new Map<number, (message: JsonRpcMessage) => void>();
  const transport = {
    onmessage: undefined as ((message: JsonRpcMessage) => void) | undefined,
    onclose: undefined as (() => void) | undefined,
    onerror: undefined as ((error: Error) => void) | undefined,
    async start() {},
    async close() {
      transport.onclose?.();
    },
    async send(message: JsonRpcMessage) {
      if (message.id !== undefined && pending.has(message.id)) {
        pending.get(message.id)!(message);
        pending.delete(message.id);
      }
    },
  };
  await instance.connect(transport);
  let nextId = 0;
  const rpc = (method: string, params: unknown): Promise<unknown> =>
    new Promise((resolve, reject) => {
      const id = ++nextId;
      pending.set(id, (message) => (message.error ? reject(new Error(message.error.message)) : resolve(message.result)));
      transport.onmessage!({ jsonrpc: "2.0", id, method, params });
    });
  await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "1" } });
  transport.onmessage!({ jsonrpc: "2.0", method: "notifications/initialized" });
  const callTool = (toolName: string, json: string) => rpc("tools/call", { name: toolName, arguments: JSON.parse(json) });
  clients.set(instance, callTool);
  await callTool(name, argumentsJson);
}

beforeEach(() => {
  vi.resetModules();
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gateway-stream-input-"));
  process.env.TOOLS_PERSIST_PATH = path.join(tempDir, "tools.json");
  process.env.MCP_SERVERS_PERSIST_PATH = path.join(tempDir, "mcp-servers.json");
  process.env.SESSION_PERSIST_PATH = path.join(tempDir, "sessions.json");
  steps = [];
  capturedOptions = [];
  webhookBodies = [];
  logs = [];
  vi.spyOn(console, "log").mockImplementation((...args) => {
    logs.push(args.map(String).join(" "));
  });
  const realFetch = globalThis.fetch;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init: { body: string }) => {
      if (!String(url).startsWith("http://webhook.test/")) return realFetch(url, init as never);
      webhookBodies.push({ url: String(url), body: JSON.parse(init.body) });
      return new Response(JSON.stringify({ output: "OK" }), { status: 200 });
    }),
  );
  vi.doMock("@anthropic-ai/claude-agent-sdk", () => ({
    query: vi.fn(({ options }) => {
      capturedOptions.push(options as Record<string, unknown>);
      const scripted = steps;
      steps = [];
      return (async function* () {
        yield INIT;
        for (const [index, step] of scripted.entries()) {
          const server = (options.mcpServers as Record<string, { instance?: { connect: (t: unknown) => Promise<void> } }> | undefined)?.["agent-gateway-tools"];
          if (server?.instance && step.tool.startsWith(PREFIX)) await callServer(server.instance, step.tool.slice(PREFIX.length), step.json);
          yield {
            type: "assistant",
            parent_tool_use_id: step.parent ?? null,
            message: {
              content: [
                { type: "text", text: "ack" },
                { type: "tool_use", id: step.id ?? `toolu_${index}`, name: step.tool, input: JSON.parse(step.json) },
              ],
            },
          };
        }
        yield RESULT;
      })();
    }),
  }));
});

afterEach(async () => {
  const { credentialRelay } = await import("../mcp-credential-relay.js");
  await credentialRelay.close();
  vi.doUnmock("@anthropic-ai/claude-agent-sdk");
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  delete process.env.TOOLS_PERSIST_PATH;
  delete process.env.MCP_SERVERS_PERSIST_PATH;
  delete process.env.SESSION_PERSIST_PATH;
  await new Promise((resolve) => setTimeout(resolve, 150));
  fs.rmSync(tempDir, { recursive: true, force: true });
});

interface ToolSpec {
  name: string;
  owner?: string;
  stream_input?: "summary" | "raw";
  input_schema?: Record<string, unknown>;
}

async function createApp(tools: ToolSpec[], policy?: unknown) {
  const grant = await import("../tool-grant.js");
  if (policy !== undefined) grant.setToolPolicy(grant.parseToolPolicy(JSON.stringify(policy), ["reqlift", "diemcrm"]));
  const { registerTool } = await import("../tools.js");
  for (const spec of tools) {
    registerTool({
      name: spec.name,
      description: spec.name,
      input_schema: spec.input_schema ?? TOOL_SCHEMA,
      webhook_url: `http://webhook.test/${spec.name}`,
      ...(spec.owner ? { owner: spec.owner } : {}),
      ...(spec.stream_input ? { stream_input: spec.stream_input } : {}),
    });
  }
  const { credentialRelay } = await import("../mcp-credential-relay.js");
  await credentialRelay.start();
  const { queryRouter } = await import("../query.js");
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.clientLabel = (req.headers["x-test-label"] as string | undefined) ?? "reqlift";
    next();
  });
  app.use(queryRouter);
  return app;
}

function events(text: string): Record<string, unknown>[] {
  return text.split("\n").filter((line) => line.trim()).map((line) => JSON.parse(line) as Record<string, unknown>);
}

const toolUses = (list: Record<string, unknown>[]) => list.filter((e) => e.type === "tool_use");

/** Runs one query that makes the given calls and returns the stream's and the replay's `tool_use` events. */
async function run(app: express.Express, calls: Step[], body: Record<string, unknown> = {}, label = "reqlift", headers: Record<string, string> = {}) {
  steps = calls;
  const queryId = `q-${Math.random().toString(36).slice(2)}`;
  const res = await request(app)
    .post("/v1/query")
    .set("x-test-label", label)
    .set(headers)
    .send({ queryId, prompt: "go", useSession: false, user_id: "user-1", ...body });
  expect(res.status).toBe(200);
  const replay = await request(app).get(`/v1/query/${queryId}/events`).set("x-test-label", label);
  expect(replay.status).toBe(200);
  return { queryId, stream: toolUses(events(res.text)), replayed: toolUses(events(replay.text)) };
}

const RAW: ToolSpec = { name: "reqlift_present_choices", owner: "reqlift", stream_input: "raw" };
const FULL = `${PREFIX}reqlift_present_choices`;
const call = (input: unknown, extra: Partial<Step> = {}): Step => ({ tool: FULL, json: JSON.stringify(input), ...extra });

describe("a raw tool streams the object its webhook received", () => {
  it("the AC example: stream, replay and webhook body are the same object", async () => {
    const app = await createApp([RAW]);
    const { stream, replayed } = await run(app, [call(CHOICES, { id: "toolu_ac" })]);
    expect(stream).toHaveLength(1);
    expect(stream[0]).toMatchObject({ type: "tool_use", toolName: FULL, toolUseId: "toolu_ac", input: CHOICES, parentToolUseId: null });
    expect(typeof stream[0].seq).toBe("number");
    expect(typeof stream[0].startedAt).toBe("number");
    expect(replayed).toEqual(stream);
    expect(webhookBodies).toEqual([{ url: "http://webhook.test/reqlift_present_choices", body: CHOICES }]);
  });

  it.each([
    ["an undeclared top-level key", '{"question":"q","extra":"dropped"}'],
    ["an undeclared nested key", '{"question":"q","options":[{"label":"A","hidden":1}]}'],
    ["a nested __proto__ key", '{"question":"q","options":[{"label":"A","__proto__":{"polluted":true}}]}'],
    ["a nested key named like an Object.prototype member", '{"question":"q","options":[{"label":"A","toString":"x","constructor":"y"}]}'],
  ])("%s: the event equals the body the real MCP server forwarded", async (_label, json) => {
    const app = await createApp([RAW]);
    const { stream, replayed } = await run(app, [{ tool: FULL, json }]);
    expect(webhookBodies).toHaveLength(1);
    expect(stream[0].input).toEqual(webhookBodies[0].body);
    expect(Object.keys(stream[0].input as object).sort()).toEqual(Object.keys(webhookBodies[0].body as object).sort());
    expect(replayed).toEqual(stream);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it("a property named like an Object.prototype member at the top level (the z.preprocess path)", async () => {
    const schema = { type: "object", properties: { toString: { type: "string" }, name: { type: "string" } } };
    const app = await createApp([{ ...RAW, input_schema: schema }]);
    const { stream } = await run(app, [{ tool: FULL, json: '{"name":"x"}' }, { tool: FULL, json: '{"toString":"own","name":"y"}' }]);
    expect(stream).toHaveLength(2);
    expect(webhookBodies.map((w) => w.body)).toEqual([{ name: "x" }, { name: "y", toString: "own" }] as unknown[]);
    expect(stream.map((e) => e.input)).toEqual(webhookBodies.map((w) => w.body));
  });

  it("a sub-agent's call keeps its parentToolUseId", async () => {
    const app = await createApp([RAW]);
    const { stream } = await run(app, [call(CHOICES, { id: "toolu_child", parent: "tu_parent" })]);
    expect(stream[0]).toMatchObject({ toolUseId: "toolu_child", parentToolUseId: "tu_parent", input: CHOICES });
  });

  it("the 16 KiB bound counts UTF-8 bytes: 16384 bytes stay an object, 16385 become a summary string", async () => {
    const app = await createApp([RAW]);
    const wrapper = Buffer.byteLength(JSON.stringify({ question: "" }), "utf8");
    const exact = { question: "a".repeat(16384 - wrapper) };
    const over = { question: "a".repeat(16385 - wrapper) };
    // 'ä' is two bytes: 8185 characters are 16370 bytes; the whole input is far below 16384 characters.
    const multibyte = { question: "ä".repeat((16385 - wrapper) / 2) };
    expect(multibyte.question.length).toBeLessThan(16384);
    const { stream, replayed } = await run(app, [call(exact), call(over), call(multibyte)]);
    expect(stream[0].input).toEqual(exact);
    for (const index of [1, 2]) {
      expect(typeof stream[index].input).toBe("string");
      expect((stream[index].input as string).length).toBeLessThanOrEqual(1000);
    }
    expect(replayed).toEqual(stream);
    expect(logs.filter((l) => l.includes("tool.stream_input.withheld"))).toEqual([
      expect.stringContaining("reason=size bytes=16385"),
      expect.stringContaining("reason=size bytes=16385"),
    ]);
  });

  it("an input that fails the schema is a summary string (the server refuses it too)", async () => {
    const app = await createApp([RAW]);
    steps = [{ tool: FULL, json: '{"options":[]}' }];
    const res = await request(app).post("/v1/query").send({ queryId: "q-bad", prompt: "go", useSession: false, user_id: "u" });
    // The scripted model sends the input to the real server, which answers with an error; the stream still ends.
    expect(res.status).toBe(200);
    const [event] = toolUses(events(res.text));
    expect(typeof event.input).toBe("string");
  });

  it("U+0000 in a value is a summary string", async () => {
    const app = await createApp([RAW]);
    const { stream, replayed } = await run(app, [{ tool: FULL, json: '{"question":"a\\u0000b"}' }]);
    expect(typeof stream[0].input).toBe("string");
    expect(replayed).toEqual(stream);
    expect(logs.join("\n")).toContain("reason=encoding bytes=-1");
  });
});

describe("what stays a summary string", () => {
  it("a summary registration, and an omitted one", async () => {
    const app = await createApp([{ ...RAW, stream_input: "summary" }, { name: "plain_tool", owner: "reqlift" }]);
    const { stream } = await run(app, [call(CHOICES), { tool: `${PREFIX}plain_tool`, json: JSON.stringify(CHOICES) }]);
    for (const event of stream) {
      expect(typeof event.input).toBe("string");
      expect(event.input).toBe(JSON.stringify(CHOICES, null, 2));
    }
  });

  it("a legacy ownerless entry that stores raw", async () => {
    const app = await createApp([{ ...RAW, owner: undefined }]);
    const { stream, replayed } = await run(app, [call(CHOICES)]);
    expect(typeof stream[0].input).toBe("string");
    expect(replayed).toEqual(stream);
  });

  it("another label's raw tool is not offered and not streamed to this label", async () => {
    const app = await createApp([{ ...RAW, owner: "diemcrm" }]);
    const { stream } = await run(app, [call(CHOICES)]);
    expect(Object.keys((capturedOptions[0].mcpServers as object | undefined) ?? {})).not.toContain("agent-gateway-tools");
    expect(typeof stream[0].input).toBe("string");
    expect(webhookBodies).toEqual([]);
  });

  it("the flag grants nothing: a policy that denies the tool leaves it unoffered, and a call to it streams a string", async () => {
    const app = await createApp([RAW], { labels: { reqlift: { deny: [FULL] } } });
    const { stream } = await run(app, [call(CHOICES)]);
    expect(Object.keys((capturedOptions[0].mcpServers as object | undefined) ?? {})).not.toContain("agent-gateway-tools");
    expect(typeof stream[0].input).toBe("string");
    expect(webhookBodies).toEqual([]);
  });

  it("a registry server named like the webhook server replaces it, and no tool streams an object", async () => {
    const app = await createApp([RAW]);
    const { registerMcpServer } = await import("../mcp-registry.js");
    const now = new Date().toISOString();
    registerMcpServer({ name: "agent-gateway-tools", description: "shadow", enabled: true, type: "stdio", command: "node", args: ["-e", ""], createdAt: now, updatedAt: now });
    const { stream } = await run(app, [call(CHOICES)]);
    const attached = (capturedOptions[0].mcpServers as Record<string, { type?: string; instance?: unknown }>)["agent-gateway-tools"];
    expect(attached.instance).toBeUndefined();
    expect(typeof stream[0].input).toBe("string");
  });

  it("a request server whose name makes the tool name ambiguous leaves the tool a summary", async () => {
    const app = await createApp([{ ...RAW, name: "present__choices" }]);
    const ambiguous = { tool: `${PREFIX}present__choices`, json: JSON.stringify({ question: "q" }) };
    const withServer = await run(app, [ambiguous], { mcpServers: { "agent-gateway-tools__present": { url: "http://127.0.0.1:9/mcp" } } });
    expect(typeof withServer.stream[0].input).toBe("string");
    const without = await run(app, [ambiguous]);
    expect(without.stream[0].input).toEqual({ question: "q" });
  });

  it("TodoWrite and a built-in keep today's events", async () => {
    const app = await createApp([RAW]);
    const todos = { todos: [{ content: "x", status: "pending", activeForm: "xing" }] };
    const { stream } = await run(app, [{ tool: "TodoWrite", json: JSON.stringify(todos) }, { tool: "Bash", json: JSON.stringify({ command: "ls" }) }]);
    expect(stream[0].input).toEqual(todos);
    expect(stream[1].input).toBe("ls");
  });
});

describe("known secret values never reach the stream, the replay or the log", () => {
  const BEARER = "gateway-bearer-0123456789";

  it("the caller's own bearer inside a raw input: a masked summary string", async () => {
    const app = await createApp([RAW]);
    const { stream, replayed } = await run(app, [call({ question: `token ${BEARER}`, options: [] })], {}, "reqlift", { authorization: `Bearer ${BEARER}` });
    expect(typeof stream[0].input).toBe("string");
    expect(stream[0].input).toContain("[REDACTED]");
    expect(JSON.stringify([stream, replayed])).not.toContain(BEARER);
    expect(logs.join("\n")).not.toContain(BEARER);
    expect(logs.join("\n")).toContain("reason=secret");
  });

  it("a credential override value inside a raw input", async () => {
    const app = await createApp([RAW]);
    const { registerMcpServer } = await import("../mcp-registry.js");
    const now = new Date().toISOString();
    registerMcpServer({ name: "jira", description: "j", enabled: true, type: "http", url: "http://127.0.0.1:9/mcp", headers: { Authorization: "Bearer registry-secret-value-1" }, createdAt: now, updatedAt: now });
    // The needle is the whole header value, as the gateway holds it.
    const OVERRIDE = "Bearer override-secret-value-2";
    const { stream, replayed } = await run(app, [call({ question: OVERRIDE })], { mcpCredentialOverrides: { jira: { headers: { Authorization: OVERRIDE } } } });
    expect(typeof stream[0].input).toBe("string");
    expect(JSON.stringify([stream, replayed])).not.toContain(OVERRIDE);
    expect(logs.join("\n")).not.toContain(OVERRIDE);
  });

  it("a request server header value inside a raw input", async () => {
    const app = await createApp([RAW]);
    const HEADER = "request-header-secret-3";
    const { stream, replayed } = await run(app, [call({ question: HEADER })], { mcpServers: { remote: { url: "http://127.0.0.1:9/mcp", headers: { "X-Key": HEADER } } } });
    expect(typeof stream[0].input).toBe("string");
    expect(JSON.stringify([stream, replayed])).not.toContain(HEADER);
    expect(logs.join("\n")).not.toContain(HEADER);
  });

  it("permitted control: the same call without the value streams the object", async () => {
    const app = await createApp([RAW]);
    const { stream } = await run(app, [call({ question: "harmless" })], {}, "reqlift", { authorization: `Bearer ${BEARER}` });
    expect(stream[0].input).toEqual({ question: "harmless" });
  });
});

describe("a restart keeps the registration", () => {
  it("a raw tool saved before the restart streams the object after it, and a file without the field streams a summary", async () => {
    const first = await createApp([RAW, { name: "old_tool", owner: "reqlift" }]);
    expect((await run(first, [call(CHOICES)])).stream[0].input).toEqual(CHOICES);
    const { flushTools } = await import("../tools.js");
    expect(flushTools()).toBe(true);
    // Simulate a file written before this change: drop the field of one entry.
    const file = process.env.TOOLS_PERSIST_PATH!;
    const saved = JSON.parse(fs.readFileSync(file, "utf-8")) as Record<string, unknown>[];
    for (const entry of saved) if (entry.name === "old_tool") delete entry.stream_input;
    fs.writeFileSync(file, JSON.stringify(saved));
    const { credentialRelay } = await import("../mcp-credential-relay.js");
    await credentialRelay.close();
    vi.resetModules();
    const { loadTools, getTool } = await import("../tools.js");
    loadTools();
    expect(getTool("reqlift_present_choices")?.stream_input).toBe("raw");
    expect(getTool("old_tool")?.stream_input).toBe("summary");
    const { credentialRelay: relay } = await import("../mcp-credential-relay.js");
    await relay.start();
    const { queryRouter } = await import("../query.js");
    const app = express();
    app.use(express.json());
    app.use((req, _res, next) => {
      req.clientLabel = "reqlift";
      next();
    });
    app.use(queryRouter);
    const { stream, replayed } = await run(app, [call(CHOICES), { tool: `${PREFIX}old_tool`, json: JSON.stringify(CHOICES) }]);
    expect(stream[0].input).toEqual(CHOICES);
    expect(typeof stream[1].input).toBe("string");
    expect(replayed).toEqual(stream);
  });
});
