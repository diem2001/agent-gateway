/**
 * Webhook tool input schemas through the SDK MCP server's real protocol
 * (MVP-7697): each test connects `createToolMcpServer(...).instance` to an
 * in-memory transport and sends JSON-RPC `initialize`, `tools/list` and
 * `tools/call`, so the advertised schema and the argument validation are the
 * SDK's own, not internal handler calls. `fetch` is stubbed as the webhook.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createToolMcpServer } from "../tool-server.js";
import { MAX_SCHEMA_DEPTH } from "../tool-input-schema.js";
import type { ToolDefinition } from "../tools.js";

interface JsonRpcMessage {
  jsonrpc: "2.0";
  id?: number;
  method?: string;
  params?: unknown;
  result?: unknown;
  error?: { code: number; message: string };
}

interface ListedTool {
  name: string;
  description?: string;
  inputSchema: { type: string; properties?: Record<string, unknown>; required?: string[]; [key: string]: unknown };
}

interface CallResult {
  isError?: boolean;
  content: { type: string; text: string }[];
}

/** A JSON-RPC client wired to the server through an in-memory transport. */
async function connect(tools: ToolDefinition[]): Promise<{
  list: () => Promise<ListedTool[]>;
  call: (name: string, argumentsJson: string) => Promise<CallResult>;
}> {
  const pending = new Map<number, (message: JsonRpcMessage) => void>();
  const transport = {
    onmessage: undefined as ((message: JsonRpcMessage, extra?: unknown) => void) | undefined,
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
  const server = createToolMcpServer(tools, { user_id: "u1", session_id: "s1" }, "client-token");
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  await server.instance.connect(transport as any);

  let nextId = 0;
  const rpc = (method: string, params: unknown): Promise<unknown> =>
    new Promise((resolve, reject) => {
      const id = ++nextId;
      pending.set(id, (message) => (message.error ? reject(new Error(message.error.message)) : resolve(message.result)));
      transport.onmessage!({ jsonrpc: "2.0", id, method, params });
    });

  await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "1" } });
  transport.onmessage!({ jsonrpc: "2.0", method: "notifications/initialized" });

  return {
    list: async () => ((await rpc("tools/list", {})) as { tools: ListedTool[] }).tools,
    // Arguments are parsed from JSON text, as the runtime's messages are (own "__proto__" keys included).
    call: async (name, argumentsJson) => (await rpc("tools/call", { name, arguments: JSON.parse(argumentsJson) })) as CallResult,
  };
}

function tool(name: string, inputSchema: Record<string, unknown>, description = `Tool ${name}`): ToolDefinition {
  return { name, description, input_schema: inputSchema, webhook_url: `https://hooks.example/${name}`, timeout_ms: 5000 };
}

let webhookBodies: { url: string; body: unknown }[] = [];

beforeEach(() => {
  webhookBodies = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init: { body: string }) => {
      webhookBodies.push({ url: String(url), body: JSON.parse(init.body) });
      return new Response(JSON.stringify({ output: "OK" }), { status: 200 });
    }),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

async function listOne(inputSchema: Record<string, unknown>): Promise<ListedTool["inputSchema"]> {
  const client = await connect([tool("t", inputSchema)]);
  return (await client.list())[0].inputSchema;
}

async function advertisedProperty(property: unknown): Promise<unknown> {
  return (await listOne({ type: "object", properties: { p: property } })).properties?.p;
}

const PAGE_TOOL = tool("page", {
  type: "object",
  properties: {
    pageId: { type: "string", description: "Confluence page id as text" },
    amount: { type: "number" },
    count: { type: "integer" },
    enabled: { type: "boolean" },
    mode: { type: "string", enum: ["a", "b"] },
    level: { type: "integer", enum: [1, 2, 3] },
    target: { type: "object", properties: { id: { type: "string" }, label: { type: "string" } }, required: ["id"] },
    lines: { type: "array", items: { type: "object", properties: { sku: { type: "string" }, qty: { type: "integer" } }, required: ["sku"] } },
    choice: { oneOf: [{ type: "string" }, { type: "number" }], description: "A name or a number" },
    note: { type: "string" },
  },
  required: ["pageId", "count", "target", "choice"],
});

const VALID_PAGE_ARGS = { pageId: "118784054", count: 3, target: { id: "T-1" }, choice: "x" };

/* ------------------------------------------------------------------ */
/*  tools/list                                                          */
/* ------------------------------------------------------------------ */

describe("tools/list advertises the registered schema (AC-3 rows)", () => {
  it.each([
    ["type string with description", { type: "string", description: "Confluence page id as text" }, { type: "string", description: "Confluence page id as text" }],
    ["type number", { type: "number" }, { type: "number" }],
    ["type integer (not widened to number)", { type: "integer" }, { type: "integer" }],
    ["type boolean", { type: "boolean" }, { type: "boolean" }],
    ['enum ["a","b"]', { type: "string", enum: ["a", "b"] }, { type: "string", enum: ["a", "b"] }],
    ["integer enum", { type: "integer", enum: [1, 2] }, { type: "integer", enum: [1, 2] }],
    ["enum without type", { enum: ["x", 2] }, { enum: ["x", 2] }],
    [
      "nested object with its own required list",
      { type: "object", description: "d", properties: { id: { type: "string", description: "i" }, n: { type: "number" } }, required: ["id"] },
      { type: "object", description: "d", properties: { id: { type: "string", description: "i" }, n: { type: "number" } }, required: ["id"] },
    ],
    [
      "array of objects",
      { type: "array", items: { type: "object", properties: { sku: { type: "string" } }, required: ["sku"] } },
      { type: "array", items: { type: "object", properties: { sku: { type: "string" } }, required: ["sku"] } },
    ],
    ["oneOf (unsupported construct)", { oneOf: [{ type: "string" }], description: "d" }, { description: "d" }],
  ])("%s", async (_row, registered, advertised) => {
    expect(await advertisedProperty(registered)).toEqual(advertised);
  });

  it('required membership is exact: required ["a","b"] and optional "c"', async () => {
    const schema = await listOne({ type: "object", properties: { a: { type: "string" }, b: { oneOf: [] }, c: { type: "string" } }, required: ["a", "b"] });
    expect(schema.required).toEqual(["a", "b"]);
  });

  it("the tool-level description and the property set are unchanged", async () => {
    const client = await connect([PAGE_TOOL]);
    const [listed] = await client.list();
    expect(listed.description).toBe(PAGE_TOOL.description);
    expect(Object.keys(listed.inputSchema.properties ?? {})).toEqual(Object.keys((PAGE_TOOL.input_schema as { properties: object }).properties));
  });

  it("a top-level schema without properties, or with properties: [] (PHP), offers no arguments", async () => {
    expect((await listOne({ type: "object" })).properties).toEqual({});
    expect((await listOne({ type: "object", properties: [], required: [] })).properties).toEqual({});
  });

  it("a nested object without properties or with properties: [] is advertised as a plain object; an array without items as a plain array", async () => {
    expect(await advertisedProperty({ type: "object", description: "any object" })).toEqual({ type: "object", description: "any object" });
    expect(await advertisedProperty({ type: "object", properties: [] })).toEqual({ type: "object" });
    expect(await advertisedProperty({ type: "array" })).toEqual({ type: "array" });
  });

  it("dangling required names are ignored", async () => {
    const schema = await listOne({ type: "object", properties: { a: { type: "string" } }, required: ["a", "ghost"] });
    expect(schema.required).toEqual(["a"]);
    expect(await advertisedProperty({ type: "object", properties: { x: { type: "string" } }, required: ["x", "ghost"] })).toEqual({
      type: "object",
      properties: { x: { type: "string" } },
      required: ["x"],
    });
  });

  it("additionalProperties is ignored: not advertised and no fallback", async () => {
    expect(await advertisedProperty({ type: "object", properties: { x: { type: "string" } }, additionalProperties: false })).toEqual({
      type: "object",
      properties: { x: { type: "string" } },
    });
  });
});

describe("unsupported constructs fall back to any value for that property only", () => {
  it.each([
    ["format", { type: "string", format: "uuid", description: "d" }],
    ["pattern", { type: "string", pattern: "^a+$", description: "d" }],
    ["numeric bound", { type: "integer", minimum: 1, description: "d" }],
    ["anyOf", { anyOf: [{ type: "string" }], description: "d" }],
    ["allOf", { allOf: [{ type: "string" }], description: "d" }],
    ["$ref", { $ref: "#/definitions/x", description: "d" }],
    ["default", { type: "string", default: "x", description: "d" }],
    ["nullable", { type: "string", nullable: true, description: "d" }],
    ["title", { type: "string", title: "T", description: "d" }],
    ["type array", { type: ["string", "null"], description: "d" }],
    ["unknown type", { type: "date", description: "d" }],
    ["missing type", { description: "d" }],
    ["enum with boolean type", { type: "boolean", enum: [true], description: "d" }],
  ])("%s: advertised with only its description, rest of the tool typed", async (_row, registered) => {
    const schema = await listOne({ type: "object", properties: { p: registered, typed: { type: "string" } }, required: ["p"] });
    expect(schema.properties?.p).toEqual({ description: "d" });
    expect(schema.properties?.typed).toEqual({ type: "string" });
    expect(schema.required).toEqual(["p"]);
  });

  it("a non-object property schema (true) accepts any value", async () => {
    expect(await advertisedProperty(true)).toEqual({});
  });

  it("a fallback property accepts any value and delivers it unchanged", async () => {
    const client = await connect([tool("f", { type: "object", properties: { id: { type: "string", format: "uuid" }, v: { oneOf: [] } }, required: ["id"] })])
    const result = await client.call("f", '{"id": 12345, "v": {"deep": [1, "two", null]}}');
    expect(result.isError).toBeFalsy();
    expect(webhookBodies.map((b) => b.body)).toEqual([{ id: 12345, v: { deep: [1, "two", null] } }]);
  });

  it("a required fallback property must still be present", async () => {
    const client = await connect([tool("f", { type: "object", properties: { id: { type: "string", format: "uuid" } }, required: ["id"] })]);
    const result = await client.call("f", "{}");
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('"id"');
    expect(result.content[0].text).toContain("expected a value, received undefined");
    expect(webhookBodies).toEqual([]);
  });
});

describe("malformed keywords are never copied into the advertised schema (F2)", () => {
  it.each([
    ["enum: []", { type: "string", enum: [], description: "d" }, { description: "d" }],
    ["duplicate enum values", { type: "string", enum: ["a", "a"], description: "d" }, { description: "d" }],
    ["enum values not matching type", { type: "string", enum: ["a", 1], description: "d" }, { description: "d" }],
    ["enum with non-literal values", { enum: [{ a: 1 }], description: "d" }, { description: "d" }],
    ["non-string description", { type: "string", description: 42 }, {}],
    ["non-array required on a nested object", { type: "object", properties: { x: { type: "string" } }, required: "x", description: "d" }, { description: "d" }],
    ["required with a non-string name", { type: "object", properties: { x: { type: "string" } }, required: [1], description: "d" }, { description: "d" }],
    ["array items (tuple form)", { type: "array", items: [{ type: "string" }], description: "d" }, { description: "d" }],
    ["non-object properties", { type: "object", properties: "x", description: "d" }, { description: "d" }],
  ])("%s falls back", async (_row, registered, advertised) => {
    expect(await advertisedProperty(registered)).toEqual(advertised);
  });

  it("a malformed top-level required makes that tool alone untyped (the previous shape); other tools stay typed", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
    const client = await connect([
      tool("broken", { type: "object", properties: { a: { type: "string" } }, required: "a" }),
      tool("fine", { type: "object", properties: { a: { type: "string" } }, required: ["a"] }),
    ]);
    const [broken, fine] = await client.list();
    expect(broken.inputSchema.properties).toEqual({ a: {} });
    expect(fine.inputSchema.properties).toEqual({ a: { type: "string" } });
    expect(log.mock.calls.map((c) => c.join(" ")).join("\n")).toContain("tools.schema.untyped_fallback tool=broken");
  });
});

/* ------------------------------------------------------------------ */
/*  tools/call                                                          */
/* ------------------------------------------------------------------ */

describe("tools/call validates before the webhook (AC-2)", () => {
  it("a valid call reaches the webhook with the declared values unchanged; no defaults are injected", async () => {
    const client = await connect([PAGE_TOOL]);
    const args = { ...VALID_PAGE_ARGS, amount: 1.5, enabled: false, mode: "b", level: 2, lines: [{ sku: "S", qty: 1 }], note: "n" };
    const result = await client.call("page", JSON.stringify(args));
    expect(result.isError).toBeFalsy();
    expect(result.content[0].text).toBe("OK");
    expect(webhookBodies).toEqual([{ url: "https://hooks.example/page", body: args }]);

    await client.call("page", JSON.stringify(VALID_PAGE_ARGS));
    expect(webhookBodies[1].body).toEqual(VALID_PAGE_ARGS);
  });

  it("an undeclared top-level key is stripped (as before); an undeclared nested key reaches the webhook", async () => {
    const client = await connect([PAGE_TOOL]);
    await client.call("page", JSON.stringify({ ...VALID_PAGE_ARGS, target: { id: "T-1", extra: [1] }, lines: [{ sku: "S", color: "red" }], undeclared: 1 }));
    expect(webhookBodies.map((b) => b.body)).toEqual([{ ...VALID_PAGE_ARGS, target: { id: "T-1", extra: [1] }, lines: [{ sku: "S", color: "red" }] }]);
  });

  it("additionalProperties: false is not enforced (unchanged behavior)", async () => {
    const client = await connect([
      tool("ap", { type: "object", properties: { o: { type: "object", properties: { x: { type: "string" } }, additionalProperties: false } }, additionalProperties: false }),
    ]);
    const result = await client.call("ap", '{"o": {"x": "1", "y": 2}, "z": 3}');
    expect(result.isError).toBeFalsy();
    expect(webhookBodies.map((b) => b.body)).toEqual([{ o: { x: "1", y: 2 } }]);
  });

  it.each([
    ["pageId as a number", { ...VALID_PAGE_ARGS, pageId: 118784054 }, "pageId", "expected string, received number"],
    ["missing required field", { count: 3, target: { id: "T-1" }, choice: "x" }, "pageId", "expected string, received undefined"],
    ["number for an integer", { ...VALID_PAGE_ARGS, count: 1.5 }, "count", "expected int, received number"],
    ["string for a number", { ...VALID_PAGE_ARGS, amount: "1" }, "amount", "expected number, received string"],
    ["string for a boolean", { ...VALID_PAGE_ARGS, enabled: "true" }, "enabled", "expected boolean, received string"],
    ["value outside the enum", { ...VALID_PAGE_ARGS, mode: "c" }, "mode", 'expected one of \\"a\\"|\\"b\\"'],
    ["value outside an integer enum", { ...VALID_PAGE_ARGS, level: 4 }, "level", "expected one of 1|2|3"],
    ["null for an optional typed field", { ...VALID_PAGE_ARGS, note: null }, "note", "expected string, received null"],
    ["nested required field missing", { ...VALID_PAGE_ARGS, target: { label: "x" } }, '"target",\n      "id"', "expected string, received undefined"],
    ["nested wrong type", { ...VALID_PAGE_ARGS, target: { id: 7 } }, '"target",\n      "id"', "expected string, received number"],
    ["array item violation", { ...VALID_PAGE_ARGS, lines: [{ sku: "S", qty: "2" }] }, '"lines",\n      0,\n      "qty"', "expected number, received string"],
    ["array instead of object", { ...VALID_PAGE_ARGS, target: [] }, "target", "expected object, received array"],
  ])("%s: tool error naming the field path and the expectation; the webhook gets no request", async (_row, args, path, expectation) => {
    const client = await connect([PAGE_TOOL]);
    const result = await client.call("page", JSON.stringify(args));
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/^MCP error -32602: Input validation error: Invalid arguments for tool page: \[/);
    expect(result.content[0].text).toContain(path.includes("\n") ? path : `"${path}"`);
    expect(result.content[0].text).toContain(expectation);
    expect(webhookBodies).toEqual([]);
  });

  it("a webhook error is still relayed as a tool error", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(new Response("pageId: invalid", { status: 422 }));
    const client = await connect([PAGE_TOOL]);
    const result = await client.call("page", JSON.stringify(VALID_PAGE_ARGS));
    // A tool's own 4xx refusal reaches the model with its message (MVP-7679: bounded, wrapped with the status).
    expect(result).toEqual({ isError: true, content: [{ type: "text", text: "The tool rejected the request (HTTP 422): pageId: invalid" }] });
  });
});

/* ------------------------------------------------------------------ */
/*  Hardening: depth, isolation, prototype names (F1, F3)                */
/* ------------------------------------------------------------------ */

describe("one registration cannot break other tools (F1)", () => {
  it("a 20,000-level nested schema still lists and dispatches; levels beyond the depth limit accept any value", async () => {
    let deepest: Record<string, unknown> = { type: "string", description: "leaf" };
    for (let i = 0; i < 20_000; i++) deepest = { type: "object", description: `level ${i}`, properties: { next: deepest }, required: ["next"] };
    const client = await connect([tool("deep", { type: "object", properties: { root: deepest }, required: ["root"] }), PAGE_TOOL]);

    const [deep, page] = await client.list();
    let node = deep.inputSchema.properties?.root as { type?: string; properties?: { next: unknown } };
    let levels = 1;
    while (node.properties) {
      node = node.properties.next as typeof node;
      levels += 1;
    }
    expect(levels).toBe(MAX_SCHEMA_DEPTH + 1);
    expect(node.type).toBeUndefined();
    expect(page.inputSchema.properties?.pageId).toEqual({ type: "string", description: "Confluence page id as text" });

    let args: unknown = { anything: [1, 2] };
    for (let i = 0; i < 40; i++) args = { next: args };
    const result = await client.call("deep", JSON.stringify({ root: args }));
    expect(result.isError).toBeFalsy();
    expect(webhookBodies.map((b) => b.body)).toEqual([{ root: args }]);
  });

  it("a tool whose conversion throws falls back to the previous untyped shape alone, with a log line naming it", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
    const properties = { a: { type: "string" } };
    Object.defineProperty(properties, "b", { enumerable: true, get: () => { throw new Error("hostile getter"); } });
    const client = await connect([tool("throws", { type: "object", properties }), PAGE_TOOL]);

    const [throws, page] = await client.list();
    expect(throws.inputSchema.properties).toEqual({ a: {}, b: {} });
    expect(page.inputSchema.properties?.pageId).toEqual({ type: "string", description: "Confluence page id as text" });
    expect(log.mock.calls.map((c) => c.join(" ")).join("\n")).toMatch(/tools\.schema\.untyped_fallback tool=throws reason=".*hostile getter/);

    const result = await client.call("throws", '{"a": 1, "b": {"x": true}}');
    expect(result.isError).toBeFalsy();
    expect(webhookBodies.map((b) => b.body)).toEqual([{ a: 1, b: { x: true } }]);
    expect((await client.call("page", JSON.stringify({ ...VALID_PAGE_ARGS, pageId: 1 }))).isError).toBe(true);
  });
});

describe("prototype-hazard property names (F3)", () => {
  const PROTO_TOOL = tool(
    "proto",
    JSON.parse(
      JSON.stringify({
        type: "object",
        properties: { city: { type: "string" }, constructor: { type: "string", description: "c" }, toString: { type: "integer" } },
        required: ["city"],
      }).replace('"city":{"type":"string"}', '"city":{"type":"string"},"__proto__":{"type":"string","description":"p"}'),
    ),
  );

  it("__proto__ and a top-level constructor are left out and logged; other prototype-named fields are advertised typed", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
    expect(Object.keys((PROTO_TOOL.input_schema as { properties: object }).properties)).toEqual(["city", "__proto__", "constructor", "toString"]);
    const client = await connect([PROTO_TOOL]);
    const [listed] = await client.list();
    expect(Object.keys(listed.inputSchema.properties ?? {})).toEqual(["city", "toString"]);
    expect(listed.inputSchema.properties?.toString).toEqual({ type: "integer" });
    expect(listed.inputSchema.required).toEqual(["city"]);
    const lines = log.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(lines).toContain("tools.schema.property_excluded tool=proto property=__proto__");
    expect(lines).toContain("tools.schema.property_excluded tool=proto property=constructor");
  });

  it("why constructor is left out: the SDK's MCP protocol rejects any call whose arguments hold a constructor key (unchanged)", async () => {
    const client = await connect([PROTO_TOOL]);
    await expect(client.call("proto", '{"city": "Berlin", "constructor": "x"}')).rejects.toThrow(/expected record/);
    expect(webhookBodies).toEqual([]);
  });

  it("the handler receives the model's arguments (not the SDK request context), with or without the optional prototype-named field", async () => {
    const client = await connect([PROTO_TOOL]);
    expect((await client.call("proto", '{"city": "Berlin", "toString": 3}')).isError).toBeFalsy();
    expect((await client.call("proto", '{"city": "Paris"}')).isError).toBeFalsy();
    expect(webhookBodies.map((b) => b.body)).toEqual<unknown[]>([{ city: "Berlin", toString: 3 }, { city: "Paris" }]);

    const wrong = await client.call("proto", '{"city": "Rome", "toString": "3"}');
    expect(wrong.isError).toBe(true);
    expect(wrong.content[0].text).toContain('"toString"');
    expect(webhookBodies).toHaveLength(2);
  });

  it("a nested constructor is typed and delivered; a required prototype-named field that is omitted is rejected as missing", async () => {
    const client = await connect([
      tool("nested", {
        type: "object",
        properties: { o: { type: "object", properties: { constructor: { type: "string" }, valueOf: { type: "integer" } }, required: ["valueOf"] } },
        required: ["o"],
      }),
    ]);
    const [listed] = await client.list();
    expect(listed.inputSchema.properties?.o).toEqual({
      type: "object",
      properties: { constructor: { type: "string" }, valueOf: { type: "integer" } },
      required: ["valueOf"],
    });
    expect((await client.call("nested", '{"o": {"constructor": "x", "valueOf": 1}}')).isError).toBeFalsy();
    expect((await client.call("nested", '{"o": {"valueOf": 2}}')).isError).toBeFalsy();
    expect(webhookBodies.map((b) => b.body)).toEqual<unknown[]>([{ o: { constructor: "x", valueOf: 1 } }, { o: { valueOf: 2 } }]);

    const missing = await client.call("nested", '{"o": {"constructor": "x"}}');
    expect(missing.isError).toBe(true);
    expect(missing.content[0].text).toContain('"valueOf"');
    expect(missing.content[0].text).toContain("expected number, received undefined");
    expect(webhookBodies).toHaveLength(2);
  });

  it("a model-sent __proto__ key, top-level or nested, causes no global prototype pollution", async () => {
    const client = await connect([PAGE_TOOL]);
    const result = await client.call(
      "page",
      '{"pageId": "p", "count": 1, "choice": 1, "target": {"id": "T", "__proto__": {"polluted": true}}, "__proto__": {"polluted": true}}',
    );
    expect(result.isError).toBeFalsy();
    expect(({} as Record<string, unknown>)["polluted"]).toBeUndefined();
    expect(Object.prototype).not.toHaveProperty("polluted");
    expect(webhookBodies).toHaveLength(1);
  });
});
