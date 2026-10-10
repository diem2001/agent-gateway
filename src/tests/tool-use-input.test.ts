/**
 * The structured `tool_use` input of a `stream_input: "raw"` webhook tool (MVP-8096, src/tool-use-input.ts): the table
 * of eligible tools and the decision per call. Expected values are written out here, not derived from the module.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MAX_INPUT_BYTES, buildStreamInputTable, streamedToolInput, type StreamInputTable } from "../tool-use-input.js";
import type { ToolDefinition } from "../tools.js";

const PREFIX = "mcp__agent-gateway-tools__";
const NAME = "present_choices";
const FULL = `${PREFIX}${NAME}`;
const SERVER = { type: "sdk", name: "agent-gateway-tools" };
const SUMMARY_MARKER = "SUMMARY";

const SCHEMA = {
  type: "object",
  properties: { question: { type: "string" }, options: { type: "array", items: { type: "object", properties: { label: { type: "string" } } } } },
  required: ["question"],
};

function def(overrides: Partial<ToolDefinition> = {}): ToolDefinition {
  return { name: NAME, description: "d", input_schema: SCHEMA, webhook_url: "https://example.com/h", owner: "reqlift", stream_input: "raw", ...overrides };
}

function table(defs: ToolDefinition[] = [def()], extra: { label?: string; servers?: Record<string, unknown>; webhook?: unknown; secrets?: string[] } = {}): StreamInputTable {
  const webhook = "webhook" in extra ? extra.webhook : SERVER;
  return buildStreamInputTable({
    registeredTools: defs,
    callerLabel: extra.label ?? "reqlift",
    mcpServers: { ...(webhook === undefined ? {} : { "agent-gateway-tools": webhook }), ...(extra.servers ?? {}) },
    webhookServer: webhook,
    secretValues: () => extra.secrets ?? [],
  });
}

/** `today`: the stand-in for the unchanged summary builder. */
const today = (_name: string, input: Record<string, unknown> | undefined): unknown => `${SUMMARY_MARKER}:${JSON.stringify(input)}`;

function call(t: StreamInputTable, input: unknown, name = FULL): unknown {
  return streamedToolInput(name, input as Record<string, unknown>, "toolu_1", t, today);
}

let logs: string[];
beforeEach(() => {
  logs = [];
  vi.spyOn(console, "log").mockImplementation((...args) => {
    logs.push(args.map(String).join(" "));
  });
});
afterEach(() => {
  vi.restoreAllMocks();
});

/** An input whose compact serialization is exactly `bytes` UTF-8 bytes. */
function inputOfBytes(bytes: number, filler = "a"): { question: string } {
  const base = Buffer.byteLength(JSON.stringify({ question: "" }), "utf8");
  const fillerBytes = Buffer.byteLength(filler, "utf8");
  const count = (bytes - base) / fillerBytes;
  expect(Number.isInteger(count)).toBe(true);
  const input = { question: filler.repeat(count) };
  expect(Buffer.byteLength(JSON.stringify(input), "utf8")).toBe(bytes);
  return input;
}

describe("sizes (UTF-8 bytes of the compact serialization)", () => {
  it("200 bytes: the original object", () => {
    const input = inputOfBytes(200);
    expect(call(table(), input)).toEqual(input);
  });

  it("16384 bytes: the original object", () => {
    const input = inputOfBytes(16384);
    expect(call(table(), input)).toEqual(input);
  });

  it("16385 bytes: the summary string, at most 1000 characters", () => {
    const result = call(table(), inputOfBytes(16385));
    expect(typeof result).toBe("string");
    expect((result as string).length).toBeLessThanOrEqual(1000);
    expect(logs.filter((l) => l.includes("tool.stream_input.withheld"))).toEqual([
      expect.stringContaining('toolName="present_choices" toolUseId="toolu_1" reason=size bytes=16385'),
    ]);
  });

  it("non-ASCII text above 16384 bytes whose character count is at most 16384: the summary string", () => {
    // 'ä' is two bytes: the question holds 8185 characters and 16370 bytes, plus the 15 bytes of the wrapper.
    const input = inputOfBytes(16385, "ä");
    expect(input.question.length).toBeLessThanOrEqual(16384);
    expect(JSON.stringify(input).length).toBeLessThan(16384);
    const result = call(table(), input);
    expect(typeof result).toBe("string");
    expect(logs.join("\n")).toContain("reason=size bytes=16385");
  });

  it("non-ASCII text just inside the byte limit stays an object", () => {
    const input = inputOfBytes(16383, "ä");
    expect(call(table(), input)).toEqual(input);
  });

  it("the limit constant is 16 KiB", () => {
    expect(MAX_INPUT_BYTES).toBe(16384);
  });
});

describe("which tools stream an object", () => {
  const input = { question: "Which environment?", options: [{ label: "Test" }, { label: "Stage" }] };

  it("summary and omitted registrations use today's builder", () => {
    expect(call(table([def({ stream_input: "summary" })]), input)).toBe(`${SUMMARY_MARKER}:${JSON.stringify(input)}`);
    expect(call(table([def({ stream_input: undefined })]), input)).toBe(`${SUMMARY_MARKER}:${JSON.stringify(input)}`);
  });

  it("another tool, and a built-in, use today's builder", () => {
    const t = table();
    expect(call(t, input, `${PREFIX}other`)).toBe(`${SUMMARY_MARKER}:${JSON.stringify(input)}`);
    expect(call(t, input, "Bash")).toBe(`${SUMMARY_MARKER}:${JSON.stringify(input)}`);
  });

  it("a legacy ownerless raw entry is never streamed as an object", () => {
    expect(table([def({ owner: undefined })]).tools.size).toBe(0);
  });

  it("another label's raw tool is not in the table", () => {
    expect(table([def({ owner: "diemcrm" })], { label: "reqlift" }).tools.size).toBe(0);
  });

  it("a run without a label has an empty table even for an owned entry", () => {
    expect(table([def()], { label: "" }).tools.size).toBe(0);
  });

  it("a registry server named agent-gateway-tools that replaced the webhook server empties the table", () => {
    expect(table([def()], { webhook: SERVER, servers: {} }).tools.size).toBe(1);
    const t = buildStreamInputTable({
      registeredTools: [def()],
      callerLabel: "reqlift",
      mcpServers: { "agent-gateway-tools": { type: "http", url: "http://127.0.0.1:1/relay" } },
      webhookServer: SERVER,
      secretValues: () => [],
    });
    expect(t.tools.size).toBe(0);
    expect(call(t, input)).toBe(`${SUMMARY_MARKER}:${JSON.stringify(input)}`);
  });

  it("no webhook server in this run: empty table", () => {
    expect(table([def()], { webhook: undefined }).tools.size).toBe(0);
  });

  it.each([
    ["a server whose name is a prefix of the full name", "agent-gateway-tools__present", "present__choices"],
    ["a server whose name normalizes to such a prefix", "agent-gateway-tools!", "_x"],
  ])("%s leaves the tool out", (_label, server, toolName) => {
    const servers = { [server]: { type: "http", url: "http://127.0.0.1:1/x" } };
    expect(table([def({ name: toolName })], { servers }).tools.size).toBe(0);
    // The same tool without that server is raw: the exclusion comes from the server name alone.
    expect(table([def({ name: toolName })]).tools.size).toBe(1);
  });

  it("an unrelated attached server leaves the tool in", () => {
    expect(table([def()], { servers: { jira: { type: "http", url: "http://127.0.0.1:1/x" } } }).tools.size).toBe(1);
  });

  it.each([["with a dot", "a.b"], ["with a space", "a b"], ["empty", ""], ["too long", "x".repeat(65)]])("a tool name %s is never raw", (_label, name) => {
    expect(table([def({ name })]).tools.size).toBe(0);
  });

  it("a 64-character name of allowed characters is raw", () => {
    expect(table([def({ name: "a_B-9".repeat(12) + "abcd" })]).tools.size).toBe(1);
  });

  it("the table is a snapshot: a later change of the definition does not flip a built table", () => {
    const d = def();
    const t = table([d]);
    d.stream_input = "summary";
    // The registry replaces a definition object on PUT; the table keeps the validator it was built with.
    expect(t.tools.size).toBe(1);
    expect(call(t, input)).toEqual(input);
  });
});

describe("schema", () => {
  it("input that fails the tool's schema: the summary string", () => {
    expect(call(table(), { options: [] })).toBe(JSON.stringify({ options: [] }, null, 2));
    expect(logs.join("\n")).toContain("reason=schema bytes=-1");
  });

  it.each([[undefined], [null], ["text"], [5], [[1]]])("a non-object input %j: a string, never a throw", (value) => {
    expect(typeof call(table(), value)).toBe("string");
  });

  it("an undeclared top-level key is stripped; an undeclared nested key stays", () => {
    const result = call(table(), { question: "q", extra: "no", options: [{ label: "A", hidden: 1 }] });
    expect(result).toEqual({ question: "q", options: [{ label: "A", hidden: 1 }] });
  });

  it("a nested __proto__ key and a property named like an Object.prototype member do not break the event", () => {
    const withProto = JSON.parse('{"question":"q","options":[{"label":"A","__proto__":{"polluted":true}}]}');
    const result = call(table(), withProto) as { question: string; options: { label: string }[] };
    expect(result.question).toBe("q");
    expect(result.options[0].label).toBe("A");
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();

    const protoTool = def({ input_schema: { type: "object", properties: { toString: { type: "string" }, name: { type: "string" } } } });
    expect(call(table([protoTool]), { name: "x" })).toEqual({ name: "x" });
    expect(call(table([protoTool]), { toString: "own", name: "x" })).toEqual({ toString: "own", name: "x" });
  });
});

describe("depth", () => {
  const free = def({ input_schema: { type: "object", properties: { tree: { type: "object" } } } });

  function nested(levels: number): Record<string, unknown> {
    // The top-level object is level 1; `tree` adds the rest.
    let node: Record<string, unknown> = {};
    for (let i = 3; i <= levels; i++) node = { n: node };
    return { tree: node };
  }

  it("32 levels: the object", () => {
    const input = nested(32);
    expect(call(table([free]), input)).toEqual(input);
  });

  it("33 levels: the summary string", () => {
    const result = call(table([free]), nested(33));
    expect(typeof result).toBe("string");
    expect(logs.join("\n")).toContain("reason=depth bytes=-1");
  });

  it("20000 levels: the summary or the placeholder, never a throw", () => {
    let node: Record<string, unknown> = {};
    for (let i = 0; i < 20000; i++) node = { n: node };
    const result = call(table([free]), { tree: node });
    expect(typeof result).toBe("string");
    expect((result as string).length).toBeLessThanOrEqual(1000);
  });

  it("20000 nested arrays: a string, never a throw", () => {
    const anyTool = def({ input_schema: { type: "object", properties: { v: { type: "array" } } } });
    let node: unknown[] = [];
    for (let i = 0; i < 20000; i++) node = [node];
    expect(typeof call(table([anyTool]), { v: node })).toBe("string");
  });
});

describe("encoding", () => {
  it.each([
    ["U+0000 in a value", { question: "a\u0000b" }],
    ["a lone high surrogate in a value", { question: "a\uD800b" }],
    ["a lone low surrogate in a value", { question: "a\uDC00b" }],
    ["U+0000 in a nested key", { question: "q", options: [{ "la\u0000bel": "x" }] }],
  ])("%s: the summary string", (_label, input) => {
    const result = call(table(), input);
    expect(typeof result).toBe("string");
    expect(logs.join("\n")).toContain("reason=encoding bytes=-1");
  });

  it("a valid surrogate pair stays an object", () => {
    expect(call(table(), { question: "ok \u{1F600}" })).toEqual({ question: "ok \u{1F600}" });
  });
});

describe("known secret values", () => {
  const SECRET = "sk-test-0123456789-abcdef";

  it.each([
    ["in a value", { question: `use ${SECRET} now` }],
    ["in a nested value", { question: "q", options: [{ label: SECRET }] }],
    ["in a key", { question: "q", options: [{ [SECRET]: 1 }] }],
  ])("a needle %s: a masked summary string, and the log has no needle", (_label, input) => {
    const result = call(table([def()], { secrets: [SECRET] }), input) as string;
    expect(typeof result).toBe("string");
    expect(result).not.toContain(SECRET);
    expect(result).toContain("[REDACTED]");
    expect(logs.join("\n")).toContain("reason=secret");
    expect(logs.join("\n")).not.toContain(SECRET);
  });

  it("a needle with a quote and a backslash is masked in its JSON-escaped form too", () => {
    const needle = 'pa"ss\\word-12345';
    const result = call(table([def()], { secrets: [needle] }), { question: needle }) as string;
    expect(typeof result).toBe("string");
    expect(result).not.toContain(needle);
    expect(result).not.toContain('pa\\"ss\\\\word-12345');
    expect(result).toContain("[REDACTED]");
  });

  it("a needle that crosses the 1000-character boundary of the pretty string is masked before the cut", () => {
    const question = "x".repeat(970) + SECRET;
    const result = call(table([def()], { secrets: [SECRET] }), { question }) as string;
    expect(result.length).toBeLessThanOrEqual(1000);
    expect(result).not.toContain("sk-test");
    expect(result).not.toContain(SECRET.slice(0, 12));
  });

  it("a withheld-for-size input also has its needles masked in the summary", () => {
    const input = { question: SECRET + "y".repeat(17000) };
    const result = call(table([def()], { secrets: [SECRET] }), input) as string;
    expect(result).not.toContain(SECRET);
  });

  it("values shorter than 8 characters are not needles", () => {
    expect(call(table([def()], { secrets: ["short"] }), { question: "a short one" })).toEqual({ question: "a short one" });
  });

  it("the same call without the value streams the object (permitted control)", () => {
    expect(call(table([def()], { secrets: [SECRET] }), { question: "harmless" })).toEqual({ question: "harmless" });
  });

  it("the needle list is computed once per run and only for a raw-eligible call", () => {
    const secretValues = vi.fn(() => [SECRET]);
    const t = buildStreamInputTable({ registeredTools: [def()], callerLabel: "reqlift", mcpServers: { "agent-gateway-tools": SERVER }, webhookServer: SERVER, secretValues });
    call(t, { question: "x" }, "Bash");
    call(t, { question: "x" }, `${PREFIX}other`);
    expect(secretValues).not.toHaveBeenCalled();
    call(t, { question: "a" });
    call(t, { question: "b" });
    expect(secretValues).toHaveBeenCalledTimes(1);
  });
});

describe("the withheld log line", () => {
  it("escapes a hostile tool use id and never prints the input", () => {
    const t = table();
    streamedToolInput(FULL, { options: "secret-looking-input" } as never, 'id"\nforged line', t, today);
    const lines = logs.filter((l) => l.includes("tool.stream_input.withheld"));
    expect(lines).toHaveLength(1);
    expect(lines[0]).toContain('toolUseId="id\\"\\nforged line"');
    expect(lines[0]).not.toContain("secret-looking-input");
    expect(lines[0].split("\n")).toHaveLength(1);
  });
});

describe("the decoupled copy", () => {
  it("is a new object, not the live one", () => {
    const input = { question: "q" };
    const result = call(table(), input);
    expect(result).toEqual(input);
    expect(result).not.toBe(input);
  });
});
