/**
 * The enforced tool set's request validation and its PreToolUse hook (MVP-7637).
 * Expected texts are written out here, not imported.
 */
import { describe, expect, it } from "vitest";
import { builtInTools, createToolPolicyHook, namesServer, validateEnforcedTools } from "../tool-policy.js";

const SERVERS = ["agent-gateway-tools", "jira"];
const DENY = {
  hookSpecificOutput: {
    hookEventName: "PreToolUse",
    permissionDecision: "deny",
    permissionDecisionReason: "Refused: this tool is not allowed for this run.",
  },
};

describe("validateEnforcedTools", () => {
  it("accepts an absent field, an empty set and SDK-qualified names", () => {
    expect(validateEnforcedTools(undefined, undefined, SERVERS)).toEqual({});
    expect(validateEnforcedTools([], undefined, SERVERS)).toEqual({ tools: [] });
    const set = ["mcp__jira__get_confluence_page", "mcp__agent-gateway-tools__reqlift_confluence_report_region", "Bash"];
    expect(validateEnforcedTools(set, undefined, SERVERS)).toEqual({ tools: set });
    expect(validateEnforcedTools(["x".repeat(128)], undefined, SERVERS)).toEqual({ tools: ["x".repeat(128)] });
    expect(validateEnforcedTools(Array.from({ length: 64 }, (_, i) => `T${i}`), undefined, SERVERS).tools).toHaveLength(64);
  });

  it.each([
    ["null", null, undefined, "enforcedTools must be an array of tool names"],
    ["a string", "Bash", undefined, "enforcedTools must be an array of tool names"],
    ["an object", { 0: "Bash" }, undefined, "enforcedTools must be an array of tool names"],
    ["with allowedTools", ["Bash"], ["Read"], "enforcedTools cannot be combined with allowedTools"],
    ["65 names", Array.from({ length: 65 }, (_, i) => `T${i}`), undefined, "enforcedTools may name at most 64 tools"],
    ["an empty name", [""], undefined, "enforcedTools[0] must be 1-128 characters of A-Z, a-z, 0-9, _ or -"],
    ["a 129-character name", ["x".repeat(129)], undefined, "enforcedTools[0] must be 1-128 characters of A-Z, a-z, 0-9, _ or -"],
    ["a wildcard", ["mcp__jira__*"], undefined, "enforcedTools[0] must be 1-128 characters of A-Z, a-z, 0-9, _ or -"],
    ["a pattern", ["Bash(*)"], undefined, "enforcedTools[0] must be 1-128 characters of A-Z, a-z, 0-9, _ or -"],
    ["a non-string", ["Read", 7], undefined, "enforcedTools[1] must be 1-128 characters of A-Z, a-z, 0-9, _ or -"],
    ["a duplicate", ["Read", "Read"], undefined, "enforcedTools[1] repeats a tool name"],
    ["Task", ["Task"], undefined, "enforcedTools[0] names a sub-agent tool, which cannot be enforced"],
    ["Agent", ["Read", "Agent"], undefined, "enforcedTools[1] names a sub-agent tool, which cannot be enforced"],
  ])("refuses %s", (_label, value, allowedTools, error) => {
    expect(validateEnforcedTools(value, allowedTools, SERVERS)).toEqual({ error });
  });

  it("refuses a name that fits more than one attached server", () => {
    // A registry name may itself contain `__`.
    const servers = ["jira", "jira__beta"];
    expect(validateEnforcedTools(["mcp__jira__beta__read"], undefined, servers)).toEqual({
      error: "enforcedTools[0] matches more than one MCP server",
    });
    expect(validateEnforcedTools(["mcp__jira__read"], undefined, servers)).toEqual({ tools: ["mcp__jira__read"] });
  });
});

describe("the set's shape", () => {
  it("names built-ins without the mcp__ prefix and servers by exact prefix", () => {
    const set = ["mcp__jira__get_confluence_page", "Bash", "mcp__agent-gateway-tools__x"];
    expect(builtInTools(set)).toEqual(["Bash"]);
    expect(builtInTools(["mcp__jira__a"])).toEqual([]);
    expect(namesServer(set, "jira")).toBe(true);
    expect(namesServer(set, "agent-gateway-tools")).toBe(true);
    expect(namesServer(set, "jir")).toBe(false);
    expect(namesServer(set, "confluence")).toBe(false);
    expect(namesServer(["mcp__jira__"], "jira")).toBe(false);
  });
});

describe("createToolPolicyHook", () => {
  const set = ["mcp__jira__get_confluence_page", "mcp__agent-gateway-tools__reqlift_confluence_report_region"];
  const hook = createToolPolicyHook(set, "q-1");
  const call = (input: unknown) => hook(input as never, "toolu_1", { signal: new AbortController().signal });

  it("makes no decision for a name in the set", async () => {
    for (const name of set) expect(await call({ hook_event_name: "PreToolUse", tool_name: name, tool_input: {} })).toEqual({});
  });

  it("denies every other name, never allowing one", async () => {
    const names: unknown[] = [
      "Bash", "WebFetch", "Write", "TodoWrite", "Task", "mcp__jira__update_confluence_page",
      "mcp__agent-gateway-tools__reqlift_record_feature", "MCP__JIRA__GET_CONFLUENCE_PAGE",
      "mcp__jira__get_confluence_page ", "", undefined, null, 7, {}, "x".repeat(10_000),
    ];
    for (const name of names) {
      const out = await call({ hook_event_name: "PreToolUse", tool_name: name, tool_input: {} });
      expect(out, String(name)).toEqual(DENY);
    }
  });

  it("denies when reading the input throws", async () => {
    const hostile = { get tool_name(): string { throw new Error("boom"); } };
    expect(await call(hostile)).toEqual(DENY);
  });

  it("never returns allow for any input", async () => {
    const outputs = await Promise.all(
      [...set, "Bash", "Read", "mcp__x__y", null].map((name) => call({ hook_event_name: "PreToolUse", tool_name: name, tool_input: {} })),
    );
    for (const out of outputs) expect(JSON.stringify(out)).not.toContain('"allow"');
  });

  it("an empty set denies everything", async () => {
    const denyAll = createToolPolicyHook([]);
    expect(await denyAll({ hook_event_name: "PreToolUse", tool_name: "Read" } as never, undefined, { signal: new AbortController().signal })).toEqual(DENY);
  });
});
