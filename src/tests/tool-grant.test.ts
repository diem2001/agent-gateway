/**
 * The trusted tool grant (MVP-7679, tool-grant.ts): AGENT_TOOL_POLICY parsing with its fixed fatal reasons, the
 * effective grant (policy intersected with the caller's narrowing, deny beats allow, omitted = policy, empty list =
 * nothing) and the built-in tool layers derived from it. Expected values are written out; none is computed from
 * the production lookup tables.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  RUNTIME_BUILT_IN_TOOLS,
  ToolPolicyConfigError,
  computeToolGrant,
  loadToolPolicy,
  parseToolPolicy,
  setToolPolicy,
} from "../tool-grant.js";

afterEach(() => {
  setToolPolicy(null);
  vi.restoreAllMocks();
});

const LABELS = ["reqlift", "diemcrm"];
const ALL_BUILT_INS = [
  "Agent", "AskUserQuestion", "Bash", "Edit", "EnterPlanMode", "ExitPlanMode", "Glob", "Grep", "KillShell", "LSP", "NotebookEdit",
  "Read", "Skill", "Task", "TaskCreate", "TaskGet", "TaskList", "TaskOutput", "TaskUpdate", "TodoWrite", "WebFetch", "WebSearch", "Write",
];

function parse(value: unknown): ReturnType<typeof parseToolPolicy> {
  return parseToolPolicy(typeof value === "string" ? value : JSON.stringify(value), LABELS);
}

function reasonOf(value: unknown): string | undefined {
  try {
    parse(value);
    return undefined;
  } catch (e) {
    if (e instanceof ToolPolicyConfigError) return e.reason;
    throw e;
  }
}

describe("the pinned built-in tool list", () => {
  it("includes the task tools of the bundled runtime", () => {
    expect([...RUNTIME_BUILT_IN_TOOLS]).toEqual(ALL_BUILT_INS);
  });
});

describe("AGENT_TOOL_POLICY parsing", () => {
  it.each([["unset", undefined], ["empty", ""], ["blank", "   "]])("%s is no policy", (_label, value) => {
    expect(parseToolPolicy(value, LABELS)).toBeNull();
  });

  it("accepts default and label entries, each with allow and deny lists", () => {
    expect(
      parse({
        default: { allow: ["Read", "mcp__jira__*"], deny: ["mcp__jira__delete_issue"] },
        labels: { reqlift: { deny: ["Bash", "Write"] }, diemcrm: { allow: [] } },
      }),
    ).toEqual({
      default: { allow: ["Read", "mcp__jira__*"], deny: ["mcp__jira__delete_issue"] },
      labels: { reqlift: { deny: ["Bash", "Write"] }, diemcrm: { allow: [] } },
    });
  });

  it.each([
    ["not JSON", "{nope", "must be a JSON object"],
    ["a JSON array", [], "must be a JSON object"],
    ["a JSON string", '"x"', "must be a JSON object"],
    ["null", "null", "must be a JSON object"],
    ["a default that is not an object", { default: [] }, "must be a JSON object"],
    ["labels that is not an object", { labels: [] }, "must be a JSON object"],
    ["a label entry that is not an object", { labels: { reqlift: "Bash" } }, "must be a JSON object"],
    ["an unknown top-level field", { default: {}, extra: 1 }, "unknown field"],
    ["an unknown entry field", { default: { allowed: ["Read"] } }, "unknown field"],
    ["a label not in API_KEYS", { labels: { someoneelse: { deny: ["Bash"] } } }, "label not in API_KEYS"],
    ["an unknown built-in tool name", { default: { deny: ["Bassh"] } }, "unknown built-in tool name"],
    ["a built-in name in the wrong case (case-sensitive)", { default: { allow: ["bash"] } }, "unknown built-in tool name"],
    ["a permission-rule specifier", { default: { allow: ["Bash(git *)"] } }, "invalid tool pattern"],
    ["an mcp pattern without a tool part", { default: { allow: ["mcp__jira"] } }, "invalid tool pattern"],
    ["an mcp pattern with a wildcard in the middle", { default: { allow: ["mcp__ji*ra__x"] } }, "invalid tool pattern"],
    ["a wildcard built-in", { default: { allow: ["*"] } }, "invalid tool pattern"],
    ["a list that is not an array", { default: { allow: "Read" } }, "invalid tool pattern"],
    ["a list entry that is not a string", { default: { allow: [1] } }, "invalid tool pattern"],
    ["an empty pattern", { default: { allow: [""] } }, "invalid tool pattern"],
  ])("refuses %s with the fixed reason", (_label, value, reason) => {
    expect(reasonOf(value)).toBe(reason);
  });

  it("the startup error line is one fixed line without the value", () => {
    try {
      parse({ default: { allow: ["SYNTH-SECRET-7679"] } });
      expect.unreachable();
    } catch (e) {
      expect((e as ToolPolicyConfigError).logLine).toBe("FATAL config key=AGENT_TOOL_POLICY reason=unknown built-in tool name");
      expect((e as ToolPolicyConfigError).logLine).not.toContain("SYNTH-SECRET");
    }
  });
});

describe("the effective grant", () => {
  it("without a policy and without narrowing everything is granted and nothing is restricted", () => {
    const grant = computeToolGrant({ label: "reqlift" });
    expect(grant.restricts).toBe(false);
    expect(grant.restrictsBuiltIns).toBe(false);
    expect(grant.allows("Bash")).toBe(true);
    expect(grant.allows("mcp__jira__anything")).toBe(true);
    expect(grant.allowsServer("jira")).toBe(true);
    expect(grant.coversServer("jira")).toBe(true);
    expect(grant.builtIns()).toEqual(ALL_BUILT_INS);
    expect(grant.deniedBuiltIns()).toEqual([]);
  });

  it("deny removes a built-in; the rest stay", () => {
    setToolPolicy(parse({ labels: { reqlift: { deny: ["Bash", "Write"] } } }));
    const grant = computeToolGrant({ label: "reqlift" });
    expect(grant.restrictsBuiltIns).toBe(true);
    expect(grant.allows("Bash")).toBe(false);
    expect(grant.allows("Write")).toBe(false);
    expect(grant.allows("Read")).toBe(true);
    expect(grant.allows("mcp__jira__x")).toBe(true);
    expect(grant.deniedBuiltIns()).toEqual(["Bash", "Write"]);
    expect(grant.builtIns()).toEqual(ALL_BUILT_INS.filter((n) => n !== "Bash" && n !== "Write"));
    // Another label has no policy and no default: unrestricted.
    expect(computeToolGrant({ label: "diemcrm" }).restricts).toBe(false);
  });

  it("a label entry replaces the default for that label", () => {
    setToolPolicy(parse({ default: { deny: ["Bash"] }, labels: { reqlift: { deny: ["Write"] } } }));
    expect(computeToolGrant({ label: "reqlift" }).allows("Bash")).toBe(true);
    expect(computeToolGrant({ label: "reqlift" }).allows("Write")).toBe(false);
    expect(computeToolGrant({ label: "diemcrm" }).allows("Bash")).toBe(false);
    expect(computeToolGrant({ label: "diemcrm" }).allows("Write")).toBe(true);
  });

  it("allow lists exactly what is named; allow [] grants nothing; deny beats allow", () => {
    setToolPolicy(parse({ labels: { reqlift: { allow: ["Read", "mcp__jira__*", "mcp__other__a"], deny: ["mcp__jira__delete_issue"] }, diemcrm: { allow: [] } } }));
    const grant = computeToolGrant({ label: "reqlift" });
    expect(grant.builtIns()).toEqual(["Read"]);
    expect(grant.allows("mcp__jira__get_issue")).toBe(true);
    expect(grant.allows("mcp__jira__delete_issue")).toBe(false);
    expect(grant.allows("mcp__other__a")).toBe(true);
    expect(grant.allows("mcp__other__b")).toBe(false);
    expect(grant.allows("mcp__third__x")).toBe(false);
    expect(grant.allowsServer("jira")).toBe(true);
    expect(grant.allowsServer("other")).toBe(true);
    expect(grant.allowsServer("third")).toBe(false);
    // jira has a denied tool, so the whole server is not covered; other names one tool.
    expect(grant.coversServer("jira")).toBe(false);
    expect(grant.coversServer("other")).toBe(false);
    const none = computeToolGrant({ label: "diemcrm" });
    expect(none.builtIns()).toEqual([]);
    expect(none.allows("mcp__jira__get_issue")).toBe(false);
    expect(none.allowsServer("jira")).toBe(false);
  });

  it("a whole-server deny removes the server", () => {
    setToolPolicy(parse({ default: { deny: ["mcp__jira__*"] } }));
    const grant = computeToolGrant({ label: "reqlift" });
    expect(grant.allowsServer("jira")).toBe(false);
    expect(grant.allows("mcp__jira__get_issue")).toBe(false);
    expect(grant.allowsServer("other")).toBe(true);
  });

  it("the caller can only narrow: the intersection of policy and narrowing", () => {
    setToolPolicy(parse({ labels: { reqlift: { deny: ["Bash"] } } }));
    const grant = computeToolGrant({ label: "reqlift", narrowing: ["Bash", "Read", "mcp__jira__*"] });
    expect(grant.allows("Bash")).toBe(false);
    expect(grant.allows("Read")).toBe(true);
    expect(grant.allows("Write")).toBe(false);
    expect(grant.allows("mcp__jira__x")).toBe(true);
    expect(grant.allows("mcp__other__x")).toBe(false);
    expect(grant.builtIns()).toEqual(["Read"]);
    expect(grant.coversServer("jira")).toBe(true);
    expect(grant.allowsServer("other")).toBe(false);
  });

  it("an explicitly empty narrowing grants nothing, with or without a policy", () => {
    const without = computeToolGrant({ label: "reqlift", narrowing: [] });
    expect(without.restrictsBuiltIns).toBe(true);
    expect(without.builtIns()).toEqual([]);
    expect(without.deniedBuiltIns()).toEqual(ALL_BUILT_INS);
    expect(without.allows("mcp__jira__x")).toBe(false);
    expect(without.allowsServer("jira")).toBe(false);
    setToolPolicy(parse({ default: { deny: ["Bash"] } }));
    expect(computeToolGrant({ label: "reqlift", narrowing: [] }).builtIns()).toEqual([]);
  });

  it("an omitted narrowing uses the policy grant", () => {
    setToolPolicy(parse({ default: { allow: ["Read", "Glob"] } }));
    expect(computeToolGrant({ label: "reqlift" }).builtIns()).toEqual(["Glob", "Read"]);
  });

  it("a narrowing that names an unknown tool grants nothing for it (an unknown name never widens)", () => {
    const grant = computeToolGrant({ label: "reqlift", narrowing: ["Bash(git *)", "NoSuchTool"] });
    expect(grant.builtIns()).toEqual([]);
    expect(grant.allows("NoSuchTool")).toBe(true);
    expect(grant.allows("Bash")).toBe(false);
  });

  it("the webhook tools are tools of the reserved server", () => {
    setToolPolicy(parse({ default: { allow: ["mcp__agent-gateway-tools__probe_read"] } }));
    const grant = computeToolGrant({ label: "reqlift" });
    expect(grant.allows("mcp__agent-gateway-tools__probe_read")).toBe(true);
    expect(grant.allows("mcp__agent-gateway-tools__probe_write")).toBe(false);
    expect(grant.allowsServer("agent-gateway-tools")).toBe(true);
  });
});

describe("the startup line per label", () => {
  it("names the effective built-ins and server patterns of every label, never a value", () => {
    const lines: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...args) => {
      lines.push(args.map(String).join(" "));
    });
    loadToolPolicy({ AGENT_TOOL_POLICY: JSON.stringify({ labels: { reqlift: { deny: ["Bash", "mcp__jira__delete_issue"] }, diemcrm: { allow: ["Read", "mcp__jira__*"] } } }) }, LABELS);
    const policyLines = lines.filter((l) => l.includes("tool.policy label="));
    expect(policyLines).toEqual([
      "[audit] tool.policy label=reqlift builtIns=Agent,AskUserQuestion,Edit,EnterPlanMode,ExitPlanMode,Glob,Grep,KillShell,LSP,NotebookEdit,Read,Skill,Task,TaskCreate,TaskGet,TaskList,TaskOutput,TaskUpdate,TodoWrite,WebFetch,WebSearch,Write servers=all deny=mcp__jira__delete_issue",
      "[audit] tool.policy label=diemcrm builtIns=Read servers=mcp__jira__*",
    ]);
  });

  it("an unset policy writes no line", () => {
    const lines: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...args) => {
      lines.push(args.map(String).join(" "));
    });
    loadToolPolicy({}, LABELS);
    expect(lines.filter((l) => l.includes("tool.policy"))).toEqual([]);
  });
});

describe("labels are own properties only", () => {
  it.each(["constructor", "toString", "hasOwnProperty", "__proto__"])("the label %s without its own entry gets the default, never an inherited object", (label) => {
    setToolPolicy(parse({ default: { deny: ["Bash"] } }));
    const grant = computeToolGrant({ label });
    expect(grant.allows("Bash")).toBe(false);
    expect(grant.allows("Read")).toBe(true);
  });

  it("a label named __proto__ with its own entry gets that entry and does not change the prototype of the label map", () => {
    const policy = parseToolPolicy(JSON.stringify({ default: { deny: ["Bash"] }, labels: JSON.parse('{"__proto__": {"allow": ["Read"]}}') }), ["__proto__"]);
    setToolPolicy(policy);
    expect(computeToolGrant({ label: "__proto__" }).builtIns()).toEqual(["Read"]);
    expect(computeToolGrant({ label: "other" }).allows("Bash")).toBe(false);
    expect(({} as Record<string, unknown>).allow).toBeUndefined();
  });
});

describe("explicitlyAllowsServer", () => {
  it("is true only when the policy's allow list names the server", () => {
    setToolPolicy(parse({ labels: { reqlift: { allow: ["Read", "mcp__chrome-devtools__*"] }, diemcrm: { deny: ["Bash"] } } }));
    expect(computeToolGrant({ label: "reqlift" }).explicitlyAllowsServer("chrome-devtools")).toBe(true);
    expect(computeToolGrant({ label: "reqlift" }).explicitlyAllowsServer("other")).toBe(false);
    expect(computeToolGrant({ label: "diemcrm" }).explicitlyAllowsServer("chrome-devtools")).toBe(false);
    expect(computeToolGrant({ label: "nobody" }).explicitlyAllowsServer("chrome-devtools")).toBe(false);
  });

  it("a caller narrowing that excludes the server turns it off", () => {
    setToolPolicy(parse({ default: { allow: ["mcp__chrome-devtools__*"] } }));
    expect(computeToolGrant({ label: "reqlift", narrowing: ["mcp__other__*"] }).explicitlyAllowsServer("chrome-devtools")).toBe(false);
    expect(computeToolGrant({ label: "reqlift", narrowing: ["mcp__chrome-devtools__*"] }).explicitlyAllowsServer("chrome-devtools")).toBe(true);
  });
});
