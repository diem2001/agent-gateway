/**
 * Per-run enforced tool set (MVP-7637).
 *
 * A caller may send `enforcedTools: string[]` with `POST /v1/query`: the exact
 * tools the run may call, as the SDK names them (built-ins such as `Bash`, MCP
 * tools as `mcp__<server>__<tool>`; the gateway's webhook tools are served by
 * the `agent-gateway-tools` server). Every other tool is refused before it
 * runs. The field is additive: without it a run's options are exactly what
 * they were before, and the existing `allowedTools` keeps its meaning.
 *
 * `agent.ts` enforces the set in layers, because each alone has a gap on the
 * pinned SDK (0.1.77):
 *   1. `settingSources: []` — no user/project settings, hooks, permission
 *      rules, `.mcp.json` or user-scope `mcpServers` from the (writable) HOME.
 *   2. `permissionMode: "dontAsk"` + `allowedTools` = exactly the set: an
 *      unlisted tool is denied, not asked for (the primary deny).
 *   3. `tools` = the built-ins in the set (`[]` for none), so other built-ins
 *      are not even offered.
 *   4. `agent-gateway-tools` holds only the registered tools in the set, and a
 *      registry or request MCP server is attached only when the set names one
 *      of its tools.
 *   5. A `PreToolUse` hook ([`createToolPolicyHook`]) that denies every name
 *      outside the set and logs `tool.denied`. It never answers "allow" — under
 *      `dontAsk` an allow overrides the mode — and any internal error denies.
 *   6. No per-user skill plugin bundle.
 * Before any other event the query route emits `{"type":"tool_policy",
 * "enforced":true,"tools":[…]}`, so the caller can confirm this gateway
 * enforced its set.
 */

import type { HookCallback } from "@anthropic-ai/claude-agent-sdk";
import { log } from "./logging.js";
import { describeFailure } from "./tool-mediation.js";

/** The tool_result text of a refused call: the one TOOL_DENIED text of every surface (MVP-7679, tool-mediation.ts). */
export const TOOL_DENIED_REASON = describeFailure({ kind: "denied" }).message;

export const MAX_ENFORCED_TOOLS = 64;
export const MAX_TOOL_NAME_LENGTH = 128;
const TOOL_NAME = /^[A-Za-z0-9_-]+$/;
/** Sub-agent tools: whether a sub-agent inherits the set is not proven. */
const REJECTED_TOOLS = new Set(["Task", "Agent"]);
const MCP_PREFIX = "mcp__";

export interface EnforcedToolsValidation {
  /** Set when the value is malformed (→ HTTP 400). */
  error?: string;
  /** The validated set; `undefined` when the field was absent. */
  tools?: string[];
}

/**
 * Validate the request's `enforcedTools`. `serverNames` are every MCP server a
 * run could attach (the webhook tool server, enabled registry servers, the
 * request's own servers): an `mcp__…` name that fits more than one of them
 * (registry names may contain `__`) is refused as ambiguous.
 */
export function validateEnforcedTools(
  value: unknown,
  allowedTools: unknown,
  serverNames: readonly string[],
): EnforcedToolsValidation {
  if (value === undefined) return {};
  if (!Array.isArray(value)) return { error: "enforcedTools must be an array of tool names" };
  if (allowedTools !== undefined) return { error: "enforcedTools cannot be combined with allowedTools" };
  if (value.length > MAX_ENFORCED_TOOLS) return { error: `enforcedTools may name at most ${MAX_ENFORCED_TOOLS} tools` };
  const seen = new Set<string>();
  for (const [index, name] of value.entries()) {
    if (typeof name !== "string" || name.length === 0 || name.length > MAX_TOOL_NAME_LENGTH || !TOOL_NAME.test(name)) {
      return { error: `enforcedTools[${index}] must be 1-${MAX_TOOL_NAME_LENGTH} characters of A-Z, a-z, 0-9, _ or -` };
    }
    if (seen.has(name)) return { error: `enforcedTools[${index}] repeats a tool name` };
    if (REJECTED_TOOLS.has(name)) return { error: `enforcedTools[${index}] names a sub-agent tool, which cannot be enforced` };
    if (name.startsWith(MCP_PREFIX) && serversOfTool(name, serverNames).length > 1) {
      return { error: `enforcedTools[${index}] matches more than one MCP server` };
    }
    seen.add(name);
  }
  return { tools: value as string[] };
}

/** The servers `name` (`mcp__<server>__<tool>`) can belong to. */
function serversOfTool(name: string, serverNames: readonly string[]): string[] {
  return serverNames.filter((server) => {
    const prefix = `${MCP_PREFIX}${server}__`;
    return name.startsWith(prefix) && name.length > prefix.length;
  });
}

/** The built-in tools in the set (every name without the `mcp__` prefix). */
export function builtInTools(enforced: readonly string[]): string[] {
  return enforced.filter((name) => !name.startsWith(MCP_PREFIX));
}

/** Whether the set names at least one tool of MCP server `server`. */
export function namesServer(enforced: readonly string[], server: string): boolean {
  return enforced.some((name) => serversOfTool(name, [server]).length > 0);
}

/** A tool name as it may appear in a log line; model-supplied text never reaches it unbounded. */
function loggableToolName(name: unknown): string {
  return typeof name === "string" && name.length > 0 && name.length <= MAX_TOOL_NAME_LENGTH && /^[A-Za-z0-9_:.-]+$/.test(name)
    ? name
    : "(unrecognized)";
}

const DENY = {
  hookSpecificOutput: {
    hookEventName: "PreToolUse" as const,
    permissionDecision: "deny" as const,
    permissionDecisionReason: TOOL_DENIED_REASON,
  },
};

/**
 * The `PreToolUse` hook of an enforced run: no decision (`{}`) for a name in
 * the set, a deny with [`TOOL_DENIED_REASON`] for every other name. It never
 * returns "allow", and an internal error denies.
 */
export function createToolPolicyHook(enforced: readonly string[], queryId?: string): HookCallback {
  const allowed = new Set(enforced);
  return async (input) => {
    try {
      const name = (input as { tool_name?: unknown }).tool_name;
      if (typeof name === "string" && allowed.has(name)) return {};
      log("audit", `tool.denied toolName=${loggableToolName(name)} queryId=${queryId ?? "none"}`);
    } catch {
      // Fall through: an error never lets a call through.
    }
    return DENY;
  };
}
