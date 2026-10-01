/**
 * The trusted tool grant of a run (MVP-7679).
 *
 * Effective grant = the trusted policy for the caller's API-key label (`AGENT_TOOL_POLICY`) intersected with
 * the caller's own narrowing (`enforcedTools`, an exact set, or `allowedTools`, names and `mcp__<server>__*`
 * patterns). A caller can only make a grant smaller: an omitted list uses the policy grant, an explicit empty
 * list grants nothing, and a configured agent, skill, prompt or sub-agent never adds authority.
 *
 * Built-in tools run inside the runtime, so their grant is enforced by what the runtime is offered (`tools`
 * and `disallowedTools`, pinned by the MVP-7679 Gate A spike on Claude Code 2.0.77). Mediated tools
 * (webhook and MCP) are checked again on the trusted side before any credential-bearing request.
 *
 * Policy format (one JSON object in the environment, never logged beyond tool names):
 *   { "default": { "allow": [...], "deny": [...] }, "labels": { "<label>": { "allow": [...], "deny": [...] } } }
 * A pattern is a built-in tool name, `mcp__<server>__*` or `mcp__<server>__<tool>`. Deny beats allow; an absent
 * `allow` means everything a run gets without a policy; `allow: []` means nothing; a label entry replaces `default`.
 */

import { log } from "./logging.js";

/** The built-in tools of the pinned runtime (Claude Code 2.0.77, `system/init` of the MVP-7679 Gate A spike). */
export const RUNTIME_BUILT_IN_TOOLS: readonly string[] = [
  "AskUserQuestion",
  "Bash",
  "Edit",
  "EnterPlanMode",
  "ExitPlanMode",
  "Glob",
  "Grep",
  "KillShell",
  "LSP",
  "NotebookEdit",
  "Read",
  "Skill",
  "Task",
  "TaskOutput",
  "TodoWrite",
  "WebFetch",
  "WebSearch",
  "Write",
];

export const MCP_PREFIX = "mcp__";
/** The reserved server that hosts the registered webhook tools. */
export const WEBHOOK_SERVER_NAME = "agent-gateway-tools";

export type PolicyReason =
  | "must be a JSON object"
  | "unknown field"
  | "label not in API_KEYS"
  | "unknown built-in tool name"
  | "invalid tool pattern";

export class ToolPolicyConfigError extends Error {
  readonly key = "AGENT_TOOL_POLICY";
  constructor(readonly reason: PolicyReason) {
    super(`AGENT_TOOL_POLICY: ${reason}`);
  }
  get logLine(): string {
    return `FATAL config key=${this.key} reason=${this.reason}`;
  }
}

export interface PolicyEntry {
  allow?: string[];
  deny?: string[];
}

export interface ToolPolicy {
  default?: PolicyEntry;
  labels: Record<string, PolicyEntry>;
}

/** `mcp__<server>__*` or `mcp__<server>__<tool>`; the server and tool parts are plain names. */
const MCP_PATTERN = /^mcp__[A-Za-z0-9][A-Za-z0-9_-]*__(\*|[A-Za-z0-9_][A-Za-z0-9_.-]*)$/;

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseList(value: unknown): string[] {
  if (!Array.isArray(value)) throw new ToolPolicyConfigError("invalid tool pattern");
  const out: string[] = [];
  for (const item of value) {
    if (typeof item !== "string" || item.length === 0 || item.length > 256) throw new ToolPolicyConfigError("invalid tool pattern");
    if (item.startsWith(MCP_PREFIX)) {
      if (!MCP_PATTERN.test(item)) throw new ToolPolicyConfigError("invalid tool pattern");
    } else {
      if (!/^[A-Za-z0-9_-]+$/.test(item)) throw new ToolPolicyConfigError("invalid tool pattern");
      if (!RUNTIME_BUILT_IN_TOOLS.includes(item)) throw new ToolPolicyConfigError("unknown built-in tool name");
    }
    out.push(item);
  }
  return out;
}

function parseEntry(value: unknown): PolicyEntry {
  if (!isObject(value)) throw new ToolPolicyConfigError("must be a JSON object");
  for (const key of Object.keys(value)) {
    if (key !== "allow" && key !== "deny") throw new ToolPolicyConfigError("unknown field");
  }
  const entry: PolicyEntry = {};
  if (value.allow !== undefined) entry.allow = parseList(value.allow);
  if (value.deny !== undefined) entry.deny = parseList(value.deny);
  return entry;
}

/**
 * Parses the `AGENT_TOOL_POLICY` value. An unset or blank value is no policy (`null`); anything else that is
 * not valid throws a `ToolPolicyConfigError` with one of the fixed reasons.
 */
export function parseToolPolicy(raw: string | undefined, labels: readonly string[]): ToolPolicy | null {
  if (raw === undefined || raw.trim() === "") return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new ToolPolicyConfigError("must be a JSON object");
  }
  if (!isObject(parsed)) throw new ToolPolicyConfigError("must be a JSON object");
  for (const key of Object.keys(parsed)) {
    if (key !== "default" && key !== "labels") throw new ToolPolicyConfigError("unknown field");
  }
  const policy: ToolPolicy = { labels: Object.create(null) as Record<string, PolicyEntry> };
  if (parsed.default !== undefined) policy.default = parseEntry(parsed.default);
  if (parsed.labels !== undefined) {
    if (!isObject(parsed.labels)) throw new ToolPolicyConfigError("must be a JSON object");
    for (const [label, entry] of Object.entries(parsed.labels)) {
      if (!labels.includes(label)) throw new ToolPolicyConfigError("label not in API_KEYS");
      policy.labels[label] = parseEntry(entry);
    }
  }
  return policy;
}

/* ------------------------------------------------------------------ */
/*  The configured policy                                               */
/* ------------------------------------------------------------------ */

let activePolicy: ToolPolicy | null = null;

/** Tests and startup: replaces the configured policy. */
export function setToolPolicy(policy: ToolPolicy | null): void {
  activePolicy = policy;
}

export function getToolPolicy(): ToolPolicy | null {
  return activePolicy;
}

/** The policy entry that applies to `label`: its own entry, else `default`, else none. */
export function policyEntryFor(label: string): PolicyEntry | undefined {
  if (!activePolicy) return undefined;
  // An own property only: a label such as `constructor` must not resolve to an inherited object.
  return (Object.hasOwn(activePolicy.labels, label) ? activePolicy.labels[label] : undefined) ?? activePolicy.default;
}

/** Startup: parses the environment value (throws `ToolPolicyConfigError`) and logs one line per label. */
export function loadToolPolicy(env: NodeJS.ProcessEnv, labels: readonly string[]): void {
  activePolicy = parseToolPolicy(env.AGENT_TOOL_POLICY, labels);
  if (!activePolicy) return;
  for (const label of labels) {
    const grant = computeToolGrant({ label });
    const builtIns = grant.restrictsBuiltIns ? grant.builtIns().join(",") || "none" : "all";
    log("audit", `tool.policy label=${label} builtIns=${builtIns} servers=${describeServers(policyEntryFor(label))}`);
  }
}

function describeServers(entry: PolicyEntry | undefined): string {
  const patterns = (entry?.allow ?? []).filter((p) => p.startsWith(MCP_PREFIX));
  const denied = (entry?.deny ?? []).filter((p) => p.startsWith(MCP_PREFIX));
  const allowText = entry?.allow === undefined ? "all" : patterns.join(",") || "none";
  return denied.length > 0 ? `${allowText} deny=${denied.join(",")}` : allowText;
}

/* ------------------------------------------------------------------ */
/*  Matching                                                            */
/* ------------------------------------------------------------------ */

function matches(pattern: string, name: string): boolean {
  return pattern.endsWith("__*") ? name.startsWith(pattern.slice(0, -1)) : pattern === name;
}

function matchesAny(list: readonly string[], name: string): boolean {
  return list.some((pattern) => matches(pattern, name));
}

/** Whether `pattern` names the tools of MCP server `server` (the whole server or one of its tools). */
function namesServer(pattern: string, server: string): boolean {
  const prefix = `${MCP_PREFIX}${server}__`;
  return pattern.startsWith(prefix) && pattern.length > prefix.length;
}

export function mcpToolName(server: string, tool: string): string {
  return `${MCP_PREFIX}${server}__${tool}`;
}

/* ------------------------------------------------------------------ */
/*  The effective grant                                                 */
/* ------------------------------------------------------------------ */

export interface GrantRequest {
  /** The caller's API-key label. */
  label: string;
  /** The caller's narrowing: `enforcedTools` (exact names) or `allowedTools` (names and `mcp__<server>__*`). */
  narrowing?: readonly string[];
}

export class ToolGrant {
  constructor(
    private readonly policy: PolicyEntry | undefined,
    private readonly narrowing: readonly string[] | undefined,
  ) {}

  /** Whether tool `name` (a built-in name or `mcp__<server>__<tool>`) is granted. */
  allows(name: string): boolean {
    if (this.policy) {
      if (this.policy.deny && matchesAny(this.policy.deny, name)) return false;
      if (this.policy.allow && !matchesAny(this.policy.allow, name)) return false;
    }
    return this.narrowing === undefined || matchesAny(this.narrowing, name);
  }

  /** Whether at least one tool of MCP server `server` can be granted: the server is worth attaching. */
  allowsServer(server: string): boolean {
    if (this.policy) {
      if (this.policy.deny?.some((p) => p === `${MCP_PREFIX}${server}__*`)) return false;
      if (this.policy.allow && !this.policy.allow.some((p) => namesServer(p, server))) return false;
    }
    return this.narrowing === undefined || this.narrowing.some((p) => namesServer(p, server));
  }

  /**
   * Whether the trusted policy NAMES `server` in its `allow` list (a pattern for the whole server or one of its tools),
   * and the caller's own narrowing does not exclude it. A policy without an `allow` list names nothing.
   */
  explicitlyAllowsServer(server: string): boolean {
    if (!this.policy?.allow?.some((p) => namesServer(p, server))) return false;
    return this.allowsServer(server);
  }

  /** Whether every tool of `server` is granted (so a method outside `tools/call` may be forwarded too). */
  coversServer(server: string): boolean {
    const whole = `${MCP_PREFIX}${server}__*`;
    if (this.policy) {
      if (this.policy.deny?.some((p) => namesServer(p, server))) return false;
      if (this.policy.allow && !this.policy.allow.includes(whole)) return false;
    }
    return this.narrowing === undefined || this.narrowing.includes(whole);
  }

  /** True when the policy or the caller restricts the built-in tools, so the runtime is given an explicit list. */
  get restrictsBuiltIns(): boolean {
    return this.narrowing !== undefined || this.policy?.allow !== undefined || (this.policy?.deny?.some((p) => !p.startsWith(MCP_PREFIX)) ?? false);
  }

  /** True when anything restricts this run's tools (built-ins, servers or webhook tools). */
  get restricts(): boolean {
    return this.narrowing !== undefined || this.policy?.allow !== undefined || (this.policy?.deny?.length ?? 0) > 0;
  }

  /** The built-in tools the run may use. */
  builtIns(): string[] {
    return RUNTIME_BUILT_IN_TOOLS.filter((name) => this.allows(name));
  }

  /** The built-in tools the run may not use. */
  deniedBuiltIns(): string[] {
    return RUNTIME_BUILT_IN_TOOLS.filter((name) => !this.allows(name));
  }
}

export function computeToolGrant(request: GrantRequest): ToolGrant {
  return new ToolGrant(policyEntryFor(request.label), request.narrowing);
}
