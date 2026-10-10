import { log } from "./logging.js";
import { isMaskingOverBudget, maskSecrets, type MaskingValues } from "./tool-mediation.js";
import { WEBHOOK_SERVER_NAME, mcpToolName } from "./tool-grant.js";
import { toolInputValidator } from "./tool-server.js";
import type { ToolDefinition } from "./tools.js";

/* ------------------------------------------------------------------ */
/*  The structured input of a `raw` webhook tool on the tool_use event  */
/* ------------------------------------------------------------------ */
//
// A tool registered with `stream_input: "raw"` streams the object its webhook receives instead of the text summary
// (MVP-8096), within bounds: the call passes the tool's input schema, nests at most MAX_INPUT_DEPTH levels (the
// top-level object is level 1), serializes to at most MAX_INPUT_BYTES UTF-8 bytes, holds no U+0000 or lone surrogate
// (the consumer stores the object as JSON text in a database), and holds no known secret value. Otherwise the event
// carries the summary string, with known secret values masked. The table below only ever holds tools that the run
// was offered, that its own label registered, and that the gateway's own webhook server serves.

/** The size limit of a streamed input: the compact JSON serialization in UTF-8 bytes (not characters). */
export const MAX_INPUT_BYTES = 16384;
/** The nesting limit of a streamed input; the top-level object is level 1. */
export const MAX_INPUT_DEPTH = 32;
/** The summary length of every tool, as `formatToolInput` cuts it. */
const SUMMARY_MAX = 1000;
const UNAVAILABLE = "[input unavailable]";
/** The summary of an input when the run's known values are over the masking budget and so cannot be masked. */
const WITHHELD = "[input withheld]";
const RAW_TOOL_NAME = /^[A-Za-z0-9_-]{1,64}$/;
const MIN_NEEDLE = 8;
/** U+0000, a high surrogate without its low one, or a low surrogate without its high one (code units, no `u` flag). */
const UNSTORABLE_TEXT = /\u0000|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

export type WithholdReason = "schema" | "depth" | "encoding" | "size" | "secret";

interface RawTool {
  /** The registered (short) name, for the log line. */
  name: string;
  validator: ReturnType<typeof toolInputValidator>;
}

export interface StreamInputTable {
  /** Full MCP tool names (`mcp__agent-gateway-tools__<name>`) of the tools that may stream their object. */
  tools: ReadonlyMap<string, RawTool>;
  /** The known secret values (computed once, on the first raw-eligible call), or `MASKING_OVER_BUDGET`. */
  needles: () => MaskingValues;
}

export interface StreamInputTableOptions {
  /** The run's registered tools, already filtered to its own label and its grant. */
  registeredTools: readonly ToolDefinition[];
  callerLabel: string;
  /** The final `mcpServers` map of the run, and the webhook server config this run created (undefined = none). */
  mcpServers: Readonly<Record<string, unknown>>;
  webhookServer: unknown;
  /** Lazy list of known secret values (any length; short ones are ignored), or `MASKING_OVER_BUDGET`. */
  secretValues: () => MaskingValues;
}

/** How the runtime names a server in a tool name: characters outside `[A-Za-z0-9_-]` become `_`. */
function normalizedServerName(name: string): string {
  return name.replace(/[^A-Za-z0-9_-]/g, "_");
}

export const EMPTY_STREAM_INPUT_TABLE: StreamInputTable = { tools: new Map(), needles: () => [] };

/**
 * The table of one run, built after `mcpServers` is final from a snapshot of the definitions, so a PUT during the
 * run changes nothing for it. Empty unless the gateway's own webhook server is the one attached under its name.
 */
export function buildStreamInputTable(options: StreamInputTableOptions): StreamInputTable {
  const { registeredTools, callerLabel, mcpServers, webhookServer, secretValues } = options;
  if (webhookServer === undefined || mcpServers[WEBHOOK_SERVER_NAME] !== webhookServer) return EMPTY_STREAM_INPUT_TABLE;
  const otherPrefixes = Object.keys(mcpServers)
    .filter((server) => server !== WEBHOOK_SERVER_NAME)
    .map((server) => mcpToolName(normalizedServerName(server), ""));
  const tools = new Map<string, RawTool>();
  for (const def of registeredTools) {
    if (def.stream_input !== "raw") continue;
    // An ownerless (legacy) entry is never raw, whatever it stores.
    if (def.owner === undefined || def.owner !== callerLabel) continue;
    if (!RAW_TOOL_NAME.test(def.name)) continue;
    const fullName = mcpToolName(WEBHOOK_SERVER_NAME, def.name);
    // Another attached server whose name makes this tool name ambiguous: the event cannot be attributed.
    if (otherPrefixes.some((prefix) => fullName.startsWith(prefix))) continue;
    tools.set(fullName, { name: def.name, validator: toolInputValidator(def) });
  }
  if (tools.size === 0) return EMPTY_STREAM_INPUT_TABLE;
  let needles: MaskingValues | undefined;
  return {
    tools,
    needles: () => {
      if (needles !== undefined) return needles;
      const values = secretValues();
      needles = isMaskingOverBudget(values) ? values : values.filter((value) => value.length >= MIN_NEEDLE);
      return needles;
    },
  };
}

/* ------------------------------------------------------------------ */
/*  Decision                                                            */
/* ------------------------------------------------------------------ */

type Json = unknown;

/** Nesting depth (top level = 1) and whether every key and string value is storable text, own keys only. */
function inspect(root: Json): { depth: number; wellFormed: boolean } {
  let depth = 0;
  let wellFormed = true;
  const stack: [Json, number][] = [[root, 1]];
  while (stack.length > 0) {
    const [value, level] = stack.pop()!;
    if (typeof value === "string") {
      if (UNSTORABLE_TEXT.test(value)) wellFormed = false;
      continue;
    }
    if (typeof value !== "object" || value === null) continue;
    if (level > depth) depth = level;
    if (depth > MAX_INPUT_DEPTH) return { depth, wellFormed };
    if (Array.isArray(value)) {
      for (const item of value) stack.push([item, level + 1]);
      continue;
    }
    for (const key of Object.keys(value)) {
      if (UNSTORABLE_TEXT.test(key)) wellFormed = false;
      stack.push([(value as Record<string, Json>)[key], level + 1]);
    }
  }
  return { depth, wellFormed };
}

/** Every key and string value, decoded, for the secret check. */
function* strings(root: Json): Generator<string> {
  const stack: Json[] = [root];
  while (stack.length > 0) {
    const value = stack.pop();
    if (typeof value === "string") yield value;
    else if (Array.isArray(value)) stack.push(...value);
    else if (typeof value === "object" && value !== null) {
      for (const key of Object.keys(value)) {
        yield key;
        stack.push((value as Record<string, Json>)[key]);
      }
    }
  }
}

/** A needle as it appears inside a JSON string literal. */
function jsonEscaped(needle: string): string {
  return JSON.stringify(needle).slice(1, -1);
}

function carriesSecret(needles: MaskingValues, data: Json, serialized: string): boolean {
  // Over the masking budget nothing can be checked, so the input counts as carrying a secret.
  if (isMaskingOverBudget(needles)) return true;
  if (needles.length === 0) return false;
  const escaped = needles.map(jsonEscaped);
  if (needles.some((needle, i) => serialized.includes(needle) || serialized.includes(escaped[i]))) return true;
  for (const text of strings(data)) {
    if (needles.some((needle) => text.includes(needle))) return true;
  }
  return false;
}

/** Today's summary of a raw-registered tool's input, with every known secret value masked before the cut. */
function maskedSummary(input: unknown, needles: MaskingValues): string {
  if (input === undefined) return "";
  if (isMaskingOverBudget(needles)) return WITHHELD;
  try {
    const text = maskSecrets(JSON.stringify(input, null, 2) ?? "", needles.flatMap((needle) => [needle, jsonEscaped(needle)]));
    return text.substring(0, SUMMARY_MAX);
  } catch {
    // V8 throws a RangeError on very deep input.
    return UNAVAILABLE;
  }
}

function logWithheld(tool: RawTool, toolUseId: string, reason: WithholdReason, bytes: number): void {
  log("audit", `tool.stream_input.withheld toolName=${JSON.stringify(tool.name)} toolUseId=${JSON.stringify(String(toolUseId).slice(0, 128))} reason=${reason} bytes=${bytes}`);
}

/**
 * The `input` of a `tool_use` event. A tool outside the table gets what `summarize` (today's builder) returns; a table
 * tool gets its structured object when every bound holds, else the masked summary string.
 */
export function streamedToolInput(
  toolName: string,
  input: Record<string, unknown> | undefined,
  toolUseId: string,
  table: StreamInputTable,
  summarize: (toolName: string, input: Record<string, unknown> | undefined) => unknown,
): unknown {
  const tool = table.tools.get(toolName);
  if (!tool) return summarize(toolName, input);
  const withheld = (reason: WithholdReason, bytes: number): string => {
    logWithheld(tool, toolUseId, reason, bytes);
    return maskedSummary(input, table.needles());
  };

  let parsed: ReturnType<typeof tool.validator.safeParse>;
  try {
    parsed = tool.validator.safeParse(input);
  } catch {
    return withheld("schema", -1);
  }
  if (!parsed.success) return withheld("schema", -1);
  const data = parsed.data;

  const shape = inspect(data);
  if (shape.depth > MAX_INPUT_DEPTH) return withheld("depth", -1);
  if (!shape.wellFormed) return withheld("encoding", -1);

  let serialized: string;
  try {
    serialized = JSON.stringify(data);
  } catch {
    return withheld("depth", -1);
  }
  const bytes = Buffer.byteLength(serialized, "utf8");
  if (bytes > MAX_INPUT_BYTES) return withheld("size", bytes);
  if (carriesSecret(table.needles(), data, serialized)) return withheld("secret", bytes);
  // Measured and returned are the same text: a decoupled copy, never the live object.
  return JSON.parse(serialized);
}
