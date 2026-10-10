/**
 * Trusted mediation of tool calls (MVP-7679).
 *
 * Every credential-bearing tool call leaves the agent sandbox through a trusted channel (the in-process webhook
 * server, or a relay binding), and the identity is bound by that channel, never by a field the agent sends.
 * `ToolRequest` and `ToolReply` are the internal contract of the Story's Specification; one mapper turns every
 * failure into a `ToolReply` error with a fixed text and one renderer writes it into the existing public shapes
 * (an MCP `isError` result or a JSON-RPC error). No new client-facing envelope exists.
 *
 * The texts carry no upstream body, header, URL or secret. `<name>` is a server name or webhook tool name
 * (both are validated name patterns).
 */

import path from "node:path";
import { getEnabledMcpServers } from "./mcp-registry.js";
import { knownSecretValues, sshPrivateKeyValues, webhookUrlValues } from "./sandbox-content.js";
import { getAllTools } from "./tools.js";
import { getWorkspaceRoot } from "./workspace.js";

export type ToolErrorCode = "TOOL_DENIED" | "TOOL_AUTH_UNAVAILABLE" | "TOOL_UNAVAILABLE" | "TOOL_TIMEOUT" | "TOOL_RESPONSE_INVALID";

export interface ToolRequest {
  /** The run the channel is bound to (the relay token or the webhook server closure). */
  runId: string;
  /** Correlation id: the JSON-RPC id or the tool-use id. */
  callId: string;
  /** The tool name inside the run's grant. */
  toolId: string;
  input: Record<string, unknown>;
}

export type ToolReply =
  | { callId: string; ok: true; output: unknown }
  | { callId: string; ok: false; error: { code: ToolErrorCode; message: string } };

/** The situations of the failure table, each with one fixed text. */
export type ToolFailure =
  | { kind: "denied" }
  | { kind: "no_credential"; name: string }
  | { kind: "user_credential_refused"; name: string }
  | { kind: "gateway_credential_refused"; name: string }
  | { kind: "unreachable"; name: string }
  | { kind: "redirect"; name: string }
  | { kind: "timeout"; name: string; timeoutMs: number }
  | { kind: "invalid_response"; name: string };

export function toolFailureReply(callId: string, failure: ToolFailure): ToolReply {
  const { code, message } = describeFailure(failure);
  return { callId, ok: false, error: { code, message } };
}

export function describeFailure(failure: ToolFailure): { code: ToolErrorCode; message: string } {
  switch (failure.kind) {
    case "denied":
      return { code: "TOOL_DENIED", message: "TOOL_DENIED: This tool is not allowed for this request. Do not retry; continue without it or tell the user." };
    case "no_credential":
      return {
        code: "TOOL_AUTH_UNAVAILABLE",
        message: `TOOL_AUTH_UNAVAILABLE: No credential for "${failure.name}" was provided with this request. Ask the user to connect their account; retrying will not help.`,
      };
    case "user_credential_refused":
      return {
        code: "TOOL_AUTH_UNAVAILABLE",
        message: `TOOL_AUTH_UNAVAILABLE: "${failure.name}" did not accept the user's credential. Ask the user to reconnect their account; retrying will not help.`,
      };
    case "gateway_credential_refused":
      return {
        code: "TOOL_AUTH_UNAVAILABLE",
        message: `TOOL_AUTH_UNAVAILABLE: "${failure.name}" did not accept the gateway's credential. Ask your gateway administrator to check this tool's credential; retrying will not help.`,
      };
    case "unreachable":
      return {
        code: "TOOL_UNAVAILABLE",
        message: `TOOL_UNAVAILABLE: "${failure.name}" could not be reached or failed. Try again later; if it keeps happening, tell your gateway administrator.`,
      };
    case "redirect":
      return {
        code: "TOOL_UNAVAILABLE",
        message: `TOOL_UNAVAILABLE: "${failure.name}" tried to send the request to another address, which the gateway does not allow. Tell your gateway administrator; retrying will not help.`,
      };
    case "timeout": {
      const seconds = Math.max(1, Math.ceil(failure.timeoutMs / 1000));
      return {
        code: "TOOL_TIMEOUT",
        message: `TOOL_TIMEOUT: "${failure.name}" did not answer within ${seconds} seconds. Try again later or with a smaller request; if it keeps happening, tell your gateway administrator.`,
      };
    }
    case "invalid_response":
      return {
        code: "TOOL_RESPONSE_INVALID",
        message: `TOOL_RESPONSE_INVALID: "${failure.name}" sent an answer the gateway could not read. If it keeps happening, tell your gateway administrator.`,
      };
  }
}

/** The MCP `tools/call` result of a failed call: `isError` with the fixed text. */
export function renderMcpError(reply: Extract<ToolReply, { ok: false }>): { isError: true; content: { type: "text"; text: string }[] } {
  return { isError: true, content: [{ type: "text", text: reply.error.message }] };
}

/** The MCP `tools/call` result of one failure situation. */
export function mcpFailureResult(failure: ToolFailure): { isError: true; content: { type: "text"; text: string }[] } {
  return { isError: true, content: [{ type: "text", text: describeFailure(failure).message }] };
}

/* ------------------------------------------------------------------ */
/*  Webhook tool errors that are the tool's own answer                  */
/* ------------------------------------------------------------------ */

const TOOL_MESSAGE_MAX = 500;

/** Control characters replaced by one space and the ends trimmed: the form of a message the model is shown. */
function cleanedMessage(text: string): string {
  // eslint-disable-next-line no-control-regex
  return text.replace(/[\u0000-\u001f\u007f]+/g, " ").trim();
}

/**
 * The forms of each known value that can appear in a refusal message once it is cleaned: the value itself, its
 * JSON-escaped form (a text/plain body may echo a value with `\"`, `\\` or `\n` escapes) and both forms with control
 * characters turned into a space (a multi-line value, such as a private key, reads that way after cleaning). Values under
 * the masking minimum stay unmasked.
 */
function refusalMaskingForms(secrets: readonly string[]): string[] {
  const forms: string[] = [];
  for (const secret of secrets) {
    if (secret.length < MIN_MASKED_LENGTH) continue;
    const escaped = JSON.stringify(secret).slice(1, -1);
    forms.push(secret, escaped, cleanedMessage(secret), cleanedMessage(escaped));
  }
  return forms;
}

/**
 * The model-facing text of a webhook 4xx answer that is the tool's own refusal (not 401/403/408/429): in this
 * order `error.message`, a string `error`, `message` of a JSON body, else a text/plain body; at most 500
 * characters with control characters removed and every known secret value masked, also a multi-line or JSON-escaped one.
 * Masking covers the whole message in one pass over all values (`maskSecrets`) before the cut to 500 characters: the masked text can
 * be far shorter than the message, so a cut first could neither be sized safely nor keep the result identical.
 */
export function webhookRejectionText(status: number, contentType: string | null, body: string, secrets: readonly string[]): string {
  let message = "";
  let parsed: unknown;
  let isJson = false;
  try {
    parsed = JSON.parse(body);
    isJson = typeof parsed === "object" && parsed !== null;
  } catch {
    isJson = false;
  }
  if (isJson) {
    const object = parsed as { error?: unknown; message?: unknown };
    if (typeof object.error === "object" && object.error !== null && typeof (object.error as { message?: unknown }).message === "string") {
      message = (object.error as { message: string }).message;
    } else if (typeof object.error === "string") {
      message = object.error;
    } else if (typeof object.message === "string") {
      message = object.message;
    }
  } else if (contentType !== null && /^text\/plain/i.test(contentType)) {
    message = body;
  }
  message = maskSecrets(cleanedMessage(message), refusalMaskingForms(secrets)).slice(0, TOOL_MESSAGE_MAX);
  return message.length > 0 ? `The tool rejected the request (HTTP ${status}): ${message}` : `The tool rejected the request (HTTP ${status}).`;
}

/** The shortest value that is masked, and the shortest token derived from an `Authorization` style value. */
const MIN_MASKED_LENGTH = 8;

/**
 * An Aho-Corasick automaton over every value to mask, built once per call. A text character costs one hash lookup and an
 * amortized constant number of failure steps, whatever the number of values, so the masking cost does not depend on
 * how many values a caller supplies. The trie holds one node per character of the distinct values (the values are
 * bounded by the request they arrive in); `longest[node]` is the length of the longest value that ends at the node or at
 * any node on its failure chain, which is the only match that matters for a position: the shorter ones end at the same
 * position and lie inside it.
 */
class ValueAutomaton {
  readonly longest: Int32Array;
  private readonly fail: Int32Array;
  private readonly mask: number;
  private readonly slotNode: Int32Array;
  private readonly slotCode: Uint16Array;
  private readonly slotNext: Int32Array;

  constructor(values: readonly string[]) {
    let nodes = 1;
    for (const value of values) nodes += value.length;
    let slots = 16;
    while (slots < nodes * 2) slots *= 2;
    this.mask = slots - 1;
    this.slotNode = new Int32Array(slots).fill(-1);
    this.slotCode = new Uint16Array(slots);
    this.slotNext = new Int32Array(slots);
    this.longest = new Int32Array(nodes);
    this.fail = new Int32Array(nodes);
    const parent = new Int32Array(nodes);
    const code = new Uint16Array(nodes);
    const depth = new Int32Array(nodes);
    let count = 1;
    let deepest = 0;
    for (const value of values) {
      let node = 0;
      for (let i = 0; i < value.length; i++) {
        const c = value.charCodeAt(i);
        let next = this.child(node, c);
        if (next === -1) {
          next = count++;
          parent[next] = node;
          code[next] = c;
          depth[next] = i + 1;
          this.put(node, c, next);
        }
        node = next;
      }
      this.longest[node] = value.length;
      deepest = Math.max(deepest, value.length);
    }
    // Failure links in order of depth (counting sort), so a node's parent chain is complete when the node is reached.
    const start = new Int32Array(deepest + 2);
    for (let v = 1; v < count; v++) start[depth[v] + 1]++;
    for (let d = 1; d < start.length; d++) start[d] += start[d - 1];
    const order = new Int32Array(count);
    for (let v = 1; v < count; v++) order[start[depth[v]]++] = v;
    for (let k = 0; k < count - 1; k++) {
      const v = order[k];
      let state = parent[v] === 0 ? 0 : this.fail[parent[v]];
      if (parent[v] !== 0) {
        while (state !== 0 && this.child(state, code[v]) === -1) state = this.fail[state];
        const hit = this.child(state, code[v]);
        state = hit === -1 ? 0 : hit;
      }
      this.fail[v] = state;
      if (this.longest[state] > this.longest[v]) this.longest[v] = this.longest[state];
    }
  }

  private slot(node: number, c: number): number {
    return ((Math.imul(node, 0x9e3779b1) ^ Math.imul(c + 1, 0x85ebca6b)) >>> 0) & this.mask;
  }

  private child(node: number, c: number): number {
    for (let at = this.slot(node, c); this.slotNode[at] !== -1; at = (at + 1) & this.mask) {
      if (this.slotNode[at] === node && this.slotCode[at] === c) return this.slotNext[at];
    }
    return -1;
  }

  private put(node: number, c: number, next: number): void {
    let at = this.slot(node, c);
    while (this.slotNode[at] !== -1) at = (at + 1) & this.mask;
    this.slotNode[at] = node;
    this.slotCode[at] = c;
    this.slotNext[at] = next;
  }

  /** The state after `c` from `state`. */
  step(state: number, c: number): number {
    for (;;) {
      const next = this.child(state, c);
      if (next !== -1) return next;
      if (state === 0) return 0;
      state = this.fail[state];
    }
  }
}

/**
 * Replaces every known secret value (8 characters or longer) with `[REDACTED]`. Every occurrence of every value is
 * located in the unmodified text, also overlapping ones; ranges that overlap or touch are replaced as one, so no
 * fragment of a value is left behind whatever the order of `secrets` (a value that starts, ends or sits inside a longer
 * one, or two values that overlap partially). One pass over the text through an automaton of all values: the cost is
 * linear in the text length plus the total length of the values (plus the replacements), independent of how many values
 * there are; memory is linear in the same two. The values a caller supplies per request are capped at request validation
 * (`MAX_CREDENTIAL_VALUES` values, `MAX_CREDENTIAL_BYTES` bytes in `mcp-overrides.ts`), which bounds the automaton for them.
 */
export function maskSecrets(text: string, secrets: readonly string[]): string {
  const values = [...new Set(secrets)].filter((secret) => secret.length >= MIN_MASKED_LENGTH && secret.length <= text.length);
  if (values.length === 0) return text;
  const automaton = new ValueAutomaton(values);
  // The merged runs, left to right. A match is found at its end, so a longer value that ends later can start before
  // earlier runs: those runs are folded into the new one.
  const starts: number[] = [];
  const ends: number[] = [];
  let state = 0;
  for (let i = 0; i < text.length; i++) {
    state = automaton.step(state, text.charCodeAt(i));
    const length = automaton.longest[state];
    if (length === 0) continue;
    let from = i + 1 - length;
    while (ends.length > 0 && ends[ends.length - 1] >= from) {
      from = Math.min(from, starts.pop()!);
      ends.pop();
    }
    starts.push(from);
    ends.push(i + 1);
  }
  if (starts.length === 0) return text;
  let out = "";
  let copied = 0;
  for (let r = 0; r < starts.length; r++) {
    out += `${text.slice(copied, starts[r])}[REDACTED]`;
    copied = ends[r];
  }
  return `${out}${text.slice(copied)}`;
}

// `\S[^]*` rather than `.+`: after the spaces the token starts at a non-space and runs to the end, so a long run of
// spaces followed by a line break cannot make the match backtrack quadratically.
const AUTH_SCHEME_VALUE = /^(?:bearer|basic) +(\S[^]*)$/i;

/**
 * `values` and, for each one that reads `Bearer <token>` or `Basic <token>` (matched on the trimmed value, scheme in any
 * case), the token itself when it has 8 or more characters: the model can send the bare token without its scheme. Other
 * schemes are not recognized and a `Basic` blob is not decoded.
 */
function withSchemeTokens(values: readonly string[]): string[] {
  const out = [...values];
  for (const value of values) {
    const token = AUTH_SCHEME_VALUE.exec(value.trim())?.[1].trim();
    if (token !== undefined && token.length >= MIN_MASKED_LENGTH) out.push(token);
  }
  return out;
}

/**
 * The gateway's known secret values, the one list behind both the sandbox's hidden files and the masking of tool
 * refusal texts: secret-looking environment values (API keys, provider credentials), the OAuth tokens of the
 * trusted credentials file, every enabled registry server's header and env values, the private-key lines of
 * `$HOME/.ssh`, the credential parts of every registered webhook URL, and `extra` (for example the bearer
 * forwarded to the webhook). A registry or `extra` value that reads `Bearer <token>` or `Basic <token>` also
 * contributes the token (`withSchemeTokens`).
 */
export function gatewayKnownValues(workspaceRoot: string, extra: readonly string[] = []): Buffer[] {
  const registry: string[] = [];
  for (const def of getEnabledMcpServers()) {
    registry.push(...Object.values(def.headers ?? {}), ...Object.values(def.env ?? {}));
  }
  const sshDir = path.join(process.env.HOME || "/home/node", ".ssh");
  return knownSecretValues(process.env, path.join(workspaceRoot, ".credentials.json"), [
    ...withSchemeTokens(registry),
    ...sshPrivateKeyValues(sshDir),
    ...webhookUrlValues(getAllTools()),
    ...withSchemeTokens(extra),
  ]);
}

/** The values to mask in a tool's refusal message: the gateway's known values (`gatewayKnownValues`) and `extra`. */
export function secretValuesForMasking(extra: readonly string[] = []): string[] {
  return gatewayKnownValues(getWorkspaceRoot(), extra).map((value) => value.toString("utf8"));
}

/* ------------------------------------------------------------------ */
/*  Deadline of a mediated MCP tool call                                */
/* ------------------------------------------------------------------ */

/** Default overall deadline of one mediated MCP `tools/call` in an agent run (`AGENT_MCP_TOOL_TIMEOUT_MS`). */
export const DEFAULT_MCP_TOOL_TIMEOUT_MS = 600_000;
const MAX_TIMER_MS = 2_147_483_647;

export class McpToolTimeoutConfigError extends Error {
  readonly key = "AGENT_MCP_TOOL_TIMEOUT_MS";
  constructor() {
    super("AGENT_MCP_TOOL_TIMEOUT_MS: must be a positive whole number of milliseconds");
  }
  get logLine(): string {
    return `FATAL config key=${this.key} reason=must be a positive whole number of milliseconds`;
  }
}

/** The configured deadline: empty or unset is the default, anything that is not a positive whole number stops startup. */
export function mcpToolTimeoutMs(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env.AGENT_MCP_TOOL_TIMEOUT_MS;
  if (raw === undefined || raw.trim() === "") return DEFAULT_MCP_TOOL_TIMEOUT_MS;
  const text = raw.trim();
  if (!/^[1-9][0-9]*$/.test(text)) throw new McpToolTimeoutConfigError();
  const value = Number(text);
  if (!Number.isSafeInteger(value) || value > MAX_TIMER_MS) throw new McpToolTimeoutConfigError();
  return value;
}
