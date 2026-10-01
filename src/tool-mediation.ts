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
import { knownSecretValues } from "./sandbox-content.js";
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

/**
 * The model-facing text of a webhook 4xx answer that is the tool's own refusal (not 401/403/408/429): in this
 * order `error.message`, a string `error`, `message` of a JSON body, else a text/plain body; at most 500
 * characters with control characters removed and every known secret value masked.
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
  // eslint-disable-next-line no-control-regex
  message = maskSecrets(message.replace(/[\u0000-\u001f\u007f]+/g, " ").trim(), secrets).slice(0, TOOL_MESSAGE_MAX);
  return message.length > 0 ? `The tool rejected the request (HTTP ${status}): ${message}` : `The tool rejected the request (HTTP ${status}).`;
}

/** Replaces every known secret value (8 characters or longer) with `[REDACTED]`. */
export function maskSecrets(text: string, secrets: readonly string[]): string {
  let out = text;
  for (const secret of secrets) {
    if (secret.length >= 8) out = out.split(secret).join("[REDACTED]");
  }
  return out;
}

/**
 * The values to mask in a tool's refusal message: the gateway's own secrets (S1's known-value list: API keys,
 * provider credentials, OAuth tokens), every enabled registry server's header and env values, and `extra`
 * (for example the bearer forwarded to the webhook).
 */
export function secretValuesForMasking(extra: readonly string[] = []): string[] {
  const registry: string[] = [];
  for (const def of getEnabledMcpServers()) {
    registry.push(...Object.values(def.headers ?? {}), ...Object.values(def.env ?? {}));
  }
  const known = knownSecretValues(process.env, path.join(getWorkspaceRoot(), ".credentials.json"), [...registry, ...extra]);
  return known.map((value) => value.toString("utf8"));
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
