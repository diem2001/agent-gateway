import type { ToolDefinition } from "./tools.js";
import { describeFailure, isMaskingOverBudget, webhookRejectionText, type MaskingValues, type ToolErrorCode } from "./tool-mediation.js";

/* ------------------------------------------------------------------ */
/*  Types                                                               */
/* ------------------------------------------------------------------ */

export interface WebhookContext {
  user_id?: string;
  conversation_id?: string;
  session_id?: string;
  api_key_label?: string;
}

export interface WebhookRequest {
  tool_use_id: string;
  tool_name: string;
  input: Record<string, unknown>;
  context: WebhookContext;
}

export interface WebhookResponse {
  output: string;
  metadata?: Record<string, unknown>;
}

export interface WebhookError {
  output: string;
  isError: true;
  /** Set when the gateway's own mediation failed (not when the tool answered with its own refusal). */
  code?: ToolErrorCode;
}

/** An answer larger than this is refused as unreadable. */
export const WEBHOOK_MAX_RESPONSE_BYTES = 8 * 1024 * 1024;

/* ------------------------------------------------------------------ */
/*  Executor                                                            */
/* ------------------------------------------------------------------ */

function failure(failureInfo: Parameters<typeof describeFailure>[0]): WebhookError {
  const { code, message } = describeFailure(failureInfo);
  return { output: message, isError: true, code };
}

/** Reads a response body up to the size cap; null when it is larger. */
async function readCapped(response: Response): Promise<string | null> {
  const reader = response.body?.getReader();
  if (!reader) return "";
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > WEBHOOK_MAX_RESPONSE_BYTES) {
      await reader.cancel().catch(() => undefined);
      return null;
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

/**
 * Calls a registered webhook tool. Never follows a redirect (the credential must not leave the registered
 * origin), never echoes an upstream body except the bounded, masked message of the tool's own 4xx refusal, and
 * maps every other failure to one of the fixed texts of tool-mediation.ts. `secrets` are the known secret values
 * masked out of a refusal message; over the masking budget (`MASKING_OVER_BUDGET`) the refusal is replaced by a fixed text.
 */
export async function executeWebhook(
  toolDef: ToolDefinition,
  toolUseId: string,
  toolName: string,
  input: Record<string, unknown>,
  context: WebhookContext,
  authToken?: string,
  secrets: MaskingValues = [],
): Promise<WebhookResponse | WebhookError> {
  const timeoutMs = toolDef.timeout_ms ?? 30000;

  // Send the tool input as the request body directly (not wrapped).
  // Webhook endpoints expect flat fields (e.g., {query: "bakery", count: 1}),
  // not the MCP envelope format ({tool_use_id, tool_name, input: {...}}).
  // Context is available via X-Webhook-Context header if needed, and comes only from the authenticated request.
  const body = { ...input };

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "Accept": "application/json",
  };
  if (authToken) {
    headers["Authorization"] = `Bearer ${authToken}`;
  }
  headers["X-Webhook-Tool-Use-Id"] = toolUseId;
  headers["X-Webhook-Tool-Name"] = toolName;
  if (context) {
    headers["X-Webhook-Context"] = JSON.stringify(context);
  }

  let response: Response;
  try {
    response = await fetch(toolDef.webhook_url, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      redirect: "manual",
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (e: unknown) {
    const err = e as Error;
    if (err.name === "TimeoutError" || err.name === "AbortError") return failure({ kind: "timeout", name: toolName, timeoutMs });
    return failure({ kind: "unreachable", name: toolName });
  }

  const status = response.status;
  if (status >= 300 && status < 400) {
    await response.body?.cancel().catch(() => undefined);
    return failure({ kind: "redirect", name: toolName });
  }
  if (status === 401 || status === 403) {
    await response.body?.cancel().catch(() => undefined);
    return failure({ kind: "gateway_credential_refused", name: toolName });
  }
  if (status === 408 || status === 429 || status >= 500) {
    await response.body?.cancel().catch(() => undefined);
    return failure({ kind: "unreachable", name: toolName });
  }
  if (!response.ok) {
    // The run's known values are over the masking budget: the refusal cannot be masked, so none of it is shown.
    if (isMaskingOverBudget(secrets)) {
      await response.body?.cancel().catch(() => undefined);
      return failure({ kind: "refusal_withheld", name: toolName });
    }
    // The tool's own refusal (its message is bounded, cleaned and masked).
    let text: string | null = "";
    try {
      text = await readCapped(response);
    } catch {
      text = "";
    }
    return { output: webhookRejectionText(status, response.headers.get("content-type"), text ?? "", authToken ? [...secrets, authToken] : secrets), isError: true };
  }

  let text: string | null;
  try {
    text = await readCapped(response);
  } catch (e: unknown) {
    const err = e as Error;
    if (err.name === "TimeoutError" || err.name === "AbortError") return failure({ kind: "timeout", name: toolName, timeoutMs });
    return failure({ kind: "unreachable", name: toolName });
  }
  if (text === null) return failure({ kind: "invalid_response", name: toolName });
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    return failure({ kind: "invalid_response", name: toolName });
  }

  // If the webhook returns {output: "..."} format, use it directly.
  // Otherwise, stringify the full response as the output (most webhooks return raw data).
  if (typeof (data as { output?: unknown } | null)?.output === "string") {
    return data as WebhookResponse;
  }
  return { output: JSON.stringify(data) };
}
