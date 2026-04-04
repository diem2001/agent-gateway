import type { ToolDefinition } from "./tools.js";

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
}

/* ------------------------------------------------------------------ */
/*  Executor                                                            */
/* ------------------------------------------------------------------ */

export async function executeWebhook(
  toolDef: ToolDefinition,
  toolUseId: string,
  toolName: string,
  input: Record<string, unknown>,
  context: WebhookContext,
  authToken?: string,
): Promise<WebhookResponse | WebhookError> {
  const timeoutMs = toolDef.timeout_ms ?? 30000;

  const body: WebhookRequest = {
    tool_use_id: toolUseId,
    tool_name: toolName,
    input,
    context,
  };

  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (authToken) {
    headers["Authorization"] = `Bearer ${authToken}`;
  }

  let response: Response;
  try {
    response = await fetch(toolDef.webhook_url, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (e: unknown) {
    const err = e as Error;
    if (err.name === "TimeoutError" || err.name === "AbortError") {
      return { output: `Tool webhook timed out after ${timeoutMs}ms`, isError: true };
    }
    return { output: `Tool webhook failed: ${err.message}`, isError: true };
  }

  if (!response.ok) {
    const text = await response.text().catch(() => "");
    return {
      output: `Tool webhook returned error: ${response.status} ${text}`.trimEnd(),
      isError: true,
    };
  }

  const data = (await response.json()) as WebhookResponse;
  return data;
}
