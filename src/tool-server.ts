import { createSdkMcpServer } from "@anthropic-ai/claude-agent-sdk";
import type { McpSdkServerConfigWithInstance } from "@anthropic-ai/claude-agent-sdk";
import { buildToolInputShape } from "./tool-input-schema.js";
import type { ToolDefinition } from "./tools.js";
import type { WebhookContext, WebhookResponse } from "./webhook.js";
import { executeWebhook } from "./webhook.js";

/* ------------------------------------------------------------------ */
/*  Factory                                                             */
/* ------------------------------------------------------------------ */

/**
 * Creates an in-process MCP server wrapping all registered tools.
 * Each tool's registered input_schema is advertised to the model and validated
 * before the handler runs (see tool-input-schema.ts); a call that violates it
 * gets a tool error and never reaches the webhook. The webhook keeps its own
 * validation. Each tool handler POSTs to its configured webhook URL.
 * Context (user_id, session_id, etc.) is baked into handler closures.
 *
 * Call once per query so the context is correctly scoped.
 */
export function createToolMcpServer(
  tools: ToolDefinition[],
  context: WebhookContext,
  authToken?: string,
): McpSdkServerConfigWithInstance {
  const sdkTools = tools.map((toolDef) => {
    const inputSchema = buildToolInputShape(toolDef.name, toolDef.input_schema);

    return {
      name: toolDef.name,
      description: toolDef.description,
      inputSchema,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      handler: async (args: Record<string, unknown>, extra: any) => {
        const toolUseId = String(extra?.requestId ?? "mcp-call");
        const result = await executeWebhook(toolDef, toolUseId, toolDef.name, args, context, authToken);

        if ("isError" in result && result.isError) {
          return {
            isError: true as const,
            content: [{ type: "text" as const, text: result.output }],
          };
        }

        // Include metadata as structured JSON so Claude sees the full data
        const success = result as WebhookResponse;
        const parts: Array<{ type: "text"; text: string }> = [
          { type: "text" as const, text: success.output },
        ];
        if (success.metadata && Object.keys(success.metadata).length > 0) {
          parts.push({
            type: "text" as const,
            text: "\n\n```json\n" + JSON.stringify(success.metadata, null, 2) + "\n```",
          });
        }
        return { content: parts };
      },
    };
  });

  return createSdkMcpServer({
    name: "agent-gateway-tools",
    version: "1.0.0",
    // Cast required: our dynamic shape satisfies SdkMcpToolDefinition<any> at runtime
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    tools: sdkTools as any,
  });
}
