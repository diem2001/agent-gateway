import { createSdkMcpServer } from "@anthropic-ai/claude-agent-sdk";
import type { McpSdkServerConfigWithInstance } from "@anthropic-ai/claude-agent-sdk";
// zod is a transitive dependency of @anthropic-ai/claude-agent-sdk (required for ZodRawShape)
import { z } from "zod";
import type { ToolDefinition } from "./tools.js";
import type { WebhookContext, WebhookResponse } from "./webhook.js";
import { executeWebhook } from "./webhook.js";

/* ------------------------------------------------------------------ */
/*  Helpers                                                             */
/* ------------------------------------------------------------------ */

/**
 * Build a ZodRawShape from a JSON Schema object.
 * Each declared property maps to z.unknown() — validation is the webhook's responsibility.
 */
function buildZodShape(jsonSchema: Record<string, unknown>): Record<string, z.ZodUnknown> {
  const shape: Record<string, z.ZodUnknown> = {};
  const props = jsonSchema["properties"];
  if (props && typeof props === "object" && !Array.isArray(props)) {
    for (const key of Object.keys(props as Record<string, unknown>)) {
      shape[key] = z.unknown();
    }
  }
  return shape;
}

/* ------------------------------------------------------------------ */
/*  Factory                                                             */
/* ------------------------------------------------------------------ */

/**
 * Creates an in-process MCP server wrapping all registered tools.
 * Each tool handler POSTs to its configured webhook URL.
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
    const inputSchema = buildZodShape(toolDef.input_schema);

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
