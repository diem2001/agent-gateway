import { query } from "@anthropic-ai/claude-agent-sdk";
import { log } from "./logging.js";
import type { StreamEvent } from "./event-cache.js";
import { getAllTools } from "./tools.js";
import type { WebhookContext } from "./webhook.js";
import { createToolMcpServer } from "./tool-server.js";

export interface QueryParams {
  prompt: string;
  systemPrompt?: string;
  model?: string;
  allowedTools?: string[];
  sessionId?: string;
  isResume?: boolean;
  abortController: AbortController;
  onEvent: (event: Omit<StreamEvent, "seq">) => void;
  webhookContext?: WebhookContext;
  clientAuthToken?: string;
}

export interface QueryResult {
  response: string;
  resultData: Record<string, unknown> | null;
}

function formatToolInput(toolName: string, input: Record<string, unknown> | undefined): string {
  if (!input) return "";
  if (toolName === "Bash" && input.command) return String(input.command);
  if ((toolName === "Read" || toolName === "Write") && input.file_path) return String(input.file_path);
  if (toolName === "Glob" && input.pattern) return String(input.pattern) + (input.path ? ` in ${input.path}` : "");
  if (toolName === "Grep" && input.pattern) return String(input.pattern) + (input.path ? ` in ${input.path}` : "");
  if (toolName === "Edit" && input.file_path) return String(input.file_path);
  if (toolName === "WebSearch" && input.query) return String(input.query);
  if (toolName === "WebFetch" && input.url) return String(input.url);
  // Reqlift tools: show readable summary
  if (toolName === "reqlift_create_draft") {
    const parts = [input.draft_type, input.title].filter(Boolean).map(String);
    if (input.project_label) parts.unshift(`[${input.project_label}]`);
    return parts.join(": ");
  }
  if (toolName === "reqlift_update_draft") {
    const parts: string[] = [];
    if (input.draft_id) parts.push(String(input.draft_id).substring(0, 8));
    if (input.title) parts.push(String(input.title));
    if (input.status) parts.push(`→ ${input.status}`);
    return parts.join(" ");
  }
  if (toolName === "reqlift_get_project_context" && input.project_label) return String(input.project_label);
  if (toolName === "reqlift_list_projects") return "list all projects";
  // Skill: show skill name
  if (toolName === "Skill" && input.skill) return String(input.skill);
  // Task/Agent: show description
  if ((toolName === "Task" || toolName === "Agent") && input.description) return String(input.description);
  return JSON.stringify(input, null, 2).substring(0, 1000);
}

const DEFAULT_TOOLS = ["Bash", "Read", "Write", "Edit", "Glob", "Grep", "WebSearch", "WebFetch", "Skill"];

export async function runQuery({ prompt, systemPrompt, model, allowedTools, sessionId, isResume, abortController, onEvent, webhookContext, clientAuthToken }: QueryParams): Promise<QueryResult> {
  const registeredTools = getAllTools();
  const registeredToolNames = registeredTools.map((t) => t.name);
  const effectiveTools = allowedTools || [...DEFAULT_TOOLS, ...registeredToolNames];
  const HOME = process.env.HOME || "/home/node";
  const options: Record<string, unknown> = {
    allowedTools: effectiveTools,
    permissionMode: "bypassPermissions",
    model: model || "claude-opus-4-6",
    abortController,
    includePartialMessages: true,
    cwd: HOME,
    settingSources: ["user", "project"],
  };
  if (isResume) { options.resume = sessionId; } else { options.systemPrompt = systemPrompt || undefined; options.sessionId = sessionId; }
  log("query", `SDK options: sessionId=${sessionId || "none"} isResume=${isResume} resume=${isResume ? sessionId : "n/a"}`);

  if (registeredTools.length > 0 && webhookContext) {
    options.mcpServers = {
      "agent-gateway-tools": createToolMcpServer(registeredTools, webhookContext, clientAuthToken),
    };
  }

  const conversation = query({ prompt, options });
  let fullResponse = "";
  let resultData: Record<string, unknown> | null = null;
  const pendingTools = new Map<string, { name: string }>();
  const toolTimings = new Map<string, number>();

  for await (const message of conversation) {
    if (abortController.signal.aborted) break;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const msg = message as any;

    if (msg.type === "assistant" && msg.message?.content) {
      for (const block of msg.message.content) {
        if (block.text) fullResponse += block.text;
        if (block.type === "tool_use") {
          const pending = pendingTools.get(block.id);
          const toolName: string = pending?.name || block.name;
          const inputStr = formatToolInput(toolName, block.input);
          toolTimings.set(block.id, Date.now());
          onEvent({ type: "tool_use", toolName, toolUseId: block.id, input: inputStr, startedAt: Date.now() });
        }
      }
    } else if (msg.type === "stream_event") {
      const event = msg.event;
      if (event?.type === "content_block_delta" && event.delta?.type === "text_delta") {
        const text: string = event.delta.text;
        fullResponse += text;
        onEvent({ type: "text", content: text });
      }
      if (event?.type === "content_block_start" && event.content_block?.type === "tool_use") {
        pendingTools.set(event.content_block.id, { name: event.content_block.name });
      }
      if (event?.type === "rate_limit_event" || event?.type === "rate_limit") {
        const retryAfterMs = ((event.retry_after_seconds || event.retry_after || 5) as number) * 1000;
        log("rate-limit", `Rate limit event detected in stream, retry_after=${retryAfterMs}ms`);
        onEvent({ type: "rate_limited", status: "waiting", retryAfterMs });
      }
    } else if (msg.type === "user" && msg.tool_use_result !== undefined) {
      const content = msg.message?.content;
      if (Array.isArray(content)) {
        for (const block of content) {
          if (block.type === "tool_result") {
            const toolUseId: string = block.tool_use_id;
            let toolName = "Tool";
            if (toolUseId && pendingTools.has(toolUseId)) { toolName = pendingTools.get(toolUseId)!.name; pendingTools.delete(toolUseId); }
            let output = "";
            if (typeof block.content === "string") { output = block.content; }
            else if (Array.isArray(block.content)) { output = block.content.filter((c: { type: string }) => c.type === "text").map((c: { text: string }) => c.text).join("\n"); }
            const truncated = output.length > 3000 ? output.substring(0, 3000) + "\n... (truncated)" : output;
            const durationMs = toolTimings.has(toolUseId) ? Date.now() - toolTimings.get(toolUseId)! : null;
            toolTimings.delete(toolUseId);
            onEvent({ type: "tool_result", toolName, toolUseId, output: truncated, durationMs });
          }
        }
      }
    } else if (msg.type === "system") {
      if (msg.subtype === "status" && msg.status === "compacting") onEvent({ type: "sdk_status", status: "compacting" });
      else if (msg.subtype === "status" && msg.status === null) onEvent({ type: "sdk_status", status: null });
      if (msg.subtype === "compact_boundary" && msg.compact_metadata) {
        onEvent({ type: "sdk_compact_complete", trigger: msg.compact_metadata.trigger || "auto", preTokens: msg.compact_metadata.pre_tokens || 0 });
      }
    } else if (msg.type === "result") { resultData = msg; }
  }

  return { response: fullResponse, resultData };
}
