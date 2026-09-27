/**
 * A scripted stand-in for the Anthropic Messages API that records what the
 * model would see about tools, so a test can assert the real Claude runtime's
 * model-facing tool definitions (`name`, `description`, `input_schema`) and the
 * `tool_result` blocks it sends back. No real model is involved.
 *
 * Script: each step names a tool (by the suffix after `__`) and the input the
 * "model" sends. An agent request (one that offers a scripted tool) whose
 * conversation holds N tool results is answered with step N as one `tool_use`
 * when step N's tool is offered; otherwise, and once every step has a result,
 * the answer is the fixed final text. The runtime's own side requests offer
 * only built-in tools (or none) and get the final text too.
 */

import http from "node:http";
import net, { type AddressInfo } from "node:net";

export const SCHEMA_FINAL_ANSWER = "PROBE-7697-FINAL-ANSWER";

export interface ScriptStep {
  /** Tool name without the `mcp__<server>__` prefix. */
  tool: string;
  input: Record<string, unknown>;
}

export interface RecordedToolDefinition {
  name: string;
  description: unknown;
  input_schema: unknown;
}

export interface RecordedStepResult {
  isError: boolean;
  text: string;
}

export interface RecordedSchemaRequest {
  tools: RecordedToolDefinition[];
  toolResultCount: number;
}

export interface ToolSchemaApi {
  /** Value for ANTHROPIC_BASE_URL. */
  baseUrl: string;
  requests: RecordedSchemaRequest[];
  /** Requests that offered a scripted tool: the agent loop, not side requests. */
  agentRequests: () => RecordedSchemaRequest[];
  /** The tool result the runtime returned for each script step, by step index (undefined: never called). */
  stepResults: () => (RecordedStepResult | undefined)[];
  close: () => Promise<void>;
}

interface ContentBlock {
  type: string;
  tool_use_id?: string;
  is_error?: boolean;
  content?: unknown;
}

function blockText(content: unknown): string {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content
      .map((c) => (c && typeof c === "object" && (c as { type?: string }).type === "text" ? String((c as { text?: unknown }).text ?? "") : ""))
      .join("\n");
  }
  return "";
}

export async function startToolSchemaApi(script: ScriptStep[]): Promise<ToolSchemaApi> {
  const requests: RecordedSchemaRequest[] = [];
  const sockets = new Set<net.Socket>();
  /** tool_use id -> script step index. */
  const stepOfToolUse = new Map<string, number>();
  const results: (RecordedStepResult | undefined)[] = [];
  const offersScriptedTool = (r: RecordedSchemaRequest) => r.tools.some((t) => script.some((step) => t.name.endsWith(`__${step.tool}`)));

  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const pathname = new URL(req.url ?? "/", "http://fake.invalid").pathname;
      if (req.method !== "POST" || !pathname.startsWith("/v1/messages")) {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ type: "error", error: { type: "not_found_error", message: "not found" } }));
        return;
      }
      if (pathname === "/v1/messages/count_tokens") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ input_tokens: 10 }));
        return;
      }
      let body: { model?: string; stream?: boolean; tools?: Record<string, unknown>[]; messages?: { role: string; content: string | ContentBlock[] }[] } = {};
      try {
        body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      } catch {
        // An unparseable body is answered like an empty one.
      }

      const tools: RecordedToolDefinition[] = (body.tools ?? []).map((t) => ({
        name: String(t.name ?? ""),
        description: t.description,
        input_schema: t.input_schema,
      }));
      let toolResultCount = 0;
      for (const message of body.messages ?? []) {
        if (message.role !== "user" || !Array.isArray(message.content)) continue;
        for (const block of message.content) {
          if (block.type !== "tool_result") continue;
          toolResultCount += 1;
          const step = stepOfToolUse.get(String(block.tool_use_id ?? ""));
          if (step !== undefined && results[step] === undefined) {
            results[step] = { isError: block.is_error === true, text: blockText(block.content) };
          }
        }
      }
      requests.push({ tools, toolResultCount });

      const model = body.model ?? "unknown";
      const stream = body.stream === true;
      type Block = { type: "tool_use"; id: string; name: string; input: Record<string, unknown> } | { type: "text"; text: string };
      let content: Block[] = [{ type: "text", text: SCHEMA_FINAL_ANSWER }];
      if (tools.length > 0 && toolResultCount < script.length) {
        const step = script[toolResultCount];
        const target = tools.find((t) => t.name.endsWith(`__${step.tool}`));
        if (target) {
          const id = `toolu_7697_${toolResultCount + 1}`;
          stepOfToolUse.set(id, toolResultCount);
          content = [{ type: "tool_use", id, name: target.name, input: step.input }];
        }
      }
      const stopReason = content[0].type === "tool_use" ? "tool_use" : "end_turn";
      const messageId = `msg_7697_${requests.length}`;
      const usage = { input_tokens: 10, output_tokens: 5, cache_creation_input_tokens: 0, cache_read_input_tokens: 0 };

      if (!stream) {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ id: messageId, type: "message", role: "assistant", model, content, stop_reason: stopReason, stop_sequence: null, usage }));
        return;
      }

      res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache" });
      const send = (event: string, data: unknown) => res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
      send("message_start", {
        type: "message_start",
        message: { id: messageId, type: "message", role: "assistant", model, content: [], stop_reason: null, stop_sequence: null, usage },
      });
      content.forEach((block, index) => {
        if (block.type === "tool_use") {
          send("content_block_start", { type: "content_block_start", index, content_block: { ...block, input: {} } });
          send("content_block_delta", { type: "content_block_delta", index, delta: { type: "input_json_delta", partial_json: JSON.stringify(block.input) } });
        } else {
          send("content_block_start", { type: "content_block_start", index, content_block: { type: "text", text: "" } });
          send("content_block_delta", { type: "content_block_delta", index, delta: { type: "text_delta", text: block.text } });
        }
        send("content_block_stop", { type: "content_block_stop", index });
      });
      send("message_delta", { type: "message_delta", delta: { stop_reason: stopReason, stop_sequence: null }, usage: { output_tokens: 5 } });
      send("message_stop", { type: "message_stop" });
      res.end();
    });
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const { port } = server.address() as AddressInfo;

  return {
    baseUrl: `http://127.0.0.1:${port}`,
    requests,
    agentRequests: () => requests.filter(offersScriptedTool),
    stepResults: () => script.map((_, index) => results[index]),
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}
