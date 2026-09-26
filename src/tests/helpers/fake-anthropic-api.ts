/**
 * A scripted stand-in for the Anthropic Messages API, so the real Claude
 * runtime can run a whole agent turn without a model. It records every
 * request's offered tool names and `tool_result` blocks.
 *
 * Script: when the offered tools include one whose name ends with
 * `__<toolName>` and the conversation has no tool result yet, answer with one
 * `tool_use` of that tool; otherwise answer with the fixed final text. Requests
 * that offer no tools (the runtime's own side requests) get the final text too.
 */

import http from "node:http";
import net, { type AddressInfo } from "node:net";

export const FINAL_ANSWER = "PROBE-7667-FINAL-ANSWER";

export interface RecordedToolResult {
  toolUseId: string;
  isError: boolean;
  text: string;
}

export interface RecordedMessagesRequest {
  model: string;
  stream: boolean;
  tools: string[];
  toolResults: RecordedToolResult[];
}

export interface FakeAnthropicApi {
  /** Value for ANTHROPIC_BASE_URL. */
  baseUrl: string;
  requests: RecordedMessagesRequest[];
  /** Requests that offered at least one tool: the agent loop, not side requests. */
  agentRequests: () => RecordedMessagesRequest[];
  close: () => Promise<void>;
}

interface MessageParam {
  role: string;
  content: string | { type: string; tool_use_id?: string; is_error?: boolean; content?: unknown }[];
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

export async function startFakeAnthropicApi(options: { toolName: string }): Promise<FakeAnthropicApi> {
  const requests: RecordedMessagesRequest[] = [];
  const sockets = new Set<net.Socket>();
  let toolUseSeq = 0;

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
      let body: { model?: string; stream?: boolean; tools?: { name?: string }[]; messages?: MessageParam[] } = {};
      try {
        body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      } catch {
        // An unparseable body is answered like an empty one.
      }
      if (pathname === "/v1/messages/count_tokens") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ input_tokens: 10 }));
        return;
      }

      const tools = (body.tools ?? []).map((t) => String(t.name ?? ""));
      const toolResults: RecordedToolResult[] = [];
      for (const message of body.messages ?? []) {
        if (message.role !== "user" || !Array.isArray(message.content)) continue;
        for (const block of message.content) {
          if (block.type === "tool_result") {
            toolResults.push({ toolUseId: String(block.tool_use_id ?? ""), isError: block.is_error === true, text: blockText(block.content) });
          }
        }
      }
      const model = body.model ?? "unknown";
      const stream = body.stream === true;
      requests.push({ model, stream, tools, toolResults });

      const target = tools.find((name) => name.endsWith(`__${options.toolName}`));
      type Block = { type: "tool_use"; id: string; name: string; input: Record<string, unknown> } | { type: "text"; text: string };
      const content: Block[] =
        target && toolResults.length === 0
          ? [{ type: "tool_use", id: `toolu_7667_${++toolUseSeq}`, name: target, input: { id: "R-1" } }]
          : [{ type: "text", text: FINAL_ANSWER }];
      const stopReason = content[0].type === "tool_use" ? "tool_use" : "end_turn";
      const messageId = `msg_7667_${requests.length}`;
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
    agentRequests: () => requests.filter((r) => r.tools.length > 0),
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}
