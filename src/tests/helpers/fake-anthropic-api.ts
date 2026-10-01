/**
 * A scripted stand-in for the Anthropic Messages API, so the real Claude
 * runtime can run a whole agent turn without a model. It records every
 * request's offered tool names and `tool_result` blocks.
 *
 * Script: when the offered tools include one whose name ends with
 * `__<toolName>` and the conversation has no tool result yet, answer with one
 * `tool_use` of that tool; otherwise answer with the fixed final text. Requests
 * that offer no tools (the runtime's own side requests) get the final text too.
 *
 * Modes: "error" answers every agent request (one that offers tools) with an
 * HTTP 400 API error; "hang-after-tool" never answers an agent request that
 * carries a tool result, so the run stays open until the client aborts it;
 * "hang" never answers any agent request, so a streaming chat answer stays
 * open from its first turn (MVP-7616 shutdown drain).
 * "drip" streams a text answer as `dripChunks` separate `text_delta` events,
 * one every `dripIntervalMs` (default 100 ms); everything else is "normal".
 *
 * Failure modes (MVP-7685) answer main requests (agent requests that are not
 * the runtime's "Warmup" requests) with a scripted provider rejection; the
 * runtime reports it on stdout and exits 1. Claude Code 2.0.77 repeats a failed
 * streaming request once without streaming, so one gateway attempt makes two
 * main requests; "the first attempt" means every main request of the first
 * runtime session seen (from the request's `metadata.user_id`).
 * - "version-too-old": 400 `invalid_request_error` with code
 *   `claude_code_version_too_old` and "requires ... VERSION_REQUIRED or newer";
 *   "version-too-old-no-versions" is the same without a version in the text.
 * - "private-material": the version rejection whose message also carries the
 *   `privateMaterial` strings, an echo of the request's user text and a
 *   stack trace (none of it may reach a client or a log).
 * - "auth-rejected": 401 `authentication_error` with `x-should-retry: false`
 *   (without it the runtime retries a 401 for minutes).
 * - "malformed": 400 with a plain-text (non-JSON) body.
 * - "fail-first": the version rejection for the first attempt only.
 * - "rate-limited": 429 `rate_limit_error` with `x-should-retry: false` for
 *   every main request; "rate-limited-once" only for the first attempt.
 * - "rate-limited-after-tool-once" (MVP-7637): in the first attempt, the main
 *   request that carries a tool result gets that 429, so the gateway retries
 *   after the scripted call.
 *
 * Exact scripted tool (MVP-7637): with `exactTool`, a main request of the
 * conversation (not a warmup, no tool result yet) is answered with one
 * `tool_use` of exactly that name and input — whether or not the runtime
 * offered it, so a test can script a call to a tool that was not offered.
 * Main requests here are the non-warmup requests that carry the query prompt
 * (`exactTool.prompt`), since an enforced run may offer no tool at all.
 */

import http from "node:http";
import net, { type AddressInfo } from "node:net";

export const FINAL_ANSWER = "PROBE-7667-FINAL-ANSWER";
/** The minimum version named by the version rejection fixtures. */
export const VERSION_REQUIRED = "2.1.280";
export const MALFORMED_BODY = "upstream proxy failure PROBE-7685-MALFORMED {\"error\": <html>";

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
  /** Text of every user message in the request, in order (a resumed session repeats earlier turns). */
  userTexts: string[];
  /** A runtime "Warmup" request (sub-agent cache priming at start-up), not part of the conversation. */
  warmup: boolean;
  /** The runtime session of the request (`..._session_<id>` in `metadata.user_id`), or "" when absent. */
  session: string;
  /** Path (no query) and query parameter names of the request (MVP-7678: what a proxy in front forwards). */
  path: string;
  query: string[];
  /** The credential headers exactly as received (MVP-7678: which credential reached the provider). */
  apiKey: string | null;
  authorization: string | null;
  anthropicBeta: string | null;
  /** The raw request body, for surface scans (MVP-7678: nothing of the gateway may be in it). */
  body: string;
}

export interface FakeAnthropicApi {
  /** Value for ANTHROPIC_BASE_URL. */
  baseUrl: string;
  requests: RecordedMessagesRequest[];
  /** Requests that offered at least one tool: the agent loop, not side requests. */
  agentRequests: () => RecordedMessagesRequest[];
  /** Agent requests without the runtime's warmup requests: the conversation's own requests. */
  mainRequests: () => RecordedMessagesRequest[];
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

export type FakeApiMode =
  | "normal"
  | "error"
  | "hang-after-tool"
  | "drip"
  | "hang"
  | "version-too-old"
  | "version-too-old-no-versions"
  | "private-material"
  | "auth-rejected"
  | "malformed"
  | "fail-first"
  | "rate-limited"
  | "rate-limited-once"
  | "rate-limited-after-tool-once";

interface ScriptedFailure {
  status: number;
  headers: Record<string, string>;
  body: string;
}

function providerError(status: number, error: Record<string, unknown>, headers: Record<string, string> = {}): ScriptedFailure {
  return { status, headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify({ type: "error", error }) };
}

function versionRejection(message: string): ScriptedFailure {
  return providerError(400, { type: "invalid_request_error", code: "claude_code_version_too_old", message });
}

const VERSION_MESSAGE = `This model requires Claude Code version ${VERSION_REQUIRED} or newer. Please update Claude Code.`;

/** The scripted rejection for a main request (`firstAttempt`: it belongs to the first runtime session), or null to answer normally. */
function scriptedFailure(mode: FakeApiMode, firstAttempt: boolean, userText: string, privateMaterial: string[]): ScriptedFailure | null {
  switch (mode) {
    case "version-too-old":
      return versionRejection(VERSION_MESSAGE);
    case "version-too-old-no-versions":
      return versionRejection("This version of Claude Code is no longer supported for this model. Please update Claude Code.");
    case "private-material":
      return versionRejection(
        [
          VERSION_MESSAGE,
          ...privateMaterial,
          `Request was: ${userText}`,
          "Error: upstream rejected\n    at handle (/srv/provider/src/gate.js:41:13)\n    at process.processTicksAndRejections (node:internal/process/task_queues:95:5)",
        ].join(" "),
      );
    case "auth-rejected":
      return providerError(401, { type: "authentication_error", message: "invalid x-api-key" }, { "x-should-retry": "false" });
    case "malformed":
      return { status: 400, headers: { "Content-Type": "text/plain" }, body: MALFORMED_BODY };
    case "fail-first":
      return firstAttempt ? versionRejection(VERSION_MESSAGE) : null;
    case "rate-limited":
      return providerError(429, { type: "rate_limit_error", message: "Number of requests has exceeded your rate limit." }, { "x-should-retry": "false" });
    case "rate-limited-once":
      return firstAttempt ? providerError(429, { type: "rate_limit_error", message: "Number of requests has exceeded your rate limit." }, { "x-should-retry": "false" }) : null;
    default:
      return null;
  }
}

/** Text of drip chunk `index` (0-based). */
export function dripChunk(index: number): string {
  return `drip-${index} `;
}

export interface ExactToolScript {
  name: string;
  input: Record<string, unknown>;
  prompt: string;
}

export async function startFakeAnthropicApi(options: {
  toolName: string;
  mode?: FakeApiMode;
  dripChunks?: number;
  dripIntervalMs?: number;
  /** Strings the "private-material" rejection carries in its message. */
  privateMaterial?: string[];
  /**
   * Script one call to exactly this tool (see the header). An array scripts several conversations at once:
   * a request is answered by the entry whose `prompt` its user text carries (MVP-7678, concurrent conversations).
   */
  exactTool?: ExactToolScript | ExactToolScript[];
}): Promise<FakeAnthropicApi> {
  const mode = options.mode ?? "normal";
  const exactTools: ExactToolScript[] = options.exactTool === undefined ? [] : Array.isArray(options.exactTool) ? options.exactTool : [options.exactTool];
  const carries = (texts: string[], script: ExactToolScript): boolean => texts.some((text) => text.includes(script.prompt));
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
      let body: { model?: string; stream?: boolean; tools?: { name?: string }[]; messages?: MessageParam[]; metadata?: { user_id?: unknown } } = {};
      const bodyText = Buffer.concat(chunks).toString("utf8");
      try {
        body = JSON.parse(bodyText);
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
      const userTexts: string[] = [];
      // Where the latest user text and each tool result sit in the conversation: a resumed conversation
      // repeats its earlier turns, and a scripted call belongs to the latest prompt only (MVP-7678).
      let lastPromptAt = -1;
      const resultAt: number[] = [];
      let messageIndex = -1;
      for (const message of body.messages ?? []) {
        messageIndex++;
        if (message.role !== "user") continue;
        const text = blockText(message.content);
        if (text) {
          userTexts.push(text);
          lastPromptAt = messageIndex;
        }
        if (!Array.isArray(message.content)) continue;
        for (const block of message.content) {
          if (block.type === "tool_result") {
            toolResults.push({ toolUseId: String(block.tool_use_id ?? ""), isError: block.is_error === true, text: blockText(block.content) });
            resultAt.push(messageIndex);
          }
        }
      }
      const resultsAfterLatestPrompt = resultAt.filter((at) => at > lastPromptAt).length;
      const model = body.model ?? "unknown";
      const stream = body.stream === true;
      const warmup = userTexts.length > 0 && userTexts.every((text) => text === "Warmup");
      const session = typeof body.metadata?.user_id === "string" ? (/_session_([^_]*)$/.exec(body.metadata.user_id)?.[1] ?? "") : "";
      const url = new URL(req.url ?? "/", "http://fake.invalid");
      const header = (name: string): string | null => (typeof req.headers[name] === "string" ? (req.headers[name] as string) : null);
      const record: RecordedMessagesRequest = {
        model,
        stream,
        tools,
        toolResults,
        userTexts,
        warmup,
        session,
        path: url.pathname,
        query: [...url.searchParams.keys()],
        apiKey: header("x-api-key"),
        authorization: header("authorization"),
        anthropicBeta: header("anthropic-beta"),
        body: bodyText,
      };
      requests.push(record);
      const latestText = userTexts.at(-1) ?? "";
      const exact = exactTools.find((script) => latestText.includes(script.prompt));
      const main = exactTools.length > 0 ? exact !== undefined && !warmup : tools.length > 0 && !warmup;
      const isMain = (r: RecordedMessagesRequest) => (exactTools.length > 0 ? exactTools.some((script) => carries(r.userTexts, script)) && !r.warmup : r.tools.length > 0 && !r.warmup);
      const firstSession = requests.find(isMain)?.session;
      if (mode === "rate-limited-after-tool-once" && main && toolResults.length > 0 && record.session === firstSession) {
        res.writeHead(429, { "Content-Type": "application/json", "x-should-retry": "false" });
        res.end(JSON.stringify({ type: "error", error: { type: "rate_limit_error", message: "Number of requests has exceeded your rate limit." } }));
        return;
      }

      const failure = main ? scriptedFailure(mode, record.session === firstSession, userTexts.join(" "), options.privateMaterial ?? []) : null;
      if (failure) {
        res.writeHead(failure.status, failure.headers);
        res.end(failure.body);
        return;
      }

      if (mode === "error" && tools.length > 0) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ type: "error", error: { type: "invalid_request_error", message: "PROBE-7667-API-ERROR" } }));
        return;
      }
      if (mode === "hang-after-tool" && tools.length > 0 && toolResults.length > 0) return;
      if (mode === "hang" && tools.length > 0) return;

      const target = tools.find((name) => name.endsWith(`__${options.toolName}`));
      type Block = { type: "tool_use"; id: string; name: string; input: Record<string, unknown> } | { type: "text"; text: string };
      const content: Block[] =
        exact && main && resultsAfterLatestPrompt === 0
          ? [{ type: "tool_use", id: `toolu_7637_${++toolUseSeq}`, name: exact.name, input: exact.input }]
          : !exact && target && toolResults.length === 0
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
      if (mode === "drip" && content[0].type === "text") {
        const chunks = options.dripChunks ?? 10;
        const intervalMs = options.dripIntervalMs ?? 100;
        send("message_start", {
          type: "message_start",
          message: { id: messageId, type: "message", role: "assistant", model, content: [], stop_reason: null, stop_sequence: null, usage },
        });
        send("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } });
        let sent = 0;
        const timer = setInterval(() => {
          if (res.writableEnded || res.destroyed) {
            clearInterval(timer);
            return;
          }
          send("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: dripChunk(sent) } });
          sent += 1;
          if (sent < chunks) return;
          clearInterval(timer);
          send("content_block_stop", { type: "content_block_stop", index: 0 });
          send("message_delta", { type: "message_delta", delta: { stop_reason: "end_turn", stop_sequence: null }, usage: { output_tokens: 5 } });
          send("message_stop", { type: "message_stop" });
          res.end();
        }, intervalMs);
        res.on("close", () => clearInterval(timer));
        return;
      }
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
    mainRequests: () =>
      requests.filter((r) => (exactTools.length > 0 ? exactTools.some((script) => carries(r.userTexts, script)) && !r.warmup : r.tools.length > 0 && !r.warmup)),
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}
