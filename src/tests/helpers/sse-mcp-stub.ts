/**
 * A loopback MCP server speaking the legacy "HTTP with SSE" transport (MVP-7679): `GET /sse` opens an event
 * stream whose first event (`endpoint`) names the URL to POST client messages to, and the answers come back as
 * `message` events. Every request is recorded with its headers and body, so a test can assert exactly which
 * credential reached which path. Failure modes script the faults of the SSE bridge's fault rows:
 * - "reset-on-call": the stream is destroyed when a `tools/call` arrives (a connection reset);
 * - "end-on-call": the stream ends cleanly when a `tools/call` arrives;
 * - "endless-event": a `tools/call` is answered with an event that never ends (data without a blank line);
 * - "hang-on-call": a `tools/call` is accepted (202) and never answered;
 * - "inline-answer": a `tools/call` is answered in the POST response instead of on the stream.
 * `callStatus` answers only the POST of a `tools/call` with that status (a credential refused at call time).
 * Server requests (`ping`, `roots/list`) can be sent right after the handshake, and the client's answers to them
 * are recorded in `clientAnswers`.
 */

import http, { type IncomingHttpHeaders, type ServerResponse } from "node:http";
import net, { type AddressInfo } from "node:net";

export type SseStubMode = "normal" | "reset-on-call" | "end-on-call" | "endless-event" | "hang-on-call" | "inline-answer";

export interface SseMcpStubOptions {
  toolNames?: string[];
  mode?: SseStubMode;
  /** The `data:` of the endpoint event for the stream's origin (default: a relative path). */
  endpoint?: (origin: string) => string;
  /** Answer the GET with this status instead of opening a stream (with `Location` for a 3xx). */
  getStatus?: number;
  getLocation?: string;
  /** Content type of the stream (default text/event-stream). */
  contentType?: string;
  /** Send a `ping` and a `roots/list` request on the stream after the first `initialize`. */
  serverRequests?: boolean;
  /** Answer a POST with this status (and no answer) instead of 202. */
  postStatus?: number;
  /** Answer the POST of a `tools/call` with this status (everything before it works). */
  callStatus?: number;
}

export interface SseStubRequest {
  method: string;
  path: string;
  headers: IncomingHttpHeaders;
  body: string;
  status: number;
}

export interface SseMcpStub {
  /** The registered endpoint (the stream URL). */
  url: string;
  origin: string;
  requests: SseStubRequest[];
  /** The tool name of every `tools/call` that arrived. */
  toolCalls: string[];
  /** The JSON bodies of the client's answers to server requests (messages with no method). */
  clientAnswers: Record<string, unknown>[];
  streamsOpened: () => number;
  close: () => Promise<void>;
}

export async function startSseMcpStub(options: SseMcpStubOptions = {}): Promise<SseMcpStub> {
  const toolNames = options.toolNames ?? ["lookup_record"];
  const mode = options.mode ?? "normal";
  const requests: SseStubRequest[] = [];
  const toolCalls: string[] = [];
  const clientAnswers: Record<string, unknown>[] = [];
  const sockets = new Set<net.Socket>();
  const streams = new Set<ServerResponse>();
  let opened = 0;
  let origin = "";
  let serverRequestsSent = false;

  const emit = (res: ServerResponse, event: string, data: string): void => {
    if (!res.destroyed && !res.writableEnded) res.write(`event: ${event}\ndata: ${data}\n\n`);
  };
  const latestStream = (): ServerResponse | undefined => [...streams].at(-1);

  const answerFor = (message: { id?: unknown; method?: string; params?: Record<string, unknown> }): unknown => {
    switch (message.method) {
      case "initialize":
        return { jsonrpc: "2.0", id: message.id, result: { protocolVersion: "2024-11-05", capabilities: { tools: {} }, serverInfo: { name: "sse-mcp-stub", version: "1.0.0" } } };
      case "tools/list":
        return {
          jsonrpc: "2.0",
          id: message.id,
          result: { tools: toolNames.map((name) => ({ name, description: name, inputSchema: { type: "object", properties: { id: { type: "string" } } } })) },
        };
      case "tools/call":
        return { jsonrpc: "2.0", id: message.id, result: { content: [{ type: "text", text: `SSE-RESULT-7679 ${String(message.params?.name)}` }] } };
      case "ping":
        return { jsonrpc: "2.0", id: message.id, result: {} };
      default:
        return { jsonrpc: "2.0", id: message.id, error: { code: -32601, message: "Method not found" } };
    }
  };

  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://stub.invalid");
    const record: SseStubRequest = { method: req.method ?? "", path: url.pathname + url.search, headers: req.headers, body: "", status: 0 };
    requests.push(record);
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      record.body = Buffer.concat(chunks).toString("utf8");
      if (req.method === "GET" && url.pathname === "/sse") {
        if (options.getStatus) {
          record.status = options.getStatus;
          res.writeHead(options.getStatus, options.getLocation ? { Location: options.getLocation } : {});
          res.end();
          return;
        }
        record.status = 200;
        opened++;
        streams.add(res);
        res.on("close", () => streams.delete(res));
        res.writeHead(200, { "Content-Type": options.contentType ?? "text/event-stream", "Cache-Control": "no-cache" });
        emit(res, "endpoint", options.endpoint ? options.endpoint(origin) : `/messages?sessionId=s-${opened}`);
        return;
      }
      if (req.method === "POST" && url.pathname === "/messages") {
        let message: { id?: unknown; method?: string; params?: Record<string, unknown> };
        try {
          message = JSON.parse(record.body);
        } catch {
          record.status = 400;
          res.writeHead(400);
          res.end();
          return;
        }
        if (message.method === undefined) {
          // The client's answer to a server request.
          clientAnswers.push(message as Record<string, unknown>);
          record.status = 202;
          res.writeHead(202);
          res.end();
          return;
        }
        if (options.postStatus) {
          record.status = options.postStatus;
          res.writeHead(options.postStatus);
          res.end();
          return;
        }
        const stream = latestStream();
        const hasId = message.id !== undefined && message.id !== null;
        record.status = 202;
        if (message.method === "tools/call") {
          toolCalls.push(String(message.params?.name ?? ""));
          if (options.callStatus) {
            record.status = options.callStatus;
            res.writeHead(options.callStatus);
            res.end();
            return;
          }
          if (mode === "reset-on-call") {
            res.writeHead(202);
            res.end();
            stream?.socket?.destroy();
            return;
          }
          if (mode === "end-on-call") {
            res.writeHead(202);
            res.end();
            stream?.end();
            return;
          }
          if (mode === "endless-event") {
            res.writeHead(202);
            res.end();
            if (stream) {
              stream.write("event: message\ndata: ");
              const filler = "x".repeat(64 * 1024);
              const timer = setInterval(() => {
                if (stream.destroyed || stream.writableEnded) {
                  clearInterval(timer);
                  return;
                }
                stream.write(filler);
              }, 1);
              stream.on("close", () => clearInterval(timer));
            }
            return;
          }
          if (mode === "hang-on-call") {
            res.writeHead(202);
            res.end();
            return;
          }
          if (mode === "inline-answer" && hasId) {
            const text = JSON.stringify(answerFor(message));
            res.writeHead(200, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(text) });
            res.end(text);
            return;
          }
        }
        res.writeHead(202);
        res.end();
        if (hasId && stream) {
          emit(stream, "message", JSON.stringify(answerFor(message)));
          if (options.serverRequests && message.method === "initialize" && !serverRequestsSent) {
            serverRequestsSent = true;
            emit(stream, "message", JSON.stringify({ jsonrpc: "2.0", id: "srv-ping", method: "ping" }));
            emit(stream, "message", JSON.stringify({ jsonrpc: "2.0", id: "srv-roots", method: "roots/list" }));
            emit(stream, "message", JSON.stringify({ jsonrpc: "2.0", id: "srv-other", method: "sampling/createMessage", params: {} }));
            emit(stream, "message", JSON.stringify({ jsonrpc: "2.0", method: "notifications/message", params: { level: "info", data: "x" } }));
          }
        }
        return;
      }
      record.status = 404;
      res.writeHead(404);
      res.end();
    });
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const { port } = server.address() as AddressInfo;
  origin = `http://127.0.0.1:${port}`;

  return {
    url: `${origin}/sse`,
    origin,
    requests,
    toolCalls,
    clientAnswers,
    streamsOpened: () => opened,
    close: async () => {
      for (const stream of streams) stream.destroy();
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}
