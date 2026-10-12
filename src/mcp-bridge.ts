import http, { type IncomingMessage } from "node:http";
import https from "node:https";
import { log } from "./logging.js";
import type { ToolFailure } from "./tool-mediation.js";

/**
 * Bridges of the trusted MCP relay (MVP-7679).
 *
 * The runtime only ever talks plain JSON-over-POST to the relay (`mcp-credential-relay.ts`); for an upstream that
 * speaks another transport the relay hands each already-checked JSON-RPC message to a bridge, which returns the
 * answer as one JSON message. This file holds the SSE bridge (the legacy MCP "HTTP with SSE" transport); the stdio
 * bridge lives in `mcp-stdio-sandbox.ts`. Both share the relay's token, grant, message rules, codes, deadline and
 * revocation, and neither opens a listener.
 *
 * Nothing in here may end the gateway process: every socket and stream has an error listener, buffers are capped,
 * and a bridge that fails answers with a `ToolFailure`, never an exception.
 */

export type JsonRpcObject = Record<string, unknown>;

/** What a bridge returns for one message the relay forwarded. */
export type BridgeResult =
  | { kind: "answer"; message: JsonRpcObject }
  | { kind: "accepted" }
  | { kind: "failure"; failure: ToolFailure };

export interface McpBridge {
  /** Sends one message; a notification (no `id`) is `accepted`, a request waits for its answer up to `deadlineMs`. */
  request(message: JsonRpcObject, deadlineMs: number): Promise<BridgeResult>;
  /** Ends every connection and fails every pending request; idempotent. */
  close(): void;
}

/** One buffer of the bridges (a stream event, a line, a response) is refused above this. */
export const BRIDGE_MAX_BUFFER_BYTES = 25 * 1024 * 1024;
/** Requests one bridge waits for at once. */
export const BRIDGE_MAX_PENDING = 32;

const transportFor = (url: URL): typeof http | typeof https => (url.protocol === "https:" ? https : http);

export interface SseBridgeOptions {
  serverName: string;
  /** The registered endpoint (the SSE stream URL). */
  url: string;
  /** The run's credential headers; sent on the stream and on every POST, never to another origin. */
  headers: Record<string, string>;
  /** No data on the stream or a POST for this long ends it (and fails what waits). */
  idleTimeoutMs: number;
  maxBufferBytes?: number;
}

interface Pending {
  resolve: (result: BridgeResult) => void;
  timer: NodeJS.Timeout;
}

/**
 * The legacy SSE transport: `GET <url>` opens an event stream whose first event (`endpoint`) names the URL to POST
 * client messages to; answers come back as `message` events and are matched to their request by id.
 *
 * - The `endpoint` event is accepted only when it resolves to the registered URL's origin: the credential is never
 *   sent anywhere else (a different origin is the redirect failure).
 * - Server-to-client requests on the stream are answered locally (`ping` with `{}`, `roots/list` with no roots,
 *   anything else with method-not-found); server notifications are dropped.
 * - A stream that ends fails every pending request as unreachable; the next request opens a new stream.
 */
export class SseBridge implements McpBridge {
  private readonly origin: string;
  private readonly maxBufferBytes: number;
  private endpoint: URL | null = null;
  private connecting: Promise<ToolFailure | null> | null = null;
  private stream: { req: http.ClientRequest; res?: IncomingMessage } | null = null;
  private closed = false;
  private readonly pending = new Map<string, Pending>();
  private readonly posts = new Set<http.ClientRequest>();

  constructor(private readonly options: SseBridgeOptions) {
    this.origin = new URL(options.url).origin;
    this.maxBufferBytes = options.maxBufferBytes ?? BRIDGE_MAX_BUFFER_BYTES;
  }

  async request(message: JsonRpcObject, deadlineMs: number): Promise<BridgeResult> {
    if (this.closed) return { kind: "failure", failure: { kind: "unreachable", name: this.options.serverName } };
    const failure = await this.ensureConnected();
    if (failure) return { kind: "failure", failure };
    const endpoint = this.endpoint;
    if (!endpoint || this.closed) return { kind: "failure", failure: { kind: "unreachable", name: this.options.serverName } };

    const hasId = message.id !== undefined && message.id !== null;
    if (!hasId) {
      const posted = await this.post(endpoint, message);
      return posted.kind === "failure" ? posted : { kind: "accepted" };
    }
    const key = JSON.stringify(message.id);
    // A request id that is still waiting, or too many waiting requests, is refused: the maps stay consistent.
    if (this.pending.has(key)) return { kind: "failure", failure: { kind: "denied" } };
    if (this.pending.size >= BRIDGE_MAX_PENDING) return { kind: "failure", failure: { kind: "unreachable", name: this.options.serverName } };
    const answered = new Promise<BridgeResult>((resolve) => {
      const entry: Pending = {
        resolve,
        timer: setTimeout(() => {
          if (this.pending.get(key) === entry) this.pending.delete(key);
          resolve({ kind: "failure", failure: { kind: "timeout", name: this.options.serverName, timeoutMs: deadlineMs } });
        }, deadlineMs),
      };
      this.pending.set(key, entry);
    });
    const posted = await this.post(endpoint, message);
    if (posted.kind === "failure") {
      this.settle(key, posted);
    } else if (posted.kind === "answer" && JSON.stringify(posted.message.id) === key) {
      // A server that answers inline in the POST response.
      this.settle(key, posted);
    }
    return answered;
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.endStream();
    for (const post of this.posts) post.destroy();
    this.posts.clear();
    this.failAllPending({ kind: "unreachable", name: this.options.serverName });
  }

  private settle(key: string, result: BridgeResult): void {
    const entry = this.pending.get(key);
    if (!entry) return;
    clearTimeout(entry.timer);
    this.pending.delete(key);
    entry.resolve(result);
  }

  private failAllPending(failure: ToolFailure): void {
    for (const key of [...this.pending.keys()]) this.settle(key, { kind: "failure", failure });
  }

  private endStream(): void {
    const stream = this.stream;
    this.stream = null;
    this.endpoint = null;
    this.connecting = null;
    if (!stream) return;
    try {
      stream.res?.destroy();
      stream.req.destroy();
    } catch {
      // Already gone.
    }
  }

  /** Opens the stream when there is none and waits for the `endpoint` event; resolves with a failure or null. */
  private ensureConnected(): Promise<ToolFailure | null> {
    if (this.endpoint) return Promise.resolve(null);
    if (!this.connecting) this.connecting = this.connect();
    return this.connecting;
  }

  private connect(): Promise<ToolFailure | null> {
    const { serverName } = this.options;
    return new Promise<ToolFailure | null>((resolve) => {
      let done = false;
      const finish = (failure: ToolFailure | null): void => {
        if (done) return;
        done = true;
        clearTimeout(opening);
        if (failure) {
          this.endStream();
        }
        resolve(failure);
      };
      const opening = setTimeout(() => finish({ kind: "timeout", name: serverName, timeoutMs: this.options.idleTimeoutMs }), this.options.idleTimeoutMs);

      let target: URL;
      try {
        target = new URL(this.options.url);
      } catch {
        finish({ kind: "unreachable", name: serverName });
        return;
      }
      const req = transportFor(target).request(target, {
        method: "GET",
        agent: false,
        headers: { ...this.options.headers, Accept: "text/event-stream", "Cache-Control": "no-cache" },
      });
      // Handlers of this stream act only while it is still the bridge's current stream: a late `close` of an
      // earlier one must not tear down its successor.
      const mine: { req: http.ClientRequest; res?: IncomingMessage } = { req };
      this.stream = mine;
      req.on("error", () => {
        if (!done) finish({ kind: "unreachable", name: serverName });
        else this.onStreamEnded(mine);
      });
      req.on("response", (res) => {
        try {
          mine.res = res;
          const status = res.statusCode ?? 0;
          if (status >= 300 && status < 400) {
            res.resume();
            finish({ kind: "redirect", name: serverName });
            return;
          }
          if (status === 401 || status === 403) {
            res.resume();
            finish({ kind: "gateway_credential_refused", name: serverName });
            return;
          }
          if (status < 200 || status >= 300) {
            res.resume();
            finish({ kind: "unreachable", name: serverName });
            return;
          }
          const contentType = String(res.headers["content-type"] ?? "");
          if (!/^text\/event-stream/i.test(contentType)) {
            res.resume();
            finish({ kind: "invalid_response", name: serverName });
            return;
          }
          this.readStream(res, mine, finish);
        } catch {
          finish({ kind: "unreachable", name: serverName });
        }
      });
      req.end();
    });
  }

  private readStream(res: IncomingMessage, mine: { req: http.ClientRequest; res?: IncomingMessage }, finishConnect: (failure: ToolFailure | null) => void): void {
    const { serverName } = this.options;
    let buffer = "";
    res.setEncoding("utf8");
    res.on("error", () => this.onStreamEnded(mine));
    res.on("close", () => this.onStreamEnded(mine));
    res.on("data", (chunk: string) => {
      if (this.stream !== mine) return;
      try {
        buffer += chunk;
        if (buffer.length > this.maxBufferBytes) {
          // An event that never ends: the stream is dropped, nothing waits for it.
          log("audit", `mcp.bridge.refused serverName=${serverName} reason=event_too_large`);
          buffer = "";
          finishConnect({ kind: "invalid_response", name: serverName });
          this.failAllPending({ kind: "invalid_response", name: serverName });
          this.endStream();
          return;
        }
        for (;;) {
          const match = /\r\n\r\n|\n\n|\r\r/.exec(buffer);
          if (!match) break;
          const raw = buffer.slice(0, match.index);
          buffer = buffer.slice(match.index + match[0].length);
          this.dispatch(raw, finishConnect);
        }
      } catch {
        finishConnect({ kind: "invalid_response", name: serverName });
        this.failAllPending({ kind: "invalid_response", name: serverName });
        this.endStream();
      }
    });
  }

  private onStreamEnded(which: { req: http.ClientRequest; res?: IncomingMessage }): void {
    if (this.closed || this.stream !== which) return;
    this.endStream();
    this.failAllPending({ kind: "unreachable", name: this.options.serverName });
  }

  private dispatch(raw: string, finishConnect: (failure: ToolFailure | null) => void): void {
    const { serverName } = this.options;
    let event = "message";
    const data: string[] = [];
    for (const line of raw.split(/\r\n|\n|\r/)) {
      if (line.startsWith(":") || line.length === 0) continue;
      const colon = line.indexOf(":");
      const field = colon === -1 ? line : line.slice(0, colon);
      const value = colon === -1 ? "" : line.slice(colon + 1).replace(/^ /, "");
      if (field === "event") event = value;
      else if (field === "data") data.push(value);
    }
    const payload = data.join("\n");
    if (event === "endpoint") {
      let endpoint: URL;
      try {
        endpoint = new URL(payload, this.options.url);
      } catch {
        finishConnect({ kind: "invalid_response", name: serverName });
        return;
      }
      if (endpoint.origin !== this.origin || (endpoint.protocol !== "http:" && endpoint.protocol !== "https:")) {
        // The credential is never sent to another origin.
        log("audit", `mcp.bridge.refused serverName=${serverName} reason=endpoint_other_origin`);
        finishConnect({ kind: "redirect", name: serverName });
        return;
      }
      this.endpoint = endpoint;
      finishConnect(null);
      return;
    }
    if (event !== "message" || payload.length === 0) return;
    let message: unknown;
    try {
      message = JSON.parse(payload);
    } catch {
      return;
    }
    if (typeof message !== "object" || message === null || Array.isArray(message)) return;
    const object = message as JsonRpcObject;
    if (typeof object.method === "string") {
      if (object.id !== undefined && object.id !== null) this.answerServerRequest(object);
      return;
    }
    if (object.id !== undefined && object.id !== null && ("result" in object || "error" in object)) {
      this.settle(JSON.stringify(object.id), { kind: "answer", message: object });
    }
  }

  /** A request from the server on the stream: answered locally, never forwarded to the runtime. */
  private answerServerRequest(request: JsonRpcObject): void {
    const endpoint = this.endpoint;
    if (!endpoint) return;
    let answer: JsonRpcObject;
    if (request.method === "ping") answer = { jsonrpc: "2.0", id: request.id, result: {} };
    else if (request.method === "roots/list") answer = { jsonrpc: "2.0", id: request.id, result: { roots: [] } };
    else answer = { jsonrpc: "2.0", id: request.id, error: { code: -32601, message: "Method not found" } };
    void this.post(endpoint, answer);
  }

  /** POSTs one message to the endpoint with the run's headers. Never throws. */
  private post(endpoint: URL, message: JsonRpcObject): Promise<BridgeResult> {
    const { serverName } = this.options;
    return new Promise<BridgeResult>((resolve) => {
      let settled = false;
      const finish = (result: BridgeResult): void => {
        if (settled) return;
        settled = true;
        resolve(result);
      };
      try {
        const body = Buffer.from(JSON.stringify(message), "utf8");
        const req = transportFor(endpoint).request(endpoint, {
          method: "POST",
          agent: false,
          headers: { ...this.options.headers, "content-type": "application/json", accept: "application/json, text/event-stream", "content-length": String(body.length) },
        });
        this.posts.add(req);
        req.on("close", () => this.posts.delete(req));
        req.setTimeout(this.options.idleTimeoutMs, () => {
          req.destroy();
          finish({ kind: "failure", failure: { kind: "timeout", name: serverName, timeoutMs: this.options.idleTimeoutMs } });
        });
        req.on("error", () => finish({ kind: "failure", failure: { kind: "unreachable", name: serverName } }));
        req.on("response", (res) => {
          try {
            const status = res.statusCode ?? 0;
            if (status >= 300 && status < 400) {
              res.resume();
              finish({ kind: "failure", failure: { kind: "redirect", name: serverName } });
              return;
            }
            if (status === 401 || status === 403) {
              res.resume();
              finish({ kind: "failure", failure: { kind: "gateway_credential_refused", name: serverName } });
              return;
            }
            if (status < 200 || status >= 300) {
              res.resume();
              finish({ kind: "failure", failure: { kind: "unreachable", name: serverName } });
              return;
            }
            const chunks: Buffer[] = [];
            let size = 0;
            res.on("error", () => finish({ kind: "accepted" }));
            res.on("data", (chunk: Buffer) => {
              size += chunk.length;
              if (size <= this.maxBufferBytes) chunks.push(chunk);
            });
            res.on("end", () => {
              if (size > this.maxBufferBytes) {
                finish({ kind: "failure", failure: { kind: "invalid_response", name: serverName } });
                return;
              }
              // 202 with an empty body is the normal answer; a JSON answer in the body is accepted as an inline answer.
              try {
                const text = Buffer.concat(chunks).toString("utf8").trim();
                if (text.startsWith("{")) {
                  const parsed = JSON.parse(text) as JsonRpcObject;
                  if (parsed.id !== undefined && ("result" in parsed || "error" in parsed)) {
                    finish({ kind: "answer", message: parsed });
                    return;
                  }
                }
              } catch {
                // Not an answer: the request was accepted and the answer comes on the stream.
              }
              finish({ kind: "accepted" });
            });
          } catch {
            finish({ kind: "failure", failure: { kind: "unreachable", name: serverName } });
          }
        });
        req.end(body);
      } catch {
        finish({ kind: "failure", failure: { kind: "unreachable", name: serverName } });
      }
    });
  }
}
