/**
 * A loopback MCP server (Streamable HTTP) that also publishes OAuth metadata
 * with a client-registration endpoint, so a runtime that reacts to a 401 by
 * starting a login has everything it needs to try. Every request is recorded,
 * and the registration, authorize and token endpoints are counted: the login
 * guard asserts those counters stay at zero.
 *
 * Refusal modes answer 401 with `WWW-Authenticate: Bearer resource_metadata=…`
 * (the header that points an OAuth-capable client at the metadata):
 * - "tools-call": only `tools/call` is refused (a token that expired mid-run);
 * - "initialize": every POST is refused, starting with `initialize`;
 * - "get-stream": only the GET event stream is refused.
 * Without a refusal the GET event stream answers 405 (the server offers none).
 */

import http, { type IncomingHttpHeaders, type ServerResponse } from "node:http";
import net, { type AddressInfo } from "node:net";

export type RefusalMode = "none" | "tools-call" | "initialize" | "get-stream";

export interface OAuthStubOptions {
  refuse?: RefusalMode;
  /** "sse" answers every JSON-RPC request with a one-event `text/event-stream`. */
  responseMode?: "json" | "sse";
  /** Size in bytes of the text in a `tools/call` result (default: a short text). */
  toolResultBytes?: number;
  /**
   * The first non-initialize POST that carries a session id answers 404 once
   * (an upstream that lost the session), so the client has to initialize again.
   */
  loseSessionOnce?: boolean;
}

export interface OAuthStubRequest {
  method: string;
  path: string;
  headers: IncomingHttpHeaders;
  /** JSON-RPC methods of a POST body (batch bodies list every method). */
  rpcMethods: string[];
  status: number;
}

export interface OAuthMcpStub {
  port: number;
  /** The MCP endpoint to register. */
  url: string;
  requests: OAuthStubRequest[];
  counters: { registration: number; authorize: number; token: number; metadata: number; mcp: number };
  /** The `Authorization` header of every request to the MCP endpoint. */
  authorizations: () => (string | undefined)[];
  /** Tool names this stub lists. None matches /auth/i. */
  toolNames: readonly string[];
  /** The text of a successful `tools/call` result begins with this. */
  toolResultPrefix: string;
  close: () => Promise<void>;
}

export const STUB_TOOL_NAME = "lookup_record";
export const STUB_TOOL_RESULT_PREFIX = "RECORD-7667-OK";
const MCP_PATH = "/mcp";

interface RpcMessage {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  params?: Record<string, unknown>;
}

export async function startOAuthMcpStub(options: OAuthStubOptions = {}): Promise<OAuthMcpStub> {
  const refuse = options.refuse ?? "none";
  const responseMode = options.responseMode ?? "json";
  const requests: OAuthStubRequest[] = [];
  const counters = { registration: 0, authorize: 0, token: 0, metadata: 0, mcp: 0 };
  const sockets = new Set<net.Socket>();
  const sessions = new Set<string>();
  let sessionSeq = 0;
  let sessionLost = false;
  let origin = "";

  const unauthorized = (res: ServerResponse): number => {
    res.writeHead(401, {
      "Content-Type": "application/json",
      "WWW-Authenticate": `Bearer resource_metadata="${origin}/.well-known/oauth-protected-resource${MCP_PATH}"`,
    });
    res.end(JSON.stringify({ error: "invalid_token" }));
    return 401;
  };

  const json = (res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): number => {
    const text = JSON.stringify(body);
    res.writeHead(status, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(text), ...headers });
    res.end(text);
    return status;
  };

  const answerRpc = (message: RpcMessage): unknown => {
    switch (message.method) {
      case "initialize":
        return {
          jsonrpc: "2.0",
          id: message.id,
          result: {
            protocolVersion: (message.params?.protocolVersion as string) || "2025-06-18",
            capabilities: { tools: {} },
            serverInfo: { name: "oauth-mcp-stub", version: "1.0.0" },
          },
        };
      case "tools/list":
        return {
          jsonrpc: "2.0",
          id: message.id,
          result: {
            tools: [
              {
                name: STUB_TOOL_NAME,
                description: "Look up a record by id.",
                inputSchema: { type: "object", properties: { id: { type: "string" } }, required: ["id"] },
              },
            ],
          },
        };
      case "tools/call": {
        const size = options.toolResultBytes ?? 0;
        const text = STUB_TOOL_RESULT_PREFIX + (size > 0 ? " " + "x".repeat(size) : "");
        return { jsonrpc: "2.0", id: message.id, result: { content: [{ type: "text", text }] } };
      }
      case "ping":
        return { jsonrpc: "2.0", id: message.id, result: {} };
      default:
        return { jsonrpc: "2.0", id: message.id, error: { code: -32601, message: "Method not found" } };
    }
  };

  const handleMcpPost = (body: string, headers: IncomingHttpHeaders, res: ServerResponse, record: OAuthStubRequest): number => {
    let parsed: RpcMessage | RpcMessage[];
    try {
      parsed = JSON.parse(body) as RpcMessage | RpcMessage[];
    } catch {
      return json(res, 400, { jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } });
    }
    const messages = Array.isArray(parsed) ? parsed : [parsed];
    record.rpcMethods = messages.map((m) => String(m.method ?? "(response)"));

    if (refuse === "initialize") return unauthorized(res);
    if (refuse === "tools-call" && messages.some((m) => m.method === "tools/call")) return unauthorized(res);

    const sessionHeader = headers["mcp-session-id"];
    const sessionId = typeof sessionHeader === "string" ? sessionHeader : undefined;
    const isInitialize = messages.some((m) => m.method === "initialize");
    if (!isInitialize && sessionId && options.loseSessionOnce && !sessionLost) {
      sessionLost = true;
      sessions.delete(sessionId);
      res.writeHead(404);
      res.end();
      return 404;
    }
    if (!isInitialize && sessionId && !sessions.has(sessionId)) {
      res.writeHead(404);
      res.end();
      return 404;
    }

    const extraHeaders: Record<string, string> = {};
    if (isInitialize) {
      const newSession = `stub-session-${++sessionSeq}`;
      sessions.add(newSession);
      extraHeaders["Mcp-Session-Id"] = newSession;
    }

    const answers = messages.filter((m) => m.method !== undefined && m.id !== undefined && m.id !== null).map(answerRpc);
    if (answers.length === 0) {
      res.writeHead(202, extraHeaders);
      res.end();
      return 202;
    }
    const payload = Array.isArray(parsed) ? answers : answers[0];
    if (responseMode === "sse") {
      res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", ...extraHeaders });
      res.end(`event: message\ndata: ${JSON.stringify(payload)}\n\n`);
      return 200;
    }
    return json(res, 200, payload, extraHeaders);
  };

  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://stub.invalid");
    const record: OAuthStubRequest = {
      method: req.method ?? "",
      path: url.pathname,
      headers: req.headers,
      rpcMethods: [],
      status: 0,
    };
    requests.push(record);
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf8");
      const p = url.pathname;
      if (p.startsWith("/.well-known/oauth-protected-resource")) {
        counters.metadata++;
        record.status = json(res, 200, { resource: `${origin}${MCP_PATH}`, authorization_servers: [origin] });
      } else if (p.startsWith("/.well-known/oauth-authorization-server") || p.startsWith("/.well-known/openid-configuration")) {
        counters.metadata++;
        record.status = json(res, 200, {
          issuer: origin,
          authorization_endpoint: `${origin}/authorize`,
          token_endpoint: `${origin}/token`,
          registration_endpoint: `${origin}/register`,
          response_types_supported: ["code"],
          grant_types_supported: ["authorization_code", "refresh_token"],
          code_challenge_methods_supported: ["S256"],
          token_endpoint_auth_methods_supported: ["none"],
        });
      } else if (p === "/register") {
        counters.registration++;
        // Answer like a real server so a runtime that registers carries on as far as it would.
        record.status = json(res, 201, {
          client_id: "stub-client-7667",
          client_id_issued_at: Math.floor(Date.now() / 1000),
          redirect_uris: [],
          token_endpoint_auth_method: "none",
        });
      } else if (p === "/authorize") {
        counters.authorize++;
        record.status = json(res, 400, { error: "invalid_request" });
      } else if (p === "/token") {
        counters.token++;
        record.status = json(res, 400, { error: "invalid_grant" });
      } else if (p === MCP_PATH) {
        counters.mcp++;
        if (req.method === "POST") {
          record.status = handleMcpPost(body, req.headers, res, record);
        } else if (req.method === "GET") {
          record.status = refuse === "get-stream" ? unauthorized(res) : json(res, 405, { error: "no event stream" });
        } else if (req.method === "DELETE") {
          const sessionHeader = req.headers["mcp-session-id"];
          if (typeof sessionHeader === "string") sessions.delete(sessionHeader);
          res.writeHead(204);
          res.end();
          record.status = 204;
        } else {
          record.status = json(res, 405, { error: "method not allowed" });
        }
      } else {
        record.status = json(res, 404, { error: "not found" });
      }
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
    port,
    url: `${origin}${MCP_PATH}`,
    requests,
    counters,
    authorizations: () => requests.filter((r) => r.path === MCP_PATH).map((r) => r.headers.authorization),
    toolNames: [STUB_TOOL_NAME],
    toolResultPrefix: STUB_TOOL_RESULT_PREFIX,
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}
