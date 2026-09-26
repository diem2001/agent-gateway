/**
 * For tests that mock the Claude Agent SDK: registered http MCP servers reach
 * the SDK as credential-relay URLs without headers, so these helpers play the
 * runtime's part. `touchHttpMcpServers` sends one JSON-RPC request through
 * every relay URL in the SDK options (while the run's relay tokens are valid),
 * and a recording upstream shows which headers arrived.
 */

import http, { type IncomingHttpHeaders } from "node:http";
import type { AddressInfo } from "node:net";

export interface UpstreamRequest {
  path: string;
  headers: IncomingHttpHeaders;
}

export interface RecordingUpstream {
  origin: string;
  requests: UpstreamRequest[];
  /** Headers of the requests that arrived on `path`. */
  headersAt: (path: string) => IncomingHttpHeaders[];
  close: () => Promise<void>;
}

/** Answers every POST with a JSON-RPC result and records its path and headers. */
export async function startRecordingUpstream(): Promise<RecordingUpstream> {
  const requests: UpstreamRequest[] = [];
  const server = http.createServer((req, res) => {
    requests.push({ path: req.url ?? "", headers: req.headers });
    req.resume();
    req.on("end", () => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { tools: [] } }));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const { port } = server.address() as AddressInfo;
  return {
    origin: `http://127.0.0.1:${port}`,
    requests,
    headersAt: (path) => requests.filter((r) => r.path === path).map((r) => r.headers),
    close: async () => {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

/** POSTs a `tools/list` request to `url` and resolves with the HTTP status. */
export function postJsonRpc(url: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" });
    const req = http.request(
      url,
      { method: "POST", agent: false, headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", "Content-Length": Buffer.byteLength(body) } },
      (res) => {
        res.resume();
        res.on("end", () => resolve(res.statusCode ?? 0));
      },
    );
    req.on("error", reject);
    req.end(body);
  });
}

/** The shape every registered http server has in the SDK options: a relay URL, no headers. */
export const RELAY_URL = /^http:\/\/127\.0\.0\.1:\d+\/mcp\/[A-Za-z0-9_-]{22}$/;

/** Sends one request through every relay URL in the SDK options; returns name → status. */
export async function touchHttpMcpServers(options: Record<string, unknown>): Promise<Record<string, number>> {
  const statuses: Record<string, number> = {};
  const servers = (options.mcpServers ?? {}) as Record<string, { type?: string; url?: string }>;
  for (const [name, config] of Object.entries(servers)) {
    if (config.type === "http" && typeof config.url === "string" && RELAY_URL.test(config.url)) statuses[name] = await postJsonRpc(config.url);
  }
  return statuses;
}
