import { applyMcpCredentialOverride, type McpCredentialOverride } from "./mcp-overrides.js";
import { toSdkConfig, type McpServerDefinition } from "./mcp-registry.js";

export type McpCallErrorCode =
  | "MCP_AUTH_FAILED"
  | "MCP_NETWORK_ERROR"
  | "MCP_TIMEOUT";

export class McpCallError extends Error {
  constructor(
    public readonly code: McpCallErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "McpCallError";
  }
}

/**
 * Execute a registered MCP server's tool directly via JSON-RPC `tools/call`,
 * with no LLM turn. Returns the MCP `tools/call` result verbatim — a tool-level
 * `{ isError: true }` result is a NORMAL return value, NOT thrown. Only
 * gateway-level transport failures throw `McpCallError`.
 *
 * Per-call credential override is applied non-mutatingly (per-call clone) over
 * the registered server's config; it never mutates the registry entry.
 */
export async function callMcpTool(
  server: McpServerDefinition,
  toolName: string,
  args: Record<string, unknown>,
  override: McpCredentialOverride = {},
  timeoutMs = 10_000,
): Promise<unknown> {
  const config = applyMcpCredentialOverride(toSdkConfig(server), override);

  if ("type" in config && (config.type === "http" || config.type === "sse")) {
    return callHttpMcpTool(config.url, config.headers ?? {}, toolName, args, timeoutMs);
  }

  throw new McpCallError(
    "MCP_NETWORK_ERROR",
    "stdio MCP tool call is not supported by this HTTP client",
  );
}

async function callHttpMcpTool(
  url: string,
  headers: Record<string, string>,
  toolName: string,
  args: Record<string, unknown>,
  timeoutMs: number,
): Promise<unknown> {
  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: {
        ...headers,
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: "agent-gateway-mcp-call",
        method: "tools/call",
        params: { name: toolName, arguments: args },
      }),
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (error) {
    const typedError = error as Error;
    if (typedError.name === "TimeoutError" || typedError.name === "AbortError") {
      throw new McpCallError("MCP_TIMEOUT", "MCP server did not respond before timeout");
    }
    throw new McpCallError("MCP_NETWORK_ERROR", typedError.message || "MCP transport failure");
  }

  if (response.status === 401 || response.status === 403) {
    throw new McpCallError("MCP_AUTH_FAILED", `upstream returned ${response.status}`);
  }
  if (!response.ok) {
    throw new McpCallError("MCP_NETWORK_ERROR", `upstream returned ${response.status}`);
  }

  const payload = await parseMcpResponse(response) as {
    result?: unknown;
  } | null;

  // Return the JSON-RPC `result` member verbatim. A tool-level error result
  // ({ ..., isError: true }) is a normal return value, not a thrown error.
  return payload?.result;
}

async function parseMcpResponse(response: Response): Promise<unknown | null> {
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.includes("text/event-stream")) {
    return response.json().catch(() => null);
  }

  const text = await response.text();
  for (const line of text.split(/\r?\n/)) {
    if (!line.startsWith("data:")) continue;
    const payload = line.slice("data:".length).trim();
    if (!payload || payload === "[DONE]") continue;
    try {
      return JSON.parse(payload);
    } catch {
      return null;
    }
  }
  return null;
}
