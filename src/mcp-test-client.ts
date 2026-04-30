import { applyMcpCredentialOverride, type McpCredentialOverride } from "./mcp-overrides.js";
import { toSdkConfig, type McpServerDefinition } from "./mcp-registry.js";

export type McpTestErrorCode =
  | "MCP_AUTH_FAILED"
  | "MCP_NETWORK_ERROR"
  | "MCP_TIMEOUT";

export class McpTestError extends Error {
  constructor(
    public readonly code: McpTestErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "McpTestError";
  }
}

export interface McpTestSuccess {
  ok: true;
  toolCount: number;
  tools: Array<{ name: string }>;
}

export async function testMcpServer(
  server: McpServerDefinition,
  override: McpCredentialOverride = {},
  timeoutMs = 10_000,
): Promise<McpTestSuccess> {
  const config = applyMcpCredentialOverride(toSdkConfig(server), override);

  if ("type" in config && (config.type === "http" || config.type === "sse")) {
    return testHttpMcpServer(config.url, config.headers ?? {}, timeoutMs);
  }

  throw new McpTestError(
    "MCP_NETWORK_ERROR",
    "stdio MCP credential test is not supported by this HTTP probe",
  );
}

async function testHttpMcpServer(
  url: string,
  headers: Record<string, string>,
  timeoutMs: number,
): Promise<McpTestSuccess> {
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
        id: "agent-gateway-mcp-test",
        method: "tools/list",
        params: {},
      }),
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (error) {
    const typedError = error as Error;
    if (typedError.name === "TimeoutError" || typedError.name === "AbortError") {
      throw new McpTestError("MCP_TIMEOUT", "MCP server did not respond before timeout");
    }
    throw new McpTestError("MCP_NETWORK_ERROR", typedError.message || "MCP transport failure");
  }

  if (response.status === 401 || response.status === 403) {
    throw new McpTestError("MCP_AUTH_FAILED", `upstream returned ${response.status}`);
  }
  if (!response.ok) {
    throw new McpTestError("MCP_NETWORK_ERROR", `upstream returned ${response.status}`);
  }

  const payload = await parseMcpResponse(response) as {
    result?: { tools?: Array<{ name?: string }> };
    tools?: Array<{ name?: string }>;
  } | null;
  const tools = (payload?.result?.tools ?? payload?.tools ?? [])
    .map((tool) => ({ name: String(tool.name ?? "") }))
    .filter((tool) => tool.name.length > 0);

  return { ok: true, toolCount: tools.length, tools };
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
