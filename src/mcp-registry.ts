import fs from "node:fs";
import path from "node:path";
import { log } from "./logging.js";

/* ------------------------------------------------------------------ */
/*  Types                                                               */
/* ------------------------------------------------------------------ */

export interface McpServerDefinition {
  name: string;
  description: string;
  enabled: boolean;
  /** Transport type. "http" for Streamable HTTP, "sse" for SSE, "stdio" for subprocess. */
  type: "http" | "sse" | "stdio";
  /** URL for http/sse transport. */
  url?: string;
  /** HTTP headers for http/sse transport (e.g. Authorization). */
  headers?: Record<string, string>;
  /** Command for stdio transport (e.g. "node"). */
  command?: string;
  /** Args for stdio transport (e.g. ["dist/index.js"]). */
  args?: string[];
  /** Environment variables for stdio transport. */
  env?: Record<string, string>;
  /** Tool name prefix pattern for allowedTools (e.g. "mcp__jira__*"). Auto-generated if omitted. */
  allowedToolsPattern?: string;
  createdAt: string;
  updatedAt: string;
}

/** Config format passed to the Claude Agent SDK's options.mcpServers. */
export type SdkMcpServerConfig =
  | { type: "http"; url: string; headers?: Record<string, string> }
  | { type: "sse"; url: string; headers?: Record<string, string> }
  | { command: string; args?: string[]; env?: Record<string, string> };

/* ------------------------------------------------------------------ */
/*  State                                                               */
/* ------------------------------------------------------------------ */

const servers = new Map<string, McpServerDefinition>();

const PERSIST_PATH =
  process.env.MCP_SERVERS_PERSIST_PATH || "./data/mcp-servers.json";

let persistTimer: ReturnType<typeof setTimeout> | null = null;

/* ------------------------------------------------------------------ */
/*  Persistence                                                         */
/* ------------------------------------------------------------------ */

export function loadMcpServers(): void {
  try {
    if (fs.existsSync(PERSIST_PATH)) {
      const raw = fs.readFileSync(PERSIST_PATH, "utf-8");
      const data: McpServerDefinition[] = JSON.parse(raw);
      for (const srv of data) {
        servers.set(srv.name, srv);
      }
      log("mcp", `Loaded ${servers.size} MCP server(s) from disk`);
    }
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    log("mcp", `Failed to load MCP servers: ${msg}`);
  }
}

function persistMcpServers(): void {
  if (persistTimer) return;
  persistTimer = setTimeout(() => {
    persistTimer = null;
    try {
      const dir = path.dirname(PERSIST_PATH);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      const data = Array.from(servers.values());
      fs.writeFileSync(PERSIST_PATH, JSON.stringify(data, null, 2));
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      log("mcp", `Failed to persist MCP servers: ${msg}`);
    }
  }, 100);
}

/* ------------------------------------------------------------------ */
/*  CRUD                                                                */
/* ------------------------------------------------------------------ */

export function registerMcpServer(def: McpServerDefinition): boolean {
  const isNew = !servers.has(def.name);
  servers.set(def.name, def);
  persistMcpServers();
  log("mcp", `${isNew ? "Registered" : "Updated"} MCP server: ${def.name} (${def.type})`);
  return isNew;
}

export function getMcpServer(name: string): McpServerDefinition | undefined {
  return servers.get(name);
}

export function getAllMcpServers(): McpServerDefinition[] {
  return Array.from(servers.values());
}

export function getEnabledMcpServers(): McpServerDefinition[] {
  return Array.from(servers.values()).filter((s) => s.enabled);
}

export function deleteMcpServer(name: string): boolean {
  const deleted = servers.delete(name);
  if (deleted) {
    persistMcpServers();
    log("mcp", `Deleted MCP server: ${name}`);
  }
  return deleted;
}

/* ------------------------------------------------------------------ */
/*  SDK config conversion                                               */
/* ------------------------------------------------------------------ */

/**
 * Convert a registry entry to the format the Claude Agent SDK expects
 * in options.mcpServers.
 */
export function toSdkConfig(def: McpServerDefinition): SdkMcpServerConfig {
  if (def.type === "http") {
    return {
      type: "http",
      url: def.url!,
      ...(def.headers && Object.keys(def.headers).length > 0 ? { headers: def.headers } : {}),
    };
  }
  if (def.type === "sse") {
    return {
      type: "sse",
      url: def.url!,
      ...(def.headers && Object.keys(def.headers).length > 0 ? { headers: def.headers } : {}),
    };
  }
  // stdio
  return {
    command: def.command!,
    ...(def.args?.length ? { args: def.args } : {}),
    ...(def.env && Object.keys(def.env).length > 0 ? { env: def.env } : {}),
  };
}

/**
 * Build the mcpServers object for the SDK query options.
 * Merges registered MCP servers with the existing webhook-tools server.
 */
export function buildMcpServersForSdk(): Record<string, SdkMcpServerConfig> | null {
  const enabled = getEnabledMcpServers();
  if (enabled.length === 0) return null;

  const result: Record<string, SdkMcpServerConfig> = {};
  for (const srv of enabled) {
    result[srv.name] = toSdkConfig(srv);
  }
  return result;
}

/**
 * Get the allowedTools patterns for all enabled MCP servers.
 * Returns patterns like ["mcp__jira__*", "mcp__confluence__*"].
 */
export function getMcpAllowedToolPatterns(): string[] {
  return getEnabledMcpServers().map(
    (srv) => srv.allowedToolsPattern || `mcp__${srv.name}__*`,
  );
}

/* ------------------------------------------------------------------ */
/*  Health check                                                        */
/* ------------------------------------------------------------------ */

/**
 * Check if an HTTP/SSE MCP server is reachable.
 * For stdio servers, returns "unknown" (no way to check without spawning).
 */
export async function checkMcpServerHealth(
  def: McpServerDefinition,
): Promise<{ status: "ok" | "error" | "unknown"; detail?: string }> {
  if (def.type === "stdio") {
    return { status: "unknown", detail: "stdio servers cannot be health-checked remotely" };
  }

  try {
    // Try the /health endpoint convention (same host, different path)
    const mcpUrl = new URL(def.url!);
    const healthUrl = `${mcpUrl.protocol}//${mcpUrl.host}/health`;

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);

    const res = await fetch(healthUrl, {
      signal: controller.signal,
      headers: def.headers,
    });
    clearTimeout(timeout);

    if (res.ok) {
      const body = await res.json().catch(() => null);
      return { status: "ok", detail: body ? JSON.stringify(body) : undefined };
    }
    return { status: "error", detail: `HTTP ${res.status}` };
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    return { status: "error", detail: msg };
  }
}
