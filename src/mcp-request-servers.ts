/**
 * Per-query MCP servers supplied in the POST /v1/query request body (MVP-6755).
 *
 * reqlift's recon feature-inventory drives a browser by injecting a per-run
 * chrome-devtools MCP server for a single query:
 *
 *   mcpServers: {
 *     "chrome-devtools": {
 *       command: "npx",
 *       args: ["chrome-devtools-mcp", "--browser-url=http://recon-<id>:9222"]
 *     }
 *   }
 *
 * These request-supplied servers are merged at the LOWEST precedence in
 * `agent.ts` — the gateway's own webhook tool server (`agent-gateway-tools`) and
 * the persistent registry servers always overlay on top, so a request can never
 * override or shadow them. The matching `mcp__<name>__*` allowed-tool patterns
 * are added to the default tool set (callers that pass an explicit `allowedTools`
 * remain authoritative for their own list).
 *
 * Trust model: a per-query stdio server lets the (API-key authenticated) caller
 * spawn a process inside the gateway. This is the same trust level the caller
 * already holds via the agent's `Bash` tool, so the capability delta is small.
 * We still validate the shape and reject the reserved `agent-gateway-tools` name.
 */

/** The reserved server name the gateway uses for its own webhook tools. */
export const RESERVED_MCP_SERVER_NAME = "agent-gateway-tools";

/** A request-supplied MCP server map (server name → SDK server config). */
export type RequestMcpServers = Record<string, Record<string, unknown>>;

export interface RequestMcpServersValidation {
  /** Set when the supplied value is malformed (→ HTTP 400). */
  error?: string;
  /** The validated server map. `undefined` when none was supplied. */
  servers?: RequestMcpServers;
}

/**
 * Validate the request body's `mcpServers` field. Accepts an object whose
 * values are either a stdio spec (`{ command, args?, env? }`) or a
 * remote spec (`{ url, type? }`). Returns `{ error }` on any malformed entry,
 * `{ servers }` on success, or `{}` when nothing was supplied.
 */
export function validateRequestMcpServers(value: unknown): RequestMcpServersValidation {
  if (value === undefined || value === null) return {};
  if (typeof value !== "object" || Array.isArray(value)) {
    return { error: "mcpServers must be an object" };
  }

  const entries = Object.entries(value as Record<string, unknown>);
  const servers: RequestMcpServers = {};

  for (const [name, raw] of entries) {
    if (name === RESERVED_MCP_SERVER_NAME) {
      return {
        error: `mcpServers must not redefine the reserved server "${RESERVED_MCP_SERVER_NAME}"`,
      };
    }
    if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
      return { error: `mcpServers["${name}"] must be an object` };
    }
    const cfg = raw as Record<string, unknown>;
    const hasCommand = typeof cfg.command === "string";
    const hasUrl = typeof cfg.url === "string";
    if (!hasCommand && !hasUrl) {
      return {
        error: `mcpServers["${name}"] must define a string "command" (stdio) or "url" (sse/http)`,
      };
    }
    if (hasCommand) {
      if (
        cfg.args !== undefined &&
        !(Array.isArray(cfg.args) && cfg.args.every((a) => typeof a === "string"))
      ) {
        return { error: `mcpServers["${name}"].args must be an array of strings` };
      }
      if (
        cfg.env !== undefined &&
        (typeof cfg.env !== "object" || cfg.env === null || Array.isArray(cfg.env))
      ) {
        return { error: `mcpServers["${name}"].env must be a string→string object` };
      }
    }
    servers[name] = cfg;
  }

  return { servers };
}

/**
 * The `allowedTools` patterns that expose a request server's tools to the SDK,
 * e.g. `["mcp__chrome-devtools__*"]`. Mirrors `getMcpAllowedToolPatterns()` for
 * the persistent registry. Returns `[]` when no request servers were supplied.
 */
export function requestMcpAllowedToolPatterns(servers: RequestMcpServers | undefined): string[] {
  if (!servers) return [];
  return Object.keys(servers).map((name) => `mcp__${name}__*`);
}
