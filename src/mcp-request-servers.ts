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
 * spawn a process inside the run's sandbox. We validate the shape on the trusted
 * side and reject the reserved `agent-gateway-tools` name and every registered
 * server name (MVP-7679). Credentials of request servers belong in `env` or
 * `headers` only: the `args` and the `url` of a server that is not relayed are
 * readable by the agent.
 */
import { credentialMapsError } from "./mcp-overrides.js";
import { WEBHOOK_SERVER_NAME } from "./tool-grant.js";

/** The reserved server name the gateway uses for its own webhook tools (one definition, shared with the registry and the run). */
export const RESERVED_MCP_SERVER_NAME = WEBHOOK_SERVER_NAME;

/** The same name rule as for registry servers. */
const MCP_SERVER_NAME_RULE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$/;

/** A request-supplied MCP server map (server name → SDK server config). */
export type RequestMcpServers = Record<string, Record<string, unknown>>;

export interface RequestMcpServersValidation {
  /** Set when the supplied value is malformed (→ HTTP 400). */
  error?: string;
  /** Set (with `error`) when the name belongs to a registered server (→ HTTP 400 `MCP_SERVER_NAME_CONFLICT`). */
  code?: "MCP_SERVER_NAME_CONFLICT";
  /** The validated, normalized server map. `undefined` when none was supplied. */
  servers?: RequestMcpServers;
}

/** A caller-supplied name as it may appear in an error text: bounded and printable. */
function shownName(name: string): string {
  return name.length <= 40 && /^[\x21-\x7e]+$/.test(name) ? name : "(invalid name)";
}

/**
 * Validate the request body's `mcpServers` field (MVP-7679: on the trusted side, before any run starts).
 * Accepts an object whose values are either a stdio spec (`{ command, args?, env? }`) or a remote spec
 * (`{ url, type?, headers? }`; a `url` without `type` is `http`, any other `type` than `http` or `sse` is refused).
 * The map that comes back holds only those fields, so nothing else (a `headersHelper`, a working directory, a
 * second transport) reaches the runtime. A name that equals any registered server (enabled, disabled or left out
 * of the run) is refused, so a caller-supplied server can never inherit a grant written for a registry name.
 * `registeredNames` are the registry's server names. Returns `{ error }` on any malformed entry, `{ servers }`
 * on success, or `{}` when nothing was supplied.
 */
export function validateRequestMcpServers(value: unknown, registeredNames: readonly string[] = []): RequestMcpServersValidation {
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
    if (!MCP_SERVER_NAME_RULE.test(name)) {
      return { error: `mcpServers name "${shownName(name)}" must be 1-32 letters, digits, '-' or '_', starting with a letter or digit` };
    }
    if (registeredNames.includes(name)) {
      return {
        code: "MCP_SERVER_NAME_CONFLICT",
        error: `mcpServers["${name}"] has the name of a registered MCP server; use another name or the registered server`,
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
    if (hasCommand && hasUrl) {
      return { error: `mcpServers["${name}"] must define either "command" or "url", not both` };
    }
    if (hasCommand) {
      if (cfg.type !== undefined) {
        return { error: `mcpServers["${name}"] defines a "command", so it must not set "type"` };
      }
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
      const envError = credentialMapsError(undefined, cfg.env, `mcpServers["${name}"].`);
      if (envError) return { error: envError };
      servers[name] = {
        command: cfg.command,
        ...(cfg.args !== undefined ? { args: cfg.args } : {}),
        ...(cfg.env !== undefined ? { env: cfg.env } : {}),
      };
      continue;
    }
    if (cfg.type !== undefined && cfg.type !== "http" && cfg.type !== "sse") {
      return { error: `mcpServers["${name}"].type must be "http" or "sse"` };
    }
    let url: URL;
    try {
      url = new URL(cfg.url as string);
    } catch {
      return { error: `mcpServers["${name}"].url must be an http or https URL` };
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      return { error: `mcpServers["${name}"].url must be an http or https URL` };
    }
    const headerError = credentialMapsError(cfg.headers, undefined, `mcpServers["${name}"].`);
    if (headerError) return { error: headerError };
    servers[name] = {
      type: cfg.type === "sse" ? "sse" : "http",
      url: cfg.url,
      ...(cfg.headers !== undefined ? { headers: cfg.headers } : {}),
    };
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
