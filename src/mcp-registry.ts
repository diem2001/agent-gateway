import { log } from "./logging.js";
import { createPersistentStore, hasValidOwners } from "./persistence.js";

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
  /** Optional per-user credential form and composition contract. */
  userCredentialSchema?: UserCredentialSchema;
  /**
   * When true, the server is attached to a run only if the run's
   * mcpCredentialOverrides contains an entry for it with a non-empty credential.
   * Default false: every existing server keeps its current behaviour.
   */
  requireUserCredentials?: boolean;
  /**
   * The API-key label that registered the server (MVP-7925). Only the owner may change or delete it. Never taken
   * from a request, never returned by the API. An entry without one is "ownerless": refused for every label and
   * left out of credential-bearing use until the operator mapping `MCP_SERVER_OWNERS` assigns its owner.
   */
  owner?: string;
  createdAt: string;
  updatedAt: string;
}

export interface CredentialField {
  /** Stable key used in templates, e.g. "email", "apiToken". */
  key: string;
  /** Human-readable label shown in the user form. */
  label: string;
  /** Input type for the user form. */
  type: "text" | "password" | "url" | "email";
  required: boolean;
  /** Optional help text rendered under the field. */
  description?: string;
  /** Optional placeholder rendered in the input. */
  placeholder?: string;
}

export interface CredentialOutput {
  /** Where the composed value is injected at runtime. */
  target: "headers" | "env";
  /** Header name or environment variable name. */
  outputKey: string;
  /** Plain `{field}` template or `basic:{userField}:{tokenField}`. */
  template: string;
}

export interface UserCredentialSchema {
  fields: CredentialField[];
  outputs: CredentialOutput[];
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

const store = createPersistentStore({
  area: "mcpServers",
  file: PERSIST_PATH,
  snapshot: () => Array.from(servers.values()),
  isValid: hasValidOwners,
});

/* ------------------------------------------------------------------ */
/*  Persistence                                                         */
/* ------------------------------------------------------------------ */

export function loadMcpServers(): void {
  const data = store.load() as McpServerDefinition[] | undefined;
  if (!data) return;
  for (const srv of data) {
    servers.set(srv.name, srv);
  }
  log("mcp", `Loaded ${servers.size} MCP server(s) from disk`);
}

/** The registry entries without an owner (registered before ownership), in registration order. */
export function getOwnerlessMcpServerNames(): string[] {
  return Array.from(servers.values())
    .filter((s) => s.owner === undefined)
    .map((s) => s.name);
}

/** Records the owner of an ownerless entry (operator mapping only); false when the entry is missing or already owned. */
export function setMcpServerOwner(name: string, owner: string): boolean {
  const def = servers.get(name);
  if (!def || def.owner !== undefined) return false;
  servers.set(name, { ...def, owner });
  persistMcpServers();
  return true;
}

/** Whether `label` registered the entry: a non-empty label equal to the stored owner. An ownerless entry has no owner. */
export function isMcpServerOwner(def: McpServerDefinition, label: string | undefined): boolean {
  return typeof label === "string" && label.length > 0 && def.owner !== undefined && def.owner === label;
}

/**
 * What an API response may do with each stored field (MVP-7936). `public` fields are returned as stored; `write-only`
 * fields (the credential maps) can be set and cleared through PUT but are never returned, to any caller; `internal`
 * fields never leave the gateway. A new field without a class here does not compile.
 */
const MCP_FIELD_CLASS: Record<keyof McpServerDefinition, "public" | "write-only" | "internal"> = {
  name: "public",
  description: "public",
  enabled: "public",
  type: "public",
  url: "public",
  headers: "write-only",
  command: "public",
  args: "public",
  env: "write-only",
  allowedToolsPattern: "public",
  userCredentialSchema: "public",
  requireUserCredentials: "public",
  owner: "internal",
  createdAt: "public",
  updatedAt: "public",
};

export type PublicMcpServer = Omit<McpServerDefinition, "owner" | "headers" | "env">;

/**
 * The entry as every API response shows it: an allowlist copy of the `public` fields. The owner label and the
 * stored `headers`/`env` are never revealed, and a key a legacy persisted file carries that no field names is not
 * copied either.
 */
export function publicMcpServer(def: McpServerDefinition): PublicMcpServer {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(def)) {
    if (MCP_FIELD_CLASS[key as keyof McpServerDefinition] === "public") out[key] = value;
  }
  return out as unknown as PublicMcpServer;
}

export interface StoredCredentialMaps {
  headers?: Record<string, string>;
  env?: Record<string, string>;
}

export type CredentialMapResolution =
  | { maps: StoredCredentialMaps }
  | { error: { code: "MCP_CREDENTIAL_MAP_INAPPLICABLE"; message: string } };

const credentialFamily = (type: McpServerDefinition["type"]) => (type === "stdio" ? "stdio" : "http");

/**
 * The credential maps an owner-authorized PUT stores. The maps are write-only, so a client that sends none must not
 * erase them: per map, omitted keeps the stored map, a non-empty map replaces it and `{}` clears it (no property
 * stored). Both maps are already validated as string maps. A change between the http/sse and stdio families with a
 * non-empty stored map whose property the body omits is refused, since the old map would silently stay behind on a
 * transport that does not use it or be dropped; the refusal names only the property and transport, never a value.
 */
export function resolveStoredCredentialMaps(
  existing: McpServerDefinition | undefined,
  body: { type: McpServerDefinition["type"]; headers?: Record<string, string>; env?: Record<string, string> },
): CredentialMapResolution {
  const familyChanged = existing !== undefined && credentialFamily(existing.type) !== credentialFamily(body.type);
  const maps: StoredCredentialMaps = {};
  for (const property of ["headers", "env"] as const) {
    const sent = body[property];
    const stored = existing?.[property];
    if (sent === undefined) {
      if (familyChanged && stored !== undefined && Object.keys(stored).length > 0) {
        return {
          error: {
            code: "MCP_CREDENTIAL_MAP_INAPPLICABLE",
            message: `The stored ${property} map does not apply to ${body.type} transport: send ${property}: {} to clear it or a new ${property} map to replace it`,
          },
        };
      }
      if (stored !== undefined) maps[property] = stored;
    } else if (Object.keys(sent).length > 0) {
      maps[property] = sent;
    }
  }
  return { maps };
}

/** Debounced atomic save (src/persistence.ts). */
function persistMcpServers(): void {
  store.schedule();
}

/** Save the MCP server registry now; false when the save failed or is suppressed. */
export function flushMcpServers(): boolean {
  return store.flush();
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
 * Build the mcpServers object for the SDK query options from the given
 * registry servers (default: every enabled server).
 * Merges registered MCP servers with the existing webhook-tools server.
 */
export function buildMcpServersForSdk(
  enabled: McpServerDefinition[] = getEnabledMcpServers(),
): Record<string, SdkMcpServerConfig> | null {
  if (enabled.length === 0) return null;

  const result: Record<string, SdkMcpServerConfig> = {};
  for (const srv of enabled) {
    result[srv.name] = toSdkConfig(srv);
  }
  return result;
}

/**
 * Get the allowedTools patterns for the given registry servers (default: every
 * enabled server). Returns patterns like ["mcp__jira__*", "mcp__confluence__*"].
 */
export function getMcpAllowedToolPatterns(servers: McpServerDefinition[] = getEnabledMcpServers()): string[] {
  return servers.map(
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

    // The health request carries the registered credential, so a redirect is never followed (MVP-7679).
    const res = await fetch(healthUrl, {
      signal: controller.signal,
      headers: def.headers,
      redirect: "manual",
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
