import { validateHeaderName, validateHeaderValue } from "node:http";
import type { McpServerDefinition, SdkMcpServerConfig } from "./mcp-registry.js";
import { getMcpServer } from "./mcp-registry.js";

export interface McpCredentialOverride {
  headers?: Record<string, string>;
  env?: Record<string, string>;
}

export type McpCredentialOverrides = Record<string, McpCredentialOverride>;

export type McpOverrideValidationErrorCode =
  | "MCP_OVERRIDE_INVALID"
  | "MCP_SERVER_DISABLED"
  | "MCP_SERVER_NOT_FOUND";

export interface McpOverrideValidationError {
  code: McpOverrideValidationErrorCode;
  message: string;
}

export function validateMcpCredentialOverrides(
  overrides: unknown,
): { overrides?: McpCredentialOverrides; error?: McpOverrideValidationError } {
  if (overrides === undefined) return {};
  if (!overrides || typeof overrides !== "object" || Array.isArray(overrides)) {
    return { error: { code: "MCP_OVERRIDE_INVALID", message: "mcpCredentialOverrides must be an object" } };
  }

  const typedOverrides = overrides as McpCredentialOverrides;
  for (const [serverName, override] of Object.entries(typedOverrides)) {
    if (!override || typeof override !== "object" || Array.isArray(override)) {
      return { error: { code: "MCP_OVERRIDE_INVALID", message: `${serverName} override must be an object` } };
    }
    const server = getMcpServer(serverName);
    if (!server) {
      return { error: { code: "MCP_SERVER_NOT_FOUND", message: `${serverName} is not registered` } };
    }
    if (!server.enabled) {
      return {
        error: {
          code: "MCP_SERVER_DISABLED",
          message: `${serverName} is registered but disabled; enable the server before sending overrides`,
        },
      };
    }
    const credentialError = credentialMapsError(override.headers, override.env, `${serverName}.`);
    if (credentialError) {
      return { error: { code: "MCP_OVERRIDE_INVALID", message: credentialError } };
    }
  }

  return { overrides: typedOverrides };
}

export function applyMcpCredentialOverrides(
  base: Record<string, SdkMcpServerConfig>,
  overrides?: McpCredentialOverrides,
): Record<string, SdkMcpServerConfig> {
  if (!overrides || Object.keys(overrides).length === 0) {
    return cloneMcpServerConfigs(base);
  }

  const merged = cloneMcpServerConfigs(base);
  for (const [serverName, override] of Object.entries(overrides)) {
    const baseConfig = merged[serverName];
    if (!baseConfig) continue;
    merged[serverName] = applyMcpCredentialOverride(baseConfig, override);
  }
  return merged;
}

export function applyMcpCredentialOverride(
  base: SdkMcpServerConfig,
  override: McpCredentialOverride,
): SdkMcpServerConfig {
  if ("type" in base && (base.type === "http" || base.type === "sse")) {
    return {
      ...base,
      headers: { ...(base.headers ?? {}), ...(override.headers ?? {}) },
    };
  }

  return {
    ...base,
    env: { ...(base.env ?? {}), ...(override.env ?? {}) },
  };
}

export function summarizeOverrideKeys(override: McpCredentialOverride): string[] {
  return [
    ...Object.keys(override.headers ?? {}).map((key) => `headers.${key}`),
    ...Object.keys(override.env ?? {}).map((key) => `env.${key}`),
  ];
}

function cloneMcpServerConfigs(
  configs: Record<string, SdkMcpServerConfig>,
): Record<string, SdkMcpServerConfig> {
  const cloned: Record<string, SdkMcpServerConfig> = {};
  for (const [name, config] of Object.entries(configs)) {
    if ("type" in config && (config.type === "http" || config.type === "sse")) {
      cloned[name] = { ...config, headers: config.headers ? { ...config.headers } : undefined };
    } else {
      cloned[name] = { ...config, args: config.args ? [...config.args] : undefined, env: config.env ? { ...config.env } : undefined };
    }
  }
  return cloned;
}

function isStringRecord(value: unknown): value is Record<string, string> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  return Object.values(value).every((entry) => typeof entry === "string");
}

function isSendableHeader(name: string, value: string): boolean {
  try {
    validateHeaderName(name);
    validateHeaderValue(name, value);
    return true;
  } catch {
    return false;
  }
}

/**
 * Checks `headers` and `env` credential maps: both must be string maps, every
 * header must be one Node can send (token name; no CR, LF, NUL or other invalid
 * character in the value), and env names and values must hold no NUL (a child
 * process cannot be started with one). Returns the error message, which never
 * echoes a value, or null. `label` prefixes the field name, e.g. "jira.".
 */
export function credentialMapsError(headers: unknown, env: unknown, label = ""): string | null {
  if (headers !== undefined) {
    if (!isStringRecord(headers)) return `${label}headers must be a string map`;
    for (const [name, value] of Object.entries(headers)) {
      if (!isSendableHeader(name, value)) return `${label}headers holds a name or value that cannot be sent as an HTTP header`;
    }
  }
  if (env !== undefined) {
    if (!isStringRecord(env)) return `${label}env must be a string map`;
    for (const [name, value] of Object.entries(env)) {
      if (name.length === 0 || name.includes("=") || name.includes("\0") || value.includes("\0")) {
        return `${label}env holds a name or value that cannot be passed to a process`;
      }
    }
  }
  return null;
}

/**
 * Whether a run's override entry carries the user credential a
 * `requireUserCredentials` server needs: at least one non-empty value for the
 * transport's target (`headers` for http/sse, `env` for stdio) and, when the
 * server has a `userCredentialSchema`, a non-empty value for every output key.
 */
export function hasUserCredential(def: McpServerDefinition, override: McpCredentialOverride | undefined): boolean {
  const target = def.type === "stdio" ? "env" : "headers";
  const values = override?.[target] ?? {};
  if (!Object.values(values).some((value) => value.length > 0)) return false;
  const required = (def.userCredentialSchema?.outputs ?? []).filter((output) => output.target === target);
  return required.every((output) => (values[output.outputKey] ?? "").length > 0);
}

/**
 * Splits the enabled registry servers for one run: a server with
 * `requireUserCredentials: true` is attached only when the run carries its user
 * credential (see `hasUserCredential`); every other server is attached as before.
 */
export function selectRegistryServersForRun(
  enabled: McpServerDefinition[],
  overrides: McpCredentialOverrides | undefined,
): { attached: McpServerDefinition[]; omitted: string[] } {
  const attached: McpServerDefinition[] = [];
  const omitted: string[] = [];
  for (const def of enabled) {
    if (def.requireUserCredentials === true && !hasUserCredential(def, overrides?.[def.name])) omitted.push(def.name);
    else attached.push(def);
  }
  return { attached, omitted };
}
