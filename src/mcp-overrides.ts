import type { SdkMcpServerConfig } from "./mcp-registry.js";
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
    if (override.headers !== undefined && !isStringRecord(override.headers)) {
      return { error: { code: "MCP_OVERRIDE_INVALID", message: `${serverName}.headers must be a string map` } };
    }
    if (override.env !== undefined && !isStringRecord(override.env)) {
      return { error: { code: "MCP_OVERRIDE_INVALID", message: `${serverName}.env must be a string map` } };
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
