import { getMcpServer } from "./mcp-registry.js";
import { log } from "./logging.js";

/**
 * Per-run MCP server configuration sent on POST /v1/query as the optional
 * top-level `mcpServers` field (sibling of `mcpCredentialOverrides`).
 *
 * SECURITY: accepting per-run stdio server configs means the caller can spawn
 * arbitrary processes inside the gateway container under bypassPermissions.
 * This is gated solely by the bearer API key — only fully-trusted backends may
 * hold one. Defense-in-depth: the executable must be on the
 * GATEWAY_PER_RUN_MCP_ALLOWED_COMMANDS allowlist (default: "npx"), and every
 * accepted spawn is audit-logged (name + command + args + env KEYS only).
 */
export interface PerRunMcpServerConfig {
  command: string;
  args: string[];
  env?: Record<string, string>;
}

export type PerRunMcpServers = Record<string, PerRunMcpServerConfig>;

export interface PerRunMcpServersValidationError {
  code: "MCP_SERVERS_INVALID";
  message: string;
}

/* Payload bounds (defense-in-depth against resource abuse). */
const MAX_SERVERS = 4;
const MAX_ARGS = 32;
const MAX_ENV_ENTRIES = 16;
const MAX_STRING_LENGTH = 2048;

/** Server names that would shadow gateway-internal or prototype machinery. */
const FORBIDDEN_NAMES = new Set(["__proto__", "constructor", "prototype", "agent-gateway-tools"]);

const DEFAULT_ALLOWED_COMMANDS = ["npx"];

function allowedCommands(): string[] {
  const raw = process.env.GATEWAY_PER_RUN_MCP_ALLOWED_COMMANDS;
  if (!raw || raw.trim().length === 0) return DEFAULT_ALLOWED_COMMANDS;
  return raw
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

function invalid(message: string): { error: PerRunMcpServersValidationError } {
  return { error: { code: "MCP_SERVERS_INVALID", message } };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Validate the per-run `mcpServers` request field.
 *
 * Accepted shape per server: `{ command: string, args: string[], env?: Record<string,string> }`
 * — nothing else expressible. Every violation returns 400 MCP_SERVERS_INVALID.
 *
 * Hardening (recorded plan-review decisions):
 * - prototype-pollution names (`__proto__`/`constructor`/`prototype`) rejected;
 *   the result map is built on `Object.create(null)`
 * - non-allowlisted commands rejected (GATEWAY_PER_RUN_MCP_ALLOWED_COMMANDS, default `npx`)
 * - names colliding with an enabled registry server are REJECTED — per-run config
 *   must never shadow a trusted registry server
 * - payload bounds: max 4 servers, 32 args, 16 env entries, 2048 chars per string
 */
export function validatePerRunMcpServers(
  input: unknown,
): { servers?: PerRunMcpServers; error?: PerRunMcpServersValidationError } {
  if (input === undefined) return {};
  if (!isPlainObject(input)) {
    return invalid("mcpServers must be an object map of server configs");
  }

  const names = Object.keys(input);
  if (names.length === 0) return {};
  if (names.length > MAX_SERVERS) {
    return invalid(`mcpServers allows at most ${MAX_SERVERS} servers`);
  }

  const servers: PerRunMcpServers = Object.create(null) as PerRunMcpServers;
  const allowed = allowedCommands();

  for (const name of names) {
    if (FORBIDDEN_NAMES.has(name)) {
      return invalid(`mcpServers server name "${name}" is not allowed`);
    }
    if (name.length === 0 || name.length > MAX_STRING_LENGTH) {
      return invalid("mcpServers server names must be non-empty strings of at most 2048 characters");
    }
    const registered = getMcpServer(name);
    if (registered && registered.enabled) {
      return invalid(
        `mcpServers name "${name}" collides with an enabled registry server; per-run servers must not shadow registry servers`,
      );
    }

    const config = (input as Record<string, unknown>)[name];
    if (!isPlainObject(config)) {
      return invalid(`mcpServers.${name} must be an object`);
    }
    for (const key of Object.keys(config)) {
      if (key !== "command" && key !== "args" && key !== "env") {
        return invalid(`mcpServers.${name}.${key} is not an allowed field (only command, args, env)`);
      }
    }

    const command = config.command;
    if (typeof command !== "string" || command.length === 0) {
      return invalid(`mcpServers.${name}.command must be a non-empty string`);
    }
    if (command.length > MAX_STRING_LENGTH) {
      return invalid(`mcpServers.${name}.command exceeds ${MAX_STRING_LENGTH} characters`);
    }
    if (!allowed.includes(command)) {
      return invalid(
        `mcpServers.${name}.command "${command}" is not allowlisted (allowed: ${allowed.join(", ")})`,
      );
    }

    const args = config.args;
    if (!Array.isArray(args) || !args.every((arg) => typeof arg === "string")) {
      return invalid(`mcpServers.${name}.args must be a string array`);
    }
    if (args.length > MAX_ARGS) {
      return invalid(`mcpServers.${name}.args allows at most ${MAX_ARGS} entries`);
    }
    if (args.some((arg) => arg.length > MAX_STRING_LENGTH)) {
      return invalid(`mcpServers.${name}.args entries must be at most ${MAX_STRING_LENGTH} characters`);
    }

    let env: Record<string, string> | undefined;
    if (config.env !== undefined) {
      if (!isPlainObject(config.env)) {
        return invalid(`mcpServers.${name}.env must be a string map`);
      }
      const entries = Object.entries(config.env);
      if (entries.length > MAX_ENV_ENTRIES) {
        return invalid(`mcpServers.${name}.env allows at most ${MAX_ENV_ENTRIES} entries`);
      }
      for (const [key, value] of entries) {
        if (typeof value !== "string") {
          return invalid(`mcpServers.${name}.env must be a string map`);
        }
        if (key.length === 0 || key.length > MAX_STRING_LENGTH || value.length > MAX_STRING_LENGTH) {
          return invalid(
            `mcpServers.${name}.env keys/values must be non-empty keys of at most ${MAX_STRING_LENGTH} characters`,
          );
        }
      }
      env = { ...(config.env as Record<string, string>) };
    }

    servers[name] = { command, args: [...(args as string[])], ...(env ? { env } : {}) };
  }

  return { servers };
}

/**
 * Merge validated per-run servers over the SDK mcpServers map and audit-log
 * every accepted spawn. Values of env vars are NEVER logged — keys only.
 *
 * Collisions with registry servers were already rejected by
 * validatePerRunMcpServers; this assignment can therefore only add new names.
 */
export function applyPerRunMcpServers(
  target: Record<string, unknown>,
  perRun?: PerRunMcpServers,
): void {
  if (!perRun) return;
  for (const [name, config] of Object.entries(perRun)) {
    target[name] = {
      command: config.command,
      args: [...config.args],
      ...(config.env ? { env: { ...config.env } } : {}),
    };
    log(
      "audit",
      `mcp.per-run.spawn serverName=${name} command=${config.command} args=[${config.args.join(" ")}] envKeys=[${Object.keys(config.env ?? {}).join(",")}]`,
    );
  }
}
