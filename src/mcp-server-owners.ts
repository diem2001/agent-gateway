import { logAlways } from "./logging.js";
import { flushMcpServers, getMcpServer, getOwnerlessMcpServerNames, setMcpServerOwner } from "./mcp-registry.js";

/**
 * The operator mapping `MCP_SERVER_OWNERS="<name>:<label>,..."` (MVP-7925): at startup it assigns the owner of
 * registered MCP servers that have none (registered before ownership). It never transfers an owned server and no
 * request can use it; an entry nobody maps stays ownerless and unusable for credential-bearing runs.
 */

type OwnersReason = "entry without a server name or label" | "the same server name listed twice";

export class McpServerOwnersConfigError extends Error {
  readonly key = "MCP_SERVER_OWNERS";
  constructor(readonly reason: OwnersReason) {
    super(`MCP_SERVER_OWNERS: ${reason}`);
  }
  get logLine(): string {
    return `FATAL config key=${this.key} reason=${this.reason}`;
  }
}

export type OwnerMappingResult = "assigned" | "already_assigned" | "already_owned" | "unknown_label" | "not_registered";

/**
 * Parses the mapping: entries are separated by `,` and trimmed, empty entries are ignored, each entry is split at
 * its LAST `:` (so a name may contain `:`; a label cannot). An entry without a name or a label, or the same name
 * twice, is a configuration error: the gateway stops with one fixed line instead of guessing.
 */
export function parseMcpServerOwners(raw: string | undefined): Map<string, string> {
  const mapping = new Map<string, string>();
  for (const part of (raw ?? "").split(",")) {
    const entry = part.trim();
    if (entry.length === 0) continue;
    const colon = entry.lastIndexOf(":");
    const name = colon === -1 ? "" : entry.slice(0, colon).trim();
    const label = colon === -1 ? "" : entry.slice(colon + 1).trim();
    if (name.length === 0 || label.length === 0) throw new McpServerOwnersConfigError("entry without a server name or label");
    if (mapping.has(name)) throw new McpServerOwnersConfigError("the same server name listed twice");
    mapping.set(name, label);
  }
  return mapping;
}

/** Log-safe form of a server name or label: anything outside printable ASCII becomes `?`. */
function printable(value: string): string {
  return value.replace(/[^\x21-\x7e]/g, "?");
}

/**
 * Applies the mapping to the loaded registry, then writes the read-back lines (always, whatever the log level):
 * one `mcp.registry.owner_assigned` / `mcp.registry.owner_mapping` line per mapped name and the summary
 * `mcp.registry.ownerless count=<N> names=<list> saved=<true|false>`. `saved` is false only when an assignment could
 * not be written to the state file.
 */
export function applyMcpServerOwners(mapping: Map<string, string>, knownLabels: string[]): Map<string, OwnerMappingResult> {
  const results = new Map<string, OwnerMappingResult>();
  let assigned = 0;
  for (const [name, label] of mapping) {
    const def = getMcpServer(name);
    let result: OwnerMappingResult;
    if (!def) result = "not_registered";
    else if (def.owner === label) result = "already_assigned";
    else if (def.owner !== undefined) result = "already_owned";
    else if (!knownLabels.includes(label)) result = "unknown_label";
    else {
      setMcpServerOwner(name, label);
      assigned++;
      result = "assigned";
    }
    results.set(name, result);
    logAlways(
      "audit",
      result === "assigned"
        ? `mcp.registry.owner_assigned serverName=${printable(name)}`
        : `mcp.registry.owner_mapping serverName=${printable(name)} result=${result}`,
    );
  }
  const saved = assigned === 0 ? true : flushMcpServers();
  const ownerless = getOwnerlessMcpServerNames();
  logAlways("audit", `mcp.registry.ownerless count=${ownerless.length} names=${ownerless.map(printable).join(",")} saved=${saved}`);
  return results;
}
