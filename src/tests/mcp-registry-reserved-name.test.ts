/**
 * A registry entry stored under the gateway's reserved name `agent-gateway-tools` (created before MVP-8203) is kept on
 * disk and stays visible to its owner, but is never offered in a run: loading it logs one audit line naming only the
 * server, `getRunMcpServers()` (the run selection) and the defaults of the SDK builders leave it out whatever its
 * `enabled` value says, while `getEnabledMcpServers()` still lists it so its header and env values stay known secrets.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const RESERVED = "agent-gateway-tools";
const AUDIT_LINE = "[audit] mcp.registry.reserved_name_excluded serverName=agent-gateway-tools";
const NOW = "2026-09-01T00:00:00.000Z";

let tempDir = "";
let persistPath = "";
let logs: string[] = [];

beforeEach(() => {
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gateway-reserved-name-"));
  persistPath = path.join(tempDir, "mcp-servers.json");
  process.env.MCP_SERVERS_PERSIST_PATH = persistPath;
  logs = [];
  vi.spyOn(console, "log").mockImplementation((...args) => {
    logs.push(args.map(String).join(" "));
  });
  vi.resetModules();
});

afterEach(async () => {
  vi.restoreAllMocks();
  delete process.env.MCP_SERVERS_PERSIST_PATH;
  await new Promise((resolve) => setTimeout(resolve, 150));
  fs.rmSync(tempDir, { recursive: true, force: true });
});

function entry(name: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { name, description: "stored", enabled: true, type: "http", url: `http://${name}.example.test/mcp`, owner: "alpha", createdAt: NOW, updatedAt: NOW, ...extra };
}

async function loadSeeded(entries: Record<string, unknown>[]) {
  fs.writeFileSync(persistPath, JSON.stringify(entries, null, 2));
  const registry = await import("../mcp-registry.js");
  registry.loadMcpServers();
  return registry;
}

const auditLines = () => logs.filter((line) => line.includes("mcp.registry.reserved_name_excluded"));

describe("a stored entry named agent-gateway-tools is kept but never offered in a run (MVP-8203)", () => {
  it.each([
    ["enabled", true],
    ["disabled", false],
  ])("%s entry: one audit line per load, kept in the registry, left out of every run selection", async (_label, enabled) => {
    const registry = await loadSeeded([entry(RESERVED, { enabled, headers: { "X-Secret": "legacy-header-value" } }), entry("jira")]);

    // The builders' defaults: the behavior through exports that exist on the baseline.
    expect(Object.keys(registry.buildMcpServersForSdk() ?? {})).toEqual(["jira"]);
    expect(registry.getMcpAllowedToolPatterns()).toEqual(["mcp__jira__*"]);

    expect(auditLines()).toEqual([AUDIT_LINE]);
    expect(registry.getAllMcpServers().map((server) => server.name).sort()).toEqual([RESERVED, "jira"]);
    expect(registry.getMcpServer(RESERVED)?.owner).toBe("alpha");
    // The run selection itself.
    expect(registry.getRunMcpServers().map((server) => server.name)).toEqual(["jira"]);
  });

  it("the entry's own allowedToolsPattern is not offered either", async () => {
    const registry = await loadSeeded([entry(RESERVED, { allowedToolsPattern: "mcp__agent-gateway-tools__*" }), entry("jira")]);
    expect(registry.getMcpAllowedToolPatterns()).toEqual(["mcp__jira__*"]);
    expect(registry.getRunMcpServers().map((server) => server.name)).toEqual(["jira"]);
  });

  it("getEnabledMcpServers still lists the enabled entry, so its header and env values stay known secret values", async () => {
    const registry = await loadSeeded([entry(RESERVED, { headers: { "X-Secret": "legacy-header-value" } }), entry("jira")]);
    expect(registry.getEnabledMcpServers().map((server) => server.name).sort()).toEqual([RESERVED, "jira"]);
  });

  it("control: a file without the reserved name logs no such line and builds every enabled entry", async () => {
    const registry = await loadSeeded([entry("jira"), entry("alpha-tools")]);
    expect(auditLines()).toEqual([]);
    expect(Object.keys(registry.buildMcpServersForSdk() ?? {})).toEqual(["jira", "alpha-tools"]);
  });

  it("a second process start logs the line again, and the audit line names only the server", async () => {
    await loadSeeded([entry(RESERVED, { headers: { "X-Secret": "legacy-header-value" } })]);
    vi.resetModules();
    const again = await import("../mcp-registry.js");
    again.loadMcpServers();
    expect(auditLines()).toEqual([AUDIT_LINE, AUDIT_LINE]);
    expect(logs.join("\n")).not.toContain("legacy-header-value");
  });
});

/**
 * Every stored entry whose name begins with `agent-gateway-tools` gets the exact name's treatment (MVP-8235): kept, one
 * audit line per entry per load, never in a run selection whatever `enabled` says, still known to the secret masking.
 */
describe("a stored entry named agent-gateway-tools* is kept but never offered in a run (MVP-8235)", () => {
  const PREFIXED = ["agent-gateway-tools", "agent-gateway-tools__x", "agent-gateway-tools_"];
  const lineOf = (name: string) => `[audit] mcp.registry.reserved_name_excluded serverName=${name}`;
  const seed = () => [
    entry("agent-gateway-tools"),
    entry("agent-gateway-tools__x", { headers: { "X-Secret": "prefixed-header-value" } }),
    entry("agent-gateway-tools_", { enabled: false }),
    entry("beta-docs"),
  ];

  it("one whole audit line per reserved entry per load, in file order, naming only the server", async () => {
    await loadSeeded(seed());
    expect(auditLines()).toEqual(PREFIXED.map(lineOf));
    expect(logs.join("\n")).not.toContain("prefixed-header-value");
  });

  it("the run selection excludes all three reserved entries, whatever enabled says, and keeps the ordinary one", async () => {
    const registry = await loadSeeded(seed());
    expect(registry.getRunMcpServers().map((server) => server.name)).toEqual(["beta-docs"]);
    expect(registry.getAllMcpServers().map((server) => server.name).sort()).toEqual([...PREFIXED, "beta-docs"].sort());
  });

  it("the defaults of the SDK builders hold no reserved key or pattern", async () => {
    const registry = await loadSeeded(seed());
    expect(Object.keys(registry.buildMcpServersForSdk() ?? {})).toEqual(["beta-docs"]);
    expect(registry.getMcpAllowedToolPatterns()).toEqual(["mcp__beta-docs__*"]);
  });

  it("getEnabledMcpServers still lists the enabled reserved entries, so their header values stay known secret values", async () => {
    const registry = await loadSeeded(seed());
    expect(registry.getEnabledMcpServers().map((server) => server.name).sort()).toEqual(["agent-gateway-tools", "agent-gateway-tools__x", "beta-docs"]);
  });

  it("a second load repeats the lines", async () => {
    await loadSeeded(seed());
    vi.resetModules();
    const again = await import("../mcp-registry.js");
    again.loadMcpServers();
    expect(auditLines()).toEqual([...PREFIXED, ...PREFIXED].map(lineOf));
  });

  it("control: a file with only ordinary and case-variant names logs no such line and builds every enabled entry", async () => {
    const registry = await loadSeeded([entry("beta-docs"), entry("agent-gateway-tool"), entry("Agent-Gateway-Tools_x")]);
    expect(auditLines()).toEqual([]);
    expect(Object.keys(registry.buildMcpServersForSdk() ?? {})).toEqual(["beta-docs", "agent-gateway-tool", "Agent-Gateway-Tools_x"]);
    expect(registry.getRunMcpServers().map((server) => server.name)).toEqual(["beta-docs", "agent-gateway-tool", "Agent-Gateway-Tools_x"]);
  });
});
