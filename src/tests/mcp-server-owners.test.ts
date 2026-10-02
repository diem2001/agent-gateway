/**
 * The operator mapping MCP_SERVER_OWNERS (MVP-7925): parsing, the five per-name outcomes, the read-back lines and
 * the state file. A process that starts with a mapping is covered by mcp-server-owner-process.test.ts.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

let tempDir = "";
let persistPath = "";
let errors: string[] = [];

beforeEach(() => {
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gateway-owners-"));
  persistPath = path.join(tempDir, "mcp-servers.json");
  process.env.MCP_SERVERS_PERSIST_PATH = persistPath;
  errors = [];
  vi.spyOn(console, "error").mockImplementation((...args) => {
    errors.push(args.map(String).join(" "));
  });
  vi.resetModules();
});

afterEach(async () => {
  vi.restoreAllMocks();
  delete process.env.MCP_SERVERS_PERSIST_PATH;
  await new Promise((resolve) => setTimeout(resolve, 150));
  fs.rmSync(tempDir, { recursive: true, force: true });
});

const entry = (name: string, owner?: string) => ({
  name,
  description: "",
  enabled: true,
  type: "http",
  url: `https://${name}.example/mcp`,
  ...(owner ? { owner } : {}),
  createdAt: "2026-09-01T00:00:00.000Z",
  updatedAt: "2026-09-01T00:00:00.000Z",
});

async function load(entries: unknown[]) {
  fs.writeFileSync(persistPath, JSON.stringify(entries));
  const registry = await import("../mcp-registry.js");
  registry.loadMcpServers();
  return registry;
}

describe("parseMcpServerOwners", () => {
  it("trims entries, ignores empty ones and splits at the last colon", async () => {
    const { parseMcpServerOwners } = await import("../mcp-server-owners.js");
    expect([...parseMcpServerOwners("  jira : reqlift , ,confluence:diemcrm,,").entries()]).toEqual([
      ["jira", "reqlift"],
      ["confluence", "diemcrm"],
    ]);
    expect([...parseMcpServerOwners("team:jira:reqlift").entries()]).toEqual([["team:jira", "reqlift"]]);
    expect(parseMcpServerOwners(undefined).size).toBe(0);
    expect(parseMcpServerOwners("").size).toBe(0);
    expect(parseMcpServerOwners(" , ").size).toBe(0);
  });

  it.each([
    ["jira", "entry without a server name or label"],
    ["jira:", "entry without a server name or label"],
    [":reqlift", "entry without a server name or label"],
    ["jira: ", "entry without a server name or label"],
    ["jira:reqlift,jira:other", "the same server name listed twice"],
    ["jira:reqlift,jira:reqlift", "the same server name listed twice"],
  ])("%j is a fatal configuration error with one fixed line", async (raw, reason) => {
    const { McpServerOwnersConfigError, parseMcpServerOwners } = await import("../mcp-server-owners.js");
    let thrown: unknown;
    try {
      parseMcpServerOwners(raw);
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(McpServerOwnersConfigError);
    expect((thrown as { logLine: string }).logLine).toBe(`FATAL config key=MCP_SERVER_OWNERS reason=${reason}`);
  });
});

describe("applyMcpServerOwners", () => {
  it("assigns the owner of ownerless entries only, keeps the rest and writes the read-back", async () => {
    const { getMcpServer, getOwnerlessMcpServerNames } = await load([
      entry("jira"),
      entry("owned", "diemcrm"),
      entry("same", "reqlift"),
      entry("left"),
    ]);
    const { applyMcpServerOwners, parseMcpServerOwners } = await import("../mcp-server-owners.js");

    const results = applyMcpServerOwners(
      parseMcpServerOwners("jira:reqlift,owned:reqlift,same:reqlift,missing:reqlift,left:ghost"),
      ["reqlift", "diemcrm"],
    );

    expect([...results.entries()]).toEqual([
      ["jira", "assigned"],
      ["owned", "already_owned"],
      ["same", "already_assigned"],
      ["missing", "not_registered"],
      ["left", "unknown_label"],
    ]);
    expect(getMcpServer("jira")?.owner).toBe("reqlift");
    expect(getMcpServer("owned")?.owner).toBe("diemcrm");
    expect(getMcpServer("same")?.owner).toBe("reqlift");
    expect(getMcpServer("left")?.owner).toBeUndefined();
    expect(getOwnerlessMcpServerNames()).toEqual(["left"]);

    expect(errors).toEqual([
      "[audit] mcp.registry.owner_assigned serverName=jira",
      "[audit] mcp.registry.owner_mapping serverName=owned result=already_owned",
      "[audit] mcp.registry.owner_mapping serverName=same result=already_assigned",
      "[audit] mcp.registry.owner_mapping serverName=missing result=not_registered",
      "[audit] mcp.registry.owner_mapping serverName=left result=unknown_label",
      "[audit] mcp.registry.ownerless count=1 names=left saved=true",
    ]);

    // The assignment is already on disk (flushed), and nothing else changed.
    const stored = JSON.parse(fs.readFileSync(persistPath, "utf-8")) as Array<{ name: string; owner?: string; updatedAt: string }>;
    expect(stored.map((s) => [s.name, s.owner])).toEqual([
      ["jira", "reqlift"],
      ["owned", "diemcrm"],
      ["same", "reqlift"],
      ["left", undefined],
    ]);
    expect(stored.every((s) => s.updatedAt === "2026-09-01T00:00:00.000Z")).toBe(true);
  });

  it("writes the summary with zero ownerless entries and without a mapping", async () => {
    await load([entry("jira", "reqlift")]);
    const { applyMcpServerOwners, parseMcpServerOwners } = await import("../mcp-server-owners.js");
    applyMcpServerOwners(parseMcpServerOwners(undefined), ["reqlift"]);
    expect(errors).toEqual(["[audit] mcp.registry.ownerless count=0 names= saved=true"]);
  });

  it("a mapped name is applied again as already_assigned and the summary shows zero", async () => {
    await load([entry("jira")]);
    const { applyMcpServerOwners, parseMcpServerOwners } = await import("../mcp-server-owners.js");
    applyMcpServerOwners(parseMcpServerOwners("jira:reqlift"), ["reqlift"]);
    errors.length = 0;
    const second = applyMcpServerOwners(parseMcpServerOwners("jira:reqlift"), ["reqlift"]);
    expect([...second.values()]).toEqual(["already_assigned"]);
    expect(errors).toEqual([
      "[audit] mcp.registry.owner_mapping serverName=jira result=already_assigned",
      "[audit] mcp.registry.ownerless count=0 names= saved=true",
    ]);
  });

  it("reports saved=false when the assignment could not be written, and keeps the entry usable in memory", async () => {
    await load([entry("jira")]);
    // The state file's directory cannot be written: the atomic save fails.
    fs.chmodSync(tempDir, 0o500);
    try {
      const { applyMcpServerOwners, parseMcpServerOwners } = await import("../mcp-server-owners.js");
      const { getMcpServer } = await import("../mcp-registry.js");
      applyMcpServerOwners(parseMcpServerOwners("jira:reqlift"), ["reqlift"]);
      expect(errors.at(-1)).toBe("[audit] mcp.registry.ownerless count=0 names= saved=false");
      expect(getMcpServer("jira")?.owner).toBe("reqlift");
    } finally {
      fs.chmodSync(tempDir, 0o700);
    }
  });

  it("lists every ownerless name and makes control characters printable", async () => {
    await load([entry("a"), entry("b c")]);
    const { applyMcpServerOwners, parseMcpServerOwners } = await import("../mcp-server-owners.js");
    applyMcpServerOwners(parseMcpServerOwners(undefined), ["reqlift"]);
    expect(errors).toEqual(["[audit] mcp.registry.ownerless count=2 names=a,b?c saved=true"]);
  });
});
