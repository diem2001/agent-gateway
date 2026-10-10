/**
 * The masking-stage budget of MVP-8207 (tool-mediation.ts): the known values a run masks with are built once per run, and
 * when their distinct values of 8 or more characters hold more than 262,144 UTF-8 bytes in total the refusal text of a
 * webhook tool and the summary of a raw tool's `tool_use` input fail closed instead of being masked. The limit is written
 * out here on purpose, not read from the source.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ToolDefinition } from "../tools.js";

const BUDGET = 262_144;
const WITHHELD = `TOOL_UNAVAILABLE: "test-tool" refused the request, and the gateway cannot show its answer safely. Tell your gateway administrator; retrying will not help.`;
const CONTEXT = { user_id: "u1", conversation_id: "c1", session_id: "s1", api_key_label: "test" };

let dir: string;
const saved = { ...process.env };
let logs: string[];

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "masking-budget-"));
  process.env.MCP_SERVERS_PERSIST_PATH = path.join(dir, "mcp-servers.json");
  process.env.TOOLS_PERSIST_PATH = path.join(dir, "tools.json");
  process.env.WORKSPACE_ROOT = path.join(dir, "ws");
  process.env.HOME = path.join(dir, "home");
  vi.resetModules();
  logs = [];
  vi.spyOn(console, "log").mockImplementation((...args) => {
    logs.push(args.map(String).join(" "));
  });
});
afterEach(async () => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  process.env = { ...saved };
  await new Promise((resolve) => setTimeout(resolve, 150));
  fs.rmSync(dir, { recursive: true, force: true });
});

/** A value of exactly `bytes` single-byte characters. */
const bytesOf = (bytes: number, fill = "a"): string => fill.repeat(bytes);

describe("maskingValuesWithinBudget", () => {
  it("accepts distinct values of 8 or more characters up to 262,144 bytes and refuses one byte more", async () => {
    const { maskingValuesWithinBudget, MASKING_OVER_BUDGET } = await import("../tool-mediation.js");
    expect(maskingValuesWithinBudget([bytesOf(BUDGET)])).toEqual([bytesOf(BUDGET)]);
    expect(maskingValuesWithinBudget([bytesOf(BUDGET + 1)])).toBe(MASKING_OVER_BUDGET);
    expect(maskingValuesWithinBudget([bytesOf(BUDGET / 2, "a"), bytesOf(BUDGET / 2, "b")])).toHaveLength(2);
    expect(maskingValuesWithinBudget([bytesOf(BUDGET / 2, "a"), bytesOf(BUDGET / 2 + 1, "b")])).toBe(MASKING_OVER_BUDGET);
  });

  it("counts UTF-8 bytes, not characters", async () => {
    const { maskingValuesWithinBudget, MASKING_OVER_BUDGET } = await import("../tool-mediation.js");
    expect(maskingValuesWithinBudget(["é".repeat(BUDGET / 2)])).toHaveLength(1);
    expect(maskingValuesWithinBudget(["é".repeat(BUDGET / 2) + "a"])).toBe(MASKING_OVER_BUDGET);
    expect(maskingValuesWithinBudget(["€".repeat(Math.floor(BUDGET / 3) + 1)])).toBe(MASKING_OVER_BUDGET);
  });

  it("counts a repeated value once and ignores values under 8 characters", async () => {
    const { maskingValuesWithinBudget } = await import("../tool-mediation.js");
    const half = bytesOf(BUDGET - 10);
    expect(maskingValuesWithinBudget([half, half, half, "short77"])).toHaveLength(4);
    const many = Array.from({ length: 100_000 }, () => "1234567");
    expect(maskingValuesWithinBudget(many)).toHaveLength(100_000);
  });
});

describe("runMaskingValues", () => {
  it("builds the list once per run, however many times it is asked", async () => {
    const { runMaskingValues } = await import("../tool-mediation.js");
    const extra = vi.fn(() => ["SYNTH-EXTRA-VALUE-8207"]);
    const values = runMaskingValues(extra);
    expect(extra).not.toHaveBeenCalled();
    const first = values();
    values();
    values();
    expect(extra).toHaveBeenCalledTimes(1);
    expect(first).toContain("SYNTH-EXTRA-VALUE-8207");
  });

  it("logs one line with the event name and a count, never a value, when the list is over budget", async () => {
    const { runMaskingValues, MASKING_OVER_BUDGET } = await import("../tool-mediation.js");
    const secret = `SYNTH-OVER-${bytesOf(BUDGET)}`;
    const values = runMaskingValues(() => [secret]);
    expect(values()).toBe(MASKING_OVER_BUDGET);
    expect(values()).toBe(MASKING_OVER_BUDGET);
    const lines = logs.filter((line) => line.includes("masking.budget_exceeded"));
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatch(/values=\d+/);
    expect(logs.join("\n")).not.toContain("SYNTH-OVER-");
  });

  it("a stored registry entry written by hand with an 8 MB header loads and puts the run over budget; the real shapes stay under", async () => {
    const now = new Date().toISOString();
    const huge = `Bearer ${bytesOf(8_000_000)}`;
    fs.writeFileSync(
      process.env.MCP_SERVERS_PERSIST_PATH!,
      JSON.stringify([{ name: "qabig", type: "http", url: "http://127.0.0.1:9/mcp", description: "", enabled: true, headers: { Authorization: huge }, owner: "reqlift", createdAt: now, updatedAt: now }]),
    );
    const { loadMcpServers, getMcpServer } = await import("../mcp-registry.js");
    loadMcpServers();
    expect(getMcpServer("qabig")).toBeDefined();
    const { runMaskingValues, MASKING_OVER_BUDGET } = await import("../tool-mediation.js");
    expect(runMaskingValues(() => [])()).toBe(MASKING_OVER_BUDGET);

    // The deployments the budget is sized for: a registry entry, reqlift's override wallet of about 20 KB, a bearer.
    vi.resetModules();
    fs.writeFileSync(
      process.env.MCP_SERVERS_PERSIST_PATH!,
      JSON.stringify([{ name: "jira", type: "http", url: "http://mcp-jira:3002/mcp", description: "", enabled: true, headers: { Authorization: "Basic SYNTH-JIRA-REGISTRY-8207" }, owner: "reqlift", createdAt: now, updatedAt: now }]),
    );
    const small = await import("../tool-mediation.js");
    (await import("../mcp-registry.js")).loadMcpServers();
    const wallet = Array.from({ length: 10 }, (_, i) => `Bearer ${bytesOf(2000, String.fromCharCode(97 + i))}`);
    const list = small.runMaskingValues(() => ["SYNTH-CLIENT-BEARER-8207", ...wallet])();
    expect(list).not.toBe(small.MASKING_OVER_BUDGET);
    expect(list as readonly string[]).toContain("Basic SYNTH-JIRA-REGISTRY-8207");
  });
});

describe("a refusing webhook tool over the budget", () => {
  const TOOL: ToolDefinition = { name: "test-tool", description: "d", input_schema: { type: "object", properties: {} }, webhook_url: "https://example.com/webhook", timeout_ms: 5000 };

  it("shows the fixed TOOL_UNAVAILABLE text and nothing of the upstream answer", async () => {
    const body = JSON.stringify({ message: "UPSTREAM-DETAIL-8207 with a plain message" });
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(body, { status: 422, headers: { "Content-Type": "application/json" } })));
    const { executeWebhook } = await import("../webhook.js");
    const { MASKING_OVER_BUDGET } = await import("../tool-mediation.js");
    const result = await executeWebhook(TOOL, "t1", "test-tool", {}, CONTEXT, undefined, MASKING_OVER_BUDGET);
    expect(result).toEqual({ output: WITHHELD, isError: true, code: "TOOL_UNAVAILABLE" });
  });

  it("describeFailure names the situation with one fixed code and text", async () => {
    const { describeFailure } = await import("../tool-mediation.js");
    expect(describeFailure({ kind: "refusal_withheld", name: "test-tool" })).toEqual({ code: "TOOL_UNAVAILABLE", message: WITHHELD });
  });

  it("within the budget the refusal is masked as before", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ message: "bad SYNTH-KNOWN-VALUE-8207 here" }), { status: 422, headers: { "Content-Type": "application/json" } })));
    const { executeWebhook } = await import("../webhook.js");
    const result = await executeWebhook(TOOL, "t1", "test-tool", {}, CONTEXT, undefined, ["SYNTH-KNOWN-VALUE-8207"]);
    expect(result).toEqual({ output: "The tool rejected the request (HTTP 422): bad [REDACTED] here", isError: true });
  });
});

describe("a raw tool's tool_use input over the budget", () => {
  const NAME = "present_choices";
  const SERVER = { type: "sdk", name: "agent-gateway-tools" };
  const def: ToolDefinition = {
    name: NAME,
    description: "d",
    input_schema: { type: "object", properties: { question: { type: "string" } }, required: ["question"] },
    webhook_url: "https://example.com/h",
    owner: "reqlift",
    stream_input: "raw",
  };

  it("falls back to the fixed placeholder, never the object and never unmasked text", async () => {
    const { buildStreamInputTable, streamedToolInput } = await import("../tool-use-input.js");
    const { MASKING_OVER_BUDGET } = await import("../tool-mediation.js");
    const table = buildStreamInputTable({ registeredTools: [def], callerLabel: "reqlift", mcpServers: { "agent-gateway-tools": SERVER }, webhookServer: SERVER, secretValues: () => MASKING_OVER_BUDGET });
    const out = streamedToolInput(`mcp__agent-gateway-tools__${NAME}`, { question: "a harmless question" }, "toolu_1", table, () => "SUMMARY");
    expect(out).toBe("[input withheld]");
  });
});
