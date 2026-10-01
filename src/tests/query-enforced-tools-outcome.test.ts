/**
 * The per-run enforced tool set through the REAL query.ts + retry.ts + agent.ts
 * path (MVP-7637), with ONLY the Claude Agent SDK boundary mocked, so the exact
 * SDK options and the NDJSON stream can be asserted. The refusal itself is
 * proven against the real runtime in tool-policy-process.test.ts.
 *
 * Expected values are written out here. One SDK mock per file.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

interface Attempt {
  messages: Record<string, unknown>[];
}

let script: Attempt[] = [];
let capturedOptions: Record<string, unknown>[] = [];
let sdkServers: { name: string; tools: { name: string }[] }[] = [];
let tempDir: string;

const INIT = { type: "system", subtype: "init", claude_code_version: "2.0.77", skills: [] };
const ANSWER: Attempt = {
  messages: [
    INIT,
    { type: "stream_event", event: { type: "content_block_delta", delta: { type: "text_delta", text: "fine" } } },
    { type: "assistant", message: { content: [{ type: "text", text: "fine" }] } },
    { type: "result", subtype: "success", is_error: false, result: "fine", session_id: "sdk-s", usage: { input_tokens: 1, output_tokens: 1 }, total_cost_usd: 0 },
  ],
};
const RATE_LIMITED: Attempt = {
  messages: [
    INIT,
    { type: "assistant", error: "rate_limit", message: { model: "<synthetic>", content: [{ type: "text", text: 'API Error: 429 {"type":"error","error":{"type":"rate_limit_error","message":"slow"}}' }] } },
    { type: "result", subtype: "success", is_error: true, result: "API Error: 429", session_id: "sdk-failed", usage: {}, total_cost_usd: 0 },
  ],
};

beforeEach(() => {
  vi.resetModules();
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gateway-enforced-tools-"));
  process.env.TOOLS_PERSIST_PATH = path.join(tempDir, "tools.json");
  process.env.MCP_SERVERS_PERSIST_PATH = path.join(tempDir, "mcp-servers.json");
  script = [];
  capturedOptions = [];
  sdkServers = [];
  vi.doMock("@anthropic-ai/claude-agent-sdk", () => ({
    createSdkMcpServer: vi.fn((options: { name: string; tools: { name: string }[] }) => {
      sdkServers.push({ name: options.name, tools: options.tools });
      return { type: "sdk", name: options.name };
    }),
    query: vi.fn(({ options }) => {
      capturedOptions.push(options as Record<string, unknown>);
      const attempt = script.shift() ?? ANSWER;
      return (async function* () {
        for (const message of attempt.messages) yield message;
      })();
    }),
  }));
});

afterEach(async () => {
  const { credentialRelay } = await import("../mcp-credential-relay.js");
  await credentialRelay.close();
  vi.doUnmock("@anthropic-ai/claude-agent-sdk");
  delete process.env.TOOLS_PERSIST_PATH;
  delete process.env.MCP_SERVERS_PERSIST_PATH;
  // The registries persist on a 100 ms debounce; let it land before removing the dir.
  await new Promise((resolve) => setTimeout(resolve, 150));
  fs.rmSync(tempDir, { recursive: true, force: true });
});

async function createApp() {
  const { registerTool } = await import("../tools.js");
  const { registerMcpServer } = await import("../mcp-registry.js");
  for (const name of ["probe_read", "probe_write"]) {
    registerTool({ name, description: name, input_schema: { type: "object", properties: {} }, webhook_url: `http://127.0.0.1:1/${name}` });
  }
  const now = new Date().toISOString();
  for (const name of ["jira", "other"]) {
    registerMcpServer({ name, description: name, enabled: true, type: "stdio", command: "node", args: ["-e", ""], createdAt: now, updatedAt: now });
  }
  // Registered servers are reached only through the trusted relay (MVP-7679), so it must be listening.
  const { credentialRelay } = await import("../mcp-credential-relay.js");
  await credentialRelay.start();
  const { queryRouter } = await import("../query.js");
  const app = express();
  app.use(express.json());
  app.use(queryRouter);
  return app;
}

function events(text: string): Record<string, unknown>[] {
  return text.split("\n").filter((line) => line.trim()).map((line) => JSON.parse(line) as Record<string, unknown>);
}

const READ_SET = ["mcp__agent-gateway-tools__probe_read", "mcp__jira__get_confluence_page"];

describe("enforcedTools (MVP-7637)", () => {
  it("sets every layer of the enforced options and attaches only the named servers", async () => {
    const app = await createApp();
    const res = await request(app)
      .post("/v1/query")
      .send({ queryId: "q-enforced", prompt: "go", useSession: false, user_id: "user-1", enforcedTools: READ_SET });
    expect(res.status).toBe(200);
    expect(capturedOptions).toHaveLength(1);
    const options = capturedOptions[0];
    expect(options.settingSources).toEqual([]);
    expect(options.permissionMode).toBe("dontAsk");
    expect(options.allowedTools).toEqual(READ_SET);
    expect(options.tools).toEqual([]);
    const hooks = options.hooks as { PreToolUse: { matcher?: string; hooks: unknown[] }[] };
    expect(Object.keys(hooks)).toEqual(["PreToolUse"]);
    expect(hooks.PreToolUse).toHaveLength(1);
    expect(hooks.PreToolUse[0].matcher).toBeUndefined();
    expect(hooks.PreToolUse[0].hooks).toHaveLength(1);
    expect(options.plugins).toBeUndefined();
    // Only the webhook tool the set names, and only the registry server it names.
    expect(Object.keys(options.mcpServers as object).sort()).toEqual(["agent-gateway-tools", "jira"]);
    expect(sdkServers).toEqual([{ name: "agent-gateway-tools", tools: [expect.objectContaining({ name: "probe_read" })] }]);
  });

  it("emits the acknowledgment as the first event, echoing the set", async () => {
    const app = await createApp();
    const res = await request(app).post("/v1/query").send({ queryId: "q-ack", prompt: "go", useSession: false, enforcedTools: READ_SET });
    const stream = events(res.text);
    expect(stream[0]).toEqual({ seq: 0, type: "tool_policy", enforced: true, tools: READ_SET });
    expect(stream.filter((e) => e.type === "tool_policy")).toHaveLength(1);
    expect(stream.at(-1)?.type).toBe("done");
  });

  it("an empty set offers no tool and attaches no server", async () => {
    const app = await createApp();
    const res = await request(app).post("/v1/query").send({ queryId: "q-empty", prompt: "go", useSession: false, enforcedTools: [] });
    expect(res.status).toBe(200);
    const options = capturedOptions[0];
    expect(options.allowedTools).toEqual([]);
    expect(options.tools).toEqual([]);
    expect(options.permissionMode).toBe("dontAsk");
    expect(options.mcpServers).toBeUndefined();
    expect(events(res.text)[0]).toEqual({ seq: 0, type: "tool_policy", enforced: true, tools: [] });
  });

  it("offers only the built-ins the set names", async () => {
    const app = await createApp();
    await request(app).post("/v1/query").send({ queryId: "q-builtin", prompt: "go", useSession: false, enforcedTools: ["Read", "mcp__other__x"] });
    expect(capturedOptions[0].tools).toEqual(["Read"]);
    expect(Object.keys(capturedOptions[0].mcpServers as object)).toEqual(["other"]);
  });

  it("a retry keeps the set, and the acknowledgment is not repeated", async () => {
    script = [RATE_LIMITED, ANSWER];
    const app = await createApp();
    const res = await request(app).post("/v1/query").send({ queryId: "q-retry", prompt: "go", useSession: false, enforcedTools: READ_SET });
    expect(capturedOptions).toHaveLength(2);
    for (const options of capturedOptions) {
      expect(options.allowedTools).toEqual(READ_SET);
      expect(options.permissionMode).toBe("dontAsk");
      expect(options.settingSources).toEqual([]);
      expect((options.hooks as { PreToolUse: unknown[] }).PreToolUse).toHaveLength(1);
    }
    const stream = events(res.text);
    expect(stream.filter((e) => e.type === "tool_policy")).toHaveLength(1);
    expect(stream[0].type).toBe("tool_policy");
    expect(stream.some((e) => e.type === "rate_limited" && e.status === "retrying")).toBe(true);
    expect(stream.at(-1)?.type).toBe("done");
  }, 15_000);

  it("without enforcedTools the options are exactly the unenforced ones", async () => {
    const app = await createApp();
    const res = await request(app).post("/v1/query").send({ queryId: "q-plain", prompt: "go", useSession: false, user_id: "user-1" });
    expect(res.status).toBe(200);
    const options = capturedOptions[0];
    expect(options.permissionMode).toBe("bypassPermissions");
    // MVP-7679: only the user source (the project source reads a `.mcp.json` the agent can write), so no `tools`.
    expect(options.settingSources).toEqual(["user"]);
    expect(options.allowedTools).toEqual([
      "Bash", "Read", "Write", "Edit", "Glob", "Grep", "WebSearch", "WebFetch", "Skill", "TodoWrite",
      "probe_read", "probe_write", "mcp__jira__*", "mcp__other__*",
    ]);
    expect(Object.keys(options).sort()).toEqual([
      "abortController", "allowedTools", "cwd", "env", "includePartialMessages", "mcpServers", "model",
      "permissionMode", "sessionId", "settingSources", "spawnClaudeCodeProcess", "systemPrompt",
    ]);
    expect(Object.keys(options.mcpServers as object).sort()).toEqual(["agent-gateway-tools", "jira", "other"]);
    expect(sdkServers[0].tools.map((t) => t.name)).toEqual(["probe_read", "probe_write"]);
    expect(events(res.text).some((e) => e.type === "tool_policy")).toBe(false);
  });

  it("the caller's allowedTools is a narrowing of the trusted grant, not an unenforced pre-approval (MVP-7679)", async () => {
    const app = await createApp();
    await request(app).post("/v1/query").send({ queryId: "q-allowed", prompt: "go", useSession: false, allowedTools: ["Read"] });
    expect(capturedOptions[0].allowedTools).toEqual(["Read"]);
    expect(capturedOptions[0].permissionMode).toBe("bypassPermissions");
    // The runtime is offered only Read; every other built-in is named as denied.
    expect(capturedOptions[0].tools).toEqual(["Read"]);
    expect((capturedOptions[0].disallowedTools as string[]).includes("Bash")).toBe(true);
    expect((capturedOptions[0].disallowedTools as string[]).includes("Read")).toBe(false);
    // No registry server and no webhook tool is granted by a list that names none of them.
    expect(capturedOptions[0].mcpServers).toBeUndefined();
  });

  it.each([
    ["null", { enforcedTools: null }, "enforcedTools must be an array of tool names"],
    ["with allowedTools", { enforcedTools: ["Read"], allowedTools: ["Read"] }, "enforcedTools cannot be combined with allowedTools"],
    ["Task", { enforcedTools: ["Task"] }, "enforcedTools[0] names a sub-agent tool, which cannot be enforced"],
    ["a wildcard", { enforcedTools: ["mcp__jira__*"] }, "enforcedTools[0] must be 1-128 characters of A-Z, a-z, 0-9, _ or -"],
  ])("refuses %s with 400 before streaming", async (_label, extra, error) => {
    const app = await createApp();
    const res = await request(app).post("/v1/query").send({ queryId: "q-bad", prompt: "go", useSession: false, ...extra });
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error });
    expect(capturedOptions).toHaveLength(0);
  });

  it("refuses a name that fits a registry server and a request server", async () => {
    const app = await createApp();
    const res = await request(app)
      .post("/v1/query")
      .send({
        queryId: "q-ambiguous",
        prompt: "go",
        useSession: false,
        mcpServers: { jira__beta: { command: "node", args: [] } },
        enforcedTools: ["mcp__jira__beta__read"],
      });
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: "enforcedTools[0] matches more than one MCP server" });
    expect(capturedOptions).toHaveLength(0);
  });
});
