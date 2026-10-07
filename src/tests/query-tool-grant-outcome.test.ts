/**
 * The trusted tool grant through the REAL query.ts + retry.ts + agent.ts path (MVP-7679), with ONLY the Claude
 * Agent SDK boundary mocked, so the exact SDK options, the hosted webhook tools and the NDJSON stream can be
 * asserted: built-in layers per policy and caller narrowing, servers without a granted tool left out, the
 * acknowledgment of enforced sets, owner-bound webhook offering and bearer forwarding, the additive
 * `success: false`, request `mcpServers` validation and per-label event replay. The refusal itself is proven
 * against the real runtime in tool-grant-process.test.ts.
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

type SdkTool = { name: string; handler: (args: Record<string, unknown>, extra: unknown) => Promise<{ isError?: boolean; content: { text: string }[] }> };

let script: Attempt[] = [];
let capturedOptions: Record<string, unknown>[] = [];
let sdkServers: { name: string; tools: SdkTool[] }[] = [];
let tempDir: string;
let logs: string[];
/** The options of every SandboxRun and the arguments of every materializeUserSkills call of the run under test (MVP-8106). */
let sandboxOptions: Record<string, unknown>[] = [];
let skillCalls: { userId: unknown; options: unknown }[] = [];

const INIT = { type: "system", subtype: "init", claude_code_version: "2.0.77", skills: [] };
const RESULT = { type: "result", subtype: "success", is_error: false, result: "fine", session_id: "sdk-s", usage: { input_tokens: 1, output_tokens: 1 }, total_cost_usd: 0 };
const ANSWER: Attempt = {
  messages: [
    INIT,
    { type: "stream_event", event: { type: "content_block_delta", delta: { type: "text_delta", text: "fine" } } },
    { type: "assistant", message: { content: [{ type: "text", text: "fine" }] } },
    RESULT,
  ],
};

const ALL_BUILT_INS = [
  "Agent", "AskUserQuestion", "Bash", "Edit", "EnterPlanMode", "ExitPlanMode", "Glob", "Grep", "KillShell", "LSP", "NotebookEdit",
  "Read", "Skill", "Task", "TaskCreate", "TaskGet", "TaskList", "TaskOutput", "TaskUpdate", "TodoWrite", "WebFetch", "WebSearch", "Write",
];

beforeEach(() => {
  vi.resetModules();
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gateway-tool-grant-"));
  process.env.TOOLS_PERSIST_PATH = path.join(tempDir, "tools.json");
  process.env.MCP_SERVERS_PERSIST_PATH = path.join(tempDir, "mcp-servers.json");
  process.env.SESSION_PERSIST_PATH = path.join(tempDir, "sessions.json");
  script = [];
  capturedOptions = [];
  sdkServers = [];
  logs = [];
  sandboxOptions = [];
  skillCalls = [];
  vi.spyOn(console, "log").mockImplementation((...args) => {
    logs.push(args.map(String).join(" "));
  });
  vi.doMock("@modelcontextprotocol/sdk/server/mcp.js", () => ({
    McpServer: class {
      tools: SdkTool[] = [];
      constructor(options: { name: string }) {
        sdkServers.push({ name: options.name, tools: this.tools });
      }
      registerTool(name: string, _config: unknown, handler: SdkTool["handler"]) {
        this.tools.push({ name, handler });
      }
    },
  }));
  // Recording wrappers around the real sandbox run and skill bundle: they only observe what agent.ts hands over.
  vi.doMock("../sandbox.js", async (importOriginal) => {
    const actual = await importOriginal<typeof import("../sandbox.js")>();
    return {
      ...actual,
      SandboxRun: class extends actual.SandboxRun {
        constructor(options: ConstructorParameters<typeof actual.SandboxRun>[0]) {
          super(options);
          sandboxOptions.push(options as unknown as Record<string, unknown>);
        }
      },
    };
  });
  vi.doMock("../user-skills.js", async (importOriginal) => {
    const actual = await importOriginal<typeof import("../user-skills.js")>();
    return {
      ...actual,
      materializeUserSkills: (userId: string | undefined, options?: Parameters<typeof actual.materializeUserSkills>[1]) => {
        skillCalls.push({ userId, options });
        return actual.materializeUserSkills(userId, options);
      },
    };
  });
  vi.doMock("@anthropic-ai/claude-agent-sdk", () => ({
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
  vi.doUnmock("../sandbox.js");
  vi.doUnmock("../user-skills.js");
  vi.doUnmock("@modelcontextprotocol/sdk/server/mcp.js");
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  delete process.env.TOOLS_PERSIST_PATH;
  delete process.env.MCP_SERVERS_PERSIST_PATH;
  delete process.env.SESSION_PERSIST_PATH;
  await new Promise((resolve) => setTimeout(resolve, 150));
  fs.rmSync(tempDir, { recursive: true, force: true });
});

async function createApp(policy?: unknown) {
  const grant = await import("../tool-grant.js");
  if (policy !== undefined) grant.setToolPolicy(grant.parseToolPolicy(JSON.stringify(policy), ["reqlift", "diemcrm"]));
  const { registerTool } = await import("../tools.js");
  const { registerMcpServer } = await import("../mcp-registry.js");
  for (const [name, owner] of [["probe_read", "reqlift"], ["probe_write", "reqlift"], ["other_tool", "diemcrm"], ["legacy_tool", undefined]] as const) {
    registerTool({ name, description: name, input_schema: { type: "object", properties: {} }, webhook_url: `http://127.0.0.1:1/${name}`, ...(owner ? { owner } : {}) });
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
  app.use((req, _res, next) => {
    req.clientLabel = (req.headers["x-test-label"] as string | undefined) ?? "reqlift";
    next();
  });
  app.use(queryRouter);
  return app;
}

function events(text: string): Record<string, unknown>[] {
  return text.split("\n").filter((line) => line.trim()).map((line) => JSON.parse(line) as Record<string, unknown>);
}

const post = (app: express.Express, body: Record<string, unknown>, label = "reqlift") =>
  request(app).post("/v1/query").set("x-test-label", label).send({ queryId: `q-${Math.random()}`, prompt: "go", useSession: false, user_id: "user-1", ...body });

describe("built-in layers from the trusted policy", () => {
  it("no policy, no list: the options are what they were (no `tools`, no `disallowedTools`) with the user setting source only", async () => {
    const app = await createApp();
    expect((await post(app, {})).status).toBe(200);
    const options = capturedOptions[0];
    expect(options.tools).toBeUndefined();
    expect(options.disallowedTools).toBeUndefined();
    expect(options.permissionMode).toBe("bypassPermissions");
    expect(options.settingSources).toEqual(["user"]);
    expect(Object.keys(options.mcpServers as object).sort()).toEqual(["agent-gateway-tools", "jira", "other"]);
  });

  it("a policy that denies Bash and Write: the runtime is offered the other 16 and the two are named as denied", async () => {
    const app = await createApp({ labels: { reqlift: { deny: ["Bash", "Write"] } } });
    await post(app, {});
    const options = capturedOptions[0];
    expect(options.tools).toEqual(ALL_BUILT_INS.filter((n) => n !== "Bash" && n !== "Write"));
    expect(options.disallowedTools).toEqual(["Bash", "Write"]);
    expect(options.permissionMode).toBe("bypassPermissions");
    expect(options.allowedTools).not.toContain("Bash");
    expect(options.allowedTools).not.toContain("Write");
    expect(options.allowedTools).toContain("Read");
  });

  it("the same policy for another label that has no entry changes nothing for that label", async () => {
    const app = await createApp({ labels: { reqlift: { deny: ["Bash", "Write"] } } });
    await post(app, {}, "diemcrm");
    expect(capturedOptions[0].tools).toBeUndefined();
    expect(capturedOptions[0].disallowedTools).toBeUndefined();
  });

  it("a request naming the denied tool explicitly cannot widen it", async () => {
    const app = await createApp({ labels: { reqlift: { deny: ["Bash"] } } });
    await post(app, { allowedTools: ["Bash", "Read"] });
    const options = capturedOptions[0];
    expect(options.tools).toEqual(["Read"]);
    expect(options.allowedTools).toEqual(["Read"]);
    expect((options.disallowedTools as string[]).includes("Bash")).toBe(true);
  });

  it("an explicitly empty allowedTools grants no tool at all, never the default set", async () => {
    const app = await createApp();
    await post(app, { allowedTools: [] });
    const options = capturedOptions[0];
    expect(options.allowedTools).toEqual([]);
    expect(options.tools).toEqual([]);
    expect(options.disallowedTools).toEqual(ALL_BUILT_INS);
    expect(options.mcpServers).toBeUndefined();
  });

  it("allowedTools with a server pattern attaches only that server and no webhook server", async () => {
    const app = await createApp();
    await post(app, { allowedTools: ["mcp__jira__*"] });
    expect(Object.keys(capturedOptions[0].mcpServers as object)).toEqual(["jira"]);
    expect(capturedOptions[0].tools).toEqual([]);
  });

  it("a server the policy leaves no tool of is not attached; one it names is", async () => {
    const app = await createApp({ default: { allow: ["Read", "mcp__jira__get_page"] } });
    await post(app, {});
    expect(Object.keys(capturedOptions[0].mcpServers as object)).toEqual(["jira"]);
    expect(capturedOptions[0].tools).toEqual(["Read"]);
  });

  it("a request server is attached only when the grant names it", async () => {
    const app = await createApp({ default: { allow: ["Read", "mcp__chrome-devtools__*"] } });
    await post(app, { mcpServers: { "chrome-devtools": { command: "npx", args: ["chrome-devtools-mcp"] }, unwanted: { command: "node" } } });
    expect(Object.keys(capturedOptions[0].mcpServers as object)).toEqual(["chrome-devtools"]);
  });

  it("a policy that denies Bash cannot be sidestepped with a request-supplied command server; one the policy names is attached", async () => {
    const app = await createApp({ labels: { reqlift: { deny: ["Bash"] } } });
    await post(app, { mcpServers: { runner: { command: "sh", args: ["-c", "id"] }, remote: { url: "http://127.0.0.1:9/mcp" } } });
    // The command server is left out (with an audit line); a url server needs no command execution.
    const attached = Object.keys(capturedOptions[0].mcpServers as object);
    expect(attached).toContain("remote");
    expect(attached).not.toContain("runner");
    expect(logs.join("\n")).toContain("mcp.server.omitted serverName=runner reason=command_not_granted");
  });

  it("a request-supplied command server is attached when the policy allows Bash, names the server, or there is no policy", async () => {
    for (const policy of [undefined, { labels: { reqlift: { deny: ["Write"] } } }, { labels: { reqlift: { allow: ["Read", "mcp__runner__*"] } } }]) {
      capturedOptions = [];
      vi.resetModules();
      const app = await createApp(policy);
      await post(app, { mcpServers: { runner: { command: "node", args: [] } } });
      expect(Object.keys((capturedOptions[0].mcpServers as object | undefined) ?? {}), JSON.stringify(policy)).toContain("runner");
    }
  });

  it("the caller's own narrowing never decides it: an enforced set naming the server attaches it when the policy does not deny Bash", async () => {
    const app = await createApp({ labels: { reqlift: { deny: ["Write"] } } });
    await post(app, { mcpServers: { runner: { command: "node" } }, enforcedTools: ["mcp__runner__act"] });
    expect(Object.keys(capturedOptions[0].mcpServers as object)).toContain("runner");
  });

  it("a retry keeps the layers", async () => {
    script = [
      { messages: [INIT, { type: "assistant", error: "rate_limit", message: { model: "<synthetic>", content: [{ type: "text", text: 'API Error: 429 {"type":"error","error":{"type":"rate_limit_error","message":"slow"}}' }] } }, { type: "result", subtype: "success", is_error: true, result: "API Error: 429", session_id: "sdk-failed", usage: {}, total_cost_usd: 0 }] },
      ANSWER,
    ];
    const app = await createApp({ labels: { reqlift: { deny: ["Bash"] } } });
    await post(app, {});
    expect(capturedOptions).toHaveLength(2);
    for (const options of capturedOptions) {
      expect(options.disallowedTools).toEqual(["Bash"]);
      expect(options.tools).toEqual(ALL_BUILT_INS.filter((n) => n !== "Bash"));
    }
  }, 15_000);
});

describe("an enforced set with a member the policy does not grant", () => {
  it("the acknowledgment still echoes the requested set, an audit line names the narrowed members, the run enforces the subset", async () => {
    const app = await createApp({ labels: { reqlift: { deny: ["Bash", "mcp__agent-gateway-tools__probe_write"] } } });
    const requested = ["Read", "Bash", "mcp__agent-gateway-tools__probe_read", "mcp__agent-gateway-tools__probe_write"];
    const res = await post(app, { queryId: "q-narrowed", enforcedTools: requested });
    expect(res.status).toBe(200);
    expect(events(res.text)[0]).toEqual({ seq: 0, type: "tool_policy", enforced: true, tools: requested });
    expect(logs.filter((l) => l.includes("tool.policy.narrowed"))).toEqual(["[audit] tool.policy.narrowed queryId=q-narrowed denied=Bash,mcp__agent-gateway-tools__probe_write"]);
    const options = capturedOptions[0];
    expect(options.allowedTools).toEqual(["Read", "mcp__agent-gateway-tools__probe_read"]);
    expect(options.tools).toEqual(["Read"]);
    expect(sdkServers).toEqual([{ name: "agent-gateway-tools", tools: [expect.objectContaining({ name: "probe_read" })] }]);
  });

  it("an enforced set the policy fully grants writes no audit line", async () => {
    const app = await createApp({ labels: { reqlift: { deny: ["Bash"] } } });
    await post(app, { enforcedTools: ["Read"] });
    expect(logs.filter((l) => l.includes("tool.policy.narrowed"))).toEqual([]);
  });
});

describe("registered webhook tools are offered by owner and grant", () => {
  it("a run is offered its own label's tools and the legacy ownerless ones, never another label's", async () => {
    const app = await createApp();
    await post(app, {}, "reqlift");
    expect(sdkServers[0].tools.map((t) => t.name).sort()).toEqual(["legacy_tool", "probe_read", "probe_write"]);
    sdkServers = [];
    await post(app, {}, "diemcrm");
    expect(sdkServers[0].tools.map((t) => t.name).sort()).toEqual(["legacy_tool", "other_tool"]);
  });

  it("a policy that grants one webhook tool hosts only that tool", async () => {
    const app = await createApp({ default: { allow: ["mcp__agent-gateway-tools__probe_read"] } });
    await post(app, {});
    expect(sdkServers[0].tools.map((t) => t.name)).toEqual(["probe_read"]);
  });

  it("a policy that grants no webhook tool does not attach the webhook server", async () => {
    const app = await createApp({ default: { allow: ["Read"] } });
    await post(app, {});
    expect(sdkServers).toEqual([]);
    expect(capturedOptions[0].mcpServers).toBeUndefined();
  });

  it("the caller's bearer goes only to tools its own label registered; a legacy tool keeps today's forwarding with one audit line per call", async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ output: "ok" }), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const app = await createApp();
    await request(app)
      .post("/v1/query")
      .set("x-test-label", "reqlift")
      .set("authorization", "Bearer SYNTH-REQLIFT-KEY-7679")
      .send({ queryId: "q-bearer", prompt: "go", useSession: false, user_id: "u" });
    const tools = Object.fromEntries(sdkServers[0].tools.map((t) => [t.name, t]));
    await tools.probe_read.handler({}, { requestId: "r1" });
    await tools.legacy_tool.handler({}, { requestId: "r2" });
    const headersOf = (index: number) => ((fetchMock.mock.calls[index] as unknown as [string, RequestInit])[1].headers as Record<string, string>);
    expect(headersOf(0).Authorization).toBe("Bearer SYNTH-REQLIFT-KEY-7679");
    expect(headersOf(1).Authorization).toBe("Bearer SYNTH-REQLIFT-KEY-7679");
    expect(logs.filter((l) => l.includes("tool.webhook.legacy_forward"))).toEqual(["[audit] tool.webhook.legacy_forward toolName=legacy_tool"]);
  });

  it("a tool of another label would never receive the bearer: it is not offered, and the owner check refuses it", async () => {
    const { default: agent } = { default: await import("../agent.js") };
    void agent;
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ output: "ok" }), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const app = await createApp();
    await request(app)
      .post("/v1/query")
      .set("x-test-label", "diemcrm")
      .set("authorization", "Bearer SYNTH-DIEMCRM-KEY-7679")
      .send({ queryId: "q-bearer2", prompt: "go", useSession: false });
    const names = sdkServers[0].tools.map((t) => t.name);
    expect(names).not.toContain("probe_read");
    expect(names).not.toContain("probe_write");
    const tools = Object.fromEntries(sdkServers[0].tools.map((t) => [t.name, t]));
    await tools.other_tool.handler({}, { requestId: "r3" });
    const headers = (fetchMock.mock.calls[0] as unknown as [string, RequestInit])[1].headers as Record<string, string>;
    expect(headers.Authorization).toBe("Bearer SYNTH-DIEMCRM-KEY-7679");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("a refusal message from the webhook never carries the caller's bearer or a gateway key", async () => {
    process.env.API_KEYS = "reqlift:SYNTH-REQLIFT-KEY-7679";
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ error: { message: "bad token SYNTH-REQLIFT-KEY-7679 and SYNTH-REQLIFT-KEY-7679" } }), { status: 400, headers: { "Content-Type": "application/json" } })));
    const app = await createApp();
    await request(app)
      .post("/v1/query")
      .set("x-test-label", "reqlift")
      .set("authorization", "Bearer SYNTH-REQLIFT-KEY-7679")
      .send({ queryId: "q-mask", prompt: "go", useSession: false });
    const result = await sdkServers[0].tools.find((t) => t.name === "probe_read")!.handler({}, { requestId: "r4" });
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toBe("The tool rejected the request (HTTP 400): bad token [REDACTED] and [REDACTED]");
    delete process.env.API_KEYS;
  });
});

describe("tool_result events of failed calls", () => {
  const toolResult = (id: string, isError: boolean | undefined, content: string) => ({
    type: "user",
    tool_use_result: {},
    message: { content: [{ type: "tool_result", tool_use_id: id, is_error: isError, content }] },
  });

  it("carry the additive success:false when the block is an error, and are byte-identical to before when it is not", async () => {
    script = [
      {
        messages: [
          INIT,
          { type: "assistant", message: { content: [{ type: "tool_use", id: "tu-1", name: "mcp__jira__get", input: {} }, { type: "tool_use", id: "tu-2", name: "mcp__jira__get", input: {} }, { type: "tool_use", id: "tu-3", name: "mcp__jira__get", input: {} }] } },
          toolResult("tu-1", true, "TOOL_DENIED: This tool is not allowed for this request. Do not retry; continue without it or tell the user."),
          toolResult("tu-2", false, "fine"),
          toolResult("tu-3", undefined, "also fine"),
          RESULT,
        ],
      },
    ];
    const app = await createApp();
    const res = await post(app, {});
    const results = events(res.text).filter((e) => e.type === "tool_result");
    expect(results.map((e) => Object.keys(e).filter((k) => k !== "durationMs" && k !== "seq").sort())).toEqual([
      ["output", "success", "toolName", "toolUseId", "type"],
      ["output", "toolName", "toolUseId", "type"],
      ["output", "toolName", "toolUseId", "type"],
    ]);
    expect(results[0]).toMatchObject({ toolUseId: "tu-1", success: false, output: "TOOL_DENIED: This tool is not allowed for this request. Do not retry; continue without it or tell the user." });
    expect(results[1]).not.toHaveProperty("success");
  });
});

describe("request mcpServers are validated on the trusted side", () => {
  it.each([
    ["a name that is not a valid server name", { "bad name": { command: "node" } }, /name "\(invalid name\)" must be 1-32 letters/],
    ["a name that is too long", { ["a".repeat(33)]: { command: "node" } }, /must be 1-32 letters/],
    ["the reserved name", { "agent-gateway-tools": { command: "node" } }, /reserved server/],
    ["a command and a url", { x: { command: "node", url: "http://127.0.0.1:9/mcp" } }, /either "command" or "url"/],
    ["a type other than http or sse", { x: { url: "http://127.0.0.1:9/mcp", type: "ws" } }, /type must be "http" or "sse"/],
    ["type stdio on a url server", { x: { url: "http://127.0.0.1:9/mcp", type: "stdio" } }, /type must be "http" or "sse"/],
    ["a type on a command server", { x: { command: "node", type: "stdio" } }, /must not set "type"/],
    ["a url that is not http(s)", { x: { url: "file:///etc/passwd" } }, /url must be an http or https URL/],
    ["a url that does not parse", { x: { url: "not a url" } }, /url must be an http or https URL/],
    ["headers that are not a string map", { x: { url: "http://127.0.0.1:9/mcp", headers: { A: 1 } } }, /headers must be a string map/],
    ["a header value with a line break", { x: { url: "http://127.0.0.1:9/mcp", headers: { A: "b\r\nX: y" } } }, /cannot be sent as an HTTP header/],
    ["an env value with a NUL", { x: { command: "node", env: { A: "b\0c" } } }, /cannot be passed to a process/],
    ["env that is not a string map", { x: { command: "node", env: { A: 1 } } }, /env must be a string→string object|env must be a string map/],
  ])("refuses %s with 400 and no run", async (_label, mcpServers, message) => {
    const app = await createApp();
    const res = await post(app, { mcpServers });
    expect(res.status).toBe(400);
    expect(typeof res.body.error === "string" ? res.body.error : res.body.error.message).toMatch(message);
    expect(capturedOptions).toHaveLength(0);
  });

  it.each([["jira"], ["other"]])("a name equal to the registered server %s is refused with MCP_SERVER_NAME_CONFLICT", async (name) => {
    const app = await createApp();
    const res = await post(app, { mcpServers: { [name]: { command: "node" } } });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe("MCP_SERVER_NAME_CONFLICT");
    expect(capturedOptions).toHaveLength(0);
  });

  it("a name equal to a disabled registered server is refused too", async () => {
    const app = await createApp();
    const { registerMcpServer } = await import("../mcp-registry.js");
    const now = new Date().toISOString();
    registerMcpServer({ name: "off", description: "", enabled: false, type: "http", url: "http://127.0.0.1:9/mcp", createdAt: now, updatedAt: now });
    const res = await post(app, { mcpServers: { off: { command: "node" } } });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe("MCP_SERVER_NAME_CONFLICT");
  });

  it("the recon-shaped request against the registry still works: chrome-devtools is accepted next to the registry server `jira`", async () => {
    const app = await createApp();
    const res = await post(app, { mcpServers: { "chrome-devtools": { command: "npx", args: ["chrome-devtools-mcp", "--browser-url=http://recon-1:9222"] } } });
    expect(res.status).toBe(200);
    expect(capturedOptions[0].mcpServers).toMatchObject({ "chrome-devtools": { command: "npx", args: ["chrome-devtools-mcp", "--browser-url=http://recon-1:9222"] } });
  });

  it("a url without a type is http; unknown fields are dropped, so nothing else reaches the runtime", async () => {
    const app = await createApp();
    const res = await post(app, { mcpServers: { remote: { url: "http://127.0.0.1:9/mcp", headersHelper: "/bin/evil", oauth: { clientId: "x" } }, local: { command: "node", args: ["a"], cwd: "/", type: undefined, extra: 1 } } });
    expect(res.status).toBe(200);
    const servers = capturedOptions[0].mcpServers as Record<string, unknown>;
    expect(servers.remote).toEqual({ type: "http", url: "http://127.0.0.1:9/mcp" });
    expect(servers.local).toEqual({ command: "node", args: ["a"] });
  });

  it("an explicit sse type is kept (a server without headers connects directly; with headers it goes through the relay, see query-mcp-mediation-outcome)", async () => {
    const app = await createApp();
    await post(app, { mcpServers: { feed: { type: "sse", url: "http://127.0.0.1:9/sse" } } });
    expect((capturedOptions[0].mcpServers as Record<string, unknown>).feed).toEqual({ type: "sse", url: "http://127.0.0.1:9/sse" });
  });
});

describe("allowedTools validation", () => {
  it.each([
    ["a string", "Bash"],
    ["an object", { Bash: true }],
    ["a list with a number", ["Read", 1]],
    ["a list with an empty name", ["Read", ""]],
    ["null", null],
  ])("%s is refused with 400 and no run", async (_label, value) => {
    const app = await createApp();
    const res = await post(app, { allowedTools: value });
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: "allowedTools must be an array of tool names" });
    expect(capturedOptions).toHaveLength(0);
  });
});

describe("the event cache is keyed by label and query id", () => {
  it("a second label reusing a queryId gets its own entry; a replay reaches only the starting label", async () => {
    const app = await createApp();
    await post(app, { queryId: "shared-id" }, "reqlift");
    script = [{ messages: [INIT, { type: "assistant", message: { content: [{ type: "text", text: "diemcrm answer" }] } }, { type: "stream_event", event: { type: "content_block_delta", delta: { type: "text_delta", text: "diemcrm answer" } } }, RESULT] }];
    await post(app, { queryId: "shared-id" }, "diemcrm");
    const replay = async (label: string) => request(app).get("/v1/query/shared-id/events").set("x-test-label", label);
    const mine = await replay("reqlift");
    const theirs = await replay("diemcrm");
    expect(mine.text).toContain("fine");
    expect(mine.text).not.toContain("diemcrm answer");
    expect(theirs.text).toContain("diemcrm answer");
    expect(theirs.text).not.toContain('"fine"');
    const stranger = await replay("someone-else");
    expect(stranger.status).toBe(404);
    expect(stranger.body).toEqual({ error: "Query not found or expired" });
  });
});

describe("command settings of skill and agent files follow the same Bash grant as the request-server gate (MVP-8106)", () => {
  const neutralized = () => sandboxOptions[0]?.neutralizeCommands;
  const commandServerAttached = () => Object.keys((capturedOptions[0].mcpServers as object | undefined) ?? {}).includes("runner");

  async function run(policy: unknown, body: Record<string, unknown> = {}, label = "reqlift") {
    sandboxOptions = [];
    skillCalls = [];
    capturedOptions = [];
    vi.resetModules();
    const app = await createApp(policy);
    await post(app, { mcpServers: { runner: { command: "node", args: [] } }, ...body }, label);
  }

  it("a policy that denies Bash for the label: the run is told to neutralize, with the label, and the per-user bundle is asked for the same", async () => {
    await run({ labels: { reqlift: { deny: ["Bash"] } } });
    expect(sandboxOptions).toHaveLength(1);
    expect(neutralized()).toBe(true);
    expect(sandboxOptions[0].label).toBe("reqlift");
    expect(skillCalls).toEqual([{ userId: "user-1", options: { neutralizeCommands: true, label: "reqlift" } }]);
  });

  it("no policy, or a policy that leaves Bash granted: nothing is neutralized, in the sandbox run and in the bundle", async () => {
    for (const policy of [undefined, { labels: { reqlift: { deny: ["Write"] } } }, { labels: { reqlift: { allow: ["Bash", "Read"] } } }, { default: { deny: ["Write"] } }]) {
      await run(policy);
      expect(neutralized(), JSON.stringify(policy)).toBe(false);
      expect(skillCalls, JSON.stringify(policy)).toEqual([{ userId: "user-1", options: { neutralizeCommands: false, label: "reqlift" } }]);
    }
  });

  it("an allow list without Bash neutralizes; so does a default entry that denies Bash, for a label that has no entry of its own", async () => {
    await run({ labels: { reqlift: { allow: ["Read", "Grep"] } } });
    expect(neutralized()).toBe(true);
    await run({ default: { deny: ["Bash"] } }, {}, "diemcrm");
    expect(neutralized()).toBe(true);
  });

  it("another label that the policy leaves alone is not neutralized, whatever a different label is denied", async () => {
    await run({ labels: { reqlift: { deny: ["Bash"] } } }, {}, "diemcrm");
    expect(neutralized()).toBe(false);
    expect(sandboxOptions[0].label).toBe("diemcrm");
  });

  it("the caller's own narrowing never decides it, in either direction", async () => {
    await run(undefined, { allowedTools: ["Read"] });
    expect(neutralized()).toBe(false);
    await run({ labels: { reqlift: { deny: ["Bash"] } } }, { allowedTools: ["Bash", "Read"] });
    expect(neutralized()).toBe(true);
    await run(undefined, { enforcedTools: ["Read"] });
    expect(neutralized()).toBe(false);
    await run({ labels: { reqlift: { deny: ["Bash"] } } }, { enforcedTools: ["Read"] });
    expect(neutralized()).toBe(true);
  });

  it("an enforced run still asks for no per-user bundle at all", async () => {
    await run({ labels: { reqlift: { deny: ["Bash"] } } }, { enforcedTools: ["Read"] });
    expect(skillCalls).toEqual([{ userId: undefined, options: undefined }]);
  });

  it("the request-server command gate is pinned: no policy attaches, deny Bash omits, an allow list without Bash omits, a policy that names the server attaches", async () => {
    const rows: [string, unknown, boolean][] = [
      ["no policy", undefined, true],
      ["deny Bash", { labels: { reqlift: { deny: ["Bash"] } } }, false],
      ["allow without Bash", { labels: { reqlift: { allow: ["Read"] } } }, false],
      ["allow naming the server", { labels: { reqlift: { allow: ["Read", "mcp__runner__*"] } } }, true],
    ];
    for (const [row, policy, attached] of rows) {
      await run(policy);
      expect(commandServerAttached(), row).toBe(attached);
    }
  });

  it("both gates read the same Bash grant: a command server is left out exactly when the run is neutralized, except where the policy names that server (an exception of the request-server gate only)", async () => {
    const rows: [string, unknown][] = [
      ["no policy", undefined],
      ["deny Write", { labels: { reqlift: { deny: ["Write"] } } }],
      ["deny Bash", { labels: { reqlift: { deny: ["Bash"] } } }],
      ["allow without Bash", { labels: { reqlift: { allow: ["Read"] } } }],
      ["allow with Bash and the server", { labels: { reqlift: { allow: ["Read", "Bash", "mcp__runner__*"] } } }],
    ];
    for (const [row, policy] of rows) {
      await run(policy);
      expect(commandServerAttached(), row).toBe(neutralized() === false);
    }
    await run({ labels: { reqlift: { allow: ["Read", "mcp__runner__*"] } } });
    expect(commandServerAttached()).toBe(true);
    expect(neutralized()).toBe(true);
  });
});
