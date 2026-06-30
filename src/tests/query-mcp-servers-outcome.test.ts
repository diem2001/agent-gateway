/**
 * Outcome Probe for MVP-6755 (Observable-Outcome AC):
 *
 *   "When a client POSTs /v1/query with mcpServers { chrome-devtools: {command, args} },
 *    the gateway injects that server into the SDK query options AND allows its tools,
 *    while the gateway's own webhook tools + registered servers still load and keep
 *    precedence (the request cannot override them)."
 *
 * This is the regression that reqlift recon depends on: it sends a per-run
 * chrome-devtools MCP server in the request body to drive a browser. Before this
 * fix the gateway silently dropped the field, so recon never got its browser tools.
 *
 * The test exercises the REAL query.ts + retry.ts + agent.ts path end-to-end,
 * mocking ONLY the Claude Agent SDK boundary (`query()`) so we can observe the
 * exact `options` the SDK receives — mirroring how reqlift calls the gateway.
 */
import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Captures the `options` argument passed to the mocked SDK query() per invocation.
let capturedOptions: Array<Record<string, unknown>> = [];

beforeEach(() => {
  vi.resetModules();
  capturedOptions = [];
  vi.doMock("@anthropic-ai/claude-agent-sdk", () => ({
    createSdkMcpServer: vi.fn((options) => ({ type: "sdk", name: options.name })),
    query: vi.fn(({ options }) => {
      capturedOptions.push(options as Record<string, unknown>);
      return (async function* () {
        yield { type: "assistant", message: { content: [{ type: "text", text: "ack" }] } };
        yield {
          type: "result",
          usage: { input_tokens: 1, output_tokens: 1 },
          total_cost_usd: 0,
          sessionId: "sdk-session",
        };
      })();
    }),
  }));
});

afterEach(() => {
  vi.doUnmock("@anthropic-ai/claude-agent-sdk");
});

async function createApp() {
  const { queryRouter } = await import("../query.js");
  const app = express();
  app.use(express.json());
  app.use(queryRouter);
  return app;
}

const CHROME_DEVTOOLS = {
  "chrome-devtools": {
    command: "npx",
    args: ["chrome-devtools-mcp", "--browser-url=http://recon-abc:9222"],
  },
};

describe("Outcome Probe — per-query mcpServers reaches the SDK options (MVP-6755)", () => {
  it("(a) injects the request server and allows its tools when no allowedTools is sent", async () => {
    const app = await createApp();

    const res = await request(app)
      .post("/v1/query")
      .send({ queryId: "probe-cdt", prompt: "navigate", useSession: false, mcpServers: CHROME_DEVTOOLS });

    expect(res.status).toBe(200);
    expect(capturedOptions).toHaveLength(1);
    const options = capturedOptions[0];

    // The server is present in the SDK mcpServers map with the exact spec.
    const mcpServers = options.mcpServers as Record<string, unknown>;
    expect(mcpServers).toBeDefined();
    expect(mcpServers["chrome-devtools"]).toEqual(CHROME_DEVTOOLS["chrome-devtools"]);

    // Its tools are allowed (reqlift recon sends no allowedTools → default branch
    // must add the pattern, otherwise the SDK never exposes mcp__chrome-devtools__*).
    expect(options.allowedTools as string[]).toContain("mcp__chrome-devtools__*");
  });

  it("(b) a request mcpServers cannot override the reserved agent-gateway-tools name", async () => {
    const app = await createApp();

    const res = await request(app)
      .post("/v1/query")
      .send({
        queryId: "probe-reserved",
        prompt: "x",
        useSession: false,
        mcpServers: { "agent-gateway-tools": { command: "evil", args: [] } },
      });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/agent-gateway-tools/);
    expect(capturedOptions).toHaveLength(0);
  });

  it("(c) rejects a malformed server (no command and no url) with 400", async () => {
    const app = await createApp();

    const res = await request(app)
      .post("/v1/query")
      .send({
        queryId: "probe-malformed",
        prompt: "x",
        useSession: false,
        mcpServers: { broken: { foo: "bar" } },
      });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/command.*url|url.*command/i);
    expect(capturedOptions).toHaveLength(0);
  });

  it("(d) omitting mcpServers leaves the SDK options unchanged (no mcpServers key)", async () => {
    const app = await createApp();

    const res = await request(app)
      .post("/v1/query")
      .send({ queryId: "probe-none", prompt: "hello", useSession: false });

    expect(res.status).toBe(200);
    expect(capturedOptions).toHaveLength(1);
    // No registered servers + no webhook tools + no request servers ⇒ no mcpServers key.
    expect(capturedOptions[0].mcpServers).toBeUndefined();
  });
});
