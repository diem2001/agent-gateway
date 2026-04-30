import http, { type Server } from "node:http";
import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { McpServerDefinition } from "../mcp-registry.js";

let logs: string[] = [];
let server: Server | null = null;

beforeEach(() => {
  vi.resetModules();
  logs = [];
  vi.spyOn(console, "log").mockImplementation((...args) => {
    logs.push(args.map(String).join(" "));
  });
  vi.doMock("@anthropic-ai/claude-agent-sdk", () => ({
    createSdkMcpServer: vi.fn((options) => ({ type: "sdk", name: options.name })),
    query: vi.fn(() => {
      return (async function* () {
        yield { type: "result", usage: {}, total_cost_usd: 0, sessionId: "sdk-session" };
      })();
    }),
  }));
});

afterEach(async () => {
  try {
    const { setLogLevel } = await import("../logging.js");
    setLogLevel("info");
  } catch {
    // Module may not have been imported by the test.
  }
  vi.restoreAllMocks();
  vi.doUnmock("@anthropic-ai/claude-agent-sdk");
  if (server) await new Promise<void>((resolve) => server?.close(() => resolve()));
  server = null;
});

async function registerServer(def: Partial<McpServerDefinition> & Pick<McpServerDefinition, "name" | "type">) {
  const { registerMcpServer } = await import("../mcp-registry.js");
  const now = new Date().toISOString();
  registerMcpServer({
    description: "",
    enabled: true,
    createdAt: now,
    updatedAt: now,
    ...def,
  } as McpServerDefinition);
}

async function startUnauthorizedMcpServer() {
  server = http.createServer((_req, res) => {
    res.writeHead(401, { "Content-Type": "text/plain" });
    res.end("token was Basic USER_X");
  });
  await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", () => resolve()));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("server did not bind");
  return `http://127.0.0.1:${address.port}/mcp`;
}

describe("credential redaction", () => {
  it("logs override application with keys only, never credential values", async () => {
    await registerServer({
      name: "jira",
      type: "http",
      url: "http://127.0.0.1:3002/mcp",
      headers: { Authorization: "Basic STATIC" },
    });
    const { runQuery } = await import("../agent.js");

    await runQuery({
      prompt: "redaction",
      abortController: new AbortController(),
      onEvent: () => undefined,
      mcpCredentialOverrides: { jira: { headers: { Authorization: "Basic USER_X" } } },
    });

    const logText = logs.join("\n");
    expect(logText).toContain("mcp.override.applied serverName=jira keys=headers.Authorization");
    expect(logText).not.toContain("Basic USER_X");
    expect(logText).not.toContain("Basic STATIC");
  });

  it("sanitizes MCP test auth failures", async () => {
    const url = await startUnauthorizedMcpServer();
    const { testMcpServer } = await import("../mcp-test-client.js");

    await expect(
      testMcpServer(
        {
          name: "jira",
          description: "",
          enabled: true,
          type: "http",
          url,
          headers: { Authorization: "Basic STATIC" },
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        },
        { headers: { Authorization: "Basic USER_X" } },
        100,
      ),
    ).rejects.toMatchObject({
      code: "MCP_AUTH_FAILED",
      message: "upstream returned 401",
    });
  });

  it("redacts credential override and test endpoint request bodies in debug request logs", async () => {
    const { requestLoggingMiddleware, setLogLevel } = await import("../logging.js");
    setLogLevel("debug");

    const app = express();
    app.use(express.json());
    app.use(requestLoggingMiddleware);
    app.post("/v1/query", (_req, res) => res.json({ ok: true }));
    app.post("/v1/mcp-servers/jira/test", (_req, res) => res.json({ ok: true }));

    await request(app)
      .post("/v1/query")
      .send({
        queryId: "q-redaction",
        prompt: "test",
        mcpCredentialOverrides: {
          jira: { headers: { Authorization: "Basic USER_X" }, env: { TOKEN: "USER_X" } },
        },
      });
    await request(app)
      .post("/v1/mcp-servers/jira/test")
      .send({ headers: { Authorization: "Basic USER_X" }, env: { TOKEN: "USER_X" } });

    const logText = logs.join("\n");
    expect(logText).toContain("[REDACTED]");
    expect(logText).not.toContain("Basic USER_X");
    expect(logText).not.toContain("\"TOKEN\":\"USER_X\"");
  });
});
