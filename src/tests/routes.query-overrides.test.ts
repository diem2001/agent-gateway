import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { McpServerDefinition } from "../mcp-registry.js";

let tempDir: string;
let persistPath: string;
let runQueryWithRetryMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gateway-query-overrides-"));
  persistPath = path.join(tempDir, "mcp-servers.json");
  process.env.MCP_SERVERS_PERSIST_PATH = persistPath;
  vi.resetModules();
  runQueryWithRetryMock = vi.fn().mockResolvedValue({
    response: "ok",
    resultData: { usage: {}, total_cost_usd: 0, sessionId: "sdk-session" },
  });
  vi.doMock("../retry.js", () => ({ runQueryWithRetry: runQueryWithRetryMock }));
});

afterEach(() => {
  vi.doUnmock("../retry.js");
  delete process.env.MCP_SERVERS_PERSIST_PATH;
  fs.rmSync(tempDir, { recursive: true, force: true });
});

async function createApp() {
  const { queryRouter } = await import("../query.js");
  const app = express();
  app.use(express.json());
  app.use(queryRouter);
  return app;
}

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

describe("POST /v1/query mcpCredentialOverrides", () => {
  it("preserves existing query fields and passes validated overrides to runQueryWithRetry", async () => {
    await registerServer({
      name: "jira",
      type: "http",
      url: "http://mcp-jira:3002/mcp",
      headers: { Authorization: "STATIC" },
    });
    const app = await createApp();

    const res = await request(app)
      .post("/v1/query")
      .send({
        queryId: "q-1",
        prompt: "hello",
        sessionId: "client-session",
        systemPrompt: "system",
        model: "claude-test",
        allowedTools: ["mcp__jira__*"],
        useSession: true,
        user_id: "u1",
        conversation_id: "c1",
        mcpCredentialOverrides: {
          jira: { headers: { Authorization: "Basic USER_X" } },
        },
      });

    expect(res.status).toBe(200);
    expect(runQueryWithRetryMock).toHaveBeenCalledOnce();
    expect(runQueryWithRetryMock.mock.calls[0][0]).toMatchObject({
      queryId: "q-1",
      prompt: "hello",
      systemPrompt: "system",
      model: "claude-test",
      allowedTools: ["mcp__jira__*"],
      mcpCredentialOverrides: {
        jira: { headers: { Authorization: "Basic USER_X" } },
      },
      webhookContext: {
        user_id: "u1",
        conversation_id: "c1",
        session_id: "client-session",
      },
    });
  });

  it("rejects overrides for unknown server names before opening the NDJSON stream", async () => {
    const app = await createApp();

    const res = await request(app)
      .post("/v1/query")
      .send({
        queryId: "q-unknown",
        prompt: "hello",
        mcpCredentialOverrides: { missing: { headers: { Authorization: "secret" } } },
      });

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe("MCP_SERVER_NOT_FOUND");
    expect(runQueryWithRetryMock).not.toHaveBeenCalled();
  });

  it("rejects overrides for disabled registered servers", async () => {
    await registerServer({
      name: "jira",
      type: "http",
      enabled: false,
      url: "http://mcp-jira:3002/mcp",
    });
    const app = await createApp();

    const res = await request(app)
      .post("/v1/query")
      .send({
        queryId: "q-disabled",
        prompt: "hello",
        mcpCredentialOverrides: { jira: { headers: { Authorization: "secret" } } },
      });

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe("MCP_SERVER_DISABLED");
    expect(res.body.error.message).toMatch(/enable the server/);
    expect(runQueryWithRetryMock).not.toHaveBeenCalled();
  });
});
