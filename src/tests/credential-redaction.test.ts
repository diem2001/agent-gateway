import http, { type Server } from "node:http";
import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { McpServerDefinition } from "../mcp-registry.js";
import { TEST_OWNER } from "./helpers/owner-auth.js";

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
    owner: TEST_OWNER,
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
    // The audit line is written for a server the run attached, and a registered server is attached only with the relay up.
    const { credentialRelay } = await import("../mcp-credential-relay.js");
    await credentialRelay.start();

    try {
      await runQuery({
        prompt: "redaction",
        abortController: new AbortController(),
        onEvent: () => undefined,
        mcpCredentialOverrides: { jira: { headers: { Authorization: "Basic USER_X" } } },
      });
    } finally {
      await credentialRelay.close();
    }

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
        // The stub answers 401 at once; a generous deadline keeps a loaded run from reporting a timeout instead.
        5000,
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

  it("redacts /call credentials in debug request logs", async () => {
    const { requestLoggingMiddleware, setLogLevel } = await import("../logging.js");
    setLogLevel("debug");

    const app = express();
    app.use(express.json());
    app.use(requestLoggingMiddleware);
    app.post("/v1/mcp-servers/jira/call", (_req, res) => res.json({ ok: true }));

    await request(app)
      .post("/v1/mcp-servers/jira/call")
      .send({
        tool: "echo",
        arguments: { q: 1 },
        credentials: {
          headers: { Authorization: "Bearer SECRET_CALLER_TOKEN" },
          env: { TOKEN: "SECRET_ENV_TOKEN" },
        },
      });

    const logText = logs.join("\n");
    expect(logText).toContain("[REDACTED]");
    expect(logText).not.toContain("SECRET_CALLER_TOKEN");
    expect(logText).not.toContain("SECRET_ENV_TOKEN");
    expect(logText).not.toContain("Bearer SECRET");
  });

  it("redacts the git routes' sshKey and URL credentials in debug request and response logs (MVP-7614)", async () => {
    const { requestLoggingMiddleware, setLogLevel } = await import("../logging.js");
    setLogLevel("debug");

    const app = express();
    app.use(express.json());
    app.use(requestLoggingMiddleware);
    // The response echoes the URL under a `url` key, so the response preview is covered too.
    app.post("/v1/workspace/git/clone", (req, res) => res.status(500).json({ error: "fatal: failed", url: req.body.url }));

    await request(app)
      .post("/v1/workspace/git/clone")
      .send({
        url: "https://user:SECRET_GIT_TOKEN@host.invalid/r.git",
        path: "r",
        sshKey: "-----BEGIN OPENSSH PRIVATE KEY-----\nSECRET_KEY_LINE\n-----END OPENSSH PRIVATE KEY-----",
        nested: { sshKey: "SECRET_NESTED_KEY", url: "ssh://git:SECRET_AT@PART@host.invalid/r.git" },
      });

    const logText = logs.join("\n");
    expect(logText).toContain('"url":"https://***@host.invalid/r.git"');
    expect(logText).toContain('"sshKey":"[REDACTED]"');
    expect(logText).toContain('"url":"ssh://***@host.invalid/r.git"');
    expect(logText).toContain('"path":"r"');
    for (const secret of ["SECRET_GIT_TOKEN", "SECRET_KEY_LINE", "PRIVATE KEY", "SECRET_NESTED_KEY", "SECRET_AT", "PART@"]) {
      expect(logText).not.toContain(secret);
    }
    expect(logText).toMatch(/\[res\] POST \/v1\/workspace\/git\/clone 500 .*"url":"https:\/\/\*\*\*@host.invalid\/r.git"/);
  });

  it("redacts git URL credentials whatever characters the token has, and url values that are not strings (MVP-7614)", async () => {
    const { requestLoggingMiddleware, setLogLevel } = await import("../logging.js");
    setLogLevel("debug");

    const app = express();
    app.use(express.json());
    app.use(requestLoggingMiddleware);
    app.post("/v1/workspace/git/clone", (req, res) => res.status(500).json({ error: "fatal: failed", url: req.body.url }));

    const tokens = ["ab/SLASHSECRET+z", "SPACESECRET ", "QU'OTE/SECRET", 'DQ"SECRET/x', "AT@SECRET/x", "PCT%SECRET", "UNI€SECRET/ä", "NL\nSECRET"];
    for (const token of tokens) {
      await request(app).post("/v1/workspace/git/clone").send({ url: `https://user:${token}@host.invalid/r.git`, path: "r" });
    }
    await request(app).post("/v1/workspace/git/clone").send({ url: ["https://user:ARRAYSECRET@host.invalid/r.git"], path: "r" });

    const logText = logs.join("\n");
    expect(logText.match(/"url":"https:\/\/\*\*\*@host.invalid\/r.git"/g)?.length).toBe(2 * tokens.length);
    expect(logText).toContain('"url":["https://***@host.invalid/r.git"]');
    expect(logText).not.toContain("SECRET");
    expect(logText).not.toContain("user:");
  });
});
