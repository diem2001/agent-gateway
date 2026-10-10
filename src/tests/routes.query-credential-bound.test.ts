/**
 * The caller-supplied credential material of one `POST /v1/query` is bounded at request validation (MVP-8207): the
 * header and env values of `mcpCredentialOverrides` plus those of the request's `mcpServers` hold at most 256 values
 * and 65,536 UTF-8 bytes together. Over either limit the answer is 400 `MCP_CREDENTIALS_TOO_LARGE` with a fixed text
 * that echoes no value, and no run starts. The limits are written out here on purpose, not read from the source.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { McpServerDefinition } from "../mcp-registry.js";

const MAX_BYTES = 65_536;
const MAX_VALUES = 256;
const FIXED_MESSAGE = "mcpCredentialOverrides and mcpServers header and env values together may hold at most 256 values and 65536 bytes";

let tempDir: string;
let runQueryWithRetryMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gateway-credential-bound-"));
  process.env.MCP_SERVERS_PERSIST_PATH = path.join(tempDir, "mcp-servers.json");
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
  const { registerMcpServer } = await import("../mcp-registry.js");
  const now = new Date().toISOString();
  registerMcpServer({ name: "jira", type: "http", url: "http://mcp-jira:3002/mcp", description: "", enabled: true, createdAt: now, updatedAt: now } as McpServerDefinition);
  const app = express();
  app.use(express.json({ limit: "25mb" }));
  app.use(queryRouter);
  return app;
}

/** `count` strings of `unit` characters in total `total` bytes (each of one byte per character), `total >= count`. */
function spread(total: number, count: number, fill = "a"): string[] {
  const base = Math.floor(total / count);
  const extra = total - base * count;
  return Array.from({ length: count }, (_, i) => fill.repeat(base + (i < extra ? 1 : 0)));
}

const asHeaders = (values: string[], prefix = "x-v"): Record<string, string> => Object.fromEntries(values.map((value, i) => [`${prefix}${i}`, value]));
const asEnv = (values: string[]): Record<string, string> => Object.fromEntries(values.map((value, i) => [`K${i}`, value]));

type Shape = { overrides?: string[]; httpServer?: string[]; stdioServer?: string[] };

function bodyOf(shape: Shape): Record<string, unknown> {
  const mcpServers: Record<string, unknown> = {};
  if (shape.httpServer) mcpServers.remote = { url: "http://example.invalid/mcp", headers: asHeaders(shape.httpServer, "x-r") };
  if (shape.stdioServer) mcpServers.local = { command: "node", env: asEnv(shape.stdioServer) };
  return {
    queryId: "q-bound",
    prompt: "hello",
    ...(shape.overrides ? { mcpCredentialOverrides: { jira: { headers: asHeaders(shape.overrides) } } } : {}),
    ...(Object.keys(mcpServers).length > 0 ? { mcpServers } : {}),
  };
}

async function post(shape: Shape): Promise<request.Response> {
  const app = await createApp();
  return request(app).post("/v1/query").send(bodyOf(shape));
}

function expectRefused(res: request.Response): void {
  expect(res.status).toBe(400);
  expect(res.body).toEqual({ error: { code: "MCP_CREDENTIALS_TOO_LARGE", message: FIXED_MESSAGE } });
  expect(runQueryWithRetryMock).not.toHaveBeenCalled();
}

function expectAccepted(res: request.Response): void {
  expect(res.status).toBe(200);
  expect(runQueryWithRetryMock).toHaveBeenCalledOnce();
}

describe("POST /v1/query bounds the caller-supplied credential material", () => {
  it("accepts exactly 65,536 bytes of override values and refuses one byte more", async () => {
    expectAccepted(await post({ overrides: spread(MAX_BYTES, 64) }));
    runQueryWithRetryMock.mockClear();
    expectRefused(await post({ overrides: spread(MAX_BYTES + 1, 64) }));
  });

  it("accepts exactly 65,536 bytes of request-server header values and refuses one byte more", async () => {
    expectAccepted(await post({ httpServer: spread(MAX_BYTES, 64) }));
    runQueryWithRetryMock.mockClear();
    expectRefused(await post({ httpServer: spread(MAX_BYTES + 1, 64) }));
  });

  it("accepts exactly 65,536 bytes of request-server env values and refuses one byte more", async () => {
    expectAccepted(await post({ stdioServer: spread(MAX_BYTES, 64) }));
    runQueryWithRetryMock.mockClear();
    expectRefused(await post({ stdioServer: spread(MAX_BYTES + 1, 64) }));
  });

  it("counts the three sources together", async () => {
    const third = Math.floor(MAX_BYTES / 3);
    const rest = MAX_BYTES - 2 * third;
    expectAccepted(await post({ overrides: spread(third, 8), httpServer: spread(third, 8), stdioServer: spread(rest, 8) }));
    runQueryWithRetryMock.mockClear();
    expectRefused(await post({ overrides: spread(third, 8), httpServer: spread(third, 8), stdioServer: spread(rest + 1, 8) }));
  });

  it("counts UTF-8 bytes, not characters", async () => {
    expectAccepted(await post({ overrides: ["é".repeat(MAX_BYTES / 2)] }));
    runQueryWithRetryMock.mockClear();
    expectRefused(await post({ overrides: ["é".repeat(MAX_BYTES / 2), "a"] }));
  });

  it("accepts 256 values and refuses 257, counted across the three sources", async () => {
    expectAccepted(await post({ overrides: spread(256, 256, "a") }));
    runQueryWithRetryMock.mockClear();
    expectRefused(await post({ overrides: spread(257, 257, "a") }));
    runQueryWithRetryMock.mockClear();
    expectAccepted(await post({ overrides: spread(100, 100), httpServer: spread(100, 100), stdioServer: spread(56, 56) }));
    runQueryWithRetryMock.mockClear();
    expectRefused(await post({ overrides: spread(100, 100), httpServer: spread(100, 100), stdioServer: spread(57, 57) }));
  });

  it("answers a fixed text that echoes no value, and starts no run", async () => {
    const marker = "SYNTH-BOUND-MARKER-0123456789";
    const res = await post({ overrides: [`Bearer ${marker}`, ...spread(MAX_BYTES, 8)] });
    expectRefused(res);
    expect(JSON.stringify(res.body)).not.toContain(marker);
    expect(res.text).not.toContain(marker);
  });

  it("refuses an 8 MB request of 1600 values with the same fixed answer", async () => {
    const values = spread(8 * 1024 * 1024, 1600);
    expectRefused(await post({ overrides: values }));
  });
});
