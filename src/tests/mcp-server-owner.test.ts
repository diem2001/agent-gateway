/**
 * Ownership of registered MCP servers (MVP-7925): only the API-key label that registered a server may
 * change or delete it. The routes are mounted behind the real authMiddleware with two labels.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

let tempDir = "";
let persistPath = "";

const KEY_A = "sk-gw-owner-a";
const KEY_B = "sk-gw-owner-b";
const ORIGINAL_URL = "https://jira.a.example/mcp";
const ATTACKER_URL = "https://attacker.example/mcp";

beforeEach(() => {
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gateway-owner-"));
  persistPath = path.join(tempDir, "mcp-servers.json");
  process.env.MCP_SERVERS_PERSIST_PATH = persistPath;
  process.env.API_KEYS = `A:${KEY_A},B:${KEY_B}`;
  vi.resetModules();
});

afterEach(async () => {
  delete process.env.MCP_SERVERS_PERSIST_PATH;
  delete process.env.API_KEYS;
  // The registry persists 100 ms after a change; let that write land before removing its directory.
  await new Promise((resolve) => setTimeout(resolve, 150));
  fs.rmSync(tempDir, { recursive: true, force: true });
});

async function createApp() {
  const { loadApiKeys, authMiddleware } = await import("../auth.js");
  loadApiKeys();
  const { default: mcpRoutes } = await import("../routes/mcp.js");
  const app = express();
  app.use(express.json());
  app.use(authMiddleware);
  app.use(mcpRoutes);
  return app;
}

const as = (key: string) => ({ Authorization: `Bearer ${key}` });

describe("another label cannot change or delete a registered MCP server", () => {
  it("label B's PUT leaves label A's address in place", async () => {
    const app = await createApp();
    const created = await request(app).put("/v1/mcp-servers/jira").set(as(KEY_A)).send({ type: "http", url: ORIGINAL_URL });
    expect(created.status).toBe(201);

    const attack = await request(app).put("/v1/mcp-servers/jira").set(as(KEY_B)).send({ type: "http", url: ATTACKER_URL });
    expect(attack.status).toBe(403);
    expect(attack.body).toEqual({
      error: { code: "MCP_SERVER_OWNER_MISMATCH", message: 'MCP server "jira" is registered by another application' },
    });

    const stored = await request(app).get("/v1/mcp-servers/jira").set(as(KEY_A));
    expect(stored.body.url).toBe(ORIGINAL_URL);
  });

  it("label B's DELETE leaves the server registered", async () => {
    const app = await createApp();
    await request(app).put("/v1/mcp-servers/jira").set(as(KEY_A)).send({ type: "http", url: ORIGINAL_URL });

    const attack = await request(app).delete("/v1/mcp-servers/jira").set(as(KEY_B));
    expect(attack.status).toBe(403);

    const stored = await request(app).get("/v1/mcp-servers/jira").set(as(KEY_A));
    expect(stored.status).toBe(200);
    expect(stored.body.url).toBe(ORIGINAL_URL);
  });
});
