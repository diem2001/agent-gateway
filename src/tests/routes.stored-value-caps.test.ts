/**
 * Write caps for the stored values that reach the masking (MVP-8207): a header, env or args value of `PUT
 * /v1/mcp-servers/:name` holds at most 65,536 UTF-8 bytes and the `webhook_url` of `PUT /v1/tools/:name` at most 8,192.
 * Over the cap the answer is 400 with a fixed code and text that echo no value, and nothing is stored. An entry already
 * stored over the cap (written before the caps, or by hand) still loads and can be edited without resending the value.
 * The limits are written out here on purpose, not read from the source.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const VALUE_CAP = 65_536;
const URL_CAP = 8_192;
let dir: string;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "stored-value-caps-"));
  process.env.MCP_SERVERS_PERSIST_PATH = path.join(dir, "mcp-servers.json");
  process.env.TOOLS_PERSIST_PATH = path.join(dir, "tools.json");
  vi.resetModules();
});
afterEach(async () => {
  delete process.env.MCP_SERVERS_PERSIST_PATH;
  delete process.env.TOOLS_PERSIST_PATH;
  await new Promise((resolve) => setTimeout(resolve, 150));
  fs.rmSync(dir, { recursive: true, force: true });
});

async function apps() {
  const mcp = (await import("../routes/mcp.js")).default;
  const tools = (await import("../routes/tools.js")).default;
  const app = express();
  app.use(express.json({ limit: "25mb" }));
  app.use((req, _res, next) => {
    (req as unknown as { clientLabel: string }).clientLabel = "reqlift";
    next();
  });
  app.use(mcp);
  app.use(tools);
  return app;
}

const HTTP = { type: "http", url: "https://example.com/mcp" };

describe("PUT /v1/mcp-servers/:name value caps", () => {
  it.each([
    ["a header value", (v: string) => ({ ...HTTP, headers: { Authorization: v } })],
    ["an env value", (v: string) => ({ type: "stdio", command: "node", env: { TOKEN: v } })],
    ["an args value", (v: string) => ({ type: "stdio", command: "node", args: [v] })],
  ])("%s of exactly 65,536 bytes is accepted and one byte more is refused with the fixed code", async (_label, body) => {
    const app = await apps();
    const ok = await request(app).put("/v1/mcp-servers/atcap").send(body("a".repeat(VALUE_CAP)));
    expect(ok.status).toBe(201);
    const marker = "SYNTH-CAP-MARKER-8207";
    const over = await request(app).put("/v1/mcp-servers/overcap").send(body(marker + "a".repeat(VALUE_CAP + 1 - marker.length)));
    expect(over.status).toBe(400);
    expect(over.body.error.code).toBe("MCP_SERVER_VALUE_TOO_LARGE");
    expect(over.body.error.message).toBe("A header, env or args value may hold at most 65536 bytes.");
    expect(over.text).not.toContain(marker);
    expect((await request(app).get("/v1/mcp-servers/overcap")).status).toBe(404);
  });

  it("counts UTF-8 bytes, not characters", async () => {
    const app = await apps();
    const ok = await request(app).put("/v1/mcp-servers/utf8ok").send({ ...HTTP, headers: { "X-Long": "é".repeat(VALUE_CAP / 2) } });
    expect(ok.status).toBe(201);
    const over = await request(app).put("/v1/mcp-servers/utf8over").send({ ...HTTP, headers: { "X-Long": "é".repeat(VALUE_CAP / 2) + "a" } });
    expect(over.status).toBe(400);
    expect(over.body.error.code).toBe("MCP_SERVER_VALUE_TOO_LARGE");
  });

  it("an entry stored over the cap loads, is listed, and an edit that omits the maps keeps them", async () => {
    const now = new Date().toISOString();
    fs.writeFileSync(
      process.env.MCP_SERVERS_PERSIST_PATH!,
      JSON.stringify([{ name: "stored", type: "http", url: "https://example.com/mcp", description: "old", enabled: true, headers: { Authorization: "x".repeat(VALUE_CAP * 4) }, owner: "reqlift", createdAt: now, updatedAt: now }]),
    );
    const { loadMcpServers, getMcpServer } = await import("../mcp-registry.js");
    loadMcpServers();
    const app = await apps();
    expect((await request(app).get("/v1/mcp-servers/stored")).status).toBe(200);
    const edit = await request(app).put("/v1/mcp-servers/stored").send({ ...HTTP, description: "edited" });
    expect(edit.status).toBe(200);
    expect(getMcpServer("stored")?.headers?.Authorization).toHaveLength(VALUE_CAP * 4);
  });
});

describe("PUT /v1/tools/:name webhook_url cap", () => {
  const tool = (url: string) => ({ description: "d", input_schema: { type: "object", properties: {} }, webhook_url: url });
  const urlOf = (bytes: number): string => `https://example.com/${"a".repeat(bytes - "https://example.com/".length)}`;

  it("an address of exactly 8,192 bytes is accepted and one byte more is refused with the fixed code", async () => {
    const app = await apps();
    expect((await request(app).put("/v1/tools/atcap").send(tool(urlOf(URL_CAP)))).status).toBe(201);
    const over = await request(app).put("/v1/tools/overcap").send(tool(`${urlOf(URL_CAP)}b`));
    expect(over.status).toBe(400);
    expect(over.body.error.code).toBe("TOOL_WEBHOOK_URL_TOO_LONG");
    expect(over.body.error.message).toBe("webhook_url may hold at most 8192 bytes.");
    expect(over.text).not.toContain("aaaaaaaa");
    expect((await request(app).get("/v1/tools/overcap")).status).toBe(404);
  });

  it("a tool stored over the cap loads and stays listed", async () => {
    fs.writeFileSync(
      process.env.TOOLS_PERSIST_PATH!,
      JSON.stringify([{ name: "stored", description: "d", input_schema: { type: "object", properties: {} }, webhook_url: urlOf(URL_CAP * 8), timeout_ms: 1000, owner: "reqlift", stream_input: "summary" }]),
    );
    const { loadTools } = await import("../tools.js");
    loadTools();
    const app = await apps();
    const got = await request(app).get("/v1/tools/stored");
    expect(got.status).toBe(200);
    expect(got.body.webhook_url).toHaveLength(URL_CAP * 8);
  });
});
