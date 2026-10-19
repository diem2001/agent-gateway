/**
 * Prevention test for MVP-7957: every `McpServerDefinition` field carries a class (public, write-only or internal) and
 * a response-path test. The fixture below must name EVERY field, so a field added without a class and a marker here
 * fails to compile and fails the key-set check; each marker is then traced through list, detail and PUT replies.
 * Also pins the one URL rule (`publicUrlProblem`) that decides both what a write accepts and what a read returns.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { McpServerDefinition } from "../mcp-registry.js";

const OWNER = "FC-MARKER-owner";
const OTHER = "label-other-fc";
const KEY_OWNER = "sk-gw-fc-owner";
const KEY_OTHER = "sk-gw-fc-other";
const URL = "https://fc.example/FC-MARKER-url";

/** One distinct marker per field; the value type forces an entry for every field of the definition. */
const FIXTURE: Record<keyof McpServerDefinition, unknown> = {
  name: "fc-server",
  description: "FC-MARKER-description",
  enabled: true,
  type: "http",
  url: URL,
  headers: { Authorization: "FC-MARKER-headers" },
  command: "FC-MARKER-command",
  args: ["FC-MARKER-args"],
  env: { TOKEN: "FC-MARKER-env" },
  allowedToolsPattern: "FC-MARKER-allowedToolsPattern",
  userCredentialSchema: {
    fields: [{ key: "FC-MARKER-userCredentialSchema", label: "Token", type: "text", required: false }],
    outputs: [],
  },
  requireUserCredentials: false,
  owner: OWNER,
  createdAt: "FC-MARKER-createdAt",
  updatedAt: "FC-MARKER-updatedAt",
};

let tempDir = "";

beforeEach(() => {
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gateway-field-class-"));
  process.env.MCP_SERVERS_PERSIST_PATH = path.join(tempDir, "mcp-servers.json");
  process.env.API_KEYS = `${OWNER}:${KEY_OWNER},${OTHER}:${KEY_OTHER}`;
  vi.spyOn(console, "log").mockImplementation(() => {});
  vi.resetModules();
});

afterEach(async () => {
  vi.restoreAllMocks();
  delete process.env.MCP_SERVERS_PERSIST_PATH;
  delete process.env.API_KEYS;
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
const markerOf = (field: string) => `FC-MARKER-${field}`;

describe("every registry field is classified and only public fields reach a client", () => {
  it("the fixture and the classification name exactly the same fields", async () => {
    const { mcpFieldClasses } = await import("../mcp-registry.js");
    expect(Object.keys(mcpFieldClasses()).sort()).toEqual(Object.keys(FIXTURE).sort());
  });

  it("the classes are the designed ones", async () => {
    const { mcpFieldClasses } = await import("../mcp-registry.js");
    const classes = mcpFieldClasses();
    expect(classes.url).toBe("public");
    expect(classes.args).toBe("write-only");
    expect(classes.headers).toBe("write-only");
    expect(classes.env).toBe("write-only");
    expect(classes.owner).toBe("internal");
  });

  const markerFields = Object.keys(FIXTURE).filter((field) => JSON.stringify(FIXTURE[field as keyof McpServerDefinition]).includes("FC-MARKER"));

  for (const [who, key] of [
    ["the owner", KEY_OWNER],
    ["another label", KEY_OTHER],
  ] as const) {
    it(`list and detail for ${who} return exactly the public fields; a marker shows only for a public field`, async () => {
      const app = await createApp();
      const { registerMcpServer, mcpFieldClasses } = await import("../mcp-registry.js");
      registerMcpServer(FIXTURE as never);
      const classes = mcpFieldClasses();
      const publicKeys = Object.keys(classes).filter((field) => classes[field as keyof typeof classes] === "public").sort();

      const list = await request(app).get("/v1/mcp-servers").set(as(key));
      const detail = await request(app).get("/v1/mcp-servers/fc-server").set(as(key));
      expect(Object.keys(list.body.servers[0]).sort()).toEqual(publicKeys);
      expect(Object.keys(detail.body).sort()).toEqual(publicKeys);
      for (const res of [list, detail]) {
        for (const field of markerFields) {
          const shown = res.text.includes(markerOf(field));
          expect({ field, shown }).toEqual({ field, shown: classes[field as keyof typeof classes] === "public" });
        }
      }
    });
  }

  it("a successful PUT reply carries no marker of a write-only or internal field", async () => {
    const app = await createApp();
    const { mcpFieldClasses } = await import("../mcp-registry.js");
    const classes = mcpFieldClasses();
    const { owner: _owner, createdAt: _c, updatedAt: _u, ...body } = FIXTURE;
    const res = await request(app).put("/v1/mcp-servers/fc-server").set(as(KEY_OWNER)).send(body);
    expect(res.status).toBe(201);
    for (const field of markerFields) {
      if (classes[field as keyof typeof classes] !== "public") expect(res.text).not.toContain(markerOf(field));
    }
    expect(res.body.url).toBe(URL);
  });
});

describe("publicUrlProblem: the one predicate behind the write rule and the read decision", () => {
  const table: Array<[string, unknown, string | null]> = [
    ["plain https", "https://host.example", null],
    ["https with path", "https://host.example/mcp/v1", null],
    ["http with port", "http://host.example:8080/mcp", null],
    ["uppercase scheme", "HTTPS://host.example/mcp", null],
    ["IPv6 host", "http://[::1]:3000/mcp", null],
    ["encoded @ in the path", "https://host.example/a%40b", null],
    ["user and password", "https://user:pw@host.example/", "user_info"],
    ["user only", "https://user@host.example/", "user_info"],
    ["empty user info", "https://@host.example/", "user_info"],
    ["encoded @ in the user", "https://us%40er@host.example/", "user_info"],
    ["IPv6 with user info", "http://u@[::1]/", "user_info"],
    ["query", "https://host.example/mcp?a=1", "query"],
    ["empty query", "https://host.example/mcp?", "query"],
    ["fragment", "https://host.example/mcp#a", "fragment"],
    ["empty fragment", "https://host.example/mcp#", "fragment"],
    ["fragment holding a question mark", "https://host.example/mcp#a?b", "fragment"],
    ["scheme without slashes and user info", "https:user:pass@host.example", "invalid"],
    ["single slash after the scheme", "http:/host.example", "invalid"],
    ["backslash", "https://host.example\\mcp", "invalid"],
    ["space", "https://host.example/a b", "invalid"],
    ["tab", "https://host.example/a\tb", "invalid"],
    ["newline", "https://host.example/a\nb", "invalid"],
    ["NUL", "https://host.example/a\0b", "invalid"],
    ["ftp", "ftp://host.example/", "invalid"],
    ["ws", "ws://host.example/", "invalid"],
    ["file", "file:///etc/passwd", "invalid"],
    ["javascript", "javascript:alert(1)", "invalid"],
    ["no host", "https:///mcp", "invalid"],
    ["unparsable", "not a url", "invalid"],
    ["empty string", "", "invalid"],
    ["null", null, "invalid"],
    ["undefined", undefined, "invalid"],
    ["number", 42, "invalid"],
    ["object", { href: "https://host.example/" }, "invalid"],
  ];

  for (const [label, input, expected] of table) {
    it(`${label} -> ${expected ?? "accepted"}`, async () => {
      const { publicUrlProblem } = await import("../mcp-registry.js");
      expect(publicUrlProblem(input)).toBe(expected);
    });
  }
});
