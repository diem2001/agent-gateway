import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { UserCredentialSchema } from "../mcp-registry.js";

let tempDir: string;
let persistPath: string;

const JIRA_SCHEMA: UserCredentialSchema = {
  fields: [
    {
      key: "email",
      label: "Atlassian Email",
      type: "email",
      required: true,
    },
    {
      key: "apiToken",
      label: "API Token",
      type: "password",
      required: true,
      description: "Generate at https://id.atlassian.com/manage-profile/security/api-tokens",
    },
  ],
  outputs: [
    {
      target: "headers",
      outputKey: "Authorization",
      template: "basic:{email}:{apiToken}",
    },
  ],
};

beforeEach(() => {
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gateway-mcp-"));
  persistPath = path.join(tempDir, "mcp-servers.json");
  process.env.MCP_SERVERS_PERSIST_PATH = persistPath;
  vi.resetModules();
});

afterEach(() => {
  delete process.env.MCP_SERVERS_PERSIST_PATH;
  fs.rmSync(tempDir, { recursive: true, force: true });
});

async function createApp() {
  const { default: mcpRoutes } = await import("../routes/mcp.js");
  const app = express();
  app.use(express.json());
  app.use(mcpRoutes);
  return app;
}

async function waitForPersistence() {
  await new Promise((resolve) => setTimeout(resolve, 150));
}

describe("PUT /v1/mcp-servers/:name userCredentialSchema", () => {
  it("round-trips a Jira HTTP header schema through PUT, GET single, GET list, and persistence", async () => {
    const app = await createApp();
    const body = {
      description: "Atlassian Jira MCP server (HTTP transport)",
      enabled: true,
      type: "http",
      url: "http://mcp-jira:3002/mcp",
      headers: {},
      userCredentialSchema: JIRA_SCHEMA,
    };

    const put = await request(app).put("/v1/mcp-servers/jira").send(body);
    expect(put.status).toBe(201);
    expect(put.body.userCredentialSchema).toEqual(JIRA_SCHEMA);

    const get = await request(app).get("/v1/mcp-servers/jira");
    expect(get.status).toBe(200);
    expect(get.body.userCredentialSchema).toEqual(JIRA_SCHEMA);

    const list = await request(app).get("/v1/mcp-servers");
    expect(list.status).toBe(200);
    expect(list.body.servers).toEqual(
      expect.arrayContaining([expect.objectContaining({ name: "jira", userCredentialSchema: JIRA_SCHEMA })]),
    );

    await waitForPersistence();
    const persisted = JSON.parse(fs.readFileSync(persistPath, "utf-8")) as Array<{
      name: string;
      userCredentialSchema?: UserCredentialSchema;
    }>;
    expect(persisted).toEqual(
      expect.arrayContaining([expect.objectContaining({ name: "jira", userCredentialSchema: JIRA_SCHEMA })]),
    );
  });

  it("keeps existing server definitions without userCredentialSchema backward-compatible", async () => {
    const app = await createApp();
    const res = await request(app).put("/v1/mcp-servers/plain").send({
      description: "Plain HTTP MCP server",
      enabled: true,
      type: "http",
      url: "http://plain.example.test/mcp",
    });

    expect(res.status).toBe(201);
    expect(res.body.userCredentialSchema).toBeUndefined();
  });

  it("rejects schema output targets that do not match the transport", async () => {
    const app = await createApp();
    const res = await request(app)
      .put("/v1/mcp-servers/jira")
      .send({
        type: "http",
        url: "http://mcp-jira:3002/mcp",
        userCredentialSchema: {
          ...JIRA_SCHEMA,
          outputs: [{ target: "env", outputKey: "JIRA_API_TOKEN", template: "{apiToken}" }],
        },
      });

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe("SCHEMA_TARGET_MISMATCH");
  });

  it("rejects templates that reference fields absent from fields", async () => {
    const app = await createApp();
    const res = await request(app)
      .put("/v1/mcp-servers/jira")
      .send({
        type: "http",
        url: "http://mcp-jira:3002/mcp",
        userCredentialSchema: {
          ...JIRA_SCHEMA,
          outputs: [{ target: "headers", outputKey: "Authorization", template: "basic:{email}:{missing}" }],
        },
      });

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe("SCHEMA_TEMPLATE_UNKNOWN_FIELD");
  });

  it("rejects duplicate field keys", async () => {
    const app = await createApp();
    const res = await request(app)
      .put("/v1/mcp-servers/jira")
      .send({
        type: "http",
        url: "http://mcp-jira:3002/mcp",
        userCredentialSchema: {
          ...JIRA_SCHEMA,
          fields: [JIRA_SCHEMA.fields[0], { ...JIRA_SCHEMA.fields[1], key: "email" }],
        },
      });

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe("SCHEMA_FIELD_KEY_DUPLICATE");
  });

  it("rejects invalid field types", async () => {
    const app = await createApp();
    const res = await request(app)
      .put("/v1/mcp-servers/jira")
      .send({
        type: "http",
        url: "http://mcp-jira:3002/mcp",
        userCredentialSchema: {
          ...JIRA_SCHEMA,
          fields: [{ ...JIRA_SCHEMA.fields[0], type: "totp" }],
        },
      });

    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe("SCHEMA_FIELD_TYPE_INVALID");
  });
});
