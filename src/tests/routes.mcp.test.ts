import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { UserCredentialSchema } from "../mcp-registry.js";
import { TEST_OWNER, mountLabelAuth, mountOwnerAuth } from "./helpers/owner-auth.js";

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
  await mountOwnerAuth(app);
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

describe("PUT /v1/mcp-servers/:name name rule for new entries (MVP-7763)", () => {
  const NAME_ERROR = {
    code: "MCP_SERVER_NAME_INVALID",
    message: "Use 1–32 letters, digits, '-' or '_', starting with a letter or digit.",
  };
  const httpBody = { type: "http", url: "http://aida-sim:8080/mcp", requireUserCredentials: true };

  it.each(["Ask Aida (AI-Admin)", "a.b", "a".repeat(33), "-aida", "_aida"])(
    "refuses to create %j with 400 MCP_SERVER_NAME_INVALID and stores nothing",
    async (name) => {
      const app = await createApp();
      const res = await request(app).put(`/v1/mcp-servers/${encodeURIComponent(name)}`).send(httpBody);

      expect(res.status).toBe(400);
      expect(res.body).toEqual({ error: NAME_ERROR });
      expect((await request(app).get(`/v1/mcp-servers/${encodeURIComponent(name)}`)).status).toBe(404);
      expect((await request(app).get("/v1/mcp-servers")).body.servers).toEqual([]);
    },
  );

  it("checks the name before any other validation", async () => {
    const app = await createApp();
    const res = await request(app).put("/v1/mcp-servers/a.b").send({});
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: NAME_ERROR });
  });

  it.each(["aida", "a".repeat(32), "A1_b-2", "9x"])("creates %j", async (name) => {
    const app = await createApp();
    const res = await request(app).put(`/v1/mcp-servers/${name}`).send(httpBody);
    expect(res.status).toBe(201);
    expect(res.body.name).toBe(name);
  });

  it("still updates and deletes a legacy entry whose name fails the rule", async () => {
    const legacy = "Ask Aida (AI-Admin)";
    const { registerMcpServer } = await import("../mcp-registry.js");
    registerMcpServer({
      name: legacy,
      description: "created before the name rule",
      enabled: true,
      type: "http",
      url: "http://aida-sim:8080/mcp",
      requireUserCredentials: true,
      owner: TEST_OWNER,
      createdAt: "2026-09-01T00:00:00.000Z",
      updatedAt: "2026-09-01T00:00:00.000Z",
    });
    const app = await createApp();
    const path = `/v1/mcp-servers/${encodeURIComponent(legacy)}`;

    const update = await request(app)
      .put(path)
      .send({ ...httpBody, enabled: false, description: "switched off" });
    expect(update.status).toBe(200);
    expect(update.body).toMatchObject({
      name: legacy,
      enabled: false,
      description: "switched off",
      createdAt: "2026-09-01T00:00:00.000Z",
    });

    const del = await request(app).delete(path);
    expect(del.status).toBe(204);
    expect((await request(app).get(path)).status).toBe(404);
  });
});


/**
 * The gateway reserves `agent-gateway-tools` for its own webhook tool server (MVP-8203). The registry refuses the name
 * after the owner check (MVP-7925), whatever the body, and never changes a stored entry of that name. Two real labels
 * act through the real authMiddleware; the persisted file is compared byte for byte after the 100 ms save debounce.
 */
describe("PUT /v1/mcp-servers/agent-gateway-tools reserved name (MVP-8203)", () => {
  const RESERVED = "agent-gateway-tools";
  const ALPHA = { Authorization: "Bearer sk-gw-reserved-alpha" };
  const BETA = { Authorization: "Bearer sk-gw-reserved-beta" };
  const RESERVED_ERROR = {
    error: { code: "MCP_SERVER_NAME_RESERVED", message: '"agent-gateway-tools" is reserved for the gateway\'s webhook tools' },
  };
  const OWNER_ERROR = {
    error: { code: "MCP_SERVER_OWNER_MISMATCH", message: `MCP server "${RESERVED}" is registered by another application` },
  };
  const validBody = { type: "http", url: "http://reserved.example.test/mcp", headers: { "X-Probe": "replaced" } };
  const NOW = "2026-09-01T00:00:00.000Z";

  afterEach(() => {
    delete process.env.API_KEYS;
  });

  async function createTwoLabelApp(options: { auth?: boolean } = {}) {
    const { default: mcpRoutes } = await import("../routes/mcp.js");
    const app = express();
    app.use(express.json());
    if (options.auth !== false) await mountLabelAuth(app, { alpha: "sk-gw-reserved-alpha", beta: "sk-gw-reserved-beta" });
    app.use(mcpRoutes);
    return app;
  }

  /** A legacy entry as stored before the fix: headers, env and args all set, owner optional. */
  async function seedLegacy(overrides: Record<string, unknown> = {}) {
    const registry = await import("../mcp-registry.js");
    registry.registerMcpServer({
      name: RESERVED,
      description: "stored before the reserved name",
      enabled: true,
      type: "stdio",
      command: "node",
      args: ["-e", "0"],
      env: { SEEDED_ENV: "seeded-env-value" },
      headers: { "X-Seeded": "seeded-header-value" },
      owner: "alpha",
      createdAt: NOW,
      updatedAt: NOW,
      ...overrides,
    } as never);
    registry.flushMcpServers();
    return registry;
  }

  const fileBytes = () => fs.readFileSync(persistPath, "utf-8");

  it("R1: a label with no entry gets 400 MCP_SERVER_NAME_RESERVED, nothing is created in memory, on the route or on disk", async () => {
    const registry = await import("../mcp-registry.js");
    const app = await createTwoLabelApp();
    const res = await request(app).put(`/v1/mcp-servers/${RESERVED}`).set(ALPHA).send(validBody);
    expect(res.status).toBe(400);
    expect(res.body).toEqual(RESERVED_ERROR);
    expect(res.text).toBe(JSON.stringify(RESERVED_ERROR));
    expect((await request(app).get(`/v1/mcp-servers/${RESERVED}`).set(ALPHA)).status).toBe(404);
    expect(registry.getMcpServer(RESERVED)).toBeUndefined();
    await waitForPersistence();
    expect(fs.existsSync(persistPath)).toBe(false);
  });

  it("R2: the owner of a legacy entry gets 400 and the stored definition, headers, env and args included, stays as seeded", async () => {
    const registry = await seedLegacy();
    const before = structuredClone(registry.getMcpServer(RESERVED));
    const bytes = fileBytes();
    const app = await createTwoLabelApp();
    const res = await request(app).put(`/v1/mcp-servers/${RESERVED}`).set(ALPHA).send(validBody);
    expect(res.status).toBe(400);
    expect(res.body).toEqual(RESERVED_ERROR);
    expect(registry.getMcpServer(RESERVED)).toEqual(before);
    expect(before).toMatchObject({ args: ["-e", "0"], env: { SEEDED_ENV: "seeded-env-value" }, headers: { "X-Seeded": "seeded-header-value" } });
    await waitForPersistence();
    expect(fileBytes()).toBe(bytes);
  });

  it("R3: another label gets the unchanged 403 MCP_SERVER_OWNER_MISMATCH and the entry stays as seeded", async () => {
    const registry = await seedLegacy();
    const before = structuredClone(registry.getMcpServer(RESERVED));
    const bytes = fileBytes();
    const app = await createTwoLabelApp();
    const res = await request(app).put(`/v1/mcp-servers/${RESERVED}`).set(BETA).send(validBody);
    expect(res.status).toBe(403);
    expect(res.body).toEqual(OWNER_ERROR);
    expect(registry.getMcpServer(RESERVED)).toEqual(before);
    await waitForPersistence();
    expect(fileBytes()).toBe(bytes);
  });

  it("R4: an ownerless legacy entry is refused for every label with the unchanged 403", async () => {
    const registry = await seedLegacy({ owner: undefined });
    const before = structuredClone(registry.getMcpServer(RESERVED));
    expect(before?.owner).toBeUndefined();
    const bytes = fileBytes();
    const app = await createTwoLabelApp();
    for (const caller of [ALPHA, BETA]) {
      const res = await request(app).put(`/v1/mcp-servers/${RESERVED}`).set(caller).send(validBody);
      expect(res.status).toBe(403);
      expect(res.body).toEqual(OWNER_ERROR);
    }
    expect(registry.getMcpServer(RESERVED)).toEqual(before);
    await waitForPersistence();
    expect(fileBytes()).toBe(bytes);
  });

  it("R5: a caller without a label and no entry keeps the unchanged 403, whatever the name", async () => {
    const registry = await import("../mcp-registry.js");
    const app = await createTwoLabelApp({ auth: false });
    const res = await request(app).put(`/v1/mcp-servers/${RESERVED}`).send(validBody);
    expect(res.status).toBe(403);
    expect(res.body).toEqual(OWNER_ERROR);
    expect(registry.getMcpServer(RESERVED)).toBeUndefined();
    await waitForPersistence();
    expect(fs.existsSync(persistPath)).toBe(false);
  });

  it.each([
    ["an empty body", {}],
    ["an invalid type", { type: "bogus" }],
  ])("R6: %s does not change the outcome: a new name and a legacy owner get 400 RESERVED, another label 403", async (_label, body) => {
    const app = await createTwoLabelApp();
    const fresh = await request(app).put(`/v1/mcp-servers/${RESERVED}`).set(ALPHA).send(body);
    expect(fresh.status).toBe(400);
    expect(fresh.body).toEqual(RESERVED_ERROR);

    await seedLegacy();
    const owner = await request(app).put(`/v1/mcp-servers/${RESERVED}`).set(ALPHA).send(body);
    expect(owner.status).toBe(400);
    expect(owner.body).toEqual(RESERVED_ERROR);
    const other = await request(app).put(`/v1/mcp-servers/${RESERVED}`).set(BETA).send(body);
    expect(other.status).toBe(403);
    expect(other.body).toEqual(OWNER_ERROR);
  });

  it("R7: a non-owner restart enables a disabled legacy entry (route unchanged), yet no run selection ever holds it", async () => {
    const registry = await seedLegacy({ enabled: false });
    const app = await createTwoLabelApp();
    const restart = await request(app).post(`/v1/mcp-servers/${RESERVED}/restart`).set(BETA);
    expect(restart.status).toBe(200);
    expect(registry.getMcpServer(RESERVED)?.enabled).toBe(true);
    expect(registry.buildMcpServersForSdk()).toBeNull();
    expect(registry.getMcpAllowedToolPatterns()).toEqual([]);
  });

  it("C1 control: the same caller registers a non-reserved name through the same route and app: 201, file changes, GET 200", async () => {
    const app = await createTwoLabelApp();
    const put = await request(app).put("/v1/mcp-servers/alpha-tools").set(ALPHA).send(validBody);
    expect(put.status).toBe(201);
    expect(put.body.name).toBe("alpha-tools");
    expect((await request(app).get("/v1/mcp-servers/alpha-tools").set(ALPHA)).status).toBe(200);
    await waitForPersistence();
    expect(JSON.parse(fileBytes())).toEqual([expect.objectContaining({ name: "alpha-tools", owner: "alpha" })]);
  });
});
