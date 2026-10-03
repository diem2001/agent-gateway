/**
 * Stored MCP server `headers` and `env` are write-only (MVP-7936): no registry read or successful write answers
 * with them, whatever the caller's label, while an owner-authorized PUT keeps a map it does not send, replaces one it
 * sends and clears one sent as `{}`. The routes are mounted behind the real authMiddleware with an owner, another
 * label and an ownerless legacy entry; the real-gateway rows are in security-registry-process.test.ts.
 */
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

let tempDir = "";

const OWNER = "label-owner";
const OTHER = "label-other";
const KEY_OWNER = "sk-gw-wo-owner";
const KEY_OTHER = "sk-gw-wo-other";
const HEADER_MARKER = "HDR-MARKER-7936-aaaa1111";
const ENV_MARKER = "ENV-MARKER-7936-bbbb2222";
const HEADER_MARKER_2 = "HDR-MARKER-7936-cccc3333";
const ENV_MARKER_2 = "ENV-MARKER-7936-dddd4444";
const MARKERS = [HEADER_MARKER, ENV_MARKER, HEADER_MARKER_2, ENV_MARKER_2];
const HTTP_URL = "https://jira.owner.example/mcp";

beforeEach(() => {
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gateway-write-only-"));
  process.env.MCP_SERVERS_PERSIST_PATH = path.join(tempDir, "mcp-servers.json");
  process.env.API_KEYS = `${OWNER}:${KEY_OWNER},${OTHER}:${KEY_OTHER}`;
  vi.spyOn(console, "log").mockImplementation(() => {});
  vi.resetModules();
});

afterEach(async () => {
  vi.restoreAllMocks();
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

/** The stored definition as the runs see it, bypassing every response filter. */
async function stored(name: string) {
  const { getMcpServer } = await import("../mcp-registry.js");
  return getMcpServer(name);
}

/** An entry as it was stored before ownership existed, optionally with a key no current field names. */
async function seedOwnerless(name: string, extra: Record<string, unknown> = {}) {
  const { registerMcpServer } = await import("../mcp-registry.js");
  const now = "2026-09-01T00:00:00.000Z";
  registerMcpServer({
    name,
    description: "legacy",
    enabled: true,
    type: "http",
    url: HTTP_URL,
    headers: { Authorization: HEADER_MARKER },
    createdAt: now,
    updatedAt: now,
    ...extra,
  } as never);
}

const httpBody = (extra: Record<string, unknown> = {}) => ({
  type: "http",
  url: HTTP_URL,
  description: "Jira",
  headers: { Authorization: HEADER_MARKER },
  env: { DORMANT_TOKEN: ENV_MARKER },
  ...extra,
});

const stdioBody = (extra: Record<string, unknown> = {}) => ({
  type: "stdio",
  command: "node",
  args: ["server.js"],
  description: "Local",
  env: { API_TOKEN: ENV_MARKER },
  ...extra,
});

function expectNoSecrets(res: { text: string }) {
  for (const marker of MARKERS) expect(res.text).not.toContain(marker);
}

function expectNoMaps(body: Record<string, unknown>) {
  expect(body).not.toHaveProperty("headers");
  expect(body).not.toHaveProperty("env");
  expect(body).not.toHaveProperty("owner");
}

describe("registry reads never disclose stored headers or env", () => {
  const callers = [
    ["the owner", KEY_OWNER],
    ["another label", KEY_OTHER],
  ] as const;

  for (const [who, key] of callers) {
    it(`list and detail for ${who}: metadata only, no property and no marker`, async () => {
      const app = await createApp();
      const created = await request(app).put("/v1/mcp-servers/jira").set(as(KEY_OWNER)).send(httpBody({ requireUserCredentials: true }));
      expect(created.status).toBe(201);
      await request(app).put("/v1/mcp-servers/local").set(as(KEY_OWNER)).send(stdioBody());
      await seedOwnerless("legacy");

      const list = await request(app).get("/v1/mcp-servers").set(as(key));
      expect(list.status).toBe(200);
      expect(list.body.servers.map((s: { name: string }) => s.name).sort()).toEqual(["jira", "legacy", "local"]);
      for (const server of list.body.servers) expectNoMaps(server);
      expectNoSecrets(list);
      const jira = list.body.servers.find((s: { name: string }) => s.name === "jira");
      expect(jira).toMatchObject({ name: "jira", type: "http", url: HTTP_URL, enabled: true, description: "Jira", requireUserCredentials: true });
      expect(jira.createdAt).toEqual(expect.any(String));
      expect(jira.updatedAt).toEqual(expect.any(String));

      for (const name of ["jira", "local", "legacy"]) {
        const detail = await request(app).get(`/v1/mcp-servers/${name}`).set(as(key));
        expect(detail.status).toBe(200);
        expectNoMaps(detail.body);
        expectNoSecrets(detail);
        expect(detail.body.name).toBe(name);
      }
      const local = await request(app).get("/v1/mcp-servers/local").set(as(key));
      expect(local.body).toMatchObject({ type: "stdio", command: "node" });
      expect(local.body).not.toHaveProperty("args");
    });
  }

  it("a missing server's detail is still 404", async () => {
    const app = await createApp();
    const res = await request(app).get("/v1/mcp-servers/nope").set(as(KEY_OTHER));
    expect(res.status).toBe(404);
  });

  it("a key in a persisted legacy file that no current field names is not returned either", async () => {
    const app = await createApp();
    await seedOwnerless("legacy", { legacyAuth: HEADER_MARKER_2, extraSecret: { nested: ENV_MARKER_2 } });

    const list = await request(app).get("/v1/mcp-servers").set(as(KEY_OTHER));
    const detail = await request(app).get("/v1/mcp-servers/legacy").set(as(KEY_OTHER));

    for (const res of [list, detail]) {
      expectNoSecrets(res);
      expect(res.text).not.toContain("legacyAuth");
      expect(res.text).not.toContain("extraSecret");
    }
    expect(detail.body.name).toBe("legacy");
  });
});

describe("a successful write never answers with stored headers or env", () => {
  it("a new registration (201) and an owner update (200) return metadata only; the registry holds the submitted maps", async () => {
    const app = await createApp();
    const created = await request(app).put("/v1/mcp-servers/jira").set(as(KEY_OWNER)).send(httpBody());
    expect(created.status).toBe(201);
    expectNoMaps(created.body);
    expectNoSecrets(created);
    expect(created.body).toMatchObject({ name: "jira", type: "http", url: HTTP_URL });
    expect(await stored("jira")).toMatchObject({ headers: { Authorization: HEADER_MARKER }, env: { DORMANT_TOKEN: ENV_MARKER } });

    const updated = await request(app)
      .put("/v1/mcp-servers/jira")
      .set(as(KEY_OWNER))
      .send(httpBody({ headers: { Authorization: HEADER_MARKER_2 }, env: { DORMANT_TOKEN: ENV_MARKER_2 } }));
    expect(updated.status).toBe(200);
    expectNoMaps(updated.body);
    expectNoSecrets(updated);
    expect(await stored("jira")).toMatchObject({ headers: { Authorization: HEADER_MARKER_2 }, env: { DORMANT_TOKEN: ENV_MARKER_2 } });
  });
});

describe("a refused write changes nothing and discloses nothing", () => {
  it("another label's PUT on an owned entry and any label's PUT on an ownerless entry: 403, both maps unchanged", async () => {
    const app = await createApp();
    await request(app).put("/v1/mcp-servers/jira").set(as(KEY_OWNER)).send(httpBody());
    await seedOwnerless("legacy", { env: { LEGACY_ENV: ENV_MARKER } });
    const jiraBefore = structuredClone(await stored("jira"));
    const legacyBefore = structuredClone(await stored("legacy"));

    const attempts = [
      await request(app).put("/v1/mcp-servers/jira").set(as(KEY_OTHER)).send(httpBody({ headers: { Authorization: HEADER_MARKER_2 }, env: {} })),
      await request(app).put("/v1/mcp-servers/legacy").set(as(KEY_OTHER)).send(httpBody({ headers: {}, env: { X: ENV_MARKER_2 } })),
      await request(app).put("/v1/mcp-servers/legacy").set(as(KEY_OWNER)).send({ type: "http", url: HTTP_URL }),
    ];
    for (const res of attempts) {
      expect(res.status).toBe(403);
      expectNoSecrets(res);
    }
    expect(await stored("jira")).toEqual(jiraBefore);
    expect(await stored("legacy")).toEqual(legacyBefore);
  });
});

describe("an owner PUT keeps, replaces or clears each stored map on its own", () => {
  async function seeded() {
    const app = await createApp();
    await request(app).put("/v1/mcp-servers/jira").set(as(KEY_OWNER)).send(httpBody());
    return app;
  }

  it("a metadata edit that omits both maps keeps both", async () => {
    const app = await seeded();
    const res = await request(app).put("/v1/mcp-servers/jira").set(as(KEY_OWNER)).send({ type: "http", url: "https://jira.owner.example/v2", description: "renamed" });
    expect(res.status).toBe(200);
    expect(await stored("jira")).toMatchObject({
      url: "https://jira.owner.example/v2",
      description: "renamed",
      headers: { Authorization: HEADER_MARKER },
      env: { DORMANT_TOKEN: ENV_MARKER },
    });
  });

  it("sending only headers replaces headers and leaves env; sending only env replaces env and leaves headers", async () => {
    const app = await seeded();
    await request(app).put("/v1/mcp-servers/jira").set(as(KEY_OWNER)).send({ type: "http", url: HTTP_URL, headers: { Authorization: HEADER_MARKER_2 } });
    expect(await stored("jira")).toMatchObject({ headers: { Authorization: HEADER_MARKER_2 }, env: { DORMANT_TOKEN: ENV_MARKER } });

    await request(app).put("/v1/mcp-servers/jira").set(as(KEY_OWNER)).send({ type: "http", url: HTTP_URL, env: { DORMANT_TOKEN: ENV_MARKER_2 } });
    expect(await stored("jira")).toMatchObject({ headers: { Authorization: HEADER_MARKER_2 }, env: { DORMANT_TOKEN: ENV_MARKER_2 } });
  });

  it("an empty map clears only that map and removes the property from storage", async () => {
    const app = await seeded();
    const clearHeaders = await request(app).put("/v1/mcp-servers/jira").set(as(KEY_OWNER)).send({ type: "http", url: HTTP_URL, headers: {} });
    expect(clearHeaders.status).toBe(200);
    const afterHeaders = await stored("jira");
    expect(afterHeaders).not.toHaveProperty("headers");
    expect(afterHeaders?.env).toEqual({ DORMANT_TOKEN: ENV_MARKER });

    const clearEnv = await request(app).put("/v1/mcp-servers/jira").set(as(KEY_OWNER)).send({ type: "http", url: HTTP_URL, env: {} });
    expect(clearEnv.status).toBe(200);
    expect(await stored("jira")).not.toHaveProperty("env");
  });

  it("a new registration that omits a map stores no map", async () => {
    const app = await createApp();
    await request(app).put("/v1/mcp-servers/fresh").set(as(KEY_OWNER)).send({ type: "http", url: HTTP_URL });
    const def = await stored("fresh");
    expect(def).not.toHaveProperty("headers");
    expect(def).not.toHaveProperty("env");
  });

  it("a stdio entry keeps its env across a command edit that omits it", async () => {
    const app = await createApp();
    await request(app).put("/v1/mcp-servers/local").set(as(KEY_OWNER)).send(stdioBody());
    await request(app).put("/v1/mcp-servers/local").set(as(KEY_OWNER)).send({ type: "stdio", command: "node", args: ["other.js"] });
    expect(await stored("local")).toMatchObject({ args: ["other.js"], env: { API_TOKEN: ENV_MARKER } });
  });

  it("a destination change that omits the maps keeps the stored credential and the next health check delivers it (accepted limit, MVP-7958)", async () => {
    const hits: Array<{ path: string | undefined; authorization: string | undefined }> = [];
    const stub = http.createServer((req, res) => {
      hits.push({ path: req.url, authorization: req.headers.authorization });
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ status: "up" }));
    });
    await new Promise<void>((resolve) => stub.listen(0, "127.0.0.1", () => resolve()));
    try {
      const address = stub.address();
      if (!address || typeof address === "string") throw new Error("stub did not bind a port");
      const app = await seeded();
      expect(hits).toEqual([]);

      // The reqlift edit-form shape: the entry as read, only the address changed.
      const detail = await request(app).get("/v1/mcp-servers/jira").set(as(KEY_OWNER));
      const moved = await request(app)
        .put("/v1/mcp-servers/jira")
        .set(as(KEY_OWNER))
        .send({ ...detail.body, url: `http://127.0.0.1:${address.port}/mcp` });
      expect(moved.status).toBe(200);
      expectNoMaps(moved.body);
      expectNoSecrets(moved);
      expect(await stored("jira")).toMatchObject({ headers: { Authorization: HEADER_MARKER }, env: { DORMANT_TOKEN: ENV_MARKER } });
      const after = await request(app).get("/v1/mcp-servers/jira").set(as(KEY_OWNER));
      expectNoMaps(after.body);
      expectNoSecrets(after);
      expect(hits).toEqual([]);

      const health = await request(app).get("/v1/mcp-servers/jira/health").set(as(KEY_OTHER));
      expect(health.status).toBe(200);
      expectNoSecrets(health);
      expect(hits).toEqual([{ path: "/health", authorization: HEADER_MARKER }]);
    } finally {
      await new Promise<void>((resolve) => stub.close(() => resolve()));
    }
  });

  it("the reqlift admin bodies keep both maps: the toggle, the edit form and the schema editor", async () => {
    const app = await seeded();
    const schema = {
      fields: [{ key: "token", label: "Token", type: "password", required: true }],
      outputs: [{ target: "headers", outputKey: "X-User", template: "{token}" }],
    };

    // Toggle: GET the entry, spread it, flip enabled, PUT it back.
    const detail = await request(app).get("/v1/mcp-servers/jira").set(as(KEY_OWNER));
    expectNoMaps(detail.body);
    expectNoSecrets(detail);
    const off = await request(app).put("/v1/mcp-servers/jira").set(as(KEY_OWNER)).send({ ...detail.body, enabled: false });
    expect(off.status).toBe(200);
    expect(await stored("jira")).toMatchObject({ enabled: false, headers: { Authorization: HEADER_MARKER }, env: { DORMANT_TOKEN: ENV_MARKER } });
    const on = await request(app).put("/v1/mcp-servers/jira").set(as(KEY_OWNER)).send({ ...(await request(app).get("/v1/mcp-servers/jira").set(as(KEY_OWNER))).body, enabled: true });
    expect(on.status).toBe(200);

    // Edit form: only the form's own fields.
    await request(app).put("/v1/mcp-servers/jira").set(as(KEY_OWNER)).send({ type: "http", url: HTTP_URL, description: "edited", enabled: true });
    // Schema editor: the entry as read plus the schema.
    const withSchema = await request(app)
      .put("/v1/mcp-servers/jira")
      .set(as(KEY_OWNER))
      .send({ ...(await request(app).get("/v1/mcp-servers/jira").set(as(KEY_OWNER))).body, userCredentialSchema: schema });
    expect(withSchema.status).toBe(200);
    expect(await stored("jira")).toMatchObject({
      description: "edited",
      enabled: true,
      userCredentialSchema: schema,
      headers: { Authorization: HEADER_MARKER },
      env: { DORMANT_TOKEN: ENV_MARKER },
    });
  });
});

describe("a transport change does not silently lose or strand a stored map", () => {
  const INAPPLICABLE = (property: string, transport: string) => ({
    error: {
      code: "MCP_CREDENTIAL_MAP_INAPPLICABLE",
      message: `The stored ${property} map does not apply to ${transport} transport: send ${property}: {} to clear it or a new ${property} map to replace it`,
    },
  });

  it("http to sse is the same family: the omitted headers stay", async () => {
    const app = await createApp();
    await request(app).put("/v1/mcp-servers/jira").set(as(KEY_OWNER)).send({ type: "http", url: HTTP_URL, headers: { Authorization: HEADER_MARKER } });
    const res = await request(app).put("/v1/mcp-servers/jira").set(as(KEY_OWNER)).send({ type: "sse", url: HTTP_URL });
    expect(res.status).toBe(200);
    expect(await stored("jira")).toMatchObject({ type: "sse", headers: { Authorization: HEADER_MARKER } });
  });

  it("http with stored headers to stdio with the headers omitted: 400, nothing changes, no value in the answer", async () => {
    const app = await createApp();
    await request(app).put("/v1/mcp-servers/jira").set(as(KEY_OWNER)).send({ type: "http", url: HTTP_URL, headers: { Authorization: HEADER_MARKER } });
    const before = structuredClone(await stored("jira"));

    const res = await request(app).put("/v1/mcp-servers/jira").set(as(KEY_OWNER)).send({ type: "stdio", command: "node", env: { A: ENV_MARKER_2 } });
    expect(res.status).toBe(400);
    expect(res.body).toEqual(INAPPLICABLE("headers", "stdio"));
    expectNoSecrets(res);
    expect(await stored("jira")).toEqual(before);
  });

  it("the same change with headers: {} is accepted and clears the headers", async () => {
    const app = await createApp();
    await request(app).put("/v1/mcp-servers/jira").set(as(KEY_OWNER)).send({ type: "http", url: HTTP_URL, headers: { Authorization: HEADER_MARKER } });
    const res = await request(app).put("/v1/mcp-servers/jira").set(as(KEY_OWNER)).send({ type: "stdio", command: "node", headers: {} });
    expect(res.status).toBe(200);
    const def = await stored("jira");
    expect(def).toMatchObject({ type: "stdio", command: "node" });
    expect(def).not.toHaveProperty("headers");
  });

  it("a dormant stored env on an http entry blocks a change to stdio that omits the env, even when headers are cleared", async () => {
    const app = await createApp();
    await request(app).put("/v1/mcp-servers/jira").set(as(KEY_OWNER)).send(httpBody());
    const before = structuredClone(await stored("jira"));

    const omitted = await request(app).put("/v1/mcp-servers/jira").set(as(KEY_OWNER)).send({ type: "stdio", command: "node", headers: {} });
    expect(omitted.status).toBe(400);
    expect(omitted.body).toEqual(INAPPLICABLE("env", "stdio"));
    expectNoSecrets(omitted);
    expect(await stored("jira")).toEqual(before);

    const resolved = await request(app).put("/v1/mcp-servers/jira").set(as(KEY_OWNER)).send({ type: "stdio", command: "node", headers: {}, env: { NEW: ENV_MARKER_2 } });
    expect(resolved.status).toBe(200);
    expect(await stored("jira")).toMatchObject({ type: "stdio", env: { NEW: ENV_MARKER_2 } });
  });

  it("stdio with stored env to http with the env omitted: 400, and env: {} resolves it", async () => {
    const app = await createApp();
    await request(app).put("/v1/mcp-servers/local").set(as(KEY_OWNER)).send(stdioBody());

    const refused = await request(app).put("/v1/mcp-servers/local").set(as(KEY_OWNER)).send({ type: "http", url: HTTP_URL });
    expect(refused.status).toBe(400);
    expect(refused.body).toEqual(INAPPLICABLE("env", "http"));
    expectNoSecrets(refused);
    expect(await stored("local")).toMatchObject({ type: "stdio", env: { API_TOKEN: ENV_MARKER } });

    const resolved = await request(app).put("/v1/mcp-servers/local").set(as(KEY_OWNER)).send({ type: "http", url: HTTP_URL, env: {}, args: [] });
    expect(resolved.status).toBe(200);
    expect(await stored("local")).not.toHaveProperty("env");
  });

  it("a family change with nothing stored needs nothing", async () => {
    const app = await createApp();
    await request(app).put("/v1/mcp-servers/jira").set(as(KEY_OWNER)).send({ type: "http", url: HTTP_URL });
    const res = await request(app).put("/v1/mcp-servers/jira").set(as(KEY_OWNER)).send({ type: "stdio", command: "node" });
    expect(res.status).toBe(200);
  });
});

describe("an invalid map keeps its existing refusal and echoes nothing", () => {
  it("null and non-string values are 400 with the existing texts", async () => {
    const app = await createApp();
    await request(app).put("/v1/mcp-servers/jira").set(as(KEY_OWNER)).send(httpBody());
    const before = structuredClone(await stored("jira"));

    const nullHeaders = await request(app).put("/v1/mcp-servers/jira").set(as(KEY_OWNER)).send({ type: "http", url: HTTP_URL, headers: null });
    expect(nullHeaders.status).toBe(400);
    expect(nullHeaders.body).toEqual({ error: "headers must be a string map" });

    const badEnv = await request(app).put("/v1/mcp-servers/jira").set(as(KEY_OWNER)).send({ type: "http", url: HTTP_URL, env: { TOKEN: 7 } });
    expect(badEnv.status).toBe(400);
    expect(badEnv.body).toEqual({ error: "env must be a string map" });
    for (const res of [nullHeaders, badEnv]) expectNoSecrets(res);
    expect(await stored("jira")).toEqual(before);
  });
});

describe("resolveStoredCredentialMaps", () => {
  const def = (type: "http" | "sse" | "stdio", maps: Record<string, Record<string, string>> = {}) =>
    ({ name: "x", description: "", enabled: true, type, createdAt: "t", updatedAt: "t", ...maps }) as never;

  it("omitted keeps, non-empty replaces, empty clears, per map", async () => {
    const { resolveStoredCredentialMaps } = await import("../mcp-registry.js");
    const existing = def("http", { headers: { A: "1" }, env: { B: "2" } });
    expect(resolveStoredCredentialMaps(existing, { type: "http" })).toEqual({ maps: { headers: { A: "1" }, env: { B: "2" } } });
    expect(resolveStoredCredentialMaps(existing, { type: "http", headers: { A: "9" } })).toEqual({ maps: { headers: { A: "9" }, env: { B: "2" } } });
    expect(resolveStoredCredentialMaps(existing, { type: "http", headers: {}, env: {} })).toEqual({ maps: {} });
    expect(resolveStoredCredentialMaps(undefined, { type: "http" })).toEqual({ maps: {} });
  });

  it("refuses a family change that leaves a non-empty omitted map, naming only property and transport", async () => {
    const { resolveStoredCredentialMaps } = await import("../mcp-registry.js");
    const result = resolveStoredCredentialMaps(def("http", { headers: { A: "SECRET-VALUE" } }), { type: "stdio" });
    expect(result).toEqual({ error: { code: "MCP_CREDENTIAL_MAP_INAPPLICABLE", message: expect.stringContaining("headers") } });
    expect(JSON.stringify(result)).not.toContain("SECRET-VALUE");
    expect(resolveStoredCredentialMaps(def("http", { headers: {} }), { type: "stdio" })).toEqual({ maps: { headers: {} } });
    expect(resolveStoredCredentialMaps(def("sse", { headers: { A: "1" } }), { type: "http" })).toEqual({ maps: { headers: { A: "1" } } });
  });
});
