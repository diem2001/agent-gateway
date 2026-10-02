/**
 * Ownership of registered MCP servers (MVP-7925): only the API-key label that registered a server may
 * change or delete it; an ownerless entry (registered before ownership) is refused for every label and never
 * receives a caller's credential until the operator mapping assigns its owner. The routes are mounted behind the
 * real authMiddleware with two labels; the process rows (restart, deploy step, real run) are in
 * mcp-server-owner-process.test.ts.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { startRecordingUpstream, type RecordingUpstream } from "./helpers/relay-upstream.js";

let tempDir = "";
let persistPath = "";
let logs: string[] = [];
const upstreams: RecordingUpstream[] = [];

const ALPHA = "label-alpha";
const BRAVO = "label-bravo";
const KEY_ALPHA = "sk-gw-owner-alpha";
const KEY_BRAVO = "sk-gw-owner-bravo";
const ORIGINAL_URL = "https://jira.alpha.example/mcp";
const ATTACKER_URL = "https://attacker.example/mcp";
const DENIAL = {
  error: { code: "MCP_SERVER_OWNER_MISMATCH", message: 'MCP server "jira" is registered by another application' },
};

beforeEach(() => {
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gateway-owner-"));
  persistPath = path.join(tempDir, "mcp-servers.json");
  process.env.MCP_SERVERS_PERSIST_PATH = persistPath;
  process.env.API_KEYS = `${ALPHA}:${KEY_ALPHA},${BRAVO}:${KEY_BRAVO}`;
  logs = [];
  vi.spyOn(console, "log").mockImplementation((...args) => {
    logs.push(args.map(String).join(" "));
  });
  vi.resetModules();
});

afterEach(async () => {
  vi.restoreAllMocks();
  delete process.env.MCP_SERVERS_PERSIST_PATH;
  delete process.env.API_KEYS;
  await Promise.all(upstreams.splice(0).map((upstream) => upstream.close()));
  // The registry persists 100 ms after a change; let that write land before removing its directory.
  await new Promise((resolve) => setTimeout(resolve, 150));
  fs.rmSync(tempDir, { recursive: true, force: true });
});

async function createApp(options: { auth?: boolean } = {}) {
  const { loadApiKeys, authMiddleware } = await import("../auth.js");
  loadApiKeys();
  const { default: mcpRoutes } = await import("../routes/mcp.js");
  const app = express();
  app.use(express.json());
  if (options.auth !== false) app.use(authMiddleware);
  app.use(mcpRoutes);
  return app;
}

const as = (key: string) => ({ Authorization: `Bearer ${key}` });

async function upstream(): Promise<RecordingUpstream> {
  const created = await startRecordingUpstream();
  upstreams.push(created);
  return created;
}

/** A registry entry as it was stored before ownership existed: no owner. */
async function seedOwnerless(name: string, url: string, extra: Record<string, unknown> = {}) {
  const { registerMcpServer } = await import("../mcp-registry.js");
  const now = "2026-09-01T00:00:00.000Z";
  registerMcpServer({ name, description: "legacy", enabled: true, type: "http", url, createdAt: now, updatedAt: now, ...extra });
}

async function persisted(): Promise<Array<Record<string, unknown>>> {
  await new Promise((resolve) => setTimeout(resolve, 150));
  return JSON.parse(fs.readFileSync(persistPath, "utf-8")) as Array<Record<string, unknown>>;
}

describe("another label cannot change or delete a registered MCP server", () => {
  it("label B's PUT is refused with the exact denial and leaves A's definition unchanged, with no call to B's address", async () => {
    const attacker = await upstream();
    const app = await createApp();
    const schema = {
      fields: [{ key: "token", label: "Token", type: "password", required: true }],
      outputs: [{ target: "headers", outputKey: "Authorization", template: "Bearer {token}" }],
    };
    const created = await request(app)
      .put("/v1/mcp-servers/jira")
      .set(as(KEY_ALPHA))
      .send({ type: "http", url: ORIGINAL_URL, headers: { "X-Shared": "alpha" }, userCredentialSchema: schema });
    expect(created.status).toBe(201);
    const before = (await request(app).get("/v1/mcp-servers/jira").set(as(KEY_ALPHA))).body;

    const attack = await request(app)
      .put("/v1/mcp-servers/jira")
      .set(as(KEY_BRAVO))
      .send({ type: "http", url: `${attacker.origin}/mcp`, headers: { "X-Shared": "bravo" } });
    expect(attack.status).toBe(403);
    expect(attack.body).toEqual(DENIAL);
    expect(attack.text).toBe(JSON.stringify(DENIAL));

    expect((await request(app).get("/v1/mcp-servers/jira").set(as(KEY_ALPHA))).body).toEqual(before);
    expect(before).toMatchObject({ url: ORIGINAL_URL, headers: { "X-Shared": "alpha" }, userCredentialSchema: schema });
    expect(attacker.requests).toEqual([]);
  });

  it("label B's DELETE is refused with the same denial and the server stays registered", async () => {
    const app = await createApp();
    await request(app).put("/v1/mcp-servers/jira").set(as(KEY_ALPHA)).send({ type: "http", url: ORIGINAL_URL });
    const before = (await request(app).get("/v1/mcp-servers/jira").set(as(KEY_ALPHA))).body;

    const attack = await request(app).delete("/v1/mcp-servers/jira").set(as(KEY_BRAVO));
    expect(attack.status).toBe(403);
    expect(attack.body).toEqual(DENIAL);

    expect((await request(app).get("/v1/mcp-servers/jira").set(as(KEY_ALPHA))).body).toEqual(before);
  });

  it("the denial of PUT, DELETE, an owned entry and an ownerless entry is byte-identical and never shows the owner", async () => {
    const app = await createApp();
    await request(app).put("/v1/mcp-servers/jira").set(as(KEY_ALPHA)).send({ type: "http", url: ORIGINAL_URL });
    await seedOwnerless("legacy", ORIGINAL_URL);

    const denials = [
      await request(app).put("/v1/mcp-servers/jira").set(as(KEY_BRAVO)).send({ type: "http", url: ATTACKER_URL }),
      await request(app).delete("/v1/mcp-servers/jira").set(as(KEY_BRAVO)),
      await request(app).put("/v1/mcp-servers/legacy").set(as(KEY_BRAVO)).send({ type: "http", url: ATTACKER_URL }),
      await request(app).delete("/v1/mcp-servers/legacy").set(as(KEY_ALPHA)),
    ];
    const names = ["jira", "jira", "legacy", "legacy"];
    denials.forEach((res, i) => {
      expect(res.status).toBe(403);
      expect(res.text).toBe(JSON.stringify({ error: { code: "MCP_SERVER_OWNER_MISMATCH", message: `MCP server "${names[i]}" is registered by another application` } }));
      // Nothing in the answer, body or headers, carries a label.
      expect(JSON.stringify(res.headers)).not.toContain(ALPHA);
      expect(JSON.stringify(res.headers)).not.toContain(BRAVO);
      expect(res.text).not.toContain(ALPHA);
    });
    // The owner-dependent parts of the answer are identical across owned and ownerless entries.
    const normalize = (res: (typeof denials)[number], name: string) => ({ status: res.status, text: res.text.replace(name, "<name>"), headers: { ...res.headers, date: "", etag: "", "content-length": "" } });
    expect(normalize(denials[0], "jira")).toEqual(normalize(denials[2], "legacy"));
    expect(normalize(denials[1], "jira")).toEqual(normalize(denials[3], "legacy"));
    expect(normalize(denials[0], "jira")).toEqual(normalize(denials[1], "jira"));
  });

  it("a non-owner gets the denial, not a 400, for an invalid payload and for a body the parser does not read", async () => {
    const app = await createApp();
    await request(app).put("/v1/mcp-servers/jira").set(as(KEY_ALPHA)).send({ type: "http", url: ORIGINAL_URL });

    const invalid = await request(app).put("/v1/mcp-servers/jira").set(as(KEY_BRAVO)).send({ type: "nonsense" });
    expect(invalid.status).toBe(403);
    expect(invalid.body).toEqual(DENIAL);

    const empty = await request(app).put("/v1/mcp-servers/jira").set(as(KEY_BRAVO)).send({});
    expect(empty.status).toBe(403);

    const nonJson = await request(app).put("/v1/mcp-servers/jira").set(as(KEY_BRAVO)).set("Content-Type", "text/plain").send("type=http");
    expect(nonJson.status).toBe(403);
    expect(nonJson.body).toEqual(DENIAL);

    const noBody = await request(app).put("/v1/mcp-servers/jira").set(as(KEY_BRAVO));
    expect(noBody.status).toBe(403);
  });

  it("the refusal is logged for the operator with the caller only", async () => {
    const app = await createApp();
    await request(app).put("/v1/mcp-servers/jira").set(as(KEY_ALPHA)).send({ type: "http", url: ORIGINAL_URL });
    await request(app).put("/v1/mcp-servers/jira").set(as(KEY_BRAVO)).send({ type: "http", url: ATTACKER_URL });
    await request(app).delete("/v1/mcp-servers/jira").set(as(KEY_BRAVO));

    const text = logs.join("\n");
    expect(text).toContain(`mcp.registry.owner_mismatch serverName=jira method=PUT caller=${BRAVO}`);
    expect(text).toContain(`mcp.registry.owner_mismatch serverName=jira method=DELETE caller=${BRAVO}`);
    expect(text).not.toContain(`caller=${ALPHA}`);
    for (const line of logs.filter((l) => l.includes("owner_mismatch"))) expect(line).not.toContain(ALPHA);
  });
});

describe("the owner keeps full control", () => {
  it("a new registration records the caller's label; the owner is persisted and never returned", async () => {
    const app = await createApp();
    const put = await request(app).put("/v1/mcp-servers/jira").set(as(KEY_ALPHA)).send({ type: "http", url: ORIGINAL_URL });
    expect(put.status).toBe(201);
    expect(put.body).not.toHaveProperty("owner");

    expect((await request(app).get("/v1/mcp-servers/jira").set(as(KEY_BRAVO))).body).not.toHaveProperty("owner");
    const list = await request(app).get("/v1/mcp-servers").set(as(KEY_BRAVO));
    expect(list.body.servers).toHaveLength(1);
    expect(list.body.servers[0]).not.toHaveProperty("owner");
    expect(JSON.stringify(list.body)).not.toContain(ALPHA);

    const stored = await persisted();
    expect(stored).toEqual([expect.objectContaining({ name: "jira", owner: ALPHA })]);
  });

  it("the owner updates (200, owner unchanged) and deletes (204) its server", async () => {
    const app = await createApp();
    await request(app).put("/v1/mcp-servers/jira").set(as(KEY_ALPHA)).send({ type: "http", url: ORIGINAL_URL });

    const update = await request(app).put("/v1/mcp-servers/jira").set(as(KEY_ALPHA)).send({ type: "http", url: "https://jira.alpha.example/v2" });
    expect(update.status).toBe(200);
    expect(update.body.url).toBe("https://jira.alpha.example/v2");
    expect(update.body).not.toHaveProperty("owner");
    expect(await persisted()).toEqual([expect.objectContaining({ name: "jira", owner: ALPHA, url: "https://jira.alpha.example/v2" })]);

    const del = await request(app).delete("/v1/mcp-servers/jira").set(as(KEY_ALPHA));
    expect(del.status).toBe(204);
    expect((await request(app).get("/v1/mcp-servers/jira").set(as(KEY_ALPHA))).status).toBe(404);
  });

  it("an owner in the request body is ignored on create and on update", async () => {
    const app = await createApp();
    await request(app).put("/v1/mcp-servers/jira").set(as(KEY_ALPHA)).send({ type: "http", url: ORIGINAL_URL, owner: BRAVO });
    expect(await persisted()).toEqual([expect.objectContaining({ owner: ALPHA })]);

    const update = await request(app).put("/v1/mcp-servers/jira").set(as(KEY_ALPHA)).send({ type: "http", url: ORIGINAL_URL, owner: BRAVO });
    expect(update.status).toBe(200);
    expect(await persisted()).toEqual([expect.objectContaining({ owner: ALPHA })]);
    // B still cannot change it.
    expect((await request(app).put("/v1/mcp-servers/jira").set(as(KEY_BRAVO)).send({ type: "http", url: ATTACKER_URL })).status).toBe(403);
  });

  it("DELETE of an unknown name stays 404 for every label", async () => {
    const app = await createApp();
    expect((await request(app).delete("/v1/mcp-servers/nothing").set(as(KEY_BRAVO))).status).toBe(404);
  });

  it("a new name is created by any label (201), invalid names still get the name rule", async () => {
    const app = await createApp();
    expect((await request(app).put("/v1/mcp-servers/other").set(as(KEY_BRAVO)).send({ type: "http", url: ATTACKER_URL })).status).toBe(201);
    const bad = await request(app).put("/v1/mcp-servers/-bad").set(as(KEY_BRAVO)).send({ type: "http", url: ATTACKER_URL });
    expect(bad.status).toBe(400);
    expect(bad.body.error.code).toBe("MCP_SERVER_NAME_INVALID");
  });

  it("without a caller label nothing is created and nothing is changed", async () => {
    const app = await createApp({ auth: false });
    const create = await request(app).put("/v1/mcp-servers/jira").send({ type: "http", url: ORIGINAL_URL });
    expect(create.status).toBe(403);
    expect(create.body).toEqual(DENIAL);
    expect((await request(app).get("/v1/mcp-servers/jira")).status).toBe(404);

    await seedOwnerless("legacy", ORIGINAL_URL);
    expect((await request(app).delete("/v1/mcp-servers/legacy")).status).toBe(403);
    expect((await request(app).put("/v1/mcp-servers/legacy").send({ type: "http", url: ATTACKER_URL })).status).toBe(403);
  });

  it("a restart keeps the stored definition and owner, and answers as before", async () => {
    const app = await createApp();
    await request(app).put("/v1/mcp-servers/jira").set(as(KEY_ALPHA)).send({ type: "http", url: ORIGINAL_URL, enabled: false });

    const restart = await request(app).post("/v1/mcp-servers/jira/restart").set(as(KEY_BRAVO));
    expect(restart.status).toBe(200);
    expect(restart.body).toEqual({ restarted: true, name: "jira" });
    expect(await persisted()).toEqual([expect.objectContaining({ owner: ALPHA, url: ORIGINAL_URL, enabled: true })]);
  });
});

describe("an ownerless entry fails closed", () => {
  it.each([
    { caller: ALPHA, key: KEY_ALPHA, verb: "PUT" },
    { caller: BRAVO, key: KEY_BRAVO, verb: "PUT" },
    { caller: ALPHA, key: KEY_ALPHA, verb: "DELETE" },
    { caller: BRAVO, key: KEY_BRAVO, verb: "DELETE" },
  ])("$verb by $caller is refused with the denial and the definition is unchanged", async ({ key, verb }) => {
    const app = await createApp();
    await seedOwnerless("jira", ORIGINAL_URL);
    const before = (await request(app).get("/v1/mcp-servers/jira").set(as(key))).body;

    const res =
      verb === "PUT"
        ? await request(app).put("/v1/mcp-servers/jira").set(as(key)).send({ type: "http", url: ATTACKER_URL })
        : await request(app).delete("/v1/mcp-servers/jira").set(as(key));
    expect(res.status).toBe(403);
    expect(res.body).toEqual(DENIAL);
    expect((await request(app).get("/v1/mcp-servers/jira").set(as(key))).body).toEqual(before);
    expect(before.url).toBe(ORIGINAL_URL);
  });

  it("a credential-bearing /call and /test are refused before any upstream request; calls without a credential are unchanged", async () => {
    const up = await upstream();
    const app = await createApp();
    await seedOwnerless("jira", `${up.origin}/mcp`);

    const call = await request(app)
      .post("/v1/mcp-servers/jira/call")
      .set(as(KEY_ALPHA))
      .send({ tool: "t", arguments: {}, credentials: { headers: { Authorization: "Bearer USER_SYNTH" } } });
    expect(call.status).toBe(403);
    expect(call.body).toEqual(DENIAL);

    const callEnv = await request(app)
      .post("/v1/mcp-servers/jira/call")
      .set(as(KEY_BRAVO))
      .send({ tool: "t", arguments: {}, credentials: { env: { TOKEN: "USER_SYNTH" } } });
    expect(callEnv.status).toBe(403);

    const test = await request(app).post("/v1/mcp-servers/jira/test").set(as(KEY_ALPHA)).send({ headers: { Authorization: "Bearer USER_SYNTH" } });
    expect(test.status).toBe(403);
    expect(test.body).toEqual(DENIAL);
    expect(up.requests).toEqual([]);
    expect(JSON.stringify(logs)).not.toContain("USER_SYNTH");

    // Empty credential values carry nothing, and a call without a credential behaves as before: it reaches the upstream.
    await request(app).post("/v1/mcp-servers/jira/call").set(as(KEY_ALPHA)).send({ tool: "t", arguments: {}, credentials: { headers: { Authorization: "" } } });
    await request(app).post("/v1/mcp-servers/jira/test").set(as(KEY_ALPHA)).send({});
    expect(up.requests.length).toBeGreaterThan(0);
  });

  it("an entry owned by another label still serves a credential-bearing call (today's sharing)", async () => {
    const up = await upstream();
    const app = await createApp();
    await request(app).put("/v1/mcp-servers/jira").set(as(KEY_ALPHA)).send({ type: "http", url: `${up.origin}/mcp` });

    await request(app)
      .post("/v1/mcp-servers/jira/call")
      .set(as(KEY_BRAVO))
      .send({ tool: "t", arguments: {}, credentials: { headers: { Authorization: "Bearer USER_SYNTH" } } });
    expect(up.requests.length).toBeGreaterThan(0);
    expect(up.requests.some((r) => r.headers.authorization === "Bearer USER_SYNTH")).toBe(true);
  });
});

describe("the owner survives the registry file", () => {
  it("an owner that is not a non-empty string sets the whole file aside and the registry starts empty", async () => {
    for (const owner of ["", 7, null]) {
      vi.resetModules();
      fs.writeFileSync(
        persistPath,
        JSON.stringify([{ name: "jira", description: "", enabled: true, type: "http", url: ORIGINAL_URL, owner, createdAt: "", updatedAt: "" }]),
      );
      const { loadMcpServers, getAllMcpServers } = await import("../mcp-registry.js");
      loadMcpServers();
      expect(getAllMcpServers()).toEqual([]);
      expect(fs.readdirSync(tempDir).some((f) => f.startsWith("mcp-servers.json.corrupt-"))).toBe(true);
      for (const f of fs.readdirSync(tempDir).filter((f) => f.includes(".corrupt-"))) fs.unlinkSync(path.join(tempDir, f));
    }
  });

  it("an entry without an owner loads as ownerless; an owned entry keeps its owner", async () => {
    fs.writeFileSync(
      persistPath,
      JSON.stringify([
        { name: "legacy", description: "", enabled: true, type: "http", url: ORIGINAL_URL, createdAt: "", updatedAt: "" },
        { name: "jira", description: "", enabled: true, type: "http", url: ORIGINAL_URL, owner: ALPHA, createdAt: "", updatedAt: "" },
      ]),
    );
    const { loadMcpServers, getOwnerlessMcpServerNames, getMcpServer } = await import("../mcp-registry.js");
    loadMcpServers();
    expect(getOwnerlessMcpServerNames()).toEqual(["legacy"]);
    expect(getMcpServer("jira")?.owner).toBe(ALPHA);
  });
});
