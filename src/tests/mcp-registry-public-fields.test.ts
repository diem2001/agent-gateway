/**
 * Stored stdio `args` are write-only and the registered `url` is public configuration (MVP-7957): no registry read or
 * successful write answers with `args`; a compliant http/sse URL (a path is public by contract) is returned verbatim
 * so reqlift can compare it with its OAuth resource; a URL with user info, a query or a fragment is refused on write
 * and, when a legacy entry still holds one, withheld on read with `urlMigrationRequired`. The routes are mounted
 * behind the real authMiddleware with an owner, another label and an ownerless legacy entry.
 */
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import express from "express";
import request from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

let tempDir = "";
let persistPath = "";
let logs: string[] = [];

const OWNER = "label-owner";
const OTHER = "label-other";
const KEY_OWNER = "sk-gw-pf-owner";
const KEY_OTHER = "sk-gw-pf-other";
const ARGS_MARKER = "ARG-MARKER-7957-aaaa1111";
const ARGS_MARKER_2 = "ARG-MARKER-7957-bbbb2222";
const URL_USER = "URLU-MARKER-7957-cccc3333";
const URL_QUERY = "URLQ-MARKER-7957-dddd4444";
const URL_FRAGMENT = "URLF-MARKER-7957-eeee5555";
const URL_MARKERS = [URL_USER, URL_QUERY, URL_FRAGMENT];
const ALL_MARKERS = [ARGS_MARKER, ARGS_MARKER_2, ...URL_MARKERS];
const HTTP_URL = "https://jira.owner.example/mcp/v1/path";

const URL_URL_INVALID = {
  error: {
    code: "MCP_SERVER_URL_INVALID",
    message:
      "The server address must be an http(s) URL without a login, query or fragment. Put credentials in headers, env or per-user credentials.",
  },
};
const ARGS_INVALID = {
  error: { code: "MCP_SERVER_ARGS_INVALID", message: "args must be a list of text values without NUL characters." },
};

const LEGACY_URLS = {
  "legacy-user": { url: `https://${URL_USER}:pw@legacy.example/mcp`, reason: "user_info" },
  "legacy-query": { url: `https://legacy.example/mcp?token=${URL_QUERY}`, reason: "query" },
  "legacy-fragment": { url: `https://legacy.example/mcp#${URL_FRAGMENT}`, reason: "fragment" },
} as const;

beforeEach(() => {
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gateway-public-fields-"));
  persistPath = path.join(tempDir, "mcp-servers.json");
  process.env.MCP_SERVERS_PERSIST_PATH = persistPath;
  process.env.API_KEYS = `${OWNER}:${KEY_OWNER},${OTHER}:${KEY_OTHER}`;
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
const sha = (value: unknown) => createHash("sha256").update(JSON.stringify(value ?? null)).digest("hex");

async function stored(name: string) {
  const { getMcpServer } = await import("../mcp-registry.js");
  return getMcpServer(name);
}

/** An entry as a legacy persisted file holds it: any field values, no validation. */
async function seed(name: string, fields: Record<string, unknown>) {
  const { registerMcpServer } = await import("../mcp-registry.js");
  const now = "2026-09-01T00:00:00.000Z";
  registerMcpServer({ name, description: "legacy", enabled: true, createdAt: now, updatedAt: now, ...fields } as never);
}

function expectNone(res: { text: string }, markers: string[] = ALL_MARKERS) {
  for (const marker of markers) expect(res.text).not.toContain(marker);
}

const stdioBody = (extra: Record<string, unknown> = {}) => ({
  type: "stdio",
  command: "node",
  args: ["server.js", `--token=${ARGS_MARKER}`],
  description: "Local",
  ...extra,
});

describe("stdio args are never returned to any client", () => {
  const callers = [
    ["the owner", KEY_OWNER],
    ["another label", KEY_OTHER],
  ] as const;

  for (const [who, key] of callers) {
    it(`list and detail for ${who}: owned and ownerless stdio entries carry no args property and no marker`, async () => {
      const app = await createApp();
      expect((await request(app).put("/v1/mcp-servers/local").set(as(KEY_OWNER)).send(stdioBody())).status).toBe(201);
      await seed("legacy-stdio", { type: "stdio", command: "node", args: [`--token=${ARGS_MARKER_2}`] });

      const list = await request(app).get("/v1/mcp-servers").set(as(key));
      expect(list.status).toBe(200);
      expect(list.body.servers.map((s: { name: string }) => s.name).sort()).toEqual(["legacy-stdio", "local"]);
      for (const server of list.body.servers) expect(server).not.toHaveProperty("args");
      expectNone(list);
      for (const name of ["local", "legacy-stdio"]) {
        const detail = await request(app).get(`/v1/mcp-servers/${name}`).set(as(key));
        expect(detail.status).toBe(200);
        expect(detail.body).not.toHaveProperty("args");
        expectNone(detail);
      }
      const local = await request(app).get("/v1/mcp-servers/local").set(as(key));
      expect(local.body).toMatchObject({ type: "stdio", command: "node" });
    });
  }

  it("a successful PUT (201 and 200) answers without args; the registry still holds the submitted list", async () => {
    const app = await createApp();
    const created = await request(app).put("/v1/mcp-servers/local").set(as(KEY_OWNER)).send(stdioBody());
    expect(created.status).toBe(201);
    expect(created.body).not.toHaveProperty("args");
    expectNone(created);
    expect((await stored("local"))?.args).toEqual(["server.js", `--token=${ARGS_MARKER}`]);

    const updated = await request(app).put("/v1/mcp-servers/local").set(as(KEY_OWNER)).send(stdioBody({ args: [ARGS_MARKER_2] }));
    expect(updated.status).toBe(200);
    expect(updated.body).not.toHaveProperty("args");
    expectNone(updated);
    expect((await stored("local"))?.args).toEqual([ARGS_MARKER_2]);
  });
});

describe("an owner PUT keeps, replaces or clears the stored args", () => {
  async function seeded() {
    const app = await createApp();
    await request(app).put("/v1/mcp-servers/local").set(as(KEY_OWNER)).send(stdioBody());
    return app;
  }

  it("a metadata edit that omits args keeps the stored list", async () => {
    const app = await seeded();
    const res = await request(app).put("/v1/mcp-servers/local").set(as(KEY_OWNER)).send({ type: "stdio", command: "node", description: "renamed" });
    expect(res.status).toBe(200);
    expect(await stored("local")).toMatchObject({ description: "renamed", args: ["server.js", `--token=${ARGS_MARKER}`] });
  });

  it("a non-empty list replaces and [] clears (no property stored)", async () => {
    const app = await seeded();
    await request(app).put("/v1/mcp-servers/local").set(as(KEY_OWNER)).send({ type: "stdio", command: "node", args: ["other.js"] });
    expect((await stored("local"))?.args).toEqual(["other.js"]);

    const cleared = await request(app).put("/v1/mcp-servers/local").set(as(KEY_OWNER)).send({ type: "stdio", command: "node", args: [] });
    expect(cleared.status).toBe(200);
    expect(await stored("local")).not.toHaveProperty("args");
  });

  it("a toggle that spreads the read reply (no args) keeps the list", async () => {
    const app = await seeded();
    const detail = await request(app).get("/v1/mcp-servers/local").set(as(KEY_OWNER));
    const off = await request(app).put("/v1/mcp-servers/local").set(as(KEY_OWNER)).send({ ...detail.body, enabled: false });
    expect(off.status).toBe(200);
    expect(await stored("local")).toMatchObject({ enabled: false, args: ["server.js", `--token=${ARGS_MARKER}`] });
  });

  it("a new stdio registration without args stores none", async () => {
    const app = await createApp();
    await request(app).put("/v1/mcp-servers/fresh").set(as(KEY_OWNER)).send({ type: "stdio", command: "node" });
    expect(await stored("fresh")).not.toHaveProperty("args");
  });

  it("malformed args (null, non-array, non-string element, NUL) are refused with the fixed text; nothing changes", async () => {
    const app = await seeded();
    const before = structuredClone(await stored("local"));
    for (const args of [null, "server.js", { a: 1 }, [1], ["ok", null], [`bad\0${ARGS_MARKER_2}`]]) {
      const res = await request(app).put("/v1/mcp-servers/local").set(as(KEY_OWNER)).send({ type: "stdio", command: "node", args });
      expect(res.status).toBe(400);
      expect(res.body).toEqual(ARGS_INVALID);
      expectNone(res);
    }
    expect(await stored("local")).toEqual(before);
  });

  it("stdio to http with stored args and args omitted: 400 naming only args; args: [] resolves it", async () => {
    const app = await seeded();
    const before = structuredClone(await stored("local"));
    const refused = await request(app).put("/v1/mcp-servers/local").set(as(KEY_OWNER)).send({ type: "http", url: HTTP_URL });
    expect(refused.status).toBe(400);
    expect(refused.body).toEqual({
      error: {
        code: "MCP_CREDENTIAL_MAP_INAPPLICABLE",
        message: "The stored args list does not apply to http transport: send args: [] to clear it or switch back to stdio.",
      },
    });
    expectNone(refused);
    expect(await stored("local")).toEqual(before);

    const resolved = await request(app).put("/v1/mcp-servers/local").set(as(KEY_OWNER)).send({ type: "http", url: HTTP_URL, args: [] });
    expect(resolved.status).toBe(200);
    expect(await stored("local")).not.toHaveProperty("args");
  });

  it("a stdio entry with no stored args switches to http without any args handling", async () => {
    const app = await createApp();
    await request(app).put("/v1/mcp-servers/local").set(as(KEY_OWNER)).send({ type: "stdio", command: "node" });
    const res = await request(app).put("/v1/mcp-servers/local").set(as(KEY_OWNER)).send({ type: "http", url: HTTP_URL });
    expect(res.status).toBe(200);
  });

  it("another label's PUT is refused (403) and the stored args stay untouched and unread", async () => {
    const app = await seeded();
    const before = structuredClone(await stored("local"));
    const res = await request(app).put("/v1/mcp-servers/local").set(as(KEY_OTHER)).send({ type: "stdio", command: "node", args: [ARGS_MARKER_2] });
    expect(res.status).toBe(403);
    expectNone(res);
    expect(await stored("local")).toEqual(before);
  });
});

describe("a compliant URL is public configuration and is returned verbatim", () => {
  it("list, detail and PUT replies carry the exact registered string, path included", async () => {
    const app = await createApp();
    const created = await request(app).put("/v1/mcp-servers/jira").set(as(KEY_OWNER)).send({ type: "http", url: HTTP_URL });
    expect(created.status).toBe(201);
    expect(created.body.url).toBe(HTTP_URL);
    expect(created.body).not.toHaveProperty("urlMigrationRequired");
    for (const key of [KEY_OWNER, KEY_OTHER]) {
      const list = await request(app).get("/v1/mcp-servers").set(as(key));
      expect(list.body.servers[0].url).toBe(HTTP_URL);
      expect(list.body.servers[0]).not.toHaveProperty("urlMigrationRequired");
      const detail = await request(app).get("/v1/mcp-servers/jira").set(as(key));
      expect(detail.body.url).toBe(HTTP_URL);
    }
    const updated = await request(app).put("/v1/mcp-servers/jira").set(as(KEY_OWNER)).send({ type: "sse", url: `${HTTP_URL}/events` });
    expect(updated.body.url).toBe(`${HTTP_URL}/events`);
  });

  it("a same-family edit that omits url keeps the stored URL; a family change to http/sse still needs one", async () => {
    const app = await createApp();
    await request(app).put("/v1/mcp-servers/jira").set(as(KEY_OWNER)).send({ type: "http", url: HTTP_URL });
    const edited = await request(app).put("/v1/mcp-servers/jira").set(as(KEY_OWNER)).send({ type: "sse", description: "edited" });
    expect(edited.status).toBe(200);
    expect(edited.body.url).toBe(HTTP_URL);
    expect((await stored("jira"))?.url).toBe(HTTP_URL);

    await request(app).put("/v1/mcp-servers/local").set(as(KEY_OWNER)).send({ type: "stdio", command: "node" });
    const missing = await request(app).put("/v1/mcp-servers/local").set(as(KEY_OWNER)).send({ type: "http" });
    expect(missing.status).toBe(400);
    expect(missing.body).toEqual({ error: "url is required for http/sse transport" });
    const fresh = await request(app).put("/v1/mcp-servers/brand-new").set(as(KEY_OWNER)).send({ type: "http" });
    expect(fresh.status).toBe(400);
    expect(await stored("brand-new")).toBeUndefined();
  });

  it("a stdio PUT body's url is ignored and never stored; http to stdio drops the stored URL", async () => {
    const app = await createApp();
    const created = await request(app)
      .put("/v1/mcp-servers/local")
      .set(as(KEY_OWNER))
      .send({ type: "stdio", command: "node", url: `https://${URL_USER}@x.example/` });
    expect(created.status).toBe(201);
    expect(created.body).not.toHaveProperty("url");
    expect(await stored("local")).not.toHaveProperty("url");

    await request(app).put("/v1/mcp-servers/jira").set(as(KEY_OWNER)).send({ type: "http", url: HTTP_URL });
    const switched = await request(app).put("/v1/mcp-servers/jira").set(as(KEY_OWNER)).send({ type: "stdio", command: "node", url: HTTP_URL });
    expect(switched.status).toBe(200);
    expect(switched.body).not.toHaveProperty("url");
    expect(await stored("jira")).not.toHaveProperty("url");
  });
});

describe("a URL with user info, a query or a fragment is refused without being echoed", () => {
  const unsafe: Array<[string, unknown]> = [
    ["user info", `https://${URL_USER}:pw@host.example/mcp`],
    ["user name only", `https://${URL_USER}@host.example/mcp`],
    ["query string", `https://host.example/mcp?token=${URL_QUERY}`],
    ["empty query", `https://host.example/mcp?`],
    ["fragment", `https://host.example/mcp#${URL_FRAGMENT}`],
    ["empty fragment", `https://host.example/mcp#`],
    ["empty string", ""],
    ["non-http scheme", `ftp://host.example/${URL_USER}`],
    ["unparsable", `not a url ${URL_USER}`],
    ["null", null],
    ["a number", 42],
  ];

  for (const [label, url] of unsafe) {
    it(`${label}: new registration and owner update answer 400 with the fixed text; nothing is stored or changed`, async () => {
      const app = await createApp();
      await request(app).put("/v1/mcp-servers/jira").set(as(KEY_OWNER)).send({ type: "http", url: HTTP_URL });
      const before = structuredClone(await stored("jira"));

      const fresh = await request(app).put("/v1/mcp-servers/brand-new").set(as(KEY_OWNER)).send({ type: "sse", url });
      const update = await request(app).put("/v1/mcp-servers/jira").set(as(KEY_OWNER)).send({ type: "http", url });
      for (const res of [fresh, update]) {
        expect(res.status).toBe(400);
        expect(res.body).toEqual(URL_URL_INVALID);
        expectNone(res);
      }
      expect(await stored("brand-new")).toBeUndefined();
      expect(await stored("jira")).toEqual(before);
      expect(logs.join("\n")).not.toMatch(/MARKER-7957/);
    });
  }

  it("the denied-PUT path stays first: another label sending an unsafe URL gets the 403, not the URL text", async () => {
    const app = await createApp();
    await request(app).put("/v1/mcp-servers/jira").set(as(KEY_OWNER)).send({ type: "http", url: HTTP_URL });
    const res = await request(app).put("/v1/mcp-servers/jira").set(as(KEY_OTHER)).send({ type: "http", url: `https://${URL_USER}@h.example/` });
    expect(res.status).toBe(403);
    expectNone(res);
  });
});

describe("a legacy URL that breaks the rule is withheld and the entry is not rewritten", () => {
  const callers = [
    ["the owner", KEY_OWNER],
    ["another label", KEY_OTHER],
  ] as const;

  const legacyEntries = async () => {
    for (const [name, { url }] of Object.entries(LEGACY_URLS)) {
      await seed(name, { type: "http", url, owner: OWNER, headers: { Authorization: "HDR-LEGACY" }, env: { E: "ENV-LEGACY" } });
    }
    await seed("legacy-bad", { type: "sse", url: "not a url", owner: OWNER });
    await seed("legacy-null", { type: "http", url: null, owner: OWNER });
    await seed("legacy-stdio-url", { type: "stdio", command: "node", url: LEGACY_URLS["legacy-user"].url, owner: OWNER });
  };
  const names = [...Object.keys(LEGACY_URLS), "legacy-bad", "legacy-null", "legacy-stdio-url"];

  for (const [who, key] of callers) {
    it(`list and detail for ${who}: no url, urlMigrationRequired true, no marker`, async () => {
      const app = await createApp();
      await legacyEntries();
      const list = await request(app).get("/v1/mcp-servers").set(as(key));
      expect(list.status).toBe(200);
      expectNone(list);
      for (const server of list.body.servers) {
        expect(server).not.toHaveProperty("url");
        expect(server.urlMigrationRequired).toBe(true);
      }
      for (const name of names) {
        const detail = await request(app).get(`/v1/mcp-servers/${name}`).set(as(key));
        expect(detail.status).toBe(200);
        expect(detail.body).not.toHaveProperty("url");
        expect(detail.body.urlMigrationRequired).toBe(true);
        expectNone(detail);
      }
    });
  }

  for (const [name, { url }] of Object.entries(LEGACY_URLS)) {
    it(`${name}: an authorized metadata PUT without url answers without it and leaves url, args, headers and env byte-identical`, async () => {
      const app = await createApp();
      await seed(name, { type: "http", url, owner: OWNER, headers: { Authorization: "HDR-LEGACY" }, env: { E: "ENV-LEGACY" } });
      const hashes = async () => {
        const def = (await stored(name)) as unknown as Record<string, unknown>;
        return ["url", "args", "headers", "env"].map((field) => sha(def[field]));
      };
      const before = await hashes();

      const res = await request(app).put(`/v1/mcp-servers/${name}`).set(as(KEY_OWNER)).send({ type: "http", description: "edited" });
      expect(res.status).toBe(200);
      expect(res.body).not.toHaveProperty("url");
      expect(res.body.urlMigrationRequired).toBe(true);
      expect(res.body.description).toBe("edited");
      expectNone(res);
      expect(await hashes()).toEqual(before);
      expect((await stored(name))?.url).toBe(url);
    });
  }

  it("a PUT that spreads a reply (urlMigrationRequired, no url) ignores the flag and keeps the stored URL", async () => {
    const app = await createApp();
    await seed("legacy-user", { type: "http", url: LEGACY_URLS["legacy-user"].url, owner: OWNER });
    const detail = await request(app).get("/v1/mcp-servers/legacy-user").set(as(KEY_OWNER));
    const res = await request(app).put("/v1/mcp-servers/legacy-user").set(as(KEY_OWNER)).send({ ...detail.body, enabled: false });
    expect(res.status).toBe(200);
    const def = (await stored("legacy-user")) as unknown as Record<string, unknown>;
    expect(def.url).toBe(LEGACY_URLS["legacy-user"].url);
    expect(def).not.toHaveProperty("urlMigrationRequired");
  });

  it("an owner can replace the legacy URL with a compliant one and the entry reads normally again", async () => {
    const app = await createApp();
    await seed("legacy-query", { type: "http", url: LEGACY_URLS["legacy-query"].url, owner: OWNER });
    const res = await request(app).put("/v1/mcp-servers/legacy-query").set(as(KEY_OWNER)).send({ type: "http", url: HTTP_URL });
    expect(res.status).toBe(200);
    expect(res.body.url).toBe(HTTP_URL);
    expect(res.body).not.toHaveProperty("urlMigrationRequired");
  });

  it("loading the persisted file logs one migration line per entry with the name and category, never the URL", async () => {
    fs.writeFileSync(
      persistPath,
      JSON.stringify([
        ...Object.entries(LEGACY_URLS).map(([name, { url }]) => ({ name, type: "http", url, enabled: true, description: "", createdAt: "t", updatedAt: "t" })),
        { name: "fine", type: "http", url: HTTP_URL, enabled: true, description: "", createdAt: "t", updatedAt: "t" },
      ]),
    );
    const { loadMcpServers } = await import("../mcp-registry.js");
    loadMcpServers();
    const lines = logs.filter((line) => line.includes("mcp.registry.url_migration_required"));
    expect(lines).toHaveLength(3);
    for (const [name, { reason }] of Object.entries(LEGACY_URLS)) {
      expect(lines.some((line) => line.includes(`serverName=${name}`) && line.includes(`reason=${reason}`))).toBe(true);
    }
    expect(logs.join("\n")).not.toMatch(/MARKER-7957/);
  });
});
