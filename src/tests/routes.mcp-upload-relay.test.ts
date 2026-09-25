/**
 * POST /v1/mcp-servers/:name/uploads/* — the streaming upload relay (SC-5).
 *
 * Runs against the real assembled gateway (`../server.js` with PORT=0 on
 * loopback), so the body-parser skip, the pre-auth guard and API-key auth are
 * exercised exactly as wired in production. The MCP server is a loopback stub
 * that records what reached it; its connection counter proves that a refused
 * upload never opened an upstream connection.
 */
import fs from "node:fs";
import http, { type Server } from "node:http";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import express from "express";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { McpServerDefinition } from "../mcp-registry.js";
import {
  MiB,
  answerCreated,
  closedPort,
  rawRequest,
  sendUpload,
  startUploadStub,
  type SendOptions,
  type StubHandler,
  type UploadStub,
} from "./helpers/upload-relay-stub.js";

const API_KEY = "relay-test-key";
const IDLE_TIMEOUT_MS = 2000;
const BEARER = { Authorization: `Bearer ${API_KEY}` };
const USER_BASIC = `Basic ${Buffer.from("user-a@example.com:user-a-token").toString("base64")}`;
const TARGET = "/v1/mcp-servers/jira/uploads/jira/issue/MVP-1?filename=shot.png";

let tempDir: string;
let gateway: Server;
let port: number;
let logs: string[] = [];
const stubs: UploadStub[] = [];

function credentialHeader(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64");
}

async function stub(handler?: StubHandler): Promise<UploadStub> {
  const created = await startUploadStub(handler);
  stubs.push(created);
  return created;
}

async function register(def: Partial<McpServerDefinition> & Pick<McpServerDefinition, "name" | "type">) {
  const { registerMcpServer } = await import("../mcp-registry.js");
  const now = new Date().toISOString();
  registerMcpServer({ description: "", enabled: true, createdAt: now, updatedAt: now, ...def } as McpServerDefinition);
}

function send(options: Omit<SendOptions, "port">) {
  return sendUpload({ port, ...options });
}

async function waitFor(check: () => boolean, ms: number): Promise<boolean> {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (check()) return true;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  return check();
}

beforeAll(async () => {
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gateway-upload-relay-"));
  process.env.PORT = "0";
  process.env.HOST = "127.0.0.1";
  process.env.API_KEYS = `relay:${API_KEY}`;
  process.env.MCP_SERVERS_PERSIST_PATH = path.join(tempDir, "mcp-servers.json");
  process.env.SESSION_PERSIST_PATH = path.join(tempDir, "sessions.json");
  process.env.TOOLS_PERSIST_PATH = path.join(tempDir, "tools.json");
  process.env.WORKSPACE_ROOT = path.join(tempDir, "workspace");
  process.env.MCP_UPLOAD_IDLE_TIMEOUT_MS = String(IDLE_TIMEOUT_MS);
  process.env.LOG_LEVEL = "info";
  vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
    logs.push(args.map(String).join(" "));
  });
  vi.doMock("@anthropic-ai/claude-agent-sdk", () => ({
    createSdkMcpServer: vi.fn((options: { name: string }) => ({ type: "sdk", name: options.name })),
    query: vi.fn(() => {
      throw new Error("the upload relay must not start an agent query");
    }),
  }));

  const mod = (await import("../server.js")) as { server: Server };
  gateway = mod.server;
  if (!gateway.listening) await new Promise<void>((resolve) => gateway.once("listening", () => resolve()));
  port = (gateway.address() as AddressInfo).port;
});

afterEach(async () => {
  await Promise.all(stubs.splice(0).map((s) => s.close()));
  const { setLogLevel } = await import("../logging.js");
  setLogLevel("info");
  logs = [];
});

afterAll(async () => {
  gateway.closeAllConnections();
  await new Promise<void>((resolve) => gateway.close(() => resolve()));
  vi.restoreAllMocks();
  vi.doUnmock("@anthropic-ai/claude-agent-sdk");
  fs.rmSync(tempDir, { recursive: true, force: true });
  for (const key of [
    "PORT",
    "HOST",
    "API_KEYS",
    "MCP_SERVERS_PERSIST_PATH",
    "SESSION_PERSIST_PATH",
    "TOOLS_PERSIST_PATH",
    "WORKSPACE_ROOT",
    "MCP_UPLOAD_IDLE_TIMEOUT_MS",
    "LOG_LEVEL",
  ]) {
    delete process.env[key];
  }
});

/* ------------------------------------------------------------------ */
/*  Success: bytes, path, query, answer                                  */
/* ------------------------------------------------------------------ */

describe("relay success", () => {
  it("forwards 5 MB byte-identical with Content-Type, Content-Length, path and query, and returns the answer verbatim", async () => {
    const upstream = await stub();
    await register({ name: "jira", type: "http", url: upstream.url });
    const total = 5 * MiB;

    const result = await send({
      path: TARGET,
      total,
      headers: { ...BEARER, "Content-Type": "image/png", "X-MCP-Credential-Headers": credentialHeader({ Authorization: USER_BASIC }) },
    });

    expect(result.status).toBe(201);
    expect(result.headers["content-type"]).toBe("application/json");
    expect(JSON.parse(result.text)).toEqual({
      attachmentId: "10001",
      mediaApiFileId: "0f0e0d0c-0b0a-4908-8706-050403020100",
      filename: "shot.png",
      size: total,
    });
    expect(upstream.requests).toHaveLength(1);
    const seen = upstream.requests[0];
    expect(seen.method).toBe("POST");
    expect(seen.url).toBe("/uploads/jira/issue/MVP-1?filename=shot.png");
    expect(seen.headers.authorization).toBe(USER_BASIC);
    expect(seen.headers["content-type"]).toBe("image/png");
    expect(seen.headers["content-length"]).toBe(String(total));
    expect(seen.sha256).toBe(result.sentSha256);
    expect(seen.bytes).toBe(total);
    expect(logs.join("\n")).toContain(`mcp.upload.relayed serverName=jira status=201 bytes=${total} result=ok`);
  });

  it("forwards the raw target path and query byte for byte", async () => {
    const upstream = await stub();
    await register({ name: "jira", type: "http", url: upstream.url });
    const query = "filename=a%20b%2Bc+d%C3%A4.png&x=1";

    const withQuery = await send({ path: `/v1/mcp-servers/jira/uploads/jira/issue/MVP-7?${query}`, total: 1024, headers: BEARER });
    const withoutQuery = await send({ path: "/v1/mcp-servers/jira/uploads/jira/issue/MVP-7", total: 1024, headers: BEARER });

    expect(withQuery.status).toBe(201);
    expect(withoutQuery.status).toBe(201);
    expect(upstream.requests.map((r) => r.url)).toEqual([
      `/uploads/jira/issue/MVP-7?${query}`,
      "/uploads/jira/issue/MVP-7",
    ]);
  });

  it("relays to an sse registration the same way", async () => {
    const upstream = await stub();
    await register({ name: "jira-sse", type: "sse", url: `http://127.0.0.1:${upstream.port}/sse` });

    const result = await send({ path: "/v1/mcp-servers/jira-sse/uploads/jira/issue/MVP-1", total: 2048, headers: BEARER });

    expect(result.status).toBe(201);
    expect(upstream.requests[0].url).toBe("/uploads/jira/issue/MVP-1");
  });

  it("forwards a chunked request chunked", async () => {
    const upstream = await stub();
    await register({ name: "jira", type: "http", url: upstream.url });

    const result = await send({ path: TARGET, total: 3 * MiB, chunked: true, headers: BEARER });

    expect(result.status).toBe(201);
    const seen = upstream.requests[0];
    expect(seen.headers["transfer-encoding"]).toBe("chunked");
    expect(seen.headers["content-length"]).toBeUndefined();
    expect(seen.sha256).toBe(result.sentSha256);
  });

  it.each([400, 401, 403, 404, 413, 502])("passes an MCP server %i answer through verbatim", async (status) => {
    const body = JSON.stringify({ error: { code: `UPLOAD_CODE_${status}`, message: `answer ${status}` } });
    const upstream = await stub(async ({ res, consume }) => {
      if (!(await consume())) return;
      res.writeHead(status, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) });
      res.end(body);
    });
    await register({ name: "jira", type: "http", url: upstream.url });

    const result = await send({ path: TARGET, total: 64 * 1024, headers: BEARER });

    expect(result.status).toBe(status);
    expect(result.text).toBe(body);
    expect(result.headers["content-type"]).toBe("application/json");
  });
});

/* ------------------------------------------------------------------ */
/*  Header rules                                                         */
/* ------------------------------------------------------------------ */

describe("forwarded headers", () => {
  it("takes only Authorization from the override, static headers from the registration, hop-by-hop from the relay", async () => {
    const upstream = await stub();
    await register({ name: "jira", type: "http", url: upstream.url, headers: { "X-Static": "1" } });
    const total = 256 * 1024;

    const result = await send({
      path: TARGET,
      total,
      headers: {
        ...BEARER,
        "Content-Type": "image/png",
        "X-MCP-Credential-Headers": credentialHeader({
          Authorization: USER_BASIC,
          Host: "evil.example",
          "Content-Length": "1",
          "Transfer-Encoding": "chunked",
          Connection: "keep-alive",
          "X-Other": "other",
        }),
      },
    });

    expect(result.status).toBe(201);
    const seen = upstream.requests[0].headers;
    expect(seen.authorization).toBe(USER_BASIC);
    expect(seen["x-static"]).toBe("1");
    expect(seen.host).toBe(`127.0.0.1:${upstream.port}`);
    expect(seen["content-length"]).toBe(String(total));
    expect(seen["transfer-encoding"]).toBeUndefined();
    expect(seen.connection).toBe("close");
    expect(seen["x-other"]).toBeUndefined();
    expect(seen["x-mcp-credential-headers"]).toBeUndefined();
    expect(upstream.requests[0].sha256).toBe(result.sentSha256);
  });

  it("sends the registered static Authorization without an override, and the override instead of it when present", async () => {
    const upstream = await stub();
    await register({ name: "jira", type: "http", url: upstream.url, headers: { authorization: "Basic STATIC" } });

    await send({ path: TARGET, total: 1024, headers: BEARER });
    await send({ path: TARGET, total: 1024, headers: { ...BEARER, "X-MCP-Credential-Headers": credentialHeader({ Authorization: USER_BASIC }) } });

    expect(upstream.requests[0].headers.authorization).toBe("Basic STATIC");
    expect(upstream.requests[1].headers.authorization).toBe(USER_BASIC);
    // Never the gateway's own Bearer key.
    expect(upstream.requests.every((r) => !String(r.headers.authorization).includes(API_KEY))).toBe(true);
  });

  it("never forwards a registered Content-Type, Host or hop-by-hop header", async () => {
    const upstream = await stub();
    await register({
      name: "jira",
      type: "http",
      url: upstream.url,
      headers: { "Content-Type": "application/json", Host: "other.example", Connection: "keep-alive", "Proxy-Authorization": "x", "X-Static": "1" },
    });

    await send({ path: TARGET, total: 1024, headers: { ...BEARER, "Content-Type": "image/png" } });

    const seen = upstream.requests[0].headers;
    expect(seen["content-type"]).toBe("image/png");
    expect(seen.host).toBe(`127.0.0.1:${upstream.port}`);
    expect(seen.connection).toBe("close");
    expect(seen["proxy-authorization"]).toBeUndefined();
    expect(seen["x-static"]).toBe("1");
  });

  it("an own __proto__ key in the override is inert", async () => {
    const upstream = await stub();
    await register({ name: "jira", type: "http", url: upstream.url });
    const raw = Buffer.from(`{"__proto__":"x","Authorization":"${USER_BASIC}"}`, "utf8").toString("base64");

    const result = await send({ path: TARGET, total: 1024, headers: { ...BEARER, "X-MCP-Credential-Headers": raw } });

    expect(result.status).toBe(201);
    expect(upstream.requests[0].headers.authorization).toBe(USER_BASIC);
  });
});

/* ------------------------------------------------------------------ */
/*  Refusals: nothing reaches the MCP server                             */
/* ------------------------------------------------------------------ */

describe("refusals before any upstream connection", () => {
  async function refused(options: Omit<SendOptions, "port" | "total"> & { total?: number }) {
    const upstream = await stub();
    await register({ name: "jira", type: "http", url: upstream.url });
    await register({ name: "off", type: "http", url: upstream.url, enabled: false });
    await register({ name: "local", type: "stdio", command: "node" });
    const result = await send({ total: 4096, ...options });
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(upstream.connections()).toBe(0);
    expect(upstream.requests).toHaveLength(0);
    return { status: result.status, body: JSON.parse(result.text), headers: result.headers };
  }

  it("missing API key → the existing 401", async () => {
    const reply = await refused({ path: TARGET });
    expect(reply.status).toBe(401);
    expect(reply.body).toEqual({ error: "Missing or malformed Authorization header" });
    expect(reply.headers.connection).toBe("close");
  });

  it("wrong API key → the existing 401", async () => {
    const reply = await refused({ path: TARGET, headers: { Authorization: "Bearer wrong" } });
    expect(reply.status).toBe(401);
    expect(reply.body).toEqual({ error: "Invalid API key" });
  });

  it("unknown server → 400 MCP_SERVER_NOT_FOUND with the /call text", async () => {
    const reply = await refused({ path: "/v1/mcp-servers/missing/uploads/jira/issue/MVP-1", headers: BEARER });
    expect(reply.status).toBe(400);
    expect(reply.body).toEqual({ error: { code: "MCP_SERVER_NOT_FOUND", message: "missing is not registered" } });
  });

  it("disabled server → 400 MCP_SERVER_DISABLED with the /call text", async () => {
    const reply = await refused({ path: "/v1/mcp-servers/off/uploads/jira/issue/MVP-1", headers: BEARER });
    expect(reply.status).toBe(400);
    expect(reply.body).toEqual({
      error: {
        code: "MCP_SERVER_DISABLED",
        message: "off is registered but disabled; enable the server before calling its tools",
      },
    });
  });

  it("stdio server → 400 MCP_UPLOAD_UNSUPPORTED", async () => {
    const reply = await refused({ path: "/v1/mcp-servers/local/uploads/jira/issue/MVP-1", headers: BEARER });
    expect(reply.status).toBe(400);
    expect(reply.body.error.code).toBe("MCP_UPLOAD_UNSUPPORTED");
  });

  const invalidOverrides: [string, string | string[]][] = [
    ["not base64", "!!!not-base64!!!"],
    ["base64 without padding", "e30"],
    ["non-canonical base64 padding bits", "e31="],
    ["base64 of non-JSON", Buffer.from("not json").toString("base64")],
    ["base64 of invalid UTF-8", Buffer.from([0x7b, 0x22, 0xff, 0x22, 0x3a, 0x22, 0x22, 0x7d]).toString("base64")],
    ["JSON array", credentialHeader([USER_BASIC])],
    ["JSON string", credentialHeader(USER_BASIC)],
    ["JSON null", credentialHeader(null)],
    ["non-string value", credentialHeader({ Authorization: 1 })],
    ["object value", credentialHeader({ Authorization: { value: USER_BASIC } })],
    ["CR/LF in a value", credentialHeader({ Authorization: "Basic a\r\nX-Injected: 1" })],
    ["NUL in another key's value", credentialHeader({ Authorization: USER_BASIC, "X-Other": "a\u0000b" })],
    ["keys differing only in case", Buffer.from(`{"Authorization":"${USER_BASIC}","authorization":"Basic OTHER"}`).toString("base64")],
    ["empty header value", ""],
    ["repeated header", [credentialHeader({ Authorization: USER_BASIC }), credentialHeader({ Authorization: USER_BASIC })]],
    ["control character \\u0001 in Authorization", credentialHeader({ Authorization: "Basic a\u0001b" })],
    ["DEL \\u007f in Authorization", credentialHeader({ Authorization: "Basic a\u007fb" })],
    ["latin-1 ÿ in Authorization", credentialHeader({ Authorization: "Basic aÿb" })],
    ["non-latin-1 character in Authorization", credentialHeader({ Authorization: "Basic a€b" })],
    ["empty Authorization", credentialHeader({ Authorization: "" })],
    ["__proto__ object value", Buffer.from(`{"__proto__":{"Authorization":"Basic EVIL"}}`).toString("base64")],
  ];

  it.each(invalidOverrides)("invalid override (%s) → 400 MCP_OVERRIDE_INVALID without echoing it", async (_label, value) => {
    const reply = await refused({
      path: TARGET,
      headers: { ...BEARER, "X-MCP-Credential-Headers": value as string },
    });
    expect(reply.status).toBe(400);
    expect(reply.body.error.code).toBe("MCP_OVERRIDE_INVALID");
    const text = JSON.stringify(reply.body);
    expect(text).not.toContain("user-a-token");
    expect(text).not.toContain(USER_BASIC);
    expect(text).not.toContain("EVIL");
  });

  const invalidTargets = [
    "/v1/mcp-servers/jira/uploads",
    "/v1/mcp-servers/jira/uploads/",
    "/v1/mcp-servers/jira/uploads/..",
    "/v1/mcp-servers/jira/uploads/.",
    "/v1/mcp-servers/jira/uploads/jira/../mcp",
    "/v1/mcp-servers/jira/uploads/jira/./issue/MVP-1",
    "/v1/mcp-servers/jira/uploads/%2e%2e/mcp",
    "/v1/mcp-servers/jira/uploads/%2E./mcp",
    "/v1/mcp-servers/jira/uploads/.%2e/mcp",
    "/v1/mcp-servers/jira/uploads/jira%2fissue/MVP-1",
    "/v1/mcp-servers/jira/uploads/jira%2Fissue/MVP-1",
    "/v1/mcp-servers/jira/uploads/jira%5cissue/MVP-1",
    "/v1/mcp-servers/jira/uploads/jira\\issue/MVP-1",
  ];

  it.each(invalidTargets)("target %s → 400 UPLOAD_TARGET_INVALID", async (target) => {
    const reply = await refused({ path: `${target}?filename=shot.png`, headers: BEARER });
    expect(reply.status).toBe(400);
    expect(reply.body.error.code).toBe("UPLOAD_TARGET_INVALID");
  });

  it("a registration url that is not http(s) → 502 UPLOAD_UPSTREAM_FAILED, nothing sent", async () => {
    await register({ name: "ftp", type: "http", url: "ftp://127.0.0.1/mcp" });
    const result = await send({ path: "/v1/mcp-servers/ftp/uploads/jira/issue/MVP-1", total: 1024, headers: BEARER });
    expect(result.status).toBe(502);
    expect(JSON.parse(result.text)).toEqual({
      error: { code: "UPLOAD_UPSTREAM_FAILED", message: "The MCP server ftp could not be reached; nothing was sent" },
    });
  });

  it("a registered header value Node cannot send → 502 UPLOAD_UPSTREAM_FAILED, no connection", async () => {
    const upstream = await stub();
    await register({ name: "badheader", type: "http", url: upstream.url, headers: { "X-Static": "a\nb" } });
    const result = await send({ path: "/v1/mcp-servers/badheader/uploads/jira/issue/MVP-1", total: 1024, headers: BEARER });
    expect(result.status).toBe(502);
    expect(JSON.parse(result.text).error.code).toBe("UPLOAD_UPSTREAM_FAILED");
    expect(upstream.connections()).toBe(0);
  });
});

/* ------------------------------------------------------------------ */
/*  Pre-auth guard: refusals do not read a large body                   */
/* ------------------------------------------------------------------ */

describe("refusal while a large body is still arriving", () => {
  it.each([
    ["401 without an API key", TARGET, {}, 401],
    ["400 for an unknown server", "/v1/mcp-servers/missing/uploads/jira/issue/MVP-1", BEARER, 400],
  ] as const)("%s: readable answer, socket closed within about 5 s", async (_label, target, headers, status) => {
    const upstream = await stub();
    await register({ name: "jira", type: "http", url: upstream.url });
    const total = 50 * MiB;

    const result = await send({ path: target, total, headers: { ...headers } });
    expect(result.status).toBe(status);
    expect(JSON.parse(result.text)).toHaveProperty("error");
    expect(result.headers.connection).toBe("close");
    expect(await waitFor(() => result.socketClosedAt() !== null, 6000)).toBe(true);
    expect(result.socketClosedAt()! - result.finishedAt).toBeLessThan(5500);
    expect(result.written()).toBeLessThan(total);
    expect(upstream.connections()).toBe(0);
  }, 15_000);
});

/* ------------------------------------------------------------------ */
/*  Body parsers never see an upload (one shared path rule)             */
/* ------------------------------------------------------------------ */

describe("body parsers skip the upload path", () => {
  const jsonBody = Buffer.from(JSON.stringify({ a: 1, note: "must arrive byte-identical, not parsed" }), "utf8");

  it.each([
    ["application/json", "/v1/mcp-servers/jira/uploads/jira/issue/MVP-1?filename=a.json"],
    ["text/plain", "/v1/mcp-servers/jira/uploads/jira/issue/MVP-1?filename=a.txt"],
    ["application/json", "/V1/MCP-SERVERS/jira/UPLOADS/jira/issue/MVP-1?filename=a.json"],
  ])("%s body on %s reaches the MCP server byte-identical", async (contentType, target) => {
    const upstream = await stub();
    await register({ name: "jira", type: "http", url: upstream.url });

    const result = await send({ path: target, total: 3 * MiB, prefix: jsonBody, headers: { ...BEARER, "Content-Type": contentType } });

    expect(result.status).toBe(201);
    expect(upstream.requests[0].sha256).toBe(result.sentSha256);
    expect(upstream.requests[0].headers["content-type"]).toBe(contentType);
  });

  it("a server named `uploads` is relayed with the target after its own /uploads/", async () => {
    const upstream = await stub();
    await register({ name: "uploads", type: "http", url: upstream.url });

    const result = await send({
      path: "/v1/mcp-servers/uploads/uploads/jira/issue/MVP-1?filename=a.json",
      total: 2 * MiB,
      prefix: jsonBody,
      headers: { ...BEARER, "Content-Type": "application/json" },
    });

    expect(result.status).toBe(201);
    expect(upstream.requests[0].url).toBe("/uploads/jira/issue/MVP-1?filename=a.json");
    expect(upstream.requests[0].sha256).toBe(result.sentSha256);
  });

  it("an absolute-form request line is relayed byte-identical to the registered host only", async () => {
    const upstream = await stub();
    await register({ name: "jira", type: "http", url: upstream.url });
    const body = Buffer.concat([jsonBody, Buffer.alloc(100_000, 7)]);

    const response = await rawRequest(
      port,
      `POST http://evil.example:9/v1/mcp-servers/jira/uploads/jira/issue/MVP-1?filename=a.json HTTP/1.1\r\n` +
        `Host: evil.example:9\r\nAuthorization: Bearer ${API_KEY}\r\nContent-Type: application/json\r\n` +
        `Content-Length: ${body.length}\r\n\r\n`,
      body,
    );

    expect(response.startsWith("HTTP/1.1 201")).toBe(true);
    const { createHash } = await import("node:crypto");
    expect(upstream.requests[0].url).toBe("/uploads/jira/issue/MVP-1?filename=a.json");
    expect(upstream.requests[0].headers.host).toBe(`127.0.0.1:${upstream.port}`);
    expect(upstream.requests[0].sha256).toBe(createHash("sha256").update(body).digest("hex"));
  });

  it("non-upload routes still parse JSON", async () => {
    const response = await rawRequest(
      port,
      `PUT /v1/logging HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer ${API_KEY}\r\n` +
        `Content-Type: application/json\r\nContent-Length: 17\r\nConnection: close\r\n\r\n`,
      Buffer.from('{"level":"debug"}'),
    );
    expect(response.startsWith("HTTP/1.1 200")).toBe(true);
    expect(response).toContain('"level":"debug"');
  });
});

describe("server-wide timeouts", () => {
  it("the kept listen handle allows 3600 s per request for the relay", () => {
    expect(gateway.requestTimeout).toBe(3_600_000);
  });

  it("a non-upload request body still incomplete at the deadline closes the connection; an upload is exempt", async () => {
    const { nonUploadBodyDeadline, skipForUploads } = await import("../mcp-upload-relay.js");
    const app = express();
    app.use(nonUploadBodyDeadline(300));
    app.use(skipForUploads(express.json()));
    app.post(/.*/, (_req, res) => {
      res.json({ ok: true });
    });
    const server = app.listen(0, "127.0.0.1");
    await new Promise<void>((resolve) => server.once("listening", () => resolve()));
    const testPort = (server.address() as AddressInfo).port;
    try {
      const partial = (target: string) =>
        new Promise<number>((resolve) => {
          const started = Date.now();
          import("node:net").then(({ default: net }) => {
            const socket = net.connect(testPort, "127.0.0.1", () => {
              socket.write(
                `POST ${target} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{"a":`,
              );
            });
            socket.on("error", () => undefined);
            socket.on("close", () => resolve(Date.now() - started));
            setTimeout(() => {
              socket.destroy();
            }, 1500);
          });
        });
      const [slowJson, upload] = await Promise.all([
        partial("/v1/logging"),
        partial("/v1/mcp-servers/jira/uploads/jira/issue/MVP-1"),
      ]);
      expect(slowJson).toBeGreaterThanOrEqual(250);
      expect(slowJson).toBeLessThan(1200);
      // The upload is answered at once by the route (the parser never waits for
      // its body) and is not cut by the deadline; the client closes it at 1.5 s.
      expect(upload).toBeGreaterThanOrEqual(1400);
    } finally {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("MCP_UPLOAD_IDLE_TIMEOUT_MS: positive integers are used, anything else falls back to 60000", async () => {
    const { readUploadIdleTimeout } = await import("../mcp-upload-relay.js");
    expect(readUploadIdleTimeout(undefined)).toBe(60_000);
    expect(readUploadIdleTimeout("2500")).toBe(2500);
    for (const invalid of ["0", "-5", "1.5", "abc", "1e3", " 10"]) {
      expect(readUploadIdleTimeout(invalid)).toBe(60_000);
    }
  });
});

/* ------------------------------------------------------------------ */
/*  Upstream failures, early answers, timeouts, sender disconnect       */
/* ------------------------------------------------------------------ */

describe("failure behavior", () => {
  it("unreachable MCP server → 502 UPLOAD_UPSTREAM_FAILED, nothing sent", async () => {
    await register({ name: "dead", type: "http", url: `http://127.0.0.1:${await closedPort()}/mcp` });

    const result = await send({ path: "/v1/mcp-servers/dead/uploads/jira/issue/MVP-1", total: 2 * MiB, headers: BEARER });

    expect(result.status).toBe(502);
    expect(JSON.parse(result.text)).toEqual({
      error: { code: "UPLOAD_UPSTREAM_FAILED", message: "The MCP server dead could not be reached; nothing was sent" },
    });
  });

  it("MCP server drops the connection mid-body → 502 UPLOAD_UPSTREAM_FAILED, outcome unconfirmed", async () => {
    const upstream = await stub(({ req, record }) => {
      req.on("data", (chunk: Buffer) => {
        record.bytes += chunk.length;
        if (record.bytes > MiB) req.socket.destroy();
      });
    });
    await register({ name: "jira", type: "http", url: upstream.url });

    const result = await send({ path: TARGET, total: 20 * MiB, headers: BEARER });

    expect(result.status).toBe(502);
    const body = JSON.parse(result.text);
    expect(body.error.code).toBe("UPLOAD_UPSTREAM_FAILED");
    expect(body.error.message).toContain("unconfirmed");
    expect(logs.join("\n")).toContain("result=upstream_failed");
  }, 15_000);

  it("MCP server answers early while a 50 MB body still streams → the sender gets that answer verbatim", async () => {
    const early = JSON.stringify({ error: { code: "UPLOAD_FILENAME_INVALID", message: "refused early" } });
    // Like mcp-jira's early refusal: answer first, drain briefly, then close.
    const upstream = await stub(({ req, res }) => {
      res.writeHead(400, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(early), Connection: "close" });
      res.write(early);
      req.resume();
      setTimeout(() => res.end(() => req.socket.destroy()), 300);
    });
    await register({ name: "jira", type: "http", url: upstream.url });

    const result = await send({ path: TARGET, total: 50 * MiB, headers: BEARER });

    expect(result.status).toBe(400);
    expect(result.text).toBe(early);
    expect(result.headers.connection).toBe("close");
    expect(result.written()).toBeLessThan(50 * MiB);
  }, 15_000);

  it("a socket error after the MCP server's answer leaves the answer unchanged", async () => {
    const upstream = await stub(async (ctx) => {
      await answerCreated(ctx);
      setTimeout(() => ctx.req.socket.destroy(), 20);
    });
    await register({ name: "jira", type: "http", url: upstream.url });

    const result = await send({ path: TARGET, total: 4 * MiB, headers: BEARER });
    await new Promise((resolve) => setTimeout(resolve, 100));

    expect(result.status).toBe(201);
    expect(JSON.parse(result.text).size).toBe(4 * MiB);
  });

  it("an answer that breaks off after its status line closes the sender connection instead of completing it", async () => {
    const upstream = await stub(async ({ req, res, consume }) => {
      if (!(await consume())) return;
      res.writeHead(201, { "Content-Type": "application/json", "Content-Length": "100" });
      res.write('{"partial":');
      setTimeout(() => req.socket.destroy(), 50);
    });
    await register({ name: "jira", type: "http", url: upstream.url });

    const outcome = await new Promise<{ status: number; complete: boolean; bytes: number }>((resolve) => {
      const req = http.request(
        { host: "127.0.0.1", port, method: "POST", path: TARGET, agent: false, headers: { ...BEARER, "Content-Length": 1024 } },
        (res) => {
          let bytes = 0;
          res.on("data", (chunk: Buffer) => (bytes += chunk.length));
          res.on("error", () => undefined);
          res.on("close", () => resolve({ status: res.statusCode ?? 0, complete: res.complete, bytes }));
        },
      );
      req.on("error", () => undefined);
      req.end(Buffer.alloc(1024));
    });

    expect(outcome.status).toBe(201);
    expect(outcome.complete).toBe(false);
    expect(outcome.bytes).toBeLessThan(100);
    expect(await waitFor(() => logs.join("\n").includes("status=201 bytes=1024 result=upstream_failed"), 1000)).toBe(true);
  });

  it("a slow but progressing upload (one chunk per second for 10 s) completes with the idle timeout at 2000 ms", async () => {
    const upstream = await stub();
    await register({ name: "jira", type: "http", url: upstream.url });

    const result = await send({ path: TARGET, total: 10 * 16 * 1024, chunkSize: 16 * 1024, intervalMs: 1000, headers: BEARER });

    expect(result.status).toBe(201);
    expect(result.finishedAt - result.startedAt).toBeGreaterThanOrEqual(9000);
    expect(upstream.requests[0].sha256).toBe(result.sentSha256);
  }, 20_000);

  it("a sender that stalls for 3 s after its first chunk → 504 UPLOAD_TIMEOUT and the upstream request is aborted", async () => {
    const upstream = await stub();
    await register({ name: "jira", type: "http", url: upstream.url });

    const result = await send({ path: TARGET, total: MiB, stallAfter: 64 * 1024, headers: BEARER });

    expect(result.status).toBe(504);
    expect(JSON.parse(result.text)).toEqual({
      error: { code: "UPLOAD_TIMEOUT", message: `No upload progress for ${IDLE_TIMEOUT_MS} ms; the relay was aborted` },
    });
    const elapsed = result.finishedAt - result.startedAt;
    expect(elapsed).toBeGreaterThanOrEqual(IDLE_TIMEOUT_MS - 100);
    expect(elapsed).toBeLessThan(IDLE_TIMEOUT_MS + 1500);
    expect(await waitFor(() => upstream.requests[0]?.aborted === true, 1000)).toBe(true);
    expect(logs.join("\n")).toContain("result=timeout");
  }, 10_000);

  it("an MCP server that takes the whole body and never answers → 504 UPLOAD_TIMEOUT, outcome unconfirmed", async () => {
    const upstream = await stub(async ({ consume }) => {
      await consume();
    });
    await register({ name: "jira", type: "http", url: upstream.url });

    const result = await send({ path: TARGET, total: MiB, headers: BEARER });

    expect(result.status).toBe(504);
    const body = JSON.parse(result.text);
    expect(body.error.code).toBe("UPLOAD_TIMEOUT");
    expect(body.error.message).toContain("unconfirmed");
    expect(upstream.requests[0].complete).toBe(true);
  }, 10_000);

  it("the sender disconnects after 10 MB of 50 MB → the upstream request is aborted within 2 s", async () => {
    const upstream = await stub();
    await register({ name: "jira", type: "http", url: upstream.url });

    await expect(send({ path: TARGET, total: 50 * MiB, abortAfter: 10 * MiB, headers: BEARER })).rejects.toThrow();
    const disconnectedAt = Date.now();

    expect(await waitFor(() => upstream.requests[0]?.aborted === true, 2000)).toBe(true);
    expect(upstream.requests[0].abortedAt! - disconnectedAt).toBeLessThan(2000);
    expect(upstream.requests[0].complete).toBe(false);
    expect(await waitFor(() => logs.join("\n").includes("result=client_aborted"), 1000)).toBe(true);
  }, 15_000);
});

/* ------------------------------------------------------------------ */
/*  Credentials and bytes never in logs or answers                      */
/* ------------------------------------------------------------------ */

describe("credential and byte hygiene", () => {
  it("at LOG_LEVEL debug no log line carries the credential, the override header or the bytes", async () => {
    const { setLogLevel } = await import("../logging.js");
    setLogLevel("debug");
    const upstream = await stub();
    await register({ name: "jira", type: "http", url: upstream.url });
    const override = credentialHeader({ Authorization: USER_BASIC });
    const marker = Buffer.from("RELAY-MARKER-7564-e5b1", "utf8");

    const ok = await send({
      path: TARGET,
      total: MiB,
      prefix: marker,
      headers: { ...BEARER, "Content-Type": "text/plain", "X-MCP-Credential-Headers": override },
    });
    await register({ name: "dead", type: "http", url: `http://127.0.0.1:${await closedPort()}/mcp` });
    const failed = await send({
      path: "/v1/mcp-servers/dead/uploads/jira/issue/MVP-1",
      total: MiB,
      prefix: marker,
      headers: { ...BEARER, "Content-Type": "application/json", "X-MCP-Credential-Headers": override },
    });

    expect(ok.status).toBe(201);
    expect(failed.status).toBe(502);
    const logText = logs.join("\n");
    expect(logText).toContain("[req] POST /v1/mcp-servers/jira/uploads/jira/issue/MVP-1?filename=shot.png");
    for (const secret of [USER_BASIC, override, "user-a-token", "user-a@example.com:user-a-token", API_KEY, marker.toString()]) {
      expect(logText).not.toContain(secret);
      expect(ok.text).not.toContain(secret);
      expect(failed.text).not.toContain(secret);
    }
  });
});
