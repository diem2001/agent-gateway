/**
 * GW-S2 — E2E Outcome Probe (MVP-6648 / gate MVP-6680).
 *
 * Boots the REAL assembled gateway in-process (imports the exported `app` from
 * `../server.js`, which wires requestLogging → authMiddleware → all routes incl.
 * the `/call` handler) and registers a fake TEST MCP echo server, then proves the
 * LLM-free `POST /v1/mcp-servers/{name}/call` passthrough guarantee end-to-end:
 *
 *   1. A registered TEST tool runs via /call and returns its verbatim result.
 *   2. NO LLM query / NO token usage runs for the call (log + module-load + body
 *      evidence).
 *   3. Per-request credentials A override the server's static credentials.
 *   4. A server-unreachable failure returns the gateway error envelope within the
 *      deadline (no hang) and leaks no credential.
 *
 * Self-contained: no live Atlassian/mcp-jira, no external deploy. `PORT=0` makes
 * the top-level `app.listen` bind a throwaway loopback port harmlessly; no runtime
 * source is modified. Excluded from the fast unit gate (`npm test` excludes
 * `src/tests/e2e-*`); runs under `npm run test:e2e`.
 */
import http, { type Server } from "node:http";
import os from "node:os";
import path from "node:path";
import fs from "node:fs";
import request from "supertest";
import type { Express } from "express";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const API_KEY = "e2e-key";
const CALL_TIMEOUT_MS = 300;

let logs: string[] = [];
let sdkQueryInvoked = false;
let servers: Server[] = [];
let tempDir: string;
let httpServer: import("node:http").Server | null = null;

/** Start a fake MCP server; returns its base /mcp URL. Closed in afterEach. */
async function startFakeMcpServer(
  handler: (req: http.IncomingMessage, res: http.ServerResponse) => void,
): Promise<string> {
  const server = http.createServer(handler);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("fake server did not bind a port");
  return `http://127.0.0.1:${address.port}/mcp`;
}

/**
 * An echo MCP server: it reflects the inbound Authorization header it actually
 * received back into the tool result text as `OK:<auth>`. This is what proves the
 * per-request credential override reached the upstream verbatim.
 */
function echoAuthResponder(record?: (auth: string) => void) {
  return (req: http.IncomingMessage, res: http.ServerResponse) => {
    const auth = String(req.headers.authorization ?? "");
    record?.(auth);
    res.setHeader("Content-Type", "application/json");
    res.end(
      JSON.stringify({
        jsonrpc: "2.0",
        id: "agent-gateway-mcp-call",
        result: { content: [{ type: "text", text: `OK:${auth}` }], isError: false },
      }),
    );
  };
}

async function registerServer(def: {
  name: string;
  type: "http";
  url: string;
  headers?: Record<string, string>;
  enabled?: boolean;
}): Promise<void> {
  // Imported AFTER ../server.js (no resetModules in between) so this is the SAME
  // in-memory registry instance the running app reads from.
  const { registerMcpServer } = await import("../mcp-registry.js");
  const now = new Date().toISOString();
  registerMcpServer({
    description: "",
    enabled: true,
    createdAt: now,
    updatedAt: now,
    ...def,
  } as never);
}

/** Boot the real assembled gateway in-process and return its Express app. */
async function bootGateway(): Promise<Express> {
  const mod = (await import("../server.js")) as { default: Express };
  // Keep a handle to the throwaway listener so we can close it for hygiene.
  // The app's own `app.listen` already bound a PORT=0 socket at import time.
  httpServer = null;
  return mod.default;
}

beforeEach(() => {
  vi.resetModules();
  logs = [];
  sdkQueryInvoked = false;

  // Env wired BEFORE importing ../server.js (its top-level bootstrap reads these).
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gateway-e2e-call-"));
  process.env.PORT = "0"; // top-level app.listen binds a throwaway loopback port harmlessly
  process.env.HOST = "127.0.0.1";
  process.env.API_KEYS = `caller:${API_KEY}`;
  process.env.MCP_SERVERS_PERSIST_PATH = path.join(tempDir, "mcp-servers.json");
  process.env.MCP_CALL_TIMEOUT_MS = String(CALL_TIMEOUT_MS);
  process.env.LOG_LEVEL = "info";

  // Capture the gateway's log stream. `log()`/`logDebug()` (logging.ts) and the
  // query.ts token signal all funnel through console.log.
  vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
    logs.push(args.map(String).join(" "));
  });

  // The Agent SDK's query() is the ONLY LLM/token path in the gateway. NOTE: the
  // assembled server imports the query router (query.ts → retry.ts → agent.ts →
  // @anthropic-ai/claude-agent-sdk) at BOOT, so the SDK *module* is loaded merely by
  // standing up the gateway — module load is therefore NOT a no-LLM signal. The real
  // guarantee is that the SDK's query() is never INVOKED during a /call. This mock's
  // query() flips sdkQueryInvoked and throws, so any accidental LLM turn both records
  // itself and blows up loudly; the /call passthrough must leave it false.
  vi.doMock("@anthropic-ai/claude-agent-sdk", () => ({
    createSdkMcpServer: vi.fn((options: { name: string }) => ({ type: "sdk", name: options.name })),
    query: vi.fn(() => {
      sdkQueryInvoked = true;
      throw new Error("LLM/Agent-SDK query() must not run for /call");
    }),
  }));
});

afterEach(async () => {
  await Promise.all(
    servers.map((server) => new Promise<void>((resolve) => server.close(() => resolve()))),
  );
  servers = [];
  if (httpServer) await new Promise<void>((resolve) => httpServer?.close(() => resolve()));
  httpServer = null;

  vi.restoreAllMocks();
  vi.doUnmock("@anthropic-ai/claude-agent-sdk");
  vi.resetModules();

  fs.rmSync(tempDir, { recursive: true, force: true });
  delete process.env.PORT;
  delete process.env.HOST;
  delete process.env.API_KEYS;
  delete process.env.MCP_SERVERS_PERSIST_PATH;
  delete process.env.MCP_CALL_TIMEOUT_MS;
  delete process.env.LOG_LEVEL;
});

describe("E2E Outcome Probe — /call passthrough on the real gateway (MVP-6648)", () => {
  it("runs a registered tool with NO LLM and honors per-request credentials", async () => {
    const seenAuth: string[] = [];
    const url = await startFakeMcpServer(echoAuthResponder((auth) => seenAuth.push(auth)));

    const app = await bootGateway();
    // Server's STATIC credential must be overridden by the per-request credential.
    await registerServer({ name: "echo", type: "http", url, headers: { Authorization: "STATIC" } });

    const res = await request(app)
      .post("/v1/mcp-servers/echo/call")
      .set("Authorization", `Bearer ${API_KEY}`)
      .send({
        tool: "echo",
        arguments: { q: 1 },
        credentials: { headers: { Authorization: "Basic CREDS_A" } },
      });

    // --- AC fact 1: tool executes via /call, verbatim result. ---
    expect(res.status).toBe(200);
    // --- AC fact 3: per-request creds A honored (override beat STATIC). ---
    expect(res.body).toEqual({ content: [{ type: "text", text: "OK:Basic CREDS_A" }], isError: false });
    // The upstream actually received the override, not the server's static value.
    expect(seenAuth).toEqual(["Basic CREDS_A"]);

    const logText = logs.join("\n");

    // --- AC fact 2: NO LLM / NO token usage. ---
    // (a) The /call success audit line WAS emitted (the call really ran the tool).
    expect(logText).toContain("mcp.call.called serverName=echo tool=echo result=ok");
    // (b) No LLM query ran: the query.ts token signal never appears.
    expect(logText).not.toContain("[query]");
    expect(logText).not.toContain("tokens=");
    // (c) The Agent SDK's query() (the sole LLM/token path) was never invoked on
    //     the /call path. (The SDK module loads at boot via the query router — that
    //     is expected and is NOT an LLM turn; only an invocation would be.)
    expect(sdkQueryInvoked).toBe(false);
    // (d) The response carries no token-usage signal of any kind.
    expect(res.body).not.toHaveProperty("usage");
    expect(res.body).not.toHaveProperty("inputTokens");
    expect(res.body).not.toHaveProperty("outputTokens");
    expect(JSON.stringify(res.body)).not.toContain("tokens");
  });

  it("returns the gateway error envelope within the deadline when the server is unreachable (no hang, no creds leak)", async () => {
    // A fake server we close BEFORE the call so the bound port is dead (connection
    // refused) → MCP_NETWORK_ERROR, fast. (A held-open socket would instead exercise
    // MCP_TIMEOUT; either is an accepted envelope per the AC.)
    const deadServer = http.createServer(() => undefined);
    await new Promise<void>((resolve) => deadServer.listen(0, "127.0.0.1", () => resolve()));
    const address = deadServer.address();
    if (!address || typeof address === "string") throw new Error("dead server did not bind a port");
    const deadUrl = `http://127.0.0.1:${address.port}/mcp`;
    await new Promise<void>((resolve) => deadServer.close(() => resolve()));

    const app = await bootGateway();
    await registerServer({ name: "dead", type: "http", url: deadUrl });

    const startedAt = Date.now();
    const res = await request(app)
      .post("/v1/mcp-servers/dead/call")
      .set("Authorization", `Bearer ${API_KEY}`)
      .send({
        tool: "echo",
        arguments: {},
        // Distinct, searchable credential — must NOT leak into logs or body.
        credentials: { headers: { Authorization: "Basic CREDS_B" } },
      });
    const elapsed = Date.now() - startedAt;

    // --- AC fact 4: gateway error envelope, no hang. ---
    expect([502, 504]).toContain(res.status);
    expect(["MCP_NETWORK_ERROR", "MCP_TIMEOUT"]).toContain(res.body?.error?.code);
    expect(typeof res.body?.error?.message).toBe("string");
    // Returned within (a small multiple of) the configured deadline — proves no hang.
    expect(elapsed).toBeLessThan(CALL_TIMEOUT_MS + 2000);

    // No credential leak: neither the body nor the captured logs contain CREDS_B.
    expect(JSON.stringify(res.body)).not.toContain("CREDS_B");
    expect(logs.join("\n")).not.toContain("CREDS_B");

    // Still no LLM path on the failure route.
    expect(sdkQueryInvoked).toBe(false);
    expect(logs.join("\n")).not.toContain("[query]");
  });
});
