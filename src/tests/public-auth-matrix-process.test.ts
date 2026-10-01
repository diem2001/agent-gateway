/**
 * The public gateway authentication on every protected route, and the upload relay's no-progress timeout, behind the
 * trusted boundary (MVP-7679, Gate E; Story outlines "Public gateway authentication is preserved on every protected
 * route" and "Upload relay keeps its no-progress timeout behind the boundary").
 *
 * A task-owned gateway (the compiled `dist/server.js`) is configured with one valid gateway key, a registered MCP
 * server double that records every request it receives (HTTP JSON-RPC and upload endpoints) and a deterministic
 * local model double that records every agent run. Each of the nine matrix rows is one request with one credential;
 * the model double must record exactly the stated number of agent runs and the MCP double exactly the stated number
 * of upstream requests. A direct MCP call and an upload start no agent run at all.
 *
 * Needs `npm run build`. Linux only. Every secret is synthetic.
 */
import http from "node:http";
import { afterEach, describe, expect, it, vi } from "vitest";
import { FINAL_ANSWER, startFakeAnthropicApi, type FakeAnthropicApi } from "./helpers/fake-anthropic-api.js";
import { GATEWAY_API_KEY, gatewayRequest, spawnGateway, type Cleanup, type SpawnedGateway } from "./helpers/git-process-gateway.js";
import { startOAuthMcpStub, type OAuthMcpStub } from "./helpers/oauth-mcp-stub.js";
import { MiB, sendUpload, startUploadStub, type UploadStub } from "./helpers/upload-relay-stub.js";

vi.setConfig({ testTimeout: 120_000 });

const cleanups: Cleanup[] = [];
afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()!();
});

const UNKNOWN_KEY = "SYNTH-UNKNOWN-KEY-7679";
const REGISTRY_TOKEN = "SYNTH-REGISTRY-UPLOAD-CREDENTIAL-7679";
const PROMPT = "AUTH-MATRIX-PROMPT";

interface Fixture {
  api: FakeAnthropicApi;
  gateway: SpawnedGateway;
  mcp: OAuthMcpStub;
  uploads: UploadStub;
}

async function fixture(env: Record<string, string> = {}): Promise<Fixture> {
  const mcp = await startOAuthMcpStub({});
  cleanups.push(() => mcp.close());
  const uploads = await startUploadStub();
  cleanups.push(() => uploads.close());
  const api = await startFakeAnthropicApi({ toolName: "unused-7679" });
  cleanups.push(() => api.close());
  const gateway = await spawnGateway(cleanups, {
    rootPrefix: "mvp7679-auth-",
    env: { ANTHROPIC_BASE_URL: api.baseUrl, ANTHROPIC_API_KEY: "sk-ant-fake-auth-7679", DISABLE_TELEMETRY: "1", CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1", ...env },
  });
  const records = await gatewayRequest(gateway.port, "PUT", "/v1/mcp-servers/records", { type: "http", url: mcp.url, headers: { "X-Registry-Token": REGISTRY_TOKEN } });
  expect(records.status, records.text).toBe(201);
  const upload = await gatewayRequest(gateway.port, "PUT", "/v1/mcp-servers/store", { type: "http", url: uploads.url, headers: { "X-Upload-Credential": REGISTRY_TOKEN } });
  expect(upload.status, upload.text).toBe(201);
  // The registry persists on a debounce; give it time before any restart-free assertion needs it.
  await new Promise((resolve) => setTimeout(resolve, 300));
  return { api, gateway, mcp, uploads };
}

/** A request with an explicit credential (`undefined` = no Authorization header at all). */
function call(port: number, key: string | undefined, method: string, urlPath: string, body?: unknown): Promise<{ status: number; text: string }> {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body), "utf8");
    const req = http.request(
      { host: "127.0.0.1", port, method, path: urlPath, agent: false, headers: { ...(key ? { Authorization: `Bearer ${key}` } : {}), ...(payload ? { "Content-Type": "application/json", "Content-Length": payload.length } : {}) } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString("utf8") }));
      },
    );
    req.on("error", reject);
    req.end(payload);
  });
}

const agentRuns = (f: Fixture): number => new Set(f.api.requests.filter((q) => q.userTexts.some((t) => t.includes(PROMPT)) && !q.warmup).map((q) => q.session)).size;
const upstreamRequests = (f: Fixture): number => f.mcp.requests.filter((q) => q.path === "/mcp").length;
const uploadRequests = (f: Fixture): number => f.uploads.requests.length;

type Operation = "query" | "direct" | "upload";
const MATRIX: [Operation, string, string | undefined, number | "ok", number, number][] = [
  ["query", "no key", undefined, 401, 0, 0],
  ["query", "an unknown key", UNKNOWN_KEY, 401, 0, 0],
  ["query", "the valid key", GATEWAY_API_KEY, "ok", 1, 0],
  ["direct", "no key", undefined, 401, 0, 0],
  ["direct", "an unknown key", UNKNOWN_KEY, 401, 0, 0],
  ["direct", "the valid key", GATEWAY_API_KEY, "ok", 0, 1],
  ["upload", "no key", undefined, 401, 0, 0],
  ["upload", "an unknown key", UNKNOWN_KEY, 401, 0, 0],
  ["upload", "the valid key", GATEWAY_API_KEY, "ok", 0, 1],
];

describe("public authentication on every protected route (9 rows)", () => {
  it.each(MATRIX)("%s with %s: %s, %i agent run(s), %i upstream request(s)", async (operation, _credential, key, expected, runs, upstream) => {
    const f = await fixture();
    let status = 0;
    let text = "";
    if (operation === "query") {
      // "An agent query that invokes no tool": it is granted none (an enforced empty set), so the registered server is
      // not attached and the MCP double sees nothing. A run that does attach a server contacts it for the handshake and
      // the tool list at start; that case is the next describe block.
      const res = await call(f.gateway.port, key, "POST", "/v1/query", { queryId: `q-${Date.now()}`, prompt: PROMPT, model: "claude-sonnet-4-5", useSession: false, enforcedTools: [] });
      status = res.status;
      text = res.text;
    } else if (operation === "direct") {
      const res = await call(f.gateway.port, key, "POST", "/v1/mcp-servers/records/call", { tool: "lookup_record", arguments: { id: "R-1" } });
      status = res.status;
      text = res.text;
    } else {
      const res = await sendUpload({ port: f.gateway.port, path: "/v1/mcp-servers/store/uploads/jira/issue/MVP-1?filename=shot.png", headers: key ? { Authorization: `Bearer ${key}` } : {}, total: 64 * 1024 });
      status = res.status;
      text = res.text;
    }

    if (expected === "ok") {
      expect(status, text).toBeLessThan(300);
      if (operation === "query") expect(text).toContain(FINAL_ANSWER);
      if (operation === "direct") expect(JSON.parse(text).content[0].text).toContain("RECORD-7667-OK");
      if (operation === "upload") expect(JSON.parse(text)).toMatchObject({ attachmentId: "10001" });
    } else {
      expect(status, text).toBe(expected);
    }
    expect(agentRuns(f), "agent runs").toBe(runs);
    expect(operation === "upload" ? uploadRequests(f) : upstreamRequests(f), "upstream requests").toBe(upstream);
    // The other double never saw anything for this operation.
    expect(operation === "upload" ? upstreamRequests(f) : uploadRequests(f)).toBe(0);
  });
});

describe("a query that attaches the registered server and invokes no tool", () => {
  it("contacts it only for the handshake and the tool list, never for a tool call, and the credential stays on the trusted side", async () => {
    const f = await fixture();
    const res = await call(f.gateway.port, GATEWAY_API_KEY, "POST", "/v1/query", { queryId: `q-${Date.now()}`, prompt: PROMPT, model: "claude-sonnet-4-5", useSession: false });
    expect(res.text).toContain(FINAL_ANSWER);
    expect(agentRuns(f)).toBe(1);
    expect(f.mcp.toolCalls).toEqual([]);
    const methods = f.mcp.requests.flatMap((q) => q.rpcMethods);
    expect(methods).toEqual(expect.arrayContaining(["initialize", "tools/list"]));
    expect(methods).not.toContain("tools/call");
    expect(f.mcp.requests.filter((q) => q.path === "/mcp").every((q) => q.headers["x-registry-token"] === REGISTRY_TOKEN)).toBe(true);
    for (const surface of [res.text, f.gateway.output(), JSON.stringify(f.api.requests.map((q) => q.body))]) expect(surface).not.toContain(REGISTRY_TOKEN);
  });
});

describe("a direct MCP request and an upload do not start a model run", () => {
  it("the model double records no request at all while both succeed with credentials added only on the trusted side", async () => {
    const f = await fixture();
    const direct = await call(f.gateway.port, GATEWAY_API_KEY, "POST", "/v1/mcp-servers/records/call", { tool: "lookup_record", arguments: { id: "R-1" } });
    const upload = await sendUpload({ port: f.gateway.port, path: "/v1/mcp-servers/store/uploads/jira/issue/MVP-1?filename=shot.png", headers: { Authorization: `Bearer ${GATEWAY_API_KEY}` }, total: 64 * 1024 });
    expect(direct.status).toBe(200);
    expect(upload.status).toBe(201);
    expect(f.api.requests).toEqual([]);
    // The registry credential reached the upstreams and nothing the caller can read.
    expect(f.mcp.requests.every((q) => q.headers["x-registry-token"] === REGISTRY_TOKEN)).toBe(true);
    expect(f.uploads.requests.every((q) => q.headers["x-upload-credential"] === REGISTRY_TOKEN)).toBe(true);
    for (const surface of [direct.text, upload.text, f.gateway.output()]) expect(surface).not.toContain(REGISTRY_TOKEN);
  });
});

describe("the upload relay keeps its no-progress timeout (2 rows, MCP_UPLOAD_IDLE_TIMEOUT_MS=1500)", () => {
  it("an upload that keeps sending for longer than the idle timeout in total, with every gap shorter than it, returns the server's response", async () => {
    const f = await fixture({ MCP_UPLOAD_IDLE_TIMEOUT_MS: "1500" });
    const started = Date.now();
    const res = await sendUpload({
      port: f.gateway.port,
      path: "/v1/mcp-servers/store/uploads/jira/issue/MVP-1?filename=slow.png",
      headers: { Authorization: `Bearer ${GATEWAY_API_KEY}` },
      total: 8 * 8192,
      chunkSize: 8192,
      intervalMs: 500,
    });
    expect(Date.now() - started).toBeGreaterThan(2500);
    expect(res.status, res.text).toBe(201);
    expect(JSON.parse(res.text)).toMatchObject({ attachmentId: "10001", size: 8 * 8192 });
    expect(f.uploads.requests.at(-1)).toMatchObject({ complete: true, aborted: false });
    expect(agentRuns(f)).toBe(0);
    expect(f.api.requests).toEqual([]);
    expect(res.text + f.gateway.output()).not.toContain(REGISTRY_TOKEN);
  });

  it("an upload that sends a first chunk and then stops sending for longer than the idle timeout is HTTP 504 UPLOAD_TIMEOUT and the upstream upload request is aborted", async () => {
    const f = await fixture({ MCP_UPLOAD_IDLE_TIMEOUT_MS: "1500" });
    const res = await sendUpload({
      port: f.gateway.port,
      path: "/v1/mcp-servers/store/uploads/jira/issue/MVP-1?filename=stall.png",
      headers: { Authorization: `Bearer ${GATEWAY_API_KEY}` },
      total: MiB,
      stallAfter: 64 * 1024,
    });
    expect(res.status, res.text).toBe(504);
    expect(JSON.parse(res.text).error.code).toBe("UPLOAD_TIMEOUT");
    await vi.waitFor(() => expect(f.uploads.requests.at(-1)?.aborted).toBe(true), { timeout: 5000 });
    expect(f.api.requests).toEqual([]);
    expect(res.text + f.gateway.output()).not.toContain(REGISTRY_TOKEN);
  });
});
