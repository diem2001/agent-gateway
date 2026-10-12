/**
 * The SSE bridge behind the trusted relay (MVP-7679, mcp-bridge.ts, mcp-credential-relay.ts): a registered SSE
 * server reaches the runtime as one JSON-over-POST relay URL. Rows: the happy path with the run's credential on the
 * stream and on every POST, the endpoint-origin rule, local answers to server requests, every failure code, the
 * fault rows (stream reset, an event that never ends, an upstream that hangs) with the relay surviving, and the
 * revocation that closes the stream. Expected texts are written out.
 */
import http from "node:http";
import { type AddressInfo } from "node:net";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { CredentialRelay, type RelayGrant } from "../mcp-credential-relay.js";
import { startSseMcpStub, type SseMcpStub, type SseMcpStubOptions } from "./helpers/sse-mcp-stub.js";

const ALLOW_ALL: RelayGrant = { allowsTool: () => true, coversServer: true };
const cleanups: (() => Promise<void> | void)[] = [];
let logs: string[] = [];

beforeEach(() => {
  logs = [];
  vi.spyOn(console, "log").mockImplementation((...args) => {
    logs.push(args.map(String).join(" "));
  });
});

afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()!();
  vi.restoreAllMocks();
});

async function relay(options?: ConstructorParameters<typeof CredentialRelay>[0]): Promise<CredentialRelay> {
  const created = new CredentialRelay(options);
  await created.start();
  cleanups.push(() => created.close());
  return created;
}

async function sse(options: SseMcpStubOptions = {}): Promise<SseMcpStub> {
  const created = await startSseMcpStub(options);
  cleanups.push(() => created.close());
  return created;
}

function post(url: string, body: unknown): Promise<{ status: number; json: Record<string, unknown> | null; text: string }> {
  const target = new URL(url);
  const payload = Buffer.from(JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: target.hostname, port: target.port, path: target.pathname, method: "POST", agent: false, headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", "Content-Length": payload.length } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          let json: Record<string, unknown> | null = null;
          try {
            json = JSON.parse(text) as Record<string, unknown>;
          } catch {
            // Not JSON.
          }
          resolve({ status: res.statusCode ?? 0, json, text });
        });
      },
    );
    req.on("error", reject);
    req.end(payload);
  });
}

const rpc = (method: string, id?: number, params: Record<string, unknown> = {}) => ({ jsonrpc: "2.0", ...(id === undefined ? {} : { id }), method, params });
const UNAVAILABLE = 'TOOL_UNAVAILABLE: "feed" could not be reached or failed. Try again later; if it keeps happening, tell your gateway administrator.';
const REDIRECTED = 'TOOL_UNAVAILABLE: "feed" tried to send the request to another address, which the gateway does not allow. Tell your gateway administrator; retrying will not help.';
const INVALID = 'TOOL_RESPONSE_INVALID: "feed" sent an answer the gateway could not read. If it keeps happening, tell your gateway administrator.';
const GATEWAY_REFUSED = `TOOL_AUTH_UNAVAILABLE: "feed" did not accept the gateway's credential. Ask your gateway administrator to check this tool's credential; retrying will not help.`;
const USER_REFUSED = `TOOL_AUTH_UNAVAILABLE: "feed" did not accept the user's credential. Ask the user to reconnect their account; retrying will not help.`;

async function bound(stub: SseMcpStub, extra: Partial<Parameters<CredentialRelay["register"]>[0]> = {}, options?: ConstructorParameters<typeof CredentialRelay>[0]) {
  const r = await relay(options);
  const registered = r.register({ grant: ALLOW_ALL, serverName: "feed", url: stub.url, headers: { Authorization: "Bearer SYNTH-SSE-CREDENTIAL-7679" }, kind: "sse", ...extra });
  return { r, ...registered };
}

describe("the SSE bridge: the happy path", () => {
  it("initialize, tools/list and tools/call answer as JSON; the credential is on the stream and on every POST, never on a path of another origin", async () => {
    const stub = await sse();
    const { url } = await bound(stub);

    const init = await post(url, rpc("initialize", 1, { protocolVersion: "2025-06-18" }));
    const note = await post(url, rpc("notifications/initialized"));
    const list = await post(url, rpc("tools/list", 2));
    const call = await post(url, rpc("tools/call", 3, { name: "lookup_record", arguments: { id: "R-1" } }));

    expect(init.status).toBe(200);
    expect((init.json?.result as { serverInfo: { name: string } }).serverInfo.name).toBe("sse-mcp-stub");
    expect(note.status).toBe(202);
    expect((list.json?.result as { tools: { name: string }[] }).tools.map((t) => t.name)).toEqual(["lookup_record"]);
    expect(call.json).toEqual({ jsonrpc: "2.0", id: 3, result: { content: [{ type: "text", text: "SSE-RESULT-7679 lookup_record" }] } });
    expect(stub.requests.map((q) => `${q.method} ${q.path.split("?")[0]}`)).toEqual(["GET /sse", "POST /messages", "POST /messages", "POST /messages", "POST /messages"]);
    expect(stub.requests.every((q) => q.headers.authorization === "Bearer SYNTH-SSE-CREDENTIAL-7679")).toBe(true);
    // One stream serves the whole run.
    expect(stub.streamsOpened()).toBe(1);
    // The runtime's own headers never travel.
    expect(stub.requests.every((q) => q.headers.cookie === undefined)).toBe(true);
  });

  it("an absolute endpoint on the registered origin is accepted", async () => {
    const stub = await sse({ endpoint: (origin) => `${origin}/messages?sessionId=abs` });
    const { url } = await bound(stub);
    const res = await post(url, rpc("ping", 1));
    expect(res.json).toEqual({ jsonrpc: "2.0", id: 1, result: {} });
  });

  it("a server that answers inline in the POST response is accepted", async () => {
    const stub = await sse({ mode: "inline-answer" });
    const { url } = await bound(stub);
    await post(url, rpc("initialize", 1));
    const call = await post(url, rpc("tools/call", 2, { name: "lookup_record", arguments: {} }));
    expect((call.json?.result as { content: { text: string }[] }).content[0].text).toBe("SSE-RESULT-7679 lookup_record");
  });

  it("server requests on the stream are answered locally and never reach the runtime; server notifications are dropped", async () => {
    const stub = await sse({ serverRequests: true });
    const { url } = await bound(stub);

    const init = await post(url, rpc("initialize", 1));
    await new Promise((resolve) => setTimeout(resolve, 200));

    expect((init.json?.result as { serverInfo: unknown }).serverInfo).toBeDefined();
    expect(stub.clientAnswers).toEqual([
      { jsonrpc: "2.0", id: "srv-ping", result: {} },
      { jsonrpc: "2.0", id: "srv-roots", result: { roots: [] } },
      { jsonrpc: "2.0", id: "srv-other", error: { code: -32601, message: "Method not found" } },
    ]);
  });

  it("the grant applies before the bridge: an ungranted tool is TOOL_DENIED and never reaches the server", async () => {
    const stub = await sse({ toolNames: ["lookup_record", "delete_record"] });
    const { url } = await bound(stub, { grant: { allowsTool: (tool) => tool === "lookup_record", coversServer: false } });
    const denied = await post(url, rpc("tools/call", 1, { name: "delete_record", arguments: {} }));
    expect((denied.json?.result as { isError: boolean }).isError).toBe(true);
    expect(JSON.stringify(denied.json)).toContain("TOOL_DENIED");
    // Not even the stream was opened for a refused message.
    expect(stub.requests).toHaveLength(0);
    expect(stub.toolCalls).toEqual([]);
  });
});

describe("the SSE bridge: the endpoint stays on the registered origin", () => {
  it.each([
    ["another host", (origin: string) => origin.replace("127.0.0.1", "localhost") + "/messages"],
    ["another port", () => "http://127.0.0.1:1/messages"],
    ["another scheme", (origin: string) => origin.replace("http:", "https:") + "/messages"],
    ["a protocol-relative URL to another host", () => "//attacker.example/messages"],
    ["a non-http scheme", () => "file:///etc/passwd"],
  ])("%s: the redirect failure, and the credential is never sent to the other origin", async (_label, endpoint) => {
    const stub = await sse({ endpoint });
    const { url } = await bound(stub);
    const res = await post(url, rpc("tools/call", 1, { name: "lookup_record", arguments: {} }));
    expect(res.json).toEqual({ jsonrpc: "2.0", id: 1, result: { content: [{ type: "text", text: REDIRECTED }], isError: true } });
    // Only the stream was opened; no POST carried the credential anywhere.
    expect(stub.requests.map((q) => q.method)).toEqual(["GET"]);
    expect(logs.join("\n")).toContain("mcp.bridge.refused serverName=feed reason=endpoint_other_origin");
  });
});

describe("the SSE bridge: failure codes", () => {
  it.each([
    [301, REDIRECTED],
    [302, REDIRECTED],
    [307, REDIRECTED],
    [401, GATEWAY_REFUSED],
    [403, GATEWAY_REFUSED],
    [404, UNAVAILABLE],
    [429, UNAVAILABLE],
    [500, UNAVAILABLE],
    [503, UNAVAILABLE],
  ])("a %i answer to the stream request is the matching text", async (getStatus, text) => {
    const target = await sse();
    const stub = await sse({ getStatus, getLocation: target.url });
    const { url } = await bound(stub);
    const res = await post(url, rpc("tools/call", 1, { name: "lookup_record", arguments: {} }));
    expect((res.json?.result as { content: { text: string }[] }).content[0].text).toBe(text);
    // A redirect target never gets a request, so the credential is never sent to it.
    expect(target.requests).toEqual([]);
  });

  it("a user credential that is refused reads with the user text", async () => {
    const stub = await sse({ getStatus: 401 });
    const { url } = await bound(stub, { credentialSource: "user" });
    const res = await post(url, rpc("tools/call", 1, { name: "lookup_record", arguments: {} }));
    expect((res.json?.result as { content: { text: string }[] }).content[0].text).toBe(USER_REFUSED);
  });

  it.each([401, 403, 500, 302])("a %i answer to a POST is a failure; a refused credential is not retried", async (postStatus) => {
    const stub = await sse({ postStatus });
    const { url } = await bound(stub);
    const res = await post(url, rpc("tools/call", 1, { name: "lookup_record", arguments: {} }));
    const text = (res.json?.result as { content: { text: string }[] }).content[0].text;
    expect(text).toBe(postStatus === 401 || postStatus === 403 ? GATEWAY_REFUSED : postStatus === 302 ? REDIRECTED : UNAVAILABLE);
    expect(stub.requests.filter((q) => q.method === "POST")).toHaveLength(1);
  });

  it("a stream that is not an event stream is TOOL_RESPONSE_INVALID", async () => {
    const stub = await sse({ contentType: "text/html" });
    const { url } = await bound(stub);
    const res = await post(url, rpc("tools/call", 1, { name: "lookup_record", arguments: {} }));
    expect((res.json?.result as { content: { text: string }[] }).content[0].text).toBe(INVALID);
  });

  it("an unreachable server is TOOL_UNAVAILABLE", async () => {
    const stub = await sse();
    const { url } = await bound(stub, { url: "http://127.0.0.1:1/sse" });
    const res = await post(url, rpc("tools/call", 1, { name: "lookup_record", arguments: {} }));
    expect((res.json?.result as { content: { text: string }[] }).content[0].text).toBe(UNAVAILABLE);
    void stub;
  });

  it("a stream with no endpoint event within the idle timeout is TOOL_TIMEOUT", async () => {
    const hang = http.createServer((req, res) => {
      req.resume();
      res.writeHead(200, { "Content-Type": "text/event-stream" });
      res.write(": nothing to say\n\n");
    });
    await new Promise<void>((resolve) => hang.listen(0, "127.0.0.1", () => resolve()));
    cleanups.push(async () => {
      hang.closeAllConnections();
      await new Promise<void>((resolve) => hang.close(() => resolve()));
    });
    const r = await relay({ idleTimeoutMs: 300 });
    const { url } = r.register({ grant: ALLOW_ALL, serverName: "feed", url: `http://127.0.0.1:${(hang.address() as AddressInfo).port}/sse`, headers: {}, kind: "sse" });
    const started = Date.now();
    const res = await post(url, rpc("initialize", 1));
    expect(Date.now() - started).toBeGreaterThanOrEqual(250);
    expect((res.json?.error as { message: string }).message).toContain('TOOL_TIMEOUT: "feed" did not answer within 1 seconds.');
  });

  it("an accepted request that is never answered ends at the overall deadline with TOOL_TIMEOUT", async () => {
    const stub = await sse({ mode: "hang-on-call" });
    const { url } = await bound(stub, {}, { toolTimeoutMs: 400 });
    await post(url, rpc("initialize", 1));
    const started = Date.now();
    const res = await post(url, rpc("tools/call", 2, { name: "lookup_record", arguments: {} }));
    expect(Date.now() - started).toBeGreaterThanOrEqual(350);
    expect(Date.now() - started).toBeLessThan(3000);
    expect((res.json?.result as { content: { text: string }[] }).content[0].text).toContain('TOOL_TIMEOUT: "feed" did not answer within 1 seconds.');
  });
});

describe("the SSE bridge: faults the gateway survives", () => {
  it("a stream reset while a call waits is TOOL_UNAVAILABLE; the next request opens a new stream and works", async () => {
    const stub = await sse({ mode: "reset-on-call" });
    const { url } = await bound(stub);
    await post(url, rpc("initialize", 1));
    const failed = await post(url, rpc("tools/call", 2, { name: "lookup_record", arguments: {} }));
    expect((failed.json?.result as { content: { text: string }[] }).content[0].text).toBe(UNAVAILABLE);
    const after = await post(url, rpc("tools/list", 3));
    expect((after.json?.result as { tools: unknown[] }).tools).toHaveLength(1);
    expect(stub.streamsOpened()).toBe(2);
  });

  it("a stream that ends cleanly while a call waits is TOOL_UNAVAILABLE", async () => {
    const stub = await sse({ mode: "end-on-call" });
    const { url } = await bound(stub);
    await post(url, rpc("initialize", 1));
    const failed = await post(url, rpc("tools/call", 2, { name: "lookup_record", arguments: {} }));
    expect((failed.json?.result as { content: { text: string }[] }).content[0].text).toBe(UNAVAILABLE);
  });

  it("an event that never ends is cut at the buffer cap: TOOL_RESPONSE_INVALID, the stream is dropped, the relay keeps serving", async () => {
    const stub = await sse({ mode: "endless-event" });
    const r = await relay({ maxResponseBytes: 256 * 1024 });
    const { url } = r.register({ grant: ALLOW_ALL, serverName: "feed", url: stub.url, headers: {}, kind: "sse" });
    await post(url, rpc("initialize", 1));
    const started = Date.now();
    const failed = await post(url, rpc("tools/call", 2, { name: "lookup_record", arguments: {} }));
    expect((failed.json?.result as { content: { text: string }[] }).content[0].text).toBe(INVALID);
    expect(Date.now() - started).toBeLessThan(5000);
    expect(logs.join("\n")).toContain("mcp.bridge.refused serverName=feed reason=event_too_large");
    // The relay is alive: another binding on it still answers.
    const other = await sse();
    const second = r.register({ grant: ALLOW_ALL, serverName: "feed", url: other.url, headers: {}, kind: "sse" });
    expect((await post(second.url, rpc("ping", 1))).json).toEqual({ jsonrpc: "2.0", id: 1, result: {} });
  });

  it("a run's other binding is untouched by a failing one", async () => {
    const bad = await sse({ mode: "reset-on-call" });
    const good = await sse();
    const r = await relay();
    const a = r.register({ grant: ALLOW_ALL, serverName: "feed", url: bad.url, headers: {}, kind: "sse" });
    const b = r.register({ grant: ALLOW_ALL, serverName: "feed", url: good.url, headers: {}, kind: "sse" });
    await post(a.url, rpc("initialize", 1));
    await post(a.url, rpc("tools/call", 2, { name: "lookup_record", arguments: {} }));
    const ok = await post(b.url, rpc("tools/call", 1, { name: "lookup_record", arguments: {} }));
    expect((ok.json?.result as { content: { text: string }[] }).content[0].text).toBe("SSE-RESULT-7679 lookup_record");
  });
});

describe("the SSE bridge: revocation", () => {
  it("revoking the token closes the stream and fails a waiting call; later requests with the token get a local 404 and reach nothing", async () => {
    const stub = await sse({ mode: "hang-on-call" });
    const { r, url, token } = await bound(stub, {}, { toolTimeoutMs: 20_000 });
    await post(url, rpc("initialize", 1));
    const waiting = post(url, rpc("tools/call", 2, { name: "lookup_record", arguments: {} })).then(
      (res) => `status ${res.status}`,
      () => "destroyed",
    );
    while (stub.toolCalls.length === 0) await new Promise((resolve) => setTimeout(resolve, 10));
    r.revoke(token);
    expect(["destroyed", "status 200", "status 404"]).toContain(await waiting);
    const before = stub.requests.length;
    const later = await post(url, rpc("tools/list", 3));
    expect(later.status).toBe(404);
    await new Promise((resolve) => setTimeout(resolve, 100));
    expect(stub.requests.length).toBe(before);
  });
});

describe("the SSE bridge: request ids", () => {
  it("a request id that is still waiting is refused with TOOL_DENIED; the first request is still answered", async () => {
    const stub = await sse({ mode: "hang-on-call" });
    const { url } = await bound(stub, {}, { toolTimeoutMs: 1500 });
    await post(url, rpc("initialize", 1));
    const first = post(url, rpc("tools/call", 7, { name: "lookup_record", arguments: {} }));
    while (stub.toolCalls.length === 0) await new Promise((resolve) => setTimeout(resolve, 10));
    const duplicate = await post(url, rpc("tools/call", 7, { name: "lookup_record", arguments: {} }));
    expect(JSON.stringify(duplicate.json)).toContain("TOOL_DENIED");
    // The first one is not disturbed by the duplicate: it ends at its own deadline.
    expect(JSON.stringify((await first).json)).toContain("TOOL_TIMEOUT");
    expect(stub.toolCalls).toEqual(["lookup_record"]);
  });
});
