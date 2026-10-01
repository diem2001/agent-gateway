/**
 * Trusted MCP mediation against the real runtime (MVP-7679, Gate C): the compiled gateway (`dist/server.js`,
 * built by `npm run build`) with the production Claude Agent SDK (0.1.77), its bundled runtime (2.0.77), real
 * `bwrap`, a scripted stand-in for the Anthropic Messages API and loopback MCP servers that record every request
 * with its headers. The "model" calls exactly the tool a row scripts.
 *
 * Rows: a registered SSE server and an http server reached through relay URLs (tool names unchanged, the credential
 * only at the upstream, none in the runtime's command line, environment, home or logs); a process in the agent's
 * sandbox that finds the relay URL in the runtime's command line and sends it an ungranted tool, an unparsable
 * body, a batch, a method-less message, `resources/read` and a changed Authorization header (each refused with its
 * fixed text and no upstream request); the saved relay URL after the run ended; and every failure code reaching
 * the model with `success: false` in the stream.
 *
 * Needs `npm run build`, `bwrap` and user namespaces. Linux only. Every secret is synthetic.
 */
import fs from "node:fs";
import http from "node:http";
import net, { type AddressInfo } from "node:net";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { startFakeAnthropicApi, type ExactToolScript, type FakeAnthropicApi } from "./helpers/fake-anthropic-api.js";
import { gatewayRequest, spawnGateway, type Cleanup, type SpawnedGateway } from "./helpers/git-process-gateway.js";
import { startOAuthMcpStub, type OAuthMcpStub, type OAuthStubOptions } from "./helpers/oauth-mcp-stub.js";
import { startSseMcpStub, type SseMcpStub, type SseMcpStubOptions } from "./helpers/sse-mcp-stub.js";

vi.setConfig({ testTimeout: 180_000 });

const cleanups: Cleanup[] = [];
afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()!();
});

const FEED_KEY = "SYNTH-FEED-KEY-7679";
const JIRA_SHARED = "Basic SYNTH-JIRA-SHARED-7679";
const JIRA_USER = "Bearer SYNTH-JIRA-USER-7679";
const DENIED = "TOOL_DENIED: This tool is not allowed for this request. Do not retry; continue without it or tell the user.";

interface Rig {
  api: FakeAnthropicApi;
  gateway: SpawnedGateway;
  scripts: ExactToolScript[];
}

async function rig(scripts: ExactToolScript[], env: Record<string, string> = {}): Promise<Rig> {
  const api = await startFakeAnthropicApi({ toolName: "unused-7679", exactTool: scripts });
  cleanups.push(() => api.close());
  const gateway = await spawnGateway(cleanups, {
    rootPrefix: "mvp7679-mcp-",
    env: {
      ANTHROPIC_BASE_URL: api.baseUrl,
      ANTHROPIC_API_KEY: "sk-ant-fake-mcp-7679",
      DISABLE_TELEMETRY: "1",
      CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
      ...env,
    },
  });
  return { api, gateway, scripts };
}

async function sse(options: SseMcpStubOptions = {}): Promise<SseMcpStub> {
  const created = await startSseMcpStub(options);
  cleanups.push(() => created.close());
  return created;
}

async function oauthStub(options: OAuthStubOptions = {}): Promise<OAuthMcpStub> {
  const created = await startOAuthMcpStub(options);
  cleanups.push(() => created.close());
  return created;
}

async function registerServer(r: Rig, name: string, body: Record<string, unknown>): Promise<void> {
  const put = await gatewayRequest(r.gateway.port, "PUT", `/v1/mcp-servers/${name}`, body);
  expect(put.status, put.text).toBe(201);
}

interface Ndjson {
  type: string;
  [key: string]: unknown;
}

async function ask(r: Rig, body: Record<string, unknown>): Promise<{ events: Ndjson[] }> {
  const res = await gatewayRequest(r.gateway.port, "POST", "/v1/query", { queryId: `q-7679-${Date.now()}-${Math.floor(Math.random() * 1e6)}`, model: "claude-sonnet-4-5", ...body });
  return { events: res.text.split("\n").filter((l) => l.trim().startsWith("{")).map((l) => JSON.parse(l) as Ndjson) };
}

function resultFor(r: Rig, prompt: string): { isError: boolean; text: string } | undefined {
  return r.api.requests.filter((q) => q.userTexts.at(-1)?.includes(prompt) && !q.warmup).at(-1)?.toolResults.at(-1);
}

function offeredFor(r: Rig, prompt: string): string[] {
  return r.api.requests.find((q) => q.userTexts.at(-1)?.includes(prompt) && !q.warmup)?.tools ?? [];
}

function sessionHome(r: Rig, clientId: string): string {
  const saved = JSON.parse(fs.readFileSync(path.join(r.gateway.dirs.persist, "sessions.json"), "utf8")) as { sessionsByLabel: Record<string, Record<string, { sandboxDirId?: string }>> };
  return path.join(r.gateway.dirs.home, ".agent-sandbox", "sessions", saved.sessionsByLabel.proc[clientId].sandboxDirId!, "home");
}

const call = (prompt: string, tool: string, input: Record<string, unknown> = { id: "R-1" }): ExactToolScript => ({ name: tool, prompt, input });

/* ------------------------------------------------------------------ */
/*  Registered servers through relay URLs                               */
/* ------------------------------------------------------------------ */

describe("registered http and SSE servers through relay URLs (real runtime)", () => {
  it("a tool of each is called with unchanged names; the credential reaches only the upstream; the runtime's own surfaces hold none", async () => {
    const feed = await sse();
    const jira = await oauthStub({ toolNames: ["get_page", "update_page"] });
    const r = await rig([call("M1-FEED", "mcp__feed__lookup_record"), call("M1-JIRA", "mcp__jira__get_page")]);
    await registerServer(r, "feed", { type: "sse", url: feed.url, headers: { "X-Api-Key": FEED_KEY } });
    await registerServer(r, "jira", { type: "http", url: jira.url, headers: { Authorization: JIRA_SHARED } });

    const feedRun = await ask(r, { prompt: "M1-FEED", sessionId: "m1", useSession: true });
    const jiraRun = await ask(r, { prompt: "M1-JIRA", useSession: false, mcpCredentialOverrides: { jira: { headers: { authorization: JIRA_USER } } } });

    expect(offeredFor(r, "M1-FEED")).toEqual(expect.arrayContaining(["mcp__feed__lookup_record", "mcp__jira__get_page", "mcp__jira__update_page"]));
    expect(resultFor(r, "M1-FEED")).toEqual(expect.objectContaining({ isError: false, text: "SSE-RESULT-7679 lookup_record" }));
    expect(resultFor(r, "M1-JIRA")).toMatchObject({ isError: false, text: expect.stringContaining("RECORD-7667-OK") });
    expect(feedRun.events.at(-1)?.type).toBe("done");
    expect(jiraRun.events.at(-1)?.type).toBe("done");
    // The upstreams received exactly the bound credential: the SSE key on the stream and every POST, the user's
    // override (not the shared value, whatever its casing) at the http server.
    expect(feed.requests.length).toBeGreaterThanOrEqual(4);
    expect(feed.requests.every((q) => q.headers["x-api-key"] === FEED_KEY)).toBe(true);
    expect(jira.authorizations().every((a) => a === JIRA_USER)).toBe(true);
    expect(jira.authorizations().length).toBeGreaterThan(0);
    // No credential anywhere the model or the agent can read, and none in the gateway log.
    const surfaces = [JSON.stringify(r.api.requests.map((q) => q.body)), JSON.stringify(feedRun.events), JSON.stringify(jiraRun.events), r.gateway.output()];
    for (const secret of [FEED_KEY, "SYNTH-JIRA-SHARED-7679", "SYNTH-JIRA-USER-7679"]) {
      for (const surface of surfaces) expect(surface).not.toContain(secret);
    }
    const home = sessionHome(r, "m1");
    const found: string[] = [];
    const walk = (dir: string): void => {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) walk(full);
        else if (entry.isFile() && fs.statSync(full).size < 5_000_000 && fs.readFileSync(full, "utf8").includes(FEED_KEY)) found.push(full);
      }
    };
    walk(home);
    expect(found).toEqual([]);
  });

  it("a refused SSE credential reaches the model as TOOL_AUTH_UNAVAILABLE with success:false and starts no login", async () => {
    const feed = await sse({ getStatus: 401 });
    const r = await rig([call("M2-401", "mcp__feed__lookup_record")]);
    await registerServer(r, "feed", { type: "sse", url: feed.url, headers: { "X-Api-Key": FEED_KEY } });
    const { events } = await ask(r, { prompt: "M2-401", useSession: false });
    const text = `TOOL_AUTH_UNAVAILABLE: "feed" did not accept the gateway's credential. Ask your gateway administrator to check this tool's credential; retrying will not help.`;
    expect(resultFor(r, "M2-401")).toEqual(expect.objectContaining({ isError: true, text }));
    expect(events.find((e) => e.type === "tool_result")).toMatchObject({ output: text, success: false });
    expect(events.at(-1)?.type).toBe("done");
  });

  it.each([
    ["an http upstream that answers 500", { type: "http" }, { status: 500 }, 'TOOL_UNAVAILABLE: "svc" could not be reached or failed. Try again later; if it keeps happening, tell your gateway administrator.'],
    ["an http upstream that answers 401", { type: "http" }, { status: 401 }, `TOOL_AUTH_UNAVAILABLE: "svc" did not accept the gateway's credential. Ask your gateway administrator to check this tool's credential; retrying will not help.`],
    ["an http upstream that redirects", { type: "http" }, { status: 302 }, 'TOOL_UNAVAILABLE: "svc" tried to send the request to another address, which the gateway does not allow. Tell your gateway administrator; retrying will not help.'],
    ["an http upstream whose answer is not JSON-RPC", { type: "http" }, { status: 200, body: "<html>nope</html>" }, 'TOOL_RESPONSE_INVALID: "svc" sent an answer the gateway could not read. If it keeps happening, tell your gateway administrator.'],
  ])("%s: the model gets the fixed text, the stream says success:false", async (_label, server, upstreamAnswer, text) => {
    // A scripted http upstream: a valid handshake, then the scripted answer to tools/call.
    const hits: string[] = [];
    const upstream = http.createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (chunk: Buffer) => chunks.push(chunk));
      req.on("end", () => {
        const message = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}") as { id?: number; method?: string };
        hits.push(String(message.method));
        if (message.method === "tools/call") {
          res.writeHead(upstreamAnswer.status, upstreamAnswer.status === 302 ? { Location: "http://127.0.0.1:9/collect" } : {});
          res.end((upstreamAnswer as { body?: string }).body ?? "");
          return;
        }
        if (message.id === undefined) {
          res.writeHead(202);
          res.end();
          return;
        }
        res.writeHead(200, { "Content-Type": "application/json" });
        const result = message.method === "tools/list" ? { tools: [{ name: "act", description: "act", inputSchema: { type: "object", properties: {} } }] } : { protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "x", version: "1" } };
        res.end(JSON.stringify({ jsonrpc: "2.0", id: message.id, result }));
      });
    });
    await new Promise<void>((resolve) => upstream.listen(0, "127.0.0.1", () => resolve()));
    cleanups.push(async () => {
      upstream.closeAllConnections();
      await new Promise<void>((resolve) => upstream.close(() => resolve()));
    });
    const r = await rig([call("M3-FAIL", "mcp__svc__act", {})]);
    await registerServer(r, "svc", { ...server, url: `http://127.0.0.1:${(upstream.address() as AddressInfo).port}/mcp`, headers: { Authorization: "Basic SYNTH-SVC-7679" } });
    const { events } = await ask(r, { prompt: "M3-FAIL", useSession: false });
    expect(resultFor(r, "M3-FAIL")).toEqual(expect.objectContaining({ isError: true, text }));
    expect(events.find((e) => e.type === "tool_result")).toMatchObject({ output: text, success: false });
    expect(JSON.stringify(events) + r.gateway.output()).not.toContain("nope");
    expect(hits).toContain("tools/call");
  });

  it("an upstream that hangs on tools/call ends at AGENT_MCP_TOOL_TIMEOUT_MS with TOOL_TIMEOUT, the gateway survives", async () => {
    const hang = await sse({ mode: "hang-on-call" });
    const r = await rig([call("M4-HANG", "mcp__feed__lookup_record")], { AGENT_MCP_TOOL_TIMEOUT_MS: "2000" });
    await registerServer(r, "feed", { type: "sse", url: hang.url, headers: { "X-Api-Key": FEED_KEY } });
    const started = Date.now();
    const { events } = await ask(r, { prompt: "M4-HANG", useSession: false });
    expect(Date.now() - started).toBeLessThan(60_000);
    expect(resultFor(r, "M4-HANG")?.text).toBe('TOOL_TIMEOUT: "feed" did not answer within 2 seconds. Try again later or with a smaller request; if it keeps happening, tell your gateway administrator.');
    expect(events.at(-1)?.type).toBe("done");
    expect(r.gateway.child.exitCode).toBeNull();
  });

  it("a model call of a tool outside the caller's grant is TOOL_DENIED at the relay; the upstream sees no tools/call", async () => {
    const feed = await sse({ toolNames: ["lookup_record", "delete_record"] });
    const r = await rig([call("M5-DENIED", "mcp__feed__delete_record")]);
    await registerServer(r, "feed", { type: "sse", url: feed.url, headers: { "X-Api-Key": FEED_KEY } });
    const { events } = await ask(r, { prompt: "M5-DENIED", useSession: false, allowedTools: ["mcp__feed__lookup_record"] });
    expect(resultFor(r, "M5-DENIED")).toEqual(expect.objectContaining({ isError: true, text: DENIED }));
    expect(events.find((e) => e.type === "tool_result")).toMatchObject({ success: false });
    expect(feed.toolCalls).toEqual([]);
  });
});

/* ------------------------------------------------------------------ */
/*  A process in the sandbox attacks the relay URL                      */
/* ------------------------------------------------------------------ */

/**
 * Runs inside the agent's sandbox: reads the relay URL of server `feed` from the runtime's command line (the
 * runtime is process 2 inside the sandbox) and sends it hostile messages, printing one JSON line per case.
 */
const ATTACK = String.raw`python3 - <<'PY'
import json, re, sys, urllib.request, urllib.error
cmd = open('/proc/2/cmdline', 'rb').read().replace(b'\0', b' ').decode()
url = re.search(r'http://127\.0\.0\.1:\d+/mcp/[A-Za-z0-9_-]+', cmd).group(0)
open('/home/node/relay-url', 'w').write(url)
def send(label, raw, headers=None):
    h = {'Content-Type': 'application/json'}
    h.update(headers or {})
    req = urllib.request.Request(url, data=raw, headers=h, method='POST')
    try:
        r = urllib.request.urlopen(req, timeout=20)
        status, body = r.status, r.read().decode('utf8', 'replace')
    except urllib.error.HTTPError as e:
        status, body = e.code, e.read().decode('utf8', 'replace')
    print(json.dumps({'case': label, 'status': status, 'body': body}))
def rpc(method, id=1, params=None):
    return json.dumps({'jsonrpc': '2.0', 'id': id, 'method': method, 'params': params or {}}).encode()
send('ungranted', rpc('tools/call', 11, {'name': 'delete_record', 'arguments': {}}))
send('unparsable', b'{nope')
send('batch', json.dumps([{'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'}]).encode())
send('methodless', json.dumps({'jsonrpc': '2.0', 'id': 5, 'result': {}}).encode())
send('resources', rpc('resources/read', 12, {'uri': 'file:///etc/passwd'}))
send('bom', b'\xef\xbb\xbf' + rpc('tools/list', 13))
send('granted-with-agent-authorization', rpc('tools/call', 14, {'name': 'lookup_record', 'arguments': {'id': 'R-1'}}), {'Authorization': 'Bearer AGENT-CHOSEN', 'X-Api-Key': 'AGENT-CHOSEN'})
PY`;

describe("a process in the sandbox that finds the relay URL (real runtime)", () => {
  it("cannot reach an ungranted tool, send raw or batch bodies, use other methods or replace the credential; the saved URL is dead once the run ended", async () => {
    const feed = await sse({ toolNames: ["lookup_record", "delete_record"] });
    const r = await rig([
      { name: "Bash", prompt: "A1-ATTACK", input: { command: ATTACK, description: "probe" } },
      { name: "Bash", prompt: "A2-RETRY", input: { command: "python3 - <<'PY'\nimport urllib.request, urllib.error, json\nurl = open('/home/node/relay-url').read()\nreq = urllib.request.Request(url, data=json.dumps({'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'lookup_record','arguments':{}}}).encode(), headers={'Content-Type':'application/json'}, method='POST')\ntry:\n    r = urllib.request.urlopen(req, timeout=20); print(r.status)\nexcept urllib.error.HTTPError as e:\n    print(e.code)\nPY", description: "probe" } },
    ]);
    await registerServer(r, "feed", { type: "sse", url: feed.url, headers: { "X-Api-Key": FEED_KEY } });
    const grantBody = { sessionId: "atk", useSession: true, allowedTools: ["Bash", "mcp__feed__lookup_record"] };

    const first = await ask(r, { prompt: "A1-ATTACK", ...grantBody });
    expect(first.events.at(-1)?.type).toBe("done");
    const out = resultFor(r, "A1-ATTACK");
    expect(out?.isError, out?.text).toBe(false);
    const cases = Object.fromEntries(
      out!.text
        .split("\n")
        .filter((line) => line.startsWith("{"))
        .map((line) => {
          const parsed = JSON.parse(line) as { case: string; status: number; body: string };
          return [parsed.case, parsed];
        }),
    );
    const body = (name: string) => JSON.parse(cases[name].body) as { id: unknown; result?: { isError?: boolean; content?: { text: string }[] }; error?: { code: number; message: string } };

    expect(body("ungranted")).toEqual({ jsonrpc: "2.0", id: 11, result: { content: [{ type: "text", text: DENIED }], isError: true } });
    for (const refused of ["unparsable", "batch", "bom"]) expect(body(refused).error, refused).toEqual({ code: -32600, message: DENIED });
    expect(body("methodless")).toEqual({ jsonrpc: "2.0", id: 5, error: { code: -32600, message: DENIED } });
    expect(body("resources")).toEqual({ jsonrpc: "2.0", id: 12, error: { code: -32001, message: DENIED } });
    // The granted call works, and the agent's own credential headers were not used.
    expect(body("granted-with-agent-authorization").result?.content?.[0].text).toBe("SSE-RESULT-7679 lookup_record");
    expect(feed.toolCalls).toEqual(["lookup_record"]);
    expect(feed.requests.every((q) => q.headers["x-api-key"] === FEED_KEY)).toBe(true);
    expect(feed.requests.some((q) => JSON.stringify(q.headers).includes("AGENT-CHOSEN"))).toBe(false);
    // Nothing the agent sent was forwarded raw: only well-formed single messages reached the server.
    for (const q of feed.requests.filter((x) => x.method === "POST")) expect(() => JSON.parse(q.body)).not.toThrow();

    // A later run (a new sandbox, a new relay token): the URL saved by the earlier run no longer works.
    const requestsBefore = feed.requests.length;
    await ask(r, { prompt: "A2-RETRY", ...grantBody });
    expect(resultFor(r, "A2-RETRY")?.text.trim()).toBe("404");
    expect(feed.requests.length).toBe(requestsBefore);
    expect(r.gateway.child.exitCode).toBeNull();
  });
});

/* ------------------------------------------------------------------ */
/*  Faults                                                              */
/* ------------------------------------------------------------------ */

describe("faults at the upstream do not end the gateway (real runtime)", () => {
  it.each([
    ["a stream reset on tools/call", { mode: "reset-on-call" as const }],
    ["a stream that ends on tools/call", { mode: "end-on-call" as const }],
  ])("%s: TOOL_UNAVAILABLE for the model, the gateway keeps answering", async (_label, options) => {
    const feed = await sse(options);
    const r = await rig([call("F1-FAULT", "mcp__feed__lookup_record")]);
    await registerServer(r, "feed", { type: "sse", url: feed.url, headers: { "X-Api-Key": FEED_KEY } });
    const { events } = await ask(r, { prompt: "F1-FAULT", useSession: false });
    expect(resultFor(r, "F1-FAULT")?.text).toBe('TOOL_UNAVAILABLE: "feed" could not be reached or failed. Try again later; if it keeps happening, tell your gateway administrator.');
    expect(events.at(-1)?.type).toBe("done");
    expect(r.gateway.child.exitCode).toBeNull();
    // Still alive: a second request is answered.
    const health = await new Promise<number>((resolve) => {
      http.get({ host: "127.0.0.1", port: r.gateway.port, path: "/health", agent: false }, (res) => {
        res.resume();
        resolve(res.statusCode ?? 0);
      });
    });
    expect(health).toBe(200);
  });

  it("an upstream port that refuses connections is TOOL_UNAVAILABLE", async () => {
    const closed = net.createServer();
    await new Promise<void>((resolve) => closed.listen(0, "127.0.0.1", () => resolve()));
    const port = (closed.address() as AddressInfo).port;
    await new Promise<void>((resolve) => closed.close(() => resolve()));
    const r = await rig([call("F2-REFUSED", "mcp__feed__lookup_record")]);
    await registerServer(r, "feed", { type: "sse", url: `http://127.0.0.1:${port}/sse`, headers: { "X-Api-Key": FEED_KEY } });
    await ask(r, { prompt: "F2-REFUSED", useSession: false });
    // The server never connected, so the runtime listed no tools of it: the call is refused by the runtime or the relay.
    const result = resultFor(r, "F2-REFUSED");
    expect(result?.isError).toBe(true);
    expect(r.gateway.child.exitCode).toBeNull();
  });
});
