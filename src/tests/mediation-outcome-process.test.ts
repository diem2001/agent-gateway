/**
 * Outcome Probe for the Story "mediate authorized tool calls without exposing credentials to agents" (MVP-7679,
 * Gate E): the observer's view of the whole boundary, end to end, with the compiled gateway (`dist/server.js`), the
 * production Claude Agent SDK (0.1.77), its bundled runtime (2.0.77), real `bwrap` and a scripted model.
 *
 * Scenario: a gateway with synthetic markers in `API_KEYS`, the provider key, a registry http header (replaced by a
 * per-user override), a registry SSE header, a registry stdio env value and args marker, a request-body server header
 * and env, a webhook bearer (the caller's own gateway key), a repository token URL and an ssh key. Recording doubles
 * stand for the http MCP server, the SSE MCP server, the stdio MCP servers (running in their own tool sandboxes), the
 * request-body servers, the webhook and the git remote. A scripted model drives an ordinary chat that is granted Bash
 * and every mediated tool: it calls each tool once, then Bash scans every process command line and environment and
 * the home and `/tmp` for every marker, sends the run's relay URL an ungranted tool name, an unparsable body, a batch,
 * a method-less message, `resources/read` and a changed Authorization header, sends the relay token and the model
 * proxy token as `Bearer` to the gateway's administrative and query routes, and finally a later run retries the saved
 * relay URL.
 *
 * Assertions: each authorized call returns its fixture within the deadline; each double received exactly the
 * credential bound to its operation and nothing else; every marker has 0 matches on the five agent and model surfaces
 * (tool outputs, model-bound requests, stream events, gateway log, session transcript and home); every refused attempt
 * yields its fixed text or 401 and no double's request count changes; a deliberately planted marker (negative
 * control) is found by the same detector.
 *
 * Needs `npm run build`, `bwrap` and user namespaces. Linux only. Every secret is synthetic.
 */
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createBareRepo, startDumbHttpGitRemote, type DumbHttpGitRemote } from "./helpers/dumb-http-git-remote.js";
import { startFakeAnthropicApi, type ExactToolScript, type FakeAnthropicApi } from "./helpers/fake-anthropic-api.js";
import { GATEWAY_API_KEY, gatewayRequest, spawnGateway, type Cleanup, type SpawnedGateway } from "./helpers/git-process-gateway.js";
import { startOAuthMcpStub, type OAuthMcpStub } from "./helpers/oauth-mcp-stub.js";
import { startSseMcpStub, type SseMcpStub } from "./helpers/sse-mcp-stub.js";

vi.setConfig({ testTimeout: 300_000 });

const cleanups: Cleanup[] = [];
afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()!();
});

/* ------------------------------------------------------------------ */
/*  Markers                                                             */
/* ------------------------------------------------------------------ */

const PROVIDER_KEY = "SYNTH-PROVIDER-KEY-7679-outcome";
const JIRA_REGISTRY = "Basic SYNTH-REG-HTTP-HEADER-7679";
const JIRA_USER = "Bearer SYNTH-USER-OVERRIDE-HEADER-7679";
const FEED_KEY = "SYNTH-REG-SSE-HEADER-7679";
const STDIO_ENV = "SYNTH-REG-STDIO-ENV-7679";
const STDIO_ARGS = "SYNTH-REG-STDIO-ARGS-7679";
const REQ_HTTP = "Bearer SYNTH-REQUEST-HTTP-HEADER-7679";
const REQ_ENV = "SYNTH-REQUEST-STDIO-ENV-7679";
const SSH_LINE = "SYNTH-SSH-KEY-LINE-7679-abcdefghijklmnop";
const SSH_KEY = `-----BEGIN RSA PRIVATE KEY-----\n${SSH_LINE}\n${SSH_LINE}2\n-----END RSA PRIVATE KEY-----`;

/** The 5-surface detector's needles: each marker once. The gateway key is the webhook bearer. */
const MARKERS: Record<string, string> = {
  gatewayKey: GATEWAY_API_KEY,
  providerKey: PROVIDER_KEY,
  registryHttpHeader: "SYNTH-REG-HTTP-HEADER-7679",
  userOverrideHeader: "SYNTH-USER-OVERRIDE-HEADER-7679",
  registrySseHeader: FEED_KEY,
  registryStdioEnv: STDIO_ENV,
  registryStdioArgs: STDIO_ARGS,
  requestHttpHeader: "SYNTH-REQUEST-HTTP-HEADER-7679",
  requestStdioEnv: REQ_ENV,
  sshKeyLine: SSH_LINE,
};

const DENIED = "TOOL_DENIED: This tool is not allowed for this request. Do not retry; continue without it or tell the user.";

/** An MCP server over stdio whose `echo` tool reports the env value it was given. */
const STDIO_SOURCE = String.raw`// OUTCOME-STDIO-SERVER
const rl = require('node:readline').createInterface({ input: process.stdin });
const send = (m) => process.stdout.write(JSON.stringify(m) + '\n');
rl.on('line', (line) => {
  let m; try { m = JSON.parse(line); } catch { return; }
  if (m.id === undefined) return;
  if (m.method === 'initialize') send({ jsonrpc: '2.0', id: m.id, result: { protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'outcome-stdio', version: '1' } } });
  else if (m.method === 'tools/list') send({ jsonrpc: '2.0', id: m.id, result: { tools: [{ name: 'echo', description: 'echo', inputSchema: { type: 'object', properties: {} } }] } });
  else if (m.method === 'tools/call') send({ jsonrpc: '2.0', id: m.id, result: { content: [{ type: 'text', text: 'STDIO-RESULT:' + (process.env.SERVER_TOKEN || '').length }] } });
  else send({ jsonrpc: '2.0', id: m.id, error: { code: -32601, message: 'Method not found' } });
});
`;

/* ------------------------------------------------------------------ */
/*  The agent-side scripts (they run inside the sandbox)                */
/* ------------------------------------------------------------------ */

/** A Python scanner; needles are split so the script's own text never contains one whole. */
function scanScript(needles: Record<string, string>): string {
  const split = Object.fromEntries(Object.entries(needles).map(([name, value]) => [name, [value.slice(0, Math.ceil(value.length / 2)), value.slice(Math.ceil(value.length / 2))]]));
  return String.raw`python3 - <<'PY'
import json, os
needles = {k: a + b for k, (a, b) in json.loads(${JSON.stringify(JSON.stringify(split))}).items()}
hits = {k: [] for k in needles}
me = str(os.getpid())
for pid in os.listdir('/proc'):
    if not pid.isdigit() or pid == me:
        continue
    for name in ('cmdline', 'environ'):
        try:
            data = open('/proc/%s/%s' % (pid, name), 'rb').read().replace(b'\0', b' ').decode('utf8', 'replace')
        except Exception:
            continue
        for k, v in needles.items():
            if v in data:
                hits[k].append('/proc/%s/%s' % (pid, name))
for root in ('/home/node', '/tmp'):
    for base, dirs, names in os.walk(root):
        for n in names:
            p = os.path.join(base, n)
            try:
                if os.path.getsize(p) > 5000000:
                    continue
                data = open(p, 'rb').read().decode('utf8', 'replace')
            except Exception:
                continue
            for k, v in needles.items():
                if v in data:
                    hits[k].append(p)
print(json.dumps({'scan': hits}))
PY`;
}

/** Plants a marker where the scanner looks, for the negative control. */
const plantScript = (marker: string): string => `printf '%s' '${marker}' > /tmp/negative-control-7679.txt; echo planted`;

/**
 * Finds the relay URL where an agent process can read it, sends it hostile messages, then sends the relay token and
 * the model proxy token as Bearer to the gateway's routes. One JSON line per case.
 */
const attackScript = (gatewayPort: () => number): string =>
  String.raw`python3 - <<'PY'
import json, os, re, sys, urllib.request, urllib.error
GATEWAY = 'http://127.0.0.1:${gatewayPort()}'
pattern = re.compile(rb'http://127\.0\.0\.1:\d+/mcp/[A-Za-z0-9_-]+')
def find_urls():
    found = []
    def add(data):
        for m in pattern.finditer(data):
            u = m.group(0).decode()
            if u not in found:
                found.append(u)
    for pid in os.listdir('/proc'):
        if not pid.isdigit():
            continue
        for name in ('cmdline', 'environ'):
            try:
                add(open('/proc/%s/%s' % (pid, name), 'rb').read())
            except Exception:
                continue
    for root in ('/tmp', '/home/node'):
        for base, dirs, files in os.walk(root):
            for f in files:
                try:
                    p = os.path.join(base, f)
                    if os.path.getsize(p) > 5000000:
                        continue
                    add(open(p, 'rb').read())
                except Exception:
                    continue
    return found
def proxy_token():
    for pid in os.listdir('/proc'):
        if not pid.isdigit():
            continue
        try:
            data = open('/proc/%s/environ' % pid, 'rb').read().split(b'\0')
        except Exception:
            continue
        for item in data:
            if item.startswith(b'ANTHROPIC_API_KEY='):
                return item.split(b'=', 1)[1].decode()
    return None
def post(url, raw, headers=None):
    h = {'Content-Type': 'application/json'}
    h.update(headers or {})
    req = urllib.request.Request(url, data=raw, headers=h, method='POST')
    try:
        r = urllib.request.urlopen(req, timeout=20)
        return r.status, r.read().decode('utf8', 'replace')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf8', 'replace')
    except Exception as e:
        return 0, str(e)
def get(url, headers):
    req = urllib.request.Request(url, headers=headers, method='GET')
    try:
        r = urllib.request.urlopen(req, timeout=20)
        return r.status, r.read().decode('utf8', 'replace')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf8', 'replace')
    except Exception as e:
        return 0, str(e)
def out(label, status, body):
    print(json.dumps({'case': label, 'status': status, 'body': body}))
def rpc(method, id=1, params=None):
    return json.dumps({'jsonrpc': '2.0', 'id': id, 'method': method, 'params': params or {}}).encode()
# The server whose grant names one tool only: the one that lists lookup_record (the others are granted whole).
url = None
for candidate in find_urls():
    s, b = post(candidate, rpc('tools/list', 99))
    if 'lookup_record' in b:
        url = candidate
        break
if url is None:
    out('no-url', 0, '')
    sys.exit(0)
open('/home/node/relay-url', 'w').write(url)
token = url.rsplit('/', 1)[1]
for label, raw, hdr in [
    ('ungranted', rpc('tools/call', 11, {'name': 'delete_record', 'arguments': {}}), None),
    ('unparsable', b'{nope', None),
    ('batch', json.dumps([{'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'}]).encode(), None),
    ('methodless', json.dumps({'jsonrpc': '2.0', 'id': 5, 'result': {}}).encode(), None),
    ('resources', rpc('resources/read', 12, {'uri': 'file:///etc/passwd'}), None),
    ('changed-authorization', rpc('tools/call', 14, {'name': 'lookup_record', 'arguments': {'id': 'R-1'}}), {'Authorization': 'Bearer AGENT-CHOSEN-7679', 'X-Api-Key': 'AGENT-CHOSEN-7679'}),
]:
    s, b = post(url, raw, hdr)
    out(label, s, b)
ptoken = proxy_token()
for who, tok in (('relay-token', token), ('proxy-token', ptoken)):
    if tok is None:
        out('admin-%s' % who, 0, 'no token found')
        continue
    h = {'Authorization': 'Bearer ' + tok}
    for route in ('/v1/tools', '/v1/mcp-servers', '/v1/auth/status', '/v1/sessions'):
        s, b = get(GATEWAY + route, h)
        out('%s GET %s' % (who, route), s, b[:200])
    for route in ('/v1/auth/login', '/v1/query'):
        s, b = post(GATEWAY + route, b'{}', h)
        out('%s POST %s' % (who, route), s, b[:200])
PY`;

/* ------------------------------------------------------------------ */
/*  Fixture                                                             */
/* ------------------------------------------------------------------ */

interface Counting {
  base: string;
  hits: { path: string; authorization?: string; context?: string }[];
}

async function webhookDouble(): Promise<Counting> {
  const hits: Counting["hits"] = [];
  const sockets = new Set<import("node:net").Socket>();
  const server = http.createServer((req, res) => {
    hits.push({ path: req.url ?? "", authorization: req.headers.authorization, context: String(req.headers["x-webhook-context"] ?? "") });
    req.resume();
    req.on("end", () => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ output: `WEBHOOK-RESULT ${req.url}` }));
    });
  });
  server.on("connection", (s) => {
    sockets.add(s);
    s.on("close", () => sockets.delete(s));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  cleanups.push(async () => {
    for (const s of sockets) s.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
  return { base: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, hits };
}

interface Fixture {
  api: FakeAnthropicApi;
  gateway: SpawnedGateway;
  jira: OAuthMcpStub;
  feed: SseMcpStub;
  reqHttp: OAuthMcpStub;
  webhook: Counting;
  remote: DumbHttpGitRemote;
  scripts: ExactToolScript[];
  attackInput: { command: string };
}

function realGit(): string {
  return execFileSync("sh", ["-c", "command -v git"], { encoding: "utf8" }).trim();
}

async function fixture(scriptsFor: (f: { attack: () => string; scan: () => string }) => ExactToolScript[]): Promise<Fixture> {
  const jira = await startOAuthMcpStub({ toolNames: ["get_page", "update_page"] });
  cleanups.push(() => jira.close());
  const feed = await startSseMcpStub({ toolNames: ["lookup_record", "delete_record"] });
  cleanups.push(() => feed.close());
  const reqHttp = await startOAuthMcpStub({ toolNames: ["get_page"] });
  cleanups.push(() => reqHttp.close());
  const webhook = await webhookDouble();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "mvp7679-outcome-remote-"));
  cleanups.push(() => fs.rmSync(root, { recursive: true, force: true }));
  const remote = await startDumbHttpGitRemote(root, realGit());
  cleanups.push(() => remote.close());
  void createBareRepo;

  let gatewayPort = 0;
  const scan = scanScript(MARKERS);
  const attackInput = { command: "" };
  const scripts = scriptsFor({ attack: () => attackScript(() => gatewayPort), scan: () => scan });
  const api = await startFakeAnthropicApi({ toolName: "unused-7679", exactTool: scripts });
  cleanups.push(() => api.close());
  const gateway = await spawnGateway(cleanups, {
    rootPrefix: "mvp7679-outcome-",
    env: { ANTHROPIC_BASE_URL: api.baseUrl, ANTHROPIC_API_KEY: PROVIDER_KEY, DISABLE_TELEMETRY: "1", CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1" },
  });
  gatewayPort = gateway.port;
  // The attack script needs the gateway's port, known only now: fill it into every scripted Bash command.
  for (const script of scripts) {
    const steps = [script, ...(script.then ?? [])] as { input: Record<string, unknown> }[];
    for (const step of steps) {
      if (typeof step.input.command === "string" && step.input.command.includes("GATEWAY = 'http://127.0.0.1:0'")) step.input.command = step.input.command.replace("GATEWAY = 'http://127.0.0.1:0'", `GATEWAY = 'http://127.0.0.1:${gateway.port}'`);
    }
  }

  const register = async (name: string, body: Record<string, unknown>): Promise<void> => {
    const put = await gatewayRequest(gateway.port, "PUT", `/v1/mcp-servers/${name}`, body);
    expect(put.status, put.text).toBe(201);
  };
  await register("jira", { type: "http", url: jira.url, headers: { Authorization: JIRA_REGISTRY } });
  await register("feed", { type: "sse", url: feed.url, headers: { "X-Api-Key": FEED_KEY } });
  await register("local", { type: "stdio", command: "node", args: ["-e", STDIO_SOURCE, STDIO_ARGS], env: { SERVER_TOKEN: STDIO_ENV } });
  const tool = await gatewayRequest(gateway.port, "PUT", "/v1/tools/probe_read", { description: "probe", input_schema: { type: "object", properties: {} }, webhook_url: `${webhook.base}/probe_read` });
  expect(tool.status, tool.text).toBeLessThan(300);
  await new Promise((resolve) => setTimeout(resolve, 300));
  return { api, gateway, jira, feed, reqHttp, webhook, remote, scripts, attackInput };
}

interface Ndjson {
  type: string;
  [key: string]: unknown;
}

async function ask(f: Fixture, body: Record<string, unknown>): Promise<Ndjson[]> {
  const res = await gatewayRequest(f.gateway.port, "POST", "/v1/query", { queryId: `q-7679-${Date.now()}-${Math.floor(Math.random() * 1e6)}`, model: "claude-sonnet-4-5", ...body });
  return res.text.split("\n").filter((l) => l.trim().startsWith("{")).map((l) => JSON.parse(l) as Ndjson);
}

function resultsFor(f: Fixture, prompt: string): { isError: boolean; text: string }[] {
  return f.api.requests.filter((q) => q.userTexts.at(-1)?.includes(prompt) && !q.warmup).at(-1)?.toolResults ?? [];
}

/** Every regular file below `dir` (below 5 MB) whose text holds `needle`. */
function filesHolding(dir: string, needle: string): string[] {
  const found: string[] = [];
  const walk = (current: string): void => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile()) {
        try {
          if (fs.statSync(full).size < 5_000_000 && fs.readFileSync(full, "utf8").includes(needle)) found.push(full);
        } catch {
          // Unreadable: skipped.
        }
      }
    }
  };
  walk(dir);
  return found;
}

/* ------------------------------------------------------------------ */
/*  The probe                                                           */
/* ------------------------------------------------------------------ */

const PROMPT = "OUTCOME-PROBE-RUN";

describe("Outcome Probe: authorized integrations work behind the boundary and nothing reusable is readable", () => {
  it("every mediated tool answers, every double got only its own credential, no marker is on any agent or model surface, every hostile attempt is refused", async () => {
    const f = await fixture(({ scan, attack }) => [
      {
        name: "mcp__jira__get_page",
        prompt: PROMPT,
        input: { id: "P-1" },
        then: [
          { name: "mcp__feed__lookup_record", input: { id: "R-1" } },
          { name: "mcp__local__echo", input: {} },
          { name: "mcp__agent-gateway-tools__probe_read", input: {} },
          { name: "mcp__reqhttp__get_page", input: { id: "P-2" } },
          { name: "mcp__reqlocal__echo", input: {} },
          { name: "Bash", input: { command: scan(), description: "scan" } },
          { name: "Bash", input: { command: attack(), description: "attack" } },
        ],
      },
    ]);

    // The repository operations: a token-URL clone before the run (so its checkout exists in the sandbox mount plan)
    // and an ssh-key clone while the run is active.
    const cloneBefore = await gatewayRequest(f.gateway.port, "POST", "/v1/workspace/git/clone", { url: f.remote.authUrl, path: "outcome-repo" });
    expect(cloneBefore.status, cloneBefore.text).toBe(200);

    const started = Date.now();
    const [events, cloneDuring] = await Promise.all([
      ask(f, {
        prompt: PROMPT,
        sessionId: "outcome",
        useSession: true,
        user_id: "user-1",
        allowedTools: ["Bash", "mcp__jira__*", "mcp__feed__lookup_record", "mcp__local__*", "mcp__agent-gateway-tools__probe_read", "mcp__reqhttp__*", "mcp__reqlocal__*"],
        mcpCredentialOverrides: { jira: { headers: { authorization: JIRA_USER } } },
        mcpServers: {
          reqhttp: { type: "http", url: f.reqHttp.url, headers: { Authorization: REQ_HTTP } },
          reqlocal: { command: "node", args: ["-e", STDIO_SOURCE], env: { SERVER_TOKEN: REQ_ENV } },
        },
      }),
      gatewayRequest(f.gateway.port, "POST", "/v1/workspace/git/clone", { url: f.remote.authUrl, path: "outcome-repo-ssh", sshKey: SSH_KEY }),
    ]);
    const elapsed = Date.now() - started;
    expect(cloneDuring.status, cloneDuring.text).toBe(200);
    expect(events.at(-1)?.type, JSON.stringify(events.at(-1))).toBe("done");
    expect(elapsed).toBeLessThan(120_000);

    // 1. Each authorized call returned its fixture result.
    const results = resultsFor(f, PROMPT);
    expect(results).toHaveLength(8);
    expect(results.slice(0, 7).map((r) => r.isError)).toEqual([false, false, false, false, false, false, false]);
    expect(results[0].text).toContain("RECORD-7667-OK");
    expect(results[1].text).toBe("SSE-RESULT-7679 lookup_record");
    expect(results[2].text).toBe(`STDIO-RESULT:${STDIO_ENV.length}`);
    expect(results[3].text).toBe("WEBHOOK-RESULT /probe_read");
    expect(results[4].text).toContain("RECORD-7667-OK");
    expect(results[5].text).toBe(`STDIO-RESULT:${REQ_ENV.length}`);

    // 2. Each double received exactly the credential bound to its operation, nothing else.
    expect(f.jira.authorizations().length).toBeGreaterThan(0);
    expect(f.jira.authorizations().every((a) => a === JIRA_USER)).toBe(true);
    expect(f.feed.requests.length).toBeGreaterThan(0);
    expect(f.feed.requests.every((q) => q.headers["x-api-key"] === FEED_KEY)).toBe(true);
    expect(f.reqHttp.authorizations().every((a) => a === REQ_HTTP)).toBe(true);
    expect(f.webhook.hits.map((h) => `${h.path} ${h.authorization}`)).toEqual([`/probe_read Bearer ${GATEWAY_API_KEY}`]);
    expect(JSON.parse(f.webhook.hits[0].context ?? "{}")).toMatchObject({ api_key_label: "proc", user_id: "user-1" });
    // The git remote saw the token only on its own requests (the clone authenticated against it).
    expect(f.remote.requests.some((r) => r.authorized)).toBe(true);

    // 3. The scan inside the sandbox found no marker on any process, in the home or in /tmp.
    const scan = JSON.parse(results[6].text) as { scan: Record<string, string[]> };
    expect(scan.scan, JSON.stringify(scan)).toEqual(Object.fromEntries(Object.keys(MARKERS).map((k) => [k, []])));

    // 4. Every hostile attempt is refused with its fixed text (or 401 on /v1/*), and no double's count changed.
    const cases = Object.fromEntries(
      results[7].text
        .split("\n")
        .filter((line) => line.startsWith("{"))
        .map((line) => {
          const parsed = JSON.parse(line) as { case: string; status: number; body: string };
          return [parsed.case, parsed];
        }),
    );
    expect(cases["no-url"], "the relay URL was not readable where an agent can look; the attack rows did not run").toBeUndefined();
    const body = (name: string) => JSON.parse(cases[name].body) as { id: unknown; result?: { content?: { text: string }[]; isError?: boolean }; error?: { code: number; message: string } };
    expect(body("ungranted").result).toEqual({ content: [{ type: "text", text: DENIED }], isError: true });
    for (const refused of ["unparsable", "batch"]) expect(body(refused).error).toEqual({ code: -32600, message: DENIED });
    expect(body("methodless").error).toEqual({ code: -32600, message: DENIED });
    expect(body("resources").error).toEqual({ code: -32001, message: DENIED });
    expect(body("changed-authorization").result?.content?.[0].text).toBe("SSE-RESULT-7679 lookup_record");
    // The server received exactly the authorized calls: the model's own call and the one with the agent-chosen headers.
    expect(f.feed.toolCalls).toEqual(["lookup_record", "lookup_record"]);
    expect(f.feed.requests.some((q) => JSON.stringify(q.headers).includes("AGENT-CHOSEN-7679"))).toBe(false);
    for (const [label, entry] of Object.entries(cases)) {
      if (label.startsWith("relay-token ") || label.startsWith("proxy-token ")) expect([label, entry.status], label).toEqual([label, 401]);
    }
    expect(Object.keys(cases).filter((k) => k.startsWith("relay-token ")).length).toBe(6);
    expect(Object.keys(cases).filter((k) => k.startsWith("proxy-token ")).length).toBe(6);

    // 5. After the run: the saved relay URL is dead and nothing reaches any double.
    const retryScript = "python3 - <<'PY'\nimport urllib.request, urllib.error, json\nurl = open('/home/node/relay-url').read()\nreq = urllib.request.Request(url, data=json.dumps({'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'lookup_record','arguments':{}}}).encode(), headers={'Content-Type':'application/json'}, method='POST')\ntry:\n    r = urllib.request.urlopen(req, timeout=20); print(r.status)\nexcept urllib.error.HTTPError as e:\n    print(e.code)\nPY";
    const before = { feed: f.feed.requests.length, jira: f.jira.requests.length };
    f.scripts.push({ name: "Bash", prompt: "OUTCOME-RETRY", input: { command: retryScript, description: "retry" } });
    await ask(f, { prompt: "OUTCOME-RETRY", sessionId: "outcome", useSession: true, user_id: "user-1", allowedTools: ["Bash"] });
    // The resumed conversation repeats the earlier turn's tool results: the retry's own result is the last one.
    expect(resultsFor(f, "OUTCOME-RETRY").at(-1)?.text.trim()).toBe("404");
    expect(f.feed.requests.length).toBe(before.feed);
    expect(f.jira.requests.length).toBe(before.jira);

    // 6. The five agent and model surfaces hold no marker: tool outputs, model-bound requests, stream events, the
    //    gateway log, and the session transcript and home (the whole gateway home, which holds both).
    const outputs = f.api.requests.flatMap((q) => q.toolResults.map((t) => t.text)).join("\n");
    const modelRequests = f.api.requests.map((q) => q.body).join("\n");
    const stream = JSON.stringify(events);
    const log = f.gateway.output();
    for (const [name, marker] of Object.entries(MARKERS)) {
      expect(outputs.includes(marker), `tool outputs: ${name}`).toBe(false);
      expect(modelRequests.includes(marker), `model-bound requests: ${name}`).toBe(false);
      expect(stream.includes(marker), `stream events: ${name}`).toBe(false);
      expect(log.includes(marker), `gateway log: ${name}`).toBe(false);
      expect(filesHolding(f.gateway.dirs.home, marker), `session transcript and home: ${name}`).toEqual([]);
    }
    const gitToken = f.remote.token;
    for (const [surface, text] of Object.entries({ outputs, modelRequests, stream, log })) expect(text.includes(gitToken), `${surface}: git token`).toBe(false);
    expect(filesHolding(f.gateway.dirs.home, gitToken).filter((file) => !file.includes("/.git/"))).toEqual([]);
    expect(f.gateway.child.exitCode).toBeNull();
  });

  it("negative control: a marker planted where the agent can read it is found by the same detector", async () => {
    const planted = "SYNTH-NEGATIVE-CONTROL-MARKER-7679";
    const f = await fixture(() => [
      { name: "Bash", prompt: "CONTROL-RUN", input: { command: plantScript(planted), description: "plant" }, then: [{ name: "Bash", input: { command: scanScript({ planted }), description: "scan" } }] },
    ]);
    await ask(f, { prompt: "CONTROL-RUN", sessionId: "control", useSession: true, allowedTools: ["Bash"] });
    const results = resultsFor(f, "CONTROL-RUN");
    const scan = JSON.parse(results[1].text) as { scan: Record<string, string[]> };
    expect(scan.scan.planted).toContain("/tmp/negative-control-7679.txt");
    // The host-side file detector finds the same planted marker in the session's own home or the run's temp files too.
    expect(f.api.requests.map((q) => q.body).join("\n").includes(planted)).toBe(true);
  });
});
