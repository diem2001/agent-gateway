/**
 * Trusted stdio MCP servers in their own sandbox, against the real runtime and real bwrap (MVP-7679, Gate D): the
 * compiled gateway (`dist/server.js`, built by `npm run build`) with the production Claude Agent SDK (0.1.77), its
 * bundled runtime (2.0.77), a scripted stand-in for the Anthropic Messages API and a registered stdio server whose
 * env value, args marker and home file are synthetic.
 *
 * Rows: the tool answers through the relay with its own env value (a per-user override replacing the registry
 * value); from the agent's sandbox neither the server's env, its command line, its files nor its process can be seen
 * (a /proc scan and a file search), the agent's own files are invisible to the server; the runtime's argv holds no
 * registry `args`, `env` or override value; cancel and a gateway SIGKILL leave no tool-sandbox process or run
 * directory behind.
 *
 * Needs `npm run build`, `bwrap` and user namespaces. Linux only. Every secret is synthetic.
 */
import { createHash } from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { startFakeAnthropicApi, type ExactToolScript, type FakeAnthropicApi } from "./helpers/fake-anthropic-api.js";
import { descendants, gatewayRequest, spawnGateway, type Cleanup, type SpawnedGateway } from "./helpers/git-process-gateway.js";

vi.setConfig({ testTimeout: 180_000 });

const cleanups: Cleanup[] = [];
afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()!();
});

const REGISTRY_ENV = "SYNTH-STDIO-REGISTRY-ENV-7679";
const USER_ENV = "SYNTH-STDIO-USER-ENV-7679";
const ARGS_MARKER = "SYNTH-STDIO-ARGS-7679";
const sha = (value: string): string => createHash("sha256").update(value).digest("hex");
/** Assembled at run time so this file's own command line and scans never contain the needle. */
const SERVER_NEEDLE = ["STDIO-SERVER", "7679"].join("-");

/** The server: an MCP server over stdio that answers `echo` with its own view and `hang` never. */
const SERVER_SOURCE = String.raw`// ${SERVER_NEEDLE}
const fs = require('node:fs');
const home = process.env.HOME;
fs.writeFileSync(home + '/server-home-file-7679', 'SYNTH-TOOL-HOME-CONTENT-7679');
const rl = require('node:readline').createInterface({ input: process.stdin });
const send = (m) => process.stdout.write(JSON.stringify(m) + '\n');
rl.on('line', (line) => {
  let m; try { m = JSON.parse(line); } catch { return; }
  if (m.id === undefined) return;
  if (m.method === 'initialize') send({ jsonrpc: '2.0', id: m.id, result: { protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'stdio-real', version: '1' } } });
  else if (m.method === 'tools/list') send({ jsonrpc: '2.0', id: m.id, result: { tools: [
    { name: 'echo', description: 'echo', inputSchema: { type: 'object', properties: {} } },
    { name: 'hang', description: 'hang', inputSchema: { type: 'object', properties: {} } } ] } });
  else if (m.method === 'tools/call' && m.params.name === 'echo') {
    // Values are reported as hashes: the answer travels to the model, and no marker may.
    const sha = (v) => require('node:crypto').createHash('sha256').update(String(v)).digest('hex');
    const view = {
      tokenSha: sha(process.env.SERVER_TOKEN),
      argShas: process.argv.slice(1).map(sha),
      envKeys: Object.keys(process.env).filter((k) => !['PWD', 'SHLVL', '_', 'OLDPWD'].includes(k)).sort(),
      homeEntries: fs.readdirSync(home).sort(),
      tmpEntries: fs.readdirSync('/tmp').sort(),
      sawAgentCanary: fs.existsSync('/home/node/agent-canary-7679') || fs.existsSync('/tmp/agent-tmp-canary-7679'),
      uid: process.getuid(),
    };
    send({ jsonrpc: '2.0', id: m.id, result: { content: [{ type: 'text', text: JSON.stringify(view) }] } });
  } else if (m.method === 'tools/call') { /* hang: never answers */ }
  else send({ jsonrpc: '2.0', id: m.id, error: { code: -32601, message: 'Method not found' } });
});
`;

interface Rig {
  api: FakeAnthropicApi;
  gateway: SpawnedGateway;
}

async function rig(scripts: ExactToolScript[], env: Record<string, string> = {}): Promise<Rig> {
  const api = await startFakeAnthropicApi({ toolName: "unused-7679", exactTool: scripts });
  cleanups.push(() => api.close());
  const gateway = await spawnGateway(cleanups, {
    rootPrefix: "mvp7679-stdio-",
    env: { ANTHROPIC_BASE_URL: api.baseUrl, ANTHROPIC_API_KEY: "sk-ant-fake-stdio-7679", DISABLE_TELEMETRY: "1", CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1", ...env },
  });
  const put = await gatewayRequest(gateway.port, "PUT", "/v1/mcp-servers/local", {
    type: "stdio",
    command: "node",
    args: ["-e", SERVER_SOURCE, ARGS_MARKER],
    env: { SERVER_TOKEN: REGISTRY_ENV },
  });
  expect(put.status, put.text).toBe(201);
  return { api, gateway };
}

function resultFor(r: Rig, prompt: string): { isError: boolean; text: string } | undefined {
  return r.api.requests.filter((q) => q.userTexts.at(-1)?.includes(prompt) && !q.warmup).at(-1)?.toolResults.at(-1);
}

function toolResultsFor(r: Rig, prompt: string): { isError: boolean; text: string }[] {
  return r.api.requests.filter((q) => q.userTexts.at(-1)?.includes(prompt) && !q.warmup).at(-1)?.toolResults ?? [];
}

/** Host processes whose command line holds the server needle (the bwrap launcher carries the command after `--`). */
function hostServerProcesses(): number[] {
  const found: number[] = [];
  for (const entry of fs.readdirSync("/proc")) {
    if (!/^[0-9]+$/.test(entry) || Number(entry) === process.pid) continue;
    try {
      if (fs.readFileSync(`/proc/${entry}/cmdline`, "utf8").includes(SERVER_NEEDLE)) found.push(Number(entry));
    } catch {
      // Gone while reading.
    }
  }
  return found;
}

/** Runs in the agent's sandbox: plants canaries, then (after the tool call) scans every surface it can read. */
const PLANT = `printf 'canary' > /home/node/agent-canary-7679; printf 'canary' > /tmp/agent-tmp-canary-7679; echo planted`;
const SCAN = String.raw`python3 - <<'PY'
import json, os
needles = {
    'env': ['SYNTH-STDIO-REGISTRY-ENV-7' + '679', 'SYNTH-STDIO-USER-ENV-7' + '679'],
    'args': ['SYNTH-STDIO-ARGS-7' + '679'],
    'server': ['STDIO-SERVER-7' + '679'],
}
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
        for kind, values in needles.items():
            for v in values:
                if v in data:
                    hits[kind].append('%s/%s' % (pid, name))
files = []
for root in ('/home/node', '/tmp', '/var', '/etc', '/usr'):
    for base, dirs, names in os.walk(root):
        for n in names:
            if 'server-home-file-7' + '679' in n:
                files.append(os.path.join(base, n))
        if len(files) > 5:
            break
print(json.dumps({'hits': hits, 'serverFiles': files}))
PY`;

describe("a registered stdio server in its own tool sandbox (real runtime, real bwrap)", () => {
  it("its tool answers with its own env value (the user's override replaces the registry value) while the agent sees none of it", async () => {
    const r = await rig([
      {
        name: "Bash",
        prompt: "S1-RUN",
        input: { command: PLANT, description: "probe" },
        then: [
          { name: "mcp__local__echo", input: {} },
          { name: "Bash", input: { command: SCAN, description: "probe" } },
        ],
      },
    ]);
    const res = await gatewayRequest(r.gateway.port, "POST", "/v1/query", {
      queryId: `q-7679-${Date.now()}`,
      model: "claude-sonnet-4-5",
      prompt: "S1-RUN",
      sessionId: "s1",
      useSession: true,
      allowedTools: ["Bash", "mcp__local__echo"],
      mcpCredentialOverrides: { local: { env: { SERVER_TOKEN: USER_ENV } } },
    });
    const events = res.text.split("\n").filter((l) => l.trim().startsWith("{")).map((l) => JSON.parse(l) as { type: string });
    expect(events.at(-1)?.type).toBe("done");
    const results = toolResultsFor(r, "S1-RUN");
    expect(results.map((x) => x.isError)).toEqual([false, false, false]);

    // The server's own view: the user's override replaced the registry value; the base environment plus its env only;
    // a private home and /tmp; it cannot see the agent's canaries; the args it was given are its own.
    const view = JSON.parse(results[1].text) as { tokenSha: string; argShas: string[]; envKeys: string[]; homeEntries: string[]; tmpEntries: string[]; sawAgentCanary: boolean; uid: number };
    expect(view.tokenSha).toBe(sha(USER_ENV));
    expect(view.argShas).toEqual([sha(ARGS_MARKER)]);
    expect(view.envKeys).toEqual(["HOME", "LANG", "PATH", "SERVER_TOKEN", "TERM", "TMPDIR", "USER"]);
    expect(view.homeEntries).toEqual(["server-home-file-7679"]);
    expect(view.tmpEntries).toEqual([]);
    expect(view.sawAgentCanary).toBe(false);

    // The agent's scan of every process and file it can see: none of the server's values, command line or files.
    const scan = JSON.parse(results[2].text) as { hits: Record<string, string[]>; serverFiles: string[] };
    expect(scan.hits).toEqual({ env: [], args: [], server: [] });
    expect(scan.serverFiles).toEqual([]);

    // Nothing of it in what the model, the stream or the logs carry, and the registry value was never sent to the runtime.
    const surfaces = [JSON.stringify(r.api.requests.map((q) => q.body)), r.gateway.output()];
    for (const surface of surfaces) {
      expect(surface).not.toContain(REGISTRY_ENV);
      expect(surface).not.toContain(ARGS_MARKER);
    }
    expect(r.gateway.output()).not.toContain("credential_in_runtime_args");

    // The tool sandbox is gone with the run, and no run directory is left.
    await vi.waitFor(() => expect(hostServerProcesses()).toEqual([]), { timeout: 10_000 });
    const runs = path.join(r.gateway.dirs.home, ".agent-sandbox", "runs");
    await vi.waitFor(() => expect(fs.readdirSync(runs)).toEqual([]), { timeout: 10_000 });
  });

  it("without an override the registry value is the one the server sees, and its tool is offered under the unchanged name", async () => {
    const r = await rig([{ name: "mcp__local__echo", prompt: "S2-RUN", input: {} }]);
    const res = await gatewayRequest(r.gateway.port, "POST", "/v1/query", { queryId: `q-7679-${Date.now()}`, model: "claude-sonnet-4-5", prompt: "S2-RUN", useSession: false });
    expect(res.status).toBe(200);
    const offered = r.api.requests.find((q) => q.userTexts.at(-1)?.includes("S2-RUN") && !q.warmup)?.tools ?? [];
    expect(offered).toEqual(expect.arrayContaining(["mcp__local__echo", "mcp__local__hang"]));
    const view = JSON.parse(resultFor(r, "S2-RUN")!.text) as { tokenSha: string };
    expect(view.tokenSha).toBe(sha(REGISTRY_ENV));
  });

  it("a tool outside the caller's grant is TOOL_DENIED and never reaches the server", async () => {
    const r = await rig([{ name: "mcp__local__hang", prompt: "S3-RUN", input: {} }]);
    await gatewayRequest(r.gateway.port, "POST", "/v1/query", { queryId: `q-7679-${Date.now()}`, model: "claude-sonnet-4-5", prompt: "S3-RUN", useSession: false, allowedTools: ["mcp__local__echo"] });
    expect(resultFor(r, "S3-RUN")).toEqual(expect.objectContaining({ isError: true, text: "TOOL_DENIED: This tool is not allowed for this request. Do not retry; continue without it or tell the user." }));
  });

  it("an unanswered call ends at AGENT_MCP_TOOL_TIMEOUT_MS with TOOL_TIMEOUT, and the tool sandbox is gone afterwards", async () => {
    const r = await rig([{ name: "mcp__local__hang", prompt: "S4-RUN", input: {} }], { AGENT_MCP_TOOL_TIMEOUT_MS: "2000" });
    await gatewayRequest(r.gateway.port, "POST", "/v1/query", { queryId: `q-7679-${Date.now()}`, model: "claude-sonnet-4-5", prompt: "S4-RUN", useSession: false });
    expect(resultFor(r, "S4-RUN")?.text).toBe('TOOL_TIMEOUT: "local" did not answer within 2 seconds. Try again later or with a smaller request; if it keeps happening, tell your gateway administrator.');
    await vi.waitFor(() => expect(hostServerProcesses()).toEqual([]), { timeout: 10_000 });
  });
});

describe("the tool sandbox does not outlive its run (real runtime, real bwrap)", () => {
  /** Starts a query that calls the hanging tool and resolves once the server process exists on the host. */
  async function startHangingCall(r: Rig): Promise<{ abort: () => void; ended: Promise<void> }> {
    const req = http.request(
      {
        host: "127.0.0.1",
        port: r.gateway.port,
        method: "POST",
        path: "/v1/query",
        agent: false,
        headers: { Authorization: "Bearer git-proc-gateway-key-7614", "Content-Type": "application/json" },
      },
      (res) => res.resume(),
    );
    const ended = new Promise<void>((resolve) => {
      req.on("error", () => resolve());
      req.on("close", () => resolve());
    });
    req.end(JSON.stringify({ queryId: `q-7679-${Date.now()}`, model: "claude-sonnet-4-5", prompt: "K-RUN", useSession: false }));
    await vi.waitFor(() => expect(hostServerProcesses().length).toBeGreaterThan(0), { timeout: 30_000 });
    return { abort: () => req.destroy(), ended };
  }

  it("cancel (the client goes away) leaves no tool-sandbox process and no run directory", async () => {
    const r = await rig([{ name: "mcp__local__hang", prompt: "K-RUN", input: {} }], { AGENT_MCP_TOOL_TIMEOUT_MS: "600000" });
    const call = await startHangingCall(r);
    call.abort();
    await call.ended;
    await vi.waitFor(() => expect(hostServerProcesses()).toEqual([]), { timeout: 20_000 });
    const runs = path.join(r.gateway.dirs.home, ".agent-sandbox", "runs");
    await vi.waitFor(() => expect(fs.readdirSync(runs)).toEqual([]), { timeout: 20_000 });
    expect(r.gateway.child.exitCode).toBeNull();
  });

  it("a gateway SIGKILL leaves no tool-sandbox process behind", async () => {
    const r = await rig([{ name: "mcp__local__hang", prompt: "K-RUN", input: {} }], { AGENT_MCP_TOOL_TIMEOUT_MS: "600000" });
    const call = await startHangingCall(r);
    const below = descendants(r.gateway.child.pid!);
    expect(below.length).toBeGreaterThan(0);
    r.gateway.child.kill("SIGKILL");
    await new Promise<void>((resolve) => r.gateway.child.once("exit", () => resolve()));
    call.abort();
    await vi.waitFor(() => expect(hostServerProcesses()).toEqual([]), { timeout: 20_000 });
    for (const pid of below) {
      await vi.waitFor(() => expect(() => process.kill(pid, 0)).toThrow(), { timeout: 20_000 });
    }
  });
});
