/**
 * The stdio bridge of the trusted MCP relay (MVP-7679, mcp-stdio-sandbox.ts) with a stand-in for `bwrap`: the
 * shim reads the launcher's option pipe (so the exact argv is asserted) and runs the server directly, which lets the
 * bridge's own logic be driven fast and deterministically: id correlation, local answers to server requests, the
 * environment allowlist, the single restart before `initialize`, deadlines, an endless line, EPIPE, a start that
 * never passes its check and the kill on close. What the real sandbox hides from the agent is proven with real
 * bwrap in mcp-stdio-sandbox-process.test.ts.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { StdioBridge, buildToolSandboxEnv } from "../mcp-stdio-sandbox.js";
import type { IsolationConfig } from "../sandbox.js";

let dir: string;
let logs: string[];
const bridges: StdioBridge[] = [];

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "mvp7679-stdio-"));
  fs.chmodSync(dir, 0o700);
  logs = [];
  vi.spyOn(console, "log").mockImplementation((...args) => {
    logs.push(args.map(String).join(" "));
  });
});

afterEach(() => {
  while (bridges.length > 0) bridges.pop()!.close();
  vi.restoreAllMocks();
  fs.rmSync(dir, { recursive: true, force: true });
});

/** A stand-in for bwrap: records the option pipe and the command line, prints the check line, execs the server. */
function shim(options: { silent?: boolean } = {}): string {
  const file = path.join(dir, "bwrap");
  fs.writeFileSync(
    file,
    [
      "#!/bin/sh",
      `cat <&3 > ${JSON.stringify(path.join(dir, "bwrap-options"))}`,
      `printf '%s\\n' "$@" > ${JSON.stringify(path.join(dir, "bwrap-argv"))}`,
      // Everything up to and including the launch wrapper's argv0 ("sandbox") is the launcher's own.
      "while [ \"$1\" != \"sandbox\" ]; do shift; done; shift",
      options.silent ? "sleep 30" : "echo SANDBOX-CHECK-OK >&2",
      'exec "$@"',
    ].join("\n"),
    { mode: 0o755 },
  );
  return file;
}

function config(bwrapPath = shim(), startupTimeoutMs = 5000): IsolationConfig {
  const sandboxRoot = path.join(dir, "root");
  fs.mkdirSync(sandboxRoot, { mode: 0o700, recursive: true });
  return { startupTimeoutMs, runTimeoutMs: 60_000, sandboxRoot, bwrapPath };
}

/** A stdio MCP server; `mode` picks a behavior, `dir` holds its files. */
function serverScript(): string {
  const file = path.join(dir, "server.cjs");
  fs.writeFileSync(
    file,
    String.raw`
const fs = require("node:fs");
const mode = process.argv[2] || "normal";
const stateDir = process.argv[3];
const starts = (() => { try { return Number(fs.readFileSync(stateDir + "/starts", "utf8")); } catch { return 0; } })() + 1;
fs.writeFileSync(stateDir + "/starts", String(starts));
fs.writeFileSync(stateDir + "/pid", String(process.pid));
fs.writeFileSync(stateDir + "/env", JSON.stringify(process.env));
const send = (m) => process.stdout.write(JSON.stringify(m) + "\n");
process.stderr.write("SERVER-STDERR-SECRET-7679\n");
if (mode === "banner") process.stdout.write("starting up...\nnot json\n");
if (mode === "die-first" && starts === 1) process.exit(3);
if (mode === "die-always") process.exit(4);
process.stdin.on("error", () => {});
process.stdout.on("error", () => {});
let buffer = "";
process.stdin.on("data", (chunk) => {
  buffer += chunk;
  for (;;) {
    const i = buffer.indexOf("\n");
    if (i < 0) break;
    const line = buffer.slice(0, i); buffer = buffer.slice(i + 1);
    let m; try { m = JSON.parse(line); } catch { continue; }
    if (m.method === undefined) { fs.appendFileSync(stateDir + "/client-answers", JSON.stringify(m) + "\n"); continue; }
    if (m.id === undefined) continue;
    if (m.method === "initialize") {
      send({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "stdio-stub", version: "1" } } });
      if (mode === "server-requests") {
        send({ jsonrpc: "2.0", id: "s-ping", method: "ping" });
        send({ jsonrpc: "2.0", id: "s-roots", method: "roots/list" });
        send({ jsonrpc: "2.0", id: "s-x", method: "sampling/createMessage", params: {} });
        send({ jsonrpc: "2.0", method: "notifications/message", params: {} });
      }
    } else if (m.method === "tools/list") {
      send({ jsonrpc: "2.0", id: m.id, result: { tools: [{ name: "echo_env", inputSchema: { type: "object" } }] } });
    } else if (m.method === "tools/call") {
      if (mode === "hang") continue;
      if (mode === "no-newline") { const filler = "x".repeat(65536); const t = setInterval(() => process.stdout.write(filler), 1); continue; }
      if (mode === "die-on-call") process.exit(5);
      if (mode === "reverse") { fs.appendFileSync(stateDir + "/held", JSON.stringify(m) + "\n"); const held = fs.readFileSync(stateDir + "/held", "utf8").trim().split("\n"); if (held.length === 2) { for (const l of held.reverse()) { const h = JSON.parse(l); send({ jsonrpc: "2.0", id: h.id, result: { content: [{ type: "text", text: "answer-" + h.params.arguments.n }] } }); } } continue; }
      send({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: JSON.stringify({ env: process.env, args: process.argv.slice(2) }) }] } });
    } else {
      send({ jsonrpc: "2.0", id: m.id, error: { code: -32601, message: "Method not found" } });
    }
  }
});
`,
  );
  return file;
}

function bridge(mode: string, env: Record<string, string> = {}, extra: Partial<ConstructorParameters<typeof StdioBridge>[0]> = {}, cfg: IsolationConfig = config()): { bridge: StdioBridge; state: string } {
  const state = path.join(dir, `state-${mode}`);
  fs.mkdirSync(state, { recursive: true });
  const created = new StdioBridge({ serverName: "local", command: process.execPath, args: [serverScript(), mode, state], env, config: cfg, ...extra });
  bridges.push(created);
  return { bridge: created, state };
}

const msg = (method: string, id?: number, params: Record<string, unknown> = {}) => ({ jsonrpc: "2.0", ...(id === undefined ? {} : { id }), method, params });
const UNAVAILABLE = 'TOOL_UNAVAILABLE: "local" could not be reached or failed. Try again later; if it keeps happening, tell your gateway administrator.';
const text = (failure: { kind: string } & Record<string, unknown>): string => JSON.stringify(failure);

describe("the tool sandbox environment", () => {
  it("is the base allowlist and the server's own env: never the gateway's secrets, the proxy token or a run-log path", () => {
    const gatewayEnv = {
      PATH: "/gateway/bin",
      HOME: "/root",
      API_KEYS: "reqlift:SYNTH-KEY",
      ANTHROPIC_API_KEY: "SYNTH-PROVIDER",
      ANTHROPIC_BASE_URL: "http://127.0.0.1:1234",
      CLAUDE_CODE_DEBUG_LOGS_DIR: "/tmp/run-logs",
      LANG: "de_DE.UTF-8",
      LC_ALL: "de_DE.UTF-8",
      LC_EVIL: "x y",
    };
    expect(buildToolSandboxEnv(gatewayEnv, { TOKEN: "server-own" })).toEqual({
      HOME: "/home/node",
      USER: "node",
      PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
      LANG: "de_DE.UTF-8",
      TERM: "xterm",
      TMPDIR: "/tmp",
      LC_ALL: "de_DE.UTF-8",
      TOKEN: "server-own",
    });
  });

  it("removes every loader setting of the server's env before launch and keeps every other key unchanged (MVP-8020)", () => {
    const serverEnv = {
      LD_PRELOAD: "/home/node/evil.so",
      LD_AUDIT: "/home/node/audit.so",
      LD_LIBRARY_PATH: "/home/node",
      LD_DEBUG: "all",
      LD_X: "anything",
      GLIBC_TUNABLES: "glibc.malloc.check=3",
      TOKEN: "server-own",
      LDAP_URI: "ldap://example.invalid",
      OLD_LD_PRELOAD: "kept",
      PATH: "/srv/bin",
    };
    expect(buildToolSandboxEnv({}, serverEnv)).toEqual({
      HOME: "/home/node",
      USER: "node",
      PATH: "/srv/bin",
      LANG: "C.UTF-8",
      TERM: "xterm",
      TMPDIR: "/tmp",
      TOKEN: "server-own",
      LDAP_URI: "ldap://example.invalid",
      OLD_LD_PRELOAD: "kept",
    });
  });

  it("the server's own env wins over the base values", () => {
    expect(buildToolSandboxEnv({}, { PATH: "/srv/bin", HOME: "/srv" })).toMatchObject({ PATH: "/srv/bin", HOME: "/srv" });
  });
});

describe("the sandbox command line (exact options)", () => {
  it("gives the server its own namespaces, a private empty home and no gateway content", async () => {
    const { bridge: b, state } = bridge("normal", { TOKEN: "SYNTH-STDIO-SECRET-7679" });
    await b.request(msg("initialize", 1), 5000);
    const options = fs.readFileSync(path.join(dir, "bwrap-options"), "utf8").split("\0").filter(Boolean);
    expect(options.slice(0, 11)).toEqual(["--unshare-user", "--disable-userns", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup", "--die-with-parent", "--new-session", "--cap-drop", "ALL", "--ro-bind"]);
    const bindIndex = options.indexOf("--bind");
    expect(options[bindIndex + 2]).toBe("/home/node");
    // The home is a fresh directory below the runs root, empty and private.
    const home = options[bindIndex + 1];
    expect(path.dirname(path.dirname(home))).toBe(path.join(dir, "root", "runs"));
    expect(fs.existsSync(home)).toBe(true);
    expect(fs.readdirSync(home)).toEqual([]);
    expect(options).toContain("--tmpfs");
    // Nothing else is bound writable and no trusted content, run-log path or secret is on the command line.
    expect(options.filter((o) => o === "--bind")).toHaveLength(1);
    expect(options.join(" ")).not.toContain("SYNTH-STDIO-SECRET-7679");
    expect(options.join(" ")).not.toContain(state);
    expect(options.join(" ")).not.toMatch(/\.credentials|sessions\.json|\.ssh/);
    const argv = fs.readFileSync(path.join(dir, "bwrap-argv"), "utf8");
    expect(argv).not.toContain("SYNTH-STDIO-SECRET-7679");
  });

  it("the server's process environment is the allowlist plus its own env, nothing of the gateway's", async () => {
    process.env.ANTHROPIC_API_KEY = "SYNTH-PROVIDER-NOT-FOR-TOOLS-7679";
    process.env.API_KEYS = "x:SYNTH-GATEWAY-KEY-7679";
    try {
      const { bridge: b } = bridge("normal", { TOKEN: "SYNTH-STDIO-SECRET-7679" });
      await b.request(msg("initialize", 1), 5000);
      const reply = await b.request(msg("tools/call", 2, { name: "echo_env", arguments: {} }), 5000);
      expect(reply.kind).toBe("answer");
      const content = JSON.parse((reply as unknown as { message: { result: { content: { text: string }[] } } }).message.result.content[0].text) as { env: Record<string, string> };
      expect(content.env.TOKEN).toBe("SYNTH-STDIO-SECRET-7679");
      const keys = Object.keys(content.env).filter((k) => !["PWD", "SHLVL", "_", "OLDPWD"].includes(k)).sort();
      expect(keys).toEqual(["HOME", "LANG", "PATH", "TERM", "TMPDIR", "TOKEN", "USER"]);
      expect(JSON.stringify(content.env)).not.toContain("SYNTH-PROVIDER-NOT-FOR-TOOLS-7679");
      expect(JSON.stringify(content.env)).not.toContain("SYNTH-GATEWAY-KEY-7679");
    } finally {
      delete process.env.ANTHROPIC_API_KEY;
      delete process.env.API_KEYS;
    }
  });
});

describe("messages", () => {
  it("initialize, tools/list and tools/call are answered; a notification is accepted", async () => {
    const { bridge: b } = bridge("normal");
    const init = await b.request(msg("initialize", 1), 5000);
    const note = await b.request(msg("notifications/initialized"), 5000);
    const list = await b.request(msg("tools/list", 2), 5000);
    expect(init).toMatchObject({ kind: "answer", message: { id: 1, result: { serverInfo: { name: "stdio-stub" } } } });
    expect(note).toEqual({ kind: "accepted" });
    expect(list).toMatchObject({ kind: "answer", message: { id: 2, result: { tools: [{ name: "echo_env" }] } } });
  });

  it("two calls in flight are matched to their requests by id even when answered in the other order", async () => {
    const { bridge: b } = bridge("reverse");
    await b.request(msg("initialize", 1), 5000);
    const first = b.request(msg("tools/call", 2, { name: "echo_env", arguments: { n: "one" } }), 5000);
    const second = b.request(msg("tools/call", 3, { name: "echo_env", arguments: { n: "two" } }), 5000);
    expect(await first).toMatchObject({ kind: "answer", message: { id: 2, result: { content: [{ text: "answer-one" }] } } });
    expect(await second).toMatchObject({ kind: "answer", message: { id: 3, result: { content: [{ text: "answer-two" }] } } });
  });

  it("an unknown method gets the server's own JSON-RPC error", async () => {
    const { bridge: b } = bridge("normal");
    await b.request(msg("initialize", 1), 5000);
    expect(await b.request(msg("resources/list", 2), 5000)).toMatchObject({ kind: "answer", message: { id: 2, error: { code: -32601 } } });
  });

  it("non-JSON lines on stdout are ignored; the server's stderr is discarded and never logged", async () => {
    const { bridge: b } = bridge("banner");
    const init = await b.request(msg("initialize", 1), 5000);
    expect(init.kind).toBe("answer");
    expect(logs.join("\n")).not.toContain("SERVER-STDERR-SECRET-7679");
    expect(logs.join("\n")).not.toContain("not json");
  });

  it("requests from the server are answered locally and never reach the runtime", async () => {
    const { bridge: b, state } = bridge("server-requests");
    await b.request(msg("initialize", 1), 5000);
    await new Promise((resolve) => setTimeout(resolve, 300));
    const answers = fs.readFileSync(path.join(state, "client-answers"), "utf8").trim().split("\n").map((l) => JSON.parse(l) as Record<string, unknown>);
    expect(answers).toEqual([
      { jsonrpc: "2.0", id: "s-ping", result: {} },
      { jsonrpc: "2.0", id: "s-roots", result: { roots: [] } },
      { jsonrpc: "2.0", id: "s-x", error: { code: -32601, message: "Method not found" } },
    ]);
  });
});

describe("failures", () => {
  it("a server that dies before it answered initialize gets one restart, then works", async () => {
    const { bridge: b, state } = bridge("die-first");
    const init = await b.request(msg("initialize", 1), 8000);
    expect(init).toMatchObject({ kind: "answer", message: { id: 1, result: { serverInfo: { name: "stdio-stub" } } } });
    expect(fs.readFileSync(path.join(state, "starts"), "utf8")).toBe("2");
  });

  it("a server that always dies is TOOL_UNAVAILABLE after exactly one restart (two starts)", async () => {
    const { bridge: b, state } = bridge("die-always");
    const init = await b.request(msg("initialize", 1), 8000);
    expect(init).toEqual({ kind: "failure", failure: { kind: "unreachable", name: "local" } });
    expect(fs.readFileSync(path.join(state, "starts"), "utf8")).toBe("2");
  });

  it("a server that dies after initialize is not restarted: waiting and later calls are unreachable", async () => {
    const { bridge: b, state } = bridge("die-on-call");
    await b.request(msg("initialize", 1), 5000);
    const call = await b.request(msg("tools/call", 2, { name: "echo_env", arguments: {} }), 5000);
    expect(call).toEqual({ kind: "failure", failure: { kind: "unreachable", name: "local" } });
    const later = await b.request(msg("tools/list", 3), 5000);
    expect(later).toEqual({ kind: "failure", failure: { kind: "unreachable", name: "local" } });
    expect(fs.readFileSync(path.join(state, "starts"), "utf8")).toBe("1");
  });

  it("a command that does not exist is unreachable and the bridge keeps answering", async () => {
    const created = new StdioBridge({ serverName: "local", command: "/no/such/server-7679", args: [], env: {}, config: config() });
    bridges.push(created);
    expect(await created.request(msg("initialize", 1), 8000)).toEqual({ kind: "failure", failure: { kind: "unreachable", name: "local" } });
  });

  it("a call that is never answered ends at the deadline with the timeout failure; the server stays up until close", async () => {
    const { bridge: b, state } = bridge("hang");
    await b.request(msg("initialize", 1), 5000);
    const started = Date.now();
    const result = await b.request(msg("tools/call", 2, { name: "echo_env", arguments: {} }), 400);
    expect(Date.now() - started).toBeGreaterThanOrEqual(350);
    expect(result).toEqual({ kind: "failure", failure: { kind: "timeout", name: "local", timeoutMs: 400 } });
    const pid = Number(fs.readFileSync(path.join(state, "pid"), "utf8"));
    expect(() => process.kill(pid, 0)).not.toThrow();
  });

  it("a line that never ends is cut at the cap: TOOL_RESPONSE_INVALID, the server is killed", async () => {
    const { bridge: b, state } = bridge("no-newline", {}, { maxLineBytes: 256 * 1024 });
    await b.request(msg("initialize", 1), 5000);
    const result = await b.request(msg("tools/call", 2, { name: "echo_env", arguments: {} }), 8000);
    expect(result).toEqual({ kind: "failure", failure: { kind: "invalid_response", name: "local" } });
    expect(logs.join("\n")).toContain("mcp.bridge.refused serverName=local reason=line_too_large");
    const pid = Number(fs.readFileSync(path.join(state, "pid"), "utf8"));
    await vi.waitFor(() => expect(() => process.kill(pid, 0)).toThrow(), { timeout: 5000 });
  });

  it("a start that never passes its check is bounded by the startup timeout", async () => {
    const created = new StdioBridge({ serverName: "local", command: process.execPath, args: [serverScript(), "normal", dir], env: {}, config: config(shim({ silent: true }), 400) });
    bridges.push(created);
    const started = Date.now();
    const result = await created.request(msg("initialize", 1), 5000);
    expect(Date.now() - started).toBeLessThan(4000);
    expect(result).toEqual({ kind: "failure", failure: { kind: "unreachable", name: "local" } });
  });

  it("failures map to the fixed texts of the table", () => {
    expect(text({ kind: "unreachable" })).toContain("unreachable");
    expect(UNAVAILABLE).toContain("TOOL_UNAVAILABLE");
  });
});

describe("request ids and load", () => {
  it("a request id that is still waiting is refused; the first one ends at its own deadline", async () => {
    const { bridge: b } = bridge("hang");
    await b.request(msg("initialize", 1), 5000);
    const first = b.request(msg("tools/call", 7, { name: "echo_env", arguments: {} }), 600);
    await new Promise((resolve) => setTimeout(resolve, 100));
    const duplicate = await b.request(msg("tools/call", 7, { name: "echo_env", arguments: {} }), 600);
    expect(duplicate).toEqual({ kind: "failure", failure: { kind: "denied" } });
    expect(await first).toEqual({ kind: "failure", failure: { kind: "timeout", name: "local", timeoutMs: 600 } });
  });

  it("too many waiting requests are refused at once", async () => {
    const { bridge: b } = bridge("hang");
    await b.request(msg("initialize", 1), 5000);
    const waiting = Array.from({ length: 32 }, (_, i) => b.request(msg("tools/call", 100 + i, { name: "echo_env", arguments: {} }), 2000));
    const overflow = await b.request(msg("tools/call", 999, { name: "echo_env", arguments: {} }), 2000);
    expect(overflow).toEqual({ kind: "failure", failure: { kind: "unreachable", name: "local" } });
    b.close();
    await Promise.all(waiting);
  });
});

describe("close", () => {
  it("kills the server and removes its sandbox directory; later requests are unreachable; close is idempotent", async () => {
    const { bridge: b, state } = bridge("normal");
    await b.request(msg("initialize", 1), 5000);
    const pid = Number(fs.readFileSync(path.join(state, "pid"), "utf8"));
    const runs = path.join(dir, "root", "runs");
    expect(fs.readdirSync(runs).filter((n) => n.startsWith("run-"))).toHaveLength(1);
    b.close();
    b.close();
    await vi.waitFor(() => expect(() => process.kill(pid, 0)).toThrow(), { timeout: 5000 });
    await vi.waitFor(() => expect(fs.readdirSync(runs).filter((n) => n.startsWith("run-"))).toEqual([]), { timeout: 5000 });
    expect(await b.request(msg("tools/list", 2), 1000)).toEqual({ kind: "failure", failure: { kind: "unreachable", name: "local" } });
  });

  it("fails a request that is waiting", async () => {
    const { bridge: b } = bridge("hang");
    await b.request(msg("initialize", 1), 5000);
    const waiting = b.request(msg("tools/call", 2, { name: "echo_env", arguments: {} }), 20_000);
    await new Promise((resolve) => setTimeout(resolve, 100));
    b.close();
    expect(await waiting).toEqual({ kind: "failure", failure: { kind: "unreachable", name: "local" } });
  });
});
