/**
 * The security matrix harness (MVP-7677): everything the credential-isolation acceptance suites share. It has
 * no vitest import, so the Docker integration probe can import the compiled copy from `dist/tests/helpers`.
 *
 * - Synthetic marker classes with a random suffix per run (the seed is overridable so a parent process can
 *   recognize a child's markers without ever holding a real secret).
 * - Observation surfaces and the detector: `detect()` returns `surface:marker` names, `assertNoLeak()` fails with
 *   names and counts only, never a value. Every surface has a byte floor so an empty capture cannot pass.
 * - Evidence lines: `SECURITY-EVIDENCE` (once per suite), `SECURITY-MATRIX` (one per row, with a stable AC row id
 *   and `expected= observed= result=`), `SECURITY-SUMMARY` (expected rows, observed rows, missing ids).
 * - Host prerequisites that fail with a fixed `host prerequisite missing: <name>` line instead of skipping.
 * - Host-side samplers: a process sampler (an agent runtime without a sandbox ancestor, overlap windows of
 *   concurrent roles) and an egress sampler (non-loopback destinations of the gateway's network namespace).
 * - A rig: the compiled gateway, a scripted model, recording MCP/webhook/git doubles and every synthetic marker.
 *
 * Only case names, booleans and counts are ever printed. Needs `npm run build`, `bwrap` and user namespaces.
 */
import { execFileSync, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import net, { type AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import { createBareRepo, startDumbHttpGitRemote, type DumbHttpGitRemote } from "./dumb-http-git-remote.js";
import { startFakeAnthropicApi, type ExactToolScript, type FakeAnthropicApi, type RecordedMessagesRequest } from "./fake-anthropic-api.js";
import { REPO_ROOT, descendants, gatewayRequest, spawnGateway, type Cleanup, type SpawnedGateway } from "./git-process-gateway.js";
import { startOAuthMcpStub, type OAuthMcpStub } from "./oauth-mcp-stub.js";
import { startSseMcpStub, type SseMcpStub } from "./sse-mcp-stub.js";

/* ------------------------------------------------------------------ */
/*  Markers                                                             */
/* ------------------------------------------------------------------ */

export type MarkerClass = "gatewayKey" | "provider" | "mcp" | "repository" | "secondSession" | "legacy" | "state";

const MARKER_NAMES: Record<string, MarkerClass> = {
  gatewayKeyReqlift: "gatewayKey",
  gatewayKeyDiemcrm: "gatewayKey",
  providerApiKey: "provider",
  oauthAccess: "provider",
  oauthRefresh: "provider",
  registryHttpHeader: "mcp",
  userOverrideHeader: "mcp",
  sseHeader: "mcp",
  stdioEnv: "mcp",
  stdioArgs: "mcp",
  requestHttpHeader: "mcp",
  requestStdioEnv: "mcp",
  sshKey: "repository",
  cloneToken: "repository",
  githubToken: "repository",
  sessionBFile: "secondSession",
  sessionBTurn: "secondSession",
  sessionB2File: "secondSession",
  legacyTranscript: "legacy",
  stateFile: "state",
};

export interface SecurityMarkers {
  seed: string;
  /** Marker name to value. */
  values: Record<string, string>;
  classOf: (name: string) => MarkerClass;
}

/** One value per marker name, every value distinct and carrying the run's seed. `seed` defaults to `SECURITY_MARKER_SEED` or a random one. */
export function createMarkers(seed: string = process.env.SECURITY_MARKER_SEED ?? randomBytes(4).toString("hex")): SecurityMarkers {
  const values: Record<string, string> = {};
  for (const name of Object.keys(MARKER_NAMES)) values[name] = `SYNTH-${name.toUpperCase()}-${seed}`;
  return { seed, values, classOf: (name) => MARKER_NAMES[name] ?? "state" };
}

/** A marker split in two halves, so a script that searches for it never contains it whole. */
export function splitNeedle(value: string): [string, string] {
  const cut = Math.ceil(value.length / 2);
  return [value.slice(0, cut), value.slice(cut)];
}

/** The needles as JSON for an in-sandbox scanner: `{ name: [firstHalf, secondHalf] }`. */
export function splitNeedles(values: Record<string, string>): string {
  return JSON.stringify(Object.fromEntries(Object.entries(values).map(([name, value]) => [name, splitNeedle(value)])));
}

/* ------------------------------------------------------------------ */
/*  Surfaces and the detector                                           */
/* ------------------------------------------------------------------ */

export interface Surface {
  name: string;
  text: string;
}

/** Byte floors per surface name: a capture below its floor did not observe anything. */
export const SURFACE_FLOORS: Record<string, number> = {
  "tool-results": 200,
  "model-requests": 1000,
  events: 100,
  "gateway-log": 100,
  transcripts: 200,
};

/** Which (surface, marker) pairs match, as `surface:marker` names. */
export function detect(surfaces: Surface[], markers: Record<string, string>): string[] {
  const hits: string[] = [];
  for (const surface of surfaces) {
    for (const [name, value] of Object.entries(markers)) if (surface.text.includes(value)) hits.push(`${surface.name}:${name}`);
  }
  return hits;
}

/** Fails with names and counts only: the hits, and any surface below its byte floor. Never a marker value. */
export function assertNoLeak(row: string, surfaces: Surface[], markers: Record<string, string>, floors: Record<string, number> = SURFACE_FLOORS): void {
  const hits = detect(surfaces, markers);
  const thin = surfaces.filter((surface) => surface.text.length < (floors[surface.name] ?? 1)).map((surface) => surface.name);
  const problems: string[] = [];
  if (hits.length > 0) problems.push(`hits=${hits.length} [${hits.join(", ")}]`);
  if (thin.length > 0) problems.push(`below the byte floor: [${thin.join(", ")}]`);
  if (problems.length > 0) throw new Error(`security row ${row}: ${problems.join("; ")}`);
}

/** Replaces every marker value in `text` with `[name]`, so a child's output can be shown without any value. */
export function scrub(text: string, markers: Record<string, string>): string {
  let result = text;
  for (const [name, value] of Object.entries(markers)) result = result.split(value).join(`[${name}]`);
  return result;
}

/* ------------------------------------------------------------------ */
/*  Evidence                                                            */
/* ------------------------------------------------------------------ */

/** One evidence line. Written to stderr: vitest 4 keeps it in the runner log for passing tests. */
export function emit(line: string): void {
  process.stderr.write(`${line}\n`);
}

function kv(fields: Record<string, string | number | boolean | undefined>): string {
  return Object.entries(fields)
    .filter(([, value]) => value !== undefined)
    .map(([key, value]) => `${key}=${typeof value === "string" && /[\s"]/.test(value) ? JSON.stringify(value) : String(value)}`)
    .join(" ");
}

function tryExec(file: string, args: string[], cwd: string = REPO_ROOT): string {
  try {
    return execFileSync(file, args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    return "unknown";
  }
}

export interface EvidenceInfo {
  suite: string;
  /** Non-secret configuration keys and values of the gateway under test. */
  config: Record<string, string>;
  /** Every deadline the suite asserts, in ms, by name. */
  deadlines: Record<string, number>;
  offline: boolean;
  logLevel: string;
}

/** The runtime facts a `SECURITY-EVIDENCE` line carries. */
export function runtimeFacts(): Record<string, string> {
  const sdk = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "node_modules", "@anthropic-ai", "claude-agent-sdk", "package.json"), "utf8")) as { version: string };
  const cli = fs.readFileSync(path.join(REPO_ROOT, "node_modules", "@anthropic-ai", "claude-agent-sdk", "cli.js"), "utf8");
  return {
    claude_code_version: /VERSION:"([0-9.]+)"/.exec(cli)?.[1] ?? "unknown",
    sdk: sdk.version,
    bwrap: tryExec("bwrap", ["--version"]).replace(/^bubblewrap\s*/, ""),
    node: process.version,
  };
}

/** `SECURITY-EVIDENCE`: commit, tree, versions, non-secret configuration and deadlines. Names and values of settings only. */
export function evidenceLine(info: EvidenceInfo): string {
  const dirty = tryExec("git", ["status", "--porcelain", "--untracked-files=no"]).split("\n").filter(Boolean).length;
  return `SECURITY-EVIDENCE ${kv({
    suite: info.suite,
    commit: tryExec("git", ["rev-parse", "HEAD"]),
    tree: tryExec("git", ["rev-parse", "HEAD^{tree}"]),
    tracked_changes: dirty,
    ...runtimeFacts(),
    log_level: info.logLevel,
    offline: info.offline,
    config: Object.entries(info.config).map(([key, value]) => `${key}:${value}`).join(","),
    deadlines: Object.entries(info.deadlines).map(([key, value]) => `${key}:${value}`).join(","),
  })}`;
}

export type RowExpectation = "pass" | "fail";

export interface MatrixRow {
  /** The stable AC row id (see AC_ROWS), optionally with a mode suffix (`RT.env.fresh`). */
  id: string;
  mode?: string;
  /** What the row must do: `pass` for a security row, `fail` for a negative control. */
  expected: RowExpectation;
  /** What the observation was: `pass` when no hit and every control held, else `fail`. */
  observed: RowExpectation;
  hits: number;
  durationMs: number;
  deadlineMs: number;
  surfaces: Surface[];
  /** Names of the controls that held (permitted operation ran, scanner canary found, ...). */
  controls?: string[];
}

/** `SECURITY-MATRIX`: one row. A negative control reads `expected=fail observed=fail result=pass`. */
export function matrixLine(row: MatrixRow): string {
  return `SECURITY-MATRIX ${kv({
    id: row.id,
    mode: row.mode,
    expected: row.expected,
    observed: row.observed,
    result: row.expected === row.observed ? "pass" : "fail",
    hits: row.hits,
    duration_ms: Math.round(row.durationMs),
    deadline_ms: row.deadlineMs,
    controls: row.controls?.join(","),
    surfaces: row.surfaces.map((surface) => `${surface.name}:${surface.text.length}`).join(","),
  })}`;
}

/** Collects the rows of one suite and prints its `SECURITY-SUMMARY`. */
export class MatrixRecorder {
  private readonly rows: MatrixRow[] = [];

  constructor(
    readonly suite: string,
    private readonly expectedIds: string[],
    private readonly out: (line: string) => void = emit,
  ) {}

  /** Records and prints a row; returns the row's `result`. */
  record(row: MatrixRow): "pass" | "fail" {
    this.rows.push(row);
    this.out(matrixLine(row));
    return row.expected === row.observed ? "pass" : "fail";
  }

  observedIds(): string[] {
    return this.rows.map((row) => row.id);
  }

  summary(): { expected: number; observed: number; pass: number; fail: number; hits: number; missing: string[] } {
    const observed = new Set(this.observedIds());
    const missing = this.expectedIds.filter((id) => !observed.has(id));
    const pass = this.rows.filter((row) => row.expected === row.observed).length;
    return { expected: this.expectedIds.length, observed: this.rows.length, pass, fail: this.rows.length - pass, hits: this.rows.reduce((sum, row) => sum + row.hits, 0), missing };
  }

  /** Prints `SECURITY-SUMMARY` and returns it; the suite asserts `missing` is empty and `fail` is 0. */
  finish(): ReturnType<MatrixRecorder["summary"]> {
    const summary = this.summary();
    this.out(`SECURITY-SUMMARY ${kv({ suite: this.suite, expected: summary.expected, observed: summary.observed, pass: summary.pass, fail: summary.fail, hits: summary.hits, missing: summary.missing.join(",") || "none" })}`);
    return summary;
  }
}

/**
 * The AC row ids (the A6 map): every Gherkin row of MVP-7677 has one stable id. A row id may carry a `.mode` suffix
 * (`fresh`, `resumed`, `restarted`) where the AC runs in several execution modes.
 */
export const AC_ROWS: Record<string, string> = {
  "RP.regression": "Real-process regression: an ordinary chat shows its environment, nothing leaks, the authorized operation works",
  "RP.negative-control": "Real-process regression: the suite fails on a deliberately exposed credential",
  "RT.env": "Route: inherited environment of the agent and its subprocesses",
  "RT.proc": "Route: gateway, parent, sibling and trusted-worker process information",
  "RT.config": "Route: gateway key files, provider OAuth state and MCP configuration",
  "RT.repo": "Route: trusted repository and SSH credentials",
  "RT.session": "Route: another concurrently running session's workspace or transcript",
  "RT.legacy": "Route: a credential-bearing legacy transcript",
  "RT.links": "Route: path traversal and symlink escape from the approved workspace",
  "RT.routing": "Route: unauthorized tool routing, identity substitution or cross-origin redirect",
  "NC.chat": "Normal chat: three turns of env | sort and an allowed workspace command",
  "NC.interpreter": "Normal chat: alternate interpreter environment read",
  "NC.read": "Normal chat: built-in Read of a credential file",
  "EP.ordinary": "Entry point: ordinary chat without agent or skill",
  "EP.agent": "Entry point: configured agent",
  "EP.skill": "Entry point: skill chat",
  "EP.subagent": "Entry point: delegated sub-agent",
  "EP.mcp-direct": "Entry point: authenticated direct MCP call",
  "EP.upload": "Entry point: authenticated streaming upload relay",
  "EP.denied": "Entry point: denied-tool branch",
  "EP.enlarge": "Entry point: grant-enlargement attempts",
  "IF.startup-exit": "Failure: sandbox startup failure (exit)",
  "IF.startup-hang": "Failure: sandbox startup failure (hang)",
  "IF.policy": "Failure: policy enforcement failure before the first tool",
  "IF.cancel": "Failure: cancellation during a tool call with a child process",
  "IF.restart-term": "Failure: gateway restart (SIGTERM) during that tool call",
  "IF.restart-kill": "Failure: gateway restart (SIGKILL) during that tool call",
  "IF.cred-missing": "Failure: missing upstream credential",
  "IF.cred-refused": "Failure: refused upstream credential",
  "IF.timeout": "Failure: upstream timeout",
  "IF.unavailable": "Failure: upstream connection reset",
  "IF.legacy": "Failure: resume of a legacy session",
};

/* ------------------------------------------------------------------ */
/*  Host prerequisites                                                  */
/* ------------------------------------------------------------------ */

export type Prerequisite = "bwrap" | "userns" | "unshare" | "git" | "python3" | "docker" | "uid1000" | "build";

/** Throws `host prerequisite missing: <name>` for the first missing prerequisite. A suite never skips. */
export function requireHost(needs: Prerequisite[]): void {
  const missing = (name: Prerequisite): boolean => {
    switch (name) {
      case "bwrap":
        return tryExec("bwrap", ["--version"]) === "unknown";
      case "userns":
        return tryExec("bwrap", ["--ro-bind", "/", "/", "--unshare-user", "true"]) === "unknown" && !fs.existsSync("/proc/self/ns/user");
      case "unshare":
        return tryExec("unshare", ["--version"]) === "unknown";
      case "git":
        return tryExec("git", ["--version"]) === "unknown";
      case "python3":
        return tryExec("python3", ["--version"]) === "unknown";
      case "docker":
        return tryExec("sudo", ["-n", "docker", "version", "--format", "{{.Server.Version}}"]) === "unknown";
      case "uid1000":
        return typeof process.getuid !== "function" || process.getuid() !== 1000;
      case "build":
        return !fs.existsSync(path.join(REPO_ROOT, "dist", "server.js"));
    }
  };
  for (const need of needs) if (missing(need)) throw new Error(`host prerequisite missing: ${need}`);
}

/* ------------------------------------------------------------------ */
/*  Text collectors                                                     */
/* ------------------------------------------------------------------ */

/** All regular files below `dir` (no link followed, each below 4 MiB) as one text, with the file count. */
export function treeText(dir: string): { text: string; files: number } {
  let text = "";
  let files = 0;
  const walk = (current: string): void => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = path.join(current, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile()) {
        try {
          if (fs.statSync(full).size < 4 * 1024 * 1024) {
            text += `\n${fs.readFileSync(full, "latin1")}`;
            files++;
          }
        } catch {
          // Unreadable or gone: skipped.
        }
      }
    }
  };
  walk(dir);
  return { text, files };
}

/** The conversation directories (`.../sessions/<dirId>`) of the named conversations, from the persisted state. */
export function conversationDirs(gateway: SpawnedGateway, clientIds: string[]): string[] {
  let saved: { sessions?: Record<string, { sandboxDirId?: string }>; sessionsByLabel?: Record<string, Record<string, { sandboxDirId?: string }>> };
  try {
    saved = JSON.parse(fs.readFileSync(path.join(gateway.dirs.persist, "sessions.json"), "utf8"));
  } catch {
    return [];
  }
  return clientIds.flatMap((id) => {
    const dirIds = [...Object.values(saved.sessionsByLabel ?? {}).map((entries) => entries[id]?.sandboxDirId), saved.sessions?.[id]?.sandboxDirId].filter((v): v is string => typeof v === "string");
    return dirIds.map((dirId) => path.join(gateway.dirs.home, ".agent-sandbox", "sessions", dirId));
  });
}

/** Transcripts, `/work` and home of the named conversations (the agent-writable storage), plus their file count. */
export function conversationText(gateway: SpawnedGateway, clientIds: string[]): { text: string; files: number } {
  const parts = conversationDirs(gateway, clientIds).map(treeText);
  return { text: parts.map((part) => part.text).join("\n"), files: parts.reduce((sum, part) => sum + part.files, 0) };
}

/** The runtime's per-run log directory and every other leftover below the sandbox root outside the conversation directories. */
export function runLeftoversText(gateway: SpawnedGateway): { text: string; files: number } {
  const root = path.join(gateway.dirs.home, ".agent-sandbox");
  let text = "";
  let files = 0;
  let entries: fs.Dirent[] = [];
  try {
    entries = fs.readdirSync(root, { withFileTypes: true });
  } catch {
    return { text, files };
  }
  for (const entry of entries) {
    if (entry.name === "sessions" || !entry.isDirectory()) continue;
    const part = treeText(path.join(root, entry.name));
    text += part.text;
    files += part.files;
  }
  return { text, files };
}

/* ------------------------------------------------------------------ */
/*  Model double helpers                                                */
/* ------------------------------------------------------------------ */

export const bash = (prompt: string, command: string, then: { name: string; input: Record<string, unknown> }[] = []): ExactToolScript => ({
  name: "Bash",
  prompt,
  input: { command, description: "probe" },
  ...(then.length > 0 ? { then } : {}),
});
export const read = (prompt: string, file: string): ExactToolScript => ({ name: "Read", prompt, input: { file_path: file } });

/** The model double's requests of the conversation(s) that carry `prompt` (a resumed conversation repeats earlier turns). */
export function requestsFor(api: FakeAnthropicApi, prompt: string): RecordedMessagesRequest[] {
  return api.requests.filter((request) => request.userTexts.some((text) => text.includes(prompt)));
}

/** The tool results of the latest turn whose latest prompt is `prompt`, in order. */
export function resultsFor(api: FakeAnthropicApi, prompt: string): { isError: boolean; text: string }[] {
  const matching = api.requests.filter((request) => request.userTexts.at(-1)?.includes(prompt) && !request.warmup);
  return matching.at(-1)?.toolResults ?? [];
}

/* ------------------------------------------------------------------ */
/*  Host-side samplers                                                  */
/* ------------------------------------------------------------------ */

interface ProcInfo {
  pid: number;
  ppid: number;
  comm: string;
  cmdline: string;
}

function readProc(pid: number): ProcInfo | null {
  try {
    const stat = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
    const afterName = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
    return {
      pid,
      ppid: Number(afterName[1]),
      comm: fs.readFileSync(`/proc/${pid}/comm`, "utf8").trim(),
      cmdline: fs.readFileSync(`/proc/${pid}/cmdline`).toString("latin1").replace(/\0/g, " "),
    };
  } catch {
    return null;
  }
}

export interface ProcessSample {
  /** Distinct pids of an agent runtime (`cli.js`) whose ancestors up to the gateway include no `bwrap`. */
  unsandboxedRuntimes: number[];
  /** Distinct runtime pids seen (sandboxed or not). */
  runtimesSeen: number;
  /** First and last epoch ms at which a process whose command line holds the tag existed (below the gateway). */
  windows: Record<string, { first: number; last: number } | undefined>;
}

/**
 * Samples the processes below the gateway every `intervalMs` (20 ms by default): an agent runtime without a bwrap
 * ancestor is a run outside the sandbox (a model request would not prove it: it would not reach the double), and the
 * windows of command-line tags prove that concurrent roles overlapped a scan.
 */
export function startProcessSampler(gatewayPid: () => number, tags: string[] = [], intervalMs = 20): { stop: () => ProcessSample; peek: () => ProcessSample } {
  const unsandboxed = new Set<number>();
  const runtimes = new Set<number>();
  const windows: ProcessSample["windows"] = {};
  const timer = setInterval(() => {
    const root = gatewayPid();
    const infos = new Map<number, ProcInfo>();
    for (const pid of descendants(root)) {
      const info = readProc(pid);
      if (info) infos.set(pid, info);
    }
    const now = Date.now();
    for (const info of infos.values()) {
      if (/(^|[ /])cli\.js( |$)/.test(info.cmdline) && info.comm !== "bwrap") {
        runtimes.add(info.pid);
        let ancestor = infos.get(info.ppid);
        let sandboxed = false;
        while (ancestor) {
          if (ancestor.comm === "bwrap") sandboxed = true;
          ancestor = infos.get(ancestor.ppid);
        }
        if (!sandboxed) unsandboxed.add(info.pid);
      }
      for (const tag of tags) {
        if (!info.cmdline.includes(tag)) continue;
        const window = windows[tag];
        windows[tag] = { first: window?.first ?? now, last: now };
      }
    }
  }, intervalMs);
  const snapshot = (): ProcessSample => ({ unsandboxedRuntimes: [...unsandboxed], runtimesSeen: runtimes.size, windows: { ...windows } });
  return {
    peek: snapshot,
    stop: () => {
      clearInterval(timer);
      return snapshot();
    },
  };
}

function ipv4FromHex(hex: string): string {
  const bytes = hex.match(/../g)!.map((pair) => parseInt(pair, 16)).reverse();
  return bytes.join(".");
}

/**
 * The non-loopback remote hosts in the text of one `/proc/net/<table>` file (listening sockets and loopback excluded).
 * The table lists every socket of the network namespace, so `inodes` restricts it to the sockets one process tree owns.
 */
export function destinationsFromTable(table: "tcp" | "udp" | "tcp6" | "udp6", text: string, inodes?: Set<string>): string[] {
  const found = new Set<string>();
  for (const line of text.split("\n").slice(1)) {
    const fields = line.trim().split(/\s+/);
    if (fields.length < 10) continue;
    const [remote, state, inode] = [fields[2], fields[3], fields[9]];
    if (inodes && !inodes.has(inode)) continue;
    if (table.startsWith("tcp") && state === "0A") continue;
    const [address] = remote.split(":");
    if (/^0+$/.test(address)) continue;
    if (table.endsWith("6")) {
      if (address === "00000000000000000000000001000000" || (address.startsWith("0000000000000000FFFF0000") && ipv4FromHex(address.slice(24)).startsWith("127."))) continue;
      found.add(`ipv6:${address.slice(0, 8)}`);
    } else {
      const host = ipv4FromHex(address);
      if (!host.startsWith("127.")) found.add(host);
    }
  }
  return [...found];
}

/** The socket inodes held open by `pid` and every process below it. */
export function socketInodesOf(pid: number): Set<string> {
  const inodes = new Set<string>();
  for (const candidate of [pid, ...descendants(pid)]) {
    let fds: string[];
    try {
      fds = fs.readdirSync(`/proc/${candidate}/fd`);
    } catch {
      continue;
    }
    for (const fd of fds) {
      try {
        const match = /^socket:\[(\d+)\]$/.exec(fs.readlinkSync(`/proc/${candidate}/fd/${fd}`));
        if (match) inodes.add(match[1]);
      } catch {
        // The descriptor closed while reading.
      }
    }
  }
  return inodes;
}

/** The non-loopback destination hosts of the TCP and UDP sockets that `pid` and its descendants hold (host only, no payload). */
export function nonLoopbackDestinations(pid: number): string[] {
  const inodes = socketInodesOf(pid);
  const found = new Set<string>();
  if (inodes.size === 0) return [];
  for (const table of ["tcp", "udp", "tcp6", "udp6"] as const) {
    let text: string;
    try {
      text = fs.readFileSync(`/proc/${pid}/net/${table}`, "utf8");
    } catch {
      continue;
    }
    for (const host of destinationsFromTable(table, text, inodes)) found.add(host);
  }
  return [...found];
}

/** Samples `nonLoopbackDestinations(gatewayPid)` every 50 ms; `stop()` returns every destination host seen (a connection shorter than the interval can be missed). */
export function startEgressSampler(gatewayPid: () => number, intervalMs = 50): { stop: () => string[] } {
  const seen = new Set<string>();
  const timer = setInterval(() => {
    for (const host of nonLoopbackDestinations(gatewayPid())) seen.add(host);
  }, intervalMs);
  return {
    stop: () => {
      clearInterval(timer);
      return [...seen];
    },
  };
}

/* ------------------------------------------------------------------ */
/*  Query driver                                                        */
/* ------------------------------------------------------------------ */

export interface Ndjson {
  type: string;
  content?: string;
  [key: string]: unknown;
}

export interface QueryOutcome {
  status: number;
  events: Ndjson[];
  raw: string;
  ms: number;
  /** True when the response ended without its terminating chunk (the connection was cut). */
  aborted: boolean;
}

/** One `POST /v1/query` as `key`, streamed to the end. `deadlineMs` ends a hanging request (the result then has `aborted`). */
export function queryAs(port: number, key: string, body: Record<string, unknown>, deadlineMs = 180_000): Promise<QueryOutcome> {
  return new Promise((resolve) => {
    const started = Date.now();
    const payload = Buffer.from(JSON.stringify({ model: "claude-sonnet-4-5", ...body }), "utf8");
    const chunks: Buffer[] = [];
    let aborted = false;
    let settled = false;
    const finish = (status: number): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      const raw = Buffer.concat(chunks).toString("utf8");
      const events: Ndjson[] = [];
      for (const line of raw.split("\n")) {
        if (!line.trim().startsWith("{")) continue;
        try {
          events.push(JSON.parse(line) as Ndjson);
        } catch {
          // A cut line.
        }
      }
      resolve({ status, events, raw, ms: Date.now() - started, aborted });
    };
    const req = http.request(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/query", agent: false, headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json", "Content-Length": payload.length } },
      (res) => {
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => finish(res.statusCode ?? 0));
        res.on("error", () => {
          aborted = true;
          finish(res.statusCode ?? 0);
        });
        res.on("aborted", () => {
          aborted = true;
        });
        res.on("close", () => {
          if (!res.complete) aborted = true;
          finish(res.statusCode ?? 0);
        });
      },
    );
    const timer = setTimeout(() => {
      aborted = true;
      req.destroy();
      finish(0);
    }, deadlineMs);
    req.on("error", () => {
      aborted = true;
      finish(0);
    });
    req.end(payload);
  });
}

/* ------------------------------------------------------------------ */
/*  Offline execution                                                   */
/* ------------------------------------------------------------------ */

/**
 * The argv prefix that runs a command in a loopback-only network namespace under the caller's own uid: an outer user
 * namespace owns the network namespace (it brings `lo` up), an inner one maps the caller's uid back, so the gateway,
 * bwrap and every file see the same owner as on the host. Nothing in it can reach a non-loopback address.
 */
export function offlinePrefix(): string[] {
  const uid = process.getuid?.() ?? 1000;
  const gid = process.getgid?.() ?? 1000;
  return ["unshare", "--user", "--map-root-user", "--net", "sh", "-c", `ip link set lo up && exec unshare --user --map-user=${uid} --map-group=${gid} "$@"`, "offline"];
}

/** Whether the offline mode works on this host (a loopback-only namespace that still runs bwrap). */
export function offlineAvailable(): boolean {
  try {
    execFileSync(offlinePrefix()[0], [...offlinePrefix().slice(1), "sh", "-c", "ip -br addr show lo | grep -q 127.0.0.1 && bwrap --ro-bind / / --unshare-user --unshare-pid --dev /dev --proc /proc true"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

/* ------------------------------------------------------------------ */
/*  The rig                                                             */
/* ------------------------------------------------------------------ */

export interface Counting {
  base: string;
  hits: { path: string; authorization?: string; context?: string }[];
  close: () => Promise<void>;
}

/** A recording http double: every request answered 200 with a fixed JSON result; `redirectTo` answers 302 instead. */
export async function startCountingDouble(options: { redirectTo?: string } = {}): Promise<Counting> {
  const hits: Counting["hits"] = [];
  const sockets = new Set<net.Socket>();
  const server = http.createServer((req, res) => {
    hits.push({ path: req.url ?? "", authorization: req.headers.authorization, context: String(req.headers["x-webhook-context"] ?? "") });
    req.resume();
    req.on("end", () => {
      if (options.redirectTo) {
        res.writeHead(302, { Location: options.redirectTo });
        res.end();
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ output: `WEBHOOK-RESULT ${req.url}` }));
    });
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  return {
    base: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    hits,
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

export interface TokenDouble {
  url: string;
  /** The refresh tokens it received (they are markers: only this double may ever see one). */
  refreshTokens: string[];
  close: () => Promise<void>;
}

/** A local OAuth token endpoint: every refresh is answered with a fresh access token that lasts an hour. */
export async function startTokenDouble(): Promise<TokenDouble> {
  const refreshTokens: string[] = [];
  const sockets = new Set<net.Socket>();
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      try {
        refreshTokens.push(String((JSON.parse(Buffer.concat(chunks).toString("utf8")) as { refresh_token?: unknown }).refresh_token ?? ""));
      } catch {
        refreshTokens.push("");
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ access_token: `refreshed-access-${refreshTokens.length}`, refresh_token: "refreshed-refresh-token", expires_in: 3600 }));
    });
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  return {
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/oauth/token`,
    refreshTokens,
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

/** An MCP server over stdio whose `echo` tool reports the length of its `SERVER_TOKEN` env value. The first argv names the tag. */
export const STDIO_SOURCE = String.raw`// SECURITY-STDIO-SERVER
const rl = require('node:readline').createInterface({ input: process.stdin });
const send = (m) => process.stdout.write(JSON.stringify(m) + '\n');
rl.on('line', (line) => {
  let m; try { m = JSON.parse(line); } catch { return; }
  if (m.id === undefined) return;
  if (m.method === 'initialize') send({ jsonrpc: '2.0', id: m.id, result: { protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'security-stdio', version: '1' } } });
  else if (m.method === 'tools/list') send({ jsonrpc: '2.0', id: m.id, result: { tools: [{ name: 'echo', description: 'echo', inputSchema: { type: 'object', properties: {} } }] } });
  else if (m.method === 'tools/call') send({ jsonrpc: '2.0', id: m.id, result: { content: [{ type: 'text', text: 'STDIO-RESULT:' + (process.env.SERVER_TOKEN || '').length }] } });
  else send({ jsonrpc: '2.0', id: m.id, error: { code: -32601, message: 'Method not found' } });
});
`;

export interface RigOptions {
  /** Prefix of the gateway's temp root. */
  rootPrefix?: string;
  /** Provider credential source: `api-key` (default) or `oauth` (the credentials file, with a refresh against a local token double). */
  mode?: "api-key" | "oauth";
  /** Extra gateway environment; wins over the rig's own. */
  env?: Record<string, string>;
  /** The patched `dist/server.js` of a negative control. */
  distServer?: string;
  /** Fake-git bin directory first on the gateway's PATH. */
  fakeGitBin?: string;
  /** `LOG_LEVEL` of the gateway (default info). */
  logLevel?: "info" | "debug";
  /** Further state planted before the first start. */
  seed?: (dirs: SpawnedGateway["dirs"], markers: SecurityMarkers) => void;
  markers?: SecurityMarkers;
}

export interface SecurityRig {
  markers: SecurityMarkers;
  keys: { reqlift: string; diemcrm: string };
  api: FakeAnthropicApi;
  /** The current gateway process (a restart replaces it). */
  gateway: SpawnedGateway;
  /** The model double's script list: push a script before a request that needs it. */
  scripts: ExactToolScript[];
  jira: OAuthMcpStub;
  feed: SseMcpStub;
  reqHttp: OAuthMcpStub;
  webhook: Counting;
  /** A recording "other origin" that a redirect would send a credential to. */
  otherOrigin: Counting;
  /** The local OAuth token endpoint the model proxy refreshes against. */
  tokenDouble: TokenDouble;
  remote: DumbHttpGitRemote;
  /** Gateway output since the rig started (survives restarts: each process's output is appended). */
  log: () => string;
  /** `POST /v1/query` as `label`. */
  ask: (label: "reqlift" | "diemcrm", body: Record<string, unknown>, deadlineMs?: number) => Promise<QueryOutcome>;
  /** SIGTERM, wait for the exit, start a new process on the same directories. */
  restart: () => Promise<void>;
  /** Registered ownership aware helper: `PUT /v1/mcp-servers/<name>` as `label`. */
  register: (label: "reqlift" | "diemcrm", name: string, body: Record<string, unknown>) => Promise<void>;
  baseEnv: Record<string, string>;
}

export const SECURITY_PROMPT_MODEL = "claude-sonnet-4-5";

function write(file: string, content: string): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content);
}

/**
 * The rig: markers in every place the Story names (both gateway keys, the provider key or the OAuth file's access and
 * refresh tokens, a registered http server's header replaced by a per-user override, an SSE header, a stdio env and
 * args value, request-body server header and env, the caller's gateway key as the webhook bearer, an ssh key, a token
 * clone URL, planted links, a legacy transcript, a state file), recording doubles for every upstream, and a scripted
 * model. Everything is cleaned through `cleanups`.
 */
export async function createRig(cleanups: Cleanup[], options: RigOptions = {}): Promise<SecurityRig> {
  const markers = options.markers ?? createMarkers();
  const v = markers.values;
  const keys = { reqlift: v.gatewayKeyReqlift, diemcrm: v.gatewayKeyDiemcrm };
  const scripts: ExactToolScript[] = [];
  const api = await startFakeAnthropicApi({ toolName: "unused-7677", exactTool: scripts });
  cleanups.push(() => api.close());
  const jira = await startOAuthMcpStub({ toolNames: ["get_page", "update_page"] });
  cleanups.push(() => jira.close());
  const feed = await startSseMcpStub({ toolNames: ["lookup_record", "delete_record"] });
  cleanups.push(() => feed.close());
  const reqHttp = await startOAuthMcpStub({ toolNames: ["get_page"] });
  cleanups.push(() => reqHttp.close());
  const webhook = await startCountingDouble();
  cleanups.push(() => webhook.close());
  const otherOrigin = await startCountingDouble();
  cleanups.push(() => otherOrigin.close());
  const tokenDouble = await startTokenDouble();
  cleanups.push(() => tokenDouble.close());
  const remoteRoot = fs.mkdtempSync(path.join(os.tmpdir(), "mvp7677-remote-"));
  cleanups.push(() => fs.rmSync(remoteRoot, { recursive: true, force: true }));
  const realGit = execFileSync("sh", ["-c", "command -v git"], { encoding: "utf8" }).trim();
  const remote = await startDumbHttpGitRemote(remoteRoot, realGit);
  cleanups.push(() => remote.close());
  void createBareRepo;
  markers.values.cloneToken = remote.token;

  const baseEnv: Record<string, string> = {
    API_KEYS: `reqlift:${keys.reqlift},diemcrm:${keys.diemcrm}`,
    ANTHROPIC_BASE_URL: api.baseUrl,
    // The provider's OAuth token endpoint stays a local address in every mode, so a refresh can never leave the host.
    MODEL_PROXY_OAUTH_TOKEN_URL: tokenDouble.url,
    DISABLE_TELEMETRY: "1",
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
    LOG_LEVEL: options.logLevel ?? "info",
    ...((options.mode ?? "api-key") === "api-key" ? { ANTHROPIC_API_KEY: v.providerApiKey } : {}),
  };
  const gatewayEnv = { ...baseEnv, ...options.env };

  let output = "";
  const track = (gateway: SpawnedGateway): SpawnedGateway => {
    gateway.child.stdout!.on("data", (data: Buffer) => (output += data.toString("utf8")));
    gateway.child.stderr!.on("data", (data: Buffer) => (output += data.toString("utf8")));
    output += gateway.output();
    return gateway;
  };

  const gateway = track(
    await spawnGateway(cleanups, {
      rootPrefix: options.rootPrefix ?? "mvp7677-sec-",
      env: gatewayEnv,
      distServer: options.distServer,
      fakeGitBin: options.fakeGitBin,
      seed: (dirs) => {
        const ws = dirs.workspace;
        write(path.join(ws, ".credentials.json"), JSON.stringify({ claudeAiOauth: { accessToken: v.oauthAccess, refreshToken: v.oauthRefresh, expiresAt: Date.now() + ((options.mode ?? "api-key") === "oauth" ? 1000 : 3_600_000) } }));
        write(path.join(dirs.home, ".ssh", "id_rsa"), `-----BEGIN RSA PRIVATE KEY-----\n${v.sshKey}\n-----END RSA PRIVATE KEY-----\n`);
        write(path.join(dirs.home, ".config", "gh", "hosts.yml"), `github.com:\n  oauth_token: ${v.githubToken}\n`);
        write(path.join(ws, "notes-state.json"), JSON.stringify({ note: v.stateFile }));
        write(path.join(ws, "CLAUDE.md"), "GLOBAL-MEMORY-OK");
        write(path.join(ws, "skills", "ok", "SKILL.md"), "---\nname: ok\ndescription: a harmless global skill\n---\nSKILL-OK");
        write(path.join(ws, "agents", "reviewer.md"), "---\nname: reviewer\ndescription: a harmless configured agent\n---\nYou review things. AGENT-OK");
        // A repository whose configuration holds a token clone URL.
        write(path.join(ws, "projects", "repo", "src", "main.txt"), "REPO-OK");
        const git = (...args: string[]): void => {
          execFileSync(realGit, ["-C", path.join(ws, "projects", "repo"), ...args], {
            env: { PATH: process.env.PATH ?? "", HOME: dirs.home, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@example.test", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@example.test" },
            stdio: "ignore",
          });
        };
        git("init", "-q", "-b", "main");
        git("add", ".");
        git("commit", "-q", "-m", "init");
        git("remote", "add", "origin", `https://x-access-token:${remote.token}@github.com/acme/repo.git`);
        // Links and copies planted before the update.
        fs.symlinkSync(path.join(ws, ".credentials.json"), path.join(ws, "skills", "to-credentials"));
        fs.symlinkSync("../.credentials.json", path.join(ws, "skills", "to-credentials-relative"));
        fs.symlinkSync(dirs.home, path.join(ws, "projects", "linked-home"));
        fs.linkSync(path.join(ws, ".credentials.json"), path.join(ws, "skills", "hardlinked-credentials"));
        write(path.join(ws, "memory", "copy.md"), `copied ${v.oauthAccess}`);
        // A legacy conversation and its credential-bearing transcript.
        write(path.join(ws, "projects", "-home-node", "sdk-legacy.jsonl"), JSON.stringify({ note: v.legacyTranscript }));
        write(
          path.join(dirs.persist, "sessions.json"),
          JSON.stringify({ sessions: { "legacy-conv": { sessionId: "gw-legacy", sdkSessionId: "sdk-legacy", systemPrompt: "", model: "m", lastUsed: Date.now() } }, settings: { sessionIdleTimeoutMs: 0 } }),
        );
        options.seed?.(dirs, markers);
      },
    }),
  );

  const rig: SecurityRig = {
    markers,
    keys,
    api,
    gateway,
    scripts,
    jira,
    feed,
    reqHttp,
    webhook,
    otherOrigin,
    tokenDouble,
    remote,
    log: () => output,
    baseEnv,
    ask: (label, body, deadlineMs) => queryAs(rig.gateway.port, keys[label], body, deadlineMs),
    register: async (label, name, body) => {
      const put = await gatewayRequest(rig.gateway.port, "PUT", `/v1/mcp-servers/${name}`, body, keys[label]);
      if (put.status !== 201 && put.status !== 200) throw new Error(`registering ${name} as ${label} answered ${put.status}`);
    },
    restart: async () => {
      const old = rig.gateway;
      old.child.kill("SIGTERM");
      await new Promise<void>((resolve) => (old.child.exitCode !== null || old.child.signalCode !== null ? resolve() : old.child.once("exit", () => resolve())));
      rig.gateway = track(await spawnGateway(cleanups, { reuse: old, env: gatewayEnv, distServer: options.distServer, fakeGitBin: options.fakeGitBin }));
    },
  };
  return rig;
}

/** Registers the standard doubles the way the callers do: reqlift owns `jira`, diemcrm owns `feed`; both register a webhook tool. */
export async function registerStandardServers(rig: SecurityRig): Promise<void> {
  const v = rig.markers.values;
  await rig.register("reqlift", "jira", { type: "http", url: rig.jira.url, headers: { Authorization: `Basic ${v.registryHttpHeader}` } });
  await rig.register("diemcrm", "feed", { type: "sse", url: rig.feed.url, headers: { "X-Api-Key": v.sseHeader } });
  await rig.register("reqlift", "local", { type: "stdio", command: "node", args: ["-e", STDIO_SOURCE, v.stdioArgs], env: { SERVER_TOKEN: v.stdioEnv } });
  const tool = await gatewayRequest(
    rig.gateway.port,
    "PUT",
    "/v1/tools/probe_read",
    { description: "probe", input_schema: { type: "object", properties: {} }, webhook_url: `${rig.webhook.base}/probe_read` },
    rig.keys.reqlift,
  );
  if (tool.status >= 300) throw new Error(`registering the webhook tool answered ${tool.status}`);
  await new Promise((resolve) => setTimeout(resolve, 300));
}

/** The request-scoped credentials every route-probe run carries (per-user override, request-body http header and stdio env). */
export function requestCredentials(rig: SecurityRig): Record<string, unknown> {
  const v = rig.markers.values;
  return {
    mcpCredentialOverrides: { jira: { headers: { authorization: `Bearer ${v.userOverrideHeader}` } } },
    mcpServers: {
      reqhttp: { type: "http", url: rig.reqHttp.url, headers: { Authorization: `Bearer ${v.requestHttpHeader}` } },
      reqlocal: { command: "node", args: ["-e", STDIO_SOURCE], env: { SERVER_TOKEN: v.requestStdioEnv } },
    },
  };
}

/** Spawns a child with stdio piped, returning its collected output; used by the negative control. */
export function runChild(argv: string[], env: NodeJS.ProcessEnv, cwd: string, deadlineMs: number): Promise<{ code: number | null; output: string; timedOut: boolean }> {
  return new Promise((resolve) => {
    const child = spawn(argv[0], argv.slice(1), { cwd, env, stdio: ["ignore", "pipe", "pipe"], detached: true });
    let output = "";
    let timedOut = false;
    child.stdout!.on("data", (data: Buffer) => (output += data.toString("utf8")));
    child.stderr!.on("data", (data: Buffer) => (output += data.toString("utf8")));
    const timer = setTimeout(() => {
      timedOut = true;
      try {
        process.kill(-child.pid!, "SIGKILL");
      } catch {
        // Already gone.
      }
    }, deadlineMs);
    child.on("exit", (code) => {
      clearTimeout(timer);
      resolve({ code, output, timedOut });
    });
  });
}
