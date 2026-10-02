/**
 * Outcome Probe for MVP-7919: "content an agent planted before the isolation update cannot reach a run,
 * whatever its size, while clean content of every size stays available".
 *
 * The compiled gateway runs as a child process with the production Claude runtime and real bwrap (no mock of the
 * scanner or the sandbox). Before it starts, a fixture plants synthetic markers for every row of the acceptance
 * table in a mounted global directory (`memory/`) and in a repository under `projects/`: a known service credential
 * (an `API_KEYS` key) in a 2 MiB file, an SSH private key (the gateway's own `$HOME/.ssh` key) and registered
 * webhook URL credentials (query token, path token, user-info password), each under and over 1 MiB with the marker
 * placed after the first MiB in the large files, plus a 2 MiB global `CLAUDE.md` holding the known credential, a clean
 * small file and a clean 2 MiB file, each with a clean sentinel. A scripted ordinary chat then lists, `tail`s, greps
 * and reads every planted path. Observation: the raw tool results, the model-bound request bodies (which carry the
 * `CLAUDE.md` text), the NDJSON events, the gateway log and the conversations' own homes (transcripts). Assertion:
 * every marker has 0 matches on every surface, every planted file is an empty stand-in, and the clean sentinels ARE
 * in the tool results. Per surface, a deliberately leaking run proves the same detector reports a hit.
 *
 * `SCAN_RESIDUALS_DIST` points the spawned gateway at another compiled `server.js` (the red run against the
 * revision before the fix); without it the repository's `dist/` is used.
 *
 * Needs `npm run build`, `bwrap` and user namespaces. Linux only. Only case names and counts are printed
 * (`SCAN-RESIDUALS-MATRIX ...`); never a marker value.
 */
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { startFakeAnthropicApi, type ExactToolScript, type FakeAnthropicApi } from "./helpers/fake-anthropic-api.js";
import { spawnGateway, type Cleanup, type SpawnedGateway } from "./helpers/git-process-gateway.js";

vi.setConfig({ testTimeout: 240_000 });

const MiB = 1024 * 1024;

const KEY_ALPHA = "SYNTH-API-KEY-ALPHA-7919";
const KEY_BETA = "SYNTH-API-KEY-BETA-7919";
const PROVIDER_KEY = "SYNTH-PROVIDER-KEY-7919";

const keyLine = (n: number): string => `SYNTHSSHPRIVATEKEY7919BODY${n}`.padEnd(64, "QWErty123456");
const SSH_LINES = [keyLine(1), keyLine(2), keyLine(3)];
const SSH_KEY_TEXT = `-----BEGIN OPENSSH PRIVATE KEY-----\n${SSH_LINES.join("\n")}\n-----END OPENSSH PRIVATE KEY-----\n`;

const WEBHOOK_QUERY_TOKEN = "SYNTH-WEBHOOK-QUERY-7919-abcdef";
const WEBHOOK_PATH_TOKEN = "SYNTH-WEBHOOK-PATH-7919-abcdef";
const WEBHOOK_PASSWORD = "SYNTH-WEBHOOK-PASS-7919";
const WEBHOOK_URLS = [
  `https://hooks.example.test/api/v1/notify?token=${WEBHOOK_QUERY_TOKEN}`,
  `https://hooks.example.test/services/${WEBHOOK_PATH_TOKEN}/deliver`,
  `https://synthuser7919:${WEBHOOK_PASSWORD}@hooks.example.test/hook`,
];

/** Every marker: each must have 0 matches on every agent-side surface. */
const MARKERS: Record<string, string> = {
  knownCredential: KEY_ALPHA,
  sshLine1: SSH_LINES[0],
  sshLine2: SSH_LINES[1],
  sshLine3: SSH_LINES[2],
  webhookQuery: WEBHOOK_QUERY_TOKEN,
  webhookPath: WEBHOOK_PATH_TOKEN,
  webhookPassword: WEBHOOK_PASSWORD,
};

interface Row {
  id: string;
  /** What the file holds. */
  content: "credential" | "ssh" | "webhook" | "clean";
  size: number;
}

/** One file per acceptance row, plus the clean controls. */
const ROWS: Row[] = [
  { id: "credential-2MiB", content: "credential", size: 2 * MiB },
  { id: "ssh-under", content: "ssh", size: 8 * 1024 },
  { id: "ssh-over", content: "ssh", size: 2 * MiB },
  { id: "webhook-under", content: "webhook", size: 8 * 1024 },
  { id: "webhook-over", content: "webhook", size: 2 * MiB },
  { id: "clean-small", content: "clean", size: 8 * 1024 },
  { id: "clean-large", content: "clean", size: 2 * MiB },
];

const tailSentinel = (row: Row): string => `TAIL-SENTINEL-${row.id}-7919`;

/** Line-oriented filler, then the payload after at least `size - 1 KiB` bytes, then the clean sentinel. */
function fileFor(row: Row): string {
  const payload =
    row.content === "credential"
      ? `export SERVICE_KEY=${KEY_ALPHA}\n`
      : row.content === "ssh"
        ? SSH_KEY_TEXT
        : row.content === "webhook"
          ? WEBHOOK_URLS.map((url) => `curl -X POST ${url}\n`).join("")
          : "no secret here\n";
  const tail = `${tailSentinel(row)}\n`;
  const lines: string[] = [];
  let bytes = 0;
  const target = row.size - payload.length - tail.length;
  for (let i = 0; bytes < target; i++) {
    const line = `filler line ${String(i).padStart(8, "0")} ${"lorem ipsum dolor sit amet ".repeat(3)}`.slice(0, 79);
    lines.push(line);
    bytes += line.length + 1;
  }
  return `${lines.join("\n")}\n${payload}${tail}`;
}

const GLOBAL_DIR = "memory/planted";
const REPO_DIR = "projects/repo/planted";
const SANDBOX_GLOBAL = "/home/node/.claude/memory/planted";
const SANDBOX_REPO = "/home/node/.claude/projects/repo/planted";

const cleanups: Cleanup[] = [];
afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()!();
});

/** One evidence line (case names and counts only). Written to stderr, which the runner log keeps for passing tests. */
function report(line: string): void {
  process.stderr.write(`${line}\n`);
}

interface Surface {
  name: string;
  text: string;
}

/** The detector: which (surface, marker) pairs match. */
function detect(surfaces: Surface[], markers: Record<string, string> = MARKERS): string[] {
  const hits: string[] = [];
  for (const surface of surfaces) {
    for (const [name, value] of Object.entries(markers)) if (surface.text.includes(value)) hits.push(`${surface.name}:${name}`);
  }
  return hits;
}

interface Ndjson {
  type: string;
  content?: string;
  [key: string]: unknown;
}

function queryAs(port: number, key: string, body: Record<string, unknown>): Promise<Ndjson[]> {
  return new Promise((resolve, reject) => {
    const payload = Buffer.from(JSON.stringify({ model: "claude-sonnet-4-5", ...body }), "utf8");
    const req = http.request(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/query", agent: false, headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json", "Content-Length": payload.length } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve(
            Buffer.concat(chunks)
              .toString("utf8")
              .split("\n")
              .filter((l) => l.trim().startsWith("{"))
              .map((l) => JSON.parse(l) as Ndjson),
          ),
        );
      },
    );
    req.on("error", reject);
    req.end(payload);
  });
}

function write(file: string, content: string): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content);
}

function requestsFor(api: FakeAnthropicApi, prompt: string) {
  return api.requests.filter((r) => r.userTexts.some((t) => t.includes(prompt)));
}

/** The tool results of the latest turn of the conversation whose latest prompt is `prompt`. */
function lastResults(api: FakeAnthropicApi, prompt: string): string[] {
  const matching = api.requests.filter((r) => r.userTexts.at(-1)?.includes(prompt) && !r.warmup);
  return (matching.at(-1)?.toolResults ?? []).map((r) => r.text);
}

function conversationHomes(gateway: SpawnedGateway, onlyFor: string[]): string[] {
  const saved = JSON.parse(fs.readFileSync(path.join(gateway.dirs.persist, "sessions.json"), "utf8")) as {
    sessions?: Record<string, { sandboxDirId?: string }>;
    sessionsByLabel?: Record<string, Record<string, { sandboxDirId?: string }>>;
  };
  const entryFor = (id: string): { sandboxDirId?: string } | undefined => {
    for (const entries of Object.values(saved.sessionsByLabel ?? {})) if (entries[id]) return entries[id];
    return saved.sessions?.[id];
  };
  return onlyFor.flatMap((id) => {
    const dirId = entryFor(id)?.sandboxDirId;
    if (!dirId) return [];
    const sessionDir = path.join(gateway.dirs.home, ".agent-sandbox", "sessions", dirId);
    return [path.join(sessionDir, "home"), path.join(sessionDir, "work")];
  });
}

function homeText(home: string): string {
  let text = "";
  const walk = (dir: string): void => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile() && fs.statSync(full).size < 4 * MiB) text += `\n${fs.readFileSync(full, "utf8")}`;
    }
  };
  walk(home);
  return text;
}

const bash = (prompt: string, command: string): ExactToolScript => ({ name: "Bash", prompt, input: { command, description: "probe" } });
const read = (prompt: string, file: string): ExactToolScript => ({ name: "Read", prompt, input: { file_path: file } });

interface Fixture {
  api: FakeAnthropicApi;
  gateway: SpawnedGateway;
  scripts: ExactToolScript[];
}

/** The fixture gateway: every planted row in a global directory and a repository, the SSH key and the webhook tools. */
async function fixture(routeScripts: ExactToolScript[], options: { claudeMd?: "planted" | "none"; env?: Record<string, string> } = {}): Promise<Fixture> {
  const scripts: ExactToolScript[] = [...routeScripts];
  const api = await startFakeAnthropicApi({ toolName: "unused-7919", exactTool: scripts });
  cleanups.push(() => api.close());
  const gateway = await spawnGateway(cleanups, {
    rootPrefix: "mvp7919-scan-",
    distServer: process.env.SCAN_RESIDUALS_DIST || undefined,
    env: {
      API_KEYS: `alpha:${KEY_ALPHA},beta:${KEY_BETA}`,
      ANTHROPIC_BASE_URL: api.baseUrl,
      ANTHROPIC_API_KEY: PROVIDER_KEY,
      DISABLE_TELEMETRY: "1",
      CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
      ...options.env,
    },
    seed: (dirs) => {
      write(path.join(dirs.home, ".ssh", "id_ed25519"), SSH_KEY_TEXT);
      fs.chmodSync(path.join(dirs.home, ".ssh", "id_ed25519"), 0o600);
      write(
        path.join(dirs.persist, "tools.json"),
        JSON.stringify(
          WEBHOOK_URLS.map((webhook_url, i) => ({ name: `hook${i}`, description: "synthetic webhook tool", input_schema: { type: "object", properties: {} }, webhook_url, timeout_ms: 5000, owner: "alpha" })),
        ),
      );
      for (const row of ROWS) {
        const text = fileFor(row);
        write(path.join(dirs.workspace, GLOBAL_DIR, `${row.id}.txt`), text);
        write(path.join(dirs.workspace, REPO_DIR, `${row.id}.txt`), text);
      }
      write(path.join(dirs.workspace, "projects", "repo", "README.md"), "REPO-OK");
      if (options.claudeMd !== "none") {
        write(path.join(dirs.workspace, "CLAUDE.md"), `${"global instruction line\n".repeat(90_000)}export SERVICE_KEY=${KEY_ALPHA}\nCLAUDE-TAIL-7919\n`);
      }
    },
  });
  return { api, gateway, scripts };
}

const PROMPTS = {
  list: "SCAN-LIST",
  tailGlobal: "SCAN-TAIL-GLOBAL",
  tailRepo: "SCAN-TAIL-REPO",
  grep: "SCAN-GREP",
  readSmall: "SCAN-READ-SMALL",
  readClaudeMd: "SCAN-READ-CLAUDEMD",
};

/** `wc -c` and the last two lines of every row's file in one directory. */
function tailCommand(dir: string): string {
  return ROWS.map((row) => `echo "== ${row.id}"; wc -c < ${dir}/${row.id}.txt; tail -n 2 ${dir}/${row.id}.txt`).join("; ");
}

/** The scripted ordinary chat: it reaches every planted path in every ordinary way. */
function chatScripts(): ExactToolScript[] {
  return [
    bash(PROMPTS.list, `ls -l ${SANDBOX_GLOBAL} ${SANDBOX_REPO}; wc -c /home/node/.claude/CLAUDE.md`),
    bash(PROMPTS.tailGlobal, tailCommand(SANDBOX_GLOBAL)),
    bash(PROMPTS.tailRepo, tailCommand(SANDBOX_REPO)),
    bash(
      PROMPTS.grep,
      "grep -rah --binary-files=text -e 'SYNTH-API-KEY-ALPH[A]-7919' -e 'SYNTHSSHPRIVATEKEY7919BOD[Y]' -e 'SYNTH-WEBHOOK-[A-Z]*-7919' /home/node/.claude /work 2>&1; cat /home/node/.claude/memory/planted/* /home/node/.claude/projects/repo/planted/* 2>&1 | grep -a -c 'SYNTH'",
    ),
    read(PROMPTS.readSmall, `${SANDBOX_GLOBAL}/ssh-under.txt`),
    read(PROMPTS.readClaudeMd, "/home/node/.claude/CLAUDE.md"),
  ];
}

const CHAT_PROMPTS = Object.values(PROMPTS);

function surfacesOf(f: Fixture, events: Record<string, Ndjson[]>, prompts: string[], conversationIds: string[]): Surface[] {
  const requests = f.api.requests.filter((q) => q.userTexts.some((text) => prompts.some((p) => text.includes(p))));
  return [
    { name: "tool-results", text: requests.flatMap((q) => q.toolResults.map((r) => r.text)).join("\n") },
    { name: "model-requests", text: requests.map((q) => q.body).join("\n") },
    { name: "events", text: JSON.stringify(Object.values(events)) },
    { name: "gateway-log", text: f.gateway.output() },
    { name: "transcripts", text: conversationHomes(f.gateway, conversationIds).map(homeText).join("\n") },
  ];
}

describe("the Outcome Probe: planted credentials of every size stay unreadable, clean content stays available", () => {
  it("an ordinary chat that reads every planted path gets no marker on any surface and the clean sentinels", async () => {
    const f = await fixture(chatScripts(), { env: { LOG_LEVEL: "debug" } });
    const events: Record<string, Ndjson[]> = {};
    for (const prompt of CHAT_PROMPTS) {
      const result = await queryAs(f.gateway.port, KEY_ALPHA, { queryId: `q-${prompt}`, sessionId: `conv-${prompt}`, prompt, user_id: "user-1", useSession: true });
      events[prompt] = result;
      expect(result.at(-1)?.type, `${prompt}: ${JSON.stringify(result.at(-1))}`).toBe("done");
    }

    // Accessible control: every clean file is there with its sentinel, and the planted rows are empty stand-ins.
    // Every row is judged before anything is asserted, so a red run names all failing rows, not only the first.
    const rowVerdicts: Record<string, boolean> = {};
    for (const prompt of [PROMPTS.tailGlobal, PROMPTS.tailRepo]) {
      const text = lastResults(f.api, prompt)[0] ?? "";
      const location = prompt === PROMPTS.tailGlobal ? "global" : "repository";
      for (const row of ROWS) {
        const section = new RegExp(`^== ${row.id}\\n(\\d+)\\n([\\s\\S]*?)(?=^== |(?![\\s\\S]))`, "m").exec(text);
        const size = section ? Number(section[1]) : -1;
        const tail = section ? section[2] : "";
        rowVerdicts[`${location}:${row.id}`] =
          row.content === "clean" ? size === Buffer.byteLength(fileFor(row)) && tail.includes(tailSentinel(row)) : size === 0 && tail.trim() === "";
      }
    }
    // The 2 MiB global CLAUDE.md is hidden too.
    rowVerdicts["global:CLAUDE.md-2MiB"] = /^0 \/home\/node\/\.claude\/CLAUDE\.md$/m.test(lastResults(f.api, PROMPTS.list)[0] ?? "");

    const surfaces = surfacesOf(f, events, CHAT_PROMPTS, CHAT_PROMPTS.map((p) => `conv-${p}`));
    const hits = detect(surfaces);
    const failingRows = Object.entries(rowVerdicts).filter(([, ok]) => !ok).map(([name]) => name);
    report(`SCAN-RESIDUALS-MATRIX ${JSON.stringify({ surfaces: surfaces.map((s) => ({ surface: s.name, bytes: s.text.length })), markers: Object.keys(MARKERS).length, rows: ROWS.length, locations: 2, rowChecks: Object.keys(rowVerdicts).length, rowsFailing: failingRows, cleanRows: ROWS.filter((r) => r.content === "clean").length * 2, hits: hits.length, hitPairs: hits })}`);
    expect(failingRows).toEqual([]);
    expect(hits).toEqual([]);
    // Every surface is non-trivial (the detector looked at something).
    for (const surface of surfaces) expect(surface.text.length, surface.name).toBeGreaterThan(200);
    // The audit lines name the hidden entries and reasons, never a value.
    expect(f.gateway.output()).toMatch(/sandbox\.content\.skipped kind=global name=CLAUDE\.md reason=known_value/);
    expect(f.gateway.output()).toMatch(/sandbox\.content\.skipped kind=global name=memory reason=known_value/);
    expect(f.gateway.output()).toMatch(/sandbox\.content\.skipped kind=repo name=repo reason=known_value/);
  });
});

describe("the detector", () => {
  it("catches a marker on any surface, and only that marker", () => {
    expect(detect([{ name: "x", text: "clean" }])).toEqual([]);
    expect(detect([{ name: "x", text: `prefix ${WEBHOOK_PATH_TOKEN} suffix` }, { name: "y", text: "clean" }])).toEqual(["x:webhookPath"]);
  });

  it("negative control: a run that deliberately prints every marker is caught on each surface it reaches", async () => {
    const leak = `echo ${KEY_ALPHA}; echo ${SSH_LINES.join("; echo ")}; echo ${WEBHOOK_QUERY_TOKEN}; echo ${WEBHOOK_PATH_TOKEN}; echo ${WEBHOOK_PASSWORD}`;
    const f = await fixture([bash("SCAN-LEAK", leak)], { claudeMd: "none", env: { LOG_LEVEL: "debug" } });
    const events = { leak: await queryAs(f.gateway.port, KEY_ALPHA, { queryId: "q-leak", sessionId: "conv-leak", prompt: "SCAN-LEAK", user_id: "user-1", useSession: true }) };
    expect(events.leak.at(-1)?.type, JSON.stringify(events.leak.at(-1))).toBe("done");
    const surfaces = surfacesOf(f, events, ["SCAN-LEAK"], ["conv-leak"]);
    const hits = detect(surfaces);
    // Tool results, model-bound requests and transcripts carry the printed output; every marker is found there.
    for (const surface of ["tool-results", "model-requests", "transcripts"]) {
      for (const marker of Object.keys(MARKERS)) expect(hits, `${surface}:${marker}`).toContain(`${surface}:${marker}`);
    }
    // The events and the debug-level gateway log carry the printed command or output too: each surface has at least one hit.
    for (const surface of ["events", "gateway-log"]) expect(hits.some((h) => h.startsWith(`${surface}:`)), surface).toBe(true);
    report(`SCAN-RESIDUALS-NEGATIVE-CONTROL ${JSON.stringify({ reached: [...new Set(hits.map((h) => h.split(":")[0]))], hits: hits.length })}`);
  });
});
