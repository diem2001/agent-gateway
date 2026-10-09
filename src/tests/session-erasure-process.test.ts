/**
 * Erasure of a deleted conversation through the compiled gateway, the real Claude runtime and real bwrap
 * (MVP-7402, Gate C): the operator outcome (HTTP answer, a listing of the sessions directory, a byte search for the
 * uploaded image), a failed first turn, content the agent planted (links to host files, a tree deeper than PATH_MAX,
 * unreadable directories), a delete while a run is in progress (503, blocked conversation, the gateway finishes the
 * erasure when the run ends, also across a restart), a file system error and a restart, idle expiry, the late-retry
 * answers, a seeded legacy store and the ownership rows. The model is a scripted stand-in; every secret is synthetic.
 * Fixtures outside the gateway's own directories live under `/tmp/mvp7402-*` and are removed by literal path.
 *
 * Needs `npm run build`, `bwrap` and user namespaces. Linux only.
 */
import { execFileSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { deflateSync } from "node:zlib";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { startFakeAnthropicApi, type ExactToolScript, type FakeAnthropicApi, type FakeApiMode } from "./helpers/fake-anthropic-api.js";
import { descendants, killGatewayGroup, spawnGateway, type Cleanup, type SpawnedGateway } from "./helpers/git-process-gateway.js";

vi.setConfig({ testTimeout: 240_000, hookTimeout: 60_000 });

const KEY_ALPHA = "SYNTH-ALPHA-API-KEY-7402";
const KEY_BETA = "SYNTH-BETA-API-KEY-7402";
const PROVIDER_KEY = "SYNTH-PROVIDER-KEY-7402";
const ERASING_TEXT = "This conversation is being deleted. Its content is erased as soon as the gateway can finish, so it cannot be used any more. Please start a new conversation.";
const LEGACY_TEXT = "This conversation was started before a gateway security update and cannot be continued safely. Please start a new conversation. Retrying will not help.";
const CRC_TABLE = Array.from({ length: 256 }, (_v, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});

function crc32(data: Buffer): number {
  let c = 0xffffffff;
  for (const byte of data) c = CRC_TABLE[(c ^ byte) & 0xff]! ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/** A valid 16x16 PNG with random pixels: the runtime accepts it as it is, and its base64 text is unique to this run. */
function randomPng(): Buffer {
  const chunk = (type: string, data: Buffer): Buffer => {
    const body = Buffer.concat([Buffer.from(type, "latin1"), data]);
    const length = Buffer.alloc(4);
    length.writeUInt32BE(data.length);
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(crc32(body));
    return Buffer.concat([length, body, crc]);
  };
  const size = 16;
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr.set([8, 2, 0, 0, 0], 8);
  const rows = Array.from({ length: size }, () => Buffer.concat([Buffer.from([0]), randomBytes(size * 3)]));
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk("IHDR", ihdr), chunk("IDAT", deflateSync(Buffer.concat(rows))), chunk("IEND", Buffer.alloc(0))]);
}

const IMAGE_B64 = randomPng().toString("base64");
const DIR_C = "c0c0c0c0c0c0c0c0c0c0c0c0";
const DIR_O = "0f0f0f0f0f0f0f0f0f0f0f0f";
const DIR_B = "b0b0b0b0b0b0b0b0b0b0b0b0";

/** `ERASURE_PROCESS_DIST` points the rows at another compiled server (the red run against the baseline). */
const DIST = process.env.ERASURE_PROCESS_DIST;

const cleanups: Cleanup[] = [];
const scratch: string[] = [];
afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()!();
  // Whatever a failed assertion left unreadable is made readable before the fixture goes (literal /tmp/mvp7402-* roots).
  for (const dir of scratch.splice(0)) {
    try {
      execFileSync("/usr/bin/chmod", ["-R", "u+rwx", "--", dir], { stdio: "ignore" });
    } catch {
      // Gone already.
    }
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

interface Ndjson {
  type: string;
  content?: string;
  [key: string]: unknown;
}

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

async function until(what: string, condition: () => boolean, timeoutMs = 30_000): Promise<void> {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    if (condition()) return;
    await sleep(100);
  }
  throw new Error(`timed out waiting for: ${what}`);
}

/** The last lines the gateway wrote, for an assertion message. */
const tail = (g: SpawnedGateway): string => g.output().split("\n").slice(-25).join("\n");

function parseEvents(text: string): Ndjson[] {
  return text.split("\n").filter((l) => l.trim().startsWith("{")).map((l) => JSON.parse(l) as Ndjson);
}

/** POST /v1/query; `req` lets a test drop the connection (the gateway then stops the run). */
function startQuery(port: number, key: string, body: Record<string, unknown>): { req: http.ClientRequest; result: Promise<{ status: number; events: Ndjson[] }> } {
  const payload = Buffer.from(JSON.stringify({ model: "claude-sonnet-4-5", ...body }), "utf8");
  let request!: http.ClientRequest;
  const result = new Promise<{ status: number; events: Ndjson[] }>((resolve, reject) => {
    request = http.request(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/query", agent: false, headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json", "Content-Length": payload.length } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, events: parseEvents(Buffer.concat(chunks).toString("utf8")) }));
        res.on("error", reject);
      },
    );
    request.on("error", reject);
    request.end(payload);
  });
  return { req: request, result };
}

const queryAs = (port: number, key: string, body: Record<string, unknown>): Promise<{ status: number; events: Ndjson[] }> => startQuery(port, key, body).result;

/** A request with a verbatim path: Node's client does not normalize `..`. */
function rawAs(port: number, key: string | null, method: "GET" | "DELETE", urlPath: string): Promise<{ status: number; json: Record<string, unknown> | null }> {
  return new Promise((resolve, reject) => {
    const headers: Record<string, string> = key ? { Authorization: `Bearer ${key}` } : {};
    const req = http.request({ host: "127.0.0.1", port, method, path: urlPath, agent: false, headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => {
        let json: Record<string, unknown> | null = null;
        try {
          json = JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, unknown>;
        } catch {
          // Not JSON.
        }
        resolve({ status: res.statusCode ?? 0, json });
      });
    });
    req.on("error", reject);
    req.end();
  });
}

const del = (g: SpawnedGateway, key: string, id: string) => rawAs(g.port, key, "DELETE", `/v1/sessions/${encodeURIComponent(id)}`);
const health = async (g: SpawnedGateway): Promise<{ sessions: number; erasurePending: number; persistence: string }> => (await rawAs(g.port, null, "GET", "/health")).json as never;

const sandboxRoot = (g: SpawnedGateway["dirs"]): string => path.join(g.home, ".agent-sandbox");
const sessionsDir = (g: SpawnedGateway["dirs"]): string => path.join(sandboxRoot(g), "sessions");
const folderOf = (g: SpawnedGateway, dirId: string): string => path.join(sessionsDir(g.dirs), dirId);

interface StoredEntry {
  sandboxDirId?: string;
  erasePendingSince?: number;
}

function readStore(g: SpawnedGateway): { sessions?: Record<string, StoredEntry>; sessionsByLabel?: Record<string, Record<string, StoredEntry>>; erasedByLabel?: Record<string, Record<string, Record<string, unknown>>> } {
  return JSON.parse(fs.readFileSync(path.join(g.dirs.persist, "sessions.json"), "utf8"));
}

function entryOf(g: SpawnedGateway, label: string, id: string): StoredEntry | undefined {
  return readStore(g).sessionsByLabel?.[label]?.[id];
}

async function dirIdOf(g: SpawnedGateway, label: string, id: string): Promise<string> {
  await until(`sessions.json lists ${label}/${id}`, () => {
    try {
      return entryOf(g, label, id)?.sandboxDirId !== undefined;
    } catch {
      return false;
    }
  }, 15_000);
  return entryOf(g, label, id)!.sandboxDirId!;
}

const gone = (p: string): boolean => {
  try {
    fs.lstatSync(p);
    return false;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "ENOENT";
  }
};

/** Regular files below `dir` that contain `needle`; links and special files are not followed or read. */
function filesWith(dir: string, needle: string): string[] {
  const hits: string[] = [];
  if (gone(dir)) return hits;
  const walk = (d: string): void => {
    for (const entry of fs.readdirSync(d, { withFileTypes: true })) {
      const full = path.join(d, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile() && fs.readFileSync(full, "latin1").includes(needle)) hits.push(full);
    }
  };
  walk(dir);
  return hits;
}

/** Regular files below `dir` with their sizes, for an assertion message. */
function listing(dir: string): string {
  const out: string[] = [];
  const walk = (d: string): void => {
    for (const entry of fs.readdirSync(d, { withFileTypes: true })) {
      const full = path.join(d, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile()) out.push(`${path.relative(dir, full)} ${fs.statSync(full).size}`);
    }
  };
  if (!gone(dir)) walk(dir);
  return out.join("; ");
}

/** Every path below `dir` with mode and the SHA-256 of regular files (links are listed, not followed). */
function snapshot(dir: string): string[] {
  const out: string[] = [];
  const walk = (p: string): void => {
    const st = fs.lstatSync(p);
    const rel = path.relative(dir, p) || ".";
    if (st.isSymbolicLink()) out.push(`${rel} -> ${fs.readlinkSync(p)}`);
    else if (st.isDirectory()) {
      out.push(`${rel}/ ${(st.mode & 0o777).toString(8)}`);
      for (const name of fs.readdirSync(p).sort()) walk(path.join(p, name));
    } else if (st.isFile()) out.push(`${rel} ${(st.mode & 0o777).toString(8)} ${createHash("sha256").update(fs.readFileSync(p)).digest("hex")}`);
    else out.push(`${rel} special`);
  };
  walk(dir);
  return out;
}

const bash = (prompt: string, command: string): ExactToolScript => ({ name: "Bash", prompt, input: { command, description: "probe" } });

const GATEWAY_ENV = (api: FakeAnthropicApi | null, extra: Record<string, string> = {}): Record<string, string> => ({
  API_KEYS: `alpha:${KEY_ALPHA},beta:${KEY_BETA}`,
  ...(api ? { ANTHROPIC_BASE_URL: api.baseUrl } : {}),
  ANTHROPIC_API_KEY: PROVIDER_KEY,
  DISABLE_TELEMETRY: "1",
  CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
  ...extra,
});

interface Rig {
  api: FakeAnthropicApi;
  gateway: SpawnedGateway;
  env: Record<string, string>;
}

async function rig(options: { mode?: FakeApiMode; scripts?: ExactToolScript[]; env?: Record<string, string>; seed?: (dirs: SpawnedGateway["dirs"]) => void } = {}): Promise<Rig> {
  const api = await startFakeAnthropicApi({ toolName: "unused-7402", mode: options.mode, exactTool: options.scripts ?? [] });
  cleanups.push(() => api.close());
  const env = GATEWAY_ENV(api, options.env);
  const gateway = await spawnGateway(cleanups, { rootPrefix: "mvp7402-gw-", env, seed: options.seed, distServer: DIST });
  return { api, gateway, env };
}

/** A gateway without a model stand-in: for rows that never start a run. */
async function bareGateway(options: { env?: Record<string, string>; seed?: (dirs: SpawnedGateway["dirs"]) => void; detached?: boolean } = {}): Promise<SpawnedGateway> {
  return spawnGateway(cleanups, { rootPrefix: "mvp7402-gw-", env: GATEWAY_ENV(null, options.env), seed: options.seed, distServer: DIST, detached: options.detached });
}

async function restart(old: SpawnedGateway, env: Record<string, string>): Promise<SpawnedGateway> {
  old.child.kill("SIGTERM");
  await new Promise<void>((resolve) => (old.child.exitCode !== null ? resolve() : old.child.once("exit", () => resolve())));
  return spawnGateway(cleanups, { reuse: old, env, distServer: DIST });
}

function fixtureDir(): string {
  const dir = fs.mkdtempSync("/tmp/mvp7402-");
  fs.chmodSync(dir, 0o700);
  scratch.push(dir);
  return dir;
}

/** A conversation folder written by hand: a transcript with the image, a work file. */
function handFolder(dirs: SpawnedGateway["dirs"], dirId: string, marker: string): void {
  const dir = path.join(sessionsDir(dirs), dirId);
  fs.mkdirSync(path.join(dir, "home", ".claude", "projects", "-work"), { recursive: true });
  fs.mkdirSync(path.join(dir, "work"), { recursive: true });
  fs.writeFileSync(path.join(dir, "home", ".claude", "projects", "-work", "t.jsonl"), `${marker} ${IMAGE_B64}\n`);
  fs.writeFileSync(path.join(dir, "work", "note.txt"), `${marker} work file\n`);
}

const ownedEntry = (label: string, dirId: string, extra: Record<string, unknown> = {}): Record<string, unknown> => ({
  sessionId: "gw-session",
  sdkSessionId: "sdk-session",
  systemPrompt: "",
  model: "m",
  lastUsed: Date.now(),
  owner: { label, userId: null },
  sandboxDirId: dirId,
  ...extra,
});

/** The trusted storage root with its private sessions directory, plus the listed conversations (entries and folders). */
function seedStore(
  dirs: SpawnedGateway["dirs"],
  options: { owned?: { label: string; id: string; dirId: string; extra?: Record<string, unknown> }[]; orphans?: string[]; legacy?: Record<string, unknown>; settings?: Record<string, unknown> },
): void {
  fs.mkdirSync(sandboxRoot(dirs), { mode: 0o700 });
  fs.mkdirSync(sessionsDir(dirs), { mode: 0o700 });
  fs.chmodSync(sandboxRoot(dirs), 0o700);
  fs.chmodSync(sessionsDir(dirs), 0o700);
  const byLabel: Record<string, Record<string, unknown>> = {};
  for (const o of options.owned ?? []) {
    (byLabel[o.label] ??= {})[o.id] = ownedEntry(o.label, o.dirId, o.extra);
    handFolder(dirs, o.dirId, `SYNTH-CONTENT-${o.id}`);
  }
  for (const dirId of options.orphans ?? []) handFolder(dirs, dirId, "SYNTH-ORPHAN");
  fs.writeFileSync(path.join(dirs.persist, "sessions.json"), JSON.stringify({ sessions: options.legacy ?? {}, sessionsByLabel: byLabel, settings: { sessionIdleTimeoutMs: 0, ...options.settings } }));  // the saved key is ignored by the gateway (MVP-7402 R1); old files carry it
}

const failedLines = (g: SpawnedGateway): string[] => g.output().split("\n").filter((l) => l.includes("sessions.erasure.failed"));

describe("the operator outcome: a deleted conversation is erased from the gateway host", () => {
  it("an image and a tool call are erased by one DELETE (200, no folder, no base64 anywhere); reqlift's replay pattern gets a new empty conversation; neighbours are untouched", async () => {
    const MARKER = "SYNTH-ERASE-MARKER-7402";
    const r = await rig({
      scripts: [
        bash("PROBE-ERASE", "echo WORK-FILE > /work/note.txt; echo DONE-ERASE"),
        bash("PROBE-NEIGHBOUR", "echo NEIGHBOUR > /work/neighbour.txt; echo DONE-NEIGHBOUR"),
        bash("PROBE-REUSE", "echo REUSE-LIST=[$(ls -A /work | tr '\\n' ' ')]; echo DONE-REUSE"),
      ],
    });
    const g = r.gateway;
    const image = { type: "image", source: { type: "base64", media_type: "image/png", data: IMAGE_B64 } };
    const first = await queryAs(g.port, KEY_ALPHA, { queryId: "q-1", sessionId: "erase-1", user_id: "user-1", content: [{ type: "text", text: `PROBE-ERASE ${MARKER}` }, image] });
    expect(first.events.at(-1)?.type, `${JSON.stringify(first.events.at(-1))}\n${tail(g)}`).toBe("done");
    // Another label's conversation and an orphan folder must survive every erase below.
    const neighbour = await queryAs(g.port, KEY_BETA, { queryId: "q-n", sessionId: "other-1", prompt: "PROBE-NEIGHBOUR" });
    expect(neighbour.events.at(-1)?.type, JSON.stringify(neighbour.events.at(-1))).toBe("done");
    handFolder(g.dirs, DIR_O, "SYNTH-ORPHAN");

    const dirId = await dirIdOf(g, "alpha", "erase-1");
    const neighbourDir = await dirIdOf(g, "beta", "other-1");
    const folder = folderOf(g, dirId);
    // Positive controls: the image and the marker really are in the folder before the delete, and the search is live.
    expect(filesWith(folder, IMAGE_B64).length, `the transcript holds the image; files: ${listing(folder)}`).toBeGreaterThan(0);
    expect(filesWith(folder, MARKER).length).toBeGreaterThan(0);
    expect(fs.readFileSync(path.join(folder, "work", "note.txt"), "utf8").trim()).toBe("WORK-FILE");
    const neighbourBefore = snapshot(folderOf(g, neighbourDir));
    const orphanBefore = snapshot(folderOf(g, DIR_O));
    expect(filesWith(folderOf(g, DIR_O), IMAGE_B64).length, "control: the search finds the planted orphan copy").toBe(1);
    expect(fs.readdirSync(sessionsDir(g.dirs))).toContain(dirId);

    // The operator's view: HTTP answer and a listing of the sessions directory.
    const deleted = await del(g, KEY_ALPHA, "erase-1");
    expect([deleted.status, deleted.json]).toEqual([200, { deleted: true }]);
    expect(fs.readdirSync(sessionsDir(g.dirs))).not.toContain(dirId);
    expect(gone(folder)).toBe(true);
    // No base64 copy of the image and no marker anywhere under the sandbox storage (the orphan's planted copy is the control that the search runs).
    expect(filesWith(sandboxRoot(g.dirs), IMAGE_B64)).toEqual([path.join(folderOf(g, DIR_O), "home", ".claude", "projects", "-work", "t.jsonl")]);
    expect(filesWith(sandboxRoot(g.dirs), MARKER)).toEqual([]);
    expect(snapshot(folderOf(g, DIR_O))).toEqual(orphanBefore);
    expect(snapshot(folderOf(g, neighbourDir))).toEqual(neighbourBefore);
    // Entry gone, the list is empty, the repeat answers 200, another label and a never-used id answer 404.
    expect(((await rawAs(g.port, KEY_ALPHA, "GET", "/v1/sessions")).json as { count: number }).count).toBe(0);
    for (let n = 0; n < 2; n++) expect((await del(g, KEY_ALPHA, "erase-1")).json).toEqual({ deleted: true });
    expect((await del(g, KEY_BETA, "erase-1")).status).toBe(404);
    expect((await del(g, KEY_ALPHA, "never-used")).status).toBe(404);
    // The completed erasure is saved like every other change (debounced).
    await until("the completed erasure is saved", () => readStore(g).erasedByLabel?.alpha?.["erase-1"] !== undefined, 10_000);
    expect(entryOf(g, "alpha", "erase-1")).toBeUndefined();
    expect(Object.keys(readStore(g).erasedByLabel?.alpha?.["erase-1"] ?? {})).toEqual(["erasedAt"]);
    expect(JSON.stringify(readStore(g))).not.toContain(dirId);
    expect((await health(g)).erasurePending).toBe(0);

    // The log names the id and nothing else: no marker, no image bytes, no folder name.
    const log = g.output();
    expect(log).toContain('sessions.erasure.done id="erase-1"');
    expect(log).not.toContain(MARKER);
    expect(log).not.toContain(IMAGE_B64.slice(0, 200));
    // No erasure line names the folder.
    expect(log.split("\n").filter((l) => l.includes("sessions.erasure")).join("\n")).not.toContain(dirId);

    // Reqlift's replay pattern: DELETE, then at once a query with the same id. 200, no refusal, a new empty conversation.
    const replay = await queryAs(g.port, KEY_ALPHA, { queryId: "q-2", sessionId: "erase-1", user_id: "user-1", prompt: "PROBE-REUSE" });
    expect(replay.events.some((e) => e.type === "error"), JSON.stringify(replay.events)).toBe(false);
    expect(replay.events.at(-1)?.type).toBe("done");
    const newDir = await dirIdOf(g, "alpha", "erase-1");
    expect(newDir).not.toBe(dirId);
    expect(filesWith(folderOf(g, newDir), IMAGE_B64)).toEqual([]);
    expect(filesWith(folderOf(g, newDir), MARKER)).toEqual([]);
    const reuseRequest = r.api.requests.filter((q) => !q.warmup && q.userTexts.some((t) => t.includes("PROBE-REUSE"))).at(-1);
    const reuseResult = reuseRequest?.toolResults.map((t) => t.text).join("\n") ?? "";
    expect(reuseResult).toContain("DONE-REUSE");
    expect(reuseResult).not.toContain("note.txt");
    expect(JSON.stringify(reuseRequest?.userTexts)).not.toContain(MARKER);
    // A later delete concerns the new conversation and erases it under the same rules.
    expect((await del(g, KEY_ALPHA, "erase-1")).status).toBe(200);
    expect(gone(folderOf(g, newDir))).toBe(true);
    expect(snapshot(folderOf(g, DIR_O))).toEqual(orphanBefore);
  });

  it("content the agent planted does not stop the erasure or reach beyond the folder: links to host files, a tree deeper than PATH_MAX, unreadable directories, a FIFO", async () => {
    const outside = fixtureDir();
    fs.mkdirSync(path.join(outside, "dir"));
    fs.writeFileSync(path.join(outside, "dir", "inner.txt"), "outside inner");
    fs.writeFileSync(path.join(outside, "file.txt"), "outside file");
    fs.chmodSync(path.join(outside, "file.txt"), 0o400);
    fs.chmodSync(path.join(outside, "dir"), 0o500);
    const plant = [
      `ln -s ${outside}/file.txt /work/to-file`,
      `ln -s ${outside}/dir /work/to-dir`,
      `ln -s ${outside} /work/to-fixture-root`,
      "mkfifo /work/pipe",
      "mkdir -p /work/locked/inner && echo x > /work/locked/inner/f && chmod 000 /work/locked/inner && chmod 500 /work/locked",
      "cd /work && i=0 && while [ $i -lt 25 ]; do n=$(printf 'd%.0s' $(seq 1 200)); mkdir $n && cd $n; i=$((i+1)); done",
      "echo deep > file; mkdir bottom; echo b > bottom/f; chmod 000 bottom",
      "cd /work; echo PLANTED",
    ].join("; ");
    const r = await rig({ scripts: [bash("PROBE-PLANT", plant)] });
    const g = r.gateway;
    const res = await queryAs(g.port, KEY_ALPHA, { queryId: "q-1", sessionId: "plant-1", prompt: "PROBE-PLANT" });
    expect(res.events.at(-1)?.type, `${JSON.stringify(res.events.at(-1))}\n${tail(g)}`).toBe("done");
    // The orphan folder is written after the first run: the gateway creates its storage root itself.
    handFolder(g.dirs, DIR_O, "SYNTH-ORPHAN");
    const toolResult = r.api.requests.filter((q) => !q.warmup && q.toolResults.length > 0).at(-1)?.toolResults.map((t) => t.text).join("\n") ?? "";
    expect(toolResult).toContain("PLANTED");
    const dirId = await dirIdOf(g, "alpha", "plant-1");
    const work = path.join(folderOf(g, dirId), "work");
    // Controls: the links, the FIFO and the unreadable directory exist; the tree is deeper than the kernel allows a path to be.
    expect(fs.lstatSync(path.join(work, "to-file")).isSymbolicLink()).toBe(true);
    expect(fs.lstatSync(path.join(work, "pipe")).isFIFO()).toBe(true);
    expect(fs.lstatSync(path.join(work, "locked")).mode & 0o777).toBe(0o500);
    expect(fs.lstatSync(path.join(work, "d".repeat(200))).isDirectory()).toBe(true);
    const outsideBefore = snapshot(outside);
    const orphanBefore = snapshot(folderOf(g, DIR_O));
    const res2 = await del(g, KEY_ALPHA, "plant-1");
    expect([res2.status, res2.json]).toEqual([200, { deleted: true }]);
    expect(gone(folderOf(g, dirId))).toBe(true);
    expect(snapshot(outside)).toEqual(outsideBefore);
    expect(snapshot(folderOf(g, DIR_O))).toEqual(orphanBefore);
    expect(outsideBefore.some((l) => l.startsWith("dir/ 500"))).toBe(true);
    expect(outsideBefore.some((l) => l.startsWith("file.txt 400"))).toBe(true);
  });
});

describe("a conversation whose first turn failed", () => {
  it("the next query starts a fresh runtime session in the same folder; one delete erases both turns", async () => {
    const M1 = "SYNTH-FAILED-TURN-7402";
    const M2 = "SYNTH-SECOND-TURN-7402";
    const r = await rig({ mode: "fail-first" });
    const g = r.gateway;
    const first = await queryAs(g.port, KEY_ALPHA, { queryId: "q-1", sessionId: "fail-1", prompt: `${M1} first request` });
    expect(first.events.at(-1)?.type, JSON.stringify(first.events)).toBe("error");
    const dirId = await dirIdOf(g, "alpha", "fail-1");
    const second = await queryAs(g.port, KEY_ALPHA, { queryId: "q-2", sessionId: "fail-1", prompt: `${M2} second request` });
    expect(second.events.at(-1)?.type, JSON.stringify(second.events)).toBe("done");
    // Same conversation, same folder; the second turn did not resume the failed one.
    expect(await dirIdOf(g, "alpha", "fail-1")).toBe(dirId);
    const secondRequests = r.api.requests.filter((q) => !q.warmup && q.userTexts.some((t) => t.includes(M2)));
    expect(secondRequests.length).toBeGreaterThan(0);
    expect(JSON.stringify(secondRequests.map((q) => q.userTexts))).not.toContain(M1);
    const folder = folderOf(g, dirId);
    // Controls: the folder holds the successful turn's transcript, and its search is live. The failed turn's own record is reported, not required.
    expect(filesWith(folder, M2).length).toBeGreaterThan(0);
    const failedTurnCopies = filesWith(folder, M1).length;
    console.info(`MVP-7402 failed-turn transcript files before delete: ${failedTurnCopies}`);
    const deleted = await del(g, KEY_ALPHA, "fail-1");
    expect([deleted.status, deleted.json]).toEqual([200, { deleted: true }]);
    expect(gone(folder)).toBe(true);
    expect(filesWith(sandboxRoot(g.dirs), M1)).toEqual([]);
    expect(filesWith(sandboxRoot(g.dirs), M2)).toEqual([]);
  });
});

describe("a delete while a run is in progress", () => {
  it("answers 503, blocks the conversation, and the gateway erases the folder itself when the run ends, also across a restart", async () => {
    const MARKER = "SYNTH-HANG-MARKER-7402";
    const r = await rig({ mode: "hang", env: { SESSION_ERASURE_RETRY_MS: "1000" } });
    let g = r.gateway;
    const running = startQuery(g.port, KEY_ALPHA, { queryId: "q-run", sessionId: "run-1", user_id: "user-1", content: [{ type: "text", text: `PROBE-HANG ${MARKER}` }, { type: "image", source: { type: "base64", media_type: "image/png", data: IMAGE_B64 } }] });
    running.result.catch(() => undefined);
    await until("the model stand-in has the request", () => r.api.requests.some((q) => !q.warmup && q.userTexts.some((t) => t.includes("PROBE-HANG"))), 60_000);
    const dirId = await dirIdOf(g, "alpha", "run-1");
    const folder = folderOf(g, dirId);
    await until(`the transcript holds the image (files: ${listing(folder)})`, () => filesWith(folder, IMAGE_B64).length > 0, 30_000);

    const pending = await del(g, KEY_ALPHA, "run-1");
    expect([pending.status, pending.json]).toEqual([503, { error: "erasure_pending" }]);
    expect(fs.existsSync(folder)).toBe(true);
    expect(typeof entryOf(g, "alpha", "run-1")?.erasePendingSince).toBe("number");
    // Blocked: a new query is refused with the fixed text and starts no run; the list hides it; /health counts it.
    const requestsBefore = r.api.requests.length;
    const refused = await queryAs(g.port, KEY_ALPHA, { queryId: "q-refused", sessionId: "run-1", prompt: "PROBE-AFTER-DELETE" });
    expect(refused.events).toEqual([{ seq: 0, type: "error", content: ERASING_TEXT }]);
    expect(r.api.requests.length).toBe(requestsBefore);
    expect(((await rawAs(g.port, KEY_ALPHA, "GET", "/v1/sessions")).json as { count: number }).count).toBe(0);
    const during = await health(g);
    expect([during.sessions, during.erasurePending]).toEqual([0, 1]);
    expect((await del(g, KEY_ALPHA, "run-1")).status).toBe(503);

    // The run ends (the client goes away): the gateway finishes the erasure itself, with no further request.
    running.req.destroy();
    await until("the folder is gone", () => gone(folder), 60_000);
    await until("the entry is gone", () => entryOf(g, "alpha", "run-1") === undefined, 10_000);
    expect(filesWith(sandboxRoot(g.dirs), IMAGE_B64)).toEqual([]);
    expect(filesWith(sandboxRoot(g.dirs), MARKER)).toEqual([]);
    expect((await health(g)).erasurePending).toBe(0);
    // The late retry answers: the owner 200 every time, another label and a never-used id 404.
    for (let n = 0; n < 2; n++) expect((await del(g, KEY_ALPHA, "run-1")).json).toEqual({ deleted: true });
    expect((await del(g, KEY_BETA, "run-1")).status).toBe(404);
    expect((await del(g, KEY_ALPHA, "never-used")).status).toBe(404);
    // And after a restart.
    g = await restart(g, r.env);
    for (let n = 0; n < 2; n++) expect((await del(g, KEY_ALPHA, "run-1")).json).toEqual({ deleted: true });
    expect((await del(g, KEY_BETA, "run-1")).status).toBe(404);
    expect(g.output()).not.toContain(MARKER);
  });
});

describe("a file system error and a restart", () => {
  it("S1: a persistent error gives 503, a blocked conversation that survives a restart, a bounded number of attempts, and a repeated delete completes it", async () => {
    let g = await bareGateway({ env: { SESSION_ERASURE_RETRY_MS: "600000" }, seed: (dirs) => seedStore(dirs, { owned: [{ label: "alpha", id: "fs-1", dirId: DIR_C }], orphans: [DIR_O] }) });
    const env = GATEWAY_ENV(null, { SESSION_ERASURE_RETRY_MS: "600000" });
    const folder = folderOf(g, DIR_C);
    const orphanBefore = snapshot(folderOf(g, DIR_O));
    expect(filesWith(folder, IMAGE_B64).length).toBe(1);
    const sessions = sessionsDir(g.dirs);
    try {
      fs.chmodSync(sessions, 0o500);
      const res = await del(g, KEY_ALPHA, "fs-1");
      expect([res.status, res.json]).toEqual([503, { error: "erasure_pending" }]);
      expect(fs.existsSync(folder)).toBe(true);
      const refused = await queryAs(g.port, KEY_ALPHA, { queryId: "q-1", sessionId: "fs-1", prompt: "PROBE-NOPE" });
      expect(refused.events).toEqual([{ seq: 0, type: "error", content: ERASING_TEXT }]);
      expect((await health(g)).erasurePending).toBe(1);
      // Two seconds under a persistent error, a sweep interval of ten minutes: one attempt (the delete), one warning line.
      await sleep(2000);
      expect(failedLines(g)).toHaveLength(1);
      expect(failedLines(g)[0]).toMatch(/^\[sessions\] sessions\.erasure\.failed id="fs-1" code=[a-z_]+$/);
      expect(g.output()).not.toContain(DIR_C);

      // A restart while the error lasts: the tombstone is persisted, the startup sweep tries once more and fails.
      g = await restart(g, env);
      expect(typeof entryOf(g, "alpha", "fs-1")?.erasePendingSince).toBe("number");
      const afterRestart = await health(g);
      expect([afterRestart.sessions, afterRestart.erasurePending]).toEqual([0, 1]);
      await until("the startup sweep has tried", () => failedLines(g).length >= 1, 15_000);
      const refusedAgain = await queryAs(g.port, KEY_ALPHA, { queryId: "q-2", sessionId: "fs-1", prompt: "PROBE-NOPE" });
      expect(refusedAgain.events).toEqual([{ seq: 0, type: "error", content: ERASING_TEXT }]);
      expect(fs.existsSync(folder)).toBe(true);
    } finally {
      fs.chmodSync(sessions, 0o700);
    }
    // The cause is gone; the caller repeats the delete before any sweep (interval ten minutes) and gets 200.
    const repeat = await del(g, KEY_ALPHA, "fs-1");
    expect([repeat.status, repeat.json]).toEqual([200, { deleted: true }]);
    expect(gone(folder)).toBe(true);
    expect(snapshot(folderOf(g, DIR_O))).toEqual(orphanBefore);
    expect((await health(g)).erasurePending).toBe(0);
  });

  it("the gateway's own sweep finishes the erasure within its interval once the error is gone, with no further request", async () => {
    const g = await bareGateway({ env: { SESSION_ERASURE_RETRY_MS: "500" }, seed: (dirs) => seedStore(dirs, { owned: [{ label: "alpha", id: "fs-2", dirId: DIR_C }, { label: "beta", id: "live-b", dirId: DIR_B }], orphans: [DIR_O] }) });
    const sessions = sessionsDir(g.dirs);
    const orphanBefore = snapshot(folderOf(g, DIR_O));
    const liveBefore = snapshot(folderOf(g, DIR_B));
    try {
      fs.chmodSync(sessions, 0o500);
      expect((await del(g, KEY_ALPHA, "fs-2")).status).toBe(503);
      await sleep(1600);
      expect(fs.existsSync(folderOf(g, DIR_C))).toBe(true);
      expect(failedLines(g).length).toBeGreaterThanOrEqual(2);
    } finally {
      fs.chmodSync(sessions, 0o700);
    }
    await until("the sweep erased the folder", () => gone(folderOf(g, DIR_C)), 20_000);
    await until("the entry is gone", () => entryOf(g, "alpha", "fs-2") === undefined, 10_000);
    expect((await health(g)).erasurePending).toBe(0);
    for (let n = 0; n < 2; n++) expect((await del(g, KEY_ALPHA, "fs-2")).json).toEqual({ deleted: true });
    expect((await del(g, KEY_BETA, "fs-2")).status).toBe(404);
    // Label B's live conversation and the orphan are unchanged after every sweep.
    expect(snapshot(folderOf(g, DIR_B))).toEqual(liveBefore);
    expect(snapshot(folderOf(g, DIR_O))).toEqual(orphanBefore);
    expect(entryOf(g, "beta", "live-b")?.sandboxDirId).toBe(DIR_B);
  });
});

describe("idle expiry", () => {
  it("erases the folder of a conversation that has been idle longer than SESSION_IDLE_TIMEOUT_MS, and the owner's late delete answers 200", async () => {
    const g = await bareGateway({
      env: { SESSION_IDLE_TIMEOUT_MS: "2000", SESSION_ERASURE_RETRY_MS: "500" },
      seed: (dirs) => seedStore(dirs, { owned: [{ label: "alpha", id: "idle-1", dirId: DIR_C }], orphans: [DIR_O] }),
    });
    const orphanBefore = snapshot(folderOf(g, DIR_O));
    await until("the idle conversation is erased", () => gone(folderOf(g, DIR_C)), 30_000);
    await until("the entry is gone", () => entryOf(g, "alpha", "idle-1") === undefined, 10_000);
    expect(((await rawAs(g.port, KEY_ALPHA, "GET", "/v1/sessions")).json as { count: number }).count).toBe(0);
    for (let n = 0; n < 2; n++) expect((await del(g, KEY_ALPHA, "idle-1")).json).toEqual({ deleted: true });
    expect((await del(g, KEY_BETA, "idle-1")).status).toBe(404);
    expect(snapshot(folderOf(g, DIR_O))).toEqual(orphanBefore);
  });
});

describe("what a delete never touches", () => {
  const seedCommon = (dirs: SpawnedGateway["dirs"]): void => {
    const transcripts = path.join(dirs.workspace, "projects", "-home-node");
    fs.mkdirSync(transcripts, { recursive: true });
    fs.writeFileSync(path.join(transcripts, "T.jsonl"), `${JSON.stringify({ type: "user", message: { content: "legacy transcript SYNTH-LEGACY-7402" } })}\n`);
    seedStore(dirs, {
      owned: [{ label: "alpha", id: "C", dirId: DIR_C }],
      orphans: [DIR_O],
      legacy: { P: { sessionId: "gw-p", sdkSessionId: "sdk-p", systemPrompt: "", model: "m", lastUsed: Date.now() } },
    });
  };

  it.each([["A", KEY_ALPHA], ["B", KEY_BETA]])("a legacy conversation answers 409 legacy_not_erased for label %s, twice; the entry, the old store, C and its folder are unchanged and P is still refused", async (_name, key) => {
    const g = await bareGateway({ seed: seedCommon });
    const store = path.join(g.dirs.workspace, "projects", "-home-node");
    const storeBefore = snapshot(store);
    const folderBefore = snapshot(folderOf(g, DIR_C));
    for (let n = 0; n < 2; n++) {
      const res = await del(g, key, "P");
      expect([res.status, res.json]).toEqual([409, { error: "legacy_not_erased" }]);
    }
    expect(snapshot(store)).toEqual(storeBefore);
    expect(snapshot(folderOf(g, DIR_C))).toEqual(folderBefore);
    expect(entryOf(g, "alpha", "C")?.sandboxDirId).toBe(DIR_C);
    expect(readStore(g).sessions?.P).toBeDefined();
    const refused = await queryAs(g.port, KEY_ALPHA, { queryId: "q-p", sessionId: "P", prompt: "PROBE-LEGACY" });
    expect(refused.events).toEqual([{ seq: 0, type: "error", content: LEGACY_TEXT }]);
  });

  it.each([
    ["label B", KEY_BETA, "C"],
    ["label A, an id with no entry", KEY_ALPHA, "no-entry"],
    ["label A, `..`", KEY_ALPHA, ".."],
    ["label A, an encoded path", KEY_ALPHA, "..%2F..%2Fetc"],
    ["label A, an absolute path", KEY_ALPHA, "%2Fetc%2Fpasswd"],
    ["label A, the folder name of C", KEY_ALPHA, DIR_C],
    ["label A, the name of the orphan", KEY_ALPHA, DIR_O],
  ])("only the owner erases: %s answers 404 and C and the orphan O are unchanged", async (_name, key, id) => {
    const g = await bareGateway({ seed: seedCommon });
    const folderBefore = snapshot(folderOf(g, DIR_C));
    const orphanBefore = snapshot(folderOf(g, DIR_O));
    const res = await rawAs(g.port, key, "DELETE", `/v1/sessions/${id.includes("%") || id === ".." ? id : encodeURIComponent(id)}`);
    expect([res.status, res.json]).toEqual([404, { error: "Session not found" }]);
    expect(snapshot(folderOf(g, DIR_C))).toEqual(folderBefore);
    expect(snapshot(folderOf(g, DIR_O))).toEqual(orphanBefore);
    expect(entryOf(g, "alpha", "C")?.sandboxDirId).toBe(DIR_C);
    expect((await health(g)).erasurePending).toBe(0);
  });
});

describe("configuration and state files", () => {
  it.each(["0", "-1", "abc", "1.5"])("SESSION_ERASURE_RETRY_MS=%s stops startup with the fixed line", async (value) => {
    await expect(spawnGateway(cleanups, { rootPrefix: "mvp7402-gw-", env: GATEWAY_ENV(null, { SESSION_ERASURE_RETRY_MS: value }), readyTimeoutMs: 15_000, distServer: DIST })).rejects.toThrow(/FATAL config key=SESSION_ERASURE_RETRY_MS reason=must be a positive whole number of milliseconds/);
  });

  it("S5 residual: a set-aside sessions.json loses its tombstones and markers, /health reports degraded persistence and no pending count", async () => {
    const g = await bareGateway({
      seed: (dirs) => {
        seedStore(dirs, { owned: [{ label: "alpha", id: "C", dirId: DIR_C, extra: { erasePendingSince: Date.now() } }] });
        // An erasePendingSince on a legacy entry is unexpected content: the whole file is set aside at load.
        const file = path.join(dirs.persist, "sessions.json");
        const data = JSON.parse(fs.readFileSync(file, "utf8")) as { sessions: Record<string, unknown> };
        data.sessions.bad = { sessionId: "gw", systemPrompt: "", model: "m", lastUsed: Date.now(), erasePendingSince: Date.now() };
        fs.writeFileSync(file, JSON.stringify(data));
      },
    });
    const h = (await rawAs(g.port, null, "GET", "/health")).json as { persistence: string; erasurePending: number; sessions: number };
    expect([h.persistence, h.erasurePending, h.sessions]).toEqual(["degraded", 0, 0]);
    expect(fs.readdirSync(g.dirs.persist).some((f) => f.startsWith("sessions.json.corrupt-"))).toBe(true);
    // The folder is an orphan now (MVP-8166 owns that cleanup): it is not touched by anything here.
    expect(fs.existsSync(folderOf(g, DIR_C))).toBe(true);
  });
});

/* ------------------------------------------------------------------ */
/*  Rework R1: the idle timeout comes from the environment only          */
/* ------------------------------------------------------------------ */

/** A request with a JSON body and a verbatim path. */
function sendAs(port: number, key: string, method: "PUT" | "GET", urlPath: string, body?: unknown): Promise<{ status: number; json: Record<string, unknown> | null }> {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body), "utf8");
    const headers: Record<string, string | number> = { Authorization: `Bearer ${key}` };
    if (payload) {
      headers["Content-Type"] = "application/json";
      headers["Content-Length"] = payload.length;
    }
    const req = http.request({ host: "127.0.0.1", port, method, path: urlPath, agent: false, headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => {
        let json: Record<string, unknown> | null = null;
        try {
          json = JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, unknown>;
        } catch {
          // Not JSON.
        }
        resolve({ status: res.statusCode ?? 0, json });
      });
    });
    req.on("error", reject);
    req.end(payload);
  });
}

describe("R1: no API key can change the idle timeout, and the sweep stays live for the operator's value", () => {
  /** Alpha's conversation with a canary file in its folder, beta's none: the two-label scenario of the QA finding B1. */
  const seedAlpha = (lastUsed: number) => (dirs: SpawnedGateway["dirs"]): void => {
    seedStore(dirs, { owned: [{ label: "alpha", id: "alpha-chat", dirId: DIR_C, extra: { lastUsed } }], orphans: [DIR_O] });
    fs.writeFileSync(path.join(sessionsDir(dirs), DIR_C, "work", "canary.txt"), "SYNTH-CANARY-7402-ALPHA\n");
  };
  const canarySha = (g: SpawnedGateway): string => createHash("sha256").update(fs.readFileSync(path.join(folderOf(g, DIR_C), "work", "canary.txt"))).digest("hex");
  const CANARY_SHA = createHash("sha256").update("SYNTH-CANARY-7402-ALPHA\n").digest("hex");

  async function expectAlphaIntact(g: SpawnedGateway): Promise<void> {
    // The folder check comes first: this is the data the finding showed to be erased.
    expect(fs.existsSync(folderOf(g, DIR_C)), `alpha's folder must still exist\n${tail(g)}`).toBe(true);
    expect(canarySha(g)).toBe(CANARY_SHA);
    expect(entryOf(g, "alpha", "alpha-chat")?.sandboxDirId).toBe(DIR_C);
    expect(entryOf(g, "alpha", "alpha-chat")?.erasePendingSince).toBeUndefined();
    const settings = await sendAs(g.port, KEY_BETA, "GET", "/v1/settings");
    expect([settings.status, settings.json]).toEqual([200, { sessionIdleTimeoutMs: 0 }]);
  }

  it("R1-T1: label beta sets the timeout to 1 ms with logging off: the PUT answers 400, alpha's folder, entry and canary are unchanged for 6 sweep intervals and after a restart", async () => {
    const g = await bareGateway({ env: { SESSION_ERASURE_RETRY_MS: "500" }, seed: seedAlpha(Date.now() - 60_000) });
    const orphanBefore = snapshot(folderOf(g, DIR_O));
    const logging = await sendAs(g.port, KEY_BETA, "PUT", "/v1/logging", { level: "off" });
    expect(logging.status).toBe(200);
    const put = await sendAs(g.port, KEY_BETA, "PUT", "/v1/settings", { sessionIdleTimeoutMs: 1 });
    await sleep(3200);
    // The folder check comes before the status check: the data is what the finding showed to be erased.
    await expectAlphaIntact(g);
    expect([put.status, put.json]).toEqual([400, { error: "setting_read_only" }]);
    expect(snapshot(folderOf(g, DIR_O))).toEqual(orphanBefore);
    // The refusal is logged although logging is off; the old success line never appears.
    const refused = g.output().split("\n").filter((l) => l.includes("settings.refused"));
    expect(refused).toEqual(["[audit] settings.refused key=sessionIdleTimeoutMs label=beta"]);
    expect((readStore(g) as { settings?: { sessionIdleTimeoutMs?: number } }).settings?.sessionIdleTimeoutMs).not.toBe(1);
    expect(g.output()).not.toContain("Idle timeout updated");

    const again = await restart(g, GATEWAY_ENV(null, { SESSION_ERASURE_RETRY_MS: "500" }));
    await sleep(1600);
    await expectAlphaIntact(again);
    expect((await health(again)).erasurePending).toBe(0);
  });

  it("R1-T2 (control): with SESSION_IDLE_TIMEOUT_MS=1500 the same sweep is live: the idle conversation is erased, the marker is saved and the expiry line is logged", async () => {
    // lastUsed a few seconds ahead so that the load-time rule cannot take it; the sweep takes it once it is 1.5 s old.
    const g = await bareGateway({ env: { SESSION_IDLE_TIMEOUT_MS: "1500", SESSION_ERASURE_RETRY_MS: "500" }, seed: seedAlpha(Date.now() + 3000) });
    expect(fs.existsSync(folderOf(g, DIR_C)), "the folder exists at the first check").toBe(true);
    expect(canarySha(g)).toBe(CANARY_SHA);
    await until("the idle conversation is erased", () => gone(folderOf(g, DIR_C)), 15_000);
    await until("the entry is gone and the marker saved", () => entryOf(g, "alpha", "alpha-chat") === undefined && readStore(g).erasedByLabel?.alpha?.["alpha-chat"] !== undefined, 15_000);
    expect(g.output()).toContain("Expired 1 idle session(s)");
    expect(g.output()).toContain("sessions.idle_timeout ms=1500");
    expect((await sendAs(g.port, KEY_BETA, "GET", "/v1/settings")).json).toEqual({ sessionIdleTimeoutMs: 1500 });
  });

  it("R1-T4 (process): a timeout saved by an earlier version is ignored after a restart", async () => {
    const g = await bareGateway({
      env: { SESSION_ERASURE_RETRY_MS: "500" },
      seed: (dirs) => {
        seedAlpha(Date.now() - 3_600_000)(dirs);
        const file = path.join(dirs.persist, "sessions.json");
        const data = JSON.parse(fs.readFileSync(file, "utf8")) as Record<string, unknown>;
        data.settings = { sessionIdleTimeoutMs: 1 };
        fs.writeFileSync(file, JSON.stringify(data));
      },
    });
    await sleep(2000);
    await expectAlphaIntact(g);
    expect(g.output().split("\n").filter((l) => l.includes("sessions.settings.ignored"))).toEqual(["[sessions] sessions.settings.ignored key=sessionIdleTimeoutMs"]);
  });

  it.each(["30m", "1h", "1e6", "-5", "0x10"])("R1-T9: SESSION_IDLE_TIMEOUT_MS=%s stops startup with the fixed line, and a seeded idle folder is unchanged", async (value) => {
    let seeded: SpawnedGateway["dirs"] | undefined;
    const store = (dirs: SpawnedGateway["dirs"]): string => path.join(dirs.persist, "sessions.json");
    let storeBefore = "";
    await expect(
      spawnGateway(cleanups, {
        rootPrefix: "mvp7402-gw-",
        env: GATEWAY_ENV(null, { SESSION_IDLE_TIMEOUT_MS: value, SESSION_ERASURE_RETRY_MS: "500" }),
        seed: (dirs) => {
          seeded = dirs;
          seedAlpha(1)(dirs);
          storeBefore = fs.readFileSync(store(dirs), "utf8");
        },
        readyTimeoutMs: 15_000,
        distServer: DIST,
      }),
    ).rejects.toThrow(/FATAL config key=SESSION_IDLE_TIMEOUT_MS reason=must be a whole number of milliseconds \(0 = disabled\)/);
    // Nothing was erased or rewritten by the process that did not start.
    expect(fs.existsSync(path.join(sessionsDir(seeded!), DIR_C))).toBe(true);
    expect(fs.readFileSync(path.join(sessionsDir(seeded!), DIR_C, "work", "canary.txt"), "utf8")).toBe("SYNTH-CANARY-7402-ALPHA\n");
    expect(fs.readFileSync(store(seeded!), "utf8")).toBe(storeBefore);
  });

  it.each([
    ["", 0],
    ["0", 0],
    ["86400000", 86_400_000],
  ])("R1-T9: SESSION_IDLE_TIMEOUT_MS=%j starts and reports %i", async (value, expected) => {
    const g = await bareGateway({ env: { SESSION_IDLE_TIMEOUT_MS: value } });
    expect((await sendAs(g.port, KEY_ALPHA, "GET", "/v1/settings")).json).toEqual({ sessionIdleTimeoutMs: expected });
    expect(g.output()).toContain(`sessions.idle_timeout ms=${expected}`);
  });
});

/* ------------------------------------------------------------------ */
/*  Rework R1: the tombstone is on disk before the removal starts        */
/* ------------------------------------------------------------------ */

describe("R1-T7: a hard kill of the gateway and its children in the middle of a delete is finished after the restart", () => {
  const FILES_PER_DIR = 100;
  const DIRS = 100;

  /** About 10,000 small files in 100 `work/` directories plus one directory at mode 0, so `chmod -R` has work to do. */
  function fatFolder(dirs: SpawnedGateway["dirs"], dirId: string): void {
    handFolder(dirs, dirId, "SYNTH-FAT");
    const work = path.join(sessionsDir(dirs), dirId, "work");
    for (let d = 0; d < DIRS; d++) {
      const dir = path.join(work, `d${d}`);
      fs.mkdirSync(dir);
      for (let f = 0; f < FILES_PER_DIR; f++) fs.writeFileSync(path.join(dir, `f${f}.txt`), `SYNTH-FAT ${d} ${f}\n`);
    }
    fs.mkdirSync(path.join(work, "locked"));
    fs.writeFileSync(path.join(work, "locked", "inner.txt"), "locked\n");
    fs.chmodSync(path.join(work, "locked"), 0o000);
  }

  /** The `chmod -R` or `rm -rf` child of the gateway whose arguments name that folder, or null. */
  function removalChild(gatewayPid: number, folder: string): number | null {
    for (const pid of descendants(gatewayPid)) {
      let args: string[];
      try {
        args = fs.readFileSync(`/proc/${pid}/cmdline`, "utf8").split("\0");
      } catch {
        continue;
      }
      const tool = path.basename(args[0] ?? "");
      if ((tool === "chmod" || tool === "rm") && args.slice(1).some((a) => a === folder)) return pid;
    }
    return null;
  }

  const groupGone = (pgid: number): boolean => {
    try {
      process.kill(-pgid, 0);
      return false;
    } catch (e) {
      return (e as NodeJS.ErrnoException).code === "ESRCH";
    }
  };

  it("R1-T7: the tombstone is on disk before the first removal child runs; after a SIGKILL of the whole group and a restart the gateway finishes the erasure on its own", async () => {
    const g = await bareGateway({
      seed: (dirs) => {
        seedStore(dirs, { owned: [{ label: "alpha", id: "fat-1", dirId: DIR_C }, { label: "alpha", id: "timing-1", dirId: DIR_O }, { label: "beta", id: "live-b", dirId: DIR_B }] });
        fatFolder(dirs, DIR_C);
        fatFolder(dirs, DIR_O);
      },
      detached: true,
    });
    // The recorded tree is made readable again before the fixture goes, whatever the outcome.
    cleanups.push(() => {
      for (const dir of [g.root]) {
        try {
          execFileSync("/usr/bin/chmod", ["-R", "u+rwx", "--", dir], { stdio: "ignore" });
        } catch {
          // Gone already.
        }
      }
    });
    const liveBefore = snapshot(folderOf(g, DIR_B));

    // Control and measurement: the same kind of folder is removed by an ordinary DELETE (200), so the fixture is erasable and the time is known.
    const timing = Date.now();
    expect((await del(g, KEY_ALPHA, "timing-1")).status).toBe(200);
    const removalMs = Date.now() - timing;
    expect(gone(folderOf(g, DIR_O))).toBe(true);
    console.log(`R1-T7 measured removal time of ${DIRS * FILES_PER_DIR} files: ${removalMs} ms (DELETE answered 200)`);

    const folder = folderOf(g, DIR_C);
    expect(fs.existsSync(folder)).toBe(true);
    expect(entryOf(g, "alpha", "fat-1")?.erasePendingSince).toBeUndefined();

    // DELETE, then look for the removal child every 10 ms and kill the recorded group the moment it is seen.
    const answer = del(g, KEY_ALPHA, "fat-1").then(
      (r) => ({ answered: r }),
      (error: unknown) => ({ dropped: String(error) }),
    );
    let seen: number | null = null;
    const deadline = Date.now() + 10_000;
    while (seen === null && Date.now() < deadline) {
      seen = removalChild(g.child.pid!, folder);
      if (seen === null) await sleep(10);
    }
    expect(seen, `a chmod or rm child for the conversation folder must appear within 10 s\n${tail(g)}`).not.toBeNull();
    killGatewayGroup(g);
    const outcome = await answer;
    await new Promise<void>((resolve) => (g.child.exitCode !== null || g.child.signalCode !== null ? resolve() : g.child.once("exit", () => resolve())));
    // Hard preconditions: each one that is not met fails the row.
    expect(outcome, "the DELETE got no answer").toHaveProperty("dropped");
    await until("the killed group is gone", () => groupGone(g.child.pid!), 10_000);
    expect(fs.existsSync(folder), "the folder still exists after the kill").toBe(true);
    // The tombstone was on disk before the removal started.
    expect(typeof entryOf(g, "alpha", "fat-1")?.erasePendingSince, "sessions.json holds the entry with erasePendingSince before the restart").toBe("number");

    // After the restart the gateway finishes the erasure by itself (startup sweep, sweep interval 500 ms).
    const started = Date.now();
    const again = await spawnGateway(cleanups, { reuse: g, env: GATEWAY_ENV(null, { SESSION_ERASURE_RETRY_MS: "500" }), distServer: DIST });
    await sleep(600);
    await until("the folder and the entry are gone", () => gone(folder) && entryOf(again, "alpha", "fat-1") === undefined, 30_000);
    console.log(`R1-T7 restart to erased: ${Date.now() - started} ms`);
    await until("the marker is saved", () => readStore(again).erasedByLabel?.alpha?.["fat-1"] !== undefined, 10_000);
    const h = await health(again);
    expect([h.erasurePending, h.sessions]).toEqual([0, 1]);
    const repeat = await del(again, KEY_ALPHA, "fat-1");
    expect([repeat.status, repeat.json]).toEqual([200, { deleted: true }]);
    expect(snapshot(folderOf(again, DIR_B))).toEqual(liveBefore);
    expect(entryOf(again, "beta", "live-b")?.sandboxDirId).toBe(DIR_B);
  });

  it("the group kill refuses a gateway that was not spawned detached, and signals nothing", async () => {
    const g = await bareGateway();
    expect(() => killGatewayGroup(g)).toThrow(/not spawned detached/);
    expect(g.child.exitCode).toBeNull();
    expect(g.child.signalCode).toBeNull();
    expect((await health(g)).persistence).toBeDefined();
  });
});
