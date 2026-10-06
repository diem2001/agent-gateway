/**
 * Conversation isolation through the compiled gateway, the real Claude runtime and real bwrap
 * (MVP-7678, Gate D): legacy conversations are refused and their transcripts never reach the
 * model, conversations of different callers running at the same time cannot see each other (another
 * person of the same API-key label continues the conversation, MVP-8044), a conversation survives a
 * gateway restart in its own home (and still cannot read credentials), and a second request for a
 * conversation that is still answering is refused. Every secret is
 * synthetic; the model is a scripted stand-in.
 *
 * Needs `npm run build`, `bwrap` and user namespaces. Linux only.
 */
import { createHash } from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { startFakeAnthropicApi, type ExactToolScript, type FakeAnthropicApi } from "./helpers/fake-anthropic-api.js";
import { spawnGateway, type Cleanup, type SpawnedGateway } from "./helpers/git-process-gateway.js";

vi.setConfig({ testTimeout: 120_000 });

const KEY_ALPHA = "SYNTH-ALPHA-API-KEY-7678";
const KEY_BETA = "SYNTH-BETA-API-KEY-7678";
const PROVIDER_KEY = "SYNTH-PROVIDER-KEY-7678-sessions";
const OAUTH_ACCESS = "SYNTH-OAUTH-ACCESS-7678-sessions";
const LEGACY_CONTAMINATED = "SYNTH-LEGACY-CONTAMINATED-7678";
const LEGACY_CLEAN_TEXT = "an ordinary old conversation about nothing secret";

const cleanups: Cleanup[] = [];
afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()!();
});

interface Ndjson {
  type: string;
  content?: string;
  [key: string]: unknown;
}

function queryAs(port: number, key: string, body: Record<string, unknown>): Promise<{ events: Ndjson[]; status: number }> {
  return new Promise((resolve, reject) => {
    const payload = Buffer.from(JSON.stringify({ model: "claude-sonnet-4-5", ...body }), "utf8");
    const req = http.request(
      { host: "127.0.0.1", port, method: "POST", path: "/v1/query", agent: false, headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json", "Content-Length": payload.length } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          resolve({ status: res.statusCode ?? 0, events: text.split("\n").filter((l) => l.trim().startsWith("{")).map((l) => JSON.parse(l) as Ndjson) });
        });
      },
    );
    req.on("error", reject);
    req.end(payload);
  });
}

function getAs(port: number, key: string, method: "GET" | "DELETE", urlPath: string): Promise<{ status: number; json: Record<string, unknown> | null }> {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, method, path: urlPath, agent: false, headers: { Authorization: `Bearer ${key}` } }, (res) => {
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

interface Rig {
  api: FakeAnthropicApi;
  gateway: SpawnedGateway;
  scripts: ExactToolScript[];
}

const GATEWAY_ENV = (api: FakeAnthropicApi): Record<string, string> => ({
  API_KEYS: `alpha:${KEY_ALPHA},beta:${KEY_BETA}`,
  ANTHROPIC_BASE_URL: api.baseUrl,
  ANTHROPIC_API_KEY: PROVIDER_KEY,
  DISABLE_TELEMETRY: "1",
  CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
});

async function rig(scripts: ExactToolScript[], seed?: (dirs: SpawnedGateway["dirs"]) => void): Promise<Rig> {
  const api = await startFakeAnthropicApi({ toolName: "unused-7678", exactTool: scripts });
  cleanups.push(() => api.close());
  const gateway = await spawnGateway(cleanups, {
    rootPrefix: "mvp7678-sess-",
    env: GATEWAY_ENV(api),
    seed: (dirs) => {
      fs.writeFileSync(path.join(dirs.workspace, ".credentials.json"), JSON.stringify({ claudeAiOauth: { accessToken: OAUTH_ACCESS, refreshToken: "SYNTH-REFRESH-7678", expiresAt: Date.now() + 3_600_000 } }));
      seed?.(dirs);
    },
  });
  return { api, gateway, scripts };
}

const bash = (prompt: string, command: string): ExactToolScript => ({ name: "Bash", prompt, input: { command, description: "probe" } });

/** The tool results the model stand-in saw for the latest turn of the conversation with this prompt, in order (earlier turns are repeated by a resumed conversation, so the latest is last). */
function resultsFor(api: FakeAnthropicApi, prompt: string): { isError: boolean; text: string }[] {
  const matching = api.requests.filter((r) => r.userTexts.at(-1)?.includes(prompt) && !r.warmup);
  return matching.at(-1)?.toolResults ?? [];
}

function requestsFor(api: FakeAnthropicApi, prompt: string) {
  return api.requests.filter((r) => r.userTexts.some((t) => t.includes(prompt)));
}

/** A persisted conversation by client id: below its API-key label since MVP-7679 (the label is not needed by these rows). */
function savedEntry(gateway: SpawnedGateway, clientId: string): { sandboxDirId?: string } | undefined {
  const saved = JSON.parse(fs.readFileSync(path.join(gateway.dirs.persist, "sessions.json"), "utf8")) as {
    sessions?: Record<string, { sandboxDirId?: string }>;
    sessionsByLabel?: Record<string, Record<string, { sandboxDirId?: string }>>;
  };
  for (const entries of Object.values(saved.sessionsByLabel ?? {})) if (entries[clientId]) return entries[clientId];
  return saved.sessions?.[clientId];
}

/** The home of the conversation `clientId` of API-key label `label` (the label's own entry). */
function savedEntryFor(gateway: SpawnedGateway, label: string, clientId: string): string | undefined {
  const saved = JSON.parse(fs.readFileSync(path.join(gateway.dirs.persist, "sessions.json"), "utf8")) as { sessionsByLabel?: Record<string, Record<string, { sandboxDirId?: string }>> };
  const id = saved.sessionsByLabel?.[label]?.[clientId]?.sandboxDirId;
  return id ? path.join(gateway.dirs.home, ".agent-sandbox", "sessions", id, "home") : undefined;
}

function sessionHome(gateway: SpawnedGateway, clientId: string): string {
  const id = savedEntry(gateway, clientId)?.sandboxDirId;
  if (!id) throw new Error(`no sandbox home recorded for ${clientId}`);
  return path.join(gateway.dirs.home, ".agent-sandbox", "sessions", id, "home");
}

async function waitForSessionsFile(gateway: SpawnedGateway, clientId: string): Promise<void> {
  const end = Date.now() + 10_000;
  while (Date.now() < end) {
    try {
      if (savedEntry(gateway, clientId)) return;
    } catch {
      // Not written yet.
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`sessions.json never listed ${clientId}`);
}

function grepTree(dir: string, needle: string): string[] {
  const hits: string[] = [];
  const walk = (d: string): void => {
    for (const entry of fs.readdirSync(d, { withFileTypes: true })) {
      const full = path.join(d, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile() && fs.readFileSync(full, "utf8").includes(needle)) hits.push(full);
    }
  };
  walk(dir);
  return hits;
}

describe("legacy conversations (created before the update)", () => {
  it("are refused with the fixed text before any model request or run; their transcripts never reach the model; new conversations work", async () => {
    const seed = (dirs: SpawnedGateway["dirs"]): void => {
      const transcripts = path.join(dirs.workspace, "projects", "-home-node");
      fs.mkdirSync(transcripts, { recursive: true });
      fs.writeFileSync(path.join(transcripts, "sdk-contaminated.jsonl"), JSON.stringify({ type: "user", message: { role: "user", content: `please remember ${LEGACY_CONTAMINATED}` } }) + "\n");
      fs.writeFileSync(path.join(transcripts, "sdk-clean.jsonl"), JSON.stringify({ type: "user", message: { role: "user", content: LEGACY_CLEAN_TEXT } }) + "\n");
      const now = Date.now();
      fs.writeFileSync(
        path.join(dirs.persist, "sessions.json"),
        JSON.stringify({
          sessions: {
            "legacy-contaminated": { sessionId: "gw-1", sdkSessionId: "sdk-contaminated", systemPrompt: "", model: "m", lastUsed: now },
            "legacy-clean": { sessionId: "gw-2", sdkSessionId: "sdk-clean", systemPrompt: "", model: "m", lastUsed: now },
          },
          settings: { sessionIdleTimeoutMs: 0 },
        }),
      );
    };
    const r = await rig([bash("PROBE-NEW", "echo LEGACY_TRANSCRIPTS=$(grep -rl --exclude-dir=proc --exclude-dir=sys 'SYNTH-LEGACY-CONTAMINATED-7[6]78' / 2>/dev/null | wc -l); echo JSONL_FILES=$(find / -xdev -name 'sdk-*.jsonl' 2>/dev/null | wc -l)")], seed);
    const expectedText = "This conversation was started before a gateway security update and cannot be continued safely. Please start a new conversation. Retrying will not help.";
    for (const [id, prompt] of [["legacy-contaminated", "resume the old one"], ["legacy-clean", "resume the clean old one"]] as const) {
      const started = Date.now();
      const refused = await queryAs(r.gateway.port, KEY_ALPHA, { queryId: `q-${id}`, sessionId: id, prompt, user_id: "user-1" });
      expect(Date.now() - started).toBeLessThan(2000);
      expect(refused.events).toEqual([{ seq: 0, type: "error", content: expectedText }]);
    }
    // Nothing reached the model, nothing ran, nothing was created.
    expect(r.api.requests).toEqual([]);
    expect(fs.existsSync(path.join(r.gateway.dirs.home, ".agent-sandbox", "sessions"))).toBe(false);
    // A refusal under another label and another user id is the same refusal (no owner is on record).
    const other = await queryAs(r.gateway.port, KEY_BETA, { queryId: "q-other", sessionId: "legacy-clean", prompt: "x" });
    expect(other.events).toEqual([{ seq: 0, type: "error", content: expectedText }]);
    // The audit line carries counts only.
    // The audit line travels through the gateway's output pipe after the answer: give the last one a moment to arrive on a loaded host.
    for (const end = Date.now() + 3000; r.gateway.output().split("\n").filter((l) => l.includes("sessions.legacy.refused")).length < 3 && Date.now() < end; ) await new Promise((resolve) => setTimeout(resolve, 50));
    const audit = r.gateway.output().split("\n").filter((l) => l.includes("sessions.legacy.refused"));
    expect(audit).toEqual(["[audit] sessions.legacy.refused total=1", "[audit] sessions.legacy.refused total=2", "[audit] sessions.legacy.refused total=3"]);
    expect(r.gateway.output()).not.toContain(LEGACY_CONTAMINATED);

    // A new conversation works, and the legacy transcripts are invisible to its agent.
    const fresh = await queryAs(r.gateway.port, KEY_ALPHA, { queryId: "q-fresh", sessionId: "fresh", prompt: "PROBE-NEW", user_id: "user-1" });
    expect(fresh.events.at(-1)?.type, JSON.stringify(fresh.events.at(-1))).toBe("done");
    const result = resultsFor(r.api, "PROBE-NEW").at(-1);
    expect(result?.text).toContain("LEGACY_TRANSCRIPTS=0");
    expect(result?.text).toContain("JSONL_FILES=0");
    expect(JSON.stringify(r.api.requests.map((q) => [q.userTexts, q.toolResults]))).not.toContain(LEGACY_CONTAMINATED);
    expect(JSON.stringify(r.api.requests.map((q) => [q.userTexts, q.toolResults]))).not.toContain(LEGACY_CLEAN_TEXT);

    // Legacy entries stay listable and deletable (for any label), as before.
    const list = await getAs(r.gateway.port, KEY_BETA, "GET", "/v1/sessions");
    expect((list.json?.sessions as { id: string }[]).map((s) => s.id).sort()).toEqual(["legacy-clean", "legacy-contaminated"]);
    expect((await getAs(r.gateway.port, KEY_BETA, "DELETE", "/v1/sessions/legacy-clean")).status).toBe(200);
  });
});

describe("conversations of different callers that run at the same time", () => {
  it("neither sees the other's files, processes, transcript or model traffic", async () => {
    const SECRET_A = "SYNTH-A-SECRET-7678";
    const SECRET_B = "SYNTH-B-SECRET-7678";
    const probeFor = (mine: string, file: string, otherPattern: string, otherFile: string): string =>
      [
        `echo ${mine} > /home/node/${file}`,
        `echo ${mine} > /work/${file}`,
        "sleep 8",
        `echo HITS=$(grep -rl --exclude-dir=proc --exclude-dir=sys '${otherPattern}' /home /work /tmp /etc /var /srv /opt /root /mnt 2>/dev/null | wc -l)`,
        `echo FILES=$(find / -xdev -name '${otherFile}' 2>/dev/null | wc -l)`,
        `echo PROCS=$(cat /proc/[0-9]*/cmdline /proc/[0-9]*/environ 2>/dev/null | tr '\\0' '\\n' | grep -c '${otherPattern}')`,
        `echo OWN=$(cat /home/node/${file})`,
        "echo HOMES=$(ls -A /home/node | grep -c '[.]agent-sandbox')",
      ].join("; ");
    const r = await rig([bash("PROBE-A", probeFor(SECRET_A, "a.txt", "SYNTH-B-SECRET-7[6]78", "b.tx[t]")), bash("PROBE-B", probeFor(SECRET_B, "b.txt", "SYNTH-A-SECRET-7[6]78", "a.tx[t]"))]);
    const [a, b] = await Promise.all([
      queryAs(r.gateway.port, KEY_ALPHA, { queryId: "q-a", sessionId: "conv-A", prompt: "PROBE-A", user_id: "user-a" }),
      queryAs(r.gateway.port, KEY_BETA, { queryId: "q-b", sessionId: "conv-B", prompt: "PROBE-B", user_id: "user-b" }),
    ]);
    expect(a.events.at(-1)?.type, JSON.stringify(a.events.at(-1))).toBe("done");
    expect(b.events.at(-1)?.type, JSON.stringify(b.events.at(-1))).toBe("done");

    // Both commands really overlapped: each file was written well within the other's 8 s wait.
    await waitForSessionsFile(r.gateway, "conv-A");
    const homeA = sessionHome(r.gateway, "conv-A");
    const homeB = sessionHome(r.gateway, "conv-B");
    expect(homeA).not.toBe(homeB);
    expect(Math.abs(fs.statSync(path.join(homeA, "a.txt")).mtimeMs - fs.statSync(path.join(homeB, "b.txt")).mtimeMs)).toBeLessThan(6000);

    const resultA = resultsFor(r.api, "PROBE-A").at(-1)?.text ?? "";
    const resultB = resultsFor(r.api, "PROBE-B").at(-1)?.text ?? "";
    // Controls: each sees its own file. The other's marker is nowhere: not in a file, a process or an environment.
    expect(resultA).toContain(`OWN=${SECRET_A}`);
    expect(resultB).toContain(`OWN=${SECRET_B}`);
    for (const result of [resultA, resultB]) {
      expect(result).toContain("HITS=0");
      expect(result).toContain("FILES=0");
      expect(result).toContain("PROCS=0");
      expect(result).toContain("HOMES=0");
    }
    // Model-bound requests, events and transcripts of each conversation hold nothing of the other.
    expect(JSON.stringify(requestsFor(r.api, "PROBE-A").map((q) => [q.userTexts, q.toolResults]))).not.toContain(SECRET_B);
    expect(JSON.stringify(requestsFor(r.api, "PROBE-B").map((q) => [q.userTexts, q.toolResults]))).not.toContain(SECRET_A);
    expect(JSON.stringify(a.events)).not.toContain(SECRET_B);
    expect(JSON.stringify(b.events)).not.toContain(SECRET_A);
    expect(grepTree(homeA, SECRET_B)).toEqual([]);
    expect(grepTree(homeB, SECRET_A)).toEqual([]);
    // Control: the transcripts do hold the conversation's own marker.
    expect(grepTree(homeA, SECRET_A).length).toBeGreaterThan(0);
    expect(grepTree(homeB, SECRET_B).length).toBeGreaterThan(0);

    // Another person of the same API-key label continues conv-A in conv-A's own home (the label decides, MVP-8044):
    // with another user id and with none, each gets a run that reads conv-A's file and no refusal text. Another
    // API-key label does not see the conversation at all (MVP-7679): it gets its own new conversation under the same
    // id. Neither label lists or deletes the other's conversation.
    r.scripts.push(bash("PROBE-A-WRITER", "echo SEEN=$(cat /work/a.txt)"), bash("PROBE-A-NOUSER", "echo SEEN=$(cat /work/a.txt)"));
    const sameLabelOtherUser = await queryAs(r.gateway.port, KEY_ALPHA, { queryId: "q-writer", sessionId: "conv-A", prompt: "PROBE-A-WRITER", user_id: "user-other" });
    expect(sameLabelOtherUser.events.at(-1)?.type, JSON.stringify(sameLabelOtherUser.events.at(-1))).toBe("done");
    expect(sameLabelOtherUser.events.some((e) => e.type === "error")).toBe(false);
    expect(resultsFor(r.api, "PROBE-A-WRITER").at(-1)?.text).toContain(`SEEN=${SECRET_A}`);
    const noUser = await queryAs(r.gateway.port, KEY_ALPHA, { queryId: "q-nouser", sessionId: "conv-A", prompt: "PROBE-A-NOUSER" });
    expect(noUser.events.at(-1)?.type, JSON.stringify(noUser.events.at(-1))).toBe("done");
    expect(resultsFor(r.api, "PROBE-A-NOUSER").at(-1)?.text).toContain(`SEEN=${SECRET_A}`);
    expect(sessionHome(r.gateway, "conv-A")).toBe(homeA);
    const listBeta = await getAs(r.gateway.port, KEY_BETA, "GET", "/v1/sessions");
    expect((listBeta.json?.sessions as { id: string }[]).map((s) => s.id)).toEqual(["conv-B"]);
    expect((await getAs(r.gateway.port, KEY_BETA, "DELETE", "/v1/sessions/conv-A")).status).toBe(404);
    expect((await getAs(r.gateway.port, KEY_ALPHA, "GET", "/v1/sessions")).json?.count).toBe(1);
    // Beta using alpha's id gets its OWN conversation: a different home with none of alpha's files.
    const betaSameId = await queryAs(r.gateway.port, KEY_BETA, { queryId: "q-beta-same", sessionId: "conv-A", prompt: "PROBE-B", user_id: "user-b" });
    expect(betaSameId.events.at(-1)?.type, JSON.stringify(betaSameId.events.at(-1))).toBe("done");
    const homeOfBetaA = savedEntryFor(r.gateway, "beta", "conv-A");
    expect(homeOfBetaA).toBeDefined();
    expect(homeOfBetaA).not.toBe(homeA);
    expect(fs.existsSync(path.join(homeOfBetaA!, "a.txt"))).toBe(false);
  });
});

describe("a conversation created after the update", () => {
  it("resumes after a gateway restart in its own home, with its earlier turn, and still cannot read credentials", async () => {
    const r = await rig([
      bash("PROBE-TURN1", "echo SYNTH-PERSIST-7678 > /work/persist.txt; echo WROTE"),
      bash("PROBE-TURN2", "echo PERSISTED=$(cat /work/persist.txt); echo CREDS=$(cat /home/node/.claude/.credentials.json 2>&1 | grep -c 'SYNTH-OAUTH-ACCES[S]'); echo CREDS_ANYWHERE=$(grep -rl --exclude-dir=proc --exclude-dir=sys 'SYNTH-OAUTH-ACCES[S]' / 2>/dev/null | wc -l)"),
    ]);
    const first = await queryAs(r.gateway.port, KEY_ALPHA, { queryId: "q-1", sessionId: "keep", prompt: "PROBE-TURN1", user_id: "user-1", useSession: true });
    expect(first.events.at(-1)?.type, JSON.stringify(first.events.at(-1))).toBe("done");
    await waitForSessionsFile(r.gateway, "keep");
    const home = sessionHome(r.gateway, "keep");
    expect(fs.readFileSync(path.join(path.dirname(home), "work", "persist.txt"), "utf8").trim()).toBe("SYNTH-PERSIST-7678");

    // Restart: stop the gateway cleanly, start a new process on the same directories.
    const old = r.gateway;
    old.child.kill("SIGTERM");
    await new Promise<void>((resolve) => (old.child.exitCode !== null ? resolve() : old.child.once("exit", () => resolve())));
    const restarted = await spawnGateway(cleanups, { reuse: old, env: GATEWAY_ENV(r.api) });
    expect(restarted.port).not.toBe(old.port);

    const started = Date.now();
    const second = await queryAs(restarted.port, KEY_ALPHA, { queryId: "q-2", sessionId: "keep", prompt: "PROBE-TURN2", user_id: "user-1", useSession: true });
    expect(second.events.at(-1)?.type, JSON.stringify(second.events.at(-1))).toBe("done");
    expect(Date.now() - started).toBeLessThan(60_000);
    // The resumed turn carries the earlier one, and the agent finds its own file but no credential.
    const turn2 = r.api.requests.filter((q) => q.userTexts.at(-1)?.includes("PROBE-TURN2") && !q.warmup);
    expect(turn2.length).toBeGreaterThan(0);
    expect(turn2[0].userTexts.join(" ")).toContain("PROBE-TURN1");
    const result = resultsFor(r.api, "PROBE-TURN2").at(-1);
    expect(result?.text).toContain("PERSISTED=SYNTH-PERSIST-7678");
    expect(result?.text).toContain("CREDS=0");
    expect(result?.text).toContain("CREDS_ANYWHERE=0");
    // Another user of the label continues it after the restart as well, in the same work area (the label decides, MVP-8044).
    r.scripts.push(bash("PROBE-TURN3", "echo PERSISTED=$(cat /work/persist.txt)"));
    const other = await queryAs(restarted.port, KEY_ALPHA, { queryId: "q-3", sessionId: "keep", prompt: "PROBE-TURN3", user_id: "user-2" });
    expect(other.events.at(-1)?.type, JSON.stringify(other.events.at(-1))).toBe("done");
    expect(resultsFor(r.api, "PROBE-TURN3").at(-1)?.text).toContain("PERSISTED=SYNTH-PERSIST-7678");
    // The home is the same directory before and after.
    expect(sessionHome(restarted, "keep")).toBe(home);
  });
});

describe("one active request per conversation", () => {
  it("a second request while the first still runs is refused with no run, even while the first keeps swapping links in its home; the conversation is free again afterwards", async () => {
    const swap = "i=0; while [ $i -lt 60 ]; do ln -sfn /home/node/.claude/CLAUDE.md /home/node/swap; ln -sfn /home /home/node/swap2; ln -sfn /home/node/.claude /home/node/swap3; i=$((i+1)); sleep 0.1; done; echo LOOP-DONE";
    const r = await rig([bash("PROBE-LONG", swap), bash("PROBE-SECOND", "echo SECOND-RAN"), bash("PROBE-THIRD", "echo THIRD-RAN")]);
    const first = queryAs(r.gateway.port, KEY_ALPHA, { queryId: "q-long", sessionId: "busy", prompt: "PROBE-LONG", user_id: "user-1", useSession: true });
    // Wait until the first run is really inside its command (the model stand-in has seen the prompt).
    const end = Date.now() + 30_000;
    while (requestsFor(r.api, "PROBE-LONG").filter((q) => !q.warmup).length === 0 && Date.now() < end) await new Promise((x) => setTimeout(x, 50));
    await new Promise((x) => setTimeout(x, 800));
    const started = Date.now();
    const second = await queryAs(r.gateway.port, KEY_ALPHA, { queryId: "q-second", sessionId: "busy", prompt: "PROBE-SECOND", user_id: "user-1", useSession: true });
    expect(Date.now() - started).toBeLessThan(2000);
    expect(second.events).toEqual([{ seq: 0, type: "error", content: "This conversation is still answering an earlier request. Please wait until it has finished, then try again." }]);
    expect(requestsFor(r.api, "PROBE-SECOND")).toEqual([]);
    // Another conversation of the same owner is not blocked.
    const parallel = await queryAs(r.gateway.port, KEY_ALPHA, { queryId: "q-par", sessionId: "busy-2", prompt: "PROBE-THIRD", user_id: "user-1", useSession: true });
    expect(parallel.events.at(-1)?.type).toBe("done");
    const firstResult = await first;
    expect(firstResult.events.at(-1)?.type, JSON.stringify(firstResult.events.at(-1))).toBe("done");
    expect(resultsFor(r.api, "PROBE-LONG").at(-1)?.text).toContain("LOOP-DONE");
    // Free again: the next request of the conversation is accepted and runs.
    const after = await queryAs(r.gateway.port, KEY_ALPHA, { queryId: "q-after", sessionId: "busy", prompt: "PROBE-SECOND", user_id: "user-1", useSession: true });
    expect(after.events.at(-1)?.type, JSON.stringify(after.events.at(-1))).toBe("done");
    expect(resultsFor(r.api, "PROBE-SECOND").at(-1)?.text).toContain("SECOND-RAN");
    // The links the first run planted sit in its own home only and hold no marker; the home dir name is the recorded random id.
    const home = sessionHome(r.gateway, "busy");
    expect(path.basename(path.dirname(home))).toMatch(/^[0-9a-f]{24}$/);
    expect(createHash("sha256").update("busy").digest("hex").slice(0, 24)).not.toBe(path.basename(path.dirname(home)));
  });
});
