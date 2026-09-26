/**
 * MVP-7614 Outcome Probe — the gateway keeps answering and streaming while git
 * runs.
 *
 * Process rows: the compiled gateway runs as a child process (see
 * helpers/git-process-gateway.ts) with a fake `git` first on PATH that sleeps in
 * a pipe-holding grandchild before running the real git. While a slow git
 * operation runs, the test polls GET /health every 100 ms and reads a
 * POST /v1/query NDJSON stream whose model answer (a scripted stand-in for the
 * Anthropic API, "drip" mode) arrives as one text delta every 100 ms.
 *
 * In-process row: the real git router and a test route that writes one line
 * every 100 ms share this process; perf_hooks measures the event-loop delay
 * while a slow git operation runs.
 */
import { afterEach, describe, expect, it } from "vitest";
import express from "express";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { monitorEventLoopDelay } from "node:perf_hooks";
import { createFakeGit, type FakeGit } from "./helpers/fake-git.js";
import { createBareRepo, fixtureGit } from "./helpers/dumb-http-git-remote.js";
import { startFakeAnthropicApi } from "./helpers/fake-anthropic-api.js";
import { GATEWAY_API_KEY, gatewayRequest, getHealth, spawnGateway, type Cleanup, type SpawnedGateway } from "./helpers/git-process-gateway.js";

const cleanups: Cleanup[] = [];

afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()!();
});

/** The acceptance bounds. */
const HEALTH_LIMIT_MS = 200;
const STREAM_GAP_LIMIT_MS = 500;
const LOOP_DELAY_LIMIT_MS = 100;
/** The Outcome scenario's git operation takes 10 seconds. */
const OUTCOME_GIT_MS = 10_000;
/** The Missing Scenario rows: longer than reqlift's 3 s health-check timeout. */
const MISSING_ROW_GIT_MS = 4_000;

function testRoot(prefix: string): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  cleanups.push(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

/** Polls GET /health every 100 ms until `done` settles; returns every latency. */
async function pollHealthUntil(port: number, done: Promise<unknown>): Promise<{ status: number; ms: number }[]> {
  let finished = false;
  void done.finally(() => (finished = true));
  const results: { status: number; ms: number }[] = [];
  while (!finished) {
    const tickStart = performance.now();
    results.push(await getHealth(port));
    const rest = 100 - (performance.now() - tickStart);
    if (rest > 0) await new Promise((resolve) => setTimeout(resolve, rest));
  }
  return results;
}

/** Largest gap between consecutive arrivals that overlaps [from, to]; also counts arrivals inside it. */
function gapsDuring(arrivals: number[], from: number, to: number): { maxGap: number; inside: number } {
  let maxGap = 0;
  for (let i = 1; i < arrivals.length; i++) {
    if (arrivals[i] < from || arrivals[i - 1] > to) continue;
    maxGap = Math.max(maxGap, arrivals[i] - arrivals[i - 1]);
  }
  return { maxGap, inside: arrivals.filter((t) => t >= from && t <= to).length };
}

interface StreamRecorder {
  /** performance.now() of every NDJSON text line received. */
  textArrivals: number[];
  firstText: Promise<void>;
  finished: Promise<void>;
}

function startQueryStream(gateway: SpawnedGateway): StreamRecorder {
  const textArrivals: number[] = [];
  let resolveFirst!: () => void;
  const firstText = new Promise<void>((resolve) => (resolveFirst = resolve));
  const finished = new Promise<void>((resolve, reject) => {
    const payload = Buffer.from(
      JSON.stringify({ queryId: `q-7614-${Date.now()}`, prompt: "Say something long.", model: "claude-sonnet-4-5", useSession: false }),
    );
    const req = http.request(
      {
        host: "127.0.0.1",
        port: gateway.port,
        method: "POST",
        path: "/v1/query",
        agent: false,
        headers: { Authorization: `Bearer ${GATEWAY_API_KEY}`, "Content-Type": "application/json", "Content-Length": payload.length },
      },
      (res) => {
        let buffer = "";
        res.on("data", (chunk: Buffer) => {
          const now = performance.now();
          buffer += chunk.toString("utf8");
          let newline: number;
          while ((newline = buffer.indexOf("\n")) >= 0) {
            const line = buffer.slice(0, newline).trim();
            buffer = buffer.slice(newline + 1);
            if (!line.startsWith("{")) continue;
            if ((JSON.parse(line) as { type?: string }).type === "text") {
              textArrivals.push(now);
              resolveFirst();
            }
          }
        });
        res.on("end", () => resolve());
        res.on("error", reject);
      },
    );
    req.on("error", reject);
    req.end(payload);
  });
  return { textArrivals, firstText, finished };
}

async function gatewayWithFakeGit(prefix: string, env: Record<string, string> = {}): Promise<{ gateway: SpawnedGateway; fake: FakeGit; bare: string }> {
  const root = testRoot(prefix);
  const fake = createFakeGit(root);
  const bare = path.join(root, "remote.git");
  createBareRepo(fake.realGit, bare);
  const gateway = await spawnGateway(cleanups, { fakeGitBin: fake.binDir, env: { LOG_LEVEL: "info", ...env } });
  return { gateway, fake, bare };
}

describe("the gateway stays responsive while git runs (spawned gateway)", () => {
  it("Outcome: during a 10 s git operation /health answers 200 within 200 ms and the NDJSON stream has no gap over 500 ms", async () => {
    const api = await startFakeAnthropicApi({ toolName: "no_such_tool_7614", mode: "drip", dripChunks: 170, dripIntervalMs: 100 });
    cleanups.push(() => api.close());
    const { gateway, fake, bare } = await gatewayWithFakeGit("mvp7614-outcome-", {
      ANTHROPIC_BASE_URL: api.baseUrl,
      ANTHROPIC_API_KEY: "sk-ant-fake-outcome-7614",
      DISABLE_TELEMETRY: "1",
      CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
    });
    const checkout = path.join(gateway.dirs.projects, "outcome-repo");
    fixtureGit(fake.realGit, ["clone", "-b", "main", "--", bare, checkout], gateway.root);

    const stream = startQueryStream(gateway);
    await stream.firstText;

    fake.setSlow({ sleepMs: OUTCOME_GIT_MS, on: ["pull"] });
    const gitStart = performance.now();
    const gitReply = gatewayRequest(gateway.port, "POST", "/v1/workspace/git/clone", { url: bare, path: "outcome-repo" });
    let gitEnd = 0;
    void gitReply.finally(() => (gitEnd = performance.now()));
    const health = await pollHealthUntil(gateway.port, gitReply);
    const reply = await gitReply;
    await stream.finished;

    const worstHealth = Math.max(...health.map((h) => h.ms));
    const { maxGap, inside } = gapsDuring(stream.textArrivals, gitStart, gitEnd);
    const evidence = {
      gitMs: Math.round(gitEnd - gitStart),
      healthPolls: health.length,
      worstHealthMs: Math.round(worstHealth),
      streamLinesDuringGit: inside,
      maxStreamGapMs: Math.round(maxGap),
    };
    console.log(`[MVP-7614 outcome] ${JSON.stringify(evidence)}`);

    expect(reply.status).toBe(200);
    expect(reply.json).toMatchObject({ status: "pulled", path: "outcome-repo", branch: "main" });
    expect(evidence.gitMs).toBeGreaterThanOrEqual(OUTCOME_GIT_MS);
    expect(health.every((h) => h.status === 200)).toBe(true);
    expect(health.length).toBeGreaterThanOrEqual(40);
    expect(worstHealth).toBeLessThan(HEALTH_LIMIT_MS);
    // The stream kept flowing through the whole git window.
    expect(inside).toBeGreaterThanOrEqual(40);
    expect(stream.textArrivals[stream.textArrivals.length - 1]).toBeGreaterThan(gitEnd);
    expect(maxGap).toBeLessThan(STREAM_GAP_LIMIT_MS);
  }, 90_000);

  it("Missing Scenario: /health answers within 200 ms during a slow first clone, a slow pull and a slow status", async () => {
    const { gateway, fake, bare } = await gatewayWithFakeGit("mvp7614-missing-");
    const rows: { name: string; on: string[]; run: () => ReturnType<typeof gatewayRequest> }[] = [
      { name: "first clone", on: ["clone"], run: () => gatewayRequest(gateway.port, "POST", "/v1/workspace/git/clone", { url: bare, path: "missing-repo" }) },
      { name: "pull", on: ["pull"], run: () => gatewayRequest(gateway.port, "POST", "/v1/workspace/git/pull", { path: "missing-repo" }) },
      { name: "status", on: ["status"], run: () => gatewayRequest(gateway.port, "GET", "/v1/workspace/git/status?path=missing-repo") },
    ];
    for (const row of rows) {
      fake.setSlow({ sleepMs: MISSING_ROW_GIT_MS, on: row.on });
      const started = performance.now();
      const pending = row.run();
      const health = await pollHealthUntil(gateway.port, pending);
      const reply = await pending;
      const elapsed = performance.now() - started;
      const worst = Math.max(...health.map((h) => h.ms));
      console.log(`[MVP-7614 missing-scenario] ${JSON.stringify({ row: row.name, gitMs: Math.round(elapsed), polls: health.length, worstHealthMs: Math.round(worst) })}`);
      expect(reply.status, `${row.name}: ${reply.text}`).toBe(200);
      expect(elapsed).toBeGreaterThanOrEqual(MISSING_ROW_GIT_MS);
      expect(health.every((h) => h.status === 200)).toBe(true);
      expect(health.length).toBeGreaterThanOrEqual(15);
      expect(worst, row.name).toBeLessThan(HEALTH_LIMIT_MS);
    }
    fake.setSlow(null);
  }, 90_000);
});

describe("the gateway stays responsive while git runs (in-process)", () => {
  it("a stream line every 100 ms keeps flowing and the event-loop delay stays below 100 ms during a 10 s git operation", async () => {
    const root = testRoot("mvp7614-eld-");
    const fake = createFakeGit(root);
    const workspace = path.join(root, "workspace");
    fs.mkdirSync(path.join(workspace, "projects"), { recursive: true });
    const bare = path.join(root, "remote.git");
    createBareRepo(fake.realGit, bare);
    process.env.WORKSPACE_ROOT = workspace;
    process.env.GIT_CONFIG_NOSYSTEM = "1";
    process.env.GIT_CONFIG_GLOBAL = "/dev/null";
    process.env.PATH = `${fake.binDir}${path.delimiter}${process.env.PATH ?? ""}`;
    const { default: gitRoutes } = await import("../routes/git.js");

    const app = express();
    app.use(express.json());
    app.get("/test-stream", (_req, res) => {
      res.setHeader("Content-Type", "application/x-ndjson");
      let n = 0;
      const timer = setInterval(() => {
        res.write(JSON.stringify({ n: n++ }) + "\n");
      }, 100);
      res.on("close", () => clearInterval(timer));
    });
    app.use(gitRoutes);
    const server = await new Promise<Server>((resolve) => {
      const s = app.listen(0, "127.0.0.1", () => resolve(s));
    });
    cleanups.push(() => new Promise<void>((resolve) => server.close(() => resolve())));
    const port = (server.address() as AddressInfo).port;

    const arrivals: number[] = [];
    const streamReq = http.get({ host: "127.0.0.1", port, path: "/test-stream", agent: false }, (res) => {
      res.on("data", () => arrivals.push(performance.now()));
    });
    streamReq.on("error", () => undefined);
    cleanups.push(() => void streamReq.destroy());
    while (arrivals.length < 3) await new Promise((resolve) => setTimeout(resolve, 50));

    fake.setSlow({ sleepMs: OUTCOME_GIT_MS, on: ["clone"] });
    const histogram = monitorEventLoopDelay({ resolution: 10 });
    histogram.enable();
    const gitStart = performance.now();
    const res = await fetch(`http://127.0.0.1:${port}/v1/workspace/git/clone`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: bare, path: "eld-repo" }),
    });
    const gitEnd = performance.now();
    histogram.disable();
    const body = await res.json();
    // One more line after the git operation closes the last gap.
    const count = arrivals.length;
    while (arrivals.length === count) await new Promise((resolve) => setTimeout(resolve, 20));

    const { maxGap, inside } = gapsDuring(arrivals, gitStart, gitEnd);
    const maxDelayMs = histogram.max / 1e6;
    console.log(
      `[MVP-7614 in-process] ${JSON.stringify({ gitMs: Math.round(gitEnd - gitStart), maxLoopDelayMs: Math.round(maxDelayMs), streamLinesDuringGit: inside, maxStreamGapMs: Math.round(maxGap) })}`,
    );
    expect(res.status).toBe(200);
    expect(body).toMatchObject({ status: "cloned", path: "eld-repo" });
    expect(gitEnd - gitStart).toBeGreaterThanOrEqual(OUTCOME_GIT_MS);
    expect(maxDelayMs).toBeLessThan(LOOP_DELAY_LIMIT_MS);
    expect(inside).toBeGreaterThanOrEqual(80);
    expect(maxGap).toBeLessThan(STREAM_GAP_LIMIT_MS);
  }, 60_000);
});
