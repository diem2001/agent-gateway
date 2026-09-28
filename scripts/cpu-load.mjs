#!/usr/bin/env node
/**
 * Runs a command on a deliberately loaded host, so timing-sensitive tests are
 * measured under a documented, repeatable CPU load instead of whatever else
 * happens to run (MVP-7805).
 *
 *   node scripts/cpu-load.mjs [--workers N] [--warmup-ms MS] [--max-ms MS] -- <command> [args...]
 *
 * Starts N busy worker threads (default: os.availableParallelism()), waits
 * until the 1-minute load average is at least the CPU count, records the CPU
 * count and /proc/loadavg, runs the command, records /proc/loadavg again and
 * stops the workers. Prints one `[cpu-load]` line per step and a final summary
 * line; the exit code is the command's.
 *
 * Exit codes:
 *   <command's code>  the command exited normally
 *   128 + N           the command was killed by signal N (never 0)
 *   75                inconclusive: the load average did not reach the CPU count
 *                     within --warmup-ms, or the command could not start
 *   124               inconclusive: --max-ms passed; the command was stopped
 *
 * The load degrades every other service on the host for its duration. Run it
 * only inside scripts/run-verification.mjs (the host-wide lease), so it never
 * overlaps another session's reserved run, and keep the command short.
 */
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import { Worker } from "node:worker_threads";

const DEFAULT_WARMUP_MS = 180_000;
const DEFAULT_MAX_MS = 30 * 60_000;
const SAMPLE_MS = 5_000;
const SIGNALS = os.constants.signals;

function usage(message) {
  if (message) console.error(`[cpu-load] ${message}`);
  console.error("usage: node scripts/cpu-load.mjs [--workers N] [--warmup-ms MS] [--max-ms MS] -- <command> [args...]");
  process.exit(2);
}

function parseArgs(argv) {
  const separator = argv.indexOf("--");
  if (separator === -1 || separator === argv.length - 1) usage("expected -- <command>");
  const options = { workers: os.availableParallelism(), warmupMs: DEFAULT_WARMUP_MS, maxMs: DEFAULT_MAX_MS };
  const names = { "--workers": "workers", "--warmup-ms": "warmupMs", "--max-ms": "maxMs" };
  for (let i = 0; i < separator; i += 2) {
    const key = names[argv[i]];
    const value = Number(argv[i + 1]);
    if (!key || i + 1 >= separator || !Number.isSafeInteger(value) || value < 1) usage(`invalid option ${argv[i]}`);
    options[key] = value;
  }
  options.command = argv.slice(separator + 1);
  return options;
}

function loadavg() {
  return fs.readFileSync("/proc/loadavg", "utf8").trim();
}

function oneMinute() {
  return Number(loadavg().split(" ")[0]);
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** A busy loop that allocates nothing; `terminate()` interrupts it. */
const BUSY_LOOP = "let x = 1; for (;;) { x = (Math.imul(x, 1103515245) + 12345) | 0; }";

const options = parseArgs(process.argv.slice(2));
const cpus = os.availableParallelism();
const startedAt = Date.now();
const workers = Array.from({ length: options.workers }, () => new Worker(BUSY_LOOP, { eval: true }));
let child = null;
let stopRequested = null;

function stopWorkers() {
  return Promise.all(workers.map((worker) => worker.terminate()));
}

function killChildGroup(signal) {
  if (!child?.pid) return;
  try {
    process.kill(-child.pid, signal);
  } catch {
    // The group is already gone.
  }
}

async function finish(code, reason) {
  await stopWorkers();
  console.log(
    `[cpu-load] summary: result=${reason} exit=${code} cpus=${cpus} workers=${options.workers} ` +
      `max_ms=${options.maxMs} load_duration_ms=${Date.now() - startedAt}`,
  );
  process.exit(code);
}

// The runner stops its owned process group with SIGINT/SIGTERM; pass that on.
for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => {
    stopRequested = signal;
    if (child) killChildGroup(signal);
    else void finish(128 + SIGNALS[signal], "interrupted");
  });
}

console.log(`[cpu-load] cpus=${cpus} workers=${options.workers} warmup_ms=${options.warmupMs} max_ms=${options.maxMs}`);
console.log(`[cpu-load] loadavg at start: ${loadavg()}`);

const warmupDeadline = Date.now() + options.warmupMs;
while (oneMinute() < cpus) {
  if (Date.now() >= warmupDeadline) {
    console.log(`[cpu-load] warm-up failed: 1-minute load ${oneMinute()} < ${cpus} after ${options.warmupMs} ms`);
    await finish(75, "warmup_failed");
  }
  await sleep(1_000);
}

const before = loadavg();
console.log(`[cpu-load] loadavg before command: ${before} (warm-up ${Date.now() - startedAt} ms)`);

let minDuring = Infinity;
let maxDuring = 0;
const sampler = setInterval(() => {
  const value = oneMinute();
  minDuring = Math.min(minDuring, value);
  maxDuring = Math.max(maxDuring, value);
}, SAMPLE_MS);

let timedOut = false;
child = spawn(options.command[0], options.command.slice(1), { stdio: "inherit", detached: true });
const cap = setTimeout(() => {
  timedOut = true;
  console.log(`[cpu-load] max duration ${options.maxMs} ms reached; stopping the command`);
  killChildGroup("SIGTERM");
  setTimeout(() => killChildGroup("SIGKILL"), 5_000).unref();
}, options.maxMs);

const { code, signal, spawnError } = await new Promise((resolve) => {
  child.once("error", () => resolve({ code: null, signal: null, spawnError: true }));
  child.once("exit", (exitCode, exitSignal) => resolve({ code: exitCode, signal: exitSignal, spawnError: false }));
});
clearTimeout(cap);
clearInterval(sampler);
// Leave no background process of the command behind.
killChildGroup("SIGKILL");

const after = loadavg();
const range = Number.isFinite(minDuring) ? ` 1-min min=${minDuring} max=${maxDuring} (sampled every ${SAMPLE_MS} ms)` : "";
console.log(`[cpu-load] loadavg after command: ${after};${range}`);

if (spawnError) await finish(75, "command_not_started");
if (timedOut) await finish(124, "timeout");
if (signal) await finish(128 + (SIGNALS[signal] ?? 0), stopRequested ? "interrupted" : `signal_${signal}`);
await finish(code ?? 1, "completed");
