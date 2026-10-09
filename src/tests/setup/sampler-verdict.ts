/**
 * The verdict of the process sampler windows of a test file (MVP-8139). A window with a lost tick (a counted `/proc` read that failed with an
 * error that does not say "the process is gone") cannot be assessed, whatever its test asserted. This setup file makes that a failure for every
 * test that started a window:
 *
 * - `beforeEach` names the running test, so that a window knows which test started it;
 * - the global `afterEach` stops every window the test left running, asks `lostTickVerdict` and fails the test with the not-assessable text;
 * - `afterAll` fails the file on any window that no `afterEach` decided on (started or stopped in `beforeAll`, `afterAll` or outside a test),
 *   prints one `SECURITY-LOST-TICKS` line for the file when it had windows, and clears the ledger so that a reused worker carries nothing over.
 *
 * It reads only the ledger on `globalThis` (see `samplerLedger` in the helper) and loads the helper lazily, so a file without a sampler pays nothing.
 * Vitest 4 runs the `afterEach` hooks of a setup file after those of the test file (`sequence.hooks: "stack"`, the default; `vitest.config.ts`
 * must not override it), so fixtures are reaped before windows are judged.
 */
import { afterAll, afterEach, beforeEach, expect } from "vitest";
import type { SamplerLedger } from "../helpers/security-matrix.js";

const LEDGER = Symbol.for("agent-gateway.sampler-ledger");
const holder = globalThis as Record<symbol, SamplerLedger | undefined>;
let testNumber = 0;

beforeEach(() => {
  const ledger = (holder[LEDGER] ??= { entries: [], current: undefined, nextId: 1 });
  ledger.current = `test-${++testNumber}`;
});

afterEach(async () => {
  const ledger = holder[LEDGER];
  if (ledger === undefined) return;
  const mine = ledger.entries.filter((entry) => entry.test === ledger.current && !entry.drained);
  ledger.current = undefined;
  if (mine.length === 0) return;
  for (const entry of mine) if (entry.running) entry.stop();
  const { lostTickVerdict } = await import("../helpers/security-matrix.js");
  const { problems } = lostTickVerdict(mine);
  for (const entry of mine) entry.drained = true;
  if (problems.length > 0) throw new Error(problems.join("; "));
});

afterAll(async () => {
  const ledger = holder[LEDGER];
  holder[LEDGER] = undefined;
  if (ledger === undefined || ledger.entries.length === 0) return;
  const undecided = ledger.entries.filter((entry) => !entry.drained);
  for (const entry of undecided) if (entry.running) entry.stop();
  const { lostTickVerdict } = await import("../helpers/security-matrix.js");
  const lost = ledger.entries.reduce((sum, entry) => sum + entry.natural + entry.injected, 0);
  const injected = ledger.entries.reduce((sum, entry) => sum + entry.injected, 0);
  const notAcknowledged = ledger.entries.reduce((sum, entry) => sum + entry.natural + entry.injected - Math.min(entry.acknowledged, entry.injected), 0);
  const file = (expect.getState().testPath ?? "unknown").split("/").at(-1);
  process.stderr.write(`SECURITY-LOST-TICKS file=${file} windows=${ledger.entries.length} lost_ticks=${lost} injected=${injected} not_acknowledged=${notAcknowledged}\n`);
  const { problems } = lostTickVerdict(undecided);
  if (undecided.length > 0) throw new Error(`${undecided.length} sampler window(s) started or stopped outside a test were never judged by an afterEach${problems.length > 0 ? `: ${problems.join("; ")}` : ""}`);
});
