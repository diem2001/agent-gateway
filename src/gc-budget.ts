/**
 * Byte-budgeted garbage collection for relayed uploads (ported from mcp-jira
 * `src/uploads/gc-budget.ts`).
 *
 * Node copies every received body chunk into a new buffer. The upload relay
 * forwards each chunk and drops it, but V8 frees those buffers only when it
 * collects garbage, and on its own it lets tens of MB of them pile up first.
 * Without help, a single relayed upload therefore raises the process peak by
 * tens of MB although it never holds more than a few chunks.
 *
 * The relay calls `add()` for every forwarded chunk; each time `budgetBytes`
 * have passed since the last collection, it forces one. This needs the process
 * to be started with `--expose-gc` (entrypoint.sh and `npm start` do that).
 * Without the flag `add()` does nothing and the relay still works, only with
 * the default peak.
 */

export type GcType = "major" | "minor";

export interface GcBudgetOptions {
  budgetBytes: number;
  type: GcType;
}

type ExposedGc = (options?: { type?: GcType; execution?: "sync" | "async" }) => unknown;

/** The `gc` function from `--expose-gc`, or null when the process was started without it. */
export function exposedGc(): ExposedGc | null {
  const candidate = (globalThis as { gc?: unknown }).gc;
  return typeof candidate === "function" ? (candidate as ExposedGc) : null;
}

/**
 * Forced collection after every 2 MiB relayed. A minor collection frees the
 * short-lived chunk buffers; a major one freed no more in mcp-jira but made
 * loopback uploads several times slower on the Node 22 image.
 */
export const DEFAULT_GC_BUDGET: GcBudgetOptions = { budgetBytes: 2 * 1024 * 1024, type: "minor" };

export class GcBudget {
  private sinceLast = 0;
  /** Collections forced by this budget (read by tests). */
  collections = 0;

  constructor(
    private readonly options: GcBudgetOptions,
    private readonly collect: ExposedGc | null = exposedGc(),
  ) {}

  add(bytes: number): void {
    if (!this.collect || this.options.budgetBytes <= 0) return;
    this.sinceLast += bytes;
    if (this.sinceLast < this.options.budgetBytes) return;
    this.sinceLast = 0;
    this.collections += 1;
    this.collect({ type: this.options.type, execution: "sync" });
  }
}
