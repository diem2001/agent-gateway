/**
 * The byte budget that forces garbage collection during a relayed upload
 * (src/gc-budget.ts). The memory effect itself is measured on a real gateway
 * process in upload-relay-process.test.ts.
 */
import { describe, expect, it } from "vitest";
import { DEFAULT_GC_BUDGET, GcBudget } from "../gc-budget.js";

const MiB = 1024 * 1024;

function recorder() {
  const calls: unknown[] = [];
  return { calls, collect: (options?: unknown) => calls.push(options) };
}

describe("GcBudget", () => {
  it("collects once per full budget of bytes, synchronously, with the configured type", () => {
    const { calls, collect } = recorder();
    const budget = new GcBudget({ budgetBytes: 2 * MiB, type: "minor" }, collect);
    for (let i = 0; i < 31; i++) budget.add(64 * 1024); // 1.94 MiB
    expect(calls).toHaveLength(0);
    budget.add(64 * 1024); // 2 MiB
    expect(calls).toEqual([{ type: "minor", execution: "sync" }]);
    for (let i = 0; i < 64; i++) budget.add(64 * 1024); // 4 MiB more
    expect(calls).toHaveLength(3);
    expect(budget.collections).toBe(3);
  });

  it("a single chunk larger than the budget triggers one collection", () => {
    const { calls, collect } = recorder();
    const budget = new GcBudget({ budgetBytes: MiB, type: "major" }, collect);
    budget.add(5 * MiB);
    expect(calls).toEqual([{ type: "major", execution: "sync" }]);
  });

  it("without an exposed gc, or with a zero budget, nothing is collected and nothing throws", () => {
    const none = new GcBudget({ budgetBytes: MiB, type: "minor" }, null);
    none.add(10 * MiB);
    expect(none.collections).toBe(0);

    const { calls, collect } = recorder();
    const zero = new GcBudget({ budgetBytes: 0, type: "minor" }, collect);
    zero.add(10 * MiB);
    expect(calls).toHaveLength(0);
  });

  it("the relay's default budget is a minor collection every 2 MiB", () => {
    expect(DEFAULT_GC_BUDGET).toEqual({ budgetBytes: 2 * MiB, type: "minor" });
  });
});
