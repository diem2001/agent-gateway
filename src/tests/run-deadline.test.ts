/**
 * AGENT_RUN_TIMEOUT_MS (MVP-7678): one deadline for the whole request, retries and backoff included.
 * The agent run is mocked here; the real-runtime deadline row is in sandbox-process.test.ts.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const runQuery = vi.fn();
vi.mock("../agent.js", () => ({ runQuery: (...args: unknown[]) => runQuery(...args) }));

import { runQueryWithRetry } from "../retry.js";
import { RunFailure, runDeadlineMessage } from "../run-failure.js";

const params = (abortController: AbortController) => ({
  queryId: "q-deadline",
  abortController,
  onEvent: () => {},
  prompt: "p",
});

beforeEach(() => {
  runQuery.mockReset();
  vi.spyOn(console, "log").mockImplementation(() => {});
});

afterEach(() => {
  delete process.env.AGENT_RUN_TIMEOUT_MS;
  vi.restoreAllMocks();
});

describe("the run deadline", () => {
  it("takes precedence over a retry backoff in progress, without starting another attempt", async () => {
    process.env.AGENT_RUN_TIMEOUT_MS = "300";
    // Every attempt fails with a transient provider error: the retry layer would wait 1 s, then 2 s, ...
    runQuery.mockRejectedValue(new Error("429 rate limit"));
    const started = Date.now();
    const controller = new AbortController();
    const error = await runQueryWithRetry(params(controller)).catch((e: unknown) => e);
    expect(Date.now() - started).toBeLessThan(900);
    expect(error).toBeInstanceOf(RunFailure);
    expect((error as RunFailure).kind).toBe("run_deadline");
    expect((error as RunFailure).message).toBe(runDeadlineMessage(300, "q-deadline"));
    expect((error as RunFailure).retryable).toBe(false);
    // One attempt ran; the backoff was cut short instead of starting a second one.
    expect(runQuery).toHaveBeenCalledTimes(1);
    expect(controller.signal.aborted).toBe(true);
  });

  it("discards an answer that arrives after the deadline", async () => {
    process.env.AGENT_RUN_TIMEOUT_MS = "100";
    runQuery.mockImplementation(async () => {
      await new Promise((r) => setTimeout(r, 300));
      return { response: "late answer", resultData: { session_id: "s" } };
    });
    const error = await runQueryWithRetry(params(new AbortController())).catch((e: unknown) => e);
    expect((error as RunFailure).kind).toBe("run_deadline");
  });

  it("does not interfere with a run that ends in time, and leaves no timer behind", async () => {
    process.env.AGENT_RUN_TIMEOUT_MS = "50";
    runQuery.mockResolvedValue({ response: "answer", resultData: null });
    const controller = new AbortController();
    await expect(runQueryWithRetry(params(controller))).resolves.toEqual({ response: "answer", resultData: null });
    await new Promise((r) => setTimeout(r, 120));
    expect(controller.signal.aborted).toBe(false);
  });

  it("hands every attempt a deadline promise that resolves at the limit and not before", async () => {
    process.env.AGENT_RUN_TIMEOUT_MS = "300";
    let seen: Promise<void> | undefined;
    let resolvedAtAttempt: boolean | undefined;
    runQuery.mockImplementation(async (attempt: { deadline?: Promise<void> }) => {
      seen = attempt.deadline;
      resolvedAtAttempt = await Promise.race([seen!.then(() => true), new Promise<boolean>((resolve) => setTimeout(() => resolve(false), 100))]);
      await new Promise((resolve) => setTimeout(resolve, 400));
      return { response: "late answer", resultData: null };
    });
    const started = Date.now();
    const error = await runQueryWithRetry(params(new AbortController())).catch((e: unknown) => e);

    expect(resolvedAtAttempt).toBe(false);
    await expect(seen).resolves.toBeUndefined();
    expect(Date.now() - started).toBeGreaterThanOrEqual(300);
    expect((error as RunFailure).kind).toBe("run_deadline");
  });
});
