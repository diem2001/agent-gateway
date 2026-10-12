/**
 * A client abort ends the request without another attempt (MVP-7866). The agent run is mocked here; the
 * real-runtime row (attempts counted at the model boundary) is in client-disconnect-control-request-process.test.ts.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const runQuery = vi.fn();
vi.mock("../agent.js", () => ({ runQuery: (...args: unknown[]) => runQuery(...args) }));

import { runQueryWithRetry } from "../retry.js";
import { isAbortError } from "../run-failure.js";

const params = (abortController: AbortController, events: unknown[] = []) => ({
  queryId: "q-abort",
  abortController,
  onEvent: (event: unknown) => events.push(event),
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

describe("no further attempt after a client abort", () => {
  it("RA1: an attempt that ends empty after the abort ends the request with the abort, no retry event, no second attempt", async () => {
    const controller = new AbortController();
    const events: unknown[] = [];
    runQuery.mockImplementation(async () => {
      controller.abort();
      return { response: "", resultData: null };
    });
    const started = Date.now();
    const error = await runQueryWithRetry(params(controller, events)).catch((e: unknown) => e);
    expect(isAbortError(error)).toBe(true);
    expect((error as Error).message).toBe("Operation aborted");
    expect(events).toEqual([]);
    expect(runQuery).toHaveBeenCalledTimes(1);
    expect(Date.now() - started).toBeLessThan(500);
  });

  it("RA2: a transient failure, then an abort during the backoff: no second attempt", async () => {
    const controller = new AbortController();
    runQuery.mockRejectedValue(new Error("429 rate limit"));
    setTimeout(() => controller.abort(), 100);
    const error = await runQueryWithRetry(params(controller)).catch((e: unknown) => e);
    expect(isAbortError(error)).toBe(true);
    expect((error as Error).message).toBe("Operation aborted");
    expect(runQuery).toHaveBeenCalledTimes(1);
  });

  it("RA3: an empty answer, then an abort during the backoff: no second attempt", async () => {
    const controller = new AbortController();
    runQuery.mockResolvedValue({ response: "", resultData: null });
    setTimeout(() => controller.abort(), 100);
    const error = await runQueryWithRetry(params(controller)).catch((e: unknown) => e);
    expect(isAbortError(error)).toBe(true);
    expect(runQuery).toHaveBeenCalledTimes(1);
  });

  it("RA3b: a transient failure of an aborted attempt is not retried and the abort wins", async () => {
    const controller = new AbortController();
    runQuery.mockImplementation(async () => {
      controller.abort();
      throw new Error("429 rate limit");
    });
    const error = await runQueryWithRetry(params(controller)).catch((e: unknown) => e);
    expect(isAbortError(error)).toBe(true);
    expect(runQuery).toHaveBeenCalledTimes(1);
  });

  it("RA4: an empty answer without an abort is still retried", async () => {
    runQuery.mockResolvedValueOnce({ response: "", resultData: null }).mockResolvedValueOnce({ response: "answer", resultData: null });
    const events: { type: string }[] = [];
    const result = await runQueryWithRetry(params(new AbortController(), events));
    expect(result.response).toBe("answer");
    expect(runQuery).toHaveBeenCalledTimes(2);
    expect(events.map((e) => e.type)).toEqual(["rate_limited"]);
  });

  it("RA5: an aborted attempt that produced an answer returns it unchanged", async () => {
    const controller = new AbortController();
    runQuery.mockImplementation(async () => {
      controller.abort();
      return { response: "partial answer", resultData: null };
    });
    await expect(runQueryWithRetry(params(controller))).resolves.toEqual({ response: "partial answer", resultData: null });
    expect(runQuery).toHaveBeenCalledTimes(1);
  });

  it("RA6: the run deadline still reports run_deadline, not the abort", async () => {
    process.env.AGENT_RUN_TIMEOUT_MS = "100";
    runQuery.mockResolvedValue({ response: "", resultData: null });
    const error = await runQueryWithRetry(params(new AbortController())).catch((e: unknown) => e);
    expect((error as { kind?: string }).kind).toBe("run_deadline");
    expect(runQuery).toHaveBeenCalledTimes(1);
  });
});
