import { randomUUID } from "node:crypto";
import { log } from "./logging.js";
import { runQuery, type QueryParams, type QueryResult } from "./agent.js";
import { RunFailure, abortError, classifyRunFailure, fixedFailure, isAbortError, runDeadlineMessage } from "./run-failure.js";
import { loadIsolationConfig } from "./sandbox.js";

const RETRY_MAX_ATTEMPTS = 3;
const RETRY_BASE_DELAY_MS = 1000;
const RETRY_BUDGET_MS = 60_000;

/** An empty answer from a run that did not fail is retried. */
function isEmptyResponse(response: string | null): boolean {
  return !response || response.trim().length === 0;
}

export interface RetryParams extends QueryParams { queryId: string; }

/**
 * Runs the query and retries empty answers and transient failures
 * (`RunFailure.retryable`) within RETRY_MAX_ATTEMPTS retries and
 * RETRY_BUDGET_MS. A permanent failure is thrown at once.
 *
 * A client abort ends the request with the abort error and starts no further attempt: an attempt that
 * ends empty or failed after the abort, or an abort during a backoff, is not retried.
 *
 * A retry resumes only an established session: the original request resumed
 * one, or an earlier attempt ended with a result that is not `is_error` and
 * carries a `session_id`. Otherwise the retry starts fresh with a new SDK
 * session ID, so it never appends to, or resumes, a failed attempt's transcript.
 * A request without a session ID never resumes.
 */
export async function runQueryWithRetry(retryParams: RetryParams): Promise<QueryResult> {
  // One deadline for the whole request, retries and backoff included (AGENT_RUN_TIMEOUT_MS, MVP-7678).
  // It stops the run through the same abort a client disconnect uses, and its expiry is reported as
  // its own failure: the run's answer is discarded and nothing is saved to the conversation.
  const limitMs = loadIsolationConfig().runTimeoutMs;
  let deadlineHit = false;
  const timer = setTimeout(() => {
    deadlineHit = true;
    retryParams.abortController.abort();
  }, limitMs);
  const deadlineFailure = (): RunFailure => fixedFailure("run_deadline", runDeadlineMessage(limitMs, retryParams.queryId));
  try {
    const result = await runWithRetry(retryParams, () => deadlineHit);
    if (deadlineHit) throw deadlineFailure();
    return result;
  } catch (err) {
    if (deadlineHit) throw deadlineFailure();
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

async function runWithRetry({ queryId, ...params }: RetryParams, deadlineHit: () => boolean): Promise<QueryResult> {
  const startTime = Date.now();
  let established = params.isResume === true;
  let sessionId = params.sessionId;
  const attemptParams = (attempt: number): QueryParams => {
    if (attempt > 0 && !established && sessionId) sessionId = randomUUID();
    return { ...params, queryId, sessionId, isResume: established };
  };
  const wait = (delayMs: number): Promise<void> =>
    new Promise<void>((resolve) => { const timer = setTimeout(resolve, delayMs); const onAbort = (): void => { clearTimeout(timer); resolve(); }; params.abortController.signal.addEventListener("abort", onAbort, { once: true }); });

  for (let attempt = 0; attempt <= RETRY_MAX_ATTEMPTS; attempt++) {
    if (params.abortController.signal.aborted) break;
    try {
      const { response, resultData } = await runQuery(attemptParams(attempt));
      const resultSessionId = typeof resultData?.session_id === "string" ? resultData.session_id : undefined;
      if (resultSessionId && params.sessionId) { established = true; sessionId = resultSessionId; }
      if (params.abortController.signal.aborted && isEmptyResponse(response)) throw abortError();
      if (attempt < RETRY_MAX_ATTEMPTS && isEmptyResponse(response)) {
        const elapsed = Date.now() - startTime;
        const delayMs = RETRY_BASE_DELAY_MS * Math.pow(2, attempt);
        if (elapsed + delayMs > RETRY_BUDGET_MS) { log("retry", `queryId=${queryId} budget exhausted after ${attempt + 1} attempt(s), ${elapsed}ms elapsed`); return { response, resultData }; }
        log("retry", `queryId=${queryId} empty response, attempt ${attempt + 1}/${RETRY_MAX_ATTEMPTS}, waiting ${delayMs}ms`);
        params.onEvent({ type: "rate_limited", status: "retrying", attempt: attempt + 1, waitMs: delayMs });
        await wait(delayMs);
        continue;
      }
      return { response, resultData };
    } catch (err) {
      if (isAbortError(err)) throw err;
      if (params.abortController.signal.aborted && !deadlineHit()) throw abortError();
      const failure = err instanceof RunFailure ? err : classifyRunFailure({ thrown: err }, queryId);
      if (attempt < RETRY_MAX_ATTEMPTS && failure.retryable) {
        const elapsed = Date.now() - startTime;
        const delayMs = RETRY_BASE_DELAY_MS * Math.pow(2, attempt);
        if (elapsed + delayMs > RETRY_BUDGET_MS) { log("retry", `queryId=${queryId} kind=${failure.kind} budget exhausted after ${attempt + 1} attempt(s)`); throw failure; }
        log("retry", `queryId=${queryId} kind=${failure.kind} attempt ${attempt + 1}/${RETRY_MAX_ATTEMPTS}, waiting ${delayMs}ms`);
        params.onEvent({ type: "rate_limited", status: "retrying", attempt: attempt + 1, waitMs: delayMs });
        await wait(delayMs);
        continue;
      }
      throw failure;
    }
  }
  // The deadline or a client abort ended the loop: no further run is started.
  if (deadlineHit()) throw fixedFailure("run_deadline", "");
  throw abortError();
}
