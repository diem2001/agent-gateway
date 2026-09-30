import { randomUUID } from "node:crypto";
import { log } from "./logging.js";
import { runQuery, type QueryParams, type QueryResult } from "./agent.js";
import { RunFailure, classifyRunFailure, isAbortError } from "./run-failure.js";

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
 * A retry resumes only an established session: the original request resumed
 * one, or an earlier attempt ended with a result that is not `is_error` and
 * carries a `session_id`. Otherwise the retry starts fresh with a new SDK
 * session ID, so it never appends to, or resumes, a failed attempt's transcript.
 * A request without a session ID never resumes.
 */
export async function runQueryWithRetry({ queryId, ...params }: RetryParams): Promise<QueryResult> {
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
  return runQuery(attemptParams(RETRY_MAX_ATTEMPTS + 1));
}
