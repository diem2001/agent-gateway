import { log } from "./logging.js";
import { runQuery, type QueryParams, type QueryResult } from "./agent.js";

const RETRY_MAX_ATTEMPTS = 3;
const RETRY_BASE_DELAY_MS = 1000;
const RETRY_BUDGET_MS = 60_000;

function shouldRetry(response: string | null, _resultData: Record<string, unknown> | null, err: Error | null): boolean {
  if (err) { const msg = err.message || ""; if (/rate.limit|429|throttl|overloaded/i.test(msg)) return true; return false; }
  if (!response || response.trim().length === 0) return true;
  return false;
}

export interface RetryParams extends QueryParams { queryId: string; }

export async function runQueryWithRetry({ queryId, ...params }: RetryParams): Promise<QueryResult> {
  const startTime = Date.now();

  for (let attempt = 0; attempt <= RETRY_MAX_ATTEMPTS; attempt++) {
    if (params.abortController.signal.aborted) break;
    try {
      const { response, resultData } = await runQuery({ ...params, isResume: attempt > 0 ? true : params.isResume });
      if (attempt < RETRY_MAX_ATTEMPTS && shouldRetry(response, resultData, null)) {
        const elapsed = Date.now() - startTime;
        const delayMs = RETRY_BASE_DELAY_MS * Math.pow(2, attempt);
        if (elapsed + delayMs > RETRY_BUDGET_MS) { log("retry", `queryId=${queryId} budget exhausted after ${attempt + 1} attempt(s), ${elapsed}ms elapsed`); return { response, resultData }; }
        log("retry", `queryId=${queryId} empty/throttled response, attempt ${attempt + 1}/${RETRY_MAX_ATTEMPTS}, waiting ${delayMs}ms`);
        params.onEvent({ type: "rate_limited", status: "retrying", attempt: attempt + 1, waitMs: delayMs });
        await new Promise<void>((resolve) => { const timer = setTimeout(resolve, delayMs); const onAbort = (): void => { clearTimeout(timer); resolve(); }; params.abortController.signal.addEventListener("abort", onAbort, { once: true }); });
        continue;
      }
      return { response, resultData };
    } catch (err) {
      const error = err as Error;
      if (attempt < RETRY_MAX_ATTEMPTS && shouldRetry(null, null, error)) {
        const elapsed = Date.now() - startTime;
        const delayMs = RETRY_BASE_DELAY_MS * Math.pow(2, attempt);
        if (elapsed + delayMs > RETRY_BUDGET_MS) { log("retry", `queryId=${queryId} budget exhausted on error after ${attempt + 1} attempt(s)`); throw error; }
        log("retry", `queryId=${queryId} rate-limit error, attempt ${attempt + 1}/${RETRY_MAX_ATTEMPTS}, waiting ${delayMs}ms: ${error.message}`);
        params.onEvent({ type: "rate_limited", status: "retrying", attempt: attempt + 1, waitMs: delayMs });
        await new Promise<void>((resolve) => { const timer = setTimeout(resolve, delayMs); const onAbort = (): void => { clearTimeout(timer); resolve(); }; params.abortController.signal.addEventListener("abort", onAbort, { once: true }); });
        continue;
      }
      throw error;
    }
  }
  return runQuery({ ...params, isResume: true });
}
