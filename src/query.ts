import { Router, type Request, type Response } from "express";
import { log, logDebug } from "./logging.js";
import { createCacheEntry, getCacheEntry, markDone, type StreamEvent } from "./event-cache.js";
import { runQueryWithRetry } from "./retry.js";
import { getSession, updateSessionSdkId } from "./sessions.js";

interface QueryRequestBody {
  queryId?: string; sessionId?: string; prompt?: string; systemPrompt?: string;
  model?: string; allowedTools?: string[]; useSession?: boolean; sshTarget?: string;
  user_id?: string; conversation_id?: string;
}

export const queryRouter = Router();

queryRouter.post("/v1/query", async (req: Request, res: Response) => {
  const { queryId, sessionId, prompt, systemPrompt, model, allowedTools, useSession, sshTarget, user_id, conversation_id } = req.body as QueryRequestBody;
  if (!queryId || !prompt) { res.status(400).json({ error: "queryId and prompt are required" }); return; }

  const webhookContext = {
    api_key_label: req.clientLabel,
    user_id: user_id || undefined,
    conversation_id: conversation_id || undefined,
    session_id: useSession !== false ? sessionId : undefined,
  };
  // Extract Bearer token from client request to forward to tool webhooks
  const clientAuthToken = (req.headers.authorization || "").replace(/^Bearer\s+/i, "") || undefined;

  res.setHeader("Content-Type", "application/x-ndjson");
  res.setHeader("Transfer-Encoding", "chunked");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("X-Accel-Buffering", "no");

  let seq = 0;
  const cacheEntry = createCacheEntry(queryId);

  function emit(event: Omit<StreamEvent, "seq">): void {
    const line = { seq: seq++, ...event } as StreamEvent;
    cacheEntry.events.push(line);
    if (!res.writableEnded) { const json = JSON.stringify(line) + "\n"; res.write(json); logDebug("out", json.trimEnd()); }
    for (const listener of cacheEntry.listeners) { listener(line); }
  }

  const abortController = new AbortController();
  res.on("close", () => { if (!res.writableEnded) abortController.abort(); });

  const startTime = Date.now();

  try {
    // Resolve session: map client sessionId → SDK sessionId for resume
    let effectiveSessionId = useSession !== false ? sessionId : undefined;
    let isResume = false;
    if (effectiveSessionId) {
      const resolved = getSession(effectiveSessionId, systemPrompt || "", model || "claude-sonnet-4-20250514");
      if (!resolved.isNew) {
        // Existing session: resume with the SDK sessionId (stored on disk)
        effectiveSessionId = resolved.sessionId;
        isResume = true;
      } else {
        // New session: use the SDK sessionId assigned by getSession
        effectiveSessionId = resolved.sessionId;
      }
    }

    const { response: _response, resultData } = await runQueryWithRetry({
      prompt, systemPrompt, model, allowedTools,
      sessionId: effectiveSessionId,
      isResume, abortController, onEvent: emit, queryId, webhookContext, clientAuthToken,
    });

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const result = resultData as any;
    const sdkResultSessionId = (result?.session_id || result?.sessionId) as string | undefined;
    log("query", `SDK session_id=${sdkResultSessionId || "none"} (client: ${sessionId || "none"}, isResume: ${isResume})`);
    // Update session mapping if SDK returned a different sessionId than what we generated
    if (sessionId && sdkResultSessionId) {
      updateSessionSdkId(sessionId, sdkResultSessionId);
    }
    const usage = result?.usage || {};
    const inputTokens: number = usage.input_tokens || 0;
    const outputTokens: number = usage.output_tokens || 0;
    const costUsd: number = result?.total_cost_usd || 0;

    let contextWindow = 200000;
    let cacheReadTokens = 0;
    let cacheCreationTokens = 0;
    if (result?.modelUsage) {
      const modelKey = Object.keys(result.modelUsage as Record<string, unknown>)[0];
      if (modelKey) {
        const mu = result.modelUsage[modelKey];
        contextWindow = mu.contextWindow || 200000;
        cacheReadTokens = mu.cacheReadInputTokens || 0;
        cacheCreationTokens = mu.cacheCreationInputTokens || 0;
      }
    }

    const usedTokens = inputTokens + outputTokens;
    const resolvedSessionId: string = result?.sessionId || sessionId || "";

    emit({
      type: "done", inputTokens, outputTokens, costUsd,
      sessionId: resolvedSessionId,
      context: { usedTokens, contextWindow, percentUsed: Math.round((usedTokens / contextWindow) * 1000) / 10, cacheReadTokens, cacheCreationTokens },
    });

    log("query", `Completed queryId=${queryId} tokens=${inputTokens}+${outputTokens} cost=$${costUsd} duration=${Date.now() - startTime}ms`);
  } catch (err) {
    const error = err as Error;
    log("query", `Error queryId=${queryId}: ${error.message}`);
    emit({ type: "error", content: error.message });
  }

  markDone(queryId);
  if (!res.writableEnded) res.end();
});

queryRouter.get("/v1/query/:queryId/events", (req: Request, res: Response) => {
  const queryId = String(req.params.queryId || "");
  const afterParam = req.query.after;
  const after = parseInt(typeof afterParam === "string" ? afterParam : "-1", 10);
  const entry = getCacheEntry(queryId);

  if (!entry) { res.status(404).json({ error: "Query not found or expired" }); return; }

  res.setHeader("Content-Type", "application/x-ndjson");
  res.setHeader("Transfer-Encoding", "chunked");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("X-Accel-Buffering", "no");

  for (const event of entry.events) { if (event.seq > after) res.write(JSON.stringify(event) + "\n"); }
  if (entry.status === "done") { res.end(); return; }

  const listener = (event: StreamEvent): void => { if (event.seq > after && !res.writableEnded) res.write(JSON.stringify(event) + "\n"); };
  entry.listeners.add(listener);
  res.on("close", () => { entry.listeners.delete(listener); });

  const checkDone = setInterval(() => {
    if (entry.status === "done") { clearInterval(checkDone); entry.listeners.delete(listener); if (!res.writableEnded) res.end(); }
  }, 500);
});
