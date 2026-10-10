import { Router, type Request, type Response } from "express";
import { log, logDebug } from "./logging.js";
import { createCacheEntry, getCacheEntry, markDone, type StreamEvent } from "./event-cache.js";
import { runQueryWithRetry } from "./retry.js";
import { admitSession, getSession, updateSessionSdkId } from "./sessions.js";
import { tryLockConversation, type ConversationLock } from "./sandbox.js";
import {
  RunFailure,
  SESSION_BUSY_MESSAGE,
  SESSION_ERASING_MESSAGE,
  SESSION_LEGACY_MESSAGE,
  classifyRunFailure,
  fixedFailure,
  formatLogFields,
  isAbortError,
} from "./run-failure.js";
import {
  validateMcpCredentialOverrides,
  type McpCredentialOverrides,
} from "./mcp-overrides.js";
import {
  RESERVED_MCP_SERVER_NAME,
  validateRequestMcpServers,
  type RequestMcpServers,
} from "./mcp-request-servers.js";
import { getAllMcpServers, getEnabledMcpServers } from "./mcp-registry.js";
import { validateEnforcedTools } from "./tool-policy.js";
import { computeToolGrant } from "./tool-grant.js";

/**
 * A single block of multimodal request content. Maps directly to the Anthropic
 * API `ContentBlockParam` shape so it can be forwarded to the Claude Agent SDK
 * without transformation.
 */
export type ContentBlock =
  | { type: "text"; text: string }
  | { type: "image"; source: { type: "base64"; media_type: "image/jpeg" | "image/png" | "image/gif" | "image/webp"; data: string } };

interface QueryRequestBody {
  queryId?: string; sessionId?: string; prompt?: string; systemPrompt?: string;
  content?: ContentBlock[];
  model?: string; allowedTools?: string[]; useSession?: boolean; sshTarget?: string;
  user_id?: string; conversation_id?: string;
  mcpCredentialOverrides?: McpCredentialOverrides;
  /**
   * Per-query MCP servers (MVP-6755). Injected into the SDK options for THIS
   * query only, at the lowest precedence (the gateway's own webhook tools +
   * registered servers always win). Used by reqlift recon to attach a per-run
   * chrome-devtools MCP server. See `mcp-request-servers.ts`.
   */
  mcpServers?: RequestMcpServers;
  /**
   * The exact tool set this run may call (MVP-7637, see tool-policy.ts). When
   * present, every other tool is refused before it runs and the stream starts
   * with a `tool_policy` event echoing the set. Absent ⇒ unchanged behavior.
   */
  enforcedTools?: string[];
}

/**
 * Validate a single content block against the supported shapes. Returns an error
 * string if the block is malformed, otherwise null. Never inspects/decodes the
 * base64 payload (image bytes are validated upstream at upload time).
 */
function validateContentBlock(block: unknown, index: number): string | null {
  if (typeof block !== "object" || block === null) {
    return `content[${index}] must be an object`;
  }
  const b = block as Record<string, unknown>;
  if (b.type === "text") {
    if (typeof b.text !== "string") return `content[${index}].text must be a string`;
    return null;
  }
  if (b.type === "image") {
    const source = b.source as Record<string, unknown> | undefined;
    if (typeof source !== "object" || source === null) {
      return `content[${index}].source must be an object`;
    }
    if (source.type !== "base64") return `content[${index}].source.type must be "base64"`;
    if (!["image/jpeg", "image/png", "image/gif", "image/webp"].includes(source.media_type as string)) {
      return `content[${index}].source.media_type must be a supported image MIME type`;
    }
    if (typeof source.data !== "string") return `content[${index}].source.data must be a string`;
    return null;
  }
  return `content[${index}].type must be "text" or "image"`;
}

/**
 * Resolve the effective content blocks from the request body.
 * - If `content` is a non-empty array, it takes precedence over `prompt`.
 * - Otherwise, if `prompt` is a non-empty string, it is wrapped as a single text block.
 * - Otherwise, neither is present → validation error.
 * Returns either `{ blocks }` or `{ error }`.
 */
function resolveContentBlocks(
  content: ContentBlock[] | undefined,
  prompt: string | undefined,
): { blocks: ContentBlock[] } | { error: string } {
  if (Array.isArray(content) && content.length > 0) {
    for (let i = 0; i < content.length; i++) {
      const err = validateContentBlock(content[i], i);
      if (err) return { error: err };
    }
    return { blocks: content };
  }
  if (typeof prompt === "string" && prompt.length > 0) {
    return { blocks: [{ type: "text", text: prompt }] };
  }
  return { error: "queryId and prompt or content are required" };
}

export const queryRouter = Router();

queryRouter.post("/v1/query", async (req: Request, res: Response) => {
  const { queryId, sessionId, prompt, content, systemPrompt, model, allowedTools, useSession, sshTarget, user_id, conversation_id, mcpCredentialOverrides, mcpServers } = req.body as QueryRequestBody;
  // An explicit `null` stays `null` here and is refused; only a missing field is absent.
  const enforcedToolsValue: unknown = (req.body as QueryRequestBody).enforcedTools;
  if (!queryId) { res.status(400).json({ error: "queryId and prompt or content are required" }); return; }
  const resolved = resolveContentBlocks(content, prompt);
  if ("error" in resolved) { res.status(400).json({ error: resolved.error }); return; }
  const contentBlocks = resolved.blocks;
  const overrideValidation = validateMcpCredentialOverrides(mcpCredentialOverrides);
  if (overrideValidation.error) {
    res.status(400).json({ error: overrideValidation.error });
    return;
  }
  const mcpServersValidation = validateRequestMcpServers(mcpServers, getAllMcpServers().map((def) => def.name));
  if (mcpServersValidation.error) {
    res.status(400).json({ error: mcpServersValidation.code ? { code: mcpServersValidation.code, message: mcpServersValidation.error } : mcpServersValidation.error });
    return;
  }
  // `allowedTools` narrows the trusted grant (MVP-7679): a list of tool names and `mcp__<server>__*` patterns.
  if (allowedTools !== undefined && !(Array.isArray(allowedTools) && allowedTools.length <= 256 && allowedTools.every((name) => typeof name === "string" && name.length > 0 && name.length <= 256))) {
    res.status(400).json({ error: "allowedTools must be an array of tool names" });
    return;
  }
  const enforcedValidation = validateEnforcedTools(enforcedToolsValue, allowedTools, [
    RESERVED_MCP_SERVER_NAME,
    ...getEnabledMcpServers().map((def) => def.name),
    ...Object.keys(mcpServersValidation.servers ?? {}),
  ]);
  if (enforcedValidation.error) {
    res.status(400).json({ error: enforcedValidation.error });
    return;
  }
  const enforcedTools = enforcedValidation.tools;

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
  const label = req.clientLabel ?? "";
  const cacheEntry = createCacheEntry(label, queryId);

  // `done` and `error` end the stream: nothing is written, cached or sent to a listener after either of them,
  // so output of a run that was stopped from outside (the run deadline, MVP-8000) cannot appear late.
  let terminal = false;

  function emit(event: Omit<StreamEvent, "seq">): void {
    if (terminal) return;
    if (event.type === "done" || event.type === "error") terminal = true;
    const line = { seq: seq++, ...event } as StreamEvent;
    cacheEntry.events.push(line);
    if (!res.writableEnded) { const json = JSON.stringify(line) + "\n"; res.write(json); logDebug("out", json.trimEnd()); }
    for (const listener of cacheEntry.listeners) { listener(line); }
  }

  /**
   * The one terminal `error` event of a failed request: `{seq, type, content}`,
   * where `content` is a safe, actionable message (run-failure.ts) or, for a
   * client abort, the SDK's abort text. A failed request gets no `done` and
   * confirms no session.
   */
  function emitError(err: unknown): void {
    if (isAbortError(err)) {
      log("query", `Error queryId=${queryId} kind=aborted`);
      emit({ type: "error", content: (err as Error).message });
      return;
    }
    const failure = err instanceof RunFailure ? err : classifyRunFailure({ thrown: err }, queryId);
    log("query", `Error queryId=${queryId} ${formatLogFields(failure.logFields)}`);
    emit({ type: "error", content: failure.message });
  }

  const abortController = new AbortController();
  res.on("close", () => { if (!res.writableEnded) abortController.abort(); });

  const startTime = Date.now();

  // Who is asking: the API-key label and the request's user id (null when it has none). The label decides which
  // conversations the caller reaches (DEC-ISO-007); the user id is passed on for the writer's skills, the webhook
  // context and per-request credentials only, and is recorded on a new conversation as informational metadata.
  const caller = { label: req.clientLabel ?? "", userId: typeof user_id === "string" && user_id.length > 0 ? user_id : null };
  const conversationId = useSession !== false && typeof sessionId === "string" && sessionId.length > 0 ? sessionId : undefined;

  // Admission comes before anything else happens for this request: a refused caller gets one fixed
  // `error` event and nothing ran (no runtime, no session change, no acknowledgment).
  const refuse = (kind: "session_legacy" | "session_busy" | "session_erasing", message: string): void => {
    log("query", `Refused queryId=${queryId} kind=${kind}`);
    emit({ type: "error", content: fixedFailure(kind, message).message });
    markDone(label, queryId);
    if (!res.writableEnded) res.end();
  };
  let conversationLock: ConversationLock | null = null;
  // Set when a deadline stop could not confirm the sandbox process's exit: the conversation then stays locked until
  // that exit is observed, so two runtimes never share one home. The request itself still ends within its bound.
  let lockHeldUntil: Promise<unknown> | null = null;
  let lockReleased = false;
  const releaseConversation = (): void => {
    if (lockReleased) return;
    lockReleased = true;
    const lock = conversationLock;
    if (lockHeldUntil) void lockHeldUntil.then(() => lock?.release(), () => lock?.release());
    else lock?.release();
  };
  if (conversationId) {
    const admission = admitSession(conversationId, caller);
    if (admission.kind === "refused") {
      // A deleted conversation whose folder is not confirmed gone gets its own fixed text, not the legacy one (MVP-7402).
      if (admission.reason === "erasing") refuse("session_erasing", SESSION_ERASING_MESSAGE);
      else refuse("session_legacy", SESSION_LEGACY_MESSAGE);
      return;
    }
    // One active request per conversation: the lock is taken before the conversation entry is touched.
    if (admission.kind === "resume") {
      conversationLock = tryLockConversation(admission.sandboxDirId);
      if (!conversationLock) {
        refuse("session_busy", SESSION_BUSY_MESSAGE);
        return;
      }
    }
  }

  // The trusted grant of this request: the policy for the caller's label intersected with the caller's narrowing.
  const grant = computeToolGrant({ label: caller.label, narrowing: enforcedTools ?? allowedTools });

  // The acknowledgment comes first and only once: the retry path below never
  // re-emits it, and every attempt gets the same set. It echoes the REQUESTED set; a member the trusted policy
  // does not grant is refused at call time (the run enforces a subset, so the acknowledgment stays true).
  if (enforcedTools) {
    const narrowed = enforcedTools.filter((name) => !grant.allows(name));
    if (narrowed.length > 0) log("audit", `tool.policy.narrowed queryId=${queryId} denied=${narrowed.join(",")}`);
    emit({ type: "tool_policy", enforced: true, tools: enforcedTools });
  }

  try {
    // Resolve session: map client sessionId → SDK sessionId for resume
    let effectiveSessionId = conversationId;
    let isResume = false;
    let sandboxDirId: string | undefined;
    if (effectiveSessionId) {
      const resolved = getSession(effectiveSessionId, systemPrompt || "", model || "claude-sonnet-4-20250514", true, caller);
      sandboxDirId = resolved.sandboxDirId;
      // A conversation created just now gets its lock here (no other request can have seen its home name yet).
      if (!conversationLock && sandboxDirId) conversationLock = tryLockConversation(sandboxDirId);
      if (!resolved.isNew) {
        // Existing session: resume with the SDK sessionId (stored on disk)
        effectiveSessionId = resolved.sessionId;
        isResume = true;
      } else {
        // New session: use the SDK sessionId assigned by getSession
        effectiveSessionId = resolved.sessionId;
      }
    }

    let runResult: Awaited<ReturnType<typeof runQueryWithRetry>>;
    try {
      runResult = await runQueryWithRetry({
        prompt, content: contentBlocks, systemPrompt, model, allowedTools,
        sessionId: effectiveSessionId,
        sandboxDirId,
        isResume, abortController, onEvent: emit, queryId, webhookContext, clientAuthToken,
        mcpCredentialOverrides: overrideValidation.overrides,
        requestMcpServers: mcpServersValidation.servers,
        userId: user_id || undefined,
        enforcedTools,
        label: caller.label,
        grant,
        holdConversation: (until) => { lockHeldUntil = until; },
      });
    } finally {
      // Every sandbox process of this request has exited (agent.ts waits for it): the conversation is free
      // again before its `done` or `error` reaches the client, so a prompt follow-up is never refused as busy.
      // The one exception is a deadline stop whose process exit was not observed in time (see lockHeldUntil).
      releaseConversation();
    }
    const { response: _response, resultData } = runResult;

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const result = resultData as any;
    const sdkResultSessionId = (result?.session_id || result?.sessionId) as string | undefined;
    log("query", `SDK session_id=${sdkResultSessionId || "none"} (client: ${sessionId || "none"}, isResume: ${isResume})`);
    // Update session mapping if SDK returned a different sessionId than what we generated
    // Only a request that used its conversation updates it, and only the caller label's own entry.
    if (conversationId && sdkResultSessionId) {
      updateSessionSdkId(conversationId, sdkResultSessionId, caller.label);
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
    releaseConversation();
    emitError(err);
  }

  markDone(label, queryId);
  if (!res.writableEnded) res.end();
});

queryRouter.get("/v1/query/:queryId/events", (req: Request, res: Response) => {
  const queryId = String(req.params.queryId || "");
  const afterParam = req.query.after;
  const after = parseInt(typeof afterParam === "string" ? afterParam : "-1", 10);
  const entry = getCacheEntry(req.clientLabel ?? "", queryId);

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
