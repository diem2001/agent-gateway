import { query } from "@anthropic-ai/claude-agent-sdk";
import type { SDKUserMessage } from "@anthropic-ai/claude-agent-sdk";
import type { ContentBlock } from "./query.js";
import { log } from "./logging.js";
import type { StreamEvent } from "./event-cache.js";
import { getAllTools } from "./tools.js";
import type { WebhookContext } from "./webhook.js";
import { createToolMcpServer } from "./tool-server.js";
import { buildMcpServersForSdk, getEnabledMcpServers, getMcpAllowedToolPatterns } from "./mcp-registry.js";
import {
  applyMcpCredentialOverrides,
  hasUserCredential,
  selectRegistryServersForRun,
  summarizeOverrideKeys,
  type McpCredentialOverride,
  type McpCredentialOverrides,
} from "./mcp-overrides.js";
import { materializeUserSkills, cleanupUserSkillBundle } from "./user-skills.js";
import { requestMcpAllowedToolPatterns, type RequestMcpServers } from "./mcp-request-servers.js";
import { credentialRelay, type RelayGrant } from "./mcp-credential-relay.js";
import { StdioBridge } from "./mcp-stdio-sandbox.js";
import { createRunLogDir, removeRunLogDirAfterExit } from "./sdk-run-logs.js";
import { SandboxRun, runtimeEnvFrom } from "./sandbox.js";
import { SANDBOX_WORK } from "./sandbox-content.js";
import { RunFailure, classifyRunFailure, fixedFailure, isAbortError } from "./run-failure.js";
import { builtInTools, createToolPolicyHook } from "./tool-policy.js";
import { WEBHOOK_SERVER_NAME, computeToolGrant, mcpToolName, type ToolGrant } from "./tool-grant.js";
import { secretValuesForMasking } from "./tool-mediation.js";
import type { ToolDefinition } from "./tools.js";

export interface QueryParams {
  prompt?: string;
  content?: ContentBlock[];
  systemPrompt?: string;
  model?: string;
  allowedTools?: string[];
  sessionId?: string;
  isResume?: boolean;
  abortController: AbortController;
  onEvent: (event: Omit<StreamEvent, "seq">) => void;
  webhookContext?: WebhookContext;
  clientAuthToken?: string;
  mcpCredentialOverrides?: McpCredentialOverrides;
  /**
   * Per-query MCP servers from the request body (MVP-6755). Merged into the SDK
   * `mcpServers` at the LOWEST precedence — the webhook tool server and the
   * persistent registry servers overlay on top, so a request can never override
   * them. The matching `mcp__<name>__*` patterns are added to the default
   * allowed-tool set (a caller-supplied `allowedTools` stays authoritative).
   */
  requestMcpServers?: RequestMcpServers;
  /**
   * The requesting user's id (DEC-GW-002 / DEC-GW-004). When present, this query
   * additionally loads that user's stored skills via the SDK `plugins` local
   * lever (request-scoped) and the emitted `skills_loaded` event carries it.
   * `undefined` ⇒ global-only load, `skills_loaded.user_id = null`.
   */
  userId?: string;
  /** Only for the log reference in the unknown-failure message (run-failure.ts). */
  queryId?: string;
  /**
   * Resolves when the run deadline expired (retry.ts). The attempt then stops once `DEADLINE_STOP_GRACE_MS`
   * have passed, even when the SDK ignores the abort and never settles (MVP-8000). Absent: no deadline race.
   */
  deadline?: Promise<void>;
  /**
   * Called when a deadline stop could not confirm that the sandbox process exited: the request ends anyway, and the
   * caller (query.ts) keeps the conversation locked until this promise settles.
   */
  holdConversation?: (until: Promise<unknown>) => void;
  /** The conversation's recorded sandbox home name (sessions.ts); without one the run has a private home. */
  sandboxDirId?: string;
  /**
   * The exact tool set this run may call (MVP-7637, see tool-policy.ts),
   * validated by the query route. `undefined` ⇒ the options are unchanged.
   * An empty array means no tool at all, never the default set.
   */
  enforcedTools?: string[];
  /** The caller's API-key label: the trusted tool policy, webhook tool ownership and the grant are resolved from it. */
  label?: string;
  /** The run's effective tool grant (query.ts); computed here from `label` and the caller's narrowing when absent. */
  grant?: ToolGrant;
}

export interface QueryResult {
  response: string;
  resultData: Record<string, unknown> | null;
}

function formatToolInput(toolName: string, input: Record<string, unknown> | undefined): string {
  if (!input) return "";
  if (toolName === "Bash" && input.command) return String(input.command);
  if ((toolName === "Read" || toolName === "Write") && input.file_path) return String(input.file_path);
  if (toolName === "Glob" && input.pattern) return String(input.pattern) + (input.path ? ` in ${input.path}` : "");
  if (toolName === "Grep" && input.pattern) return String(input.pattern) + (input.path ? ` in ${input.path}` : "");
  if (toolName === "Edit" && input.file_path) return String(input.file_path);
  if (toolName === "WebSearch" && input.query) return String(input.query);
  if (toolName === "WebFetch" && input.url) return String(input.url);
  // Reqlift tools: show readable summary
  if (toolName === "reqlift_create_draft") {
    const parts = [input.draft_type, input.title].filter(Boolean).map(String);
    if (input.project_label) parts.unshift(`[${input.project_label}]`);
    return parts.join(": ");
  }
  if (toolName === "reqlift_update_draft") {
    const parts: string[] = [];
    if (input.draft_id) parts.push(String(input.draft_id).substring(0, 8));
    if (input.title) parts.push(String(input.title));
    if (input.status) parts.push(`→ ${input.status}`);
    return parts.join(" ");
  }
  if (toolName === "reqlift_get_project_context" && input.project_label) return String(input.project_label);
  if (toolName === "reqlift_list_projects") return "list all projects";
  // Skill: show skill name
  if (toolName === "Skill" && input.skill) return String(input.skill);
  // Task/Agent: show description
  if ((toolName === "Task" || toolName === "Agent") && input.description) return String(input.description);
  return JSON.stringify(input, null, 2).substring(0, 1000);
}

/**
 * Resolve the `input` payload carried on a tool_use NDJSON event. Most tools get
 * a short human-readable STRING summary (formatToolInput). TodoWrite is special:
 * its consumer — reqlift's TodoList checklist widget (MVP-6298) — needs the
 * STRUCTURED `{ todos: [...] }` object; reqlift's parseTodos requires an object
 * and a stringified/truncated summary cannot be parsed. So forward TodoWrite's
 * raw input object verbatim (untruncated) while keeping the string summary for
 * every other tool (MVP-6497).
 */
export function toolUseEventInput(
  toolName: string,
  input: Record<string, unknown> | undefined,
): unknown {
  if (toolName === "TodoWrite") return input ?? null;
  return formatToolInput(toolName, input);
}

/**
 * Whether a request-supplied server config is an http/SSE server that carries a credential: at least one header, or a
 * user name, password or query in its URL (those would otherwise sit on the runtime's command line).
 */
function carriesHeaders(config: unknown): boolean {
  if (typeof config !== "object" || config === null) return false;
  const entry = config as { type?: unknown; url?: unknown; headers?: unknown };
  if (entry.type !== "http" && entry.type !== "sse") return false;
  if (typeof entry.url !== "string") return false;
  if (typeof entry.headers === "object" && entry.headers !== null && Object.keys(entry.headers).length > 0) return true;
  try {
    const url = new URL(entry.url);
    return url.username !== "" || url.password !== "" || url.search !== "";
  } catch {
    return false;
  }
}

/** The relay's view of the run's grant for one server. */
function relayGrantFor(grant: ToolGrant, serverName: string): RelayGrant {
  return { allowsTool: (tool) => grant.allows(mcpToolName(serverName, tool)), coversServer: grant.coversServer(serverName) };
}

/** Whether the override carries a non-empty value for the target. */
function hasOverrideValues(override: McpCredentialOverride | undefined, target: "headers" | "env"): boolean {
  return Object.values(override?.[target] ?? {}).some((value) => value.length > 0);
}

/** A server whose credential schema composes values for `target` needs the user's values for them. */
function schemaWantsTarget(def: { userCredentialSchema?: { outputs: { target: string }[] } }, target: "headers" | "env"): boolean {
  return (def.userCredentialSchema?.outputs ?? []).some((output) => output.target === target);
}

/** Whether a request-supplied server config is a stdio server that carries at least one env value. */
function carriesEnv(config: unknown): boolean {
  if (typeof config !== "object" || config === null) return false;
  const entry = config as { command?: unknown; env?: unknown };
  return typeof entry.command === "string" && typeof entry.env === "object" && entry.env !== null && Object.keys(entry.env).length > 0;
}

/** The relay binding of a stdio server has no upstream URL: its bridge talks to the tool sandbox. */
const STDIO_PLACEHOLDER_URL = "stdio://tool-sandbox";

/** A tool name as it may appear in an audit line. */
function loggableName(name: string): string {
  return /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(name) ? name : "(unrecognized)";
}

/**
 * The bearer a webhook tool receives (MVP-7679): the calling client's gateway key goes only to tools its own label
 * registered. A legacy tool without an owner keeps today's forwarding until it is registered again, with one audit
 * line per call; a tool of another label never receives it.
 */
function webhookBearer(tool: ToolDefinition, callerLabel: string, token: string | undefined): string | undefined {
  if (tool.owner === callerLabel) return token;
  if (tool.owner === undefined) {
    if (token) log("audit", `tool.webhook.legacy_forward toolName=${loggableName(tool.name)}`);
    return token;
  }
  return undefined;
}

export const DEFAULT_TOOLS = ["Bash", "Read", "Write", "Edit", "Glob", "Grep", "WebSearch", "WebFetch", "Skill", "Agent", "TodoWrite", "TaskCreate", "TaskGet", "TaskUpdate", "TaskList"];

/**
 * Build a fresh single-message AsyncIterable<SDKUserMessage> from the resolved
 * content blocks. The Claude Agent SDK's `query()` accepts
 * `prompt: string | AsyncIterable<SDKUserMessage>`; for multimodal input we yield
 * exactly one user message whose `message.content` is the content-block array,
 * which is forwarded to the Anthropic API unmodified.
 *
 * CRITICAL: an AsyncIterable is single-consumption. The retry path re-invokes
 * `runQuery` on each attempt, so a new generator MUST be constructed per call.
 * This function returns a fresh async generator every time it is called.
 */
async function* buildContentMessageStream(
  content: ContentBlock[],
  sessionId: string | undefined,
): AsyncGenerator<SDKUserMessage> {
  yield {
    type: "user",
    session_id: sessionId ?? "",
    parent_tool_use_id: null,
    message: { role: "user", content },
  };
}

/** How long messages that are already on their way are still processed after the launcher ended by an outside signal. */
export const LAUNCHER_EXIT_GRACE_MS = 1000;

/**
 * How long an SDK that ignores the abort is given to end by itself after the run deadline expired (MVP-8000). A
 * cooperative SDK ends inside it with its own abort error; after it the run is stopped from outside.
 */
export const DEADLINE_STOP_GRACE_MS = 1000;

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Yields what the SDK yields until `gone` settles first, then throws `ended()`. `gone` is the launcher's end by an
 * outside signal (MVP-7964) or the run deadline plus its grace (MVP-8000). The SDK's own next message always
 * wins when it is ready. After `gone` the SDK iterator is abandoned: its pending promise and its `return()` get a
 * no-op rejection handler, because a late SDK error must not become an unhandled rejection of the gateway process.
 */
export async function* untilLauncherGone<T>(source: AsyncIterator<T>, gone: Promise<unknown>, ended: () => Error): AsyncGenerator<T, void, undefined> {
  let finished = false;
  try {
    for (;;) {
      const next = source.next().then((result) => ({ result }));
      next.catch(() => {});
      let step: { result: IteratorResult<T> } | null;
      try {
        step = await Promise.race([next, gone.then(() => null)]);
      } catch (error) {
        finished = true;
        throw error;
      }
      if (step === null) {
        finished = true;
        Promise.resolve(source.return?.()).catch(() => {});
        throw ended();
      }
      if (step.result.done) {
        finished = true;
        return;
      }
      yield step.result.value;
    }
  } finally {
    if (!finished) await source.return?.();
  }
}

/**
 * One attempt. A failed attempt throws a `RunFailure` (run-failure.ts) with a
 * safe public message: a result with `is_error: true`, or any error the SDK
 * iterator throws. The runtime writes its diagnostic to stdout before it exits
 * 1, so the loop sees it before the SDK throws "process exited with code 1";
 * it is kept here and classified, never forwarded. The runtime process's exit
 * code and signal come from the sandbox (`SandboxRun.runtimeExit`), not from the
 * SDK's error text. Client aborts (AbortError) are rethrown unchanged.
 */
export async function runQuery({ prompt, content, systemPrompt, model, allowedTools, sessionId, isResume, abortController, onEvent, webhookContext, clientAuthToken, mcpCredentialOverrides, requestMcpServers, userId, queryId, enforcedTools, sandboxDirId, label, grant: givenGrant, deadline, holdConversation }: QueryParams): Promise<QueryResult> {
  const enforced = enforcedTools !== undefined;
  // The trusted grant of this run: policy for the caller's label intersected with the caller's own narrowing.
  const callerLabel = label ?? webhookContext?.api_key_label ?? "";
  const grant = givenGrant ?? computeToolGrant({ label: callerLabel, narrowing: enforcedTools ?? allowedTools });
  // Whether this label may execute commands at all: the trusted policy alone decides, the caller's own narrowing never
  // does. Both command gates of a run key on this one value: the request-server `command` gate below and the
  // neutralization of command settings in skill, agent and command files (MVP-8106).
  const policyGrant = computeToolGrant({ label: callerLabel });
  const commandsGranted = policyGrant.allows("Bash");
  const neutralizeCommands = !commandsGranted;
  // The set an enforced run is held to: what the caller named, minus what the trusted policy does not grant.
  const enforcedSet = enforced ? enforcedTools.filter((name) => grant.allows(name)) : undefined;
  // A run is offered only the registered tools of its own label plus legacy ownerless ones, and only granted ones.
  const registeredTools = getAllTools().filter(
    (t) => (t.owner === undefined || t.owner === callerLabel) && grant.allows(mcpToolName(WEBHOOK_SERVER_NAME, t.name)),
  );
  const registeredToolNames = registeredTools.map((t) => t.name);
  // A registry server with requireUserCredentials is left out of a run without
  // the user's credential: no SDK entry, no allowed-tool pattern, and a request
  // server may not take its name (it would otherwise fill the vacated slot).
  const selection = selectRegistryServersForRun(getEnabledMcpServers(), mcpCredentialOverrides);
  const omitted: { name: string; reason: string }[] = [...selection.omitted];
  let runRegistryServers = selection.attached;
  // Every registered server is reached only through the trusted relay (http, SSE and stdio alike); if it
  // is not listening they are left out, never connected directly (fail closed).
  const relayUp = credentialRelay.isListening();
  if (!relayUp) {
    for (const def of runRegistryServers) omitted.push({ name: def.name, reason: "relay_unavailable" });
    runRegistryServers = [];
  }
  for (const { name, reason } of omitted) {
    log("audit", `mcp.server.omitted serverName=${name} reason=${reason}`);
  }
  const omittedServers = omitted.map(({ name }) => name);
  let runRequestMcpServers = requestMcpServers
    ? Object.fromEntries(Object.entries(requestMcpServers).filter(([name]) => !omittedServers.includes(name)))
    : undefined;
  // A request server that carries headers or env needs the relay too; without it the server is left out (fail closed).
  if (runRequestMcpServers && !relayUp) {
    for (const [name, config] of Object.entries(runRequestMcpServers)) {
      if (carriesHeaders(config) || carriesEnv(config)) {
        log("audit", `mcp.server.omitted serverName=${name} reason=relay_unavailable`);
        delete runRequestMcpServers[name];
      }
    }
  }
  // A server with no granted tool is not attached at all (no wasted calls, nothing to refuse later).
  runRegistryServers = runRegistryServers.filter((def) => grant.allowsServer(def.name));
  if (runRequestMcpServers) {
    // A request-supplied `command` is code the caller picked: it is attached only when the trusted policy lets this
    // label execute commands (`Bash`) or names that server explicitly, so a policy that denies `Bash` cannot be
    // sidestepped with a request server. (The caller's own narrowing can only shrink the grant, never decide this.)
    runRequestMcpServers = Object.fromEntries(
      Object.entries(runRequestMcpServers).filter(([name, config]) => {
        if (!grant.allowsServer(name)) return false;
        if (typeof (config as { command?: unknown }).command === "string" && !commandsGranted && !policyGrant.explicitlyAllowsServer(name)) {
          log("audit", `mcp.server.omitted serverName=${name} reason=command_not_granted`);
          return false;
        }
        return true;
      }),
    );
  }
  const mcpToolPatterns = getMcpAllowedToolPatterns(runRegistryServers);
  const requestMcpToolPatterns = requestMcpAllowedToolPatterns(runRequestMcpServers);
  // `allowedTools` is the runtime's pre-approval list; the caller's list is a narrowing and was applied to the grant.
  const effectiveTools = allowedTools
    ? allowedTools.filter((name) => grant.allows(name))
    : [...DEFAULT_TOOLS.filter((name) => grant.allows(name)), ...registeredToolNames, ...mcpToolPatterns, ...requestMcpToolPatterns];
  const options: Record<string, unknown> = {
    allowedTools: effectiveTools,
    permissionMode: "bypassPermissions",
    model: model || "claude-opus-4-6",
    abortController,
    includePartialMessages: true,
    // The sandbox's working directory: the conversation's persistent work area, which the agent can write.
    cwd: SANDBOX_WORK,
    // Only the user source (MVP-7679, Gate A): the project source reads a `.mcp.json` the agent can write in its
    // working directory and would start whatever command it names on the next turn. Global skills, configured
    // agents and the read-only generated settings are user-source content and keep loading.
    settingSources: ["user"],
  };
  if (enforced) {
    // The layers of tool-policy.ts: no HOME settings, deny anything not listed,
    // offer only the listed built-ins, and a deny-only hook as second layer.
    options.settingSources = [];
    options.permissionMode = "dontAsk";
    options.allowedTools = [...enforcedSet!];
    options.tools = builtInTools(enforcedSet!);
    options.hooks = { PreToolUse: [{ hooks: [createToolPolicyHook(enforcedSet!, queryId)] }] };
    log("query", `enforced tool set: ${enforcedSet!.length} tool(s)`);
  } else if (grant.restrictsBuiltIns) {
    // The policy or the caller restricts the built-ins: the runtime is offered only the granted ones, and the others
    // are named as denied. A built-in that is not offered is refused by the runtime itself, for the main agent, a
    // configured agent, a skill, a sub-agent and a resumed conversation alike (Gate A).
    options.tools = grant.builtIns();
    options.disallowedTools = grant.deniedBuiltIns();
  }

  // Per-user skill loading (DEC-GW-002): materialize the requesting user's stored
  // skills into a request-scoped local-plugin bundle and point `plugins` at it for
  // THIS query only. Global skills still load via cwd/settingSources (additive) —
  // those are deliberately left untouched. No userId ⇒ no plugins ⇒ global-only
  // load, byte-for-byte unchanged. Caps overflow is reported here and surfaced as a
  // `skills_truncated` event below (DEC-GW-004) before the query proceeds.
  // An enforced run loads no plugin bundle (tool-policy.ts).
  // Without the `Bash` grant the bundle is written without command settings (hooks, stdio startup commands).
  const userSkills = enforced ? materializeUserSkills(undefined) : materializeUserSkills(userId, { neutralizeCommands, label: callerLabel });
  if (userSkills.pluginRoot) {
    options.plugins = [{ type: "local", path: userSkills.pluginRoot }];
    log("query", `user skills: loading plugin bundle for userId=${userId} at ${userSkills.pluginRoot}`);
  }
  if (userSkills.dropped.length > 0 && userSkills.reason) {
    onEvent({ type: "skills_truncated", dropped: userSkills.dropped, reason: userSkills.reason });
  }
  options.systemPrompt = systemPrompt
    ? { type: "preset", preset: "claude_code", append: systemPrompt }
    : { type: "preset", preset: "claude_code" };
  if (isResume) { options.resume = sessionId; } else { options.sessionId = sessionId; }
  log("query", `SDK options: sessionId=${sessionId || "none"} isResume=${isResume} resume=${isResume ? sessionId : "n/a"} model=${options.model || "default"} mcpPatterns=[${mcpToolPatterns.join(",")}]`);

  // Build mcpServers: per-query request servers (lowest precedence) +
  // webhook-based tools + registered MCP servers. The trusted servers below are
  // assigned AFTER the request servers, so a request can never override the
  // gateway's own webhook tools or a registered server (MVP-6755).
  const mcpServers: Record<string, unknown> = { ...(runRequestMcpServers ?? {}) };

  if (registeredTools.length > 0 && webhookContext) {
    const hosted = new Set(registeredToolNames);
    mcpServers[WEBHOOK_SERVER_NAME] = createToolMcpServer(
      registeredTools,
      webhookContext,
      (tool) => webhookBearer(tool, callerLabel, clientAuthToken),
      {
        isGranted: (name) => hosted.has(name) && grant.allows(mcpToolName(WEBHOOK_SERVER_NAME, name)),
        secrets: () => secretValuesForMasking(clientAuthToken ? [clientAuthToken] : []),
      },
    );
  }

  // The runtime's own log files (they hold MCP connection options) go to a
  // private per-run directory, deleted once the runtime child has exited.
  // Created before any relay token, so a failure here cannot leave a token unrevoked.
  const runLogs = createRunLogDir();
  // The runtime runs only inside this run's sandbox (MVP-7678): the SDK's spawn hook is the
  // sandbox launcher, and nothing of the gateway's environment is handed to the SDK. The
  // environment given here holds no secret; the sandbox builds its own allowlist from it.
  const sandbox = new SandboxRun({
    queryId,
    runLogDir: runLogs.dir,
    runLogEnv: runLogs.env,
    userSkillsDir: userSkills.pluginRoot,
    neutralizeCommands,
    label: callerLabel,
    sessionDirId: sandboxDirId,
    signal: abortController.signal,
  });
  options.env = { ...runtimeEnvFrom(process.env), ...runLogs.env };
  options.spawnClaudeCodeProcess = sandbox.spawnHook;

  const relayTokens: string[] = [];
  try {
    // Request stdio servers with env run in their own tool sandbox behind the relay.
    for (const [name, config] of Object.entries(mcpServers)) {
      if (!carriesEnv(config)) continue;
      const entry = config as { command: string; args?: string[]; env: Record<string, string> };
      const bridge = new StdioBridge({ serverName: name, command: entry.command, args: entry.args ?? [], env: { ...entry.env }, queryId });
      const { token, url } = credentialRelay.register({
        serverName: name,
        url: STDIO_PLACEHOLDER_URL,
        headers: {},
        kind: "stdio",
        bridge,
        grant: relayGrantFor(grant, name),
        credentialSource: "user",
      });
      relayTokens.push(token);
      mcpServers[name] = { type: "http", url };
    }
    // Request servers with headers: the runtime gets a relay URL, the header values stay with the relay.
    for (const [name, config] of Object.entries(mcpServers)) {
      if (!carriesHeaders(config)) continue;
      const kind = (config as { type?: unknown }).type === "sse" ? "sse" : "http";
      const { token, url } = credentialRelay.register({
        serverName: name,
        url: (config as { url: string }).url,
        headers: { ...((config as { headers?: Record<string, string> }).headers ?? {}) },
        kind,
        grant: relayGrantFor(grant, name),
        credentialSource: "user",
      });
      relayTokens.push(token);
      mcpServers[name] = { type: "http", url };
    }
    const registeredMcpServers = buildMcpServersForSdk(runRegistryServers);
    if (registeredMcpServers) {
      // One case-insensitive merge: a user header replaces the shared header of the same name.
      const effectiveMcpServers = applyMcpCredentialOverrides(
        registeredMcpServers,
        mcpCredentialOverrides,
      );
      // The runtime gets a loopback relay URL with a per-run token and no header; the relay holds this
      // run's URL, header snapshot and grant until the run ends.
      for (const [name, config] of Object.entries(effectiveMcpServers)) {
        const def = runRegistryServers.find((d) => d.name === name)!;
        const override = mcpCredentialOverrides?.[name];
        if (!("type" in config)) {
          // A registered stdio server (with or without env) runs in its own tool sandbox; args and env stay with the bridge.
          const bridge = new StdioBridge({ serverName: name, command: config.command, args: config.args ?? [], env: { ...(config.env ?? {}) }, queryId });
          const { token, url } = credentialRelay.register({
            serverName: name,
            url: STDIO_PLACEHOLDER_URL,
            headers: {},
            kind: "stdio",
            bridge,
            grant: relayGrantFor(grant, name),
            credentialSource: hasOverrideValues(override, "env") ? "user" : "gateway",
            noUserCredential: schemaWantsTarget(def, "env") && !hasUserCredential(def, override),
          });
          relayTokens.push(token);
          effectiveMcpServers[name] = { type: "http", url };
          continue;
        }
        if (config.type !== "http" && config.type !== "sse") continue;
        const { token, url } = credentialRelay.register({
          serverName: name,
          url: config.url,
          headers: config.headers ?? {},
          kind: config.type,
          grant: relayGrantFor(grant, name),
          credentialSource: hasOverrideValues(override, "headers") ? "user" : "gateway",
          noUserCredential: schemaWantsTarget(def, "headers") && !hasUserCredential(def, override),
        });
        relayTokens.push(token);
        effectiveMcpServers[name] = { type: "http", url };
      }
      Object.assign(mcpServers, effectiveMcpServers);
    }


  } catch (error) {
    // A binding that could not be built (for example an invalid isolation setting) must not leave the tokens, the run
    // directory or the skill bundle of this run behind.
    for (const token of relayTokens) credentialRelay.revoke(token);
    cleanupUserSkillBundle(userSkills.pluginRoot);
    void removeRunLogDirAfterExit(runLogs.dir, sandbox.child);
    await sandbox.dispose();
    throw error;
  }

  if (mcpCredentialOverrides) {
    // Only for servers this run actually attached; a server left out received nothing.
    for (const [serverName, override] of Object.entries(mcpCredentialOverrides)) {
      if (!runRegistryServers.some((def) => def.name === serverName)) continue;
      const keys = summarizeOverrideKeys(override);
      log("audit", `mcp.override.applied serverName=${serverName} keys=${keys.join(",") || "none"}`);
    }
  }

  if (Object.keys(mcpServers).length > 0) {
    options.mcpServers = mcpServers;
    log("query", `MCP servers: ${Object.keys(mcpServers).join(", ")}`);
  }

  // Choose the SDK prompt argument:
  // - Multimodal / non-trivial content blocks → a FRESH AsyncIterable<SDKUserMessage>
  //   built per call (the retry path re-invokes runQuery, and an AsyncIterable is
  //   single-consumption, so it must never be reused).
  // - A single plain text block (the backward-compatible text-only path) → the
  //   original string prompt, keeping existing behavior byte-for-byte unchanged.
  const isPlainTextOnly =
    Array.isArray(content) &&
    content.length === 1 &&
    content[0].type === "text";
  const useContentStream = Array.isArray(content) && content.length > 0 && !isPlainTextOnly;
  const promptArg = useContentStream
    ? buildContentMessageStream(content as ContentBlock[], sessionId)
    : prompt ?? (isPlainTextOnly && content[0].type === "text" ? content[0].text : "");

  let fullResponse = "";
  let resultData: Record<string, unknown> | null = null;
  // Classifier inputs (run-failure.ts): the runtime version and error-flagged
  // assistant messages. Ordinary assistant text is never classified.
  let installedVersion: unknown;
  const assistantErrors: { error: unknown; text: string }[] = [];
  const pendingTools = new Map<string, { name: string }>();
  const toolTimings = new Map<string, number>();
  // Once the run deadline expired the sandbox is stopped at once and boundedly, however this attempt ends.
  let deadlineExpired = false;
  void deadline?.then(() => { deadlineExpired = true; });

  try {
  const conversation = query({ prompt: promptArg, options });
  // A launcher that ended by a signal the gateway did not send ends this run after a short grace, even when the
  // SDK never notices (MVP-7964). The run deadline does the same for an SDK that ignores the abort (MVP-8000).
  // Messages that arrive inside either grace are still processed.
  let stop: "launcher" | "deadline" | null = null;
  const launcherGone = sandbox.unownedExit().then(() => sleep(LAUNCHER_EXIT_GRACE_MS)).then(() => { stop ??= "launcher"; });
  const deadlineGone = deadline ? deadline.then(() => sleep(DEADLINE_STOP_GRACE_MS)).then(() => { stop ??= "deadline"; }) : new Promise<never>(() => {});
  const runStopped = (): RunFailure => {
    sandbox.releaseOutput();
    // The deadline's text is substituted by retry.ts; this failure only says which kind it is.
    if (stop === "deadline") return fixedFailure("run_deadline", "");
    return classifyRunFailure({ installedVersion, result: resultData, assistantErrors, runtimeExit: sandbox.runtimeExit }, queryId);
  };
  for await (const message of untilLauncherGone(conversation[Symbol.asyncIterator](), Promise.race([launcherGone, deadlineGone]), runStopped)) {
    if (abortController.signal.aborted) break;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const msg = message as any;

    if (msg.type === "assistant" && msg.error != null) {
      // A runtime-authored error message (e.g. "API Error: 400 <raw provider
      // body>"): a classifier input only, never part of the response.
      const blocks: { text?: unknown }[] = Array.isArray(msg.message?.content) ? msg.message.content : [];
      assistantErrors.push({ error: msg.error, text: blocks.map((block) => (typeof block.text === "string" ? block.text : "")).join("\n") });
    } else if (msg.type === "assistant" && msg.message?.content) {
      for (const block of msg.message.content) {
        if (block.text) fullResponse += block.text;
        if (block.type === "tool_use") {
          const pending = pendingTools.get(block.id);
          const toolName: string = pending?.name || block.name;
          const eventInput = toolUseEventInput(toolName, block.input);
          toolTimings.set(block.id, Date.now());
          // parent_tool_use_id is carried at the SDKAssistantMessage level: null for the
          // main conversation agent, the spawning Task/Agent tool_use id for a sub-agent.
          // Forward it as parentToolUseId (always present; normalize undefined → null) so
          // downstream consumers (reqlift, MVP-6306) can attribute sub-agent tool calls.
          const parentToolUseId: string | null = msg.parent_tool_use_id ?? null;
          onEvent({ type: "tool_use", toolName, toolUseId: block.id, input: eventInput, startedAt: Date.now(), parentToolUseId });
        }
      }
    } else if (msg.type === "stream_event") {
      const event = msg.event;
      if (event?.type === "content_block_delta" && event.delta?.type === "text_delta") {
        const text: string = event.delta.text;
        fullResponse += text;
        onEvent({ type: "text", content: text });
      }
      if (event?.type === "content_block_start" && event.content_block?.type === "tool_use") {
        pendingTools.set(event.content_block.id, { name: event.content_block.name });
      }
      if (event?.type === "rate_limit_event" || event?.type === "rate_limit") {
        const retryAfterMs = ((event.retry_after_seconds || event.retry_after || 5) as number) * 1000;
        log("rate-limit", `Rate limit event detected in stream, retry_after=${retryAfterMs}ms`);
        onEvent({ type: "rate_limited", status: "waiting", retryAfterMs });
      }
    } else if (msg.type === "user" && msg.tool_use_result !== undefined) {
      const content = msg.message?.content;
      if (Array.isArray(content)) {
        for (const block of content) {
          if (block.type === "tool_result") {
            const toolUseId: string = block.tool_use_id;
            let toolName = "Tool";
            if (toolUseId && pendingTools.has(toolUseId)) { toolName = pendingTools.get(toolUseId)!.name; pendingTools.delete(toolUseId); }
            let output = "";
            if (typeof block.content === "string") { output = block.content; }
            else if (Array.isArray(block.content)) { output = block.content.filter((c: { type: string }) => c.type === "text").map((c: { text: string }) => c.text).join("\n"); }
            const truncated = output.length > 3000 ? output.substring(0, 3000) + "\n... (truncated)" : output;
            const durationMs = toolTimings.has(toolUseId) ? Date.now() - toolTimings.get(toolUseId)! : null;
            toolTimings.delete(toolUseId);
            // A failed call is flagged (additive field): absent on success, so successful events are unchanged.
            onEvent({ type: "tool_result", toolName, toolUseId, output: truncated, durationMs, ...(block.is_error === true ? { success: false } : {}) });
          }
        }
      }
    } else if (msg.type === "system") {
      if (msg.subtype === "status" && msg.status === "compacting") onEvent({ type: "sdk_status", status: "compacting" });
      else if (msg.subtype === "status" && msg.status === null) onEvent({ type: "sdk_status", status: null });
      if (msg.subtype === "compact_boundary" && msg.compact_metadata) {
        onEvent({ type: "sdk_compact_complete", trigger: msg.compact_metadata.trigger || "auto", preTokens: msg.compact_metadata.pre_tokens || 0 });
      }
      // DEC-GW-004: the SDK `init` system message carries `skills: string[]` — the
      // AUTHORITATIVE actually-loaded set (global + this query's per-user bundle).
      // Emit exactly one `skills_loaded` per query as the durable black-box
      // verification surface GW-S2 (MVP-6577) asserts. `user_id` is null when the
      // query carried none (global-only load). We derive skills[] from the SDK
      // message, NOT the gateway's own materialized list — that is what makes this
      // the real loaded-set surface.
      if (msg.subtype === "init") {
        installedVersion = msg.claude_code_version;
        const loadedSkills: string[] = Array.isArray(msg.skills) ? msg.skills : [];
        onEvent({ type: "skills_loaded", user_id: userId ?? null, skills: loadedSkills });
      }
    } else if (msg.type === "result") { resultData = msg; }
  }
  } catch (err) {
    if (isAbortError(err)) throw err;
    // A sandbox that did not start is reported with its own fixed text, never as the SDK's
    // generic "process exited" error; nothing ran.
    const startFailure = sandbox.startFailure;
    if (startFailure) throw startFailure;
    if (err instanceof RunFailure) throw err;
    throw classifyRunFailure({ installedVersion, result: resultData, assistantErrors, thrown: err, runtimeExit: sandbox.runtimeExit }, queryId);
  } finally {
    // Every end (answer, error, abort): the relay URLs and the model proxy token stop
    // working and their in-flight upstream requests are destroyed.
    for (const token of relayTokens) credentialRelay.revoke(token);
    // Request-scoped bundle: remove it once this query() call has drained.
    cleanupUserSkillBundle(userSkills.pluginRoot);
    // The sandbox process is gone before this run returns, so the conversation's lock (query.ts) is
    // released only after its home has no process left.
    void removeRunLogDirAfterExit(runLogs.dir, sandbox.child);
    if (deadlineExpired) {
      // The SDK is not trusted to stop its runtime: kill it now and wait for its exit only briefly. A launcher
      // whose exit is not observed in time does not hold the request, but the conversation stays locked for it.
      const unconfirmed = await sandbox.disposeAfterDeadline();
      if (unconfirmed) holdConversation?.(unconfirmed.exited);
    } else {
      await sandbox.dispose();
    }
  }

  // A sandbox that failed to start while the SDK ended without an error: nothing ran.
  if (sandbox.startFailure) throw sandbox.startFailure;

  // A result flagged is_error is a failure even when its subtype says "success"
  // and the runtime exited 0.
  if (resultData?.is_error === true) {
    throw classifyRunFailure({ installedVersion, result: resultData, assistantErrors, runtimeExit: sandbox.runtimeExit }, queryId);
  }

  return { response: fullResponse, resultData };
}
