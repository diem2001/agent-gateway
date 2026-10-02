# Architecture

## System Design

The Agent Gateway is a stateless HTTP service that bridges REST clients with the Claude Agent SDK. It accepts queries via a streaming NDJSON endpoint, manages Claude sessions for conversation continuity, provides workspace file management for agent memory, configuration, and skills, and exposes two complementary tool extension surfaces — a webhook-backed Tool Registry and an external MCP Server Registry — so registered tools and MCP servers are merged into every Claude query.

```
                                    +------------------+
                                    |   Claude API     |
                                    |   (Anthropic)    |
                                    +--------^---------+
                                             |
+----------+    HTTP/NDJSON    +-------------+--------------+
|  Client  | ----------------> |       Agent Gateway        |
| (Web App,|    Bearer auth    |                            |
|  CLI,    | <---------------- |  Express 5 + Agent SDK     |
|  CI/CD)  |    NDJSON stream  |                            |
+----------+                   +---+----+----+----+----+----+
                                   |    |    |    |    |    |
                              +----+  +-+--+ | +--+-+ +----+ +-------+
                              |Auth|  |Sess| | |Work| |Logs| |Tool   |
                              +----+  +----+ | +----+ +----+ |Surface|
                                             |               +-------+
                                    +--------v---------+         |
                                    |  Tool Execution  |         |
                                    | Bash, Read, Write|     +---+-----------------+
                                    | Edit, Glob, Grep |     |                     |
                                    | WebSearch, Fetch |     v                     v
                                    +------------------+   +-----------+   +---------------+
                                                           | Webhook   |   | External MCP  |
                                                           | Tools     |   | Servers       |
                                                           | (Registry)|   | (Registry +   |
                                                           | POST URL  |   |  per-request  |
                                                           +-----------+   |  overrides)   |
                                                                           +---------------+
                                                                              http/sse/stdio
```

## Components

### server.ts -- Express Application
Entry point. Configures middleware (JSON and text parsing, skipped for the upload relay path; a 300 s body deadline for every other request until it is answered; request logging; the upload path's pre-auth guard; auth), mounts all routers, and exposes health, logging, session, and settings endpoints directly. The kept `app.listen` handle (`server`) sets `requestTimeout` to 3600 s for the upload relay. At startup it also removes `DEBUG_CLAUDE_AGENT_SDK` from the environment (with a warning), sweeps leftover per-run runtime log directories, and starts the credential relay (`mcp-credential-relay.ts`).

### persistence.ts -- State Files
Shared by `sessions.ts`, `tools.ts` and `mcp-registry.ts`. Saves are debounced (100 ms) and atomic: a temp file `<file>.tmp-<pid>-<hex>` is created in the same directory (`wx`, mode 0600), written, flushed and renamed over the file; the new file then gets the previous file's mode. On start a missing file is an empty start; any other read error or invalid content moves the file to `<file>.corrupt-<UTC stamp>`; if that move fails, the file stays in place and every save of that area is suppressed for the process lifetime. Leftover temp files of the area are removed at start. The per-area issues (`corrupt-preserved`, `unreadable-not-preserved`, `write-failed`) feed the `persistence` / `persistenceIssues` fields of `/health`; see [State Files, Recovery and Shutdown](#state-files-recovery-and-shutdown).

### shutdown.ts -- Clean Stop
Installed by `server.ts` only when it is the process entry point. Handles `SIGTERM`/`SIGINT`: refuse new connections, save early, drain requests already received for up to 8 s, then save all three state files synchronously and exit 0 (all saved) or 1 (a save failed or was suppressed). A second signal ends the drain.

### auth.ts -- API Key Middleware
Parses `API_KEYS` env var at startup into a `Map<key, label>` for O(1) lookup. Validates `Authorization: Bearer <key>` on all routes except `/health`. Attaches `clientLabel` to the request for audit logging.

### query.ts -- Query Endpoint
- **POST /v1/query**: Accepts a prompt, optional system prompt, model, session ID, tool restrictions, and `mcpCredentialOverrides`. Computes the run's tool grant from the caller's API-key label (see [Tool Trust Boundary](#tool-trust-boundary-mvp-7679)), creates an event cache entry keyed by label and `queryId`, runs the query through the retry layer, and streams NDJSON events as they occur. Returns `Content-Type: application/x-ndjson`.
- **GET /v1/query/:queryId/events**: Replays cached events of a completed or in-progress query that the calling label started (another label's entry answers the same 404 as an unknown id). Supports `?after=<seq>` for resuming from a specific sequence number. For in-progress queries, keeps the connection open and streams new events in real time.

The `mcpCredentialOverrides` field carries per-request `headers` (http/sse) or `env` (stdio) values keyed by registered MCP server name. Overrides are validated up-front (`mcp-overrides.ts`), shallow-merged over the static registry config when the SDK builds its `mcpServers` map, and discarded after the query completes — they are never persisted.

### agent.ts -- Claude SDK Wrapper
Calls `query()` from `@anthropic-ai/claude-agent-sdk` with configured tools, permissions, and the merged `mcpServers` map. Translates SDK message types (assistant text, tool_use, tool_result, system status, rate limits) into typed stream events emitted via the `onEvent` callback.

Default tools: `Bash`, `Read`, `Write`, `Edit`, `Glob`, `Grep`, `WebSearch`, `WebFetch`, `Skill`, `TodoWrite`, narrowed by the run's grant. Runs read only the user setting source (`settingSources: ["user"]`; enforced runs read none) and always use the permission-bypass mode (enforced runs: `dontAsk`); built-ins outside the grant are not offered to the runtime (`tools`, `disallowedTools`).

**Isolation (MVP-7678):** the runtime is started only through the SDK's `spawnClaudeCodeProcess` hook, which is `SandboxRun.spawnHook` (`sandbox.ts`): the runtime and everything it starts run inside a bubblewrap sandbox, and `options.env` holds no secret (`runtimeEnvFrom(process.env)` plus the per-run log variables; the sandbox builds its own allowlist). Before every sandbox start `sandbox-content.ts` rebuilds the agent's home from nothing (`prepareSandboxHome`): every home-root entry except `.claude` is removed without following links, and `.claude` keeps only the runtime's data (`RUNTIME_WRITABLE_DIRS`: `projects` with its `-*` transcript directories, `todos`, `plans`, `memory`), because the runtime and its children read the home by name at every start (the shell snapshot runs `bash -l`: `.bash_profile`, `.bash_login`, `.profile`, `.bashrc`; `git` reads `.gitconfig`, `.config/git/config` and the repository at the working directory; the runtime reads `.claude.json` and `.claude/.config.json`, `QF()` in 2.0.77). The agent's persistent files live in the conversation's work area `<root>/sessions/<sandboxDirId>/work`, bound read-write at `/work`, which is the working directory (so transcripts are in `projects/-work/` and resume works); `prepareWorkArea` removes any `.git` entry at the `/work` root (directory, file or link, without following links; a `commondir` pointer or a worktree config would defeat a configuration-only rewrite), because the runtime runs `git status` there at start. Repositories are central read-only mounts, so a work-root repository is not a supported scenario. Removing `.git` is only one layer: git also treats a working directory holding `HEAD`, `objects/`, `refs/` and `config` as an implicit bare repository, so the sandbox environment carries trusted command-scope git configuration (`GIT_CONFIG_COUNT/KEY_n/VALUE_n`, highest precedence, `GIT_TRUSTED_CONFIG` in `sandbox.ts`): `safe.bareRepository=explicit`, `core.fsmonitor=false`, `core.hooksPath=/dev/null`. With no repository discovered in `/work`, the start-time git reads no agent-written file. Repositories below `/work` are not discovered from `/work` (git run inside them works, with fsmonitor and hooks off; a bare repository there needs `--git-dir`). Project settings in `/work` are never loaded (`settingSources: ["user"]`). The extension directories and `CLAUDE.md` are mounted read-only from the workspace, or from an empty trusted stand-in when the workspace has no such entry. A start problem is thrown as an `IsolationFailure` (fixed text, never retried) instead of the SDK's generic exit error. `runQuery` waits for the sandbox process to exit before it returns, so the conversation lock of `query.ts` frees only when no process is left in the conversation's home.

If registered webhook tools exist, they are wrapped as in-process MCP servers via `createToolMcpServer()` and injected into the SDK query alongside the built-in tools. The webhook context (user_id, session_id, api_key_label) and the client's Bearer token are passed to each webhook call. External MCP servers from the MCP Server Registry are merged into the same `mcpServers` map (per-server credentials applied), so the agent can call their tools over the MCP protocol. Every registered server (http, SSE and stdio) reaches the SDK only as a credential-relay URL with a per-run token and no headers, args or env (see [Credential Relay Flow](#credential-relay-flow)); the tokens are revoked when the run ends. The `tool_result` event of a failed call carries `success: false`. The SDK child environment points the runtime's own log files into a private per-run directory (`sdk-run-logs.ts`), deleted after the runtime child has exited.

**Run failures:** on a provider rejection the Claude runtime writes its diagnostic to stdout (a `system/init` message with `claude_code_version`, an assistant message with a non-null SDK `error` and the text `API Error: <status> <raw provider body>`, and a `result` with `is_error: true`, often with `subtype: "success"`) and then exits 1; the SDK yields those messages and only then throws `Claude Code process exited with code 1`. `agent.ts` keeps the classifier inputs of the attempt (the init version, error-flagged assistant messages, the result) and, on that throw or on a completed result with `is_error: true`, throws a `RunFailure` from `run-failure.ts` instead. Every other error thrown during iteration (for example an SDK JSON `SyntaxError`, whose message quotes runtime stdout) is wrapped too; only a client abort (`AbortError`) passes through unchanged. Error-flagged assistant text is never added to the answer, and ordinary assistant text is never classified.

### sandbox.ts -- Per-Run Sandbox
Configuration (`ISOLATION_STARTUP_TIMEOUT_MS`, `AGENT_RUN_TIMEOUT_MS`, `AGENT_SANDBOX_ROOT`, `AGENT_SANDBOX_BWRAP`; an invalid value throws `IsolationConfigError`, which stops startup), the exact `bwrap` argument list (`buildBwrapArgv`), the sandbox environment allowlist (`buildSandboxEnv`), the launch wrapper and `SandboxRun`. The wrapper is the first process inside a sandbox: it exits 97 when a nested user namespace can still be created (the run is then refused as `userns_not_blocked`), closes the launcher's argument descriptor, reports `SANDBOX-CHECK-OK` on stderr (the readiness signal) and execs the runtime. The options reach `bwrap` through `--args 3` so `/proc/1/cmdline` inside a sandbox shows no host path. `SandboxRun` prepares a private run directory below `AGENT_SANDBOX_ROOT/runs/` (trusted files: generated `settings.json`, git config masks, an empty file for hidden paths), the conversation's persistent home (`sessions/<sandboxDirId>/home`) or a private per-run home, validates the content plan (`sandbox-content.ts`), registers a model proxy token and starts `bwrap`; `dispose()` revokes the token, waits for the process to exit and removes the run directory. `isolationStatus()` feeds `/health`; `runIsolationSelfCheck()` starts a real sandbox at boot (canary file invisible, own PID namespace, nested user namespace refused). `tryLockConversation()` is the one-active-request-per-conversation lock. Problems are reported as one fixed log line `ERROR isolation problem=<word> reason=<fixed text> (see /health)`.

### sandbox-content.ts -- What a Sandbox May See
`checkTrusted()` (lstat, owner, tree, real path), `readFileNoFollow()`, `listRegularFilesNoFollow()`, `copyFileNoFollow()`, `allowlistGitConfig()` (remote url without user info and fetch, `branch.*`, `core.*` without `sshCommand`/`askpass`/`fsmonitor`/`hooksPath`, `extensions.*`), `KnownValueScanner` (the gateway's known secret values, read in 1 MiB chunks with overlap so a value across a chunk boundary is found, cached by mtime and size, skips git object stores; a file above the 64 MiB ceiling is never read and is hidden with audit `reason=too_large`), `sshPrivateKeyValues()` and `webhookUrlValues()` (the private-key lines of `$HOME/.ssh` and the credential parts of registered webhook URLs, assembled with the environment, OAuth and registry values by one function, `gatewayKnownValues()` in `tool-mediation.ts`, which feeds both the hidden-file scan and the masking of tool refusal texts; the scan covers the global entries and `projects/` repositories, verbatim copies only, and not the per-user skills bundle) and `planTrustedContent()` (global entries, generated settings, repositories under `projects/` with their git configs, hidden files). `prepareMountPoints()` removes links and wrong-typed entries the agent planted at mount points in its own home. Nothing here logs a value or a path below the workspace root.

### run-failure.ts -- Run Failure Classification
`classifyRunFailure()` turns one failed attempt into a `RunFailure` (an `Error` without `cause`) with `kind`, a fixed safe public `message`, `retryable`, operator-safe `logFields` and `resultSummary` (the result's usage, cost, duration, turn count, subtype, `is_error` and `session_id`, never its text or `errors`). Inputs are only the init `claude_code_version`, the result text when `is_error` is true, `result.errors[]`, the text and enum of error-flagged assistant messages, and the thrown error. A text is parsed only after an `API Error: <status>` prefix and only up to 16 KiB, reading fixed paths (`error.type`, `error.code`, `error.error.type`, `error.error.code`, `error.message`); version patterns run only on the first 1 KiB of `error.message`, and a version is used only when it matches `^\d{1,5}\.\d{1,5}\.\d{1,5}$`. The classifier is total (an internal exception gives `unknown`).

| kind | recognized by | retried |
|------|---------------|---------|
| `runtime_version_unsupported` | provider code `claude_code_version_too_old` | no |
| `authentication` | assistant `error: "authentication_failed"`, provider type `authentication_error` or `permission_error` | no |
| `transient` | status 429/529, provider type `rate_limit_error`/`overloaded_error`, assistant `error: "rate_limit"`, or (without any diagnostic) a thrown message matching the historic pattern (`rate.limit`, `429`, `throttl` or `overloaded`, case-insensitive; not for a JSON `SyntaxError`) | yes |
| `unknown` | everything else, including absent, malformed or oversized diagnostics and `billing_error`/`invalid_request`/`server_error` without a recognized code | no |
| `isolation_unavailable`, `isolation_timeout` | `IsolationFailure` from `sandbox.ts` (a permanent start problem, or no readiness within `ISOLATION_STARTUP_TIMEOUT_MS`) | no |
| `run_deadline` | `AGENT_RUN_TIMEOUT_MS` expired (retries and backoff included) | no |
| `session_other_owner`, `session_legacy`, `session_busy` | conversation admission in `query.ts` | no |

Permanent kinds beat `transient`, and `transient` beats `unknown`. The exact public messages are listed in the README ("Failed queries"). The installed version comes only from the init message and the required one only from an explicit "`<version>` or newer" or ">= `<version>`" in `error.message`.

### tool-grant.ts -- Trusted Tool Grant
Parses `AGENT_TOOL_POLICY` (fixed `FATAL config key=AGENT_TOOL_POLICY reason=<reason>` lines, one startup audit line per label) and computes a run's `ToolGrant`: the policy for the caller's label intersected with the caller's narrowing (`enforcedTools` or `allowedTools`). It answers `allows(name)`, `allowsServer(server)`, `coversServer(server)` and the built-in lists handed to the runtime. Deny beats allow; an absent `allow` means everything a run gets without a policy; `allow: []` means nothing; a label entry replaces `default`.

### tool-mediation.ts -- Tool Request/Reply Contract
The internal contract of every mediated call: `ToolRequest { runId, callId, toolId, input }` and `ToolReply` (`ok` with `output`, or an error with one of the five codes `TOOL_DENIED`, `TOOL_AUTH_UNAVAILABLE`, `TOOL_UNAVAILABLE`, `TOOL_TIMEOUT`, `TOOL_RESPONSE_INVALID` and its fixed text). One mapper (`describeFailure`) turns every failure into a text without upstream body, header, URL or secret; one renderer writes it into the existing public shapes (an MCP `isError` result or a JSON-RPC error). No new client-facing envelope exists. It also holds `webhookRejectionText()` (the model-facing text of a webhook 4xx that is the tool's own refusal), secret masking and the `AGENT_MCP_TOOL_TIMEOUT_MS` parser.

### mcp-bridge.ts -- SSE Bridge
For an upstream that speaks the legacy MCP HTTP-with-SSE transport, the relay hands each already-checked JSON-RPC message to this bridge, which opens the stream with the run's headers, accepts the `endpoint` event only on the registered origin, answers server requests locally (`ping`, `roots/list`, method-not-found) and drops server notifications. It returns each answer as one JSON message or a `ToolFailure`.

### mcp-stdio-sandbox.ts -- Stdio Tool Sandbox
Runs every registered stdio server, stdio overrides and request stdio servers with `env` in their own bubblewrap sandbox (built with `sandbox.ts`'s argv builder and launcher), with a bridge that speaks one JSON message per line over stdin/stdout. See the tool sandbox below.

### mcp-credential-relay.ts -- Credential Relay
A `node:http` listener on 127.0.0.1 (ephemeral port, never an Express route). `register()` binds a 128-bit token to a run's binding (upstream or bridge, merged credential headers or env, the run's grant); `revoke()` ends it: requests still uploading are closed, in-flight upstream requests are destroyed, and no upstream request is sent with its headers afterwards. Only `POST` and `DELETE` on the exact `/mcp/<token>` path are forwarded; see the flow below for header allowlists and refusal answers.

### sdk-run-logs.ts -- Per-Run Runtime Logs
Creates the per-run directory (0700, prefix `agent-gateway-run-` under the OS temp directory) and the SDK child environment additions `CLAUDE_CODE_DEBUG_LOGS_DIR=<dir>/debug/run.txt` and `XDG_CACHE_HOME=<dir>/cache`. A `spawnClaudeCodeProcess` hook spawns the runtime like the SDK's default and reports the child; the directory is deleted once the child has exited (after 10 s it is killed first). Also sweeps leftovers at startup (every `agent-gateway-run-*` directory in the OS temp directory, so one gateway per temp directory is assumed, as in the Docker image) and strips `DEBUG_CLAUDE_AGENT_SDK`.

### sessions.ts -- Session Management
Maps client-provided session IDs to internal Claude SDK session IDs. Sessions are:
- **Created** on first query with a given sessionId
- **Resumed** when the stored session has a confirmed SDK session ID (`sdkSessionId`)
- **Restarted** when it has none (its first query failed): the next query gets a new SDK session ID (persisted under the same client ID) and starts fresh, because Claude Code 2.0.77 would append to the failed attempt's transcript if the old ID were reused
- **Synced** via `updateSessionSdkId()` after each successful query -- the SDK may return a different session_id than the one provided, so the gateway updates the stored mapping to ensure subsequent queries resume the correct conversation. A failed query confirms nothing
- **Persisted** to disk (debounced, atomic; see `persistence.ts`) at `SESSION_PERSIST_PATH`
- **Restored** from disk on startup (expired sessions filtered out)
- **Cleaned** every 5 minutes if `SESSION_IDLE_TIMEOUT_MS > 0`
- **Keyed by label** (MVP-7679): conversations live in `sessionsByLabel[<label>][<client id>]` (additive map of `sessions.json`); public routes keep raw ids. Another label using the same id gets its own new conversation, with no refusal and nothing learned; ownerless legacy entries stay under their raw id and are refused for every label. An older gateway version ignores and drops the map, so conversations started or moved under this version start fresh after a rollback; the only valid rollback targets are images that passed the acceptance suite and both Docker probes (see the README runbook, "Rollback").
- **Owned** (MVP-7678): a new entry records its `owner` (`{label, userId|null}`) and a random `sandboxDirId` (the conversation's sandbox home). `admitSession()` runs before anything else and changes nothing: no entry means new, the exact owner resumes, another owner is refused, and an entry without a recorded owner and home (created before the update) is refused for everyone and counted in one audit line. `listSessions(label)` and `deleteSession(id, label)` are scoped to the caller's label (`deleteSession` removes the caller's own entry first, then a legacy entry).
- **Validated at load**: a present `owner` or `sandboxDirId` of the wrong shape sets the whole file aside like other unexpected content (`persistence.ts`).

Session continuity uses two SDK options:
- **New sessions**: pass `sessionId` to start a fresh conversation
- **Existing sessions**: pass `resume` with the stored SDK session ID to continue the conversation with full context

### retry.ts -- Retry with Exponential Backoff
Wraps `runQuery` with up to 3 retries. Retries on:
- Transient failures (`RunFailure.retryable`: rate limit or overload, see `run-failure.ts`)
- Empty or whitespace-only answers of a run that did not fail

Permanent failures (`runtime_version_unsupported`, `authentication`, `unknown`) are thrown at once. Uses exponential backoff (1s, 2s, 4s) with a 60-second total budget. Emits `rate_limited` events so clients can show retry status. Respects `AbortController` for cancellation. A retry resumes only an established session (the request resumed one, or an earlier attempt of a request with a session ID ended with a result that is not `is_error` and has a `session_id`); otherwise it starts fresh with a new SDK session ID. Retry log lines carry the query ID, `kind` and attempt, never an error message.

### event-cache.ts -- Event Cache
Stores NDJSON events in memory keyed by (API-key label, `queryId`), so a label can replay only its own queries. Used by `GET /v1/query/:queryId/events` for replay and real-time streaming. Entries are marked "done" when the query completes. A background timer (every 60s) garbage-collects entries older than `EVENT_CACHE_TTL_MS` (default 30 minutes).

### workspace.ts -- File Operations
Provides safe file CRUD for three workspace sections: `memory`, `agents`, `skills`. All paths are resolved relative to `WORKSPACE_ROOT` (default `$HOME/.claude`). Includes path traversal protection via `safePath()` which validates against directory escape, absolute paths, null bytes, and symlink attacks.

### logging.ts -- Runtime Logging
Three levels: `off`, `info`, `debug`. Level is adjustable at runtime via `PUT /v1/logging`. Request/response logging middleware logs method, URL, status code, and duration (body content only at debug level). At debug level, `redactCredentialsForLog()` makes a log copy of the request body (then cut to 2000 characters) and of a JSON response chunk (then cut to 500 characters) in which the whole value of every `headers` and `env` key, at any depth, is `"[REDACTED]"` with the keys kept, the `args` of every stdio server definition (an object with a `command` key or `type: "stdio"`) are `"[REDACTED]"` per element (a credential can travel on the command line), every `sshKey` value is `"[REDACTED]"`, and every string `url` value has its credentials replaced by `***` (`redactUrlCredentials()`, also used for git error text). Redaction comes before the cut, and the client payload is never changed. `text/*` request bodies are logged as their length; a non-JSON answer on a `/v1/mcp-servers` route is not previewed. `globalErrorHandler` (mounted last by `server.ts`) logs body-parser errors as `request body rejected type=<type> status=<code>`, never their message, which quotes part of the body.

### routes/ssh.ts -- SSH Key Management
**POST /v1/ssh-keys**: Uploads an SSH private key (and optional public key) to `~/.ssh/`. Derives the public key from private if not provided. Writes an SSH config with `StrictHostKeyChecking accept-new`. Validates filename to prevent path injection.

### routes/auth.ts -- Anthropic OAuth
Three-step flow using tmux to interact with Claude CLI:
1. **POST /v1/auth/login**: Starts the Claude CLI bundled with the SDK in the image (never `~/.local/bin/claude`, which agents could write) in a tmux session, captures the OAuth authorization URL.
2. **POST /v1/auth/submit-code**: Sends the authorization code to the tmux session, polls for login success.
3. **GET /v1/auth/status**: Reads the login state from the trusted files (`~/.claude/.credentials.json`, `~/.claude.json`) or `ANTHROPIC_API_KEY`; the bundled CLI has no `auth status` command. The response carries `loggedIn`, `email`, `expiresAt` (epoch ms from `claudeAiOauth.expiresAt`) and `tokenExpired` (boolean, `Date.now() > expiresAt`) so clients can warn users before queries start failing with auth errors.

### model-proxy.ts -- Trusted model proxy (MVP-7678)
A loopback listener (127.0.0.1, ephemeral port, not an Express route). An agent run gets `ANTHROPIC_BASE_URL` pointing at it and a random run token as its only `ANTHROPIC_API_KEY`. The proxy accepts the token only in `x-api-key` (constant-time, revoked when the run ends), allows only `POST /v1/messages` and `POST /v1/messages/count_tokens` (query `beta=true` or none, body up to 32 MiB, canonical paths only), drops the caller's credential headers, adds the gateway's credential (`ANTHROPIC_API_KEY`, otherwise the OAuth access token of `.credentials.json`, refreshed once at a time on the trusted side) and forwards to `ANTHROPIC_BASE_URL` (default `https://api.anthropic.com`). Status, `x-should-retry` and rate-limit headers pass through; `set-cookie` does not. It never logs headers, bodies, paths or tokens. `MODEL_PROXY_IDLE_TIMEOUT_MS` (default 600000) bounds a silent provider request.

### routes/git.ts -- Workspace Git Endpoints
Lets clients clone and refresh git repositories inside `WORKSPACE_ROOT/projects/<path>` so agents can `Read`/`Grep` real source trees as part of their context:
- **POST /v1/workspace/git/clone**: Clones `url` into `path`, optionally on a specific `branch`. If the target already has a `.git` directory, falls back to `git pull` after aligning the checkout with `branch`. Accepts an inline `sshKey` body field for one-shot clones; the key is written to a private temp directory, used via `GIT_SSH_COMMAND`, and removed in `finally`.
- **POST /v1/workspace/git/pull**: Pulls updates for an existing repo. Returns `up-to-date` or `updated` based on commit-before / commit-after comparison.
- **GET /v1/workspace/git/status?path=...**: Returns `branch`, `commit`, `dirty`, `lastCommitDate` for the repo at `path`.

All paths are resolved through `resolveProjectPath()` which rejects absolute paths and `..` traversal. A `branch` starting with `-` is rejected with `400 {"error":"Invalid branch"}` before anything is queued (`git checkout` would read it as an option, and `--` cannot help there). A clone `url` containing a line break or NUL is rejected with `400 {"error":"Invalid url"}` (git refuses such URLs, and a line break would split the URL across lines of the error text), and a `url`, `path`, `branch` or `sshKey` that is present but not a string with `400 {"error":"<field> must be a string"}`, also before anything is queued. The handlers are `async` and never block the event loop: each request takes its repository's turn (`withRepoTurn`, keyed by the resolved path), then a global slot (`withGitSlot`), and only then writes the SSH key and runs git. The existence checks (clone's pull-instead, pull's 404, status's `exists:false`) run inside the turn, so a queued request sees the outcome of the one before it. Clone runs `git clone [-b <branch>] -- <url> <path>`; the branch fetch runs `git fetch origin -- +refs/heads/<branch>:refs/remotes/origin/<branch>`, so a branch value can act neither as an option nor as a refspec of its own. The clone success line logs the URL with credentials removed.

### git-exec.ts -- Git Runner and Queues
- **`runGit(args, cwd, env?)`**: `spawn("git", args)` without a shell, in its own process group, output capped at 10 MiB. On `GIT_TIMEOUT_MS` (default 120000) or overflow the whole group gets SIGTERM, then SIGKILL after 2 s, so a helper that still holds git's pipes (`git-remote-https`, `ssh`) cannot keep the request open. The child environment sets `GIT_TERMINAL_PROMPT=0`, pins `protocol.ext.allow=never` via `GIT_CONFIG_COUNT`, and drops `GIT_TRACE*`/`GIT_CURL_VERBOSE`.
- **Error text**: a `GitError` carries git's own stderr with URL credentials removed, then cut to 4 KB. Tokens reach git unencoded and git echoes a URL it cannot parse as is, so a token may contain `/`, whitespace, quotes or `@`: on every line, everything from the first `scheme://` to the last `@` becomes `***` (`redactUrlCredentials`). This covers `http(s)://` URLs; for `ssh://`, `git://` and `file://` URLs (which do not use passwords) ssh/git may echo the user-info in a form without `scheme://`, which stays visible. This may also hide a host or path that shares the line with a URL; a timeout reads `git <subcommand> timed out after <n> s`. Node's `Command failed: <command line>` message is never used, because the command line can hold a token-bearing URL. `gitErrorText()` applies the same redaction to non-git errors.
- **Queues**: `withRepoTurn` is a per-repository FIFO chain (idle entries removed); `withGitSlot` is a global FIFO semaphore of `GIT_MAX_CONCURRENCY` (default 3) slots that never rejects and hands a released slot to the oldest waiter, whether the operation succeeded, failed or timed out. `gitQueueSnapshot()` reports `{ running, waiting }` for tests.
- **Limits**: git removes its `index.lock` on SIGTERM but not after the SIGKILL fallback; the next operation on that checkout then fails with git's lock error, and the lock is not removed automatically (agents may run git in the same checkout). Descendants killed after a timeout are re-parented to the gateway process, which does not reap them, until the container gets an init process.

### tools.ts -- Tool Registry
Manages CRUD operations for webhook-backed tool definitions. Tools are stored in-memory in a `Map<name, ToolDefinition>` and persisted to disk (debounced) at `TOOLS_PERSIST_PATH` (default `./data/tools.json`, Docker override: `/home/node/.claude/tools.json`). Each tool definition includes: `name`, `description`, `input_schema` (JSON Schema), `webhook_url`, optional `timeout_ms` (default 30s) and `owner` (the registering API-key label; legacy entries have none). Tools are loaded from disk on startup via `loadTools()`, which logs `tools.legacy.ownerless count=<n>` when entries have no owner.

### webhook.ts -- Webhook Executor
Executes tool calls by POSTing to the tool's `webhook_url`. The request body contains `tool_use_id`, `tool_name`, `input`, and `context` (user_id, conversation_id, session_id, api_key_label). The calling client's Bearer token is forwarded in the `Authorization` header only to tools its label owns (a legacy ownerless tool keeps today's forwarding, with one `tool.webhook.legacy_forward` audit line per call). `X-Webhook-Context` comes only from the authenticated request. Never follows a redirect; answers over 8 MiB are refused. Supports configurable timeouts per tool. Failures map to the fixed `TOOL_*` texts of `tool-mediation.ts`; a 4xx that is the tool's own refusal reaches the model as `The tool rejected the request (HTTP <status>): <message>`.

### tool-server.ts -- MCP Server Factory (webhook tools)
Creates an in-process MCP server wrapping the registered webhook tools the run is offered (its own label's plus legacy ownerless ones, and only granted ones) for injection into the Claude Agent SDK. Called once per query so the webhook context (session, user, auth) is correctly scoped. Each tool's registered `input_schema` is converted by `tool-input-schema.ts`: the model sees the declared field types, required fields and descriptions, and the SDK validates every call against them before the handler runs. Webhooks keep their own validation. Uses `createSdkMcpServer()` from the Agent SDK.

### tool-input-schema.ts -- Webhook Tool Input Schemas
Converts a webhook tool's `input_schema` (JSON Schema) into the Zod shape the SDK MCP server uses for `tools/list` (what the model is told) and for `tools/call` argument validation. Closed allowlist:

| Registered construct | Advertised to the model | At `tools/call` |
|---|---|---|
| `type` `string` / `number` / `integer` / `boolean` | Same type (`integer` stays `integer`) | Another type is rejected |
| `enum` (non-empty, unique string/number literals matching `type`) | Same values | A value outside the enum is rejected |
| `type: object` with `properties` / `required` | Nested properties, `required` and descriptions, recursively | Nested violations are rejected; undeclared nested keys still reach the webhook |
| `type: array` with one `items` schema | Array with the item schema | Item violations are rejected |
| `required` (top level and nested) | Exactly the registered names that exist in `properties` | A missing required field is rejected |
| `description` (string) | Same text | -- |
| `additionalProperties` | Ignored (not advertised, not enforced) | Unchanged: undeclared top-level keys are dropped before the webhook, as before |
| Anything else (`format`, `pattern`, bounds, `oneOf`/`anyOf`/`allOf`/`$ref`, `default`, `nullable`, `title`, a `type` array or unknown type, a missing `type`, tuple `items`, malformed keywords, nesting deeper than 32 levels) | That property only: "any value", keeping its description and required status | Any value is accepted; the webhook validates it as before |

There are no defaults and no coercion: a valid call reaches the webhook with the model's values unchanged. A rejected call never reaches the webhook; the model receives a tool result with `isError: true` and the text `MCP error -32602: Input validation error: Invalid arguments for tool <name>: [...]`, a JSON list of issues, each naming the field `path` and the expectation (for example `"expected": "string"` with `"message": "Invalid input: expected string, received number"`). Webhook error responses are still relayed as `Tool webhook returned error: <status> <body>`.

The SDK builds `tools/list` with its own bundled zod, so each property carries its advertised JSON fragment through zod's `_zod.toJSONSchema` override (otherwise descriptions are lost and `integer` is widened to `number`); the real-runtime contract test pins this across SDK upgrades. The registry is global, so a conversion is isolated per tool: a schema that cannot be converted (for example a malformed top-level `required`) makes that tool alone fall back to the previous untyped shape (every declared key accepts any value), with a `tools.schema.untyped_fallback tool=<name>` log line. Property names that can never reach the webhook are not advertised and are logged (`tools.schema.property_excluded`): `__proto__` at any level, and a top-level `constructor` (the SDK's MCP protocol rejects any call whose arguments hold that key). Tools are converted per query from `tools.json`, so existing registrations get typed schemas after a restart, without re-registering.

### routes/tools.ts -- Tool Registry Endpoints
REST endpoints for webhook tool management:
- **PUT /v1/tools/:name**: Register or update a tool (validates description, input_schema, webhook_url); records the authenticated label as `owner` (an `owner` in the body is ignored); another label's owned tool answers 403 `TOOL_OWNED_BY_OTHER_CLIENT`; the first label that registers a legacy ownerless tool again claims it
- **GET /v1/tools**: List all registered tools (with `owner`)
- **GET /v1/tools/:name**: Get a single tool definition (with `owner`)
- **DELETE /v1/tools/:name**: Remove a tool (403 for another label's owned tool)

### routes/workspace.ts -- Workspace CRUD
Generates GET/PUT/DELETE routes for each workspace section (`memory`, `agents`, `skills`). GET on the section root lists all files. GET/PUT/DELETE on sub-paths reads/writes/deletes individual files.

### mcp-registry.ts -- External MCP Server Registry
Registry for *external* MCP servers — distinct from the webhook Tool Registry. Each entry describes an existing MCP server (`type`: `http`, `sse`, or `stdio`) plus optional per-server credential schema. Definitions are kept in a `Map<name, McpServerDefinition>` and persisted to `MCP_SERVERS_PERSIST_PATH` (default `./data/mcp-servers.json`, Docker override `/home/node/.claude/mcp-servers.json`).

`buildMcpServersForSdk()` produces the `mcpServers` map handed to the Agent SDK on every query. Disabled servers (`enabled: false`) are skipped. Every enabled registered server then reaches the runtime only as `{type: "http", url: <relay URL>}` (see [Credential Relay Flow](#credential-relay-flow)); its credentials stay in the relay binding. Per-server `allowedToolsPattern` globs (e.g. `mcp__jira__*`) are aggregated into the SDK's `allowedTools` list, which only pre-approves tools: the pattern is not part of the grant and has no authorization effect (the grant is described in [Tool Trust Boundary](#tool-trust-boundary-mvp-7679)).

`requireUserCredentials` (optional boolean, not allowed with `sse`) marks a server that needs the requesting user's own credential. `selectRegistryServersForRun()` in `mcp-overrides.ts` leaves such a server out of a run whose `mcpCredentialOverrides` entry has no non-empty value for the transport's target (or misses a `userCredentialSchema` output key: `headers` keys are matched case-insensitively and every match must be non-empty, `env` keys exactly); `agent.ts` then drops its SDK entry and its allowed-tool pattern, and logs `mcp.server.omitted serverName=<name> reason=missing_user_credential`.

`userCredentialSchema` lets the registry advertise the form a user has to fill in to derive credentials at query time. `fields[]` declares form input definitions (`text`, `password`, `url`, `email`); `outputs[]` declares how those values compose into either `headers` (http/sse) or `env` (stdio) targets via plain substitution (`"{key}"`) or HTTP Basic encoding (`"basic:{email}:{apiToken}"`). Transport-target mismatches are rejected with `SCHEMA_TARGET_MISMATCH` at registration time.

Each entry records its owner, the API-key label of the caller that created it (`owner?` on `McpServerDefinition`, never returned by a route). Only the owner may `PUT` or `DELETE` an existing name; any other label, and every label for an ownerless entry (registered before ownership), gets HTTP 403 `MCP_SERVER_OWNER_MISMATCH` with a fixed body that names no owner, checked before the name rule and body validation. An ownerless entry is also left out of a run that carries a user credential for it (`reason=ownerless`) and refused on credential-bearing `/call`, `/test` and `/uploads/*`. `mcp-server-owners.ts` applies the deploy-step mapping `MCP_SERVER_OWNERS=<name>:<label>,...` at startup (only to ownerless entries, then `flushMcpServers()`), with read-back lines `mcp.registry.owner_assigned` / `owner_mapping` / `ownerless count=<n> ... saved=<true|false>`; a malformed mapping stops startup with `FATAL config key=MCP_SERVER_OWNERS`.

### mcp-overrides.ts -- Per-Request Credential Overrides
Validates the `mcpCredentialOverrides` body field on `POST /v1/query` against the current registry. Each override entry references a registered server by name; unknown names return `MCP_SERVER_NOT_FOUND`, disabled names return `MCP_SERVER_DISABLED`. HTTP/SSE servers may only carry `headers`; stdio servers may only carry `env`. Validated overrides are shallow-merged over the static registry config when the SDK invocation is built. Overrides are request-scoped only — they never write back to disk. `credentialMapsError()` is the shared check for `headers`/`env` maps (string maps, headers Node can send, no NUL in env), used by the overrides, the registry `PUT`, `/test` and `/call`.

### mcp-request-servers.ts -- Request MCP Servers
Validates and normalizes the request `mcpServers` map on the trusted side: name `^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$`; reserved name `agent-gateway-tools`; a server has either `command` (stdio, no `type`) or `url` (`type` only `http` or `sse`, default `http`); `headers`/`env` are string maps with sendable values; unknown fields are dropped; a name equal to any registered server (enabled, disabled or left out of the run) is HTTP 400 `MCP_SERVER_NAME_CONFLICT`. Routing in `agent.ts`: http/SSE servers with headers (or a URL with a user name, password or query) go through the relay, stdio servers with `env` run in their own tool sandbox, servers without headers/env connect directly or run inside the agent sandbox. A request `command` server is attached only when the trusted policy lets the label run `Bash` or names the server in its `allow` list (`mcp.server.omitted ... reason=command_not_granted`).

### credential-composer.ts -- Credential Template Substitution
Lightweight template engine used both by the MCP registry's `userCredentialSchema.outputs[]` validation and by future per-user credential composition. Supports plain field substitution (`"{fieldKey}"`, `"prefix-{a}-{b}"`) and HTTP Basic auth shorthand (`"basic:{email}:{apiToken}"`, emitted as `Basic <base64(email:apiToken)>`). `getCredentialTemplateFieldKeys(template)` returns the set of `{...}` placeholders so the registry can reject templates that reference fields not declared in the same schema.

### mcp-test-client.ts -- MCP Credential Test Client
Implements `POST /v1/mcp-servers/:name/test` — given a registered server name and an override payload (`headers` for http/sse, `env` for stdio), the gateway connects to the upstream MCP server, calls `tools/list`, and returns `{ ok: true, toolCount, tools[] }`. The client accepts both plain `application/json` and streamable `text/event-stream` MCP responses (MVP-3689) so providers that emit one-shot SSE responses for HTTP requests are supported. It never follows a redirect (a 3xx is `MCP_NETWORK_ERROR`, the credential never goes to the target) and uses the same case-insensitive header merge as the relay. Auth failures (401/403) surface as `MCP_AUTH_FAILED`, transport problems as `MCP_NETWORK_ERROR`, and the per-test deadline as `MCP_TIMEOUT` (configurable via `MCP_TEST_TIMEOUT_MS`, default 10s).

### mcp-upload-relay.ts -- Streaming Upload Relay
The raw-path rule shared by the body-parser skip, the pre-auth guard (`Connection: close`, bounded drain) and target extraction; strict `X-MCP-Credential-Headers` parsing (only `Authorization` is used); the upstream request builder (origin of the registered url + `/uploads/` + raw target + raw query, filtered static headers); and `UploadRelay`, which forwards chunks with backpressure, owns the idle timer and writes one audit line. See [Upload Relay Flow](#upload-relay-flow).

### gc-budget.ts -- Byte-Budgeted Garbage Collection
Forces a minor collection every 2 MiB relayed so dropped chunk buffers do not pile up (the process must run with `--expose-gc`, as `entrypoint.sh` and `npm start` do). Ported from mcp-jira's upload route.

### routes/mcp.ts -- MCP Server Registry Endpoints
REST endpoints for the external MCP server registry:
- **PUT /v1/mcp-servers/:name**: Register or update a server (validates transport, fields, output targets, template references). Records the calling label as owner on creation; a non-owner gets 403 `MCP_SERVER_OWNER_MISMATCH` before any validation. Creating a new entry first requires the name rule `^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$` (else 400 `MCP_SERVER_NAME_INVALID`); updates and deletes of existing entries are never refused because of their name
- **GET /v1/mcp-servers**: List all registered servers
- **GET /v1/mcp-servers/:name**: Get a single server definition
- **DELETE /v1/mcp-servers/:name**: Remove a server (owner only; 403 `MCP_SERVER_OWNER_MISMATCH` otherwise, 404 for an unknown name)
- **POST /v1/mcp-servers/:name/test**: Probe `tools/list` with optional override credentials, returning the discovered tool list or a typed error
- **POST /v1/mcp-servers/:name/call**: Direct `tools/call` without an LLM; answers 401 `MCP_AUTH_FAILED` before any upstream request for a `requireUserCredentials` server without a user credential; never follows a redirect
- **POST /v1/mcp-servers/:name/restart**: Bumps the server's `updatedAt` so the SDK reconnects (http/sse) or respawns (stdio) on the next query
- **GET /v1/mcp-servers/:name/health**: Cheap connectivity probe (no `tools/list`) — returns `{ ok, latencyMs, error? }`
- **POST /v1/mcp-servers/:name/uploads/\***: Streaming upload relay to `<origin>/uploads/*` of an http/sse server (see [Upload Relay Flow](#upload-relay-flow))

## Data Flow: Query Request

1. Client sends `POST /v1/query` with `queryId`, `prompt`, optional `sessionId`, optional `mcpCredentialOverrides`
2. Auth middleware validates Bearer token
3. `validateMcpCredentialOverrides()` confirms every overridden server is registered + enabled and that the override targets match transport (`headers` for http/sse, `env` for stdio)
4. Event cache entry created for `queryId`
5. Conversation admission (`query.ts`), keyed by (label, `sessionId`): another `user_id`, a legacy entry or a busy conversation ends the request here with one fixed `error` event and no run. Then the session is resolved: existing session of the label reused (with `resume`) or new one created (with `sessionId`, an owner and a sandbox home name), and the conversation lock is held until the request ends. The tool grant is computed from the caller's label and the request's `enforcedTools`/`allowedTools` (a bad `allowedTools` is HTTP 400 before streaming)
6. Registered webhook tools the run is offered (own label plus legacy ownerless, granted only) are wrapped as in-process MCP servers via `createToolMcpServer()`. External MCP servers are pulled from `mcp-registry.ts`, merged with per-request overrides, bound in the relay (token, upstream or bridge, merged credentials, grant) and added to the `mcpServers` map handed to the SDK as relay URLs; a server with no granted tool is not attached
7. `runQueryWithRetry` starts the run deadline (`AGENT_RUN_TIMEOUT_MS`) and calls `runQuery` (agent.ts), which starts the runtime in the sandbox (see Agent Isolation)
8. Agent SDK streams messages; `agent.ts` translates to events:
   - `text` -- assistant text chunks
   - `tool_use` -- tool invocation (name, input summary)
   - `tool_result` -- tool output (truncated to 3000 chars); `success: false` when the result is an error
   - `rate_limited` -- rate limit detected, retrying
   - `sdk_status` -- SDK status changes (compacting)
   - `sdk_compact_complete` -- context compaction completed
9. For registered webhook tools, the in-process MCP server handler POSTs to the webhook URL and returns the result. For registered MCP servers (http, SSE, stdio), the SDK speaks MCP to the credential relay, which checks the grant and forwards to the upstream (http), the SSE bridge or the stdio tool sandbox with the run's credentials; request servers with headers or env take the same path, other request servers connect directly or run inside the agent sandbox
10. Events are written to response stream (NDJSON) and cached under (label, `queryId`)
11. On completion, `done` event emitted with token usage, cost, context stats; SDK session ID synced via `updateSessionSdkId()`
12. On failure, exactly one `error` event `{seq, type, content}` emitted by one helper in `query.ts`: `content` is the `RunFailure` message (the SDK's text for a client abort); no `done` and no `updateSessionSdkId()`. The log line is `Error queryId=<id> kind=<kind> apiStatus=<n|none> providerType=<type|other|none> installed=<v|none> required=<v|none>`
13. Event cache entry marked "done"; per-request overrides are dropped (never persisted)

## Session Lifecycle

```
Client sends sessionId="abc"
    |
    v
Session exists with a confirmed SDK session?
    |                    |
   YES                  NO (new, or its first query failed)
    |                    |
    v                    v
Reuse stored SDK      Create new Claude
session UUID          session UUID
    |                    |
    v                    v
SDK option:           SDK option:
resume=<sdkId>        sessionId=<newId>
    |                    |
    v                    v
Resume conversation   Start fresh
    |                    |
    +--------+-----------+
             |
             v
    After a successful query:
    updateSessionSdkId() syncs
    stored ID with SDK's actual
    session_id (snake_case field).
    A failed query confirms nothing.
```

Sessions persist across server restarts via `SESSION_PERSIST_PATH`. The cleanup timer evicts sessions idle longer than `SESSION_IDLE_TIMEOUT_MS`.

## Agent Isolation

```
                  trusted (the gateway process, uid node)                      untrusted (per run)
+---------------------------------------------------------------+   +------------------------------------------+
| API keys, provider key, OAuth tokens, state files, SSH keys   |   | bubblewrap sandbox: user, PID, IPC, UTS, |
| model proxy  127.0.0.1:<p>  (run token -> provider call)  <---+---+-- cgroup namespaces; shared network        |
| credential relay 127.0.0.1:<q> (registered MCP servers)   <---+---+-- Claude runtime, Bash, interpreters,        |
| session lock, owner check, content validation and scan        |   |   Read/Write/Edit/Glob/Grep, MCP servers |
+---------------------------------------------------------------+   |   without credentials, sub-agents        |
        |  starts bwrap --args 3 (options on a pipe), env allowlist  |                                          |
        +----------------------------------------------------------->|  sees: read-only system + runtime +      |
                                                                     |  global dirs + repositories (masked git  |
                                                                     |  config) ; writable: its home, /tmp      |
                                                                     +------------------------------------------+
```

**Trust boundary.** The gateway never gives the runtime a secret: the environment is an allowlist built from nothing, the provider credential stays behind the model proxy (the runtime holds a random run token, valid for this run only), registered MCP servers stay behind the relay (credential-bearing stdio servers in their own tool sandbox), and trusted files are never mounted. The agent can write its own home and its work area, so nothing the runtime or its children read at start comes from them: the home is rebuilt from nothing before every sandbox start (only the runtime's transcripts, todos, plans and the memory mount point carry over), runs read only the user setting source (`settingSources: ["user"]`; enforced runs none) so project settings in `/work` are inert, any `/work/.git` is removed before the runtime's `git status`, and the extension directories are mounted read-only (empty when the workspace has none). Everything an agent can run is the runtime process or its child, so it is inside the sandbox; there is no command filtering to bypass.

**Data flow of a run.** caller query -> owner check -> conversation lock -> sandbox home and content validation (no-follow checks, git config masks, known-value scan) -> `bwrap` start and check (`unshare -U` must fail inside) -> runtime inside the sandbox -> provider calls to the model proxy with the run token -> tool calls (shell and files inside the sandbox; MCP servers through the relay after the grant check; webhook tools in-process through the SDK control channel) -> events and the transcript in the conversation's home -> `done` -> token revoked, process exited, lock released, run directory removed.

**Failure flows.** Cancel (client close) or gateway stop or kill ends every sandbox process (`--die-with-parent`, and the PID namespace ends every child). A restart resumes an admitted conversation from its home. A start fault is refused with the permanent or the transient isolation text, never retried, and nothing runs unsandboxed. The run deadline aborts the run, discards its answer and saves nothing to the conversation.

**Conversation lifecycle.** `POST /v1/query` with a `sessionId`: new conversation under the caller's label -> owner and `sandboxDirId` recorded, home `<AGENT_SANDBOX_ROOT>/sessions/<sandboxDirId>/home` and work area `.../work` created on first use; later requests by the same owner reuse the work area and the runtime's own transcript (the home root is rebuilt at each start); a request by another `user_id` of the label or for a pre-update conversation is refused before anything is touched (another label with the same id gets its own new conversation). Deleting a conversation removes its entry only (home and work area stay until MVP-7402 defines retention). The global `memory` directory is the workspace's `memory/`, written only through `PUT /v1/memory/*` and mounted read-only into every sandbox, so no conversation can write it; the per-run directory under `runs/` is removed when the request ends.

**Container profile.** One container, running as `node`: `cap_drop: ALL`, `no-new-privileges`, `pids_limit`, a committed seccomp profile, `systempaths=unconfined` (needed for the sandbox's fresh `/proc`) and an AppArmor profile (committed, loaded by the operator) or none. Host prerequisite: unprivileged user namespaces allowed. The Docker socket is never mounted and no port is added.

**Known residuals.** The sandbox shares the network namespace (agent code can reach network peers, credential-free MCP servers and the gateway's public port, where it gets 401 without a key); there is no agent-side ssh mediation (no caller uses it); registry ownership covers `PUT` and `DELETE` only (`/restart` stays callable by any label; any label's run or direct call may use another label's owned server with its own users' credentials; `GET /v1/mcp-servers` still returns every server's stored shared headers and env values to every label, MVP-7936; a deleted name can be registered by another label); content planted before the deploy is hidden by the scan as verbatim copies only (files up to 64 MiB, `$HOME/.ssh` key lines and webhook URL credentials, MVP-7919; transformed copies and the per-user skills bundle are not covered), and the gateway-side trusted `git` and `/v1/auth/login` still read configuration planted in `/home/node` (owned by MVP-7948, not fixed; MVP-7679 closed the sandbox-side git reads); legacy ownerless webhook tools keep today's forwarding until registered again; the per-tool grant of a credential-free request server is not enforced on the trusted side; global agents, skills and commands are trusted content whose frontmatter hooks and agent `mcpServers` execute commands: an agent cannot write them, but any API-key holder can through `PUT /v1/agents` and `PUT /v1/skills` (reachable by callers, not by agent code);  conversation homes and work areas are never removed (MVP-7402), have no size cap, and `pids_limit` is shared; a file the agent writes in its home is rebuilt away only at the next start, so a process of the same run can still read it (no trusted step does); an ownerless pre-update id stays visible.

## Security Acceptance Model (MVP-7677)

The acceptance suite shows that the isolation holds in the deployed process shape and that permitted work still works. It has one harness (`src/tests/helpers/security-matrix.ts`, no vitest import, so the Docker probe imports its compiled copy) and four parts.

- **Marker classes.** Every credential in a test is a synthetic marker with a random suffix per run: gateway keys (one per label), provider key and OAuth tokens, MCP and webhook credentials (registry header, per-user override, SSE header, stdio env and args, request-body header and env), repository credentials (ssh key, token clone URL), a second session's private content, a legacy transcript and a state file. Scanners inside a sandbox use split needles (two halves), so a script's own text never holds a marker whole.
- **Surfaces.** Five observation surfaces per row: raw tool outputs, full model-bound request bodies (recorded by the scripted model double before it answers), NDJSON events (including replay), the gateway log, and the conversation's own transcripts, `/work`, home and per-run leftovers. Every surface has a byte floor, so an empty capture cannot pass; `detect()` returns `surface:marker` names only and no failure message embeds a value.
- **Modes.** The eight secret routes run fresh, resumed (turn 2 of a conversation) and restarted (SIGTERM, a new process on the same directories, once in a conversation created before the restart and once in a new one). Every route run carries the request-scoped credentials live (a per-user override, a request-body http server, a request-body stdio server) and the doubles confirm they received their own credential in that run; the process and session routes run beside concurrent conversations (another label, the same label with another user, a stdio tool sandbox, a slow trusted git clone) whose overlap is proved from the host. Each in-sandbox probe reports the exit status of every sub-command, has a positive control (a split-needle canary the scanner must find) and writes large dumps to `/work` so the file, not a truncated tool result, is scanned.
- **Negative controls.** A child vitest run of the same row against a deliberately vulnerable copy of `dist/` (a gateway that also passes `API_KEYS` into the sandbox; a launcher that binds the credential file), offline in a loopback-only network namespace, must exit nonzero, name the row, report hits and print no marker value. They are the proof that a green row can fail.
- **Failure boundaries.** The seven injected failures each confirm from the fixture that the run reached the named boundary before the failure (a recording `AGENT_SANDBOX_BWRAP` wrapper for startup and the policy check, the tagged child and the model's recorded tool call for cancel and restart, the relay's audit line for credential, timeout and unavailability failures, the audit count for the legacy refusal). A process sampler asserts that no agent runtime ran without a `bwrap` ancestor, because a runtime outside the sandbox would not reach the model double. On a gateway restart the caller's failure signal is the stream ending without a `done` event (the stream contract is unchanged).
- **Integration gate.** `npm run probe:epic-integration` builds the image and runs one task-owned container under the committed compose profile on a task-owned `--internal` network, in OAuth mode (one refresh against a local token endpoint), with representative reqlift and diemcrm callers, the same route probes, a direct MCP call, upload relay rows (progressing and stalled), a legacy refusal with reqlift's delete-and-replay, and `docker restart`. Every double binds to the bridge's gateway address, every docker command is name-guarded, and the evidence JSON records the revision and the image digest.
- **Evidence lines.** `SECURITY-EVIDENCE`, `SECURITY-MATRIX` (one per row, stable AC row id, `expected= observed= result=`) and `SECURITY-SUMMARY` (expected rows, observed rows, missing ids). Row ids are listed in `AC_ROWS`. Known open and not claimed: MVP-7948 (gateway-side git and login reading a planted home), MVP-7936 (registry read by every label), MVP-7866 (client close during a hook or in-process tool call), the runtime's own credential-free calls to its vendor host, and a copy of a credential value that was rotated before the run (the known-value scan compares current values).

## Tool Trust Boundary (MVP-7679)

Every tool call that needs a credential leaves the agent sandbox through a trusted channel bound to the run; the identity and the credential come from the trusted side, never from a field the agent sends.

**Grant layers.** (1) `AGENT_TOOL_POLICY` for the caller's API-key label (`tool-grant.ts`); (2) the caller's narrowing, `enforcedTools` (exact set) or `allowedTools` (names and `mcp__<server>__*`), which can only make the grant smaller; (3) built-in tools are enforced by what the runtime is offered (`tools`, `disallowedTools`), so a built-in outside the grant is refused by the runtime itself (`<tool_use_error>Error: No such tool available: <name></tool_use_error>`) for the main agent, a configured agent, a skill, a sub-agent and a resumed conversation, even under the permission-bypass mode; (4) a tool that is offered but not granted (a tool of an attached MCP server) is refused at call time on the trusted side with the `TOOL_DENIED` text, before any upstream request; (5) a server with no granted tool is not attached. `allowedToolsPattern` of a registry server is not part of the grant. When `enforcedTools` names a tool the policy denies, the request is accepted, the `tool_policy` acknowledgment echoes the requested set, `tool.policy.narrowed queryId=<id> denied=<names>` is audited, and the tool is refused at call time.

**Binding kinds.** One relay token per run and server; the runtime sees only `http://127.0.0.1:<port>/mcp/<token>`.

| Binding | Upstream | Token and grant | Deadline | Revoke |
|---------|----------|-----------------|----------|--------|
| http (registered; request with `headers`) | Registered URL with the merged headers | Token per run and server; the relay checks the grant and the method rules before any upstream request | 120 s no progress, `AGENT_MCP_TOOL_TIMEOUT_MS` (default 600 s) per `tools/call` | Run end or cancel |
| sse (registered; request with `headers`) | `mcp-bridge.ts`: SSE stream opened with the run's headers, `endpoint` event only on the registered origin | Same | Same | Run end or cancel; stream closed |
| stdio (registered; overrides; request with `env`) | `mcp-stdio-sandbox.ts`: own tool sandbox, one JSON message per line | Same | Same | Run end, cancel or gateway stop (`--die-with-parent`) |
| webhook tools | In-process server `agent-gateway-tools`, `webhook.ts` | Closure of the run; grant and owner checked before the request | Per-tool `timeout_ms` (default 30 s) | Run end |

**Tool sandbox.** A stdio server never runs next to the agent. It runs in its own bubblewrap sandbox (own user, PID, IPC, UTS and cgroup namespaces, a private empty home and `/tmp`, read-only system directories only, no gateway content), with the environment `HOME`, `USER`, `PATH`, `LANG`, `LC_*`, `TERM`, `TMPDIR` plus the server's own env after overrides (never the model proxy token or URL or the run-log path). It starts with the run's first message within `ISOLATION_STARTUP_TIMEOUT_MS`, restarts once if it dies before answering `initialize`, is killed on revoke, cancel or gateway stop, and its stderr is discarded. It sees only `/usr` and the system directories, so its command must live there.

**Data flow.**

```
POST /v1/query (label from the API key)
    |  grant = policy(label) ∩ caller narrowing
    v
runQuery: offered built-ins (tools/disallowedTools), attached servers (only those with a granted tool),
          relay bindings (token, upstream or bridge, merged credentials, grant), webhook tools of the label
    v
runtime (sandbox) --- tools/call mcp__<server>__<tool> ---> relay 127.0.0.1:<q>/mcp/<token>
    |   refused locally, zero upstream requests: not strict UTF-8 JSON, batch, no `method`,
    |   method or tool name outside the grant (TOOL_DENIED)
    v
upstream: http | SSE bridge | stdio tool sandbox   (credentials added here, never in the runtime)
    |   deadline AGENT_MCP_TOOL_TIMEOUT_MS; answer buffered (25 MiB) and validated
    v
one JSON message to the runtime, or a fixed TOOL_* text
    v
tool_result event (success:false on an error) -> NDJSON stream and event cache (label, queryId)
```

**Failure texts.** `tool-mediation.ts` owns the contract: `ToolRequest { runId, callId, toolId, input }` and `ToolReply` (ok with output, or an error with one of `TOOL_DENIED`, `TOOL_AUTH_UNAVAILABLE`, `TOOL_UNAVAILABLE`, `TOOL_TIMEOUT`, `TOOL_RESPONSE_INVALID` and its fixed text). A webhook, relay or bridge failure always maps to a fixed text, never an upstream body. A tool's own answer is not a mediation failure (an MCP `isError` result passes through; a webhook 4xx other than 401/403/408/429 reaches the model as `The tool rejected the request (HTTP <status>): <message>`).

## Tool Surfaces: Webhook Registry vs MCP Server Registry

Two distinct extension points feed tools into every Claude query. Both are merged into the SDK's `mcpServers` map, but they target different integration patterns:

|                       | Tool Registry (`/v1/tools`)                                   | MCP Server Registry (`/v1/mcp-servers`)                              |
|-----------------------|---------------------------------------------------------------|----------------------------------------------------------------------|
| **Primary use case**  | Expose a custom HTTP integration as a single tool             | Embed an existing MCP server (Jira, Confluence, custom)              |
| **Transport**         | HTTP `POST` to `webhook_url`                                  | MCP protocol — `http`, `sse`, or `stdio`                             |
| **Tool schema**       | Provided by the registrar (`input_schema` JSON Schema)        | Discovered by the agent on connect (`tools/list`)                    |
| **Auth**              | The owning client's Bearer token forwarded; webhook context body | Per-server `headers` (http/sse) or `env` (stdio), held in the relay binding; per-request override possible |
| **Allowlist**         | A run is offered its own label's tools plus legacy ownerless ones, subject to the grant | Subject to the grant; `allowedToolsPattern` only pre-approves (no authorization effect) |
| **Owner**             | `owner` = registering label                                   | None (any label can change a registration)                            |
| **Per-user creds**    | Caller provides via headers / context                         | `userCredentialSchema` + `mcpCredentialOverrides` request field      |
| **State**             | In-process per query (factory)                                | Relay binding per run; `restart` forces fresh handshake              |

## Webhook Tool Execution Flow

When the agent invokes a registered webhook tool during a query:

```
Agent SDK calls tool "my-tool" with input
    |
    v
SDK MCP server validates input against the converted input_schema
(tool-input-schema.ts); a violation returns isError to the agent, no webhook call
    |
    v
MCP server handler (tool-server.ts)
    |
    v
executeWebhook() POSTs to webhook_url:
{
  tool_use_id, tool_name, input,
  context: { user_id, conversation_id, session_id, api_key_label }
}
+ Authorization: Bearer <client-token>   (only for tools the calling label owns)
    |
    v
External service processes request
    |
    v
Returns { output: "result text", metadata?: {...} }
    |
    v
MCP server returns result to Agent SDK
    |
    v
Agent continues with tool result
```

Timeouts are configurable per tool (default 30s). The call never follows a redirect and answers over 8 MiB are refused. On failure (timeout, 5xx, network error, auth refusal, redirect, invalid answer), an error result with one of the fixed `TOOL_*` texts is returned to the agent, which can decide to retry or use an alternative approach; a 4xx that is the tool's own refusal reaches the model as `The tool rejected the request (HTTP <status>): <message>`.

## External MCP Server Flow (with overrides)

```
POST /v1/query { mcpCredentialOverrides: { jira: { headers: {...} } } }
    |
    v
mcp-overrides.validate() -- ensures every overridden name is registered + enabled,
target matches transport. Failures return 400 (MCP_SERVER_NOT_FOUND /
MCP_SERVER_DISABLED / MCP_OVERRIDE_INVALID).
    |
    v
buildMcpServersForSdk() merges static registry config with overrides:
  - http/sse: shallow-merge `headers` (override wins per key)
  - stdio:   shallow-merge `env`     (override wins per key)
    |
    v
Agent SDK opens one MCP transport per server, always to the credential relay URL (no headers, args or env):
  - http:    the relay adds the merged headers (one case-insensitive merge, the per-user value replaces the shared one)
  - sse:     the relay's SSE bridge opens the stream with the merged headers
  - stdio:   the relay's bridge talks MCP over stdin/stdout to a server started with the merged env in its own tool sandbox
    |
    v
Agent calls discovered tools (the relay refuses anything outside the grant)
    |
    v
Query completes -> overrides discarded; static registry config unchanged on disk
```

`POST /v1/mcp-servers/:name/test` runs the same merge logic out-of-band so the operator can validate a credential set before persisting it. The test client accepts both `application/json` and streamable `text/event-stream` MCP responses (MVP-3689).

## Credential Relay Flow

Every registered MCP server (http, SSE and stdio) is reached only through the gateway's credential relay (MVP-7667, extended by MVP-7679). The runtime never holds their URL, `args`, `env` or credential, so an upstream refusal cannot start the runtime's MCP OAuth login and no credential reaches its command line or log files.

```
runQuery (agent.ts)
    | credentialRelay.register({ serverName, upstream | bridge, merged headers or env, grant }) -> http://127.0.0.1:<port>/mcp/<token>
    v
Claude runtime (SDK child)  -- POST/DELETE http://127.0.0.1:<port>/mcp/<token>, no credential
    v
relay listener (127.0.0.1, own node:http server)
    | Host must be 127.0.0.1:<port>; only the exact /mcp/<token> path; anything else (/.well-known/*, /register,
    | /authorize, /token, sub-paths, unknown or revoked token) -> local 404, never forwarded; GET -> 405
    | body: strict UTF-8 JSON only (no BOM or other encoding), no batch, a `method` on every message, up to 25 MiB;
    |   anything else is refused locally; only the re-serialized parsed message is forwarded (content-type: application/json)
    | methods: initialize, ping, tools/list and notifications/initialized|cancelled|progress|roots/list_changed pass;
    |   tools/call only with params.name exactly in the grant; resources/*, prompts/*, completion/* and anything else
    |   only when the grant covers the whole server (mcp__<server>__*); every refusal -> TOOL_DENIED, zero upstream requests
    | credential schema with header/env outputs and no value in the run: tools/call -> TOOL_AUTH_UNAVAILABLE ("no credential")
    |   before any upstream request (the handshake still goes upstream)
    v
upstream (http: registered url | sse: bridge | stdio: tool sandbox bridge)
    | http request headers: Accept, Content-Type, Mcp-Session-Id, Mcp-Protocol-Version, Last-Event-ID + bound headers
    |   (a runtime Authorization or Cookie is dropped); redirects are never followed
    | the answer is buffered and validated (JSON-RPC, JSON or event stream, at most 25 MiB) and returned as ONE JSON message;
    |   only Content-Type and Mcp-Session-Id go back to the runtime
    | 404 on a request with Mcp-Session-Id: a bodiless 404 (session miss)
    | failures map to the fixed texts: 401/403 -> TOOL_AUTH_UNAVAILABLE (user or gateway credential); 3xx, 5xx, 429, 408, connect
    |   errors -> TOOL_UNAVAILABLE; idle > 120 s or > AGENT_MCP_TOOL_TIMEOUT_MS -> TOOL_TIMEOUT; invalid or oversized 2xx -> TOOL_RESPONSE_INVALID
    |   tools/call -> HTTP 200 JSON-RPC result isError:true with the fixed text; initialize / list -> HTTP 200 JSON-RPC error
    |   (the server contributes no tools); notifications -> 202; DELETE -> 204; no upstream body is echoed
    v
run ends (answer, error, abort) -> credentialRelay.revoke(token): the URL answers 404 on every method, requests still uploading are closed, in-flight upstream requests destroyed, the bridge is closed (the stdio tool sandbox is killed); nothing more is sent upstream
```

**SSE bridge** (`mcp-bridge.ts`). Opens the stream with the run's headers and accepts the `endpoint` event only on the registered origin (otherwise the redirect text; the credential is never sent elsewhere). It answers server requests locally (`ping` with `{}`, `roots/list` with no roots, others method-not-found) and drops server notifications.

**Stdio bridge** (`mcp-stdio-sandbox.ts`). Every registered stdio server (with or without env), stdio overrides and request stdio servers with env run in their own tool sandbox (see [Tool Trust Boundary](#tool-trust-boundary-mvp-7679)); the bridge writes one JSON message per line to stdin and reads one per line from stdout. For stdio the gateway can observe only `TOOL_DENIED`, `TOOL_UNAVAILABLE` (failed to start or exited), `TOOL_TIMEOUT` and `TOOL_RESPONSE_INVALID`; a stdio server's own authentication failure is its tool-level `isError` result.

**Header merge.** One case-insensitive merge for the relay, the SSE bridge, the direct call and the test: the per-user value replaces the shared header of the same name in any casing. There is no broader-credential fallback and no OAuth login; no redirect is followed anywhere (webhook, relay, SSE bridge, direct call, test, health).

If the relay is not listening, registered servers (and request servers with headers or env) are left out of the run (`mcp.server.omitted serverName=<name> reason=relay_unavailable`), and a request-supplied server may not take a registered name (HTTP 400 `MCP_SERVER_NAME_CONFLICT`). Every handler is wrapped so that a relay error answers with a fixed text and never ends the gateway process. Audit lines carry the server name and reason only; the URL, path and token are never logged.

Observed with Claude Code 2.0.77: after a session-miss 404 the runtime does not initialize a new session; it reports that tool call as failed, as it does with a direct connection.

Not covered: request servers without `headers`/`env` (per-query servers such as chrome-devtools) connect directly or run inside the agent sandbox and are granted per server only; callers must pass credentials for request servers only through `env` or `headers`, never in `args` or `url`, because the agent can read those. The `mcp.server.credential_in_runtime_args` audit line no longer exists. The upload relay (`mcp-upload-relay.ts`) is unchanged.

## Upload Relay Flow

`POST /v1/mcp-servers/:name/uploads/<target>?<query>` streams a raw file to a registered http/sse MCP server (SC-5 of MVP-7560; reqlift → gateway → mcp-jira → Jira).

```
Client (reqlift)
    | POST /v1/mcp-servers/jira/uploads/jira/issue/MVP-1?filename=shot.png
    | Authorization: Bearer <key>, X-MCP-Credential-Headers: base64(JSON), <raw bytes>
    v
body parsers ------- skipped: the raw-path rule (mcp-upload-relay.ts) matches the
    |                  upload path case-insensitively, also in absolute form
request logging ---- logs method + URL (target and file name), never the body
uploadConnectionGuard  Connection: close; bounded drain after any early answer
authMiddleware ----- 401 as on every /v1/* route
    v
routes/mcp.ts ------ unknown / disabled (/call codes) -> stdio (MCP_UPLOAD_UNSUPPORTED)
    |                -> X-MCP-Credential-Headers (MCP_OVERRIDE_INVALID)
    |                -> target path (UPLOAD_TARGET_INVALID); nothing is sent before
    v
UploadRelay -------- node:http(s) request to <origin>/uploads/<target>?<query>
    |                  (fresh connection, never pooled, never retried)
    |  each sender chunk: write upstream, drop it, yield to the event loop
    |    (setImmediate; after drain when upstream is full) so an early answer
    |    is normally read before the next write
    |  a write that fails because the MCP server reset the connection first
    |    (EPIPE/ECONNRESET, no answer yet): stop forwarding, keep reading for
    |    at most ANSWER_AFTER_RESET_MS (1 s) for an answer that already arrived
    |  every 2 MiB: minor GC (gc-budget.ts, needs --expose-gc)
    |  idle timer: reset by every request chunk and every answer chunk
    v
MCP server answer -> status (200-599) + Content-Type + Content-Length + body, verbatim
```

**What is and is not held:** at any time only the chunks in flight (Node stream buffers and kernel socket buffers) are in memory; nothing is written to disk and nothing enters the session store, the transcript or the event cache. The request log line carries the URL, i.e. target and file name, never bytes or the credential. One audit line per relay: `mcp.upload.relayed serverName status bytes result`.

**Exits:**

- The MCP server answers after the whole body: its answer is streamed back and the relay ends (`ok` for 2xx, `upstream_answer` otherwise).
- The MCP server answers early (while the body still streams): forwarding stops, the answer is passed through, and the sender connection is closed after a bounded drain (at most 1 MiB read, closed when the sender closes or 5 s after the answer). This also holds when the MCP server resets the connection right after its answer (mcp-jira closes with unread body data) and the reset reaches the gateway before the answer was read: the failed write does not destroy the socket at once. Forwarding stops, the socket keeps reading for at most `ANSWER_AFTER_RESET_MS`, and the answer is passed through. Node marks a socket's readable side errored when a write fails, so `keepReadingAfterWriteReset` wraps the socket's `destroy()` and clears `_readableState.errored`; if that is not possible, the socket is destroyed at once (502 unconfirmed).
- Connection refused, DNS failure, bad registration url or an invalid registered header value: `502 UPLOAD_UPSTREAM_FAILED`, nothing sent.
- The MCP server answers with a status outside 200–599 (Node's client accepts any three digits; `writeHead` would throw below 100, which would end the process) or with headers `writeHead` refuses: the answer is discarded, the upstream request destroyed, and the sender gets `502 UPLOAD_UPSTREAM_FAILED`, outcome unconfirmed.
- The upstream connection drops before an answer: `502 UPLOAD_UPSTREAM_FAILED`, outcome unconfirmed (after a failed write, as soon as the next read reports the reset, at the latest `ANSWER_AFTER_RESET_MS` later; a 1xx is not an answer). It drops after the answer's status line: the sender connection is destroyed (the status can no longer change).
- No progress for `MCP_UPLOAD_IDLE_TIMEOUT_MS`: the upstream request is aborted and the sender gets `504 UPLOAD_TIMEOUT` (unconfirmed wording when the whole body was already sent), or the connection is destroyed if the answer had started.
- The sender disconnects: the upstream request is destroyed at once, before the multipart trailer, so mcp-jira stores nothing.

**Timers:** the relay's idle timer (default 60 s) is the only per-upload bound; Node's `requestTimeout` is raised to 3600 s on the listen handle so it does not cut a slow upload, while `nonUploadBodyDeadline` keeps a 300 s bound on every other request body until its response is sent (it clears with the response, so after an early answer the rest of that body is no longer bounded by it). mcp-jira's own no-progress timer (120 s) and `requestTimeout` (3600 s) sit behind it.

## State Files, Recovery and Shutdown

**Files:** `sessions.json` (sessions and the idle-timeout setting), `tools.json` and `mcp-servers.json` under `/home/node/.claude/` in the container (`./agent_home/.claude/` on the host). `mcp-servers.json` is the only copy of the MCP server registry.

**Saving:** every save writes a complete temp file next to the target and renames it over the target, so a kill, crash or `ENOSPC` leaves either the complete old file or the complete new one. A failed save keeps the previous file, logs an ERROR line and reports `write-failed` until a later save of that area succeeds.

**Loading:**

| File state at start | Result | `/health` |
|---------------------|--------|-----------|
| missing | empty area | no issue |
| valid | loaded | no issue |
| read error other than "not found", invalid JSON or wrong top-level shape | moved to `<file>.corrupt-<UTC stamp>` (bytes unchanged), empty area | `corrupt-preserved` while any `<file>.corrupt-*` exists |
| as above, and the move fails | file untouched, saves for the area suppressed until a restart loads it | `unreadable-not-preserved` |

**ERROR line** (via `console.error`, independent of the log level; never file content or error messages):

```
ERROR persistence area=<sessions|tools|mcpServers> problem=<corrupt-preserved|unreadable-not-preserved|write-failed|final-save-failed> file=<path> [preservedAs=<path>] reason=<fixed text> [code=<errno>] (see /health)
```

**Shutdown sequence:**

```
SIGTERM/SIGINT ──> server.close() (no new connections; idle ones closed)
               ──> save all areas now (early save)
               ──> drain: received requests and streams run on, changes saved as usual
               ──> last connection closed | 8 s deadline | second signal
               ──> destroy remaining sockets, save all areas synchronously
               ──> exit 0 (all saved) | exit 1 (a save failed or was suppressed)
```

In the image `tini` is process 1 and forwards the signal, so the container exit code is the gateway's. Exit `137` (Docker's SIGKILL after 10 s) remains possible while a synchronous git command blocks the event loop (MVP-7614): the files stay intact, but debounced changes pending at that moment can be lost.

**Recovering a `.corrupt-*` copy:** stop the gateway first (its next save would overwrite a restored file); repair the copy (it is usually damaged, or it holds an entry the gateway cannot restore: `null`, a tool or MCP server without a string `name`, a session without a numeric `lastUsed`) and copy it over `<file>`, which replaces changes made in that area since detection; restore `node:node` ownership (uid 1000) and the original mode (a copy kept after a read error has its original permissions); move the copy out of the directory or delete it, which alone clears `degraded`; confirm with `curl -s http://localhost:3001/health | jq .persistence`. Copies of `mcp-servers.json` contain MCP credentials: handle them as secrets and never attach state files or copies to tickets or evidence.

## Security Model

- **API Key Auth**: All authenticated routes require a valid Bearer token from `API_KEYS`.
- **Path Traversal Protection**: `safePath()` (workspace) and `resolveProjectPath()` (git) prevent directory escape via `../`, absolute paths, null bytes, and symlink resolution.
- **SSH Key Validation**: Filename restricted to `[a-zA-Z0-9_-]` to prevent injection. Inline keys for the git routes are written, only once the request holds a git slot, to a private per-request temp directory (`0700`, key file created exclusively with `0600`) and removed in `finally`; the key path is quoted inside `GIT_SSH_COMMAND`.
- **Git Arguments and Credentials**: git runs without a shell, with `--` before clone and fetch positionals, an explicit fetch refspec, leading-dash branches rejected and the `ext::` transport disabled. Error text and git log lines carry no user-info credentials of `http(s)://` URLs, whatever characters the token contains (on each line everything from the first `scheme://` to the last `@` is hidden; query-string tokens are not redacted). `ssh://`, `git://` and `file://` transports do not use URL passwords, and ssh/git may echo such a URL's user-info without `scheme://` or `@` (e.g. `Could not resolve hostname user:<password>`), which the redaction cannot recognize, and the debug log redacts `sshKey` values and, in every string under a `url` key, everything from `scheme://` to the last `@`.
- **Agent Isolation (MVP-7678)**: every agent run executes in a bubblewrap sandbox with an allowlisted view, an allowlisted environment and a per-run model proxy token as its only provider credential; conversations are keyed by API-key label and belong to one exact owner, run one request at a time, and pre-update conversations are refused. See "Agent Isolation".
- **Tool trust boundary (MVP-7679)**: the effective grant is `AGENT_TOOL_POLICY` for the caller's label intersected with the caller's narrowing; credential-bearing MCP servers (http, SSE, stdio) are reached only through relay bindings and never put a credential into the runtime's configuration; the grant check runs before any upstream request; failures map to fixed `TOOL_*` texts. Registered webhook tools record an owner, and the caller's key is forwarded only to its own label's tools. See "Tool Trust Boundary".
- **Tool Permissions**: the Claude SDK runs with `bypassPermissions` (enforced runs: `dontAsk`), so the gateway never relies on permission prompts: tools are limited by what the runtime is offered and by the trusted grant. Without a policy and without `allowedTools`/`enforcedTools` the grant is everything a run gets by default.
- **MCP Tool Allowlist**: `allowedToolsPattern` per registered MCP server only adds that server's tools to the pre-approved `allowedTools` list. It is not part of the grant and has no authorization effect.
- **Enforced tool set (MVP-7637)**: a caller that sends `enforcedTools` gets a run in which every tool outside the set is refused before its handler runs (`src/tool-policy.ts`). The layers: `settingSources: []` (nothing from the writable HOME — settings, hooks, permission rules, `.mcp.json`, user-scope MCP servers — applies), `permissionMode: "dontAsk"` with `allowedTools` exactly the set (the primary deny: an unlisted tool is denied, not asked for), `tools` limited to the listed built-ins, `agent-gateway-tools` and registry/request MCP servers attached only for listed tools (further narrowed by the trusted policy), a `PreToolUse` hook that denies every other name with the `TOOL_DENIED` text (it never answers "allow", because under `dontAsk` an allow would override the mode, and any internal error denies; it is the `tool.denied` audit point), and no per-user skill bundle. The query route validates the field (400) and emits a `tool_policy` event echoing the set before any other event and before the retry loop. Measured on SDK 0.1.77 with the real runtime (`src/tests/tool-policy-process.test.ts`): the refusal holds with a HOME seeded like `entrypoint.sh`, with a hostile HOME (hooks disabled, allow rules, an allow hook, a parent `.mcp.json`, user-scope servers), with the hook throwing and with the hook never deciding.
- **Credential Boundaries**: `userCredentialSchema` enforces transport-appropriate output targets (`SCHEMA_TARGET_MISMATCH`); per-request overrides are never written back to `MCP_SERVERS_PERSIST_PATH`; test-client errors are sanitized so header/env values do not leak in error messages; no registry `args`/`env`, override or request `env` value and no header reaches the runtime's command line; `/call` refuses a user-credential server without a credential before any upstream request.
- **Token Expiry Surfacing**: `/v1/auth/status` exposes `tokenExpired` + `expiresAt` so clients can warn users before queries fail with auth errors.
- **Docker Isolation**: Container runs as the `node` user from the start (`user: node`, no root step), SSH keys, sessions, tools, and MCP server definitions persist on a named volume.
- **State File Protection**: temp files are created with `O_EXCL` and mode 0600 (no symlink follow, never more readable than the owner while credentials are written); `.corrupt-*` copies keep the original bytes and permissions; ERROR lines and `/health` carry only area, problem, paths, a fixed reason and the errno.
- **Localhost Binding**: Docker compose binds port 3001 to `127.0.0.1` only -- requires a reverse proxy for external access.
- **Upload Relay**: target path and query come from the raw URL with dot segments, encoded slashes and backslashes refused; upstream host and port come only from the registry. Only `Authorization` is taken from `X-MCP-Credential-Headers`, which is never forwarded or logged; hop-by-hop headers never come from an override or a registration. Refusals on the upload path close the connection after at most 1 MiB / 5 s, so a caller without a key cannot make the gateway read a large body. The gateway enforces no size or concurrency cap of its own (reqlift's 100 MiB cap applies to reqlift callers; other key holders are bounded by the MCP server).
