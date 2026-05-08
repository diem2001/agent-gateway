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
Entry point. Configures middleware (JSON parsing, request logging, auth), mounts all routers, and exposes health, logging, session, and settings endpoints directly.

### auth.ts -- API Key Middleware
Parses `API_KEYS` env var at startup into a `Map<key, label>` for O(1) lookup. Validates `Authorization: Bearer <key>` on all routes except `/health`. Attaches `clientLabel` to the request for audit logging.

### query.ts -- Query Endpoint
- **POST /v1/query**: Accepts a prompt, optional system prompt, model, session ID, tool restrictions, and `mcpCredentialOverrides`. Creates an event cache entry, runs the query through the retry layer, and streams NDJSON events as they occur. Returns `Content-Type: application/x-ndjson`.
- **GET /v1/query/:queryId/events**: Replays cached events for a completed or in-progress query. Supports `?after=<seq>` for resuming from a specific sequence number. For in-progress queries, keeps the connection open and streams new events in real time.

The `mcpCredentialOverrides` field carries per-request `headers` (http/sse) or `env` (stdio) values keyed by registered MCP server name. Overrides are validated up-front (`mcp-overrides.ts`), shallow-merged over the static registry config when the SDK builds its `mcpServers` map, and discarded after the query completes — they are never persisted.

### agent.ts -- Claude SDK Wrapper
Calls `query()` from `@anthropic-ai/claude-agent-sdk` with configured tools, permissions, and the merged `mcpServers` map. Translates SDK message types (assistant text, tool_use, tool_result, system status, rate limits) into typed stream events emitted via the `onEvent` callback.

Default tools: `Bash`, `Read`, `Write`, `Edit`, `Glob`, `Grep`, `WebSearch`, `WebFetch`.

If registered webhook tools exist, they are wrapped as in-process MCP servers via `createToolMcpServer()` and injected into the SDK query alongside the built-in tools. The webhook context (user_id, session_id, api_key_label) and the client's Bearer token are passed to each webhook call. External MCP servers from the MCP Server Registry are merged into the same `mcpServers` map (per-server credentials applied), so the agent can call their tools directly over the MCP protocol.

### sessions.ts -- Session Management
Maps client-provided session IDs to internal Claude SDK session IDs. Sessions are:
- **Created** on first query with a given sessionId
- **Reused** when the same sessionId, systemPrompt, and model match
- **Replaced** when systemPrompt or model changes (new Claude session, same client ID)
- **Synced** via `updateSessionSdkId()` after each query -- the SDK may return a different session_id than the one provided, so the gateway updates the stored mapping to ensure subsequent queries resume the correct conversation
- **Persisted** to disk (debounced) at `SESSION_PERSIST_PATH`
- **Restored** from disk on startup (expired sessions filtered out)
- **Cleaned** every 5 minutes if `SESSION_IDLE_TIMEOUT_MS > 0`

Session continuity uses two SDK options:
- **New sessions**: pass `sessionId` to start a fresh conversation
- **Existing sessions**: pass `resume` with the stored SDK session ID to continue the conversation with full context

### retry.ts -- Retry with Exponential Backoff
Wraps `runQuery` with up to 3 retries. Retries on:
- Rate limit errors (429, "overloaded", "throttled")
- Empty or whitespace-only responses

Uses exponential backoff (1s, 2s, 4s) with a 60-second total budget. Emits `rate_limited` events so clients can show retry status. Respects `AbortController` for cancellation.

### event-cache.ts -- Event Cache
Stores NDJSON events in memory keyed by `queryId`. Used by `GET /v1/query/:queryId/events` for replay and real-time streaming. Entries are marked "done" when the query completes. A background timer (every 60s) garbage-collects entries older than `EVENT_CACHE_TTL_MS` (default 30 minutes).

### workspace.ts -- File Operations
Provides safe file CRUD for three workspace sections: `memory`, `agents`, `skills`. All paths are resolved relative to `WORKSPACE_ROOT` (default `$HOME/.claude`). Includes path traversal protection via `safePath()` which validates against directory escape, absolute paths, null bytes, and symlink attacks.

### logging.ts -- Runtime Logging
Three levels: `off`, `info`, `debug`. Level is adjustable at runtime via `PUT /v1/logging`. Request/response logging middleware logs method, URL, status code, and duration (body content only at debug level).

### routes/ssh.ts -- SSH Key Management
**POST /v1/ssh-keys**: Uploads an SSH private key (and optional public key) to `~/.ssh/`. Derives the public key from private if not provided. Writes an SSH config with `StrictHostKeyChecking accept-new`. Validates filename to prevent path injection.

### routes/auth.ts -- Anthropic OAuth
Three-step flow using tmux to interact with Claude CLI:
1. **POST /v1/auth/login**: Starts Claude CLI in a tmux session, captures the OAuth authorization URL.
2. **POST /v1/auth/submit-code**: Sends the authorization code to the tmux session, polls for login success.
3. **GET /v1/auth/status**: Checks if Claude CLI reports a valid login. The response is augmented with `expiresAt` (epoch ms from `~/.claude.json` `claudeAiOauth.expiresAt`) and `tokenExpired` (boolean, `Date.now() > expiresAt`) so clients can warn users before queries start failing with auth errors.

### routes/git.ts -- Workspace Git Endpoints
Lets clients clone and refresh git repositories inside `WORKSPACE_ROOT/projects/<path>` so agents can `Read`/`Grep` real source trees as part of their context:
- **POST /v1/workspace/git/clone**: Clones `url` into `path`, optionally on a specific `branch`. If the target already has a `.git` directory, falls back to `git pull` after aligning the checkout with `branch`. Accepts an inline `sshKey` body field for one-shot clones; the key is written to a temp file, used via `GIT_SSH_COMMAND`, and removed in `finally`.
- **POST /v1/workspace/git/pull**: Pulls updates for an existing repo. Returns `up-to-date` or `updated` based on commit-before / commit-after comparison.
- **GET /v1/workspace/git/status?path=...**: Returns `branch`, `commit`, `dirty`, `lastCommitDate` for the repo at `path`.

All paths are resolved through `resolveProjectPath()` which rejects absolute paths and `..` traversal.

### tools.ts -- Tool Registry
Manages CRUD operations for webhook-backed tool definitions. Tools are stored in-memory in a `Map<name, ToolDefinition>` and persisted to disk (debounced) at `TOOLS_PERSIST_PATH` (default `./data/tools.json`, Docker override: `/home/node/.claude/tools.json`). Each tool definition includes: `name`, `description`, `input_schema` (JSON Schema), `webhook_url`, and optional `timeout_ms` (default 30s). Tools are loaded from disk on startup via `loadTools()`.

### webhook.ts -- Webhook Executor
Executes tool calls by POSTing to the tool's `webhook_url`. The request body contains `tool_use_id`, `tool_name`, `input`, and `context` (user_id, conversation_id, session_id, api_key_label). The client's Bearer token is forwarded in the `Authorization` header. Supports configurable timeouts per tool. Returns either `WebhookResponse` (with output + optional metadata) or `WebhookError` on failure (timeout, HTTP error, network error).

### tool-server.ts -- MCP Server Factory (webhook tools)
Creates an in-process MCP server wrapping all registered webhook tools for injection into the Claude Agent SDK. Called once per query so the webhook context (session, user, auth) is correctly scoped. Each tool's JSON Schema properties are mapped to `z.unknown()` Zod shapes -- actual validation is the webhook's responsibility. Uses `createSdkMcpServer()` from the Agent SDK.

### routes/tools.ts -- Tool Registry Endpoints
REST endpoints for webhook tool management:
- **PUT /v1/tools/:name**: Register or update a tool (validates description, input_schema, webhook_url)
- **GET /v1/tools**: List all registered tools
- **GET /v1/tools/:name**: Get a single tool definition
- **DELETE /v1/tools/:name**: Remove a tool

### routes/workspace.ts -- Workspace CRUD
Generates GET/PUT/DELETE routes for each workspace section (`memory`, `agents`, `skills`). GET on the section root lists all files. GET/PUT/DELETE on sub-paths reads/writes/deletes individual files.

### mcp-registry.ts -- External MCP Server Registry
Registry for *external* MCP servers — distinct from the webhook Tool Registry. Each entry describes an existing MCP server (`type`: `http`, `sse`, or `stdio`) plus optional per-server credential schema. Definitions are kept in a `Map<name, McpServerDefinition>` and persisted to `MCP_SERVERS_PERSIST_PATH` (default `./data/mcp-servers.json`, Docker override `/home/node/.claude/mcp-servers.json`).

`buildMcpServersForSdk()` produces the `mcpServers` map handed to the Agent SDK on every query: HTTP/SSE servers contribute `{type, url, headers}`; stdio servers contribute `{type, command, args, env}`. Disabled servers (`enabled: false`) are skipped. Per-server `allowedToolsPattern` globs (e.g. `mcp__jira__*`) are aggregated into the SDK's `allowedTools` filter so the agent can only call the tools the operator explicitly opted in to.

`userCredentialSchema` lets the registry advertise the form a user has to fill in to derive credentials at query time. `fields[]` declares form input definitions (`text`, `password`, `url`, `email`); `outputs[]` declares how those values compose into either `headers` (http/sse) or `env` (stdio) targets via plain substitution (`"{key}"`) or HTTP Basic encoding (`"basic:{email}:{apiToken}"`). Transport-target mismatches are rejected with `SCHEMA_TARGET_MISMATCH` at registration time.

### mcp-overrides.ts -- Per-Request Credential Overrides
Validates the `mcpCredentialOverrides` body field on `POST /v1/query` against the current registry. Each override entry references a registered server by name; unknown names return `MCP_SERVER_NOT_FOUND`, disabled names return `MCP_SERVER_DISABLED`. HTTP/SSE servers may only carry `headers`; stdio servers may only carry `env`. Validated overrides are shallow-merged over the static registry config when the SDK invocation is built. Overrides are request-scoped only — they never write back to disk.

### credential-composer.ts -- Credential Template Substitution
Lightweight template engine used both by the MCP registry's `userCredentialSchema.outputs[]` validation and by future per-user credential composition. Supports plain field substitution (`"{fieldKey}"`, `"prefix-{a}-{b}"`) and HTTP Basic auth shorthand (`"basic:{email}:{apiToken}"`, emitted as `Basic <base64(email:apiToken)>`). `getCredentialTemplateFieldKeys(template)` returns the set of `{...}` placeholders so the registry can reject templates that reference fields not declared in the same schema.

### mcp-test-client.ts -- MCP Credential Test Client
Implements `POST /v1/mcp-servers/:name/test` — given a registered server name and an override payload (`headers` for http/sse, `env` for stdio), the gateway connects to the upstream MCP server, calls `tools/list`, and returns `{ ok: true, toolCount, tools[] }`. The client accepts both plain `application/json` and streamable `text/event-stream` MCP responses (MVP-3689) so providers that emit one-shot SSE responses for HTTP requests are supported. Auth failures (401/403) surface as `MCP_AUTH_FAILED`, transport problems as `MCP_NETWORK_ERROR`, and the per-test deadline as `MCP_TIMEOUT` (configurable via `MCP_TEST_TIMEOUT_MS`, default 10s).

### routes/mcp.ts -- MCP Server Registry Endpoints
REST endpoints for the external MCP server registry:
- **PUT /v1/mcp-servers/:name**: Register or update a server (validates transport, fields, output targets, template references)
- **GET /v1/mcp-servers**: List all registered servers
- **GET /v1/mcp-servers/:name**: Get a single server definition
- **DELETE /v1/mcp-servers/:name**: Remove a server
- **POST /v1/mcp-servers/:name/test**: Probe `tools/list` with optional override credentials, returning the discovered tool list or a typed error
- **POST /v1/mcp-servers/:name/restart**: Bumps the server's `updatedAt` so the SDK reconnects (http/sse) or respawns (stdio) on the next query
- **GET /v1/mcp-servers/:name/health**: Cheap connectivity probe (no `tools/list`) — returns `{ ok, latencyMs, error? }`

## Data Flow: Query Request

1. Client sends `POST /v1/query` with `queryId`, `prompt`, optional `sessionId`, optional `mcpCredentialOverrides`
2. Auth middleware validates Bearer token
3. `validateMcpCredentialOverrides()` confirms every overridden server is registered + enabled and that the override targets match transport (`headers` for http/sse, `env` for stdio)
4. Event cache entry created for `queryId`
5. Session resolved: existing session reused (with `resume`) or new one created (with `sessionId`)
6. Registered webhook tools are wrapped as in-process MCP servers via `createToolMcpServer()`. External MCP servers are pulled from `mcp-registry.ts`, merged with per-request overrides, and added to the same `mcpServers` map handed to the SDK
7. `runQueryWithRetry` calls `runQuery` (agent.ts)
8. Agent SDK streams messages; `agent.ts` translates to events:
   - `text` -- assistant text chunks
   - `tool_use` -- tool invocation (name, input summary)
   - `tool_result` -- tool output (truncated to 3000 chars)
   - `rate_limited` -- rate limit detected, retrying
   - `sdk_status` -- SDK status changes (compacting)
   - `sdk_compact_complete` -- context compaction completed
9. For registered webhook tools, the in-process MCP server handler POSTs to the webhook URL and returns the result. For external MCP servers, the SDK speaks MCP directly to the upstream service over the configured transport
10. Events are written to response stream (NDJSON) and cached
11. On completion, `done` event emitted with token usage, cost, context stats; SDK session ID synced via `updateSessionSdkId()`
12. On error, `error` event emitted with message
13. Event cache entry marked "done"; per-request overrides are dropped (never persisted)

## Session Lifecycle

```
Client sends sessionId="abc"
    |
    v
Session exists with same prompt + model?
    |                    |
   YES                  NO
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
    After query completes:
    updateSessionSdkId() syncs
    stored ID with SDK's actual
    session_id (snake_case field)
```

Sessions persist across server restarts via `SESSION_PERSIST_PATH`. The cleanup timer evicts sessions idle longer than `SESSION_IDLE_TIMEOUT_MS`.

## Tool Surfaces: Webhook Registry vs MCP Server Registry

Two distinct extension points feed tools into every Claude query. Both are merged into the SDK's `mcpServers` map, but they target different integration patterns:

|                       | Tool Registry (`/v1/tools`)                                   | MCP Server Registry (`/v1/mcp-servers`)                              |
|-----------------------|---------------------------------------------------------------|----------------------------------------------------------------------|
| **Primary use case**  | Expose a custom HTTP integration as a single tool             | Embed an existing MCP server (Jira, Confluence, custom)              |
| **Transport**         | HTTP `POST` to `webhook_url`                                  | MCP protocol — `http`, `sse`, or `stdio`                             |
| **Tool schema**       | Provided by the registrar (`input_schema` JSON Schema)        | Discovered by the agent on connect (`tools/list`)                    |
| **Auth**              | Client's Bearer token forwarded; webhook context body         | Per-server `headers` (http/sse) or `env` (stdio); per-request override possible |
| **Allowlist**         | All registered tools always exposed                           | `allowedToolsPattern` glob per server, aggregated into SDK filter    |
| **Per-user creds**    | Caller provides via headers / context                         | `userCredentialSchema` + `mcpCredentialOverrides` request field      |
| **State**             | In-process per query (factory)                                | Connected/spawned per query; `restart` forces fresh handshake        |

## Webhook Tool Execution Flow

When the agent invokes a registered webhook tool during a query:

```
Agent SDK calls tool "my-tool" with input
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
+ Authorization: Bearer <client-token>
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

Timeouts are configurable per tool (default 30s). On failure (timeout, HTTP error, network error), an error result is returned to the agent, which can decide to retry or use an alternative approach.

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
Agent SDK opens MCP transport per server:
  - http/sse: connects on first tool call, uses merged headers
  - stdio:   spawns command with merged env, talks MCP over stdin/stdout
    |
    v
Agent calls discovered tools (filtered through allowedToolsPattern)
    |
    v
Query completes -> overrides discarded; static registry config unchanged on disk
```

`POST /v1/mcp-servers/:name/test` runs the same merge logic out-of-band so the operator can validate a credential set before persisting it. The test client accepts both `application/json` and streamable `text/event-stream` MCP responses (MVP-3689).

## Security Model

- **API Key Auth**: All authenticated routes require a valid Bearer token from `API_KEYS`.
- **Path Traversal Protection**: `safePath()` (workspace) and `resolveProjectPath()` (git) prevent directory escape via `../`, absolute paths, null bytes, and symlink resolution.
- **SSH Key Validation**: Filename restricted to `[a-zA-Z0-9_-]` to prevent injection. Inline keys for git-clone are written to per-request temp files (`0600`) and removed in `finally`.
- **Tool Permissions**: Claude SDK runs with `bypassPermissions` -- the gateway trusts the SDK's tool execution.
- **MCP Tool Allowlist**: `allowedToolsPattern` per registered MCP server limits which tools the agent may call, even when an external MCP server advertises more.
- **Credential Boundaries**: `userCredentialSchema` enforces transport-appropriate output targets (`SCHEMA_TARGET_MISMATCH`); per-request overrides are never written back to `MCP_SERVERS_PERSIST_PATH`; test-client errors are sanitized so header/env values do not leak in error messages.
- **Token Expiry Surfacing**: `/v1/auth/status` exposes `tokenExpired` + `expiresAt` so clients can warn users before queries fail with auth errors.
- **Docker Isolation**: Container runs as `node` user (dropped from root via `gosu`), SSH keys, sessions, tools, and MCP server definitions persist on a named volume.
- **Localhost Binding**: Docker compose binds port 3001 to `127.0.0.1` only -- requires a reverse proxy for external access.
