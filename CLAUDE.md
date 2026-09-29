# CLAUDE.md -- Agent Gateway

## Project Overview

Standalone REST API service wrapping the Claude Agent SDK. Exposes Claude Code's agentic capabilities (Bash, Read, Write, Edit, Glob, Grep, WebSearch, WebFetch, Skill, TodoWrite) over HTTP with NDJSON streaming, session management, and automatic retry with exponential backoff.

**Tech stack**: Node.js 22, TypeScript, Express 5, Claude Agent SDK, Docker

## Development Commands

```bash
npm run build       # TypeScript compile (tsc)
npm run dev         # Dev server with hot-reload (tsx watch)
npm start           # Production start (node --expose-gc dist/server.js)
npm test            # Unit tests (vitest, excludes E2E)
npm run test:e2e    # E2E session tests (requires running Gateway + GATEWAY_API_KEY env var)
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | No* | -- | Anthropic API key (*or use OAuth via POST /v1/auth/login) |
| `API_KEYS` | Yes | `default:changeme` | Comma-separated `label:key` pairs for client auth |
| `PORT` | No | `3001` | HTTP listen port |
| `HOST` | No | `0.0.0.0` | Bind address |
| `LOG_LEVEL` | No | `info` | `off`, `info`, or `debug` |
| `SESSION_IDLE_TIMEOUT_MS` | No | `0` (disabled) | Auto-cleanup idle sessions after N ms |
| `SESSION_PERSIST_PATH` | No | `./data/sessions.json` | File path for session persistence (Docker override: `/home/node/.claude/sessions.json`) |
| `EVENT_CACHE_TTL_MS` | No | `1800000` (30 min) | TTL for completed query event caches |
| `WORKSPACE_ROOT` | No | `$HOME/.claude` | Root for memory/agents/skills workspace |
| `USER_SKILLS_MAX_COUNT` | No | `50` | Max per-user skills loaded per query; excess dropped (path-sorted) → `skills_truncated` |
| `USER_SKILLS_MAX_BYTES` | No | `1048576` | Max total per-user SKILL.md bytes loaded per query; overflow → `skills_truncated` |
| `TOOLS_PERSIST_PATH` | No | `./data/tools.json` | File path for tool registry persistence (Docker override: `/home/node/.claude/tools.json`) |
| `MCP_SERVERS_PERSIST_PATH` | No | `./data/mcp-servers.json` | File path for MCP server registry persistence (Docker override: `/home/node/.claude/mcp-servers.json`) |
| `MCP_TEST_TIMEOUT_MS` | No | `10000` | Per-test deadline for `POST /v1/mcp-servers/:name/test` (in ms) |
| `MCP_CALL_TIMEOUT_MS` | No | `10000` | Per-call deadline for `POST /v1/mcp-servers/:name/call` (in ms) |
| `MCP_UPLOAD_IDLE_TIMEOUT_MS` | No | `60000` | No-progress timeout for one relayed upload (`POST /v1/mcp-servers/:name/uploads/*`), in ms; 504 `UPLOAD_TIMEOUT` on expiry, no overall deadline |
| `GIT_MAX_CONCURRENCY` | No | `3` | Git operations of `/v1/workspace/git/*` that run at the same time across all repositories; further requests wait in arrival order, none is rejected |
| `GIT_TIMEOUT_MS` | No | `120000` | Deadline for one git command of `/v1/workspace/git/*`, in ms; on expiry the command's process group is stopped and the request answers 500 `git <subcommand> timed out after <n> s` |

## API Key Format

```
API_KEYS=label1:secret1,label2:secret2
```

Keys are sent as `Authorization: Bearer <secret>`. The label is used for audit logging.

## Docker

```bash
docker compose up -d --build     # Build and run
docker compose logs -f           # Follow logs
docker compose down              # Stop
```

Port `3001` binds to `127.0.0.1` only (reverse proxy expected).

## Git Conventions

- **Branch format**: `feature/<JIRA-KEY>-short-description`
- **Commit format**: `<JIRA-KEY>: <description>`
- **PR title**: `<JIRA-KEY>: <Epic/Story title>`

## Documentation Update Rule

**Every code change that affects API endpoints, configuration, or architecture MUST update the corresponding documentation in the same commit or PR.** This includes:

- New or changed endpoints: update `README.md` API table + `docs/index.html` API reference (including tool registry routes)
- New environment variables: update `CLAUDE.md` env table + `.env.example` + `docs/index.html`
- New event types: update `docs/index.html` NDJSON Event Reference
- Architecture changes: update `docs/architecture.md` + `docs/index.html` architecture diagram
- Docker changes: update `README.md` deployment section + `docs/index.html` deployment guide

## Project Structure

```
src/
  server.ts          # Express app, health/logging/session/settings routes
  auth.ts            # API key middleware (Bearer token)
  query.ts           # POST /v1/query, GET /v1/query/:queryId/events
  agent.ts           # Claude Agent SDK wrapper, event emission, MCP server injection
  sessions.ts        # Session CRUD, persistence, idle cleanup, SDK session ID sync
  retry.ts           # Exponential backoff retry (transient failures, empty responses); resumes only established sessions
  run-failure.ts     # Classifies a failed run (runtime stdout diagnostic, thrown error) into a safe public error message + safe log fields
  event-cache.ts     # In-memory NDJSON event cache with TTL
  workspace.ts       # File CRUD for memory/agents/skills directories
  logging.ts         # Runtime-adjustable log levels
  tools.ts           # Tool registry CRUD + persistence (TOOLS_PERSIST_PATH)
  webhook.ts         # Webhook executor (POST to tool webhook_url with context)
  tool-server.ts     # MCP server factory (wraps registered tools for Agent SDK)
  tool-policy.ts     # enforcedTools: request validation, built-in/server selection, deny-only PreToolUse hook (per-run enforced tool set)
  tool-input-schema.ts # Webhook tool input_schema -> typed, described SDK shape; per-property "any value" fallback, per-tool untyped fallback
  mcp-registry.ts    # External MCP server registry CRUD + persistence (MCP_SERVERS_PERSIST_PATH)
  mcp-upload-relay.ts # Streaming upload relay: raw-path rule, parser skip, pre-auth guard, X-MCP-Credential-Headers, relay core
  mcp-credential-relay.ts # Loopback relay for registered http MCP servers: per-run token, header allowlists, refusal answers (no OAuth login in the runtime)
  sdk-run-logs.ts    # Per-run directory for the Claude runtime's log files, deleted after the child exits; startup sweep; DEBUG_CLAUDE_AGENT_SDK strip
  mcp-overrides.ts   # mcpCredentialOverrides validation, header/env checks, requireUserCredentials attachment rule (headers output keys case-insensitive, every match non-empty; env keys exact)
  gc-budget.ts       # Minor GC every 2 MiB relayed (needs node --expose-gc, set in entrypoint.sh and npm start)
  git-exec.ts        # Non-blocking git runner (no shell, process-group timeout, redacted error text) + per-repository and global FIFO queues
  routes/
    ssh.ts           # POST /v1/ssh-keys
    auth.ts          # Anthropic OAuth flow (login, submit-code, status)
    workspace.ts     # CRUD for /v1/memory/*, /v1/agents/*, /v1/skills/*
    git.ts           # POST /v1/workspace/git/clone|pull, GET /v1/workspace/git/status
    tools.ts         # PUT/GET/DELETE /v1/tools (Tool Registry REST endpoints)
    mcp.ts           # PUT/GET/DELETE /v1/mcp-servers + /restart + /health + /test + /call (MCP Server Registry; PUT refuses a NEW name outside ^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$ with 400 MCP_SERVER_NAME_INVALID, existing names stay editable/deletable; /call = direct LLM-free tools/call passthrough, gates on enabled unlike /test; /uploads/* = streaming upload relay)
  tests/
    e2e-session.test.ts    # E2E session continuity tests
    routes.tools.test.ts   # Tool routes unit tests
    tool-server.test.ts    # MCP server factory tests
    tool-input-schema.test.ts # Webhook tool schemas via JSON-RPC tools/list + tools/call (advertised types, rejection, fallback, depth, prototype names)
    webhook-tool-schema-process.test.ts # Real-runtime probe: model-facing webhook tool schemas + pre-dispatch rejection, reqlift/diemcrm fixtures (needs `npm run build`)
    tools.test.ts          # Tool registry unit tests
    webhook.test.ts        # Webhook executor tests
    sdk-login-guard-process.test.ts # Real-runtime probe: spawned gateway, OAuth-capable MCP stub, scripted Anthropic API (needs `npm run build`)
    run-failure.test.ts             # Failure classifier table: kinds, exact messages, version bounds, hostile inputs
    tool-policy.test.ts             # enforcedTools validation table + the hook never allows
    query-enforced-tools-outcome.test.ts # enforcedTools through query/agent/retry with the SDK mocked: options layers, tool_policy first and once, unchanged options without it
    tool-policy-process.test.ts     # Real-runtime probe: refused webhook/MCP/Bash/WebFetch calls reach no handler; hostile HOME, faulty hook, retry, [] (needs `npm run build`)
    query-failure-outcome.test.ts   # Failed runs through query/agent/retry with the SDK mocked: one error event, no done, retry and resume rules
    query-failure-diagnostics-process.test.ts # Real-runtime probe: provider rejections reach the client as safe messages, sessions after a failed first request (needs `npm run build`)
    mcp-credential-relay.test.ts    # Credential relay unit tests
    mcp-overrides.test.ts           # Override merge + requireUserCredentials header-key casing
    routes.mcp.test.ts              # Registry PUT schema validation + new-entry name rule
    require-user-credentials.test.ts # requireUserCredentials + header/env validation
    credential-redaction-rows.test.ts # Debug-log redaction for every credential entry point
    git-exec.test.ts                # Git runner and queue unit tests
    git-routes-contract.test.ts     # Git endpoint contract, queue, injection rows (fake git on PATH)
    git-nonblocking-process.test.ts # Spawned gateway stays responsive during slow git (needs `npm run build`)
    git-credential-logs-process.test.ts # No http(s) URL token or SSH key in git error text or logs at info/debug (needs `npm run build`)
  __tests__/
    git.test.ts            # Workspace git endpoints tests
Dockerfile           # Node 22 + system tools + Claude Code CLI
docker-compose.yml   # Single-service compose with volume
entrypoint.sh        # Root setup, SSH key restore, drop to node user
```
