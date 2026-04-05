# CLAUDE.md -- Agent Gateway

## Project Overview

Standalone REST API service wrapping the Claude Agent SDK. Exposes Claude Code's agentic capabilities (Bash, Read, Write, Edit, Glob, Grep, WebSearch, WebFetch) over HTTP with NDJSON streaming, session management, and automatic retry with exponential backoff.

**Tech stack**: Node.js 22, TypeScript, Express 5, Claude Agent SDK, Docker

## Development Commands

```bash
npm run build       # TypeScript compile (tsc)
npm run dev         # Dev server with hot-reload (tsx watch)
npm start           # Production start (node dist/server.js)
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
| `TOOLS_PERSIST_PATH` | No | `./data/tools.json` | File path for tool registry persistence (Docker override: `/home/node/.claude/tools.json`) |

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
  retry.ts           # Exponential backoff retry (rate limits, empty responses)
  event-cache.ts     # In-memory NDJSON event cache with TTL
  workspace.ts       # File CRUD for memory/agents/skills directories
  logging.ts         # Runtime-adjustable log levels
  tools.ts           # Tool registry CRUD + persistence (TOOLS_PERSIST_PATH)
  webhook.ts         # Webhook executor (POST to tool webhook_url with context)
  tool-server.ts     # MCP server factory (wraps registered tools for Agent SDK)
  routes/
    ssh.ts           # POST /v1/ssh-keys
    auth.ts          # Anthropic OAuth flow (login, submit-code, status)
    workspace.ts     # CRUD for /v1/memory/*, /v1/agents/*, /v1/skills/*
    tools.ts         # PUT/GET/DELETE /v1/tools (Tool Registry REST endpoints)
  tests/
    e2e-session.test.ts    # E2E session continuity tests
    routes.tools.test.ts   # Tool routes unit tests
    tool-server.test.ts    # MCP server factory tests
    tools.test.ts          # Tool registry unit tests
    webhook.test.ts        # Webhook executor tests
Dockerfile           # Node 22 + system tools + Claude Code CLI
docker-compose.yml   # Single-service compose with volume
entrypoint.sh        # Root setup, SSH key restore, drop to node user
```
