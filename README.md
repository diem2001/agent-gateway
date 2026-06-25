# Agent Gateway

Standalone REST API service that wraps the [Claude Agent SDK](https://docs.anthropic.com/en/docs/claude-agent-sdk) and exposes agentic capabilities over HTTP. Designed for integration into web applications, CI pipelines, or any system that needs to run Claude agents programmatically.

## Quick Start

```bash
cp .env.example .env
# Edit .env: set API_KEYS (gateway auth) and choose an Anthropic auth method below

docker compose up -d --build
```

The gateway is now running at `http://localhost:3001`. Verify with:

```bash
curl http://localhost:3001/health
```

### Anthropic Authentication

The Agent Gateway needs Anthropic credentials to run Claude agents. Two methods:

**Option A: OAuth (recommended)** — Interactive login via Claude CLI. No API key needed.

```bash
# 1. Start the OAuth flow
curl -X POST http://localhost:3001/v1/auth/login \
  -H "Authorization: Bearer YOUR_API_KEY"

# 2. Open the returned URL in your browser, authorize, copy the code

# 3. Submit the code (include the full code with # and state)
curl -X POST http://localhost:3001/v1/auth/submit-code \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"code": "code#state"}'

# 4. Verify
curl http://localhost:3001/v1/auth/status \
  -H "Authorization: Bearer YOUR_API_KEY"
```

OAuth credentials persist in the `./agent_home` bind-mount. Re-authentication only needed if the token expires.

**Option B: API Key (optional)** — Only if you explicitly need direct API access instead of a subscription. Do NOT set this by default — it overrides OAuth and uses pay-per-token billing.

```env
# Only uncomment if you have a specific reason to use API credits instead of subscription:
# ANTHROPIC_API_KEY=sk-ant-...
```

> **Warning:** If `ANTHROPIC_API_KEY` is set (even empty), Claude Code will prefer it over OAuth and fail with "Credit balance is too low" when the API account has no credits. Remove the variable entirely to use the subscription.

## API Overview

All endpoints except `/health` require `Authorization: Bearer <api-key>`.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check (no auth) |
| `POST` | `/v1/query` | Run an agent query (NDJSON stream) |
| `GET` | `/v1/query/:queryId/events` | Replay/resume event stream |
| `GET` | `/v1/sessions` | List active sessions |
| `DELETE` | `/v1/sessions/:id` | Delete a session |
| `GET` | `/v1/settings` | Get session settings |
| `PUT` | `/v1/settings` | Update session settings |
| `GET` | `/v1/logging` | Get current log level |
| `PUT` | `/v1/logging` | Set log level |
| `POST` | `/v1/ssh-keys` | Upload SSH keys |
| `GET` | `/v1/auth/status` | Check Anthropic auth status |
| `POST` | `/v1/auth/login` | Start Anthropic OAuth flow |
| `POST` | `/v1/auth/submit-code` | Submit OAuth authorization code |
| `GET` | `/v1/memory` | List memory files |
| `GET` | `/v1/memory/*` | Read a memory file |
| `PUT` | `/v1/memory/*` | Write a memory file |
| `DELETE` | `/v1/memory/*` | Delete a memory file |
| `GET` | `/v1/agents` | List agent files |
| `GET` | `/v1/agents/*` | Read an agent file |
| `PUT` | `/v1/agents/*` | Write an agent file |
| `DELETE` | `/v1/agents/*` | Delete an agent file |
| `GET` | `/v1/skills` | List skill files |
| `GET` | `/v1/skills/*` | Read a skill file |
| `PUT` | `/v1/skills/*` | Write a skill file |
| `DELETE` | `/v1/skills/*` | Delete a skill file |
| `GET` | `/v1/users/{user_id}/skills` | List a user's per-user skills (reconcile; `{ files: [...] }`) |
| `PUT` | `/v1/users/{user_id}/skills/*` | Write a user-namespaced skill file (body = SKILL.md) |
| `DELETE` | `/v1/users/{user_id}/skills/*` | Delete a user-namespaced skill file |
| `GET` | `/v1/knowledge-base` | List knowledge-base files (read-only) |
| `GET` | `/v1/knowledge-base/*` | Read a knowledge-base file as `text/markdown` (read-only) |
| `PUT` | `/v1/tools/:name` | Register/update a webhook tool |
| `GET` | `/v1/tools` | List all registered tools |
| `GET` | `/v1/tools/:name` | Get a single tool |
| `DELETE` | `/v1/tools/:name` | Delete a tool |
| `PUT` | `/v1/mcp-servers/:name` | Register/update an external MCP server |
| `GET` | `/v1/mcp-servers` | List all registered MCP servers |
| `GET` | `/v1/mcp-servers/:name` | Get a single MCP server |
| `DELETE` | `/v1/mcp-servers/:name` | Unregister an MCP server |
| `POST` | `/v1/mcp-servers/:name/restart` | Force the SDK to reconnect to the MCP server on next query |
| `POST` | `/v1/mcp-servers/:name/test` | Test merged MCP credentials with `tools/list` |
| `GET` | `/v1/mcp-servers/:name/health` | Health check for a registered MCP server |
| `POST` | `/v1/workspace/git/clone` | Clone a repository into the workspace |
| `POST` | `/v1/workspace/git/pull` | Pull updates for a workspace repository |
| `GET` | `/v1/workspace/git/status` | Get git status for a workspace repository |

## Query Request Body

`POST /v1/query` accepts a JSON body. The core fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `queryId` | string | yes | Client-generated id used for the NDJSON event cache and replay |
| `prompt` | string | no\* | Plain-text prompt |
| `content` | `ContentBlock[]` | no\* | Multimodal content array (text + images) |
| `sessionId` | string | no | Resume an existing session |
| `systemPrompt` | string | no | Appended to the Claude Code preset system prompt |
| `model` | string | no | Model id |
| `allowedTools` | string[] | no | Override the default tool set |

\* Provide **either** `prompt` **or** `content`. If both are present, `content` takes precedence. If neither is present, the request is rejected with HTTP 400.

### Multimodal Content (`content[]`)

Send text and images in a single query by passing a `content` array of content blocks. The array maps directly to the Anthropic API content-block format and is forwarded to the Claude Agent SDK as a structured user message — image blocks are passed through to Anthropic **unmodified**.

```typescript
type ContentBlock =
  | { type: "text"; text: string }
  | { type: "image"; source: { type: "base64"; media_type: string; data: string } };
```

Rules:

- If `content` is a non-empty array, it takes precedence over `prompt`.
- If only `prompt` is provided (the backward-compatible path), it is wrapped internally as `[{ "type": "text", "text": prompt }]` — existing text-only queries are unchanged.
- Each block is structurally validated; a malformed block (e.g. missing `source.data`, non-`base64` `source.type`, unknown `type`) returns HTTP 400 before the stream opens.
- The NDJSON event stream is identical in shape for multimodal and text-only queries.

The JSON request body limit is **25 MB** to accommodate base64-encoded images. A body that exceeds the limit is rejected with HTTP **413**. (Per-image size and per-query image-count limits are enforced upstream by the caller, not by the gateway.)

```bash
curl -N -X POST http://localhost:3001/v1/query \
  -H "Authorization: Bearer sk-abc123" \
  -H "Content-Type: application/json" \
  -d '{
    "queryId": "q-multimodal-1",
    "content": [
      { "type": "text", "text": "What is shown in this screenshot?" },
      {
        "type": "image",
        "source": {
          "type": "base64",
          "media_type": "image/png",
          "data": "<base64-encoded-image-bytes>"
        }
      }
    ]
  }'
```

## Authentication

API keys are configured via the `API_KEYS` environment variable:

```bash
API_KEYS=myapp:sk-abc123,cicd:sk-def456
```

Each entry is `label:secret`. The label appears in server logs for audit purposes. Send the secret as a Bearer token:

```bash
curl -H "Authorization: Bearer sk-abc123" http://localhost:3001/v1/sessions
```

## Configuration

See [`.env.example`](.env.example) for all environment variables. Key settings:

| Variable | Default | Description |
|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | -- | Anthropic API key (or use OAuth via `/v1/auth/login`) |
| `API_KEYS` | `default:changeme` | Client authentication keys |
| `PORT` | `3001` | HTTP listen port |
| `HOST` | `0.0.0.0` | Bind address |
| `LOG_LEVEL` | `info` | `off`, `info`, or `debug` |
| `SESSION_IDLE_TIMEOUT_MS` | `0` | Auto-expire idle sessions (0 = disabled) |
| `SESSION_PERSIST_PATH` | `./data/sessions.json` | Session persistence file (Docker: `/home/node/.claude/sessions.json`) |
| `EVENT_CACHE_TTL_MS` | `1800000` | Query event cache TTL in ms (30 min) |
| `WORKSPACE_ROOT` | `$HOME/.claude` | Root dir for memory/agents/skills |
| `TOOLS_PERSIST_PATH` | `./data/tools.json` | Tool registry storage (Docker: `/home/node/.claude/tools.json`) |
| `MCP_SERVERS_PERSIST_PATH` | `./data/mcp-servers.json` | MCP server registry storage (Docker: `/home/node/.claude/mcp-servers.json`) |
| `MCP_TEST_TIMEOUT_MS` | `10000` | Per-test deadline for `POST /v1/mcp-servers/:name/test` |

## Development Setup

```bash
# Prerequisites: Node.js >= 22
npm install
cp .env.example .env
# Edit .env with your ANTHROPIC_API_KEY

npm run dev    # Starts with hot-reload via tsx
```

Build for production:

```bash
npm run build
npm start
```

### Testing

```bash
npm test            # Unit tests (vitest, excludes E2E)
npm run test:e2e    # E2E session tests (requires running Gateway + GATEWAY_API_KEY env var)
```

## Architecture

```
Client (HTTP)
    |
    v
Express Server (auth middleware)
    |
    +-- POST /v1/query -----> Agent (Claude SDK) ----> Built-in Tools (Bash, Read, ...)
    |                              |                |
    |                              |                +-> Registered Tools (webhook MCP servers)
    |                              |                |         |
    |                              |                |         +-> POST webhook_url
    |                              |                |
    |                              |                +-> External MCP Servers (http/sse/stdio)
    |                         NDJSON stream                   |
    |                              |                          +-> connect/spawn per query
    +-- GET /v1/query/:id/events   (replay from event cache)
    |
    +-- /v1/sessions, /v1/settings, /v1/logging
    |
    +-- /v1/ssh-keys, /v1/auth/*
    |
    +-- /v1/memory/*, /v1/agents/*, /v1/skills/*
    |
    +-- /v1/workspace/git/* (clone, pull, status)
    |
    +-- /v1/tools (Tool Registry CRUD)
    |
    +-- /v1/mcp-servers (External MCP Server Registry CRUD + restart + health)
```

### Tool Registry + Webhook Execution

External tools can be registered via the `/v1/tools` endpoints. Each tool defines a `webhook_url` that is called when the agent invokes the tool. Registered tools are wrapped as in-process MCP servers and injected into the Claude Agent SDK alongside the built-in tools.

When the agent calls a registered tool, the gateway POSTs to the webhook URL with:

```json
{
  "tool_use_id": "tu_abc",
  "tool_name": "my-tool",
  "input": { "param": "value" },
  "context": {
    "user_id": null,
    "conversation_id": null,
    "session_id": "session-1",
    "api_key_label": "myapp"
  }
}
```

The client's Bearer token is forwarded to webhook calls for authentication. Tools persist to disk at `TOOLS_PERSIST_PATH` and survive server restarts.

### External MCP Server Registry

In addition to webhook-based tools, the gateway can register full external MCP servers via `/v1/mcp-servers`. Unlike the Tool Registry (which wraps custom webhooks as tools), this feature embeds existing MCP servers into every Claude query so the agent can call their tools directly over the MCP protocol.

|                    | Tool Registry (`/v1/tools`)              | MCP Server Registry (`/v1/mcp-servers`)        |
|--------------------|------------------------------------------|------------------------------------------------|
| **Purpose**        | Expose custom integrations as tools      | Embed existing MCP servers                     |
| **Transport**      | HTTP POST to `webhook_url`               | MCP protocol: `http` / `sse` / `stdio`         |
| **Tool schema**    | Defined by the registrar                 | Discovered from the MCP server itself          |
| **Auth**           | Client's Bearer token forwarded          | Per-server `headers` / `env`                   |

Register the production Jira HTTP MCP server with per-user Basic auth outputs:

```bash
curl -X PUT http://localhost:3001/v1/mcp-servers/jira \
  -H "Authorization: Bearer sk-abc123" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "http",
    "url": "http://mcp-jira:3002/mcp",
    "headers": {},
    "description": "Atlassian Jira MCP server (HTTP transport at http://mcp-jira:3002/mcp)",
    "allowedToolsPattern": "mcp__jira__*",
    "enabled": true,
    "userCredentialSchema": {
      "fields": [
        { "key": "email", "label": "Atlassian Email", "type": "email", "required": true },
        {
          "key": "apiToken",
          "label": "API Token",
          "type": "password",
          "required": true,
          "description": "Generate at https://id.atlassian.com/manage-profile/security/api-tokens"
        }
      ],
      "outputs": [
        { "target": "headers", "outputKey": "Authorization", "template": "basic:{email}:{apiToken}" }
      ]
    }
  }'
```

Register an illustrative stdio MCP server (spawned by the gateway per query) with per-user env output:

```bash
curl -X PUT http://localhost:3001/v1/mcp-servers/stdio-example \
  -H "Authorization: Bearer sk-abc123" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "stdio",
    "command": "node",
    "args": ["./some-mcp/dist/index.js"],
    "env": {},
    "allowedToolsPattern": "mcp__stdio-example__*",
    "userCredentialSchema": {
      "fields": [
        {
          "key": "token",
          "label": "Personal Access Token",
          "type": "password",
          "required": true,
          "description": "Generate at the provider token settings page"
        }
      ],
      "outputs": [
        { "target": "env", "outputKey": "EXAMPLE_TOKEN", "template": "{token}" }
      ]
    }
  }'
```

Payload fields:

| Field | Required | Description |
|-------|----------|-------------|
| `type` | yes | `"http"`, `"sse"`, or `"stdio"` |
| `url` | http/sse | Endpoint URL of the MCP server |
| `headers` | no | Extra headers for http/sse requests |
| `command` | stdio | Executable to spawn |
| `args` | no | CLI args for stdio command |
| `env` | no | Environment variables for stdio command |
| `description` | no | Human-readable description |
| `enabled` | no | Defaults to `true` |
| `allowedToolsPattern` | no | Glob restricting which MCP tools the agent may call (e.g. `mcp__jira__*`) |
| `userCredentialSchema` | no | Per-user credential fields and output templates for `headers` or `env` overrides |

`userCredentialSchema.fields[]` defines the form that clients render for a user's credential wallet. Field `type` must be one of `text`, `password`, `url`, or `email`; `key` values must be unique. `userCredentialSchema.outputs[]` defines how those field values are composed at query time. HTTP/SSE servers may only emit `target: "headers"` outputs, and stdio servers may only emit `target: "env"` outputs. Mismatches are rejected with `SCHEMA_TARGET_MISMATCH`.

Output templates support plain substitution (`"{fieldKey}"`, `"prefix-{a}-{b}"`) and HTTP Basic auth (`"basic:{email}:{apiToken}"`, emitted as `Basic <base64(email:apiToken)>`). The composer is transport-agnostic; the registry PUT validation enforces the transport-to-target rule before definitions are persisted.

Registered MCP servers persist to `MCP_SERVERS_PERSIST_PATH` and are merged into `options.mcpServers` on every `/v1/query` call. The SDK connects (http/sse) or spawns (stdio) per query; use `POST /v1/mcp-servers/:name/restart` to force a fresh connection.

Per-request MCP credential overrides can be attached to `POST /v1/query` without changing the existing request contract:

```json
{
  "queryId": "q-001",
  "prompt": "Create the Jira issue",
  "mcpCredentialOverrides": {
    "jira": {
      "headers": { "Authorization": "Basic <base64(email:apiToken)>" }
    },
    "stdio-example": {
      "env": { "EXAMPLE_TOKEN": "user-token" }
    }
  }
}
```

Override server names must already exist and be enabled in the registry. Unknown names return `MCP_SERVER_NOT_FOUND`; disabled names return `MCP_SERVER_DISABLED`. For http/sse transports, `headers` are shallow-merged over the static registry config. For stdio transports, `env` is shallow-merged. Overrides are request-scoped only and never write back to `MCP_SERVERS_PERSIST_PATH`.

Use `POST /v1/mcp-servers/:name/test` to validate a credential set before saving or enabling it:

```bash
curl -X POST http://localhost:3001/v1/mcp-servers/jira/test \
  -H "Authorization: Bearer sk-abc123" \
  -H "Content-Type: application/json" \
  -d '{ "headers": { "Authorization": "Basic <base64(email:apiToken)>" } }'
```

Success returns `{ "ok": true, "toolCount": 2, "tools": [{ "name": "..." }] }`. Unknown servers return `MCP_SERVER_NOT_FOUND`, upstream 401/403 returns `MCP_AUTH_FAILED`, transport failures return `MCP_NETWORK_ERROR`, and timeouts return `MCP_TIMEOUT`. Error messages are sanitized and do not echo header or env values.

For detailed architecture, see [`docs/architecture.md`](docs/architecture.md).

Full API reference with curl examples: [`docs/index.html`](docs/index.html) or [Agent Gateway Wiki](https://code1.diemit.net/wiki/internal/agent-gateway.html).

## License

Private -- DiemIT GmbH
