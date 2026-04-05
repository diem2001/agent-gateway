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

**Option B: API Key** — Set `ANTHROPIC_API_KEY` in `.env`. Simpler but requires a paid API key.

```env
ANTHROPIC_API_KEY=sk-ant-...
```

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
| `PUT` | `/v1/tools/:name` | Register/update a webhook tool |
| `GET` | `/v1/tools` | List all registered tools |
| `GET` | `/v1/tools/:name` | Get a single tool |
| `DELETE` | `/v1/tools/:name` | Delete a tool |

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
| `LOG_LEVEL` | `info` | `off`, `info`, or `debug` |
| `SESSION_IDLE_TIMEOUT_MS` | `0` | Auto-expire idle sessions (0 = disabled) |
| `HOST` | `0.0.0.0` | Bind address |
| `TOOLS_PERSIST_PATH` | `./data/tools.json` | Tool registry storage path |

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
    |                         NDJSON stream               |
    |                              |                      +-> POST webhook_url
    +-- GET /v1/query/:id/events   (replay from event cache)
    |
    +-- /v1/sessions, /v1/settings, /v1/logging
    |
    +-- /v1/ssh-keys, /v1/auth/*
    |
    +-- /v1/memory/*, /v1/agents/*, /v1/skills/*
    |
    +-- /v1/tools (Tool Registry CRUD)
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

For detailed architecture, see [`docs/architecture.md`](docs/architecture.md).

Full API reference with curl examples: [`docs/index.html`](docs/index.html) or [Agent Gateway Wiki](https://code1.diemit.net/wiki/internal/agent-gateway.html).

## License

Private -- DiemIT GmbH
