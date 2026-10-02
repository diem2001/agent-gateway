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
npm run probe:docker-isolation  # Docker Outcome Probe: builds the image, runs task-owned containers under the compose security profile (needs sudo -n docker, uid 1000)
npm run probe:docker-stop       # Docker Outcome Probe for the clean stop (same profile)
npm run probe:epic-integration   # Epic Integration Gate (MVP-7677): task-owned container on an --internal network, OAuth mode, representative reqlift and diemcrm callers, the eight secret routes before and after docker restart (needs sudo -n docker, uid 1000; writes an evidence JSON with the image digest)
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
| `ISOLATION_STARTUP_TIMEOUT_MS` | No | `10000` | A sandbox must pass its start check within this many ms, otherwise it is killed and the run fails with the transient isolation text; an invalid value (non-numeric, 0, negative) stops startup |
| `AGENT_RUN_TIMEOUT_MS` | No | `7200000` | Deadline of one query request, retries and backoff included; expiry ends the run with the deadline text and saves nothing; an invalid value stops startup |
| `AGENT_MCP_TOOL_TIMEOUT_MS` | No | `600000` | Overall deadline of one mediated MCP `tools/call` in an agent run (http, SSE, stdio), in ms; empty = default; an invalid value stops startup (`FATAL config key=AGENT_MCP_TOOL_TIMEOUT_MS reason=must be a positive whole number of milliseconds`). The relay's 120 s no-progress timeout stays |
| `AGENT_TOOL_POLICY` | No | unset | Tool grant per API-key label, JSON `{"default":{allow?,deny?},"labels":{"<label>":{allow?,deny?}}}` of built-in names, `mcp__<server>__*` and `mcp__<server>__<tool>`; empty/unset = no restriction; an invalid value or a label not in `API_KEYS` stops startup (`FATAL config key=AGENT_TOOL_POLICY reason=<reason>`) |
| `MCP_SERVER_OWNERS` | No | unset | Deploy-step mapping `<server>:<label>,...` applied at startup: assigns the owner of registered MCP servers that have none (never transfers an owned one); entries trimmed, split at the last `:`; a malformed entry or a duplicate name stops startup (`FATAL config key=MCP_SERVER_OWNERS reason=<reason>`, the restart policy then loops: fix the value); read-back lines `mcp.registry.owner_assigned`, `mcp.registry.owner_mapping`, `mcp.registry.ownerless count=<n> names=<list> saved=<bool>` |
| `AGENT_SANDBOX_ROOT` | No | `$HOME/.agent-sandbox` | Trusted storage of the sandbox homes (never mounted as a whole); must be an absolute path to a private directory without symlinks, else every run fails closed |
| `AGENT_SANDBOX_BWRAP` | No | `/usr/bin/bwrap` | Path of the isolation runtime; must be an absolute path |
| `MODEL_PROXY_IDLE_TIMEOUT_MS` | No | `600000` | No-progress timeout per proxied provider request (trusted model proxy); an invalid value (non-numeric, 0, negative) stops startup |
| `GIT_MAX_CONCURRENCY` | No | `3` | Git operations of `/v1/workspace/git/*` that run at the same time across all repositories; further requests wait in arrival order, none is rejected |
| `GIT_TIMEOUT_MS` | No | `120000` | Deadline for one git command of `/v1/workspace/git/*`, in ms; on expiry the command's process group is stopped and the request answers 500 `git <subcommand> timed out after <n> s` |

## API Key Format

```
API_KEYS=label1:secret1,label2:secret2
```

Keys are sent as `Authorization: Bearer <secret>`. The label is used for audit logging and scopes sessions, the event cache and registered tools. A label named in `AGENT_TOOL_POLICY` must stay in `API_KEYS`: removing or renaming it alone stops the gateway at startup (and the restart policy keeps restarting it), so change both settings together.

## Docker

```bash
docker compose up -d --build     # Build and run
docker compose logs -f           # Follow logs
docker compose down              # Stop
```

Port `3001` binds to `127.0.0.1` only (reverse proxy expected). The container runs as `node` with the security profile of `docker-compose.yml` (`cap_drop: ALL`, `no-new-privileges`, committed seccomp profile in `security/`, `systempaths=unconfined`, `pids_limit`); the health check requires `/health` `isolation` to be `ok`. `./agent_home` must be owned by uid 1000.

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

## Isolation Rules (MVP-7678)

Every agent run executes in a bubblewrap sandbox (`src/sandbox.ts`, `src/sandbox-content.ts`). When you change anything near it:

- **Never pass `process.env` (or a copy of it) to the runtime.** The SDK `env` option and the spawn hook get only `runtimeEnvFrom(...)` plus the per-run log variables; the sandbox builds its own allowlist in `buildSandboxEnv`. A new variable the runtime needs is added to that allowlist with a test that asserts the exact key set (`sandbox.test.ts`, `sandbox-process.test.ts`), never inherited.
- **The only provider credential a run holds is its model proxy token** (`ANTHROPIC_API_KEY=<run token>`, `ANTHROPIC_BASE_URL=<loopback proxy>`). The real key and the OAuth tokens stay in `model-proxy.ts` on the trusted side.
- **No-follow rules.** Every path the trusted side binds into a sandbox, copies, lists or reads from agent-writable storage is checked with `lstat`/`O_NOFOLLOW` (`checkTrusted`, `readFileNoFollow`, `listRegularFilesNoFollow`, `copyFileNoFollow`): a regular file or directory owned by the gateway user, inside its expected tree, whose real path is the path itself. Never use `existsSync`, `statSync`, `copyFileSync` or `realpathSync`-then-use on such a path. Mount points inside a conversation home are sanitized with `prepareMountPoints`.
- **Fail closed.** A start problem must end in an `IsolationFailure` (fixed text, not retried); nothing may fall back to an unsandboxed run. New fixed texts go through `run-failure.ts` and are asserted verbatim.
- **Trusted files never enter a sandbox**: `.credentials.json`, state files, `~/.ssh`, other homes. New trusted state needs a test row that proves it is absent from a real sandbox (with a control that proves the probe works) and a synthetic marker, never a real secret.
- Real-process tests that start sandboxes and runtimes run through the workflow kit's `scripts/run-verification.mjs`; clean up only your own temp directories and containers.

## Security Acceptance Rules (MVP-7677)

- **Pre-merge rule.** There is no CI: a change is mergeable when `npm run build && npm test` passes, and, if it touches `src/sandbox*.ts`, `src/agent.ts`, `src/model-proxy.ts`, `src/mcp-*`, `Dockerfile`, `docker-compose.yml`, `entrypoint.sh`, `security/*` or `scripts/*probe*`, when `npm run probe:epic-integration` and `npm run probe:docker-isolation` pass too. Record the commands and their runner result lines in the pull request.
- **Use the workflow kit's runner for heavy runs:** `node ~/jira-workflow-kit/scripts/run-verification.mjs --wait --max-wait-minutes <N> --cwd <worktree> -- <command>` as ONE background command, from a detached worktree at the committed revision (hardlinked `node_modules`, a fresh `tsc`): the runner tests the live directory it is given, so an edit during a queue wait invalidates the run. Never poll its exit 75 in a loop.
- **A new isolation vector needs a row, not a list entry.** Add a row to `security-regression-process.test.ts` (or the matching security file) with a stable AC id in `AC_ROWS`, a permitted control that shows the route is live, and the five surfaces; `security-matrix.test.ts` checks that every id a suite requires is in the map. Security files never `skipIf`: a missing prerequisite throws `host prerequisite missing: <name>`.
- **Evidence prints names and counts only** (`SECURITY-EVIDENCE`, `SECURITY-MATRIX`, `SECURITY-SUMMARY`); never put a marker value into an assertion message, a log line or a Jira comment. A negative control must stay red: its child run exits nonzero against a deliberately vulnerable copy of `dist/` and prints no marker value.
- **Deployment and rollback** follow the README runbook "Security acceptance and deployment runbook": a rollback target is an image that passed the suite and both probes, identified by tag and digest, never by `/health` alone.

## Tool Mediation Rules (MVP-7679)

- **Never put a credential (header, env, args, override) into the runtime's MCP configuration.** The runtime gets only `{ "type": "http", "url": "http://127.0.0.1:<port>/mcp/<token>" }`; no registry `args`/`env`, override or request `env` value and no header may reach its command line. The debug log redacts the same values: `headers`, `env` and the `args` of a stdio server definition (`logging.ts`, `redactCredentialsForLog`).
- **Every credential-bearing MCP server (http, SSE, stdio) goes through a relay binding** (token, upstream or bridge, merged credentials, grant). Stdio servers with env run in their own tool sandbox. If the relay is not listening the server is left out of the run, never connected directly.
- **The grant check runs before any upstream request.** Effective grant = `AGENT_TOOL_POLICY` for the caller's label intersected with the caller's narrowing; a caller can only narrow. `allowedToolsPattern` is not part of the grant.
- **The agent can write its own home and its work area**, so nothing the runtime or its children (`bash -l` for the shell snapshot, `git`) read at start may come from them. The home is rebuilt from nothing before every sandbox start (`prepareSandboxHome`): every home-root entry except `.claude` is deleted without following links, and `.claude` keeps only `RUNTIME_WRITABLE_DIRS` (projects, todos, plans, memory) with only `-*` transcript directories below `projects`. The agent's persistent files live in the per-conversation work area `sessions/<id>/work`, bound at `/work` (the working directory, so transcripts are in `projects/-work/`); `prepareWorkArea` removes ANY `.git` entry at the `/work` root at every start (directory, file or link, never followed; a `commondir` pointer or `extensions.worktreeConfig` + `config.worktree` defeats a config-only rewrite), because the start-time `git status` runs there; repositories are central read-only mounts, so a work-root repository is not a supported scenario. Removing `.git` alone does not close the class: git also treats a working directory that holds `HEAD`, `objects/`, `refs/` and `config` as an implicit bare repository (with `core.bare=false`, `core.worktree`, `core.fsmonitor` it runs a command at `git status`). So the sandbox environment carries trusted command-scope git configuration (`GIT_TRUSTED_CONFIG` in `sandbox.ts`, `GIT_CONFIG_COUNT/KEY_n/VALUE_n`, highest precedence): `safe.bareRepository=explicit` (an implicit bare repository is refused, so git discovers no repository in `/work` and reads no agent-written file), `core.fsmonitor=false`, `core.hooksPath=/dev/null`. Repositories below `/work` are not discovered from `/work`; git run inside them works, but their fsmonitor and hooks are off and a bare repository there needs `--git-dir`. Do not add file names to a list: a new vector means a new row that plants it in `/work` and asserts no marker at the next start. `settingSources` is `["user"]` (enforced runs `[]`), so nothing in `/work` is read as configuration; the extension directories (`commands`, `agents`, `skills`, `output-styles`, `plugins`, `hooks`, `CLAUDE.md`) are always mounted read-only, from an empty trusted stand-in when the workspace has none. New agent-writable paths are untrusted by default; do not extend a deny-list or add a persistent home path. Each path the runtime is found to read at start needs a row in `sandbox-home.test.ts` and, for execution, the real runtime. Deleting conversation directories (home and work) is MVP-7402.
- **A webhook, relay or bridge failure maps to a fixed `TOOL_*` text** (`tool-mediation.ts`), never an upstream body, header, URL or secret. No redirect is followed anywhere.

## Project Structure

```
src/
  server.ts          # Express app, health/logging/session/settings routes
  auth.ts            # API key middleware (Bearer token)
  query.ts           # POST /v1/query, GET /v1/query/:queryId/events
  agent.ts           # Claude Agent SDK wrapper, event emission, MCP server injection
  sessions.ts        # Session CRUD, persistence, idle cleanup, SDK session ID sync; conversations keyed by (API-key label, sessionId) in the additive sessionsByLabel map; owner (label + user_id or null) and random sandboxDirId per conversation, admitSession (exact owner, ownerless legacy refused), caller-scoped list/delete
  retry.ts           # Exponential backoff retry (transient failures, empty responses); resumes only established sessions
  run-failure.ts     # Classifies a failed run (runtime stdout diagnostic, thrown error) into a safe public error message + safe log fields
  event-cache.ts     # In-memory NDJSON event cache with TTL, keyed by (API-key label, queryId)
  workspace.ts       # File CRUD for memory/agents/skills directories
  logging.ts         # Runtime-adjustable log levels
  tools.ts           # Tool registry CRUD + persistence (TOOLS_PERSIST_PATH); owner per tool, legacy ownerless count at startup
  webhook.ts         # Webhook executor (POST to tool webhook_url with context; no redirects, 8 MiB cap, fixed TOOL_* failure texts)
  tool-server.ts     # MCP server factory (wraps registered tools for Agent SDK)
  tool-grant.ts      # AGENT_TOOL_POLICY parsing (FATAL lines), effective grant = policy(label) intersected with enforcedTools/allowedTools, built-in lists for the runtime
  tool-mediation.ts  # Internal ToolRequest/ToolReply contract, the five TOOL_* codes with fixed texts, webhook rejection text, secret masking, AGENT_MCP_TOOL_TIMEOUT_MS
  tool-policy.ts     # enforcedTools: request validation, built-in/server selection, deny-only PreToolUse hook (per-run enforced tool set)
  tool-input-schema.ts # Webhook tool input_schema -> typed, described SDK shape; per-property "any value" fallback, per-tool untyped fallback
  mcp-registry.ts    # External MCP server registry CRUD + persistence (MCP_SERVERS_PERSIST_PATH); owner per entry (registering API-key label, never returned by a route), ownerless = registered before ownership
  mcp-server-owners.ts # MCP_SERVER_OWNERS parser (fatal fixed lines) and startup applier (only ownerless entries, read-back lines)
  mcp-upload-relay.ts # Streaming upload relay: raw-path rule, parser skip, pre-auth guard, X-MCP-Credential-Headers, relay core
  mcp-credential-relay.ts # Loopback relay for every registered MCP server (http, SSE, stdio) and request servers with headers/env: per-run token and binding, grant check, message rules, buffered and validated answers, fixed TOOL_* failures (no OAuth login in the runtime)
  mcp-bridge.ts      # SSE bridge of the relay (endpoint event only on the registered origin, local answers to server requests)
  mcp-stdio-sandbox.ts # Stdio MCP servers in their own tool sandbox (bwrap, own namespaces, private home, env allowlist + server env) with a line-based bridge
  mcp-request-servers.ts # Request mcpServers validation and normalization (name rule, command xor url, MCP_SERVER_NAME_CONFLICT)
  sdk-run-logs.ts    # Per-run directory for the Claude runtime's log files, deleted after the child exits; startup sweep; DEBUG_CLAUDE_AGENT_SDK strip
  sandbox.ts         # Per-run bubblewrap sandbox: config keys, exact bwrap argv, env allowlist, launch wrapper (nested-userns check), fail-closed IsolationFailure, /health isolation state, boot self-check
  sandbox-content.ts # What a sandbox may see: no-follow validation of every bind source, allowlist-generated git configs, known-secret-value scan, mount plan, mount-point sanitizing, prepareSandboxHome (rebuilds the home from nothing: only RUNTIME_WRITABLE_DIRS and `projects/-*` survive), prepareWorkArea (removes any /work/.git), trusted empty stand-ins for missing extension entries
  model-proxy.ts     # Trusted loopback model proxy: run token in x-api-key, POST /v1/messages[/count_tokens] only, injects the gateway's provider credential (API key or OAuth with single-flight refresh); readAuthStatus for /v1/auth/status
  mcp-overrides.ts   # mcpCredentialOverrides validation, header/env checks, requireUserCredentials attachment rule (headers output keys case-insensitive, every match non-empty; env keys exact)
  gc-budget.ts       # Minor GC every 2 MiB relayed (needs node --expose-gc, set in entrypoint.sh and npm start)
  git-exec.ts        # Non-blocking git runner (no shell, process-group timeout, redacted error text) + per-repository and global FIFO queues
  routes/
    ssh.ts           # POST /v1/ssh-keys
    auth.ts          # Anthropic OAuth flow (login, submit-code, status)
    workspace.ts     # CRUD for /v1/memory/*, /v1/agents/*, /v1/skills/*
    git.ts           # POST /v1/workspace/git/clone|pull, GET /v1/workspace/git/status
    tools.ts         # PUT/GET/DELETE /v1/tools (Tool Registry REST endpoints)
    mcp.ts           # PUT/GET/DELETE /v1/mcp-servers + /restart + /health + /test + /call (MCP Server Registry; PUT/DELETE of an existing name only for its owner, else 403 MCP_SERVER_OWNER_MISMATCH before any validation, ownerless entries refused for every label and for credential-bearing /call, /test, /uploads/*; PUT refuses a NEW name outside ^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$ with 400 MCP_SERVER_NAME_INVALID, existing names stay editable/deletable; /call = direct LLM-free tools/call passthrough, gates on enabled unlike /test; /uploads/* = streaming upload relay)
  tests/
    e2e-session.test.ts    # E2E session continuity tests
    routes.tools.test.ts   # Tool routes unit tests
    tool-server.test.ts    # MCP server factory tests
    tool-input-schema.test.ts # Webhook tool schemas via JSON-RPC tools/list + tools/call (advertised types, rejection, fallback, depth, prototype names)
    webhook-tool-schema-process.test.ts # Real-runtime probe: model-facing webhook tool schemas + pre-dispatch rejection, reqlift/diemcrm fixtures (needs `npm run build`)
    tools.test.ts          # Tool registry unit tests
    webhook.test.ts        # Webhook executor tests
    session-ownership.test.ts / session-isolation-process.test.ts # Owner rule, legacy refusal, list/delete scoping, persistence, query refusals (mocked run); real runtime: legacy transcripts, concurrent owners, restart resume, one active request per conversation (needs `npm run build`)
    sandbox.test.ts / sandbox-content.test.ts # Isolation config, exact argv, env allowlist, failure texts; no-follow validation, git config allowlist, known-value scan (chunked, any size up to 64 MiB, SSH key lines, webhook URL parts), mount plan
    scan-residuals-process.test.ts # Outcome Probe (MVP-7919): spawned gateway, real bwrap; planted known credential, SSH key and webhook URL values of every size in a global directory, a repository and a 2 MiB CLAUDE.md stay unreadable on every surface, clean small and 2 MiB files stay available, per-surface negative control; `SCAN_RESIDUALS_DIST` points it at another compiled server for the red run (needs `npm run build`)
    sandbox-process.test.ts # Real bwrap: env, /proc, trusted files, planted links, git masks, read-only content, fail-closed rows, cancel and SIGKILL, plus the real runtime through the gateway (needs `npm run build`)
    model-proxy.test.ts / model-proxy-process.test.ts # Trusted model proxy: token, path, header and refresh rules; real runtime through it
    sdk-login-guard-process.test.ts # Real-runtime probe: spawned gateway, OAuth-capable MCP stub, scripted Anthropic API (needs `npm run build`)
    run-failure.test.ts             # Failure classifier table: kinds, exact messages, version bounds, hostile inputs
    tool-policy.test.ts             # enforcedTools validation table + the hook never allows
    query-enforced-tools-outcome.test.ts # enforcedTools through query/agent/retry with the SDK mocked: options layers, tool_policy first and once, unchanged options without it
    tool-policy-process.test.ts     # Real-runtime probe: refused webhook/MCP/Bash/WebFetch calls reach no handler; hostile HOME, faulty hook, retry, [] (needs `npm run build`)
    query-failure-outcome.test.ts   # Failed runs through query/agent/retry with the SDK mocked: one error event, no done, retry and resume rules
    query-failure-diagnostics-process.test.ts # Real-runtime probe: provider rejections reach the client as safe messages, sessions after a failed first request (needs `npm run build`)
    mcp-credential-relay.test.ts    # Credential relay unit tests
    tool-grant.test.ts              # AGENT_TOOL_POLICY parsing table and the effective grant
    tool-mediation.test.ts          # Fixed TOOL_* texts, webhook rejection text, secret masking, deadline parsing
    tool-owner.test.ts              # Tool ownership: 403, forwarding, legacy ownerless claim and audit
    sandbox-home.test.ts            # Clean home (inventory rows, allow-list) and work area (/work/.git removal)
    sandbox-runtime-config.test.ts  # Trusted empty stand-ins for the extension directories in the mount plan
    query-tool-grant-outcome.test.ts # Grant through query/agent with the SDK mocked
    query-mcp-mediation-outcome.test.ts # Relay bindings and request-server routing through query/agent with the SDK mocked
    mcp-bridge-sse.test.ts / mcp-bridge-stdio.test.ts # SSE bridge and stdio tool sandbox bridge
    mcp-direct-mediation.test.ts    # Direct call, test and health: header merge, no redirect, user-credential refusal
    tool-grant-process.test.ts / mcp-mediation-process.test.ts / mcp-stdio-sandbox-process.test.ts # Real-runtime probes: built-in refusal for every actor, relay mediation, stdio tool sandbox (need `npm run build`)
    public-auth-matrix-process.test.ts / mediation-outcome-process.test.ts # Public auth matrix per label; end-to-end Outcome Probe of the mediation (need `npm run build`)
    helpers/sse-mcp-stub.ts         # SSE MCP server stub for the bridge tests
    security-matrix.test.ts         # T1 for the security harness: detector, evidence lines, route probes, samplers, offline mode
    security-regression-process.test.ts # Real-process regression: normal chat, eight secret routes x fresh/resumed/restarted, leftovers, negative controls (child runs against vulnerable dist copies); rows RP.*, RT.*, NC.*, X.* (need `npm run build`)
    security-entrypoints-process.test.ts # Entry points (ordinary chat, agent, skill, sub-agent, direct MCP call, upload relay), denied-tool and grant-enlargement rows EP.* (need `npm run build`)
    security-failure-process.test.ts # The seven injected isolation failures with boundary confirmation, rows IF.* (need `npm run build`)
    helpers/security-matrix.ts      # Harness: markers, surfaces, detector, evidence lines, samplers, offline mode, rig with recording doubles (no vitest import)
    helpers/security-routes.ts      # The eight route probes (in-sandbox Python) and their verdicts, shared with the Docker probe
    mcp-overrides.test.ts           # Override merge + requireUserCredentials header-key casing + ownerless left out of credential-bearing runs
    mcp-server-owner.test.ts / mcp-server-owners.test.ts # Registry ownership routes (two labels, real authMiddleware) and the MCP_SERVER_OWNERS parser/applier
    mcp-server-owner-process.test.ts # Outcome Probe: another label cannot redirect a registered server; restart, deploy step, ownerless run (spawned gateway, needs `npm run build`)
    routes.mcp.test.ts              # Registry PUT schema validation + new-entry name rule
    require-user-credentials.test.ts # requireUserCredentials + header/env validation
    credential-redaction-rows.test.ts # Debug-log redaction for every credential entry point
    git-exec.test.ts                # Git runner and queue unit tests
    git-routes-contract.test.ts     # Git endpoint contract, queue, injection rows (fake git on PATH)
    git-nonblocking-process.test.ts # Spawned gateway stays responsive during slow git (needs `npm run build`)
    git-credential-logs-process.test.ts # No http(s) URL token or SSH key in git error text or logs at info/debug (needs `npm run build`)
  __tests__/
    git.test.ts            # Workspace git endpoints tests
Dockerfile           # Node 22 + system tools + bubblewrap (runs as node; the Claude Code CLI is the SDK's bundled copy)
docker-compose.yml   # Single-service compose with volume
entrypoint.sh        # Root setup, SSH key restore, drop to node user
```
