# Agent Gateway

Standalone REST API service that wraps the [Claude Agent SDK](https://docs.anthropic.com/en/docs/claude-agent-sdk) and exposes agentic capabilities over HTTP. Designed for integration into web applications, CI pipelines, or any system that needs to run Claude agents programmatically.

## Quick Start

```bash
cp .env.example .env
# Edit .env: set API_KEYS (gateway auth) and choose an Anthropic auth method below

docker compose up -d --build
```

The container runs as the `node` user (uid 1000): `./agent_home` must be owned by uid 1000 (`chown 1000:1000 agent_home`). The gateway is now running at `http://localhost:3001`. Verify with:

```bash
curl http://localhost:3001/health
```

`/health` must report `"isolation":"ok"`; otherwise agent runs are refused, see [Agent isolation](#agent-isolation).

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

### Stopping and recovery

**Init process.** The image runs `tini` as process 1 (`ENTRYPOINT ["/usr/bin/tini", "--", "bash", "/app/entrypoint.sh"]`). It forwards `SIGTERM`/`SIGINT` from `docker stop`, `docker compose down` or a host shutdown to the gateway, reaps finished child processes, and exits with the gateway's exit code. `docker-compose.yml` needs no `init:` setting.

**What a stop does:**

1. The gateway stops accepting new connections and saves every pending change at once.
2. Requests already received keep running for up to 8 s, including streaming chat answers. Changes they make are saved as usual.
3. It saves the sessions, the tools and the MCP servers once more and exits. Nothing can change between this save and the exit.

A second `SIGTERM`/`SIGINT` skips the rest of the wait. An idle gateway stops within about a second; with open streams it stops after at most about 8 s, below Docker's 10 s grace period. Streams still open at 8 s are cut.

| Exit code | Meaning | What to do |
|-----------|---------|------------|
| `0` | Every final save succeeded. | Nothing. |
| `1` | At least one area's final save failed or was switched off (see `unreadable-not-preserved` below). An `ERROR persistence … problem=final-save-failed` line names the area. Its file keeps its last complete save; changes since then are lost. | Check `docker logs`, disk space and the permissions of `./agent_home/.claude`. |
| `137` | Killed by Docker after 10 s. Still possible while a git command blocks the gateway (until MVP-7614 is deployed). The files stay intact; changes from the last moment before the block can be lost. | Nothing for the files. |

**State files and `/health`.** `sessions.json`, `tools.json` and `mcp-servers.json` are saved atomically (a temp file `<file>.tmp-*` in the same directory, then a rename), so a kill, crash or full disk never leaves a half-written file. A file that cannot be read or used at start is never overwritten. `GET /health` reports problems in two additive fields; its HTTP status stays 200:

```json
{
  "status": "ok",
  "version": "0.1.0",
  "uptime": 1,
  "sessions": 0,
  "erasurePending": 0,
  "persistence": "degraded",
  "persistenceIssues": [
    {
      "area": "mcpServers",
      "problem": "corrupt-preserved",
      "file": "/home/node/.claude/mcp-servers.json",
      "preservedAs": ["/home/node/.claude/mcp-servers.json.corrupt-20260926T213634Z"]
    }
  ]
}
```

`erasurePending` is the number of deleted or expired conversations whose folder the gateway has not yet confirmed gone (a count only, no ids); a value that stays above 0 means a folder cannot be removed (look for `sessions.erasure.failed` log lines). `persistence` is `"ok"` exactly when `persistenceIssues` is empty. `area` is `sessions`, `tools` or `mcpServers`; several entries may be listed. The compose healthcheck only checks for a 2xx status, so the container stays "healthy" while `persistence` is `"degraded"`: monitoring must read the field (`curl -s http://localhost:3001/health | jq .persistence`).

| `problem` | Meaning | Data at risk | Operator action | Clears when |
|-----------|---------|--------------|-----------------|-------------|
| `corrupt-preserved` | The file could not be read or parsed at start, or it held an entry the gateway cannot restore (`null`, a tool or MCP server without a string `name`, a session without a numeric `lastUsed`). It was moved to `<file>.corrupt-<UTC stamp>` with its bytes unchanged, and the area started empty, with none of its entries. | Everything in the copy, until it is restored. | Follow the recovery procedure below. | No `<file>.corrupt-*` exists any more (checked on every `/health` request, no restart needed). |
| `unreadable-not-preserved` | The file could not be read, parsed or restored and could not be moved aside (usually permissions). The file is left untouched and saves for this area are switched off: API changes still answer success but are lost at the next restart. | Every change to this area since the start. | Fix the cause (usually ownership or permissions of `./agent_home/.claude`), then restart. | The next start loads the file. |
| `write-failed` | The latest save of this area failed, for example because the disk is full. The previous file is intact. | Changes since the last successful save. | Check disk space and permissions. | The next successful save of this area. A save runs only after a change in this area or at a stop, so after the cause is fixed `degraded` stays until the next change here; a restart also clears it. |

Every problem is also logged, whatever the log level, as one line: `ERROR persistence area=<sessions|tools|mcpServers> problem=<corrupt-preserved|unreadable-not-preserved|write-failed|final-save-failed> file=<path> [preservedAs=<path>] reason=<fixed text> [code=<errno>] (see /health)`. These lines never contain file content.

**Recovering a `.corrupt-*` copy:**

1. The container path `/home/node/.claude/<file>` is `./agent_home/.claude/<file>` on the host.
2. Stop the gateway first (`docker compose stop agent-gateway`). Otherwise its next save overwrites the restored file.
3. The copy is usually damaged (for example truncated), or it holds an entry the gateway cannot restore. To restore it, repair it (cut back to the last complete entry and close the array or object, or fix or remove the entry that is `null`, has no string `name` or, for a session, no numeric `lastUsed`; check with `jq . <copy>`) and copy it over `<file>`. This replaces the changes made in that area since the problem was detected. A copy kept after a read error has its original permissions; fix them first.
4. Give the restored file `node:node` ownership (`chown 1000:1000 <file>`) and its original mode (for example `chmod 600 mcp-servers.json`).
5. Move the copy out of `./agent_home/.claude/` or delete it. Only this clears `degraded`.
6. Start the gateway and confirm: `curl -s http://localhost:3001/health | jq '.persistence, .persistenceIssues'`.

Copies of `mcp-servers.json` contain MCP credentials (headers, env values and stdio args). Handle them as secrets, never attach state files or their copies to tickets or evidence, and delete them once resolved.

## Agent isolation

Every agent run executes inside its own sandbox. Bash commands, interpreters, the Read, Write, Edit, Glob and Grep tools, MCP servers that need no credential and sub-agents all run in the sandbox, so an agent can neither read the gateway's secrets nor see other conversations. The gateway itself (API keys, the provider credential, OAuth tokens, state files, SSH keys) stays outside.

**What a run sees.** The sandbox is built with `bubblewrap` (new user, PID, IPC, UTS and cgroup namespaces; the network is shared; all capabilities dropped; nested user namespaces disabled and checked at every start). Only an allowlist is visible:

- read-only: the system directories, the Claude runtime, the global `CLAUDE.md`, `skills/`, `agents/`, `memory/` and `commands/`, a generated `settings.json` that keeps only `permissions`, and every repository under `~/.claude/projects/` (each repository's git configuration is replaced by a copy that holds only remote URLs without user info, fetch refspecs, branch settings and core settings);
- writable: the conversation's work area at `/work` (the working directory, kept between its turns), the conversation's home at `/home/node` (rebuilt at every start, see below), a private `/tmp`, and this run's log directory;
- not visible: `.credentials.json`, `sessions.json`, `tools.json`, `mcp-servers.json` and their `.corrupt-*` copies, `~/.ssh`, legacy transcripts and logs, other conversations' homes, the Docker socket, and every process of the gateway or of other runs.

The sandbox environment is an allowlist built from nothing (`HOME`, `USER`, `PATH`, `LANG`/`LC_*`, `TERM`, `TMPDIR`, the per-run log variables, the trusted `GIT_CONFIG_*` entries, `DISABLE_AUTOUPDATER`, `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC`, the SDK's non-secret `CLAUDE_CODE_*` and `CLAUDE_AGENT_SDK_*` keys). Its only provider credential is a random per-run token for the gateway's **model proxy**: the proxy accepts the token only in the `x-api-key` header, forwards `POST /v1/messages` and `POST /v1/messages/count_tokens` to the provider with the gateway's own credential (`ANTHROPIC_API_KEY`, otherwise the OAuth token, refreshed on the gateway side) and revokes the token when the run ends. Every registered MCP server (http, SSE and stdio) is reached through the credential relay, which holds its credentials on the trusted side (see [Tool mediation](#tool-mediation)). Operator tuning variables of the runtime that are not in the allowlist (for example `MCP_TIMEOUT`, `BASH_DEFAULT_TIMEOUT_MS`) are no longer passed on.

**The agent's home and work area.** The agent can write its own home, and the runtime and the processes it starts read the home by name at every start: the shell snapshot runs `bash -l` (`.bash_profile`, `.bash_login`, `.profile`, then `.bashrc`; the `zsh` files when a zsh is installed, the production image has none), `git` reads `.gitconfig`, `.config/git/config` and the repository at the working directory, the runtime reads `.claude.json` and `.claude/.config.json`. Shielding such names one by one failed three QA rounds, so the home is **rebuilt from nothing before every sandbox start**: the trusted side deletes every home-root entry except `.claude` (no link is followed) and keeps below `.claude` only the runtime's data, the transcript directories `projects/-*`, `todos/`, `plans/` and the `memory` mount point; the runtime recreates its state file, shell snapshot and caches itself. A file an agent writes in the home lasts until its run ends and is gone at the next start; a name a later runtime version learns to read is untrusted by default. Run-time starts read nothing the agent wrote: the measured start-time reads of the runtime, `bash -l` and `git` are listed in the Jira design comment of MVP-7679 (comment 38301) and asserted by the inventory rows of `sandbox-home.test.ts`.

What an agent wants to keep goes to **`/work`**: `<AGENT_SANDBOX_ROOT>/sessions/<sandboxDirId>/work`, bound read-write at `/work`, the working directory of the runtime, private to the conversation (same lock and admission as the home) and persistent between the turns of that conversation only. Because the working directory is `/work`, the runtime keeps the transcripts under `projects/-work/` (carried over with `todos/` and `plans/`, so resume works). Nothing in `/work` is read as configuration: runs read only the user setting source (`settingSources: ["user"]`; enforced runs none), so a `.mcp.json`, `.claude/settings.json`, `.claude/settings.local.json`, `CLAUDE.md` or `.claude/agents|commands|skills` written there is never loaded (a row plants all of them with Bash denied and asserts that no server, hook, agent, command or skill starts and no instruction reaches the model). The one thing the runtime looks at in `/work` is git: it runs `git status` there at start, so before every start ANY `.git` entry at the root of `/work` (a directory, a file, a link; never followed) is removed. Rewriting only its configuration was not enough: a `commondir` file names an agent-written directory, and `extensions.worktreeConfig` with a `config.worktree` file adds a configuration the allowlist never sees. A repository at the root of `/work` is not a supported scenario (repositories are the central read-only mounts). Removing `.git` is one layer: git also treats a directory that holds `HEAD`, `objects/`, `refs/` and `config` as an implicit bare repository, so the sandbox environment carries trusted command-scope git configuration (`GIT_CONFIG_COUNT/KEY_n/VALUE_n`: `safe.bareRepository=explicit`, `core.fsmonitor=false`, `core.hooksPath=/dev/null`; highest precedence, above any file the agent writes). With no repository discovered in `/work`, the start-time git reads no agent-written file. Repositories below `/work` are untouched: git run from `/work` does not discover them and does not cross the `/work` mount upward (git run inside them works, with fsmonitor and hooks off; a bare repository there needs `--git-dir`), the sandbox environment holds no other `GIT_*` variable, and what the agent writes outside `/work`, the home and `/tmp` is gone at the next start (rows in `sandbox-process.test.ts` and `tool-grant-process.test.ts`). The extension directories (`commands`, `agents`, `skills`, `output-styles`, `plugins`, `hooks`) and `CLAUDE.md` are mounted read-only from the gateway workspace, or from an empty trusted stand-in when the workspace has none: commands, agents and skills carry frontmatter hooks and agent `mcpServers` that execute commands, so they are trusted content only.

**Repositories** under `~/.claude/projects/` stay central, read-only and live. Read-only git commands work in them, for example `git -C ~/.claude/projects/<repo> show <other-branch>:<path>`, `log`, `diff` and `ls-tree` (a row reads a file that exists only on another branch). Git's "dubious ownership" check does not block them: it compares the repository owner with the process user, only repositories owned by the gateway user are mounted, and the sandbox keeps that user. A commit or a new branch fails (read-only file system).

**Global `memory`.** `~/.claude/memory` is the gateway workspace's `memory/` directory. It is written only through `PUT /v1/memory/*` (any API-key holder; entries are not owner-scoped) and mounted read-only into every sandbox, so no conversation can write it and nothing one conversation writes reaches another through it; the conversation's own `.claude/memory` is only the mount point. A workspace without a `memory/` directory (the entrypoint always creates it) leaves the conversation's own directory writable, visible to that conversation only.

**Run directories.** The per-run directory `<root>/runs/run-XXXXXX` (generated settings, git configuration copies, empty stand-ins, and the home and work area of a run without a conversation) is removed when the request ends, whatever its outcome; a crashed gateway's leftovers are swept at start. A row asserts that no `run-*` entry is left after a request. The conversation directory `sessions/<sandboxDirId>` (home and work area) is removed when its label deletes the conversation or it expires (see Conversations).

**Every bind source the gateway mounts into a sandbox is checked without following symlinks** (a regular file or directory owned by the gateway user, inside its expected tree); anything else is left out with an `audit` log line. Mounted global workspace entries are also scanned at every sandbox start for the gateway's own secret values: API keys, provider key, OAuth tokens, registered MCP header and env values, the private-key lines of the key files in `$HOME/.ssh`, and the credential parts of every registered webhook URL (the URL, path tokens, query and fragment values, user info). Files are read in chunks, whatever their size up to 64 MiB; a file that holds a value, cannot be read safely or is larger than 64 MiB is hidden behind an empty file (audit line `reason=known_value` or `reason=too_large`). A file is read again when the value set changes (a tool registered or deleted, an SSH key written, a key rotated), or when its size or modification time changes; a start with nothing changed reads nothing. The scan finds verbatim copies of the values it knows. It does not find base64, hex, compressed or re-wrapped copies, git object stores, one-off `sshKey` values passed with a git request, non-armored key formats, values shorter than 8 characters or values of disabled MCP servers, and it does not cover repositories or the per-user skills bundle, which are mounted without this scan. Repositories are read-only in the sandbox, but a clone request against an existing checkout performs `git pull`; it does not remove untracked files. Keep repository content trusted and remove stale or sensitive files at the source or during checkout.

**Conversations.** A conversation is keyed by the API-key label and the `sessionId` the caller sent, and belongs to that label (decided as DEC-ISO-007, delivered by MVP-8044): every request through the label that sends the id continues it in the conversation's own home and work area, whatever its `user_id` (another person, none, or the creator). The gateway does not decide who inside an application may write in a conversation; the application does. The request's `user_id` keeps the jobs it was introduced for, per request: it selects the writer's personal skills, it is the `user_id` of the webhook context, and the per-request credential overrides and `requireUserCredentials` apply to the person writing, never to the creator (a writer without a credential gets the no-credential text, or the server is left out of the run). The creator's `user_id` is stored as `owner.userId` for information only and is never read for a decision; a `sessions.json` entry without that key loads. Another label that uses the same `sessionId` gets its own new conversation (no refusal, nothing learned about the first). **Residual risk, accepted:** the application alone decides who receives a conversation id, and everything a writer's tools returned and the text of any skill a writer invoked stays in the conversation (its transcript and `/work`), so later writers of the same label can see it; successful relay replies are not masked. Conversations are stored in the additive `sessionsByLabel` map of `sessions.json`; public routes keep the raw ids. Ownerless entries from before the isolation update keep their raw id and are still refused for every label. A conversation is processed by one request at a time, whoever sends it (a second request gets the "still answering" text). `GET /v1/sessions` and `DELETE /v1/sessions/:id` are scoped to the caller's API-key label. 

**Deleting a conversation (MVP-7402).** `DELETE /v1/sessions/:id` removes the conversation's whole folder `sessions/<sandboxDirId>` (runtime transcripts of every turn, failed ones included, tool results, uploaded images, the work area) and answers 200 `{"deleted": true}` only when the folder is confirmed gone. When a run still holds the conversation, or the folder cannot be removed right now (a file system error), it answers 503 `{"error": "erasure_pending"}`: the entry stays in `sessions.json` as a tombstone (`erasePendingSince`), every query for it is refused before any run with a fixed text, it is hidden from `GET /v1/sessions` and from the `/health` `sessions` count, and `/health` `erasurePending` counts it. The gateway finishes the erasure itself: when the run releases the conversation, on a sweep every `SESSION_ERASURE_RETRY_MS` (default 60000; the sweep also runs with `SESSION_IDLE_TIMEOUT_MS=0`) and once at startup, so a caller that ignores the 503 (reqlift's best-effort delete) needs no retry; a repeated DELETE completes it as well. The tombstone is saved to `sessions.json` before any removal starts (DELETE, a run's release, a sweep, the startup sweep, idle and load-time expiry), so a gateway that is killed in the middle of a removal finds it at the next start and finishes it. While the sessions file cannot be written, no erasure starts: DELETE answers 503 and the gateway logs `sessions.erasure.failed id=<id> code=tombstone_unsaved` at every log level; once the file can be written again the next sweep saves the tombstone and erases. When saves of the sessions file are switched off for the whole process (an unreadable file that could not be moved aside, `/health` `persistence` degraded) no tombstone can reach the disk, so the removal goes ahead and logs `sessions.erasure.unsaved_tombstone`. A finished erasure leaves a content-free marker (label, client id, time; no folder name) so the owning label's late retry answers 200 every time, also after a restart; another label, or an id the label never owned, gets 404. Markers are never removed and are dropped when the label starts a new conversation with that id. Idle and load-time expiry of an owned conversation go through the same erase path; the idle timeout comes from `SESSION_IDLE_TIMEOUT_MS` only and cannot be changed over the API (see the settings routes). A conversation from before the isolation update (no owner, no folder) answers 409 `{"error": "legacy_not_erased"}` and nothing is touched: its transcripts are in the old shared store, which MVP-8166 cleans; callers that need confirmed erasure cover post-isolation conversations only. The folder is reached only through the caller's own entry and its validated random name, never through a caller-supplied id, and only while the conversation lock is held. Links inside it are removed, never followed, and a mount point below it stops the removal; the removal works at any depth and also for directories the agent made unreadable, using the system `chmod` and `rm`. A missing or relinked `sessions` directory is never read as "already erased" (503).

### Configuration

| Variable | Default | When to change it |
|----------|---------|-------------------|
| `ISOLATION_STARTUP_TIMEOUT_MS` | `10000` | Raise it on a very loaded host where `/health` or users report "could not start a protected workspace in time"; the sandbox itself starts in about 10 ms. |
| `AGENT_RUN_TIMEOUT_MS` | `7200000` (120 min) | Lower it to stop runaway agents sooner, raise it for tasks that legitimately run longer. It covers the whole request including retries and backoff. The request ends at most about 2 s after the limit even when the runtime does not stop: the sandbox is killed and its late output is dropped. |
| `MODEL_PROXY_IDLE_TIMEOUT_MS` | `600000` | The time a provider request may stay silent before it is cut. Raise it only for extremely slow answers. |
| `AGENT_MCP_TOOL_TIMEOUT_MS` | `600000` | Overall deadline of one mediated MCP `tools/call` in an agent run (http, SSE, stdio); an empty value is the default. Raise it only for tools that legitimately run longer. |
| `AGENT_TOOL_POLICY` | unset | Tool grant per API-key label, see [Tool mediation](#tool-mediation). Empty or unset means every label gets the approved default built-in tools (12 tools) and every MCP server. A label not granted `Bash` also loses the command settings (hooks, stdio startup commands) of skill, agent and command files. |
| `MCP_SERVER_OWNERS` | unset | Deploy-step mapping `<server>:<label>,...` that assigns the owner of registered MCP servers that have none, see [Registry ownership](#registry-ownership). Empty or unset assigns nothing. |
| `AGENT_SANDBOX_ROOT` | `$HOME/.agent-sandbox` | Only to move the storage of the conversation homes. It must be an absolute path to a private directory owned by the gateway user; it is never mounted as a whole. `docker-compose.yml` does not forward it from the shell: add it under `environment:`. |
| `AGENT_SANDBOX_BWRAP` | `/usr/bin/bwrap` | Only if the isolation runtime lives elsewhere. Like `AGENT_SANDBOX_ROOT`, it is not forwarded by `docker-compose.yml`. |

An invalid value (not a positive whole number, or a relative path; for `AGENT_TOOL_POLICY` see its reasons below) stops the gateway at startup with one fixed line, `FATAL config key=<KEY> reason=<fixed text>` (for `AGENT_MCP_TOOL_TIMEOUT_MS`: `reason=must be a positive whole number of milliseconds`); nothing falls back silently. `AGENT_TOOL_POLICY`, `AGENT_MCP_TOOL_TIMEOUT_MS` and `MCP_SERVER_OWNERS` are forwarded by `docker-compose.yml` (`${AGENT_TOOL_POLICY:-}`, `${AGENT_MCP_TOOL_TIMEOUT_MS:-}`, `${MCP_SERVER_OWNERS:-}`). A malformed `MCP_SERVER_OWNERS` stops the gateway with `FATAL config key=MCP_SERVER_OWNERS reason=entry without a server name or label` or `reason=the same server name listed twice`; like `AGENT_TOOL_POLICY`, the restart policy then restarts it in a loop until the value is fixed.

### `/health` and the compose health check

`GET /health` carries one more field, `isolation`. `docker-compose.yml` marks the container unhealthy unless it reads `"ok"`.

| `isolation` | Meaning | What users see | What the operator does | What clears it |
|-------------|---------|----------------|------------------------|----------------|
| `starting` | The boot self-check is still running (a few hundred ms). | Nothing yet. | Wait. | The self-check finishing. |
| `ok` | A sandbox started and passed its check. | Normal answers. | Nothing. | Stays until a permanent problem occurs. |
| `unavailable` | The boot self-check or a start failed for a permanent reason. The log has one line `ERROR isolation problem=<word> reason=<fixed text> (see /health)`. | Every query ends with "The gateway cannot start a protected workspace ...". Nothing runs unsandboxed. | Read the `problem` word (`binary_missing`, `invalid_root`, `namespace_denied`, `proc_denied`, `userns_not_blocked`, `canary_visible`, `pid_namespace_shared`, `mount_failed`, `content_invalid`, `proxy_unavailable`, `start_failed`) and fix the container profile, the storage directory or the host setting it names. | The next sandbox start that succeeds: a query starts one, and a gateway restart repeats the boot self-check. `proxy_unavailable` is cleared only by a gateway restart. |

A slow start of a user's run ("could not start a protected workspace in time") does not change `isolation`. A slow start during the boot self-check does: it reads `unavailable` with `problem=start_failed` until a later start succeeds.

The launch wrapper inside every sandbox refuses a start it cannot prove (MVP-8020): `binary_missing` when `/bin/bash` is missing or not executable, or when `/usr/bin/unshare` or `/usr/bin/true` (the tools of its own nested-namespace check) is not a regular executable file or `unshare` cannot run; `start_failed` when a descriptor above 2 is still open after the close step; `proc_denied` when it cannot list its descriptors; `userns_not_blocked` when a nested user namespace can still be created. A refused start logs exactly one `ERROR isolation problem=<word>` line, at boot as well as for a run.

### Container security profile and host prerequisites

`docker-compose.yml` runs the container as `node` (uid 1000; `./agent_home` must be owned by it) with `cap_drop: ALL`, `no-new-privileges`, `pids_limit: 512`, the committed seccomp profile `security/agent-gateway-seccomp.json` (Docker's default profile plus `clone`, `unshare`, `setns`, `mount`, `umount2`, `pivot_root` for a process without capabilities) and `systempaths=unconfined`. The sandbox needs namespaces and a fresh `/proc` inside the container; Docker's default profile and masked `/proc` paths block both. This loosens the boundary between the container and the host, which is why every other control above is on. **Host prerequisites:** unprivileged user namespaces must be allowed (`kernel.apparmor_restrict_unprivileged_userns=0` on Ubuntu 24.04 and later, and `user.max_user_namespaces` above 0).

AppArmor: Docker's default AppArmor profile also blocks the sandbox's mounts. By default the compose file runs without an AppArmor profile (`apparmor=unconfined`). To keep a profile, load the committed one on the host and select it: `sudo apparmor_parser -r security/agent-gateway-apparmor`, then `AGENT_GATEWAY_APPARMOR_PROFILE=agent-gateway-isolation docker compose up -d`. Tested once (2026-10-01, Ubuntu 24.04, kernel 6.8, Docker 29.2): a task-owned container under a copy of this profile loaded with a different name (the rules are identical, only the profile name and the two self-references differ) ran in enforce mode with `isolation: ok`, and a cancelled run, `docker stop` during a run and a SIGKILL of the gateway process behaved as without a profile. The committed file under its own name, other kernels and a long-running production use are not tested. `PROBE_APPARMOR_PROFILE=<loaded profile> npm run probe:docker-isolation` repeats the check.

### Security acceptance and deployment runbook

This is the one procedure for putting an isolation-capable gateway into service, checking it, recovering it and rolling it back. It replaces the earlier "Updating a running gateway" list; every step that list held is below. Terms: this README says *sandbox* and *conversation*; the acceptance wording of the Epic MVP-7676 says "isolation runtime" (the sandbox) and "legacy-session admission" (the refusal of conversations started before the update).

**Before: decisions that must be closed (stop if any is open).**

| Decision | Where it is recorded | State when this was written (2026-10-02) |
|----------|----------------------|------------------------------------------|
| Accept the container profile: no AppArmor profile unless the committed one is selected, and `systempaths=unconfined` | Epic MVP-7676, comment 37950 | open |
| Accept that every conversation started before the update is refused (8,339 stored on the production gateway on 2026-09-30, 3,834 with a saved transcript, 1,216 used in the last 14 days; callers must start a new conversation, reqlift does not recover by itself). Not implemented: admitting them after a scan and binding each to its first caller, which keeps old conversations but lets whoever knows an id first claim it | Epic MVP-7676, comment 37950 | open |
| reqlift continuing shared (public or folder-shared) conversations | Operator ruling DEC-ISO-007 (Epic MVP-7676, comment 39462): a conversation belongs to the API-key label, so any `user_id` of the label continues it; delivered by MVP-8044 (supersedes comment 38039) | decided |
| Review of what agents planted before the update (see Known residuals; MVP-7948 owns the open part) | this runbook, Prepare step 2 | an operator task before the first deploy |

Check the comments before deploying; the table is a snapshot.

**Prepare.**

1. `./agent_home` and everything below it must be owned by uid 1000 (`sudo chown -R 1000:1000 agent_home`). The old entrypoint ran `chown -R` as root; the new one does not, and a root-owned file is left out of runs with an `audit` log line only.
2. Review and remove what agents planted in `agent_home` before the update. The global-entry secret scan now hides verbatim planted copies of known credential values, SSH private-key lines and webhook URL credentials at every start, but it does not find transformed copies, so review those too. The gateway's own trusted `git` calls and `/v1/auth/login` (tmux) still run with `HOME=/home/node` and read `~/.gitconfig`, repository hooks, `core.fsmonitor` in a repository's configuration and `~/.tmux.conf` (MVP-7948 owns this, it is not fixed): review and remove those files.
3. Tag the image that runs now, so a rollback target exists: `docker tag agent-gateway-agent-gateway:latest agent-gateway:rollback-$(date +%Y%m%d)-<first 12 characters of its digest>` (the digest: `docker image inspect --format '{{.Id}}' agent-gateway-agent-gateway:latest`). See **Rollback** for which images are valid targets.
4. Set `MCP_SERVER_OWNERS=<server>:<label>,...` for every registered MCP server that exists today (live: `jira:reqlift`), and change `AGENT_TOOL_POLICY` and `API_KEYS` together: a label named in the policy that is missing from `API_KEYS` stops the gateway at startup (`FATAL config key=AGENT_TOOL_POLICY reason=label not in API_KEYS`) and the restart policy then loops.
5. Check that no run is in flight, as a separate step before the swap (a swap kills running queries; the 2026-09-28 deploy lost one publish run this way).
6. **Registry URL inventory (MVP-7957).** Before the swap, run `npm run build && node scripts/registry-url-inventory.mjs <MCP_SERVERS_PERSIST_PATH>` (read-only; it prints `name<TAB>category` and a count line, never a URL; exit 0 = nothing to migrate, 3 = at least one entry needs it, 2 = unreadable file). Each listed entry keeps working for runs but is withheld from every registry reply with `urlMigrationRequired: true` until its owner sends a compliant URL: move the credential to a header, an env value or a per-user override and re-register the address without user info, query or fragment. An upstream that needs a secret-bearing URL is recorded as unsupported, not exposed. Then review the paths of the compliant entries through `GET /v1/mcp-servers` (the URL is public by contract) for an embedded token, and rotate any that holds one. The legacy file is never rewritten by the gateway, so the inventory can be rerun after each migration.

**Swap.** `docker compose build && docker compose up -d` in the checkout. Never chain it with the in-flight check.

**Verify.** Each read-back with its expected output; names and counts only, never a value:

| Check | Expected |
|-------|----------|
| `curl -s http://localhost:3001/health \| jq .isolation` | `"ok"` (the container is then also `healthy`) |
| `docker logs agent-gateway 2>&1 \| grep 'mcp.registry.ownerless'` | `mcp.registry.ownerless count=0 names= saved=true` (another count lists the names that stay ownerless; `saved=false` means an assignment could not be written to the state file) |
| `docker logs agent-gateway 2>&1 \| grep 'mcp.registry.owner_'` | one `owner_assigned serverName=<name>` line per mapped name (`owner_mapping ... result=already_assigned` on a later restart) |
| `jq '.[] \| select(.name=="jira") \| .owner' <MCP_SERVERS_PERSIST_PATH>` | the mapped label |
| `docker logs agent-gateway 2>&1 \| grep 'mcp.registry.url_migration_required'` | no line once every entry is migrated; each line names an entry (`serverName`) and a category (`reason`), never a URL |
| `/health` `persistence` is ok and no new `mcp-servers.json.corrupt-*` file exists | after a `corrupt-preserved` issue for `mcpServers`, restore the preserved copy before normal use: an empty registry lets any label create any name |
| `docker image inspect --format '{{.Id}}' agent-gateway-agent-gateway:latest` | equals `image.id` in the evidence JSON of the revision you built (`npm run probe:epic-integration` writes it) |

The first message of a conversation that starts an `npx` MCP server can be slower: that run's home is empty, so the package is downloaded again (about 7 s for a small server).

**Callers.** Re-register the webhook tools so each records its owner (reqlift does it at boot, diemcrm with `RegisterGatewayToolsCommand`), then read back that `GET /v1/tools` shows no entry without an `owner` and that no `tools.legacy.ownerless count=<n>` line with `n > 0` appears after a restart; the audit line `tool.webhook.legacy_forward` must have count 0 since the update. reqlift's admin edits of an ownerless MCP server are refused with 403 until the mapping is applied. Expect reqlift's admin tool success rate to drop: failed calls stop counting as successes (`"success": false`).

**Done when:** `/health` isolation is `ok`, the three registry and tool read-backs above are as expected, the image digest equals the tested digest, both callers registered their tools, and a caller's new conversation answers.

**No secret probe is run against the live gateway.** The acceptance evidence is the task-owned deployment of the same image (`npm run probe:epic-integration`); a probe with real credentials on the live service would put them in front of a test agent, and rotating shared test credentials is out of scope (DEC-ISO-002).

**Recovery.** What a caller sees and what the operator does:

| Symptom | What callers see | Operator action |
|---------|------------------|-----------------|
| `/health` `isolation` is `starting` | nothing yet (a few hundred ms) | wait |
| `isolation` is `unavailable` (log line `ERROR isolation problem=<word> reason=<fixed text> (see /health)`) | every query ends with "The gateway cannot start a protected workspace ..."; nothing runs unsandboxed | read the `problem` word in [`/health` and the compose health check](#health-and-the-compose-health-check) and fix the profile, the storage directory or the host setting it names; the next successful sandbox start clears it (`proxy_unavailable` only a restart) |
| the container keeps restarting; `docker logs` ends in `FATAL config key=<KEY> reason=<fixed text>` (`AGENT_TOOL_POLICY`, `AGENT_MCP_TOOL_TIMEOUT_MS`, `SESSION_IDLE_TIMEOUT_MS`, `MCP_SERVER_OWNERS`, `MODEL_PROXY_IDLE_TIMEOUT_MS`, `ISOLATION_STARTUP_TIMEOUT_MS`, `AGENT_RUN_TIMEOUT_MS`, `AGENT_SANDBOX_ROOT`) and `docker inspect --format '{{.RestartCount}}' agent-gateway` keeps rising | connection refused or a proxy error (a restart loop answers nothing for long) | fix the value the line names and `docker compose up -d`; the loop ends at the next start |
| `ERROR persistence ... problem=<word>` | requests work; the named state is not saved or was set aside (`.corrupt-*`) | see [Stopping and recovery](#stopping-and-recovery): restore the preserved copy, check disk space and the owner of `./agent_home/.claude` |
| the gateway restarted or was stopped during a run | the stream ends without a `done` event (the killed process cannot send a terminal event; the stream contract is unchanged); a replay of that query id answers "Query not found or expired" | resume the conversation with a new request: it runs inside a fresh sandbox |
| the gateway is stopped on purpose | connection refused until it runs again | decide beforehand; callers must tolerate it |

**Rollback.** A valid rollback target is an image whose commit and digest passed this acceptance suite and both Docker probes: the revision that contains the isolation (S1), the tool mediation (S2) and the registry ownership (MVP-7925) together, identified by the tag and digest recorded in step 3 of Prepare and in the evidence JSON, **not by `/health` alone**. An image with the isolation only also reports `isolation: ok`, but it puts MCP credentials on the runtime command line and ignores `AGENT_TOOL_POLICY`. A revision from before the isolation is not a rollback target: it restores unrestricted agent execution. Stop the gateway instead (`docker compose stop`) and decide explicitly.

To roll back to a recorded tag: `docker tag agent-gateway:rollback-<tag> agent-gateway-agent-gateway:latest && docker compose up -d --no-build`, then repeat the **Verify** table (isolation `ok`, the digest equals the digest recorded for that tag).

At the first deploy of this Epic no valid target exists. Recovery is then to stop the gateway (`docker compose stop`) and fix forward; callers see connection refused while it is stopped, and the operator decides that before deploying.

Data effects of moving between revisions of the Epic: an older version ignores and then drops the `sessionsByLabel` map of `sessions.json`, so conversations started or moved under the newer version start fresh; registered tools and MCP servers keep their `owner` field, which older versions do not use (they would let any label change or delete a registered server).

**Running the acceptance (pre-merge checks).** There is no CI in this repository: the required checks are these commands, run by the author before a merge and recorded in the pull request. `npm run build && npm test` for every change (the real-process security files are part of `npm test`). In addition both Docker probes, `npm run probe:epic-integration` and `npm run probe:docker-isolation`, for every change that touches one of these paths: `src/sandbox*.ts`, `src/agent.ts`, `src/model-proxy.ts`, `src/mcp-*`, `Dockerfile`, `docker-compose.yml`, `entrypoint.sh`, `security/*`, `scripts/*probe*`. Expected durations on the development host: the security regression and entry-point files about 8 minutes together, the failure file about 1.5 minutes, each Docker probe about 3 to 4 minutes including the image build; the full `npm test` takes longer than all of them (the evidence record of a revision names its measured time). Host prerequisites: Linux, `bwrap`, unprivileged user namespaces, `unshare`, `git`, `python3` and `perl`; for the probes also uid 1000, `sudo -n docker` and 2 GiB free in the temp directory. A missing prerequisite fails with a fixed `host prerequisite missing: <name>` line; a suite never skips. Run heavy checks through the workflow kit's `scripts/run-verification.mjs --wait --cwd <worktree> -- <command>` from a detached worktree at the committed revision, so an edit while a run waits in the queue cannot invalidate it (the runner serializes expensive runs across sessions of the same user).

**Reading the evidence.** Every security row prints one line; the suites and the probe print only case names, booleans and counts, never a secret value:

```
grep -a '^SECURITY-' <runner log>          # SECURITY-EVIDENCE (revision, tree, runtime versions, non-secret configuration, deadlines), SECURITY-MATRIX (one per row: id, expected, observed, result, hits, duration, deadline, controls, surfaces with byte counts) and SECURITY-SUMMARY (expected rows, observed rows, pass, fail, missing ids)
```

A deliberately vulnerable negative control reads `expected=fail observed=fail result=pass`. A clean run has `fail=0 missing=none` in every `SECURITY-SUMMARY`. The Docker probe writes an evidence JSON (revision, image digest, configuration, every row and an overall verdict) and ends with `EPIC-INTEGRATION-RESULT verdict=PASS`.

### Behavior changes

- The global directories and repositories are **read-only for agents**: an agent can no longer write to `~/.claude/memory`, `skills`, `agents` or a repository. The workspace API (`PUT /v1/memory/*`, git routes) stays the write path. A prompt that tells an agent to update memory files there fails until it uses the API.
- An agent has no `~/.ssh`, and there is no agent-side ssh mediation (no caller uses it).
- `claude auth status` no longer exists in the bundled CLI: `GET /v1/auth/status` is read from the credential files and returns the same fields; login runs the CLI bundled with the SDK, never `~/.local/bin/claude`. The entrypoint no longer installs a Claude CLI and no longer runs as root.
- `GET /v1/sessions` lists only the caller's label (plus ownerless pre-update entries) and `count` is that number; `/health` `sessions` stays the total of usable conversations (erasure-pending ones are counted in `erasurePending`).
- `DELETE /v1/sessions/:id` erases the conversation's folder (MVP-7402): 200 only when it is gone, 503 `erasure_pending` while the gateway still has to finish it, 409 `legacy_not_erased` for a pre-update conversation (it answered 200 for every entry before, without touching any file).
- A conversation belongs to the API-key label (DEC-ISO-007, MVP-8044): any `user_id` of the label continues it, including a request without one. The former refusal of another `user_id` of the same label no longer exists; only another label (own new conversation), a pre-update conversation (legacy text) and a busy conversation (busy text) are answered differently.
- **Tool mediation (MVP-7679):**
  - `allowedTools` now narrows the trusted grant instead of only pre-approving tools; `[]` means no tool at all.
  - A `tool_result` event of a failed call carries `"success": false`. reqlift's admin tool success rate will drop after the deploy because failed calls stop counting as successes.
  - Failed tool calls end in the fixed `TOOL_*` texts (see [Tool errors](#tool-errors)); the refusal text of `enforcedTools` is the `TOOL_DENIED` text (it was `Refused: this tool is not allowed for this run.`).
  - `AGENT_MCP_TOOL_TIMEOUT_MS` adds an overall deadline (default 600 s) to a mediated MCP `tools/call`; the relay used to have only its 120 s no-progress timeout, which stays.
  - The relay buffers and validates upstream answers and returns each as one JSON message; it forwards only methods the grant allows.
  - Conversations and the event cache are keyed by API-key label: another label cannot see or replay them.
  - A request `mcpServers` entry named like any registered server (enabled, disabled or left out of the run) answers 400 `MCP_SERVER_NAME_CONFLICT`. Registering a server named like a caller's request server makes those requests fail.
  - `allowedToolsPattern` of a registry server has no authorization effect (it only pre-approves).
  - Stdio MCP servers run in their own tool sandbox and see only `/usr` and the system directories, so their command must live there.
  - Registered webhook tools record an `owner`; a run is offered only its own label's tools plus legacy ownerless ones.
  - Registered MCP servers record an `owner` (the registering label); only the owner may change or delete one (403 `MCP_SERVER_OWNER_MISMATCH`), see [Registry ownership](#registry-ownership). Servers registered before the update are ownerless: refused for every label, left out of runs that carry a user credential for them and refused on credential-bearing `/call`, `/test` and `/uploads/*` until the operator mapping `MCP_SERVER_OWNERS` assigns an owner.
- Workspace listings (`GET /v1/memory`, `/v1/agents`, `/v1/skills`, `/v1/knowledge-base`) and user-skill bundles list and copy regular files only (a symlink is neither listed nor followed).

### Known residuals

- The sandbox shares the network namespace: agent code can reach network peers, credential-free MCP servers and the gateway's public port (where it gets 401 without a key). Loopback listeners of the proxy and relay need a run token.
- There is no agent-side ssh mediation (no caller uses it).
- Registry ownership (MVP-7925) covers `PUT` and `DELETE` only. `POST /v1/mcp-servers/:name/restart` stays callable by any label (it keeps the stored definition and can only switch a disabled server back on). Any label's run or direct call may still use another label's owned server with its own users' credentials (today's sharing). The stored `headers`, `env` and stdio `args` are write-only (MVP-7936, MVP-7957, see [Stored headers, env and args are write-only; the URL is public](#stored-headers-env-and-args-are-write-only-the-url-is-public)). When an owner deletes its server another label may register the same name.
- Content planted before the deploy: the global-entry secret scan covers files up to 64 MiB, the `$HOME/.ssh` private-key lines and webhook URL credentials (MVP-7919), as verbatim copies only (the limits are listed in the sandbox content section above). The gateway's own trusted `git` calls and `/v1/auth/login` (tmux) still run with `HOME=/home/node` and read configuration an agent planted there before the update (`~/.gitconfig`, repository hooks, `core.fsmonitor`, `~/.tmux.conf`); the sandbox-side git reads were closed by MVP-7679, the gateway-side ones are owned by MVP-7948 and not fixed. The operator reviews or removes that content before the first deploy.
- Registry URLs are public configuration (MVP-7957): every authenticated label reads the full `url` of a compliant entry, path included. The gateway cannot tell a token in a path segment from a path, so a credential placed there is exposed to every label; review the paths of existing entries (see the runbook step "Registry URL inventory"). An upstream that needs a secret-bearing URL is unsupported by this contract.
- A retarget keeps the stored credential (accepted limit, MVP-7958, decided 2026-10-03): an owner `PUT` that changes the `url` (any part, including https to http) or a stdio entry's `command` or `args`, and omits the stored `headers` / `env`, keeps them, and the gateway sends them to the new destination on the next use by any label. Stored http/sse `headers` go to the new address on `/health` (to `<origin>/health`), `/test`, `/call`, the upload relay and runs; stored stdio `env` reaches the new command in runs only. Any label can cause that delivery: `/health` is authenticated by API key but has no owner check, and an enabled server is attached to every label's runs, so the owner needs no further step. Per-user credentials that callers send for that server follow the new destination too, except reqlift OAuth tokens, which reqlift binds to the exact registered URL. It applies to the owning application (including an owner assigned to a legacy entry through `MCP_SERVER_OWNERS`) and to admins, because the reqlift edit form sends no maps; other labels get 403 (MVP-7925). It is no wider than before MVP-7936, when the owner could read the values. Send the map to set it deliberately or `{}` to clear it. The write-only rule stops read-back, not redirection; the separate disclosure routes are MVP-7957 (see [Stored headers, env and args are write-only; the URL is public](#stored-headers-env-and-args-are-write-only-the-url-is-public)).
- At `LOG_LEVEL=debug` the request preview keeps the query string and fragment of a refused URL (only user info is redacted); the preview is an operator-only surface.
- A successful `GET /v1/mcp-servers/:name/health` returns the upstream's own health JSON to every label, so an upstream that echoes request headers in it would expose them.
- A `PUT` that changes a stdio entry's `command` and omits `args` keeps the stored `args` (the same accepted limit as a retarget under MVP-7958, see the retarget bullet above): send `args` to replace or `[]` to clear.
- Legacy webhook tools without an `owner` keep today's forwarding until they are registered again.
- A credential-free request MCP server runs inside the agent sandbox and is granted per server only: a grant that names only some of its tools is not enforced on the trusted side.
- The work area has no size cap while its conversation exists: it grows with what agents keep there until the conversation is deleted or expires. The home of a run is rebuilt only at the START of the next run, so a file an agent writes there can still be read by a process of the same run (for example a shell the agent itself starts when Bash is granted); no trusted step reads it.
- Global agents, skills and commands are trusted content (their frontmatter hooks and agent `mcpServers` execute commands for a label that is granted `Bash`): an agent cannot write them (read-only mounts, an empty trusted stand-in when the workspace has none), but any API-key holder can write global agents and skills through `PUT /v1/agents` and `PUT /v1/skills`, and those load in ordinary runs, so a file saved by one label runs its commands in the runs of every label that holds the `Bash` grant. A run whose label is not granted `Bash` ignores those settings (MVP-8106, see [Tool mediation](#tool-mediation)); this is reachable by callers, not by agent code.
- A conversation's home is removed only when the conversation is deleted or expires; there is no size cap on a home or a private `/tmp`, and `pids_limit` is shared by all runs: an availability risk, not a credential exposure.
- Erasure removes the conversation's folder (MVP-7402). It does not reach: the in-memory event replay cache (the owner can replay a finished query's output for `EVENT_CACHE_TTL_MS`), runtime output at `LOG_LEVEL=debug`, `sessions.json.corrupt-*` copies of a state file that was set aside, and run-log directories a crashed gateway left (swept at the next start).
- A `sessions.json` that is set aside (MVP-7616) loses its erasure-pending entries and erased markers: the folders of pending conversations then have no entry (orphans; MVP-8166 owns that cleanup) and `/health` shows `persistence: degraded`. If the first save of a new tombstone fails it stays pending in memory and every sweep saves it again; if the folder is gone but the save of the completed erasure fails (reported by `/health` `persistence`), a restart may bring the content-free entry back, and its next DELETE answers 200 because the folder is absent. Erased markers keep only label, client id and time and are never removed, so `sessions.json` grows slowly with every erased conversation.
- Chats from before the isolation update (the old shared store) and conversation folders without an entry are not erased by this gateway (MVP-8166). A conversation whose folder was never created on a store that has no `sessions` directory yet answers 503 to DELETE until that directory exists, because a missing directory is never read as erased.
- An ownerless pre-update conversation id stays visible: a refusal versus a fresh conversation reveals that such an id exists.
- A conversation belongs to its API-key label, not to a person (DEC-ISO-007, MVP-8044): the application alone decides who receives a conversation id and may write in it, and everything a writer's tools returned and the text of any skill a writer invoked stays in the conversation (transcript and `/work`) and is visible to later writers of the same label. Successful relay replies are not masked; masking a run's own credential values in them is optional hardening that is not part of this contract. Per-person skills, webhook identity and credentials are not shared: they follow the request, never the stored creator.
- A client that closes its connection while a hook or an in-process tool call is in flight stops only its own run (MVP-7866): the SDK (0.1.77) answers such a call from a promise nobody awaits, and its late write after the abort raises an `AbortError` that a startup guard drops with one `[process] late abort rejection ignored` line; any other unhandled rejection still ends the process. A webhook call already in flight still reaches its webhook and its answer is discarded. An aborted request is never retried.
- The runtime in the sandbox shares the network namespace and can make its own credential-free calls to its vendor host (egress residual, TD-9 of the Epic). The acceptance records non-loopback destinations held by the gateway's processes and runs the negative controls offline; it does not block them.
- The known-value scan hides a mounted file that holds a secret value the gateway knows now. A copy of a credential value that was rotated before the run (for example an OAuth token before a refresh) is not recognized; the scan compares current values.

## Tool mediation

Every tool call that needs a credential leaves the agent sandbox through a trusted channel (the in-process webhook server, a relay binding, an SSE bridge or a stdio tool sandbox). The channel is bound to the run, so the identity and the credential come from the trusted side, never from a field the agent sends. The agent gets only the tools its grant allows.

### Tool policy (`AGENT_TOOL_POLICY`)

One JSON object in the environment, per API-key label (single-quote it in `.env`):

```json
{
  "default": { "allow": ["Read", "Grep", "mcp__agent-gateway-tools__*"] },
  "labels": { "cicd": { "allow": ["Read", "mcp__jira__*"], "deny": ["mcp__jira__delete_issue"] } }
}
```

- An entry is a built-in tool name of the bundled runtime (Claude Code 2.1.292, case-sensitive: `Agent`, `Bash`, `CronCreate`, `CronDelete`, `CronList`, `Edit`, `EnterWorktree`, `ExitWorktree`, `Glob`, `Grep`, `ListAgents`, `NotebookEdit`, `Read`, `ReportFindings`, `ScheduleWakeup`, `SendMessage`, `Skill`, `TaskStop`, `TodoWrite`, `WebFetch`, `WebSearch`, `Workflow`, `Write`, and `Task`, an alias of `Agent`), `mcp__<server>__*` or `mcp__<server>__<tool>`. Webhook tools are tools of the server `agent-gateway-tools`. A name the runtime does not offer as the gateway starts it (`TaskOutput`, `LSP`, `AskUserQuestion`, `EnterPlanMode`, `ExitPlanMode`, `KillShell`, `TaskCreate`, `TaskGet`, `TaskList`, `TaskUpdate`, `Artifact`, `SendUserFile`, `ShareOnboardingGuide`, `DesignSync`, `Monitor`, `PushNotification`) stops startup with `unknown built-in tool name`.
- **Approved default set (DEC-ISO-008).** Without an `allow` list a label gets exactly `Agent` (alias `Task`), `Bash`, `Edit`, `Glob`, `Grep`, `NotebookEdit`, `Read`, `Skill`, `TodoWrite`, `WebFetch`, `WebSearch`, `Write`; none of the other tools (scheduled prompts, background monitoring, messaging between agents, worktrees, workflows, `TaskStop`, claude.ai publishing tools) is offered unless a policy names it for that label. Every run passes this list to the runtime explicitly, so a runtime update cannot widen it; the gateway sets `CLAUDE_CODE_ENABLE_TASKS=false` in the runtime environment, so `TodoWrite` (the checklist reqlift shows) is offered instead of the task tools `TaskCreate`, `TaskGet`, `TaskList` and `TaskUpdate`.
- Deny beats allow (`Task` and `Agent` name the same tool). An absent `allow` means the approved default set for built-ins and every MCP server; `allow: []` means nothing. A label entry replaces `default` for that label. An empty or unset value restricts nothing beyond the approved default set.
- Startup stops with one fixed line `FATAL config key=AGENT_TOOL_POLICY reason=<reason>` for `must be a JSON object`, `unknown field`, `label not in API_KEYS`, `unknown built-in tool name` or `invalid tool pattern`. One startup audit line per label, with or without a policy, lists its effective built-in tools and server patterns (names only, never `all`).
- **Operator warning:** removing or renaming a label in `API_KEYS` while the policy still names it stops the gateway at startup; because the container restarts automatically it keeps restarting. Update both settings together.

**Effective grant** = the policy for the caller's label intersected with the caller's own narrowing (`enforcedTools`: the exact set; or `allowedTools`: names and `mcp__<server>__*` patterns). An omitted list uses the policy grant, an explicit `[]` grants no tool, and a caller can only narrow, never widen. A configured agent, skill, prompt or sub-agent never adds authority. `allowedToolsPattern` of a registry server is not part of the grant.

**How it is enforced.**

- Built-in tools run inside the runtime, so they are enforced by what the runtime is offered (`tools` and `disallowedTools`). A built-in outside the grant is refused by the runtime itself for the main agent, a configured agent, a skill, a sub-agent and a resumed conversation, even under the permission-bypass mode the gateway always uses. The runtime's own text for such a refusal is `<tool_use_error>Error: No such tool available: <name></tool_use_error>` (not changeable).
- A tool that is offered but not granted (a tool of an attached MCP server) is refused at call time on the trusted side with the `TOOL_DENIED` text, before any upstream request. A server with no granted tool is not attached.
- **A `Bash` denial also covers commands that skill, agent and command files start (MVP-8106).** The runtime starts commands on its own from the settings at the top of a skill, agent or command file: `hooks`, and an agent's stdio `mcpServers` entry with a `command`. A tool list does not cover them. For a run whose label is not granted `Bash` (the policy for the label denies it or its `allow` list does not name it; the caller's own narrowing never decides this, the same key as the request-server `command` gate above), the run sees a copy of the `skills`, `agents` and `commands` directories taken when it starts, in which every markdown file begins with a block the gateway generated: the keys `name`, `description`, `model`, `argument-hint`, `when_to_use`, `permissionMode`, `tools`, `disallowedTools`, `allowed-tools`, `skills`, `user-invocable` and `disable-model-invocation` are kept (re-encoded), `hooks`, `mcpServers` and every other key are dropped. The rest of the file keeps working: its instructions reach the model and an agent's `tools` list still narrows. The per-user skills of the request's `user_id` are written rewritten in the same way. This holds for stored files, operator-owned read-only files and the per-user plugin skills alike, for delegated agents and for resumed conversations; saving such a file stays allowed with the existing reply, the stored text is never modified, and a file saved by a label that may run commands is loaded by a label that may not without its commands. Runs with the `Bash` grant keep the live read-only directories, and these commands still run inside the isolated executor, as before. The gateway log gets one line per rewritten file and run, `command-settings.ignored label=<label> source=<skills|agents|commands|user-skills> name=<name> setting=<hooks|mcpServers|other|unparseable>`, never a path, a value or file content.
  - **Limits you may notice.** A file whose settings block cannot be read (a duplicate key, an anchor, alias or tag, tab indentation, an unterminated block) loses all of its settings; an agent without a readable `name` is then not found by the runtime. A file the gateway cannot copy safely is left out of the copy with an audit reason (`symlink`, `wrong_type`, `not_owned` or `unreadable`). A directory beyond 2000 files, 2000 folders, 10,000 entries examined or 64 MiB is copied only in part, in the order the filesystem lists it, and the gateway logs one `sandbox.content.limited` line with counts only. A file saved while a run is open is not seen by that run. Enforced runs (`enforcedTools`) load no skill or agent file. The global `plugins` directory is not loaded by the runtime with the generated settings (no plugin is enabled) and is not copied.
- Credential-free request servers that run inside the agent sandbox are granted per server only; a grant naming only some of their tools is not enforced on the trusted side.

### Where credentials go

Every registered MCP server (http, SSE and stdio) reaches the runtime only as `{ "type": "http", "url": "http://127.0.0.1:<port>/mcp/<token>" }`; the server name and every `mcp__<server>__<tool>` name stay unchanged. The relay holds the run's binding (upstream, merged credential headers, grant) until the run ends; the token is revoked at run end or cancel.

| Server | Reaches the runtime as |
|--------|------------------------|
| Registered http / SSE / stdio | Relay URL (own binding per run and server) |
| Request http/SSE server **with** `headers`, or a URL with a user name, password or query | Relay URL |
| Request stdio server **with** `env` | Relay URL; the server runs in its own tool sandbox |
| Request server without `headers` / `env` | Direct connection, or runs inside the agent sandbox |
| Webhook tools | In-process server `agent-gateway-tools`; the gateway calls the webhook |

A request-supplied `command` server is code the caller picked: it is attached only when the trusted policy lets the caller's label run `Bash` (no policy, or `Bash` not denied) or names that server in its `allow` list; otherwise it is left out with `mcp.server.omitted serverName=<name> reason=command_not_granted`. Callers must pass credentials for request servers only through `env` or `headers`, never in `args` or a URL path: those are readable by the agent (a user name, password or query in the URL is relayed, but keep credentials in `headers`). After this no registry `args`/`env`, override or request `env` value and no header reaches the runtime's command line (the old `mcp.server.credential_in_runtime_args` audit line no longer exists). If the relay is not listening, registered servers (and request servers with headers/env) are left out of the run with `mcp.server.omitted ... reason=relay_unavailable`.

**Relay message rules.** A body that does not parse as strict UTF-8 JSON (BOM, other encodings), every batch and every message without a `method` are refused locally. Only the re-serialized parsed message is forwarded, with `content-type: application/json`. Default-deny methods: `initialize`, `ping`, `tools/list` and the client notifications `notifications/initialized|cancelled|progress|roots/list_changed` are allowed; `tools/call` only with `params.name` exactly in the grant; `resources/*`, `prompts/*`, `completion/*` and anything else only when the grant covers the whole server (`mcp__<server>__*`). Every refusal is answered locally with zero upstream requests. The relay buffers and validates the upstream answer and returns it as one JSON message. For a server whose credential schema composes headers/env and a run that carries no value, `tools/call` is answered `TOOL_AUTH_UNAVAILABLE` ("no credential") before any upstream request (the handshake still goes upstream); `requireUserCredentials` omission is unchanged.

**One header merge** for relay, SSE bridge, direct call and test: the per-user value replaces the shared header of the same name in any casing. No broader-credential fallback, no OAuth login and no redirect is followed anywhere (webhook, relay, SSE bridge, direct call, test, health).

**SSE bridge.** The gateway opens the SSE stream with the run's headers and accepts the `endpoint` event only on the registered origin (otherwise the redirect text; the credential is never sent elsewhere). It answers server requests locally (`ping` with `{}`, `roots/list` with no roots, others method-not-found) and drops server notifications.

**Stdio tool sandbox.** Every registered stdio server (with or without env), stdio overrides and request stdio servers with env run in their own tool sandbox: own user, PID, IPC, UTS and cgroup namespaces, a private empty home and `/tmp`, read-only system directories only and no gateway content. The environment is the base allowlist (`HOME`, `USER`, `PATH`, `LANG`, `LC_*`, `TERM`, `TMPDIR`) plus the server's own env after overrides, never the model proxy token or URL or the run-log path. It starts with the run's first message within `ISOLATION_STARTUP_TIMEOUT_MS`, is restarted once if it dies before answering `initialize`, is killed on revoke, cancel or gateway stop (`--die-with-parent`), and its stderr is discarded. A stdio server sees only `/usr` and the system directories, so its command must live there. **Loader settings are not delivered (MVP-8020).** Every `LD_*` key (`LD_PRELOAD`, `LD_AUDIT`, `LD_LIBRARY_PATH`, `LD_DEBUG`, any other) and `GLIBC_TUNABLES` is removed from a stdio server's env before launch, whatever its source (registry, `mcpCredentialOverrides`, request `mcpServers`), and the gateway logs only the count (`mcp.stdio.loader_settings_removed count=<n>`, never a name or value). The settings would load a library into the launcher and into the in-sandbox launch wrapper before the wrapper closed its inherited descriptors. Compatibility impact: a stdio server that relied on one of these settings no longer gets it and has to be started in a way that does not need it (for example a command that sets the variable itself inside the tool sandbox, from a file in its own home, or a statically linked binary); every other env key and value is delivered unchanged.

**Deadlines.** `AGENT_MCP_TOOL_TIMEOUT_MS` (default 600 s) is the overall deadline of one mediated MCP `tools/call` (http, SSE, stdio). The relay's 120 s no-progress timeout stays. Webhook tools keep their per-tool `timeout_ms` (default 30 s), direct MCP calls keep `MCP_CALL_TIMEOUT_MS`, and the upload relay keeps its no-progress timeout with no overall deadline.

**Tool ownership.** Every `PUT /v1/tools/:name` records the authenticated API-key label as `owner` (an `owner` in the body is ignored). Another label's `PUT` or `DELETE` of an owned tool is HTTP 403 `{"error":{"code":"TOOL_OWNED_BY_OTHER_CLIENT","message":"This tool was registered by another client and can only be changed or deleted by that client."}}` (no owner name). A run is offered only its own label's tools plus legacy ownerless entries, and the calling client's gateway key is forwarded as Bearer only to tools its label owns. Legacy entries registered before the update keep today's forwarding until they are registered again (the first label that registers one claims it), with one audit line `tool.webhook.legacy_forward toolName=<name>` per such call and a startup line `tools.legacy.ownerless count=<n>`. `X-Webhook-Context` comes only from the authenticated request; tool input keys such as `context` or `user_id` stay in the body.

### Tool result size limits

The runtime decides how much of an MCP or webhook tool result the model receives. Sizes are text characters.

| Tool | Limit | Where it comes from |
|------|-------|---------------------|
| Webhook tools, other registered MCP servers, request `mcpServers` | 50,000 | The runtime default; the gateway declares nothing for these |
| The Jira server (mcp-jira, registered here as `jira`) | 250,000 | Every mcp-jira tool declares `_meta["anthropic/maxResultSizeChars"]: 250000`. It takes effect once the operator runs an mcp-jira build that carries it (see its `CHANGELOG.md`) |

- **Up to the limit** the model receives the whole result.
- **Above the limit** the runtime saves the result to a file in the conversation's private home (`projects/-work/<session>/tool-results/`) and the model receives a short notice instead. No gateway API exposes that file.
  - The notice is usually the saved-output preview: `<persisted-output>`, `Output too large (...)`, `Full output saved to: <path>` and the first 2 KB of the result. A Jira tool receives it at every size above 250,000 (3,145,728 characters measured).
  - A tool without the annotation receives a different notice far above its limit (3,145,728 characters measured): `Error: result (<n> characters across 1 line) exceeds maximum allowed tokens. Output has been saved to <path>` plus instructions to the model.
  - Both arrive as ordinary tool results: no error flag, and the `tool_result` event has no `success: false`. They are runtime texts and can change with a runtime upgrade.
- **Reaching a saved file.** The model can read it with `Read` (in parts) or `Bash`. A run whose tool set has neither, such as an [enforced tool set](#enforced-tool-set-enforcedtools) of MCP tools only, cannot read it. For such a run the Jira limit is the only way to receive a result above 50,000 characters, and above 250,000 it receives only the notice.
- The `tool_result` event shows at most the first 3,000 characters of any result, whatever its size.

Run [`tool-result-size-process.test.ts`](src/tests/tool-result-size-process.test.ts) (needs `npm run build`) to check each size class against the real runtime.

## API Overview

All endpoints except `/health` require `Authorization: Bearer <api-key>`.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check (no auth); `persistence` / `persistenceIssues` report state-file problems ([Stopping and recovery](#stopping-and-recovery)) |
| `POST` | `/v1/query` | Run an agent query (NDJSON stream) |
| `GET` | `/v1/query/:queryId/events` | Replay/resume event stream; replays only the calling API-key label's own query (another label's: 404 `Query not found or expired`) |
| `GET` | `/v1/sessions` | List the calling API-key label's active sessions (raw ids, plus ownerless pre-update entries) |
| `DELETE` | `/v1/sessions/:id` | Erase the calling label's own conversation with that id (200 once its folder is gone, 503 `erasure_pending` while the gateway finishes it, 200 again for a finished erasure of the label's own; 409 `legacy_not_erased` for a pre-update entry; another label's or an unknown id: 404) |
| `GET` | `/v1/settings` | Read-only: answers the effective settings, `{"sessionIdleTimeoutMs": <value from SESSION_IDLE_TIMEOUT_MS>}` |
| `PUT` | `/v1/settings` | Read-only: a body with a `sessionIdleTimeoutMs` field is refused with 400 `{"error": "setting_read_only"}` (nothing changes, the refusal is logged with the caller's label); any other body answers 200 with the same body as `GET` |
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
| `PUT` | `/v1/tools/:name` | Register/update a webhook tool; records the calling label as `owner` (another label's tool: 403 `TOOL_OWNED_BY_OTHER_CLIENT`) |
| `GET` | `/v1/tools` | List all registered tools (with `owner`) |
| `GET` | `/v1/tools/:name` | Get a single tool (with `owner`) |
| `DELETE` | `/v1/tools/:name` | Delete a tool (another label's tool: 403 `TOOL_OWNED_BY_OTHER_CLIENT`) |
| `PUT` | `/v1/mcp-servers/:name` | Register/update an external MCP server; records the calling label as owner on creation (another label's or an ownerless entry: 403 `MCP_SERVER_OWNER_MISMATCH`). `headers`, `env` and `args` are write-only: the reply never carries them; omitted keeps the stored value, `{}` / `[]` clears it, a non-empty one replaces it; a transport change between http/sse and stdio that would strand a stored map or args list: 400 `MCP_CREDENTIAL_MAP_INAPPLICABLE`. The `url` is public: a new or changed http/sse `url` with user info, a query string or a fragment: 400 `MCP_SERVER_URL_INVALID`; malformed `args`: 400 `MCP_SERVER_ARGS_INVALID`; a stored legacy URL that breaks the rule is withheld (see below) |
| `GET` | `/v1/mcp-servers` | List all registered MCP servers (metadata only: no `headers`, no `env`, no `args`, no owner; the full `url`, or `urlMigrationRequired: true` instead of it for a legacy entry that breaks the URL rule) |
| `GET` | `/v1/mcp-servers/:name` | Get a single MCP server (metadata only: no `headers`, no `env`, no `args`, no owner; `url` or `urlMigrationRequired` as in the list) |
| `DELETE` | `/v1/mcp-servers/:name` | Unregister an MCP server (only its owner; another label's or an ownerless entry: 403 `MCP_SERVER_OWNER_MISMATCH`, an unknown name: 404) |
| `POST` | `/v1/mcp-servers/:name/restart` | Force the SDK to reconnect to the MCP server on next query |
| `POST` | `/v1/mcp-servers/:name/test` | Test merged MCP credentials with `tools/list`; a failure answers a fixed text (stored header cannot be sent, stored address cannot be used, server could not be reached), never a stored value; an ownerless server with a caller credential: 403 `MCP_SERVER_OWNER_MISMATCH` before any upstream request |
| `POST` | `/v1/mcp-servers/:name/call` | Directly execute a registered MCP server's tool (`tools/call`, no LLM); 401 `MCP_AUTH_FAILED` before any upstream request for a `requireUserCredentials` server without a user credential; an ownerless server with a caller credential: 403 `MCP_SERVER_OWNER_MISMATCH` |
| `POST` | `/v1/mcp-servers/:name/uploads/*` | Stream a raw file upload to a registered http/sse MCP server's `/uploads/*` route (no buffering); an ownerless server with a credential header: 403 `MCP_SERVER_OWNER_MISMATCH` |
| `GET` | `/v1/mcp-servers/:name/health` | Health check for a registered MCP server; a failure `detail` is a fixed text, never a stored value |
| `POST` | `/v1/workspace/git/clone` | Clone a repository into the workspace (pulls instead when it exists); `400 Invalid branch` for a branch starting with `-`, `400 Invalid url` for a URL with a line break, `400 <field> must be a string` for a non-string `url`/`path`/`branch`/`sshKey` |
| `POST` | `/v1/workspace/git/pull` | Pull updates for a workspace repository; `400 Invalid branch` for a branch starting with `-`, `400 <field> must be a string` for a non-string `path`/`branch`/`sshKey` |
| `GET` | `/v1/workspace/git/status` | Get git status for a workspace repository |

**Workspace git:** git runs without blocking the gateway, so `/health` and running streams keep answering during a sync. Operations on the same repository run one at a time in arrival order; at most `GIT_MAX_CONCURRENCY` (default 3) run at once overall, and further requests wait in arrival order (none is rejected). Arguments are passed to git without a shell. A failed operation answers `500 {"error": "<git's message>"}` with URL credentials hidden: on each line, everything from the first `scheme://` to the last `@` is shown as `***`, so for `http://` and `https://` URLs the `user:password@` part stays hidden whatever characters the token contains (this can also hide a host or path that shares the line). `ssh://`, `git://` and `file://` transports do not use URL passwords, and ssh or git may repeat such a URL's `user:password` part in their own words (for example `Could not resolve hostname user:<password>`), which this redaction does not catch, so put tokens only into `http(s)://` URLs; a git command that exceeds `GIT_TIMEOUT_MS` (default 120 s) answers `500 {"error": "git <subcommand> timed out after <n> s"}`.

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
| `allowedTools` | string[] | no | Narrows the run's trusted tool grant to these names and `mcp__<server>__*` patterns; omitted = the policy grant, `[]` = no tool at all. A non-array or an entry that is not a non-empty string is HTTP 400 `allowedTools must be an array of tool names`. Cannot be combined with `enforcedTools` (see [Tool mediation](#tool-mediation)) |
| `enforcedTools` | string[] | no | The exact tools the run may call; every other tool is refused (see below) |
| `mcpServers` | object | no | Request-scoped MCP servers, validated and normalized on the trusted side (see [External MCP Server Registry](#external-mcp-server-registry)) |

\* Provide **either** `prompt` **or** `content`. If both are present, `content` takes precedence. If neither is present, the request is rejected with HTTP 400.

### Enforced tool set (`enforcedTools`)

`enforcedTools` restricts one run to an exact set of tools. Name each tool the way the SDK names it: built-ins as `Bash`, `Read`, …; MCP tools as `mcp__<server>__<tool>`. The gateway's registered webhook tools are served by the SDK server `agent-gateway-tools`, so a registered tool `reqlift_confluence_report_region` is `mcp__agent-gateway-tools__reqlift_confluence_report_region`. There are no wildcards.

```json
{
  "queryId": "q-1",
  "prompt": "Read the page and report each area.",
  "enforcedTools": ["mcp__jira__get_confluence_page", "mcp__agent-gateway-tools__reqlift_confluence_report_region"]
}
```

- **Refused before it runs.** Any tool call outside the set reaches no handler: no webhook request, no MCP `tools/call`, no shell command, no fetch. The model gets an error tool result (the `TOOL_DENIED` text when the gateway refuses it, or the runtime's own `<tool_use_error>Error: No such tool available: <name></tool_use_error>` for a built-in it was not offered; that text is the runtime's and cannot be changed), the `tool_result` event carries `"success": false`, and the gateway logs `audit tool.denied toolName=<name> queryId=<id>` (the name only). The run itself goes on and can end normally; deciding that a refusal fails the job is the caller's business.
- **How it is enforced** (layers, because one alone has a gap on the pinned SDK 0.1.77): no user or project settings are loaded (`settingSources: []`, so nothing in the writable HOME — settings, hooks, permission rules, `.mcp.json`, user-scope MCP servers — can widen the run); `permissionMode: "dontAsk"` with `allowedTools` set to exactly the set (an unlisted tool is denied); only the listed built-ins are offered (`tools`); `agent-gateway-tools` carries only the listed registered tools, and a registry or request MCP server is attached only when the set names one of its tools; a `PreToolUse` hook denies every other name and never answers "allow"; no per-user skill bundle is loaded.
- **Acknowledgment.** The first NDJSON event of such a run is `{"seq":0,"type":"tool_policy","enforced":true,"tools":[…]}`, echoing the set. It is sent once, before any retry, and every retry attempt keeps the same set. A caller can require it and drop the run when it is missing (reqlift does): an older gateway ignores the field and would send no acknowledgment.
- **Validation (400 before streaming):** the value must be an array (also `null` is refused) of at most 64 distinct names, each 1–128 characters of `A-Z a-z 0-9 _ -`; not together with `allowedTools`; `Task` and `Agent` are refused (whether a sub-agent inherits the set is not proven); an `mcp__…` name that fits more than one attachable server (registry names may contain `__`) is refused as ambiguous. `[]` means "no tool at all", never the default set.
- **Policy interplay.** The effective grant is the policy for the caller's label intersected with the set, so a caller can only narrow. When `enforcedTools` names a tool the policy denies, the request is accepted, the `tool_policy` acknowledgment still echoes the requested set, the gateway logs `audit tool.policy.narrowed queryId=<id> denied=<names>`, and the tool is refused at call time.
- **Large results.** A run without `Read` and `Bash` cannot read a result the runtime saved to a file; see [Tool result size limits](#tool-result-size-limits).
- **Without `enforcedTools`** the run keeps `bypassPermissions` and its other defaults, reads only the user setting source and loads the per-user bundle; its tools are the trusted grant (see [Tool mediation](#tool-mediation)).

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

### Failed queries

A failed query ends with exactly one `error` event and no `done`, and it confirms no session. The event keeps its shape `{"seq": n, "type": "error", "content": "..."}`; `content` is a safe, actionable message for the end user. The Claude runtime reports a provider rejection on its stdout before it exits with code 1; the gateway classifies that diagnostic instead of passing on the runtime's exit message (`Claude Code process exited with code 1`). Raw diagnostics (provider responses, runtime output, stack traces, headers, prompts) never appear in `content`, in any other event, or in a failure or retry log line at any log level. The debug-level request preview (see "Credentials in the debug log") is unchanged and may still contain the client's own prompt.

| Cause | Retried | `content` |
|-------|---------|-----------|
| The provider rejects the gateway's Claude runtime as too old for the model | no | `The AI runtime on the gateway server is too old for the selected model (installed 2.0.77, required 2.1.280 or newer). Ask your gateway administrator to update the gateway runtime. Retrying will not help until the administrator has done this.` |
| Authentication with the provider failed (401/403) | no | `The gateway could not authenticate with the AI provider. Ask your gateway administrator to check the gateway's authentication. Retrying will not help until the administrator has done this.` |
| Rate limit or overload (429/529) after the retry budget (3 retries, 60 s) | yes | `The AI provider is busy right now. Please try again in a few minutes.` |
| The gateway cannot start a protected workspace (the isolation runtime is missing or unusable) | no | `The gateway cannot start a protected workspace, so this request did not run. Ask your gateway administrator to check the gateway's isolation status. Retrying will not help until the administrator has done this. (reference: <queryId>)` |
| The protected workspace did not start in time (`ISOLATION_STARTUP_TIMEOUT_MS`) | no (the client may try again) | `The gateway could not start a protected workspace in time, so this request did not run. Please try again in a few minutes. If it keeps happening, tell your gateway administrator. (reference: <queryId>)` |
| The request ran longer than `AGENT_RUN_TIMEOUT_MS`, retries included | no | `The request was stopped because it ran longer than the gateway's limit of <N> minutes. Its results were not saved. Try again with a smaller task, or ask your gateway administrator to raise the limit. (reference: <queryId>)` |
| The conversation was started before the isolation update | no | `This conversation was started before a gateway security update and cannot be continued safely. Please start a new conversation. Retrying will not help.` |
| The conversation is still answering an earlier request | no (wait, then repeat) | `This conversation is still answering an earlier request. Please wait until it has finished, then try again.` |
| Anything else, including a missing or unreadable diagnostic | no | `The AI request failed on the gateway for an unknown reason. Please try again. If it keeps failing, ask your gateway administrator to check the gateway logs (reference: <queryId>).` |

In the version message each version is named only when it is known and valid (`x.y.z`): with only the installed one the parenthesis reads `(installed 2.0.77; a newer version is required)`, with only the required one `(required 2.1.280 or newer)`, and without either it is left out. The reference is left out when the `queryId` is not 1–128 characters of `A-Z a-z 0-9 . _ : -`. A client abort keeps the SDK's abort text. The next query with the same `sessionId` after a failed first query starts a fresh conversation. The gateway logs one line per failure with safe fields only: `Error queryId=<id> kind=<runtime_version_unsupported|authentication|transient|unknown|isolation_unavailable|isolation_timeout|run_deadline> apiStatus=<n|none> providerType=<known type|other|none> installed=<version|none> required=<version|none> errorClass=<class|other|none> errno=<code|other|none> exit=<integer|none> signal=<name|other|none>`. The last four fields tell an administrator why an `unknown` failure happened; the `queryId` is the reference the user was given.

| Field | Meaning and trusted source | `none` | `other` |
|-------|----------------------------|--------|---------|
| `errorClass` | The class of the error the gateway caught, from the error's prototype: one of `Error`, `TypeError`, `RangeError`, `SyntaxError`, `ReferenceError`, `EvalError`, `URIError`, `AggregateError`. A runtime process that ended gives `Error` (the SDK's own exit error). | Nothing was thrown: the runtime reported an error result, or the gateway ended the run itself because the launcher was signaled from outside | Any other class (a custom class, a non-error value) |
| `errno` | The system error code in the caught error's `code` property, only when it is a standard operating-system name such as `ENOSPC` (no space left on device); see the system's errno list (`man errno`). | The error has no `code` | A `code` that is not a standard name |
| `exit` | The exit code of the sandbox launcher process (`bwrap`), as an integer, read from the gateway's own process handle. It is the launcher's code, not a claim about the runtime's own code: a runtime ended by a signal inside the sandbox appears as `128 + signal number` (137 = SIGKILL, often out of memory; 143 = SIGTERM; 139 = SIGSEGV; 134 = SIGABRT), and a runtime that itself exits above 128 looks the same. Code inside the sandbox can influence this integer. | No exit code is known (the process has not exited, ended by a signal, or was stopped by the gateway's own cleanup) | not used |
| `signal` | The signal name that ended the launcher process itself, only when it is a standard signal name and something other than the gateway ended it. A runtime killed inside the sandbox shows `exit=137`, not `signal=SIGKILL`. | No signal ended the launcher, or the gateway's own cleanup stopped it | A signal that is not a standard name |

Each field is evaluated on its own: an unrecognized value in one field never hides a valid value in another. No field is read from an error message, runtime output, a provider response or a provider-supplied code. If the launcher is ended by a signal from outside (for example `kill -KILL` of the sandbox process), the gateway ends the run itself about one second after the launcher exit, whether or not the runtime's output is still open and whether or not the SDK has noticed: the client gets the one unchanged unknown-failure `error` event and the log gets one line with `signal=<name>`. When the SDK reports its own exit error inside that second, the line shows `errorClass=Error` as for any other runtime end; when the gateway detected the end, the SDK had said nothing and the line shows `errorClass=none errno=none exit=none`. A later SDK result changes nothing. The gateway's own endings (a client abort, the run deadline, its cleanup kill) are never reported this way.

### Tool errors

A failed tool call reaches the model as an error tool result with one of five fixed texts, and the `tool_result` event carries `"success": false`. The texts carry no upstream body, header, URL or secret (`<name>` is the server or tool name).

| Code | When | Text |
|------|------|------|
| `TOOL_DENIED` | The tool or MCP method is outside the grant | `TOOL_DENIED: This tool is not allowed for this request. Do not retry; continue without it or tell the user.` |
| `TOOL_AUTH_UNAVAILABLE` | No credential was provided for a server that needs a per-user credential | `TOOL_AUTH_UNAVAILABLE: No credential for "<name>" was provided with this request. Ask the user to connect their account; retrying will not help.` |
| `TOOL_AUTH_UNAVAILABLE` | The upstream refused the user's credential | `TOOL_AUTH_UNAVAILABLE: "<name>" did not accept the user's credential. Ask the user to reconnect their account; retrying will not help.` |
| `TOOL_AUTH_UNAVAILABLE` | The upstream refused the gateway's/shared credential, or a webhook refused the gateway key | `TOOL_AUTH_UNAVAILABLE: "<name>" did not accept the gateway's credential. Ask your gateway administrator to check this tool's credential; retrying will not help.` |
| `TOOL_UNAVAILABLE` | Connect error, DNS, reset, 5xx, 429, 408 | `TOOL_UNAVAILABLE: "<name>" could not be reached or failed. Try again later; if it keeps happening, tell your gateway administrator.` |
| `TOOL_UNAVAILABLE` | Redirect refused | `TOOL_UNAVAILABLE: "<name>" tried to send the request to another address, which the gateway does not allow. Tell your gateway administrator; retrying will not help.` |
| `TOOL_TIMEOUT` | No answer within the deadline | `TOOL_TIMEOUT: "<name>" did not answer within <N> seconds. Try again later or with a smaller request; if it keeps happening, tell your gateway administrator.` |
| `TOOL_RESPONSE_INVALID` | A 2xx answer that is not valid JSON-RPC, JSON or event stream, or is over the 25 MiB cap (webhooks: 8 MiB) | `TOOL_RESPONSE_INVALID: "<name>" sent an answer the gateway could not read. If it keeps happening, tell your gateway administrator.` |

Webhook tools and http/SSE bindings can produce every row. For stdio the gateway can observe only `TOOL_DENIED`, `TOOL_UNAVAILABLE` (the server failed to start or exited), `TOOL_TIMEOUT` and `TOOL_RESPONSE_INVALID`; a stdio server's own authentication failure is its tool-level `isError` result.

A tool's own answer is not a mediation failure: an MCP `isError` result passes through unchanged, and a webhook 4xx other than 401/403/408/429 reaches the model as `The tool rejected the request (HTTP <status>): <message>`, where `<message>` is, in order, `error.message`, a string `error`, `message` of a JSON body, else a text/plain body, at most 500 characters, control characters removed and known secret values masked. Successful upstream answers pass through unmasked: an upstream that echoes its own credential in a success answer is outside the gateway's control.

## Authentication

API keys are configured via the `API_KEYS` environment variable:

```bash
API_KEYS=myapp:sk-abc123,cicd:sk-def456
```

Each entry is `label:secret`. The label appears in server logs for audit purposes, scopes sessions, the event cache and registered tools, and is the key of `AGENT_TOOL_POLICY`. Removing or renaming a label while the policy still names it stops the gateway at startup; update `API_KEYS` and `AGENT_TOOL_POLICY` together. Send the secret as a Bearer token:

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
| `SESSION_IDLE_TIMEOUT_MS` | `0` | Auto-expire idle sessions (0 = disabled); read once at start, a whole number of milliseconds, anything else (`30m`, `1e6`, `-5`) stops startup with `FATAL config key=SESSION_IDLE_TIMEOUT_MS`; it cannot be changed over the API, and a value saved in `sessions.json` by an earlier version is ignored. Every conversation idle longer than this is erased irreversibly, folder included |
| `SESSION_ERASURE_RETRY_MS` | `60000` | Interval of the sweep that finishes pending erasures and takes idle conversations; a positive whole number of ms, anything else stops startup (`FATAL config key=SESSION_ERASURE_RETRY_MS`) |
| `SESSION_PERSIST_PATH` | `./data/sessions.json` | Session persistence file (Docker: `/home/node/.claude/sessions.json`) |
| `EVENT_CACHE_TTL_MS` | `1800000` | Query event cache TTL in ms (30 min) |
| `WORKSPACE_ROOT` | `$HOME/.claude` | Root dir for memory/agents/skills |
| `TOOLS_PERSIST_PATH` | `./data/tools.json` | Tool registry storage (Docker: `/home/node/.claude/tools.json`) |
| `MCP_SERVERS_PERSIST_PATH` | `./data/mcp-servers.json` | MCP server registry storage (Docker: `/home/node/.claude/mcp-servers.json`) |
| `MCP_TEST_TIMEOUT_MS` | `10000` | Per-test deadline for `POST /v1/mcp-servers/:name/test` |
| `MCP_CALL_TIMEOUT_MS` | `10000` | Per-call deadline for `POST /v1/mcp-servers/:name/call` |
| `MCP_UPLOAD_IDLE_TIMEOUT_MS` | `60000` | No-progress timeout for one relayed upload (`POST /v1/mcp-servers/:name/uploads/*`); no overall deadline |
| `AGENT_MCP_TOOL_TIMEOUT_MS` | `600000` | Overall deadline of one mediated MCP `tools/call` in an agent run (http, SSE, stdio); empty = default; invalid value stops startup |
| `AGENT_TOOL_POLICY` | -- | Tool grant per API-key label (JSON); empty = the approved default built-in tools for every label; see [Tool mediation](#tool-mediation) |
| `MCP_SERVER_OWNERS` | -- | Deploy-step mapping `<server>:<label>,...` assigning the owner of ownerless registered MCP servers at startup; malformed value stops startup; see [Registry ownership](#registry-ownership) |
| `ISOLATION_STARTUP_TIMEOUT_MS` | `10000` | A sandbox must pass its start check within this time; see [Agent isolation](#agent-isolation) |
| `AGENT_RUN_TIMEOUT_MS` | `7200000` | Deadline of one query request, retries included; ends the request at most about 2 s after the limit even when the runtime does not stop |
| `MODEL_PROXY_IDLE_TIMEOUT_MS` | `600000` | No-progress timeout of one proxied provider request |
| `AGENT_SANDBOX_ROOT` | `$HOME/.agent-sandbox` | Trusted storage of the sandbox homes |
| `AGENT_SANDBOX_BWRAP` | `/usr/bin/bwrap` | Path of the isolation runtime |

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
npm start      # node --expose-gc dist/server.js (the upload relay's memory bound needs --expose-gc)
```

### Testing

```bash
npm test            # Unit tests (vitest, excludes E2E)
npm run test:e2e    # E2E tests (requires running Gateway + GATEWAY_API_KEY env var)
```

The security acceptance suite (MVP-7677) proves that the isolation holds and that permitted work still works: `security-matrix.test.ts` (the harness: detector, evidence lines, route probes, samplers), `security-regression-process.test.ts` (the normal-chat route and the eight secret routes in fresh, resumed and restarted execution, leftovers, and the negative controls: child runs against deliberately vulnerable copies of `dist/` that must exit nonzero), `security-entrypoints-process.test.ts` (ordinary chat, configured agent, skill chat, delegated sub-agent, direct MCP call, upload relay, the denied-tool branch and grant-enlargement attempts) and `security-failure-process.test.ts` (the seven injected failures, each confirming that the run reached its boundary first, plus three rows that end a run holding a `setsid nohup` tool child by completion, cancellation and gateway SIGKILL and require the whole run to be gone from the host; `sandbox-process.test.ts` adds the same child at SandboxRun level, including gateway SIGKILL right after the sandbox started, and negative controls). `npm run probe:epic-integration` runs the same route probes against the built image in a task-owned container with representative reqlift and diemcrm callers; see the [runbook](#security-acceptance-and-deployment-runbook) for how to run, read and gate on them. The isolation tests (`sandbox-process`, `session-isolation-process`, `isolation-outcome-process`, `model-proxy-process`) start the compiled gateway, the real Claude runtime and real `bwrap`: run `npm run build` first, and run them on a host that allows unprivileged user namespaces. `npm run probe:docker-isolation` builds the image and checks the same isolation inside task-owned containers started with the security options of `docker-compose.yml` (it needs `sudo -n docker`, uid 1000, and removes only what it created); `npm run probe:docker-stop` does the same for the clean stop.

The E2E suite (`src/tests/e2e-*.test.ts`) runs against a **live, Anthropic-authenticated** gateway and is excluded from the fast unit gate. Each E2E file gates itself on `GATEWAY_API_KEY` (the gateway Bearer token) and **skips cleanly** when it is absent, so `npm run test:e2e` is safe to run in any environment:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GATEWAY_API_KEY` | Yes (to run) | — | Gateway Bearer token. Absent ⇒ the E2E suite skips, no failure. |
| `GATEWAY_URL` | No | `http://127.0.0.1:3001` | Base URL of the running gateway. |

E2E suites:

- `e2e-session.test.ts` — session continuity / isolation across queries.
- `e2e-user-skills.test.ts` — per-user skills Outcome Probe: a skill registered under user A is autonomously invoked by the real LLM and appears in A's `skills_loaded` NDJSON event, while it is invisible to user B (absent from B's `skills_loaded`, never invoked). Test users use the reserved `e2e-skills-` prefix and are cleaned up (DELETE + reconcile-empty) on pass and fail.

```bash
# Run the live E2E probe against a running gateway:
GATEWAY_API_KEY=<key> GATEWAY_URL=http://127.0.0.1:3001 npm run test:e2e
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
    |                              |                          +-> credential relay (grant check, bridge / tool sandbox)
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
    +-- /v1/mcp-servers (External MCP Server Registry CRUD with per-label ownership + restart + health)
```

### Tool Registry + Webhook Execution

External tools can be registered via the `/v1/tools` endpoints. Each tool defines a `webhook_url` that is called when the agent invokes the tool. Registered tools are wrapped as in-process MCP servers and injected into the Claude Agent SDK alongside the built-in tools.

The tool's `input_schema` is what the model is told about its arguments: field types (`string`, `number`, `integer`, `boolean`, `object`, `array`), `enum` values, nested `properties`/`required`, array `items` and every `description` are passed through. The gateway rejects a call that violates them before the webhook is called; the model gets a tool error naming the field and the expected type, so it can correct itself. Unsupported JSON Schema constructs (`format`, `pattern`, `oneOf`, numeric bounds, ...) make that property alone accept any value, so registration never fails because of them. Values are never converted or defaulted, undeclared top-level arguments are still dropped, and webhooks keep their own validation. Details: [docs/architecture.md](docs/architecture.md#tool-input-schemats----webhook-tool-input-schemas).

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

The calling client's Bearer token is forwarded to webhook calls for authentication, only to tools its own API-key label registered (see [Tool mediation](#tool-mediation)); a webhook call never follows a redirect, and its failures end in the fixed `TOOL_*` texts. Every tool records the registering label as `owner`, and a run is offered only its own label's tools plus legacy ownerless entries. Tools persist to disk at `TOOLS_PERSIST_PATH` and survive server restarts.

### External MCP Server Registry

In addition to webhook-based tools, the gateway can register full external MCP servers via `/v1/mcp-servers`. Unlike the Tool Registry (which wraps custom webhooks as tools), this feature embeds existing MCP servers into every Claude query so the agent can call their tools directly over the MCP protocol.

|                    | Tool Registry (`/v1/tools`)              | MCP Server Registry (`/v1/mcp-servers`)        |
|--------------------|------------------------------------------|------------------------------------------------|
| **Purpose**        | Expose custom integrations as tools      | Embed existing MCP servers                     |
| **Transport**      | HTTP POST to `webhook_url`               | MCP protocol: `http` / `sse` / `stdio`         |
| **Tool schema**    | Defined by the registrar                 | Discovered from the MCP server itself          |
| **Auth**           | Owner's client Bearer token forwarded    | Per-server `headers` / `env`                   |

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
| `url` | http/sse | Endpoint URL of the MCP server: `http(s)` without user info, query or fragment; public to every label (never put a credential in the path) |
| `headers` | no | Extra headers for http/sse requests |
| `command` | stdio | Executable to spawn |
| `args` | no | CLI args for stdio command; write-only (never returned) |
| `env` | no | Environment variables for stdio command |
| `description` | no | Human-readable description |
| `enabled` | no | Defaults to `true` |
| `allowedToolsPattern` | no | Glob of tools to pre-approve for the runtime (e.g. `mcp__jira__*`). It is **not** part of the tool grant and has no authorization effect |
| `userCredentialSchema` | no | Per-user credential fields and output templates for `headers` or `env` overrides |
| `requireUserCredentials` | no | Boolean, default `false`. When `true`, the server is attached to a run only if the run's `mcpCredentialOverrides` carries its user credential (see below). Not allowed together with `type: "sse"` |

`userCredentialSchema.fields[]` defines the form that clients render for a user's credential wallet. Field `type` must be one of `text`, `password`, `url`, or `email`; `key` values must be unique. `userCredentialSchema.outputs[]` defines how those field values are composed at query time. HTTP/SSE servers may only emit `target: "headers"` outputs, and stdio servers may only emit `target: "env"` outputs. Mismatches are rejected with `SCHEMA_TARGET_MISMATCH`.

Output templates support plain substitution (`"{fieldKey}"`, `"prefix-{a}-{b}"`) and HTTP Basic auth (`"basic:{email}:{apiToken}"`, emitted as `Basic <base64(email:apiToken)>`). The composer is transport-agnostic; the registry PUT validation enforces the transport-to-target rule before definitions are persisted.

**Server name rule:** a `PUT` that creates a new entry needs a name of 1–32 letters, digits, `-` or `_`, starting with a letter or digit (`^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$`; the Agent SDK builds tool names as `mcp__<server>__<tool>` without shortening them). Any other new name answers `400` with `{"error":{"code":"MCP_SERVER_NAME_INVALID","message":"Use 1–32 letters, digits, '-' or '_', starting with a letter or digit."}}` before any other check, and nothing is stored. An entry that already exists is never refused because of its name: a `PUT` updating it and a `DELETE` still work, so an entry created before this rule can be edited, switched off or removed.

`headers` and `env` must be string maps. Every header must be one Node can send (a token name; no CR, LF, NUL or other invalid character in the value), and env names and values must not contain NUL. `LD_*` keys and `GLIBC_TUNABLES` are accepted by the registry but removed before a stdio server is launched (see the stdio tool sandbox below). The same check applies to `mcpCredentialOverrides`, the `/test` body and the `/call` `credentials`. A violation answers `400` in each route's error style (`MCP_OVERRIDE_INVALID` outside the registry `PUT`), and the message never echoes the value.

`requireUserCredentials: true` marks a server that must run with the requesting user's own credential. A run gets such a server only when its `mcpCredentialOverrides` entry carries at least one non-empty value for the transport's target (`headers` for http, `env` for stdio) and, when the server has a `userCredentialSchema`, a value for every output key. A `headers` output key matches override headers in any casing (`authorization` is satisfied by an `Authorization` header); it counts only when at least one header matches and every matching header is non-empty, so an empty duplicate that differs only by case leaves the server out. `env` output keys must match exactly. An empty entry such as `{"aida": {}}` counts as missing. Otherwise the server is left out of that run: it is not in `options.mcpServers`, its tool pattern (custom `allowedToolsPattern` or `mcp__<name>__*`) is not in the pre-approved tools, a request `mcpServers` entry with that name is refused with 400 `MCP_SERVER_NAME_CONFLICT` (any registered name is), and the gateway logs `mcp.server.omitted serverName=<name> reason=missing_user_credential` (names only). The field is stored and returned only when sent; a `PUT` without it clears it, and `/restart` keeps it. `/test` and `/uploads/*` are not affected; `/call` answers 401 `MCP_AUTH_FAILED` without a user credential (see below).

Registered MCP servers persist to `MCP_SERVERS_PERSIST_PATH` and are attached to every `/v1/query` run through the credential relay (except a `requireUserCredentials` server when the run lacks its user credential, an ownerless server when the run carries a user credential for it (see [Registry ownership](#registry-ownership)), and a server with no granted tool). Use `POST /v1/mcp-servers/:name/restart` to force a fresh connection.

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

Per-request MCP **servers** can also be attached to a single `POST /v1/query` via the optional `mcpServers` field: an unregistered server that lives only for that one query. The gateway validates and normalizes the map on the trusted side and adds the matching `mcp__<name>__*` patterns to the pre-approved tools (subject to the grant):

```json
{
  "queryId": "q-002",
  "prompt": "Take a screenshot of the current page",
  "mcpServers": {
    "chrome-devtools": {
      "command": "npx",
      "args": ["chrome-devtools-mcp", "--browser-url=http://recon-abc:9222"]
    }
  }
}
```

Rules for each entry:

- The name matches `^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$`; `agent-gateway-tools` is reserved (400).
- A server has either `command` (stdio; it must not set `type`) or `url` (`type` only `http` or `sse`; a `url` without `type` is `http`). `headers` and `env` must be string maps with sendable values. Unknown fields are dropped. Malformed entries return 400.
- A name equal to **any** registered server (enabled, disabled or left out of the run) answers 400 `{"error":{"code":"MCP_SERVER_NAME_CONFLICT","message":...}}`, so the request can never take over a registry name or a grant written for it. Registering a server named like a caller's request server makes those requests fail.
- Request servers are merged at the lowest precedence: the gateway's `agent-gateway-tools` server and the registered servers always overlay on top. They are query-scoped only and never persisted. (Used by reqlift recon to attach a per-run chrome-devtools MCP server.)
- **Routing:** http/SSE servers **with** `headers` (or a URL with a user name, password or query) go through the relay (the runtime gets only a relay URL), stdio servers **with** `env` run in their own tool sandbox, and servers without `headers`/`env` connect directly or run inside the agent sandbox. Pass credentials for request servers only through `env` or `headers`, never in `args` or `url` (the agent can read those).

Use `POST /v1/mcp-servers/:name/test` to validate a credential set before saving or enabling it:

```bash
curl -X POST http://localhost:3001/v1/mcp-servers/jira/test \
  -H "Authorization: Bearer sk-abc123" \
  -H "Content-Type: application/json" \
  -d '{ "headers": { "Authorization": "Basic <base64(email:apiToken)>" } }'
```

Success returns `{ "ok": true, "toolCount": 2, "tools": [{ "name": "..." }] }`. Unknown servers return `MCP_SERVER_NOT_FOUND`, upstream 401/403 returns `MCP_AUTH_FAILED`, transport failures return `MCP_NETWORK_ERROR`, and timeouts return `MCP_TIMEOUT`. Error messages are sanitized and do not echo header or env values. `/test`, `/call` and the health check never follow a redirect: a 3xx is `MCP_NETWORK_ERROR` (health: `HTTP 3xx`) and the credential never goes to the target.

**Registered servers go through the credential relay:** every registered server (http, SSE and stdio) reaches the Claude runtime only as a loopback URL (`http://127.0.0.1:<port>/mcp/<token>`, one token per run and server) instead of the registered URL, headers, `args` and `env`; the relay holds the run's binding (upstream, merged headers or env, grant) and forwards what the grant allows (details in [Tool mediation](#tool-mediation)). When the server refuses the credential, the runtime never sees the refusal and never starts an OAuth login inside the gateway: a refused `tools/call` reaches the model as a `TOOL_AUTH_UNAVAILABLE` tool result, a refused `initialize` leaves that server's tools out of the run, and redirects, other errors or an unreachable server answer with the matching [tool error](#tool-errors). The relay forwards only the MCP endpoint (never `/.well-known/*`, registration, authorize or token paths), answers the GET event stream with 405, and returns only `Content-Type` and `Mcp-Session-Id` to the runtime. Tokens are revoked when the run ends or is cancelled; after that the relay sends nothing more upstream for them, and a request still in progress is closed. Observed with Claude Code 2.0.77 (not re-measured on the bundled 2.1.292): an upstream that lost its MCP session (404) makes the current tool call fail, as with a direct connection.

**The runtime's own log files are not kept:** each run gets a private directory under the OS temp directory for the runtime's debug log and MCP logs (which record connection options, including header and env values); it is deleted once the runtime process has exited, and leftovers are removed at gateway startup. `DEBUG_CLAUDE_AGENT_SDK` is ignored: the gateway removes it at startup and logs a warning, because the SDK would write its full runtime arguments, including MCP configuration, to `~/.claude/debug/sdk-*.txt`.

**Credentials in the debug log:** at `LOG_LEVEL=debug` the gateway logs request bodies (first 2000 characters) and response previews (first 500 characters). In both, the whole value of every `headers` and `env` key, at any depth, is logged as `"[REDACTED]"`; the keys stay visible (a map keeps its keys, any other shape becomes `"[REDACTED]"`). The `args` of a stdio server definition (an object with a `command` key or `type: "stdio"`) are logged as one `"[REDACTED]"` per element, because a credential can be passed on the command line (found by the MVP-7677 acceptance row at `LOG_LEVEL=debug`). At `LOG_LEVEL=debug` the log also holds the request text of every conversation (prompts, tool commands), so it is an operator-only surface. Every `sshKey` value is logged as `"[REDACTED]"`, and every string under a `url` key is logged with its credentials removed (`scheme://***@host/...`, everything from `scheme://` to the last `@`, whatever characters the token contains; git's own error text is covered only for `http(s)://` URLs, see **Workspace git**), which covers the token-bearing clone URLs and inline SSH keys of `/v1/workspace/git/*`. This covers `mcpServers[*]` and `mcpCredentialOverrides` of `POST /v1/query`, the `/test` and `/call` bodies, and registry definitions in `PUT /v1/mcp-servers/:name` bodies (the answers of `PUT` and `GET` carry no credential map). Redaction runs before the preview is shortened, so no prefix of a value can appear. Only the log copy changes: the MCP client of a run still uses the stored values (the registry routes no longer return `headers` and `env` at all, see [Stored headers and env are write-only](#stored-headers-and-env-are-write-only)). A `text/*` request body is logged as its length only, a registry answer that is not JSON is not previewed, and a request whose JSON cannot be parsed is logged as `request body rejected type=<parser error type> status=<code>` (the parser's message would quote part of the body).

### Registry ownership

Every registry entry records its owner: the API-key label of the caller that created it (a `PUT` for a new name). The owner comes only from the authenticated key (an `owner` in the body is ignored), is stored with the definition and survives a restart, and is never returned by any route.

- `PUT` and `DELETE` of an existing name succeed only for the owner. Any other label gets HTTP 403 `{"error":{"code":"MCP_SERVER_OWNER_MISMATCH","message":"MCP server \"<name>\" is registered by another application"}}`, the same for `PUT`, `DELETE`, an entry owned by another label and an ownerless entry; it never names the owner. The owner check runs before the name rule and before any body validation, so a non-owner gets the 403 for every request body the JSON parser accepts, including an invalid payload and a non-JSON content type. A malformed or oversized body is rejected earlier by the global parser (400 / 413) for every caller, without any owner information. A `DELETE` of an unknown name stays 404; a `PUT` creating a name stays 201, an owner update 200, an owner delete 204. Ownership cannot be changed through the API (no transfer). The refusal is logged for the operator as `mcp.registry.owner_mismatch serverName=<name> method=<PUT|DELETE|call|test|uploads> caller=<label>`.
- **Ownerless entries** (registered before this update) fail closed: refused on `PUT` and `DELETE` for every label (nobody can claim a name through the API), left out of a run that carries a per-user credential for them (`mcp.server.omitted serverName=<name> reason=ownerless`, no relay binding, no `mcp.override.applied` line), and refused with the same 403 on `/call`, `/test` and `/uploads/*` when the caller sends a credential (before any upstream connection). A run or call without a credential uses them as before. On those direct routes the 403 reveals that an entry has no owner to a caller that sends a credential; it cannot be used to claim it.
- **Deploy step:** `MCP_SERVER_OWNERS=<server>:<label>,...` is applied once per start, only to entries that have no owner, and written to the state file at once. Entries are trimmed, empty entries ignored, each is split at its last `:`. A malformed entry or the same server name twice stops startup with `FATAL config key=MCP_SERVER_OWNERS reason=...`. Per mapped name the log shows `mcp.registry.owner_assigned serverName=<name>` or `mcp.registry.owner_mapping serverName=<name> result=already_assigned|already_owned|unknown_label|not_registered` (an owned entry is never transferred; a label not in `API_KEYS` assigns nothing), and one summary line `mcp.registry.ownerless count=<n> names=<list> saved=<true|false>` is always written. Names containing `,` cannot be mapped and stay ownerless. See "Updating a running gateway", step 10, for the read-back.

### Stored headers, env and args are write-only; the URL is public

The stored `headers` (http/sse), `env` and `args` (stdio) of a registry entry can carry credentials that are shared by every user of the registering application. They can be set and cleared through `PUT` but are never returned (MVP-7936 for `headers` and `env`, MVP-7957 for `args`). The registered `url` is different: it is public configuration, because reqlift compares the full registered URL with its approved OAuth resource before it forwards a user's token.

- `GET /v1/mcp-servers`, `GET /v1/mcp-servers/:name` and the reply of a successful `PUT` (201 and 200) return the entry's metadata (`name`, `description`, `enabled`, `type`, `url`, `command`, `allowedToolsPattern`, `userCredentialSchema`, `requireUserCredentials`, `createdAt`, `updatedAt`) and carry no `headers`, `env` or `args` property for any label, owner included, and for an ownerless entry. The response is an allowlist of fields classified `public` in `src/mcp-registry.ts` (`MCP_FIELD_CLASS`): the owner label, the maps, the args and any key an old state file holds that no current field names are never returned, and a new field has no class (it does not compile) until someone decides; `src/tests/mcp-registry-field-class.test.ts` fills every field with a marker and fails when a field is unclassified or a non-public marker reaches a reply.
- **Update semantics of an owner `PUT`, per field:** the property omitted keeps the stored value, a non-empty string map (or non-empty `args` list) replaces it, `{}` (or `[]`) clears it (the property is removed from storage). A new registration with the property omitted stores none. A client that cannot read a field therefore cannot erase it by accident: reqlift's enable/disable toggle, its edit form and its schema editor send none of them and keep all three. The same holds across a `url` or stdio `command`/`args` change: an omitted map is kept and then sent to the new destination (accepted limit MVP-7958, see [Known residuals](#known-residuals)). An invalid map (not a string map, or a name or value that cannot be sent) keeps its 400 text and echoes nothing; malformed `args` (not a list, a non-text element, a NUL character, or `null`) answers 400 `{"error":{"code":"MCP_SERVER_ARGS_INVALID","message":"args must be a list of text values without NUL characters."}}`.
- **Transport family** (`http` and `sse` use `headers`, `stdio` uses `env` and `args`): a change between http/sse and stdio while a stored non-empty map (`headers` or `env`, including one the old transport did not use) is not named in the body is refused before any change with HTTP 400 `{"error":{"code":"MCP_CREDENTIAL_MAP_INAPPLICABLE","message":"The stored <property> map does not apply to <transport> transport: send <property>: {} to clear it or a new <property> map to replace it"}}`. The same applies to stored `args` when an entry leaves stdio: `"The stored args list does not apply to <transport> transport: send args: [] to clear it or switch back to stdio."`. Send `{}` / `[]` to clear it. The text never contains a value. `http` to `sse` keeps the family, so omitted headers stay. A stdio `PUT` ignores a `url` in its body and never stores one; a change from http/sse to stdio drops the stored URL.
- **The URL rule** (MVP-7957): a new or changed http/sse `url` must be a valid `http(s)` URL without user info, a query string or a fragment (an empty `?` or `#`, backslashes, whitespace and control characters also count). A violation answers 400 `{"error":{"code":"MCP_SERVER_URL_INVALID","message":"The server address must be an http(s) URL without a login, query or fragment. Put credentials in headers, env or per-user credentials."}}` and stores nothing; the text and the audit log never contain the URL. **The path is public:** the gateway cannot tell a token in a path segment from a path, so never put a credential in a URL path; credentials belong in `headers`, `env` or per-user overrides. An omitted `url` on a same-family edit keeps the stored one; a new entry or a change to http/sse still needs one.
- **Legacy URLs** (an entry stored before this rule): a stored `url` that breaks the rule is not returned. List, detail and `PUT` replies omit `url` and carry `urlMigrationRequired: true`; nothing derived from the URL (origin, fingerprint) is returned, and the entry is not rewritten or deleted (an authorized metadata `PUT` leaves the stored URL, args, headers and env unchanged). The gateway logs one `mcp.registry.url_migration_required serverName=<name> reason=<user_info|query|fragment|invalid>` audit line per such entry at load. An owner migrates the entry by sending a compliant `url`.
- **Failure texts** (MVP-7957): `/health`, `/test` and `/call` check the merged headers (name and value) and the address before they send anything and answer a fixed text, never a stored value and never the transport library's message: `a stored header of this server cannot be sent`, `the stored server address cannot be used` or `the MCP server could not be reached` (error codes and statuses are unchanged; the audit lines of `/test` and `/call` carry `reason=header|address|unreachable`). Authorized tool results are unchanged.
- Runs, `/call`, `/test`, the upload relay and `/health` keep using the real stored values; only the responses of the registry routes changed.
- Rotation of values exposed before this change is an operator decision outside the gateway.

### Direct tool call (`POST /v1/mcp-servers/:name/call`)

Execute a registered MCP server's tool directly, with **no LLM turn and no token cost** — the gateway opens a single `tools/call` to the upstream MCP server and returns its result verbatim. Per-call credentials override the registered server's credentials for that call only (request-scoped, never written back):

```bash
curl -X POST http://localhost:3001/v1/mcp-servers/jira/call \
  -H "Authorization: Bearer sk-abc123" \
  -H "Content-Type: application/json" \
  -d '{
        "tool": "get_issue",
        "arguments": { "issueKey": "MVP-1" },
        "credentials": { "headers": { "Authorization": "Basic <base64(email:apiToken)>" } }
      }'
```

Request body:

- `tool` (required, non-empty string) — the MCP tool name to invoke.
- `arguments` (required, object) — the tool arguments.
- `credentials` (optional) — a per-call credential override, the same `{ headers?, env? }` shape the `/test` body accepts (one entry of `mcpCredentialOverrides`, not the keyed map — the path already carries the server name). `headers` is shallow-merged for http/sse transports; `env` for stdio.

**Success (HTTP 200)** is the MCP `tools/call` result verbatim — only the JSON-RPC `result` member, no upstream envelope fields:

```jsonc
{ "content": [ /* MCP content blocks */ ], "structuredContent": { }, "isError": false }
```

A **tool-level error is still HTTP 200** with `isError: true` (the upstream call succeeded — it is the tool's result, not a gateway failure):

```jsonc
{ "content": [ /* ... */ ], "isError": true }
```

For a server with `requireUserCredentials: true` and no user credential in the call, the route answers 401 `MCP_AUTH_FAILED` ("this server requires the user's credential and none was provided") **before** any upstream request. No redirect is followed: a 3xx is `MCP_NETWORK_ERROR`.

**Gateway-level failures** (never tool errors) return the structured envelope `{ "error": { "code": "...", "message": "..." } }` and never hang past the per-call deadline:

| Condition | HTTP | `error.code` |
| --- | --- | --- |
| unknown / unregistered server | 400 | `MCP_SERVER_NOT_FOUND` |
| registered but disabled server | 400 | `MCP_SERVER_DISABLED` |
| missing/invalid `tool`/`arguments` | 400 | `MCP_CALL_INVALID` |
| invalid `credentials` override | 400 | `MCP_OVERRIDE_INVALID` |
| upstream rejects auth (401/403) | 401 | `MCP_AUTH_FAILED` |
| upstream timeout / no response | 504 | `MCP_TIMEOUT` |
| connection / transport failure | 502 | `MCP_NETWORK_ERROR` |

> **Divergence from `/test`:** `/call` rejects a registered-but-disabled server with 400 `MCP_SERVER_DISABLED` **before** opening any upstream connection. The sibling `/test` deliberately accepts disabled servers (it is a diagnostic probe for verifying credentials before enabling). `/call` is production tool execution, so the `enabled` flag gates it. Auth-middleware rejections (missing/invalid API key) return the plain `{ "error": "<message>" }` shape (401), like every other `/v1/*` route, since they fire before the route handler.

### Streaming upload relay (`POST /v1/mcp-servers/:name/uploads/*`)

Relay a raw file upload to a registered **http/sse** MCP server as a stream, with a per-call credential. The gateway is a dumb pipe: it does not parse, buffer, store or log the file. Each received chunk is forwarded and dropped, and when the MCP server reads slowly the sender is slowed down too (backpressure end to end).

```bash
CREDENTIAL=$(printf '%s' 'user@example.com:<api-token>' | base64 -w0)
curl -X POST "http://localhost:3001/v1/mcp-servers/jira/uploads/jira/issue/MVP-1?filename=shot.png" \
  -H "Authorization: Bearer sk-abc123" \
  -H "Content-Type: image/png" \
  -H "X-MCP-Credential-Headers: $(printf '{"Authorization":"Basic %s"}' "$CREDENTIAL" | base64 -w0)" \
  --data-binary @shot.png
```

is forwarded as `POST <origin of the registered url>/uploads/jira/issue/MVP-1?filename=shot.png` (for `jira` registered as `http://mcp-jira:3002/mcp` that is `http://mcp-jira:3002/uploads/...`). The MCP server's HTTP status (200–599) and body come back **verbatim** (for mcp-jira, `201 { attachmentId, mediaApiFileId, filename, size }` or its own error codes such as `401 UPLOAD_UNAUTHENTICATED`).

**Path and query:** everything after `/uploads/` and everything after the first `?` are taken from the raw request URL and forwarded byte for byte. The target is refused with `400 UPLOAD_TARGET_INVALID` when it is empty, has a `.` or `..` segment (also as `%2e`), or contains `%2f`, `%5c` or a backslash. Host and port come only from the registration.

**Headers sent to the MCP server:**

- `Authorization` from `X-MCP-Credential-Headers` — the **only** override key used on uploads; it replaces a registered `Authorization`, like `credentials.headers` on `/call`. Other override keys are dropped.
- The registered server's static headers, except `Host`, `Content-Length`, `Content-Type`, `Transfer-Encoding`, `Connection`, `Keep-Alive`, `Upgrade`, `TE`, `Trailer`, `Expect` and `Proxy-*`. Static headers of any http/sse registration therefore also travel to `<origin>/uploads/`, which matters for servers behind a path-routing proxy.
- `Content-Type` and `Content-Length` of the incoming request (a chunked request is forwarded chunked).
- Never: the gateway's own `Authorization: Bearer`, the `X-MCP-Credential-Headers` header itself.

`X-MCP-Credential-Headers` must be one header holding canonical base64 of a UTF-8 JSON object whose values are strings without CR, LF or NUL, with no two keys that differ only in case; `Authorization` must be printable ASCII. Anything else is `400 MCP_OVERRIDE_INVALID`, and the message never echoes the value.

**Errors** use the envelope `{ "error": { "code", "message" } }`; checks run in this order, all before any upstream connection:

| Condition | HTTP | `error.code` |
| --- | --- | --- |
| missing/invalid gateway API key | 401 | plain `{ "error": "<message>" }`, like every `/v1/*` route |
| unknown / unregistered server | 400 | `MCP_SERVER_NOT_FOUND` |
| registered but disabled server | 400 | `MCP_SERVER_DISABLED` |
| server uses stdio transport | 400 | `MCP_UPLOAD_UNSUPPORTED` |
| invalid `X-MCP-Credential-Headers` | 400 | `MCP_OVERRIDE_INVALID` |
| invalid target path | 400 | `UPLOAD_TARGET_INVALID` |
| MCP server unreachable or registration url not http(s) — nothing was sent | 502 | `UPLOAD_UPSTREAM_FAILED` |
| MCP server dropped the connection before answering — outcome unconfirmed, check the issue's attachments before retrying | 502 | `UPLOAD_UPSTREAM_FAILED` |
| MCP server dropped the connection after its answer headers but before any answer byte was sent to the sender — outcome unconfirmed, check the issue's attachments before retrying (a drop after answer bytes were sent truncates that answer instead, with no replacement status) | 502 | `UPLOAD_UPSTREAM_FAILED` |
| MCP server answered with a status outside 200–599 (or headers Node cannot send) — outcome unconfirmed; the upstream request is dropped | 502 | `UPLOAD_UPSTREAM_FAILED` |
| no byte from the sender and none from the MCP server for `MCP_UPLOAD_IDLE_TIMEOUT_MS` | 504 | `UPLOAD_TIMEOUT` |
| any other answer of the MCP server | its status | passed through unchanged |

**Timing and aborts:**

- `MCP_UPLOAD_IDLE_TIMEOUT_MS` (default 60000) is a no-progress timeout, not an overall deadline: every chunk from the sender and every chunk of the answer resets it, so a slow upload completes while it progresses. On expiry the upstream request is aborted; if the whole body had already been sent, the 504 message says the outcome is unconfirmed.
- Node's server-wide `requestTimeout` is 3600 s so a slow upload is not cut at 5 minutes; every other route keeps a 300 s deadline for its request body until the gateway has answered (after an early answer, such as a 401, Node's own timeouts no longer apply to the rest of that body).
- If the sender disconnects, the upstream request is aborted at once (mcp-jira then stores nothing). If the MCP server answers before the whole body was sent (an early refusal), sending stops and that answer is passed through.
- Every answer on this route carries `Connection: close`. When the gateway answers while the sender is still sending (any refusal, including the 401), it reads and discards at most 1 MiB more and closes the connection when the sender closes it or 5 s after the answer.
- The relay returns to the event loop after every forwarded chunk, so an early answer is normally read before more is written, even when a fast sender (curl) has already delivered MBs. An MCP server can still reset the connection before the gateway has read its early answer: mcp-jira refuses a missing credential at once, reads at most 1 MiB more and then closes with the rest of the body unread, which makes the kernel reset the connection, and on a busy host the reset sometimes arrives first. The gateway's next write to the MCP server then fails; the gateway stops sending and keeps reading for at most 1 s, so an answer that had already arrived (for example `401 UPLOAD_UNAUTHENTICATED`), also one whose headers and body came in separate segments, still reaches the sender unchanged. Without an answer the sender gets 502 "unconfirmed", as for any drop before an answer. The gateway sends the answer's status line to the sender only together with the first answer byte: headers received from the MCP server are not yet bytes sent to the sender. So an answer that breaks off after its headers but before any byte reached the sender ends as a complete 502 "unconfirmed" (with its own `Content-Type` and `Content-Length`, never the MCP server's status), while an answer that breaks off after bytes reached the sender stays truncated, with no replacement status. Measured under deliberate CPU load with http MCP servers, both an MCP server that closes this way and one that keeps the connection open until the sender stops delivered every early refusal unchanged. Limits: https MCP servers were not measured; reading after the failed write relies on Node stream internals, and if a Node version no longer allows it, the gateway falls back to 502 "unconfirmed" for this case and the upload relay process tests fail.

**Resources and logging:**

- The gateway has no size or concurrency cap of its own. reqlift's 100 MiB cap applies to reqlift callers only; other API-key holders are bounded by the MCP server (Jira's attachment limit). Memory stays flat per upload: the test suite asserts that a 50 MB relay raises the peak resident memory by less than 10 MB. That needs `node --expose-gc`, which `entrypoint.sh` and `npm start` use: the relay then forces a minor garbage collection every 2 MiB. Without the flag the relay still works, only with a higher peak.
- Nothing is written to disk (sessions, transcripts, event cache and temp files are untouched).
- The request log line carries the URL, i.e. the target (issue key) and the file name; never file bytes, never the credential. One audit line per relay: `mcp.upload.relayed serverName=<name> status=<code> bytes=<n> result=ok|upstream_answer|upstream_failed|timeout|client_aborted`.

For detailed architecture, see [`docs/architecture.md`](docs/architecture.md).

Full API reference with curl examples: [`docs/index.html`](docs/index.html) or [Agent Gateway Wiki](https://code1.diemit.net/wiki/internal/agent-gateway.html).

## License

Private -- DiemIT GmbH
