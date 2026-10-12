#!/bin/bash
# Agent Gateway Entrypoint
# Runs as the `node` user (the image sets USER node, docker-compose.yml user: node); there is no
# root step. Sets up the workspace and starts the gateway. All persistent state lives in
# /home/node (bind-mounted from ./agent_home, which must be owned by uid 1000).

set -e

# ------------------------------------------------------------------
# 1. Create workspace directories (persists across restarts via bind mount)
# ------------------------------------------------------------------
mkdir -p /home/node/.claude/memory \
         /home/node/.claude/agents \
         /home/node/.claude/skills \
         /home/node/.ssh

# ------------------------------------------------------------------
# 2. Write Claude settings with broad tool permissions (only if not exists)
#    (bypassPermissions alone is insufficient for SDK tools). The agent sandbox
#    sees only the `permissions` of this file.
# ------------------------------------------------------------------
if [ ! -f /home/node/.claude/settings.json ]; then
    cat > /home/node/.claude/settings.json <<'SETTINGS'
{
  "permissions": {
    "allow": [
      "Bash(*)",
      "Read(*)",
      "Write(*)",
      "Edit(*)",
      "Glob(*)",
      "Grep(*)",
      "WebSearch(*)",
      "WebFetch(*)"
    ]
  }
}
SETTINGS
    echo "[entrypoint] Created default Claude settings"
fi

# ------------------------------------------------------------------
# 3. Set up SSH config if keys exist
# ------------------------------------------------------------------
if [ "$(ls -A /home/node/.ssh/id_* 2>/dev/null)" ]; then
    find /home/node/.ssh -type f -name "id_*" ! -name "*.pub" -exec chmod 600 {} \;
    find /home/node/.ssh -type f -name "*.pub" -exec chmod 644 {} \;

    FIRST_KEY=$(find /home/node/.ssh -type f -name "id_*" ! -name "*.pub" | head -1)
    if [ -n "$FIRST_KEY" ]; then
        cat > /home/node/.ssh/config <<SSHCONF
Host *
    IdentityFile $FIRST_KEY
    StrictHostKeyChecking accept-new
    UserKnownHostsFile /home/node/.ssh/known_hosts
SSHCONF
        chmod 600 /home/node/.ssh/config
        echo "[entrypoint] SSH key found, config written: $(basename "$FIRST_KEY")"
    fi
else
    echo "[entrypoint] No SSH keys found — upload via POST /v1/ssh-keys"
fi

echo "[entrypoint] Agent Gateway starting..."
exec node --expose-gc /app/dist/server.js
