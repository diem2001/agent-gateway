#!/bin/bash
# Agent Gateway Entrypoint
# Runs as root, sets up workspace, then drops to node user via gosu.
# All persistent state lives in /home/node (bind-mounted from ./agent_home).

set -e

# ------------------------------------------------------------------
# 1. Create workspace directories (persists across restarts via bind mount)
# ------------------------------------------------------------------
mkdir -p /home/node/.claude/memory \
         /home/node/.claude/agents \
         /home/node/.claude/skills \
         /home/node/.ssh \
         /home/node/.local/bin
chown -R node:node /home/node

# ------------------------------------------------------------------
# 2. Write Claude settings with broad tool permissions (only if not exists)
#    (bypassPermissions alone is insufficient for SDK tools)
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
# 3. Install Claude Code CLI if not already present
# ------------------------------------------------------------------
if [ ! -x /home/node/.local/bin/claude ]; then
    echo "[entrypoint] Installing Claude Code CLI..."
    gosu node bash -c 'curl -fsSL https://claude.ai/install.sh | bash'
    echo "[entrypoint] Claude Code CLI installed"
else
    echo "[entrypoint] Claude Code CLI already installed ($(gosu node /home/node/.local/bin/claude --version))"
fi

# ------------------------------------------------------------------
# 4. Ensure PATH in .bashrc for interactive shells
# ------------------------------------------------------------------
if ! grep -q '.local/bin' /home/node/.bashrc 2>/dev/null; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> /home/node/.bashrc
fi

# ------------------------------------------------------------------
# 4. Set up SSH config if keys exist
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
exec gosu node node /app/dist/server.js
