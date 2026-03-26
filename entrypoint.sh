#!/bin/bash
# Agent Gateway Entrypoint
# Runs as root, sets up workspace, then drops to node user via gosu.
# All persistent state lives on the gateway_data volume mounted at /data.

set -e

SSH_SRC="/data/ssh"
SSH_DST="/home/node/.ssh"

# ------------------------------------------------------------------
# 1. Create workspace directories (on volume, persists across restarts)
# ------------------------------------------------------------------
mkdir -p /home/node/.claude/memory \
         /home/node/.claude/agents \
         /home/node/.claude/skills \
         /home/node/.ssh \
         /data/ssh

# ------------------------------------------------------------------
# 2. Write Claude settings with broad tool permissions
#    (bypassPermissions alone is insufficient for SDK tools)
# ------------------------------------------------------------------
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

# ------------------------------------------------------------------
# 3. Copy SSH keys from gateway_data volume to ~/.ssh/ if they exist
#    Keys are written here by POST /v1/ssh-keys and persist on the volume.
# ------------------------------------------------------------------
if [ -d "$SSH_SRC" ] && [ "$(ls -A "$SSH_SRC" 2>/dev/null)" ]; then
    cp -a "$SSH_SRC"/* "$SSH_DST/" 2>/dev/null || true

    # Ensure correct permissions on private keys
    find "$SSH_DST" -type f -name "id_*" ! -name "*.pub" -exec chmod 600 {} \;
    find "$SSH_DST" -type f -name "*.pub" -exec chmod 644 {} \;

    # Write SSH config if a key exists
    FIRST_KEY=$(find "$SSH_DST" -type f -name "id_*" ! -name "*.pub" | head -1)
    if [ -n "$FIRST_KEY" ]; then
        cat > "$SSH_DST/config" <<SSHCONF
Host *
    IdentityFile $FIRST_KEY
    StrictHostKeyChecking accept-new
    UserKnownHostsFile $SSH_DST/known_hosts
SSHCONF
        chmod 600 "$SSH_DST/config"
        echo "[entrypoint] SSH key found, config written: $(basename "$FIRST_KEY")"
    fi
else
    echo "[entrypoint] No SSH keys on volume — upload via POST /v1/ssh-keys"
fi

# ------------------------------------------------------------------
# 4. Fix ownership and drop to node user
# ------------------------------------------------------------------
chown -R node:node /home/node /data

echo "[entrypoint] Agent Gateway starting..."
exec gosu node node /app/dist/server.js
