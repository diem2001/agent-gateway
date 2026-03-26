FROM node:22-bookworm

# System tools needed by Claude Agent SDK (Bash, Read, Glob, Grep)
# plus utilities for agent operations (git, ssh, rsync, tmux)
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    curl \
    git \
    gosu \
    grep \
    findutils \
    coreutils \
    procps \
    wget \
    rsync \
    tmux \
    openssh-client \
    jq \
    python3 \
    && rm -rf /var/lib/apt/lists/*

# Claude Code CLI (needed by Claude Agent SDK for tool execution)
RUN npm install -g @anthropic-ai/claude-code

WORKDIR /app

COPY package*.json ./
RUN npm ci --production

COPY dist/ ./dist/
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Create home dir structure for node user
RUN mkdir -p /home/node/.claude /home/node/.ssh /data && \
    chown -R node:node /home/node /data && \
    chmod 700 /home/node/.ssh

EXPOSE 3001

ENV HOME=/home/node

ENTRYPOINT ["bash", "/app/entrypoint.sh"]
