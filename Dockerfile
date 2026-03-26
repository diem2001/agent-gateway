# ---- Stage 1: Build TypeScript ----
FROM node:22-bookworm AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src/ ./src/
RUN npm run build

# ---- Stage 2: Runtime ----
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
    mc \
    python3 \
    && rm -rf /var/lib/apt/lists/*

# Create home dir structure for node user
RUN mkdir -p /home/node/.local/bin /home/node/.claude /home/node/.ssh && \
    chown -R node:node /home/node && \
    chmod 700 /home/node/.ssh

WORKDIR /app

COPY package*.json ./
RUN npm ci --production

COPY --from=builder /app/dist/ ./dist/
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

EXPOSE 3001

ENV HOME=/home/node
ENV PATH="/home/node/.local/bin:$PATH"

ENTRYPOINT ["bash", "/app/entrypoint.sh"]
