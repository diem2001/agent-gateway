/**
 * The container security profile of the committed docker-compose.yml (MVP-7678), as `docker run`
 * arguments, so a probe starts its task-owned container exactly the way the compose file would:
 * `user`, `cap_drop`, `security_opt` (the seccomp profile path resolved against the repository,
 * `${VAR:-default}` resolved to its default), `pids_limit` and the healthcheck command.
 *
 * This reads the compose file as text (no YAML library): it only understands the shapes this repository's
 * compose file uses, and throws when a key it needs is missing, so a changed file cannot be ignored silently.
 */
import fs from "node:fs";
import path from "node:path";

function resolveDefaults(value) {
  return value.replace(/\$\{[A-Za-z0-9_]+:-([^}]*)\}/g, "$1");
}

function listUnder(lines, key) {
  const start = lines.findIndex((l) => new RegExp(`^    ${key}:\\s*$`).test(l));
  if (start < 0) throw new Error(`docker-compose.yml has no \`${key}:\` list`);
  const items = [];
  for (let i = start + 1; i < lines.length; i++) {
    const line = lines[i];
    if (/^      #/.test(line)) continue;
    const m = /^      - (.*)$/.exec(line);
    if (!m) break;
    items.push(resolveDefaults(m[1].trim()));
  }
  if (items.length === 0) throw new Error(`docker-compose.yml \`${key}:\` is empty`);
  return items;
}

function scalar(lines, key) {
  const m = lines.map((l) => new RegExp(`^    ${key}:\\s*(.+?)\\s*$`).exec(l)).find(Boolean);
  if (!m) throw new Error(`docker-compose.yml has no \`${key}:\``);
  return m[1];
}

export function readComposeSecurity(repoRoot) {
  const text = fs.readFileSync(path.join(repoRoot, "docker-compose.yml"), "utf8");
  const lines = text.split("\n");
  const user = scalar(lines, "user");
  const capDrop = listUnder(lines, "cap_drop");
  const securityOpt = listUnder(lines, "security_opt").map((opt) => {
    const m = /^seccomp=(.+)$/.exec(opt);
    // `docker run` reads a seccomp profile path itself; resolve the compose-relative path first.
    return m && !path.isAbsolute(m[1]) ? `seccomp=${path.resolve(repoRoot, m[1])}` : opt;
  });
  const pidsLimit = scalar(lines, "pids_limit");
  const health = /test:\s*\["CMD-SHELL",\s*"((?:[^"\\]|\\.)*)"\]/.exec(text);
  if (!health) throw new Error("docker-compose.yml has no CMD-SHELL healthcheck");
  const healthcheck = health[1].replace(/\\"/g, '"');
  return { user, capDrop, securityOpt, pidsLimit, healthcheck };
}

/** `docker run` arguments of the profile. */
export function composeRunArgs(repoRoot) {
  const { user, capDrop, securityOpt, pidsLimit } = readComposeSecurity(repoRoot);
  return ["--user", user, ...capDrop.flatMap((c) => ["--cap-drop", c]), ...securityOpt.flatMap((o) => ["--security-opt", o]), "--pids-limit", pidsLimit];
}
