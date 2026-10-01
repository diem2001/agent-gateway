import { createHash, randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { log } from "./logging.js";

/**
 * What an agent sandbox may see of the trusted workspace (MVP-7678, TD-4).
 *
 * The agent's own processes can write to their session home, so every file the
 * trusted side binds into a sandbox, copies or reads for one is checked WITHOUT
 * following symlinks: it must be a regular file or directory owned by the gateway
 * user whose real path is exactly the path it was found at, inside the tree it is
 * expected in. Anything else is left out with an audit line (never the content).
 * Mounted content is also scanned for the gateway's known secret values; a file
 * that holds one is hidden behind an empty file.
 *
 * Nothing here logs a secret value, a path below the workspace root or file
 * content: audit lines carry fixed words, entry names that pass `SAFE_NAME` and counts.
 */

/** Where the workspace appears inside a sandbox. */
export const SANDBOX_HOME = "/home/node";
export const SANDBOX_CLAUDE_DIR = `${SANDBOX_HOME}/.claude`;

/**
 * Global workspace entries an agent may read: (name, kind). `trusted` entries are configuration or extensions the
 * runtime loads from `~/.claude` (instructions, skills, agents, commands, output styles, plugins, hooks): a file the
 * agent writes there can carry hooks or MCP servers, so the sandbox always sees the workspace entry read-only, or a
 * trusted EMPTY one when the workspace has none (never the agent-writable directory underneath). `memory` is data.
 */
export const GLOBAL_ENTRIES: readonly { name: string; kind: "file" | "dir"; trusted: boolean }[] = [
  { name: "CLAUDE.md", kind: "file", trusted: true },
  { name: "skills", kind: "dir", trusted: true },
  { name: "agents", kind: "dir", trusted: true },
  { name: "memory", kind: "dir", trusted: false },
  { name: "commands", kind: "dir", trusted: true },
  { name: "output-styles", kind: "dir", trusted: true },
  { name: "plugins", kind: "dir", trusted: true },
  { name: "hooks", kind: "dir", trusted: true },
];

/** A repository or entry name that is used in a mount destination. */
export const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

/** Files larger than this are not scanned for secret values (credential files are small). */
export const SCAN_MAX_FILE_BYTES = 1024 * 1024;
const CONFIG_MAX_BYTES = 1024 * 1024;

export type SkipReason = "missing" | "symlink" | "not_owned" | "wrong_type" | "outside_root" | "unsafe_name" | "unsafe_git" | "unreadable";

export interface SandboxMount {
  /** Host path. */
  src: string;
  /** Path inside the sandbox. */
  dest: string;
}

export interface MountPlan {
  /** Read-only binds in the order they must be applied (later ones may sit inside earlier ones). */
  mounts: SandboxMount[];
  /** Destination paths hidden behind an empty file (known secret value found), applied after `mounts`. */
  hidden: string[];
  /** Counts for the operator log. */
  skipped: number;
  hiddenCount: number;
}

function gatewayUid(): number | undefined {
  return typeof process.getuid === "function" ? process.getuid() : undefined;
}

export function lstatOrNull(p: string): fs.Stats | null {
  try {
    return fs.lstatSync(p);
  } catch {
    return null;
  }
}

function ownedByGatewayUser(stat: fs.Stats): boolean {
  const uid = gatewayUid();
  return uid === undefined || stat.uid === uid;
}

function realpathOrNull(p: string): string | null {
  try {
    return fs.realpathSync(p);
  } catch {
    return null;
  }
}

/** `child` is `root` or below it (plain path arithmetic on already-resolved paths). */
export function isInside(root: string, child: string): boolean {
  const rel = path.relative(root, child);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

export type TrustCheck = { ok: true; stat: fs.Stats } | { ok: false; reason: SkipReason };

/**
 * A path is trusted when `lstat` (no follow) shows the wanted type owned by the
 * gateway user, it is inside `root`, and its real path is the path itself (no
 * symlink anywhere in its components). `root` must already be a real path.
 */
export function checkTrusted(p: string, kind: "file" | "dir", root: string): TrustCheck {
  const stat = lstatOrNull(p);
  if (!stat) return { ok: false, reason: "missing" };
  if (stat.isSymbolicLink()) return { ok: false, reason: "symlink" };
  if (kind === "file" ? !stat.isFile() : !stat.isDirectory()) return { ok: false, reason: "wrong_type" };
  if (!ownedByGatewayUser(stat)) return { ok: false, reason: "not_owned" };
  if (!isInside(root, p)) return { ok: false, reason: "outside_root" };
  if (realpathOrNull(p) !== p) return { ok: false, reason: "symlink" };
  return { ok: true, stat };
}

/** Reads a regular file owned by the gateway user without following a final symlink; null otherwise. */
export function readFileNoFollow(p: string, maxBytes: number = CONFIG_MAX_BYTES): Buffer | null {
  let fd: number | undefined;
  try {
    fd = fs.openSync(p, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || !ownedByGatewayUser(stat) || stat.size > maxBytes) return null;
    return fs.readFileSync(fd);
  } catch {
    return null;
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

export interface RegularFileEntry {
  path: string;
  size: number;
  modified: string;
}

/**
 * The regular files below `baseDir` (relative paths with `/`), without following
 * any symlink: a symlink is neither listed nor entered. `baseDir` itself must be a
 * real directory, not a symlink.
 */
export function listRegularFilesNoFollow(baseDir: string): RegularFileEntry[] {
  const files: RegularFileEntry[] = [];
  const top = lstatOrNull(baseDir);
  if (!top || !top.isDirectory()) return files;
  const walk = (dir: string, prefix: string): void => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
      const full = path.join(dir, entry.name);
      const stat = lstatOrNull(full);
      if (!stat || stat.isSymbolicLink()) continue;
      if (stat.isDirectory()) walk(full, rel);
      else if (stat.isFile()) files.push({ path: rel, size: stat.size, modified: stat.mtime.toISOString() });
    }
  };
  walk(baseDir, "");
  return files;
}

/**
 * Copies one regular file without following symlinks: the source is opened with
 * `O_NOFOLLOW` and must be owned by the gateway user; the destination is created
 * exclusively. Returns false (nothing copied) for anything else.
 */
export function copyFileNoFollow(src: string, dest: string): boolean {
  const content = readFileNoFollow(src, Number.MAX_SAFE_INTEGER);
  if (!content) return false;
  fs.writeFileSync(dest, content, { flag: "wx", mode: 0o600 });
  return true;
}

/**
 * Throws when any component of `relative` below `base` (inside an agent-writable
 * home) is a symlink: the trusted side must not resolve a mount destination
 * through a link the agent could have planted.
 */
export function assertNoSymlinkComponents(base: string, relative: string): boolean {
  let current = base;
  for (const part of relative.split("/").filter(Boolean)) {
    current = path.join(current, part);
    const stat = lstatOrNull(current);
    if (!stat) return true;
    if (stat.isSymbolicLink()) return false;
  }
  return true;
}

/**
 * Makes the mount points of one start safe inside an agent-writable home, without following a
 * link: every ancestor of a destination that is a symlink or not a directory is removed, and a
 * destination that exists as the wrong type (a directory where a file is mounted, or the reverse)
 * is removed, so bwrap only ever creates a fresh mount point. Links removed this way are the
 * agent's own; what they pointed to is never touched.
 */
export function prepareMountPoints(homeDir: string, mounts: { src: string; dest: string }[], hidden: string[]): void {
  const entries = [...mounts.map((m) => ({ dest: m.dest, srcIsDir: lstatOrNull(m.src)?.isDirectory() ?? false })), ...hidden.map((dest) => ({ dest, srcIsDir: false }))];
  for (const { dest, srcIsDir } of entries) {
    if (!dest.startsWith(`${SANDBOX_HOME}/`)) continue;
    const parts = dest.slice(SANDBOX_HOME.length + 1).split("/");
    let current = homeDir;
    for (let i = 0; i < parts.length; i++) {
      current = path.join(current, parts[i]);
      const stat = lstatOrNull(current);
      if (!stat) break;
      const last = i === parts.length - 1;
      const wrongType = last ? stat.isDirectory() !== srcIsDir : !stat.isDirectory();
      if (stat.isSymbolicLink() || wrongType) {
        fs.rmSync(current, { recursive: true, force: true });
        break;
      }
    }
  }
}

/* ------------------------------------------------------------------ */
/*  The runtime's per-user state file                                   */
/* ------------------------------------------------------------------ */

/**
 * `~/.claude.json` is the runtime's own state file, written by the runtime at every start and read again at the next
 * one, whatever the setting sources: its `mcpServers` (and the per-project `mcpServers` below `projects`) start a
 * command, so a file the agent writes in its own home would start one on the next turn even when the run grants it
 * no execution tool (MVP-7679, Gate A). The runtime crashes when the file is read-only, so the trusted side
 * rewrites it before every start instead: only these keys survive, each with a plain value.
 */
export const RUNTIME_STATE_KEYS: readonly string[] = [
  "cachedStatsigGates",
  "firstStartTime",
  "sonnet45MigrationComplete",
  "opus45MigrationComplete",
  "thinkingMigrationComplete",
  "userID",
  "numStartups",
  "hasCompletedOnboarding",
];

const STATE_FILE = ".claude.json";
const STATE_VALUE_MAX = 256;

function plainStateValue(key: string, value: unknown): unknown {
  if (key === "cachedStatsigGates") {
    if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
    const gates: Record<string, boolean> = {};
    for (const [name, flag] of Object.entries(value as Record<string, unknown>)) {
      if (typeof flag === "boolean" && /^[A-Za-z0-9_.-]{1,64}$/.test(name)) gates[name] = flag;
    }
    return gates;
  }
  if (typeof value === "boolean" || (typeof value === "number" && Number.isFinite(value))) return value;
  if (typeof value === "string" && value.length <= STATE_VALUE_MAX) return value;
  return undefined;
}

/**
 * Rewrites the home's runtime state file to its allowlisted keys and removes the backup copies, without following
 * any link. Runs before the sandbox of a conversation exists (the conversation lock guarantees no process of its
 * previous run is left). Throws when a file cannot be rewritten or removed: the caller fails closed.
 */
export function sanitizeRuntimeConfig(homeDir: string): void {
  const state = path.join(homeDir, STATE_FILE);
  const stat = lstatOrNull(state);
  if (stat) {
    let kept: Record<string, unknown> | null = null;
    if (stat.isFile() && !stat.isSymbolicLink() && ownedByGatewayUser(stat)) {
      const raw = readFileNoFollow(state);
      if (raw) {
        try {
          const parsed: unknown = JSON.parse(raw.toString("utf8"));
          if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
            kept = {};
            for (const key of RUNTIME_STATE_KEYS) {
              const value = plainStateValue(key, (parsed as Record<string, unknown>)[key]);
              if (value !== undefined) kept[key] = value;
            }
          }
        } catch {
          kept = null;
        }
      }
    }
    if (kept === null) {
      fs.rmSync(state, { recursive: true, force: true });
    } else {
      const temp = path.join(homeDir, `${STATE_FILE}.sanitize-${randomDirName()}`);
      fs.writeFileSync(temp, `${JSON.stringify(kept)}\n`, { flag: "wx", mode: 0o600 });
      fs.renameSync(temp, state);
    }
  }
  // Backups and temporary copies of the state file: the runtime restores a damaged state from them.
  for (const entry of fs.readdirSync(homeDir)) {
    if (entry !== STATE_FILE && entry.startsWith(`${STATE_FILE}.`)) fs.rmSync(path.join(homeDir, entry), { recursive: true, force: true });
  }
  purgeConfigDir(homeDir);
  // The runtime runs `git status` in its working directory (the home) at start: a `core.fsmonitor` command or a
  // filter driver in a repository the agent planted there would run, so the home itself is never a repository
  // (a `.git` directory, file or link is removed, never followed; repositories below the home are not touched).
  fs.rmSync(path.join(homeDir, ".git"), { recursive: true, force: true });
}

/**
 * What the agent may leave under `~/.claude` between two starts: data only, nothing the runtime reads as
 * configuration or extension. Measured on the real runtime (2.0.77): it writes `projects/` (session transcripts,
 * needed for resume), `todos/` and `plans/` there, and `memory` is the mount point of the workspace memory. Every
 * other entry is removed at every start, so a name the runtime reads today (`commands`, `agents`, `skills`,
 * `output-styles`, `plugins`, `hooks`, `settings.local.json`, `CLAUDE.md`, `.config.json`, `shell-snapshots` that are
 * sourced as scripts) or learns to read later is untrusted by default; the runtime recreates what it needs.
 */
export const RUNTIME_WRITABLE_DIRS: readonly string[] = ["memory", "plans", "projects", "todos"];

/**
 * Allow-list of the runtime's config directory (`~/.claude`, which the agent can write): everything not in
 * `RUNTIME_WRITABLE_DIRS` is removed without following links, and an allowed name that is not a real directory
 * is removed too. The runtime also prefers `<config dir>/.config.json` over `~/.claude.json` whenever it exists
 * (2.0.77, `cli.js` `QF()`), which this covers. A `.claude` that is not a real directory is removed itself.
 */
function purgeConfigDir(homeDir: string): void {
  const dir = path.join(homeDir, ".claude");
  const stat = lstatOrNull(dir);
  if (!stat) return;
  if (!stat.isDirectory()) {
    fs.rmSync(dir, { recursive: true, force: true });
    return;
  }
  for (const entry of fs.readdirSync(dir)) {
    const full = path.join(dir, entry);
    if (RUNTIME_WRITABLE_DIRS.includes(entry) && lstatOrNull(full)?.isDirectory()) continue;
    fs.rmSync(full, { recursive: true, force: true });
  }
}

/* ------------------------------------------------------------------ */
/*  Allowlist-generated git configuration                               */
/* ------------------------------------------------------------------ */

const DROPPED_CORE_KEYS = new Set(["sshcommand", "askpass", "fsmonitor", "hookspath"]);

/** `scheme://user:pass@host/x` -> `scheme://host/x`; anything else unchanged. */
export function stripUrlUserInfo(url: string): string {
  return url.replace(/^([A-Za-z][A-Za-z0-9+.-]*:\/\/)[^/?#]*@/, "$1");
}

interface ConfigEntry {
  section: string;
  subsection: string | null;
  key: string;
  value: string;
}

function unquoteValue(raw: string): string {
  let out = "";
  let inQuote = false;
  for (let i = 0; i < raw.length; i++) {
    const c = raw[i];
    if (c === "\\" && i + 1 < raw.length) {
      const next = raw[++i];
      out += next === "n" ? "\n" : next === "t" ? "\t" : next === "b" ? "\b" : next;
    } else if (c === '"') {
      inQuote = !inQuote;
    } else if (!inQuote && (c === "#" || c === ";")) {
      break;
    } else {
      out += c;
    }
  }
  return out.trim();
}

function parseGitConfig(text: string): ConfigEntry[] {
  const entries: ConfigEntry[] = [];
  let section = "";
  let subsection: string | null = null;
  const lines = text.replace(/\r\n/g, "\n").split("\n");
  for (let i = 0; i < lines.length; i++) {
    let line = lines[i].trim();
    // A trailing backslash continues the value on the next line.
    while (line.endsWith("\\") && !line.endsWith("\\\\") && i + 1 < lines.length) {
      line = `${line.slice(0, -1)}${lines[++i].trim()}`;
    }
    if (line === "" || line.startsWith("#") || line.startsWith(";")) continue;
    const header = /^\[\s*([A-Za-z0-9.-]+)(?:\s+"((?:[^"\\]|\\.)*)")?\s*\](.*)$/.exec(line);
    if (header) {
      const name = header[1];
      const dot = name.indexOf(".");
      if (header[2] !== undefined) {
        section = name.toLowerCase();
        subsection = header[2].replace(/\\(.)/g, "$1");
      } else if (dot > 0) {
        // Legacy `[section.subsection]` form: the subsection is lower-cased by git.
        section = name.slice(0, dot).toLowerCase();
        subsection = name.slice(dot + 1);
      } else {
        section = name.toLowerCase();
        subsection = null;
      }
      line = header[3].trim();
      if (line === "" || line.startsWith("#") || line.startsWith(";")) continue;
    }
    const kv = /^([A-Za-z][A-Za-z0-9-]*)\s*(?:=\s*(.*))?$/.exec(line);
    if (!kv || section === "") continue;
    entries.push({ section, subsection, key: kv[1].toLowerCase(), value: kv[2] === undefined ? "true" : unquoteValue(kv[2]) });
  }
  return entries;
}

function quoteValue(value: string): string {
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n").replace(/\t/g, "\\t")}"`;
}

/**
 * A git configuration rebuilt from an allowlist: `remote.<n>.url` (user info stripped)
 * and `.fetch`, every `branch.<n>.*`, `core.*` without `sshCommand`, `askpass`,
 * `fsmonitor` and `hooksPath`, and `extensions.*` (the repository format).
 * Everything else (credential helpers, `url.<x>.insteadOf`, `http.*` headers,
 * includes, aliases, tokens in other keys) is not copied.
 */
export function allowlistGitConfig(text: string): string {
  const sections = new Map<string, string[]>();
  const add = (entry: ConfigEntry, value: string): void => {
    const header = entry.subsection === null ? `[${entry.section}]` : `[${entry.section} ${quoteValue(entry.subsection)}]`;
    const lines = sections.get(header) ?? [];
    lines.push(`\t${entry.key} = ${quoteValue(value)}`);
    sections.set(header, lines);
  };
  for (const entry of parseGitConfig(text)) {
    if (entry.section === "remote" && entry.subsection !== null) {
      if (entry.key === "url") add(entry, stripUrlUserInfo(entry.value));
      else if (entry.key === "fetch") add(entry, entry.value);
    } else if (entry.section === "branch" && entry.subsection !== null) {
      add(entry, entry.value);
    } else if (entry.section === "core" && entry.subsection === null) {
      if (!DROPPED_CORE_KEYS.has(entry.key)) add(entry, entry.value);
    } else if (entry.section === "extensions" && entry.subsection === null) {
      add(entry, entry.value);
    }
  }
  return [...sections].map(([header, lines]) => `${header}\n${lines.join("\n")}\n`).join("");
}

/* ------------------------------------------------------------------ */
/*  Known-value scan                                                    */
/* ------------------------------------------------------------------ */

const SECRET_ENV_NAME = /(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)/i;
const MIN_SECRET_LENGTH = 8;

/**
 * The gateway's known secret values: its own secret-looking environment values
 * (provider key, OAuth token variable, every `API_KEYS` key, ...), the OAuth tokens
 * of the trusted credentials file and any `extra` values (registry headers and env).
 * Shorter than 8 characters is ignored (a short value would match ordinary text).
 */
export function knownSecretValues(env: NodeJS.ProcessEnv, credentialsFile: string | null, extra: string[] = []): Buffer[] {
  const values = new Set<string>();
  const add = (value: unknown): void => {
    if (typeof value === "string" && value.trim().length >= MIN_SECRET_LENGTH) values.add(value.trim());
  };
  for (const [name, value] of Object.entries(env)) {
    if (!SECRET_ENV_NAME.test(name) || typeof value !== "string") continue;
    if (name === "API_KEYS") {
      for (const entry of value.split(",")) {
        const colon = entry.indexOf(":");
        if (colon > 0) add(entry.slice(colon + 1));
      }
    } else {
      add(value);
    }
  }
  if (credentialsFile) {
    const raw = readFileNoFollow(credentialsFile);
    if (raw) {
      try {
        const oauth = (JSON.parse(raw.toString("utf8")) as { claudeAiOauth?: Record<string, unknown> }).claudeAiOauth;
        add(oauth?.accessToken);
        add(oauth?.refreshToken);
      } catch {
        // An unreadable credentials file contributes no value.
      }
    }
  }
  for (const value of extra) add(value);
  return [...values].sort().map((value) => Buffer.from(value, "utf8"));
}

function needleDigest(needles: Buffer[]): string {
  const hash = createHash("sha256");
  for (const needle of needles) hash.update(createHash("sha256").update(needle).digest());
  return hash.digest("hex");
}

interface CachedScan {
  mtimeMs: number;
  size: number;
  hit: boolean;
}

/** `name` inside `dir` is a git object store (`.git/objects` and the object stores below `.git/modules`): compressed, never scanned or searched for configs. */
function isObjectsDir(dir: string, name: string): boolean {
  if (name !== "objects") return false;
  return path.basename(dir) === ".git" || `${dir}${path.sep}`.includes(`${path.sep}.git${path.sep}modules${path.sep}`);
}

/**
 * Scans trees for the known values. Results are cached per file by mtime and size,
 * so a run only re-reads files that changed since the last scan; a different set of
 * values (or `invalidate`) rescans everything.
 */
export class KnownValueScanner {
  private cache = new Map<string, CachedScan>();
  private digest = "";

  /** Forget cached results below `prefix` (after a trusted git sync), or all of them. */
  invalidate(prefix?: string): void {
    if (prefix === undefined) {
      this.cache.clear();
      return;
    }
    for (const key of [...this.cache.keys()]) if (isInside(prefix, key)) this.cache.delete(key);
  }

  /** Absolute paths of the files below `root` that hold a known value. Symlinks are not followed or entered. */
  scan(root: string, needles: Buffer[]): string[] {
    const digest = needleDigest(needles);
    if (digest !== this.digest) {
      this.cache.clear();
      this.digest = digest;
    }
    const hits: string[] = [];
    if (needles.length === 0) return hits;
    const walk = (dir: string): void => {
      let entries: fs.Dirent[];
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
      } catch {
        return;
      }
      for (const entry of entries) {
        const full = path.join(dir, entry.name);
        const stat = lstatOrNull(full);
        if (!stat || stat.isSymbolicLink()) continue;
        if (stat.isDirectory()) {
          if (!isObjectsDir(dir, entry.name)) walk(full);
          continue;
        }
        if (!stat.isFile() || stat.size === 0 || stat.size > SCAN_MAX_FILE_BYTES) continue;
        const cached = this.cache.get(full);
        let hit: boolean;
        if (cached && cached.mtimeMs === stat.mtimeMs && cached.size === stat.size) {
          hit = cached.hit;
        } else {
          const content = readFileNoFollow(full, SCAN_MAX_FILE_BYTES);
          // A file that cannot be read safely is treated as a hit: it is hidden, never shown.
          hit = content === null ? true : needles.some((needle) => content.includes(needle));
          this.cache.set(full, { mtimeMs: stat.mtimeMs, size: stat.size, hit });
        }
        if (hit) hits.push(full);
      }
    };
    walk(root);
    return hits;
  }
}

/** The gateway's scanner (agent runs and trusted git syncs share it). */
export const contentScanner = new KnownValueScanner();

/**
 * A trusted write changed `dir` (a git clone or pull): its cached scan results are dropped,
 * so the next sandbox start scans it again before any of it is mounted.
 */
export function noteTrustedContentChange(dir: string): void {
  contentScanner.invalidate(dir);
  const real = realpathOrNull(dir);
  if (real && real !== dir) contentScanner.invalidate(real);
}

/* ------------------------------------------------------------------ */
/*  Mount plan                                                          */
/* ------------------------------------------------------------------ */

export interface PlanOptions {
  /** The workspace root (`WORKSPACE_ROOT`). */
  workspaceRoot: string;
  /** A directory only the trusted side can see; generated files (settings, git configs) are written below it. */
  trustedDir: string;
  /** The gateway's known secret values. */
  needles: Buffer[];
  scanner?: KnownValueScanner;
}

/** An empty read-only stand-in below the trusted directory (created once per start, shared by every entry of that kind). */
function trustedEmpty(trustedDir: string, kind: "file" | "dir"): string {
  const target = path.join(trustedDir, kind === "dir" ? "empty-dir" : "empty-file");
  if (!lstatOrNull(target)) {
    if (kind === "dir") fs.mkdirSync(target, { mode: 0o555 });
    else fs.writeFileSync(target, "", { flag: "wx", mode: 0o444 });
  }
  return target;
}

function audit(kind: string, name: string, reason: SkipReason | "known_value"): void {
  log("audit", `sandbox.content.skipped kind=${kind} name=${SAFE_NAME.test(name) ? name : "invalid"} reason=${reason}`);
}

/** Every `config` file to mask in a repository, as paths relative to the repository root, or null when the layout is unsafe. */
function gitConfigFiles(repo: string): string[] | null {
  const gitDir = path.join(repo, ".git");
  const stat = lstatOrNull(gitDir);
  if (!stat) return [];
  if (stat.isSymbolicLink()) return null;
  // A `.git` file (submodule or worktree checkout) only points at a git directory that is not part of the view.
  if (stat.isFile()) return ownedByGatewayUser(stat) ? [] : null;
  if (!stat.isDirectory() || !ownedByGatewayUser(stat)) return null;

  const files: string[] = [];
  const main = lstatOrNull(path.join(gitDir, "config"));
  if (main) {
    if (!main.isFile()) return null;
    files.push(".git/config");
  }
  const walk = (dir: string, rel: string, nested: boolean): boolean => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return true;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      const entryRel = `${rel}/${entry.name}`;
      const entryStat = lstatOrNull(full);
      if (!entryStat) continue;
      if (entry.name === "config" && nested) {
        if (!entryStat.isFile()) return false;
        files.push(entryRel);
        continue;
      }
      if (entryStat.isSymbolicLink()) {
        // A link that could stand for a configuration file is not tolerated; any other link resolves inside the sandbox only.
        if (entry.name === "config") return false;
        continue;
      }
      if (entryStat.isDirectory() && !isObjectsDir(dir, entry.name) && !walk(full, entryRel, true)) return false;
    }
    return true;
  };
  for (const sub of ["modules", "worktrees"]) {
    const subStat = lstatOrNull(path.join(gitDir, sub));
    if (!subStat) continue;
    if (subStat.isSymbolicLink() || !subStat.isDirectory()) return null;
    if (!walk(path.join(gitDir, sub), `.git/${sub}`, false)) return null;
  }
  // `.git/worktrees/*/config` and `.git/modules/**/config` only: a `config` directly in `modules` or `worktrees` is not one.
  return files.filter((f) => f === ".git/config" || /^\.git\/(modules|worktrees)\/.+\/config$/.test(f));
}

/**
 * The read-only mounts of one sandbox: the global workspace entries, a generated
 * `settings.json` that keeps only `permissions`, every repository under
 * `projects/` (names starting with `-` are runtime transcript directories and never
 * mounted) with its git configuration replaced by allowlist-generated copies, and
 * the files hidden because they hold a known secret value. Entries that fail the
 * no-follow checks are left out with an audit line.
 */
export function planTrustedContent(options: PlanOptions): MountPlan {
  const scanner = options.scanner ?? contentScanner;
  const plan: MountPlan = { mounts: [], hidden: [], skipped: 0, hiddenCount: 0 };
  const root = realpathOrNull(options.workspaceRoot);
  fs.mkdirSync(options.trustedDir, { recursive: true, mode: 0o700 });
  const skip = (kind: string, name: string, reason: SkipReason): void => {
    plan.skipped++;
    audit(kind, name, reason);
  };
  const hide = (kind: string, name: string, base: string, baseDest: string): void => {
    const hits = scanner.scan(base, options.needles);
    for (const hit of hits) plan.hidden.push(path.posix.join(baseDest, ...path.relative(base, hit).split(path.sep)));
    plan.hiddenCount += hits.length;
    if (hits.length > 0) audit(kind, name, "known_value");
  };

  for (const entry of GLOBAL_ENTRIES) {
    const source = root ? path.join(root, entry.name) : "";
    const check: TrustCheck = root ? checkTrusted(source, entry.kind, root) : { ok: false, reason: "missing" };
    if (!check.ok) {
      if (check.reason !== "missing") skip("global", entry.name, check.reason);
      // No trusted workspace entry: the sandbox sees an empty read-only one, never the agent-writable directory.
      if (entry.trusted) plan.mounts.push({ src: trustedEmpty(options.trustedDir, entry.kind), dest: `${SANDBOX_CLAUDE_DIR}/${entry.name}` });
      continue;
    }
    if (entry.kind === "file") {
      const content = readFileNoFollow(source);
      if (content && options.needles.some((needle) => content.includes(needle))) {
        plan.hidden.push(`${SANDBOX_CLAUDE_DIR}/${entry.name}`);
        plan.hiddenCount++;
        audit("global", entry.name, "known_value");
      }
    }
    plan.mounts.push({ src: source, dest: `${SANDBOX_CLAUDE_DIR}/${entry.name}` });
    if (entry.kind === "dir") hide("global", entry.name, source, `${SANDBOX_CLAUDE_DIR}/${entry.name}`);
  }

  if (!root) return plan;
  const settings = generatedSettings(root, options.trustedDir);
  if (settings) plan.mounts.push({ src: settings, dest: `${SANDBOX_CLAUDE_DIR}/settings.json` });

  const projects = path.join(root, "projects");
  const projectsCheck = checkTrusted(projects, "dir", root);
  if (!projectsCheck.ok) {
    if (projectsCheck.reason !== "missing") skip("repo", "projects", projectsCheck.reason);
    return plan;
  }
  let names: string[] = [];
  try {
    names = fs.readdirSync(projects).sort();
  } catch {
    return plan;
  }
  let maskIndex = 0;
  for (const name of names) {
    // `-home-node` and friends are the runtime's own per-directory transcript folders.
    if (name.startsWith("-")) continue;
    if (!SAFE_NAME.test(name)) {
      skip("repo", name, "unsafe_name");
      continue;
    }
    const repo = path.join(projects, name);
    const check = checkTrusted(repo, "dir", root);
    if (!check.ok) {
      skip("repo", name, check.reason);
      continue;
    }
    const configs = gitConfigFiles(repo);
    if (configs === null) {
      skip("repo", name, "unsafe_git");
      continue;
    }
    const masks: SandboxMount[] = [];
    let unreadable = false;
    for (const rel of configs) {
      const text = readFileNoFollow(path.join(repo, rel));
      if (!text) {
        unreadable = true;
        break;
      }
      const generated = path.join(options.trustedDir, "gitcfg", String(maskIndex++));
      fs.mkdirSync(path.dirname(generated), { recursive: true, mode: 0o700 });
      fs.writeFileSync(generated, allowlistGitConfig(text.toString("utf8")), { flag: "wx", mode: 0o600 });
      masks.push({ src: generated, dest: `${SANDBOX_CLAUDE_DIR}/projects/${name}/${rel}` });
    }
    if (unreadable) {
      skip("repo", name, "unreadable");
      continue;
    }
    plan.mounts.push({ src: repo, dest: `${SANDBOX_CLAUDE_DIR}/projects/${name}` }, ...masks);
    hide("repo", name, repo, `${SANDBOX_CLAUDE_DIR}/projects/${name}`);
  }
  return plan;
}

/** The `settings.json` the sandbox sees: only `permissions` of the trusted one, written below `trustedDir`. */
function generatedSettings(root: string, trustedDir: string): string | null {
  const source = path.join(root, "settings.json");
  const check = checkTrusted(source, "file", root);
  let permissions: unknown;
  if (check.ok) {
    const raw = readFileNoFollow(source);
    if (raw) {
      try {
        const parsed = JSON.parse(raw.toString("utf8")) as { permissions?: unknown };
        if (parsed.permissions && typeof parsed.permissions === "object" && !Array.isArray(parsed.permissions)) permissions = parsed.permissions;
      } catch {
        permissions = undefined;
      }
    }
  } else if (check.reason !== "missing") {
    audit("settings", "settings.json", check.reason);
  }
  const target = path.join(trustedDir, "settings.json");
  fs.mkdirSync(trustedDir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(target, `${JSON.stringify(permissions === undefined ? {} : { permissions }, null, 2)}\n`, { flag: "wx", mode: 0o600 });
  return target;
}

/** A random identifier for run and session directories. */
export function randomDirName(): string {
  return randomBytes(12).toString("hex");
}
