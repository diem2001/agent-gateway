/**
 * The agent sandbox with the real `bwrap` of this host (MVP-7678, Gate C): real processes, a real
 * model proxy, a fixture workspace full of synthetic secrets and planted symlinks, and probe
 * scripts that run as the agent would. Every "absent" row has a permitted control in the same
 * run, so a row cannot pass because the probe itself was broken. All secrets are synthetic.
 *
 * Needs `bwrap` and user namespaces (the Docker probe of Gate E covers the container profile) and
 * `npm run build` (the SIGKILL row starts the compiled launcher). Linux only.
 */
import { spawn, execFileSync, type ChildProcess } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { ModelProxy, ProviderCredentials } from "../model-proxy.js";
import { createRunLogDir } from "../sdk-run-logs.js";
import {
  IsolationFailure,
  SandboxRun,
  isolationStatus,
  loadIsolationConfig,
  resetIsolationStatusForTests,
  runIsolationSelfCheck,
  sweepSandboxRuns,
  type IsolationConfig,
} from "../sandbox.js";
import { FINAL_ANSWER, startFakeAnthropicApi, type FakeAnthropicApi, type FakeApiMode } from "./helpers/fake-anthropic-api.js";
import { assertFreshBuild, descendants, gatewayRequest, getHealth, spawnGateway, type Cleanup, type SpawnedGateway } from "./helpers/git-process-gateway.js";

// Real processes on a shared, loaded host: every row gets a generous deadline.
vi.setConfig({ testTimeout: 60_000 });

const here = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(here, "..", "..");
const SDK_CLI = path.join(path.dirname(createRequire(import.meta.url).resolve("@anthropic-ai/claude-agent-sdk")), "cli.js");

const PROVIDER_KEY = "SYNTH-PROVIDER-KEY-7678-process";
const GATEWAY_KEY = "SYNTH-GATEWAY-API-KEY-7678";
const OAUTH_ACCESS = "SYNTH-OAUTH-ACCESS-7678-process";
const OAUTH_REFRESH = "SYNTH-OAUTH-REFRESH-7678-process";
const SSH_KEY = "SYNTH-SSH-PRIVATE-KEY-7678";
const CLONE_TOKEN = "SYNTH-CLONE-TOKEN-7678-process";
const STATE_MARKER = "SYNTH-STATE-FILE-MARKER-7678";
const LEGACY_MARKER = "SYNTH-LEGACY-TRANSCRIPT-7678";
const OTHER_SESSION_MARKER = "SYNTH-OTHER-SESSION-7678";
const ENV_SECRETS: Record<string, string> = {
  ANTHROPIC_API_KEY: PROVIDER_KEY,
  API_KEYS: `probe:${GATEWAY_KEY}`,
  CLAUDE_CODE_OAUTH_TOKEN: "SYNTH-OAUTH-ENV-TOKEN-7678",
  GITHUB_TOKEN: "SYNTH-GITHUB-TOKEN-7678-x",
  AWS_SECRET_ACCESS_KEY: "SYNTH-AWS-SECRET-7678-xx",
  HTTPS_PROXY: "http://synth-proxy.invalid:3128",
  MCP_TIMEOUT: "77777",
};
const ALL_MARKERS = [PROVIDER_KEY, GATEWAY_KEY, OAUTH_ACCESS, OAUTH_REFRESH, SSH_KEY, CLONE_TOKEN, STATE_MARKER, LEGACY_MARKER, OTHER_SESSION_MARKER, ...Object.values(ENV_SECRETS).filter((v) => v.startsWith("SYNTH"))];

let tmp: string;
let home: string;
let ws: string;
let sandboxRoot: string;
let proxy: ModelProxy;
let savedEnv: Record<string, string | undefined> = {};
let logs: string[] = [];

function write(file: string, content: string): string {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content);
  return file;
}

/** The fixture: the trusted workspace and home of a gateway, with planted symlinks and hardlinks. */
function buildFixture(): void {
  tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "sandbox-proc-")));
  home = path.join(tmp, "home");
  ws = path.join(home, ".claude");
  sandboxRoot = path.join(home, ".agent-sandbox");
  fs.mkdirSync(home, { recursive: true });
  // Trusted files that must never be visible.
  const creds = write(path.join(ws, ".credentials.json"), JSON.stringify({ claudeAiOauth: { accessToken: OAUTH_ACCESS, refreshToken: OAUTH_REFRESH, expiresAt: Date.now() + 3_600_000 } }));
  write(path.join(ws, "sessions.json"), JSON.stringify({ sessions: {}, note: STATE_MARKER }));
  write(path.join(ws, "tools.json"), JSON.stringify({ note: STATE_MARKER }));
  write(path.join(ws, "mcp-servers.json"), JSON.stringify({ note: STATE_MARKER }));
  write(path.join(ws, "sessions.json.corrupt-20260930T000000Z"), STATE_MARKER);
  write(path.join(home, ".ssh", "id_rsa"), SSH_KEY);
  write(path.join(home, ".local", "bin", "claude"), "#!/bin/sh\necho planted\n");
  write(path.join(ws, "projects", "-home-node", "legacy.jsonl"), LEGACY_MARKER);
  write(path.join(ws, "debug", "legacy.txt"), LEGACY_MARKER);
  // Global content an agent may read.
  write(path.join(ws, "CLAUDE.md"), "GLOBAL-MEMORY-OK");
  write(path.join(ws, "skills", "ok", "SKILL.md"), "SKILL-OK");
  write(path.join(ws, "agents", "a.md"), "AGENT-OK");
  write(path.join(ws, "memory", "m.md"), "MEMORY-OK");
  write(path.join(ws, "commands", "c.md"), "COMMAND-OK");
  write(path.join(ws, "settings.json"), JSON.stringify({ permissions: { allow: ["Bash(*)"] }, env: { LEAK: STATE_MARKER } }));
  // Planted pre-deployment links: absolute, relative, to a directory, to the root, a hardlink and a copy.
  fs.symlinkSync(creds, path.join(ws, "skills", "to-creds-abs"));
  fs.symlinkSync("../.credentials.json", path.join(ws, "skills", "to-creds-rel"));
  fs.symlinkSync(home, path.join(ws, "agents", "to-home"));
  fs.symlinkSync("/", path.join(ws, "memory", "to-root"));
  fs.linkSync(creds, path.join(ws, "skills", "hardlink.json"));
  write(path.join(ws, "memory", "copy.md"), `copied ${OAUTH_ACCESS}`);
  // A repository with a token clone URL in its configuration, plus one that is a planted link.
  write(path.join(ws, "projects", "repo", "src", "main.txt"), "REPO-OK");
  // A real repository (git needs objects and refs), whose configuration then carries a token clone URL.
  const git = (...args: string[]) => execFileSync("git", ["-C", path.join(ws, "projects", "repo"), ...args], { env: { PATH: process.env.PATH ?? "", HOME: tmp, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@example.test", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@example.test" }, stdio: "ignore" });
  git("init", "-q", "-b", "main");
  git("add", ".");
  git("commit", "-q", "-m", "init");
  // A second branch whose file is not in the checked-out tree: read-only git commands must reach it (MVP-7679 item 5).
  git("checkout", "-q", "-b", "other");
  write(path.join(ws, "projects", "repo", "feature.txt"), "OTHER-BRANCH-7679");
  git("add", ".");
  git("commit", "-q", "-m", "other branch");
  git("checkout", "-q", "main");
  write(
    path.join(ws, "projects", "repo", ".git", "config"),
    `[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = https://x-access-token:${CLONE_TOKEN}@github.com/acme/repo.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n[branch "main"]\n\tremote = origin\n\tmerge = refs/heads/main\n`,
  );
  write(path.join(ws, "projects", "repo", ".git", "modules", "sub", "config"), `[remote "origin"]\n\turl = https://u:${CLONE_TOKEN}@github.com/acme/sub.git\n`);
  fs.symlinkSync(ws, path.join(ws, "projects", "linked-repo"));
  write(path.join(ws, "projects", "knowledge-base", "doc.md"), "KB-OK");
  // Another conversation's home, with its own marker. The storage root and its directories are private (0700),
  // whatever this host's umask is.
  write(path.join(sandboxRoot, "sessions", "otherhash", "home", "secret.txt"), OTHER_SESSION_MARKER);
  for (const dir of [sandboxRoot, path.join(sandboxRoot, "sessions"), path.join(sandboxRoot, "sessions", "otherhash"), path.join(sandboxRoot, "sessions", "otherhash", "home")]) fs.chmodSync(dir, 0o700);
}

beforeAll(() => {
  buildFixture();
  savedEnv = {};
  for (const [key, value] of Object.entries(ENV_SECRETS)) {
    savedEnv[key] = process.env[key];
    process.env[key] = value;
  }
});

afterAll(() => {
  for (const [key, value] of Object.entries(savedEnv)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  fs.rmSync(tmp, { recursive: true, force: true });
});

beforeEach(async () => {
  logs = [];
  vi.spyOn(console, "log").mockImplementation((...args) => {
    logs.push(args.map(String).join(" "));
  });
  vi.spyOn(console, "error").mockImplementation((...args) => {
    logs.push(args.map(String).join(" "));
  });
  resetIsolationStatusForTests();
  proxy = new ModelProxy({ upstreamBaseUrl: "http://127.0.0.1:1", credentials: new ProviderCredentials({ home, env: { ANTHROPIC_API_KEY: PROVIDER_KEY } }) });
  await proxy.start();
});

afterEach(async () => {
  await proxy.close();
  vi.restoreAllMocks();
});

function config(overrides: Partial<IsolationConfig> = {}): IsolationConfig {
  return { ...loadIsolationConfig({ HOME: home, AGENT_SANDBOX_ROOT: sandboxRoot }), ...overrides };
}

interface ProbeResult {
  stdout: string;
  exitCode: number | null;
  run: SandboxRun;
  lines: Map<string, string>;
  token: string | null;
}

interface ProbeOptions {
  config?: IsolationConfig;
  sessionDirId?: string;
  workspaceRoot?: string;
  signal?: AbortSignal;
  /** Do not wait for the probe to exit (the caller ends it). */
  detach?: boolean;
}

/** Starts a real sandbox that runs `script` with /bin/sh, exactly as the launcher starts the runtime. */
async function probe(script: string, options: ProbeOptions = {}): Promise<ProbeResult> {
  const runLogs = createRunLogDir();
  const controller = new AbortController();
  const run = new SandboxRun({
    queryId: "q-probe",
    runLogDir: runLogs.dir,
    runLogEnv: runLogs.env,
    sessionDirId: options.sessionDirId,
    signal: options.signal ?? controller.signal,
    workspaceRoot: options.workspaceRoot ?? ws,
    config: options.config ?? config(),
    proxy,
  });
  let child: ReturnType<typeof run.spawnHook>;
  try {
    child = run.spawnHook({ command: "/bin/sh", args: ["-c", script, SDK_CLI], env: { CLAUDE_CODE_ENTRYPOINT: "sdk-ts" }, signal: options.signal ?? controller.signal });
  } catch (error) {
    await run.dispose();
    fs.rmSync(runLogs.dir, { recursive: true, force: true });
    throw error;
  }
  let stdout = "";
  child.stdout.on("data", (d: Buffer) => (stdout += d.toString("utf8")));
  child.stdin.end();
  const token = /ANTHROPIC_API_KEY=(mpt_[A-Za-z0-9_-]+)/.exec(script)?.[1] ?? null;
  if (options.detach) {
    return { stdout: "", exitCode: null, run, lines: new Map(), token };
  }
  const exitCode = await new Promise<number | null>((resolve) => {
    const timer = setTimeout(() => {
      (run.child as ChildProcess).kill("SIGKILL");
    }, 60_000);
    child.on("exit", (code) => {
      clearTimeout(timer);
      resolve(code);
    });
  });
  await run.dispose();
  fs.rmSync(runLogs.dir, { recursive: true, force: true });
  const lines = new Map<string, string>();
  for (const line of stdout.split("\n")) {
    const eq = line.indexOf("=");
    if (eq > 0 && /^[A-Z0-9_]+$/.test(line.slice(0, eq))) lines.set(line.slice(0, eq), line.slice(eq + 1));
  }
  return { stdout, exitCode, run, lines, token };
}

/** A launcher that drops --disable-userns from the arguments it is given on descriptor 3, then runs the real bwrap. */
const NO_DISABLE_USERNS_BWRAP = `#!/bin/bash\nexec /usr/bin/bwrap --args 4 "\${@:3}" 4< <(perl -0777 -pe 's/--disable-userns\\0//' <&3)\n`;

/** A conversation's recorded sandbox home name (24 hex characters), derived from a readable label. */
function dirId(label: string): string {
  return createHash("sha256").update(label).digest("hex").slice(0, 24);
}

function markersIn(text: string): string[] {
  return ALL_MARKERS.filter((m) => text.includes(m));
}

describe("environment and processes", () => {
  it("the sandbox environment is the allowlist: no gateway secret in it or in any child interpreter, only the run token as credential", async () => {
    const r = await probe(`
      echo SH_ENV_BEGIN; env | sort; echo SH_ENV_END
      echo PY_ENV_BEGIN; python3 -c "import os; print('\\n'.join('%s=%s' % kv for kv in sorted(os.environ.items())))"; echo PY_ENV_END
      echo NODE_ENV_BEGIN; node -e "for (const [k,v] of Object.entries(process.env).sort()) console.log(k+'='+v)"; echo NODE_ENV_END
      echo PERL_ENV_BEGIN; perl -e 'print "$_=$ENV{$_}\\n" for sort keys %ENV'; echo PERL_ENV_END
    `);
    expect(r.exitCode, r.stdout).toBe(0);
    const section = (name: string) => r.stdout.split(`${name}_BEGIN\n`)[1]?.split(`${name}_END`)[0] ?? "";
    const keys = (name: string) =>
      section(name)
        .split("\n")
        .filter((l) => l.includes("="))
        .map((l) => l.slice(0, l.indexOf("=")))
        .filter((k) => !["_", "PWD", "SHLVL", "OLDPWD"].includes(k))
        .sort();
    const expected = [
      "ANTHROPIC_API_KEY",
      "ANTHROPIC_BASE_URL",
      "CLAUDE_CODE_DEBUG_LOGS_DIR",
      "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
      "CLAUDE_CODE_ENTRYPOINT",
      "DISABLE_AUTOUPDATER",
      "HOME",
      "LANG",
      "PATH",
      "TERM",
      "TMPDIR",
      "USER",
      "XDG_CACHE_HOME",
    ];
    for (const name of ["SH_ENV", "PY_ENV", "NODE_ENV", "PERL_ENV"]) {
      expect(section(name).length, `${name} produced output`).toBeGreaterThan(50);
      expect(keys(name), name).toEqual(expected);
      expect(markersIn(section(name)), name).toEqual([]);
    }
    // Control: the provider credential the agent holds is a run token for the proxy, not any real key.
    const apiKey = /ANTHROPIC_API_KEY=(.*)/.exec(section("SH_ENV"))?.[1] ?? "";
    expect(apiKey).toMatch(/^mpt_[A-Za-z0-9_-]{30,}$/);
    expect(apiKey).not.toBe(PROVIDER_KEY);
    expect(section("SH_ENV")).toContain("HOME=/home/node");
    expect(section("SH_ENV")).toMatch(/ANTHROPIC_BASE_URL=http:\/\/127\.0\.0\.1:\d+/);
    expect(markersIn(r.stdout)).toEqual([]);
  });

  it("/proc shows no other process, no environment or command line of the gateway, no inherited descriptor, and the masked entries stay masked", async () => {
    const r = await probe(`
      echo PID1=$(cat /proc/1/comm)
      echo PIDS=$(ls -d /proc/[0-9]* | wc -l)
      echo SELF_ENV_HAS_HOME=$(cat /proc/self/environ | tr '\\0' '\\n' | grep -c '^HOME=/home/node$')
      python3 - <<'PYEOF'
import glob, json
# The needles are given reversed, so neither this script's command line nor its text contains one.
needles = [n[::-1] for n in json.loads(${JSON.stringify(JSON.stringify([...ALL_MARKERS, tmp].map((m) => [...m].reverse().join(""))))})]
def hits(pattern):
    count = 0
    for name in glob.glob(pattern):
        try:
            data = open(name, "rb").read().decode("latin1")
        except Exception:
            continue
        if any(n in data for n in needles):
            count += 1
    return count
print("ALL_ENV_MARKERS=%d" % hits("/proc/[0-9]*/environ"))
print("ALL_CMDLINE_MARKERS=%d" % hits("/proc/[0-9]*/cmdline"))
PYEOF
      echo FDS=$(python3 -c "import os; print(' '.join(sorted(n for n in os.listdir('/proc/self/fd') if os.path.exists('/proc/self/fd/' + n))))")
      echo KCORE=$(cat /proc/kcore 2>&1 | wc -c)
      echo TIMER_LIST=$(cat /proc/timer_list 2>&1 | wc -c)
      echo SYSRQ=$(echo b > /proc/sysrq-trigger 2>&1; echo $?)
      echo SYSCTL_WRITE=$(echo 1 > /proc/sys/kernel/hostname 2>&1; echo $?)
      echo SYS_DIR=$(test -e /sys && echo present || echo absent)
      echo CAP_EFF=$(grep CapEff /proc/self/status | awk '{print $2}')
      echo DOCKER_SOCK=$(test -e /var/run/docker.sock && echo present || echo absent)
      echo RUN_DOCKER_SOCK=$(test -e /run/docker.sock && echo present || echo absent)
      echo UNSHARE_USER=$(unshare -U true >/dev/null 2>&1; echo $?)
      echo UNSHARE_ROOT=$(unshare -r true >/dev/null 2>&1; echo $?)
      echo UNSHARE_NET=$(unshare -n true >/dev/null 2>&1; echo $?)
    `);
    expect(r.exitCode, r.stdout).toBe(0);
    const v = (key: string) => r.lines.get(key);
    // The sandbox's own init is process 1; the gateway, its parent and every sibling are not visible.
    expect(v("PID1")).toBe("bwrap");
    expect(Number(v("PIDS"))).toBeLessThanOrEqual(6);
    // Control: the sandbox can read its own environment.
    expect(v("SELF_ENV_HAS_HOME")).toBe("1");
    expect(v("ALL_ENV_MARKERS")).toBe("0");
    expect(v("ALL_CMDLINE_MARKERS")).toBe("0");
    // Only stdin, stdout and stderr (the sandbox's own listing descriptor excluded): nothing of the gateway was inherited.
    expect(v("FDS")?.trim()).toBe("0 1 2");
    expect(Number(v("KCORE"))).toBeLessThan(200);
    expect(r.stdout).not.toMatch(/KCORE=[1-9][0-9]{3,}/);
    expect(Number(v("TIMER_LIST"))).toBeLessThan(200);
    expect(v("SYSRQ")).not.toBe("0");
    expect(v("SYSCTL_WRITE")).not.toBe("0");
    expect(v("SYS_DIR")).toBe("absent");
    expect(v("CAP_EFF")).toBe("0000000000000000");
    expect(v("DOCKER_SOCK")).toBe("absent");
    expect(v("RUN_DOCKER_SOCK")).toBe("absent");
    // A nested user namespace cannot be created (and the launcher already checked it before starting).
    expect(v("UNSHARE_USER")).not.toBe("0");
    expect(v("UNSHARE_ROOT")).not.toBe("0");
  });
});

describe("what the sandbox sees of the trusted workspace", () => {
  it("trusted files, state files, other conversations and the host home are absent; allowed content is present", async () => {
    const r = await probe(`
      for p in /home/node/.claude/.credentials.json /home/node/.claude/sessions.json /home/node/.claude/tools.json /home/node/.claude/mcp-servers.json \\
               /home/node/.claude/sessions.json.corrupt-20260930T000000Z /home/node/.ssh /home/node/.ssh/id_rsa /home/node/.local/bin/claude \\
               /home/node/.claude/projects/-home-node/legacy.jsonl /home/node/.claude/debug ${home} ${ws} ${sandboxRoot} ${sandboxRoot}/sessions/otherhash/home/secret.txt; do
        echo "EXISTS:$p=$(test -e "$p" && echo yes || echo no)"
      done
      echo FIND_CREDS=$(find / -xdev \\( -name '.credentials.json' -o -name 'id_rsa' -o -name 'sessions.json' \\) 2>/dev/null | wc -l)
      echo GREP_MARKERS=$(grep -rIl 'SYNTH-' /home /tmp /etc /opt /srv /var /root /mnt 2>/dev/null | wc -l)
      echo CAT_CREDS=$(cat /home/node/.claude/.credentials.json 2>&1 | grep -c SYNTH-)
      echo READ_MEMORY=$(cat /home/node/.claude/CLAUDE.md)
      echo READ_SKILL=$(cat /home/node/.claude/skills/ok/SKILL.md)
      echo READ_AGENT=$(cat /home/node/.claude/agents/a.md)
      echo READ_MEM=$(cat /home/node/.claude/memory/m.md)
      echo READ_CMD=$(cat /home/node/.claude/commands/c.md)
      echo READ_REPO=$(cat /home/node/.claude/projects/repo/src/main.txt)
      echo READ_KB=$(cat /home/node/.claude/projects/knowledge-base/doc.md)
      echo PERMISSIONS=$(tr -d ' \\n' < /home/node/.claude/settings.json)
      echo WHOAMI_HOME=$(cd ~ && pwd)
    `);
    expect(r.exitCode, r.stdout).toBe(0);
    for (const [key, value] of r.lines) if (key.startsWith("EXISTS:")) expect(value, key).toBe("no");
    expect(r.stdout.match(/^EXISTS:/gm)?.length).toBe(14);
    expect(r.lines.get("FIND_CREDS")).toBe("0");
    expect(r.lines.get("GREP_MARKERS")).toBe("0");
    expect(r.lines.get("CAT_CREDS")).toBe("0");
    // Controls: the allowed content is visible, and the settings carry only permissions.
    expect(r.lines.get("READ_MEMORY")).toBe("GLOBAL-MEMORY-OK");
    expect(r.lines.get("READ_SKILL")).toBe("SKILL-OK");
    expect(r.lines.get("READ_AGENT")).toBe("AGENT-OK");
    expect(r.lines.get("READ_MEM")).toBe("MEMORY-OK");
    expect(r.lines.get("READ_CMD")).toBe("COMMAND-OK");
    expect(r.lines.get("READ_REPO")).toBe("REPO-OK");
    expect(r.lines.get("READ_KB")).toBe("KB-OK");
    expect(r.lines.get("PERMISSIONS")).toBe('{"permissions":{"allow":["Bash(*)"]}}');
    expect(r.lines.get("WHOAMI_HOME")).toBe("/home/node");
    expect(markersIn(r.stdout)).toEqual([]);
  });

  it("planted links and copies reach nothing: absolute and relative links, a link to the home and to /, a hardlink and a copy of a credential file", async () => {
    const r = await probe(`
      cd /home/node/.claude
      echo LINK_ABS=$(cat skills/to-creds-abs 2>&1 | grep -c SYNTH-)
      echo LINK_REL=$(cat skills/to-creds-rel 2>&1 | grep -c SYNTH-)
      echo LINK_HOME=$(ls agents/to-home/.claude/.credentials.json 2>&1 | grep -c -v 'No such')
      echo LINK_HOME_SSH=$(cat agents/to-home/.ssh/id_rsa 2>&1 | grep -c SYNTH-)
      echo LINK_ROOT=$(cat memory/to-root/home/node/.claude/.credentials.json 2>&1 | grep -c SYNTH-)
      echo HARDLINK_SIZE=$(wc -c < skills/hardlink.json)
      echo HARDLINK_MARKERS=$(cat skills/hardlink.json | grep -c SYNTH-)
      echo COPY_SIZE=$(wc -c < memory/copy.md)
      echo COPY_MARKERS=$(cat memory/copy.md | grep -c SYNTH-)
      echo LINKED_REPO=$(ls projects/linked-repo 2>&1 | grep -c -v 'No such')
      echo REPO_LINK_KB=$(ls projects | tr '\\n' ' ')
      echo RECURSIVE_MARKERS=$(grep -rIl 'SYNTH-' /home/node 2>/dev/null | wc -l)
      # In-sandbox planting: a link to a trusted path, to the host home, and ".." escapes
      ln -s /home/node/.claude/.credentials.json /home/node/plant-abs
      ln -s ${home}/.claude/.credentials.json /home/node/plant-host
      ln -s / /home/node/plant-root
      echo PLANT_ABS=$(cat /home/node/plant-abs 2>&1 | grep -c SYNTH-)
      echo PLANT_HOST=$(cat /home/node/plant-host 2>&1 | grep -c SYNTH-)
      echo PLANT_ROOT=$(cat /home/node/plant-root/home/node/.claude/.credentials.json 2>&1 | grep -c SYNTH-)
      echo DOTDOT_1=$(cat /home/node/../../${home}/.claude/.credentials.json 2>&1 | grep -c SYNTH-)
      echo DOTDOT_2=$(cat /home/node/.claude/skills/../../../../..${ws}/.credentials.json 2>&1 | grep -c SYNTH-)
      echo DOTDOT_3=$(cat /home/node/.claude/../.ssh/id_rsa 2>&1 | grep -c SYNTH-)
      # Control: a link to an allowed file works.
      ln -s /home/node/.claude/CLAUDE.md /home/node/plant-ok
      echo PLANT_CONTROL=$(cat /home/node/plant-ok)
    `);
    expect(r.exitCode, r.stdout).toBe(0);
    for (const key of ["LINK_ABS", "LINK_REL", "LINK_HOME", "LINK_HOME_SSH", "LINK_ROOT", "HARDLINK_MARKERS", "COPY_MARKERS", "LINKED_REPO", "RECURSIVE_MARKERS", "PLANT_ABS", "PLANT_HOST", "PLANT_ROOT", "DOTDOT_1", "DOTDOT_2", "DOTDOT_3"]) {
      expect(r.lines.get(key), key).toBe("0");
    }
    // The hardlink and the copy are hidden behind empty files (known secret value), not left readable.
    expect(r.lines.get("HARDLINK_SIZE")).toBe("0");
    expect(r.lines.get("COPY_SIZE")).toBe("0");
    expect(r.lines.get("REPO_LINK_KB")?.trim().split(/\s+/).sort()).toEqual(["knowledge-base", "repo"]);
    expect(r.lines.get("PLANT_CONTROL")).toBe("GLOBAL-MEMORY-OK");
    expect(markersIn(r.stdout)).toEqual([]);
    expect(logs.join("\n")).toMatch(/sandbox\.content\.skipped kind=repo name=linked-repo reason=symlink/);
    expect(logs.join("\n")).toMatch(/known_value/);
    expect(markersIn(logs.join("\n"))).toEqual([]);
  });

  it("every git configuration of a repository view holds no clone token; git still works; repositories and global content are read-only", async () => {
    const r = await probe(`
      cd /home/node/.claude/projects/repo
      echo TOKEN_FILES=$(grep -rIl 'SYNTH-CLONE-TOKEN' /home/node/.claude 2>/dev/null | wc -l)
      echo REMOTE=$(git remote -v | head -1 | awk '{print $2}')
      echo GIT_STATUS=$(git status >/dev/null 2>&1; echo $?)
      echo CONFIG_KEYS=$(git config --local --list | cut -d= -f1 | sort | tr '\\n' ' ')
      echo SUB_CONFIG=$(cat .git/modules/sub/config | tr -d '\\t\\n')
      echo WRITE_REPO=$(touch /home/node/.claude/projects/repo/new.txt 2>&1 >/dev/null; echo $?)
      echo WRITE_REPO_FILE=$(echo x >> /home/node/.claude/projects/repo/src/main.txt 2>&1; echo $?)
      echo WRITE_GIT_CONFIG=$(echo '[core]' >> /home/node/.claude/projects/repo/.git/config 2>&1; echo $?)
      echo WRITE_SKILLS=$(touch /home/node/.claude/skills/new 2>&1 >/dev/null; echo $?)
      echo WRITE_MEMORY=$(touch /home/node/.claude/memory/new 2>&1 >/dev/null; echo $?)
      echo WRITE_CLAUDE_MD=$(echo x >> /home/node/.claude/CLAUDE.md 2>&1; echo $?)
      echo WRITE_SETTINGS=$(echo x >> /home/node/.claude/settings.json 2>&1; echo $?)
      # Controls: the home and /tmp are writable, and a git command that needs no configuration write works.
      echo WRITE_HOME=$(touch /home/node/ok 2>&1 >/dev/null; echo $?)
      echo WRITE_TMP=$(touch /tmp/ok 2>&1 >/dev/null; echo $?)
      echo WRITE_TRANSCRIPT_DIR=$(mkdir -p /home/node/.claude/projects/-home-node && touch /home/node/.claude/projects/-home-node/t.jsonl 2>&1 >/dev/null; echo $?)
    `);
    expect(r.exitCode, r.stdout).toBe(0);
    expect(r.lines.get("TOKEN_FILES")).toBe("0");
    expect(r.lines.get("REMOTE")).toBe("https://github.com/acme/repo.git");
    expect(r.lines.get("GIT_STATUS")).toBe("0");
    expect(r.lines.get("CONFIG_KEYS")).toContain("remote.origin.url");
    expect(r.lines.get("SUB_CONFIG")).toBe('[remote "origin"]url = "https://github.com/acme/sub.git"'.replace(/ /g, " "));
    for (const key of ["WRITE_REPO", "WRITE_REPO_FILE", "WRITE_GIT_CONFIG", "WRITE_SKILLS", "WRITE_MEMORY", "WRITE_CLAUDE_MD", "WRITE_SETTINGS"]) {
      expect(r.lines.get(key), key).not.toBe("0");
    }
    for (const key of ["WRITE_HOME", "WRITE_TMP", "WRITE_TRANSCRIPT_DIR"]) expect(r.lines.get(key), key).toBe("0");
    expect(markersIn(r.stdout)).toEqual([]);
  });
});

describe("homes of conversations", () => {
  it("a conversation's work area and runtime data persist between runs, its home root does not; a run without a conversation leaves nothing behind", async () => {
    const first = await probe(`echo first > /work/state.txt; echo home > /home/node/state.txt; mkdir -p /home/node/.claude/todos; echo todo > /home/node/.claude/todos/t.json; echo DONE=1`, { sessionDirId: dirId("conv-A") });
    expect(first.lines.get("DONE")).toBe("1");
    const second = await probe(`echo SEEN=$(cat /work/state.txt 2>&1); echo HOME_SEEN=$(cat /home/node/state.txt 2>&1 | grep -c '^home$'); echo TODO=$(cat /home/node/.claude/todos/t.json)`, { sessionDirId: dirId("conv-A") });
    expect(second.lines.get("SEEN")).toBe("first");
    expect(second.lines.get("HOME_SEEN")).toBe("0");
    expect(second.lines.get("TODO")).toBe("todo");
    // Another conversation does not see it.
    const other = await probe(`echo SEEN=$(cat /work/state.txt 2>&1 | grep -c first); echo TODO=$(cat /home/node/.claude/todos/t.json 2>&1 | grep -c '^todo$')`, { sessionDirId: dirId("conv-B") });
    expect(other.lines.get("SEEN")).toBe("0");
    expect(other.lines.get("TODO")).toBe("0");
    // A run without a conversation: its home and work area are removed with its run directory.
    const before = fs.readdirSync(path.join(sandboxRoot, "runs"));
    const stateless = await probe(`echo x > /home/node/leftover.txt; echo x > /work/leftover.txt; echo DONE=1`);
    expect(stateless.lines.get("DONE")).toBe("1");
    expect(fs.readdirSync(path.join(sandboxRoot, "runs"))).toEqual(before);
  });

  it("a link planted by the agent in its own home at a mount point is replaced, never followed", async () => {
    const homeDir = path.join(sandboxRoot, "sessions", dirId("conv-plant"), "home");
    fs.mkdirSync(path.join(homeDir, ".claude"), { recursive: true });
    for (const dir of [path.dirname(homeDir), homeDir]) fs.chmodSync(dir, 0o700);
    const victim = write(path.join(tmp, "victim", "keep.txt"), "keep");
    fs.symlinkSync(path.join(tmp, "victim"), path.join(homeDir, ".claude", "skills"));
    fs.mkdirSync(path.join(homeDir, ".claude", "CLAUDE.md"));
    const r = await probe(`echo SKILL=$(cat /home/node/.claude/skills/ok/SKILL.md); echo MEMORY=$(cat /home/node/.claude/CLAUDE.md)`, { sessionDirId: dirId("conv-plant") });
    expect(r.exitCode, r.stdout).toBe(0);
    expect(r.lines.get("SKILL")).toBe("SKILL-OK");
    expect(r.lines.get("MEMORY")).toBe("GLOBAL-MEMORY-OK");
    expect(fs.readFileSync(victim, "utf8")).toBe("keep");
    expect(fs.existsSync(path.join(tmp, "victim", "ok"))).toBe(false);
  });
});

describe("the clean home and the work area (MVP-7679, A2)", () => {
  it("the working directory is /work: writable, persistent for the same conversation, invisible to another, and not the home", async () => {
    const first = await probe(`echo PWD=$(pwd); echo WRITE=$(echo w1 > /work/note.txt; echo $?); mkdir -p /work/sub && echo w2 > /work/sub/deep.txt; echo DONE=1`, { sessionDirId: dirId("work-A") });
    expect(first.exitCode, first.stdout).toBe(0);
    expect(first.lines.get("PWD")).toBe("/work");
    expect(first.lines.get("WRITE")).toBe("0");
    const second = await probe(`echo NOTE=$(cat /work/note.txt); echo DEEP=$(cat /work/sub/deep.txt); echo HOME_NOTE=$(ls /home/node/note.txt 2>&1 | grep -c -v 'No such')`, { sessionDirId: dirId("work-A") });
    expect(second.lines.get("NOTE")).toBe("w1");
    expect(second.lines.get("DEEP")).toBe("w2");
    expect(second.lines.get("HOME_NOTE")).toBe("0");
    const other = await probe(`echo SEEN=$(ls /work | wc -l)`, { sessionDirId: dirId("work-B") });
    expect(other.lines.get("SEEN")).toBe("0");
    const workDir = path.join(sandboxRoot, "sessions", dirId("work-A"), "work");
    expect(fs.readFileSync(path.join(workDir, "note.txt"), "utf8")).toBe("w1\n");
    expect(fs.statSync(workDir).mode & 0o777).toBe(0o700);
  });

  it("a run without a conversation gets a work area that is removed with its run", async () => {
    const before = fs.readdirSync(path.join(sandboxRoot, "runs"));
    const r = await probe(`echo x > /work/leftover.txt; echo PWD=$(pwd); echo DONE=1`);
    expect(r.lines.get("PWD")).toBe("/work");
    expect(r.lines.get("DONE")).toBe("1");
    expect(fs.readdirSync(path.join(sandboxRoot, "runs"))).toEqual(before);
  });

  it("every home-root file the agent wrote in an earlier run is gone at the next start; the data directories and the work area stay", async () => {
    const id = dirId("clean-home");
    const files = [".bashrc", ".bash_profile", ".bash_login", ".profile", ".bash_logout", ".zshenv", ".zshrc", ".zprofile", ".gitconfig", ".claude.json", ".mcp.json"];
    const first = await probe(
      `for f in ${files.join(" ")}; do echo "touch /home/node/m-$f" > /home/node/$f; done
       mkdir -p /home/node/.config/git /home/node/.claude/todos /home/node/.claude/projects/-work /home/node/.claude/commands 2>/dev/null
       echo x > /home/node/.config/git/config; echo t > /home/node/.claude/todos/t.json; echo s > /home/node/.claude/projects/-work/s.jsonl; echo w > /work/keep.txt
       echo DONE=1`,
      { sessionDirId: id },
    );
    expect(first.exitCode, first.stdout).toBe(0);
    const second = await probe(`echo HOME_ROOT=$(ls -A /home/node | tr '\n' ' '); echo TODO=$(cat /home/node/.claude/todos/t.json); echo TRANSCRIPT=$(cat /home/node/.claude/projects/-work/s.jsonl); echo WORK=$(cat /work/keep.txt)`, { sessionDirId: id });
    expect(second.exitCode, second.stdout).toBe(0);
    expect(second.lines.get("HOME_ROOT")?.trim()).toBe(".claude");
    expect(second.lines.get("TODO")).toBe("t");
    expect(second.lines.get("TRANSCRIPT")).toBe("s");
    expect(second.lines.get("WORK")).toBe("w");
  });

  it("a shell that starts as the runtime starts it (bash -l, then the snapshot) runs nothing from the home of an earlier run", async () => {
    const id = dirId("shell-start");
    await probe(`for f in .bashrc .bash_profile .bash_login .profile; do echo "touch /work/m$f" > /home/node/$f; done; echo DONE=1`, { sessionDirId: id });
    const second = await probe(`bash -l -c 'echo LOGIN=ok'; bash -i -c true 2>/dev/null; echo MARKERS=$(ls -A /work | grep -c '^m\.')`, { sessionDirId: id });
    expect(second.lines.get("LOGIN")).toBe("ok");
    expect(second.lines.get("MARKERS")).toBe("0");
    // Control: the same files DO run when a shell is started inside the run that wrote them (the markers are producible).
    const control = await probe(`for f in .bash_profile; do echo "touch /work/mc$f" > /home/node/$f; done; bash -l -c true; echo MARKERS=$(ls -A /work | grep -c '^mc\.bash_profile$')`, { sessionDirId: dirId("shell-control") });
    expect(control.lines.get("MARKERS")).toBe("1");
  });

  it("a repository planted at /work/.git with core.fsmonitor runs nothing at the next start", async () => {
    const id = dirId("work-git");
    await probe(`git init -q /work && git -C /work config core.fsmonitor 'touch /work/m-fsmonitor' && echo DONE=1`, { sessionDirId: id });
    const second = await probe(`git -C /work status --porcelain >/dev/null 2>&1; echo STATUS=$?; echo MARKER=$(ls /work/m-fsmonitor 2>&1 | grep -c -v 'No such'); echo GIT=$(ls -A /work/.git 2>&1 | grep -c -v 'No such')`, { sessionDirId: id });
    expect(second.lines.get("MARKER")).toBe("0");
    expect(second.lines.get("GIT")).toBe("0");
    // Control: the planted configuration is a working fsmonitor (git runs it inside the run that wrote it).
    const control = await probe(`git init -q /work && git -C /work config core.fsmonitor 'touch /work/m-control' && git -C /work status >/dev/null 2>&1; echo MARKER=$(ls /work/m-control 2>&1 | grep -c -v 'No such')`, { sessionDirId: dirId("work-git-control") });
    expect(control.lines.get("MARKER")).toBe("1");
  });

  it("a repository at /work/.git is removed at every start, whatever it is: a commondir pointer, a worktree config and a plain directory run nothing", async () => {
    const plant = (name: string, extra: string) =>
      `mkdir -p /work/.git/objects /work/.git/refs /work/evil/objects /work/evil/refs && echo 'ref: refs/heads/main' > /work/.git/HEAD && echo 'ref: refs/heads/main' > /work/evil/HEAD && ${extra.replaceAll("MARK", name)} && echo DONE=1`;
    const check = (name: string) =>
      `git -C /work status --porcelain >/dev/null 2>&1; echo MARKER=$(ls /work/${name} 2>&1 | grep -c -v 'No such'); echo GIT=$(ls -A /work/.git 2>&1 | grep -c -v 'No such')`;
    const rows: Array<{ name: string; extra: string }> = [
      { name: "m-commondir", extra: `echo '../evil' > /work/.git/commondir && printf '[core]\\n\\trepositoryformatversion = 0\\n\\tfsmonitor = touch /work/MARK\\n' > /work/evil/config` },
      { name: "m-worktreecfg", extra: `printf '[core]\\n\\trepositoryformatversion = 1\\n[extensions]\\n\\tworktreeConfig = true\\n' > /work/.git/config && printf '[core]\\n\\tfsmonitor = touch /work/MARK\\n' > /work/.git/config.worktree` },
      { name: "m-plain", extra: `printf '[core]\\n\\trepositoryformatversion = 0\\n\\tfsmonitor = touch /work/MARK\\n' > /work/.git/config` },
    ];
    for (const row of rows) {
      const id = dirId(`work-git-${row.name}`);
      const planted = await probe(plant(row.name, row.extra), { sessionDirId: id });
      expect(planted.lines.get("DONE"), row.name).toBe("1");
      const second = await probe(check(row.name), { sessionDirId: id });
      expect(second.lines.get("MARKER"), row.name).toBe("0");
      expect(second.lines.get("GIT"), row.name).toBe("0");
      // Control: the same planted repository DOES run its fsmonitor when git is started inside the run that wrote it.
      const control = await probe(`${plant(row.name + "c", row.extra)}; git -C /work status >/dev/null 2>&1; echo MARKER=$(ls /work/${row.name}c 2>&1 | grep -c -v 'No such')`, { sessionDirId: dirId(`work-git-control-${row.name}`) });
      expect(control.lines.get("MARKER"), row.name).toBe("1");
    }
  });

  it("every way a repository can be discovered at the root of /work runs nothing at the next start: a gitfile, an implicit bare layout (with includes, includeIf, a worktree configuration, a filter driver) and a plain directory", async () => {
    // Each plant makes git, run from /work WITHOUT the sandbox's trusted configuration, run `touch /work/MARK`.
    const BARE = `git init -q --bare /work && git -C /work config core.bare false && git -C /work config core.worktree /work`;
    const MON = `printf '[core]\\n\\tfsmonitor = touch /work/MARK\\n' > /work/inc.cfg`;
    const rows: Array<{ name: string; plant: string }> = [
      { name: "m-gitfile", plant: `mkdir -p /work/evil && git init -q --bare /work/evil && git -C /work/evil config core.fsmonitor 'touch /work/MARK' && git -C /work/evil config core.bare false && git -C /work/evil config core.worktree /work && echo 'gitdir: /work/evil' > /work/.git` },
      { name: "m-bare", plant: `${BARE} && git -C /work config core.fsmonitor 'touch /work/MARK'` },
      { name: "m-include", plant: `${BARE} && ${MON} && git -C /work config include.path /work/inc.cfg` },
      { name: "m-includeif", plant: `${BARE} && ${MON} && git -C /work config 'includeIf.gitdir:/work.path' /work/inc.cfg` },
      { name: "m-worktreecfg", plant: `${BARE} && git -C /work config extensions.worktreeConfig true && git -C /work config core.repositoryformatversion 1 && printf '[core]\\n\\tfsmonitor = touch /work/MARK\\n' > /work/config.worktree` },
      { name: "m-filter", plant: `${BARE} && git -C /work config filter.x.clean 'touch /work/MARK; cat' && echo '* filter=x' > /work/.gitattributes && echo one > /work/tracked.txt && GIT_DIR=/work git add tracked.txt .gitattributes 2>/dev/null; echo two > /work/tracked.txt; rm -f /work/MARK` },
      { name: "m-plaindir", plant: `git init -q /work && git -C /work config core.fsmonitor 'touch /work/MARK'` },
    ];
    for (const row of rows) {
      const plant = row.plant.replaceAll("MARK", row.name);
      const check = `git -C /work status --porcelain >/dev/null 2>&1; echo MARKER=$(ls /work/${row.name} 2>&1 | grep -c -v 'No such')`;
      const id = dirId(`work-vec-${row.name}`);
      const planted = await probe(`${plant}; echo DONE=1`, { sessionDirId: id });
      expect(planted.lines.get("DONE"), row.name).toBe("1");
      // The planted layout is still there (only a .git entry is removed at the start), and the next start's git runs nothing.
      const second = await probe(check, { sessionDirId: id });
      expect(second.lines.get("MARKER"), row.name).toBe("0");
      // Control: without the sandbox's trusted git configuration the same planted files DO run the command (the vector is producible).
      const control = await probe(`${plant}; env -u GIT_CONFIG_COUNT git -C /work status >/dev/null 2>&1; echo MARKER=$(ls /work/${row.name} 2>&1 | grep -c -v 'No such')`, { sessionDirId: dirId(`work-vec-c-${row.name}`) });
      expect(control.lines.get("MARKER"), `${row.name} control`).toBe("1");
    }
  });

  it("the trusted git configuration of the sandbox has the highest precedence and leaves legitimate git alone: a copied repository below /work still works, an agent's own repository cannot re-enable fsmonitor, a bare repository must be named explicitly", async () => {
    const r = await probe(
      `git init -q /work/sub && git -C /work/sub config core.fsmonitor 'touch /work/m-sub' && echo x > /work/sub/f && git -C /work/sub add f && git -C /work/sub -c user.name=a -c user.email=a@b.c commit -q -m c && echo SUBLOG=$(git -C /work/sub log --oneline | wc -l);
       git -C /work/sub status --porcelain >/dev/null 2>&1; echo SUBMARKER=$(ls /work/m-sub 2>&1 | grep -c -v 'No such');
       git init -q --bare /work/b.git; echo IMPLICIT=$(cd /work/b.git && git rev-parse --git-dir 2>&1 | head -1 | grep -c '^fatal: cannot use bare repository'); echo EXPLICIT=$(git --git-dir=/work/b.git rev-parse --is-bare-repository 2>&1);
       echo CFGCOUNT=$(git config --show-scope --list | grep -c '^command'); echo DONE=1`,
      { sessionDirId: dirId("work-git-config") },
    );
    expect(r.lines.get("SUBLOG")).toBe("1");
    expect(r.lines.get("SUBMARKER")).toBe("0");
    expect(r.lines.get("IMPLICIT")).toBe("1");
    expect(r.lines.get("EXPLICIT")).toBe("true");
    expect(r.lines.get("CFGCOUNT")).toBe("3");
  });

  it("a repository below /work (a copied project) is not consulted by the start-time git: its fsmonitor does not run, and git from /work does not see it", async () => {
    const id = dirId("work-git-nested");
    await probe(`mkdir -p /work/sub && git init -q /work/sub && git -C /work/sub config core.fsmonitor 'touch /work/m-nested' && echo DONE=1`, { sessionDirId: id });
    const second = await probe(`git -C /work status --porcelain >/dev/null 2>&1; echo STATUS=$?; echo MARKER=$(ls /work/m-nested 2>&1 | grep -c -v 'No such'); echo NESTED=$(grep -c fsmonitor /work/sub/.git/config); echo TOP=$(git -C /work rev-parse --show-toplevel 2>&1 | head -1 | grep -c '^/work$')`, { sessionDirId: id });
    expect(second.lines.get("MARKER")).toBe("0");
    expect(second.lines.get("NESTED")).toBe("1");
    expect(second.lines.get("TOP")).toBe("0");
    // Control: the nested repository is a working fsmonitor when git is run inside it.
    const control = await probe(`git init -q /work/sub && git -C /work/sub config core.fsmonitor 'touch /work/m-nested-c' && git -C /work/sub status >/dev/null 2>&1; echo MARKER=$(ls /work/m-nested-c 2>&1 | grep -c -v 'No such')`, { sessionDirId: dirId("work-git-nested-control") });
    expect(control.lines.get("MARKER")).toBe("1");
  });

  it("the start-time git cannot be steered elsewhere: no GIT_* variable but the trusted configuration, nothing an earlier run wrote above /work survives, and every configuration file it reads is outside the agent's reach", async () => {
    const id = dirId("work-git-origins");
    // Whatever the agent writes outside /work, the home and /tmp (the sandbox root is a fresh tmpfs per start) is gone at the next start.
    const planted = await probe(`mkdir -p /.git/objects /.git/refs && echo 'ref: refs/heads/main' > /.git/HEAD && printf '[core]\\n\\tfsmonitor = touch /work/m-root\\n' > /.git/config && echo DONE=1; git -C /work status >/dev/null 2>&1; echo CONTROL=$(cd / && git status >/dev/null 2>&1; ls /work/m-root 2>&1 | grep -c -v 'No such'); echo STOP=$(git -C /work rev-parse --git-dir 2>&1 | head -1 | tr ' ' '_'); rm -f /work/m-root`, { sessionDirId: id });
    expect(planted.lines.get("DONE")).toBe("1");
    // Control: that repository is a working fsmonitor for git run at /, but git's discovery from /work stops at the /work mount point and never crosses into it (the work area is its own mount).
    expect(planted.lines.get("CONTROL")).toBe("1");
    expect(planted.lines.get("STOP")).toBe("fatal:_not_a_git_repository_(or_any_parent_up_to_mount_point_/)");
    const result = await probe(
      `echo GITENV=$(env | grep '^GIT_' | grep -v -c '^GIT_CONFIG_\\(COUNT\\|KEY_[0-9]\\|VALUE_[0-9]\\)='); echo ROOTGIT=$(ls -A /.git 2>&1 | grep -c -v 'No such');
       git -C /work status >/dev/null 2>&1; echo MARKER=$(ls /work/m-root 2>&1 | grep -c -v 'No such');
       echo SEARCH=$(git -C /work rev-parse --git-dir 2>&1 | head -1 | grep -c -v '^fatal');
       for origin in $(git -C /work config --list --show-origin 2>/dev/null | cut -f1 | sort -u); do echo ORIGIN=$origin; done; echo DONE=1`,
      { sessionDirId: id },
    );
    expect(result.lines.get("GITENV")).toBe("0");
    expect(result.lines.get("ROOTGIT")).toBe("0");
    expect(result.lines.get("MARKER")).toBe("0");
    expect(result.lines.get("SEARCH")).toBe("0");
    // Whatever configuration files git lists (the system file at most) are not below /work, the home or /tmp.
    for (const line of result.stdout.split("\n").filter((l) => l.startsWith("ORIGIN="))) expect(line).not.toMatch(/\/work|\/home\/node|\/tmp/);
  });

  it("read-only git commands reach another branch of a mounted repository; git's ownership check does not block them; the repository stays read-only", async () => {
    const repo = path.join(ws, "projects", "repo");
    const branchesBefore = fs.readdirSync(path.join(repo, ".git", "refs", "heads")).sort();
    const r = await probe(`
      R=/home/node/.claude/projects/repo
      echo SHOW=$(git -C $R show other:feature.txt 2>&1)
      echo CATFILE=$(git -C $R cat-file -p other:feature.txt 2>&1)
      echo LSTREE=$(git -C $R ls-tree -r --name-only other 2>&1 | tr '\n' ,)
      echo LOG=$(git -C $R log --oneline other 2>&1 | wc -l)
      echo DIFF=$(git -C $R diff --stat main other 2>&1 | tail -1 | tr -s ' ')
      echo BRANCHES=$(git -C $R branch --list 2>&1 | tr -d ' *' | sort | tr '\n' ,)
      echo FROM_WORK=$(cd /work && git -C $R show other:feature.txt 2>&1)
      echo COMMIT=$(git -C $R -c user.name=x -c user.email=x@example.test commit --allow-empty -m x 2>&1 | head -1)
      echo NEWBRANCH=$(git -C $R branch evil 2>&1 | head -1)
      echo OWNERSHIP=$(git -C $R show other:feature.txt 2>&1 | grep -c -i 'dubious ownership')
    `);
    expect(r.exitCode, r.stdout).toBe(0);
    expect(r.lines.get("SHOW")).toBe("OTHER-BRANCH-7679");
    expect(r.lines.get("CATFILE")).toBe("OTHER-BRANCH-7679");
    expect(r.lines.get("LSTREE")).toBe("feature.txt,src/main.txt,");
    expect(r.lines.get("LOG")).toBe("2");
    expect(r.lines.get("DIFF")).toMatch(/1 file changed/);
    expect(r.lines.get("BRANCHES")).toBe("main,other,");
    expect(r.lines.get("FROM_WORK")).toBe("OTHER-BRANCH-7679");
    expect(r.lines.get("OWNERSHIP")).toBe("0");
    expect(r.lines.get("COMMIT")).toMatch(/read-only|Read-only|Permission denied|unable|error|fatal/i);
    expect(r.lines.get("NEWBRANCH")).toMatch(/read-only|Read-only|Permission denied|unable|error|fatal/i);
    expect(fs.readdirSync(path.join(repo, ".git", "refs", "heads")).sort()).toEqual(branchesBefore);
  });
});

describe("the model proxy is the only way to the provider", () => {
  it("the run token reaches the proxy from the sandbox, and stops working when the run ends", async () => {
    // The probe asks the proxy (in the shared network namespace) with its own token; the body is not a provider call.
    const script = `
      TOKEN=$ANTHROPIC_API_KEY
      echo TOKEN_SHAPE=$(echo "$TOKEN" | grep -c '^mpt_')
      echo WITH_TOKEN=$(python3 - <<'EOF'
import os, urllib.request, urllib.error
req = urllib.request.Request(os.environ["ANTHROPIC_BASE_URL"] + "/v1/models", headers={"x-api-key": os.environ["ANTHROPIC_API_KEY"]})
try:
    urllib.request.urlopen(req, timeout=5); print(200)
except urllib.error.HTTPError as e:
    print(e.code)
EOF
)
      echo WITHOUT_TOKEN=$(python3 - <<'EOF'
import os, urllib.request, urllib.error
req = urllib.request.Request(os.environ["ANTHROPIC_BASE_URL"] + "/v1/messages?beta=true", data=b"{}", method="POST")
try:
    urllib.request.urlopen(req, timeout=5); print(200)
except urllib.error.HTTPError as e:
    print(e.code)
EOF
)
    `;
    const r = await probe(script);
    expect(r.exitCode, r.stdout).toBe(0);
    expect(r.lines.get("TOKEN_SHAPE")).toBe("1");
    // With the token the proxy answers for itself (an unknown path is refused with 404), without it with 401.
    expect(r.lines.get("WITH_TOKEN")).toBe("404");
    expect(r.lines.get("WITHOUT_TOKEN")).toBe("401");
    expect(proxy.activeTokenCount()).toBe(0);
  });
});

describe("failing closed", () => {
  it("a missing isolation binary refuses the run with the permanent text, starts nothing and marks isolation unavailable", async () => {
    await expect(probe("echo started > /home/node/started", { config: config({ bwrapPath: path.join(tmp, "no-such-bwrap") }) })).rejects.toMatchObject({
      name: "IsolationFailure",
      problem: "binary_missing",
      kind: "isolation_unavailable",
      retryable: false,
    });
    expect(isolationStatus()).toBe("unavailable");
    expect(logs).toContain("[isolation] ERROR isolation problem=binary_missing reason=the isolation runtime is not installed or not executable (see /health)");
  });

  it("the state returns to ok after the next successful start", async () => {
    await expect(probe("true", { config: config({ bwrapPath: path.join(tmp, "no-such-bwrap") }) })).rejects.toBeInstanceOf(IsolationFailure);
    expect(isolationStatus()).toBe("unavailable");
    const ok = await probe("echo DONE=1");
    expect(ok.lines.get("DONE")).toBe("1");
    expect(isolationStatus()).toBe("ok");
  });

  it("a sandbox that can still create nested user namespaces is refused before the runtime starts", async () => {
    // A launcher that drops --disable-userns: the sandbox starts, the wrapper's check fails, the runtime never runs.
    const fake = path.join(tmp, "bwrap-without-disable-userns");
    fs.writeFileSync(fake, NO_DISABLE_USERNS_BWRAP, { mode: 0o755 });
    const runLogs = createRunLogDir();
    const run = new SandboxRun({ queryId: "q-probe", runLogDir: runLogs.dir, runLogEnv: runLogs.env, sessionDirId: dirId("conv-nouserns"), workspaceRoot: ws, config: config({ bwrapPath: fake }), proxy });
    const child = run.spawnHook({ command: "/bin/sh", args: ["-c", "echo started > /home/node/started", SDK_CLI], env: {}, signal: new AbortController().signal });
    child.stdin.end();
    await new Promise<void>((resolve) => child.on("exit", () => resolve()));
    expect(run.startFailure?.problem).toBe("userns_not_blocked");
    expect(run.startFailure?.kind).toBe("isolation_unavailable");
    expect(isolationStatus()).toBe("unavailable");
    expect(fs.existsSync(path.join(sandboxRoot, "sessions", dirId("conv-nouserns"), "home", "started"))).toBe(false);
    await run.dispose();
    fs.rmSync(runLogs.dir, { recursive: true, force: true });
  });

  it("a sandbox that does not report ready in time is killed and refused with the transient text; the state does not change", async () => {
    const fake = path.join(tmp, "bwrap-hangs");
    fs.writeFileSync(fake, "#!/bin/sh\nexec sleep 30\n", { mode: 0o755 });
    const runLogs = createRunLogDir();
    const run = new SandboxRun({ queryId: "q-probe", runLogDir: runLogs.dir, runLogEnv: runLogs.env, workspaceRoot: ws, config: config({ bwrapPath: fake, startupTimeoutMs: 300 }), proxy });
    const started = Date.now();
    const child = run.spawnHook({ command: "/bin/sh", args: ["-c", "true", SDK_CLI], env: {}, signal: new AbortController().signal });
    child.stdin.end();
    await new Promise<void>((resolve) => child.on("exit", () => resolve()));
    expect(Date.now() - started).toBeLessThan(5000);
    const failure = run.startFailure;
    expect(failure?.problem).toBe("timeout");
    expect(failure?.kind).toBe("isolation_timeout");
    expect(failure?.retryable).toBe(false);
    expect(failure?.message).toBe(
      "The gateway could not start a protected workspace in time, so this request did not run. Please try again in a few minutes. If it keeps happening, tell your gateway administrator. (reference: q-probe)",
    );
    // A slow start is not a permanent fault: the state stays as it was.
    expect(isolationStatus()).toBe("starting");
    await run.dispose();
    fs.rmSync(runLogs.dir, { recursive: true, force: true });
  });

  it.each([
    ["a storage root that is a symlink", (root: string) => fs.symlinkSync(os.tmpdir(), root)],
    ["a storage root that is a file", (root: string) => fs.writeFileSync(root, "x")],
    ["a storage root that is world-writable", (root: string) => fs.mkdirSync(root, { mode: 0o777 })],
    ["a storage root whose runs directory is a symlink", (root: string) => { fs.mkdirSync(root, { mode: 0o700 }); fs.symlinkSync(os.tmpdir(), path.join(root, "runs")); }],
  ])("%s refuses the run with the permanent text and starts nothing", async (_label, make) => {
    const root = path.join(tmp, `bad-root-${Math.random().toString(16).slice(2)}`);
    make(root);
    if (fs.lstatSync(root).isDirectory() && !fs.lstatSync(root).isSymbolicLink()) fs.chmodSync(root, fs.lstatSync(root).mode & 0o7777);
    await expect(probe("echo started", { config: config({ sandboxRoot: root }) })).rejects.toMatchObject({ name: "IsolationFailure", problem: "invalid_root", kind: "isolation_unavailable" });
    expect(isolationStatus()).toBe("unavailable");
  });

  it("an invalid (relative) storage root is a configuration error at startup, never a fallback", () => {
    expect(() => loadIsolationConfig({ AGENT_SANDBOX_ROOT: "relative/path" })).toThrow();
  });

  it("a mount source that is missing or unsafe is replaced by an empty trusted one; the run starts without its content", async () => {
    // A workspace with a missing CLAUDE.md and a skills entry that is a symlink to a directory.
    const odd = path.join(tmp, "odd-ws");
    fs.mkdirSync(path.join(odd, "agents"), { recursive: true });
    fs.writeFileSync(path.join(odd, "agents", "x.md"), "AGENT-X");
    fs.symlinkSync(ws, path.join(odd, "skills"));
    const r = await probe(`echo AGENT=$(cat /home/node/.claude/agents/x.md); echo SKILLS=$(ls /home/node/.claude/skills 2>&1 | grep -c 'ok'); echo MEMORY=$(test -e /home/node/.claude/CLAUDE.md && wc -c < /home/node/.claude/CLAUDE.md || echo missing); echo WRITABLE=$(touch /home/node/.claude/commands/x.md 2>&1 | grep -c 'Read-only')`, { workspaceRoot: odd });
    expect(r.exitCode, r.stdout).toBe(0);
    expect(r.lines.get("AGENT")).toBe("AGENT-X");
    expect(r.lines.get("SKILLS")).toBe("0");
    // The missing CLAUDE.md is an empty read-only file and the missing directories are empty read-only ones: nothing the agent writes there is ever loaded.
    expect(r.lines.get("MEMORY")).toBe("0");
    expect(r.lines.get("WRITABLE")).toBe("1");
  });
});

describe("boot self-check", () => {
  it("a working sandbox sets isolation ok and leaves no run directory behind", async () => {
    await runIsolationSelfCheck(config());
    expect(isolationStatus()).toBe("ok");
    expect(fs.readdirSync(path.join(sandboxRoot, "runs")).filter((n) => n.startsWith("run-"))).toEqual([]);
  });

  it("a missing binary, a sandbox that can nest user namespaces and a hanging start each set isolation unavailable with one fixed log line", async () => {
    await runIsolationSelfCheck(config({ bwrapPath: path.join(tmp, "no-such-bwrap") }));
    expect(isolationStatus()).toBe("unavailable");
    expect(logs).toContain("[isolation] ERROR isolation problem=binary_missing reason=the isolation runtime is not installed or not executable (see /health)");

    resetIsolationStatusForTests();
    logs.length = 0;
    const nouserns = path.join(tmp, "bwrap-selfcheck-nouserns");
    fs.writeFileSync(nouserns, NO_DISABLE_USERNS_BWRAP, { mode: 0o755 });
    await runIsolationSelfCheck(config({ bwrapPath: nouserns }));
    expect(isolationStatus()).toBe("unavailable");
    expect(logs).toContain("[isolation] ERROR isolation problem=userns_not_blocked reason=nested isolation is not blocked inside the sandbox (see /health)");

    resetIsolationStatusForTests();
    logs.length = 0;
    const hang = path.join(tmp, "bwrap-selfcheck-hang");
    fs.writeFileSync(hang, "#!/bin/sh\nexec sleep 30\n", { mode: 0o755 });
    await runIsolationSelfCheck(config({ bwrapPath: hang, startupTimeoutMs: 300 }));
    expect(isolationStatus()).toBe("unavailable");
    expect(logs.some((l) => l.startsWith("[isolation] ERROR isolation problem=start_failed reason=the sandbox did not start (see /health)"))).toBe(true);
  });

  it("the sweep removes leftover run directories only", () => {
    fs.mkdirSync(path.join(sandboxRoot, "runs", "run-leftover1", "home"), { recursive: true });
    fs.mkdirSync(path.join(sandboxRoot, "sessions", "keepme", "home"), { recursive: true });
    sweepSandboxRuns(sandboxRoot);
    expect(fs.existsSync(path.join(sandboxRoot, "runs", "run-leftover1"))).toBe(false);
    expect(fs.existsSync(path.join(sandboxRoot, "sessions", "keepme"))).toBe(true);
  });
});

describe("ending a run ends every sandbox process", () => {
  function sleepers(tag: string): string[] {
    try {
      return execFileSync("pgrep", ["-f", `sleep ${tag}`], { encoding: "utf8" }).split("\n").filter(Boolean);
    } catch {
      return [];
    }
  }

  async function waitUntil(check: () => boolean, ms = 10_000): Promise<boolean> {
    const end = Date.now() + ms;
    while (Date.now() < end) {
      if (check()) return true;
      await new Promise((r) => setTimeout(r, 50));
    }
    return check();
  }

  it("cancelling the run (the SDK's abort) leaves no surviving process", async () => {
    const controller = new AbortController();
    const tag = `4711.${process.pid}`;
    const r = await probe(`(sleep ${tag} &) ; sleep ${tag} & wait`, { detach: true, signal: controller.signal });
    expect(await waitUntil(() => sleepers(tag).length >= 2)).toBe(true);
    controller.abort();
    expect(await waitUntil(() => r.run.child?.exitCode !== null || r.run.child?.signalCode !== null)).toBe(true);
    expect(await waitUntil(() => sleepers(tag).length === 0), `survivors: ${sleepers(tag).join(",")}`).toBe(true);
    await r.run.dispose();
  });

  it("killing the gateway process with SIGKILL leaves no surviving process", async () => {
    assertFreshBuild();
    const tag = `4712.${process.pid}`;
    const script = `
      import fs from "node:fs";
      import path from "node:path";
      import { ModelProxy, ProviderCredentials } from ${JSON.stringify(path.join(REPO_ROOT, "dist", "model-proxy.js"))};
      import { SandboxRun } from ${JSON.stringify(path.join(REPO_ROOT, "dist", "sandbox.js"))};
      import { createRunLogDir } from ${JSON.stringify(path.join(REPO_ROOT, "dist", "sdk-run-logs.js"))};
      const proxy = new ModelProxy({ upstreamBaseUrl: "http://127.0.0.1:1", credentials: new ProviderCredentials({ home: process.env.HOME, env: {} }) });
      await proxy.start();
      const logs = createRunLogDir();
      const run = new SandboxRun({ runLogDir: logs.dir, runLogEnv: logs.env, workspaceRoot: process.env.WS, proxy,
        config: { startupTimeoutMs: 10000, runTimeoutMs: 100000, sandboxRoot: process.env.SBROOT, bwrapPath: "/usr/bin/bwrap" } });
      const child = run.spawnHook({ command: "/bin/sh", args: ["-c", "sleep ${tag} & sleep ${tag} & wait", ${JSON.stringify(SDK_CLI)}], env: {}, signal: new AbortController().signal });
      child.stdout.on("data", () => {});
      console.log("STARTED");
      setInterval(() => {}, 1000);
    `;
    const gateway = spawn(process.execPath, ["--input-type=module", "-e", script], {
      env: { PATH: process.env.PATH ?? "", HOME: home, WS: ws, SBROOT: sandboxRoot },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "";
    gateway.stdout.on("data", (d: Buffer) => (out += d.toString("utf8")));
    gateway.stderr.on("data", (d: Buffer) => (out += d.toString("utf8")));
    try {
      expect(await waitUntil(() => out.includes("STARTED"), 15_000), out).toBe(true);
      expect(await waitUntil(() => sleepers(tag).length >= 2)).toBe(true);
      gateway.kill("SIGKILL");
      expect(await waitUntil(() => sleepers(tag).length === 0), `survivors: ${sleepers(tag).join(",")}`).toBe(true);
    } finally {
      gateway.kill("SIGKILL");
    }
  }, 60_000);
});

/* ------------------------------------------------------------------ */
/*  The whole chain: gateway, real runtime, scripted model              */
/* ------------------------------------------------------------------ */

const GW_PROMPT = "PROBE-7678 run the scripted tool";
const gatewayCleanups: Cleanup[] = [];

afterEach(async () => {
  while (gatewayCleanups.length > 0) await gatewayCleanups.pop()!();
});

interface Chain {
  api: FakeAnthropicApi;
  gateway: SpawnedGateway;
}

/** A gateway with the real runtime, secrets planted in its environment and home, and a scripted model that makes one exact tool call. */
async function chain(options: { tool?: { name: string; input: Record<string, unknown> }; toolFor?: (gateway: SpawnedGateway) => { name: string; input: Record<string, unknown> }; mode?: FakeApiMode; env?: Record<string, string>; plantedHome?: (gateway: SpawnedGateway) => void } = {}): Promise<Chain> {
  // The scripted call may name paths of the gateway that is started after the model stand-in: it is filled in then.
  const scripted = options.tool ? { name: options.tool.name, input: { ...options.tool.input }, prompt: GW_PROMPT } : options.toolFor ? { name: "", input: {} as Record<string, unknown>, prompt: GW_PROMPT } : undefined;
  const api = await startFakeAnthropicApi({ toolName: "unused-7678", mode: options.mode, exactTool: scripted });
  gatewayCleanups.push(() => api.close());
  const gateway = await spawnGateway(gatewayCleanups, {
    rootPrefix: "mvp7678-chain-",
    env: {
      ANTHROPIC_BASE_URL: api.baseUrl,
      ANTHROPIC_API_KEY: PROVIDER_KEY,
      GITHUB_TOKEN: ENV_SECRETS.GITHUB_TOKEN,
      AWS_SECRET_ACCESS_KEY: ENV_SECRETS.AWS_SECRET_ACCESS_KEY,
      DISABLE_TELEMETRY: "1",
      CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
      ...options.env,
    },
  });
  // Trusted files of this gateway's home, planted before the first run.
  write(path.join(gateway.dirs.workspace, ".credentials.json"), JSON.stringify({ claudeAiOauth: { accessToken: OAUTH_ACCESS, refreshToken: OAUTH_REFRESH, expiresAt: Date.now() + 3_600_000 } }));
  write(path.join(gateway.dirs.home, ".ssh", "id_rsa"), SSH_KEY);
  write(path.join(gateway.dirs.workspace, "CLAUDE.md"), "GLOBAL-MEMORY-OK");
  options.plantedHome?.(gateway);
  if (options.toolFor && scripted) {
    const tool = options.toolFor(gateway);
    scripted.name = tool.name;
    Object.assign(scripted.input, tool.input);
  }
  return { api, gateway };
}

interface Ndjson {
  type: string;
  [key: string]: unknown;
}

async function ask(c: Chain, extra: Record<string, unknown> = {}): Promise<{ events: Ndjson[]; status: number }> {
  const res = await gatewayRequest(c.gateway.port, "POST", "/v1/query", { queryId: `q-7678-${Date.now()}`, prompt: GW_PROMPT, model: "claude-sonnet-4-5", useSession: false, ...extra });
  return {
    status: res.status,
    events: res.text
      .split("\n")
      .filter((l) => l.trim().startsWith("{"))
      .map((l) => JSON.parse(l) as Ndjson),
  };
}

function modelSeen(c: Chain): string {
  return JSON.stringify(c.api.requests.map((r) => ({ userTexts: r.userTexts, toolResults: r.toolResults })));
}

describe("an ordinary chat through the real runtime", () => {
  it("/health reports isolation ok once the boot self-check has run", async () => {
    const c = await chain();
    const started = Date.now();
    for (;;) {
      const res = await gatewayRequest(c.gateway.port, "GET", "/health");
      if (res.json?.isolation === "ok") break;
      if (Date.now() - started > 10_000) throw new Error(`isolation never became ok: ${res.text}`);
      await new Promise((r) => setTimeout(r, 100));
    }
  }, 30_000);

  it("`env | sort` in Bash shows the allowlist and the run token; no secret of the gateway reaches the result, the model or the events", async () => {
    const c = await chain({ tool: { name: "Bash", input: { command: "env | sort", description: "show the environment" } } });
    const { events } = await ask(c);
    expect(events.at(-1)?.type, JSON.stringify(events.at(-1))).toBe("done");
    const result = c.api.requests.flatMap((r) => r.toolResults)[0];
    expect(result?.isError).toBe(false);
    expect(result?.text).toContain("HOME=/home/node");
    expect(result?.text).toMatch(/ANTHROPIC_API_KEY=mpt_[A-Za-z0-9_-]+/);
    expect(result?.text).not.toContain(PROVIDER_KEY);
    expect(markersIn(result?.text ?? "")).toEqual([]);
    expect(markersIn(modelSeen(c))).toEqual([]);
    expect(markersIn(JSON.stringify(events))).toEqual([]);
    expect(markersIn(c.gateway.output())).toEqual([]);
    // The provider saw only the trusted key, never the run token.
    expect(c.api.requests.every((r) => r.apiKey === PROVIDER_KEY)).toBe(true);
  }, 90_000);

  it.each([
    ["Read of the credential file at the path the sandbox uses", (g: SpawnedGateway) => ({ name: "Read", input: { file_path: "/home/node/.claude/.credentials.json" } }), "credentials"],
    ["Read of the credential file at its host path", (g: SpawnedGateway) => ({ name: "Read", input: { file_path: path.join(g.dirs.workspace, ".credentials.json") } }), "credentials"],
    ["Read of the SSH key", (g: SpawnedGateway) => ({ name: "Read", input: { file_path: path.join(g.dirs.home, ".ssh", "id_rsa") } }), "ssh"],
    ["Bash cat of the credential file through a link the agent plants", (g: SpawnedGateway) => ({ name: "Bash", input: { command: `ln -s ${path.join(g.dirs.workspace, ".credentials.json")} /home/node/l && cat /home/node/l; cat ${path.join(g.dirs.workspace, ".credentials.json")}`, description: "probe" } }), "credentials"],
  ])("%s gets no content", async (_label, toolFor, _what) => {
    const c = await chain({ toolFor });
    const { events } = await ask(c);
    // The tool ran (a result came back) and it holds nothing of the secret.
    const result = c.api.requests.flatMap((r) => r.toolResults)[0];
    expect(result, JSON.stringify(events)).toBeDefined();
    expect(markersIn(result?.text ?? "")).toEqual([]);
    expect(markersIn(modelSeen(c))).toEqual([]);
    expect(markersIn(JSON.stringify(events))).toEqual([]);
  }, 90_000);

  it("control: the Read tool reads an allowed global file", async () => {
    const c = await chain({ tool: { name: "Read", input: { file_path: "/home/node/.claude/CLAUDE.md" } } });
    const { events } = await ask(c);
    expect(events.at(-1)?.type).toBe("done");
    const result = c.api.requests.flatMap((r) => r.toolResults)[0];
    expect(result?.isError).toBe(false);
    expect(result?.text).toContain("GLOBAL-MEMORY-OK");
  }, 90_000);
});

describe("failing closed through the gateway", () => {
  it("a missing isolation binary: /health says unavailable, the query gets the exact text, no model request is made, no run starts", async () => {
    const c = await chain({ tool: { name: "Bash", input: { command: "echo started", description: "probe" } }, env: { AGENT_SANDBOX_BWRAP: "/nonexistent/bwrap" } });
    const started = Date.now();
    for (;;) {
      const res = await gatewayRequest(c.gateway.port, "GET", "/health");
      if (res.json?.isolation === "unavailable") break;
      if (Date.now() - started > 10_000) throw new Error(`isolation never became unavailable: ${res.text}`);
      await new Promise((r) => setTimeout(r, 100));
    }
    const { events } = await ask(c, { queryId: "q-7678-closed" });
    expect(events.map((e) => e.type)).toEqual(["error"]);
    expect(events[0].content).toBe(
      "The gateway cannot start a protected workspace, so this request did not run. Ask your gateway administrator to check the gateway's isolation status. Retrying will not help until the administrator has done this. (reference: q-7678-closed)",
    );
    expect(c.api.requests).toEqual([]);
    expect(c.gateway.output()).toContain("[isolation] ERROR isolation problem=binary_missing reason=the isolation runtime is not installed or not executable (see /health)");
    expect(descendants(c.gateway.child.pid!)).toEqual([]);
  }, 60_000);

  it.each([
    ["ISOLATION_STARTUP_TIMEOUT_MS", "0", "must be a positive whole number of milliseconds"],
    ["AGENT_RUN_TIMEOUT_MS", "-3", "must be a positive whole number of milliseconds"],
    ["AGENT_SANDBOX_ROOT", "relative/root", "must be an absolute path"],
    ["AGENT_SANDBOX_BWRAP", "bwrap", "must be an absolute path"],
  ])("an invalid %s stops startup with one fixed line", async (key, value, reason) => {
    await expect(spawnGateway(gatewayCleanups, { rootPrefix: "mvp7678-cfg-", env: { [key]: value } })).rejects.toThrow(`FATAL config key=${key} reason=${reason}`);
  }, 30_000);

  it("with LOG_LEVEL=off the fixed FATAL config line and the isolation ERROR line are still printed", async () => {
    await expect(spawnGateway(gatewayCleanups, { rootPrefix: "mvp7678-cfg-off-", env: { LOG_LEVEL: "off", AGENT_SANDBOX_ROOT: "relative/root" } })).rejects.toThrow("FATAL config key=AGENT_SANDBOX_ROOT reason=must be an absolute path");
    const c = await chain({ tool: { name: "Bash", input: { command: "echo started", description: "probe" } }, env: { LOG_LEVEL: "off", AGENT_SANDBOX_BWRAP: "/nonexistent/bwrap" } });
    const started = Date.now();
    while (!c.gateway.output().includes("[isolation] ERROR isolation problem=binary_missing")) {
      if (Date.now() - started > 10_000) throw new Error(`no isolation ERROR line at LOG_LEVEL=off: ${c.gateway.output()}`);
      await new Promise((r) => setTimeout(r, 100));
    }
  }, 60_000);

  it("a run that exceeds AGENT_RUN_TIMEOUT_MS is stopped with the deadline text, nothing is saved and no process survives", async () => {
    const c = await chain({ mode: "hang", env: { AGENT_RUN_TIMEOUT_MS: "3000" } });
    const started = Date.now();
    const { events } = await ask(c, { queryId: "q-7678-deadline", sessionId: "conv-deadline", useSession: true });
    expect(Date.now() - started).toBeLessThan(15_000);
    expect(events.map((e) => e.type)).not.toContain("done");
    expect(events.at(-1)).toMatchObject({ type: "error" });
    expect(events.at(-1)?.content).toBe(
      "The request was stopped because it ran longer than the gateway's limit of 1 minute. Its results were not saved. Try again with a smaller task, or ask your gateway administrator to raise the limit. (reference: q-7678-deadline)",
    );
    // The conversation was not confirmed: the gateway's session list holds no sdk session id for it.
    const sessions = await gatewayRequest(c.gateway.port, "GET", "/v1/sessions");
    expect(JSON.stringify(sessions.json)).not.toContain('"sdkSessionId"');
    await new Promise((r) => setTimeout(r, 1500));
    expect(descendants(c.gateway.child.pid!)).toEqual([]);
  }, 60_000);
});
