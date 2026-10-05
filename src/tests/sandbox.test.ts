/**
 * The isolation building blocks that need no sandbox process (MVP-7678): configuration
 * parsing with fatal invalid values, the exact bwrap argument list, the sandbox environment
 * allowlist, the fixed public failure texts and their kinds, and the run deadline.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { EventEmitter } from "node:events";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  IsolationConfigError,
  IsolationFailure,
  EXIT_CHECK_TOOL_MISSING,
  EXIT_FDS_NOT_CLOSED,
  EXIT_FDS_NOT_LISTABLE,
  EXIT_USERNS_NOT_BLOCKED,
  LAUNCH_INTERPRETER,
  LAUNCH_WRAPPER,
  buildBwrapArgv,
  buildSandboxEnv,
  launchBwrap,
  loadIsolationConfig,
  resetIsolationStatusForTests,
  runtimeEnvFrom,
  sdkProcessOf,
  SandboxRun,
  DEADLINE_KILL_CONFIRM_MS,
  type BwrapSpec,
} from "../sandbox.js";
import { RunFailure, fixedFailure, isolationTimeoutMessage, isolationUnavailableMessage, runDeadlineMessage } from "../run-failure.js";

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe("isolation configuration", () => {
  it("defaults", () => {
    expect(loadIsolationConfig({ HOME: "/home/node" })).toEqual({
      startupTimeoutMs: 10_000,
      runTimeoutMs: 7_200_000,
      sandboxRoot: "/home/node/.agent-sandbox",
      bwrapPath: "/usr/bin/bwrap",
    });
  });

  it("takes valid values", () => {
    expect(
      loadIsolationConfig({ ISOLATION_STARTUP_TIMEOUT_MS: "2500", AGENT_RUN_TIMEOUT_MS: "60000", AGENT_SANDBOX_ROOT: "/srv/sandbox", AGENT_SANDBOX_BWRAP: "/opt/bwrap" }),
    ).toEqual({ startupTimeoutMs: 2500, runTimeoutMs: 60_000, sandboxRoot: "/srv/sandbox", bwrapPath: "/opt/bwrap" });
  });

  it.each([
    ["ISOLATION_STARTUP_TIMEOUT_MS", ["", "abc", "0", "-5", "1.5", "1e3", "NaN", "99999999999999999999"], "positive_number"],
    ["AGENT_RUN_TIMEOUT_MS", ["", "abc", "0", "-5", "1.5", "0x10"], "positive_number"],
    ["AGENT_SANDBOX_ROOT", ["", "relative/dir", "./x", "a\0b"], "absolute_path"],
    ["AGENT_SANDBOX_BWRAP", ["", "bwrap", "../bwrap"], "absolute_path"],
  ] as const)("%s: an invalid value stops startup with a fixed line", (key, values, reason) => {
    for (const value of values) {
      let error: unknown;
      try {
        loadIsolationConfig({ [key]: value });
      } catch (e) {
        error = e;
      }
      expect(error, `${key}=${JSON.stringify(value)}`).toBeInstanceOf(IsolationConfigError);
      const config = error as IsolationConfigError;
      expect(config.key).toBe(key);
      expect(config.reason).toBe(reason);
      expect(config.logLine).toBe(
        reason === "positive_number"
          ? `FATAL config key=${key} reason=must be a positive whole number of milliseconds`
          : `FATAL config key=${key} reason=must be an absolute path`,
      );
      // The value itself is never part of the line.
      expect(config.logLine).not.toContain(value === "" ? "\u0000" : value);
    }
  });
});

const SPEC: BwrapSpec = {
  layout: { symlinks: [{ link: "/bin", target: "usr/bin" }, { link: "/lib", target: "usr/lib" }], binds: [] },
  procMasks: { files: ["kcore", "timer_list"], dirs: ["acpi"] },
  homeDir: "/srv/sb/sessions/abc/home",
  workDir: "/srv/sb/sessions/abc/work",
  mounts: [
    { src: "/ws/CLAUDE.md", dest: "/home/node/.claude/CLAUDE.md" },
    { src: "/ws/projects/repo", dest: "/home/node/.claude/projects/repo" },
    { src: "/srv/sb/runs/r1/trusted/gitcfg/0", dest: "/home/node/.claude/projects/repo/.git/config" },
  ],
  hidden: ["/home/node/.claude/projects/repo/leak.txt"],
  emptyFile: "/srv/sb/runs/r1/trusted/empty",
  roBinds: ["/app/node_modules/@anthropic-ai/claude-agent-sdk", "/tmp/agw-userskills-x"],
  rwBinds: ["/tmp/agent-gateway-run-x"],
  command: "/usr/local/bin/node",
  args: ["/app/node_modules/@anthropic-ai/claude-agent-sdk/cli.js", "--verbose"],
};

describe("bwrap argument list", () => {
  it("is exactly the allowlist, in this order", () => {
    expect(buildBwrapArgv(SPEC)).toEqual([
      "--unshare-user",
      "--disable-userns",
      "--unshare-pid",
      "--unshare-ipc",
      "--unshare-uts",
      "--unshare-cgroup",
      "--die-with-parent",
      "--new-session",
      "--cap-drop",
      "ALL",
      "--ro-bind",
      "/usr",
      "/usr",
      "--symlink",
      "usr/bin",
      "/bin",
      "--symlink",
      "usr/lib",
      "/lib",
      "--ro-bind",
      "/etc",
      "/etc",
      "--proc",
      "/proc",
      "--dev",
      "/dev",
      "--tmpfs",
      "/tmp",
      "--ro-bind",
      "/dev/null",
      "/proc/kcore",
      "--ro-bind",
      "/dev/null",
      "/proc/timer_list",
      "--tmpfs",
      "/proc/acpi",
      "--ro-bind",
      "/proc/sys",
      "/proc/sys",
      "--bind",
      "/srv/sb/sessions/abc/home",
      "/home/node",
      "--bind",
      "/srv/sb/sessions/abc/work",
      "/work",
      "--ro-bind",
      "/ws/CLAUDE.md",
      "/home/node/.claude/CLAUDE.md",
      "--ro-bind",
      "/ws/projects/repo",
      "/home/node/.claude/projects/repo",
      "--ro-bind",
      "/srv/sb/runs/r1/trusted/gitcfg/0",
      "/home/node/.claude/projects/repo/.git/config",
      "--ro-bind",
      "/srv/sb/runs/r1/trusted/empty",
      "/home/node/.claude/projects/repo/leak.txt",
      "--ro-bind",
      "/app/node_modules/@anthropic-ai/claude-agent-sdk",
      "/app/node_modules/@anthropic-ai/claude-agent-sdk",
      "--ro-bind",
      "/tmp/agw-userskills-x",
      "/tmp/agw-userskills-x",
      "--bind",
      "/tmp/agent-gateway-run-x",
      "/tmp/agent-gateway-run-x",
      "--chdir",
      "/work",
      "--",
      "/bin/bash",
      "--norc",
      "-p",
      "-c",
      LAUNCH_WRAPPER,
      "sandbox",
      "/usr/local/bin/node",
      "/app/node_modules/@anthropic-ai/claude-agent-sdk/cli.js",
      "--verbose",
    ]);
  });

  it("never shares the network, never binds the home of the gateway or the storage root, and keeps the isolation flags", () => {
    const argv = buildBwrapArgv(SPEC);
    for (const flag of ["--unshare-user", "--disable-userns", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup", "--die-with-parent", "--new-session"]) {
      expect(argv).toContain(flag);
    }
    expect(argv).not.toContain("--unshare-net");
    expect(argv).not.toContain("--share-net");
    expect(argv).not.toContain("--dev-bind");
    expect(argv).not.toContain("--cap-add");
    expect(argv.join(" ")).not.toContain("/srv/sb/sessions ");
  });

  it("the launch wrapper closes every descriptor above 2 first, verifies it, refuses without a descriptor listing or a start-check tool, then checks the nested user namespace, reports it and starts the runtime last", () => {
    // bash, because dash cannot close descriptors above 9: `-p` ignores BASH_ENV, exported functions and SHELLOPTS,
    // `--norc` keeps the sshd-style start files out (the launcher's stdio are sockets).
    expect(LAUNCH_INTERPRETER).toEqual(["/bin/bash", "--norc", "-p", "-c"]);
    const steps = [
      "[ -e /proc/self/fd/0 ] || exit 96",
      "for f in /proc/self/fd/*",
      'eval "exec $n>&-"',
      'if [ "$n" -gt 2 ] && [ -L "$f" ]; then exit 94; fi',
      "[ -f /usr/bin/unshare ] && [ -x /usr/bin/unshare ] && [ -f /usr/bin/true ] && [ -x /usr/bin/true ] || exit 95",
      "/usr/bin/unshare -U /usr/bin/true",
      "[ $r -eq 0 ] && exit 97",
      "[ $r -eq 1 ] || exit 95",
      "SANDBOX-CHECK-OK",
      'exec "$@"',
    ];
    const positions = steps.map((step) => LAUNCH_WRAPPER.indexOf(step));
    expect(positions.every((p) => p >= 0), JSON.stringify(positions)).toBe(true);
    expect([...positions].sort((a, b) => a - b)).toEqual(positions);
    expect(LAUNCH_WRAPPER.endsWith('exec "$@"')).toBe(true);
    expect(EXIT_FDS_NOT_CLOSED).toBe(94);
    expect(EXIT_CHECK_TOOL_MISSING).toBe(95);
    expect(EXIT_FDS_NOT_LISTABLE).toBe(96);
    expect(EXIT_USERNS_NOT_BLOCKED).toBe(97);
    // Builtins and absolute paths only: no PATH lookup (a poisoned PATH skipped the namespace check before), no substitution (it would open a descriptor of its own).
    expect(LAUNCH_WRAPPER).not.toMatch(/\$\(|`|<\(/);
    expect(LAUNCH_WRAPPER).not.toMatch(/(^|[;&| ])unshare /);
    expect(LAUNCH_WRAPPER).not.toContain("exec 3>&-");
  });
});

describe("an early exit of the launcher is classified (MVP-8020)", () => {
  const dirs: string[] = [];

  afterEach(() => {
    for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
    resetIsolationStatusForTests();
  });

  /** A launcher that writes `stderr`, waits until the data is surely read and exits with `code`; returns the start problem. */
  async function problemOf(stderr: string, code: number): Promise<string | null> {
    vi.spyOn(console, "log").mockImplementation(() => {});
    vi.spyOn(console, "error").mockImplementation(() => {});
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "launcher-class-"));
    dirs.push(dir);
    const launcher = path.join(dir, "bwrap");
    fs.writeFileSync(launcher, `#!/bin/sh\ncat >&2 <<'STDERR-END'\n${stderr}\nSTDERR-END\nsleep 0.3\nexit ${code}\n`, { mode: 0o755 });
    const config = { ...loadIsolationConfig({ HOME: dir, AGENT_SANDBOX_ROOT: path.join(dir, "root") }), bwrapPath: launcher };
    const launch = launchBwrap(config, ["--", "/bin/true"], { PATH: "/usr/bin:/bin" }, { markOk: false });
    const failure = await launch.ready.then(
      () => null,
      (f: IsolationFailure) => f,
    );
    return failure?.problem ?? null;
  }

  it.each([
    ["exit 95 (a start-check tool is missing)", "", 95, "binary_missing"],
    ["exit 94 (a descriptor survived the close)", "", 94, "start_failed"],
    ["exit 96 (no descriptor listing)", "", 96, "proc_denied"],
    ["exit 97 (nested user namespaces still work)", "", 97, "userns_not_blocked"],
    ["an interpreter that is not executable", "bwrap: execvp /bin/bash: Permission denied", 1, "binary_missing"],
    ["an interpreter that is missing", "bwrap: execvp /bin/bash: No such file or directory", 1, "binary_missing"],
    ["a mount that is denied (not the interpreter)", "bwrap: Can't bind mount /oldroot/x on /newroot/x: Permission denied", 1, "mount_failed"],
  ])("%s is classified as its problem word", async (_label, stderr, code, expected) => {
    expect(await problemOf(stderr, code)).toBe(expected);
  });
});

describe("sandbox environment", () => {
  const base = { proxyBaseUrl: "http://127.0.0.1:4455", runToken: "mpt_RUN_TOKEN", runLogEnv: { CLAUDE_CODE_DEBUG_LOGS_DIR: "/tmp/agent-gateway-run-x/debug/run.txt", XDG_CACHE_HOME: "/tmp/agent-gateway-run-x/cache" } };

  it("is an exact-key allowlist: the gateway's secrets and everything else are absent", () => {
    const secrets = {
      ANTHROPIC_API_KEY: "SYNTH-PROVIDER-KEY-x",
      API_KEYS: "a:SYNTH-GATEWAY-KEY",
      CLAUDE_CODE_OAUTH_TOKEN: "SYNTH-OAUTH-ENV",
      CLAUDE_CODE_API_KEY_HELPER_TTL_MS: "1",
      AWS_SECRET_ACCESS_KEY: "SYNTH-AWS",
      GITHUB_TOKEN: "SYNTH-GH",
      HTTPS_PROXY: "http://proxy.invalid:3128",
      HTTP_PROXY: "http://proxy.invalid:3128",
      NO_PROXY: "x",
      NODE_OPTIONS: "--require /x.js",
      LD_PRELOAD: "/x.so",
      SSH_AUTH_SOCK: "/tmp/agent.sock",
      MCP_TIMEOUT: "99",
      PATH: "/home/node/.local/bin:/usr/bin",
      DEBUG_CLAUDE_AGENT_SDK: "1",
    };
    const env = buildSandboxEnv({
      ...base,
      gatewayEnv: { ...secrets, LANG: "de_DE.UTF-8", LC_ALL: "de_DE.UTF-8", LC_CTYPE: "bad value with spaces" },
      sdkEnv: { ...secrets, CLAUDE_CODE_ENTRYPOINT: "sdk-ts", CLAUDE_AGENT_SDK_VERSION: "0.1.77", CLAUDE_CODE_ENABLE_SDK_FILE_CHECKPOINTING: "true", CLAUDE_CODE_SECRET_THING: "x" },
    });
    expect(Object.keys(env).sort()).toEqual(
      [
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_BASE_URL",
        "CLAUDE_AGENT_SDK_VERSION",
        "CLAUDE_CODE_DEBUG_LOGS_DIR",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
        "CLAUDE_CODE_ENABLE_SDK_FILE_CHECKPOINTING",
        "CLAUDE_CODE_ENTRYPOINT",
        "DISABLE_AUTOUPDATER",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_KEY_0",
        "GIT_CONFIG_KEY_1",
        "GIT_CONFIG_KEY_2",
        "GIT_CONFIG_VALUE_0",
        "GIT_CONFIG_VALUE_1",
        "GIT_CONFIG_VALUE_2",
        "HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "TERM",
        "TMPDIR",
        "USER",
        "XDG_CACHE_HOME",
      ].sort(),
    );
    expect(env).toMatchObject({
      HOME: "/home/node",
      USER: "node",
      TMPDIR: "/tmp",
      LANG: "de_DE.UTF-8",
      ANTHROPIC_BASE_URL: "http://127.0.0.1:4455",
      // The run token is the only provider credential the sandbox holds.
      ANTHROPIC_API_KEY: "mpt_RUN_TOKEN",
      DISABLE_AUTOUPDATER: "1",
      CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
    });
    expect(env.PATH).toBe("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    // Trusted, highest-precedence git configuration: no fsmonitor, no hooks, no implicit bare repository.
    const gitConfig = Object.fromEntries([0, 1, 2].map((i) => [env[`GIT_CONFIG_KEY_${i}`], env[`GIT_CONFIG_VALUE_${i}`]]));
    expect(env.GIT_CONFIG_COUNT).toBe("3");
    expect(gitConfig).toEqual({ "core.fsmonitor": "false", "core.hooksPath": "/dev/null", "safe.bareRepository": "explicit" });
    const text = JSON.stringify(env);
    for (const secret of Object.values(secrets).filter((v) => v.length >= 8)) expect(text).not.toContain(secret);
    for (const name of ["HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "NODE_OPTIONS", "LD_PRELOAD", "SSH_AUTH_SOCK", "MCP_TIMEOUT", "DEBUG_CLAUDE_AGENT_SDK", "GITHUB_TOKEN", "API_KEYS", "CLAUDE_CODE_OAUTH_TOKEN"]) expect(env[name], name).toBeUndefined();
  });

  it("passes only non-secret runtime keys from a source", () => {
    expect(
      runtimeEnvFrom({
        CLAUDE_CODE_ENTRYPOINT: "sdk-ts",
        CLAUDE_AGENT_SDK_VERSION: "0.1.77",
        CLAUDE_CODE_OAUTH_TOKEN: "SYNTH",
        CLAUDE_CODE_SECRET: "SYNTH",
        CLAUDE_CODE_FOO_KEY: "SYNTH",
        CLAUDE_CODE_PASSWORD: "SYNTH",
        CLAUDE_CODE_CREDENTIAL_PATH: "/x",
        CLAUDE_CODE_LOWER: undefined,
        claude_code_x: "1",
        CLAUDE_CODE_SPACES: "a b c",
        OTHER: "x",
      }),
    ).toEqual({ CLAUDE_CODE_ENTRYPOINT: "sdk-ts", CLAUDE_AGENT_SDK_VERSION: "0.1.77" });
  });
});

describe("fixed failure texts", () => {
  it("are exactly the pinned texts and name no internal term", () => {
    expect(isolationUnavailableMessage("q-1")).toBe(
      "The gateway cannot start a protected workspace, so this request did not run. Ask your gateway administrator to check the gateway's isolation status. Retrying will not help until the administrator has done this. (reference: q-1)",
    );
    expect(isolationTimeoutMessage("q-1")).toBe(
      "The gateway could not start a protected workspace in time, so this request did not run. Please try again in a few minutes. If it keeps happening, tell your gateway administrator. (reference: q-1)",
    );
    expect(runDeadlineMessage(7_200_000, "q-1")).toBe(
      "The request was stopped because it ran longer than the gateway's limit of 120 minutes. Its results were not saved. Try again with a smaller task, or ask your gateway administrator to raise the limit. (reference: q-1)",
    );
    expect(runDeadlineMessage(90_000, "q-1")).toContain("limit of 2 minutes");
    expect(runDeadlineMessage(1_000, "q-1")).toContain("limit of 1 minute.");
    for (const text of [isolationUnavailableMessage("q"), isolationTimeoutMessage("q"), runDeadlineMessage(60_000, "q")]) {
      expect(text).not.toMatch(/bwrap|bubblewrap|namespace|sandbox|seccomp|apparmor|proxy|userns/i);
    }
  });

  it("omit the reference for a query id that is not a plain token", () => {
    expect(isolationUnavailableMessage(undefined)).not.toContain("reference");
    expect(isolationUnavailableMessage("a b")).not.toContain("reference");
    expect(isolationTimeoutMessage("x".repeat(200))).not.toContain("reference");
  });

  it("are never retried and carry no provider facts", () => {
    const permanent = new IsolationFailure("binary_missing", "q-1");
    const timeout = new IsolationFailure("timeout", "q-1");
    const deadline = fixedFailure("run_deadline", runDeadlineMessage(60_000, "q-1"));
    for (const failure of [permanent, timeout, deadline]) {
      expect(failure).toBeInstanceOf(RunFailure);
      expect(failure.retryable).toBe(false);
      expect(failure.logFields).toMatchObject({ apiStatus: "none", providerType: "none" });
    }
    expect(permanent.kind).toBe("isolation_unavailable");
    expect(permanent.message).toBe(isolationUnavailableMessage("q-1"));
    expect(timeout.kind).toBe("isolation_timeout");
    expect(timeout.message).toBe(isolationTimeoutMessage("q-1"));
    expect(timeout.problem).toBe("timeout");
  });
});

describe("runtime exit metadata (MVP-7852)", () => {
  /** A SandboxRun whose launcher is a real process; the test owns and always reaps it. */
  function runWithLauncher(script: string) {
    const run = new SandboxRun({ runLogDir: "/nonexistent/run-log", runLogEnv: {} });
    const child = spawn(process.execPath, ["-e", script], { stdio: "ignore" });
    (run as unknown as { launch: unknown }).launch = { child, failure: () => null, ready: Promise.resolve() };
    return { run, child };
  }

  it("is null without a launch and before the launcher has exited", () => {
    expect(new SandboxRun({ runLogDir: "/nonexistent/run-log", runLogEnv: {} }).runtimeExit).toBeNull();
    const { run, child } = runWithLauncher("setTimeout(() => {}, 60000)");
    try {
      expect(run.runtimeExit).toEqual({ exitCode: null, signalCode: null });
    } finally {
      child.kill("SIGKILL");
    }
  });

  it("reports the launcher's exit code and its signal as observed", async () => {
    const exited = runWithLauncher("process.exit(3)");
    await new Promise((resolve) => exited.child.once("exit", resolve));
    expect(exited.run.runtimeExit).toEqual({ exitCode: 3, signalCode: null });

    const killed = runWithLauncher("setTimeout(() => {}, 60000)");
    const gone = new Promise((resolve) => killed.child.once("exit", resolve));
    killed.child.kill("SIGKILL");
    await gone;
    expect(killed.run.runtimeExit).toEqual({ exitCode: null, signalCode: "SIGKILL" });
  });

  it("a launcher that outlives the dispose wait and is killed by dispose() is not reported as an outside kill", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const { run, child } = runWithLauncher("setTimeout(() => {}, 60000)");
    await run.dispose(50);
    expect(child.signalCode).toBe("SIGKILL");
    expect(run.runtimeExit).toBeNull();
  });
});

describe("a launcher that ends by an outside signal (MVP-7964)", () => {
  const HOLD = "setTimeout(() => {}, 60000)";
  const reaped: ChildProcess[] = [];

  afterEach(() => {
    for (const child of reaped.splice(0)) {
      if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    }
  });

  /** A SandboxRun that watches a real launcher process; the test owns and always reaps it. */
  function watched(script: string, spawnSignal?: AbortSignal) {
    const run = new SandboxRun({ runLogDir: "/nonexistent/run-log", runLogEnv: {} });
    const child = spawn(process.execPath, ["-e", script], { stdio: "ignore" });
    reaped.push(child);
    const launch = { child, failure: () => null, ready: Promise.resolve() };
    (run as unknown as { launch: unknown }).launch = launch;
    run.watchLaunch(launch, spawnSignal);
    return { run, child };
  }

  const exited = (child: ChildProcess): Promise<void> => new Promise((resolve) => child.once("exit", () => resolve()));
  const settled = (promise: Promise<unknown>, waitMs = 200): Promise<"resolved" | "pending"> =>
    Promise.race([promise.then(() => "resolved" as const), new Promise<"pending">((resolve) => setTimeout(() => resolve("pending"), waitMs))]);

  it("unownedExit resolves with the signal when the launcher is signaled from outside", async () => {
    const { run, child } = watched(HOLD);
    process.kill(child.pid!, "SIGKILL");
    await expect(run.unownedExit()).resolves.toEqual({ exitCode: null, signalCode: "SIGKILL" });
  });

  it.each([
    ["exit code 0", "process.exit(0)"],
    ["exit code 1", "process.exit(1)"],
  ])("unownedExit stays pending for a launcher that ends with %s", async (_name, script) => {
    const { run, child } = watched(script);
    await exited(child);
    expect(await settled(run.unownedExit())).toBe("pending");
  });

  it("unownedExit stays pending for a launcher the gateway process itself killed (SDK close, abort, start failure)", async () => {
    const { run, child } = watched(HOLD);
    const gone = exited(child);
    child.kill("SIGTERM");
    await gone;
    expect(child.killed).toBe(true);
    expect(await settled(run.unownedExit())).toBe("pending");
  });

  it("unownedExit stays pending for the launcher dispose() killed after its wait", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const { run, child } = watched(HOLD);
    await run.dispose(50);
    expect(child.signalCode).toBe("SIGKILL");
    expect(await settled(run.unownedExit())).toBe("pending");
  });

  it("unownedExit stays pending when the run was already aborted", async () => {
    const aborted = new AbortController();
    const { run, child } = watched(HOLD, aborted.signal);
    aborted.abort();
    const gone = exited(child);
    process.kill(child.pid!, "SIGKILL");
    await gone;
    expect(await settled(run.unownedExit())).toBe("pending");
  });

  it("unownedExit stays pending without a launch", async () => {
    expect(await settled(new SandboxRun({ runLogDir: "/nonexistent/run-log", runLogEnv: {} }).unownedExit())).toBe("pending");
  });

  describe("the process object the SDK gets", () => {
    it("calls an exit listener registered after the end once, with the recorded code and signal", async () => {
      const child = spawn(process.execPath, ["-e", HOLD], { stdio: "ignore" });
      reaped.push(child);
      const process_ = sdkProcessOf(child);
      const gone = exited(child);
      process.kill(child.pid!, "SIGKILL");
      await gone;
      expect(process_.exitCode).toBeNull();
      expect(process_.killed).toBe(false);

      const calls: unknown[][] = [];
      process_.once("exit", (code, signal) => calls.push([code, signal]));
      expect(calls).toEqual([]);
      await new Promise((resolve) => setTimeout(resolve, 50));
      expect(calls).toEqual([[null, "SIGKILL"]]);
    });

    it("does not replay a listener registered before the end, and does not replay one that was removed", async () => {
      const child = spawn(process.execPath, ["-e", HOLD], { stdio: "ignore" });
      reaped.push(child);
      const process_ = sdkProcessOf(child);
      const live: unknown[][] = [];
      process_.on("exit", (code, signal) => live.push([code, signal]));
      const gone = exited(child);
      process.kill(child.pid!, "SIGKILL");
      await gone;

      const removed = vi.fn();
      process_.once("exit", removed);
      process_.off("exit", removed);
      await new Promise((resolve) => setTimeout(resolve, 50));
      expect(live).toEqual([[null, "SIGKILL"]]);
      expect(removed).not.toHaveBeenCalled();
    });

    it("passes streams, kill and the live state through to the launcher", async () => {
      const child = spawn(process.execPath, ["-e", HOLD], { stdio: ["pipe", "pipe", "ignore"] });
      reaped.push(child);
      const process_ = sdkProcessOf(child);
      expect(process_.stdin).toBe(child.stdin);
      expect(process_.stdout).toBe(child.stdout);
      expect(process_.killed).toBe(false);
      const gone = exited(child);
      expect(process_.kill("SIGTERM")).toBe(true);
      await gone;
      expect(process_.killed).toBe(true);
    });
  });
});

describe("the bounded stop of a run whose deadline expired (MVP-8000)", () => {
  const reaped: ChildProcess[] = [];
  const dirs: string[] = [];

  afterEach(() => {
    for (const child of reaped.splice(0)) {
      if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    }
    for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
  });

  /** A SandboxRun that owns a run directory and the given launcher. */
  function stoppable(child: unknown) {
    const run = new SandboxRun({ runLogDir: "/nonexistent/run-log", runLogEnv: {}, queryId: "q-stop" });
    const runDir = fs.mkdtempSync(path.join(os.tmpdir(), "mvp8000-rundir-"));
    dirs.push(runDir);
    (run as unknown as { launch: unknown; runDir: string }).launch = { child, failure: () => null, ready: Promise.resolve() };
    (run as unknown as { runDir: string }).runDir = runDir;
    return { run, runDir };
  }

  it("kills a launcher that ignores SIGTERM at once, confirms its exit and removes the run directory", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    const child = spawn(process.execPath, ["-e", "process.on('SIGTERM', () => {}); process.stdout.write('ready'); setTimeout(() => {}, 60000)"], { stdio: ["ignore", "pipe", "ignore"] });
    reaped.push(child);
    await new Promise((resolve) => child.stdout!.once("data", resolve));
    const { run, runDir } = stoppable(child);
    run.watchLaunch({ child, failure: () => null, ready: Promise.resolve() } as never);

    const started = Date.now();
    const pending = await run.disposeAfterDeadline();

    expect(pending).toBeNull();
    expect(Date.now() - started).toBeLessThan(DEADLINE_KILL_CONFIRM_MS);
    expect(child.signalCode).toBe("SIGKILL");
    expect(run.runtimeExit).toBeNull();
    expect(fs.existsSync(runDir)).toBe(false);
    const stayed = await Promise.race([run.unownedExit().then(() => "resolved"), new Promise((resolve) => setTimeout(() => resolve("pending"), 200))]);
    expect(stayed).toBe("pending");
  });

  it("returns within the confirm bound for a launcher whose exit is never observed, logs one line and hands back its pending exit", async () => {
    const lines: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => { lines.push(args.map(String).join(" ")); });
    const stub = Object.assign(new EventEmitter(), { exitCode: null, signalCode: null, kill: vi.fn(() => true) });
    const { run, runDir } = stoppable(stub);

    const started = Date.now();
    const pending = await run.disposeAfterDeadline();
    const elapsed = Date.now() - started;

    expect(stub.kill).toHaveBeenCalledWith("SIGKILL");
    expect(elapsed).toBeGreaterThanOrEqual(DEADLINE_KILL_CONFIRM_MS - 50);
    expect(elapsed).toBeLessThan(DEADLINE_KILL_CONFIRM_MS + 100);
    expect(lines.filter((line) => /^\[query\] sandbox exit not confirmed after deadline stop queryId=q-stop waitedMs=\d+$/.test(line))).toHaveLength(1);
    expect(pending).not.toBeNull();
    const settled = await Promise.race([pending!.exited.then(() => "exited"), new Promise((resolve) => setTimeout(() => resolve("pending"), 100))]);
    expect(settled).toBe("pending");
    expect(fs.existsSync(runDir)).toBe(true);

    stub.emit("exit", null, "SIGKILL");
    await pending!.exited;
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(fs.existsSync(runDir)).toBe(false);
  });

  it("revokes the run token even when no launcher was started", async () => {
    const proxy = { revoke: vi.fn() };
    const run = new SandboxRun({ runLogDir: "/nonexistent/run-log", runLogEnv: {}, proxy: proxy as never });
    (run as unknown as { proxyToken: string }).proxyToken = "mpt_synthetic";

    expect(await run.disposeAfterDeadline()).toBeNull();

    expect(proxy.revoke).toHaveBeenCalledWith("mpt_synthetic");
  });
});
