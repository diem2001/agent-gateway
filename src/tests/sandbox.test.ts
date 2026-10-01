/**
 * The isolation building blocks that need no sandbox process (MVP-7678): configuration
 * parsing with fatal invalid values, the exact bwrap argument list, the sandbox environment
 * allowlist, the fixed public failure texts and their kinds, and the run deadline.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  IsolationConfigError,
  IsolationFailure,
  LAUNCH_WRAPPER,
  buildBwrapArgv,
  buildSandboxEnv,
  loadIsolationConfig,
  runtimeEnvFrom,
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
      "/home/node",
      "--",
      "/bin/sh",
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

  it("the launch wrapper refuses to run unless a nested user namespace fails, reports the check and starts the runtime last", () => {
    expect(LAUNCH_WRAPPER).toContain("unshare -U true");
    expect(LAUNCH_WRAPPER).toContain("exit 97");
    expect(LAUNCH_WRAPPER.indexOf("exit 97")).toBeLessThan(LAUNCH_WRAPPER.indexOf("exec 3>&-"));
    expect(LAUNCH_WRAPPER.indexOf("exec 3>&-")).toBeLessThan(LAUNCH_WRAPPER.indexOf("SANDBOX-CHECK-OK"));
    expect(LAUNCH_WRAPPER.endsWith('exec "$@"')).toBe(true);
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
