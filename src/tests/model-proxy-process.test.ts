/**
 * Real-process probe for the trusted model proxy (MVP-7678, Gate B): the compiled
 * proxy (`dist/model-proxy.js`, built by `npm run build`) runs in its own process,
 * and the real Claude runtime bundled with the SDK talks to it with a run token as
 * its only "API key". The provider is a scripted stand-in for the Anthropic
 * Messages API (no real model, no real credential; every credential is synthetic).
 *
 * The runtime gets an environment ALLOWLIST (never the parent's secrets) and a
 * fresh HOME. Linux only.
 */
import { spawn, type ChildProcess } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { FINAL_ANSWER, startFakeAnthropicApi, type FakeAnthropicApi, type FakeApiMode } from "./helpers/fake-anthropic-api.js";
import { assertFreshBuild, gatewayRequest, spawnGateway, type Cleanup } from "./helpers/git-process-gateway.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(here, "..", "..");
const RUNTIME_CLI = path.join(REPO_ROOT, "node_modules", "@anthropic-ai", "claude-agent-sdk", "cli.js");

const PROVIDER_KEY = "SYNTH-PROVIDER-KEY-7678-process";
const ACCESS_2 = "SYNTH-OAUTH-ACCESS-2-7678-process";
const REFRESH_2 = "SYNTH-OAUTH-REFRESH-2-7678-process";

const cleanups: Cleanup[] = [];
afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()!();
});

function tempDir(prefix: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  cleanups.push(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

interface ProxyProcess {
  baseUrl: string;
  token: string;
  home: string;
  child: ChildProcess;
  /** Revokes the run token inside the proxy process. */
  revoke: () => Promise<void>;
}

/** The compiled proxy in its own process; prints its base URL and one run token, revokes on the line "revoke". */
async function startProxyProcess(options: { upstream: string; env: Record<string, string>; credentials?: Record<string, unknown> }): Promise<ProxyProcess> {
  assertFreshBuild();
  const home = tempDir("mvp7678-proxy-home-");
  fs.mkdirSync(path.join(home, ".claude"), { recursive: true });
  if (options.credentials) {
    fs.writeFileSync(path.join(home, ".claude", ".credentials.json"), JSON.stringify({ claudeAiOauth: options.credentials }), { mode: 0o600 });
  }
  const script = `
    import { ModelProxy, ProviderCredentials } from ${JSON.stringify(path.join(REPO_ROOT, "dist", "model-proxy.js"))};
    const proxy = new ModelProxy({ upstreamBaseUrl: process.env.TEST_UPSTREAM, credentials: new ProviderCredentials({ home: process.env.HOME }) });
    await proxy.start();
    const { token, baseUrl } = proxy.register();
    console.log(JSON.stringify({ token, baseUrl }));
    process.stdin.on("data", (d) => { if (String(d).includes("revoke")) { proxy.revoke(token); console.log("revoked"); } });
  `;
  const child = spawn(process.execPath, ["--input-type=module", "-e", script], {
    env: { PATH: process.env.PATH ?? "", HOME: home, TEST_UPSTREAM: options.upstream, ...options.env },
    stdio: ["pipe", "pipe", "pipe"],
  });
  cleanups.push(() => {
    child.kill("SIGKILL");
  });
  let out = "";
  let err = "";
  child.stdout!.on("data", (d: Buffer) => (out += d.toString("utf8")));
  child.stderr!.on("data", (d: Buffer) => (err += d.toString("utf8")));
  const started = Date.now();
  while (!out.includes("\n")) {
    if (child.exitCode !== null) throw new Error(`proxy process exited early: ${err}`);
    if (Date.now() - started > 10_000) throw new Error(`proxy process not ready: ${err}`);
    await new Promise((r) => setTimeout(r, 25));
  }
  const { token, baseUrl } = JSON.parse(out.split("\n")[0]) as { token: string; baseUrl: string };
  const revoke = async (): Promise<void> => {
    child.stdin!.write("revoke\n");
    const t = Date.now();
    while (!out.includes("revoked")) {
      if (Date.now() - t > 5000) throw new Error("revoke not confirmed");
      await new Promise((r) => setTimeout(r, 20));
    }
  };
  return { baseUrl, token, home, child, revoke };
}

interface RuntimeRun {
  exitCode: number | null;
  stdout: string;
  result: { is_error?: boolean; result?: string; subtype?: string } | null;
}

/** The real bundled runtime: one print-mode turn, with the run token as its only credential. */
async function runRuntime(baseUrl: string, token: string): Promise<RuntimeRun> {
  const home = tempDir("mvp7678-runtime-home-");
  const child = spawn(process.execPath, [RUNTIME_CLI, "-p", "say hello", "--output-format", "json", "--dangerously-skip-permissions"], {
    cwd: home,
    env: {
      PATH: process.env.PATH ?? "",
      HOME: home,
      TMPDIR: home,
      ANTHROPIC_BASE_URL: baseUrl,
      ANTHROPIC_API_KEY: token,
      DISABLE_AUTOUPDATER: "1",
      CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  cleanups.push(() => {
    child.kill("SIGKILL");
  });
  let stdout = "";
  child.stdout!.on("data", (d: Buffer) => (stdout += d.toString("utf8")));
  const exitCode = await new Promise<number | null>((resolve) => {
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
    }, 60_000);
    child.on("exit", (code) => {
      clearTimeout(timer);
      resolve(code);
    });
  });
  let result: RuntimeRun["result"] = null;
  try {
    result = JSON.parse(stdout.trim().split("\n").pop() ?? "") as RuntimeRun["result"];
  } catch {
    result = null;
  }
  return { exitCode, stdout, result };
}

async function fakeApi(mode: FakeApiMode = "normal"): Promise<FakeAnthropicApi> {
  const api = await startFakeAnthropicApi({ toolName: "none", mode });
  cleanups.push(() => api.close());
  return api;
}

/** A token endpoint that answers every refresh with the synthetic second token pair. */
async function tokenEndpoint(): Promise<{ url: string; calls: () => number }> {
  let calls = 0;
  const server = http.createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      calls++;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ access_token: ACCESS_2, refresh_token: REFRESH_2, expires_in: 3600 }));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  cleanups.push(() => {
    server.closeAllConnections();
    return new Promise<void>((resolve) => server.close(() => resolve()));
  });
  return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/v1/oauth/token`, calls: () => calls };
}

describe("model proxy with the real runtime", () => {
  it("answers a real runtime turn while only the trusted API key reaches the provider", async () => {
    const api = await fakeApi();
    const proxy = await startProxyProcess({ upstream: api.baseUrl, env: { ANTHROPIC_API_KEY: PROVIDER_KEY } });
    const run = await runRuntime(proxy.baseUrl, proxy.token);
    expect(run.exitCode).toBe(0);
    expect(run.result?.is_error).toBe(false);
    expect(run.result?.result).toBe(FINAL_ANSWER);
    expect(api.requests.length).toBeGreaterThan(0);
    for (const request of api.requests) {
      expect(request.path).toBe("/v1/messages");
      expect(request.query).toEqual(["beta"]);
      expect(request.apiKey).toBe(PROVIDER_KEY);
      expect(request.authorization).toBeNull();
    }
    // The run token never reaches the provider, and the runtime never saw the provider key (it was never in its environment).
    expect(JSON.stringify(api.requests)).not.toContain(proxy.token);
    expect(run.stdout).not.toContain(PROVIDER_KEY);
  }, 90_000);

  it("uses the trusted OAuth file, refreshes it on the trusted side and never gives the runtime a provider token", async () => {
    const api = await fakeApi();
    const tokens = await tokenEndpoint();
    const proxy = await startProxyProcess({
      upstream: api.baseUrl,
      env: { MODEL_PROXY_OAUTH_TOKEN_URL: tokens.url },
      credentials: { accessToken: "SYNTH-OAUTH-ACCESS-1-expired", refreshToken: "SYNTH-OAUTH-REFRESH-1", expiresAt: 1000, scopes: ["user:inference"], subscriptionType: "max" },
    });
    const run = await runRuntime(proxy.baseUrl, proxy.token);
    expect(run.exitCode).toBe(0);
    expect(run.result?.result).toBe(FINAL_ANSWER);
    expect(tokens.calls()).toBe(1);
    for (const request of api.requests) {
      expect(request.authorization).toBe(`Bearer ${ACCESS_2}`);
      expect(request.apiKey).toBeNull();
      expect(request.anthropicBeta ?? "").toContain("oauth-2025-04-20");
    }
    expect(JSON.stringify(api.requests)).not.toContain(proxy.token);
    const saved = JSON.parse(fs.readFileSync(path.join(proxy.home, ".claude", ".credentials.json"), "utf8")) as { claudeAiOauth: Record<string, unknown> };
    expect(saved.claudeAiOauth).toMatchObject({ accessToken: ACCESS_2, refreshToken: REFRESH_2 });
  }, 90_000);

  it("passes a provider 401 through with x-should-retry so the runtime reports an authentication failure without retrying", async () => {
    const api = await fakeApi("auth-rejected");
    const proxy = await startProxyProcess({ upstream: api.baseUrl, env: { ANTHROPIC_API_KEY: PROVIDER_KEY } });
    const run = await runRuntime(proxy.baseUrl, proxy.token);
    expect(run.exitCode).not.toBe(0);
    expect(run.result?.is_error).toBe(true);
    // A retried 401 would be dozens of requests (see the gateway notes); a passed-through x-should-retry: false stays small.
    expect(api.requests.length).toBeLessThan(10);
    expect(api.requests.every((r) => r.apiKey === PROVIDER_KEY)).toBe(true);
  }, 90_000);

  it("refuses the run token after it is revoked, with no further provider request", async () => {
    const api = await fakeApi();
    const proxy = await startProxyProcess({ upstream: api.baseUrl, env: { ANTHROPIC_API_KEY: PROVIDER_KEY } });
    const before = await runRuntime(proxy.baseUrl, proxy.token);
    expect(before.exitCode).toBe(0);
    const count = api.requests.length;
    await proxy.revoke();
    const replay = await runRuntime(proxy.baseUrl, proxy.token);
    expect(replay.result?.is_error).toBe(true);
    expect(api.requests).toHaveLength(count);
  }, 120_000);
});

describe("gateway wiring", () => {
  it("reports the login state of GET /v1/auth/status from the trusted files, without the bundled CLI and without any token", async () => {
    const gateway = await spawnGateway(cleanups, { rootPrefix: "mvp7678-auth-gw-" });
    const home = gateway.dirs.home;
    fs.writeFileSync(path.join(home, ".claude", ".credentials.json"), JSON.stringify({ claudeAiOauth: { accessToken: "SYNTH-STATUS-ACCESS", refreshToken: "SYNTH-STATUS-REFRESH", expiresAt: Date.now() + 3_600_000, subscriptionType: "max" } }), { mode: 0o600 });
    fs.writeFileSync(path.join(home, ".claude.json"), JSON.stringify({ oauthAccount: { emailAddress: "user@example.test" } }));
    const status = await gatewayRequest(gateway.port, "GET", "/v1/auth/status");
    expect(status.status).toBe(200);
    expect(status.json).toMatchObject({ loggedIn: true, authMethod: "claude.ai", email: "user@example.test", subscriptionType: "max", tokenExpired: false });
    expect(status.text).not.toContain("SYNTH-STATUS");
  }, 60_000);

  it("stops startup with a fixed fatal line for an invalid MODEL_PROXY_IDLE_TIMEOUT_MS", async () => {
    for (const bad of ["0", "-1", "abc"]) {
      await expect(spawnGateway(cleanups, { rootPrefix: "mvp7678-cfg-gw-", env: { MODEL_PROXY_IDLE_TIMEOUT_MS: bad } })).rejects.toThrow(
        /FATAL config key=MODEL_PROXY_IDLE_TIMEOUT_MS reason=must be a positive whole number of milliseconds/,
      );
    }
  }, 60_000);
});
