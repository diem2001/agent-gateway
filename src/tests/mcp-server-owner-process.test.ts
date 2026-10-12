/**
 * Outcome Probe and process rows for the ownership of registered MCP servers (MVP-7925, Gate B): the compiled
 * gateway (`dist/server.js`, built by `npm run build`) with two real API-key labels, the production Claude Agent SDK
 * and its bundled runtime, real `bwrap`, a scripted stand-in for the Anthropic Messages API and loopback MCP
 * servers that record every request with its headers. Every secret is synthetic.
 *
 * Outcome Probe: label alpha registers `jira` at the original server; label bravo's attempt to point it at an
 * attacker server and to delete it is refused with the exact 403; alpha's next run, with its user's credential,
 * still reaches the original server with that credential and the attacker server receives nothing.
 *
 * Rows: ownership across a gateway restart; the deploy step (an ownerless registry file plus `MCP_SERVER_OWNERS`,
 * the read-back lines and the owner on disk after a restart); an ownerless entry never receives a run's user
 * credential; a malformed or duplicate mapping stops the gateway with one fixed line.
 *
 * Needs `npm run build`, `bwrap` and user namespaces. Linux only.
 */
import fs from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { startFakeAnthropicApi, type ExactToolScript, type FakeAnthropicApi } from "./helpers/fake-anthropic-api.js";
import { gatewayRequest, spawnGateway, type Cleanup, type SpawnedGateway } from "./helpers/git-process-gateway.js";
import { startOAuthMcpStub, type OAuthMcpStub } from "./helpers/oauth-mcp-stub.js";

vi.setConfig({ testTimeout: 180_000 });

const cleanups: Cleanup[] = [];
afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()!();
});

const ALPHA = "label-alpha";
const BRAVO = "label-bravo";
const KEY_ALPHA = "SYNTH-GW-KEY-ALPHA-7925";
const KEY_BRAVO = "SYNTH-GW-KEY-BRAVO-7925";
const JIRA_SHARED = "Basic SYNTH-JIRA-SHARED-7925";
const JIRA_USER = "Bearer SYNTH-JIRA-USER-7925";
const DENIAL = { error: { code: "MCP_SERVER_OWNER_MISMATCH", message: 'MCP server "jira" is registered by another application' } };

interface Rig {
  api: FakeAnthropicApi;
  gateway: SpawnedGateway;
  env: Record<string, string>;
}

function gatewayEnv(api: FakeAnthropicApi, extra: Record<string, string> = {}): Record<string, string> {
  return {
    API_KEYS: `${ALPHA}:${KEY_ALPHA},${BRAVO}:${KEY_BRAVO}`,
    ANTHROPIC_BASE_URL: api.baseUrl,
    ANTHROPIC_API_KEY: "sk-ant-fake-owner-7925",
    DISABLE_TELEMETRY: "1",
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
    ...extra,
  };
}

async function rig(options: { scripts?: ExactToolScript[]; env?: Record<string, string>; seed?: (dirs: SpawnedGateway["dirs"]) => void } = {}): Promise<Rig> {
  const api = await startFakeAnthropicApi({ toolName: "unused-7925", exactTool: options.scripts ?? [] });
  cleanups.push(() => api.close());
  const env = gatewayEnv(api, options.env);
  const gateway = await spawnGateway(cleanups, { rootPrefix: "mvp7925-owner-", env, seed: options.seed });
  return { api, gateway, env };
}

async function restart(r: Rig, extraEnv: Record<string, string> = {}): Promise<SpawnedGateway> {
  const old = r.gateway;
  old.child.kill("SIGTERM");
  await new Promise<void>((resolve) => (old.child.exitCode !== null ? resolve() : old.child.once("exit", () => resolve())));
  return spawnGateway(cleanups, { reuse: old, env: { ...r.env, ...extraEnv } });
}

async function stub(): Promise<OAuthMcpStub> {
  const created = await startOAuthMcpStub({ toolNames: ["get_page"] });
  cleanups.push(() => created.close());
  return created;
}

const asAlpha = (port: number, method: string, urlPath: string, body?: unknown) => gatewayRequest(port, method, urlPath, body, KEY_ALPHA);
const asBravo = (port: number, method: string, urlPath: string, body?: unknown) => gatewayRequest(port, method, urlPath, body, KEY_BRAVO);

interface Ndjson {
  type: string;
  [key: string]: unknown;
}

async function ask(port: number, key: string, body: Record<string, unknown>): Promise<Ndjson[]> {
  const res = await gatewayRequest(port, "POST", "/v1/query", { queryId: `q-7925-${Date.now()}-${Math.floor(Math.random() * 1e6)}`, model: "claude-sonnet-4-5", useSession: false, ...body }, key);
  return res.text.split("\n").filter((l) => l.trim().startsWith("{")).map((l) => JSON.parse(l) as Ndjson);
}

function resultFor(api: FakeAnthropicApi, prompt: string): { isError: boolean; text: string } | undefined {
  return api.requests.filter((q) => q.userTexts.at(-1)?.includes(prompt) && !q.warmup).at(-1)?.toolResults.at(-1);
}

const call = (prompt: string, tool: string, input: Record<string, unknown> = { id: "R-1" }): ExactToolScript => ({ name: tool, prompt, input });

function stateFile(g: SpawnedGateway): Array<Record<string, unknown>> {
  return JSON.parse(fs.readFileSync(path.join(g.dirs.persist, "mcp-servers.json"), "utf8")) as Array<Record<string, unknown>>;
}

const ownerlessEntry = (name: string, url: string) => ({
  name,
  description: "registered before ownership",
  enabled: true,
  type: "http",
  url,
  headers: { Authorization: JIRA_SHARED },
  createdAt: "2026-09-01T00:00:00.000Z",
  updatedAt: "2026-09-01T00:00:00.000Z",
});

/* ------------------------------------------------------------------ */
/*  Outcome Probe                                                       */
/* ------------------------------------------------------------------ */

describe("Outcome Probe: another label cannot redirect a registered MCP server (real gateway, real runtime)", () => {
  it("bravo's address change and delete are refused; alpha's next run still reaches the original server with its user's credential", async () => {
    const original = await stub();
    const attacker = await stub();
    const r = await rig({ scripts: [call("PROBE-OWNER-RUN", "mcp__jira__get_page")] });
    const port = r.gateway.port;

    const created = await asAlpha(port, "PUT", "/v1/mcp-servers/jira", { type: "http", url: original.url, headers: { Authorization: JIRA_SHARED } });
    expect(created.status, created.text).toBe(201);

    // The attempt: observed status, body and the stored address.
    const change = await asBravo(port, "PUT", "/v1/mcp-servers/jira", { type: "http", url: attacker.url, headers: { Authorization: "Basic SYNTH-ATTACKER-7925" } });
    const remove = await asBravo(port, "DELETE", "/v1/mcp-servers/jira");
    process.stderr.write(`OUTCOME-PROBE-7925 bravoPut=${change.status} bravoDelete=${remove.status} body=${change.text}\n`);
    expect(change.status).toBe(403);
    expect(change.text).toBe(JSON.stringify(DENIAL));
    expect(remove.status).toBe(403);
    expect(remove.text).toBe(JSON.stringify(DENIAL));
    const stored = await asAlpha(port, "GET", "/v1/mcp-servers/jira");
    expect(stored.json).toMatchObject({ name: "jira", url: original.url });
    expect(stored.json).not.toHaveProperty("owner");

    // Alpha's next run, with its user's credential, still reaches the original server.
    const events = await ask(port, KEY_ALPHA, { prompt: "PROBE-OWNER-RUN", mcpCredentialOverrides: { jira: { headers: { authorization: JIRA_USER } } } });
    expect(events.at(-1)?.type, JSON.stringify(events.at(-1))).toBe("done");
    expect(resultFor(r.api, "PROBE-OWNER-RUN")).toMatchObject({ isError: false, text: expect.stringContaining("RECORD-7667-OK") });
    process.stderr.write(`OUTCOME-PROBE-7925 originalRequests=${original.authorizations().length} attackerRequests=${attacker.requests.length}\n`);
    expect(original.authorizations().length).toBeGreaterThan(0);
    expect(original.authorizations().every((a) => a === JIRA_USER)).toBe(true);
    expect(attacker.requests).toEqual([]);
    expect(JSON.stringify(events) + r.gateway.output()).not.toContain("SYNTH-JIRA-USER-7925");
  });
});

/* ------------------------------------------------------------------ */
/*  Ownership across a restart                                          */
/* ------------------------------------------------------------------ */

describe("ownership persists across a gateway restart", () => {
  it("bravo is still refused and alpha still accepted after a restart; the owner is in the state file and never in a response", async () => {
    const original = await stub();
    const r = await rig();
    expect((await asAlpha(r.gateway.port, "PUT", "/v1/mcp-servers/jira", { type: "http", url: original.url })).status).toBe(201);

    const restarted = await restart(r);
    expect(restarted.port).not.toBe(r.gateway.port);

    const attack = await asBravo(restarted.port, "PUT", "/v1/mcp-servers/jira", { type: "http", url: "http://127.0.0.1:9/mcp" });
    expect(attack.status).toBe(403);
    expect(attack.text).toBe(JSON.stringify(DENIAL));
    expect((await asBravo(restarted.port, "DELETE", "/v1/mcp-servers/jira")).status).toBe(403);
    const update = await asAlpha(restarted.port, "PUT", "/v1/mcp-servers/jira", { type: "http", url: original.url, description: "after restart" });
    expect(update.status).toBe(200);
    expect(update.text).not.toContain(ALPHA);
    // The registry saves 100 ms after a change.
    await new Promise((resolve) => setTimeout(resolve, 400));
    expect(stateFile(restarted)).toEqual([expect.objectContaining({ name: "jira", owner: ALPHA, description: "after restart", url: original.url })]);
  });
});

/* ------------------------------------------------------------------ */
/*  Deploy step: operator mapping                                       */
/* ------------------------------------------------------------------ */

describe("deploy step: an ownerless registry and MCP_SERVER_OWNERS", () => {
  const seedOwnerless = (url: string) => (dirs: SpawnedGateway["dirs"]) => {
    fs.writeFileSync(path.join(dirs.persist, "mcp-servers.json"), JSON.stringify([ownerlessEntry("jira", url), ownerlessEntry("legacy", url)], null, 2));
  };

  it("assigns the mapped owner at startup, reads back zero ownerless entries and keeps it after a restart", async () => {
    const original = await stub();
    const r = await rig({ env: { MCP_SERVER_OWNERS: `jira:${ALPHA}, legacy:${BRAVO}` }, seed: seedOwnerless(original.url) });

    const out = r.gateway.output();
    expect(out).toContain("mcp.registry.owner_assigned serverName=jira");
    expect(out).toContain("mcp.registry.owner_assigned serverName=legacy");
    expect(out).toContain("mcp.registry.ownerless count=0 names= saved=true");
    expect(stateFile(r.gateway).map((e) => [e.name, e.owner])).toEqual([
      ["jira", ALPHA],
      ["legacy", BRAVO],
    ]);
    const health = (await asAlpha(r.gateway.port, "GET", "/health")).json as { persistence?: string };
    expect(health.persistence ?? "ok").toBe("ok");

    // Restart with the same mapping: nothing changes, the read-back still shows zero.
    const restarted = await restart(r);
    const again = restarted.output();
    expect(again).toContain("mcp.registry.owner_mapping serverName=jira result=already_assigned");
    expect(again).toContain("mcp.registry.ownerless count=0 names= saved=true");
    expect((await asBravo(restarted.port, "PUT", "/v1/mcp-servers/jira", { type: "http", url: "http://127.0.0.1:9/mcp" })).status).toBe(403);
    expect((await asAlpha(restarted.port, "PUT", "/v1/mcp-servers/jira", { type: "http", url: original.url })).status).toBe(200);
    expect(fs.readdirSync(restarted.dirs.persist).filter((f) => f.includes(".corrupt-"))).toEqual([]);
  });

  it("does not transfer an owned server, does not assign an unknown label and lists what stays ownerless", async () => {
    const original = await stub();
    const r = await rig({
      env: { MCP_SERVER_OWNERS: `jira:${ALPHA},jira:${ALPHA}` },
      seed: seedOwnerless(original.url),
    }).catch((e: unknown) => e);
    // A duplicate name is a configuration error, not a transfer.
    expect(String((r as Error).message)).toContain("FATAL config key=MCP_SERVER_OWNERS reason=the same server name listed twice");

    const second = await rig({
      env: { MCP_SERVER_OWNERS: `jira:${ALPHA},legacy:no-such-label,gone:${ALPHA}` },
      seed: seedOwnerless(original.url),
    });
    const out = second.gateway.output();
    expect(out).toContain("mcp.registry.owner_assigned serverName=jira");
    expect(out).toContain("mcp.registry.owner_mapping serverName=legacy result=unknown_label");
    expect(out).toContain("mcp.registry.owner_mapping serverName=gone result=not_registered");
    expect(out).toContain("mcp.registry.ownerless count=1 names=legacy saved=true");
    // The entry that stayed ownerless is refused for every label.
    expect((await asAlpha(second.gateway.port, "DELETE", "/v1/mcp-servers/legacy")).status).toBe(403);
    expect((await asBravo(second.gateway.port, "PUT", "/v1/mcp-servers/legacy", { type: "http", url: "http://127.0.0.1:9/mcp" })).status).toBe(403);
    // A later mapping for an owned entry changes nothing.
    const restarted = await restart(second, { MCP_SERVER_OWNERS: `jira:${BRAVO}` });
    expect(restarted.output()).toContain("mcp.registry.owner_mapping serverName=jira result=already_owned");
    expect(stateFile(restarted).find((e) => e.name === "jira")?.owner).toBe(ALPHA);
  });

  it.each([
    ["jira", "entry without a server name or label"],
    [`:${ALPHA}`, "entry without a server name or label"],
    ["jira:", "entry without a server name or label"],
  ])("a malformed mapping %j stops the gateway with one fixed line", async (mapping, reason) => {
    const outcome = await rig({ env: { MCP_SERVER_OWNERS: mapping } }).catch((e: unknown) => e);
    expect(outcome).toBeInstanceOf(Error);
    const message = (outcome as Error).message;
    expect(message).toContain(`FATAL config key=MCP_SERVER_OWNERS reason=${reason}`);
    expect(message).not.toContain("Agent Gateway v");
  });
});

/* ------------------------------------------------------------------ */
/*  An ownerless entry never receives a run's credential                */
/* ------------------------------------------------------------------ */

describe("an ownerless entry does not receive a run's per-user credential (real runtime)", () => {
  it("the run leaves it out (reason=ownerless), the server sees no request and no credential appears in the log", async () => {
    const original = await stub();
    const r = await rig({
      scripts: [call("PROBE-OWNERLESS-RUN", "mcp__jira__get_page")],
      seed: (dirs) => fs.writeFileSync(path.join(dirs.persist, "mcp-servers.json"), JSON.stringify([ownerlessEntry("jira", original.url)], null, 2)),
    });
    expect(r.gateway.output()).toContain("mcp.registry.ownerless count=1 names=jira saved=true");

    const events = await ask(r.gateway.port, KEY_ALPHA, { prompt: "PROBE-OWNERLESS-RUN", mcpCredentialOverrides: { jira: { headers: { authorization: JIRA_USER } } } });
    expect(events.at(-1)?.type, JSON.stringify(events.at(-1))).toBe("done");
    expect(r.gateway.output()).toContain("mcp.server.omitted serverName=jira reason=ownerless");
    expect(r.gateway.output()).not.toContain("mcp.override.applied serverName=jira");
    expect(original.requests).toEqual([]);
    expect(JSON.stringify(events) + r.gateway.output()).not.toContain("SYNTH-JIRA-USER-7925");

    // The registry routes refuse it for every label and the direct routes refuse a credential.
    expect((await asAlpha(r.gateway.port, "PUT", "/v1/mcp-servers/jira", { type: "http", url: "http://127.0.0.1:9/mcp" })).status).toBe(403);
    const direct = await asAlpha(r.gateway.port, "POST", "/v1/mcp-servers/jira/call", { tool: "get_page", arguments: {}, credentials: { headers: { authorization: JIRA_USER } } });
    expect(direct.status).toBe(403);
    expect(direct.text).toBe(JSON.stringify(DENIAL));
    expect(original.requests).toEqual([]);
  });
});
