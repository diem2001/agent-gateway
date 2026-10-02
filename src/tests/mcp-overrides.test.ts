import { describe, expect, it } from "vitest";
import {
  applyMcpCredentialOverride,
  applyMcpCredentialOverrides,
  hasUserCredential,
  carriesCredentialValue,
  selectRegistryServersForRun,
  summarizeOverrideKeys,
} from "../mcp-overrides.js";
import type { McpServerDefinition, SdkMcpServerConfig } from "../mcp-registry.js";

function perUserServer(overrides: Partial<McpServerDefinition> = {}): McpServerDefinition {
  return {
    name: "aida",
    description: "",
    enabled: true,
    type: "http",
    url: "http://aida-sim:8080/mcp",
    requireUserCredentials: true,
    owner: "reqlift",
    createdAt: "2026-09-28T00:00:00.000Z",
    updatedAt: "2026-09-28T00:00:00.000Z",
    ...overrides,
  };
}

function headerSchema(outputKey: string): McpServerDefinition["userCredentialSchema"] {
  return {
    fields: [{ key: "token", label: "Token", type: "password", required: true }],
    outputs: [{ target: "headers", outputKey, template: "Bearer {token}" }],
  };
}

describe("MCP credential overrides", () => {
  it("shallow-merges HTTP headers with override keys winning", () => {
    const base: SdkMcpServerConfig = {
      type: "http",
      url: "http://127.0.0.1:3002/mcp",
      headers: { Authorization: "STATIC", "X-Static": "1" },
    };

    expect(
      applyMcpCredentialOverride(base, {
        headers: { Authorization: "Bearer USER_X" },
        env: { TOKEN: "ignored" },
      }),
    ).toEqual({
      type: "http",
      url: "http://127.0.0.1:3002/mcp",
      headers: { Authorization: "Bearer USER_X", "X-Static": "1" },
    });
    expect(base.headers?.Authorization).toBe("STATIC");
  });

  it("shallow-merges SSE headers with override keys winning", () => {
    const base: SdkMcpServerConfig = {
      type: "sse",
      url: "http://127.0.0.1:3003/sse",
      headers: { Authorization: "STATIC" },
    };

    expect(applyMcpCredentialOverride(base, { headers: { Authorization: "Bearer USER_X" } })).toEqual({
      type: "sse",
      url: "http://127.0.0.1:3003/sse",
      headers: { Authorization: "Bearer USER_X" },
    });
  });

  it("shallow-merges stdio env with override keys winning", () => {
    const base: SdkMcpServerConfig = {
      command: "node",
      args: ["env-probe.js"],
      env: { TOKEN: "STATIC", KEEP: "1" },
    };

    expect(
      applyMcpCredentialOverride(base, {
        env: { TOKEN: "USER_X" },
        headers: { Authorization: "ignored" },
      }),
    ).toEqual({
      command: "node",
      args: ["env-probe.js"],
      env: { TOKEN: "USER_X", KEEP: "1" },
    });
    expect(base.env?.TOKEN).toBe("STATIC");
  });

  it("applies overrides without mutating the registry config map", () => {
    const base: Record<string, SdkMcpServerConfig> = {
      jira: {
        type: "http",
        url: "http://mcp-jira:3002/mcp",
        headers: { Authorization: "Basic STATIC" },
      },
    };

    const mergedA = applyMcpCredentialOverrides(base, {
      jira: { headers: { Authorization: "Basic USER_A" } },
    });
    const mergedB = applyMcpCredentialOverrides(base, {
      jira: { headers: { Authorization: "Basic USER_B" } },
    });

    expect((mergedA.jira as { headers: Record<string, string> }).headers.Authorization).toBe("Basic USER_A");
    expect((mergedB.jira as { headers: Record<string, string> }).headers.Authorization).toBe("Basic USER_B");
    expect((base.jira as { headers: Record<string, string> }).headers.Authorization).toBe("Basic STATIC");
  });

  it("summarizes override keys without values", () => {
    expect(
      summarizeOverrideKeys({
        headers: { Authorization: "Bearer USER_X" },
        env: { TOKEN: "USER_X" },
      }),
    ).toEqual(["headers.Authorization", "env.TOKEN"]);
  });
});

describe("requireUserCredentials header output keys (MVP-7763)", () => {
  const casings = ["Authorization", "authorization", "AUTHORIZATION"];

  it.each(casings)("a headers output key %s is satisfied by an Authorization header", (outputKey) => {
    const def = perUserServer({ userCredentialSchema: headerSchema(outputKey) });
    expect(hasUserCredential(def, { headers: { Authorization: "Bearer USER_X" } })).toBe(true);
  });

  it.each(casings)("selectRegistryServersForRun attaches the server for output key %s", (outputKey) => {
    const def = perUserServer({ userCredentialSchema: headerSchema(outputKey) });
    expect(selectRegistryServersForRun([def], { aida: { headers: { Authorization: "Bearer USER_X" } } })).toEqual({
      attached: [def],
      omitted: [],
    });
  });

  it("is not satisfied by an empty duplicate header that differs only by case", () => {
    const def = perUserServer({ userCredentialSchema: headerSchema("Authorization") });
    const override = { headers: { Authorization: "Bearer USER_X", authorization: "" } };
    expect(hasUserCredential(def, override)).toBe(false);
    expect(selectRegistryServersForRun([def], { aida: override })).toEqual({ attached: [], omitted: [{ name: "aida", reason: "missing_user_credential" }] });
  });

  it("is not satisfied by an empty Authorization header alone", () => {
    const def = perUserServer({ userCredentialSchema: headerSchema("Authorization") });
    expect(hasUserCredential(def, { headers: { Authorization: "", "X-Other": "1" } })).toBe(false);
  });

  it("is not satisfied when no header matches the output key in any casing", () => {
    const def = perUserServer({ userCredentialSchema: headerSchema("authorization") });
    expect(hasUserCredential(def, { headers: { "X-Api-Key": "KEY" } })).toBe(false);
  });

  it("keeps env output keys case-sensitive for stdio servers", () => {
    const def = perUserServer({
      type: "stdio",
      url: undefined,
      command: "node",
      userCredentialSchema: {
        fields: [{ key: "token", label: "Token", type: "password", required: true }],
        outputs: [{ target: "env", outputKey: "API_TOKEN", template: "{token}" }],
      },
    });
    expect(hasUserCredential(def, { env: { api_token: "USER_X" } })).toBe(false);
    expect(hasUserCredential(def, { env: { API_TOKEN: "USER_X" } })).toBe(true);
    expect(selectRegistryServersForRun([def], { aida: { env: { api_token: "USER_X" } } })).toEqual({
      attached: [],
      omitted: [{ name: "aida", reason: "missing_user_credential" }],
    });
  });
});


describe("ownerless servers (MVP-7925)", () => {
  const ownerless = (): McpServerDefinition => {
    const { owner: _owner, ...rest } = perUserServer({ requireUserCredentials: undefined });
    return rest;
  };

  it("carriesCredentialValue needs one non-empty header or env value", () => {
    expect(carriesCredentialValue(undefined)).toBe(false);
    expect(carriesCredentialValue({})).toBe(false);
    expect(carriesCredentialValue({ headers: { Authorization: "" }, env: { TOKEN: "" } })).toBe(false);
    expect(carriesCredentialValue({ headers: { Authorization: "Bearer X" } })).toBe(true);
    expect(carriesCredentialValue({ env: { TOKEN: "x" } })).toBe(true);
  });

  it("leaves an ownerless server out of a run that carries a credential for it, with the reason", () => {
    const def = ownerless();
    expect(selectRegistryServersForRun([def], { aida: { headers: { Authorization: "Bearer USER_X" } } })).toEqual({
      attached: [],
      omitted: [{ name: "aida", reason: "ownerless" }],
    });
    expect(selectRegistryServersForRun([def], { aida: { env: { TOKEN: "USER_X" } } }).omitted).toEqual([{ name: "aida", reason: "ownerless" }]);
  });

  it("attaches an ownerless server when the run carries no credential for it", () => {
    const def = ownerless();
    expect(selectRegistryServersForRun([def], undefined)).toEqual({ attached: [def], omitted: [] });
    expect(selectRegistryServersForRun([def], { aida: {} })).toEqual({ attached: [def], omitted: [] });
    expect(selectRegistryServersForRun([def], { aida: { headers: { Authorization: "" } } })).toEqual({ attached: [def], omitted: [] });
    // A credential for another server does not matter.
    expect(selectRegistryServersForRun([def], { other: { headers: { Authorization: "Bearer X" } } })).toEqual({ attached: [def], omitted: [] });
  });

  it("attaches an owned server with a credential, and leaves a flagged ownerless one out for the ownership reason", () => {
    const owned = perUserServer({ requireUserCredentials: undefined });
    expect(selectRegistryServersForRun([owned], { aida: { headers: { Authorization: "Bearer USER_X" } } })).toEqual({ attached: [owned], omitted: [] });
    const flagged = { ...ownerless(), requireUserCredentials: true };
    expect(selectRegistryServersForRun([flagged], { aida: { headers: { Authorization: "Bearer USER_X" } } }).omitted).toEqual([{ name: "aida", reason: "ownerless" }]);
    expect(selectRegistryServersForRun([flagged], undefined).omitted).toEqual([{ name: "aida", reason: "missing_user_credential" }]);
  });
});
