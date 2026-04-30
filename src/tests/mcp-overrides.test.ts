import { describe, expect, it } from "vitest";
import {
  applyMcpCredentialOverride,
  applyMcpCredentialOverrides,
  summarizeOverrideKeys,
} from "../mcp-overrides.js";
import type { SdkMcpServerConfig } from "../mcp-registry.js";

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
