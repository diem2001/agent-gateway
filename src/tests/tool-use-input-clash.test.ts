/**
 * The run's tool-name assertion on its own (MVP-8235): before the runtime connects, no server in the run's final
 * `mcpServers` map may produce the full name of one of the caller's webhook tools, and the `agent-gateway-tools` key
 * holds exactly the gateway's own webhook server. The runtime names a tool `mcp__<xn(server)>__<xn(tool)>` where `xn`
 * turns every character outside `[A-Za-z0-9_-]` into `_`; the function applies that rule itself and does not use the
 * reserved-name helper, so it still holds when a filter in front of it is wrong. It returns the server name to log, or
 * `undefined` when the run may start.
 */
import { describe, expect, it } from "vitest";
import { runToolNameProblem } from "../tool-use-input.js";

const WEBHOOK = "agent-gateway-tools";
const WEBHOOK_SERVER = { type: "sdk", name: WEBHOOK, instance: {} };
const stub = () => ({ type: "http", url: "http://127.0.0.1:1/mcp" });

function problem(toolNames: string[], servers: Record<string, unknown>, webhookServer: unknown = WEBHOOK_SERVER): string | undefined {
  return runToolNameProblem({ webhookToolNames: toolNames, mcpServers: { [WEBHOOK]: webhookServer, ...servers }, webhookServer });
}

describe("run tool-name assertion: a server whose tool names can equal a webhook tool's full name", () => {
  it("agent-gateway-tools__x against the webhook tool x__y is a clash", () => {
    expect(problem(["x__y"], { "agent-gateway-tools__x": stub() })).toBe("agent-gateway-tools__x");
  });

  it("agent-gateway-tools_ against the webhook tool _t is a clash", () => {
    expect(problem(["_t"], { "agent-gateway-tools_": stub() })).toBe("agent-gateway-tools_");
  });

  it("tool-name normalization: agent-gateway-tools_ against the webhook tool .t is a clash", () => {
    expect(problem([".t"], { "agent-gateway-tools_": stub() })).toBe("agent-gateway-tools_");
  });

  it("key normalization: agent-gateway-tools..x against the webhook tool x__y is a clash", () => {
    expect(problem(["x__y"], { "agent-gateway-tools..x": stub() })).toBe("agent-gateway-tools..x");
  });

  it("names the first clashing server and no other", () => {
    expect(problem(["x__y"], { "beta-docs": stub(), "agent-gateway-tools__x": stub() })).toBe("agent-gateway-tools__x");
  });
});

describe("run tool-name assertion: names that cannot clash", () => {
  it("agent-gateway-tools.x (normalized agent-gateway-tools_x) against x__y is no clash", () => {
    expect(problem(["x__y"], { "agent-gateway-tools.x": stub() })).toBeUndefined();
  });

  it("agent-gateway-tools-x against x__y is no clash", () => {
    expect(problem(["x__y"], { "agent-gateway-tools-x": stub() })).toBeUndefined();
  });

  it("control: an ordinary server beside the webhook server is no clash", () => {
    expect(problem(["x__y", "reqlift_ping"], { "beta-docs": stub(), jira: stub() })).toBeUndefined();
  });

  it("a caller without webhook tools has no webhook key and nothing to clash with", () => {
    expect(runToolNameProblem({ webhookToolNames: [], mcpServers: { "agent-gateway-tools__x": stub() }, webhookServer: undefined })).toBeUndefined();
  });
});

describe("run tool-name assertion: the webhook key holds the gateway's own server", () => {
  it("the key missing although the gateway created its server is a problem", () => {
    expect(runToolNameProblem({ webhookToolNames: ["x__y"], mcpServers: { "beta-docs": stub() }, webhookServer: WEBHOOK_SERVER })).toBe(WEBHOOK);
  });

  it("the key holding a foreign server is a problem", () => {
    expect(runToolNameProblem({ webhookToolNames: ["x__y"], mcpServers: { [WEBHOOK]: stub() }, webhookServer: WEBHOOK_SERVER })).toBe(WEBHOOK);
  });

  it("the key present although the gateway created no server is a problem", () => {
    expect(runToolNameProblem({ webhookToolNames: [], mcpServers: { [WEBHOOK]: stub() }, webhookServer: undefined })).toBe(WEBHOOK);
  });

  it("control: the key holding exactly the gateway's own server is no problem", () => {
    expect(runToolNameProblem({ webhookToolNames: ["x__y"], mcpServers: { [WEBHOOK]: WEBHOOK_SERVER }, webhookServer: WEBHOOK_SERVER })).toBeUndefined();
  });
});
