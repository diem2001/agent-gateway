/**
 * The fixed texts and mapping of trusted tool mediation (MVP-7679, tool-mediation.ts): every situation of the
 * failure table with its exact code and text, the MCP rendering, the webhook refusal message rules, the secret
 * masking and the AGENT_MCP_TOOL_TIMEOUT_MS key. Texts are asserted verbatim: callers and models act on them.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  DEFAULT_MCP_TOOL_TIMEOUT_MS,
  McpToolTimeoutConfigError,
  describeFailure,
  maskSecrets,
  mcpFailureResult,
  mcpToolTimeoutMs,
  secretValuesForMasking,
  toolFailureReply,
  webhookRejectionText,
  type ToolFailure,
} from "../tool-mediation.js";

const TABLE: [string, ToolFailure, string, string][] = [
  ["denied", { kind: "denied" }, "TOOL_DENIED", "TOOL_DENIED: This tool is not allowed for this request. Do not retry; continue without it or tell the user."],
  [
    "no credential",
    { kind: "no_credential", name: "jira" },
    "TOOL_AUTH_UNAVAILABLE",
    'TOOL_AUTH_UNAVAILABLE: No credential for "jira" was provided with this request. Ask the user to connect their account; retrying will not help.',
  ],
  [
    "user credential refused",
    { kind: "user_credential_refused", name: "jira" },
    "TOOL_AUTH_UNAVAILABLE",
    `TOOL_AUTH_UNAVAILABLE: "jira" did not accept the user's credential. Ask the user to reconnect their account; retrying will not help.`,
  ],
  [
    "gateway credential refused",
    { kind: "gateway_credential_refused", name: "jira" },
    "TOOL_AUTH_UNAVAILABLE",
    `TOOL_AUTH_UNAVAILABLE: "jira" did not accept the gateway's credential. Ask your gateway administrator to check this tool's credential; retrying will not help.`,
  ],
  [
    "unreachable",
    { kind: "unreachable", name: "jira" },
    "TOOL_UNAVAILABLE",
    'TOOL_UNAVAILABLE: "jira" could not be reached or failed. Try again later; if it keeps happening, tell your gateway administrator.',
  ],
  [
    "redirect",
    { kind: "redirect", name: "jira" },
    "TOOL_UNAVAILABLE",
    'TOOL_UNAVAILABLE: "jira" tried to send the request to another address, which the gateway does not allow. Tell your gateway administrator; retrying will not help.',
  ],
  [
    "timeout",
    { kind: "timeout", name: "jira", timeoutMs: 600_000 },
    "TOOL_TIMEOUT",
    'TOOL_TIMEOUT: "jira" did not answer within 600 seconds. Try again later or with a smaller request; if it keeps happening, tell your gateway administrator.',
  ],
  [
    "invalid response",
    { kind: "invalid_response", name: "jira" },
    "TOOL_RESPONSE_INVALID",
    'TOOL_RESPONSE_INVALID: "jira" sent an answer the gateway could not read. If it keeps happening, tell your gateway administrator.',
  ],
];

describe("the failure table", () => {
  it.each(TABLE)("%s", (_label, failure, code, message) => {
    expect(describeFailure(failure)).toEqual({ code, message });
    expect(toolFailureReply("call-1", failure)).toEqual({ callId: "call-1", ok: false, error: { code, message } });
    expect(mcpFailureResult(failure)).toEqual({ isError: true, content: [{ type: "text", text: message }] });
  });

  it("every text names who acts or whether retrying helps, and starts with its code", () => {
    for (const [, failure, code, message] of TABLE) {
      expect(message.startsWith(`${code}: `)).toBe(true);
      expect(message).toMatch(/retry|Try again|tell|Ask|continue/i);
      void failure;
    }
  });

  it.each([
    [1, 1],
    [200, 1],
    [1000, 1],
    [1001, 2],
    [5000, 5],
    [30_000, 30],
  ])("a %i ms deadline reads as %i second(s) (rounded up, at least 1)", (timeoutMs, seconds) => {
    expect(describeFailure({ kind: "timeout", name: "x", timeoutMs }).message).toContain(`within ${seconds} seconds.`);
  });

  it("no text carries a URL, header, upstream body or secret: only the validated name varies", () => {
    for (const [, failure] of TABLE) {
      expect(describeFailure(failure).message).not.toMatch(/https?:|Bearer|Authorization|password/i);
    }
  });
});

describe("a webhook tool's own refusal", () => {
  it("is wrapped with the status and the extracted message", () => {
    expect(webhookRejectionText(400, "application/json", JSON.stringify({ error: { code: "x", message: "Title is required." } }), [])).toBe(
      "The tool rejected the request (HTTP 400): Title is required.",
    );
  });

  it("without a usable message only the status is given", () => {
    expect(webhookRejectionText(404, "application/json", "{}", [])).toBe("The tool rejected the request (HTTP 404).");
    expect(webhookRejectionText(404, null, "<html>", [])).toBe("The tool rejected the request (HTTP 404).");
    expect(webhookRejectionText(404, "application/json", "[1,2]", [])).toBe("The tool rejected the request (HTTP 404).");
  });

  it("an object `error` without a string message is not echoed", () => {
    expect(webhookRejectionText(400, "application/json", JSON.stringify({ error: { code: 7, detail: "SECRET-DETAIL" } }), [])).toBe("The tool rejected the request (HTTP 400).");
  });
});

describe("masking", () => {
  it("replaces every occurrence of a known value of 8 or more characters, and nothing shorter", () => {
    expect(maskSecrets("a SYNTH-KEY-12345 b SYNTH-KEY-12345 c abc", ["SYNTH-KEY-12345", "abc"])).toBe("a [REDACTED] b [REDACTED] c abc");
  });

  const SHORT = "dbuser01";
  const LONG = "dbuser01:Pa55w0rdXYZ";

  it("M1 a value that starts a longer one: short value first leaves no fragment of the longer one", () => {
    expect(maskSecrets(`login ${LONG} now`, [SHORT, LONG])).toBe("login [REDACTED] now");
  });

  it("M1 a value that starts a longer one: long value first", () => {
    expect(maskSecrets(`login ${LONG} now`, [LONG, SHORT])).toBe("login [REDACTED] now");
  });

  // The shorter value sits at the end, or in the middle, of the longer one.
  const WHOLE = "pre-SYNTHlong-TAILvalue";
  const TAIL = "TAILvalue";
  const MIDDLE = "SYNTHlong";

  it("M2 the shorter value at the end of the longer one, short first", () => {
    expect(maskSecrets(`x ${WHOLE} y`, [TAIL, WHOLE])).toBe("x [REDACTED] y");
  });

  it("M2 the shorter value at the end of the longer one, long first", () => {
    expect(maskSecrets(`x ${WHOLE} y`, [WHOLE, TAIL])).toBe("x [REDACTED] y");
  });

  it("M2 the shorter value in the middle of the longer one, short first", () => {
    expect(maskSecrets(`x ${WHOLE} y`, [MIDDLE, WHOLE])).toBe("x [REDACTED] y");
  });

  it("M2 the shorter value in the middle of the longer one, long first", () => {
    expect(maskSecrets(`x ${WHOLE} y`, [WHOLE, MIDDLE])).toBe("x [REDACTED] y");
  });

  // Neither value contains the other: the text holds A followed by the rest of B, overlapping in "1234".
  const LEFT = "SYNTHabcd1234";
  const RIGHT = "1234wxyzSYNTH";
  const OVERLAPPING = "SYNTHabcd1234wxyzSYNTH";

  it("M3 a partial overlap, left value first: no fragment of either value", () => {
    expect(maskSecrets(`a ${OVERLAPPING} b`, [LEFT, RIGHT])).toBe("a [REDACTED] b");
  });

  it("M3 a partial overlap, right value first: no fragment of either value", () => {
    expect(maskSecrets(`a ${OVERLAPPING} b`, [RIGHT, LEFT])).toBe("a [REDACTED] b");
  });

  it("M3b a value that overlaps itself: every occurrence, also the overlapping ones, is found", () => {
    expect(maskSecrets("ababababab", ["abababab"])).toBe("[REDACTED]");
  });

  it("M3c values that only touch are replaced as one range", () => {
    expect(maskSecrets("x SYNTHabcd1234ABCDEFGHIJ y", ["SYNTHabcd1234", "ABCDEFGHIJ"])).toBe("x [REDACTED] y");
  });

  it("M6 a longer value that ends after two separate shorter ones starts before both and replaces them as one range", () => {
    const text = "12345678--9abcdefg--hijklmno";
    const secrets = ["12345678", "9abcdefg", "5678--9abcdefg--hijklmno"];
    expect(maskSecrets(text, secrets)).toBe("[REDACTED]");
    expect(maskSecrets(text, [...secrets].reverse())).toBe("[REDACTED]");
  });

  it("M4 a value under 8 characters is not masked", () => {
    expect(maskSecrets("a short77 b", ["short77"])).toBe("a short77 b");
    expect(maskSecrets("a short77 b", ["short77", "12345678"])).toBe("a short77 b");
  });
});

/** The previous implementation (one range per position, quadratic): the reference every input must still match. */
function referenceMask(text: string, secrets: readonly string[]): string {
  const ranges: [number, number][] = [];
  for (const secret of new Set(secrets)) {
    if (secret.length < 8) continue;
    for (let at = text.indexOf(secret); at !== -1; at = text.indexOf(secret, at + 1)) ranges.push([at, at + secret.length]);
  }
  if (ranges.length === 0) return text;
  ranges.sort((a, b) => a[0] - b[0] || b[1] - a[1]);
  let out = "";
  let copied = 0;
  let [start, end] = ranges[0];
  for (const [from, to] of ranges.slice(1)) {
    if (from <= end) {
      end = Math.max(end, to);
      continue;
    }
    out += `${text.slice(copied, start)}[REDACTED]`;
    copied = end;
    [start, end] = [from, to];
  }
  return `${out}${text.slice(copied, start)}[REDACTED]${text.slice(end)}`;
}

describe("masking cost and equivalence (MVP-8207 rework)", () => {
  it("gives the reference result on 6000 random inputs over a tiny alphabet", () => {
    let seed = 20261010;
    const next = (bound: number): number => {
      seed = (Math.imul(seed, 1103515245) + 12345) >>> 0;
      return (seed >>> 8) % bound;
    };
    const word = (alphabet: string, length: number): string => Array.from({ length }, () => alphabet[next(alphabet.length)]).join("");
    for (let i = 0; i < 6000; i++) {
      const alphabet = i % 3 === 0 ? "ab" : i % 3 === 1 ? "abc" : "ab-";
      const text = word(alphabet, 10 + next(70));
      const secrets = Array.from({ length: 1 + next(4) }, () => word(alphabet, 6 + next(9)));
      expect(maskSecrets(text, secrets), JSON.stringify({ text, secrets })).toBe(referenceMask(text, secrets));
      expect(maskSecrets(text, secrets.reverse())).toBe(referenceMask(text, secrets));
    }
  });

  it("gives the reference result on 3000 random inputs with many values", () => {
    let seed = 20261011;
    const next = (bound: number): number => {
      seed = (Math.imul(seed, 1103515245) + 12345) >>> 0;
      return (seed >>> 8) % bound;
    };
    const word = (alphabet: string, length: number): string => Array.from({ length }, () => alphabet[next(alphabet.length)]).join("");
    for (let i = 0; i < 3000; i++) {
      const alphabet = i % 3 === 0 ? "ab" : i % 3 === 1 ? "abc" : "ab-";
      const text = word(alphabet, 20 + next(120));
      const secrets = Array.from({ length: 8 + next(40) }, () => (next(3) === 0 ? text.slice(next(text.length), next(text.length) + 8 + next(6)) : word(alphabet, 6 + next(9))));
      secrets.push(secrets[0], "", "short");
      expect(maskSecrets(text, secrets), JSON.stringify({ text, secrets })).toBe(referenceMask(text, secrets));
      expect(maskSecrets(text, secrets.reverse())).toBe(referenceMask(text, secrets));
    }
  });

  it("C1 a 1 MiB text and a 20 KiB value that overlap at every position finish within the budget", () => {
    const text = "a".repeat(1024 * 1024);
    const started = performance.now();
    expect(maskSecrets(text, ["a".repeat(20 * 1024)])).toBe("[REDACTED]");
    expect(performance.now() - started).toBeLessThan(500);
  });

  it("C2 a 2 MiB text of one repeated 8-character value finishes within the budget", () => {
    const text = "abcdefgh".repeat(256 * 1024);
    const started = performance.now();
    expect(maskSecrets(text, ["abcdefgh"])).toBe("[REDACTED]");
    expect(performance.now() - started).toBeLessThan(500);
  });

  it("C2b a 2 MiB text of one repeated character and an 8-character value of it finishes within the budget", () => {
    const text = "a".repeat(2 * 1024 * 1024);
    const started = performance.now();
    expect(maskSecrets(text, ["a".repeat(8)])).toBe("[REDACTED]");
    expect(performance.now() - started).toBeLessThan(500);
  });

  it("C3 an 8 MiB refusal body with several long repetitive values stays within the budget", () => {
    const body = "ab".repeat(4 * 1024 * 1024);
    const secrets = ["ab".repeat(10 * 1024), "ba".repeat(10 * 1024), "a".repeat(8), "abab".repeat(5000)];
    const started = performance.now();
    const text = webhookRejectionText(400, "text/plain", body, secrets);
    expect(performance.now() - started).toBeLessThan(2500);
    expect(text).toBe("The tool rejected the request (HTTP 400): [REDACTED]");
  });

  it.each([200, 1000])("C5 %i caller-supplied values over an 8 MiB text finish within the budget whether they match or not", (count) => {
    const text = "a".repeat(8 * 1024 * 1024);
    const missing = Array.from({ length: count }, (_, i) => `${"a".repeat(10 + i)}b`);
    let started = performance.now();
    expect(maskSecrets(text, missing)).toBe(text);
    const missingMs = performance.now() - started;
    const matching = Array.from({ length: count }, (_, i) => "a".repeat(10 + i));
    started = performance.now();
    expect(maskSecrets(text, matching)).toBe("[REDACTED]");
    const matchingMs = performance.now() - started;
    expect(Math.max(missingMs, matchingMs)).toBeLessThan(4000);
  });

  it("C6 an 8 MiB refusal body with 200 repetitive caller values stays within the budget", () => {
    const body = "a".repeat(8 * 1024 * 1024 - 64);
    const secrets = Array.from({ length: 200 }, (_, i) => `${"a".repeat(10 + i)}b`);
    const started = performance.now();
    const text = webhookRejectionText(400, "text/plain", body, secrets);
    expect(performance.now() - started).toBeLessThan(4000);
    expect(text).toBe(`The tool rejected the request (HTTP 400): ${"a".repeat(500)}`);
  });

  it("C4 a stored header of 'Bearer' and 40,000 spaces then a line break does not stall the known-value list", () => {
    const value = `Bearer${" ".repeat(40000)}\nx`;
    const started = performance.now();
    const values = secretValuesForMasking([value]);
    expect(performance.now() - started).toBeLessThan(500);
    expect(values).toContain(value);
  });
});

describe("a refusal text is masked before it is cleaned (MVP-8207 rework)", () => {
  const PEM = "-----BEGIN KEY-----\nSYNTHline1abcdef\nSYNTHline2abcdef\n-----END KEY-----";

  it("R1 a multi-line known value in a JSON body is masked", () => {
    const body = JSON.stringify({ error: `bad key ${PEM} given` });
    expect(webhookRejectionText(400, "application/json", body, [PEM])).toBe("The tool rejected the request (HTTP 400): bad key [REDACTED] given");
  });

  it("R2 a multi-line known value in a text/plain body is masked", () => {
    expect(webhookRejectionText(400, "text/plain", `bad key ${PEM} given`, [PEM])).toBe("The tool rejected the request (HTTP 400): bad key [REDACTED] given");
  });

  it("R3 a known value with a quote and a backslash, JSON-escaped in a text/plain body, is masked", () => {
    const secret = 'pa"ss\\word-SYNTH';
    const escaped = JSON.stringify(secret).slice(1, -1);
    expect(webhookRejectionText(400, "text/plain", `got ${escaped} here`, [secret])).toBe("The tool rejected the request (HTTP 400): got [REDACTED] here");
  });

  it("R4 a multi-line value whose JSON-escaped form appears in a text/plain body is masked", () => {
    const escaped = JSON.stringify(PEM).slice(1, -1);
    expect(webhookRejectionText(400, "text/plain", `got ${escaped} here`, [PEM])).toBe("The tool rejected the request (HTTP 400): got [REDACTED] here");
  });

  it("R5 a message without a known value is unchanged (control)", () => {
    expect(webhookRejectionText(400, "text/plain", "list the open tickets", [PEM])).toBe("The tool rejected the request (HTTP 400): list the open tickets");
  });
});

describe("the values masked in a refusal message", () => {
  let dir: string;
  const saved = { ...process.env };
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "tool-mediation-"));
    process.env.MCP_SERVERS_PERSIST_PATH = path.join(dir, "mcp-servers.json");
  });
  afterEach(async () => {
    process.env = { ...saved };
    await new Promise((resolve) => setTimeout(resolve, 150));
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("holds the gateway's API key values, the provider credential, registry header and env values and the extras", async () => {
    process.env.API_KEYS = "reqlift:SYNTH-KEY-reqlift-7679,diemcrm:SYNTH-KEY-diemcrm-7679";
    process.env.ANTHROPIC_API_KEY = "SYNTH-PROVIDER-KEY-7679";
    const { registerMcpServer } = await import("../mcp-registry.js");
    const now = new Date().toISOString();
    registerMcpServer({ name: "jira", description: "", enabled: true, type: "http", url: "http://127.0.0.1:9/mcp", headers: { Authorization: "Basic SYNTH-REGISTRY-HEADER-7679" }, createdAt: now, updatedAt: now });
    registerMcpServer({ name: "local", description: "", enabled: true, type: "stdio", command: "node", env: { TOKEN: "SYNTH-REGISTRY-ENV-7679" }, createdAt: now, updatedAt: now });
    const values = secretValuesForMasking(["SYNTH-FORWARDED-BEARER-7679"]);
    for (const expected of [
      "SYNTH-KEY-reqlift-7679",
      "SYNTH-KEY-diemcrm-7679",
      "SYNTH-PROVIDER-KEY-7679",
      "Basic SYNTH-REGISTRY-HEADER-7679",
      "SYNTH-REGISTRY-ENV-7679",
      "SYNTH-FORWARDED-BEARER-7679",
    ]) {
      expect(values, expected).toContain(expected);
    }
  });
});

describe("the registry values in the masking list (MVP-8207)", () => {
  let dir: string;
  const saved = { ...process.env };
  const V1 = "dbuser01";
  const V2 = "dbuser01:Pa55w0rdXYZ";
  const REG_TOKEN = "regTokenAAAA1111";
  const ENV_TOKEN = "envTokenDDDD4444";
  const OVR_TOKEN = "ovrTokenCCCC3333";
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "tool-mediation-8207-"));
    process.env.MCP_SERVERS_PERSIST_PATH = path.join(dir, "mcp-servers.json");
    process.env.TOOLS_PERSIST_PATH = path.join(dir, "tools.json");
    vi.resetModules();
  });
  afterEach(async () => {
    process.env = { ...saved };
    await new Promise((resolve) => setTimeout(resolve, 150));
    fs.rmSync(dir, { recursive: true, force: true });
  });

  async function register(headers: Record<string, string>, env: Record<string, string> = {}): Promise<void> {
    const { registerMcpServer } = await import("../mcp-registry.js");
    const now = new Date().toISOString();
    registerMcpServer({ name: "dbhttp", description: "", enabled: true, type: "http", url: "http://127.0.0.1:9/mcp", headers, createdAt: now, updatedAt: now });
    if (Object.keys(env).length > 0) {
      registerMcpServer({ name: "dbstdio", description: "", enabled: true, type: "stdio", command: "node", env, createdAt: now, updatedAt: now });
    }
  }

  it("M5 a webhook refusal text masks an overlapping pair and a prefixed token, with the secrets from the real list", async () => {
    await register({ "X-Db-User": V1, Authorization: `Bearer ${REG_TOKEN}` }, { DB_LOGIN: V2 });
    const mediation = await import("../tool-mediation.js");
    const secrets = mediation.secretValuesForMasking();
    // The sorted list holds the shorter value first, which is what makes the leak deterministic.
    expect(secrets.indexOf(V1)).toBeGreaterThanOrEqual(0);
    expect(secrets.indexOf(V1)).toBeLessThan(secrets.indexOf(V2));
    const text = mediation.webhookRejectionText(422, "text/plain", `login ${V2} and ${REG_TOKEN} done`, secrets);
    expect(text.includes("Pa55w0rdXYZ")).toBe(false);
    expect(text.includes(REG_TOKEN)).toBe(false);
    expect(text).toBe("The tool rejected the request (HTTP 422): login [REDACTED] and [REDACTED] done");
  });

  it("K1 a registry header `Bearer <token>` yields the whole value and the token", async () => {
    await register({ Authorization: `Bearer ${REG_TOKEN}` });
    const { secretValuesForMasking } = await import("../tool-mediation.js");
    const values = secretValuesForMasking();
    expect(values).toContain(`Bearer ${REG_TOKEN}`);
    expect(values).toContain(REG_TOKEN);
  });

  it("K1 a registry env value `Bearer <token>` yields the token too", async () => {
    await register({}, { AUTH_HEADER: `Bearer ${ENV_TOKEN}` });
    const { secretValuesForMasking } = await import("../tool-mediation.js");
    const values = secretValuesForMasking();
    expect(values).toContain(`Bearer ${ENV_TOKEN}`);
    expect(values).toContain(ENV_TOKEN);
  });

  it("K1 the scheme is case-insensitive and may be followed by several spaces", async () => {
    await register({ Authorization: `basic   ${OVR_TOKEN}` });
    const { secretValuesForMasking } = await import("../tool-mediation.js");
    const values = secretValuesForMasking();
    expect(values).toContain(`basic   ${OVR_TOKEN}`);
    expect(values).toContain(OVR_TOKEN);
  });

  it("K1 an extra value is matched on its trimmed form, also with a leading space", async () => {
    await register({});
    const { secretValuesForMasking } = await import("../tool-mediation.js");
    const values = secretValuesForMasking([" Bearer reqTokenBBBB2222 ", "BASIC leadTokenEEEE5555"]);
    expect(values).toContain("Bearer reqTokenBBBB2222");
    expect(values).toContain("reqTokenBBBB2222");
    expect(values).toContain("BASIC leadTokenEEEE5555");
    expect(values).toContain("leadTokenEEEE5555");
  });

  it("K1 a remainder under 8 characters is not added, the whole value stays", async () => {
    await register({ Authorization: "Bearer abc1234" });
    const { secretValuesForMasking } = await import("../tool-mediation.js");
    const values = secretValuesForMasking();
    expect(values).toContain("Bearer abc1234");
    expect(values).not.toContain("abc1234");
  });

  it("K1 boundary row: another scheme (`Token`) yields no remainder, the whole value stays", async () => {
    await register({ Authorization: "Token xyz12345678" });
    const { secretValuesForMasking } = await import("../tool-mediation.js");
    const values = secretValuesForMasking();
    expect(values).toContain("Token xyz12345678");
    expect(values).not.toContain("xyz12345678");
  });
});

describe("the SSH key and webhook URL values in the masking list and the sandbox scan list", () => {
  let dir: string;
  const saved = { ...process.env };
  const SSH_LINE = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABSYNTH7919MASK";
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "tool-mediation-keys-"));
    fs.mkdirSync(path.join(dir, "home", ".ssh"), { recursive: true });
    fs.writeFileSync(path.join(dir, "home", ".ssh", "id_ed25519"), `-----BEGIN OPENSSH PRIVATE KEY-----\n${SSH_LINE}\n-----END OPENSSH PRIVATE KEY-----\n`);
    process.env.HOME = path.join(dir, "home");
    process.env.MCP_SERVERS_PERSIST_PATH = path.join(dir, "mcp-servers.json");
    process.env.TOOLS_PERSIST_PATH = path.join(dir, "tools.json");
  });
  afterEach(async () => {
    process.env = { ...saved };
    await new Promise((resolve) => setTimeout(resolve, 150));
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("masks an SSH private-key line and a webhook URL token in a webhook refusal text, and the sandbox scan list holds the same values", async () => {
    vi.resetModules();
    const { registerTool } = await import("../tools.js");
    registerTool({ name: "hook", description: "d", input_schema: { type: "object" }, webhook_url: "https://hooks.example.test/services/PATHTOKENsynth7919ABCDEF?token=QUERYTOKEN7919", owner: "reqlift" });
    const mediation = await import("../tool-mediation.js");
    const secrets = mediation.secretValuesForMasking();
    const text = mediation.webhookRejectionText(400, "text/plain", `bad ${SSH_LINE} and PATHTOKENsynth7919ABCDEF and QUERYTOKEN7919`, secrets);
    expect(text.includes(SSH_LINE)).toBe(false);
    expect(text.includes("PATHTOKENsynth7919ABCDEF")).toBe(false);
    expect(text.includes("QUERYTOKEN7919")).toBe(false);
    expect(text).toContain("[REDACTED]");
    const scan = mediation.gatewayKnownValues(path.join(dir, "ws")).map((b) => b.toString("utf8"));
    expect([...secrets].sort()).toEqual(scan.sort());
  });
});

describe("AGENT_MCP_TOOL_TIMEOUT_MS", () => {
  it.each([[undefined], [""], ["  "]])("%j is the default of 600000 ms", (value) => {
    expect(mcpToolTimeoutMs({ AGENT_MCP_TOOL_TIMEOUT_MS: value })).toBe(DEFAULT_MCP_TOOL_TIMEOUT_MS);
    expect(DEFAULT_MCP_TOOL_TIMEOUT_MS).toBe(600_000);
  });

  it("a positive whole number is used", () => {
    expect(mcpToolTimeoutMs({ AGENT_MCP_TOOL_TIMEOUT_MS: "1500" })).toBe(1500);
    expect(mcpToolTimeoutMs({ AGENT_MCP_TOOL_TIMEOUT_MS: " 42 " })).toBe(42);
  });

  it.each([["0"], ["-5"], ["1.5"], ["abc"], ["10s"], ["1e3"], ["0x10"], ["2147483648"], ["99999999999999999999"]])("%s stops startup with one fixed line", (value) => {
    try {
      mcpToolTimeoutMs({ AGENT_MCP_TOOL_TIMEOUT_MS: value });
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(McpToolTimeoutConfigError);
      expect((e as McpToolTimeoutConfigError).logLine).toBe("FATAL config key=AGENT_MCP_TOOL_TIMEOUT_MS reason=must be a positive whole number of milliseconds");
    }
  });
});
