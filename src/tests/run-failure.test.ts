/**
 * Classifier table for failed runs (MVP-7685). Expected kinds, retry decisions
 * and message texts are written out here, independent of run-failure.ts, so a
 * wording or mapping change in production fails this test.
 */
import { describe, expect, it } from "vitest";
import { RunFailure, classifyRunFailure, fixedFailure, formatLogFields, type RunDiagnostics } from "../run-failure.js";

const RETRY_WILL_NOT_HELP = "Retrying will not help until the administrator has done this.";
const UPDATE = `Ask your gateway administrator to update the gateway runtime. ${RETRY_WILL_NOT_HELP}`;
const LEAD = "The AI runtime on the gateway server is too old for the selected model";
const VERSION_BOTH = `${LEAD} (installed 2.0.77, required 2.1.280 or newer). ${UPDATE}`;
const VERSION_INSTALLED_ONLY = `${LEAD} (installed 2.0.77; a newer version is required). ${UPDATE}`;
const VERSION_REQUIRED_ONLY = `${LEAD} (required 2.1.280 or newer). ${UPDATE}`;
const VERSION_NEITHER = `${LEAD}. ${UPDATE}`;
const AUTHENTICATION = `The gateway could not authenticate with the AI provider. Ask your gateway administrator to check the gateway's authentication. ${RETRY_WILL_NOT_HELP}`;
const BUSY = "The AI provider is busy right now. Please try again in a few minutes.";
const UNKNOWN_NO_REFERENCE =
  "The AI request failed on the gateway for an unknown reason. Please try again. If it keeps failing, ask your gateway administrator to check the gateway logs.";
const unknownWithReference = (id: string): string =>
  `The AI request failed on the gateway for an unknown reason. Please try again. If it keeps failing, ask your gateway administrator to check the gateway logs (reference: ${id}).`;

const QUERY_ID = "q-7685.ref:1";

/** The runtime's text for a provider rejection: `API Error: <status> <body>`. */
function apiError(status: number, error: Record<string, unknown>): string {
  return `API Error: ${status} ${JSON.stringify({ type: "error", error })}`;
}

/** The runtime's stdout for a provider rejection: an error-flagged assistant message plus an is_error result. */
function rejection(text: string, assistantError = "unknown", installedVersion: unknown = "2.0.77"): RunDiagnostics {
  return {
    installedVersion,
    assistantErrors: [{ error: assistantError, text }],
    result: { type: "result", subtype: "success", is_error: true, result: text, session_id: "sdk-1", usage: { input_tokens: 0 }, total_cost_usd: 0, num_turns: 1 },
    thrown: new Error("Claude Code process exited with code 1"),
  };
}

const versionError = (message: string): string =>
  apiError(400, { type: "invalid_request_error", code: "claude_code_version_too_old", message });

interface Row {
  name: string;
  diagnostics: RunDiagnostics;
  kind: string;
  retryable: boolean;
  message: string;
}

const ROWS: Row[] = [
  {
    name: "version rejection with installed and required versions",
    diagnostics: rejection(versionError("This model requires Claude Code version 2.1.280 or newer. Please update Claude Code.")),
    kind: "runtime_version_unsupported",
    retryable: false,
    message: VERSION_BOTH,
  },
  {
    name: "native runtime plain-text version rejection",
    diagnostics: rejection("API Error: 400 This model requires Claude Code version 2.1.280 or newer. Please update Claude Code."),
    kind: "runtime_version_unsupported",
    retryable: false,
    message: VERSION_BOTH,
  },
  {
    name: "native runtime plain-text version rejection without required version",
    diagnostics: rejection("API Error: 400 This version of Claude Code is no longer supported for this model. Please update Claude Code."),
    kind: "runtime_version_unsupported",
    retryable: false,
    message: VERSION_INSTALLED_ONLY,
  },
  {
    name: "version rejection with a >= required version",
    diagnostics: rejection(versionError("Claude Code >= 2.1.280 is required for this model.")),
    kind: "runtime_version_unsupported",
    retryable: false,
    message: VERSION_BOTH,
  },
  {
    name: "version rejection without a required version",
    diagnostics: rejection(versionError("This version of Claude Code is no longer supported for this model.")),
    kind: "runtime_version_unsupported",
    retryable: false,
    message: VERSION_INSTALLED_ONLY,
  },
  {
    name: "version rejection without an installed version (no init message)",
    diagnostics: rejection(versionError("This model requires Claude Code version 2.1.280 or newer."), "unknown", null),
    kind: "runtime_version_unsupported",
    retryable: false,
    message: VERSION_REQUIRED_ONLY,
  },
  {
    name: "version rejection with neither version",
    diagnostics: rejection(versionError("Please update Claude Code."), "unknown", null),
    kind: "runtime_version_unsupported",
    retryable: false,
    message: VERSION_NEITHER,
  },
  {
    name: "version code in a nested error wrapper",
    diagnostics: rejection(`API Error: 400 ${JSON.stringify({ error: { error: { type: "invalid_request_error", code: "claude_code_version_too_old" } } })}`),
    kind: "runtime_version_unsupported",
    retryable: false,
    message: VERSION_INSTALLED_ONLY,
  },
  {
    name: "runtime authentication_failed (no provider body)",
    diagnostics: rejection("Invalid API key · Fix external API key", "authentication_failed"),
    kind: "authentication",
    retryable: false,
    message: AUTHENTICATION,
  },
  {
    name: "provider 401 authentication_error",
    diagnostics: rejection(apiError(401, { type: "authentication_error", message: "invalid x-api-key" })),
    kind: "authentication",
    retryable: false,
    message: AUTHENTICATION,
  },
  {
    name: "provider 403 permission_error",
    diagnostics: rejection(apiError(403, { type: "permission_error", message: "Your API key does not have permission to use the specified resource." })),
    kind: "authentication",
    retryable: false,
    message: AUTHENTICATION,
  },
  {
    name: "provider 429 rate_limit_error",
    diagnostics: rejection(apiError(429, { type: "rate_limit_error", message: "Number of requests has exceeded your rate limit." }), "rate_limit"),
    kind: "transient",
    retryable: true,
    message: BUSY,
  },
  {
    name: "provider 529 overloaded_error",
    diagnostics: rejection(apiError(529, { type: "overloaded_error", message: "Overloaded" })),
    kind: "transient",
    retryable: true,
    message: BUSY,
  },
  {
    name: "runtime rate_limit enum without a parseable body",
    diagnostics: rejection("Rate limited", "rate_limit"),
    kind: "transient",
    retryable: true,
    message: BUSY,
  },
  {
    name: "thrown rate-limit error without any diagnostic (historic retry pattern)",
    diagnostics: { thrown: new Error("429 Too Many Requests") },
    kind: "transient",
    retryable: true,
    message: BUSY,
  },
  {
    name: "billing_error enum without a recognized provider code is unknown and not retried",
    diagnostics: rejection("Credit balance is too low", "billing_error"),
    kind: "unknown",
    retryable: false,
    message: unknownWithReference(QUERY_ID),
  },
  {
    name: "invalid_request enum without a recognized code",
    diagnostics: rejection(apiError(400, { type: "invalid_request_error", message: "messages: field required" }), "invalid_request"),
    kind: "unknown",
    retryable: false,
    message: unknownWithReference(QUERY_ID),
  },
  {
    name: "server_error enum with a 500 api_error",
    diagnostics: rejection(apiError(500, { type: "api_error", message: "Internal server error" }), "server_error"),
    kind: "unknown",
    retryable: false,
    message: unknownWithReference(QUERY_ID),
  },
  {
    name: "exit 1 without a usable diagnostic",
    diagnostics: { installedVersion: "2.0.77", thrown: new Error("Claude Code process exited with code 1") },
    kind: "unknown",
    retryable: false,
    message: unknownWithReference(QUERY_ID),
  },
  {
    name: "malformed (non-JSON) provider body",
    diagnostics: rejection('API Error: 400 upstream proxy failure {"error": <html>'),
    kind: "unknown",
    retryable: false,
    message: unknownWithReference(QUERY_ID),
  },
  {
    name: "SDK JSON SyntaxError quoting stdout that looks like a rate limit",
    diagnostics: { thrown: new SyntaxError('Unexpected token r in JSON at position 3: "rate limit 429"') },
    kind: "unknown",
    retryable: false,
    message: unknownWithReference(QUERY_ID),
  },
  {
    name: "result text is ignored when is_error is not true",
    diagnostics: { result: { type: "result", is_error: false, result: versionError("requires 2.1.280 or newer") }, thrown: new Error("Claude Code process exited with code 1") },
    kind: "unknown",
    retryable: false,
    message: unknownWithReference(QUERY_ID),
  },
  {
    name: "result.errors[] carries the rejection",
    diagnostics: { installedVersion: "2.0.77", result: { type: "result", subtype: "error_during_execution", is_error: true, errors: [versionError("needs 2.1.280 or newer")] } },
    kind: "runtime_version_unsupported",
    retryable: false,
    message: VERSION_BOTH,
  },
  {
    name: "a permanent kind beats transient (429 plus a version code)",
    diagnostics: {
      installedVersion: "2.0.77",
      assistantErrors: [{ error: "rate_limit", text: apiError(429, { type: "rate_limit_error", message: "slow down" }) }],
      result: { is_error: true, result: versionError("requires 2.1.280 or newer") },
    },
    kind: "runtime_version_unsupported",
    retryable: false,
    message: VERSION_BOTH,
  },
  {
    name: "authentication beats transient",
    diagnostics: rejection(apiError(429, { type: "authentication_error", message: "x" }), "rate_limit"),
    kind: "authentication",
    retryable: false,
    message: AUTHENTICATION,
  },
];

describe("classifyRunFailure: kind, retry decision and exact public message", () => {
  for (const row of ROWS) {
    it(row.name, () => {
      const failure = classifyRunFailure(row.diagnostics, QUERY_ID);
      expect(failure).toBeInstanceOf(RunFailure);
      expect(failure).toBeInstanceOf(Error);
      expect(failure.kind).toBe(row.kind);
      expect(failure.retryable).toBe(row.retryable);
      expect(failure.message).toBe(row.message);
      expect(failure.cause).toBeUndefined();
    });
  }

  it("the unknown message drops the reference when the query ID is not a safe token", () => {
    const thrown = new Error("Claude Code process exited with code 1");
    expect(classifyRunFailure({ thrown }, "bad id <script>").message).toBe(UNKNOWN_NO_REFERENCE);
    expect(classifyRunFailure({ thrown }, "x".repeat(129)).message).toBe(UNKNOWN_NO_REFERENCE);
    expect(classifyRunFailure({ thrown }).message).toBe(UNKNOWN_NO_REFERENCE);
    expect(classifyRunFailure({ thrown }, "x".repeat(128)).message).toBe(unknownWithReference("x".repeat(128)));
  });
});

describe("version validation boundaries", () => {
  const cases: [string, string, unknown, string][] = [
    ["a suffixed required version does not validate", "requires 2.1.280-X or newer", "2.0.77", VERSION_INSTALLED_ONLY],
    ["a four-part required version does not validate", "requires 1.2.3.4 or newer", "2.0.77", VERSION_INSTALLED_ONLY],
    ["a six-digit component does not validate", "requires 123456.1.1 or newer", "2.0.77", VERSION_INSTALLED_ONLY],
    ["a four-part installed version does not validate", "requires 2.1.280 or newer", "1.2.3.4", VERSION_REQUIRED_ONLY],
    ["a non-string installed version does not validate", "requires 2.1.280 or newer", 2077, VERSION_REQUIRED_ONLY],
    ["a suffixed installed version does not validate", "requires 2.1.280 or newer", "2.0.77-beta", VERSION_REQUIRED_ONLY],
  ];
  for (const [name, message, installed, expected] of cases) {
    it(name, () => {
      expect(classifyRunFailure(rejection(versionError(message), "unknown", installed), QUERY_ID).message).toBe(expected);
    });
  }

  it("a version outside error.message (e.g. in another field) is not read", () => {
    const text = `API Error: 400 ${JSON.stringify({ error: { type: "invalid_request_error", code: "claude_code_version_too_old", hint: "2.1.280 or newer" } })}`;
    expect(classifyRunFailure(rejection(text), QUERY_ID).message).toBe(VERSION_INSTALLED_ONLY);
  });

  it("a version beyond the first 1 KiB of error.message is not read", () => {
    const message = `${"x".repeat(1100)} requires 2.1.280 or newer`;
    expect(classifyRunFailure(rejection(versionError(message)), QUERY_ID).message).toBe(VERSION_INSTALLED_ONLY);
  });
});

describe("hostile inputs finish quickly and give the unknown failure", () => {
  const BOUND_MS = 250;
  const hostile: [string, string][] = [
    ["a 1 MiB provider body", `API Error: 400 ${JSON.stringify({ error: { code: "claude_code_version_too_old", message: "a".repeat(1024 * 1024) } })}`],
    ["a 100k-digit run", `API Error: 400 ${"9".repeat(100_000)}`],
    ["a 100k-digit status-like prefix", `API Error: ${"4".repeat(100_000)}`],
    ["JSON nested 10k deep", `API Error: 400 ${"[".repeat(10_000)}${"]".repeat(10_000)}`],
    ["JSON objects nested 10k deep", `API Error: 400 ${'{"error":'.repeat(10_000)}1${"}".repeat(10_000)}`],
  ];
  for (const [name, text] of hostile) {
    it(name, () => {
      const started = performance.now();
      const failure = classifyRunFailure(rejection(text), QUERY_ID);
      expect(performance.now() - started).toBeLessThan(BOUND_MS);
      expect(failure.kind).toBe("unknown");
      expect(failure.message).toBe(unknownWithReference(QUERY_ID));
    });
  }

  it("a long dotted digit run inside error.message under the parse cap does not stall the version patterns", () => {
    const message = `${"1.".repeat(5000)}1 or newer`;
    const started = performance.now();
    const failure = classifyRunFailure(rejection(versionError(message)), QUERY_ID);
    expect(performance.now() - started).toBeLessThan(BOUND_MS);
    expect(failure.message).toBe(VERSION_INSTALLED_ONLY);
  });

  it("the classifier is total: a throwing input gives unknown", () => {
    const evil = { get error(): string { throw new Error("boom"); }, text: "x" };
    const failure = classifyRunFailure({ assistantErrors: [evil] }, QUERY_ID);
    expect(failure.kind).toBe("unknown");
    expect(failure.message).toBe(unknownWithReference(QUERY_ID));
  });
});

describe("no raw diagnostic leaves the classifier", () => {
  const TOKEN = "sk-ant-api03-SENTINEL7685";
  const BEARER = "Bearer SENTINEL7685BEARER";
  const PROMPT = "PrivatePromptSentinel7685";
  const STACK = "at handle (/srv/provider/src/gate.js:41:13)";
  const text = versionError(`This model requires Claude Code version 2.1.280 or newer. token=${TOKEN} Authorization: ${BEARER} Request was: ${PROMPT} Error: x\n    ${STACK}`);

  it("message, logFields and resultSummary carry none of the private material; the cause stays understandable", () => {
    const failure = classifyRunFailure(rejection(text), QUERY_ID);
    expect(failure.message).toBe(VERSION_BOTH);
    const serialized = JSON.stringify({ message: failure.message, logFields: failure.logFields, resultSummary: failure.resultSummary, own: Object.entries(failure) });
    for (const sentinel of [TOKEN, BEARER, PROMPT, STACK, "API Error", "claude_code_version_too_old"]) expect(serialized).not.toContain(sentinel);
  });

  it("resultSummary keeps usage and cost but never result or errors", () => {
    const failure = classifyRunFailure(rejection(text), QUERY_ID);
    expect(failure.resultSummary).toEqual({ subtype: "success", is_error: true, session_id: "sdk-1", usage: { input_tokens: 0 }, total_cost_usd: 0, num_turns: 1 });
  });

  it("log fields name the kind, status, allowlisted provider type and versions only", () => {
    expect(formatLogFields(classifyRunFailure(rejection(text), QUERY_ID).logFields)).toBe(
      "kind=runtime_version_unsupported apiStatus=400 providerType=invalid_request_error installed=2.0.77 required=2.1.280 errorClass=Error errno=none exit=none signal=none",
    );
    expect(formatLogFields(classifyRunFailure(rejection(apiError(418, { type: `custom_${TOKEN}` })), QUERY_ID).logFields)).toBe(
      "kind=unknown apiStatus=418 providerType=other installed=2.0.77 required=none errorClass=Error errno=none exit=none signal=none",
    );
    expect(formatLogFields(classifyRunFailure({ thrown: new Error("x") }, QUERY_ID).logFields)).toBe(
      "kind=unknown apiStatus=none providerType=none installed=none required=none errorClass=Error errno=none exit=none signal=none",
    );
  });
});

/** The four cause fields (MVP-7852) of a failure whose only input is `thrown` and the runtime's exit metadata. */
function cause(thrown: unknown, runtimeExit?: RunDiagnostics["runtimeExit"]): string {
  const tail = formatLogFields(classifyRunFailure({ thrown, runtimeExit }, QUERY_ID).logFields).split(" ");
  return tail.slice(-4).join(" ");
}

describe("cause fields come only from trusted structured sources (MVP-7852)", () => {
  class LeakyCustomError extends Error {}
  const withCode = (code: unknown): Error => Object.assign(new Error("m"), { code });

  it.each([
    ["Error", new Error("x"), "Error"],
    ["TypeError", new TypeError("x"), "TypeError"],
    ["RangeError", new RangeError("x"), "RangeError"],
    ["SyntaxError", new SyntaxError("x"), "SyntaxError"],
    ["ReferenceError", new ReferenceError("x"), "ReferenceError"],
    ["EvalError", new EvalError("x"), "EvalError"],
    ["URIError", new URIError("x"), "URIError"],
    ["AggregateError", new AggregateError([], "x"), "AggregateError"],
  ])("allowlisted class %s is written as its fixed literal", (_name, thrown, expected) => {
    expect(cause(thrown)).toBe(`errorClass=${expected} errno=none exit=none signal=none`);
  });

  it("a custom subclass, a spoofed constructor/name, a string and a Node internal class are `other`", () => {
    expect(cause(new LeakyCustomError("x"))).toBe("errorClass=other errno=none exit=none signal=none");
    const spoof = Object.assign(Object.create(null) as object, { constructor: { name: "Error" }, name: "Error", message: "x" });
    expect(cause(spoof)).toBe("errorClass=other errno=none exit=none signal=none");
    expect(cause("PRIVATE_TOKEN")).toBe("errorClass=other errno=none exit=none signal=none");
    const internal = Object.assign(new TypeError("x"), { name: "TypeError" });
    Object.setPrototypeOf(internal, Object.create(TypeError.prototype));
    expect(cause(internal)).toBe("errorClass=other errno=none exit=none signal=none");
  });

  it("nothing thrown is `none`", () => {
    expect(cause(undefined)).toBe("errorClass=none errno=none exit=none signal=none");
    expect(cause(null)).toBe("errorClass=none errno=none exit=none signal=none");
  });

  it.each([
    ["canonical ENOSPC", withCode("ENOSPC"), "ENOSPC"],
    ["canonical EACCES", withCode("EACCES"), "EACCES"],
    ["non-canonical", withCode("PRIVATE_TOKEN"), "other"],
    ["lowercase of a canonical key", withCode("enospc"), "other"],
    ["non-string", withCode(28), "other"],
    ["absent", new Error("m"), "none"],
    ["undefined", withCode(undefined), "none"],
    ["inherited key name", withCode("toString"), "other"],
  ])("errno: %s", (_name, thrown, expected) => {
    expect(cause(thrown)).toBe(`errorClass=Error errno=${expected} exit=none signal=none`);
  });

  it("errno: a throwing getter gives `other`", () => {
    const thrown = new Error("m");
    Object.defineProperty(thrown, "code", {
      get() {
        throw new Error("boom");
      },
    });
    expect(cause(thrown)).toBe("errorClass=Error errno=other exit=none signal=none");
  });

  it.each([
    ["integer 3", 3, "3"],
    ["integer 137", 137, "137"],
    ["zero", 0, "0"],
    ["string", "3", "none"],
    ["non-integer", 1.5, "none"],
    ["null", null, "none"],
    ["NaN", Number.NaN, "none"],
    ["unsafe integer", 2 ** 60, "none"],
  ])("exit: %s", (_name, exitCode, expected) => {
    expect(cause(new Error("x"), { exitCode, signalCode: null })).toBe(`errorClass=Error errno=none exit=${expected} signal=none`);
  });

  it.each([
    ["SIGKILL", "SIGKILL", "SIGKILL"],
    ["SIGTERM", "SIGTERM", "SIGTERM"],
    ["hostile name", "SIGSECRET", "other"],
    ["lowercase", "sigkill", "other"],
    ["non-string", 9, "other"],
    ["null", null, "none"],
  ])("signal: %s", (_name, signalCode, expected) => {
    expect(cause(new Error("x"), { exitCode: null, signalCode })).toBe(`errorClass=Error errno=none exit=none signal=${expected}`);
  });

  it("fields are independent: one invalid field never changes another", () => {
    expect(cause(Object.assign(new LeakyCustomError("x"), { code: "ENOSPC" }), { exitCode: "3", signalCode: "SIGKILL" })).toBe(
      "errorClass=other errno=ENOSPC exit=none signal=SIGKILL",
    );
    expect(cause(withCode("PRIVATE_TOKEN"), { exitCode: 3, signalCode: "SIGSECRET" })).toBe("errorClass=Error errno=other exit=3 signal=other");
  });

  it("a Proxy whose prototype lookup and `code` read both throw gives other/other and classification stays total", () => {
    const hostile = new Proxy(
      {},
      {
        getPrototypeOf() {
          throw new Error("boom");
        },
        get() {
          throw new Error("boom");
        },
      },
    );
    const failure = classifyRunFailure({ thrown: hostile }, QUERY_ID);
    expect(failure.kind).toBe("unknown");
    expect(formatLogFields(failure.logFields).split(" ").slice(-4).join(" ")).toBe("errorClass=other errno=other exit=none signal=none");
  });

  it("fixed failures carry no cause", () => {
    expect(formatLogFields(fixedFailure("run_deadline", "x").logFields)).toBe(
      "kind=run_deadline apiStatus=none providerType=none installed=none required=none errorClass=none errno=none exit=none signal=none",
    );
  });
});
