/**
 * Classifies a failed agent run (MVP-7685) into a safe, actionable public
 * message. The Claude runtime reports a provider rejection on stdout (an
 * assistant message with a non-null `error` and a `result` with
 * `is_error: true`, text `API Error: <status> <raw provider body>`) and then
 * exits 1; the SDK throws "Claude Code process exited with code 1". Only the
 * inputs in `RunDiagnostics` are read: never ordinary assistant text, which is
 * model output and can be steered.
 *
 * Raw diagnostic text (provider bodies, result text, stderr, prompts, headers)
 * never leaves this module: `message` is one of the fixed texts below and
 * `logFields` holds only allowlisted values. A `RunFailure` has no `cause`.
 */

export type RunFailureKind =
  | "runtime_version_unsupported"
  | "authentication"
  | "transient"
  | "unknown"
  | "isolation_unavailable"
  | "isolation_timeout"
  | "run_deadline"
  | "session_other_owner"
  | "session_legacy"
  | "session_busy";

/** Everything agent.ts may pass to the classifier for one attempt. */
export interface RunDiagnostics {
  /** `claude_code_version` of the runtime's `system/init` message. */
  installedVersion?: unknown;
  /** The `result` message of the attempt, if one arrived. Its text is read only when `is_error === true`. */
  result?: Record<string, unknown> | null;
  /** Assistant messages whose SDK `error` field is non-null: the enum value and the message's text. */
  assistantErrors?: { error: unknown; text: string }[];
  /** The error the SDK iterator threw, if any. */
  thrown?: unknown;
}

/** Operator log fields; every value is a number, a validated version, an allowlisted word or "none"/"other". */
export interface RunFailureLogFields {
  kind: RunFailureKind;
  apiStatus: string;
  providerType: string;
  installed: string;
  required: string;
}

/** The failed attempt's result without its text (`result`) and without `errors`. */
export type ResultSummary = Partial<
  Record<"subtype" | "is_error" | "session_id" | "usage" | "modelUsage" | "total_cost_usd" | "duration_ms" | "duration_api_ms" | "num_turns", unknown>
>;

export class RunFailure extends Error {
  readonly kind: RunFailureKind;
  readonly retryable: boolean;
  readonly logFields: RunFailureLogFields;
  readonly resultSummary: ResultSummary | null;

  constructor(kind: RunFailureKind, message: string, logFields: RunFailureLogFields, resultSummary: ResultSummary | null) {
    super(message);
    this.name = "RunFailure";
    this.kind = kind;
    this.retryable = kind === "transient";
    this.logFields = logFields;
    this.resultSummary = resultSummary;
  }
}

const RETRY_WILL_NOT_HELP = "Retrying will not help until the administrator has done this.";
const UPDATE_RUNTIME = `Ask your gateway administrator to update the gateway runtime. ${RETRY_WILL_NOT_HELP}`;

function versionMessage(installed: string | null, required: string | null): string {
  const lead = "The AI runtime on the gateway server is too old for the selected model";
  if (installed && required) return `${lead} (installed ${installed}, required ${required} or newer). ${UPDATE_RUNTIME}`;
  if (installed) return `${lead} (installed ${installed}; a newer version is required). ${UPDATE_RUNTIME}`;
  if (required) return `${lead} (required ${required} or newer). ${UPDATE_RUNTIME}`;
  return `${lead}. ${UPDATE_RUNTIME}`;
}

const AUTHENTICATION_MESSAGE = `The gateway could not authenticate with the AI provider. Ask your gateway administrator to check the gateway's authentication. ${RETRY_WILL_NOT_HELP}`;
const TRANSIENT_MESSAGE = "The AI provider is busy right now. Please try again in a few minutes.";

function unknownMessage(queryId: string | undefined): string {
  const reference = queryId && /^[A-Za-z0-9._:-]{1,128}$/.test(queryId) ? ` (reference: ${queryId})` : "";
  return `The AI request failed on the gateway for an unknown reason. Please try again. If it keeps failing, ask your gateway administrator to check the gateway logs${reference}.`;
}

/** Longest provider body that is parsed; anything longer counts as malformed. */
const MAX_BODY_CHARS = 16 * 1024;
/** Longest provider `error.message` the version patterns run on. */
const MAX_VERSION_TEXT_CHARS = 1024;

const VERSION = /^\d{1,5}\.\d{1,5}\.\d{1,5}$/;
const REQUIRED_OR_NEWER = /(?<![\d.])(\d{1,5}\.\d{1,5}\.\d{1,5}) or newer/;
const REQUIRED_AT_LEAST = />=\s{0,3}(\d{1,5}\.\d{1,5}\.\d{1,5})(?![\w.-])/;
/** The runtime's prefix for a provider rejection. */
const API_ERROR_PREFIX = /^API Error: (\d{3})(?![\d])\s?/;
/** The retry layer's historic pattern for a thrown error without any diagnostic. */
const TRANSIENT_THROWN = /rate.limit|429|throttl|overloaded/i;

const PROVIDER_TYPES = new Set([
  "invalid_request_error",
  "authentication_error",
  "permission_error",
  "not_found_error",
  "request_too_large",
  "rate_limit_error",
  "api_error",
  "overloaded_error",
  "billing_error",
]);

interface ProviderFacts {
  status: number | null;
  types: string[];
  codes: string[];
  message: string | null;
}

function stringAt(value: unknown, ...keys: string[]): string | null {
  let current = value;
  for (const key of keys) {
    if (!current || typeof current !== "object" || Array.isArray(current)) return null;
    current = (current as Record<string, unknown>)[key];
  }
  return typeof current === "string" ? current : null;
}

/** Status and fixed-path fields of one error-flagged text; never a recursive walk. */
function providerFacts(text: string): ProviderFacts {
  const facts: ProviderFacts = { status: null, types: [], codes: [], message: null };
  const prefix = API_ERROR_PREFIX.exec(text.slice(0, 32));
  if (!prefix) return facts;
  facts.status = Number(prefix[1]);
  const body = text.slice(prefix[0].length);
  if (body.length > MAX_BODY_CHARS) return facts;
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return facts;
  }
  for (const path of [["error", "type"], ["error", "error", "type"]]) {
    const value = stringAt(parsed, ...path);
    if (value) facts.types.push(value);
  }
  for (const path of [["error", "code"], ["error", "error", "code"]]) {
    const value = stringAt(parsed, ...path);
    if (value) facts.codes.push(value);
  }
  facts.message = stringAt(parsed, "error", "message");
  return facts;
}

/** A thrown SDK error, not a JSON SyntaxError: that one quotes runtime stdout, which is untrusted. */
function thrownMayBeTransient(thrown: unknown): boolean {
  return thrown instanceof Error && !(thrown instanceof SyntaxError) && typeof thrown.message === "string";
}

function requiredVersion(message: string | null): string | null {
  if (!message) return null;
  const text = message.slice(0, MAX_VERSION_TEXT_CHARS);
  const match = REQUIRED_OR_NEWER.exec(text) ?? REQUIRED_AT_LEAST.exec(text);
  return match && VERSION.test(match[1]) ? match[1] : null;
}

function summarize(result: Record<string, unknown> | null | undefined): ResultSummary | null {
  if (!result || typeof result !== "object") return null;
  const summary: ResultSummary = {};
  for (const key of ["subtype", "is_error", "session_id", "usage", "modelUsage", "total_cost_usd", "duration_ms", "duration_api_ms", "num_turns"] as const) {
    if (key in result) summary[key] = result[key];
  }
  return summary;
}

function classify(diagnostics: RunDiagnostics, queryId: string | undefined): RunFailure {
  const installed = typeof diagnostics.installedVersion === "string" && VERSION.test(diagnostics.installedVersion) ? diagnostics.installedVersion : null;
  const result = diagnostics.result && typeof diagnostics.result === "object" ? diagnostics.result : null;

  const texts: string[] = [];
  if (result?.is_error === true && typeof result.result === "string") texts.push(result.result);
  if (Array.isArray(result?.errors)) for (const entry of result.errors) if (typeof entry === "string") texts.push(entry);
  const assistantErrors = Array.isArray(diagnostics.assistantErrors) ? diagnostics.assistantErrors : [];
  const errorEnums = assistantErrors.map((entry) => entry.error).filter((value): value is string => typeof value === "string");
  for (const entry of assistantErrors) if (typeof entry.text === "string") texts.push(entry.text);

  const facts = texts.map(providerFacts);
  const statuses = facts.map((f) => f.status).filter((s): s is number => s !== null);
  const types = facts.flatMap((f) => f.types);
  const codes = facts.flatMap((f) => [...f.codes, ...f.types]);
  const hasDiagnostic = texts.length > 0 || errorEnums.length > 0;

  let kind: RunFailureKind = "unknown";
  let required: string | null = null;
  if (codes.includes("claude_code_version_too_old")) {
    kind = "runtime_version_unsupported";
    for (const f of facts) {
      if (f.codes.includes("claude_code_version_too_old") || f.types.includes("claude_code_version_too_old")) required ??= requiredVersion(f.message);
    }
  } else if (errorEnums.includes("authentication_failed") || types.includes("authentication_error") || types.includes("permission_error")) {
    kind = "authentication";
  } else if (
    statuses.includes(429) ||
    statuses.includes(529) ||
    types.includes("rate_limit_error") ||
    types.includes("overloaded_error") ||
    errorEnums.includes("rate_limit") ||
    (!hasDiagnostic && thrownMayBeTransient(diagnostics.thrown) && TRANSIENT_THROWN.test((diagnostics.thrown as Error).message.slice(0, MAX_VERSION_TEXT_CHARS)))
  ) {
    kind = "transient";
  }

  const message =
    kind === "runtime_version_unsupported"
      ? versionMessage(installed, required)
      : kind === "authentication"
        ? AUTHENTICATION_MESSAGE
        : kind === "transient"
          ? TRANSIENT_MESSAGE
          : unknownMessage(queryId);
  const firstType = types[0];
  const logFields: RunFailureLogFields = {
    kind,
    apiStatus: statuses.length > 0 ? String(statuses[0]) : "none",
    providerType: firstType === undefined ? "none" : PROVIDER_TYPES.has(firstType) ? firstType : "other",
    installed: installed ?? "none",
    required: required ?? "none",
  };
  return new RunFailure(kind, message, logFields, summarize(result));
}

/**
 * The failure of one attempt. Total: any internal exception gives the
 * `unknown` failure. Precedence: runtime version and authentication beat
 * transient, and transient beats unknown.
 */
export function classifyRunFailure(diagnostics: RunDiagnostics, queryId?: string): RunFailure {
  try {
    return classify(diagnostics, queryId);
  } catch {
    const fields: RunFailureLogFields = { kind: "unknown", apiStatus: "none", providerType: "none", installed: "none", required: "none" };
    return new RunFailure("unknown", unknownMessage(queryId), fields, null);
  }
}

/** The operator log line tail for a failure: `kind=<kind> apiStatus=<n|none> ...`. */
export function formatLogFields(fields: RunFailureLogFields): string {
  return `kind=${fields.kind} apiStatus=${fields.apiStatus} providerType=${fields.providerType} installed=${fields.installed} required=${fields.required}`;
}

/** The SDK's AbortError (the class sets no `name`) or a DOM AbortError: a client abort, not a run failure. */
export function isAbortError(err: unknown): boolean {
  return err instanceof Error && (err.name === "AbortError" || err.constructor?.name === "AbortError");
}

/* ------------------------------------------------------------------ */
/*  Isolation and deadline failures (MVP-7678)                          */
/* ------------------------------------------------------------------ */

function referenceSuffix(queryId: string | undefined): string {
  return queryId && /^[A-Za-z0-9._:-]{1,128}$/.test(queryId) ? ` (reference: ${queryId})` : "";
}

/** Fixed texts; the tests assert them verbatim. They name no internal term and say who acts and whether retrying helps. */
export function isolationUnavailableMessage(queryId: string | undefined): string {
  return `The gateway cannot start a protected workspace, so this request did not run. Ask your gateway administrator to check the gateway's isolation status. ${RETRY_WILL_NOT_HELP}${referenceSuffix(queryId)}`;
}

export function isolationTimeoutMessage(queryId: string | undefined): string {
  return `The gateway could not start a protected workspace in time, so this request did not run. Please try again in a few minutes. If it keeps happening, tell your gateway administrator.${referenceSuffix(queryId)}`;
}

export function runDeadlineMessage(limitMs: number, queryId: string | undefined): string {
  const minutes = Math.max(1, Math.ceil(limitMs / 60_000));
  return `The request was stopped because it ran longer than the gateway's limit of ${minutes} ${minutes === 1 ? "minute" : "minutes"}. Its results were not saved. Try again with a smaller task, or ask your gateway administrator to raise the limit.${referenceSuffix(queryId)}`;
}

/** A failure with a fixed public text and no provider facts. It is never retried. */
export function fixedFailure(kind: RunFailureKind, message: string): RunFailure {
  const fields: RunFailureLogFields = { kind, apiStatus: "none", providerType: "none", installed: "none", required: "none" };
  return new RunFailure(kind, message, fields, null);
}

/** Conversation admission refusals (MVP-7678). The "other owner" text does not confirm that the conversation exists. */
export const SESSION_OTHER_OWNER_MESSAGE = "This conversation cannot be continued from your account. Please start a new conversation.";
export const SESSION_LEGACY_MESSAGE = "This conversation was started before a gateway security update and cannot be continued safely. Please start a new conversation. Retrying will not help.";
export const SESSION_BUSY_MESSAGE = "This conversation is still answering an earlier request. Please wait until it has finished, then try again.";
