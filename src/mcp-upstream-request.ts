import { validateHeaderName, validateHeaderValue } from "node:http";

/**
 * What an unusable stored configuration or an unreachable upstream makes the health, test and call routes say
 * (MVP-7957). The texts are fixed: the transport library's own message quotes the header, the URL or the value it
 * refused, so no `error.message` of a failed request reaches a client or a log line.
 */
export const MCP_FAILURE_TEXT = {
  header: "a stored header of this server cannot be sent",
  address: "the stored server address cannot be used",
  unreachable: "the MCP server could not be reached",
} as const;

export type McpFailureReason = keyof typeof MCP_FAILURE_TEXT;

/** Whether Node can send the header: a token name and a value without CR, LF, NUL or other invalid characters. */
export function isSendableHeader(name: string, value: unknown): boolean {
  if (typeof value !== "string") return false;
  try {
    validateHeaderName(name);
    validateHeaderValue(name, value);
    return true;
  } catch {
    return false;
  }
}

/**
 * Why a request to `url` with `headers` cannot be made, or null when it can: an address that is not a parseable
 * http(s) URL without user info, or a header name or value Node cannot send. Checked before `fetch`, so the
 * library never has a chance to quote the offending value. The address is checked first.
 */
export function upstreamRequestProblem(url: unknown, headers: Record<string, unknown> | undefined): "address" | "header" | null {
  try {
    if (typeof url !== "string") return "address";
    const parsed = new URL(url);
    if ((parsed.protocol !== "http:" && parsed.protocol !== "https:") || parsed.username !== "" || parsed.password !== "") {
      return "address";
    }
  } catch {
    return "address";
  }
  for (const [name, value] of Object.entries(headers ?? {})) {
    if (!isSendableHeader(name, value)) return "header";
  }
  return null;
}
