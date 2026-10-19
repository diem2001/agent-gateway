import { logAlways } from "./logging.js";
import { isAbortError } from "./run-failure.js";

/* ------------------------------------------------------------------ */
/*  Late abort rejections (MVP-7866)                                    */
/* ------------------------------------------------------------------ */

/**
 * The SDK answers a runtime's tool or hook call (a control request) from a promise nobody awaits. When a
 * client disconnect aborted the run before that answer is written, the write throws the SDK's AbortError and
 * the rejection reaches no handler of the gateway: without a listener, Node ends the whole process and every
 * other client's run with it. Only that error is dropped, with one fixed line that carries no message, stack
 * or request data; any other unhandled rejection is rethrown from the listener and ends the process as before.
 */
export function installAbortRejectionGuard(): void {
  process.on("unhandledRejection", (reason: unknown) => {
    if (!isAbortError(reason)) throw reason;
    logAlways("process", "late abort rejection ignored");
  });
}
