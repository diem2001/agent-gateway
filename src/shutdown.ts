import type { IncomingMessage, Server, ServerResponse } from "node:http";
import type { Socket } from "node:net";
import { log } from "./logging.js";
import { logPersistenceError, registeredStores, type PersistentStore } from "./persistence.js";

/* ------------------------------------------------------------------ */
/*  Clean stop on SIGTERM / SIGINT (MVP-7616)                           */
/* ------------------------------------------------------------------ */

/** Hard deadline after the first signal; below Docker's 10 s grace period. */
export const SHUTDOWN_DEADLINE_MS = 8000;

export interface ShutdownOptions {
  server: Server;
  /** The stores saved early and at the end; default: every registered store. */
  stores?: () => PersistentStore[];
  exit?: (code: number) => void;
  deadlineMs?: number;
}

export interface ShutdownController {
  /** Called for every SIGTERM/SIGINT: the first starts the drain, a second ends it. */
  onSignal: (signal: string) => void;
}

/**
 * The shutdown sequence:
 * 1. first signal: stop accepting connections, save every store at once;
 * 2. drain: requests already received (including streaming answers and bodies
 *    still arriving) run on and may change state, saved as usual;
 * 3. when the last connection has closed, at the deadline, or on a second
 *    signal: destroy remaining sockets and save every store synchronously.
 *    Nothing can change state between that save and the exit;
 * 4. exit 0 when every final save succeeded, 1 otherwise.
 */
export function createShutdown(options: ShutdownOptions): ShutdownController {
  const { server } = options;
  const stores = options.stores ?? registeredStores;
  const exit = options.exit ?? ((code: number) => process.exit(code));
  const deadlineMs = options.deadlineMs ?? SHUTDOWN_DEADLINE_MS;

  let draining = false;
  let finished = false;
  let deadline: ReturnType<typeof setTimeout> | null = null;

  // Sockets with the number of responses still open on each, and those responses.
  const sockets = new Map<Socket, number>();
  const responses = new Set<ServerResponse>();
  server.on("connection", (socket: Socket) => {
    sockets.set(socket, 0);
    socket.once("close", () => sockets.delete(socket));
  });
  server.on("request", (req: IncomingMessage, res: ServerResponse) => {
    const socket = req.socket;
    sockets.set(socket, (sockets.get(socket) ?? 0) + 1);
    responses.add(res);
    if (draining) res.shouldKeepAlive = false;
    res.once("close", () => {
      responses.delete(res);
      const open = (sockets.get(socket) ?? 1) - 1;
      if (sockets.has(socket)) sockets.set(socket, open);
      // During the drain a connection ends with its last response.
      if (draining && open === 0) socket.destroySoon();
    });
  });

  function finish(reason: string): void {
    if (finished) return;
    finished = true;
    if (deadline) clearTimeout(deadline);
    for (const socket of sockets.keys()) socket.destroy();

    let failed = false;
    for (const store of stores()) {
      if (store.flush()) continue;
      failed = true;
      const suppressed = store.issues().some((i) => i.problem === "unreadable-not-preserved");
      logPersistenceError({
        area: store.area,
        problem: "final-save-failed",
        file: store.file,
        reason: suppressed
          ? "final save suppressed, unreadable file was not moved aside"
          : "final save failed, file keeps its last complete save",
        code: suppressed ? undefined : store.lastWriteErrorCode,
      });
    }
    log("server", `Shutdown complete (${reason}), exit ${failed ? 1 : 0}`);
    exit(failed ? 1 : 0);
  }

  function onSignal(signal: string): void {
    if (finished) return;
    if (draining) {
      log("server", `Second ${signal}: ending the drain now`);
      finish(`second ${signal}`);
      return;
    }
    draining = true;
    log("server", `${signal} received: refusing new connections, draining for up to ${deadlineMs} ms`);

    // No new connections; idle ones close now, busy ones after their last response.
    server.close(() => finish("drained"));
    for (const [socket, open] of sockets) {
      if (open === 0) socket.destroySoon();
    }
    for (const res of responses) {
      if (!res.headersSent) res.shouldKeepAlive = false;
    }

    // Early save, so a later kill loses nothing made before the signal.
    for (const store of stores()) store.flush();

    deadline = setTimeout(() => finish("deadline"), deadlineMs);
  }

  return { onSignal };
}

/** Install the SIGTERM/SIGINT handlers. Only for the process entry point. */
export function installShutdownHandlers(server: Server): void {
  const controller = createShutdown({ server });
  process.on("SIGTERM", () => controller.onSignal("SIGTERM"));
  process.on("SIGINT", () => controller.onSignal("SIGINT"));
}
