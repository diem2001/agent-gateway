/**
 * Unit tests for the shutdown sequence (MVP-7616 Gate B) on a real loopback
 * HTTP server with recording stores and a recorded exit: ordering of the early
 * and final saves, the drain, the deadline, the second signal and the exit code.
 */
import http from "node:http";
import net, { type AddressInfo } from "node:net";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { PersistentStore } from "../persistence.js";
import { createShutdown } from "../shutdown.js";

type Area = PersistentStore["area"];

interface FakeStore {
  area: Area;
  file: string;
  lastWriteErrorCode: string | undefined;
  flush: () => boolean;
  issues: () => { problem: string }[];
}

let events: string[];
let errors: string[];
let server: http.Server;
let port: number;
/** Requests the handler holds open until released. */
let held: Map<string, () => void>;

function store(area: Area, behaviour: "ok" | "fail" | "suppressed" = "ok"): FakeStore {
  return {
    area,
    file: `/tmp/${area}.json`,
    lastWriteErrorCode: behaviour === "fail" ? "ENOSPC" : undefined,
    flush: () => {
      events.push(`flush:${area}`);
      return behaviour === "ok";
    },
    issues: () => (behaviour === "suppressed" ? [{ problem: "unreadable-not-preserved" }] : []),
  };
}

beforeEach(async () => {
  events = [];
  errors = [];
  held = new Map();
  vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
    errors.push(args.map(String).join(" "));
  });
  vi.spyOn(console, "log").mockImplementation(() => undefined);
  server = http.createServer((req, res) => {
    const name = new URL(req.url ?? "/", "http://x").searchParams.get("hold");
    if (name) {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.write("started\n");
      held.set(name, () => res.end("done\n"));
      return;
    }
    events.push(`request:${req.url}`);
    res.end("ok\n");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  port = (server.address() as AddressInfo).port;
});

afterEach(async () => {
  vi.restoreAllMocks();
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

function setup(stores: FakeStore[], deadlineMs = 400) {
  let exitCode: number | undefined;
  let exitAt = 0;
  let resolveExit: (code: number) => void;
  const exited = new Promise<number>((resolve) => (resolveExit = resolve));
  const controller = createShutdown({
    server,
    stores: () => stores as unknown as PersistentStore[],
    deadlineMs,
    exit: (code) => {
      events.push(`exit:${code}`);
      exitCode = code;
      exitAt = Date.now();
      resolveExit(code);
    },
  });
  return { controller, exited, exitCode: () => exitCode, exitAt: () => exitAt };
}

const agent = () => new http.Agent({ keepAlive: true, maxSockets: 1 });

function get(path: string, a?: http.Agent): Promise<{ status: number; body: string; connection: string | undefined }> {
  return new Promise((resolve, reject) => {
    const req = http.get({ host: "127.0.0.1", port, path, agent: a ?? false }, (res) => {
      let body = "";
      res.on("data", (d: Buffer) => (body += d.toString()));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body, connection: res.headers.connection }));
      res.on("error", reject);
    });
    req.on("error", reject);
  });
}

/** Starts a held request and resolves once its first bytes arrived. */
function startHeld(name: string): Promise<{ done: Promise<string> }> {
  return new Promise((resolve, reject) => {
    const req = http.get({ host: "127.0.0.1", port, path: `/?hold=${name}`, agent: false }, (res) => {
      let body = "";
      const done = new Promise<string>((r) => {
        res.on("end", () => r(body));
        res.on("error", () => r(`${body}<aborted>`));
        res.on("close", () => r(`${body}<closed>`));
      });
      res.once("data", (d: Buffer) => {
        body += d.toString();
        res.on("data", (more: Buffer) => (body += more.toString()));
        resolve({ done });
      });
    });
    req.on("error", reject);
  });
}

function connectRefused(): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = net.connect(port, "127.0.0.1");
    socket.once("connect", () => {
      socket.destroy();
      resolve(false);
    });
    socket.once("error", () => resolve(true));
  });
}

describe("createShutdown", () => {
  it("idle: saves early, closes, saves every store again and exits 0", async () => {
    const t = setup([store("sessions"), store("tools"), store("mcpServers")]);
    t.controller.onSignal("SIGTERM");
    expect(await t.exited).toBe(0);
    expect(events).toEqual([
      "flush:sessions",
      "flush:tools",
      "flush:mcpServers",
      "flush:sessions",
      "flush:tools",
      "flush:mcpServers",
      "exit:0",
    ]);
  });

  it("closes an idle keep-alive connection at once", async () => {
    const a = agent();
    await get("/first", a);
    const t = setup([store("sessions")]);
    const started = Date.now();
    t.controller.onSignal("SIGINT");
    expect(await t.exited).toBe(0);
    expect(Date.now() - started).toBeLessThan(300);
    a.destroy();
  });

  it("drain: an open response finishes, new connections are refused, the final save follows the response", async () => {
    const t = setup([store("sessions"), store("tools"), store("mcpServers")], 5000);
    const open = await startHeld("stream");
    t.controller.onSignal("SIGTERM");
    expect(events).toEqual(["flush:sessions", "flush:tools", "flush:mcpServers"]);
    expect(await connectRefused()).toBe(true);
    await new Promise((r) => setTimeout(r, 100));
    expect(t.exitCode()).toBeUndefined();

    events.push("release");
    held.get("stream")!();
    expect(await open.done).toBe("started\ndone\n");
    expect(await t.exited).toBe(0);
    expect(events.slice(3)).toEqual(["release", "flush:sessions", "flush:tools", "flush:mcpServers", "exit:0"]);
  });

  it("deadline: a response that never ends is cut and the process exits 0 after the deadline", async () => {
    const t = setup([store("sessions")], 300);
    const open = await startHeld("forever");
    const started = Date.now();
    t.controller.onSignal("SIGTERM");
    expect(await t.exited).toBe(0);
    const elapsed = t.exitAt() - started;
    expect(elapsed).toBeGreaterThanOrEqual(290);
    expect(elapsed).toBeLessThan(1000);
    expect(await open.done).toMatch(/^started\n<(aborted|closed)>$/);
  });

  it("second signal ends the drain at once", async () => {
    const t = setup([store("sessions"), store("tools")], 5000);
    const open = await startHeld("stream");
    t.controller.onSignal("SIGTERM");
    await new Promise((r) => setTimeout(r, 50));
    const second = Date.now();
    t.controller.onSignal("SIGINT");
    expect(await t.exited).toBe(0);
    expect(t.exitAt() - second).toBeLessThan(100);
    expect(events).toEqual(["flush:sessions", "flush:tools", "flush:sessions", "flush:tools", "exit:0"]);
    await open.done;
  });

  it("signals after the final save are ignored", async () => {
    const t = setup([store("sessions")]);
    t.controller.onSignal("SIGTERM");
    await t.exited;
    t.controller.onSignal("SIGTERM");
    expect(events.filter((e) => e.startsWith("exit"))).toEqual(["exit:0"]);
  });

  it("exits 1 with a final-save-failed ERROR line when a final save fails", async () => {
    const t = setup([store("sessions"), store("tools", "fail"), store("mcpServers")]);
    t.controller.onSignal("SIGTERM");
    expect(await t.exited).toBe(1);
    // Every store is still saved; one failure does not skip the others.
    expect(events.slice(3)).toEqual(["flush:sessions", "flush:tools", "flush:mcpServers", "exit:1"]);
    expect(errors).toEqual([
      "ERROR persistence area=tools problem=final-save-failed file=/tmp/tools.json reason=final save failed, file keeps its last complete save code=ENOSPC (see /health)",
    ]);
  });

  it("exits 1 when an area's saves are suppressed", async () => {
    const t = setup([store("sessions", "suppressed"), store("tools")]);
    t.controller.onSignal("SIGINT");
    expect(await t.exited).toBe(1);
    expect(errors).toEqual([
      "ERROR persistence area=sessions problem=final-save-failed file=/tmp/sessions.json reason=final save suppressed, unreadable file was not moved aside (see /health)",
    ]);
  });
});
