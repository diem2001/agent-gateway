/**
 * Test doubles for the upload relay: an upstream stub that records what reached
 * it (and whether it was aborted), and a sender that streams a generated body
 * with backpressure, so neither side ever holds a large upload in memory.
 */

import { createHash } from "node:crypto";
import http, { type IncomingHttpHeaders, type IncomingMessage, type ServerResponse } from "node:http";
import net, { type AddressInfo } from "node:net";

export const MiB = 1024 * 1024;

/* ------------------------------------------------------------------ */
/*  Upstream stub                                                       */
/* ------------------------------------------------------------------ */

export interface StubRequest {
  method: string;
  url: string;
  headers: IncomingHttpHeaders;
  bytes: number;
  sha256: string | null;
  /** True once the whole body arrived. */
  complete: boolean;
  /** True when the connection closed before the body was complete. */
  aborted: boolean;
  abortedAt: number | null;
}

export interface StubContext {
  req: IncomingMessage;
  res: ServerResponse;
  record: StubRequest;
  /**
   * Reads the body (hashing it) until it ends or the connection closes; resolves
   * true when the body was complete. `bytesPerSecond` throttles the read.
   */
  consume: (options?: { bytesPerSecond?: number }) => Promise<boolean>;
}

export type StubHandler = (ctx: StubContext) => void | Promise<void>;

export interface UploadStub {
  port: number;
  /** Registration url: the relay derives `<origin>/uploads/` from it. */
  url: string;
  requests: StubRequest[];
  /** TCP connections accepted, including ones that never sent a request. */
  connections: () => number;
  close: () => Promise<void>;
}

/** Default handler: read the whole body, answer 201 with an SC-2 shaped body. */
export const answerCreated: StubHandler = async ({ res, record, consume }) => {
  if (!(await consume())) return;
  const body = JSON.stringify({
    attachmentId: "10001",
    mediaApiFileId: "0f0e0d0c-0b0a-4908-8706-050403020100",
    filename: "shot.png",
    size: record.bytes,
  });
  res.writeHead(201, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) });
  res.end(body);
};

export async function startUploadStub(handler: StubHandler = answerCreated): Promise<UploadStub> {
  const requests: StubRequest[] = [];
  let connections = 0;
  const sockets = new Set<net.Socket>();

  const server = http.createServer((req, res) => {
    const record: StubRequest = {
      method: req.method ?? "",
      url: req.url ?? "",
      headers: req.headers,
      bytes: 0,
      sha256: null,
      complete: false,
      aborted: false,
      abortedAt: null,
    };
    requests.push(record);
    req.on("close", () => {
      if (!req.complete && !record.aborted) {
        record.aborted = true;
        record.abortedAt = Date.now();
      }
    });
    req.on("error", () => undefined);

    const hash = createHash("sha256");
    const consume = (options: { bytesPerSecond?: number } = {}) =>
      new Promise<boolean>((resolve) => {
        const started = Date.now();
        req.on("data", (chunk: Buffer) => {
          record.bytes += chunk.length;
          hash.update(chunk);
          if (options.bytesPerSecond) {
            const due = started + (record.bytes / options.bytesPerSecond) * 1000;
            const wait = due - Date.now();
            if (wait > 0) {
              req.pause();
              setTimeout(() => req.resume(), wait);
            }
          }
        });
        req.on("end", () => {
          record.complete = true;
          record.sha256 = hash.digest("hex");
          resolve(true);
        });
        req.on("close", () => {
          if (!req.complete) resolve(false);
        });
      });
    void handler({ req, res, record, consume });
  });
  server.on("connection", (socket) => {
    connections += 1;
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const { port } = server.address() as AddressInfo;
  return {
    port,
    url: `http://127.0.0.1:${port}/mcp`,
    requests,
    connections: () => connections,
    close: () =>
      new Promise<void>((resolve) => {
        for (const socket of sockets) socket.destroy();
        server.close(() => resolve());
      }),
  };
}

/** A port that refuses connections (bound, then released). */
export async function closedPort(): Promise<number> {
  const server = net.createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const { port } = server.address() as AddressInfo;
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
}

/* ------------------------------------------------------------------ */
/*  Sender                                                              */
/* ------------------------------------------------------------------ */

export interface SendOptions {
  port: number;
  path: string;
  headers?: Record<string, string>;
  /** Body size in bytes; the body is generated, never held whole. */
  total: number;
  /** Omit Content-Length and send the body chunked. */
  chunked?: boolean;
  chunkSize?: number;
  /** Delay before every chunk after the first (ms). */
  intervalMs?: number;
  /** Stop sending (without ending) after this many bytes. */
  stallAfter?: number;
  /** Destroy the connection after this many bytes. */
  abortAfter?: number;
  /** Byte that starts the generated pattern, so different bodies differ. */
  seed?: number;
  /** Bytes placed at the start of the body (e.g. a PNG signature or a marker). */
  prefix?: Buffer;
  /** Called with the running total each time a chunk is handed to the socket. */
  onWritten?: (written: number) => void;
  /**
   * Hand the whole body to the socket in one write, as curl does with
   * `--data-binary @file`. The gateway then receives it in large bursts.
   * Holds the body in memory: use for small uploads only.
   */
  oneWrite?: boolean;
}

export interface SendResult {
  status: number;
  headers: IncomingHttpHeaders;
  text: string;
  /** sha256 of the bytes handed to the socket. */
  sentSha256: string;
  written: () => number;
  /** When the sender's socket closed (ms epoch), once it has. */
  socketClosedAt: () => number | null;
  startedAt: number;
  finishedAt: number;
}

const chunkCache = new Map<string, Buffer>();

/**
 * Byte `i` of a generated body is `(i * 31 + seed) & 0xff`, so a chunk depends
 * only on its size and `offset mod 256`. Chunks are cached and reused, which
 * keeps the sender about as fast as curl: a slow sender would give the gateway
 * time to poll the upstream socket between chunks and hide races (MVP-7564).
 * Never mutate a returned chunk.
 */
export function bodyChunk(size: number, offset: number, seed = 0): Buffer {
  const key = `${size}:${offset & 0xff}:${seed}`;
  let chunk = chunkCache.get(key);
  if (!chunk) {
    chunk = Buffer.allocUnsafe(size);
    for (let i = 0; i < size; i++) chunk[i] = (offset + i) * 31 + seed;
    if (chunkCache.size > 64) chunkCache.clear();
    chunkCache.set(key, chunk);
  }
  return chunk;
}

/**
 * Streams a generated body to the gateway and resolves with the answer. Rejects
 * when the connection fails before an answer arrived.
 */
export function sendUpload(options: SendOptions): Promise<SendResult> {
  const chunkSize = options.chunkSize ?? 64 * 1024;
  const hash = createHash("sha256");
  let written = 0;
  let socketClosedAt: number | null = null;
  const startedAt = Date.now();
  const headers: Record<string, string | number> = { ...(options.headers ?? {}) };
  if (!options.chunked) headers["Content-Length"] = options.total;

  return new Promise((resolve, reject) => {
    const req = http.request({
      host: "127.0.0.1",
      port: options.port,
      method: "POST",
      path: options.path,
      headers,
      agent: false,
    });
    req.on("socket", (socket) => socket.on("close", () => (socketClosedAt = Date.now())));
    let answered = false;
    req.on("response", (res) => {
      answered = true;
      const chunks: Buffer[] = [];
      res.on("data", (chunk: Buffer) => chunks.push(chunk));
      res.on("end", () =>
        resolve({
          status: res.statusCode ?? 0,
          headers: res.headers,
          text: Buffer.concat(chunks).toString("utf8"),
          sentSha256: hash.digest("hex"),
          written: () => written,
          socketClosedAt: () => socketClosedAt,
          startedAt,
          finishedAt: Date.now(),
        }),
      );
      res.on("error", () => undefined);
    });
    req.on("error", (err) => {
      if (!answered) reject(err);
    });

    let stopped = false;
    const next = (): Buffer | null => {
      if (written >= options.total) return null;
      let size = Math.min(chunkSize, options.total - written);
      if (options.stallAfter !== undefined) size = Math.min(size, options.stallAfter - written);
      if (options.abortAfter !== undefined) size = Math.min(size, options.abortAfter - written);
      const shared = bodyChunk(size, written, options.seed);
      if (!options.prefix || written >= options.prefix.length) return shared;
      const chunk = Buffer.from(shared);
      options.prefix.copy(chunk, 0, written, Math.min(options.prefix.length, written + size));
      return chunk;
    };
    const pump = () => {
      while (!stopped) {
        if (options.stallAfter !== undefined && written >= options.stallAfter) return;
        if (options.abortAfter !== undefined && written >= options.abortAfter) {
          stopped = true;
          req.destroy();
          return;
        }
        const chunk = next();
        if (!chunk) {
          stopped = true;
          req.end();
          return;
        }
        written += chunk.length;
        options.onWritten?.(written);
        hash.update(chunk);
        const ok = req.write(chunk);
        if (options.intervalMs) {
          setTimeout(pump, options.intervalMs);
          return;
        }
        if (!ok) {
          req.once("drain", pump);
          return;
        }
      }
    };
    req.on("close", () => (stopped = true));
    if (options.oneWrite) {
      const body = Buffer.allocUnsafe(options.total);
      for (let offset = 0; offset < options.total; offset += chunkSize) {
        bodyChunk(Math.min(chunkSize, options.total - offset), offset, options.seed).copy(body, offset);
      }
      options.prefix?.copy(body, 0);
      written = body.length;
      options.onWritten?.(written);
      hash.update(body);
      req.end(body);
      return;
    }
    pump();
  });
}

/**
 * Sends a hand-written request over a raw socket (for request lines a client
 * library would normalize) and returns everything the server wrote until it
 * closed the connection.
 */
export function rawRequest(port: number, head: string, body: Buffer): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, "127.0.0.1");
    const received: Buffer[] = [];
    socket.on("data", (data: Buffer) => received.push(data));
    socket.on("error", reject);
    socket.on("close", () => resolve(Buffer.concat(received).toString("latin1")));
    socket.on("connect", () => {
      socket.write(head);
      socket.write(body);
    });
  });
}
