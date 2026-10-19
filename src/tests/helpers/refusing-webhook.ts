/**
 * A recording webhook double that refuses every call with HTTP 422 and a `message`: the n-th request is answered with
 * the n-th queued message (the last one repeats), so a scripted run decides what each refusal says (MVP-8207).
 */
import http from "node:http";
import type net from "node:net";
import type { AddressInfo } from "node:net";

export interface RefusingDouble {
  base: string;
  hits: { path: string }[];
  /** The refusal messages, answered in order. */
  messages: string[];
  close: () => Promise<void>;
}

export async function startRefusingDouble(messages: string[], host = "127.0.0.1"): Promise<RefusingDouble> {
  const hits: RefusingDouble["hits"] = [];
  const queue = [...messages];
  const sockets = new Set<net.Socket>();
  const server = http.createServer((req, res) => {
    hits.push({ path: req.url ?? "" });
    req.resume();
    req.on("end", () => {
      const message = queue.length > 1 ? queue.shift()! : (queue[0] ?? "refused");
      res.writeHead(422, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ message }));
    });
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  await new Promise<void>((resolve) => server.listen(0, host, () => resolve()));
  return {
    base: `http://${host}:${(server.address() as AddressInfo).port}`,
    hits,
    messages,
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}
