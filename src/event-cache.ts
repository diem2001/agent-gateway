import { logDebug } from "./logging.js";

export interface StreamEvent {
  seq: number;
  type: string;
  [key: string]: unknown;
}

export interface CacheEntry {
  events: StreamEvent[];
  status: "running" | "done";
  doneAt: number | null;
  listeners: Set<(event: StreamEvent) => void>;
}

const eventCache = new Map<string, CacheEntry>();

const EVENT_CACHE_TTL_MS = parseInt(
  process.env.EVENT_CACHE_TTL_MS || String(30 * 60 * 1000), 10,
);

export function createCacheEntry(queryId: string): CacheEntry {
  const entry: CacheEntry = { events: [], status: "running", doneAt: null, listeners: new Set() };
  eventCache.set(queryId, entry);
  return entry;
}

export function getCacheEntry(queryId: string): CacheEntry | undefined {
  return eventCache.get(queryId);
}

export function markDone(queryId: string): void {
  const entry = eventCache.get(queryId);
  if (entry) { entry.status = "done"; entry.doneAt = Date.now(); }
}

export function getCacheSize(): number { return eventCache.size; }

setInterval(() => {
  const now = Date.now();
  let cleaned = 0;
  for (const [queryId, entry] of eventCache) {
    if (entry.status === "done" && entry.doneAt && now - entry.doneAt > EVENT_CACHE_TTL_MS) {
      eventCache.delete(queryId); cleaned++;
    }
  }
  if (cleaned > 0) logDebug("cache", `GC: removed ${cleaned} expired queries`);
}, 60_000);
