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

/**
 * Entries are keyed by (API-key label, queryId) (MVP-7679): `queryId` is chosen by the caller, so a second
 * label reusing it gets its own entry and a replay never reaches another label's events.
 */
const eventCache = new Map<string, CacheEntry>();

function cacheKey(label: string, queryId: string): string {
  return `${label}\u0000${queryId}`;
}

const EVENT_CACHE_TTL_MS = parseInt(
  process.env.EVENT_CACHE_TTL_MS || String(30 * 60 * 1000), 10,
);

export function createCacheEntry(label: string, queryId: string): CacheEntry {
  const entry: CacheEntry = { events: [], status: "running", doneAt: null, listeners: new Set() };
  eventCache.set(cacheKey(label, queryId), entry);
  return entry;
}

export function getCacheEntry(label: string, queryId: string): CacheEntry | undefined {
  return eventCache.get(cacheKey(label, queryId));
}

export function markDone(label: string, queryId: string): void {
  const entry = eventCache.get(cacheKey(label, queryId));
  if (entry) { entry.status = "done"; entry.doneAt = Date.now(); }
}

export function getCacheSize(): number { return eventCache.size; }

setInterval(() => {
  const now = Date.now();
  let cleaned = 0;
  for (const [key, entry] of eventCache) {
    if (entry.status === "done" && entry.doneAt && now - entry.doneAt > EVENT_CACHE_TTL_MS) {
      eventCache.delete(key); cleaned++;
    }
  }
  if (cleaned > 0) logDebug("cache", `GC: removed ${cleaned} expired queries`);
}, 60_000);
