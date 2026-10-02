import type { Express } from "express";

/**
 * The label every registry route test acts as unless it sets its own Authorization header (MVP-7925): the routes
 * read the caller's label from the real authMiddleware, and registry fixtures carry this label as their owner.
 */
export const TEST_OWNER = "owner-test";
export const TEST_OWNER_KEY = "sk-gw-owner-test";

/**
 * Mounts the real authMiddleware on `app` with one API key for TEST_OWNER and gives every request that sends no
 * Authorization header that key. Call it before mounting the routes, after `vi.resetModules()` (it imports the
 * middleware fresh so its key table belongs to the module graph the routes use).
 */
export async function mountOwnerAuth(app: Express): Promise<void> {
  process.env.API_KEYS = `${TEST_OWNER}:${TEST_OWNER_KEY}`;
  const { loadApiKeys, authMiddleware } = await import("../../auth.js");
  loadApiKeys();
  app.use((req, _res, next) => {
    req.headers.authorization ??= `Bearer ${TEST_OWNER_KEY}`;
    next();
  });
  app.use(authMiddleware);
}
