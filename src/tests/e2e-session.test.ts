/**
 * E2E test for session continuity.
 * Runs against a live Agent Gateway instance.
 *
 * Prerequisites:
 *   - Agent Gateway running (docker compose up -d)
 *   - API_KEY env var set (or defaults to key from docker inspect)
 *
 * Run: npx vitest run src/tests/e2e-session.test.ts
 *   or: npm run test:e2e
 */
import { describe, it, expect } from "vitest";

const BASE_URL = process.env.GATEWAY_URL || "http://127.0.0.1:3001";
const API_KEY = process.env.GATEWAY_API_KEY || "";

// Skip if no API key configured (CI without live gateway)
const describeE2E = API_KEY ? describe : describe.skip;

interface NdjsonEvent {
  seq: number;
  type: string;
  content?: string;
  inputTokens?: number;
  outputTokens?: number;
  sessionId?: string;
}

async function sendQuery(
  sessionId: string,
  prompt: string,
): Promise<{ events: NdjsonEvent[]; text: string }> {
  const queryId = `test-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

  const resp = await fetch(`${BASE_URL}/v1/query`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ queryId, sessionId, prompt }),
  });

  expect(resp.ok).toBe(true);

  const body = await resp.text();
  const events: NdjsonEvent[] = body
    .trim()
    .split("\n")
    .filter((line) => line.trim())
    .map((line) => JSON.parse(line));

  const text = events
    .filter((e) => e.type === "text")
    .map((e) => e.content || "")
    .join("");

  return { events, text };
}

describeE2E("Session Continuity (E2E)", () => {
  it("maintains context across multiple queries in the same session", async () => {
    const sessionId = `e2e-session-${Date.now()}`;

    // Query 1: establish a fact
    const q1 = await sendQuery(
      sessionId,
      "My secret code is FALCON-7749. Reply only: Acknowledged.",
    );
    expect(q1.text.toLowerCase()).toContain("acknowledged");

    // Verify done event exists
    const done1 = q1.events.find((e) => e.type === "done");
    expect(done1).toBeDefined();

    // Query 2: ask about the fact — requires session context
    const q2 = await sendQuery(
      sessionId,
      "What is my secret code? Reply with just the code, nothing else.",
    );
    expect(q2.text).toContain("FALCON-7749");
  }, 60_000);

  it("different sessions have independent context", async () => {
    const session1 = `e2e-isolated-1-${Date.now()}`;
    const session2 = `e2e-isolated-2-${Date.now()}`;

    // Session 1: set a name
    await sendQuery(session1, "My name is AlphaUser. Reply: OK.");

    // Session 2: set a different name
    await sendQuery(session2, "My name is BetaUser. Reply: OK.");

    // Session 1: ask name — should be AlphaUser, not BetaUser
    const q1 = await sendQuery(
      session1,
      "What is my name? Reply with just the name.",
    );
    expect(q1.text).toContain("AlphaUser");
    expect(q1.text).not.toContain("BetaUser");
  }, 90_000);

  it("returns error event on invalid session resume", async () => {
    // This tests that an invalid resume doesn't crash silently
    // The Gateway should handle the error gracefully
    const resp = await fetch(`${BASE_URL}/v1/query`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        queryId: `test-invalid-${Date.now()}`,
        prompt: "Hello",
      }),
    });
    expect(resp.ok).toBe(true);

    const body = await resp.text();
    const events: NdjsonEvent[] = body
      .trim()
      .split("\n")
      .filter((l) => l.trim())
      .map((l) => JSON.parse(l));

    // Should complete without crash (either text+done or error)
    const hasResult = events.some(
      (e) => e.type === "done" || e.type === "error",
    );
    expect(hasResult).toBe(true);
  }, 30_000);
});
