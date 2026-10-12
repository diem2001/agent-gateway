/**
 * The startup guard for late abort rejections (MVP-7866): the compiled `dist/process-guards.js` runs in child
 * processes (built by `npm run build`). The SDK raises its AbortError from a promise nobody awaits; only that
 * error is dropped, every other unhandled rejection still ends the process.
 */
import { spawn } from "node:child_process";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { REPO_ROOT } from "./helpers/git-process-gateway.js";

const GUARDS = path.join(REPO_ROOT, "dist", "process-guards.js");
const GUARD_LINE = "[process] late abort rejection ignored";

interface ChildResult {
  code: number | null;
  signal: NodeJS.Signals | null;
  stderr: string;
  stdout: string;
}

/** Runs `body` as an ES module in a fresh node process after an optional guard installation. */
function runChild(body: string, installGuard: boolean): Promise<ChildResult> {
  const script = [
    installGuard ? `import { installAbortRejectionGuard } from ${JSON.stringify(GUARDS)}; installAbortRejectionGuard();` : "",
    body,
    "setTimeout(() => {}, 300);",
  ].join("\n");
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["--input-type=module", "-e", script], { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d: Buffer) => (stdout += d.toString("utf8")));
    child.stderr.on("data", (d: Buffer) => (stderr += d.toString("utf8")));
    child.on("error", reject);
    child.on("exit", (code, signal) => resolve({ code, signal, stderr, stdout }));
  });
}

const ABORT = 'class AbortError extends Error {}; Promise.reject(new AbortError("Operation aborted"));';
const OTHER = 'Promise.reject(new Error("boom"));';

describe("the late abort rejection guard", () => {
  it("G1: an AbortError rejection is dropped with one fixed line and the process lives on", async () => {
    const result = await runChild(ABORT, true);
    expect(result.code).toBe(0);
    expect(result.signal).toBeNull();
    expect(result.stderr.split("\n").filter((line) => line.includes(GUARD_LINE))).toHaveLength(1);
    expect(result.stderr).not.toContain("Operation aborted");
    expect(result.stderr).not.toContain("    at ");
  });

  it("G2: any other rejection still ends the process, like without the guard", async () => {
    const guarded = await runChild(OTHER, true);
    const control = await runChild(OTHER, false);
    expect(control.code).not.toBe(0);
    expect(guarded.code).toBe(control.code);
    expect(guarded.stderr).toContain("boom");
    expect(guarded.stderr).not.toContain(GUARD_LINE);
  });

  it("G3: control: without the guard an AbortError rejection ends the process", async () => {
    const control = await runChild(ABORT, false);
    expect(control.code).not.toBe(0);
    expect(control.stderr).toContain("Operation aborted");
  });
});
