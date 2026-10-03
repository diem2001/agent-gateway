/**
 * The rollout inventory (MVP-7957, scripts/registry-url-inventory.mjs) lists only names and categories of entries whose
 * stored URL the gateway would withhold, never a URL, and never writes the file. Runs the real script against fixture
 * files holding synthetic markers (needs `npm run build`: the script uses the compiled predicate).
 */
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const SCRIPT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../scripts/registry-url-inventory.mjs");
const MARKER = "INV-MARKER-7957-ffff6666";

let dir = "";
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-gateway-inventory-"));
});
afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

function run(content: string | null, args: string[] = []) {
  const file = path.join(dir, "mcp-servers.json");
  if (content !== null) fs.writeFileSync(file, content);
  const result = spawnSync(process.execPath, [SCRIPT, ...(args.length ? args : [file])], { encoding: "utf-8" });
  return { file, status: result.status, out: result.stdout, err: result.stderr };
}

const entry = (name: string, extra: Record<string, unknown>) => ({ name, type: "http", enabled: true, description: "", createdAt: "t", updatedAt: "t", ...extra });

describe("registry-url-inventory", () => {
  it("lists name and category for every non-compliant URL of any entry type, exits 3, and prints no value", () => {
    const content = JSON.stringify([
      entry("fine", { url: "https://ok.example/mcp/path" }),
      entry("with-user", { url: `https://${MARKER}:pw@h.example/` }),
      entry("with-query", { type: "sse", url: `https://h.example/?t=${MARKER}` }),
      entry("with-fragment", { url: `https://h.example/#${MARKER}` }),
      entry("broken", { url: `not a url ${MARKER}` }),
      entry("nulled", { url: null }),
      entry("stdio-with-url", { type: "stdio", command: "node", url: `https://${MARKER}@h.example/` }),
      entry("local", { type: "stdio", command: "node" }),
    ]);
    const result = run(content);
    expect(result.status).toBe(3);
    expect(result.out.trim().split("\n")).toEqual([
      "with-user\tuser_info",
      "with-query\tquery",
      "with-fragment\tfragment",
      "broken\tinvalid",
      "nulled\tinvalid",
      "stdio-with-url\tuser_info",
      "6 of 8 entries need a URL migration",
    ]);
    expect(result.out + result.err).not.toContain(MARKER);
    expect(fs.readFileSync(result.file, "utf-8")).toBe(content);
  });

  it("exits 0 with only the count line when every URL is compliant", () => {
    const result = run(JSON.stringify([entry("fine", { url: "https://ok.example/mcp" }), entry("local", { type: "stdio", command: "node" })]));
    expect(result.status).toBe(0);
    expect(result.out.trim()).toBe("0 of 2 entries need a URL migration");
  });

  it("answers a fixed message for invalid JSON without quoting the file", () => {
    const result = run(`[{"name":"x","url":"https://${MARKER}@h.example/"`);
    expect(result.status).toBe(2);
    expect(result.err.trim()).toBe("the registry file could not be read or is not valid JSON");
    expect(result.out + result.err).not.toContain(MARKER);
  });

  it("answers fixed messages for a missing file, a wrong shape and a missing argument", () => {
    expect(run(null, [path.join(dir, "absent.json")]).err.trim()).toBe("the registry file could not be read or is not valid JSON");
    const shape = run(JSON.stringify({ name: "x", url: `https://${MARKER}@h.example/` }));
    expect(shape.status).toBe(2);
    expect(shape.err.trim()).toBe("the registry file does not hold a list of named entries");
    expect(shape.out + shape.err).not.toContain(MARKER);
    const none = spawnSync(process.execPath, [SCRIPT], { encoding: "utf-8" });
    expect(none.status).toBe(2);
  });
});
