#!/usr/bin/env node
/**
 * Rollout inventory for MVP-7957: lists the MCP registry entries whose stored URL breaks the public-URL rule
 * (http(s) without user info, query or fragment) and would be withheld by the gateway until it is migrated.
 *
 *   node scripts/registry-url-inventory.mjs <path to mcp-servers.json>
 *
 * Prints one `name<TAB>category` line per entry (category: user_info, query, fragment or invalid) and a count line,
 * never a URL or any part of one. Exit 0: nothing needs migrating; 3: at least one entry does; 2: the file could
 * not be read or is not a registry file (fixed message, no file content). Read-only: the file is never written.
 * Uses the compiled predicate of the gateway (`npm run build` first), so the list is exactly what the gateway withholds.
 */
import fs from "node:fs";
import { publicUrlProblem } from "../dist/mcp-registry.js";

const file = process.argv[2];
if (!file) {
  console.error("usage: registry-url-inventory.mjs <path to mcp-servers.json>");
  process.exit(2);
}

let entries;
try {
  entries = JSON.parse(fs.readFileSync(file, "utf-8"));
} catch {
  console.error("the registry file could not be read or is not valid JSON");
  process.exit(2);
}
if (!Array.isArray(entries) || entries.some((entry) => entry === null || typeof entry !== "object" || typeof entry.name !== "string")) {
  console.error("the registry file does not hold a list of named entries");
  process.exit(2);
}

let needed = 0;
for (const entry of entries) {
  if (entry.url === undefined) continue;
  const problem = publicUrlProblem(entry.url);
  if (problem) {
    needed += 1;
    console.log(`${entry.name}\t${problem}`);
  }
}
console.log(`${needed} of ${entries.length} entries need a URL migration`);
process.exit(needed > 0 ? 3 : 0);
