/**
 * Searches of a folder tree for the erasure rows (MVP-7402): which regular files hold a byte string, and a size listing.
 * Links and special files are not followed or read.
 */
import fs from "node:fs";
import path from "node:path";

/** Regular files below `dir` that contain `needle`. */
export function filesWith(dir: string, needle: string): string[] {
  const hits: string[] = [];
  const walk = (d: string): void => {
    for (const entry of fs.readdirSync(d, { withFileTypes: true })) {
      const full = path.join(d, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile() && fs.readFileSync(full, "latin1").includes(needle)) hits.push(full);
    }
  };
  walk(dir);
  return hits;
}

/** Regular files below `dir` with their sizes, for an assertion message. */
export function listing(dir: string): string {
  const out: string[] = [];
  const walk = (d: string): void => {
    for (const entry of fs.readdirSync(d, { withFileTypes: true })) {
      const full = path.join(d, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile()) out.push(`${path.relative(dir, full)} ${fs.statSync(full).size}`);
    }
  };
  walk(dir);
  return out.join("; ");
}
