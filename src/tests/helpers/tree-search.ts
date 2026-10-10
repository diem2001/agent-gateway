/**
 * Searches of a folder tree for the erasure rows (MVP-7402): which regular files hold a byte string, and a size listing.
 * Links and special files are not followed or read. A live conversation folder changes while it is searched (the Claude
 * runtime creates and removes lock directories and temporary files), so an entry that vanished between the directory
 * read and the descent or the content read holds nothing and is skipped; every other error is raised.
 */
import fs from "node:fs";
import path from "node:path";

/** Runs `step`; true when it ran, false when the path it concerned was gone. */
function unlessGone(step: () => void): boolean {
  try {
    step();
    return true;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw e;
  }
}

/** Calls `visit` for every regular file below `dir`; a directory or file that vanished is skipped. */
function eachFile(dir: string, visit: (file: string) => void): void {
  const walk = (d: string): void => {
    let entries: fs.Dirent[] = [];
    if (!unlessGone(() => { entries = fs.readdirSync(d, { withFileTypes: true }); })) return;
    for (const entry of entries) {
      const full = path.join(d, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile()) unlessGone(() => visit(full));
    }
  };
  walk(dir);
}

/** Regular files below `dir` that contain `needle`. */
export function filesWith(dir: string, needle: string): string[] {
  const hits: string[] = [];
  eachFile(dir, (file) => {
    if (fs.readFileSync(file, "latin1").includes(needle)) hits.push(file);
  });
  return hits;
}

/** Regular files below `dir` with their sizes, for an assertion message. */
export function listing(dir: string): string {
  const out: string[] = [];
  eachFile(dir, (file) => {
    out.push(`${path.relative(dir, file)} ${fs.statSync(file).size}`);
  });
  return out.join("; ");
}
