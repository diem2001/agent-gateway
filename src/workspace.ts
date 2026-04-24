import fs from "node:fs";
import path from "node:path";
import { log } from "./logging.js";

const HOME = process.env.HOME || "/home/node";
const WORKSPACE_ROOT = process.env.WORKSPACE_ROOT || path.join(HOME, ".claude");

export function getWorkspaceRoot(): string { return WORKSPACE_ROOT; }
export function getWorkspaceDir(subdir: string): string { return path.join(WORKSPACE_ROOT, subdir); }

export function safePath(baseDir: string, userPath: string): string | null {
  if (!userPath) return null;
  if (path.isAbsolute(userPath)) return null;
  if (userPath.includes("\0")) return null;
  const candidate = path.resolve(baseDir, userPath);
  const normalizedBase = path.resolve(baseDir) + path.sep;
  if (!candidate.startsWith(normalizedBase) && candidate !== path.resolve(baseDir)) return null;
  if (fs.existsSync(candidate)) {
    const real = fs.realpathSync(candidate);
    const realBase = fs.realpathSync(baseDir);
    const realBasePrefix = realBase + path.sep;
    if (!real.startsWith(realBasePrefix) && real !== realBase) return null;
    return real;
  }
  const parentDir = path.dirname(candidate);
  if (fs.existsSync(parentDir)) {
    const realParent = fs.realpathSync(parentDir);
    const realBase = fs.existsSync(baseDir) ? fs.realpathSync(baseDir) : path.resolve(baseDir);
    const realBasePrefix = realBase + path.sep;
    if (!realParent.startsWith(realBasePrefix) && realParent !== realBase) return null;
  }
  return candidate;
}

export interface FileEntry { path: string; size: number; modified: string; }

export function listFiles(baseDir: string): FileEntry[] {
  const files: FileEntry[] = [];
  const walk = (dir: string, prefix = ""): void => {
    if (!fs.existsSync(dir)) return;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) { walk(fullPath, rel); }
      else { const stat = fs.statSync(fullPath); files.push({ path: rel, size: stat.size, modified: stat.mtime.toISOString() }); }
    }
  };
  walk(baseDir);
  return files;
}

export function readFile(filePath: string): string { return fs.readFileSync(filePath, "utf-8"); }
export function writeFile(filePath: string, content: string): void {
  const dir = path.dirname(filePath);
  // If a parent path segment exists as a file (e.g. old flat-file skill),
  // remove it so mkdirSync can create the directory structure
  let check = dir;
  while (check !== path.dirname(check)) {
    if (fs.existsSync(check) && !fs.statSync(check).isDirectory()) {
      fs.unlinkSync(check);
      break;
    }
    check = path.dirname(check);
  }
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(filePath, content);
}
export function deleteFile(filePath: string): void { fs.unlinkSync(filePath); }
export function ensureDir(dirPath: string): void { fs.mkdirSync(dirPath, { recursive: true }); log("workspace", "Ensured directory: " + dirPath); }
