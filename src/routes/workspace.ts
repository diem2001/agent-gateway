import { Router } from "express";
import fs from "node:fs";
import type { Request, Response } from "express";
import { log } from "../logging.js";
import { getWorkspaceDir, safePath, listFiles, readFile, writeFile, deleteFile } from "../workspace.js";

const router = Router();
type WorkspaceSection = "memory" | "agents" | "skills";
const SECTIONS: WorkspaceSection[] = ["memory", "agents", "skills"];

function extractSubPath(req: Request, prefix: string): string {
  const fullPath = req.path;
  const prefixPath = "/v1/" + prefix;
  if (fullPath === prefixPath || fullPath === prefixPath + "/") return "";
  return fullPath.substring(prefixPath.length + 1);
}

for (const section of SECTIONS) {
  const baseDir = getWorkspaceDir(section);

  router.get("/v1/" + section, (_req: Request, res: Response) => {
    try { res.json({ files: listFiles(baseDir) }); }
    catch (e) { res.status(500).json({ error: e instanceof Error ? e.message : String(e) }); }
  });

  router.get("/v1/" + section + "/{*subpath}", (req: Request, res: Response) => {
    const subPath = extractSubPath(req, section);
    if (!subPath) { res.json({ files: listFiles(baseDir) }); return; }
    const filePath = safePath(baseDir, subPath);
    if (!filePath) { res.status(400).json({ error: "Invalid path" }); return; }
    if (!fs.existsSync(filePath)) { res.status(404).json({ error: "File not found" }); return; }
    try { const content = readFile(filePath); subPath.endsWith(".json") ? res.type("application/json").send(content) : res.type("text/plain").send(content); }
    catch (e) { res.status(500).json({ error: e instanceof Error ? e.message : String(e) }); }
  });

  router.put("/v1/" + section + "/{*subpath}", (req: Request, res: Response) => {
    const subPath = extractSubPath(req, section);
    if (!subPath) { res.status(400).json({ error: "Path is required" }); return; }
    const filePath = safePath(baseDir, subPath);
    if (!filePath) { res.status(400).json({ error: "Invalid path" }); return; }
    try { const content = typeof req.body === "string" ? req.body : JSON.stringify(req.body); writeFile(filePath, content); log("workspace", "Written: " + section + "/" + subPath); res.json({ status: "ok", path: section + "/" + subPath }); }
    catch (e) { res.status(500).json({ error: e instanceof Error ? e.message : String(e) }); }
  });

  router.delete("/v1/" + section + "/{*subpath}", (req: Request, res: Response) => {
    const subPath = extractSubPath(req, section);
    if (!subPath) { res.status(400).json({ error: "Path is required" }); return; }
    const filePath = safePath(baseDir, subPath);
    if (!filePath) { res.status(400).json({ error: "Invalid path" }); return; }
    if (!fs.existsSync(filePath)) { res.status(404).json({ error: "File not found" }); return; }
    try { deleteFile(filePath); log("workspace", "Deleted: " + section + "/" + subPath); res.json({ status: "ok" }); }
    catch (e) { res.status(500).json({ error: e instanceof Error ? e.message : String(e) }); }
  });
}

/* ------------------------------------------------------------------ */
/*  Read-only knowledge-base section                                    */
/*                                                                      */
/*  Registered SEPARATELY from the mutable SECTIONS loop above — that   */
/*  loop also wires PUT/DELETE, which would violate the read-only       */
/*  contract. Do NOT add "knowledge-base" to SECTIONS. KB content is    */
/*  served as text/markdown; the read route's 500 branch returns a      */
/*  fixed envelope (matching the global handler in server.ts) so a      */
/*  filesystem error cannot leak a path.                                */
/* ------------------------------------------------------------------ */

const KB_SECTION = "knowledge-base";
const kbBaseDir = getWorkspaceDir("projects/knowledge-base");

// GET /v1/knowledge-base — recursive list; { files: [] } when the KB dir is absent (never 500).
router.get("/v1/" + KB_SECTION, (_req: Request, res: Response) => {
  try { res.json({ files: listFiles(kbBaseDir) }); }
  catch { res.status(500).json({ error: "Internal server error" }); }
});

// GET /v1/knowledge-base/{*path} — read one doc as text/markdown.
router.get("/v1/" + KB_SECTION + "/{*subpath}", (req: Request, res: Response) => {
  const subPath = extractSubPath(req, KB_SECTION);
  if (!subPath) { res.json({ files: listFiles(kbBaseDir) }); return; }
  const filePath = safePath(kbBaseDir, subPath);
  if (!filePath) { res.status(400).json({ error: "Invalid path" }); return; }
  // isFile() guard rejects both missing paths and directories with 404,
  // avoiding an EISDIR 500 when a directory path is requested.
  let stat: fs.Stats;
  try { stat = fs.statSync(filePath); }
  catch { res.status(404).json({ error: "File not found" }); return; }
  if (!stat.isFile()) { res.status(404).json({ error: "File not found" }); return; }
  try { res.type("text/markdown; charset=utf-8").send(readFile(filePath)); }
  catch { res.status(500).json({ error: "Internal server error" }); }
});

export default router;
