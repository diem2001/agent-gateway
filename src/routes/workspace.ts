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

  router.get("/v1/" + section + "/*", (req: Request, res: Response) => {
    const subPath = extractSubPath(req, section);
    if (!subPath) { res.json({ files: listFiles(baseDir) }); return; }
    const filePath = safePath(baseDir, subPath);
    if (!filePath) { res.status(400).json({ error: "Invalid path" }); return; }
    if (!fs.existsSync(filePath)) { res.status(404).json({ error: "File not found" }); return; }
    try { const content = readFile(filePath); subPath.endsWith(".json") ? res.type("application/json").send(content) : res.type("text/plain").send(content); }
    catch (e) { res.status(500).json({ error: e instanceof Error ? e.message : String(e) }); }
  });

  router.put("/v1/" + section + "/*", (req: Request, res: Response) => {
    const subPath = extractSubPath(req, section);
    if (!subPath) { res.status(400).json({ error: "Path is required" }); return; }
    const filePath = safePath(baseDir, subPath);
    if (!filePath) { res.status(400).json({ error: "Invalid path" }); return; }
    try { const content = typeof req.body === "string" ? req.body : JSON.stringify(req.body); writeFile(filePath, content); log("workspace", "Written: " + section + "/" + subPath); res.json({ status: "ok", path: section + "/" + subPath }); }
    catch (e) { res.status(500).json({ error: e instanceof Error ? e.message : String(e) }); }
  });

  router.delete("/v1/" + section + "/*", (req: Request, res: Response) => {
    const subPath = extractSubPath(req, section);
    if (!subPath) { res.status(400).json({ error: "Path is required" }); return; }
    const filePath = safePath(baseDir, subPath);
    if (!filePath) { res.status(400).json({ error: "Invalid path" }); return; }
    if (!fs.existsSync(filePath)) { res.status(404).json({ error: "File not found" }); return; }
    try { deleteFile(filePath); log("workspace", "Deleted: " + section + "/" + subPath); res.json({ status: "ok" }); }
    catch (e) { res.status(500).json({ error: e instanceof Error ? e.message : String(e) }); }
  });
}

export default router;
