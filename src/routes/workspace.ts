import { Router } from "express";
import fs from "node:fs";
import type { Request, Response } from "express";
import { log } from "../logging.js";
import { getWorkspaceDir, getUserSkillsDir, safePath, listFiles, readFile, writeFile, deleteFile } from "../workspace.js";

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

/* ------------------------------------------------------------------ */
/*  Per-user skill section  (DEC-GW-003)                                */
/*                                                                      */
/*  User-namespaced skill CRUD that reqlift R-S5 (MVP-6582) consumes.   */
/*  Mirrors the mutable SECTIONS loop above (extractSubPath → safePath  */
/*  → listFiles → { files: [] }) but the base dir is keyed on the       */
/*  `:user_id` route segment, so it cannot live inside that loop (which */
/*  assumes a single flat base dir). The `:user_id` segment is          */
/*  sanitized via getUserSkillsDir (reject `..`, `/`, NUL, absolute,    */
/*  control chars → 400) BEFORE any disk access; the `{*subpath}` is    */
/*  guarded by the same safePath realpath traversal check as the        */
/*  sectioned routes.                                                   */
/* ------------------------------------------------------------------ */

const USER_SKILLS_PREFIX = "/v1/users";

// Express 5 decodes `:user_id`; the trailing wildcard is captured as the
// `subpath` param. Both express's params and a manual re-derivation collapse to
// the same value, so read straight from req.params.
function extractUserSubPath(req: Request): string {
  const raw = req.params.subpath;
  if (Array.isArray(raw)) return raw.join("/");
  return typeof raw === "string" ? raw : "";
}

// In Express 5 a route param is typed `string | string[]`. A user_id is a single
// segment; if it ever arrives as an array (it shouldn't for `:user_id`), treat it
// as invalid by returning a non-string so getUserSkillsDir rejects it.
function userIdParam(req: Request): string | undefined {
  const raw = req.params.user_id;
  return typeof raw === "string" ? raw : undefined;
}

// GET /v1/users/:user_id/skills — reconcile list (mirrors GET /v1/skills shape).
// 200 { files: [{ path, size, modified }, ...] }. Empty namespace → { files: [] }.
router.get(USER_SKILLS_PREFIX + "/:user_id/skills", (req: Request, res: Response) => {
  const baseDir = getUserSkillsDir(userIdParam(req));
  if (!baseDir) { res.status(400).json({ error: "Invalid user_id" }); return; }
  try { res.json({ files: listFiles(baseDir) }); }
  catch (e) { res.status(500).json({ error: e instanceof Error ? e.message : String(e) }); }
});

// PUT /v1/users/:user_id/skills/{*subpath} — body = SKILL.md content.
router.put(USER_SKILLS_PREFIX + "/:user_id/skills/{*subpath}", (req: Request, res: Response) => {
  const baseDir = getUserSkillsDir(userIdParam(req));
  if (!baseDir) { res.status(400).json({ error: "Invalid user_id" }); return; }
  const subPath = extractUserSubPath(req);
  if (!subPath) { res.status(400).json({ error: "Path is required" }); return; }
  const filePath = safePath(baseDir, subPath);
  if (!filePath) { res.status(400).json({ error: "Invalid path" }); return; }
  try {
    const content = typeof req.body === "string" ? req.body : JSON.stringify(req.body);
    writeFile(filePath, content);
    log("workspace", "Written: users/" + (userIdParam(req) ?? "") + "/skills/" + subPath);
    res.json({ status: "ok", path: subPath });
  } catch (e) { res.status(500).json({ error: e instanceof Error ? e.message : String(e) }); }
});

// DELETE /v1/users/:user_id/skills/{*subpath}
router.delete(USER_SKILLS_PREFIX + "/:user_id/skills/{*subpath}", (req: Request, res: Response) => {
  const baseDir = getUserSkillsDir(userIdParam(req));
  if (!baseDir) { res.status(400).json({ error: "Invalid user_id" }); return; }
  const subPath = extractUserSubPath(req);
  if (!subPath) { res.status(400).json({ error: "Path is required" }); return; }
  const filePath = safePath(baseDir, subPath);
  if (!filePath) { res.status(400).json({ error: "Invalid path" }); return; }
  if (!fs.existsSync(filePath)) { res.status(404).json({ error: "File not found" }); return; }
  try {
    deleteFile(filePath);
    log("workspace", "Deleted: users/" + (userIdParam(req) ?? "") + "/skills/" + subPath);
    res.json({ status: "ok" });
  } catch (e) { res.status(500).json({ error: e instanceof Error ? e.message : String(e) }); }
});

export default router;
