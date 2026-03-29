import { Router } from "express";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { execSync } from "node:child_process";
import type { Request, Response } from "express";
import { log } from "../logging.js";

const router = Router();
const HOME = process.env.HOME || "/home/node";
const WORKSPACE_ROOT =
  process.env.WORKSPACE_ROOT || path.join(HOME, ".claude");
const PROJECTS_DIR = path.join(WORKSPACE_ROOT, "projects");

/**
 * Resolve and validate a project path. Must stay inside PROJECTS_DIR.
 */
function resolveProjectPath(userPath: string): string | null {
  if (!userPath || path.isAbsolute(userPath) || userPath.includes("\0")) {
    return null;
  }
  const resolved = path.resolve(PROJECTS_DIR, userPath);
  const normalizedBase = path.resolve(PROJECTS_DIR) + path.sep;
  if (!resolved.startsWith(normalizedBase) && resolved !== path.resolve(PROJECTS_DIR)) {
    return null;
  }
  return resolved;
}

/**
 * Write an SSH key to a temp file, return its path.
 * The caller MUST delete it after use.
 */
function writeTempSshKey(sshKey: string): string {
  const tmpDir = os.tmpdir();
  const keyPath = path.join(tmpDir, `agw-ssh-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`);
  fs.writeFileSync(keyPath, sshKey.trim() + "\n", { mode: 0o600 });
  return keyPath;
}

/**
 * Build env object with GIT_SSH_COMMAND pointing to a temp key file.
 */
function gitEnvWithSshKey(keyPath: string): Record<string, string> {
  return {
    ...process.env as Record<string, string>,
    GIT_SSH_COMMAND: `ssh -i ${keyPath} -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes`,
  };
}

/**
 * Safely remove a temp SSH key file.
 */
function removeTempKey(keyPath: string): void {
  try {
    fs.unlinkSync(keyPath);
  } catch {
    log("git", "Warning: failed to remove temp SSH key: " + keyPath);
  }
}

/**
 * Run a git command and return stdout.
 */
function git(args: string, cwd: string, env?: Record<string, string>): string {
  return execSync(`git ${args}`, {
    cwd,
    env: env || (process.env as Record<string, string>),
    timeout: 120_000,
    maxBuffer: 10 * 1024 * 1024,
  })
    .toString()
    .trim();
}

/**
 * Get current branch, commit, dirty status for a repo.
 */
function repoInfo(repoPath: string): {
  branch: string;
  commit: string;
  dirty: boolean;
  lastCommitDate: string;
} {
  const branch = git("rev-parse --abbrev-ref HEAD", repoPath);
  const commit = git("rev-parse --short HEAD", repoPath);
  const dirty = git("status --porcelain", repoPath).length > 0;
  const lastCommitDate = git("log -1 --format=%aI", repoPath);
  return { branch, commit, dirty, lastCommitDate };
}

/* ------------------------------------------------------------------ */
/*  POST /v1/workspace/git/clone                                       */
/* ------------------------------------------------------------------ */

router.post("/v1/workspace/git/clone", (req: Request, res: Response) => {
  const { url, path: userPath, branch, sshKey } = req.body as {
    url?: string;
    path?: string;
    branch?: string;
    sshKey?: string;
  };

  if (!url) {
    res.status(400).json({ error: "url is required" });
    return;
  }
  if (!userPath) {
    res.status(400).json({ error: "path is required" });
    return;
  }

  const targetPath = resolveProjectPath(userPath);
  if (!targetPath) {
    res.status(400).json({ error: "Invalid path (must be relative, no traversal)" });
    return;
  }

  let tempKeyPath: string | null = null;

  try {
    let env: Record<string, string> | undefined;
    if (sshKey) {
      tempKeyPath = writeTempSshKey(sshKey);
      env = gitEnvWithSshKey(tempKeyPath);
    }

    // If directory already exists with a .git folder, do pull instead
    if (fs.existsSync(path.join(targetPath, ".git"))) {
      log("git", "Clone target exists, pulling instead: " + userPath);
      git("pull", targetPath, env);
      const info = repoInfo(targetPath);
      log("git", `Pulled ${userPath}: ${info.branch}@${info.commit}`);
      res.json({ status: "pulled", path: userPath, branch: info.branch, commit: info.commit });
      return;
    }

    // Ensure parent directory exists
    fs.mkdirSync(path.dirname(targetPath), { recursive: true });

    // Clone
    const branchArg = branch ? ` -b ${branch}` : "";
    git(`clone${branchArg} ${url} ${targetPath}`, WORKSPACE_ROOT, env);

    const info = repoInfo(targetPath);
    log("git", `Cloned ${url} -> ${userPath}: ${info.branch}@${info.commit}`);
    res.json({ status: "cloned", path: userPath, branch: info.branch, commit: info.commit });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    log("git", "Clone failed: " + msg);
    res.status(500).json({ error: msg });
  } finally {
    if (tempKeyPath) removeTempKey(tempKeyPath);
  }
});

/* ------------------------------------------------------------------ */
/*  POST /v1/workspace/git/pull                                        */
/* ------------------------------------------------------------------ */

router.post("/v1/workspace/git/pull", (req: Request, res: Response) => {
  const { path: userPath, sshKey } = req.body as {
    path?: string;
    sshKey?: string;
  };

  if (!userPath) {
    res.status(400).json({ error: "path is required" });
    return;
  }

  const targetPath = resolveProjectPath(userPath);
  if (!targetPath) {
    res.status(400).json({ error: "Invalid path (must be relative, no traversal)" });
    return;
  }

  if (!fs.existsSync(path.join(targetPath, ".git"))) {
    res.status(404).json({ error: "Not a git repository: " + userPath });
    return;
  }

  let tempKeyPath: string | null = null;

  try {
    let env: Record<string, string> | undefined;
    if (sshKey) {
      tempKeyPath = writeTempSshKey(sshKey);
      env = gitEnvWithSshKey(tempKeyPath);
    }

    const beforeCommit = git("rev-parse HEAD", targetPath);
    git("pull", targetPath, env);
    const afterCommit = git("rev-parse HEAD", targetPath);

    const info = repoInfo(targetPath);
    const status = beforeCommit === afterCommit ? "up-to-date" : "updated";

    log("git", `Pull ${userPath}: ${status} (${info.branch}@${info.commit})`);
    res.json({ status, branch: info.branch, commit: info.commit });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    log("git", "Pull failed: " + msg);
    res.status(500).json({ error: msg });
  } finally {
    if (tempKeyPath) removeTempKey(tempKeyPath);
  }
});

/* ------------------------------------------------------------------ */
/*  GET /v1/workspace/git/status                                       */
/* ------------------------------------------------------------------ */

router.get("/v1/workspace/git/status", (req: Request, res: Response) => {
  const userPath = req.query.path as string | undefined;

  if (!userPath) {
    res.status(400).json({ error: "path query parameter is required" });
    return;
  }

  const targetPath = resolveProjectPath(userPath);
  if (!targetPath) {
    res.status(400).json({ error: "Invalid path (must be relative, no traversal)" });
    return;
  }

  if (!fs.existsSync(path.join(targetPath, ".git"))) {
    res.json({ exists: false });
    return;
  }

  try {
    const info = repoInfo(targetPath);
    res.json({
      exists: true,
      branch: info.branch,
      commit: info.commit,
      dirty: info.dirty,
      lastCommitDate: info.lastCommitDate,
    });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    log("git", "Status failed: " + msg);
    res.status(500).json({ error: msg });
  }
});

export default router;
