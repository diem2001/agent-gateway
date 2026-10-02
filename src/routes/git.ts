import { Router } from "express";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import type { Request, Response } from "express";
import { log, redactUrlValue } from "../logging.js";
import { gitErrorText, runGit, withGitSlot, withRepoTurn } from "../git-exec.js";

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
 * A branch starting with "-" would be read as an option by `git checkout`,
 * where "--" cannot help (it switches checkout to paths). Git itself does not
 * allow such branch names.
 */
function isInvalidBranch(branch: unknown): boolean {
  return typeof branch === "string" && branch.startsWith("-");
}

/**
 * A line break would split the URL across lines of git's error text, where the
 * line-based credential redaction cannot follow it, and a NUL cannot be passed
 * to a process at all; git refuses such URLs anyway.
 */
function isInvalidUrl(url: string): boolean {
  return /[\r\n\0]/.test(url);
}

/**
 * The first of `fields` that is present but not a string, as a 400 message.
 * An array or object would reach git or the key file unchecked.
 */
function nonStringField(body: Record<string, unknown>, fields: string[]): string | null {
  for (const field of fields) {
    const value = body[field];
    if (value !== undefined && value !== null && typeof value !== "string") return `${field} must be a string`;
  }
  return null;
}

/**
 * Write an SSH key into a private temp directory (0700, exclusive create) and
 * return the directory and key path. The caller MUST remove the directory.
 */
async function writeTempSshKey(sshKey: string): Promise<{ dir: string; keyPath: string }> {
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "agw-ssh-"));
  const keyPath = path.join(dir, "key");
  try {
    await fs.promises.writeFile(keyPath, sshKey.trim() + "\n", { flag: "wx", mode: 0o600 });
  } catch (e) {
    await removeTempKeyDir(dir);
    throw e;
  }
  return { dir, keyPath };
}

/**
 * Build env object with GIT_SSH_COMMAND pointing to a temp key file. The
 * command is run by a shell, so the path is single-quoted.
 */
function gitEnvWithSshKey(keyPath: string): NodeJS.ProcessEnv {
  const quoted = `'${keyPath.replace(/'/g, `'\\''`)}'`;
  return {
    ...process.env,
    GIT_SSH_COMMAND: `ssh -i ${quoted} -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes`,
  };
}

/**
 * Safely remove a temp SSH key directory.
 */
async function removeTempKeyDir(dir: string): Promise<void> {
  try {
    await fs.promises.rm(dir, { recursive: true, force: true });
  } catch {
    log("git", "Warning: failed to remove temp SSH key directory: " + dir);
  }
}

/**
 * Run `fn` with a git environment for the SSH key, if one was given. The key
 * file exists only while `fn` runs, i.e. after the operation got its slot.
 */
async function withSshKey<T>(sshKey: string | undefined, fn: (env?: NodeJS.ProcessEnv) => Promise<T>): Promise<T> {
  if (!sshKey) return fn(undefined);
  const key = await writeTempSshKey(sshKey);
  try {
    return await fn(gitEnvWithSshKey(key.keyPath));
  } finally {
    await removeTempKeyDir(key.dir);
  }
}

/**
 * Run a git command (argument array, no shell) and return stdout.
 */
function git(args: string[], cwd: string, env?: NodeJS.ProcessEnv): Promise<string> {
  return runGit(args, cwd, env);
}

/**
 * Ensure the local repo is on `branch` and that branch tracks `origin/branch`.
 * Idempotent. Required before running `git pull` on an existing checkout —
 * otherwise pull fails with "There is no tracking information for the current
 * branch" when the working copy was put on a branch that wasn't created with
 * `-u origin/...`.
 */
async function ensureBranchAndUpstream(
  repoPath: string,
  branch: string,
  env?: NodeJS.ProcessEnv,
): Promise<void> {
  // Make sure we have the latest ref for this branch from origin. The explicit
  // refspec keeps a branch value from acting as a refspec of its own
  // (`a:refs/heads/x` would otherwise write a local ref).
  await git(["fetch", "origin", "--", `+refs/heads/${branch}:refs/remotes/origin/${branch}`], repoPath, env);

  // Switch (or create) the local branch tracking origin/<branch>.
  const currentBranch = await git(["rev-parse", "--abbrev-ref", "HEAD"], repoPath, env);
  if (currentBranch !== branch) {
    let localExists = true;
    try {
      await git(["rev-parse", "--verify", "--quiet", `refs/heads/${branch}`], repoPath, env);
    } catch {
      localExists = false;
    }
    if (localExists) {
      await git(["checkout", branch], repoPath, env);
    } else {
      await git(["checkout", "-b", branch, `origin/${branch}`], repoPath, env);
    }
  }

  // Set/repair upstream — safe to run even when already correct.
  await git(["branch", `--set-upstream-to=origin/${branch}`, branch], repoPath, env);
}

/**
 * Get current branch, commit, dirty status for a repo.
 */
async function repoInfo(repoPath: string): Promise<{
  branch: string;
  commit: string;
  dirty: boolean;
  lastCommitDate: string;
}> {
  const branch = await git(["rev-parse", "--abbrev-ref", "HEAD"], repoPath);
  const commit = await git(["rev-parse", "--short", "HEAD"], repoPath);
  const dirty = (await git(["status", "--porcelain"], repoPath)).length > 0;
  const lastCommitDate = await git(["log", "-1", "--format=%aI"], repoPath);
  return { branch, commit, dirty, lastCommitDate };
}

/*
 * Every operation runs inside its repository's turn (same resolved path: one
 * at a time, in arrival order) and then inside a global slot
 * (GIT_MAX_CONCURRENCY). Existence checks run inside the turn, so a queued
 * request sees the result of the operation before it.
 */

/* ------------------------------------------------------------------ */
/*  POST /v1/workspace/git/clone                                       */
/* ------------------------------------------------------------------ */

router.post("/v1/workspace/git/clone", async (req: Request, res: Response) => {
  const { url, path: userPath, branch, sshKey } = req.body as {
    url?: string;
    path?: string;
    branch?: string;
    sshKey?: string;
  };

  const typeError = nonStringField(req.body, ["url", "path", "branch", "sshKey"]);
  if (typeError) {
    res.status(400).json({ error: typeError });
    return;
  }

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
  if (isInvalidBranch(branch)) {
    res.status(400).json({ error: "Invalid branch" });
    return;
  }
  if (isInvalidUrl(url)) {
    res.status(400).json({ error: "Invalid url" });
    return;
  }

  try {
    const result = await withRepoTurn(targetPath, () =>
      withGitSlot(() =>
        withSshKey(sshKey, async (env) => {
          // If directory already exists with a .git folder, do pull instead.
          // The caller may have changed the desired branch (or the local branch
          // may lack upstream tracking) so we have to align the checkout with
          // `branch` before pulling.
          if (fs.existsSync(path.join(targetPath, ".git"))) {
            log("git", "Clone target exists, pulling instead: " + userPath);
            if (branch) {
              await ensureBranchAndUpstream(targetPath, branch, env);
            }
            await git(["pull"], targetPath, env);
            const info = await repoInfo(targetPath);
            log("git", `Pulled ${userPath}: ${info.branch}@${info.commit}`);
            return { status: "pulled", path: userPath, branch: info.branch, commit: info.commit };
          }

          // Ensure parent directory exists
          await fs.promises.mkdir(path.dirname(targetPath), { recursive: true });

          // Clone. "--" keeps a URL such as "--upload-pack=…" from being read as an option.
          const branchArgs = branch ? ["-b", branch] : [];
          await git(["clone", ...branchArgs, "--", url, targetPath], WORKSPACE_ROOT, env);

          const info = await repoInfo(targetPath);
          log("git", `Cloned ${redactUrlValue(url)} -> ${userPath}: ${info.branch}@${info.commit}`);
          return { status: "cloned", path: userPath, branch: info.branch, commit: info.commit };
        }),
      ),
    );
    res.json(result);
  } catch (e) {
    const msg = gitErrorText(e);
    log("git", "Clone failed: " + msg);
    res.status(500).json({ error: msg });
  }
});

/* ------------------------------------------------------------------ */
/*  POST /v1/workspace/git/pull                                        */
/* ------------------------------------------------------------------ */

router.post("/v1/workspace/git/pull", async (req: Request, res: Response) => {
  const { path: userPath, branch, sshKey } = req.body as {
    path?: string;
    branch?: string;
    sshKey?: string;
  };

  const typeError = nonStringField(req.body, ["path", "branch", "sshKey"]);
  if (typeError) {
    res.status(400).json({ error: typeError });
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
  if (isInvalidBranch(branch)) {
    res.status(400).json({ error: "Invalid branch" });
    return;
  }

  try {
    const result = await withRepoTurn(targetPath, async () => {
      if (!fs.existsSync(path.join(targetPath, ".git"))) return null;
      return withGitSlot(() =>
        withSshKey(sshKey, async (env) => {
          if (branch) {
            await ensureBranchAndUpstream(targetPath, branch, env);
          }

          const beforeCommit = await git(["rev-parse", "HEAD"], targetPath);
          await git(["pull"], targetPath, env);
          const afterCommit = await git(["rev-parse", "HEAD"], targetPath);

          const info = await repoInfo(targetPath);
          const status = beforeCommit === afterCommit ? "up-to-date" : "updated";

          log("git", `Pull ${userPath}: ${status} (${info.branch}@${info.commit})`);
          return { status, branch: info.branch, commit: info.commit };
        }),
      );
    });
    if (!result) {
      res.status(404).json({ error: "Not a git repository: " + userPath });
      return;
    }
    res.json(result);
  } catch (e) {
    const msg = gitErrorText(e);
    log("git", "Pull failed: " + msg);
    res.status(500).json({ error: msg });
  }
});

/* ------------------------------------------------------------------ */
/*  GET /v1/workspace/git/status                                       */
/* ------------------------------------------------------------------ */

router.get("/v1/workspace/git/status", async (req: Request, res: Response) => {
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

  try {
    const info = await withRepoTurn(targetPath, async () => {
      if (!fs.existsSync(path.join(targetPath, ".git"))) return null;
      return withGitSlot(() => repoInfo(targetPath));
    });
    if (!info) {
      res.json({ exists: false });
      return;
    }
    res.json({
      exists: true,
      branch: info.branch,
      commit: info.commit,
      dirty: info.dirty,
      lastCommitDate: info.lastCommitDate,
    });
  } catch (e) {
    const msg = gitErrorText(e);
    log("git", "Status failed: " + msg);
    res.status(500).json({ error: msg });
  }
});

export default router;
