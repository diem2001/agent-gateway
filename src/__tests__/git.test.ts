import { describe, it, before, after, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { execSync } from "node:child_process";
import express from "express";
import type { Server } from "node:http";

// Set WORKSPACE_ROOT before importing routes
const TEST_WORKSPACE = fs.mkdtempSync(path.join(os.tmpdir(), "agw-test-"));
process.env.WORKSPACE_ROOT = TEST_WORKSPACE;

const { default: gitRoutes } = await import("../routes/git.js");

const PROJECTS_DIR = path.join(TEST_WORKSPACE, "projects");

function createTestRepo(name: string): string {
  const repoPath = path.join(PROJECTS_DIR, name);
  fs.mkdirSync(repoPath, { recursive: true });
  execSync("git init", { cwd: repoPath });
  execSync("git config user.email 'test@test.com'", { cwd: repoPath });
  execSync("git config user.name 'Test'", { cwd: repoPath });
  fs.writeFileSync(path.join(repoPath, "README.md"), "# Test\n");
  execSync("git add . && git commit -m 'init'", { cwd: repoPath });
  return repoPath;
}

function createBareRemote(name: string): string {
  const barePath = path.join(TEST_WORKSPACE, "remotes", name + ".git");
  fs.mkdirSync(barePath, { recursive: true });
  execSync("git init --bare", { cwd: barePath });
  return barePath;
}

async function request(
  app: express.Express,
  method: "GET" | "POST",
  urlPath: string,
  body?: Record<string, unknown>,
): Promise<{ status: number; body: Record<string, unknown> }> {
  return new Promise((resolve) => {
    const server = app.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (!addr || typeof addr === "string") throw new Error("No address");
      const port = addr.port;
      const url = `http://127.0.0.1:${port}${urlPath}`;
      const options: RequestInit = {
        method,
        headers: { "Content-Type": "application/json" },
      };
      if (body) options.body = JSON.stringify(body);
      fetch(url, options)
        .then((res) =>
          res.json().then((json) => {
            server.close();
            resolve({ status: res.status, body: json as Record<string, unknown> });
          }),
        )
        .catch((err) => {
          server.close();
          throw err;
        });
    });
  });
}

describe("Git Routes", () => {
  let app: express.Express;

  before(() => {
    app = express();
    app.use(express.json());
    app.use(gitRoutes);
  });

  after(() => {
    fs.rmSync(TEST_WORKSPACE, { recursive: true, force: true });
  });

  describe("POST /v1/workspace/git/clone", () => {
    it("should require url", async () => {
      const res = await request(app, "POST", "/v1/workspace/git/clone", {
        path: "test-repo",
      });
      assert.equal(res.status, 400);
      assert.equal(res.body.error, "url is required");
    });

    it("should require path", async () => {
      const res = await request(app, "POST", "/v1/workspace/git/clone", {
        url: "https://example.com/repo.git",
      });
      assert.equal(res.status, 400);
      assert.equal(res.body.error, "path is required");
    });

    it("should reject absolute paths", async () => {
      const res = await request(app, "POST", "/v1/workspace/git/clone", {
        url: "https://example.com/repo.git",
        path: "/etc/passwd",
      });
      assert.equal(res.status, 400);
      assert.match(res.body.error as string, /Invalid path/);
    });

    it("should reject path traversal", async () => {
      const res = await request(app, "POST", "/v1/workspace/git/clone", {
        url: "https://example.com/repo.git",
        path: "../../../etc/passwd",
      });
      assert.equal(res.status, 400);
      assert.match(res.body.error as string, /Invalid path/);
    });

    it("should clone a local bare repo", async () => {
      const bare = createBareRemote("clone-test");
      // Push something to the bare remote first
      const tmpSrc = path.join(TEST_WORKSPACE, "tmp-src");
      fs.mkdirSync(tmpSrc, { recursive: true });
      execSync("git init", { cwd: tmpSrc });
      execSync("git config user.email 'test@test.com'", { cwd: tmpSrc });
      execSync("git config user.name 'Test'", { cwd: tmpSrc });
      fs.writeFileSync(path.join(tmpSrc, "file.txt"), "hello");
      execSync("git add . && git commit -m 'init'", { cwd: tmpSrc });
      execSync(`git remote add origin ${bare}`, { cwd: tmpSrc });
      execSync("git push origin master", { cwd: tmpSrc });
      fs.rmSync(tmpSrc, { recursive: true, force: true });

      const res = await request(app, "POST", "/v1/workspace/git/clone", {
        url: bare,
        path: "cloned-repo",
      });
      assert.equal(res.status, 200);
      assert.equal(res.body.status, "cloned");
      assert.equal(res.body.path, "cloned-repo");
      assert.ok(res.body.branch);
      assert.ok(res.body.commit);
      // Verify the file was cloned
      assert.ok(
        fs.existsSync(path.join(PROJECTS_DIR, "cloned-repo", "file.txt")),
      );
    });

    it("should pull instead of clone if target exists", async () => {
      // Create a bare remote and clone it so the local repo has a tracking remote
      const bare = createBareRemote("existing-remote");
      const tmpSrc = path.join(TEST_WORKSPACE, "tmp-existing-src");
      fs.mkdirSync(tmpSrc, { recursive: true });
      execSync("git init", { cwd: tmpSrc });
      execSync("git config user.email 'test@test.com'", { cwd: tmpSrc });
      execSync("git config user.name 'Test'", { cwd: tmpSrc });
      fs.writeFileSync(path.join(tmpSrc, "file.txt"), "content");
      execSync("git add . && git commit -m 'init'", { cwd: tmpSrc });
      execSync(`git remote add origin ${bare}`, { cwd: tmpSrc });
      execSync("git push origin master", { cwd: tmpSrc });
      fs.rmSync(tmpSrc, { recursive: true, force: true });

      // Clone into the target path first
      const targetPath = path.join(PROJECTS_DIR, "existing-repo");
      execSync(`git clone ${bare} ${targetPath}`);

      // Now call clone again — should pull instead
      const res = await request(app, "POST", "/v1/workspace/git/clone", {
        url: bare,
        path: "existing-repo",
      });
      assert.equal(res.status, 200);
      assert.equal(res.body.status, "pulled");
    });
  });

  describe("POST /v1/workspace/git/pull", () => {
    it("should require path", async () => {
      const res = await request(app, "POST", "/v1/workspace/git/pull", {});
      assert.equal(res.status, 400);
      assert.equal(res.body.error, "path is required");
    });

    it("should return 404 for non-git directory", async () => {
      const nonGitDir = path.join(PROJECTS_DIR, "not-a-repo");
      fs.mkdirSync(nonGitDir, { recursive: true });
      const res = await request(app, "POST", "/v1/workspace/git/pull", {
        path: "not-a-repo",
      });
      assert.equal(res.status, 404);
      assert.match(res.body.error as string, /Not a git repository/);
    });

    it("should pull an existing repo (up-to-date)", async () => {
      // Create a bare remote and clone it
      const bare = createBareRemote("pull-remote");
      const tmpSrc = path.join(TEST_WORKSPACE, "tmp-pull-src");
      fs.mkdirSync(tmpSrc, { recursive: true });
      execSync("git init", { cwd: tmpSrc });
      execSync("git config user.email 'test@test.com'", { cwd: tmpSrc });
      execSync("git config user.name 'Test'", { cwd: tmpSrc });
      fs.writeFileSync(path.join(tmpSrc, "file.txt"), "content");
      execSync("git add . && git commit -m 'init'", { cwd: tmpSrc });
      execSync(`git remote add origin ${bare}`, { cwd: tmpSrc });
      execSync("git push origin master", { cwd: tmpSrc });
      fs.rmSync(tmpSrc, { recursive: true, force: true });

      const targetPath = path.join(PROJECTS_DIR, "pull-test");
      execSync(`git clone ${bare} ${targetPath}`);

      const res = await request(app, "POST", "/v1/workspace/git/pull", {
        path: "pull-test",
      });
      assert.equal(res.status, 200);
      assert.equal(res.body.status, "up-to-date");
      assert.ok(res.body.branch);
      assert.ok(res.body.commit);
    });
  });

  describe("GET /v1/workspace/git/status", () => {
    it("should require path query param", async () => {
      const res = await request(app, "GET", "/v1/workspace/git/status");
      assert.equal(res.status, 400);
      assert.equal(res.body.error, "path query parameter is required");
    });

    it("should return exists=false for non-existent repo", async () => {
      const res = await request(
        app,
        "GET",
        "/v1/workspace/git/status?path=nonexistent",
      );
      assert.equal(res.status, 200);
      assert.equal(res.body.exists, false);
    });

    it("should return repo info for existing repo", async () => {
      createTestRepo("status-test");
      const res = await request(
        app,
        "GET",
        "/v1/workspace/git/status?path=status-test",
      );
      assert.equal(res.status, 200);
      assert.equal(res.body.exists, true);
      assert.ok(res.body.branch);
      assert.ok(res.body.commit);
      assert.equal(res.body.dirty, false);
      assert.ok(res.body.lastCommitDate);
    });

    it("should detect dirty state", async () => {
      const repoPath = createTestRepo("dirty-test");
      fs.writeFileSync(path.join(repoPath, "new-file.txt"), "dirty");
      const res = await request(
        app,
        "GET",
        "/v1/workspace/git/status?path=dirty-test",
      );
      assert.equal(res.status, 200);
      assert.equal(res.body.exists, true);
      assert.equal(res.body.dirty, true);
    });

    it("should reject path traversal", async () => {
      const res = await request(
        app,
        "GET",
        "/v1/workspace/git/status?path=../../etc",
      );
      assert.equal(res.status, 400);
      assert.match(res.body.error as string, /Invalid path/);
    });
  });
});
