import { describe, it, beforeAll, afterAll, beforeEach } from "vitest";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import http from "node:http";
import express from "express";

// Set WORKSPACE_ROOT before importing the routes (the workspace module reads it
// at import time). Mirrors src/tests/routes.workspace-kb.test.ts.
const TEST_WORKSPACE = fs.mkdtempSync(path.join(os.tmpdir(), "agw-userskills-test-"));
process.env.WORKSPACE_ROOT = TEST_WORKSPACE;

const SKILL_BODY =
  "---\nname: deploy-helper\ndescription: Deploys the thing\n---\n\nRun the deploy.\n";
// A sibling secret OUTSIDE any user's skills root, used to prove traversal is blocked.
const SECRET_CONTENT = "TOP SECRET — must never leak through the user-skills route\n";

const { default: workspaceRoutes } = await import("../routes/workspace.js");

async function request(
  app: express.Express,
  method: "GET" | "PUT" | "DELETE",
  urlPath: string,
  body?: string,
): Promise<{ status: number; contentType: string | null; text: string }> {
  return new Promise((resolve, reject) => {
    const server = app.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (!addr || typeof addr === "string") { server.close(); reject(new Error("No address")); return; }
      const url = `http://127.0.0.1:${addr.port}${urlPath}`;
      const options: RequestInit = { method };
      if (body !== undefined) { options.body = body; options.headers = { "Content-Type": "text/plain" }; }
      fetch(url, options)
        .then((res) => res.text().then((text) => {
          server.close();
          resolve({ status: res.status, contentType: res.headers.get("content-type"), text });
        }))
        .catch((err) => { server.close(); reject(err); });
    });
  });
}

// Sends the path EXACTLY as given (no URL normalization) so literal `..` segments
// reach the router and exercise safePath / the user_id sanitizer.
async function rawRequest(
  app: express.Express,
  method: "GET" | "PUT" | "DELETE",
  rawPath: string,
  body?: string,
): Promise<{ status: number; contentType: string | null; text: string }> {
  return new Promise((resolve, reject) => {
    const server = app.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (!addr || typeof addr === "string") { server.close(); reject(new Error("No address")); return; }
      const headers: Record<string, string> = {};
      if (body !== undefined) headers["Content-Type"] = "text/plain";
      const req = http.request(
        { host: "127.0.0.1", port: addr.port, method, path: rawPath, headers },
        (res) => {
          let text = "";
          res.setEncoding("utf-8");
          res.on("data", (chunk) => (text += chunk));
          res.on("end", () => {
            server.close();
            resolve({ status: res.statusCode ?? 0, contentType: res.headers["content-type"] ?? null, text });
          });
        },
      );
      req.on("error", (err) => { server.close(); reject(err); });
      if (body !== undefined) req.write(body);
      req.end();
    });
  });
}

describe("Per-user skill routes (/v1/users/:user_id/skills)", () => {
  let app: express.Express;

  beforeAll(() => {
    app = express();
    app.use(express.json());
    app.use(express.text({ type: "text/*" }));
    app.use(workspaceRoutes);
    // Seed a sibling secret directly under WORKSPACE_ROOT to prove escape is blocked.
    fs.writeFileSync(path.join(TEST_WORKSPACE, "secret"), SECRET_CONTENT);
  });

  afterAll(() => {
    fs.rmSync(TEST_WORKSPACE, { recursive: true, force: true });
  });

  beforeEach(() => {
    // Clean per-user namespaces between tests (keep the sibling secret).
    const usersDir = path.join(TEST_WORKSPACE, "users");
    fs.rmSync(usersDir, { recursive: true, force: true });
  });

  describe("PUT then GET (CRUD round-trip)", () => {
    it("PUT stores SKILL.md and GET lists it with { files: [{ path, size, modified }] }", async () => {
      const put = await request(app, "PUT", "/v1/users/alice/skills/deploy/SKILL.md", SKILL_BODY);
      assert.equal(put.status, 200);
      const putBody = JSON.parse(put.text) as { status: string; path: string };
      assert.equal(putBody.status, "ok");
      assert.equal(putBody.path, "deploy/SKILL.md");

      // Content is on disk in the per-user namespace.
      const onDisk = path.join(TEST_WORKSPACE, "users", "alice", "skills", "deploy", "SKILL.md");
      assert.ok(fs.existsSync(onDisk));
      assert.equal(fs.readFileSync(onDisk, "utf-8"), SKILL_BODY);

      const list = await request(app, "GET", "/v1/users/alice/skills");
      assert.equal(list.status, 200);
      const body = JSON.parse(list.text) as { files: { path: string; size: number; modified: string }[] };
      assert.ok(Array.isArray(body.files), "files must be an array");
      const paths = body.files.map((f) => f.path).sort();
      assert.deepEqual(paths, ["deploy/SKILL.md"]);
      for (const entry of body.files) {
        assert.ok(!entry.path.startsWith("/"), "path must be relative");
        assert.ok(!entry.path.includes("\\"), "path must use forward slashes");
        assert.equal(typeof entry.size, "number");
        assert.ok(entry.size > 0);
        assert.equal(new Date(entry.modified).toISOString(), entry.modified);
      }
    });

    it("GET on an empty/absent namespace returns 200 { files: [] }", async () => {
      const list = await request(app, "GET", "/v1/users/ghost/skills");
      assert.equal(list.status, 200);
      assert.deepEqual(JSON.parse(list.text), { files: [] });
    });

    it("namespaces are isolated: alice's skill is not visible under bob", async () => {
      await request(app, "PUT", "/v1/users/alice/skills/x/SKILL.md", SKILL_BODY);
      const bob = await request(app, "GET", "/v1/users/bob/skills");
      assert.equal(bob.status, 200);
      assert.deepEqual(JSON.parse(bob.text), { files: [] });
      const alice = await request(app, "GET", "/v1/users/alice/skills");
      assert.deepEqual((JSON.parse(alice.text) as { files: { path: string }[] }).files.map((f) => f.path), ["x/SKILL.md"]);
    });
  });

  describe("DELETE", () => {
    it("DELETE removes the skill; subsequent GET no longer lists it", async () => {
      await request(app, "PUT", "/v1/users/alice/skills/gone/SKILL.md", SKILL_BODY);
      const del = await request(app, "DELETE", "/v1/users/alice/skills/gone/SKILL.md");
      assert.equal(del.status, 200);
      assert.equal(JSON.parse(del.text).status, "ok");
      const list = await request(app, "GET", "/v1/users/alice/skills");
      assert.deepEqual((JSON.parse(list.text) as { files: { path: string }[] }).files, []);
    });

    it("DELETE on a non-existent skill returns 404", async () => {
      const del = await request(app, "DELETE", "/v1/users/alice/skills/never/SKILL.md");
      assert.equal(del.status, 404);
      assert.equal(JSON.parse(del.text).error, "File not found");
    });
  });

  describe("Path safety — user_id segment", () => {
    it("rejects a traversal user_id `..` with 400 and does not leak the sibling secret", async () => {
      // RAW so the literal `..` reaches the router as the :user_id segment.
      const res = await rawRequest(app, "GET", "/v1/users/../skills");
      // Either the sanitizer rejects (400) or express fails to match (404) — never
      // 200 with foreign content.
      assert.ok(res.status >= 400, `expected 4xx, got ${res.status}`);
      assert.ok(!res.text.includes("TOP SECRET"), "must not leak the sibling secret");
    });

    it("encoded traversal vectors in user_id all yield 4xx with no foreign content", async () => {
      const vectors = [
        "/v1/users/..%2f..%2fsecret/skills",
        "/v1/users/%00/skills",
        "/v1/users/.%2e/skills",
      ];
      for (const v of vectors) {
        const res = await rawRequest(app, "GET", v);
        assert.ok(res.status >= 400 && res.status < 500, `expected 4xx for ${v}, got ${res.status}`);
        assert.ok(!res.text.includes("TOP SECRET"), `must not leak secret for ${v}`);
      }
    });

    it("PUT with an absolute-looking encoded user_id is rejected", async () => {
      const res = await rawRequest(app, "PUT", "/v1/users/%2fetc/skills/x/SKILL.md", SKILL_BODY);
      assert.ok(res.status >= 400, `expected 4xx, got ${res.status}`);
    });
  });

  describe("Path safety — subpath", () => {
    it("rejects a subpath traversal with 400 and does not escape the namespace", async () => {
      const res = await rawRequest(app, "PUT", "/v1/users/alice/skills/../../secret", "pwned\n");
      assert.equal(res.status, 400);
      assert.equal(JSON.parse(res.text).error, "Invalid path");
      // The sibling secret on disk is unchanged.
      assert.equal(fs.readFileSync(path.join(TEST_WORKSPACE, "secret"), "utf-8"), SECRET_CONTENT);
    });

    it("rejects a NUL-byte subpath", async () => {
      const res = await rawRequest(app, "PUT", "/v1/users/alice/skills/x%00.md", "x");
      assert.ok(res.status >= 400, `expected 4xx, got ${res.status}`);
    });
  });
});
