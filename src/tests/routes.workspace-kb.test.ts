import { describe, it, beforeAll, afterAll } from "vitest";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import http from "node:http";
import express from "express";

// Set WORKSPACE_ROOT before importing the routes (the workspace module reads it
// at import time). Mirrors the harness in src/__tests__/git.test.ts.
const TEST_WORKSPACE = fs.mkdtempSync(path.join(os.tmpdir(), "agw-kb-test-"));
process.env.WORKSPACE_ROOT = TEST_WORKSPACE;

const KB_DIR = path.join(TEST_WORKSPACE, "projects", "knowledge-base");
const INDEX_CONTENT = "# Knowledge Base Index\n\nWelcome to the KB.\n";
const NESTED_CONTENT = "# OneCRM Code Patterns\n\n- pattern A\n- pattern B\n";
// Sibling secret OUTSIDE the KB root — used to prove the KB route cannot escape.
const SECRET_CONTENT = "TOP SECRET MEMORY — must never leak through the KB route\n";

function seedKb(): void {
  fs.mkdirSync(path.join(KB_DIR, "onecrm"), { recursive: true });
  fs.writeFileSync(path.join(KB_DIR, "INDEX.md"), INDEX_CONTENT);
  fs.writeFileSync(path.join(KB_DIR, "onecrm", "CODE-PATTERNS.md"), NESTED_CONTENT);
  // Sibling memory secret (the workspace "memory" section root is <WORKSPACE_ROOT>/memory).
  fs.mkdirSync(path.join(TEST_WORKSPACE, "memory"), { recursive: true });
  fs.writeFileSync(path.join(TEST_WORKSPACE, "memory", "secret"), SECRET_CONTENT);
}

function clearKb(): void {
  fs.rmSync(KB_DIR, { recursive: true, force: true });
}

// The workspace module caches WORKSPACE_ROOT at import time, so import AFTER setting env.
const { default: workspaceRoutes } = await import("../routes/workspace.js");

/**
 * Drive the app with the platform `fetch` client. Note: `fetch` NORMALIZES the
 * URL path (collapses `../`, decodes nothing extra) before sending, so it is the
 * correct client for the encoded-vector and normalized-traversal cases, but it
 * CANNOT send a literal `..` segment — see rawRequest for that.
 */
async function request(
  app: express.Express,
  method: "GET" | "PUT" | "DELETE",
  urlPath: string,
  body?: string,
): Promise<{ status: number; contentType: string | null; text: string }> {
  return new Promise((resolve, reject) => {
    const server = app.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (!addr || typeof addr === "string") {
        server.close();
        reject(new Error("No address"));
        return;
      }
      const url = `http://127.0.0.1:${addr.port}${urlPath}`;
      const options: RequestInit = { method };
      if (body !== undefined) {
        options.body = body;
        options.headers = { "Content-Type": "text/plain" };
      }
      fetch(url, options)
        .then((res) =>
          res.text().then((text) => {
            server.close();
            resolve({
              status: res.status,
              contentType: res.headers.get("content-type"),
              text,
            });
          }),
        )
        .catch((err) => {
          server.close();
          reject(err);
        });
    });
  });
}

/**
 * Drive the app with a RAW node:http request that sends the path EXACTLY as
 * given — no URL normalization. This is required to push a literal `../`
 * segment through to the Express router so the KB handler's `safePath` guard is
 * actually exercised (a normalizing client would collapse `../` before sending,
 * rewriting the request onto a different route entirely).
 */
async function rawRequest(
  app: express.Express,
  method: "GET" | "PUT" | "DELETE",
  rawPath: string,
): Promise<{ status: number; contentType: string | null; text: string }> {
  return new Promise((resolve, reject) => {
    const server = app.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (!addr || typeof addr === "string") {
        server.close();
        reject(new Error("No address"));
        return;
      }
      const req = http.request(
        { host: "127.0.0.1", port: addr.port, method, path: rawPath },
        (res) => {
          let text = "";
          res.setEncoding("utf-8");
          res.on("data", (chunk) => (text += chunk));
          res.on("end", () => {
            server.close();
            resolve({
              status: res.statusCode ?? 0,
              contentType: res.headers["content-type"] ?? null,
              text,
            });
          });
        },
      );
      req.on("error", (err) => {
        server.close();
        reject(err);
      });
      req.end();
    });
  });
}

describe("Knowledge-base routes (read-only)", () => {
  let app: express.Express;

  beforeAll(() => {
    app = express();
    app.use(express.json());
    app.use(express.text({ type: "text/*" }));
    app.use(workspaceRoutes);
    seedKb();
  });

  afterAll(() => {
    fs.rmSync(TEST_WORKSPACE, { recursive: true, force: true });
  });

  describe("GET /v1/knowledge-base (list)", () => {
    it("returns 200 with { files: [{ path, size, modified }] } covering the whole tree", async () => {
      const res = await request(app, "GET", "/v1/knowledge-base");
      assert.equal(res.status, 200);
      const body = JSON.parse(res.text) as {
        files: { path: string; size: number; modified: string }[];
      };
      assert.ok(Array.isArray(body.files), "files must be an array");

      const paths = body.files.map((f) => f.path).sort();
      assert.deepEqual(paths, ["INDEX.md", "onecrm/CODE-PATTERNS.md"]);

      for (const entry of body.files) {
        // forward-slash, relative paths (no leading slash, no backslash)
        assert.ok(!entry.path.startsWith("/"), "path must be relative");
        assert.ok(!entry.path.includes("\\"), "path must use forward slashes");
        // numeric size
        assert.equal(typeof entry.size, "number");
        assert.ok(entry.size > 0);
        // ISO-8601 modified string that round-trips through Date
        assert.equal(typeof entry.modified, "string");
        assert.equal(
          new Date(entry.modified).toISOString(),
          entry.modified,
          "modified must be a valid ISO-8601 timestamp",
        );
      }
    });
  });

  describe("GET /v1/knowledge-base/{*path} (read)", () => {
    it("returns 200 text/markdown with the exact file bytes", async () => {
      const res = await request(app, "GET", "/v1/knowledge-base/INDEX.md");
      assert.equal(res.status, 200);
      assert.equal(res.contentType, "text/markdown; charset=utf-8");
      assert.equal(res.text, INDEX_CONTENT);
    });

    it("reads a nested doc by its forward-slash relative path", async () => {
      const res = await request(
        app,
        "GET",
        "/v1/knowledge-base/onecrm/CODE-PATTERNS.md",
      );
      assert.equal(res.status, 200);
      assert.equal(res.contentType, "text/markdown; charset=utf-8");
      assert.equal(res.text, NESTED_CONTENT);
    });

    it("returns 404 for a safe but non-existent doc", async () => {
      const res = await request(
        app,
        "GET",
        "/v1/knowledge-base/does-not-exist.md",
      );
      assert.equal(res.status, 404);
      assert.equal(JSON.parse(res.text).error, "File not found");
    });

    it("returns 404 for a directory path (isFile guard, not EISDIR 500)", async () => {
      const res = await request(app, "GET", "/v1/knowledge-base/onecrm");
      assert.equal(res.status, 404);
      assert.equal(JSON.parse(res.text).error, "File not found");
    });
  });

  describe("GET /v1/knowledge-base (empty / absent KB dir)", () => {
    it("returns 200 { files: [] } when the KB directory is absent (never 500)", async () => {
      clearKb();
      try {
        const res = await request(app, "GET", "/v1/knowledge-base");
        assert.equal(res.status, 200);
        assert.deepEqual(JSON.parse(res.text), { files: [] });
      } finally {
        seedKb(); // restore for later tests
      }
    });
  });

  describe("Path traversal — must genuinely exercise safePath", () => {
    it("RAW un-normalized `../memory/secret` reaches the handler → 400 Invalid path, no foreign content", async () => {
      // node:http sends the literal `..` so it reaches the KB route's safePath
      // guard (a normalizing client would rewrite this onto /v1/memory/secret).
      const res = await rawRequest(
        app,
        "GET",
        "/v1/knowledge-base/../memory/secret",
      );
      assert.equal(res.status, 400);
      assert.equal(JSON.parse(res.text).error, "Invalid path");
      assert.ok(
        !res.text.includes("TOP SECRET"),
        "must not leak the sibling secret content",
      );
    });

    it("RAW un-normalized deep `../../memory/secret` → 400, no foreign content", async () => {
      const res = await rawRequest(
        app,
        "GET",
        "/v1/knowledge-base/../../memory/secret",
      );
      assert.equal(res.status, 400);
      assert.equal(JSON.parse(res.text).error, "Invalid path");
      assert.ok(!res.text.includes("TOP SECRET"));
    });

    it("normalized `fetch` traversal does NOT leak foreign content via the KB handler", async () => {
      // A normalizing client collapses `../` BEFORE sending, rewriting this onto
      // the memory route — it never reaches the KB handler. The regression guard:
      // the KB route can never serve content from outside its root. Whatever the
      // collapsed request resolves to, the KB *handler* did not produce it.
      const res = await request(
        app,
        "GET",
        "/v1/knowledge-base/../memory/secret",
      );
      // It resolved to /v1/memory/secret (the memory section, served as text/plain),
      // NOT to a KB markdown response — proving the KB route did not escape its root.
      assert.notEqual(
        res.contentType,
        "text/markdown; charset=utf-8",
        "must not be served by the KB markdown handler",
      );
    });

    it("encoded traversal vectors all yield 4xx with no foreign content", async () => {
      const vectors = [
        "/v1/knowledge-base/..%2f..%2fmemory%2fsecret",
        "/v1/knowledge-base/..%5cmemory",
        "/v1/knowledge-base/%00",
        "/v1/knowledge-base/INDEX.md%00.png",
        "/v1/knowledge-base//etc/passwd",
      ];
      for (const v of vectors) {
        const res = await rawRequest(app, "GET", v);
        assert.ok(
          res.status >= 400 && res.status < 500,
          `expected 4xx for ${v}, got ${res.status}`,
        );
        assert.ok(
          !res.text.includes("TOP SECRET"),
          `must not leak secret content for ${v}`,
        );
        assert.ok(
          !res.text.includes("root:"),
          `must not leak /etc/passwd for ${v}`,
        );
      }
    });
  });

  describe("No-write invariant — read-only section", () => {
    it("PUT /v1/knowledge-base/INDEX.md → 404 (no handler) and bytes-on-disk unchanged", async () => {
      const onDiskPath = path.join(KB_DIR, "INDEX.md");
      const before = fs.readFileSync(onDiskPath, "utf-8");
      const beforeMtime = fs.statSync(onDiskPath).mtimeMs;

      const res = await request(
        app,
        "PUT",
        "/v1/knowledge-base/INDEX.md",
        "# OVERWRITTEN\n",
      );
      assert.equal(res.status, 404, "no PUT handler must be registered");

      const after = fs.readFileSync(onDiskPath, "utf-8");
      assert.equal(after, before, "file content must be unchanged");
      assert.equal(after, INDEX_CONTENT);
      assert.equal(
        fs.statSync(onDiskPath).mtimeMs,
        beforeMtime,
        "file mtime must be unchanged",
      );
    });

    it("DELETE /v1/knowledge-base/INDEX.md → 404 (no handler) and file still exists", async () => {
      const onDiskPath = path.join(KB_DIR, "INDEX.md");
      const before = fs.readFileSync(onDiskPath, "utf-8");
      const beforeMtime = fs.statSync(onDiskPath).mtimeMs;

      const res = await request(app, "DELETE", "/v1/knowledge-base/INDEX.md");
      assert.equal(res.status, 404, "no DELETE handler must be registered");

      assert.ok(fs.existsSync(onDiskPath), "file must still exist");
      assert.equal(fs.readFileSync(onDiskPath, "utf-8"), before);
      assert.equal(
        fs.statSync(onDiskPath).mtimeMs,
        beforeMtime,
        "file mtime must be unchanged",
      );
    });
  });
});
