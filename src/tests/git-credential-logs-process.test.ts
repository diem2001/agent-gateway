/**
 * MVP-7614 — credentials never appear in the gateway log or in error text.
 *
 * The compiled gateway runs as a child process (helpers/git-process-gateway.ts)
 * at LOG_LEVEL info and debug; every request goes through the full HTTP path
 * (JSON parser, request logging, API-key check, git route). Both stdout and
 * stderr of the gateway are scanned, together with every response body, for
 * the token, `user:token`, its Base64 form and every line of the SSH key.
 *
 * The token-protected remote is a loopback dumb-HTTP git server with Basic
 * auth; the failing remote is a closed loopback port. The SSH key is random
 * text in the shape of an RSA-4096 key (longer than the 2000-character request
 * preview); the remotes are local, so ssh never reads it.
 */
import { afterEach, describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  closedPort,
  createBareRepo,
  fixtureGit,
  startDumbHttpGitRemote,
  type DumbHttpGitRemote,
} from "./helpers/dumb-http-git-remote.js";
import { gatewayRequest, spawnGateway, type Cleanup, type SpawnedGateway } from "./helpers/git-process-gateway.js";

const cleanups: Cleanup[] = [];

afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()!();
});

function realGit(): string {
  return execFileSync("sh", ["-c", "command -v git"], { encoding: "utf8" }).trim();
}

/** Random text shaped like an RSA-4096 private key (PEM, 64-character lines). */
function fakeRsa4096Key(): string {
  const body = randomBytes(2350).toString("base64");
  const lines = body.match(/.{1,64}/g)!;
  return ["-----BEGIN RSA PRIVATE KEY-----", ...lines, "-----END RSA PRIVATE KEY-----"].join("\n");
}

function needlesFor(user: string, token: string): string[] {
  return [token, `${user}:${token}`, Buffer.from(`${user}:${token}`, "utf8").toString("base64")];
}

interface Seen {
  replies: string[];
}

/** Every needle found in the gateway output or in a response body, as "<where>: <needle prefix>". */
function leaks(gateway: SpawnedGateway, seen: Seen, needles: string[]): string[] {
  const hits: string[] = [];
  const output = gateway.output();
  for (const needle of needles) {
    if (output.includes(needle)) hits.push(`gateway output: ${needle.slice(0, 12)}…`);
    for (const reply of seen.replies) if (reply.includes(needle)) hits.push(`response body: ${needle.slice(0, 12)}…`);
  }
  return hits;
}

async function send(gateway: SpawnedGateway, seen: Seen, method: string, urlPath: string, body?: unknown) {
  const reply = await gatewayRequest(gateway.port, method, urlPath, body);
  seen.replies.push(reply.text);
  return reply;
}

let remote: DumbHttpGitRemote;

async function remoteFor(root: string): Promise<DumbHttpGitRemote> {
  remote = await startDumbHttpGitRemote(root, realGit());
  cleanups.push(() => remote.close());
  return remote;
}

function testRoot(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "mvp7614-credlogs-"));
  cleanups.push(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

for (const level of ["info", "debug"] as const) {
  describe(`credentials stay out of the log and error text at LOG_LEVEL=${level}`, () => {
    it("a token-bearing first clone that succeeds", async () => {
      const root = testRoot();
      const http = await remoteFor(root);
      const gateway = await spawnGateway(cleanups, { env: { LOG_LEVEL: level } });
      const seen: Seen = { replies: [] };
      const reply = await send(gateway, seen, "POST", "/v1/workspace/git/clone", { url: http.authUrl, path: "cred-clone-ok" });
      expect(reply.status, reply.text).toBe(200);
      expect(reply.json).toMatchObject({ status: "cloned", path: "cred-clone-ok", branch: "main" });
      // The request was really authenticated with the token.
      expect(http.requests.some((r) => r.authorized)).toBe(true);
      expect(gateway.output()).toContain("cred-clone-ok");
      expect(leaks(gateway, seen, needlesFor(http.user, http.token))).toEqual([]);
    });

    it("a token-bearing first clone that fails (closed port)", async () => {
      const gateway = await spawnGateway(cleanups, { env: { LOG_LEVEL: level } });
      const token = `SECRET-TOKEN-${randomBytes(12).toString("hex")}`;
      const seen: Seen = { replies: [] };
      const url = `http://user:${token}@127.0.0.1:${await closedPort()}/repo.git`;
      const reply = await send(gateway, seen, "POST", "/v1/workspace/git/clone", { url, path: "cred-clone-fail" });
      expect(reply.status).toBe(500);
      expect(gateway.output()).toMatch(/Clone failed/);
      expect(leaks(gateway, seen, needlesFor("user", token))).toEqual([]);
    });

    it("a pull that fails on a checkout whose stored origin URL carries the token (401 and closed port)", async () => {
      const root = testRoot();
      const http = await remoteFor(root);
      const gateway = await spawnGateway(cleanups, { env: { LOG_LEVEL: level } });
      const seen: Seen = { replies: [] };
      const git = realGit();
      // Fixture checkouts come from the bare path (a synchronous clone over HTTP would block
      // the in-process remote) and then get the token-bearing origin URL.
      const checkout401 = path.join(gateway.dirs.projects, "cred-pull-401");
      fixtureGit(git, ["clone", "-b", "main", "--", http.barePath, checkout401], root);
      fixtureGit(git, ["remote", "set-url", "origin", http.authUrl], checkout401);
      http.setReject(true);
      const rejected = await send(gateway, seen, "POST", "/v1/workspace/git/pull", { path: "cred-pull-401", branch: "main" });
      expect(rejected.status).toBe(500);

      const closedToken = `SECRET-TOKEN-${randomBytes(12).toString("hex")}`;
      const closedCheckout = path.join(gateway.dirs.projects, "cred-pull-closed");
      fixtureGit(git, ["clone", "-b", "main", "--", http.barePath, closedCheckout], root);
      fixtureGit(git, ["remote", "set-url", "origin", `http://user:${closedToken}@127.0.0.1:${await closedPort()}/repo.git`], closedCheckout);
      const refused = await send(gateway, seen, "POST", "/v1/workspace/git/pull", { path: "cred-pull-closed" });
      expect(refused.status).toBe(500);

      expect(gateway.output()).toMatch(/Pull failed/);
      expect(leaks(gateway, seen, [...needlesFor(http.user, http.token), ...needlesFor("user", closedToken)])).toEqual([]);
    });

    // reqlift inserts tokens into the clone URL unencoded, and git echoes a URL it cannot
    // parse as is. Every token is built from random markers; no marker may appear anywhere.
    it("token-bearing first clones that fail, with '/', whitespace, quotes, '@', '%', '+' or unicode in the token", async () => {
      const gateway = await spawnGateway(cleanups, { env: { LOG_LEVEL: level } });
      const seen: Seen = { replies: [] };
      const port = await closedPort();
      const needles: string[] = [];
      const marker = () => {
        const value = `SECRET${randomBytes(6).toString("hex").toUpperCase()}`;
        needles.push(value);
        return value;
      };
      const tokens = [
        `${marker()}/${marker()}+z`,
        `${marker()} `,
        `${marker()} ${marker()}`,
        `${marker()}\t${marker()}`,
        `${marker()}'${marker()}/c`,
        `${marker()}"${marker()}/c`,
        `${marker()}@${marker()}+z`,
        `${marker()}%${marker()}/c`,
        `${marker()}+${marker()}/c`,
        `${marker()}€ä${marker()}/c`,
      ];
      for (const token of tokens) {
        const reply = await send(gateway, seen, "POST", "/v1/workspace/git/clone", { url: `http://user:${token}@127.0.0.1:${port}/repo.git`, path: "cred-odd" });
        expect(reply.status, reply.text).toBe(500);
      }
      expect(gateway.output()).toMatch(/Clone failed/);
      expect(leaks(gateway, seen, needles)).toEqual([]);
    });

    it("a pull that fails on a checkout whose stored origin URL has a token with '/'", async () => {
      const root = testRoot();
      const git = realGit();
      const bare = path.join(root, "remote.git");
      createBareRepo(git, bare);
      const gateway = await spawnGateway(cleanups, { env: { LOG_LEVEL: level } });
      const seen: Seen = { replies: [] };
      const [a, b] = [`SECRET${randomBytes(6).toString("hex")}`, `SECRET${randomBytes(6).toString("hex")}`];
      const checkout = path.join(gateway.dirs.projects, "cred-pull-slash");
      fixtureGit(git, ["clone", "-b", "main", "--", bare, checkout], root);
      fixtureGit(git, ["remote", "set-url", "origin", `http://user:${a}/${b}@127.0.0.1:${await closedPort()}/repo.git`], checkout);
      const reply = await send(gateway, seen, "POST", "/v1/workspace/git/pull", { path: "cred-pull-slash", branch: "main" });
      expect(reply.status, reply.text).toBe(500);
      expect(gateway.output()).toMatch(/Pull failed/);
      expect(leaks(gateway, seen, [a, b])).toEqual([]);
    });

    it("a clone URL whose token holds a line break is refused before git runs", async () => {
      const gateway = await spawnGateway(cleanups, { env: { LOG_LEVEL: level } });
      const seen: Seen = { replies: [] };
      const [a, b] = [`SECRET${randomBytes(6).toString("hex")}`, `SECRET${randomBytes(6).toString("hex")}`];
      const reply = await send(gateway, seen, "POST", "/v1/workspace/git/clone", {
        url: `http://user:${a}\n${b}@127.0.0.1:${await closedPort()}/repo.git`,
        path: "cred-newline",
      });
      expect(reply.status).toBe(400);
      expect(reply.json).toEqual({ error: "Invalid url" });
      expect(leaks(gateway, seen, [a, b])).toEqual([]);
    });
  });
}

describe("SSH keys stay out of the debug log", () => {
  for (const endpoint of ["clone", "pull"] as const) {
    it(`an sshKey on ${endpoint} (a key longer than the request preview)`, async () => {
      const root = testRoot();
      const git = realGit();
      const bare = path.join(root, "remote.git");
      createBareRepo(git, bare);
      const gateway = await spawnGateway(cleanups, { env: { LOG_LEVEL: "debug" } });
      const key = fakeRsa4096Key();
      expect(key.length).toBeGreaterThan(3000);
      const seen: Seen = { replies: [] };
      if (endpoint === "pull") fixtureGit(git, ["clone", "-b", "main", "--", bare, path.join(gateway.dirs.projects, "ssh-repo")], root);
      const reply =
        endpoint === "clone"
          ? await send(gateway, seen, "POST", "/v1/workspace/git/clone", { url: bare, path: "ssh-repo", sshKey: key })
          : await send(gateway, seen, "POST", "/v1/workspace/git/pull", { path: "ssh-repo", sshKey: key });
      expect(reply.status, reply.text).toBe(200);
      // The debug request log line for the route was written.
      expect(gateway.output()).toMatch(new RegExp(`\\[req\\] POST /v1/workspace/git/${endpoint}`));
      expect(leaks(gateway, seen, key.split("\n"))).toEqual([]);
    });
  }
});
