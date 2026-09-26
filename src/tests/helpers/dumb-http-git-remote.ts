/**
 * A loopback git remote over git's "dumb" HTTP protocol: static files of a bare
 * repository (prepared with `git update-server-info`) behind HTTP Basic auth.
 * Every request without the expected `user:<token>` credentials gets
 * 401 with a Basic challenge; `setReject(true)` answers every request with 401,
 * so the credentials stored in a checkout's origin URL stop working.
 *
 * The bare repository has one commit on `main`; `pushCommit()` adds another.
 */
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import net, { type AddressInfo } from "node:net";
import path from "node:path";

export interface DumbHttpGitRemote {
  /** e.g. "SECRET-TOKEN-<random hex>". */
  token: string;
  user: string;
  /** http://user:<token>@127.0.0.1:<port>/repo.git */
  authUrl: string;
  /** The same URL with a wrong password. */
  wrongAuthUrl: string;
  /** Path of the bare repository on disk. */
  barePath: string;
  /** Requests received, in order. */
  requests: { path: string; authorized: boolean }[];
  setReject: (reject: boolean) => void;
  /** Adds a commit on `main`, refreshes the dumb-protocol info files and returns its full SHA. */
  pushCommit: (message: string) => string;
  close: () => Promise<void>;
}

/** Environment for fixture git commands: no global or system config, fixed identity. */
export function fixtureGitEnv(): NodeJS.ProcessEnv {
  return {
    ...process.env,
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_AUTHOR_NAME: "Test",
    GIT_AUTHOR_EMAIL: "test@test.invalid",
    GIT_COMMITTER_NAME: "Test",
    GIT_COMMITTER_EMAIL: "test@test.invalid",
  };
}

/** Runs the given git binary for fixture setup. */
export function fixtureGit(gitBinary: string, args: string[], cwd: string): string {
  return execFileSync(gitBinary, args, { cwd, env: fixtureGitEnv(), encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}

/**
 * A bare repository at `barePath` with one commit on `main` (and HEAD on main),
 * built through a scratch working copy next to it.
 */
export function createBareRepo(gitBinary: string, barePath: string, file = "README.md", content = "# fixture\n"): void {
  fs.mkdirSync(barePath, { recursive: true });
  fixtureGit(gitBinary, ["init", "--bare", "-b", "main"], barePath);
  const work = `${barePath}.work`;
  fs.mkdirSync(work, { recursive: true });
  fixtureGit(gitBinary, ["init", "-b", "main"], work);
  fs.writeFileSync(path.join(work, file), content);
  fixtureGit(gitBinary, ["add", "."], work);
  fixtureGit(gitBinary, ["commit", "-m", "init"], work);
  fixtureGit(gitBinary, ["push", barePath, "main"], work);
}

/** Adds a commit on `main` of a bare repository created by createBareRepo. */
export function pushFixtureCommit(gitBinary: string, barePath: string, message: string): string {
  const work = `${barePath}.work`;
  fs.writeFileSync(path.join(work, `${message.replace(/[^a-z0-9]/gi, "-")}.txt`), message);
  fixtureGit(gitBinary, ["add", "."], work);
  fixtureGit(gitBinary, ["commit", "-m", message], work);
  fixtureGit(gitBinary, ["push", barePath, "main"], work);
  return fixtureGit(gitBinary, ["rev-parse", "HEAD"], work);
}

export async function startDumbHttpGitRemote(root: string, gitBinary: string): Promise<DumbHttpGitRemote> {
  const barePath = path.join(root, "http-remote", "repo.git");
  createBareRepo(gitBinary, barePath);
  fixtureGit(gitBinary, ["update-server-info"], barePath);

  const user = "user";
  const token = `SECRET-TOKEN-${randomBytes(12).toString("hex")}`;
  const expected = `Basic ${Buffer.from(`${user}:${token}`, "utf8").toString("base64")}`;
  const requests: DumbHttpGitRemote["requests"] = [];
  const sockets = new Set<net.Socket>();
  let reject = false;

  const server = http.createServer((req, res) => {
    const pathname = decodeURIComponent(new URL(req.url ?? "/", "http://remote.invalid").pathname);
    const authorized = !reject && req.headers.authorization === expected;
    requests.push({ path: pathname, authorized });
    if (!authorized) {
      res.writeHead(401, { "WWW-Authenticate": 'Basic realm="fixture"', "Content-Type": "text/plain" });
      res.end("unauthorized\n");
      return;
    }
    const prefix = "/repo.git/";
    const relative = pathname.startsWith(prefix) ? pathname.slice(prefix.length) : "";
    const file = path.resolve(barePath, relative);
    if (!relative || !file.startsWith(barePath + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
      res.writeHead(404, { "Content-Type": "text/plain" });
      res.end("not found\n");
      return;
    }
    res.writeHead(200, { "Content-Type": "application/octet-stream" });
    res.end(fs.readFileSync(file));
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const { port } = server.address() as AddressInfo;

  return {
    token,
    user,
    authUrl: `http://${user}:${token}@127.0.0.1:${port}/repo.git`,
    wrongAuthUrl: `http://${user}:WRONG-${token}@127.0.0.1:${port}/repo.git`,
    barePath,
    requests,
    setReject: (value) => {
      reject = value;
    },
    pushCommit: (message) => {
      const sha = pushFixtureCommit(gitBinary, barePath, message);
      fixtureGit(gitBinary, ["update-server-info"], barePath);
      return sha;
    },
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

/** A loopback port with nothing listening on it (connection refused). */
export async function closedPort(): Promise<number> {
  const server = net.createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const { port } = server.address() as AddressInfo;
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
}
