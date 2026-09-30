/**
 * Spawned-gateway harness for the git process tests: the compiled gateway
 * (`dist/server.js`, built by `npm run build`) runs as a child process with an
 * environment ALLOWLIST (never the parent's API or Jira secrets) and fresh temp
 * directories for HOME, TMPDIR, cwd, every persist path and WORKSPACE_ROOT.
 * An optional fake-git bin directory goes first on the child's PATH.
 *
 * Every started gateway is registered with the caller's cleanup list; cleanup
 * SIGKILLs the gateway and every process below it, then removes its root.
 */
import { spawn, type ChildProcess } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import net, { type AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = path.resolve(here, "..", "..", "..");
const DIST_SERVER = path.join(REPO_ROOT, "dist", "server.js");

export const GATEWAY_API_KEY = "git-proc-gateway-key-7614";

/** Environment ALLOWLIST for the spawned gateway. Never turn this into a denylist. */
const ALLOWED_ENV_KEYS = ["PATH", "LANG"] as const;

/** Fails loudly when dist/ is missing or older than src/ (run `npm run build`). */
export function assertFreshBuild(): void {
  const srcRoot = path.join(REPO_ROOT, "src");
  for (const entry of fs.readdirSync(srcRoot, { withFileTypes: true, recursive: true })) {
    if (!entry.isFile() || !entry.name.endsWith(".ts") || entry.name.endsWith(".test.ts")) continue;
    const source = path.join(entry.parentPath, entry.name);
    const relative = path.relative(srcRoot, source);
    if (relative.startsWith("tests") || relative.startsWith("__tests__")) continue;
    const compiled = path.join(REPO_ROOT, "dist", relative.replace(/\.ts$/, ".js"));
    if (!fs.existsSync(compiled) || fs.statSync(compiled).mtimeMs < fs.statSync(source).mtimeMs) {
      throw new Error(`dist is missing or older than src for ${relative}; run \`npm run build\` first`);
    }
  }
}

export interface SpawnedGateway {
  child: ChildProcess;
  port: number;
  root: string;
  dirs: { home: string; tmp: string; cwd: string; persist: string; workspace: string; projects: string };
  /** Everything the gateway wrote to stdout and stderr so far. */
  output: () => string;
}

export type Cleanup = () => Promise<void> | void;

async function freePort(): Promise<number> {
  const server = net.createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const { port } = server.address() as AddressInfo;
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
}

function childPids(pid: number): number[] {
  const result: number[] = [];
  let tasks: string[] = [];
  try {
    tasks = fs.readdirSync(`/proc/${pid}/task`);
  } catch {
    return result;
  }
  for (const tid of tasks) {
    try {
      const text = fs.readFileSync(`/proc/${pid}/task/${tid}/children`, "utf8").trim();
      if (text) result.push(...text.split(/\s+/).map(Number));
    } catch {
      // Thread ended while reading.
    }
  }
  return result;
}

/** Every process below `pid` (not `pid` itself). Linux /proc only. */
export function descendants(pid: number): number[] {
  const found: number[] = [];
  const queue = [pid];
  while (queue.length > 0) {
    for (const child of childPids(queue.shift()!)) {
      found.push(child);
      queue.push(child);
    }
  }
  return found;
}

export async function spawnGateway(
  cleanups: Cleanup[],
  options: {
    fakeGitBin?: string;
    env?: Record<string, string>;
    rootPrefix?: string;
    distServer?: string;
    /** Called with the directories before the gateway starts (state files, planted content). */
    seed?: (dirs: SpawnedGateway["dirs"]) => void;
    /** A restart: the directories of an earlier gateway (its cleanup removes them), with a new process and port. */
    reuse?: SpawnedGateway;
  } = {},
): Promise<SpawnedGateway> {
  assertFreshBuild();
  const port = await freePort();
  const root = options.reuse?.root ?? fs.mkdtempSync(path.join(os.tmpdir(), options.rootPrefix ?? "mvp7614-gw-"));
  const base = { home: path.join(root, "home"), tmp: path.join(root, "tmp"), cwd: path.join(root, "cwd"), persist: path.join(root, "persist") };
  const workspace = path.join(base.home, ".claude");
  const dirs = options.reuse?.dirs ?? { ...base, workspace, projects: path.join(workspace, "projects") };
  if (!options.reuse) {
    for (const dir of Object.values(base)) fs.mkdirSync(dir);
    fs.mkdirSync(dirs.projects, { recursive: true });
    options.seed?.(dirs);
  }

  const childEnv: NodeJS.ProcessEnv = {};
  for (const key of ALLOWED_ENV_KEYS) {
    if (process.env[key] !== undefined) childEnv[key] = process.env[key];
  }
  if (options.fakeGitBin) childEnv.PATH = `${options.fakeGitBin}${path.delimiter}${childEnv.PATH ?? ""}`;
  Object.assign(childEnv, {
    HOME: dirs.home,
    TMPDIR: dirs.tmp,
    PORT: String(port),
    HOST: "127.0.0.1",
    API_KEYS: `proc:${GATEWAY_API_KEY}`,
    SESSION_PERSIST_PATH: path.join(dirs.persist, "sessions.json"),
    TOOLS_PERSIST_PATH: path.join(dirs.persist, "tools.json"),
    MCP_SERVERS_PERSIST_PATH: path.join(dirs.persist, "mcp-servers.json"),
    WORKSPACE_ROOT: workspace,
    ...options.env,
  });

  const child = spawn(process.execPath, ["--expose-gc", options.distServer ?? DIST_SERVER], {
    cwd: dirs.cwd,
    env: childEnv,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  child.stdout!.on("data", (data: Buffer) => (output += data.toString("utf8")));
  child.stderr!.on("data", (data: Buffer) => (output += data.toString("utf8")));
  cleanups.push(async () => {
    for (const pid of descendants(child.pid!)) {
      try {
        process.kill(pid, "SIGKILL");
      } catch {
        // Already gone.
      }
    }
    if (child.exitCode === null && child.signalCode === null) {
      const exited = new Promise<void>((resolve) => child.once("exit", () => resolve()));
      child.kill("SIGKILL");
      await exited;
    }
    if (!options.reuse) fs.rmSync(root, { recursive: true, force: true });
  });

  const started = Date.now();
  for (;;) {
    if (child.exitCode !== null) throw new Error(`gateway exited early: ${output}`);
    if ((await getHealth(port)).status === 200) break;
    if (Date.now() - started > 15_000) throw new Error(`gateway not ready: ${output}`);
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  return { child, port, root, dirs, output: () => output };
}

/** GET /health; status 0 when the connection failed. */
export function getHealth(port: number): Promise<{ status: number; ms: number }> {
  const started = performance.now();
  return new Promise((resolve) => {
    const probe = http.get({ host: "127.0.0.1", port, path: "/health", agent: false }, (res) => {
      res.resume();
      res.on("end", () => resolve({ status: res.statusCode ?? 0, ms: performance.now() - started }));
    });
    probe.on("error", () => resolve({ status: 0, ms: performance.now() - started }));
  });
}

/** An authenticated JSON request to the spawned gateway. */
export function gatewayRequest(
  port: number,
  method: string,
  urlPath: string,
  body?: unknown,
): Promise<{ status: number; text: string; json: Record<string, unknown> | null }> {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body), "utf8");
    const req = http.request(
      {
        host: "127.0.0.1",
        port,
        method,
        path: urlPath,
        agent: false,
        headers: {
          Authorization: `Bearer ${GATEWAY_API_KEY}`,
          ...(payload ? { "Content-Type": "application/json", "Content-Length": payload.length } : {}),
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          let json: Record<string, unknown> | null = null;
          try {
            json = JSON.parse(text) as Record<string, unknown>;
          } catch {
            // Not JSON.
          }
          resolve({ status: res.statusCode ?? 0, text, json });
        });
      },
    );
    req.on("error", reject);
    req.end(payload);
  });
}
