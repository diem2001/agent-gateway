/**
 * Process-level proofs for MVP-7616 Gate A: the compiled gateway
 * (`dist/server.js`, built by `npm run build`) runs as a child process with an
 * environment ALLOWLIST and fresh temp directories. Each persistence area gets
 * its own directory, so one area can be damaged or unwritable while the other
 * two keep saving. State files and `.corrupt-*` copies never leave the temp
 * directory.
 *
 * Covers the ticket's outlines "An interrupted write never damages the saved
 * file", "An unreadable file is kept, reported and never overwritten", "An
 * unreadable file that cannot be moved aside is left untouched", "Several
 * damaged areas are all reported", "A failed save is reported until a later
 * save succeeds", a file whose entries cannot be restored (valid JSON, set
 * aside like invalid JSON), and the credential invariant of MVP-7667 for the
 * new ERROR lines and /health fields.
 */
import { spawn, type ChildProcess } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import net, { type AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const here = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(here, "..", "..");
const DIST_SERVER = path.join(REPO_ROOT, "dist", "server.js");

const API_KEY = "proc-gateway-key-7616";
const IS_ROOT = process.getuid?.() === 0;
/** Permission rows need a non-root user: root ignores directory and file modes. */
const skipAsRoot = IS_ROOT ? "skipped: tests run as root, permission-based rows need a non-root user" : "";

type Area = "sessions" | "tools" | "mcpServers";
const AREAS: Area[] = ["sessions", "tools", "mcpServers"];
const FILE_NAME: Record<Area, string> = { sessions: "sessions.json", tools: "tools.json", mcpServers: "mcp-servers.json" };
const ENV_KEY: Record<Area, string> = {
  sessions: "SESSION_PERSIST_PATH",
  tools: "TOOLS_PERSIST_PATH",
  mcpServers: "MCP_SERVERS_PERSIST_PATH",
};

/** A complete earlier state per area, as the gateway itself writes it. */
function earlierState(area: Area): unknown {
  switch (area) {
    case "sessions":
      return {
        sessions: { "earlier-session": { sessionId: "sdk-earlier", systemPrompt: "", model: "m", lastUsed: Date.now() } },
        settings: { sessionIdleTimeoutMs: 0 },
      };
    case "tools":
      return [{ name: "earlier-tool", description: "d", input_schema: { type: "object" }, webhook_url: "http://127.0.0.1:9/hook" }];
    case "mcpServers":
      return [
        {
          name: "earlier-mcp",
          description: "",
          enabled: true,
          type: "http",
          url: "http://127.0.0.1:9/mcp",
          createdAt: "2026-09-25T00:00:00.000Z",
          updatedAt: "2026-09-25T00:00:00.000Z",
        },
      ];
  }
}

/** Fails loudly when dist/ is missing or older than src/ (run `npm run build`). */
function assertFreshBuild(): void {
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

/** Environment ALLOWLIST for spawned processes. Never turn this into a denylist. */
const ALLOWED_ENV_KEYS = ["PATH", "LANG"] as const;

interface Fixture {
  root: string;
  home: string;
  dirs: Record<Area, string>;
  file: (area: Area) => string;
  env: () => NodeJS.ProcessEnv;
}

interface Gateway {
  child: ChildProcess;
  port: number;
  output: () => string;
}

const cleanups: (() => Promise<void> | void)[] = [];

afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()!();
});

function fixture(): Fixture {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "mvp7616-persist-"));
  const home = path.join(root, "home");
  const tmp = path.join(root, "tmp");
  fs.mkdirSync(home);
  fs.mkdirSync(tmp);
  const dirs = {} as Record<Area, string>;
  for (const area of AREAS) {
    dirs[area] = path.join(root, `persist-${area}`);
    fs.mkdirSync(dirs[area]);
  }
  cleanups.push(() => {
    // Restore modes the tests removed, so the whole tree can be deleted.
    for (const entry of fs.readdirSync(root, { recursive: true, withFileTypes: true })) {
      try {
        fs.chmodSync(path.join(entry.parentPath, entry.name), entry.isDirectory() ? 0o755 : 0o600);
      } catch {
        // gone already
      }
    }
    for (const dir of Object.values(dirs)) fs.chmodSync(dir, 0o755);
    fs.rmSync(root, { recursive: true, force: true });
  });
  const file = (area: Area) => path.join(dirs[area], FILE_NAME[area]);
  const env = () => {
    const childEnv: NodeJS.ProcessEnv = {};
    for (const key of ALLOWED_ENV_KEYS) {
      if (process.env[key] !== undefined) childEnv[key] = process.env[key];
    }
    Object.assign(childEnv, {
      HOME: home,
      TMPDIR: tmp,
      API_KEYS: `proc:${API_KEY}`,
      WORKSPACE_ROOT: path.join(home, ".claude"),
    });
    for (const area of AREAS) childEnv[ENV_KEY[area]] = file(area);
    return childEnv;
  };
  return { root, home, dirs, file, env };
}

async function freePort(): Promise<number> {
  const server = net.createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const { port } = server.address() as AddressInfo;
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
}

async function startGateway(fx: Fixture): Promise<Gateway> {
  assertFreshBuild();
  const port = await freePort();
  const child = spawn(process.execPath, ["--expose-gc", DIST_SERVER], {
    cwd: fx.root,
    env: { ...fx.env(), PORT: String(port), HOST: "127.0.0.1" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  child.stdout!.on("data", (data: Buffer) => (output += data.toString("utf8")));
  child.stderr!.on("data", (data: Buffer) => (output += data.toString("utf8")));
  const gateway = { child, port, output: () => output };
  cleanups.push(() => kill(gateway));

  const started = Date.now();
  for (;;) {
    if (child.exitCode !== null) throw new Error(`gateway exited early: ${output}`);
    if ((await request(port, "GET", "/health").catch(() => null))?.status === 200) break;
    if (Date.now() - started > 15_000) throw new Error(`gateway not ready: ${output}`);
    await delay(50);
  }
  return gateway;
}

/** A hard kill, as today's `docker stop` ends. Only after saves have landed. */
async function kill(gateway: Gateway): Promise<void> {
  const { child } = gateway;
  if (child.exitCode !== null || child.signalCode !== null) return;
  const exited = new Promise<void>((resolve) => child.once("exit", () => resolve()));
  child.kill("SIGKILL");
  await exited;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function request(port: number, method: string, urlPath: string, body?: unknown): Promise<{ status: number; text: string; json: () => any }> {
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
          Authorization: `Bearer ${API_KEY}`,
          ...(payload ? { "Content-Type": "application/json", "Content-Length": payload.length } : {}),
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          resolve({ status: res.statusCode ?? 0, text, json: () => JSON.parse(text) });
        });
      },
    );
    req.on("error", reject);
    req.end(payload);
  });
}

/** One API change in the area; resolves after the 100 ms debounced save had time to land. */
async function changeArea(gateway: Gateway, area: Area, tag: string): Promise<void> {
  let reply;
  switch (area) {
    case "sessions":
      reply = await request(gateway.port, "PUT", "/v1/settings", { sessionIdleTimeoutMs: tagNumber(tag) });
      break;
    case "tools":
      reply = await request(gateway.port, "PUT", `/v1/tools/tool-${tag}`, {
        description: "d",
        input_schema: { type: "object" },
        webhook_url: "http://127.0.0.1:9/hook",
      });
      break;
    case "mcpServers":
      reply = await request(gateway.port, "PUT", `/v1/mcp-servers/mcp-${tag}`, { type: "http", url: "http://127.0.0.1:9/mcp" });
      break;
  }
  expect([200, 201]).toContain(reply.status);
  await delay(300);
}

/** A distinct idle-timeout value per tag, so a settings change is visible in sessions.json. */
function tagNumber(tag: string): number {
  return 100_000 + [...tag].reduce((sum, ch) => sum * 31 + ch.charCodeAt(0), 7) % 800_000;
}

/** Whether the saved file holds the change made by changeArea(tag). */
function fileHoldsChange(file: string, area: Area, tag: string): boolean {
  const data = JSON.parse(fs.readFileSync(file, "utf8"));
  switch (area) {
    case "sessions":
      return data.settings?.sessionIdleTimeoutMs === tagNumber(tag);
    case "tools":
      return data.some((t: { name: string }) => t.name === `tool-${tag}`);
    case "mcpServers":
      return data.some((s: { name: string }) => s.name === `mcp-${tag}`);
  }
}

/** Names the running gateway reports for the area (sessions: ids; settings are checked via the file). */
async function listNames(gateway: Gateway, area: Area): Promise<string[]> {
  switch (area) {
    case "sessions":
      return (await request(gateway.port, "GET", "/v1/sessions")).json().sessions.map((s: { id: string }) => s.id);
    case "tools":
      return (await request(gateway.port, "GET", "/v1/tools")).json().tools.map((t: { name: string }) => t.name);
    case "mcpServers":
      return (await request(gateway.port, "GET", "/v1/mcp-servers")).json().servers.map((s: { name: string }) => s.name);
  }
}

const EARLIER_NAME: Record<Area, string> = { sessions: "earlier-session", tools: "earlier-tool", mcpServers: "earlier-mcp" };

async function health(gateway: Gateway) {
  const reply = await request(gateway.port, "GET", "/health");
  expect(reply.status).toBe(200);
  const body = reply.json();
  // The four existing fields stay as they were.
  expect(body.status).toBe("ok");
  expect(typeof body.version).toBe("string");
  expect(typeof body.uptime).toBe("number");
  expect(typeof body.sessions).toBe("number");
  return body as {
    persistence: "ok" | "degraded";
    persistenceIssues: { area: Area; problem: string; file: string; preservedAs?: string[] }[];
  };
}

function corruptCopies(fx: Fixture, area: Area): string[] {
  const prefix = `${FILE_NAME[area]}.corrupt-`;
  return fs
    .readdirSync(fx.dirs[area])
    .filter((n) => n.startsWith(prefix))
    .map((n) => path.join(fx.dirs[area], n));
}

function errorLines(output: string): string[] {
  return output.split("\n").filter((l) => l.startsWith("ERROR persistence "));
}

/* ------------------------------------------------------------------ */
/*  An interrupted write never damages the saved file                   */
/* ------------------------------------------------------------------ */

const KILL_BEFORE_RENAME = `
import fs from "node:fs";
const area = process.env.AREA;
const url = (name) => new URL(name, process.env.DIST_URL).href;
let flush;
if (area === "sessions") {
  const m = await import(url("sessions.js"));
  m.loadSessions();
  m.updateSettings({ sessionIdleTimeoutMs: 424242 });
  flush = m.flushSessions;
} else if (area === "tools") {
  const m = await import(url("tools.js"));
  m.loadTools();
  m.registerTool({ name: "never-saved", description: "d", input_schema: { type: "object" }, webhook_url: "http://127.0.0.1:9/x" });
  flush = m.flushTools;
} else {
  const m = await import(url("mcp-registry.js"));
  m.loadMcpServers();
  m.registerMcpServer({ name: "never-saved", description: "", enabled: true, type: "http", url: "http://127.0.0.1:9/m", createdAt: "x", updatedAt: "x" });
  flush = m.flushMcpServers;
}
// The process dies after the new content is in the temp file, before the rename.
fs.renameSync = () => { process.kill(process.pid, "SIGKILL"); for (;;) {} };
flush();
`;

describe("An interrupted write never damages the saved file", () => {
  it.each(AREAS)("%s: the earlier complete state survives a kill between temp write and rename", async (area) => {
    assertFreshBuild();
    const fx = fixture();
    for (const a of AREAS) fs.writeFileSync(fx.file(a), JSON.stringify(earlierState(a), null, 2));
    const before = fs.readFileSync(fx.file(area));

    const child = spawn(process.execPath, ["--input-type=module", "-e", KILL_BEFORE_RENAME], {
      cwd: fx.root,
      env: { ...fx.env(), AREA: area, DIST_URL: pathToFileURL(path.join(REPO_ROOT, "dist") + path.sep).href },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let childOutput = "";
    child.stderr!.on("data", (d: Buffer) => (childOutput += d.toString("utf8")));
    const signal = await new Promise<NodeJS.Signals | null>((resolve) => child.once("exit", (_code, sig) => resolve(sig)));
    expect(signal, childOutput).toBe("SIGKILL");

    // The target is byte-identical; the complete new content sits in a private temp file.
    expect(fs.readFileSync(fx.file(area)).equals(before)).toBe(true);
    const temps = fs.readdirSync(fx.dirs[area]).filter((n) => n.startsWith(`${FILE_NAME[area]}.tmp-`));
    expect(temps).toHaveLength(1);
    const temp = path.join(fx.dirs[area], temps[0]);
    expect(fs.statSync(temp).mode & 0o077).toBe(0);
    expect(fs.readFileSync(temp, "utf8")).toMatch(/424242|never-saved/);

    const gateway = await startGateway(fx);
    expect(await listNames(gateway, area)).toContain(EARLIER_NAME[area]);
    expect(await listNames(gateway, area)).not.toContain("never-saved");
    expect((await health(gateway)).persistence).toBe("ok");
    expect(errorLines(gateway.output())).toEqual([]);
    // The start removed the leftover temp file of this area.
    expect(fs.existsSync(temp)).toBe(false);
  }, 60_000);
});

/* ------------------------------------------------------------------ */
/*  An unreadable file is kept, reported and never overwritten          */
/* ------------------------------------------------------------------ */

type Defect = "invalid JSON" | "read error";
const KEPT_ROWS: [Area, Defect][] = AREAS.flatMap((area) => [
  [area, "invalid JSON"],
  [area, "read error"],
] as [Area, Defect][]);

describe("An unreadable file is kept, reported and never overwritten", () => {
  it.each(KEPT_ROWS)("%s, %s", async (area, defect) => {
    const fx = fixture();
    const file = fx.file(area);
    let originalBytes: Buffer;
    if (defect === "invalid JSON") {
      originalBytes = Buffer.from(JSON.stringify(earlierState(area), null, 2).slice(0, 40));
      fs.writeFileSync(file, originalBytes);
    } else if (!IS_ROOT) {
      // EACCES: a complete file the gateway user cannot read.
      originalBytes = Buffer.from(JSON.stringify(earlierState(area), null, 2));
      fs.writeFileSync(file, originalBytes);
      fs.chmodSync(file, 0o000);
    } else {
      // As root, mode 000 is readable; a directory at the path gives EISDIR.
      originalBytes = Buffer.from("inside a directory");
      fs.mkdirSync(file);
      fs.writeFileSync(path.join(file, "entry"), originalBytes);
    }
    const readCopy = (copy: string): Buffer => {
      if (defect === "read error" && IS_ROOT) return fs.readFileSync(path.join(copy, "entry"));
      if (defect === "read error") {
        fs.chmodSync(copy, 0o600);
        try {
          return fs.readFileSync(copy);
        } finally {
          fs.chmodSync(copy, 0o000);
        }
      }
      return fs.readFileSync(copy);
    };

    const first = await startGateway(fx);
    const copies = corruptCopies(fx, area);
    expect(copies).toHaveLength(1);
    const [copy] = copies;
    expect(path.basename(copy)).toMatch(new RegExp(`^${FILE_NAME[area].replace(".", "\\.")}\\.corrupt-\\d{8}T\\d{6}Z$`));
    expect(readCopy(copy).equals(originalBytes)).toBe(true);
    const copyStat = fs.statSync(copy);

    const lines = errorLines(first.output());
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatch(
      new RegExp(`^ERROR persistence area=${area} problem=corrupt-preserved file=${file.replace(/[.]/g, "\\.")} preservedAs=${copy.replace(/[.]/g, "\\.")} reason=(invalid JSON|read error), starting empty`),
    );
    if (defect === "read error") expect(lines[0]).toMatch(/code=(EACCES|EISDIR)/);

    let report = await health(first);
    expect(report.persistence).toBe("degraded");
    expect(report.persistenceIssues).toEqual([{ area, problem: "corrupt-preserved", file, preservedAs: [copy] }]);

    // A save in that area writes a new file and leaves the copy alone.
    await changeArea(first, area, "after-damage");
    expect(fileHoldsChange(file, area, "after-damage")).toBe(true);
    expect(readCopy(copy).equals(originalBytes)).toBe(true);
    await kill(first);

    // Another start with a valid file in place still reports the copy.
    const second = await startGateway(fx);
    report = await health(second);
    expect(report.persistence).toBe("degraded");
    expect(report.persistenceIssues).toEqual([{ area, problem: "corrupt-preserved", file, preservedAs: [copy] }]);
    expect(errorLines(second.output())).toEqual([]);

    // The gateway never modified the copy.
    const after = fs.statSync(copy);
    expect([after.size, after.mtimeMs, after.mode]).toEqual([copyStat.size, copyStat.mtimeMs, copyStat.mode]);
    expect(readCopy(copy).equals(originalBytes)).toBe(true);

    // The operator removes the copy: the next /health is clear, without a restart.
    fs.chmodSync(copy, 0o700);
    fs.rmSync(copy, { recursive: true });
    report = await health(second);
    expect(report.persistenceIssues).toEqual([]);
    expect(report.persistence).toBe("ok");
  }, 90_000);
});

/* ------------------------------------------------------------------ */
/*  An unreadable file that cannot be moved aside is left untouched     */
/* ------------------------------------------------------------------ */

describe.skipIf(IS_ROOT)(`An unreadable file that cannot be moved aside is left untouched ${skipAsRoot}`, () => {
  it.each(AREAS)("%s", async (area) => {
    const fx = fixture();
    const file = fx.file(area);
    const original = Buffer.from("{ this is not json");
    fs.writeFileSync(file, original);
    // The area's directory is read-only: the rename aside fails with EACCES.
    fs.chmodSync(fx.dirs[area], 0o555);

    const gateway = await startGateway(fx);
    const [first] = errorLines(gateway.output());
    expect(first).toBe(
      `ERROR persistence area=${area} problem=unreadable-not-preserved file=${file} reason=invalid JSON, move aside failed, saves suppressed code=EACCES (see /health)`,
    );
    let report = await health(gateway);
    expect(report.persistence).toBe("degraded");
    expect(report.persistenceIssues).toEqual([{ area, problem: "unreadable-not-preserved", file }]);

    // Saves are suppressed even once the directory is writable again.
    fs.chmodSync(fx.dirs[area], 0o755);
    for (const a of AREAS) await changeArea(gateway, a, "while-unreadable");

    expect(fs.readFileSync(file).equals(original)).toBe(true);
    expect(corruptCopies(fx, area)).toEqual([]);
    expect(errorLines(gateway.output()).slice(1)).toEqual([
      `ERROR persistence area=${area} problem=unreadable-not-preserved file=${file} reason=save suppressed, unreadable file was not moved aside (see /health)`,
    ]);
    for (const other of AREAS.filter((a) => a !== area)) {
      expect(fileHoldsChange(fx.file(other), other, "while-unreadable")).toBe(true);
    }
    report = await health(gateway);
    expect(report.persistenceIssues).toEqual([{ area, problem: "unreadable-not-preserved", file }]);
  }, 60_000);
});

/* ------------------------------------------------------------------ */
/*  Several damaged areas are all reported                              */
/* ------------------------------------------------------------------ */

describe("Several damaged areas are all reported", () => {
  it("tools.json and mcp-servers.json both invalid: one entry each", async () => {
    const fx = fixture();
    fs.writeFileSync(fx.file("tools"), "[{");
    fs.writeFileSync(fx.file("mcpServers"), "[{\"name\":");
    const gateway = await startGateway(fx);
    const report = await health(gateway);
    expect(report.persistence).toBe("degraded");
    expect(report.persistenceIssues).toEqual([
      { area: "tools", problem: "corrupt-preserved", file: fx.file("tools"), preservedAs: corruptCopies(fx, "tools") },
      { area: "mcpServers", problem: "corrupt-preserved", file: fx.file("mcpServers"), preservedAs: corruptCopies(fx, "mcpServers") },
    ]);
    expect(errorLines(gateway.output()).map((l) => l.split(" ")[2])).toEqual(["area=tools", "area=mcpServers"]);
  }, 60_000);
});

/* ------------------------------------------------------------------ */
/*  A file with an entry that cannot be restored is kept aside          */
/* ------------------------------------------------------------------ */

/** Valid JSON whose entries the gateway cannot restore; before the fix, rows 1, 3 and 5 stopped start-up. */
const UNRESTORABLE_ROWS: [area: Area, label: string, content: () => unknown][] = [
  ["tools", "null entry", () => [null]],
  ["tools", "entry without name", () => [{ description: "d", input_schema: { type: "object" }, webhook_url: "http://127.0.0.1:9/hook" }]],
  ["mcpServers", "null entry", () => [null]],
  ["mcpServers", "entry without name", () => [{ description: "", enabled: true, type: "http", url: "http://127.0.0.1:9/mcp", createdAt: "x", updatedAt: "x" }]],
  ["sessions", "null session, idle timeout on", () => ({ sessions: { "earlier-session": null }, settings: { sessionIdleTimeoutMs: 60_000 } })],
  [
    "sessions",
    "session without lastUsed, idle timeout on",
    () => ({ sessions: { "earlier-session": { sessionId: "sdk-earlier", systemPrompt: "", model: "m" } }, settings: { sessionIdleTimeoutMs: 60_000 } }),
  ],
];

describe("A file with an entry that cannot be restored is kept aside and the gateway keeps serving", () => {
  it.each(UNRESTORABLE_ROWS)("%s, %s", async (area, _label, content) => {
    const fx = fixture();
    const file = fx.file(area);
    const originalBytes = Buffer.from(JSON.stringify(content(), null, 2));
    fs.writeFileSync(file, originalBytes);
    // A complete entry in another area is still restored.
    const other: Area = area === "tools" ? "mcpServers" : "tools";
    fs.writeFileSync(fx.file(other), JSON.stringify(earlierState(other), null, 2));

    const gateway = await startGateway(fx);
    const copies = corruptCopies(fx, area);
    expect(copies).toHaveLength(1);
    expect(fs.readFileSync(copies[0]).equals(originalBytes)).toBe(true);
    expect(fs.existsSync(file)).toBe(false);

    const lines = errorLines(gateway.output());
    expect(lines).toEqual([
      `ERROR persistence area=${area} problem=corrupt-preserved file=${file} preservedAs=${copies[0]} reason=unexpected content, starting empty (see /health)`,
    ]);

    const report = await health(gateway);
    expect(report.persistence).toBe("degraded");
    expect(report.persistenceIssues).toEqual([{ area, problem: "corrupt-preserved", file, preservedAs: copies }]);

    // The area starts empty, with nothing of the file restored; the other area is intact.
    expect(await listNames(gateway, area)).toEqual([]);
    expect(await listNames(gateway, other)).toEqual([EARLIER_NAME[other]]);

    // The area keeps saving; the copy stays as it was.
    await changeArea(gateway, area, "after-bad-entry");
    expect(fileHoldsChange(file, area, "after-bad-entry")).toBe(true);
    expect(fs.readFileSync(copies[0]).equals(originalBytes)).toBe(true);
  }, 60_000);
});

/* ------------------------------------------------------------------ */
/*  A failed save is reported until a later save succeeds               */
/* ------------------------------------------------------------------ */

describe.skipIf(IS_ROOT)(`A failed save is reported until a later save succeeds ${skipAsRoot}`, () => {
  it.each(AREAS)("%s", async (area) => {
    const fx = fixture();
    for (const a of AREAS) fs.writeFileSync(fx.file(a), JSON.stringify(earlierState(a), null, 2));
    const file = fx.file(area);
    const gateway = await startGateway(fx);
    expect((await health(gateway)).persistence).toBe("ok");
    const before = fs.readFileSync(file);

    // Injected write error: the temp file cannot be created in a read-only directory.
    fs.chmodSync(fx.dirs[area], 0o555);
    await changeArea(gateway, area, "lost-save");
    expect(fs.readFileSync(file).equals(before)).toBe(true);
    expect(() => JSON.parse(fs.readFileSync(file, "utf8"))).not.toThrow();
    expect(errorLines(gateway.output())).toEqual([
      `ERROR persistence area=${area} problem=write-failed file=${file} reason=save failed, previous file kept code=EACCES (see /health)`,
    ]);
    let report = await health(gateway);
    expect(report.persistence).toBe("degraded");
    expect(report.persistenceIssues).toEqual([{ area, problem: "write-failed", file }]);

    // The write error is removed; the next save lands and clears the issue.
    fs.chmodSync(fx.dirs[area], 0o755);
    await changeArea(gateway, area, "later-save");
    expect(fileHoldsChange(file, area, "later-save")).toBe(true);
    expect(fileHoldsChange(file, area, "lost-save")).toBe(area !== "sessions");
    report = await health(gateway);
    expect(report.persistenceIssues).toEqual([]);
    expect(report.persistence).toBe("ok");
  }, 60_000);
});

/* ------------------------------------------------------------------ */
/*  Credential invariant (MVP-7667)                                     */
/* ------------------------------------------------------------------ */

const HEADER_SECRET = "Hx7616qZ-vK3pL9mWr2Tn8Yc4Jb6Ds1Fg";
const ENV_SECRET = "Ex7616wQ-uR5tY2iO9pA3sD7fG1hJ4kLz";

function fragments(value: string, size = 6): string[] {
  const out: string[] = [];
  for (let i = 0; i + size <= value.length; i++) out.push(value.slice(i, i + size));
  return out;
}

describe("Unreadable mcp-servers.json: no credential fragment in logs or /health", () => {
  it.each([
    ["inside a header value", HEADER_SECRET],
    ["inside an env value", ENV_SECRET],
  ])("truncated %s", async (_where, secret) => {
    const fx = fixture();
    const full = JSON.stringify(
      [
        { name: "h", description: "", enabled: true, type: "http", url: "http://127.0.0.1:9/mcp", headers: { Authorization: `Bearer ${HEADER_SECRET}` }, createdAt: "x", updatedAt: "x" },
        { name: "s", description: "", enabled: true, type: "stdio", command: "node", env: { TOKEN: ENV_SECRET }, createdAt: "x", updatedAt: "x" },
      ],
      null,
      2,
    );
    // Cut in the middle of the secret, as a kill mid-write would leave it.
    const cut = full.indexOf(secret) + Math.floor(secret.length / 2);
    const written = full.slice(0, cut);
    fs.writeFileSync(fx.file("mcpServers"), written);
    // Every part of either secret that is in the file.
    const inFile = [HEADER_SECRET, ENV_SECRET]
      .map((s) => (written.includes(s) ? s : s.slice(0, Math.max(0, cut - full.indexOf(s)))))
      .filter((s) => s.length >= 6);
    expect(inFile).toContain(secret.slice(0, Math.floor(secret.length / 2)));

    const gateway = await startGateway(fx);
    const healthText = (await request(gateway.port, "GET", "/health")).text;
    expect(errorLines(gateway.output())).toHaveLength(1);
    expect(healthText).toContain('"problem":"corrupt-preserved"');
    const seen = gateway.output() + healthText;
    for (const fragment of inFile.flatMap((s) => fragments(s))) {
      expect(seen, `fragment ${fragment}`).not.toContain(fragment);
    }
  }, 60_000);
});
