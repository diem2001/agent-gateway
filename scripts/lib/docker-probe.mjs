/**
 * Docker helpers of the Epic Integration Gate (MVP-7677): every container, network, image and temp directory a
 * probe creates carries the probe's prefix and a random suffix, and every mutating docker command refuses a name
 * that does not. The live shared gateway (and any other resource of the host) can therefore not be touched, even by
 * a typo: `docker rm agent-gateway` throws before it runs.
 *
 * Needs `sudo -n docker` and uid 1000 (the container's `node` user must own the mounted home).
 */
import { execFile, execFileSync, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";

/** Throws `host prerequisite missing: <name>` (a probe never skips and never degrades). */
export function requireProbeHost(needs) {
  const missing = (name) => {
    switch (name) {
      case "uid1000":
        return typeof process.getuid !== "function" || process.getuid() !== 1000;
      case "docker":
        try {
          return !/^\d/.test(execFileSync("sudo", ["-n", "docker", "version", "--format", "{{.Server.Version}}"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim());
        } catch {
          return true;
        }
      case "space": {
        const stat = fs.statfsSync(os.tmpdir());
        return stat.bavail * stat.bsize < 2 * 1024 ** 3;
      }
      case "build":
        return !fs.existsSync(new URL("../../dist/server.js", import.meta.url)) || !fs.existsSync(new URL("../../dist/tests/helpers/security-matrix.js", import.meta.url));
      default:
        return false;
    }
  };
  for (const need of needs) if (missing(need)) throw new Error(`host prerequisite missing: ${need}`);
}

export function runText(file, args, options = {}) {
  return new Promise((resolve, reject) => {
    execFile(file, args, { maxBuffer: 256 * 1024 * 1024, ...options }, (error, stdout, stderr) => {
      if (error) {
        error.message = `${file} ${args.join(" ")} failed: ${stderr || error.message}`;
        error.stdout = stdout;
        reject(error);
        return;
      }
      resolve(stdout.trim());
    });
  });
}

export const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** A free TCP port on `host`. */
export async function freePortOn(host) {
  const server = net.createServer();
  await new Promise((resolve) => server.listen(0, host, resolve));
  const { port } = server.address();
  await new Promise((resolve) => server.close(resolve));
  return port;
}

/**
 * The probe's docker session. `names` are derived from `prefix` and a random suffix; `docker()` runs `sudo -n docker`
 * after checking that every resource a mutating subcommand names is one of the probe's own.
 */
export function createDockerSession({ prefix, tagBase }) {
  const rand = randomBytes(4).toString("hex");
  const names = { rand, image: `${tagBase}:${rand}`, network: `${prefix}${rand}-net`, container: `${prefix}${rand}-gw`, ownPrefix: `${prefix}${rand}` };
  const ownedContainers = new Set();
  const tempDirs = [];
  let imageBuilt = false;
  let networkCreated = false;

  const isOwnName = (name) => name.startsWith(names.ownPrefix) || name === names.image || ownedContainers.has(name);

  /** Refuses a mutating command that names anything outside the probe's own resources. */
  function guard(args) {
    const [first, second] = args;
    const need = (value, what) => {
      if (typeof value !== "string" || !isOwnName(value)) throw new Error(`refusing to run docker ${args.slice(0, 3).join(" ")}: ${what} "${value}" is not a resource of this probe (${names.ownPrefix}*)`);
    };
    switch (first) {
      case "run": {
        const nameAt = args.indexOf("--name");
        need(args[nameAt + 1], "container name");
        const netAt = args.indexOf("--network");
        if (netAt >= 0) need(args[netAt + 1], "network");
        // A task-owned container never mounts anything but its own temp directories and never joins the host's namespaces.
        for (let i = 0; i < args.length; i++) {
          if (args[i] === "-v" && !tempDirs.some((dir) => args[i + 1].startsWith(`${dir}:`))) throw new Error(`refusing to mount ${args[i + 1]}: not a temp directory of this probe`);
          if (["--privileged", "--pid=host", "--ipc=host", "--userns=host"].includes(args[i])) throw new Error(`refusing ${args[i]}`);
          if (args[i] === "--network" && args[i + 1] === "host") throw new Error("refusing --network host");
        }
        return;
      }
      case "rm":
      case "stop":
      case "restart":
      case "start":
      case "kill":
        for (const target of args.slice(1).filter((a) => !a.startsWith("-") && !/^\d+$/.test(a))) need(target, "container");
        return;
      case "network":
        if (["create", "rm"].includes(second)) need(args.at(-1), "network");
        return;
      case "image":
        if (second === "rm") need(args.at(-1), "image");
        return;
      case "build": {
        const tagAt = args.indexOf("-t");
        need(args[tagAt + 1], "image tag");
        return;
      }
      default:
    }
  }

  const docker = (...args) => {
    guard(args);
    return runText("sudo", ["-n", "docker", ...args]);
  };

  return {
    names,
    docker,
    tempDir(label) {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), `${names.ownPrefix}-${label}-`));
      tempDirs.push(dir);
      return dir;
    },
    /** The container's complete log: stdout and stderr (the gateway's `logAlways` lines go to stderr). */
    logs(name) {
      return new Promise((resolve) => {
        execFile("sudo", ["-n", "docker", "logs", name], { maxBuffer: 256 * 1024 * 1024 }, (error, stdout, stderr) => resolve(`${stdout}\n${stderr}`));
      });
    },
    ownContainer(id) {
      ownedContainers.add(id);
    },
    build(repoRoot) {
      imageBuilt = true;
      return new Promise((resolve, reject) => {
        guard(["build", "-t", names.image]);
        const child = spawn("sudo", ["-n", "docker", "build", "--progress=plain", "-t", names.image, repoRoot], { stdio: ["ignore", "inherit", "inherit"] });
        child.on("error", reject);
        child.on("exit", (code) => (code === 0 ? resolve() : reject(new Error(`docker build exited ${code}`))));
      });
    },
    async createNetwork() {
      networkCreated = true;
      await docker("network", "create", "--internal", names.network);
      return docker("network", "inspect", names.network, "-f", "{{(index .IPAM.Config 0).Gateway}}");
    },
    async containerIp(id) {
      return docker("inspect", "-f", `{{(index .NetworkSettings.Networks "${names.network}").IPAddress}}`, id);
    },
    /** Removes exactly the probe's own containers, network, image and temp directories; returns what remained afterwards. */
    async cleanup(log = () => {}) {
      for (const id of ownedContainers) await docker("rm", "-f", id).then(() => log(`removed container ${id.slice(0, 12)}`), (e) => log(`container cleanup failed: ${e.message}`));
      if (networkCreated) await docker("network", "rm", names.network).then(() => log(`removed network ${names.network}`), (e) => log(`network cleanup failed: ${e.message}`));
      if (imageBuilt) await docker("image", "rm", names.image).then(() => log(`removed image ${names.image}`), (e) => log(`image cleanup failed: ${e.message}`));
      const tmpRoot = fs.realpathSync(os.tmpdir());
      for (const dir of tempDirs) {
        try {
          const real = fs.realpathSync(dir);
          if (path.dirname(real) === tmpRoot && path.basename(real).startsWith(names.ownPrefix)) fs.rmSync(real, { recursive: true, force: true });
          else log(`not removing ${real}: outside ${tmpRoot} or without the probe prefix`);
        } catch (e) {
          if (e.code !== "ENOENT") log(`temp cleanup failed for ${dir}: ${e.code ?? e.message}`);
        }
      }
      return this.leftovers();
    },
    /** Counts of the probe's resources still present (containers, networks, images, temp directories); all 0 after a clean run. */
    async leftovers() {
      const names1 = async (...args) => (await docker(...args).catch(() => "")).split("\n").filter((line) => line.startsWith(names.ownPrefix) || line === names.image);
      const containers = await names1("ps", "-a", "--format", "{{.Names}}");
      const networks = await names1("network", "ls", "--format", "{{.Name}}");
      const images = await names1("images", "--format", "{{.Repository}}:{{.Tag}}");
      const dirs = fs.readdirSync(os.tmpdir()).filter((entry) => entry.startsWith(names.ownPrefix));
      return { containers: containers.length, networks: networks.length, images: images.length, tempDirs: dirs.length };
    },
  };
}
