/**
 * Descriptor evidence for the sandbox process tests (MVP-7991): one reader, one redactor, one checker and one
 * test-owned bwrap wrapper with exec-transparent recorders, shared by every descriptor row.
 *
 * Observation points (a capture is `valid` only when it was read and is not empty; an unreadable or empty capture
 * is "missing", never "absent"):
 *   O1  the test process's own table, right after `spawnHook()` returned
 *   O2  sandbox entry: the first in-sandbox process, before the launch wrapper (the recorder wrapper below)
 *   O3  the probe shell's own table, its first statement
 *   O4  the Python listing of the probe
 *   O5  right after the launch wrapper, before the runtime command (the recorder wrapper below)
 * The outer bwrap's own table is never evidence: it closes extra descriptors right after its fork while the
 * sandbox still receives them.
 *
 * Nothing here prints file contents, argument vectors or environments, only descriptor numbers, redacted link
 * targets and open flags.
 */
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

export interface FdEntry {
  fd: number;
  /** The raw link target (never printed without `redactTarget`). */
  target: string;
  /** `fdinfo` flags, octal text; null when unreadable. */
  flags: string | null;
}

export interface FdTable {
  point: string;
  /** Read and not empty. */
  valid: boolean;
  entries: FdEntry[];
  /** Why the capture is missing, when it is. */
  reason?: string;
}

export interface RedactContext {
  /** Prefixes that become `<tmp>` (the test tmp root, os.tmpdir()). */
  tmpRoots: string[];
  /** Prefixes that become `<home>`. */
  homes: string[];
  /** Every identifiable value that must never appear (synthetic secrets, descriptor markers). */
  markers: string[];
}

const O_CLOEXEC = 0o2000000;

export function isCloseOnExec(flags: string | null): boolean | null {
  if (flags === null || !/^[0-7]+$/.test(flags)) return null;
  return (parseInt(flags, 8) & O_CLOEXEC) !== 0;
}

/** Replaces markers, run tokens and URL credentials in any evidence line. */
export function redactText(text: string, ctx: RedactContext): string {
  let out = text;
  for (const marker of ctx.markers) if (marker.length > 0) out = out.split(marker).join("<redacted>");
  out = out.replace(/mpt_[A-Za-z0-9_-]+/g, "<redacted>");
  out = out.replace(/(\/\/)[^/@\s]*@/g, "$1<redacted>@");
  out = out.replace(/(\?)[^\s)]*/g, "$1<redacted>");
  return out;
}

const KEPT_SHAPES = [/^pipe:\[\d+\]$/, /^socket:\[\d+\]$/, /^anon_inode:\[?[A-Za-z0-9_-]+\]?$/, /^\/dev\/null$/, /^\/dev\/pts\/\d+$/, /^\/dev\/(?:zero|urandom|random|tty)$/];

function replacePrefix(value: string, prefixes: string[], token: string): string {
  for (const prefix of prefixes) {
    const clean = prefix.replace(/\/+$/, "");
    if (clean.length > 1 && (value === clean || value.startsWith(`${clean}/`))) return token + value.slice(clean.length);
  }
  return value;
}

/** A link target as it may be printed: a kept shape, or a path with its prefix and session names replaced, or a class token. */
export function redactTarget(target: string, ctx: RedactContext): string {
  let value = target;
  let deleted = false;
  if (value.endsWith(" (deleted)")) {
    deleted = true;
    value = value.slice(0, -" (deleted)".length);
  }
  const flag = deleted ? " (deleted)" : "";
  if (value.startsWith("memfd:")) return `memfd:<redacted>${flag}`;
  value = redactText(value, ctx);
  if (!deleted && KEPT_SHAPES.some((shape) => shape.test(value))) return value;
  // The more specific prefix first: a home usually lives below a tmp root.
  value = replacePrefix(value, ctx.homes, "<home>");
  value = replacePrefix(value, ctx.tmpRoots, "<tmp>");
  value = value.replace(/\/sessions\/[0-9a-f]{16,}/g, "/sessions/<session>");
  if (/^<(tmp|home)>(\/|$)/.test(value) || /^<redacted>$/.test(value)) return `${value}${flag}`;
  if (/^\/(usr|lib|lib64|bin|sbin|etc)(\/|$)/.test(value)) return `<path:system>${flag}`;
  if (/^\/proc(\/|$)/.test(value)) return `<path:proc>${flag}`;
  if (value.startsWith("/")) return `<path:other>${flag}`;
  return `<other>${flag}`;
}

function readFlags(fdinfo: string): string | null {
  try {
    const line = fs.readFileSync(fdinfo, "utf8").split("\n").find((l) => l.startsWith("flags:"));
    return line ? (line.split(/\s+/)[1] ?? null) : null;
  } catch {
    return null;
  }
}

/** The own table of a process (`self` or a pid): targets and flags. The directory descriptor of this very listing is dropped. */
export function readFdTable(point: string, pid: number | "self" = "self"): FdTable {
  const base = `/proc/${pid}`;
  let names: string[];
  try {
    names = fs.readdirSync(`${base}/fd`).filter((n) => /^\d+$/.test(n));
  } catch (error) {
    return { point, valid: false, entries: [], reason: `unreadable: ${(error as NodeJS.ErrnoException).code ?? "error"}` };
  }
  const entries: FdEntry[] = [];
  for (const name of names.sort((a, b) => Number(a) - Number(b))) {
    let target: string;
    try {
      target = fs.readlinkSync(`${base}/fd/${name}`);
    } catch {
      continue;
    }
    // The listing's own directory descriptor, and nothing else, points at the fd directory itself.
    if (pid === "self" && /^\/proc\/\d+\/fd$/.test(target)) continue;
    entries.push({ fd: Number(name), target, flags: readFlags(`${base}/fdinfo/${name}`) });
  }
  return entries.length === 0 ? { point, valid: false, entries, reason: "empty" } : { point, valid: true, entries };
}

/**
 * Parses `FDREC <point> <fd> <flags|-> <target>` lines (printed by the in-sandbox probes); a point with no line is
 * missing, not absent.
 */
export function parseFdRecords(text: string, point: string): FdTable {
  const entries: FdEntry[] = [];
  for (const line of text.split("\n")) {
    const m = /^FDREC (\S+) (\d+) (\S+) (.*)$/.exec(line.replace(/\r$/, ""));
    if (!m || m[1] !== point) continue;
    entries.push({ fd: Number(m[2]), target: m[4], flags: m[3] === "-" ? null : m[3] });
  }
  return entries.length === 0 ? { point, valid: false, entries, reason: "no FDREC line" } : { point, valid: true, entries };
}

export interface FdCheck {
  ok: boolean;
  /** Descriptors beyond the allowed ones. */
  extra: FdEntry[];
  /** The failure text: names every unexpected descriptor with its redacted target and flags. */
  message: string;
}

/** The one checker of every descriptor row. */
export function checkDescriptors(table: FdTable, ctx: RedactContext, allowed: number[] = [0, 1, 2]): FdCheck {
  if (!table.valid) return { ok: false, extra: [], message: `descriptor capture ${table.point} is missing (${table.reason ?? "invalid"}); a missing capture proves nothing` };
  const extra = table.entries.filter((e) => !allowed.includes(e.fd));
  if (extra.length === 0) return { ok: true, extra, message: `${table.point}: ${table.entries.map((e) => e.fd).join(" ")}` };
  const named = extra.map((e) => `${e.fd} -> ${redactTarget(e.target, ctx)} (flags ${e.flags ?? "unknown"}, close-on-exec ${closeOnExecText(e.flags)})`);
  return { ok: false, extra, message: `unexpected inherited descriptor(s) at ${table.point}: ${named.join("; ")}; expected only ${allowed.join(" ")}` };
}

function closeOnExecText(flags: string | null): string {
  const c = isCloseOnExec(flags);
  return c === null ? "unknown" : c ? "yes" : "no";
}

/** `FD-EVIDENCE` lines for one capture, redacted. */
export function evidenceLines(table: FdTable, ctx: RedactContext): string[] {
  if (!table.valid) return [`FD-EVIDENCE ${table.point} valid=no reason=${table.reason ?? "invalid"}`];
  return [
    `FD-EVIDENCE ${table.point} valid=yes fds=${table.entries.map((e) => e.fd).join(",")}`,
    ...table.entries.map((e) => `FD-EVIDENCE ${table.point} fd=${e.fd} target=${redactTarget(e.target, ctx)} flags=${e.flags ?? "unknown"} cloexec=${closeOnExecText(e.flags)}`),
  ];
}

const KIND_ID = /^(pipe|socket):\[\d+\]$/;

/**
 * Which processes hold the same pipe or socket as an extra descriptor: the test process's own table (O1) and every
 * process of this uid on the host. Printed as `comm` and pid only.
 */
export function crossReference(extra: FdEntry[], own: FdTable | null, ownPid: number): string[] {
  const wanted = new Map<string, number[]>();
  for (const e of extra) if (KIND_ID.test(e.target)) wanted.set(e.target, [...(wanted.get(e.target) ?? []), e.fd]);
  const lines: string[] = [];
  for (const [target, fds] of wanted) {
    const holders: string[] = [];
    if (own?.entries.some((e) => e.target === target)) holders.push(`test-process(${ownPid})`);
    for (const pid of fs.readdirSync("/proc").filter((n) => /^\d+$/.test(n))) {
      if (Number(pid) === ownPid) continue;
      let found = false;
      try {
        for (const name of fs.readdirSync(`/proc/${pid}/fd`)) {
          try {
            if (fs.readlinkSync(`/proc/${pid}/fd/${name}`) === target) {
              found = true;
              break;
            }
          } catch {
            // The descriptor closed while reading.
          }
        }
      } catch {
        continue;
      }
      if (found) {
        let comm = "unreadable";
        try {
          comm = fs.readFileSync(`/proc/${pid}/comm`, "utf8").trim();
        } catch {
          // Gone.
        }
        holders.push(`${comm}(${pid})`);
      }
    }
    lines.push(`FD-EVIDENCE xref fd=${fds.join(",")} kind=${target.split(":")[0]} holders=${holders.length === 0 ? "none" : holders.join(",")}`);
  }
  return lines;
}

/** One summary line per run: descriptor numbers per observation point (numbers only), `missing` for a capture that was not valid. */
export function summaryLine(tables: (FdTable | null)[], extra: Record<string, string> = {}): string {
  const parts = Object.entries(extra).map(([k, v]) => `${k}=${v}`);
  for (const t of tables) if (t) parts.push(`${t.point}=${t.valid ? t.entries.map((e) => e.fd).join(",") : "missing"}`);
  return `FD-EVIDENCE summary ${parts.join(" ")}`;
}

/** Writes evidence lines to stderr (vitest swallows `console.log` of passing tests). */
export function emitEvidence(lines: string[]): void {
  for (const line of lines) process.stderr.write(`${line}\n`);
}

/* ------------------------------------------------------------------ */
/*  The recorder and its bwrap wrapper                                  */
/* ------------------------------------------------------------------ */

/**
 * Exec-transparent recorder (Python): lists its own descriptors with targets and flags, writes them to a JSON file,
 * closes that file, lists again to prove it holds no descriptor of its own that would survive the exec (everything
 * Python opens is close-on-exec), and execs the rest of its command line with its original environment (read from
 * `/proc/self/environ`, so Python's locale coercion cannot leak into the next program).
 */
export const RECORDER_PY = String.raw`import json, os, shutil, sys, time

out_path, point, command = sys.argv[1], sys.argv[2], sys.argv[3:]

def snapshot():
    names = sorted((n for n in os.listdir("/proc/self/fd") if n.isdigit()), key=int)
    rows = []
    for n in names:
        try:
            rows.append({"fd": int(n), "target": os.readlink("/proc/self/fd/" + n)})
        except OSError:
            continue
    for row in rows:
        flags = None
        try:
            handle = os.open("/proc/self/fdinfo/%d" % row["fd"], os.O_RDONLY)
            try:
                text = os.read(handle, 4096).decode("latin1")
            finally:
                os.close(handle)
            for line in text.split("\n"):
                if line.startswith("flags:"):
                    flags = line.split()[1]
        except OSError:
            pass
        row["flags"] = flags
    return rows

def survivors(rows):
    return sorted(r["fd"] for r in rows if r["flags"] is not None and not (int(r["flags"], 8) & 0o2000000))

rows = snapshot()
# What the sandbox's init (process 1) holds: link targets only.
pid1 = []
try:
    for n in os.listdir("/proc/1/fd"):
        try:
            pid1.append(os.readlink("/proc/1/fd/" + n))
        except OSError:
            pass
except OSError:
    pid1 = None
# One file per launch (a gateway also starts a boot self-check through the same wrapper); "runtime" marks the start of the agent runtime.
out_path = "%s.%d.json" % (out_path, time.time_ns())
runtime = any(arg.endswith("cli.js") or arg.endswith("/claude") for arg in command)
with open(out_path, "w") as handle:
    json.dump({"point": point, "runtime": runtime, "entries": rows, "pid1": pid1}, handle)
after = survivors(snapshot())
with open(out_path + ".exec", "w") as handle:
    json.dump({"survivors": after}, handle)

raw = open("/proc/self/environ", "rb").read()
env = {}
for item in raw.split(b"\0"):
    if b"=" in item:
        key, value = item.split(b"=", 1)
        env[os.fsdecode(key)] = os.fsdecode(value)
program = command[0] if "/" in command[0] else shutil.which(command[0], path=env.get("PATH", "/usr/bin:/bin"))
if program is None:
    sys.stderr.write("fd-recorder: command not found\n")
    os._exit(127)
os.execve(program, command, env)
`;

export interface RecorderWrapperOptions {
  /** Directory the test owns: holds the recorder, the wrapper and the evidence files. */
  dir: string;
  /** Insert a recorder at sandbox entry, before the launch wrapper (O2). */
  entry?: boolean;
  /** Insert a recorder right after the launch wrapper, before the runtime command (O5). */
  start?: boolean;
  /** Descriptors the wrapper holds open (non-close-on-exec) while it execs bwrap, one per entry. */
  markers?: { fd: number; file: string }[];
  /** Replace whole elements of the post-`--` argument vector (the negative control substitutes the pre-fix wrapper text, another row a missing interpreter). */
  replace?: { from: string; to: string }[];
  /** Extra bwrap options, appended after the launcher's (e.g. a tmpfs over a directory the sandbox needs to be missing). */
  extraArgs?: string[];
  /** Prefix of the evidence file names. */
  name?: string;
}

export interface RecorderWrapper {
  /** The executable to use as `config.bwrapPath`. */
  bwrapPath: string;
  /** Every capture of one observation point so far, oldest first (a gateway also starts a boot self-check through the wrapper). */
  captures: (point: "O2" | "O5") => RecorderCapture[];
}

export interface RecorderCapture {
  table: FdTable;
  /** Descriptors that survive the recorder's exec (no close-on-exec flag), read after it closed its evidence file; null when unreadable. */
  survivors: number[] | null;
  /** The command that follows names the agent runtime (`cli.js` or native `claude`). */
  runtime: boolean;
  /** Link targets of the sandbox init's descriptors (`/proc/1/fd`), null when unreadable. */
  pid1: string[] | null;
}

const SANDBOX_EVIDENCE_DIR = "/fd-evidence";

function shQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

/**
 * A test-owned bwrap wrapper. The wrapper is bash and adds no descriptor of its own (no process or command
 * substitution); it execs the real bwrap with the post-`--` argument vector rewritten.
 */
export function writeRecorderWrapper(options: RecorderWrapperOptions): RecorderWrapper {
  const name = options.name ?? "fd";
  fs.mkdirSync(options.dir, { recursive: true });
  const recorder = path.join(options.dir, "fd-recorder.py");
  fs.writeFileSync(recorder, RECORDER_PY);
  const markerOpens = (options.markers ?? []).map((m) => `exec ${m.fd}<${shQuote(m.file)}`).join("\n");
  const replacements = (options.replace ?? []).map(
    (r) => `for i in "\${!post[@]}"; do if [ "\${post[$i]}" = ${shQuote(r.from)} ]; then post[$i]=${shQuote(r.to)}; fi; done`,
  );
  const python = `/usr/bin/python3 -I -S ${SANDBOX_EVIDENCE_DIR}/fd-recorder.py`;
  const lines = [
    // Privileged mode: a hostile server environment (BASH_ENV, exported functions, SHELLOPTS) must not change this helper either.
    "#!/bin/bash -p",
    markerOpens,
    "pre=()",
    'while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do pre+=("$1"); shift; done',
    "shift",
    'post=("$@")',
    ...replacements,
    `mounts=(--ro-bind ${shQuote(recorder)} ${SANDBOX_EVIDENCE_DIR}/fd-recorder.py --bind ${shQuote(options.dir)} ${SANDBOX_EVIDENCE_DIR}/out${(options.extraArgs ?? []).map((a) => ` ${shQuote(a)}`).join("")})`,
    'idx=-1; for i in "${!post[@]}"; do if [ "${post[$i]}" = sandbox ]; then idx=$i; break; fi; done',
    options.start ? `if [ "$idx" -ge 0 ]; then post=("\${post[@]:0:$((idx+1))}" ${python} ${SANDBOX_EVIDENCE_DIR}/out/${name}-O5 O5 "\${post[@]:$((idx+1))}"); fi` : "",
    options.entry
      ? `exec /usr/bin/bwrap "\${pre[@]}" "\${mounts[@]}" -- ${python} ${SANDBOX_EVIDENCE_DIR}/out/${name}-O2 O2 "\${post[@]}"`
      : `exec /usr/bin/bwrap "\${pre[@]}" "\${mounts[@]}" -- "\${post[@]}"`,
    "",
  ];
  const script = path.join(options.dir, `${name}-bwrap.sh`);
  fs.writeFileSync(script, lines.filter((l) => l !== "").join("\n") + "\n", { mode: 0o755 });
  const captures = (point: "O2" | "O5"): RecorderCapture[] =>
    fs
      .readdirSync(options.dir)
      .filter((f) => new RegExp(`^${name}-${point}\\.\\d+\\.json$`).test(f))
      .sort((x, y) => Number(x.split(".")[1]) - Number(y.split(".")[1]))
      .map((f) => readRecorderFile(point, path.join(options.dir, f)));
  return { bwrapPath: script, captures };
}

/** One recorder capture file; missing or empty means not valid. */
export function readRecorderFile(point: string, file: string): RecorderCapture {
  let table: FdTable;
  let runtime = false;
  let pid1: string[] | null = null;
  try {
    const parsed = JSON.parse(fs.readFileSync(file, "utf8")) as { entries: FdEntry[]; runtime?: boolean; pid1?: string[] | null };
    runtime = parsed.runtime === true;
    pid1 = parsed.pid1 ?? null;
    table = parsed.entries.length === 0 ? { point, valid: false, entries: [], reason: "empty" } : { point, valid: true, entries: parsed.entries };
  } catch {
    table = { point, valid: false, entries: [], reason: "no recorder file" };
  }
  let survivors: number[] | null = null;
  try {
    survivors = (JSON.parse(fs.readFileSync(`${file}.exec`, "utf8")) as { survivors: number[] }).survivors;
  } catch {
    survivors = null;
  }
  return { table, survivors, runtime, pid1 };
}

/** The table a program would inherit across exec from the recorder's capture: the descriptors without the close-on-exec flag, minus the recorder's own listing directory. */
export function inheritedAtExec(table: FdTable): FdTable {
  return { ...table, entries: table.entries.filter((e) => isCloseOnExec(e.flags) === false) };
}

/** True when `python3` exists on this host (the recorder needs it inside the sandbox, which binds the host `/usr`). */
export function recorderAvailable(): boolean {
  try {
    execFileSync("/usr/bin/python3", ["-c", "pass"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}
