/**
 * A `git` wrapper for tests. `createFakeGit()` writes an executable `git` into a
 * test-owned bin directory; put that directory first on PATH and the gateway
 * runs the wrapper instead of git. The wrapper
 *
 * - appends one `start` and one `end` line per invocation to its log (single
 *   short appends, so concurrent invocations do not interleave within a line):
 *   `start|end <TAB> pid <TAB> epoch ms <TAB> cwd <TAB> argv joined by \x1f`
 *   (the end line carries the exit code as a sixth field);
 * - optionally sleeps before running git, when the invocation matches the
 *   control file. The sleep runs in a background grandchild that inherits
 *   stdout/stderr and the wrapper waits for it, so killing only the wrapper
 *   leaves the pipes held open (a process-group kill ends both);
 * - then runs the real git (resolved by absolute path when the helper is
 *   created) with the unchanged arguments.
 *
 * Git invocations started by git itself (FAKE_GIT_NESTED set) go straight to the
 * real git without logging or sleeping.
 */
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

export interface FakeGitInvocation {
  pid: number;
  start: number;
  /** Undefined while the invocation is still running (or was killed before its end line). */
  end?: number;
  exitCode?: number;
  cwd: string;
  argv: string[];
  /** First argument that is not an option, e.g. "clone". */
  subcommand: string;
}

export interface SlowRule {
  /** Milliseconds to sleep before running git. */
  sleepMs: number;
  /** Subcommands that sleep, e.g. ["clone", "pull"]. Empty: every subcommand. */
  on?: string[];
  /** Only invocations whose "cwd argv..." text contains this substring sleep. */
  match?: string;
}

export interface FakeGit {
  /** Directory to put first on PATH. */
  binDir: string;
  /** Absolute path of the real git. */
  realGit: string;
  logFile: string;
  /** Replace the sleep rule; `null` turns sleeping off. Applies to invocations that start afterwards. */
  setSlow: (rule: SlowRule | null) => void;
  invocations: () => FakeGitInvocation[];
  /** Forget all logged invocations. */
  clearLog: () => void;
  /** Highest number of wrapper invocations that ran at the same moment. */
  maxOverlap: (filter?: (inv: FakeGitInvocation) => boolean) => number;
  /** Resolves once an invocation matching `filter` has started. */
  waitForStart: (filter: (inv: FakeGitInvocation) => boolean, timeoutMs?: number) => Promise<FakeGitInvocation>;
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function resolveRealGit(): string {
  const found = execFileSync("sh", ["-c", "command -v git"], { encoding: "utf8" }).trim();
  if (!found || !path.isAbsolute(found)) throw new Error("real git not found on PATH");
  return fs.realpathSync(found);
}

export function createFakeGit(root: string): FakeGit {
  const binDir = path.join(root, "fake-git-bin");
  fs.mkdirSync(binDir, { recursive: true });
  const logFile = path.join(root, "fake-git.log");
  const controlFile = path.join(root, "fake-git.control");
  const realGit = resolveRealGit();
  fs.writeFileSync(logFile, "");
  fs.writeFileSync(controlFile, "");

  const script = `#!/bin/sh
REAL_GIT=${shellQuote(realGit)}
if [ -n "$FAKE_GIT_NESTED" ]; then exec "$REAL_GIT" "$@"; fi
FAKE_GIT_NESTED=1
export FAKE_GIT_NESTED
LOG=${shellQuote(logFile)}
sleep_s=""
sleep_on=""
sleep_match=""
. ${shellQuote(controlFile)}
sub=""
for a in "$@"; do
  case "$a" in -*) ;; *) sub="$a"; break ;; esac
done
argv=""
for a in "$@"; do argv="$argv$a$(printf '\\037')"; done
printf 'start\\t%s\\t%s\\t%s\\t%s\\n' "$$" "$(date +%s%3N)" "$PWD" "$argv" >> "$LOG"
if [ -n "$sleep_s" ]; then
  hit=1
  if [ -n "$sleep_on" ]; then
    hit=0
    for s in $sleep_on; do [ "$s" = "$sub" ] && hit=1; done
  fi
  if [ -n "$sleep_match" ]; then
    case "$PWD $*" in *"$sleep_match"*) ;; *) hit=0 ;; esac
  fi
  if [ "$hit" = 1 ]; then
    sleep "$sleep_s" &
    wait $!
  fi
fi
"$REAL_GIT" "$@"
rc=$?
printf 'end\\t%s\\t%s\\t%s\\t%s\\t%s\\n' "$$" "$(date +%s%3N)" "$PWD" "$argv" "$rc" >> "$LOG"
exit $rc
`;
  const gitPath = path.join(binDir, "git");
  fs.writeFileSync(gitPath, script, { mode: 0o755 });

  const invocations = (): FakeGitInvocation[] => {
    const byPid = new Map<number, FakeGitInvocation>();
    const list: FakeGitInvocation[] = [];
    for (const line of fs.readFileSync(logFile, "utf8").split("\n")) {
      if (!line) continue;
      const [kind, pidText, msText, cwd, argvText, rcText] = line.split("\t");
      const pid = Number(pidText);
      if (kind === "start") {
        const argv = (argvText ?? "").split("\x1f").slice(0, -1);
        const inv: FakeGitInvocation = { pid, start: Number(msText), cwd, argv, subcommand: argv.find((a) => !a.startsWith("-")) ?? "" };
        byPid.set(pid, inv);
        list.push(inv);
      } else if (kind === "end") {
        const inv = byPid.get(pid);
        if (inv) {
          inv.end = Number(msText);
          inv.exitCode = Number(rcText);
        }
      }
    }
    return list;
  };

  return {
    binDir,
    realGit,
    logFile,
    setSlow: (rule) => {
      if (!rule) {
        fs.writeFileSync(controlFile, "");
        return;
      }
      const lines = [
        `sleep_s=${shellQuote((rule.sleepMs / 1000).toFixed(3))}`,
        `sleep_on=${shellQuote((rule.on ?? []).join(" "))}`,
        `sleep_match=${shellQuote(rule.match ?? "")}`,
      ];
      fs.writeFileSync(controlFile, lines.join("\n") + "\n");
    },
    invocations,
    clearLog: () => fs.writeFileSync(logFile, ""),
    maxOverlap: (filter) => {
      const events: [number, number][] = [];
      for (const inv of invocations()) {
        if (filter && !filter(inv)) continue;
        events.push([inv.start, 1]);
        events.push([inv.end ?? Number.MAX_SAFE_INTEGER, -1]);
      }
      // An end at the same millisecond as a start counts first: touching is not overlapping.
      events.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
      let running = 0;
      let max = 0;
      for (const [, delta] of events) {
        running += delta;
        max = Math.max(max, running);
      }
      return max;
    },
    waitForStart: async (filter, timeoutMs = 15_000) => {
      const started = Date.now();
      for (;;) {
        const found = invocations().find(filter);
        if (found) return found;
        if (Date.now() - started > timeoutMs) throw new Error(`no matching git invocation started within ${timeoutMs} ms`);
        await new Promise((resolve) => setTimeout(resolve, 20));
      }
    },
  };
}
