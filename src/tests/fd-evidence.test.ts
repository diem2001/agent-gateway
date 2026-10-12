/**
 * The descriptor evidence helper (MVP-7991): the redactor, the checker and the table readers, without a sandbox.
 * Synthetic values only.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { checkDescriptors, evidenceLines, inheritedAtExec, isCloseOnExec, parseFdRecords, readFdTable, redactTarget, redactText, type FdTable, type RedactContext } from "./helpers/fd-evidence.js";

const MARKER = "SYNTH-FD-MARKER-7991";
const TMP = "/tmp/sandbox-proc-abc123";
const ctx: RedactContext = { tmpRoots: [TMP], homes: [`${TMP}/home`], markers: [MARKER] };

describe("redactTarget", () => {
  it("keeps the safe target shapes", () => {
    for (const target of ["pipe:[12345]", "socket:[777]", "anon_inode:[eventpoll]", "anon_inode:inotify", "/dev/null", "/dev/pts/3"]) {
      expect(redactTarget(target, ctx), target).toBe(target);
    }
  });

  it("redacts a path holding a synthetic marker", () => {
    const out = redactTarget(`${TMP}/${MARKER}`, ctx);
    expect(out).toBe("<tmp>/<redacted>");
    expect(out).not.toContain(MARKER);
  });

  it("redacts a run token", () => {
    expect(redactText("run mpt_AbC123-xYz_000 here", ctx)).toBe("run <redacted> here");
    expect(redactTarget(`${TMP}/mpt_AbC123-xYz_000`, ctx)).toBe("<tmp>/<redacted>");
  });

  it("redacts URL userinfo and query", () => {
    const out = redactText("https://x-access-token:SYNTH-CLONE@github.com/acme/repo.git?token=abc&x=1", ctx);
    expect(out).toBe("https://<redacted>@github.com/acme/repo.git?<redacted>");
    expect(out).not.toContain("SYNTH-CLONE");
    expect(out).not.toContain("abc");
  });

  it("redacts a memfd name", () => {
    expect(redactTarget("memfd:secret-name (deleted)", ctx)).toBe("memfd:<redacted> (deleted)");
    expect(redactTarget("memfd:secret-name", ctx)).toBe("memfd:<redacted>");
  });

  it("keeps the deleted flag and redacts its path like any other", () => {
    expect(redactTarget(`${TMP}/${MARKER} (deleted)`, ctx)).toBe("<tmp>/<redacted> (deleted)");
    expect(redactTarget("/srv/private/thing (deleted)", ctx)).toBe("<path:other> (deleted)");
  });

  it("replaces a session directory name", () => {
    const out = redactTarget(`${TMP}/home/.agent-sandbox/sessions/0123456789abcdef01234567/home/x`, ctx);
    expect(out).toBe("<home>/.agent-sandbox/sessions/<session>/home/x");
  });

  it("turns a path outside the known-safe prefixes into a class token", () => {
    expect(redactTarget("/var/lib/secret/db", ctx)).toBe("<path:other>");
    expect(redactTarget("/usr/lib/x86_64-linux-gnu/libc.so.6", ctx)).toBe("<path:system>");
    expect(redactTarget("/proc/123/fd", ctx)).toBe("<path:proc>");
  });
});

describe("checkDescriptors", () => {
  const table = (entries: { fd: number; target: string; flags?: string | null }[]): FdTable => ({ point: "O3", valid: true, entries: entries.map((e) => ({ flags: "0100000", ...e })) });

  it("passes exactly 0 1 2", () => {
    const check = checkDescriptors(table([{ fd: 0, target: "pipe:[1]" }, { fd: 1, target: "pipe:[2]" }, { fd: 2, target: "pipe:[3]" }]), ctx);
    expect(check.ok).toBe(true);
    expect(check.extra).toEqual([]);
  });

  it("names every unexpected descriptor with its redacted target and flags", () => {
    const check = checkDescriptors(
      table([
        { fd: 0, target: "pipe:[1]" },
        { fd: 1, target: "pipe:[2]" },
        { fd: 2, target: "pipe:[3]" },
        { fd: 38, target: `${TMP}/${MARKER}`, flags: "0100000" },
        { fd: 40, target: "pipe:[99]", flags: "02100000" },
      ]),
      ctx,
    );
    expect(check.ok).toBe(false);
    expect(check.extra.map((e) => e.fd)).toEqual([38, 40]);
    expect(check.message).toContain("38 -> <tmp>/<redacted> (flags 0100000, close-on-exec no)");
    expect(check.message).toContain("40 -> pipe:[99] (flags 02100000, close-on-exec yes)");
    expect(check.message).not.toContain(MARKER);
  });

  it("treats a missing capture as a failure, never as absent", () => {
    const check = checkDescriptors({ point: "O2", valid: false, entries: [], reason: "no recorder file" }, ctx);
    expect(check.ok).toBe(false);
    expect(check.message).toContain("missing");
  });
});

describe("tables", () => {
  it("parses FDREC lines of one point only", () => {
    const text = ["noise", "FDREC O3 0 0100002 pipe:[10]", "FDREC O4 0 - pipe:[11]", "FDREC O3 45 0100000 /tmp/x (deleted)"].join("\n");
    const o3 = parseFdRecords(text, "O3");
    expect(o3.valid).toBe(true);
    expect(o3.entries).toEqual([
      { fd: 0, target: "pipe:[10]", flags: "0100002" },
      { fd: 45, target: "/tmp/x (deleted)", flags: "0100000" },
    ]);
    expect(parseFdRecords(text, "O2")).toMatchObject({ valid: false, reason: "no FDREC line" });
  });

  it("reads the own table with flags and without the listing directory", () => {
    const table = readFdTable("O1");
    expect(table.valid).toBe(true);
    expect(table.entries.some((e) => e.fd === 0)).toBe(true);
    expect(table.entries.every((e) => !/^\/proc\/\d+\/fd$/.test(e.target))).toBe(true);
    expect(table.entries.every((e) => e.flags !== null)).toBe(true);
  });

  it("sees a descriptor held open without close-on-exec as inheritable, and a Node-opened one as not", () => {
    const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "fd-evidence-")), "held");
    fs.writeFileSync(file, "x");
    const fd = fs.openSync(file, "r");
    try {
      const entry = readFdTable("O1").entries.find((e) => e.fd === fd);
      expect(entry?.target).toBe(file);
      expect(isCloseOnExec(entry?.flags ?? null)).toBe(true);
      expect(inheritedAtExec(readFdTable("O1")).entries.some((e) => e.fd === fd)).toBe(false);
    } finally {
      fs.closeSync(fd);
      fs.rmSync(path.dirname(file), { recursive: true, force: true });
    }
  });

  it("prints evidence lines with redacted targets", () => {
    const lines = evidenceLines({ point: "O1", valid: true, entries: [{ fd: 7, target: `${TMP}/${MARKER}`, flags: "0100000" }] }, ctx);
    expect(lines).toEqual(["FD-EVIDENCE O1 valid=yes fds=7", "FD-EVIDENCE O1 fd=7 target=<tmp>/<redacted> flags=0100000 cloexec=no"]);
    expect(evidenceLines({ point: "O2", valid: false, entries: [], reason: "empty" }, ctx)).toEqual(["FD-EVIDENCE O2 valid=no reason=empty"]);
  });
});
