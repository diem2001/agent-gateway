/**
 * The folder searches of the erasure rows meet a tree that changes under them (MVP-7402): the Claude runtime creates and
 * removes lock directories (`.claude.json.lock`) in a live conversation folder while a row polls it. An entry that
 * vanished between the directory read and the descent holds nothing; it is not an error.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { filesWith, listing } from "./helpers/tree-search.js";

const roots: string[] = [];
afterEach(() => {
  vi.restoreAllMocks();
  for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

/** Runs `change` right after the directory `root` was read, before the search descends into what it listed. */
function afterRootRead(root: string, change: () => void): void {
  const real = fs.readdirSync;
  vi.spyOn(fs, "readdirSync").mockImplementation(((dir: fs.PathLike, options?: unknown) => {
    const result = (real as (d: fs.PathLike, o?: unknown) => unknown)(dir, options);
    if (dir === root) change();
    return result;
  }) as typeof fs.readdirSync);
}

function scratch(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "mvp7402-tree-"));
  roots.push(root);
  return root;
}

/** A folder with one file, a subdirectory with a file, and a lock directory. */
function lockedTree(): string {
  const root = scratch();
  fs.writeFileSync(path.join(root, "a.txt"), "NEEDLE");
  fs.mkdirSync(path.join(root, "sub"));
  fs.writeFileSync(path.join(root, "sub", "b.txt"), "NEEDLE");
  fs.mkdirSync(path.join(root, ".claude.json.lock"));
  return root;
}

describe("folder searches over a tree that changes", () => {
  it("filesWith skips a directory that vanished between the read and the descent", () => {
    const root = lockedTree();
    afterRootRead(root, () => fs.rmdirSync(path.join(root, ".claude.json.lock")));
    expect(filesWith(root, "NEEDLE").sort()).toEqual([path.join(root, "a.txt"), path.join(root, "sub", "b.txt")]);
  });

  it("listing skips a directory that vanished between the read and the descent", () => {
    const root = lockedTree();
    afterRootRead(root, () => fs.rmdirSync(path.join(root, ".claude.json.lock")));
    expect(listing(root).split("; ").sort()).toEqual(["a.txt 6", "sub/b.txt 6"]);
  });

  it("a file that vanished between the read and its content read is skipped", () => {
    const root = scratch();
    fs.writeFileSync(path.join(root, "gone.txt"), "NEEDLE");
    fs.writeFileSync(path.join(root, "kept.txt"), "NEEDLE");
    afterRootRead(root, () => fs.rmSync(path.join(root, "gone.txt")));
    expect(filesWith(root, "NEEDLE")).toEqual([path.join(root, "kept.txt")]);
  });

  it("a folder that does not exist holds nothing", () => {
    expect(filesWith("/tmp/mvp7402-tree-never-created", "NEEDLE")).toEqual([]);
    expect(listing("/tmp/mvp7402-tree-never-created")).toBe("");
  });

  it("a file that is there is found: the search is live", () => {
    const root = lockedTree();
    expect(filesWith(root, "NEEDLE")).toHaveLength(2);
    expect(filesWith(root, "ABSENT")).toEqual([]);
  });
});
