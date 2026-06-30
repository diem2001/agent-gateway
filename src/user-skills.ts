import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { getUserSkillsDir, listFiles } from "./workspace.js";
import { log } from "./logging.js";

/**
 * Per-user skill loading (DEC-GW-002): for a single `query()` call we materialize
 * the requesting user's stored skills into an on-disk SDK *local plugin* bundle
 * and point `options.plugins` at it. The SDK re-scans local plugins on every
 * `query()` call (options are built per call), so the bundle is request-scoped —
 * user A's skills never leak into user B's query.
 *
 * On-disk layout the SDK expects:
 *   <plugin-root>/.claude-plugin/plugin.json   { name, version }
 *   <plugin-root>/skills/<slug>/SKILL.md       frontmatter + body (stored verbatim)
 *
 * Caps (owned by GW-S1): a user namespace is bounded by USER_SKILLS_MAX_COUNT
 * skills and USER_SKILLS_MAX_BYTES total SKILL.md bytes. On overflow we drop the
 * excess deterministically (path-sorted, lowest-priority last), report it so the
 * caller can emit a `skills_truncated` warning, and load the remainder anyway —
 * never hard-fail.
 */

export const DEFAULT_USER_SKILLS_MAX_COUNT = 50;
export const DEFAULT_USER_SKILLS_MAX_BYTES = 1048576; // 1 MiB

function readPositiveIntEnv(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined) return fallback;
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n) || n < 0) return fallback;
  return n;
}

export function getUserSkillsMaxCount(): number {
  return readPositiveIntEnv("USER_SKILLS_MAX_COUNT", DEFAULT_USER_SKILLS_MAX_COUNT);
}

export function getUserSkillsMaxBytes(): number {
  return readPositiveIntEnv("USER_SKILLS_MAX_BYTES", DEFAULT_USER_SKILLS_MAX_BYTES);
}

export type TruncationReason = "count_cap" | "size_cap";

export interface MaterializedUserSkills {
  /** Absolute path to the materialized local-plugin root, or null if nothing to load. */
  pluginRoot: string | null;
  /** Stored skill paths that were dropped by a cap (deterministic, path-sorted). */
  dropped: string[];
  /** Why the drop happened, if any. Set only when `dropped` is non-empty. */
  reason: TruncationReason | null;
}

/**
 * Turn a stored skill file path into a plugin skill slug. The SDK loads a skill
 * from `skills/<slug>/SKILL.md`; we derive `<slug>` from the stored path so two
 * users' identically-named skills stay in their own bundles (isolation comes
 * from the per-query bundle, not the slug). Sanitized to a safe directory name.
 */
function slugForStoredPath(storedPath: string): string {
  const withoutSkillMd = storedPath.replace(/\/SKILL\.md$/i, "").replace(/\.md$/i, "");
  const slug = withoutSkillMd
    .replace(/[^A-Za-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .toLowerCase();
  return slug || "skill";
}

/**
 * Materialize the requesting user's skills into a fresh temp local-plugin bundle
 * for ONE query and return its root path (or null when there is nothing to load).
 * Applies the per-user caps and reports any deterministic truncation.
 *
 * Caller is responsible for the lifecycle of the returned root only insofar as it
 * lives under the OS temp dir; it is safe to leave for the OS to reap, but
 * `cleanupUserSkillBundle` is provided for explicit removal after the query.
 */
export function materializeUserSkills(userId: string | undefined): MaterializedUserSkills {
  const empty: MaterializedUserSkills = { pluginRoot: null, dropped: [], reason: null };
  if (!userId) return empty;

  const baseDir = getUserSkillsDir(userId);
  if (!baseDir || !fs.existsSync(baseDir)) return empty;

  // Stable order so caps drop deterministically and the loaded set is reproducible.
  const entries = listFiles(baseDir)
    .filter((f) => /\.md$/i.test(f.path))
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  if (entries.length === 0) return empty;

  const maxCount = getUserSkillsMaxCount();
  const maxBytes = getUserSkillsMaxBytes();

  const kept: typeof entries = [];
  const dropped: string[] = [];
  let reason: TruncationReason | null = null;
  let runningBytes = 0;

  for (const entry of entries) {
    if (kept.length >= maxCount) {
      dropped.push(entry.path);
      reason = reason ?? "count_cap";
      continue;
    }
    if (runningBytes + entry.size > maxBytes) {
      dropped.push(entry.path);
      reason = reason ?? "size_cap";
      continue;
    }
    kept.push(entry);
    runningBytes += entry.size;
  }

  if (kept.length === 0) {
    // Everything was dropped (e.g. a single oversized skill vs. a tiny byte cap).
    return { pluginRoot: null, dropped, reason };
  }

  const pluginRoot = fs.mkdtempSync(path.join(os.tmpdir(), "agw-userskills-"));
  const pluginMetaDir = path.join(pluginRoot, ".claude-plugin");
  fs.mkdirSync(pluginMetaDir, { recursive: true });
  fs.writeFileSync(
    path.join(pluginMetaDir, "plugin.json"),
    JSON.stringify({ name: "user-" + userId + "-skills", version: "0.0.0" }) + "\n",
  );

  const skillsDir = path.join(pluginRoot, "skills");
  const usedSlugs = new Set<string>();
  for (const entry of kept) {
    let slug = slugForStoredPath(entry.path);
    // Guard against slug collisions between distinct stored paths.
    let unique = slug;
    let n = 1;
    while (usedSlugs.has(unique)) { unique = `${slug}-${n++}`; }
    usedSlugs.add(unique);
    slug = unique;

    const srcPath = path.join(baseDir, entry.path);
    const destDir = path.join(skillsDir, slug);
    fs.mkdirSync(destDir, { recursive: true });
    fs.copyFileSync(srcPath, path.join(destDir, "SKILL.md"));
  }

  if (dropped.length > 0) {
    log("user-skills", `caps: kept=${kept.length} dropped=${dropped.length} reason=${reason} userId=${userId}`);
  }

  return { pluginRoot, dropped, reason };
}

/** Remove a materialized bundle after the query completes. Best-effort. */
export function cleanupUserSkillBundle(pluginRoot: string | null): void {
  if (!pluginRoot) return;
  try { fs.rmSync(pluginRoot, { recursive: true, force: true }); }
  catch (e) { log("user-skills", "cleanup failed for " + pluginRoot + ": " + (e instanceof Error ? e.message : String(e))); }
}
