/**
 * repo-intel (Ingest lane)
 *
 * Clones the target repo (read-only, shallow) and builds an inventory:
 * manifests/lockfiles, file count, commit count, default branch.
 *
 * SECURITY: the target repo is UNTRUSTED input. We only ever `git clone`
 * and read files. We NEVER execute hooks, install scripts, or any repo
 * code. Clone with --no-checkout-safe defaults; hooks don't run on clone,
 * but we also pass -c core.hooksPath=/dev/null as belt-and-braces.
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtempSync, readdirSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import type { Manifest, ManifestKind, RepoInventory } from "../contracts.js";

const exec = promisify(execFile);

const CLONE_DEPTH = process.env.VULNVETO_CLONE_DEPTH || "50";

interface ManifestPattern {
  file: RegExp;
  kind: ManifestKind;
  lockfile: boolean;
}

const MANIFEST_PATTERNS: ManifestPattern[] = [
  { file: /^package-lock\.json$/, kind: "npm", lockfile: true },
  { file: /^npm-shrinkwrap\.json$/, kind: "npm", lockfile: true },
  { file: /^yarn\.lock$/, kind: "npm", lockfile: true },
  { file: /^pnpm-lock\.yaml$/, kind: "npm", lockfile: true },
  { file: /^package\.json$/, kind: "npm", lockfile: false },
  { file: /^requirements\.txt$/, kind: "pip", lockfile: false },
  { file: /^requirements.*\.txt$/, kind: "pip", lockfile: false },
  { file: /^Pipfile\.lock$/, kind: "pip", lockfile: true },
  { file: /^Pipfile$/, kind: "pip", lockfile: false },
  { file: /^poetry\.lock$/, kind: "pip", lockfile: true },
  { file: /^pyproject\.toml$/, kind: "pip", lockfile: false },
  { file: /^pom\.xml$/, kind: "maven", lockfile: false },
  { file: /^build\.gradle(\.kts)?$/, kind: "gradle", lockfile: false },
  { file: /^go\.mod$/, kind: "go", lockfile: false },
  { file: /^go\.sum$/, kind: "go", lockfile: true },
  { file: /^Cargo\.lock$/, kind: "cargo", lockfile: true },
  { file: /^Cargo\.toml$/, kind: "cargo", lockfile: false },
  { file: /^.*\.csproj$/, kind: "nuget", lockfile: false },
  { file: /^packages\.lock\.json$/, kind: "nuget", lockfile: true },
];

const SKIP_DIRS = new Set([".git", "node_modules", "__pycache__", ".venv", "venv", "target", "dist", "build", ".next"]);

function walk(dir: string, root: string, files: string[]): void {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const rel = full.slice(root.length + 1);
    const st = statSync(full);
    if (st.isDirectory()) {
      if (SKIP_DIRS.has(entry)) continue;
      walk(full, root, files);
    } else if (st.isFile()) {
      files.push(rel.split(sep).join("/"));
    }
  }
}

/** Only https GitHub URLs for now. SSH/other hosts are a later lane. */
export function assertSupportedRepoUrl(url: string): void {
  if (!/^https:\/\/github\.com\/[\w.-]+\/[\w.-]+(\.git)?\/?$/.test(url)) {
    throw new Error(`Unsupported repo URL (https github.com only for now): ${url}`);
  }
}

export async function analyzeRepo(repoUrl: string): Promise<RepoInventory> {
  assertSupportedRepoUrl(repoUrl);
  const localPath = mkdtempSync(join(tmpdir(), "vulnveto-"));

  await exec("git", [
    "-c",
    "core.hooksPath=/dev/null",
    "clone",
    "--depth",
    CLONE_DEPTH,
    "--no-tags",
    repoUrl,
    localPath,
  ]);

  const files: string[] = [];
  walk(localPath, localPath, files);

  const manifests: Manifest[] = [];
  for (const f of files) {
    const base = f.split("/").pop()!;
    for (const p of MANIFEST_PATTERNS) {
      if (p.file.test(base)) {
        manifests.push({ kind: p.kind, path: f, lockfile: p.lockfile });
        break;
      }
    }
  }

  let defaultBranch = "HEAD";
  try {
    const { stdout } = await exec("git", ["-C", localPath, "rev-parse", "--abbrev-ref", "HEAD"]);
    defaultBranch = stdout.trim();
  } catch {
    /* keep HEAD */
  }

  let commitCount = 0;
  try {
    const { stdout } = await exec("git", ["-C", localPath, "rev-list", "--count", "HEAD"]);
    commitCount = parseInt(stdout.trim(), 10) || 0;
  } catch {
    /* keep 0 */
  }

  return { repoUrl, localPath, defaultBranch, manifests, totalFiles: files.length, commitCount };
}
