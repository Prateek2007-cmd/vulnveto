/**
 * Shared npm lockfile parsing (used by dep-scan, package-risk, sbom).
 * Handles lockfileVersion 1 (dependencies{}), 2 and 3 (packages{}).
 */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

export interface NpmPackage {
  name: string;
  version: string;
}

export function parseNpmLock(root: string): NpmPackage[] {
  const out = new Map<string, string>();
  for (const file of ["package-lock.json", "npm-shrinkwrap.json"]) {
    const p = join(root, file);
    if (!existsSync(p)) continue;
    let lock: any;
    try {
      lock = JSON.parse(readFileSync(p, "utf8"));
    } catch {
      continue;
    }
    const packages = lock.packages as Record<string, { version?: string }> | undefined;
    if (packages) {
      for (const [key, val] of Object.entries(packages)) {
        if (!key.startsWith("node_modules/") || !val?.version) continue;
        // nested: node_modules/a/node_modules/b -> b
        const name = key.split("node_modules/").pop()!;
        if (!out.has(name)) out.set(name, val.version);
      }
    }
    const deps = lock.dependencies as Record<string, { version?: string }> | undefined;
    if (deps) {
      for (const [name, val] of Object.entries(deps)) {
        if (val?.version && !out.has(name)) out.set(name, val.version);
      }
    }
  }
  return [...out.entries()].map(([name, version]) => ({ name, version }));
}
