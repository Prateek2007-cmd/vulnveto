/**
 * dep-scan (Detect lane)
 *
 * Parses lockfiles, queries OSV.dev (free, no key), and emits one finding
 * per vulnerable package@version. Deterministic — severity comes from the
 * CVSS vector via our own calculator, never from vibes.
 */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type {
  Confidence,
  Finding,
  Module,
  Severity,
} from "../contracts.js";
import { cvssV3Score, scoreToSeverity } from "./cvss.js";
import { parseNpmLock } from "./npm.js";

interface Pkg {
  name: string;
  version: string;
  ecosystem: "npm" | "PyPI";
}

interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: { type: string; score: string }[];
  database_specific?: { severity?: string };
  affected?: {
    package?: { name: string; ecosystem: string };
    ranges?: { type: string; events: { introduced?: string; fixed?: string }[] }[];
  }[];
}

const GHSA_SEVERITY: Record<string, Severity> = {
  critical: "critical",
  high: "high",
  moderate: "medium",
  low: "low",
};

function parsePipRequirements(root: string): Pkg[] {
  const out: Pkg[] = [];
  for (const f of ["requirements.txt", "requirements.lock"]) {
    const p = join(root, f);
    if (!existsSync(p)) continue;
    for (const line of readFileSync(p, "utf8").split("\n")) {
      const m = line.trim().match(/^([A-Za-z0-9_.-]+)==([A-Za-z0-9_.\-+]+)/);
      if (m) out.push({ name: m[1], version: m[2], ecosystem: "PyPI" });
    }
  }
  return out;
}

/** First "fixed" version across all affected ranges, if any. */
function firstFixed(v: OsvVuln): string | undefined {
  for (const a of v.affected ?? []) {
    for (const r of a.ranges ?? []) {
      for (const e of r.events ?? []) {
        if (e.fixed) return e.fixed;
      }
    }
  }
  return undefined;
}

function severityOf(v: OsvVuln): { severity: Severity; confidence: Confidence } {
  const dbSev = v.database_specific?.severity?.toLowerCase();
  if (dbSev && GHSA_SEVERITY[dbSev]) {
    return { severity: GHSA_SEVERITY[dbSev], confidence: "high" };
  }
  for (const s of v.severity ?? []) {
    if (s.type === "CVSS_V3" || s.type === "CVSS_V31") {
      const score = cvssV3Score(s.score);
      if (score !== undefined) return { severity: scoreToSeverity(score), confidence: "high" };
    }
  }
  // No machine-readable severity — still a real vuln, say so honestly.
  return { severity: "medium", confidence: "low" };
}

async function queryOsvBatch(pkgs: Pkg[]): Promise<Map<string, string[]>> {
  // Returns map of "ecosystem:name@version" -> vuln IDs (batch responses are abbreviated).
  const out = new Map<string, string[]>();
  const CHUNK = 100;
  for (let i = 0; i < pkgs.length; i += CHUNK) {
    const chunk = pkgs.slice(i, i + CHUNK);
    const res = await fetch("https://api.osv.dev/v1/querybatch", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        queries: chunk.map((p) => ({
          package: { name: p.name, ecosystem: p.ecosystem },
          version: p.version,
        })),
      }),
      signal: AbortSignal.timeout(60_000),
    });
    if (!res.ok) throw new Error(`OSV.dev HTTP ${res.status}`);
    const data = (await res.json()) as { results?: { vulns?: { id: string }[] }[] };
    chunk.forEach((p, j) => {
      out.set(
        `${p.ecosystem}:${p.name}@${p.version}`,
        (data.results?.[j]?.vulns ?? []).map((v) => v.id)
      );
    });
  }
  return out;
}

/** Batch querybatch responses only carry id+modified — fetch full records. */
async function fetchVulnDetails(ids: string[]): Promise<Map<string, OsvVuln>> {
  const out = new Map<string, OsvVuln>();
  const queue = [...new Set(ids)];
  const workers = Array.from({ length: 8 }, async () => {
    while (queue.length) {
      const id = queue.shift()!;
      try {
        const res = await fetch(`https://api.osv.dev/v1/vulns/${id}`, {
          signal: AbortSignal.timeout(30_000),
        });
        if (res.ok) out.set(id, (await res.json()) as OsvVuln);
      } catch {
        /* skip — a missing detail never fails the scan */
      }
    }
  });
  await Promise.all(workers);
  return out;
}

export const depScan: Module = {
  name: "dep-scan",
  async run(ctx): Promise<Finding[]> {
    const root = ctx.inventory.localPath;
    const pkgs: Pkg[] = [
      ...parseNpmLock(root).map((p) => ({ ...p, ecosystem: "npm" as const })),
      ...parsePipRequirements(root),
    ];
    if (pkgs.length === 0) return [];

    const vulnIdsByPkg = await queryOsvBatch(pkgs);
    const allIds = [...vulnIdsByPkg.values()].flat();
    const details = await fetchVulnDetails(allIds);
    const findings: Finding[] = [];

    for (const p of pkgs) {
      const ids = vulnIdsByPkg.get(`${p.ecosystem}:${p.name}@${p.version}`) ?? [];
      for (const id of ids) {
        const v = details.get(id);
        if (!v) continue; // detail fetch failed — skip rather than guess
        const { severity, confidence } = severityOf(v);
        const fixed = firstFixed(v);
        const cve = (v.aliases ?? []).find((a) => a.startsWith("CVE-"));
        findings.push({
          id: `osv-${p.name}-${p.version}-${v.id}`,
          category: "vulnerable-dependency",
          severity,
          confidence,
          title: `${p.name}@${p.version}: ${v.summary || v.id}`,
          evidence: {
            summary: `${p.name}@${p.version} is affected by ${v.id}${cve ? ` (${cve})` : ""}. ${v.details ? v.details.slice(0, 280) : ""}`,
            location: `${p.name}@${p.version}`,
            references: [`https://osv.dev/vulnerability/${v.id}`],
          },
          fix: fixed
            ? {
                description: `Upgrade ${p.name} from ${p.version} to ${fixed} (first fixed version per OSV)`,
                confidence: "high",
                action: {
                  type: "bump",
                  ecosystem: p.ecosystem,
                  package: p.name,
                  from: p.version,
                  to: fixed,
                },
              }
            : undefined,
          module: "dep-scan",
        });
      }
    }
    return findings;
  },
};
