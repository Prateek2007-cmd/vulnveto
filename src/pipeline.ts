/**
 * Orchestrator. Runs modules in lane order and merges findings.
 *
 *   Ingest → Detect (dep-scan, secret-scan, package-risk, sbom)
 *          → Remediate (ai-remediation enrichment)
 *          → report
 *
 * human-gate is intentionally NOT in the auto pipeline — it only runs
 * from the `fix` command after explicit per-fix approval.
 *
 * A failing module never fails the scan — it contributes zero findings.
 */
import type {
  AiClient,
  Finding,
  Module,
  ModuleContext,
  ScanReport,
  Severity,
} from "./contracts.js";
import { analyzeRepo } from "./modules/repo-intel.js";
import { depScan } from "./modules/dep-scan.js";
import { secretScan } from "./modules/secret-scan.js";
import { packageRisk } from "./modules/package-risk.js";
import { sbom } from "./modules/sbom.js";
import { enrichFindings } from "./modules/ai-remediation.js";

const MODULES: Module[] = [depScan, secretScan, packageRisk, sbom];

function emptySummary(): Record<Severity, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

export async function runScan(repoUrl: string, ai: AiClient): Promise<ScanReport> {
  const inventory = await analyzeRepo(repoUrl);
  const ctx: ModuleContext = { inventory, ai, workdir: inventory.localPath };

  const results = await Promise.allSettled(MODULES.map((m) => m.run(ctx)));
  let findings: Finding[] = [];
  for (const r of results) {
    if (r.status === "fulfilled") findings.push(...r.value);
  }

  // AI enrichment with graceful degradation (never throws).
  findings = await enrichFindings(findings, ai);

  const summary = emptySummary();
  for (const f of findings) summary[f.severity]++;

  return {
    repoUrl,
    scannedAt: new Date().toISOString(),
    sbomPath: "vulnveto-sbom.json",
    findings,
    summary,
  };
}
