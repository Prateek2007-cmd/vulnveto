/**
 * report (Experience lane)
 *
 * Turns a ScanReport into a prioritized, explainable text report.
 * Severity order first; every finding shows evidence, fix, and confidence
 * so a human can judge it without trusting the tool blindly.
 */
import type { ScanReport, Severity } from "./contracts.js";

const ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export function renderReport(r: ScanReport): string {
  const lines: string[] = [];
  const s = r.summary;
  lines.push(`vulnveto security report`);
  lines.push(`repo:      ${r.repoUrl}`);
  lines.push(`scanned:   ${r.scannedAt}`);
  lines.push(
    `findings:  ${r.findings.length} ` +
      `(critical ${s.critical} · high ${s.high} · medium ${s.medium} · low ${s.low} · info ${s.info})`
  );
  lines.push("");

  const sorted = [...r.findings].sort(
    (a, b) => ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity)
  );
  for (const f of sorted) {
    lines.push(`[${f.severity.toUpperCase()}] ${f.title}`);
    lines.push(`  category:   ${f.category}  ·  module: ${f.module}  ·  confidence: ${f.confidence}`);
    if (f.evidence.location) lines.push(`  location:   ${f.evidence.location}`);
    lines.push(`  evidence:   ${f.evidence.summary.split("\n")[0]}`);
    for (const ref of f.evidence.references ?? []) lines.push(`  ref:        ${ref}`);
    if (f.fix) {
      lines.push(`  fix:        ${f.fix.description} (confidence: ${f.fix.confidence})`);
    } else {
      lines.push(`  fix:        none suggested — review manually`);
    }
    lines.push("");
  }
  return lines.join("\n");
}
