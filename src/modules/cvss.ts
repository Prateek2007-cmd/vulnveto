/**
 * Minimal CVSS v3.x base-score calculator (FIRST specification).
 * Deterministic severity mapping — no AI involved, fully explainable.
 */
import type { Severity } from "../contracts.js";

const AV: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC: Record<string, number> = { L: 0.77, H: 0.44 };
const PR_UNCHANGED: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
const PR_CHANGED: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 };
const UI: Record<string, number> = { N: 0.85, R: 0.62 };
const CIA: Record<string, number> = { H: 0.56, L: 0.22, N: 0 };

function roundup(n: number): number {
  // Smallest 1-decimal number >= n (inputs are non-negative here).
  return Math.ceil(n * 10 - 1e-9) / 10;
}

/** Returns the base score 0–10, or undefined if the vector can't be parsed. */
export function cvssV3Score(vector: string): number | undefined {
  const m: Record<string, string> = {};
  for (const part of vector.split("/")) {
    const i = part.indexOf(":");
    if (i > 0) m[part.slice(0, i)] = part.slice(i + 1);
  }
  if (!m.AV || !m.AC || !m.PR || !m.UI || !m.C || !m.I || !m.A) return undefined;

  const scopeChanged = m.S === "C";
  const iss =
    1 -
    (1 - (CIA[m.C] ?? 0)) * (1 - (CIA[m.I] ?? 0)) * (1 - (CIA[m.A] ?? 0));

  let impact: number;
  if (scopeChanged) {
    impact = iss <= 0 ? 0 : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  } else {
    impact = 6.42 * iss;
  }
  if (impact <= 0) return 0;

  const pr = (scopeChanged ? PR_CHANGED : PR_UNCHANGED)[m.PR] ?? 0;
  const exploitability =
    8.22 * (AV[m.AV] ?? 0) * (AC[m.AC] ?? 0) * pr * (UI[m.UI] ?? 0);

  const score = scopeChanged
    ? Math.min(1.08 * (impact + exploitability), 10)
    : Math.min(impact + exploitability, 10);
  return roundup(score);
}

export function scoreToSeverity(score: number): Severity {
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  if (score > 0) return "low";
  return "info";
}
