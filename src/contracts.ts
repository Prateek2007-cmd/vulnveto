/**
 * Shared contracts — FROZEN.
 *
 * Every module speaks this language. Lane owners: do not change these shapes
 * without team agreement. New categories/severities are additive-only.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Confidence = "high" | "medium" | "low";

export type FindingCategory =
  | "vulnerable-dependency"
  | "risky-package"
  | "leaked-secret"
  | "code-issue"
  | "sbom";

export interface Evidence {
  /** Human-readable. MUST NOT contain raw secrets — mask them. */
  summary: string;
  /** file:line, commit sha (short), or package@version */
  location?: string;
  /** CVE links, OSV entries, advisory URLs */
  references?: string[];
}

export interface SuggestedFix {
  description: string;
  confidence: Confidence;
  /**
   * Machine-readable action, e.g.
   * { type: "bump", package: "lodash", from: "4.17.20", to: "4.17.21" }
   * { type: "patch", file: "src/auth.ts", diff: "..." }
   * Only applied after explicit human approval (human-gate lane).
   */
  action: Record<string, unknown>;
}

export interface Finding {
  /** Stable id, e.g. "osv-lodash-4.17.20-CVE-2021-23337" */
  id: string;
  category: FindingCategory;
  severity: Severity;
  confidence: Confidence;
  title: string;
  evidence: Evidence;
  fix?: SuggestedFix;
  /** Name of the module that produced it (e.g. "dep-scan"). */
  module: string;
}

export type ManifestKind =
  | "npm"
  | "pip"
  | "maven"
  | "gradle"
  | "go"
  | "cargo"
  | "nuget"
  | "unknown";

export interface Manifest {
  kind: ManifestKind;
  /** Relative to repo root, e.g. "package-lock.json" */
  path: string;
  lockfile: boolean;
}

export interface RepoInventory {
  repoUrl: string;
  /** Local clone path (temp dir, cleaned up by caller if desired). */
  localPath: string;
  defaultBranch: string;
  manifests: Manifest[];
  totalFiles: number;
  commitCount: number;
}

export interface ScanReport {
  repoUrl: string;
  scannedAt: string; // ISO timestamp
  sbomPath?: string;
  findings: Finding[];
  summary: Record<Severity, number>;
}

/** Thrown when no AI backend in the chain can serve a request. */
export class AiUnavailableError extends Error {
  constructor(message = "AI backend unavailable") {
    super(message);
    this.name = "AiUnavailableError";
  }
}

export interface AiCompletion {
  text: string;
  model: string;
  backend: string;
}

export interface AiClient {
  /**
   * Complete a prompt. Tries backends in order; throws AiUnavailableError
   * when none can serve. Callers MUST catch it and degrade gracefully
   * (template-based explanations) — a scan never fails for lack of AI.
   */
  complete(prompt: string, opts?: { maxTokens?: number }): Promise<AiCompletion>;
  /** False when configured with backend "none". */
  readonly available: boolean;
}

export interface ModuleContext {
  inventory: RepoInventory;
  ai: AiClient;
  /** Writable scratch dir for the module. */
  workdir: string;
}

export interface Module {
  name: string;
  run(ctx: ModuleContext): Promise<Finding[]>;
}
