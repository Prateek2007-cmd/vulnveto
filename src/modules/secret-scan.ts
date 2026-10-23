/**
 * secret-scan (Detect lane)
 *
 * Wraps gitleaks (established OSS scanner — we don't hand-roll secret
 * detection). Scans the working tree AND full git history.
 *
 * SECRET HYGIENE: gitleaks is run with --redact, and we mask values again
 * ourselves. Raw secret material NEVER appears in findings, logs, reports,
 * or AI prompts. Only the rule name, file:line, and commit are reported.
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Finding, Module } from "../contracts.js";

const exec = promisify(execFile);

interface GitleaksHit {
  Description?: string;
  StartLine?: number;
  EndLine?: number;
  File?: string;
  Commit?: string;
  RuleID?: string;
  Secret?: string;
}

function gitleaksBinary(): string {
  const local = join(process.env.HOME || "", ".local", "bin", "gitleaks");
  return existsSync(local) ? local : "gitleaks"; // bare name resolves via PATH
}

function mask(secret: string): string {
  if (!secret || secret === "REDACTED") return "***";
  return secret.slice(0, 3) + "***";
}

export const secretScan: Module = {
  name: "secret-scan",
  async run(ctx): Promise<Finding[]> {
    const binary = gitleaksBinary();
    const reportPath = join(mkdtempSync(join(tmpdir(), "vulnveto-gitleaks-")), "report.json");
    try {
      // Exit code is 1 when leaks are found — that's the happy path here.
      await exec(binary, [
        "detect",
        "--source",
        ctx.inventory.localPath,
        "--report-format",
        "json",
        "--report-path",
        reportPath,
        "--redact",
        "--no-color",
      ]);
    } catch (err: any) {
      const code = err?.code;
      if (code === 1 || code === "1") {
        // leaks found — report file should exist
      } else if (code === "ENOENT") {
        console.warn("secret-scan: gitleaks not installed — skipping (install from https://github.com/gitleaks/gitleaks)");
        return [];
      } else {
        console.warn(`secret-scan: gitleaks failed (${String(err?.message).slice(0, 120)}) — skipping`);
        return [];
      }
    }

    let hits: GitleaksHit[] = [];
    try {
      hits = JSON.parse(readFileSync(reportPath, "utf8"));
    } catch {
      return [];
    } finally {
      try { rmSync(reportPath); } catch { /* ignore */ }
    }

    return hits.map((h, i) => {
      const commit = h.Commit ? `commit ${h.Commit.slice(0, 8)}` : "working tree";
      return {
        id: `secret-${h.RuleID || "generic"}-${i}-${(h.File || "").replace(/[^a-zA-Z0-9]/g, "_")}`,
        category: "leaked-secret" as const,
        severity: "high" as const,
        confidence: "high" as const,
        title: `Possible ${h.Description || h.RuleID || "secret"} in ${h.File || "unknown file"}`,
        evidence: {
          // Masked value proves shape without exposing the secret.
          summary: `${h.Description || "secret pattern"} matched in ${h.File || "?"}:${h.StartLine ?? "?"} (${commit}). Value shape: ${mask(h.Secret || "")} — rotate this credential immediately.`,
          location: `${h.File || "?"}:${h.StartLine ?? "?"}${h.Commit ? "@" + h.Commit.slice(0, 8) : ""}`,
          references: ["https://github.com/gitleaks/gitleaks"],
        },
        fix: {
          description: "Revoke/rotate the credential, purge it from git history (e.g. git-filter-repo), and add the file pattern to .gitignore",
          confidence: "high",
          action: { type: "manual", kind: "rotate-secret" },
        },
        module: "secret-scan",
      };
    });
  },
};
