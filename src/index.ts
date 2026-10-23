#!/usr/bin/env node
/**
 * vulnveto CLI.
 *
 *   vulnveto scan <github-repo-url> [--json]   full scan → report + SBOM
 *   vulnveto intel <github-repo-url>           repo inventory only
 *   vulnveto fix <github-repo-url>             scan, then interactively approve
 *                                              fixes → draft PRs (needs GITHUB_TOKEN)
 */
import { createInterface } from "node:readline";
import { writeFileSync } from "node:fs";
import { loadConfig } from "./config.js";
import { OpenAiCompatibleClient } from "./ai/adapter.js";
import { runScan } from "./pipeline.js";
import { analyzeRepo } from "./modules/repo-intel.js";
import { applyBumpAsDraftPR } from "./modules/human-gate.js";
import { renderReport } from "./report.js";
import type { ScanReport } from "./contracts.js";

function help(): void {
  console.log(`vulnveto — agentic repository security scanner

Usage:
  vulnveto scan <github-repo-url> [--json]   full scan (SBOM, vulns, secrets, risk)
  vulnveto intel <github-repo-url>           repo inventory only
  vulnveto fix <github-repo-url>             scan + approve fixes → draft PRs (GITHUB_TOKEN)
  vulnveto --help                            this help

Config (env):
  VULNVETO_AI         antseed | gemini | ollama | none   (default: antseed)
  VULNVETO_MODEL      model name override (e.g. glm5.3-flash, deepseek-v4-flash)
  VULNVETO_BASE_URL   OpenAI-compatible base URL override
  VULNVETO_API_KEY    API key (optional for local proxies)
  GITHUB_TOKEN        required for 'fix' (draft PRs)

Examples:
  vulnveto scan https://github.com/owner/repo
  VULNVETO_AI=ollama vulnveto scan https://github.com/owner/repo --json
  vulnveto fix https://github.com/owner/repo`);
}

async function cmdScan(repoUrl: string, asJson: boolean): Promise<ScanReport> {
  const ai = new OpenAiCompatibleClient(loadConfig());
  const report = await runScan(repoUrl, ai);
  if (asJson) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(renderReport(report));
    console.log(`full JSON → vulnveto-report.json · SBOM → vulnveto-sbom.json`);
  }
  writeFileSync("vulnveto-report.json", JSON.stringify(report, null, 2));
  return report;
}

async function cmdIntel(repoUrl: string): Promise<void> {
  const inv = await analyzeRepo(repoUrl);
  console.log(`repo: ${inv.repoUrl}`);
  console.log(`branch: ${inv.defaultBranch}  files: ${inv.totalFiles}  commits(≤depth): ${inv.commitCount}`);
  console.log(`manifests:`);
  for (const m of inv.manifests) {
    console.log(`  ${m.kind}${m.lockfile ? " (lockfile)" : ""}  ${m.path}`);
  }
  console.log(`\ncloned to ${inv.localPath}`);
}

function ask(question: string): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => rl.question(question, (a) => { rl.close(); resolve(a); }));
}

async function cmdFix(repoUrl: string): Promise<void> {
  const report = await cmdScan(repoUrl, false);
  const fixable = report.findings.filter(
    (f) => f.fix && (f.fix.action as { type?: string }).type === "bump"
  );
  if (fixable.length === 0) {
    console.log("\nNo auto-fixable findings. Nothing to approve.");
    return;
  }
  console.log(`\n${fixable.length} fixable finding(s). Each needs your explicit approval.\n`);
  const inv = { repoUrl, localPath: "", defaultBranch: "", manifests: [], totalFiles: 0, commitCount: 0 };
  for (const f of fixable) {
    console.log(`[${f.severity}] ${f.title}`);
    console.log(`  fix: ${f.fix!.description} (confidence: ${f.fix!.confidence})`);
    const answer = (await ask("  Apply as draft PR? [y/N] ")).trim().toLowerCase();
    if (answer !== "y" && answer !== "yes") {
      console.log("  skipped.\n");
      continue;
    }
    try {
      const applied = await applyBumpAsDraftPR(inv, f);
      console.log(`  ✓ draft PR opened: ${applied.prUrl}\n`);
    } catch (err) {
      console.log(`  ✗ failed: ${(err as Error).message}\n`);
    }
  }
}

async function main(): Promise<void> {
  const [cmd, arg, flag] = process.argv.slice(2);
  if (!cmd || cmd === "--help" || cmd === "-h") return help();
  try {
    if (cmd === "scan" && arg) await cmdScan(arg, flag === "--json");
    else if (cmd === "intel" && arg) await cmdIntel(arg);
    else if (cmd === "fix" && arg) await cmdFix(arg);
    else return help();
  } catch (err) {
    console.error(`error: ${(err as Error).message}`);
    process.exit(1);
  }
}

main();
