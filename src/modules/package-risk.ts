/**
 * package-risk (Detect lane)
 *
 * Evidence-backed heuristics for suspicious / poorly-maintained npm packages:
 *   - typosquatting: edit distance <= 2 from a well-known package name
 *   - abandoned: no publish in 18+ months (npm registry time.modified)
 *   - bus factor: a single maintainer
 *
 * Every flag cites its evidence. No AI involved.
 */
import type { Finding, Module } from "../contracts.js";
import { parseNpmLock } from "./npm.js";

// Well-known packages used as typosquat anchors.
const POPULAR = [
  "lodash", "react", "react-dom", "express", "axios", "commander", "chalk",
  "typescript", "webpack", "babel", "eslint", "jest", "mocha", "vue",
  "angular", "next", "nuxt", "svelte", "ember", "jquery", "moment",
  "dayjs", "uuid", "dotenv", "cors", "helmet", "morgan", "body-parser",
  "mongoose", "sequelize", "redis", "socket.io", "ws", "graphql",
  "apollo", "prisma", "knex", "typeorm", "passport", "jsonwebtoken",
  "bcrypt", "nodemailer", "multer", "sharp", "jimp", "pdfkit",
  "cheerio", "puppeteer", "playwright", "cypress", "ts-node", "tsx",
  "vite", "rollup", "esbuild", "parcel", "tailwindcss", "bootstrap",
  "sass", "postcss", "autoprefixer", "prettier", "husky", "lint-staged",
];

function levenshtein(a: string, b: string): number {
  const dp: number[] = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let prev = dp[0];
    dp[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const cur = dp[j];
      dp[j] = Math.min(dp[j] + 1, dp[j - 1] + 1, prev + (a[i - 1] === b[j - 1] ? 0 : 1));
      prev = cur;
    }
  }
  return dp[b.length];
}

interface RegistryMeta {
  monthsSincePublish: number | undefined;
  maintainers: number | undefined;
}

async function fetchMeta(name: string): Promise<RegistryMeta> {
  try {
    const res = await fetch(`https://registry.npmjs.org/${encodeURIComponent(name)}`, {
      headers: { accept: "application/json" },
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) return { monthsSincePublish: undefined, maintainers: undefined };
    const doc = (await res.json()) as {
      time?: { modified?: string };
      maintainers?: unknown[];
    };
    const modified = doc.time?.modified ? Date.parse(doc.time.modified) : NaN;
    const months = isNaN(modified)
      ? undefined
      : (Date.now() - modified) / (30 * 24 * 3600 * 1000);
    return { monthsSincePublish: months, maintainers: doc.maintainers?.length };
  } catch {
    return { monthsSincePublish: undefined, maintainers: undefined };
  }
}

const ABANDONED_MONTHS = 18;
const MAX_PACKAGES = 150; // registry courtesy: don't hammer it on huge lockfiles

export const packageRisk: Module = {
  name: "package-risk",
  async run(ctx): Promise<Finding[]> {
    const pkgs = parseNpmLock(ctx.inventory.localPath).slice(0, MAX_PACKAGES);
    const findings: Finding[] = [];

    // Typosquat check is local and instant — do it for all packages.
    for (const p of pkgs) {
      const base = p.name.split("/").pop()!; // strip @scope/
      if (POPULAR.includes(base)) continue;
      for (const pop of POPULAR) {
        if (Math.abs(base.length - pop.length) > 2) continue;
        if (levenshtein(base, pop) <= 2) {
          findings.push({
            id: `risk-typosquat-${p.name}`,
            category: "risky-package",
            severity: "high",
            confidence: "medium",
            title: `${p.name} looks like a typosquat of "${pop}"`,
            evidence: {
              summary: `Package name "${p.name}" is within edit distance 2 of the well-known package "${pop}". Typosquatted packages are a classic supply-chain attack vector — verify this dependency is intentional.`,
              location: `${p.name}@${p.version}`,
            },
            fix: {
              description: `Confirm "${p.name}" is the intended dependency; if not, replace with "${pop}"`,
              confidence: "medium",
              action: { type: "manual", kind: "review-dependency", package: p.name },
            },
            module: "package-risk",
          });
          break;
        }
      }
    }

    // Registry checks with bounded concurrency.
    const metas = new Map<string, RegistryMeta>();
    const queue = [...new Set(pkgs.map((p) => p.name))];
    const workers = Array.from({ length: 5 }, async () => {
      while (queue.length) {
        const name = queue.shift()!;
        metas.set(name, await fetchMeta(name));
      }
    });
    await Promise.all(workers);

    for (const p of pkgs) {
      const meta = metas.get(p.name);
      if (!meta) continue;
      if (meta.monthsSincePublish !== undefined && meta.monthsSincePublish >= ABANDONED_MONTHS) {
        const months = Math.round(meta.monthsSincePublish);
        findings.push({
          id: `risk-abandoned-${p.name}`,
          category: "risky-package",
          severity: "medium",
          confidence: "high",
          title: `${p.name} appears abandoned (no release in ~${months} months)`,
          evidence: {
            summary: `No new version of "${p.name}" published in ~${months} months (npm registry time.modified). Abandoned packages don't get security fixes — check for maintained forks or alternatives.`,
            location: `${p.name}@${p.version}`,
            references: [`https://www.npmjs.com/package/${p.name}`],
          },
          fix: {
            description: `Evaluate replacing "${p.name}" with a maintained alternative`,
            confidence: "medium",
            action: { type: "manual", kind: "review-dependency", package: p.name },
          },
          module: "package-risk",
        });
      }
      if (meta.maintainers !== undefined && meta.maintainers <= 1) {
        findings.push({
          id: `risk-busfactor-${p.name}`,
          category: "risky-package",
          severity: "low",
          confidence: "high",
          title: `${p.name} has a bus factor of ${meta.maintainers}`,
          evidence: {
            summary: `"${p.name}" lists ${meta.maintainers} maintainer(s) on npm. Single-maintainer packages are higher-risk for abandonment or account-takeover supply-chain attacks.`,
            location: `${p.name}@${p.version}`,
          },
          module: "package-risk",
        });
      }
    }
    return findings;
  },
};
