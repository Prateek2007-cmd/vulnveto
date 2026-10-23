/**
 * sbom (Detect lane)
 *
 * Generates a CycloneDX 1.5 JSON software bill of materials from the
 * lockfile inventory and writes it to ./vulnveto-sbom.json (downloadable
 * artifact for the demo). Emits an info finding so the SBOM shows up in
 * the report like everything else.
 */
import { randomUUID } from "node:crypto";
import { writeFileSync } from "node:fs";
import type { Finding, Module } from "../contracts.js";
import { parseNpmLock } from "./npm.js";

export const SBOM_PATH = "vulnveto-sbom.json";

export const sbom: Module = {
  name: "sbom",
  async run(ctx): Promise<Finding[]> {
    const pkgs = parseNpmLock(ctx.inventory.localPath);
    const repoName = ctx.inventory.repoUrl.split("/").pop()?.replace(/\.git$/, "") || "unknown";

    const bom = {
      bomFormat: "CycloneDX",
      specVersion: "1.5",
      serialNumber: `urn:uuid:${randomUUID()}`,
      version: 1,
      metadata: {
        timestamp: new Date().toISOString(),
        component: {
          "bom-ref": repoName,
          type: "application",
          name: repoName,
        },
        tools: [{ name: "vulnveto", version: "0.1.0" }],
      },
      components: pkgs.map((p) => ({
        "bom-ref": `pkg:npm/${p.name}@${p.version}`,
        type: "library",
        name: p.name,
        version: p.version,
        purl: `pkg:npm/${encodeURIComponent(p.name)}@${p.version}`,
      })),
    };

    writeFileSync(SBOM_PATH, JSON.stringify(bom, null, 2));

    return [
      {
        id: `sbom-generated-${pkgs.length}`,
        category: "sbom",
        severity: "info",
        confidence: "high",
        title: `SBOM generated: ${pkgs.length} components`,
        evidence: {
          summary: `CycloneDX 1.5 software bill of materials with ${pkgs.length} npm components written to ${SBOM_PATH}.`,
          location: SBOM_PATH,
        },
        module: "sbom",
      },
    ];
  },
};
