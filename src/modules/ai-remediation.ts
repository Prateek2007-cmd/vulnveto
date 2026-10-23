/**
 * ai-remediation (Remediate lane)
 *
 * Enriches findings with AI-generated explanations and fix suggestions,
 * each carrying a confidence level. GRACEFUL DEGRADATION is the whole
 * point: if AI is unavailable (or a single call fails), the finding keeps
 * its deterministic data and gets a template fix instead. The scan never
 * depends on the model.
 */
import { AiUnavailableError, type Finding } from "../contracts.js";

const PROMPT = (f: Finding) => `You are a security engineer reviewing an automated scan finding.
Respond with ONLY a JSON object (no markdown, no commentary) shaped like:
{"explanation": "<2-3 sentence plain-English explanation of the risk>", "fix": "<concrete remediation steps>", "confidence": "<high|medium|low>"}

Finding:
${JSON.stringify({ title: f.title, severity: f.severity, category: f.category, evidence: f.evidence }, null, 2)}`;

function templateFix(f: Finding): Finding {
  if (f.fix) return f;
  const templates: Record<string, string> = {
    "vulnerable-dependency": "Upgrade the package to a non-vulnerable version (check the OSV reference for fixed versions).",
    "leaked-secret": "Rotate the credential immediately and purge it from git history.",
    "risky-package": "Review whether this dependency is intentional and maintained.",
    "code-issue": "Review the flagged code and apply the suggested change.",
    sbom: "No action needed.",
  };
  return {
    ...f,
    fix: {
      description: templates[f.category] ?? "Review manually.",
      confidence: "low",
      action: { type: "manual" },
    },
  };
}

function tryParseEnrichment(text: string): { explanation?: string; fix?: string; confidence?: string } {
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  if (start < 0 || end <= start) return {};
  try {
    return JSON.parse(text.slice(start, end + 1));
  } catch {
    return {};
  }
}

export interface AiLike {
  complete(prompt: string, opts?: { maxTokens?: number }): Promise<{ text: string }>;
}

/**
 * Called by the pipeline AFTER all detect modules finish.
 * Never throws: worst case, findings keep their deterministic data.
 */
export async function enrichFindings(findings: Finding[], ai: AiLike): Promise<Finding[]> {
  return Promise.all(
    findings.map(async (f) => {
      let enriched = templateFix(f);
      try {
        const { text } = await ai.complete(PROMPT(f), { maxTokens: 500 });
        const parsed = tryParseEnrichment(text);
        if (parsed.explanation || parsed.fix) {
          enriched = {
            ...enriched,
            evidence: {
              ...enriched.evidence,
              summary: `${enriched.evidence.summary}\n\nAI explanation: ${parsed.explanation || "n/a"}`,
            },
            fix: parsed.fix
              ? {
                  description: parsed.fix,
                  confidence:
                    parsed.confidence === "high" || parsed.confidence === "medium" || parsed.confidence === "low"
                      ? parsed.confidence
                      : "medium",
                  action: enriched.fix!.action,
                }
              : enriched.fix,
          };
        }
      } catch (err) {
        if (!(err instanceof AiUnavailableError)) {
          // Single-call failure: keep the deterministic finding, move on.
        }
      }
      return enriched;
    })
  );
}
