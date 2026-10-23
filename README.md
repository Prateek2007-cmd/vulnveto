# vulnveto

Agentic repository security scanner. Give it a GitHub repo URL; it gives you back
an SBOM, vulnerable dependencies (via OSV.dev), leaked secrets (via gitleaks),
risky-package flags, AI-explained remediations with confidence levels — and draft
fix PRs only after you explicitly approve them.

Nothing merges on vibes. Everything passes the veto.

## Quickstart

```bash
npm install
npm run build

# inventory a repo (clone + manifest map, no scan yet)
node dist/index.js intel https://github.com/owner/repo

# full scan (modules land lane by lane — see below)
node dist/index.js scan https://github.com/owner/repo --json
```

## AI backends (all free)

The AI layer is provider-agnostic — anything speaking OpenAI's
`/v1/chat/completions` works. Configure with env vars:

| Backend | Default base URL | Notes |
|---|---|---|
| `antseed` (default) | `http://localhost:8377/v1` | Local P2P proxy. Free models observed: `deepseek-v4-flash`, `glm5.3-flash`. |
| `gemini` | Google AI Studio free tier | `VULNVETO_API_KEY` required |
| `ollama` | `http://localhost:11434/v1` | Fully local, fully free |
| `none` | — | AI disabled; scans still run with template explanations |

```bash
VULNVETO_AI=antseed VULNVETO_MODEL=glm5.3-flash node dist/index.js scan <url>
VULNVETO_AI=ollama node dist/index.js scan <url>
VULNVETO_AI=none node dist/index.js scan <url>   # deterministic only
```

Backends are tried in order (primary, then fallbacks). If all fail, the scan
degrades gracefully — findings are still reported, AI explanations are skipped.
A scan never fails just because AI is unreachable.

## Architecture

```
repo URL → repo-intel → dep-scan ─┐
                    → secret-scan ─┼→ findings[] → ai-remediation → risk report → human-gate → draft PR
                    → package-risk ┘                    (SBOM generated alongside)
```

Every module emits `Finding` objects (see `src/contracts.ts` — frozen shapes).
The pipeline merges, prioritizes, and reports. The human-gate module is the
only writer: no commits, no PRs, no pushes without explicit approval.

## Lane ownership (parallel agents)

| Lane | Directory | Modules |
|---|---|---|
| Ingest | `src/modules/repo-intel.ts` | repo inventory (done) |
| Detect | `src/modules/dep-scan.ts`, `secret-scan.ts`, `package-risk.ts`, `sbom.ts` | OSV.dev, gitleaks, heuristics, CycloneDX |
| Remediate | `src/modules/ai-remediation.ts`, `human-gate.ts` | fixes + confidence, approved draft PRs |
| Experience | `src/report.ts`, CLI polish | explainable prioritized report |

Rules: own your lane's files, don't touch others'. `src/contracts.ts` changes
need team agreement. Integration checkpoints: contract freeze → first e2e scan
on the fixture repo → demo rehearsal.

## Security model

- Target repos are **untrusted input**: we clone and read, never execute repo
  code, hooks, or install scripts (`core.hooksPath=/dev/null` on clone).
- Secrets are **masked** in all output; raw values are never logged or transmitted.
- Token permissions are minimal; writes happen only via human-gate approval.

## Origin note

Built from scratch for this project. The review-pipeline concepts (token-aware
passes, relevance filtering, human approval gates) are inspired by the
architecture of ProPR (Elastic License 2.0) — **no ProPR code is included in
this repository.**

## License

MIT — see `LICENSE`.
