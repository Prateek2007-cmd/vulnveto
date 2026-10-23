/**
 * pr-review (Review lane) — ProPR-style AI code review, built from scratch.
 *
 * Fetches a PR's diff via the GitHub API, filters out noise (lockfiles,
 * minified assets, generated code), asks the AI to review each file, and
 * posts the result as a real GitHub PR review: inline comments on the
 * exact lines plus an overall summary.
 *
 * Dry-run by default: `vulnveto review <pr-url>` prints the review.
 * `--post` asks for confirmation, then posts (needs GITHUB_TOKEN).
 * Same human-gate philosophy as the rest of vulnveto.
 */
import type { AiClient } from "../contracts.js";

export interface PRRef {
  owner: string;
  repo: string;
  number: number;
}

export function parsePRUrl(url: string): PRRef {
  const m = url.match(/^https:\/\/github\.com\/([\w.-]+)\/([\w.-]+)\/pull\/(\d+)\/?$/);
  if (!m) throw new Error(`Not a GitHub PR URL: ${url}`);
  return { owner: m[1], repo: m[2], number: parseInt(m[3], 10) };
}

export interface PRFile {
  filename: string;
  status: string;
  patch?: string;
}

/**
 * New-file line numbers actually present in the diff.
 * The GitHub review API only accepts comments on diff lines — this is
 * the valid target set we hand to the AI.
 */
export function diffNewLines(patch: string): number[] {
  const lines: number[] = [];
  let newLine = 0;
  for (const l of patch.split("\n")) {
    const h = l.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
    if (h) {
      newLine = parseInt(h[1], 10);
      continue;
    }
    if (l.startsWith("+") && !l.startsWith("+++")) {
      lines.push(newLine);
      newLine++;
    } else if (l.startsWith("-") && !l.startsWith("---")) {
      // removed line: new-side numbering doesn't advance
    } else if (l.startsWith(" ")) {
      newLine++;
    }
    // "\ No newline" markers etc: ignore
  }
  return lines;
}

const SKIP_PATTERNS = [
  /package-lock\.json$/,
  /yarn\.lock$/,
  /pnpm-lock\.yaml$/,
  /\.min\.js$/,
  /\.map$/,
  /(^|\/)dist\//,
  /(^|\/)build\//,
  /\.snap$/,
];

const MAX_PATCH_CHARS = 12_000;
const MAX_COMMENTS_PER_FILE = 5;

export interface ReviewComment {
  path: string;
  line: number;
  severity: "high" | "medium" | "low";
  body: string;
}

export interface FileReview {
  filename: string;
  comments: ReviewComment[];
  summary: string;
}

async function gh(token: string | undefined, path: string, init?: RequestInit): Promise<any> {
  const res = await fetch(`https://api.github.com${path}`, {
    ...init,
    headers: {
      accept: "application/vnd.github+json",
      "user-agent": "vulnveto/0.1.0",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...(init?.headers as Record<string, string> | undefined),
      "content-type": "application/json",
    },
    signal: AbortSignal.timeout(30_000),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`GitHub API ${path} → ${res.status}: ${text.slice(0, 160)}`);
  }
  return res.json();
}

export async function fetchPRFiles(ref: PRRef, token?: string): Promise<PRFile[]> {
  const files: PRFile[] = [];
  let page = 1;
  for (;;) {
    const batch = (await gh(
      token,
      `/repos/${ref.owner}/${ref.repo}/pulls/${ref.number}/files?per_page=100&page=${page}`
    )) as PRFile[];
    files.push(...batch);
    if (batch.length < 100) break;
    page++;
  }
  return files;
}

export function filterRelevant(files: PRFile[]): PRFile[] {
  return files.filter(
    (f) =>
      f.patch &&
      f.status !== "removed" &&
      !SKIP_PATTERNS.some((re) => re.test(f.filename))
  );
}

const REVIEW_PROMPT = (
  filename: string,
  validLines: number[],
  patch: string
) => `You are a senior staff engineer doing code review. Review ONLY the added/changed lines in this diff.

File: ${filename}
You may comment ONLY on these new-file line numbers (they are the lines present in the diff): ${validLines.join(", ")}

Diff:
${patch}

Rules:
- Comment only on real issues: bugs, security problems, race conditions, broken error handling, performance traps, API misuse.
- No nitpicks about style, formatting, or naming unless it causes a bug. No praise, no "looks good".
- Max ${MAX_COMMENTS_PER_FILE} comments. Fewer is better — silence means approval.
- Keep each comment to 1-2 sentences, actionable, with the fix direction.

Respond with ONLY a JSON object, no markdown:
{"comments": [{"line": <number from the allowed list>, "severity": "high|medium|low", "comment": "<text>"}], "summary": "<2-3 sentence overall assessment>"}`;

function tryParseReview(text: string): { comments?: any[]; summary?: string } {
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  if (start < 0 || end <= start) return {};
  try {
    return JSON.parse(text.slice(start, end + 1));
  } catch {
    return {};
  }
}

export async function reviewFile(
  ai: AiClient,
  file: PRFile
): Promise<FileReview> {
  const patch =
    file.patch!.length > MAX_PATCH_CHARS
      ? file.patch!.slice(0, MAX_PATCH_CHARS) + "\n…(truncated)"
      : file.patch!;
  const validLines = new Set(diffNewLines(patch));

  const { text } = await ai.complete(REVIEW_PROMPT(file.filename, [...validLines], patch), {
    maxTokens: 1500,
  });
  const parsed = tryParseReview(text);

  const comments: ReviewComment[] = [];
  for (const c of parsed.comments ?? []) {
    const line = Number(c.line);
    if (!validLines.has(line)) continue; // AI hallucinated a line — drop it
    if (!["high", "medium", "low"].includes(c.severity)) continue;
    if (typeof c.comment !== "string" || !c.comment.trim()) continue;
    comments.push({
      path: file.filename,
      line,
      severity: c.severity,
      body: `**[vulnveto · ${c.severity}]** ${c.comment.trim()}`,
    });
    if (comments.length >= MAX_COMMENTS_PER_FILE) break;
  }

  return {
    filename: file.filename,
    comments,
    summary: typeof parsed.summary === "string" ? parsed.summary : "",
  };
}

export async function reviewPR(
  ai: AiClient,
  ref: PRRef,
  token?: string,
  onFile?: (filename: string) => void
): Promise<{ reviews: FileReview[]; totalComments: number }> {
  const files = filterRelevant(await fetchPRFiles(ref, token));
  const reviews: FileReview[] = [];
  for (const f of files) {
    onFile?.(f.filename);
    try {
      reviews.push(await reviewFile(ai, f));
    } catch (err) {
      // One bad file never kills the review.
      console.warn(`review: skipping ${f.filename} (${(err as Error).message.slice(0, 100)})`);
    }
  }
  return { reviews, totalComments: reviews.reduce((n, r) => n + r.comments.length, 0) };
}

export async function postReview(
  token: string,
  ref: PRRef,
  reviews: FileReview[]
): Promise<string> {
  const pr = (await gh(token, `/repos/${ref.owner}/${ref.repo}/pulls/${ref.number}`)) as {
    head: { sha: string };
  };
  const summary = reviews
    .filter((r) => r.summary)
    .map((r) => `**${r.filename}** — ${r.summary}`)
    .join("\n");

  const res = (await gh(token, `/repos/${ref.owner}/${ref.repo}/pulls/${ref.number}/reviews`, {
    method: "POST",
    body: JSON.stringify({
      commit_id: pr.head.sha,
      event: "COMMENT",
      body: `## 🤖 vulnveto code review\n\n${summary || "No blocking issues found."}\n\n> Automated review — treat inline comments as suggestions, not verdicts.`,
      comments: reviews.flatMap((r) =>
        r.comments.map((c) => ({
          path: c.path,
          line: c.line,
          side: "RIGHT" as const,
          body: c.body,
        }))
      ),
    }),
  })) as { html_url: string };
  return res.html_url;
}
