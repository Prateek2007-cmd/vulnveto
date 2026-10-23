/**
 * Unit tests for the pr-review lane — no network.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { parsePRUrl, diffNewLines, filterRelevant } from "../modules/pr-review.js";

describe("parsePRUrl", () => {
  it("parses a PR url", () => {
    assert.deepEqual(parsePRUrl("https://github.com/owner/repo/pull/42"), {
      owner: "owner",
      repo: "repo",
      number: 42,
    });
  });
  it("rejects non-PR urls", () => {
    assert.throws(() => parsePRUrl("https://github.com/owner/repo"), /Not a GitHub PR URL/);
    assert.throws(() => parsePRUrl("https://gitlab.com/o/r/-/merge_requests/1"), /Not a GitHub PR URL/);
  });
});

describe("diffNewLines", () => {
  it("maps hunks to new-file line numbers", () => {
    const patch = [
      "@@ -1,3 +1,4 @@",
      " context",
      "-removed",
      "+added1",
      "+added2",
      " context2",
    ].join("\n");
    // new side: 1=context, 2=added1, 3=added2, 4=context2
    assert.deepEqual(diffNewLines(patch), [2, 3]);
  });

  it("handles multiple hunks", () => {
    const patch = ["@@ -10,2 +10,3 @@", " a", "+b", "@@ -20,1 +21,2 @@", " c", "+d"].join("\n");
    assert.deepEqual(diffNewLines(patch), [11, 22]);
  });
});

describe("filterRelevant", () => {
  it("skips lockfiles, minified assets and removed files", () => {
    const files = [
      { filename: "src/app.ts", status: "modified", patch: "@@ -1 +1 @@\n+x" },
      { filename: "package-lock.json", status: "modified", patch: "@@ -1 +1 @@\n+x" },
      { filename: "dist/bundle.min.js", status: "added", patch: "@@ -0,0 +1 @@\n+x" },
      { filename: "old.ts", status: "removed", patch: "@@ -1 +0,0 @@\n-x" },
    ];
    assert.deepEqual(filterRelevant(files).map((f) => f.filename), ["src/app.ts"]);
  });
});
