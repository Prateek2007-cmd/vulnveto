/**
 * Smoke tests — no network, no git. Run: npm test
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { loadConfig } from "../config.js";
import { OpenAiCompatibleClient } from "../ai/adapter.js";
import { AiUnavailableError } from "../contracts.js";

describe("config", () => {
  it("loads antseed defaults", () => {
    delete process.env.VULNVETO_AI;
    const cfg = loadConfig();
    assert.equal(cfg.ai.name, "antseed");
    assert.equal(cfg.ai.baseUrl, "http://localhost:8377/v1");
    assert.ok(cfg.fallbacks.length >= 1);
  });

  it("supports VULNVETO_AI=none", () => {
    process.env.VULNVETO_AI = "none";
    const cfg = loadConfig();
    assert.equal(cfg.ai.name, "none");
    assert.equal(cfg.fallbacks.length, 0);
    delete process.env.VULNVETO_AI;
  });

  it("rejects unknown backends", () => {
    process.env.VULNVETO_AI = "skynet";
    assert.throws(() => loadConfig(), /Unknown AI backend/);
    delete process.env.VULNVETO_AI;
  });
});

describe("ai adapter", () => {
  it("is unavailable when backend is none, and complete() throws AiUnavailableError", async () => {
    process.env.VULNVETO_AI = "none";
    const ai = new OpenAiCompatibleClient(loadConfig());
    assert.equal(ai.available, false);
    await assert.rejects(() => ai.complete("hello"), AiUnavailableError);
    delete process.env.VULNVETO_AI;
  });
});
