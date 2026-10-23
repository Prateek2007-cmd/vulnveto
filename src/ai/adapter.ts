/**
 * Provider-agnostic AI client.
 *
 * Speaks the OpenAI /v1/chat/completions shape, so ANY compatible backend
 * works: Antseed (localhost:8377), Ollama, LiteLLM gateways, Gemini's
 * OpenAI-compatible endpoint, OpenRouter, ...
 *
 * Tries backends in order (primary, then fallbacks). Throws
 * AiUnavailableError when the whole chain fails — callers must catch it
 * and degrade to template-based explanations. A scan NEVER fails just
 * because AI is unreachable.
 */
import type { AiBackendConfig, VulnVetoConfig } from "../config.js";
import { AiUnavailableError, type AiClient, type AiCompletion } from "../contracts.js";

const REQUEST_TIMEOUT_MS = 60_000;

export class OpenAiCompatibleClient implements AiClient {
  constructor(private readonly cfg: VulnVetoConfig) {}

  get available(): boolean {
    return this.cfg.ai.name !== "none";
  }

  async complete(prompt: string, opts?: { maxTokens?: number }): Promise<AiCompletion> {
    if (!this.available) {
      throw new AiUnavailableError("AI disabled (VULNVETO_AI=none)");
    }
    const chain = [this.cfg.ai, ...this.cfg.fallbacks];
    const errors: string[] = [];
    for (const backend of chain) {
      try {
        return await this.tryBackend(backend, prompt, opts?.maxTokens ?? 1024);
      } catch (err) {
        errors.push(`${backend.name}: ${(err as Error).message}`);
      }
    }
    throw new AiUnavailableError(`All AI backends failed — ${errors.join("; ")}`);
  }

  private async tryBackend(
    backend: AiBackendConfig,
    prompt: string,
    maxTokens: number
  ): Promise<AiCompletion> {
    const url = `${backend.baseUrl.replace(/\/$/, "")}/chat/completions`;
    const res = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        // Antseed's local proxy ignores the key; keep a placeholder so
        // backends that require one don't 401.
        authorization: `Bearer ${backend.apiKey || "vulnveto"}`,
      },
      body: JSON.stringify({
        model: backend.model,
        messages: [{ role: "user", content: prompt }],
        max_tokens: maxTokens,
        temperature: 0.2,
      }),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status} from ${backend.name}`);
    }
    const data = (await res.json()) as {
      choices?: { message?: { content?: string } }[];
    };
    const text = data.choices?.[0]?.message?.content?.trim();
    if (!text) {
      throw new Error(`empty completion from ${backend.name}`);
    }
    return { text, model: backend.model, backend: backend.name };
  }
}
