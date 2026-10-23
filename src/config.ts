/**
 * Configuration. Env vars only — never commit secrets.
 *
 *   VULNVETO_AI        primary backend: antseed | gemini | ollama | none (default: antseed)
 *   VULNVETO_MODEL     model name override, e.g. deepseek-v4-flash, glm5.3-flash
 *   VULNVETO_BASE_URL  base URL override (any OpenAI-compatible endpoint)
 *   VULNVETO_API_KEY   API key (antseed's local proxy accepts any placeholder)
 *
 * The AI layer is provider-agnostic: anything speaking the OpenAI
 * /v1/chat/completions shape works — Antseed, Ollama, LiteLLM, etc.
 */

export type AiBackendName = "antseed" | "gemini" | "ollama" | "none";

export interface AiBackendConfig {
  name: AiBackendName;
  /** OpenAI-compatible base URL, e.g. http://localhost:8377/v1 */
  baseUrl: string;
  model: string;
  apiKey?: string;
}

export interface VulnVetoConfig {
  ai: AiBackendConfig;
  fallbacks: AiBackendConfig[];
}

const PRESETS: Record<Exclude<AiBackendName, "none">, { baseUrl: string; model: string }> = {
  // Local P2P AI network proxy. Free models observed: deepseek-v4-flash, glm5.3-flash.
  antseed: { baseUrl: "http://localhost:8377/v1", model: "deepseek-v4-flash" },
  // Google AI Studio free tier, via its OpenAI-compatible endpoint.
  gemini: { baseUrl: "https://generativelanguage.googleapis.com/v1beta/openai", model: "gemini-2.0-flash" },
  // Fully local, fully free.
  ollama: { baseUrl: "http://localhost:11434/v1", model: "llama3.1:8b" },
};

const ALL_BACKENDS: Exclude<AiBackendName, "none">[] = ["antseed", "gemini", "ollama"];

function backendFromEnv(name: Exclude<AiBackendName, "none">): AiBackendConfig {
  const preset = PRESETS[name];
  return {
    name,
    baseUrl: process.env.VULNVETO_BASE_URL || preset.baseUrl,
    model: process.env.VULNVETO_MODEL || preset.model,
    apiKey: process.env.VULNVETO_API_KEY,
  };
}

export function loadConfig(): VulnVetoConfig {
  const primary = (process.env.VULNVETO_AI || "antseed").toLowerCase() as AiBackendName;

  if (primary === "none") {
    return { ai: { name: "none", baseUrl: "", model: "" }, fallbacks: [] };
  }
  if (!ALL_BACKENDS.includes(primary)) {
    throw new Error(
      `Unknown AI backend "${primary}". Choose one of: ${[...ALL_BACKENDS, "none"].join(", ")}`
    );
  }

  // Fallback chain: every other backend, in default priority order.
  // A scan degrades to template explanations only if ALL of these fail.
  const fallbacks = ALL_BACKENDS.filter((b) => b !== primary).map(backendFromEnv);
  return { ai: backendFromEnv(primary), fallbacks };
}
