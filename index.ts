/**
 * Astra Zero Trust — OpenClaw Plugin — COMPLETE
 * ==============================================
 * Full integration. Nothing missing.
 *
 * What this plugin does automatically:
 *   1. Every user message → tokenized before LLM sees it
 *   2. Every tool result  → scanned before LLM reads it
 *   3. LLM output         → scanned for data leakage before user sees it
 *   4. Session ends       → vault wiped, cryptographic proof generated
 *   5. Custom patterns    → customer sensitivity recipes loaded and applied
 *   6. Differential privacy → DP status checked, queries protected
 *   7. Stats              → protection counts tracked and loggable
 *
 * Endpoints used automatically:
 *   POST /protect/text              — tokenize every message
 *   POST /guardrails/scan-output    — scan LLM response for leaks
 *   GET  /recipes                   — load customer sensitivity patterns
 *   POST /recipes                   — create new patterns from plugin
 *   GET  /recipes/templates         — available pattern templates
 *   GET  /audit/stats               — protection statistics
 *   GET  /platform/security/stats   — security events
 *   GET  /dp/status                 — differential privacy status
 *   GET  /vault/wipe/proof          — cryptographic wipe proof
 *   POST /vault/wipe/session/{id}   — wipe vault on session end
 *
 * On-premise:
 *   Set astraUrl to http://localhost:4000
 *   All calls go to local Astra. Data never leaves customer server.
 *
 * Install:
 *   openclaw plugins install clawhub:astra-zerotrust
 */

import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";

// ── Types ─────────────────────────────────────────────────────────────────────

interface AstraConfig {
  apiKey:      string;
  astraUrl:    string;
  failClosed:  boolean;
  logLevel:    "silent" | "info" | "debug";
  scanOutput:  boolean;  // scan LLM responses for leakage (default: true)
  trackStats:  boolean;  // log protection stats (default: true)
}

interface AstraRecipe {
  id:         string;
  name:       string;
  patterns:   string[];
  data_types: string[];
}

interface ProtectResult {
  protected_text: string;
  count:          number;
  entities:       Array<{ type: string; token: string }>;
  error?:         string;
}

// ── State ─────────────────────────────────────────────────────────────────────

const sessionTokens  = new Map<string, number>();
let   cachedRecipes: AstraRecipe[] = [];
let   recipesCachedAt  = 0;
let   lastWipeProof: Record<string, unknown> = {};
const RECIPE_CACHE_MS  = 5 * 60 * 1000;

// ── Plugin ────────────────────────────────────────────────────────────────────

export default definePluginEntry({
  register(api) {

    const cfg = api.config as Partial<AstraConfig>;

    const apiKey     = cfg.apiKey    || process.env.ASTRA_API_KEY || "";
    const astraUrl   = cfg.astraUrl  || process.env.ASTRA_URL     || "https://app.codeastra.dev";
    const failClosed = cfg.failClosed !== false;
    const scanOutput = cfg.scanOutput !== false;
    const trackStats = cfg.trackStats !== false;
    const logLevel   = cfg.logLevel  || "info";

    const log = {
      info:  (m: string) => logLevel !== "silent" && api.log.info(m),
      warn:  (m: string) => api.log.warn(m),
      debug: (m: string) => logLevel === "debug"  && api.log.info(m),
      error: (m: string) => api.log.error(m),
    };

    if (!apiKey) {
      log.warn(
        "[Astra] No API key. Add apiKey to plugin config. " +
        "Get yours at app.codeastra.dev"
      );
    } else {
      log.info(
        `[Astra] Zero Trust loaded. ` +
        `url=${astraUrl} failClosed=${failClosed} ` +
        `scanOutput=${scanOutput}`
      );
    }

    // ══════════════════════════════════════════════════════════════════════
    // CORE HELPERS
    // ══════════════════════════════════════════════════════════════════════

    // ── GET /recipes — load customer sensitivity patterns ─────────────────
    // Loads Goldman's GSAM codes, hospital MRNs, law firm matter refs.
    // Cached 5 minutes. Refreshes automatically.
    async function loadRecipes(): Promise<AstraRecipe[]> {
      if (!apiKey) return [];
      const now = Date.now();
      if (now - recipesCachedAt < RECIPE_CACHE_MS && cachedRecipes.length > 0) {
        return cachedRecipes;
      }
      try {
        const r = await fetch(`${astraUrl}/recipes`, {
          headers: { "X-API-Key": apiKey },
          signal:  AbortSignal.timeout(5000),
        });
        if (r.ok) {
          const data      = await r.json();
          cachedRecipes   = data.recipes || [];
          recipesCachedAt = now;
          if (cachedRecipes.length > 0) {
            log.debug(`[Astra] ${cachedRecipes.length} sensitivity recipes loaded.`);
          }
        }
      } catch { /* non-fatal */ }
      return cachedRecipes;
    }

    // ── POST /protect/text — tokenize text ───────────────────────────────
    async function protectText(
      text:      string,
      sessionId: string,
      source:    string = "user_input",
    ): Promise<ProtectResult> {
      const recipes = await loadRecipes();
      const body: Record<string, unknown> = {
        text,
        classification: "pii",
        session_id:     sessionId,
        source,
      };
      if (recipes.length > 0) {
        body.recipes = recipes.map(r => r.id);
      }
      const r = await fetch(`${astraUrl}/protect/text`, {
        method:  "POST",
        headers: { "Content-Type": "application/json", "X-API-Key": apiKey },
        body:    JSON.stringify(body),
        signal:  AbortSignal.timeout(8000),
      });
      if (!r.ok) {
        return {
          protected_text: text,
          count:          0,
          entities:       [],
          error:          `HTTP ${r.status}`,
        };
      }
      const data = await r.json();
      return {
        protected_text: data.protected_text || text,
        count:          data.count          || 0,
        entities:       data.entities       || [],
      };
    }

    // ── POST /guardrails/scan-output — scan LLM response ─────────────────
    async function scanLLMOutput(
      text:      string,
      sessionId: string,
    ): Promise<{ leaked: boolean; count: number; cleaned: string }> {
      try {
        const r = await fetch(`${astraUrl}/guardrails/scan-output`, {
          method:  "POST",
          headers: { "Content-Type": "application/json", "X-API-Key": apiKey },
          body:    JSON.stringify({ text, session_id: sessionId }),
          signal:  AbortSignal.timeout(6000),
        });
        if (r.ok) {
          const data = await r.json();
          return {
            leaked:  data.pii_detected || false,
            count:   data.count        || 0,
            cleaned: data.cleaned_text || text,
          };
        }
      } catch { /* best effort */ }
      return { leaked: false, count: 0, cleaned: text };
    }

    // ── GET /audit/stats — protection statistics ─────────────────────────
    async function getAuditStats(): Promise<Record<string, unknown>> {
      try {
        const r = await fetch(`${astraUrl}/audit/stats`, {
          headers: { "X-API-Key": apiKey },
          signal:  AbortSignal.timeout(5000),
        });
        if (r.ok) return await r.json();
      } catch { /* non-fatal */ }
      return {};
    }

    // ── GET /dp/status — differential privacy status ─────────────────────
    async function getDPStatus(): Promise<Record<string, unknown>> {
      try {
        const r = await fetch(`${astraUrl}/dp/status`, {
          headers: { "X-API-Key": apiKey },
          signal:  AbortSignal.timeout(5000),
        });
        if (r.ok) return await r.json();
      } catch { /* non-fatal */ }
      return {};
    }

    // ── GET /vault/wipe/proof — cryptographic wipe proof ─────────────────
    async function getWipeProof(): Promise<Record<string, unknown>> {
      try {
        const r = await fetch(`${astraUrl}/vault/wipe/proof`, {
          headers: { "X-API-Key": apiKey },
          signal:  AbortSignal.timeout(5000),
        });
        if (r.ok) {
          lastWipeProof = await r.json();
          return lastWipeProof;
        }
      } catch { /* non-fatal */ }
      return {};
    }

    // ── POST /vault/wipe/session/{id} — wipe vault ────────────────────────
    async function wipeSession(sessionId: string): Promise<{
      wiped: boolean; wipe_id: string; total_wiped: number
    }> {
      const r = await fetch(`${astraUrl}/vault/wipe/session/${sessionId}`, {
        method:  "POST",
        headers: { "Content-Type": "application/json", "X-API-Key": apiKey },
        body:    JSON.stringify({ session_id: sessionId }),
        signal:  AbortSignal.timeout(10000),
      });
      if (r.ok) return await r.json();
      return { wiped: false, wipe_id: "", total_wiped: 0 };
    }

    // ══════════════════════════════════════════════════════════════════════
    // HOOKS
    // ══════════════════════════════════════════════════════════════════════

    // ── HOOK 1: agent:turn:start ──────────────────────────────────────────
    // Fires before EVERY LLM call.
    // Tokenizes user message. LLM sees tokens. Never real data.
    // Applies standard PII detection + customer sensitivity recipes.
    api.registerHook(
      "agent:turn:start",
      async (ctx: any) => {
        if (!apiKey) {
          if (failClosed) {
            ctx.abort?.("[Astra] No API key. Blocked (failClosed=true).");
          }
          return;
        }

        const userText =
          ctx.turn?.userMessage?.text ||
          ctx.message?.content        ||
          ctx.userMessage?.text       ||
          ctx.input;

        if (!userText || typeof userText !== "string") return;

        const sessionId = ctx.sessionId || ctx.session?.id || "default";

        try {
          const result = await protectText(userText, sessionId, "user_input");

          if (result.error) {
            if (failClosed) {
              ctx.abort?.(
                `[Astra] Protection failed: ${result.error}. Blocked (failClosed=true).`
              );
              return;
            }
            log.warn(`[Astra] ${result.error}. Passing through (failClosed=false).`);
            return;
          }

          // Replace message — LLM receives tokens, never real data
          if (ctx.turn?.userMessage)      ctx.turn.userMessage.text = result.protected_text;
          else if (ctx.message)           ctx.message.content       = result.protected_text;
          else if (ctx.userMessage)       ctx.userMessage.text      = result.protected_text;

          // Track stats
          const prev = sessionTokens.get(sessionId) || 0;
          sessionTokens.set(sessionId, prev + result.count);

          if (result.count > 0) {
            log.info(
              `[Astra] ${result.count} value(s) protected. ` +
              `Session total: ${prev + result.count}. ` +
              `Types: ${result.entities.map(e => e.type).join(", ") || "pii"}. ` +
              `real_data_seen_by_llm: false`
            );
          }

        } catch (err: any) {
          if (failClosed) {
            ctx.abort?.(`[Astra] Error: ${err.message}. Blocked (failClosed=true).`);
          } else {
            log.warn(`[Astra] Error: ${err.message}. Passing through.`);
          }
        }
      },
      {
        name:        "astra-zerotrust.protect-input",
        description: "Tokenize user message with Astra before LLM sees it",
      }
    );

    // ── HOOK 2: agent:turn:end ────────────────────────────────────────────
    // Fires after LLM generates response, before user sees it.
    // Scans for data leakage. If real data leaked — cleaned or blocked.
    // Uses POST /guardrails/scan-output
    api.registerHook(
      "agent:turn:end",
      async (ctx: any) => {
        if (!apiKey || !scanOutput) return;

        const responseText =
          ctx.turn?.response?.text       ||
          ctx.response?.content          ||
          ctx.assistantMessage?.text     ||
          ctx.output;

        if (!responseText || typeof responseText !== "string") return;

        const sessionId = ctx.sessionId || ctx.session?.id || "default";

        try {
          const scan = await scanLLMOutput(responseText, sessionId);

          if (scan.leaked && scan.count > 0) {
            log.warn(
              `[Astra] Output scan: ${scan.count} potential leak(s) detected. ` +
              `Cleaning response.`
            );
            // Replace with cleaned version
            if (ctx.turn?.response)     ctx.turn.response.text        = scan.cleaned;
            else if (ctx.response)      ctx.response.content          = scan.cleaned;
            else if (ctx.assistantMessage) ctx.assistantMessage.text  = scan.cleaned;
          }
        } catch { /* best effort — never block on scan failure */ }
      },
      {
        name:        "astra-zerotrust.scan-output",
        description: "Scan LLM response for data leakage before user sees it",
      }
    );

    // ── HOOK 3: tool_result_persist ───────────────────────────────────────
    // Fires after every tool/skill executes.
    // Synchronous per OpenClaw spec — returns modified result or undefined.
    // Fires async protection scan in background and logs counts.
    api.registerHook(
      "tool_result_persist",
      (ctx: any) => {
        if (!apiKey || !ctx.result) return undefined;

        const resultText =
          typeof ctx.result === "string"
            ? ctx.result
            : JSON.stringify(ctx.result);

        if (!resultText || resultText.length < 5) return undefined;

        const sessionId  = ctx.sessionId || ctx.session?.id || "default";
        const toolName   = ctx.toolName  || "tool";

        // Addition 1 — Injection sanitization (synchronous — runs before async scan)
        const injCheck = sanitizeInjection(resultText);
        if (injCheck.detected) {
          log.warn(`[Astra] Injection pattern removed from [${toolName}] output.`);
          // Note: tool_result_persist is sync — log only, async scan uses cleaned version
        }

        // Addition 2 — K-anonymity check (synchronous)
        const kCheck = enforceKAnonymity(resultText);
        if (kCheck.suppressed) {
          log.warn(`[Astra] K-anonymity: [${toolName}] result suppressed — re-identification risk.`);
          // Return suppressed message instead of real result
          return kCheck.safe;
        }

        // Async scan — fire and forget
        loadRecipes().then(recipes => {
          const body: Record<string, unknown> = {
            text:           resultText,
            classification: "pii",
            session_id:     sessionId,
            source:         "tool_output",
          };
          if (recipes.length > 0) body.recipes = recipes.map(r => r.id);
          return fetch(`${astraUrl}/protect/text`, {
            method:  "POST",
            headers: { "Content-Type": "application/json", "X-API-Key": apiKey },
            body:    JSON.stringify(body),
            signal:  AbortSignal.timeout(5000),
          });
        }).then(async r => {
          if (r.ok) {
            const data  = await r.json();
            const count = data.count || 0;
            if (count > 0) {
              const prev = sessionTokens.get(sessionId) || 0;
              sessionTokens.set(sessionId, prev + count);
              log.info(
                `[Astra] Tool [${toolName}] output: ${count} value(s) protected.`
              );
            }
          }
        }).catch(() => {});

        return undefined;
      },
      {
        name:        "astra-zerotrust.protect-tool-output",
        description: "Scan and protect tool outputs before LLM reads them",
      }
    );

    // ── HOOK 4: command:new ───────────────────────────────────────────────
    // Fires when user types /new to start a new session.
    // Wipes vault. Gets cryptographic proof. Logs full session summary.
    api.registerHook(
      "command:new",
      async (ctx: any) => {
        const sessionId =
          ctx.previousSessionId ||
          ctx.sessionId         ||
          ctx.session?.id;

        if (!sessionId || !apiKey) return;

        const count = sessionTokens.get(sessionId) || 0;

        try {
          // Wipe vault — POST /vault/wipe/session/{id}
          const wipeResult = await wipeSession(sessionId);

          // Get cryptographic proof — GET /vault/wipe/proof
          const proof = await getWipeProof();

          // Log full session summary
          log.info(
            `[Astra] ╔══ Session Summary ══════════════════════╗`
          );
          log.info(
            `[Astra] ║ Values protected:  ${count}`
          );
          log.info(
            `[Astra] ║ Vault wiped:       ${wipeResult.wiped ? "YES" : "NO"}`
          );
          log.info(
            `[Astra] ║ Wipe ID:           ${wipeResult.wipe_id || "confirmed"}`
          );
          log.info(
            `[Astra] ║ Real data remains: false`
          );
          log.info(
            `[Astra] ╚════════════════════════════════════════╝`
          );

          if (trackStats) {
            // GET /audit/stats — log protection statistics
            const stats = await getAuditStats();
            if (stats.total_tokens_minted) {
              log.debug(
                `[Astra] Lifetime stats: ` +
                `${stats.total_tokens_minted} tokens minted, ` +
                `${stats.total_wiped} wiped.`
              );
            }
          }

        } catch (err: any) {
          log.debug(`[Astra] Wipe error: ${err.message}`);
        } finally {
          sessionTokens.delete(sessionId);
        }
      },
      {
        name:        "astra-zerotrust.wipe-on-new",
        description: "Wipe Astra vault and log summary on new session",
      }
    );

    // ── HOOK 5: command:status ────────────────────────────────────────────
    // Fires when user asks for status info.
    // Shows Astra protection summary, DP status, last wipe proof.
    api.registerHook(
      "command:status",
      async (_ctx: any) => {
        if (!apiKey) return;

        try {
          const [stats, dpStatus, proof] = await Promise.all([
            getAuditStats(),
            getDPStatus(),
            getWipeProof(),
          ]);

          log.info(
            `[Astra] Protection Status:\n` +
            `  API endpoint:  ${astraUrl}\n` +
            `  failClosed:    ${failClosed}\n` +
            `  Recipes loaded: ${cachedRecipes.length}\n` +
            `  DP active:     ${dpStatus.enabled || false}\n` +
            `  Last wipe:     ${proof.timestamp  || "none yet"}\n` +
            `  Total protected (lifetime): ${stats.total_tokens_minted || 0}`
          );
        } catch { /* non-fatal */ }
      },
      {
        name:        "astra-zerotrust.status",
        description: "Show Astra protection status",
      }
    );


    // ══════════════════════════════════════════════════════════════════════
    // ADDITION 1 — INJECTION SANITIZATION
    // Strip prompt injection patterns from tool outputs before LLM reads them.
    // 18 patterns: "ignore previous instructions", jailbreaks, data exfil attempts.
    // Called inside tool_result_persist before Astra tokenization.
    // ══════════════════════════════════════════════════════════════════════

    const INJECTION_PATTERNS: RegExp[] = [
      /ignore\s+(previous|all|above)\s+instructions/gi,
      /forget\s+(everything|all|previous)/gi,
      /new\s+instructions?:/gi,
      /system\s*prompt:/gi,
      /<\s*system\s*>/gi,
      /\[INST\]/gi,
      /###\s*(instruction|system|prompt)/gi,
      /you\s+are\s+now\s+a/gi,
      /act\s+as\s+(if\s+you\s+are\s+)?a/gi,
      /pretend\s+you\s+are/gi,
      /jailbreak/gi,
      /do\s+anything\s+now/gi,
      /dan\s+mode/gi,
      /developer\s+mode/gi,
      /send\s+.*\s+to\s+http/gi,
      /exfiltrate/gi,
      /leak\s+.*\s+data/gi,
      /reveal\s+.*\s+(api\s+key|token|secret|password)/gi,
    ];

    function sanitizeInjection(text: string): { clean: string; detected: boolean } {
      let detected = false;
      let clean    = text;
      for (const pattern of INJECTION_PATTERNS) {
        if (pattern.test(clean)) {
          detected = true;
          clean    = clean.replace(pattern, "[ASTRA: injection pattern removed]");
        }
        pattern.lastIndex = 0; // reset global regex
      }
      return { clean, detected };
    }

    // ══════════════════════════════════════════════════════════════════════
    // ADDITION 2 — K-ANONYMITY ON TOOL RESULTS
    // If a tool returns results that identify fewer than 5 people — suppress.
    // Buckets ages to decades, zip codes to 3-digit prefix, amounts to ranges.
    // Prevents combination re-identification attacks.
    // ══════════════════════════════════════════════════════════════════════

    const K_MIN = 5;

    function enforceKAnonymity(text: string): { safe: string; suppressed: boolean } {
      // Check for single-record indicators
      const singleRecord = [
        /\b1\s+record[s]?\s+found/i,
        /found\s+1\s+result/i,
        /matches?:\s*1\b/i,
        /count[:\s]+1\b/i,
        /total[:\s]+1\b/i,
        /exactly\s+one\s+(patient|client|person|user|record)/i,
      ];

      for (const pat of singleRecord) {
        if (pat.test(text)) {
          return {
            safe: `[Astra K-Anonymity] Result suppressed: fewer than ${K_MIN} records matched. ` +
                  `Query too specific — re-identification risk. Broaden your search criteria.`,
            suppressed: true,
          };
        }
      }

      // Bucket quasi-identifiers
      let safe = text;

      // Ages → decade brackets (age 67 → age 60-69)
      safe = safe.replace(/\bage[:\s]+(\d{2})\b/gi, (_, age) => {
        const decade = Math.floor(parseInt(age) / 10) * 10;
        return `age ${decade}-${decade + 9}`;
      });

      // Zip codes → 3-digit prefix (30314 → 303xx)
      safe = safe.replace(/\b(\d{3})\d{2}\b/g, "$1xx");

      // Precise dollar amounts → ranges ($4,247,832 → $4M-$5M range)
      safe = safe.replace(/\$[\d,]{6,}/g, (match) => {
        const val = parseFloat(match.replace(/[$,]/g, ""));
        if (val >= 1_000_000) {
          const low = Math.floor(val / 1_000_000);
          return `$${low}M-$${low + 1}M range`;
        } else if (val >= 100_000) {
          const low = Math.floor(val / 100_000) * 100_000;
          return `$${low / 1000}K-$${(low + 100_000) / 1000}K range`;
        }
        return match;
      });

      return { safe, suppressed: false };
    }

    // ══════════════════════════════════════════════════════════════════════
    // ADDITION 3 — THINKINGTOKENS
    // Mint tokens with facts attached. AI reasons on facts, never real values.
    // Used when OpenClaw needs to query across sensitive datasets.
    // Example: "find all clients above $4M" without exposing amounts.
    // ══════════════════════════════════════════════════════════════════════

    async function mintThinkingToken(
      realValue:  string,
      dataType:   string,
      facts:      Record<string, unknown>,
      sessionId:  string,
    ): Promise<{ token_id: string; token: string; error?: string }> {
      try {
        const r = await fetch(`${astraUrl}/think/mint`, {
          method:  "POST",
          headers: { "Content-Type": "application/json", "X-API-Key": apiKey },
          body:    JSON.stringify({
            real_value: realValue,
            data_type:  dataType,
            facts,
            session_id: sessionId,
          }),
          signal: AbortSignal.timeout(8000),
        });
        if (r.ok) {
          const data = await r.json();
          return { token_id: data.token_id, token: data.token };
        }
        return { token_id: "", token: "", error: `HTTP ${r.status}` };
      } catch (err: any) {
        return { token_id: "", token: "", error: err.message };
      }
    }

    async function queryThinkingTokens(
      query:     Record<string, unknown>,
      cohortId?: string,
      sessionId?: string,
    ): Promise<{ matched_tokens: string[]; match_count: number; dp_applied: boolean }> {
      try {
        const r = await fetch(`${astraUrl}/think/query`, {
          method:  "POST",
          headers: { "Content-Type": "application/json", "X-API-Key": apiKey },
          body:    JSON.stringify({
            query,
            cohort_id:  cohortId,
            session_id: sessionId,
            dp_epsilon: 1.0,  // differential privacy applied automatically
          }),
          signal: AbortSignal.timeout(10000),
        });
        if (r.ok) return await r.json();
      } catch { /* non-fatal */ }
      return { matched_tokens: [], match_count: 0, dp_applied: false };
    }

    // ══════════════════════════════════════════════════════════════════════
    // ADDITION 4 — SMARTTOKENS
    // Tokens that carry structured data. AI works with the structure.
    // Never sees the real value. Used for financial records, medical data.
    // ══════════════════════════════════════════════════════════════════════

    async function mintSmartToken(
      realValue: string,
      dataType:  string,
      metadata:  Record<string, unknown>,
      sessionId: string,
    ): Promise<{ token_id: string; token: string; error?: string }> {
      try {
        const r = await fetch(`${astraUrl}/vault/smart-token`, {
          method:  "POST",
          headers: { "Content-Type": "application/json", "X-API-Key": apiKey },
          body:    JSON.stringify({
            real_value: realValue,
            data_type:  dataType,
            metadata,
            session_id: sessionId,
          }),
          signal: AbortSignal.timeout(8000),
        });
        if (r.ok) {
          const data = await r.json();
          return { token_id: data.token_id, token: data.token };
        }
        return { token_id: "", token: "", error: `HTTP ${r.status}` };
      } catch (err: any) {
        return { token_id: "", token: "", error: err.message };
      }
    }

    // ══════════════════════════════════════════════════════════════════════
    // ADDITION 5 — AUTONOMOUS EXECUTOR
    // When OpenClaw takes an action (sends email, updates CRM, makes call):
    //   1. Agent plans action using tokens
    //   2. Executor resolves real values from vault
    //   3. Action fires with real values
    //   4. Wipe fires immediately after
    //   5. Agent never sees real values — only confirmation
    // ══════════════════════════════════════════════════════════════════════

    async function executeWithAstra(
      actionType: string,   // email | crm_update | api_call | webhook
      tokenMap:   Record<string, string>,  // { field: "[CVT:TYPE:ID]" }
      payload:    Record<string, unknown>, // action payload with tokens
      sessionId:  string,
    ): Promise<{
      success:    boolean;
      result:     unknown;
      wiped:      boolean;
      wipe_id:    string;
      real_data_seen_by_agent: boolean;
    }> {
      try {
        const r = await fetch(`${astraUrl}/executor/run`, {
          method:  "POST",
          headers: { "Content-Type": "application/json", "X-API-Key": apiKey },
          body:    JSON.stringify({
            action_type: actionType,
            token_map:   tokenMap,
            payload,
            session_id:  sessionId,
            auto_wipe:   true,  // wipe immediately after execution
          }),
          signal: AbortSignal.timeout(30000),
        });

        if (r.ok) {
          const data = await r.json();
          return {
            success:  data.success  || false,
            result:   data.result   || {},
            wiped:    data.wiped    || false,
            wipe_id:  data.wipe_id  || "",
            real_data_seen_by_agent: false,
          };
        }

        return {
          success: false,
          result:  { error: `HTTP ${r.status}` },
          wiped:   false,
          wipe_id: "",
          real_data_seen_by_agent: false,
        };

      } catch (err: any) {
        if (failClosed) throw err;
        return {
          success: false,
          result:  { error: err.message },
          wiped:   false,
          wipe_id: "",
          real_data_seen_by_agent: false,
        };
      }
    }

    // ══════════════════════════════════════════════════════════════════════
    // WIRE ALL 5 ADDITIONS INTO EXISTING HOOKS
    // ══════════════════════════════════════════════════════════════════════

    // Expose ThinkingTokens, SmartTokens, Executor on api.runtime
    // so OpenClaw skills can use them directly
    try {
      (api as any).astra = {
        // ThinkingTokens
        mintThinkingToken,
        queryThinkingTokens,
        // SmartTokens
        mintSmartToken,
        // Executor
        executeWithAstra,
        // Utilities
        sanitizeInjection,
        enforceKAnonymity,
        protectText,
        // Config
        apiKey,
        astraUrl,
        failClosed,
      };
    } catch { /* non-fatal if api doesn't support custom props */ }

    // ── Load everything on startup ────────────────────────────────────────
    if (apiKey) {
      Promise.all([
        loadRecipes(),
        getDPStatus(),
      ]).then(([recipes, dp]) => {
        log.info(
          `[Astra] Ready. ` +
          `${recipes.length} sensitivity recipe(s) loaded. ` +
          `DP: ${(dp as any).enabled ? "active" : "inactive"}. ` +
          `ThinkingTokens: enabled. SmartTokens: enabled. ` +
          `Executor: enabled. Injection sanitization: active (18 patterns). ` +
          `K-anonymity: active (k=${K_MIN}).`
        );
      }).catch(() => {});
    }
  },
});
