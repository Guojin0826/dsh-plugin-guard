/**
 * dsh-plugin-guard AI audit: calls the harness default model with a layered
 * picture — the plugin's *self-declared purpose* (package.json/README), the
 * static code findings plus source evidence, and a best-effort *internet
 * reputation* lookup (npm registry + weekly downloads + a web search). The
 * model is told to judge whether dangerous capabilities are consistent with
 * the plugin's stated job, not to flag them in isolation. Runs entirely on the
 * Host; the Web client only sees the typed `AiAuditResult` over the guard
 * Remote and the live `AuditProgress` over `guard/getAiAuditStatus`.
 */
import type { Context } from '@deepseek-ai/cordis';
import { type PluginMetadata } from './scanner.ts';
import { type AiAssessment, type AiAuditResult, type AuditPhase, type PluginAudit, type ReputationEvidence } from './contracts.ts';
/** Minimal callable faces; the module stays independent of exact package types. */
interface ModelSelection {
    provider: string;
    model: string;
}
/**
 * Resolve the harness default model identity (provider/model) used for the LLM
 * verdict — exported so the verdict cache can key on it too: switching the
 * default model invalidates an otherwise-matching fingerprint within TTL.
 */
export declare function resolveAuditModel(ctx: Context): ModelSelection;
/** Fallback 0–100 score when the model omits the field (also used for older cached results). */
export declare function scoreFromVerdict(verdict: AiAssessment['verdict']): number;
/**
 * True when the fresh reputation carries a negative signal the cached verdict
 * never saw: a new OSV advisory, a new relevance-filtered malicious/attack web
 * report, or a newly-applied npm deprecation. Any of these invalidates the
 * cached verdict because its "safe" judgment was made without that evidence.
 */
export declare function hasNewNegativeSignal(cached: ReputationEvidence, fresh: ReputationEvidence): boolean;
/**
 * Fetch the live reputation layer (npm registry + OSV + web search + GitHub)
 * for one plugin. Cheap and deterministic enough to refresh on every audit,
 * even when the model verdict itself is served from the cache.
 */
export declare function fetchPluginReputation(plugin: PluginAudit, metadata: PluginMetadata, pluginDir: string, githubToken: string, emit: (phase: AuditPhase, detail: string) => void): Promise<ReputationEvidence>;
/**
 * Audit one plugin with the default model, layered with the plugin's stated
 * purpose and internet-reputation context so the model judges capability vs.
 * function — not raw API presence. Throws with a readable message on
 * resolution, call, or parse failure — the Remote surface turns it into an
 * `ok: false` result the panel renders.
 */
export declare function auditPluginWithAi(ctx: Context, plugin: PluginAudit, profileDir: string, githubToken: string, onProgress?: (phase: AuditPhase, detail: string) => void, prefetchedReputation?: ReputationEvidence): Promise<AiAuditResult>;
export {};
