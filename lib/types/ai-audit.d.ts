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
import { type AiAuditResult, type AuditPhase, type PluginAudit } from './contracts.ts';
/**
 * Audit one plugin with the default model, layered with the plugin's stated
 * purpose and internet-reputation context so the model judges capability vs.
 * function — not raw API presence. Throws with a readable message on
 * resolution, call, or parse failure — the Remote surface turns it into an
 * `ok: false` result the panel renders.
 */
export declare function auditPluginWithAi(ctx: Context, plugin: PluginAudit, profileDir: string, githubToken: string, onProgress?: (phase: AuditPhase, detail: string) => void): Promise<AiAuditResult>;
