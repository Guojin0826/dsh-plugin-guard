/**
 * dsh-plugin-guard host Remote service (`ctx.guard`, wire namespace `guard`).
 * Registered as a TypertRemoteService so the Gateway exports `getReport` to
 * the Web client under `/api/guard/getReport` with zero generated artifacts.
 */
import type { Context } from '@deepseek-ai/cordis';
import { TypertRemoteService } from '@deepseek-ai/dsh-typert-protocol';
import type { AiAuditResult, AuditProgress, GithubTokenStatus, SecurityReport } from './contracts.ts';
/** Resolved, defaults-applied plugin configuration. */
export interface ResolvedConfig {
    /** Profile name under `$DSH_HOME/profiles` to audit. */
    profile: string;
    /** Hard cap on source files scanned per plugin. */
    maxScanFiles: number;
    /** Optional GitHub PAT for authenticated repo/owner lookups; empty = anonymous. */
    githubToken: string;
}
export declare class GuardRuntime extends TypertRemoteService {
    private readonly config;
    /** Live progress of in-flight AI audits, keyed by plugin name. Entries persist after completion so a reopened panel can read the last status. */
    private readonly progress;
    /** GitHub PAT in effect for reputation lookups (config first, then a persisted panel-set value). */
    private githubToken;
    constructor(ctx: Context, config: ResolvedConfig);
    /** Resolve the audited profile directory from `$DSH_HOME` (+ the configured profile name). */
    private profileDir;
    /** Directory holding the plugin's own persisted token file (best-effort, Host-local). */
    private tokenDir;
    private tokenFile;
    private loadPersistedToken;
    private persistToken;
    /** Record an audit phase for one plugin, keeping the original start timestamp. */
    private track;
    /** Run a fresh static audit over the profile's installed third-party plugins. */
    getReport(): Promise<SecurityReport>;
    /** Ask the default model to assess one plugin against both the static scan and source evidence. */
    getAiAudit(pluginName: string): Promise<AiAuditResult>;
    /** Poll the current AI audit progress for one plugin, or `null` when none has been recorded. */
    getAiAuditStatus(pluginName: string): Promise<AuditProgress | null>;
    /** Masked state of the GitHub token (never returns the token value itself). */
    getGithubTokenStatus(): Promise<GithubTokenStatus>;
    /** Store (or clear, with an empty string) the GitHub PAT used by `getAiAudit` reputation lookups. */
    setGithubToken(token: string): Promise<GithubTokenStatus>;
}
