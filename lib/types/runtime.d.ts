/**
 * dsh-plugin-guard host Remote service (`ctx.guard`, wire namespace `guard`).
 * Registered as a TypertRemoteService so the Gateway exports `getReport` to
 * the Web client under `/api/guard/getReport` with zero generated artifacts.
 */
import type { Context } from '@deepseek-ai/cordis';
import { TypertRemoteService } from '@deepseek-ai/dsh-typert-protocol';
import type { AiAuditResult, AuditCacheConfig, AuditProgress, GithubTokenStatus, SecurityReport } from './contracts.ts';
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
    /** File holding the previous scan's baseline, for version-diff alerting (best-effort, Host-local). */
    private baselineFile;
    private loadBaseline;
    private saveBaseline;
    /** File holding the persisted AI-audit result cache (best-effort, Host-local). */
    private aiCacheFile;
    private loadAiCache;
    private saveAiCache;
    /** Current AI-audit cache TTL in hours (0 disables the cache). */
    getAuditConfig(): Promise<AuditCacheConfig>;
    /** Set the AI-audit cache TTL in hours (0 disables the cache) and persist it. */
    setAuditTtl(ttlHours: number): Promise<AuditCacheConfig>;
    /** Run a fresh static audit, diff it against the previous scan's baseline, then persist the new baseline. */
    getReport(): Promise<SecurityReport>;
    /** Assess one plugin: always refresh live reputation, then reuse the cached verdict only when the fingerprint is unchanged, within TTL, and no new negative reputation signal appeared. */
    getAiAudit(pluginName: string): Promise<AiAuditResult>;
    /** Bypass the verdict cache and always run a full model audit for one plugin (reputation still fetched fresh). */
    forceAiAudit(pluginName: string): Promise<AiAuditResult>;
    /**
     * Return every AI verdict still valid in the on-disk cache (fingerprint matched
     * and within TTL), with no network access. The client calls this on mount to
     * restore AI classifications/scores after a page refresh. Purely a display
     * restore: a real `getAiAudit` still re-checks negative reputation signals.
     */
    getAiAuditCacheSnapshot(): Promise<AiAuditResult[]>;
    private runAiAudit;
    /** Poll the current AI audit progress for one plugin, or `null` when none has been recorded. */
    getAiAuditStatus(pluginName: string): Promise<AuditProgress | null>;
    /** Masked state of the GitHub token (never returns the token value itself). */
    getGithubTokenStatus(): Promise<GithubTokenStatus>;
    /** Store (or clear, with an empty string) the GitHub PAT used by `getAiAudit` reputation lookups. */
    setGithubToken(token: string): Promise<GithubTokenStatus>;
}
