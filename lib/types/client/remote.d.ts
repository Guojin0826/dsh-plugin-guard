/**
 * The client-side Typert Remote contribution for the dsh-plugin-guard host
 * service: mounts the shared strict descriptors into `ctx.remote.guard`.
 * The descriptors and codecs come from the shared contract module, so the
 * browser bundle and the host manifest stay on one wire definition.
 */
import type { RemoteResult, TypertRemoteContribution } from '@deepseek-ai/dsh-typert-protocol';
import type { AiAuditResult, AuditProgress, GithubTokenStatus, SafeSkillReport, SafeSkillStatus, SecurityReport, SkillEntry, SkillScanResult } from '../contracts.ts';
export type { SecurityReport, AiAuditResult, AuditProgress, GithubTokenStatus, SafeSkillReport, SafeSkillStatus, SkillEntry, SkillScanResult } from '../contracts.ts';
/** The guard Remote namespace's client contribution. */
export declare const GUARD_REMOTE: TypertRemoteContribution;
declare module '@deepseek-ai/dsh-typert-protocol' {
    /** Typed face of the mounted `guard` namespace. */
    interface TypertRemoteNamespace$guard {
        getReport: () => Promise<RemoteResult<SecurityReport>>;
        getAiAudit: (pluginName: string) => Promise<RemoteResult<AiAuditResult>>;
        getAiAuditStatus: (pluginName: string) => Promise<RemoteResult<AuditProgress | null>>;
        getAiAuditCacheSnapshot: () => Promise<RemoteResult<AiAuditResult[]>>;
        getGithubTokenStatus: () => Promise<RemoteResult<GithubTokenStatus>>;
        setGithubToken: (token: string) => Promise<RemoteResult<GithubTokenStatus>>;
        getSafeSkillStatus: () => Promise<RemoteResult<SafeSkillStatus>>;
        setSafeSkillKey: (key: string) => Promise<RemoteResult<SafeSkillStatus>>;
        listSkills: () => Promise<RemoteResult<SkillEntry[]>>;
        scanSkill: (skillName: string) => Promise<RemoteResult<SafeSkillReport>>;
        getSafeSkillCacheSnapshot: () => Promise<RemoteResult<SkillScanResult[]>>;
        scanAllSkills: () => Promise<RemoteResult<SkillScanResult[]>>;
    }
    interface TypertRemoteMap {
        'guard/getReport': () => Promise<RemoteResult<SecurityReport>>;
        'guard/getAiAudit': (pluginName: string) => Promise<RemoteResult<AiAuditResult>>;
        'guard/getAiAuditStatus': (pluginName: string) => Promise<RemoteResult<AuditProgress | null>>;
        'guard/getAiAuditCacheSnapshot': () => Promise<RemoteResult<AiAuditResult[]>>;
        'guard/getGithubTokenStatus': () => Promise<RemoteResult<GithubTokenStatus>>;
        'guard/setGithubToken': (token: string) => Promise<RemoteResult<GithubTokenStatus>>;
        'guard/getSafeSkillStatus': () => Promise<RemoteResult<SafeSkillStatus>>;
        'guard/setSafeSkillKey': (key: string) => Promise<RemoteResult<SafeSkillStatus>>;
        'guard/listSkills': () => Promise<RemoteResult<SkillEntry[]>>;
        'guard/scanSkill': (skillName: string) => Promise<RemoteResult<SafeSkillReport>>;
        'guard/getSafeSkillCacheSnapshot': () => Promise<RemoteResult<SkillScanResult[]>>;
        'guard/scanAllSkills': () => Promise<RemoteResult<SkillScanResult[]>>;
    }
    interface TypertRemoteNamespaceMap {
        guard: TypertRemoteNamespace$guard;
    }
}
