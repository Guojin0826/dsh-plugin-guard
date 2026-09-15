/**
 * The client-side Typert Remote contribution for the dsh-plugin-guard host
 * service: mounts the shared strict descriptors into `ctx.remote.guard`.
 * The descriptors and codecs come from the shared contract module, so the
 * browser bundle and the host manifest stay on one wire definition.
 */
import type { RemoteResult, TypertRemoteContribution } from '@deepseek-ai/dsh-typert-protocol'
import { GUARD_INVOCATIONS } from '../contracts.ts'
import type { AiAuditResult, AuditCacheConfig, AuditProgress, GithubTokenStatus, SafeSkillStatus, SecurityReport, SkillAiAuditOutcome, SkillAiAuditResult, SkillEntry, SkillScanResult } from '../contracts.ts'

export type { SecurityReport, AiAuditResult, AuditCacheConfig, AuditProgress, GithubTokenStatus, SafeSkillStatus, SkillAiAuditOutcome, SkillAiAuditResult, SkillEntry, SkillScanResult } from '../contracts.ts'

/** The guard Remote namespace's client contribution. */
export const GUARD_REMOTE: TypertRemoteContribution = {
  package: 'dsh-plugin-guard',
  descriptors: GUARD_INVOCATIONS,
}

declare module '@deepseek-ai/dsh-typert-protocol' {
  /** Typed face of the mounted `guard` namespace. */
  interface TypertRemoteNamespace$guard {
    getReport: () => Promise<RemoteResult<SecurityReport>>
    getAiAudit: (pluginName: string) => Promise<RemoteResult<AiAuditResult>>
    forceAiAudit: (pluginName: string) => Promise<RemoteResult<AiAuditResult>>
    getAiAuditStatus: (pluginName: string) => Promise<RemoteResult<AuditProgress | null>>
    getGithubTokenStatus: () => Promise<RemoteResult<GithubTokenStatus>>
    setGithubToken: (token: string) => Promise<RemoteResult<GithubTokenStatus>>
    getAuditConfig: () => Promise<RemoteResult<AuditCacheConfig>>
    setAuditTtl: (ttlHours: number) => Promise<RemoteResult<AuditCacheConfig>>
    getAiAuditCacheSnapshot: () => Promise<RemoteResult<AiAuditResult[]>>
    getSafeSkillStatus: () => Promise<RemoteResult<SafeSkillStatus>>
    setSafeSkillKey: (key: string) => Promise<RemoteResult<SafeSkillStatus>>
    listSkills: () => Promise<RemoteResult<SkillEntry[]>>
    scanSkill: (skillName: string) => Promise<RemoteResult<SkillScanResult>>
    getSafeSkillCacheSnapshot: () => Promise<RemoteResult<SkillScanResult[]>>
    scanAllSkills: () => Promise<RemoteResult<SkillScanResult[]>>
    auditSkill: (skillName: string) => Promise<RemoteResult<SkillAiAuditOutcome>>
    getSkillAiAuditSnapshot: () => Promise<RemoteResult<SkillAiAuditResult[]>>
  }
  interface TypertRemoteMap {
    'guard/getReport': () => Promise<RemoteResult<SecurityReport>>
    'guard/getAiAudit': (pluginName: string) => Promise<RemoteResult<AiAuditResult>>
    'guard/forceAiAudit': (pluginName: string) => Promise<RemoteResult<AiAuditResult>>
    'guard/getAiAuditStatus': (pluginName: string) => Promise<RemoteResult<AuditProgress | null>>
    'guard/getGithubTokenStatus': () => Promise<RemoteResult<GithubTokenStatus>>
    'guard/setGithubToken': (token: string) => Promise<RemoteResult<GithubTokenStatus>>
    'guard/getAuditConfig': () => Promise<RemoteResult<AuditCacheConfig>>
    'guard/setAuditTtl': (ttlHours: number) => Promise<RemoteResult<AuditCacheConfig>>
    'guard/getAiAuditCacheSnapshot': () => Promise<RemoteResult<AiAuditResult[]>>
    'guard/getSafeSkillStatus': () => Promise<RemoteResult<SafeSkillStatus>>
    'guard/setSafeSkillKey': (key: string) => Promise<RemoteResult<SafeSkillStatus>>
    'guard/listSkills': () => Promise<RemoteResult<SkillEntry[]>>
    'guard/scanSkill': (skillName: string) => Promise<RemoteResult<SkillScanResult>>
    'guard/getSafeSkillCacheSnapshot': () => Promise<RemoteResult<SkillScanResult[]>>
    'guard/scanAllSkills': () => Promise<RemoteResult<SkillScanResult[]>>
    'guard/auditSkill': (skillName: string) => Promise<RemoteResult<SkillAiAuditOutcome>>
    'guard/getSkillAiAuditSnapshot': () => Promise<RemoteResult<SkillAiAuditResult[]>>
  }
  interface TypertRemoteNamespaceMap {
    guard: TypertRemoteNamespace$guard
  }
}