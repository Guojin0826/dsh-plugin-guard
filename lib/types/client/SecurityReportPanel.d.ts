/** Settings section rendering the plugin security audit report (green/yellow/red) plus per-plugin AI audit with live progress. */
import type { InjectFace, PropsLocale } from '@deepseek-ai/dsh-client-ui-slots';
import { type ReactElement } from 'react';
import type { AiAuditResult, AuditCacheConfig, AuditProgress, GithubTokenStatus, SafeSkillReport, SafeSkillStatus, SecurityReport, SkillEntry, SkillScanResult } from '../contracts.ts';
export interface SecuritySectionInjected {
    getReport: () => Promise<SecurityReport>;
    getAiAudit: (pluginName: string) => Promise<AiAuditResult>;
    forceAiAudit: (pluginName: string) => Promise<AiAuditResult>;
    getAiAuditStatus: (pluginName: string) => Promise<AuditProgress | null>;
    getAiAuditCacheSnapshot: () => Promise<AiAuditResult[]>;
    getGithubTokenStatus: () => Promise<GithubTokenStatus>;
    setGithubToken: (token: string) => Promise<GithubTokenStatus>;
    getAuditConfig: () => Promise<AuditCacheConfig>;
    setAuditTtl: (ttlHours: number) => Promise<AuditCacheConfig>;
    getSafeSkillStatus: () => Promise<SafeSkillStatus>;
    setSafeSkillKey: (key: string) => Promise<SafeSkillStatus>;
    listSkills: () => Promise<SkillEntry[]>;
    scanSkill: (skillName: string) => Promise<SafeSkillReport>;
    getSafeSkillCacheSnapshot: () => Promise<SkillScanResult[]>;
    scanAllSkills: () => Promise<SkillScanResult[]>;
}
type SecuritySectionProps = InjectFace<SecuritySectionInjected> & PropsLocale<'dsh-plugin-guard'>;
export declare function SecuritySection({ getReport, getAiAudit, forceAiAudit, getAiAuditStatus, getAiAuditCacheSnapshot, getGithubTokenStatus, setGithubToken, getAuditConfig, setAuditTtl, getSafeSkillStatus, setSafeSkillKey, listSkills, scanSkill, getSafeSkillCacheSnapshot, scanAllSkills, t }: SecuritySectionProps): ReactElement;
export {};
