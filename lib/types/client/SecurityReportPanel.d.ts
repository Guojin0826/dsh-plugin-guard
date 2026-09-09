/** Settings section rendering the plugin security audit report (green/yellow/red) plus per-plugin AI audit with live progress. */
import type { InjectFace, PropsLocale } from '@deepseek-ai/dsh-client-ui-slots';
import { type ReactElement } from 'react';
import type { AiAuditResult, AuditCacheConfig, AuditProgress, GithubTokenStatus, SecurityReport } from '../contracts.ts';
export interface SecuritySectionInjected {
    getReport: () => Promise<SecurityReport>;
    getAiAudit: (pluginName: string) => Promise<AiAuditResult>;
    forceAiAudit: (pluginName: string) => Promise<AiAuditResult>;
    getAiAuditStatus: (pluginName: string) => Promise<AuditProgress | null>;
    getGithubTokenStatus: () => Promise<GithubTokenStatus>;
    setGithubToken: (token: string) => Promise<GithubTokenStatus>;
    getAuditConfig: () => Promise<AuditCacheConfig>;
    setAuditTtl: (ttlHours: number) => Promise<AuditCacheConfig>;
}
type SecuritySectionProps = InjectFace<SecuritySectionInjected> & PropsLocale<'dsh-plugin-guard'>;
export declare function SecuritySection({ getReport, getAiAudit, forceAiAudit, getAiAuditStatus, getGithubTokenStatus, setGithubToken, getAuditConfig, setAuditTtl, t }: SecuritySectionProps): ReactElement;
export {};
