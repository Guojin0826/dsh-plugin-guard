/** Settings section rendering the plugin security audit report (green/yellow/red) plus per-plugin AI audit with live progress. */
import type { InjectFace, PropsLocale } from '@deepseek-ai/dsh-client-ui-slots';
import { type ReactElement } from 'react';
import type { AiAuditResult, AuditProgress, GithubTokenStatus, SecurityReport } from '../contracts.ts';
export interface SecuritySectionInjected {
    getReport: () => Promise<SecurityReport>;
    getAiAudit: (pluginName: string) => Promise<AiAuditResult>;
    getAiAuditStatus: (pluginName: string) => Promise<AuditProgress | null>;
    getGithubTokenStatus: () => Promise<GithubTokenStatus>;
    setGithubToken: (token: string) => Promise<GithubTokenStatus>;
}
type SecuritySectionProps = InjectFace<SecuritySectionInjected> & PropsLocale<'dsh-plugin-guard'>;
export declare function SecuritySection({ getReport, getAiAudit, getAiAuditStatus, getGithubTokenStatus, setGithubToken, t }: SecuritySectionProps): ReactElement;
export {};
