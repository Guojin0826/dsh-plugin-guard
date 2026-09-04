/**
 * The client-side Typert Remote contribution for the dsh-plugin-guard host
 * service: mounts the shared strict descriptors into `ctx.remote.guard`.
 * The descriptors and codecs come from the shared contract module, so the
 * browser bundle and the host manifest stay on one wire definition.
 */
import type { RemoteResult, TypertRemoteContribution } from '@deepseek-ai/dsh-typert-protocol'
import { GUARD_INVOCATIONS } from '../contracts.ts'
import type { AiAuditResult, AuditProgress, GithubTokenStatus, SecurityReport } from '../contracts.ts'

export type { SecurityReport, AiAuditResult, AuditProgress, GithubTokenStatus } from '../contracts.ts'

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
    getAiAuditStatus: (pluginName: string) => Promise<RemoteResult<AuditProgress | null>>
    getGithubTokenStatus: () => Promise<RemoteResult<GithubTokenStatus>>
    setGithubToken: (token: string) => Promise<RemoteResult<GithubTokenStatus>>
  }
  interface TypertRemoteMap {
    'guard/getReport': () => Promise<RemoteResult<SecurityReport>>
    'guard/getAiAudit': (pluginName: string) => Promise<RemoteResult<AiAuditResult>>
    'guard/getAiAuditStatus': (pluginName: string) => Promise<RemoteResult<AuditProgress | null>>
    'guard/getGithubTokenStatus': () => Promise<RemoteResult<GithubTokenStatus>>
    'guard/setGithubToken': (token: string) => Promise<RemoteResult<GithubTokenStatus>>
  }
  interface TypertRemoteNamespaceMap {
    guard: TypertRemoteNamespace$guard
  }
}