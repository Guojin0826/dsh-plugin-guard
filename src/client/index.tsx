/**
 * dsh-plugin-guard client plugin: mounts the guard Remote namespace and
 * registers the security-report settings section. The Host re-runs the audit
 * per `getReport` call; the "rescan" button simply re-fetches.
 */
import type {} from '@deepseek-ai/dsh-api-remotes/client'
import type { Context as ClientContext } from '@deepseek-ai/cordis'
// Type-only: brings ctx.slots (SlotRegistry) into this program.
import type {} from '@deepseek-ai/dsh-client-ui-renderer/client'
// Type-only: brings the settings.section SlotMap declaration into this program.
import type {} from '@deepseek-ai/dsh-client-ui-settings/client'
// Type-only: brings the ctx.locale Context merge into this program.
import type {} from '@deepseek-ai/dsh-client-locale/client'
import { GUARD_REMOTE } from './remote.ts'
import { SecuritySection, type SecuritySectionInjected } from './SecurityReportPanel.tsx'
import { NS, zh, en } from './locales.ts'
import type { AiAuditResult, AuditCacheConfig, AuditProgress, GithubTokenStatus, SecurityReport } from '../contracts.ts'

/** Required services: the Remote face, the slot registry, and locale. */
export const inject = ['remote', 'slots', 'locale']

/** The mounted `guard` namespace service's callable face. */
type RemoteOutcome<T> = { ok: true; value: T } | { ok: false; error: { code: string; message: string } }
interface GuardFace {
  getReport(): Promise<RemoteOutcome<SecurityReport>>
  getAiAudit(pluginName: string): Promise<RemoteOutcome<AiAuditResult>>
  getAiAuditStatus(pluginName: string): Promise<RemoteOutcome<AuditProgress | null>>
  getGithubTokenStatus(): Promise<RemoteOutcome<GithubTokenStatus>>
  setGithubToken(token: string): Promise<RemoteOutcome<GithubTokenStatus>>
  getAuditConfig(): Promise<RemoteOutcome<AuditCacheConfig>>
  setAuditTtl(ttlHours: number): Promise<RemoteOutcome<AuditCacheConfig>>
}

/** Compose the security-report surface. */
export function apply(ctx: ClientContext): void {
  ctx.effect(() => ctx.locale.register(NS, { zh, en }), 'dsh-plugin-guard: dictionaries')

  const t = ctx.locale.bind(NS)

  let guard: GuardFace | undefined
  ctx.effect(async () => {
    const dispose = await ctx.remote.$mount(GUARD_REMOTE)
    guard = (ctx.reflect as unknown as { get(name: string): unknown }).get('remote.guard') as GuardFace | undefined
    if (guard === undefined) throw new Error('dsh-plugin-guard: the guard Remote namespace did not mount')
    return () => {
      guard = undefined
      void dispose()
    }
  }, 'dsh-plugin-guard: remote')

  ctx.slots.inject('settings.section', () => ctx.slots.register({
    name: 'settings.section',
    id: 'dsh-plugin-guard',
    order: 60,
    label: () => t('nav'),
    locale: NS,
    inject: (): SecuritySectionInjected => ({
      getReport: async () => {
        if (guard === undefined) throw new Error('dsh-plugin-guard: the guard Remote is not mounted')
        const result = await guard.getReport()
        if (!result.ok) throw new Error(`${result.error.code}: ${result.error.message}`)
        return result.value
      },
      getAiAudit: async (pluginName: string) => {
        if (guard === undefined) throw new Error('dsh-plugin-guard: the guard Remote is not mounted')
        const result = await guard.getAiAudit(pluginName)
        if (!result.ok) throw new Error(`${result.error.code}: ${result.error.message}`)
        return result.value
      },
      getAiAuditStatus: async (pluginName: string) => {
        if (guard === undefined) throw new Error('dsh-plugin-guard: the guard Remote is not mounted')
        const result = await guard.getAiAuditStatus(pluginName)
        if (!result.ok) throw new Error(`${result.error.code}: ${result.error.message}`)
        return result.value
      },
      getGithubTokenStatus: async () => {
        if (guard === undefined) throw new Error('dsh-plugin-guard: the guard Remote is not mounted')
        const result = await guard.getGithubTokenStatus()
        if (!result.ok) throw new Error(`${result.error.code}: ${result.error.message}`)
        return result.value
      },
      setGithubToken: async (token: string) => {
        if (guard === undefined) throw new Error('dsh-plugin-guard: the guard Remote is not mounted')
        const result = await guard.setGithubToken(token)
        if (!result.ok) throw new Error(`${result.error.code}: ${result.error.message}`)
        return result.value
      },
      getAuditConfig: async () => {
        if (guard === undefined) throw new Error('dsh-plugin-guard: the guard Remote is not mounted')
        const result = await guard.getAuditConfig()
        if (!result.ok) throw new Error(`${result.error.code}: ${result.error.message}`)
        return result.value
      },
      setAuditTtl: async (ttlHours: number) => {
        if (guard === undefined) throw new Error('dsh-plugin-guard: the guard Remote is not mounted')
        const result = await guard.setAuditTtl(ttlHours)
        if (!result.ok) throw new Error(`${result.error.code}: ${result.error.message}`)
        return result.value
      },
    }),
  }, SecuritySection))
}