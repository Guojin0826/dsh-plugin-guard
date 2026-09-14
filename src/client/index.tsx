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
import type { AiAuditResult, AuditCacheConfig, AuditProgress, GithubTokenStatus, SafeSkillStatus, SecurityReport, SkillEntry, SkillScanResult } from '../contracts.ts'

/** Required services: the Remote face, the slot registry, and locale. */
export const inject = ['remote', 'slots', 'locale']

/** The mounted `guard` namespace service's callable face. */
type RemoteOutcome<T> = { ok: true; value: T } | { ok: false; error: { code: string; message: string } }
interface GuardFace {
  getReport(): Promise<RemoteOutcome<SecurityReport>>
  getAiAudit(pluginName: string): Promise<RemoteOutcome<AiAuditResult>>
  forceAiAudit(pluginName: string): Promise<RemoteOutcome<AiAuditResult>>
  getAiAuditStatus(pluginName: string): Promise<RemoteOutcome<AuditProgress | null>>
  getAiAuditCacheSnapshot(): Promise<RemoteOutcome<AiAuditResult[]>>
  getGithubTokenStatus(): Promise<RemoteOutcome<GithubTokenStatus>>
  setGithubToken(token: string): Promise<RemoteOutcome<GithubTokenStatus>>
  getAuditConfig(): Promise<RemoteOutcome<AuditCacheConfig>>
  setAuditTtl(ttlHours: number): Promise<RemoteOutcome<AuditCacheConfig>>
  getSafeSkillStatus(): Promise<RemoteOutcome<SafeSkillStatus>>
  setSafeSkillKey(key: string): Promise<RemoteOutcome<SafeSkillStatus>>
  listSkills(): Promise<RemoteOutcome<SkillEntry[]>>
  scanSkill(skillName: string): Promise<RemoteOutcome<SkillScanResult>>
  getSafeSkillCacheSnapshot(): Promise<RemoteOutcome<SkillScanResult[]>>
  scanAllSkills(): Promise<RemoteOutcome<SkillScanResult[]>>
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

  /**
   * Unwrap one Remote call: fail loudly when the namespace has not mounted yet,
   * and turn the wire's `ok: false` branch into a thrown Error. `guard` is read
   * at call time, so a call made before mount still reports correctly.
   */
  const call = async <T,>(invoke: (face: GuardFace) => Promise<RemoteOutcome<T>>): Promise<T> => {
    const face = guard
    if (face === undefined) throw new Error('dsh-plugin-guard: the guard Remote is not mounted')
    const result = await invoke(face)
    if (!result.ok) throw new Error(`${result.error.code}: ${result.error.message}`)
    return result.value
  }

  ctx.slots.inject('settings.section', () => ctx.slots.register({
    name: 'settings.section',
    id: 'dsh-plugin-guard',
    order: 60,
    label: () => t('nav'),
    locale: NS,
    inject: (): SecuritySectionInjected => ({
      getReport: () => call(face => face.getReport()),
      getAiAudit: (pluginName: string) => call(face => face.getAiAudit(pluginName)),
      forceAiAudit: (pluginName: string) => call(face => face.forceAiAudit(pluginName)),
      getAiAuditStatus: (pluginName: string) => call(face => face.getAiAuditStatus(pluginName)),
      getAiAuditCacheSnapshot: () => call(face => face.getAiAuditCacheSnapshot()),
      getGithubTokenStatus: () => call(face => face.getGithubTokenStatus()),
      setGithubToken: (token: string) => call(face => face.setGithubToken(token)),
      getAuditConfig: () => call(face => face.getAuditConfig()),
      setAuditTtl: (ttlHours: number) => call(face => face.setAuditTtl(ttlHours)),
      getSafeSkillStatus: () => call(face => face.getSafeSkillStatus()),
      setSafeSkillKey: (key: string) => call(face => face.setSafeSkillKey(key)),
      listSkills: () => call(face => face.listSkills()),
      scanSkill: (skillName: string) => call(face => face.scanSkill(skillName)),
      getSafeSkillCacheSnapshot: () => call(face => face.getSafeSkillCacheSnapshot()),
      scanAllSkills: () => call(face => face.scanAllSkills()),
    }),
  }, SecuritySection))
}