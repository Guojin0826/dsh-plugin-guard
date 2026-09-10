/**
 * dsh-plugin-guard host plugin: mounts the `guard` Typert Remote service
 * (static source + dependency audit of the profile's installed plugins) and
 * registers its strict Typert manifest. On load it performs an initial audit
 * and logs a summary; the Web client renders the full report on demand.
 */
import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
// Type-only: brings the `ctx.typert` Context merge into this program.
import type {} from '@deepseek-ai/dsh-typert-registry'
import { GuardRuntime } from './runtime.ts'
import { TYPERT_MANIFEST } from './typert.ts'
import { runAudit } from './scanner.ts'

/** Cordis plugin name (the Loader entry and client bundle id). */
export const name = 'dsh-plugin-guard'

/** Services required before load: the Typert registry, plus the LLM runtime and default-model selection for AI audit. */
export const inject = ['typert', 'llm', 'agentDefaultModel']

/** Host plugin configuration, validated at load by the Loader. */
export interface Config {
  /** Profile name under `$DSH_HOME/profiles` to audit. */
  profile: string
  /** Hard cap on source files scanned per plugin. */
  maxScanFiles: number
  /** Optional GitHub PAT for authenticated repo/owner lookups (raises the 60/h limit to 5000/h). */
  githubToken: string
}

/** Configuration schema: defaults apply when the callable schema is invoked with `{}`. */
export const Config = z.object({
  profile: z.string().default('web'),
  maxScanFiles: z.natural().min(1).default(5000),
  githubToken: z.string().role('secret').default('')
    .description('可选的 GitHub Personal Access Token。填写后 AI 审计走 GitHub 认证 API，限额从 60 次/小时提升到 5000 次/小时；留空则匿名查询。'),
})

/**
 * Mount the guard service, register its Typert manifest, and log an initial
 * audit summary. The Remote re-runs the audit per call, so the client's
 * "rescan" button always reflects the current install state.
 * @param ctx - host cordis context.
 * @param config - validated plugin configuration (schema defaults applied).
 */
export function apply(ctx: Context, config?: Config): void {
  const resolved = Config(config ?? {})
  new GuardRuntime(ctx, { profile: resolved.profile, maxScanFiles: resolved.maxScanFiles, githubToken: resolved.githubToken })

  ctx.effect(() => {
    const dispose = ctx.typert.register(TYPERT_MANIFEST)
    return () => { void dispose() }
  }, 'dsh-plugin-guard: typert manifest')

  // Best-effort boot summary (detective control; the panel is the real UI).
  ctx.effect(() => {
    try {
      const report = runAudit(resolved.profile, resolved.maxScanFiles)
      const logger = ctx.logger as { info?: (line: string) => void } | undefined
      const line = `[plugin-guard] 审计完成: ${report.greenCount} 绿 / ${report.yellowCount} 黄 / ${report.redCount} 红 (共 ${report.pluginCount} 个插件)`
      if (typeof logger?.info === 'function') logger.info(line)
      else console.info(line)
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      const logger = ctx.logger as { warn?: (line: string) => void } | undefined
      if (typeof logger?.warn === 'function') logger.warn(`[plugin-guard] 初始审计失败: ${message}`)
      else console.warn(`[plugin-guard] 初始审计失败: ${message}`)
    }
    return () => {}
  }, 'dsh-plugin-guard: boot audit summary')
}