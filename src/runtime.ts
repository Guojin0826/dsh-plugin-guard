/**
 * dsh-plugin-guard host Remote service (`ctx.guard`, wire namespace `guard`).
 * Registered as a TypertRemoteService so the Gateway exports `getReport` to
 * the Web client under `/api/guard/getReport` with zero generated artifacts.
 */
import type { Context } from '@deepseek-ai/cordis'
import { Remote, TypertRemoteService } from '@deepseek-ai/dsh-typert-protocol'
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { auditPluginWithAi } from './ai-audit.ts'
import { runAudit } from './scanner.ts'
import type { AiAuditResult, AuditProgress, GithubTokenStatus, SecurityReport } from './contracts.ts'

/** Resolved, defaults-applied plugin configuration. */
export interface ResolvedConfig {
  /** Profile name under `$DSH_HOME/profiles` to audit. */
  profile: string
  /** Hard cap on source files scanned per plugin. */
  maxScanFiles: number
  /** Optional GitHub PAT for authenticated repo/owner lookups; empty = anonymous. */
  githubToken: string
}

export class GuardRuntime extends TypertRemoteService {
  /** Live progress of in-flight AI audits, keyed by plugin name. Entries persist after completion so a reopened panel can read the last status. */
  private readonly progress = new Map<string, AuditProgress>()

  /** GitHub PAT in effect for reputation lookups (config first, then a persisted panel-set value). */
  private githubToken: string

  constructor(
    ctx: Context,
    private readonly config: ResolvedConfig,
  ) {
    super(ctx, 'guard')
    this.githubToken = config.githubToken.trim()
    if (this.githubToken === '') this.githubToken = this.loadPersistedToken()
  }

  /** Resolve the audited profile directory from `$DSH_HOME` (+ the configured profile name). */
  private profileDir(): string {
    const home = process.env.DSH_HOME
    if (home === undefined || home.trim().length === 0) {
      throw new Error('dsh-plugin-guard: DSH_HOME is not set; cannot locate the profile to audit')
    }
    return join(home, 'profiles', this.config.profile)
  }

  /** Directory holding the plugin's own persisted token file (best-effort, Host-local). */
  private tokenDir(): string {
    const home = process.env.DSH_HOME
    return home === undefined || home.trim() === '' ? '' : join(home, 'storages', 'dsh-plugin-guard')
  }

  private tokenFile(): string {
    const dir = this.tokenDir()
    return dir === '' ? '' : join(dir, 'github-token.txt')
  }

  private loadPersistedToken(): string {
    const file = this.tokenFile()
    if (file === '') return ''
    try {
      return readFileSync(file, 'utf-8').trim()
    } catch {
      return ''
    }
  }

  private persistToken(token: string): void {
    const file = this.tokenFile()
    if (file === '') return
    try {
      if (token === '') {
        rmSync(file, { force: true })
        return
      }
      mkdirSync(this.tokenDir(), { recursive: true })
      writeFileSync(file, token, 'utf-8')
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      console.warn(`[plugin-guard] 无法持久化 GitHub token: ${message}`)
    }
  }

  /** Record an audit phase for one plugin, keeping the original start timestamp. */
  private track(pluginName: string, phase: AuditProgress['phase'], detail: string): void {
    const previous = this.progress.get(pluginName)
    const startedAt = previous?.startedAt ?? new Date().toISOString()
    this.progress.set(pluginName, { pluginName, phase, detail, startedAt })
  }

  /** Run a fresh static audit over the profile's installed third-party plugins. */
  @Remote
  async getReport(): Promise<SecurityReport> {
    return runAudit(this.profileDir(), this.config.maxScanFiles)
  }

  /** Ask the default model to assess one plugin against both the static scan and source evidence. */
  @Remote
  async getAiAudit(pluginName: string): Promise<AiAuditResult> {
    this.track(pluginName, 'collecting', '正在定位插件并运行静态扫描…')
    try {
      const report = runAudit(this.profileDir(), this.config.maxScanFiles)
      const plugin = report.plugins.find(candidate => candidate.name === pluginName)
      if (plugin === undefined) {
        throw new Error(`dsh-plugin-guard: 未找到第三方插件 "${pluginName}"（可能未安装或属于不受审计的 @deepseek-ai 核心）`)
      }
      return await auditPluginWithAi(this.ctx, plugin, this.profileDir(), this.githubToken, (phase, detail) => {
        this.track(pluginName, phase, detail)
      })
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      this.track(pluginName, 'error', message)
      throw error
    }
  }

  /** Poll the current AI audit progress for one plugin, or `null` when none has been recorded. */
  @Remote
  async getAiAuditStatus(pluginName: string): Promise<AuditProgress | null> {
    return this.progress.get(pluginName) ?? null
  }

  /** Masked state of the GitHub token (never returns the token value itself). */
  @Remote
  async getGithubTokenStatus(): Promise<GithubTokenStatus> {
    return { configured: this.githubToken !== '' }
  }

  /** Store (or clear, with an empty string) the GitHub PAT used by `getAiAudit` reputation lookups. */
  @Remote
  async setGithubToken(token: string): Promise<GithubTokenStatus> {
    const next = (typeof token === 'string' ? token : '').trim()
    this.githubToken = next
    this.persistToken(next)
    return { configured: next !== '' }
  }
}