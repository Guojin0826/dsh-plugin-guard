/**
 * dsh-plugin-guard host Remote service (`ctx.guard`, wire namespace `guard`).
 * Registered as a TypertRemoteService so the Gateway exports `getReport` to
 * the Web client under `/api/guard/getReport` with zero generated artifacts.
 */
import type { Context } from '@deepseek-ai/cordis'
import { Remote, TypertRemoteService } from '@deepseek-ai/dsh-typert-protocol'
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { auditPluginWithAi, fetchPluginReputation, hasNewNegativeSignal, resolveAuditModel, scoreFromVerdict } from './ai-audit.ts'
import { buildBaseline, collectPluginMetadata, computePluginDeltas, computePluginFingerprint, runAudit, type BaselineSnapshot } from './scanner.ts'
import type { AiAuditResult, AuditCacheConfig, AuditProgress, GithubTokenStatus, PluginAudit, SecurityReport } from './contracts.ts'

/** Resolved, defaults-applied plugin configuration. */
export interface ResolvedConfig {
  /** Profile name under `$DSH_HOME/profiles` to audit. */
  profile: string
  /** Hard cap on source files scanned per plugin. */
  maxScanFiles: number
  /** Optional GitHub PAT for authenticated repo/owner lookups; empty = anonymous. */
  githubToken: string
}

/** Hours a fresh AI verdict stays cached before a forced re-audit (overridable in the panel). */
const DEFAULT_TTL_HOURS = 72

/** One cached AI-audit verdict, keyed by its content fingerprint. */
interface AiCacheEntry {
  readonly fingerprint: string
  readonly cachedAt: string
  readonly result: AiAuditResult
}

/** On-disk shape of the AI-audit result cache. */
interface AiCacheFile {
  ttlHours: number
  plugins: Record<string, AiCacheEntry>
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

  /** File holding the previous scan's baseline, for version-diff alerting (best-effort, Host-local). */
  private baselineFile(): string {
    const dir = this.tokenDir()
    return dir === '' ? '' : join(dir, 'baseline.json')
  }

  private loadBaseline(): BaselineSnapshot {
    const file = this.baselineFile()
    if (file === '') return {}
    try {
      const parsed = JSON.parse(readFileSync(file, 'utf-8')) as { plugins?: unknown }
      const plugins = parsed.plugins
      if (plugins === null || typeof plugins !== 'object') return {}
      const snapshot: BaselineSnapshot = {}
      for (const [name, entry] of Object.entries(plugins as Record<string, unknown>)) {
        if (entry === null || typeof entry !== 'object') continue
        const record = entry as Record<string, unknown>
        snapshot[name] = {
          version: typeof record.version === 'string' ? record.version : '',
          flags: Array.isArray(record.flags) ? record.flags.filter((item): item is string => typeof item === 'string') : [],
          perms: Array.isArray(record.perms) ? record.perms.filter((item): item is string => typeof item === 'string') : [],
        }
      }
      return snapshot
    } catch {
      return {}
    }
  }

  private saveBaseline(plugins: PluginAudit[]): void {
    const file = this.baselineFile()
    if (file === '') return
    try {
      mkdirSync(this.tokenDir(), { recursive: true })
      writeFileSync(file, JSON.stringify({ generatedAt: new Date().toISOString(), plugins: buildBaseline(plugins) }), 'utf-8')
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      console.warn(`[plugin-guard] 无法持久化扫描基线: ${message}`)
    }
  }

  /** File holding the persisted AI-audit result cache (best-effort, Host-local). */
  private aiCacheFile(): string {
    const dir = this.tokenDir()
    return dir === '' ? '' : join(dir, 'ai-cache.json')
  }

  private loadAiCache(): AiCacheFile {
    const file = this.aiCacheFile()
    const fallback: AiCacheFile = { ttlHours: DEFAULT_TTL_HOURS, plugins: {} }
    if (file === '') return fallback
    try {
      const raw = JSON.parse(readFileSync(file, 'utf-8')) as Record<string, unknown>
      const ttlHours = typeof raw.ttlHours === 'number' && Number.isFinite(raw.ttlHours) && raw.ttlHours >= 0 ? raw.ttlHours : DEFAULT_TTL_HOURS
      const plugins: Record<string, AiCacheEntry> = {}
      const rawPlugins = raw.plugins
      if (rawPlugins !== null && typeof rawPlugins === 'object') {
        for (const [name, entry] of Object.entries(rawPlugins as Record<string, unknown>)) {
          if (entry === null || typeof entry !== 'object') continue
          const record = entry as Record<string, unknown>
          if (typeof record.fingerprint !== 'string' || typeof record.cachedAt !== 'string' || record.result === null || typeof record.result !== 'object') continue
          plugins[name] = {
            fingerprint: record.fingerprint,
            cachedAt: record.cachedAt,
            result: record.result as unknown as AiAuditResult,
          }
        }
      }
      return { ttlHours, plugins }
    } catch {
      return fallback
    }
  }

  private saveAiCache(cache: AiCacheFile): void {
    const file = this.aiCacheFile()
    if (file === '') return
    try {
      mkdirSync(this.tokenDir(), { recursive: true })
      writeFileSync(file, JSON.stringify(cache), 'utf-8')
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      console.warn(`[plugin-guard] 无法持久化 AI 审计缓存: ${message}`)
    }
  }

  /** Current AI-audit cache TTL in hours (0 disables the cache). */
  @Remote
  async getAuditConfig(): Promise<AuditCacheConfig> {
    return { ttlHours: this.loadAiCache().ttlHours }
  }

  /** Set the AI-audit cache TTL in hours (0 disables the cache) and persist it. */
  @Remote
  async setAuditTtl(ttlHours: number): Promise<AuditCacheConfig> {
    const next = typeof ttlHours === 'number' && Number.isFinite(ttlHours) && ttlHours >= 0 ? Math.floor(ttlHours) : DEFAULT_TTL_HOURS
    const cache = this.loadAiCache()
    cache.ttlHours = next
    this.saveAiCache(cache)
    return { ttlHours: next }
  }

  /** Run a fresh static audit, diff it against the previous scan's baseline, then persist the new baseline. */
  @Remote
  async getReport(): Promise<SecurityReport> {
    const report = runAudit(this.profileDir(), this.config.maxScanFiles)
    const deltas = computePluginDeltas(report.plugins, this.loadBaseline())
    this.saveBaseline(report.plugins)
    return { ...report, deltas }
  }

  /** Assess one plugin: always refresh live reputation, then reuse the cached verdict only when the fingerprint is unchanged, within TTL, and no new negative reputation signal appeared. */
  @Remote
  async getAiAudit(pluginName: string): Promise<AiAuditResult> {
    return this.runAiAudit(pluginName, false)
  }

  /** Bypass the verdict cache and always run a full model audit for one plugin (reputation still fetched fresh). */
  @Remote
  async forceAiAudit(pluginName: string): Promise<AiAuditResult> {
    return this.runAiAudit(pluginName, true)
  }

  /**
   * Return every AI verdict still valid in the on-disk cache (fingerprint matched
   * and within TTL), with no network access. The client calls this on mount to
   * restore AI classifications/scores after a page refresh. Purely a display
   * restore: a real `getAiAudit` still re-checks negative reputation signals.
   */
  @Remote
  async getAiAuditCacheSnapshot(): Promise<AiAuditResult[]> {
    const cache = this.loadAiCache()
    if (cache.ttlHours <= 0) return []
    const profileDir = this.profileDir()
    const report = runAudit(profileDir, this.config.maxScanFiles)
    let modelKey = ''
    try {
      const model = resolveAuditModel(this.ctx)
      modelKey = model.provider + '/' + model.model
    } catch {
      // No default model yet: keep the key empty, mirroring `runAiAudit`.
    }
    const restored: AiAuditResult[] = []
    for (const plugin of report.plugins) {
      const entry = cache.plugins[plugin.name]
      if (entry === undefined) continue
      const pluginDir = join(profileDir, 'node_modules', plugin.name)
      const fingerprint = computePluginFingerprint(pluginDir, plugin.version, modelKey)
      if (entry.fingerprint !== fingerprint) continue
      const ageHours = (Date.now() - new Date(entry.cachedAt).getTime()) / 3_600_000
      if (!(Number.isFinite(ageHours) && ageHours >= 0 && ageHours < cache.ttlHours)) continue
      restored.push({ ...entry.result, score: entry.result.score ?? scoreFromVerdict(entry.result.verdict), cached: true })
    }
    return restored
  }

  private async runAiAudit(pluginName: string, force: boolean): Promise<AiAuditResult> {
    this.track(pluginName, 'collecting', '正在定位插件并运行静态扫描…')
    try {
      const profileDir = this.profileDir()
      const report = runAudit(profileDir, this.config.maxScanFiles)
      const plugin = report.plugins.find(candidate => candidate.name === pluginName)
      if (plugin === undefined) {
        throw new Error(`dsh-plugin-guard: 未找到第三方插件 "${pluginName}"（可能未安装或属于不受审计的 @deepseek-ai 核心）`)
      }

      const pluginDir = join(profileDir, 'node_modules', plugin.name)
      // Fold the default model identity into the fingerprint so switching models
      // invalidates a would-be cache hit (the verdict is model-specific).
      let modelKey = ''
      try {
        const model = resolveAuditModel(this.ctx)
        modelKey = model.provider + '/' + model.model
      } catch {
        // No default model configured yet: leave the key empty; a cache miss still
        // surfaces the missing-model error from the audit call itself.
      }
      const fingerprint = computePluginFingerprint(pluginDir, plugin.version, modelKey)
      const emit = (phase: AuditProgress['phase'], detail: string): void => {
        this.track(pluginName, phase, detail)
      }

      // Reputation is refreshed on every audit; only the model verdict is cached.
      const freshReputation = await fetchPluginReputation(plugin, collectPluginMetadata(pluginDir), pluginDir, this.githubToken, emit)

      const cache = this.loadAiCache()
      const entry = cache.plugins[plugin.name]
      const ageHours = entry === undefined || entry.fingerprint !== fingerprint
        ? Number.NaN
        : (Date.now() - new Date(entry.cachedAt).getTime()) / 3_600_000
      const withinTtl = cache.ttlHours > 0 && Number.isFinite(ageHours) && ageHours >= 0 && ageHours < cache.ttlHours

      if (!force && entry !== undefined && withinTtl) {
        if (hasNewNegativeSignal(entry.result.reputation, freshReputation)) {
          emit('researching', '发现新的负面声誉信号，忽略缓存、强制重审…')
        } else {
          emit('done', '命中缓存，复用上次判定；声誉已拉取最新')
          return { ...entry.result, score: entry.result.score ?? scoreFromVerdict(entry.result.verdict), reputation: freshReputation, cached: true }
        }
      }

      const result = await auditPluginWithAi(this.ctx, plugin, profileDir, this.githubToken, emit, freshReputation)
      cache.plugins[plugin.name] = { fingerprint, cachedAt: new Date().toISOString(), result }
      this.saveAiCache(cache)
      return result
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