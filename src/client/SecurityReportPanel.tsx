/** Settings section rendering the plugin security audit report (green/yellow/red) plus per-plugin AI audit with live progress. */
import type { InjectFace, PropsLocale } from '@deepseek-ai/dsh-client-ui-slots'
import { useEffect, useReducer, useRef, useState, type ReactElement } from 'react'
import type { AiAuditResult, AuditCacheConfig, AuditPhase, AuditProgress, GithubEvidence, GithubTokenStatus, PluginAudit, PluginDelta, ReputationEvidence, SafeSkillReport, SafeSkillStatus, SafeSkillThreat, SecurityReport, SkillEntry, SkillScanResult } from '../contracts.ts'

export interface SecuritySectionInjected {
  getReport: () => Promise<SecurityReport>
  getAiAudit: (pluginName: string) => Promise<AiAuditResult>
  forceAiAudit: (pluginName: string) => Promise<AiAuditResult>
  getAiAuditStatus: (pluginName: string) => Promise<AuditProgress | null>
  getAiAuditCacheSnapshot: () => Promise<AiAuditResult[]>
  getGithubTokenStatus: () => Promise<GithubTokenStatus>
  setGithubToken: (token: string) => Promise<GithubTokenStatus>
  getAuditConfig: () => Promise<AuditCacheConfig>
  setAuditTtl: (ttlHours: number) => Promise<AuditCacheConfig>
  getSafeSkillStatus: () => Promise<SafeSkillStatus>
  setSafeSkillKey: (key: string) => Promise<SafeSkillStatus>
  listSkills: () => Promise<SkillEntry[]>
  scanSkill: (skillName: string) => Promise<SafeSkillReport>
  getSafeSkillCacheSnapshot: () => Promise<SkillScanResult[]>
  scanAllSkills: () => Promise<SkillScanResult[]>
}

type SecuritySectionProps = InjectFace<SecuritySectionInjected> & PropsLocale<'dsh-plugin-guard'>

const RISK_KEY = { red: 'riskRed', yellow: 'riskYellow', green: 'riskGreen' } as const
const VERDICT_KEY = {
  safe: 'aiSafe',
  suspicious: 'aiSuspicious',
  malicious: 'aiMalicious',
  inconclusive: 'aiInconclusive',
} as const

/**
 * Fuse the static detection risk with the AI verdict. The AI audit is the deeper
 * judgment layer (it reads claimed purpose + reputation), so once it returns, its
 * verdict drives the classification: malicious→red, suspicious→yellow (red when
 * static already found hard evidence), inconclusive→never drops below yellow of a
 * flagged plugin, safe→green. A disagreement with the static risk is surfaced
 * explicitly — never silently.
 */
function effRisk(staticRisk: PluginAudit['risk'], verdict: AiAuditResult['verdict'] | undefined): PluginAudit['risk'] {
  if (verdict === undefined) return staticRisk
  switch (verdict) {
    case 'malicious': return 'red'
    case 'suspicious': return staticRisk === 'red' ? 'red' : 'yellow'
    case 'inconclusive': return staticRisk === 'green' ? 'yellow' : staticRisk
    case 'safe': return 'green'
  }
}

// Two palettes so the panel reads well in both the app's light and dark themes.
// `palette` is a mutable object: the theme effect in SecuritySection reassigns
// its fields, and every render reads the properties directly, so child
// components always see the current theme's colors.
const lightPalette = {
  red: '#d93025',
  redBg: '#fdebea',
  yellow: '#b27000',
  yellowBg: '#fff6e0',
  green: '#1a7f37',
  greenBg: '#e8f5ec',
  border: 'rgba(0,0,0,0.12)',
  mute: 'rgba(0,0,0,0.55)',
  dim: '#444',
  busy: '#3b5b8c',
  busyBg: '#f0f4fb',
  busyBorder: '#d5e0f0',
  surface: '#fff',
  surfaceHi: 'rgba(0,0,0,0.05)',
}

const darkPalette: typeof lightPalette = {
  red: '#ff8a80',
  redBg: 'rgba(255,138,128,0.16)',
  yellow: '#ffd54f',
  yellowBg: 'rgba(255,213,79,0.16)',
  green: '#69db7c',
  greenBg: 'rgba(105,219,124,0.16)',
  border: 'rgba(255,255,255,0.16)',
  mute: 'rgba(255,255,255,0.55)',
  dim: '#c1c5cb',
  busy: '#8ab4f8',
  busyBg: 'rgba(138,180,248,0.14)',
  busyBorder: 'rgba(138,180,248,0.28)',
  surface: '#26282b',
  surfaceHi: 'rgba(255,255,255,0.07)',
}

/** Whether the app is currently in dark theme, read from the app's own `data-ds-dark-theme` body flag. */
function isAppDark(): boolean {
  if (typeof document === 'undefined' || document.body === null) return false
  const flag = document.body.getAttribute('data-ds-dark-theme') ?? document.documentElement.getAttribute('data-ds-dark-theme')
  if (flag === null) return false
  return flag !== 'false' && flag !== '0' && flag !== 'off'
}

const palette = { ...(isAppDark() ? darkPalette : lightPalette) }

function riskColor(risk: PluginAudit['risk']): string {
  return palette[risk]
}
function riskBg(risk: PluginAudit['risk']): string {
  return risk === 'red' ? palette.redBg : risk === 'yellow' ? palette.yellowBg : palette.greenBg
}

function FlagRow({ flag }: { flag: PluginAudit['flags'][number] }): ReactElement {
  const sevColor = flag.severity === 'high' ? palette.red : flag.severity === 'medium' ? palette.yellow : palette.dim
  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center', padding: '4px 0' }}>
      <code style={{ fontSize: 12, color: sevColor, fontWeight: 600 }}>{flag.code}</code>
      <span style={{ fontSize: 13 }}>{flag.label}</span>
      <span style={{ fontSize: 12, color: palette.mute, wordBreak: 'break-all' }}>{flag.files.join(' · ')}</span>
    </div>
  )
}

function PermissionRow({ permission }: { permission: PluginAudit['permissions'][number] }): ReactElement {
  const sevColor = permission.severity === 'high' ? palette.red : permission.severity === 'medium' ? palette.yellow : palette.dim
  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center', padding: '4px 0' }}>
      <code style={{ fontSize: 12, color: sevColor, fontWeight: 600 }}>{permission.name}</code>
      <span style={{ fontSize: 13 }}>{permission.label}</span>
    </div>
  )
}

type AiState = {
  loading: boolean
  result: AiAuditResult | null
  error: string | null
  progress: { phase: AuditPhase; detail: string } | null
}

/**
 * Module-level store so an in-flight AI audit survives closing the settings
 * panel: the RPC keeps running on the Host and the polling keeps writing here,
 * so reopening the panel shows the finished (or still-running) result.
 */
const aiStore = new Map<string, AiState>()
const aiListeners = new Set<() => void>()

function getAiState(pluginName: string): AiState {
  return aiStore.get(pluginName) ?? { loading: false, result: null, error: null, progress: null }
}
function setAiState(pluginName: string, update: Partial<AiState>): void {
  aiStore.set(pluginName, { ...getAiState(pluginName), ...update })
  for (const listener of aiListeners) listener()
}
function subscribeAi(listener: () => void): () => void {
  aiListeners.add(listener)
  return () => { aiListeners.delete(listener) }
}

type SkillState = {
  loading: boolean
  report: SafeSkillReport | null
  error: string | null
  fromCache?: boolean
}

/** Module-level store so a SafeSkill scan keeps running (and stays visible) across panel close, mirroring the AI store. */
const skillStore = new Map<string, SkillState>()
const skillListeners = new Set<() => void>()

function getSkillState(skillName: string): SkillState {
  return skillStore.get(skillName) ?? { loading: false, report: null, error: null }
}
function setSkillState(skillName: string, update: Partial<SkillState>): void {
  skillStore.set(skillName, { ...getSkillState(skillName), ...update })
  for (const listener of skillListeners) listener()
}
function subscribeSkill(listener: () => void): () => void {
  skillListeners.add(listener)
  return () => { skillListeners.delete(listener) }
}

/** Render an untrusted URL as a link only when its scheme is http(s); otherwise plain text. */
function SafeLink({ url, label }: { url: string; label: string }): ReactElement {
  if (!/^https?:\/\//i.test(url)) {
    return <span style={{ marginRight: 12, fontSize: 12 }}>{label}: <code style={{ fontSize: 11 }}>{url}</code></span>
  }
  return <a href={url} target="_blank" rel="noopener noreferrer" style={{ marginRight: 12, fontSize: 12, color: palette.busy }}>{label}</a>
}

/** GitHub repo + owner intelligence (stars, account age, other repos) shown under the verdict. */
function GithubBox({ github, t }: { github: GithubEvidence; t: (key: string) => string }): ReactElement | null {
  if (github.fullName === '') {
    if (github.note !== '') return <div style={{ marginTop: 6, color: palette.mute, fontStyle: 'italic' }}>{github.note}</div>
    return null
  }
  const dateOf = (iso: string): string => (iso === '' ? t('aiUnknown') : iso.slice(0, 10))
  const pushedMs = github.pushedAt !== '' ? new Date(github.pushedAt).getTime() : Number.NaN
  const daysSincePush = Number.isFinite(pushedMs) ? Math.floor((Date.now() - pushedMs) / 86_400_000) : -1
  const stale = daysSincePush > 365
  return (
    <div style={{ marginTop: 8, paddingTop: 6, borderTop: `1px dashed ${palette.border}` }}>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '3px 10px', alignItems: 'center' }}>
        <SafeLink url={github.htmlUrl} label={github.fullName} />
        {github.stars >= 0 && <span>⭐ {github.stars.toLocaleString()}</span>}
        {github.forks >= 0 && <span>⑂ {github.forks.toLocaleString()}</span>}
        {github.archived && <span style={{ color: palette.mute }}>({t('aiArchived')})</span>}
        {stale && <span style={{ color: palette.red, fontWeight: 600 }}>{t('aiStale')}</span>}
      </div>
      {github.description !== '' && <div style={{ marginTop: 2, color: '#555' }}>{github.description}</div>}
      <div style={{ marginTop: 2, color: '#555' }}>
        {t('aiRepoCreated')} {dateOf(github.createdAt)} · {t('aiRepoPushed')} {dateOf(github.pushedAt)}
      </div>
      <div style={{ marginTop: 2, color: '#555' }}>
        {t('aiAccountRegistered')} {dateOf(github.ownerCreatedAt)}
        {github.ownerPublicRepos >= 0 && ` · ${t('aiPublicRepos')} ${github.ownerPublicRepos}`}
        {github.ownerFollowers >= 0 && ` · ${t('aiFollowers')} ${github.ownerFollowers}`}
      </div>
      <div style={{ marginTop: 2, color: '#555' }}>
        {github.license !== '' && <span>{t('aiLicense')}: {github.license}</span>}
        {github.openIssues >= 0 && <span> · {t('aiOpenIssues')} {github.openIssues.toLocaleString()}</span>}
        <span style={{ color: palette.mute }}> · {t('aiSecurity')}: {github.hasSecurityPolicy ? '✓ SECURITY.md' : '✗'}</span>
      </div>
      {github.note !== '' && <div style={{ marginTop: 3, color: palette.mute, fontStyle: 'italic' }}>{github.note}</div>}
    </div>
  )
}

/** Known vulnerability / malicious-package advisories from OSV.dev (authoritative, highlighted when malicious). */
function AdvisoriesBox({ reputation, t }: { reputation: ReputationEvidence; t: (key: string) => string }): ReactElement {
  const advisories = reputation.advisories ?? []
  const heading = <div style={{ fontWeight: 600 }}>{t('aiAdvisories')}</div>
  if (advisories.length === 0) {
    return (
      <div style={{ marginTop: 8 }}>
        {heading}
        <div style={{ color: palette.mute }}>{t('aiAdvisoriesNone')}</div>
      </div>
    )
  }
  const hasMalicious = advisories.some(item => item.malicious)
  return (
    <div style={{ marginTop: 8, padding: '8px 10px', borderRadius: 6, background: hasMalicious ? palette.redBg : palette.busyBg, border: `1px solid ${hasMalicious ? palette.red : palette.busyBorder}` }}>
      {heading}
      <ul style={{ margin: '4px 0 0', paddingLeft: 0, listStyle: 'none' }}>
        {advisories.map((advisory, index) => (
          <li key={index} style={{ margin: '4px 0' }}>
            <span style={{ fontWeight: 600, color: advisory.malicious ? palette.red : palette.dim }}>
              {advisory.malicious ? '⚠ ' : ''}{advisory.id}
            </span>
            {advisory.aliases.length > 0 && <span style={{ color: palette.mute, fontSize: 12 }}> ({advisory.aliases.join(', ')})</span>}
            {advisory.summary !== '' && <div style={{ fontSize: 12, color: '#555', wordBreak: 'break-all' }}>{advisory.summary}</div>}
          </li>
        ))}
      </ul>
    </div>
  )
}

/** Vulnerabilities found in the plugin's resolved direct dependencies (OSV.dev batch). */
function DependencyAdvisoriesBox({ reputation, t }: { reputation: ReputationEvidence; t: (key: string) => string }): ReactElement | null {
  const deps = reputation.dependencyAdvisories ?? []
  if (deps.length === 0) return null
  const impacted = deps.filter(dep => dep.advisories.length > 0)
  const heading = <div style={{ fontWeight: 600 }}>{t('aiDeps')}</div>
  if (impacted.length === 0) {
    return (
      <div style={{ marginTop: 8 }}>
        {heading}
        <div style={{ color: palette.mute }}>{t('aiDepsClean')} ({deps.length})</div>
      </div>
    )
  }
  const hasMalicious = impacted.some(dep => dep.advisories.some(adv => adv.malicious))
  return (
    <div style={{ marginTop: 8, padding: '8px 10px', borderRadius: 6, background: hasMalicious ? palette.redBg : palette.busyBg, border: `1px solid ${hasMalicious ? palette.red : palette.busyBorder}` }}>
      {heading}
      <ul style={{ margin: '4px 0 0', paddingLeft: 0, listStyle: 'none' }}>
        {impacted.map((dep, index) => (
          <li key={index} style={{ margin: '4px 0' }}>
            <span style={{ fontWeight: 600, color: palette.dim }}>{dep.name}@{dep.version}</span>
            {dep.advisories.map((adv, j) => (
              <div key={j} style={{ fontSize: 12, color: adv.malicious ? palette.red : '#555', wordBreak: 'break-all' }}>
                {adv.malicious ? '⚠ ' : ''}{adv.id}{adv.summary !== '' ? ` — ${adv.summary}` : ''}
              </div>
            ))}
          </li>
        ))}
      </ul>
    </div>
  )
}

/** Malicious/attack web-report hits surfaced with clickable links (falls back to flat text for older results). */
function WebReportsBox({ reputation, t }: { reputation: ReputationEvidence; t: (key: string) => string }): ReactElement {
  const hits = reputation.webSearchHits ?? []
  const heading = <div style={{ fontWeight: 600 }}>{t('aiWebReports')}</div>
  if (hits.length === 0) {
    return (
      <div style={{ marginTop: 6 }}>
        {heading}
        <div style={{ color: palette.mute }}>{t('aiWebNoReports')}</div>
      </div>
    )
  }
  return (
    <div style={{ marginTop: 8 }}>
      {heading}
      <ul style={{ margin: '3px 0 0', paddingLeft: 0, listStyle: 'none' }}>
        {hits.map((hit, index) => (
          <li key={index} style={{ margin: '5px 0' }}>
            {hit.url !== ''
              ? <SafeLink url={hit.url} label={hit.title !== '' ? hit.title : hit.url} />
              : <span style={{ fontWeight: 600, fontSize: 12 }}>{hit.title}</span>}
            {hit.snippet !== '' && <div style={{ fontSize: 12, color: '#555', wordBreak: 'break-all', marginTop: 1 }}>{hit.snippet}</div>}
          </li>
        ))}
      </ul>
    </div>
  )
}

/** Reputation evidence panel shown under the AI verdict — collapsed by default, click to expand. */
function ReputationBox({ reputation, t }: { reputation: ReputationEvidence; t: (key: string) => string }): ReactElement {
  const hasNpm = reputation.npmDescription !== '' || reputation.npmLatest !== '' || reputation.npmMaintainers.length > 0
  const ageDays = reputation.npmCreated !== '' ? Math.floor((Date.now() - new Date(reputation.npmCreated).getTime()) / 86_400_000) : -1
  const showAge = Number.isFinite(ageDays) && ageDays >= 0
  return (
    <details style={{ marginTop: 10, paddingTop: 8, borderTop: `1px dashed ${palette.border}`, fontSize: 12 }}>
      <summary style={{ cursor: 'pointer', fontWeight: 600, color: palette.mute, userSelect: 'none' }}>
        {t('aiReputation')}
      </summary>
      <div style={{ marginTop: 6 }}>
        {hasNpm && (
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '3px 12px' }}>
            {reputation.npmDescription !== '' && <span>npm: {reputation.npmDescription}</span>}
            {reputation.npmLatest !== '' && <span>v{reputation.npmLatest}</span>}
            {reputation.npmMaintainers.length > 0 && <span>{t('aiMaintainers')}: {reputation.npmMaintainers.join(', ')}</span>}
          </div>
        )}
        <div style={{ marginTop: 3 }}>
          {t('aiDownloads')}: {reputation.weeklyDownloads >= 0 ? reputation.weeklyDownloads.toLocaleString() : t('aiUnknown')}
        </div>
        {(showAge || reputation.npmDeprecated !== '') && (
          <div style={{ marginTop: 3, display: 'flex', flexWrap: 'wrap', gap: '3px 12px' }}>
            {showAge && (
              <span style={ageDays < 30 ? { color: palette.red, fontWeight: 600 } : undefined}>
                {t('aiAge')}: {ageDays} {t('aiDays')}{ageDays < 30 ? ` · ${t('aiNewPackage')}` : ''}
              </span>
            )}
            {reputation.npmDeprecated !== '' && (
              <span style={{ color: palette.red, fontWeight: 600 }}>⚠ {t('aiDeprecated')}: {reputation.npmDeprecated}</span>
            )}
          </div>
        )}
        {(reputation.npmHomepage !== '' || reputation.npmRepository !== '') && (
          <div style={{ marginTop: 3 }}>
            {reputation.npmHomepage !== '' && <SafeLink url={reputation.npmHomepage} label={t('aiHomepage')} />}
            {reputation.npmRepository !== '' && <SafeLink url={reputation.npmRepository} label={t('aiRepository')} />}
          </div>
        )}
        <GithubBox github={reputation.github} t={t} />
        <AdvisoriesBox reputation={reputation} t={t} />
        <DependencyAdvisoriesBox reputation={reputation} t={t} />
        <WebReportsBox reputation={reputation} t={t} />
        {reputation.note !== '' && (
          <div style={{ marginTop: 6, color: palette.mute, fontStyle: 'italic' }}>{reputation.note}</div>
        )}
      </div>
    </details>
  )
}

function AiAuditBox({ state, t }: { state: AiState; t: (key: string) => string }): ReactElement | null {
  if (state.loading) {
    return (
      <div style={{ marginTop: 10, padding: '8px 12px', borderRadius: 6, background: palette.busyBg, border: `1px solid ${palette.busyBorder}`, fontSize: 12, color: palette.busy }}>
        <span style={{ fontWeight: 600 }}>{t('aiAuditing')}</span>
        {state.progress !== null && <span> · {state.progress.detail}</span>}
      </div>
    )
  }
  if (state.error !== null) {
    return (
      <div style={{ marginTop: 10, padding: '8px 12px', borderRadius: 6, background: palette.redBg, color: palette.red, fontSize: 12 }}>
        {t('loadError')}: {state.error}
      </div>
    )
  }
  if (state.result === null) return null
  const result = state.result
  return (
    <div style={{ marginTop: 10, padding: '10px 12px', borderRadius: 6, border: `1px solid ${riskColor(result.risk)}`, background: riskBg(result.risk) }}>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10, alignItems: 'center' }}>
        <span style={{ fontWeight: 700, fontSize: 13, color: riskColor(result.risk) }}>{t('aiVerdict')}: {t(VERDICT_KEY[result.verdict])}</span>
        <span style={{ fontSize: 12, fontWeight: 600 }}>{t('colScore')}: {result.score}</span>
        <span style={{ fontSize: 11, color: palette.mute }}>{t('aiModel')}: {result.provider}/{result.model}</span>
        {result.cached === true && <span style={{ fontSize: 11, color: palette.mute, fontWeight: 600 }}>⟳ {t('cacheHit')}</span>}
      </div>
      <div style={{ fontSize: 13, marginTop: 6, whiteSpace: 'pre-wrap' }}>{result.summary}</div>
      {result.concerns.length > 0 && (
        <div style={{ marginTop: 8 }}>
          <div style={{ fontWeight: 600, fontSize: 12 }}>{t('aiConcerns')}</div>
          <ul style={{ margin: '4px 0 0', paddingLeft: 18, fontSize: 13 }}>
            {result.concerns.map((concern, index) => <li key={index}>{concern}</li>)}
          </ul>
        </div>
      )}
      {result.recommendations.length > 0 && (
        <div style={{ marginTop: 8 }}>
          <div style={{ fontWeight: 600, fontSize: 12 }}>{t('aiRecommendations')}</div>
          <ul style={{ margin: '4px 0 0', paddingLeft: 18, fontSize: 13 }}>
            {result.recommendations.map((recommendation, index) => <li key={index}>{recommendation}</li>)}
          </ul>
        </div>
      )}
      <ReputationBox reputation={result.reputation} t={t} />
    </div>
  )
}

function PluginRow({ plugin, t, aiState, onAudit, onForceAudit, delta }: {
  plugin: PluginAudit
  t: (key: string) => string
  aiState: AiState
  onAudit: () => void
  onForceAudit: () => void
  delta?: PluginDelta
}): ReactElement {
  const verdict = aiState.result?.verdict
  const eff = effRisk(plugin.risk, verdict)
  const aiScore = aiState.result?.score
  const badge = (
    <span style={{
      display: 'inline-block',
      minWidth: 48,
      textAlign: 'center',
      padding: '2px 8px',
      borderRadius: 10,
      fontSize: 12,
      fontWeight: 600,
      color: riskColor(eff),
      background: riskBg(eff),
    }}>
      {t(RISK_KEY[eff])}
    </span>
  )

  return (
    <details style={{ border: `1px solid ${palette.border}`, borderRadius: 8, marginTop: 12, overflow: 'hidden' }}>
      <summary style={{ cursor: 'pointer', listStyle: 'none', display: 'flex', alignItems: 'center', gap: 12, padding: '10px 14px', flexWrap: 'wrap' }}>
        {badge}
        {verdict !== undefined && (
          <span style={{ fontSize: 11, fontWeight: 700, color: eff !== plugin.risk ? palette.yellow : palette.mute }}>
            {t('aiVerdict')} {t(VERDICT_KEY[verdict])}{eff !== plugin.risk ? ` · ${t('staticBadge')} ${t(RISK_KEY[plugin.risk])}` : ''}
          </span>
        )}
        <code style={{ fontWeight: 600, fontSize: 14 }}>{plugin.name}</code>
        <span style={{ fontSize: 12, color: palette.mute }}>v{plugin.version}</span>
        {delta !== undefined && (
          <span style={{ fontSize: 11, fontWeight: 700, color: palette.red }}>{delta.isNew ? `🆕 ${t('deltaNew')}` : `↑ ${t('deltaChanged')}`}</span>
        )}
        <span style={{ fontSize: 11, opacity: 0.75 }}>{plugin.active ? t('active') : t('inactive')}</span>
        <span style={{ marginLeft: 'auto', fontSize: 12, color: palette.mute }}>
          {t('colScore')}: {aiScore ?? plugin.score}{aiScore !== undefined ? ' · AI' : ''}
        </span>
      </summary>

      <div style={{ borderTop: `1px solid ${palette.border}`, padding: '12px 14px', display: 'flex', flexDirection: 'column', gap: 12 }}>
        {delta !== undefined && (
          <div style={{ padding: '8px 10px', borderRadius: 6, background: palette.yellowBg, border: `1px solid ${palette.yellow}`, fontSize: 12 }}>
            <div style={{ fontWeight: 700, marginBottom: 4, color: palette.yellow }}>
              {delta.isNew ? `🆕 ${t('deltaNewPlugin')}` : `⚠ ${t('deltaSinceLastScan')}`}
            </div>
            {!delta.isNew && delta.previousVersion !== delta.currentVersion && (
              <div>{t('colVersion')}: {delta.previousVersion} → {delta.currentVersion}</div>
            )}
            {delta.addedFlags.length > 0 && (
              <div>{t('deltaAddedFlags')}: <code>{delta.addedFlags.join(', ')}</code></div>
            )}
            {delta.addedPerms.length > 0 && (
              <div>{t('deltaAddedPerms')}: <code>{delta.addedPerms.join(', ')}</code></div>
            )}
          </div>
        )}

        <div>
          <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 4 }}>{t('flags')} ({plugin.flags.length})</div>
          {plugin.flags.length === 0
            ? <div style={{ fontSize: 13, color: palette.mute }}>{t('noFlags')}</div>
            : plugin.flags.map(flag => <FlagRow key={flag.code} flag={flag} />)}
        </div>

        <div>
          <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 4 }}>{t('perms')} ({plugin.permissions.length}){plugin.permissions.length > 0 ? ` · ${t('colScore')}: ${plugin.permScore}` : ''}</div>
          {plugin.permissions.length === 0
            ? <div style={{ fontSize: 13, color: palette.mute }}>{t('noPerms')}</div>
            : (
              <div>
                {plugin.permissions.map(permission => <PermissionRow key={permission.name} permission={permission} />)}
                {plugin.capabilityMismatch && (
                  <div style={{ fontSize: 12, color: palette.red, fontWeight: 600, marginTop: 4 }}>⚠ {t('permMismatch')}</div>
                )}
              </div>
            )}
        </div>

        <div>
          <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 4 }}>{t('deps')} ({plugin.dependencies.length})</div>
          {plugin.dependencies.length === 0
            ? <div style={{ fontSize: 13, color: palette.mute }}>{t('noDeps')}</div>
            : plugin.dependencies.map(dep => (
              <div key={dep.name} style={{ display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center', padding: '3px 0', fontSize: 13 }}>
                <code style={{ fontSize: 12 }}>{dep.name}</code>
                <span style={{ fontSize: 12, color: palette.mute }}>{dep.version}</span>
                {dep.suspicious && (
                  <span style={{ fontSize: 11, color: palette.red, fontWeight: 600 }}>
                    ⚠ {t('suspiciousDep')}{dep.reason ? ` · ${dep.reason}` : ''}
                  </span>
                )}
              </div>
            ))}
        </div>

        {plugin.errors.length > 0 && (
          <div>
            <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 4 }}>{t('errors')}</div>
            {plugin.errors.map((err, index) => <div key={index} style={{ fontSize: 12, color: palette.red }}>{err}</div>)}
          </div>
        )}

        <div style={{ fontSize: 12, color: palette.mute }}>{t('filesScanned')}: {plugin.scannedFiles}</div>

        <div style={{ borderTop: `1px dashed ${palette.border}`, paddingTop: 10 }}>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <button
              type="button"
              disabled={aiState.loading}
              onClick={onAudit}
              style={{
                padding: '6px 12px',
                borderRadius: 6,
                border: `1px solid ${palette.border}`,
                background: palette.surface,
                cursor: aiState.loading ? 'default' : 'pointer',
                fontSize: 13,
                opacity: aiState.loading ? 0.6 : 1,
              }}
            >
              {aiState.loading ? t('aiAuditing') : t('aiAudit')}
            </button>
            <button
              type="button"
              disabled={aiState.loading}
              onClick={onForceAudit}
              style={{
                padding: '6px 12px',
                borderRadius: 6,
                border: `1px solid ${palette.border}`,
                background: palette.surface,
                cursor: aiState.loading ? 'default' : 'pointer',
                fontSize: 13,
                opacity: aiState.loading ? 0.6 : 1,
              }}
            >
              {t('aiForceAudit')}
            </button>
          </div>
          <AiAuditBox state={aiState} t={t} />
        </div>
      </div>
    </details>
  )
}

const THREAT_KEY = {
  malicious: 'skillThreatMalicious',
  suspicious: 'skillThreatSuspicious',
  unknown: 'skillThreatUnknown',
  clean: 'skillThreatClean',
} as const

function threatColor(threat: SafeSkillThreat): string {
  if (threat === 'malicious') return palette.red
  if (threat === 'suspicious') return palette.yellow
  if (threat === 'clean') return palette.green
  return palette.dim
}

function threatBg(threat: SafeSkillThreat): string {
  if (threat === 'malicious') return palette.redBg
  if (threat === 'suspicious') return palette.yellowBg
  if (threat === 'clean') return palette.greenBg
  return 'transparent'
}

interface SkillSectionProps {
  getSafeSkillStatus: () => Promise<SafeSkillStatus>
  setSafeSkillKey: (key: string) => Promise<SafeSkillStatus>
  listSkills: () => Promise<SkillEntry[]>
  scanSkill: (skillName: string) => Promise<SafeSkillReport>
  getSafeSkillCacheSnapshot: () => Promise<SkillScanResult[]>
  scanAllSkills: () => Promise<SkillScanResult[]>
  t: (key: string) => string
}

/** Skill audit block: SafeSkill API-key opt-in + per-skill multi-engine scan. */
function SkillSection({ getSafeSkillStatus, setSafeSkillKey, listSkills, scanSkill, getSafeSkillCacheSnapshot, scanAllSkills, t }: SkillSectionProps): ReactElement {
  const [, forceRender] = useReducer((n: number) => n + 1, 0)
  const [skills, setSkills] = useState<SkillEntry[]>([])
  const [skillsError, setSkillsError] = useState<string | null>(null)
  const [configured, setConfigured] = useState(false)
  const [draft, setDraft] = useState('')
  const [keyBusy, setKeyBusy] = useState(false)
  const [keyError, setKeyError] = useState<string | null>(null)
  const [keySaved, setKeySaved] = useState(false)
  const [scanningAll, setScanningAll] = useState(false)
  const [scanProgress, setScanProgress] = useState<{ current: number; total: number } | null>(null)

  useEffect(() => subscribeSkill(forceRender), [])

  // Restore cached SafeSkill scan results on mount / refresh.
  useEffect(() => {
    let disposed = false
    void (async () => {
      try {
        const cached = await getSafeSkillCacheSnapshot()
        if (disposed) return
        for (const entry of cached) {
          if (entry.report !== null) {
            setSkillState(entry.skillName, { loading: false, report: entry.report, error: null, fromCache: true })
          }
        }
      } catch {
        // best-effort — cache restore failure is never surfaced
      }
    })()
    return () => { disposed = true }
  }, [getSafeSkillCacheSnapshot])

  const refreshSkills = async (): Promise<void> => {
    setSkillsError(null)
    try {
      setSkills(await listSkills())
    } catch (cause) {
      setSkillsError(cause instanceof Error ? cause.message : String(cause))
    }
  }

  useEffect(() => {
    let disposed = false
    void (async () => {
      try {
        const status = await getSafeSkillStatus()
        if (disposed) return
        setConfigured(status.configured)
      } catch (cause) {
        if (disposed) return
        setKeyError(cause instanceof Error ? cause.message : String(cause))
      }
      await refreshSkills()
    })()
    return () => { disposed = true }
  }, [getSafeSkillStatus, listSkills])

  const saveKey = async (): Promise<void> => {
    if (keyBusy) return
    setKeyBusy(true)
    setKeyError(null)
    setKeySaved(false)
    try {
      const status = await setSafeSkillKey(draft)
      setConfigured(status.configured)
      if (status.configured) setDraft('')
      setKeySaved(true)
    } catch (cause) {
      setKeyError(cause instanceof Error ? cause.message : String(cause))
    } finally {
      setKeyBusy(false)
    }
  }

  const clearKey = async (): Promise<void> => {
    if (keyBusy) return
    setKeyBusy(true)
    setKeyError(null)
    try {
      await setSafeSkillKey('')
      setConfigured(false)
      setDraft('')
    } catch (cause) {
      setKeyError(cause instanceof Error ? cause.message : String(cause))
    } finally {
      setKeyBusy(false)
    }
  }

  const scan = async (name: string): Promise<void> => {
    if (getSkillState(name).loading) return
    setSkillState(name, { loading: true, report: null, error: null, fromCache: false })
    try {
      const report = await scanSkill(name)
      setSkillState(name, { loading: false, report, error: null, fromCache: false })
    } catch (cause) {
      setSkillState(name, { loading: false, report: null, error: cause instanceof Error ? cause.message : String(cause), fromCache: false })
    }
  }

  const scanAll = async (): Promise<void> => {
    if (scanningAll || !configured) return
    setScanningAll(true)
    setScanProgress({ current: 0, total: skills.length })
    try {
      const results = await scanAllSkills()
      for (let i = 0; i < results.length; i++) {
        const r = results[i]!
        setScanProgress({ current: i + 1, total: results.length })
        if (r.report !== null) {
          setSkillState(r.skillName, { loading: false, report: r.report, error: null, fromCache: r.fromCache })
        } else {
          setSkillState(r.skillName, { loading: false, report: null, error: r.error ?? t('skillScanFail'), fromCache: false })
        }
      }
    } catch (cause) {
      setSkillsError(cause instanceof Error ? cause.message : String(cause))
    } finally {
      setScanningAll(false)
      setScanProgress(null)
    }
  }

  function trustScoreColor(score: number): string {
    if (score < 0) return palette.dim
    if (score >= 70) return palette.green
    if (score >= 40) return palette.yellow
    return palette.red
  }

  return (
    <div style={{ marginTop: 20, padding: '12px 14px', border: `1px solid ${palette.border}`, borderRadius: 8 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
        <h3 style={{ fontSize: 14, fontWeight: 700, margin: 0 }}>{t('skillTitle')}</h3>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          {scanProgress !== null && (
            <span style={{ fontSize: 12, color: palette.busy }}>
              {t('skillScanningAll').replace('{current}', String(scanProgress.current)).replace('{total}', String(scanProgress.total))}
            </span>
          )}
          <button
            type="button"
            onClick={() => { void scanAll() }}
            disabled={scanningAll || !configured || skills.length === 0}
            style={{
              padding: '6px 12px', borderRadius: 6, border: `1px solid ${palette.border}`, background: palette.surface,
              cursor: (scanningAll || !configured || skills.length === 0) ? 'default' : 'pointer', fontSize: 13,
              opacity: (scanningAll || !configured || skills.length === 0) ? 0.6 : 1,
            }}
          >
            {scanningAll ? (scanProgress !== null ? `${scanProgress.current}/${scanProgress.total}` : '…') : t('skillScanAll')}
          </button>
          <button
            type="button"
            onClick={() => { void refreshSkills() }}
            style={{ padding: '6px 12px', borderRadius: 6, border: `1px solid ${palette.border}`, background: palette.surface, cursor: 'pointer', fontSize: 13 }}
          >
            {t('skillRefresh')}
          </button>
        </div>
      </div>
      <p style={{ fontSize: 12, color: palette.mute, margin: '6px 0 10px' }}>{t('skillDesc')}</p>

      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        <span style={{ fontWeight: 600, fontSize: 13 }}>{t('skillKeyLabel')}</span>
        <span style={{ fontSize: 12, color: configured ? palette.green : palette.mute, fontWeight: 600 }}>
          {configured ? t('tokenConfigured') : t('tokenNotConfigured')}
        </span>
      </div>
      <p style={{ fontSize: 12, color: palette.mute, margin: '4px 0 8px' }}>{t('skillKeyHint')}</p>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        <input
          type="password"
          value={draft}
          onChange={event => setDraft(event.target.value)}
          placeholder={t('skillKeyPlaceholder')}
          autoComplete="off"
          spellCheck={false}
          style={{ flex: 1, minWidth: 220, padding: '6px 10px', borderRadius: 6, border: `1px solid ${palette.border}`, fontSize: 13 }}
        />
        <button
          type="button"
          disabled={keyBusy}
          onClick={() => { void saveKey() }}
          style={{
            padding: '6px 12px', borderRadius: 6, border: `1px solid ${palette.border}`, background: palette.surface,
            cursor: keyBusy ? 'default' : 'pointer', fontSize: 13, opacity: keyBusy ? 0.6 : 1,
          }}
        >
          {t('tokenSave')}
        </button>
        {configured && (
          <button
            type="button"
            disabled={keyBusy}
            onClick={() => { void clearKey() }}
            style={{
              padding: '6px 12px', borderRadius: 6, border: `1px solid ${palette.border}`, background: palette.surface,
              cursor: keyBusy ? 'default' : 'pointer', fontSize: 13, opacity: keyBusy ? 0.6 : 1,
            }}
          >
            {t('tokenClear')}
          </button>
        )}
      </div>
      {keySaved && <div style={{ marginTop: 6, fontSize: 12, color: palette.green }}>{t('tokenSaved')}</div>}
      {keyError !== null && <div style={{ marginTop: 6, fontSize: 12, color: palette.red }}>{keyError}</div>}
      {!configured && <div style={{ marginTop: 10, fontSize: 12, color: palette.mute, fontStyle: 'italic' }}>{t('skillNoKey')}</div>}

      <div style={{ marginTop: 10 }}>
        {skillsError !== null
          ? <div style={{ fontSize: 12, color: palette.red, marginTop: 8 }}>{skillsError}</div>
          : skills.length === 0
            ? <div style={{ marginTop: 8, fontSize: 13, color: palette.mute }}>{t('skillEmpty')}</div>
            : skills.map(skill => {
              const state = getSkillState(skill.name)
              return (
                <div key={skill.name} style={{ padding: '10px 0', borderTop: `1px solid ${palette.border}` }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                    <code style={{ fontWeight: 600, fontSize: 13 }}>{skill.name}</code>
                    {skill.description !== '' && <span style={{ fontSize: 12, color: palette.mute }}>{skill.description}</span>}
                    <button
                      type="button"
                      disabled={state.loading || !configured}
                      onClick={() => { void scan(skill.name) }}
                      style={{
                        marginLeft: 'auto',
                        padding: '6px 12px', borderRadius: 6, border: `1px solid ${palette.border}`, background: palette.surface,
                        cursor: (state.loading || !configured) ? 'default' : 'pointer', fontSize: 13, opacity: (state.loading || !configured) ? 0.6 : 1,
                      }}
                    >
                      {t('skillScan')}
                    </button>
                  </div>
                  {state.loading && (
                    <div style={{ marginTop: 8, padding: '8px 12px', borderRadius: 6, background: palette.busyBg, border: `1px solid ${palette.busyBorder}`, fontSize: 12, color: palette.busy }}>
                      {t('skillScanning')}
                    </div>
                  )}
                  {state.error !== null && (
                    <div style={{ marginTop: 8, padding: '8px 12px', borderRadius: 6, background: palette.redBg, color: palette.red, fontSize: 12 }}>
                      {t('loadError')}: {state.error}
                    </div>
                  )}
                  {state.report !== null && (
                    <div style={{ marginTop: 8, padding: '10px 12px', borderRadius: 6, border: `1px solid ${threatColor(state.report.threatLevel)}`, background: threatBg(state.report.threatLevel) }}>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10, alignItems: 'center' }}>
                        <span style={{ fontWeight: 700, fontSize: 13, color: threatColor(state.report.threatLevel) }}>
                          {t('skillThreat')}: {t(THREAT_KEY[state.report.threatLevel])}
                        </span>
                        {state.report.trustScore >= 0 && <span style={{ fontSize: 12, fontWeight: 600, color: trustScoreColor(state.report.trustScore) }}>{t('skillTrust')}: {state.report.trustScore}/100</span>}
                        {state.report.threatClassify !== '' && <span style={{ fontSize: 12, color: palette.mute }}>{t('skillClassify')}: {state.report.threatClassify}</span>}
                        {state.fromCache && <span style={{ fontSize: 11, color: palette.mute, fontStyle: 'italic' }}>{t('skillFromCache')}</span>}
                        {state.report.permalink !== '' && <SafeLink url={state.report.permalink} label={t('skillPermalink')} />}
                      </div>
                      {Object.keys(state.report.multiVerdict).length > 0 && (
                        <div style={{ marginTop: 6, display: 'flex', flexWrap: 'wrap', gap: 6, alignItems: 'center', fontSize: 12 }}>
                          <span style={{ fontWeight: 600 }}>{t('skillMulti')}:</span>
                          {Object.entries(state.report.multiVerdict).map(([engine, verdict]) => (
                            <span key={engine} style={{ padding: '1px 6px', borderRadius: 8, background: palette.surfaceHi }}>{engine}: {verdict}</span>
                          ))}
                        </div>
                      )}
                      {state.report.indicators.length > 0 && (
                        <div style={{ marginTop: 8 }}>
                          <div style={{ fontWeight: 600, fontSize: 12 }}>{t('skillIndicators')}</div>
                          <ul style={{ margin: '4px 0 0', paddingLeft: 18, fontSize: 13 }}>
                            {state.report.indicators.map((indicator, index) => (
                              <li key={index} style={{ marginTop: 4 }}>
                                <span style={{ fontWeight: 600 }}>{indicator.indicator}</span>
                                {indicator.category !== '' && <span style={{ color: palette.mute }}> · {indicator.category}</span>}
                                <span style={{ color: indicator.severity === 'high' ? palette.red : indicator.severity === 'medium' ? palette.yellow : palette.dim }}> [{indicator.severity}]</span>
                                {indicator.evidence !== '' && <div style={{ fontSize: 12, color: palette.mute, whiteSpace: 'pre-wrap' }}>{indicator.evidence}</div>}
                                {indicator.sources.length > 0 && (
                                  <div style={{ fontSize: 11, color: palette.mute }}>{indicator.sources.map(source => (source.lines !== '' ? `${source.file}:${source.lines}` : source.file)).join(' · ')}</div>
                                )}
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )
            })}
      </div>
    </div>
  )
}

export function SecuritySection({ getReport, getAiAudit, forceAiAudit, getAiAuditStatus, getAiAuditCacheSnapshot, getGithubTokenStatus, setGithubToken, getAuditConfig, setAuditTtl, getSafeSkillStatus, setSafeSkillKey, listSkills, scanSkill, getSafeSkillCacheSnapshot, scanAllSkills, t }: SecuritySectionProps): ReactElement {
  const [report, setReport] = useState<SecurityReport | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [, forceRender] = useReducer((n: number) => n + 1, 0)

  // GitHub token form state; the token value itself is never read back (secret).
  const [tokenConfigured, setTokenConfigured] = useState(false)
  const [tokenDraft, setTokenDraft] = useState('')
  const [tokenBusy, setTokenBusy] = useState(false)
  const [tokenError, setTokenError] = useState<string | null>(null)
  const [tokenSaved, setTokenSaved] = useState(false)

  // AI-audit cache TTL form state (hours; 0 disables the cache).
  const [ttl, setTtl] = useState<number | null>(null)
  const [ttlDraft, setTtlDraft] = useState('')
  const [ttlBusy, setTtlBusy] = useState(false)
  const [ttlError, setTtlError] = useState<string | null>(null)
  const [ttlSaved, setTtlSaved] = useState(false)

  // In-flight AI-audit progress poll, cleared on unmount to avoid leaking the interval.
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  // Re-render whenever the module-level AI store changes (results survive unmount).
  useEffect(() => subscribeAi(forceRender), [])

  // Stop the AI-audit progress poll if the section unmounts mid-audit.
  useEffect(() => () => { if (pollRef.current !== null) clearInterval(pollRef.current) }, [])

  // Follow the app's light/dark theme live: repaint the palette and re-render on toggle.
  useEffect(() => {
    const apply = (): void => {
      Object.assign(palette, isAppDark() ? darkPalette : lightPalette)
      forceRender()
    }
    apply()
    if (typeof document === 'undefined') return
    const observer = new MutationObserver(apply)
    const options = { attributes: true, attributeFilter: ['data-ds-dark-theme'] }
    observer.observe(document.body, options)
    observer.observe(document.documentElement, options)
    return () => observer.disconnect()
  }, [])

  // Load the masked token state once on mount.
  useEffect(() => {
    let disposed = false
    void (async () => {
      try {
        const status = await getGithubTokenStatus()
        if (!disposed) setTokenConfigured(status.configured)
      } catch (cause) {
        if (!disposed) setTokenError(cause instanceof Error ? cause.message : String(cause))
      }
    })()
    return () => { disposed = true }
  }, [getGithubTokenStatus])

  // Load the current cache TTL once on mount.
  useEffect(() => {
    let disposed = false
    void (async () => {
      try {
        const config = await getAuditConfig()
        if (!disposed) {
          setTtl(config.ttlHours)
          setTtlDraft(String(config.ttlHours))
        }
      } catch (cause) {
        if (!disposed) setTtlError(cause instanceof Error ? cause.message : String(cause))
      }
    })()
    return () => { disposed = true }
  }, [getAuditConfig])

  const saveTtl = async (): Promise<void> => {
    if (ttlBusy) return
    const value = Number(ttlDraft)
    if (ttlDraft.trim() === '' || !Number.isInteger(value) || value < 0) {
      setTtlError(t('ttlInvalid'))
      return
    }
    setTtlBusy(true)
    setTtlError(null)
    setTtlSaved(false)
    try {
      const config = await setAuditTtl(value)
      setTtl(config.ttlHours)
      setTtlDraft(String(config.ttlHours))
      setTtlSaved(true)
    } catch (cause) {
      setTtlError(cause instanceof Error ? cause.message : String(cause))
    } finally {
      setTtlBusy(false)
    }
  }

  const saveToken = async (): Promise<void> => {
    if (tokenBusy) return
    setTokenBusy(true)
    setTokenError(null)
    setTokenSaved(false)
    try {
      const status = await setGithubToken(tokenDraft)
      setTokenConfigured(status.configured)
      if (status.configured) setTokenDraft('')
      setTokenSaved(true)
    } catch (cause) {
      setTokenError(cause instanceof Error ? cause.message : String(cause))
    } finally {
      setTokenBusy(false)
    }
  }

  const clearToken = async (): Promise<void> => {
    if (tokenBusy) return
    setTokenBusy(true)
    setTokenError(null)
    setTokenSaved(false)
    try {
      await setGithubToken('')
      setTokenConfigured(false)
      setTokenDraft('')
    } catch (cause) {
      setTokenError(cause instanceof Error ? cause.message : String(cause))
    } finally {
      setTokenBusy(false)
    }
  }

  const run = async (): Promise<void> => {
    setLoading(true)
    setError(null)
    try {
      setReport(await getReport())
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause))
    } finally {
      setLoading(false)
    }
  }

  const runAiWith = async (pluginName: string, invoke: (name: string) => Promise<AiAuditResult>): Promise<void> => {
    setAiState(pluginName, { loading: true, result: null, error: null, progress: { phase: 'collecting', detail: t('aiStarting') } })
    // Poll live progress so the user can see the audit phase + what is audited.
    const poll = setInterval(() => {
      getAiAuditStatus(pluginName)
        .then(progress => {
          if (progress !== null) {
            setAiState(pluginName, { progress: { phase: progress.phase, detail: progress.detail } })
          }
        })
        .catch(() => { /* poll errors are non-fatal; the audit RPC still reports the final failure */ })
    }, 1200)
    pollRef.current = poll
    try {
      const result = await invoke(pluginName)
      clearInterval(poll)
      pollRef.current = null
      setAiState(pluginName, { loading: false, result, error: null, progress: null })
    } catch (cause) {
      clearInterval(poll)
      pollRef.current = null
      const message = cause instanceof Error ? cause.message : String(cause)
      setAiState(pluginName, { loading: false, result: null, error: message, progress: null })
    }
  }

  const runAi = async (pluginName: string): Promise<void> => { await runAiWith(pluginName, getAiAudit) }
  const runAiForce = async (pluginName: string): Promise<void> => { await runAiWith(pluginName, forceAiAudit) }

  useEffect(() => { void run() }, [])

  // Restore AI classifications/scores that were cached before a page refresh.
  const restoreAi = async (): Promise<void> => {
    try {
      const cached = await getAiAuditCacheSnapshot()
      for (const result of cached) {
        setAiState(result.pluginName, { loading: false, result, error: null, progress: null })
      }
    } catch {
      // Best-effort restore: a manual AI audit always works regardless.
    }
  }
  useEffect(() => { void restoreAi() }, [])

  const totalScanned = report?.plugins.reduce((sum, plugin) => sum + plugin.scannedFiles, 0) ?? 0
  const deltaMap = new Map((report?.deltas ?? []).map(delta => [delta.name, delta]))
  const effCounts = { red: 0, yellow: 0, green: 0 }
  for (const plugin of report?.plugins ?? []) {
    const risk = effRisk(plugin.risk, getAiState(plugin.name).result?.verdict)
    if (risk === 'red') effCounts.red += 1
    else if (risk === 'yellow') effCounts.yellow += 1
    else effCounts.green += 1
  }

  return (
    <section style={{ padding: '4px 0' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
        <h2 style={{ fontSize: 16, fontWeight: 700, margin: 0 }}>{t('title')}</h2>
        <button
          type="button"
          disabled={loading}
          onClick={() => { void run() }}
          style={{
            padding: '6px 12px',
            borderRadius: 6,
            border: `1px solid ${palette.border}`,
            background: palette.surface,
            cursor: loading ? 'default' : 'pointer',
            fontSize: 13,
            opacity: loading ? 0.6 : 1,
          }}
        >
          {loading ? t('rescanning') : t('rescan')}
        </button>
      </div>

      <p style={{ fontSize: 13, color: palette.mute, margin: '8px 0 0' }}>{t('desc')}</p>

      <div style={{ marginTop: 14, padding: '12px 14px', border: `1px solid ${palette.border}`, borderRadius: 8 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <span style={{ fontWeight: 600, fontSize: 13 }}>{t('tokenLabel')}</span>
          <span style={{ fontSize: 12, color: tokenConfigured ? palette.green : palette.mute, fontWeight: 600 }}>
            {tokenConfigured ? t('tokenConfigured') : t('tokenNotConfigured')}
          </span>
        </div>
        <p style={{ fontSize: 12, color: palette.mute, margin: '4px 0 8px' }}>{t('tokenHint')}</p>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <input
            type="password"
            value={tokenDraft}
            onChange={event => setTokenDraft(event.target.value)}
            placeholder={t('tokenPlaceholder')}
            autoComplete="off"
            spellCheck={false}
            style={{ flex: 1, minWidth: 220, padding: '6px 10px', borderRadius: 6, border: `1px solid ${palette.border}`, fontSize: 13 }}
          />
          <button
            type="button"
            disabled={tokenBusy}
            onClick={() => { void saveToken() }}
            style={{
              padding: '6px 12px', borderRadius: 6, border: `1px solid ${palette.border}`, background: palette.surface,
              cursor: tokenBusy ? 'default' : 'pointer', fontSize: 13, opacity: tokenBusy ? 0.6 : 1,
            }}
          >
            {t('tokenSave')}
          </button>
          {tokenConfigured && (
            <button
              type="button"
              disabled={tokenBusy}
              onClick={() => { void clearToken() }}
              style={{
                padding: '6px 12px', borderRadius: 6, border: `1px solid ${palette.border}`, background: palette.surface,
                cursor: tokenBusy ? 'default' : 'pointer', fontSize: 13, opacity: tokenBusy ? 0.6 : 1,
              }}
            >
              {t('tokenClear')}
            </button>
          )}
        </div>
        {tokenSaved && <div style={{ marginTop: 6, fontSize: 12, color: palette.green }}>{t('tokenSaved')}</div>}
        {tokenError !== null && <div style={{ marginTop: 6, fontSize: 12, color: palette.red }}>{t('loadError')}: {tokenError}</div>}
      </div>

      <div style={{ marginTop: 12, padding: '12px 14px', border: `1px solid ${palette.border}`, borderRadius: 8 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <span style={{ fontWeight: 600, fontSize: 13 }}>{t('ttlLabel')}</span>
          {ttl !== null && <span style={{ fontSize: 12, color: palette.mute }}>{t('ttlValue')}: {ttl} {t('ttlHoursUnit')}{ttl === 0 ? ` · ${t('ttlDisabled')}` : ''}</span>}
        </div>
        <p style={{ fontSize: 12, color: palette.mute, margin: '4px 0 8px' }}>{t('ttlHint')}</p>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <input
            type="number"
            min={0}
            step={1}
            value={ttlDraft}
            onChange={event => setTtlDraft(event.target.value)}
            style={{ width: 110, padding: '6px 10px', borderRadius: 6, border: `1px solid ${palette.border}`, fontSize: 13 }}
          />
          <button
            type="button"
            disabled={ttlBusy}
            onClick={() => { void saveTtl() }}
            style={{
              padding: '6px 12px', borderRadius: 6, border: `1px solid ${palette.border}`, background: palette.surface,
              cursor: ttlBusy ? 'default' : 'pointer', fontSize: 13, opacity: ttlBusy ? 0.6 : 1,
            }}
          >
            {t('ttlSave')}
          </button>
          {ttlSaved && <span style={{ fontSize: 12, color: palette.green }}>{t('ttlSaved')}</span>}
          {ttlError !== null && <span style={{ fontSize: 12, color: palette.red }}>{ttlError}</span>}
        </div>
      </div>

      {error !== null && (
        <div style={{ marginTop: 12, padding: '8px 12px', borderRadius: 6, background: palette.redBg, color: palette.red, fontSize: 13 }}>
          {t('loadError')}: {error}
        </div>
      )}

      {report === null
        ? <div style={{ marginTop: 16, fontSize: 13, color: palette.mute }}>{loading ? t('loading') : t('empty')}</div>
        : (
          <div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10, alignItems: 'center', marginTop: 14 }}>
              <span style={{ padding: '4px 12px', borderRadius: 12, fontSize: 13, fontWeight: 600, color: palette.green, background: palette.greenBg }}>
                {t('riskGreen')} {effCounts.green}
              </span>
              <span style={{ padding: '4px 12px', borderRadius: 12, fontSize: 13, fontWeight: 600, color: palette.yellow, background: palette.yellowBg }}>
                {t('riskYellow')} {effCounts.yellow}
              </span>
              <span style={{ padding: '4px 12px', borderRadius: 12, fontSize: 13, fontWeight: 600, color: palette.red, background: palette.redBg }}>
                {t('riskRed')} {effCounts.red}
              </span>
              <span style={{ marginLeft: 'auto', fontSize: 12, color: palette.mute }}>{t('filesScanned')}: {totalScanned}</span>
            </div>

            {report.plugins.length === 0
              ? <div style={{ marginTop: 16, fontSize: 13, color: palette.mute }}>{t('empty')}</div>
              : report.plugins.map(plugin => (
                <PluginRow
                  key={plugin.name}
                  plugin={plugin}
                  t={t}
                  aiState={getAiState(plugin.name)}
                  onAudit={() => { void runAi(plugin.name) }}
                  onForceAudit={() => { void runAiForce(plugin.name) }}
                  delta={deltaMap.get(plugin.name)}
                />
              ))}
          </div>
        )}

      <SkillSection
        getSafeSkillStatus={getSafeSkillStatus}
        setSafeSkillKey={setSafeSkillKey}
        listSkills={listSkills}
        scanSkill={scanSkill}
        getSafeSkillCacheSnapshot={getSafeSkillCacheSnapshot}
        scanAllSkills={scanAllSkills}
        t={t}
      />
    </section>
  )
}