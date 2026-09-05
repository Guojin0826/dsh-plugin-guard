/** Settings section rendering the plugin security audit report (green/yellow/red) plus per-plugin AI audit with live progress. */
import type { InjectFace, PropsLocale } from '@deepseek-ai/dsh-client-ui-slots'
import { useEffect, useReducer, useState, type ReactElement } from 'react'
import type { AiAuditResult, AuditPhase, AuditProgress, GithubEvidence, GithubTokenStatus, PluginAudit, ReputationEvidence, SecurityReport } from '../contracts.ts'

export interface SecuritySectionInjected {
  getReport: () => Promise<SecurityReport>
  getAiAudit: (pluginName: string) => Promise<AiAuditResult>
  getAiAuditStatus: (pluginName: string) => Promise<AuditProgress | null>
  getGithubTokenStatus: () => Promise<GithubTokenStatus>
  setGithubToken: (token: string) => Promise<GithubTokenStatus>
}

type SecuritySectionProps = InjectFace<SecuritySectionInjected> & PropsLocale<'dsh-plugin-guard'>

const RISK_KEY = { red: 'riskRed', yellow: 'riskYellow', green: 'riskGreen' } as const
const VERDICT_KEY = {
  safe: 'aiSafe',
  suspicious: 'aiSuspicious',
  malicious: 'aiMalicious',
  inconclusive: 'aiInconclusive',
} as const

const palette = {
  red: '#d93025',
  redBg: '#fdebea',
  yellow: '#b27000',
  yellowBg: '#fff6e0',
  green: '#1a7f37',
  greenBg: '#e8f5ec',
  border: 'rgba(0,0,0,0.12)',
  mute: 'rgba(0,0,0,0.55)',
  busy: '#3b5b8c',
  busyBg: '#f0f4fb',
  busyBorder: '#d5e0f0',
}

function riskColor(risk: PluginAudit['risk']): string {
  return palette[risk]
}
function riskBg(risk: PluginAudit['risk']): string {
  return risk === 'red' ? palette.redBg : risk === 'yellow' ? palette.yellowBg : palette.greenBg
}

function FlagRow({ flag }: { flag: PluginAudit['flags'][number] }): ReactElement {
  const sevColor = flag.severity === 'high' ? palette.red : flag.severity === 'medium' ? palette.yellow : '#444'
  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center', padding: '4px 0' }}>
      <code style={{ fontSize: 12, color: sevColor, fontWeight: 600 }}>{flag.code}</code>
      <span style={{ fontSize: 13 }}>{flag.label}</span>
      <span style={{ fontSize: 12, color: palette.mute, wordBreak: 'break-all' }}>{flag.files.join(' · ')}</span>
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
  return (
    <div style={{ marginTop: 8, paddingTop: 6, borderTop: `1px dashed ${palette.border}` }}>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '3px 10px', alignItems: 'center' }}>
        <SafeLink url={github.htmlUrl} label={github.fullName} />
        {github.stars >= 0 && <span>⭐ {github.stars.toLocaleString()}</span>}
        {github.forks >= 0 && <span>⑂ {github.forks.toLocaleString()}</span>}
        {github.archived && <span style={{ color: palette.mute }}>({t('aiArchived')})</span>}
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
            <span style={{ fontWeight: 600, color: advisory.malicious ? palette.red : '#444' }}>
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
        {(reputation.npmHomepage !== '' || reputation.npmRepository !== '') && (
          <div style={{ marginTop: 3 }}>
            {reputation.npmHomepage !== '' && <SafeLink url={reputation.npmHomepage} label={t('aiHomepage')} />}
            {reputation.npmRepository !== '' && <SafeLink url={reputation.npmRepository} label={t('aiRepository')} />}
          </div>
        )}
        <GithubBox github={reputation.github} t={t} />
        <AdvisoriesBox reputation={reputation} t={t} />
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
        <span style={{ fontSize: 11, color: palette.mute }}>{t('aiModel')}: {result.provider}/{result.model}</span>
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

function PluginRow({ plugin, t, aiState, onAudit }: {
  plugin: PluginAudit
  t: (key: string) => string
  aiState: AiState
  onAudit: () => void
}): ReactElement {
  const badge = (
    <span style={{
      display: 'inline-block',
      minWidth: 48,
      textAlign: 'center',
      padding: '2px 8px',
      borderRadius: 10,
      fontSize: 12,
      fontWeight: 600,
      color: riskColor(plugin.risk),
      background: riskBg(plugin.risk),
    }}>
      {t(RISK_KEY[plugin.risk])}
    </span>
  )

  return (
    <details style={{ border: `1px solid ${palette.border}`, borderRadius: 8, marginTop: 12, overflow: 'hidden' }}>
      <summary style={{ cursor: 'pointer', listStyle: 'none', display: 'flex', alignItems: 'center', gap: 12, padding: '10px 14px', flexWrap: 'wrap' }}>
        {badge}
        <code style={{ fontWeight: 600, fontSize: 14 }}>{plugin.name}</code>
        <span style={{ fontSize: 12, color: palette.mute }}>v{plugin.version}</span>
        <span style={{ fontSize: 11, opacity: 0.75 }}>{plugin.active ? t('active') : t('inactive')}</span>
        <span style={{ marginLeft: 'auto', fontSize: 12, color: palette.mute }}>{t('colScore')}: {plugin.score}</span>
      </summary>

      <div style={{ borderTop: `1px solid ${palette.border}`, padding: '12px 14px', display: 'flex', flexDirection: 'column', gap: 12 }}>
        <div>
          <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 4 }}>{t('flags')} ({plugin.flags.length})</div>
          {plugin.flags.length === 0
            ? <div style={{ fontSize: 13, color: palette.mute }}>{t('noFlags')}</div>
            : plugin.flags.map(flag => <FlagRow key={flag.code} flag={flag} />)}
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
          <button
            type="button"
            disabled={aiState.loading}
            onClick={onAudit}
            style={{
              padding: '6px 12px',
              borderRadius: 6,
              border: `1px solid ${palette.border}`,
              background: '#fff',
              cursor: aiState.loading ? 'default' : 'pointer',
              fontSize: 13,
              opacity: aiState.loading ? 0.6 : 1,
            }}
          >
            {aiState.loading ? t('aiAuditing') : t('aiAudit')}
          </button>
          <AiAuditBox state={aiState} t={t} />
        </div>
      </div>
    </details>
  )
}

export function SecuritySection({ getReport, getAiAudit, getAiAuditStatus, getGithubTokenStatus, setGithubToken, t }: SecuritySectionProps): ReactElement {
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

  // Re-render whenever the module-level AI store changes (results survive unmount).
  useEffect(() => subscribeAi(forceRender), [])

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

  const runAi = async (pluginName: string): Promise<void> => {
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
    try {
      const result = await getAiAudit(pluginName)
      clearInterval(poll)
      setAiState(pluginName, { loading: false, result, error: null, progress: null })
    } catch (cause) {
      clearInterval(poll)
      const message = cause instanceof Error ? cause.message : String(cause)
      setAiState(pluginName, { loading: false, result: null, error: message, progress: null })
    }
  }

  useEffect(() => { void run() }, [])

  const totalScanned = report?.plugins.reduce((sum, plugin) => sum + plugin.scannedFiles, 0) ?? 0

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
            background: '#fff',
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
              padding: '6px 12px', borderRadius: 6, border: `1px solid ${palette.border}`, background: '#fff',
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
                padding: '6px 12px', borderRadius: 6, border: `1px solid ${palette.border}`, background: '#fff',
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
                {t('riskGreen')} {report.greenCount}
              </span>
              <span style={{ padding: '4px 12px', borderRadius: 12, fontSize: 13, fontWeight: 600, color: palette.yellow, background: palette.yellowBg }}>
                {t('riskYellow')} {report.yellowCount}
              </span>
              <span style={{ padding: '4px 12px', borderRadius: 12, fontSize: 13, fontWeight: 600, color: palette.red, background: palette.redBg }}>
                {t('riskRed')} {report.redCount}
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
                />
              ))}
          </div>
        )}
    </section>
  )
}