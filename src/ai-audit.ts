/**
 * dsh-plugin-guard AI audit: calls the harness default model with a layered
 * picture — the plugin's *self-declared purpose* (package.json/README), the
 * static code findings plus source evidence, and a best-effort *internet
 * reputation* lookup (npm registry + weekly downloads + a web search). The
 * model is told to judge whether dangerous capabilities are consistent with
 * the plugin's stated job, not to flag them in isolation. Runs entirely on the
 * Host; the Web client only sees the typed `AiAuditResult` over the guard
 * Remote and the live `AuditProgress` over `guard/getAiAuditStatus`.
 */
import type { Context } from '@deepseek-ai/cordis'
import { BlockAssembler, createUserMessage } from '@deepseek-ai/dsh-llm'
import { join } from 'node:path'
import { collectEvidence, collectPluginMetadata, type EvidenceSnippet, type PluginMetadata } from './scanner.ts'
import {
  aiAssessmentSchema,
  type AiAssessment,
  type AiAuditResult,
  type AuditPhase,
  type GithubEvidence,
  type PluginAudit,
  type ReputationEvidence,
  type RiskLevel,
} from './contracts.ts'

/** Minimal callable faces; the module stays independent of exact package types. */
interface ModelSelection {
  provider: string
  model: string
}

interface LlmCallOptions {
  provider: string
  model: string
  messages: unknown[]
  system: string
  maxTokens: number
  signal: AbortSignal
}

interface LlmFace {
  stream(options: LlmCallOptions): AsyncIterable<unknown>
}

interface GuardContext {
  llm: LlmFace
  agentDefaultModel: { currentSelection(): ModelSelection }
}

/**
 * Model output bound. Reasoning models spend most of this budget on chain-of-
 * thought, so a small cap truncates the final JSON; the assessment JSON itself
 * is only a few hundred tokens. 32768 leaves generous room for reasoning +
 * answer even when a model decides to reason long.
 */
const MAX_OUTPUT_TOKENS = 32768
/** Abort a call that runs away instead of hanging the settings panel. */
const AI_TIMEOUT_MS = 300_000
/** Per-fetch bound for the reputation lookups (they run in parallel). */
const FETCH_TIMEOUT_MS = 7000

const SYSTEM_PROMPT = [
  '你是一名资深应用安全审计专家。你会收到一个 DeepSeek Harness 第三方插件的三层信息：',
  '  1) 插件自称的功能（package.json 描述 / 关键词 / README 摘要 / 安装脚本）；',
  '  2) 静态代码扫描结果与关键代码片段；',
  '  3) 互联网声誉信息（npm registry 元数据、周下载量、搜索结果；可能缺失或不全）。',
  '',
  '你的任务：结合三层信息判断该插件的安全风险，只输出一个严格的 JSON 对象，不要输出任何其他文字、解释或 Markdown 代码块。',
  '',
  '输出 JSON 必须正好包含以下字段（键名固定为英文）：',
  '{',
  '  "verdict": "safe" | "suspicious" | "malicious" | "inconclusive",',
  '  "risk": "green" | "yellow" | "red",',
  '  "summary": "一两句中文风险评估概述",',
  '  "concerns": ["具体担忧点", "..."],',
  '  "recommendations": ["建议的处置措施", "..."]',
  '}',
  '',
  '核心判断原则——必须结合插件自称的功能，不要孤立地看待危险能力：',
  '- 危险能力（子进程、文件读写、网络访问、环境变量、eval 等）本身不是恶意的证据；先判断这些能力是否与插件自称的功能一致。',
  '- 例如：自称"文件管理器 / 终端工具 / 代码执行器 / 爬虫"的插件读写文件、执行命令、发网络请求是它的合理本职，不应仅因此判为恶意。',
  '- 只有当能力明显超出自称功能，且指向数据外传、凭据窃取、后门、挖矿、勒索、隐蔽联网回传等恶意目的时，才判 "malicious"。',
  '- 若能力与功能基本一致、仅实现上值得警惕（如命令拼接、硬编码外联地址），给出 "suspicious" 及具体复核建议。',
  '- 互联网声誉只作为佐证：知名维护者 / 大量下载 / 正常仓库 / 中立搜索结果可降低疑点；无名新包、混淆代码、可疑安装脚本、负面搜索命中则提高疑点。声誉信息缺失时不臆造。',
  '- GitHub 仓库信号（若提供）：作者账号刚注册、公开仓库极少、仓库极新却 star 异常偏高、或 npm 包与仓库内容明显不符，都是仿冒/钓鱼/刷星的信号，应提高疑点；反之老账号、多仓库、star 与活跃度匹配则降低疑点。注意"短时间内 star 不合理暴涨"与"无其他仓库的新号作者"组合尤其可疑。',
  '',
  '判定标准：',
  '- "safe": 危险能力属于该插件的合理功能，未发现超出功能的恶意意图。',
  '- "suspicious": 能力超出功能、实现可疑或有负面声誉线索，需要人工复核。',
  '- "malicious": 有明显恶意意图（窃取数据、后门、挖矿、勒索、凭据外传等）。',
  '- "inconclusive": 静态证据与声誉信息都不足以得出结论。',
  '- risk 与 verdict 对应：malicious→red；suspicious→yellow（若含高危能力且意图存疑→red）；inconclusive→yellow；safe→green。',
  '',
  'concerns 与 recommendations 应基于"功能一致性 + 声誉"给出；若没有，输出空数组 []。summary 必须用中文，并说明插件功能与其危险能力之间的关系。',
  '只输出 JSON。',
].join('\n')

function buildUserPrompt(
  plugin: PluginAudit,
  snippets: EvidenceSnippet[],
  metadata: PluginMetadata,
  reputation: ReputationEvidence,
): string {
  const lines: string[] = []
  lines.push(`插件名: ${plugin.name}`)
  lines.push(`版本: ${plugin.version}`)
  lines.push(`来源(spec): ${plugin.source}`)
  lines.push(`是否启用: ${plugin.active ? '是' : '否'}`)
  lines.push('')

  lines.push('【插件自称的功能】')
  lines.push(`- package.json 描述: ${metadata.description || '(无)'}`)
  lines.push(`- dsh 插件描述: ${metadata.manifestDescription || '(无)'}`)
  lines.push(`- 关键词: ${metadata.keywords.length > 0 ? metadata.keywords.join(', ') : '(无)'}`)
  lines.push(`- 作者: ${metadata.author || '(无)'}`)
  lines.push(`- 仓库: ${metadata.repository || '(无)'}`)
  lines.push(`- 主页: ${metadata.homepage || '(无)'}`)
  lines.push(`- 安装脚本: ${metadata.scripts !== '' ? `\n${metadata.scripts}` : '(无)'}`)
  if (metadata.readmeExcerpt !== '') {
    lines.push('- README 摘要（节选）:')
    lines.push(`"""${metadata.readmeExcerpt.slice(0, 1500).replace(/\r/g, '')}"""`)
  }
  lines.push('')

  lines.push('【互联网声誉】（供佐证，可能不全）')
  lines.push(`- npm 描述: ${reputation.npmDescription || '(未收录)'}`)
  lines.push(`- npm 最新版本: ${reputation.npmLatest || '(未知)'}`)
  lines.push(`- npm 维护者: ${reputation.npmMaintainers.length > 0 ? reputation.npmMaintainers.join(', ') : '(未知)'}`)
  lines.push(`- npm 首次发布: ${reputation.npmCreated || '(未知)'}`)
  lines.push(`- npm 最近更新: ${reputation.npmModified || '(未知)'}`)
  lines.push(`- 周下载量: ${reputation.weeklyDownloads >= 0 ? String(reputation.weeklyDownloads) : '(未知)'}`)
  if (reputation.searchResults !== '') {
    lines.push('- 搜索结果:')
    lines.push(reputation.searchResults)
  } else {
    lines.push('- 搜索结果: (无)')
  }
  if (reputation.note !== '') lines.push(`- 声誉查询备注: ${reputation.note}`)
  lines.push('')

  const github = reputation.github
  if (github.fullName !== '') {
    lines.push('【GitHub 仓库】（供佐证，可能不全）')
    lines.push(`- 仓库: ${github.fullName}`)
    if (github.description !== '') lines.push(`- 仓库描述: ${github.description}`)
    lines.push(`- stars: ${github.stars >= 0 ? String(github.stars) : '(未知)'}`)
    lines.push(`- forks: ${github.forks >= 0 ? String(github.forks) : '(未知)'}`)
    if (github.archived) lines.push('- 仓库状态: 已归档')
    lines.push(`- 创建时间: ${github.createdAt || '(未知)'}`)
    lines.push(`- 最近推送: ${github.pushedAt || '(未知)'}`)
    if (github.ownerCreatedAt !== '') lines.push(`- 作者账号注册时间: ${github.ownerCreatedAt}`)
    if (github.ownerPublicRepos >= 0) lines.push(`- 作者公开仓库数: ${github.ownerPublicRepos}`)
    if (github.ownerFollowers >= 0) lines.push(`- 作者 followers: ${github.ownerFollowers}`)
    if (github.note !== '') lines.push(`- GitHub 查询备注: ${github.note}`)
    lines.push('')
  } else if (github.note !== '') {
    lines.push(`【GitHub 仓库】未解析到仓库（${github.note}）`)
    lines.push('')
  }

  lines.push('【静态扫描】')
  lines.push(`风险等级 ${plugin.risk}，风险分 ${plugin.score}，扫描 ${plugin.scannedFiles} 个文件`)
  if (plugin.flags.length > 0) {
    lines.push('风险标记:')
    for (const flag of plugin.flags) {
      lines.push(`- [${flag.severity}] ${flag.label} (${flag.code}): ${flag.files.slice(0, 4).join(', ')}`)
    }
  } else {
    lines.push('风险标记: 无')
  }
  const suspicious = plugin.dependencies.filter(dep => dep.suspicious)
  if (suspicious.length > 0) {
    lines.push('可疑依赖:')
    for (const dep of suspicious) lines.push(`- ${dep.name} @ ${dep.version} — ${dep.reason || ''}`)
  } else {
    lines.push('可疑依赖: 无')
  }
  lines.push('')

  if (snippets.length > 0) {
    lines.push('【关键代码片段】（文件:行号 规则] 代码）:')
    for (const snippet of snippets) {
      lines.push(`- ${snippet.file}:${snippet.line} [${snippet.severity}/${snippet.code}] ${snippet.text}`)
    }
    lines.push('')
  }

  lines.push('请结合该插件的自称功能与声誉信息，判断上述危险能力是否属于合理实现，并给出审计结论（只输出 JSON）。')
  return lines.join('\n')
}

/**
 * Strip markdown fences (case-insensitive ```json / ```) and extract the first
 * balanced `{...}` object from raw model text. Models wrap JSON in fences,
 * prefix reasoning, or append prose; this pulls just the object out and parses
 * it, with the raw output trimmed into the error for diagnosis.
 */
function parseJsonObject(text: string): unknown {
  const trimmed = text.trim()
  const snippet = trimmed.slice(0, 300)
  let body = trimmed
  const fence = body.match(/```(?:json)?\s*([\s\S]*?)\s*```/i)
  if (fence !== null) body = fence[1].trim()
  const start = body.indexOf('{')
  if (start === -1) {
    throw new Error(`AI 审计：模型未返回 JSON 对象（原始输出前 300 字: ${snippet || '(空)'}）`)
  }
  try {
    const objectText = extractBalancedJson(body, start)
    return JSON.parse(objectText)
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error)
    throw new Error(`AI 审计：模型输出无法解析为 JSON（${reason}；原始输出前 300 字: ${snippet}）`)
  }
}

/** Return the balanced `{...}` substring starting at `start`, tracking string literals, escapes, and nesting. */
function extractBalancedJson(body: string, start: number): string {
  let depth = 0
  let inString = false
  let escaped = false
  for (let index = start; index < body.length; index += 1) {
    const char = body[index]
    if (inString) {
      if (escaped) escaped = false
      else if (char === '\\') escaped = true
      else if (char === '"') inString = false
      continue
    }
    if (char === '"') {
      inString = true
      continue
    }
    if (char === '{') {
      depth += 1
    } else if (char === '}') {
      depth -= 1
      if (depth === 0) return body.slice(start, index + 1)
    }
  }
  throw new Error('JSON 对象未闭合（可能被截断）')
}

/**
 * Re-prompt the model after a parse failure. Keeps the FULL audit context (the
 * de-contextualized "just re-output JSON" retry made reasoning models report
 * "missing inputs" because they had nothing to assess) and re-states the strict
 * JSON-only contract for the second pass.
 */
function buildStrictRetryPrompt(fullPrompt: string): string {
  return [
    '上一次没有拿到可解析的审计 JSON。这一次必须直接、只输出一个严格的 JSON 对象：不要输出任何推理、思考过程、解释或导语，不要 Markdown 代码块，也不要重复字段模板，直接给出最终结论 JSON。',
    '',
    '下面是审计信息（再次完整提供）：',
    fullPrompt,
  ].join('\n')
}

function deriveRisk(verdict: AiAssessment['verdict']): RiskLevel {
  switch (verdict) {
    case 'malicious': return 'red'
    case 'safe': return 'green'
    case 'suspicious': return 'yellow'
    case 'inconclusive': return 'yellow'
  }
}

/** Stream one model call and return the assembled text blocks, or throw on terminal failure. */
async function runLlmText(guardCtx: GuardContext, options: LlmCallOptions): Promise<string> {
  const assembler = new BlockAssembler()
  for await (const chunk of guardCtx.llm.stream(options)) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    assembler.push(chunk as any)
  }
  const finish = assembler.finish as { kind: string; failure?: { message?: string } }
  if (finish.kind === 'error' || finish.kind === 'aborted') {
    const detail = finish.failure?.message !== undefined ? `: ${finish.failure.message}` : ''
    throw new Error(`AI 审计调用失败 (${finish.kind})${detail}`)
  }
  if (finish.kind === 'tool-calls') {
    throw new Error('AI 审计：模型尝试调用工具，但审计要求仅输出 JSON')
  }
  // `max-tokens` is NOT fatal here: a reasoning model can finish its JSON and
  // then get truncated emitting trailing content. The parse step accepts a
  // complete object and only triggers the retry when the JSON was cut short.
  const text = assembler
    .blocks()
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    .filter((block: any) => block.type === 'text')
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    .map((block: any) => block.text)
    .join('')
  if (text.trim().length === 0) throw new Error('AI 审计：模型未产生文本输出')
  return text
}

async function fetchJson(url: string, timeoutMs: number, headers?: Record<string, string>): Promise<unknown> {
  const response = await fetch(url, {
    signal: AbortSignal.timeout(timeoutMs),
    headers: { accept: 'application/json', 'user-agent': 'dsh-plugin-guard/0.1.0 (security audit)', ...(headers ?? {}) },
  })
  if (!response.ok) throw new Error(`HTTP ${response.status}`)
  return response.json()
}

function reasonOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

function stripHtml(html: string): string {
  return html
    .replace(/<[^>]+>/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#x27;|&#39;/g, "'")
    .replace(/&nbsp;/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
}

/** Best-effort DuckDuckGo HTML scrape: extract up to ~5 result titles + snippets. Never throws. */
async function searchReputation(pluginName: string): Promise<string> {
  const query = `${JSON.stringify(pluginName)} plugin security OR malicious OR malware OR vulnerability`
  const url = `https://html.duckduckgo.com/html/?q=${encodeURIComponent(query)}`
  const response = await fetch(url, {
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    headers: {
      'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36',
      'accept-language': 'zh-CN,zh;q=0.9,en;q=0.8',
    },
  })
  if (!response.ok) return ''
  const html = await response.text()
  const titles: string[] = []
  for (const match of html.matchAll(/<a[^>]*class="result__a"[^>]*>([\s\S]*?)<\/a>/g)) {
    titles.push(stripHtml(match[1] ?? ''))
  }
  const snippets: string[] = []
  for (const match of html.matchAll(/<a[^>]*class="result__snippet"[^>]*>([\s\S]*?)<\/a>/g)) {
    snippets.push(stripHtml(match[1] ?? ''))
  }
  const lines: string[] = []
  const count = Math.max(titles.length, snippets.length)
  for (let index = 0; index < Math.min(count, 5); index += 1) {
    const title = (titles[index] ?? '').slice(0, 160)
    const snippet = (snippets[index] ?? '').slice(0, 200)
    if (title === '' && snippet === '') continue
    lines.push(`- ${title}${snippet !== '' ? ` — ${snippet}` : ''}`)
  }
  return lines.join('\n')
}

/** Best-effort parse of `owner/repo` from the many shapes a package.json repository url takes. */
function parseGithubRepo(repository: string): { owner: string; repo: string } | null {
  if (repository === '') return null
  const cleaned = repository
    .replace(/^git\+/, '')
    .replace(/^git:\/\//, '')
    .replace(/^github:/, '')
    .replace(/\.git$/, '')
    .replace(/\/$/, '')
    .replace(/^git@github\.com:/, '')
    .replace(/^ssh:\/\/git@github\.com\//, '')
    .replace(/^https?:\/\//, '')
  const rest = cleaned.replace(/^github\.com\//, '')
  const parts = rest.split('/')
  const owner = parts[0] ?? ''
  // Drop any trailing "#readme" / sub-path that can ride along on the repo segment.
  const repo = (parts[1] ?? '').split('#')[0] ?? ''
  if (owner === '' || repo === '') return null
  if (!/^[A-Za-z0-9_.-]+$/.test(owner) || !/^[A-Za-z0-9_.-]+$/.test(repo)) return null
  return { owner, repo }
}

/** Fetch repo + owner info from the GitHub REST API; never throws, degrades to note. */
async function lookupGithubRepo(repositoryUrl: string, githubToken: string): Promise<GithubEvidence> {
  const empty: GithubEvidence = {
    fullName: '',
    htmlUrl: '',
    description: '',
    stars: -1,
    forks: -1,
    archived: false,
    createdAt: '',
    pushedAt: '',
    ownerCreatedAt: '',
    ownerPublicRepos: -1,
    ownerFollowers: -1,
    note: '',
  }
  const parsed = parseGithubRepo(repositoryUrl)
  if (parsed === null) return { ...empty, note: '未从包元数据解析到 GitHub 仓库' }
  const { owner, repo } = parsed
  const github: GithubEvidence = {
    ...empty,
    fullName: `${owner}/${repo}`,
    htmlUrl: `https://github.com/${owner}/${repo}`,
  }
  const notes: string[] = []
  const authHeaders = githubToken !== '' ? { authorization: `Bearer ${githubToken}` } : undefined
  const [repoResult, ownerResult] = await Promise.allSettled([
    fetchJson(`https://api.github.com/repos/${owner}/${repo}`, FETCH_TIMEOUT_MS, authHeaders),
    fetchJson(`https://api.github.com/users/${owner}`, FETCH_TIMEOUT_MS, authHeaders),
  ])
  if (repoResult.status === 'fulfilled') {
    const info = repoResult.value as Record<string, unknown>
    if (typeof info.message === 'string') {
      notes.push(`GitHub 仓库查询失败: ${info.message}`)
    } else {
      github.fullName = typeof info.full_name === 'string' ? info.full_name : github.fullName
      github.htmlUrl = typeof info.html_url === 'string' ? info.html_url : github.htmlUrl
      github.description = typeof info.description === 'string' ? info.description : ''
      github.stars = typeof info.stargazers_count === 'number' ? info.stargazers_count : -1
      github.forks = typeof info.forks_count === 'number' ? info.forks_count : -1
      github.archived = info.archived === true
      github.createdAt = typeof info.created_at === 'string' ? info.created_at : ''
      github.pushedAt = typeof info.pushed_at === 'string' ? info.pushed_at : ''
    }
  } else {
    notes.push(`GitHub 仓库查询失败 (${reasonOf(repoResult.reason)})`)
  }
  if (ownerResult.status === 'fulfilled') {
    const user = ownerResult.value as Record<string, unknown>
    if (typeof user.message === 'string') {
      notes.push(`GitHub 用户查询失败: ${user.message}`)
    } else {
      github.ownerCreatedAt = typeof user.created_at === 'string' ? user.created_at : ''
      github.ownerPublicRepos = typeof user.public_repos === 'number' ? user.public_repos : -1
      github.ownerFollowers = typeof user.followers === 'number' ? user.followers : -1
    }
  } else {
    notes.push(`GitHub 用户查询失败 (${reasonOf(ownerResult.reason)})`)
  }
  github.note = notes.join('；')
  return github
}

/** npm registry + download stats + a web search, run in parallel with graceful degradation. */
async function lookupPluginReputation(pluginName: string): Promise<ReputationEvidence> {
  const emptyGithub: GithubEvidence = {
    fullName: '',
    htmlUrl: '',
    description: '',
    stars: -1,
    forks: -1,
    archived: false,
    createdAt: '',
    pushedAt: '',
    ownerCreatedAt: '',
    ownerPublicRepos: -1,
    ownerFollowers: -1,
    note: '',
  }
  const context: ReputationEvidence = {
    npmDescription: '',
    npmLatest: '',
    npmHomepage: '',
    npmRepository: '',
    npmMaintainers: [],
    npmCreated: '',
    npmModified: '',
    weeklyDownloads: -1,
    searchResults: '',
    github: emptyGithub,
    note: '',
  }
  const notes: string[] = []
  // Scoped names (@scope/pkg) map naturally onto URL path segments; npm
  // package names are restricted to URL-safe characters, so the raw name is safe.
  const registryUrl = `https://registry.npmjs.org/${pluginName}`
  const downloadsUrl = `https://api.npmjs.org/downloads/point/last-week/${pluginName}`

  const [npmResult, downloadsResult, searchResult] = await Promise.allSettled([
    fetchJson(registryUrl, FETCH_TIMEOUT_MS),
    fetchJson(downloadsUrl, FETCH_TIMEOUT_MS),
    searchReputation(pluginName),
  ])

  if (npmResult.status === 'fulfilled') {
    const info = npmResult.value as Record<string, unknown>
    if (info.error !== undefined) {
      notes.push('npm 未收录该包名')
    } else {
      context.npmDescription = typeof info.description === 'string' ? info.description : ''
      const distTags = info['dist-tags'] as Record<string, unknown> | undefined
      context.npmLatest = typeof distTags?.latest === 'string' ? String(distTags.latest) : ''
      context.npmHomepage = typeof info.homepage === 'string' ? info.homepage : ''
      const repository = info.repository
      if (typeof repository === 'string') context.npmRepository = repository
      else if (repository !== null && typeof repository === 'object') {
        const url = (repository as Record<string, unknown>).url
        context.npmRepository = typeof url === 'string' ? url : ''
      }
      const maintainers = info.maintainers
      if (Array.isArray(maintainers)) {
        context.npmMaintainers = maintainers
          .map(maintainer => (maintainer !== null && typeof maintainer === 'object' ? String((maintainer as Record<string, unknown>).name ?? '') : ''))
          .filter(item => item !== '')
          .slice(0, 10)
      }
      const time = info.time as Record<string, unknown> | undefined
      context.npmCreated = typeof time?.created === 'string' ? String(time.created) : ''
      context.npmModified = typeof time?.modified === 'string' ? String(time.modified) : ''
    }
  } else {
    notes.push(`npm 查询失败 (${reasonOf(npmResult.reason)})`)
  }

  if (downloadsResult.status === 'fulfilled') {
    const info = downloadsResult.value as Record<string, unknown>
    if (typeof info.downloads === 'number') context.weeklyDownloads = info.downloads
  }

  if (searchResult.status === 'fulfilled') context.searchResults = searchResult.value

  context.note = notes.join('；')
  return context
}

/**
 * Audit one plugin with the default model, layered with the plugin's stated
 * purpose and internet-reputation context so the model judges capability vs.
 * function — not raw API presence. Throws with a readable message on
 * resolution, call, or parse failure — the Remote surface turns it into an
 * `ok: false` result the panel renders.
 */
export async function auditPluginWithAi(
  ctx: Context,
  plugin: PluginAudit,
  profileDir: string,
  githubToken: string,
  onProgress?: (phase: AuditPhase, detail: string) => void,
): Promise<AiAuditResult> {
  const guardCtx = ctx as unknown as GuardContext
  const logger = (ctx as unknown as { logger?: { info?: (line: string) => void } }).logger
  const emit = (phase: AuditPhase, detail: string): void => {
    const line = `[dsh-plugin-guard] AI 审计 ${plugin.name}: ${detail}`
    if (logger?.info !== undefined) logger.info(line)
    else console.info(line)
    onProgress?.(phase, detail)
  }

  const selection = guardCtx.agentDefaultModel.currentSelection()
  if (selection === undefined || selection.provider === undefined || selection.model === undefined) {
    throw new Error('AI 审计：未配置默认模型，请先在模型设置中选择默认模型')
  }
  emit('calling', `预计调用默认模型 ${selection.provider}/${selection.model}`)

  const pluginDir = join(profileDir, 'node_modules', String(plugin.name))
  emit('collecting', '提取关键代码证据…')
  const snippets = collectEvidence(pluginDir, 15)
  emit('collecting', `已提取 ${snippets.length} 条关键代码片段`)

  emit('collecting', '读取插件自称的功能 (package.json / README)…')
  const metadata = collectPluginMetadata(pluginDir)
  if (metadata.description !== '') emit('collecting', `插件自述功能：${metadata.description.slice(0, 80)}`)

  emit('researching', '联网查询 npm 声誉与搜索结果…')
  const reputation = await lookupPluginReputation(plugin.name)

  emit('researching', '查询 GitHub 仓库与作者账号信息…')
  const repoUrl = metadata.repository !== '' ? metadata.repository : reputation.npmRepository
  const github = await lookupGithubRepo(repoUrl, githubToken)
  reputation.github = github
  const githubSummary = github.fullName !== ''
    ? `GitHub: ${github.fullName} ⭐${github.stars >= 0 ? String(github.stars) : '?'}`
    : 'GitHub: 未解析到仓库'

  const repute = reputation.npmDescription !== ''
    ? `npm: ${reputation.npmDescription.slice(0, 60)}`
    : `npm 未收录，搜索命中 ${reputation.searchResults === '' ? 0 : '若干'}条`
  emit('researching', `声誉查询完成（${repute}；${githubSummary}）`)

  const llmCall = (callMessages: unknown[]): Promise<string> => runLlmText(guardCtx, {
    provider: selection.provider,
    model: selection.model,
    messages: callMessages,
    system: SYSTEM_PROMPT,
    maxTokens: MAX_OUTPUT_TOKENS,
    signal: AbortSignal.timeout(AI_TIMEOUT_MS),
  })
  const userMessage = (text: string): unknown[] => [
    createUserMessage({
      content: [{ type: 'text', text }],
      source: { kind: 'plugin', plugin: 'dsh-plugin-guard' },
    }),
  ]
  const auditPrompt = buildUserPrompt(plugin, snippets, metadata, reputation)
  const callAndParse = async (promptText: string): Promise<ReturnType<typeof aiAssessmentSchema.parse>> => {
    const raw = await llmCall(userMessage(promptText))
    return aiAssessmentSchema.parse(parseJsonObject(raw))
  }

  emit('calling', `正在调用模型 ${selection.provider}/${selection.model}（最长约 5 分钟）`)
  let parsed: ReturnType<typeof aiAssessmentSchema.parse>
  try {
    parsed = await callAndParse(auditPrompt)
  } catch (firstError) {
    const reason = firstError instanceof Error ? firstError.message : String(firstError)
    emit('parsing', `首次解析失败（${reason.slice(0, 160)}），携带完整信息重试并要求仅输出 JSON…`)
    parsed = await callAndParse(buildStrictRetryPrompt(auditPrompt))
  }

  emit('parsing', '解析模型返回的审计 JSON…')
  const assessment: AiAssessment = {
    verdict: parsed.verdict,
    risk: parsed.risk ?? deriveRisk(parsed.verdict),
    summary: parsed.summary.trim(),
    concerns: parsed.concerns.filter(item => item.trim().length > 0),
    recommendations: parsed.recommendations.filter(item => item.trim().length > 0),
  }

  emit('done', `审计完成（判定 ${parsed.verdict}）`)
  return {
    ...assessment,
    pluginName: plugin.name,
    provider: selection.provider,
    model: selection.model,
    generatedAt: new Date().toISOString(),
    reputation,
  }
}