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
import { collectEvidence, collectPluginMetadata, findGithubUrls, readInstalledDependencies, type EvidenceSnippet, type PluginMetadata } from './scanner.ts'
import {
  aiAssessmentSchema,
  type AdvisoryFinding,
  type AiAssessment,
  type AiAuditResult,
  type AuditPhase,
  type DependencyFinding,
  type GithubEvidence,
  type PluginAudit,
  type ReputationEvidence,
  type RiskLevel,
  type WebSearchHit,
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
 * Resolve the harness default model identity (provider/model) used for the LLM
 * verdict — exported so the verdict cache can key on it too: switching the
 * default model invalidates an otherwise-matching fingerprint within TTL.
 */
export function resolveAuditModel(ctx: Context): ModelSelection {
  const guardCtx = ctx as unknown as GuardContext
  const selection = guardCtx.agentDefaultModel.currentSelection()
  if (selection === undefined || selection.provider === undefined || selection.model === undefined) {
    throw new Error('AI 审计：未配置默认模型，请先在模型设置中选择默认模型')
  }
  return selection
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
  '  "score": 0到100的整数（整体风险分，越高越危险，必须与 verdict/risk 一致）,',
  '  "summary": "一两句中文风险评估概述",',
  '  "concerns": ["具体担忧点", "..."],',
  '  "recommendations": ["建议的处置措施", "..."]',
  '}',
  '',
  '核心判断原则——必须结合插件自称的功能，不要孤立地看待危险能力：',
  '- 危险能力（子进程、文件读写、网络访问、环境变量、eval 等）本身不是恶意的证据；先判断这些能力是否与插件自称的功能一致。',
  '- 判断危险能力时区分『签名文本』与『真实调用点』：安全审计、扫描、杀毒类插件，其源码里必然出现它用来检测别人的签名（正则里的 `curl | sh`、`eval`、`new Function`、`child_process` 等字样，以及 RegExp 的 `.exec(` 方法调用）——这些只是检测规则 / 字符串，不是插件自己在执行动作。只有真实的 `eval(...)`、`new Function(...)`、`child_process.exec/spawn(...)`、shell 管道等真实调用点，才算插件具备该危险能力；不要因为扫描结果或代码片段里出现这些关键词字样就认定插件自己执行了它们。',
  '- 反向警惕：插件主动自称安全、审计、防护、杀毒工具，是更高审查等级的信号（攻击者常伪装成防护工具以降低戒心），绝不是免责理由——这类插件尤其要核对其签名检测之外是否真的存在执行、外联、凭据访问等真实行为。',
  '- 例如：自称"文件管理器 / 终端工具 / 代码执行器 / 爬虫"的插件读写文件、执行命令、发网络请求是它的合理本职，不应仅因此判为恶意。',
  '- 只有当能力明显超出自称功能，且指向数据外传、凭据窃取、后门、挖矿、勒索、隐蔽联网回传等恶意目的时，才判 "malicious"。',
  '- 若能力与功能基本一致、仅实现上值得警惕（如命令拼接、硬编码外联地址），给出 "suspicious" 及具体复核建议。',
  '- 互联网声誉只作为佐证：知名维护者 / 大量下载 / 正常仓库 / 中立搜索结果可降低疑点；无名新包、混淆代码、可疑安装脚本则提高疑点。尤其「互联网恶意/攻击报告检索」若命中"该插件被举报为恶意 / malware / trojan / backdoor / 供应链攻击 / 后门 / 挖矿"等明确指控，应显著提高判为 "malicious" 或 "suspicious" 的权重；但这些指控也可能是误报、竞品抹黑或营销内容，需结合命中来源的可信度（安全厂商 / 官方公告 / 可信开发者 / 社区讨论）综合判断，不要把单一负面命中直接等同于恶意。声誉信息缺失时不臆造。',
  '- 「已知漏洞/恶意库记录（OSV.dev）」是权威信号：若出现 [恶意] 标记（MAL- 前缀或 "Malicious code/package" 摘要），说明该包已被官方恶意包数据库收录，应强烈倾向判为 "malicious"；若只是普通漏洞（ReDoS、注入等非恶意条目），则作为 "suspicious" 的佐证，并在 recommendations 中给出升级/加固建议；无收录不代表安全。',
  '- GitHub 仓库信号（若提供）：作者账号刚注册、公开仓库极少、仓库极新却 star 异常偏高、或 npm 包与仓库内容明显不符，都是仿冒/钓鱼/刷星的信号，应提高疑点；反之老账号、多仓库、star 与活跃度匹配则降低疑点。注意"短时间内 star 不合理暴涨"与"无其他仓库的新号作者"组合尤其可疑。若 GitHub 查询备注标明该仓库是“按包名从 npm 推断”（插件自身未声明地址），则它很可能只是同名仓库、与该插件无关，其 star/作者/创建时间等不可作为该插件的可信证据，应忽略或仅作弱参考。',
  '- 「声明的宿主服务权限」反映插件请求宿主注入的服务面：声明的服务越强（模型 / 网络 / 文件 / 进程 / 密钥 / 浏览器），插件默认可接触的宿主资源越多。当代码静态扫描出现高危能力、但声明的宿主服务全部为轻量级（UI / 国际化 / 配置类）时，属于"能力与声明面不匹配"，应显著提高判为 suspicious 或 malicious 的怀疑；未声明宿主服务时不做该推断。',
  '- 「包龄 / 弃用」信号：首次发布距今很短（如 < 30 天）的新包，恶意比例显著偏高（攻击者常"发布→得手→数日内被下架"）；若 npm 标记该包 deprecated（维护者亲自声明弃用 / 有安全问题 / 已迁移），是来自源头的权威"不可信"信号。两者都应提高疑点，但年龄本身不是铁证（合法新包也存在）、deprecated 也可能只是改名迁移——作为风险乘数与上下文，不要仅凭此判恶意。',
  '',
  '判定标准：',
  '- "safe": 危险能力属于该插件的合理功能，未发现超出功能的恶意意图。',
  '- "suspicious": 能力超出功能、实现可疑或有负面声誉线索，需要人工复核。',
  '- "malicious": 有明显恶意意图（窃取数据、后门、挖矿、勒索、凭据外传等）。',
  '- "inconclusive": 静态证据与声誉信息都不足以得出结论。',
  '- risk 与 verdict 对应：malicious→red；suspicious→yellow（若含高危能力且意图存疑→red）；inconclusive→yellow；safe→green。',
  '- score 是 0–100 的整体风险分（数字）：safe 通常 < 30、suspicious 约 40–70、malicious ≥ 70；要综合静态高危旗、声明的宿主权限、声誉负面信号与功能一致性打分，且必须与 verdict / risk 一致。',
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
  if (reputation.npmCreated !== '') {
    const ageDays = Math.floor((Date.now() - new Date(reputation.npmCreated).getTime()) / 86_400_000)
    if (Number.isFinite(ageDays) && ageDays >= 0) {
      lines.push(`- 包龄: ${ageDays} 天${ageDays < 30 ? '（⚠ 新包，恶意比例偏高）' : ''}`)
    }
  }
  if (reputation.npmDeprecated !== '') lines.push(`- ⚠ 已被维护者标记弃用 (deprecated): ${reputation.npmDeprecated.slice(0, 120)}`)
  if (reputation.note !== '') lines.push(`- 声誉查询备注: ${reputation.note}`)
  lines.push('')

  lines.push('【已知漏洞/恶意库记录（OSV.dev，权威）】（该包被公开收录的漏洞 / 恶意报告）')
  if (reputation.advisories.length > 0) {
    const maliciousCount = reputation.advisories.filter(item => item.malicious).length
    lines.push(`- 共 ${reputation.advisories.length} 条，其中明确"恶意代码/恶意包" ${maliciousCount} 条：`)
    for (const advisory of reputation.advisories) {
      const tag = advisory.malicious ? '[恶意]' : '[漏洞]'
      const aliases = advisory.aliases.length > 0 ? `（${advisory.aliases.join(', ')}）` : ''
      lines.push(`- ${tag} ${advisory.id}${aliases}: ${advisory.summary}`)
    }
  } else {
    lines.push('- (OSV.dev 无收录，或查询不可达)')
  }
  lines.push('')

  lines.push('【互联网恶意/攻击报告检索】（针对"该插件是否为恶意插件"的搜索命中）')
  if (reputation.webSearchHits.length > 0) {
    lines.push(`- 命中 ${reputation.webSearchHits.length} 条：`)
    for (const hit of reputation.webSearchHits.slice(0, 8)) {
      const head = hit.title !== '' ? hit.title : hit.url
      const urlPart = hit.url !== '' && hit.title !== '' ? ` <${hit.url}>` : ''
      lines.push(`- ${head}${urlPart}`)
      if (hit.snippet !== '') lines.push(`    ${hit.snippet}`)
    }
  } else {
    lines.push('- (未检索到与该插件直接相关的互联网恶意/攻击报告)')
  }
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

  lines.push('【声明的宿主服务权限】(inject：插件请求宿主注入哪些服务)')
  if (plugin.permissions.length > 0) {
    for (const permission of plugin.permissions) {
      lines.push(`- [${permission.severity}] ${permission.name}: ${permission.label}`)
    }
    lines.push(`声明权限风险分: ${plugin.permScore}`)
  } else {
    lines.push('- (未声明宿主服务依赖，无法据此判断)')
  }
  if (plugin.capabilityMismatch) {
    lines.push('⚠ 高危能力与声明面不匹配：代码含高危能力，但声明的宿主服务均为轻量级，越权嫌疑较高。')
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
 * Remove complete reasoning/thinking blocks that reasoning models emit BEFORE
 * the answer (` thinking…`, `<thinking>`, `<reasoning>`, `<scratchpad>`). Their
 * prose often contains a draft `{…}` (with trailing commas or half-written
 * fields) that would otherwise be mistaken for the result, so strip them before
 * locating the real JSON object.
 */
function stripReasoningBlocks(text: string): string {
  return text
    .replace(/ thinking[\s\S]*?<\/think>/gi, ' ')
    .replace(/<thinking>[\s\S]*?<\/thinking>/gi, ' ')
    .replace(/<reasoning>[\s\S]*?<\/reasoning>/gi, ' ')
    .replace(/<scratchpad>[\s\S]*?<\/scratchpad>/gi, ' ')
}

/**
 * Strip reasoning blocks + markdown fences (case-insensitive ```json / ```) and
 * extract the first balanced `{...}` object from raw model text. Models wrap
 * JSON in fences, prefix reasoning, or append prose; this pulls just the object
 * out and parses it, with the raw output trimmed into the error for diagnosis.
 */
function parseJsonObject(text: string): unknown {
  const trimmed = text.trim()
  const snippet = trimmed.slice(0, 300)
  let body = stripReasoningBlocks(trimmed)
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

/** Fallback 0–100 score when the model omits the field (also used for older cached results). */
export function scoreFromVerdict(verdict: AiAssessment['verdict']): number {
  switch (verdict) {
    case 'malicious': return 90
    case 'suspicious': return 65
    case 'inconclusive': return 50
    case 'safe': return 10
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

const BROWSER_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36'

/** Decode HTML entities common to search-result snippets (named + numeric), so the model reads clean text. */
function decodeEntities(text: string): string {
  return text
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;|&#34;/g, '"')
    .replace(/&#x27;|&#39;/g, "'")
    .replace(/&nbsp;|&ensp;|&emsp;|&thinsp;/g, ' ')
    .replace(/&#(\d+);/g, (_match, code: string) => {
      const value = Number(code)
      return value >= 32 && value < 0xd800 ? String.fromCodePoint(value) : ' '
    })
    .replace(/&#x([0-9a-fA-F]+);/g, (_match, code: string) => {
      const value = parseInt(code, 16)
      return value >= 32 && value < 0xd800 ? String.fromCodePoint(value) : ' '
    })
}

function stripHtml(html: string): string {
  return decodeEntities(html.replace(/<[^>]+>/g, ' ')).replace(/\s+/g, ' ').trim()
}

/** One parsed search-engine result before dedupe/cap. */
interface RawHit {
  title: string
  url: string
  snippet: string
}

/** Keep a URL only when it is http(s); otherwise return '' (rendered as plain text downstream). */
function sanitizeUrl(raw: string): string {
  const url = raw.trim().replace(/&amp;/g, '&')
  return /^https?:\/\//i.test(url) ? url : ''
}

/** Extract title/url/snippet from one Bing `b_algo` result block. */
function parseBingBlock(block: string): RawHit {
  const anchor = block.match(/<h2[^>]*>\s*<a[^>]*href="([^"]*)"[^>]*>([\s\S]*?)<\/a>/)
  const title = stripHtml(anchor?.[2] ?? '')
  const url = sanitizeUrl(anchor?.[1] ?? '')
  const paragraph = block.match(/<p[^>]*>([\s\S]*?)<\/p>/)
  const snippet = stripHtml(paragraph?.[1] ?? '')
  return { title, url, snippet }
}

/** One Bing query; empty on any failure (best-effort). */
async function searchBing(query: string): Promise<RawHit[]> {
  const url = `https://www.bing.com/search?q=${encodeURIComponent(query)}&count=10&setlang=zh-hans`
  const response = await fetch(url, {
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    headers: { 'user-agent': BROWSER_UA, 'accept-language': 'zh-CN,zh;q=0.9,en;q=0.8' },
  })
  if (!response.ok) return []
  const html = await response.text()
  return html
    .split('<li class="b_algo"')
    .slice(1)
    .map(parseBingBlock)
    .filter(hit => hit.title !== '' || hit.url !== '' || hit.snippet !== '')
    .slice(0, 8)
}

/** Decode DuckDuckGo's `uddg=` redirect back to the destination URL. */
function decodeDdgUrl(href: string): string {
  const match = href.match(/uddg=([^&]+)/)
  if (match === null) return ''
  try {
    return sanitizeUrl(decodeURIComponent(match[1] ?? ''))
  } catch {
    return ''
  }
}

/** DuckDuckGo HTML fallback for hosts where Bing is unreachable; empty on failure. */
async function searchDuckDuckGo(query: string): Promise<RawHit[]> {
  const url = `https://html.duckduckgo.com/html/?q=${encodeURIComponent(query)}`
  const response = await fetch(url, {
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    headers: { 'user-agent': BROWSER_UA, 'accept-language': 'zh-CN,zh;q=0.9,en;q=0.8' },
  })
  if (!response.ok) return []
  const html = await response.text()
  const anchors = [...html.matchAll(/<a[^>]*class="result__a"[^>]*href="([^"]*)"[^>]*>([\s\S]*?)<\/a>/g)]
  const snippets = [...html.matchAll(/<a[^>]*class="result__snippet"[^>]*>([\s\S]*?)<\/a>/g)]
  const hits: RawHit[] = []
  const count = Math.max(anchors.length, snippets.length)
  for (let index = 0; index < Math.min(count, 8); index += 1) {
    const title = stripHtml(anchors[index]?.[2] ?? '')
    const url = decodeDdgUrl(anchors[index]?.[1] ?? '')
    const snippet = stripHtml(snippets[index]?.[1] ?? '')
    if (title === '' && url === '' && snippet === '') continue
    hits.push({ title, url, snippet })
  }
  return hits
}

/**
 * Terms that mark a scraped hit as genuinely discussing malicious / attack /
 * vulnerability activity. A hit must contain the plugin name AND one of these
 * to be surfaced, so unrelated Bing/DDG noise (throttle pages, generic "npm"
 * results, homonym matches) is never shown as a report about the plugin.
 */
const MALICIOUS_REPORT_KEYWORDS = [
  'malicious', 'malware', 'backdoor', 'compromised', 'compromise', 'typosquat', 'typosquatting',
  'credential', 'stealer', 'infostealer', 'steal', 'stolen', 'supply chain', 'supply-chain',
  'vulnerability', 'vulnerabilities', 'exploit', 'attack', 'attacker', 'breach', 'breached',
  'trojan', 'ransomware', 'hijack', 'hijacked', 'phishing', 'botnet', 'cryptominer', 'miner',
  'malvertising', 'security incident', 'cve-', 'mal-', 'poisoned', 'poisoning',
  '恶意', '后门', '供应链', '攻击', '木马', '病毒', '窃取', '盗取', '泄露', '泄漏', '劫持',
  '钓鱼', '漏洞', '入侵', '投毒', '篡改', '挖矿', '僵尸网络', '安全事件', '中毒', '感染',
]

/** Lowercased name variants a hit must mention (handles scoped `@org/pkg`). */
function nameNeedles(pluginName: string): string[] {
  const trimmed = pluginName.trim().toLowerCase()
  if (trimmed === '') return []
  const needles = [trimmed]
  const unscoped = trimmed.replace(/^@[^/]+\//, '')
  if (unscoped !== '' && unscoped !== trimmed) needles.push(unscoped)
  return needles
}

/**
 * A scraped hit only counts as evidence when it is genuinely about THIS plugin
 * AND discusses malicious/attack/vulnerability activity. Keyless Bing/DDG
 * scraping frequently returns unrelated noise, so require both a name match and
 * a security term before the hit is surfaced to the model or the panel.
 */
function isRelevantHit(hit: RawHit, needles: string[]): boolean {
  if (needles.length === 0) return false
  const hay = `${hit.title}\n${hit.snippet}\n${hit.url}`.toLowerCase()
  if (!needles.some(needle => hay.includes(needle))) return false
  return MALICIOUS_REPORT_KEYWORDS.some(keyword => hay.includes(keyword))
}

/**
 * Search the web for reports that a plugin is malicious/compromised. Runs
 * several targeted queries (English + Chinese) through Bing, falling back to
 * DuckDuckGo per query, aggregates the hits, dedupes by URL, and flattens them
 * into a compact text summary for the model. Never throws — a blocked engine
 * only degrades to fewer (or no) hits.
 */
async function searchMaliciousReports(pluginName: string): Promise<WebSearchHit[]> {
  const queries = [
    `${JSON.stringify(pluginName)} npm malicious OR malware OR backdoor OR compromised`,
    `${JSON.stringify(pluginName)} npm 恶意 OR 后门 OR 供应链攻击`,
  ]
  const needles = nameNeedles(pluginName)
  const collected = new Map<string, WebSearchHit>()
  const push = (hit: RawHit): void => {
    if (hit.title === '' && hit.url === '' && hit.snippet === '') return
    if (!isRelevantHit(hit, needles)) return
    if (collected.size >= 10) return
    const key = hit.url !== '' ? hit.url : `${hit.title}|${collected.size}`
    if (collected.has(key)) return
    collected.set(key, {
      title: hit.title.slice(0, 200),
      url: hit.url,
      snippet: hit.snippet.slice(0, 260),
    })
  }

  for (const query of queries) {
    if (collected.size >= 10) break
    let hits: RawHit[] = []
    try {
      hits = await searchBing(query)
      if (hits.length === 0) hits = await searchDuckDuckGo(query)
    } catch {
      /* best-effort: a failing engine contributes nothing */
    }
    for (const hit of hits) push(hit)
    // Stagger engineered requests so an aggressive engine is less likely to throttle.
    if (collected.size < 10) await new Promise(resolve => setTimeout(resolve, 350))
  }

  // No hit genuinely tied to this plugin + a malicious/attack term: report
  // "none" rather than surfacing unrelated search noise to the model/panel.
  return [...collected.values()]
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

/**
 * Resolve which GitHub repo to investigate, preferring an address the plugin
 * states about ITSELF over a name-based lookup. Order: package.json
 * `repository` -> `homepage` -> README/docs (preferring a repo whose name
 * matches the plugin) -> npm registry by package name. The last is a name-based
 * guess that can land on an unrelated same-named repo, so it is flagged.
 */
function resolvePluginRepo(
  metadata: PluginMetadata,
  npmRepository: string,
  pluginName: string,
): { url: string; fromOwnContent: boolean } {
  const unscoped = pluginName.replace(/^@[^/]+\//, '').toLowerCase()
  // 1. package.json repository — the plugin's own explicit declaration.
  const declared = parseGithubRepo(metadata.repository)
  if (declared !== null) return { url: `https://github.com/${declared.owner}/${declared.repo}`, fromOwnContent: true }
  // 2. package.json homepage, when it is a github repo URL.
  const home = findGithubUrls(metadata.homepage)
  if (home.length > 0) return { url: home[0] ?? '', fromOwnContent: true }
  // 3. README / docs — prefer a repo whose name matches the plugin over any link.
  const readme = metadata.readmeGithubUrls
  if (readme.length > 0) {
    const matching = readme.find(url => url.toLowerCase().endsWith(`/${unscoped}`))
    return { url: matching ?? readme[0] ?? '', fromOwnContent: true }
  }
  // 4. Last resort: npm registry repository for the same package NAME — can be
  //    an unrelated project that merely shares the name, so flag it downstream.
  const byName = parseGithubRepo(npmRepository)
  if (byName !== null) return { url: `https://github.com/${byName.owner}/${byName.repo}`, fromOwnContent: false }
  return { url: '', fromOwnContent: false }
}

/** Zero-valued GithubEvidence: every lookup starts from this and fills what it can. */
const EMPTY_GITHUB: GithubEvidence = {
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
  openIssues: -1,
  license: '',
  hasSecurityPolicy: false,
  note: '',
}

/** Cheap HEAD-style GET probe for `SECURITY.md` at the repo head; false on 404 / network error. */
async function checkSecurityPolicy(owner: string, repo: string): Promise<boolean> {
  try {
    const response = await fetch(`https://raw.githubusercontent.com/${owner}/${repo}/HEAD/SECURITY.md`, {
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    })
    return response.ok
  } catch {
    return false
  }
}

/** Fetch repo + owner info from the GitHub REST API; never throws, degrades to note. */
async function lookupGithubRepo(repositoryUrl: string, githubToken: string, fromOwnContent: boolean): Promise<GithubEvidence> {
  const parsed = parseGithubRepo(repositoryUrl)
  if (parsed === null) return { ...EMPTY_GITHUB, note: '未解析到 GitHub 仓库地址' }
  const { owner, repo } = parsed
  const github: GithubEvidence = {
    ...EMPTY_GITHUB,
    fullName: `${owner}/${repo}`,
    htmlUrl: `https://github.com/${owner}/${repo}`,
  }
  const notes: string[] = []
  if (!fromOwnContent) {
    notes.push('⚠ 插件自身未声明 GitHub 地址，此仓库是按包名从 npm 推断的，可能为同名仓库，请人工核对')
  }
  const authHeaders = githubToken !== '' ? { authorization: `Bearer ${githubToken}` } : undefined
  const [repoResult, ownerResult, securityResult] = await Promise.allSettled([
    fetchJson(`https://api.github.com/repos/${owner}/${repo}`, FETCH_TIMEOUT_MS, authHeaders),
    fetchJson(`https://api.github.com/users/${owner}`, FETCH_TIMEOUT_MS, authHeaders),
    checkSecurityPolicy(owner, repo),
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
      github.openIssues = typeof info.open_issues_count === 'number' ? info.open_issues_count : -1
      const license = info.license as { spdx_id?: unknown; name?: unknown } | null | undefined
      if (license !== null && license !== undefined) {
        github.license = typeof license.spdx_id === 'string' ? license.spdx_id : typeof license.name === 'string' ? license.name : ''
      }
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
  if (securityResult.status === 'fulfilled' && securityResult.value === true) github.hasSecurityPolicy = true
  github.note = notes.join('；')
  return github
}

/**
 * Query OSV.dev for known advisory / malicious-package records of an npm
 * package. This is the authoritative, keyless "has it been reported as
 * malicious?" signal. Never throws — degrades to an empty list.
 */
/** Map an OSV `vulns` array to findings; shared by the single and batch endpoints. */
function mapOsvVulns(vulns: Array<Record<string, unknown>>): AdvisoryFinding[] {
  return vulns.slice(0, 6).map((entry): AdvisoryFinding => {
    const id = typeof entry.id === 'string' ? entry.id : ''
    const summary = typeof entry.summary === 'string' ? entry.summary : ''
    const aliases = (Array.isArray(entry.aliases) ? entry.aliases : []).map(value => String(value)).filter(value => value !== '')
    const malicious = id.startsWith('MAL-') || /malicious/i.test(summary)
    return { id, summary, malicious, aliases, source: 'OSV.dev' }
  }).filter(entry => entry.id !== '' || entry.summary !== '')
}

async function lookupOsvAdvisories(pluginName: string): Promise<AdvisoryFinding[]> {
  try {
    const response = await fetch('https://api.osv.dev/v1/query', {
      method: 'POST',
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      headers: {
        'content-type': 'application/json',
        accept: 'application/json',
        'user-agent': 'dsh-plugin-guard/0.1.0 (security audit)',
      },
      body: JSON.stringify({ package: { name: pluginName, ecosystem: 'npm' } }),
    })
    if (!response.ok) return []
    const data = await response.json() as { vulns?: unknown }
    const vulns = Array.isArray(data.vulns) ? data.vulns : []
    return mapOsvVulns(vulns as Array<Record<string, unknown>>)
  } catch {
    return []
  }
}

/** Batch-query OSV.dev for many resolved dependencies in a single request. */
async function lookupOsvAdvisoriesBatch(deps: Array<{ name: string; version: string }>): Promise<DependencyFinding[]> {
  if (deps.length === 0) return []
  try {
    const response = await fetch('https://api.osv.dev/v1/querybatch', {
      method: 'POST',
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      headers: {
        'content-type': 'application/json',
        accept: 'application/json',
        'user-agent': 'dsh-plugin-guard/0.1.0 (security audit)',
      },
      body: JSON.stringify({ queries: deps.map(dep => ({ package: { name: dep.name, ecosystem: 'npm' }, version: dep.version })) }),
    })
    if (!response.ok) return []
    const data = await response.json() as { results?: unknown }
    const results = Array.isArray(data.results) ? data.results : []
    return deps.map((dep, index): DependencyFinding => {
      const entry = results[index] as { vulns?: unknown } | undefined
      const vulns = entry !== undefined && Array.isArray(entry.vulns) ? entry.vulns as Array<Record<string, unknown>> : []
      return { name: dep.name, version: dep.version, advisories: mapOsvVulns(vulns) }
    })
  } catch {
    return deps.map(dep => ({ name: dep.name, version: dep.version, advisories: [] }))
  }
}

/** Enumerate a plugin's resolved direct dependencies and batch-check them against OSV.dev. */
async function lookupDependencyAdvisories(pluginDir: string): Promise<DependencyFinding[]> {
  return lookupOsvAdvisoriesBatch(readInstalledDependencies(pluginDir))
}

/** npm registry + download stats + OSV advisories + a web search, run in parallel with graceful degradation. */
async function lookupPluginReputation(pluginName: string): Promise<ReputationEvidence> {
  const context: ReputationEvidence = {
    npmDescription: '',
    npmLatest: '',
    npmHomepage: '',
    npmRepository: '',
    npmMaintainers: [],
    npmCreated: '',
    npmModified: '',
    npmDeprecated: '',
    weeklyDownloads: -1,
    webSearchHits: [],
    advisories: [],
    github: EMPTY_GITHUB,
    dependencyAdvisories: [],
    note: '',
  }
  const notes: string[] = []
  // Scoped names (@scope/pkg) map naturally onto URL path segments; npm
  // package names are restricted to URL-safe characters, so the raw name is safe.
  const registryUrl = `https://registry.npmjs.org/${pluginName}`
  const downloadsUrl = `https://api.npmjs.org/downloads/point/last-week/${pluginName}`

  const [npmResult, downloadsResult, searchResult, advisoryResult] = await Promise.allSettled([
    fetchJson(registryUrl, FETCH_TIMEOUT_MS),
    fetchJson(downloadsUrl, FETCH_TIMEOUT_MS),
    searchMaliciousReports(pluginName),
    lookupOsvAdvisories(pluginName),
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
      const versions = info.versions as Record<string, Record<string, unknown>> | undefined
      const latestVersion = context.npmLatest !== '' ? versions?.[context.npmLatest] : undefined
      context.npmDeprecated = typeof latestVersion?.deprecated === 'string' ? String(latestVersion.deprecated) : ''
    }
  } else {
    notes.push(`npm 查询失败 (${reasonOf(npmResult.reason)})`)
  }

  if (downloadsResult.status === 'fulfilled') {
    const info = downloadsResult.value as Record<string, unknown>
    if (typeof info.downloads === 'number') context.weeklyDownloads = info.downloads
  }

  if (searchResult.status === 'fulfilled') {
    context.webSearchHits = searchResult.value
  }

  if (advisoryResult.status === 'fulfilled') context.advisories = advisoryResult.value

  context.note = notes.join('；')
  return context
}

/** Keys of the "negative" reputation signals a cached verdict must be re-checked against. */
function negativeFootprint(reputation: ReputationEvidence): string[] {
  const keys: string[] = []
  for (const advisory of reputation.advisories) keys.push('adv:' + advisory.id)
  for (const dep of reputation.dependencyAdvisories ?? []) {
    for (const advisory of dep.advisories) keys.push(`dep-adv:${dep.name}:${advisory.id}`)
  }
  for (const hit of reputation.webSearchHits) keys.push('web:' + hit.url)
  if (reputation.npmDeprecated !== '') keys.push('deprecated:' + reputation.npmDeprecated)
  return keys
}

/**
 * True when the fresh reputation carries a negative signal the cached verdict
 * never saw: a new OSV advisory, a new relevance-filtered malicious/attack web
 * report, or a newly-applied npm deprecation. Any of these invalidates the
 * cached verdict because its "safe" judgment was made without that evidence.
 */
export function hasNewNegativeSignal(cached: ReputationEvidence, fresh: ReputationEvidence): boolean {
  const known = new Set(negativeFootprint(cached))
  return negativeFootprint(fresh).some(key => !known.has(key))
}

/**
 * Fetch the live reputation layer (npm registry + OSV + web search + GitHub)
 * for one plugin. Cheap and deterministic enough to refresh on every audit,
 * even when the model verdict itself is served from the cache.
 */
export async function fetchPluginReputation(
  plugin: PluginAudit,
  metadata: PluginMetadata,
  pluginDir: string,
  githubToken: string,
  emit: (phase: AuditPhase, detail: string) => void,
): Promise<ReputationEvidence> {
  emit('researching', '联网查询 npm 声誉与搜索结果…')
  const [reputation, dependencyAdvisories] = await Promise.all([
    lookupPluginReputation(plugin.name),
    lookupDependencyAdvisories(pluginDir),
  ])
  emit('researching', '查询 GitHub 仓库与作者账号信息…')
  const resolvedRepo = resolvePluginRepo(metadata, reputation.npmRepository, plugin.name)
  reputation.github = await lookupGithubRepo(resolvedRepo.url, githubToken, resolvedRepo.fromOwnContent)
  reputation.dependencyAdvisories = dependencyAdvisories
  return reputation
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
  prefetchedReputation?: ReputationEvidence,
): Promise<AiAuditResult> {
  const guardCtx = ctx as unknown as GuardContext
  const logger = (ctx as unknown as { logger?: { info?: (line: string) => void } }).logger
  const emit = (phase: AuditPhase, detail: string): void => {
    const line = `[dsh-plugin-guard] AI 审计 ${plugin.name}: ${detail}`
    if (logger?.info !== undefined) logger.info(line)
    else console.info(line)
    onProgress?.(phase, detail)
  }

  const selection = resolveAuditModel(ctx)
  emit('calling', `预计调用默认模型 ${selection.provider}/${selection.model}`)

  const pluginDir = join(profileDir, 'node_modules', String(plugin.name))
  emit('collecting', '提取关键代码证据…')
  const snippets = collectEvidence(pluginDir, 15)
  emit('collecting', `已提取 ${snippets.length} 条关键代码片段`)

  emit('collecting', '读取插件自称的功能 (package.json / README)…')
  const metadata = collectPluginMetadata(pluginDir)
  if (metadata.description !== '') emit('collecting', `插件自述功能：${metadata.description.slice(0, 80)}`)

  const reputation = prefetchedReputation ?? await fetchPluginReputation(plugin, metadata, pluginDir, githubToken, emit)
  const github = reputation.github
  const githubSummary = github.fullName !== ''
    ? `GitHub: ${github.fullName} ⭐${github.stars >= 0 ? String(github.stars) : '?'}`
    : 'GitHub: 未解析到仓库'

  const repute = reputation.npmDescription !== ''
    ? `npm: ${reputation.npmDescription.slice(0, 60)}`
    : `npm 未收录，搜索命中 ${reputation.webSearchHits.length === 0 ? 0 : '若干'}条`
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
    score: parsed.score === undefined ? scoreFromVerdict(parsed.verdict) : Math.round(Math.min(100, Math.max(0, parsed.score))),
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
    cached: false,
    reputation,
  }
}