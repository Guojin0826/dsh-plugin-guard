/**
 * dsh-plugin-guard static scanner: audits third-party plugins installed in a
 * profile's node_modules without executing any of their code. Pure Node-side
 * logic with no cordis imports, so it stays testable and never leaks into the
 * browser bundle (the client imports only contracts.ts, which has no Node
 * imports).
 *
 * Scope honesty: this is a *detective* post-hoc control. It reads source and
 * manifests to surface red flags; it can never re-sandbox code that the loader
 * has already executed at `import()` time.
 */
import { createHash } from 'node:crypto'
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import type { DepFinding, PermissionFinding, PluginAudit, PluginDelta, RiskLevel, ScanFlag, SecurityReport, Severity } from './contracts.ts'

/** File extensions treated as source for scanning. */
const SCAN_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.jsx', '.tsx'])
/** Directories never descended into. */
const SKIP_DIRS = new Set(['node_modules', '.git', '.pnpm'])
/** Per-file read cap; larger files are skipped to bound scan time. */
const MAX_FILE_BYTES = 1024 * 1024

interface DangerRule {
  code: string
  severity: Severity
  label: string
  /** Global regex; matched against one file's text at a time. */
  re: RegExp
}

/**
 * Download-and-execute chain: a network fetch piped straight to a shell or iex
 * (the classic "curl | bash" supply-chain kicker). Deliberately single-line and
 * length-bounded so `curl … && ./configure && make` build steps stay out.
 */
const DOWNLOAD_EXEC_RE = /\b(?:curl|wget|iwr|Invoke-WebRequest)\b[^\r\n]{0,120}\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash|iex|\/bin\/sh|\/bin\/bash)\b/gi
/** Known secret/token formats plus a quoted long-value assignment for generic API keys. */
const HARDCODED_SECRET_RE = /-----BEGIN [A-Z ]*PRIVATE KEY-----|\bAKIA[0-9A-Z]{16}\b|\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b|\bxox[baprs]-[A-Za-z0-9-]{12,}\b|\bsk_live_[A-Za-z0-9]{20,}\b|\bsk_test_[A-Za-z0-9]{20,}\b|\bsk-[A-Za-z0-9]{20,}\b|(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|client[_-]?secret)\s*[:=]\s*['"`][A-Za-z0-9+/_\-]{24,}['"`]/gi

/** Static danger rules, weighted by severity. */
const DANGER_RULES: DangerRule[] = [
  { code: 'child-process', severity: 'high', label: '子进程执行 (child_process)', re: /\b(?:execSync|execFileSync|spawnSync|fork|exec|spawn|execFile)\s*\(|\brequire\s*\(\s*['"]child_process['"]\s*\)|from\s+['"]child_process['"]|import\s*\(\s*['"]child_process['"]\s*\)/g },
  { code: 'eval', severity: 'high', label: '动态代码执行 (eval / new Function)', re: /\beval\s*\(|\bnew\s+Function\s*\(/g },
  { code: 'vm-module', severity: 'high', label: 'VM 模块 (沙箱逃逸面)', re: /\brequire\s*\(\s*['"]vm['"]\s*\)|from\s+['"]vm['"]|import\s*\(\s*['"]vm['"]\s*\)/g },
  { code: 'shell', severity: 'high', label: 'Shell 命令执行面', re: /shell\s*:\s*true|['"`]\s*(?:rm\s+-rf|curl\s|wget\s|nc\s|sh\s+-c|bash\s+-c|cmd\s*\/[ck]|powershell\s|nslookup\s|whoami\b|ipconfig\b|netstat\b|chmod\s+)/g },
  { code: 'fs-write', severity: 'medium', label: '文件写入 / 删除', re: /\b(?:writeFileSync|writeFile|appendFile|appendFileSync|unlinkSync|unlink|rmSync|renameSync|rename|truncateSync|createWriteStream|chmodSync|mkdirSync|mkdtempSync|rmdirSync)\s*\(/g },
  { code: 'fs-read', severity: 'medium', label: '文件读取', re: /\b(?:readFileSync|readFile|readdirSync|readdir|createReadStream|cpSync|copyFileSync)\s*\(/g },
  { code: 'network', severity: 'medium', label: '网络 / 套接字访问', re: /\brequire\s*\(\s*['"](?:net|dgram|dns|tls|ws|undici|node-fetch|got|axios)['"]\s*\)|from\s+['"](?:net|dgram|dns|tls|ws|undici|node-fetch|got|axios)['"]/g },
  { code: 'http', severity: 'low', label: 'HTTP 请求', re: /\b(?:fetch|XMLHttpRequest|axios|got|request)\s*\(/g },
  { code: 'env', severity: 'low', label: '环境变量读取', re: /process\.env\./g },
  { code: 'system-info', severity: 'low', label: '系统信息探测', re: /\b(?:os\.networkInterfaces|os\.hostname|os\.userInfo|os\.platform|os\.cpus|os\.homedir)\s*\(/g },
  { code: 'obfuscation', severity: 'low', label: '编码 / 混淆迹象', re: /\batob\s*\(|\bBuffer\.from\s*\(\s*['"][^'"]*['"]\s*,\s*['"]base64/gi },
  { code: 'exfil-url', severity: 'medium', label: '可疑外联地址', re: /(?:pastebin\.com|webhook\.site|requestbin|ngrok\.io|discord\.com\/api\/webhooks|api\.telegram\.org\/bot|\.onion\b)/gi },
  { code: 'download-exec', severity: 'high', label: '下载即执行 (curl/wget 管道给 shell)', re: DOWNLOAD_EXEC_RE },
  { code: 'hardcoded-secret', severity: 'high', label: '疑似硬编码密钥 / 令牌', re: HARDCODED_SECRET_RE },
]

const SEVERITY_SCORE: Record<Severity, number> = { high: 40, medium: 18, low: 6 }

/** Package-name substrings flagged in the dependency review (low signal, honest about it). */
const SUSPICIOUS_NAME = /(miner|stealer|keylogger|ransomware|trojan|backdoor|infostealer|credential-steal|exfil)/i

/** Dep specs that bypass the npm registry provenance chain. */
function isNonRegistrySpec(spec: string): boolean {
  return /^(git\+|git:|github:|https?:\/\/|file:|link:|\.{1,2}[\\/])/.test(spec)
}

function* walkSource(dir: string, depth: number, maxDepth: number): Generator<string> {
  let entries: string[]
  try {
    // ponytail: sort for a stable traversal — readdir order is FS-dependent, and both the
    // maxFiles truncation and the per-rule 8-file cap must sample the SAME files every run.
    entries = readdirSync(dir).sort()
  } catch {
    return
  }
  for (const name of entries) {
    const full = join(dir, name)
    let st
    try {
      st = statSync(full)
    } catch {
      continue
    }
    if (st.isDirectory()) {
      if (SKIP_DIRS.has(name) || depth >= maxDepth) continue
      yield* walkSource(full, depth + 1, maxDepth)
    } else if (st.isFile()) {
      const dot = name.lastIndexOf('.')
      const ext = dot === -1 ? '' : name.slice(dot)
      if (!SCAN_EXTENSIONS.has(ext)) continue
      if (name.endsWith('.map') || name.endsWith('.d.ts') || name.endsWith('.min.js')) continue
      yield full
    }
  }
}

interface SourceScanResult {
  flags: ScanFlag[]
  scannedFiles: number
}

/** Capability sinks that, co-occurring with `env` reads in one file, approximate a credential-exfiltration taint. */
const EXEC_NET_SINKS = new Set(['child-process', 'shell', 'http', 'network', 'exfil-url'])

/** Shannon entropy (bits per character) of a string. */
function shannonEntropy(value: string): number {
  const freq = new Map<string, number>()
  for (const char of value) freq.set(char, (freq.get(char) ?? 0) + 1)
  let entropy = 0
  for (const count of freq.values()) {
    const p = count / value.length
    entropy -= p * Math.log2(p)
  }
  return entropy
}

/** Escape-aware string-literal matcher (single / double / backtick quotes). */
const STRING_LITERAL_RE = /(['"`])((?:\\.|(?!\1)[^\\])*)\1/g

/**
 * ponytail: heuristic for an encoded/encrypted payload — a long, whitespace-free
 * string literal with Shannon entropy ≥ 4.3 that is not a data URI, URL, or pure
 * hex hash. Catches base64/random blobs regardless of how they are later decoded
 * (the `obfuscation` rule only catches the decode call itself).
 */
function hasHighEntropyString(text: string): boolean {
  STRING_LITERAL_RE.lastIndex = 0
  let match: RegExpExecArray | null
  while ((match = STRING_LITERAL_RE.exec(text)) !== null) {
    const value = match[2]
    if (value === undefined || value.length < 40) continue
    if (/\s/.test(value)) continue
    if (/^(?:data:|https?:\/\/)/i.test(value)) continue
    if (/^[0-9a-f]+$/i.test(value)) continue
    if (shannonEntropy(value) >= 4.3) return true
  }
  return false
}

/** Scan one plugin directory's own source (its nested node_modules is skipped). */
function scanSourceTree(dir: string, maxFiles: number): SourceScanResult {
  const matches = new Map<string, { severity: Severity; label: string; files: Set<string> }>()
  const taintFiles = new Set<string>()
  const entropyFiles = new Set<string>()
  let scannedFiles = 0

  for (const file of walkSource(dir, 0, 5)) {
    if (scannedFiles >= maxFiles) break
    let text: string
    try {
      const st = statSync(file)
      if (st.size > MAX_FILE_BYTES) continue
      text = readFileSync(file, 'utf-8')
    } catch {
      continue
    }
    scannedFiles += 1
    const rel = relative(dir, file)
    const matchedCodes = new Set<string>()
    for (const rule of DANGER_RULES) {
      rule.re.lastIndex = 0
      if (!rule.re.test(text)) continue
      matchedCodes.add(rule.code)
      let entry = matches.get(rule.code)
      if (entry === undefined) {
        entry = { severity: rule.severity, label: rule.label, files: new Set() }
        matches.set(rule.code, entry)
      }
      if (entry.files.size < 8) entry.files.add(rel)
    }
    // ponytail: same-file env-read + exec/network co-occurrence — a cheap taint proxy for credential exfiltration.
    if (taintFiles.size < 8 && matchedCodes.has('env')) {
      for (const code of matchedCodes) {
        if (EXEC_NET_SINKS.has(code)) {
          taintFiles.add(rel)
          break
        }
      }
    }
    if (entropyFiles.size < 8 && hasHighEntropyString(text)) entropyFiles.add(rel)
  }

  const flags: ScanFlag[] = [...matches.entries()].map(([code, entry]) => ({
    code,
    severity: entry.severity,
    label: entry.label,
    files: [...entry.files],
  }))
  if (taintFiles.size > 0) {
    flags.push({ code: 'env-exfil', severity: 'medium', label: '同文件读取环境变量并执行/外联（疑似凭据外传）', files: [...taintFiles] })
  }
  if (entropyFiles.size > 0) {
    flags.push({ code: 'high-entropy', severity: 'medium', label: '高熵字符串（疑似编码/加密载荷）', files: [...entropyFiles] })
  }
  flags.sort((a, b) => SEVERITY_SCORE[b.severity] - SEVERITY_SCORE[a.severity] || a.code.localeCompare(b.code))
  return { flags, scannedFiles }
}

function reviewDependencies(pkg: Record<string, unknown>): DepFinding[] {
  const found: DepFinding[] = []
  const deps = { ...(pkg.dependencies as Record<string, string> ?? {}), ...(pkg.optionalDependencies as Record<string, string> ?? {}) }
  for (const [name, spec] of Object.entries(deps)) {
    const specStr = String(spec)
    let suspicious = false
    let reason: string | undefined
    if (isNonRegistrySpec(specStr)) {
      suspicious = true
      reason = '非 npm registry 来源 (git/file/link/URL)'
    } else if (SUSPICIOUS_NAME.test(name)) {
      suspicious = true
      reason = '包名命中可疑关键词'
    }
    found.push({ name, version: specStr, suspicious, reason: reason ?? '' })
  }
  found.sort((a, b) => a.name.localeCompare(b.name))
  return found
}

function checkInstallScripts(pkg: Record<string, unknown>): ScanFlag[] {
  const scripts = pkg.scripts as Record<string, string> ?? {}
  const risky = ['preinstall', 'install', 'postinstall'].filter(key => scripts[key] !== undefined)
  if (risky.length === 0) return []
  const flags: ScanFlag[] = [{
    code: 'install-script',
    severity: 'high',
    label: `声明安装脚本 (${risky.join(', ')})`,
    files: ['package.json'],
  }]
  // The supply-chain kicker: an install script that downloads and pipes straight to a shell.
  const body = risky.map(key => String(scripts[key])).join('\n')
  DOWNLOAD_EXEC_RE.lastIndex = 0
  if (DOWNLOAD_EXEC_RE.test(body)) {
    flags.push({ code: 'download-exec', severity: 'high', label: '安装脚本下载即执行 (curl/wget | shell)', files: ['package.json'] })
  }
  return flags
}

function scoreFor(flags: ScanFlag[]): { score: number; risk: RiskLevel } {
  let score = 0
  for (const flag of flags) score += SEVERITY_SCORE[flag.severity]
  score = Math.min(score, 100)
  const risk: RiskLevel = flags.some(flag => flag.severity === 'high') || score >= 40
    ? 'red'
    : flags.some(flag => flag.severity === 'medium') || score >= 15
      ? 'yellow'
      : 'green'
  return { score, risk }
}

/** Keywords implying a declaration lets the plugin reach the host's model/network/files/process/secrets. */
const POWERFUL_SERVICE = /(llm|agent|model|provider|tool|mcp|remote|typert|api|http|fetch|net|server|univer|file|fs|shell|exec|spawn|process|terminal|command|secret|key|token|credential|browser|sandbox|eval|runtime|storage|database|sql)/
/** Keywords implying UI / i18n / config / data-flow only. */
const LIGHT_SERVICE = /(locale|i18n|slot|renderer|theme|setting|config|schema|logger|registry|notification|toast|session|prompt|indexer|watcher)/

/** Normalize a declared service/package id to its bare lowercase name for tier matching. */
function serviceKey(name: string): string {
  return name
    .toLowerCase()
    .replace(/^@deepseek-ai\//, '')
    .replace(/^dsh-(?:client-)?(?:ui-)?/, '')
    .replace(/-/g, '')
}

/** ponytail: heuristic tier for a declared `inject` entry; unknown defaults to `medium` (review), never `green`. */
function classifyService(name: string): PermissionFinding {
  const key = serviceKey(name)
  if (POWERFUL_SERVICE.test(key)) return { name, severity: 'high', label: '涉及模型 / 网络 / 文件 / 进程 / 凭据 / 浏览器等宿主能力' }
  if (LIGHT_SERVICE.test(key)) return { name, severity: 'low', label: 'UI / 国际化 / 配置 / 数据流类宿主能力' }
  return { name, severity: 'medium', label: '未识别的宿主服务，需人工复核' }
}

/** Read a plugin's declared host-service dependencies without executing any of its code. */
function collectDeclaredServices(dir: string): string[] {
  const services = new Set<string>()
  const readList = (file: string, pick: (root: Record<string, unknown>) => unknown): void => {
    try {
      const root = JSON.parse(readFileSync(join(dir, file), 'utf-8')) as Record<string, unknown>
      const list = pick(root)
      if (Array.isArray(list)) for (const item of list) if (typeof item === 'string') services.add(item)
    } catch {
      /* optional file, or malformed manifest — ignore */
    }
  }
  readList('package.json', root => ((root.dsh as { client?: { inject?: unknown } } | undefined))?.client?.inject)
  readList('dsh.plugin.json', root => ((root.entry as { inject?: unknown } | undefined))?.inject)
  return [...services]
}

function auditPermissions(services: string[]): { permissions: PermissionFinding[]; permScore: number } {
  const permissions = services.map(classifyService)
  permissions.sort((a, b) => SEVERITY_SCORE[b.severity] - SEVERITY_SCORE[a.severity] || a.name.localeCompare(b.name))
  let permScore = 0
  for (const permission of permissions) permScore += SEVERITY_SCORE[permission.severity]
  return { permissions, permScore: Math.min(permScore, 100) }
}

function auditPlugin(nodeModules: string, name: string, spec: string, active: boolean, maxFiles: number): PluginAudit {
  const dir = join(nodeModules, name)
  const errors: string[] = []
  let version = spec
  let flags: ScanFlag[] = []
  let dependencies: DepFinding[] = []
  let scannedFiles = 0
  let permissions: PermissionFinding[] = []
  let permScore = 0

  if (!existsSync(dir)) {
    errors.push('目录不存在（可能被 pnpm 提升或未安装）')
  } else {
    try {
      const pkg = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf-8')) as Record<string, unknown>
      version = typeof pkg.version === 'string' ? pkg.version : spec
      flags.push(...checkInstallScripts(pkg))
      const scan = scanSourceTree(dir, maxFiles)
      flags.push(...scan.flags)
      scannedFiles = scan.scannedFiles
      dependencies = reviewDependencies(pkg)
      const perms = auditPermissions(collectDeclaredServices(dir))
      permissions = perms.permissions
      permScore = perms.permScore
    } catch (error) {
      errors.push(error instanceof Error ? error.message : String(error))
    }
  }

  const capabilityMismatch = flags.some(flag => flag.severity === 'high')
    && permissions.length > 0
    && !permissions.some(permission => permission.severity === 'high')

  const { score, risk } = scoreFor(flags)
  const merged = new Map<string, ScanFlag>()
  for (const flag of flags) {
    const existing = merged.get(flag.code)
    if (existing === undefined) merged.set(flag.code, flag)
    else {
      const files = new Set([...existing.files, ...flag.files])
      merged.set(flag.code, { ...existing, files: [...files].slice(0, 8) })
    }
  }

  return {
    name,
    version,
    active,
    source: spec,
    risk,
    score,
    flags: [...merged.values()].sort((a, b) => SEVERITY_SCORE[b.severity] - SEVERITY_SCORE[a.severity] || a.code.localeCompare(b.code)),
    dependencies,
    scannedFiles,
    permissions,
    permScore,
    capabilityMismatch,
    errors,
  }
}

const RISK_ORDER: Record<RiskLevel, number> = { red: 0, yellow: 1, green: 2 }

/** One extracted source line that matched a danger rule, for AI-audit evidence. */
export interface EvidenceSnippet {
  /** Plugin-relative file path. */
  readonly file: string
  /** 1-based line number. */
  readonly line: number
  readonly severity: Severity
  /** Rule code, e.g. `child-process`. */
  readonly code: string
  /** Rule label, e.g. "子进程执行". */
  readonly label: string
  /** The matched line, trimmed and bounded. */
  readonly text: string
}

/**
 * Extract bounded source-line evidence for AI auditing: walks one plugin's
 * source and, for each danger-rule match, records the file, line number, and
 * trimmed line text. Purely additive to the aggregate report — the Line/column
 * granularity here feeds the model's reasoning, not the static score.
 */
export function collectEvidence(pluginDir: string, maxSnippets: number): EvidenceSnippet[] {
  const snippets: EvidenceSnippet[] = []
  for (const file of walkSource(pluginDir, 0, 5)) {
    if (snippets.length >= maxSnippets) break
    let text: string
    try {
      const st = statSync(file)
      if (st.size > MAX_FILE_BYTES) continue
      text = readFileSync(file, 'utf-8')
    } catch {
      continue
    }
    const rel = relative(pluginDir, file)
    const lines = text.split('\n')
    for (const rule of DANGER_RULES) {
      for (let index = 0; index < lines.length; index += 1) {
        const line = lines[index]
        if (line === undefined) continue
        rule.re.lastIndex = 0
        if (!rule.re.test(line)) continue
        snippets.push({
          file: rel,
          line: index + 1,
          severity: rule.severity,
          code: rule.code,
          label: rule.label,
          text: line.trim().slice(0, 200),
        })
        if (snippets.length >= maxSnippets) break
      }
      if (snippets.length >= maxSnippets) break
    }
  }
  return snippets
}

/** A plugin's self-declared purpose and publish metadata, for AI-audit consistency judgment. */
export interface PluginMetadata {
  /** package.json description (the plugin's stated purpose). */
  description: string
  keywords: string[]
  author: string
  repository: string
  homepage: string
  /** Install/postinstall scripts verbatim (supply-chain attack surface). */
  scripts: string
  /** First ~3KB of README — the plugin's own documentation of what it does. */
  readmeExcerpt: string
  /** GitHub repo URLs found anywhere in the FULL README (drives repo resolution, not the prompt). */
  readmeGithubUrls: string[]
  /** dsh.plugin.json description when present. */
  manifestDescription: string
}

/** Cap on README bytes fed to the model, keeping the audit prompt bounded. */
const README_MAX_BYTES = 3000

function stringOf(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

function authorOf(value: unknown): string {
  if (typeof value === 'string') return value
  if (value !== null && typeof value === 'object') {
    const record = value as Record<string, unknown>
    const name = stringOf(record.name)
    const email = stringOf(record.email)
    return email !== '' ? `${name} <${email}>` : name
  }
  return ''
}

function repositoryOf(value: unknown): string {
  if (typeof value === 'string') return value
  if (value !== null && typeof value === 'object') return stringOf((value as Record<string, unknown>).url)
  return ''
}

/** All github.com owner/repo URLs mentioned in arbitrary text (README, homepage, etc.). */
export function findGithubUrls(text: string): string[] {
  if (text === '') return []
  const urls: string[] = []
  const pattern = /(?:https?:\/\/(?:www\.)?github\.com\/|git@github\.com:|git\+ssh:\/\/git@github\.com\/)([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)/gi
  let match: RegExpExecArray | null
  while ((match = pattern.exec(text)) !== null) {
    const owner = match[1] ?? ''
    const repo = (match[2] ?? '').replace(/\.git$/i, '')
    if (owner === '' || repo === '') continue
    urls.push(`https://github.com/${owner}/${repo}`)
  }
  return urls
}

/**
 * Read a plugin's self-description without executing it: package.json
 * (description/keywords/author/repository/homepage/scripts), the README's
 * first bytes, and the dsh.plugin.json description. The model uses this to
 * judge whether the dangerous capabilities match the plugin's stated job —
 * a file-manager plugin writing files is expected, a calculator that reads
 * SSH keys is not.
 */
export function collectPluginMetadata(pluginDir: string): PluginMetadata {
  const metadata: PluginMetadata = {
    description: '',
    keywords: [],
    author: '',
    repository: '',
    homepage: '',
    scripts: '',
    readmeExcerpt: '',
    readmeGithubUrls: [],
    manifestDescription: '',
  }

  try {
    const pkg = JSON.parse(readFileSync(join(pluginDir, 'package.json'), 'utf-8')) as Record<string, unknown>
    metadata.description = stringOf(pkg.description)
    const keywords = pkg.keywords
    if (Array.isArray(keywords)) {
      metadata.keywords = keywords.filter((item): item is string => typeof item === 'string').slice(0, 20)
    }
    metadata.author = authorOf(pkg.author)
    metadata.repository = repositoryOf(pkg.repository)
    metadata.homepage = stringOf(pkg.homepage)
    const scripts = pkg.scripts
    if (scripts !== null && typeof scripts === 'object') {
      metadata.scripts = Object.entries(scripts as Record<string, unknown>)
        .map(([key, value]) => `${key}: ${stringOf(value)}`)
        .join('\n')
    }
  } catch {
    /* package.json may be absent for non-registry installs */
  }

  for (const candidate of ['README.md', 'README', 'readme.md', 'README.txt', 'readme.txt', 'Readme.md']) {
    try {
      const path = join(pluginDir, candidate)
      if (!existsSync(path)) continue
      const st = statSync(path)
      if (!st.isFile() || st.size === 0) continue
      const buf = readFileSync(path)
      metadata.readmeExcerpt = buf.subarray(0, README_MAX_BYTES).toString('utf-8')
      // Repo links can sit at the very bottom of a README; scan the whole file
      // while the prompt keeps only the capped excerpt.
      metadata.readmeGithubUrls = findGithubUrls(buf.toString('utf-8'))
      if (metadata.readmeExcerpt !== '') break
    } catch {
      /* try the next filename */
    }
  }

  try {
    const manifest = JSON.parse(readFileSync(join(pluginDir, 'dsh.plugin.json'), 'utf-8')) as Record<string, unknown>
    metadata.manifestDescription = stringOf(manifest.description)
  } catch {
    /* optional manifest */
  }

  return metadata
}

/** Run a full audit over one profile directory (contains package.json + node_modules). */
export function runAudit(profileDir: string, maxScanFiles: number): SecurityReport {
  const nodeModules = join(profileDir, 'node_modules')
  const manifestPath = join(profileDir, 'package.json')
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf-8')) as {
    dependencies?: Record<string, string>
    dsh?: { profile?: { bundles?: string[] } }
  }

  const deps = manifest.dependencies ?? {}
  const bundles = new Set(manifest.dsh?.profile?.bundles ?? [])
  const plugins: PluginAudit[] = []

  for (const [name, spec] of Object.entries(deps)) {
    // In-box core bundles are the trusted harness itself; skip them.
    if (name.startsWith('@deepseek-ai/')) continue
    plugins.push(auditPlugin(nodeModules, name, String(spec), bundles.has(name), maxScanFiles))
  }

  plugins.sort((a, b) => RISK_ORDER[a.risk] - RISK_ORDER[b.risk] || b.score - a.score || a.name.localeCompare(b.name))

  const redCount = plugins.filter(plugin => plugin.risk === 'red').length
  const yellowCount = plugins.filter(plugin => plugin.risk === 'yellow').length
  const greenCount = plugins.filter(plugin => plugin.risk === 'green').length

  return {
    generatedAt: new Date().toISOString(),
    dshHome: process.env.DSH_HOME ?? '(unknown)',
    profile: profileDir,
    pluginCount: plugins.length,
    redCount,
    yellowCount,
    greenCount,
    plugins,
    deltas: [],
  }
}

/** One plugin's persisted state from the previous scan, for version-diff alerting. */
export interface BaselineEntry {
  readonly version: string
  readonly flags: readonly string[]
  readonly perms: readonly string[]
}

/** The persisted baseline snapshot: plugin name → its last-seen state. */
export type BaselineSnapshot = Record<string, BaselineEntry>

/** Build the baseline snapshot to persist from a fresh audit. */
export function buildBaseline(plugins: PluginAudit[]): BaselineSnapshot {
  const snapshot: BaselineSnapshot = {}
  for (const plugin of plugins) {
    snapshot[plugin.name] = {
      version: plugin.version,
      flags: plugin.flags.map(flag => flag.code),
      perms: plugin.permissions.map(permission => permission.name),
    }
  }
  return snapshot
}

/**
 * Diff a fresh audit against the previous baseline: one delta per plugin that is
 * newly installed, changed version, or gained flags/permissions. An empty
 * baseline (first scan) yields no deltas — there is nothing to compare against.
 */
export function computePluginDeltas(plugins: PluginAudit[], baseline: BaselineSnapshot): PluginDelta[] {
  if (Object.keys(baseline).length === 0) return []
  const deltas: PluginDelta[] = []
  for (const plugin of plugins) {
    const previous = baseline[plugin.name]
    if (previous === undefined) {
      deltas.push({ name: plugin.name, isNew: true, previousVersion: '', currentVersion: plugin.version, addedFlags: [], addedPerms: [] })
      continue
    }
    const addedFlags = plugin.flags.map(flag => flag.code).filter(code => !previous.flags.includes(code))
    const addedPerms = plugin.permissions.map(permission => permission.name).filter(name => !previous.perms.includes(name))
    if (previous.version !== plugin.version || addedFlags.length > 0 || addedPerms.length > 0) {
      deltas.push({ name: plugin.name, isNew: false, previousVersion: previous.version, currentVersion: plugin.version, addedFlags, addedPerms })
    }
  }
  return deltas
}

/**
 * Content fingerprint of everything the AI audit actually reads for one plugin:
 * version, package.json, dsh.plugin.json, README, and every scanned source file.
 * Equal fingerprints mean identical audit inputs, so a cached verdict stays valid.
 * Hashing is content-based (not flag-based), so even a one-byte source change
 * invalidates the fingerprint and forces a re-audit.
 */
export function computePluginFingerprint(pluginDir: string, version: string, modelKey = ''): string {
  const hash = createHash('sha256')
  hash.update('version\0' + version + '\0')
  if (modelKey !== '') hash.update('model\0' + modelKey + '\0')

  for (const name of ['package.json', 'dsh.plugin.json']) {
    hash.update(name + '\0')
    try {
      hash.update(readFileSync(join(pluginDir, name), 'utf-8'))
    } catch {
      hash.update('<absent>')
    }
  }

  for (const candidate of ['README.md', 'README', 'readme.md', 'README.txt', 'readme.txt', 'Readme.md']) {
    const path = join(pluginDir, candidate)
    if (!existsSync(path)) continue
    hash.update('readme\0')
    try {
      hash.update(readFileSync(path, 'utf-8'))
    } catch {
      hash.update('<unreadable>')
    }
    break
  }

  for (const file of walkSource(pluginDir, 0, 5)) {
    try {
      if (statSync(file).size > MAX_FILE_BYTES) continue
    } catch {
      continue
    }
    hash.update('file\0' + relative(pluginDir, file) + '\0')
    try {
      hash.update(readFileSync(file, 'utf-8'))
    } catch {
      hash.update('<unreadable>')
    }
  }

  return hash.digest('hex')
}