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
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import type { DepFinding, PluginAudit, RiskLevel, ScanFlag, SecurityReport, Severity } from './contracts.ts'

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
    entries = readdirSync(dir)
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

/** Scan one plugin directory's own source (its nested node_modules is skipped). */
function scanSourceTree(dir: string, maxFiles: number): SourceScanResult {
  const matches = new Map<string, { severity: Severity; label: string; files: Set<string> }>()
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
    for (const rule of DANGER_RULES) {
      rule.re.lastIndex = 0
      if (!rule.re.test(text)) continue
      let entry = matches.get(rule.code)
      if (entry === undefined) {
        entry = { severity: rule.severity, label: rule.label, files: new Set() }
        matches.set(rule.code, entry)
      }
      if (entry.files.size < 8) entry.files.add(rel)
    }
  }

  const flags: ScanFlag[] = [...matches.entries()].map(([code, entry]) => ({
    code,
    severity: entry.severity,
    label: entry.label,
    files: [...entry.files],
  }))
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
  return [{
    code: 'install-script',
    severity: 'high',
    label: `声明安装脚本 (${risky.join(', ')})`,
    files: ['package.json'],
  }]
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

function auditPlugin(nodeModules: string, name: string, spec: string, active: boolean, maxFiles: number): PluginAudit {
  const dir = join(nodeModules, name)
  const errors: string[] = []
  let version = spec
  let flags: ScanFlag[] = []
  let dependencies: DepFinding[] = []
  let scannedFiles = 0

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
    } catch (error) {
      errors.push(error instanceof Error ? error.message : String(error))
    }
  }

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
      metadata.readmeExcerpt = readFileSync(path).subarray(0, README_MAX_BYTES).toString('utf-8')
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
  }
}