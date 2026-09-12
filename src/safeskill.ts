/**
 * SafeSkill (https://safeskill.cn/docs) integration: multi-engine security
 * detection for locally installed DSH skills via 微步's Skill scanner.
 *
 * Flow: enumerate `$DSH_HOME/skills/<name>/SKILL.md` → pack a skill folder into
 * an in-memory ZIP (stored, no compression) → POST /api/v1/scan (multipart) →
 * poll GET /api/v1/report by sha256 until a verdict lands (≤ 5 min) → normalize
 * into the shared `SafeSkillReport` shape consumed by the panel.
 *
 * Node-only: imported exclusively by the Host runtime, never the browser bundle.
 */
import { existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { createHash } from 'node:crypto'
import { isSafePackageName } from './scanner.ts'
import type { SafeSkillReport, SafeSkillThreat, SafeSkillIndicator, SkillEntry, SafeSkillCacheEntry, SkillScanResult } from './contracts.ts'
import type { Severity } from './contracts.ts'

const SAFESKILL_API = 'https://api.safeskill.cn'
const SKILL_ENTRY = 'SKILL.md'
const REPORT_URL = 'https://safeskill.cn/report'

/** Poll cadence for the report endpoint, and the overall scan ceiling. */
const POLL_INTERVAL_MS = 10_000
const POLL_TIMEOUT_MS = 30_000
const SCAN_DEADLINE_MS = 5 * 60_1000
const SUBMIT_TIMEOUT_MS = 60_000

/** Upload guards — SafeSkill rejects oversized submissions. */
const MAX_SKILL_FILES = 200
const MAX_SKILL_FILE_BYTES = 5 * 1024 * 1024
const MAX_SKILL_TOTAL_BYTES = 15 * 1024 * 1024

const USER_AGENT = 'dsh-plugin-guard/0.3.0 (skill audit)'

function skillsRoot(): string {
  const home = process.env.DSH_HOME
  return home === undefined || home.trim() === '' ? '' : join(home, 'skills')
}

const sleep = (ms: number): Promise<void> => new Promise<void>(resolve => setTimeout(resolve, ms))

/** First non-empty, heading-stripped line of a SKILL.md, bounded for list UI. */
function readSkillDescription(skillMd: string): string {
  try {
    const text = readFileSync(skillMd, 'utf-8')
    const line = text.split(/\r?\n/).map(item => item.replace(/^#+\s*/, '').trim()).find(item => item !== '')
    return (line ?? '').slice(0, 140)
  } catch {
    return ''
  }
}

/** Enumerate installed skills: every `$DSH_HOME/skills/<name>` with a SKILL.md. */
export function listLocalSkills(): SkillEntry[] {
  const root = skillsRoot()
  if (root === '') return []
  let names: string[]
  try {
    names = readdirSync(root).sort()
  } catch {
    return []
  }
  const entries: SkillEntry[] = []
  for (const name of names) {
    if (!isSafePackageName(name)) continue
    const skillMd = join(root, name, SKILL_ENTRY)
    if (!existsSync(skillMd)) continue
    entries.push({ name, description: readSkillDescription(skillMd) })
  }
  return entries
}

interface ZipEntry {
  path: string
  data: Uint8Array
}

/** Walk one skill folder, collecting its files (symlinks and VCS/dep dirs skipped). */
function collectSkillFiles(dir: string): ZipEntry[] {
  const files: ZipEntry[] = []
  let total = 0
  const walk = (current: string, prefix: string): boolean => {
    let names: string[]
    try {
      names = readdirSync(current).sort()
    } catch {
      return false
    }
    for (const name of names) {
      if (name === '.git' || name === 'node_modules') continue
      const full = join(current, name)
      let st
      try {
        st = lstatSync(full)
      } catch {
        continue
      }
      if (st.isSymbolicLink()) continue
      if (st.isDirectory()) {
        walk(full, prefix === '' ? name : `${prefix}/${name}`)
        continue
      }
      if (!st.isFile()) continue
      if (st.size > MAX_SKILL_FILE_BYTES || files.length >= MAX_SKILL_FILES || total + st.size > MAX_SKILL_TOTAL_BYTES) continue
      const rel = prefix === '' ? name : `${prefix}/${name}`
      files.push({ path: rel, data: readFileSync(full) })
      total += st.size
    }
    return true
  }
  walk(dir, '')
  return files
}

// ── Minimal ZIP writer (method 0 = stored, no compression) ──────────────────
// Node has no built-in zip, and pulling a dependency for a folder of a few
// small files is not worth it. A "stored" archive is a plain container: local
// header + data + central directory + end record. CRC32 uses the standard
// reflected IEEE table.

const CRC_TABLE = (() => {
  const table = new Uint32Array(256)
  for (let n = 0; n < 256; n += 1) {
    let c = n
    for (let k = 0; k < 8; k += 1) c = (c & 1) !== 0 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
    table[n] = c >>> 0
  }
  return table
})()

function crc32(data: Uint8Array): number {
  let crc = 0xffffffff
  for (let i = 0; i < data.length; i += 1) crc = CRC_TABLE[(crc ^ data[i]!) & 0xff]! ^ (crc >>> 8)
  return (crc ^ 0xffffffff) >>> 0
}

function zipStored(files: ZipEntry[]): Uint8Array {
  const encoder = new TextEncoder()
  const chunks: Uint8Array[] = []
  const central: Uint8Array[] = []
  let offset = 0
  for (const file of files) {
    const nameBytes = encoder.encode(file.path)
    const crc = crc32(file.data)

    const local = new DataView(new ArrayBuffer(30))
    local.setUint32(0, 0x04034b50, true)
    local.setUint16(4, 20, true)
    local.setUint16(6, 0x0800, true) // UTF-8 filenames
    local.setUint16(8, 0, true) // stored
    local.setUint16(10, 0, true)
    local.setUint16(12, 0x21, true) // 1980-01-01
    local.setUint32(14, crc, true)
    local.setUint32(18, file.data.length, true)
    local.setUint32(22, file.data.length, true)
    local.setUint16(26, nameBytes.length, true)
    local.setUint16(28, 0, true)
    chunks.push(new Uint8Array(local.buffer), nameBytes, file.data)

    const centralHeader = new DataView(new ArrayBuffer(46))
    centralHeader.setUint32(0, 0x02014b50, true)
    centralHeader.setUint16(4, 20, true)
    centralHeader.setUint16(6, 20, true)
    centralHeader.setUint16(8, 0x0800, true)
    centralHeader.setUint16(10, 0, true)
    centralHeader.setUint16(12, 0, true)
    centralHeader.setUint16(14, 0x21, true)
    centralHeader.setUint32(16, crc, true)
    centralHeader.setUint32(20, file.data.length, true)
    centralHeader.setUint32(24, file.data.length, true)
    centralHeader.setUint16(28, nameBytes.length, true)
    centralHeader.setUint32(42, offset, true)
    central.push(new Uint8Array(centralHeader.buffer), nameBytes)

    offset += 30 + nameBytes.length + file.data.length
  }

  const centralSize = central.reduce((sum, chunk) => sum + chunk.length, 0)
  const end = new DataView(new ArrayBuffer(22))
  end.setUint32(0, 0x06054b50, true)
  end.setUint16(8, files.length, true)
  end.setUint16(10, files.length, true)
  end.setUint32(12, centralSize, true)
  end.setUint32(16, offset, true)
  chunks.push(...central, new Uint8Array(end.buffer))

  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0)
  const out = new Uint8Array(total)
  let pos = 0
  for (const chunk of chunks) {
    out.set(chunk, pos)
    pos += chunk.length
  }
  return out
}

function asObject(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === 'object' ? (value as Record<string, unknown>) : undefined
}

function safeSkillError(code: number | undefined, verboseMsg: string | undefined): string {
  const msg = verboseMsg !== undefined && verboseMsg !== '' ? verboseMsg : '未知错误'
  return `SafeSkill 请求失败（code=${String(code ?? '?')}）：${msg}`
}

async function readJson(response: Response): Promise<Record<string, unknown>> {
  const text = await response.text()
  try {
    return JSON.parse(text) as Record<string, unknown>
  } catch {
    throw new Error(`SafeSkill 返回非 JSON（HTTP ${response.status}）`)
  }
}

/** Submit a packed skill zip, returning its content sha256 (report key). */
async function submitSkill(zip: Uint8Array, fileName: string, apiKey: string): Promise<{ sha256: string; permalink: string }> {
  const form = new FormData()
  form.append('apikey', apiKey)
  // zipStored always returns a fresh, full-length Uint8Array, so its `.buffer` is the whole archive.
  form.append('file', new Blob([zip.buffer as ArrayBuffer], { type: 'application/zip' }), fileName)
  const response = await fetch(`${SAFESKILL_API}/api/v1/scan`, {
    method: 'POST',
    body: form,
    signal: AbortSignal.timeout(SUBMIT_TIMEOUT_MS),
    headers: { 'user-agent': USER_AGENT },
  })
  const payload = await readJson(response)
  const code = typeof payload.response_code === 'number' ? payload.response_code : undefined
  if (code !== 0) throw new Error(safeSkillError(code, asString(payload.verbose_msg)))
  const data = asObject(payload.data)
  const sha256 = asString(data?.sha256)
  if (sha256 === '') throw new Error('SafeSkill 未返回 sha256')
  const permalink = asString(data?.permalink)
  return { sha256, permalink: permalink !== '' ? permalink : `${REPORT_URL}/${sha256}` }
}

function asRecord(value: unknown): Record<string, string> {
  const out: Record<string, string> = {}
  if (value !== null && typeof value === 'object') {
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      out[key] = typeof item === 'string' ? item : String(item ?? '')
    }
  }
  return out
}

function asString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : ''
}

function normalizeThreat(value: unknown): SafeSkillThreat {
  if (value === 'malicious' || value === 'suspicious' || value === 'clean' || value === 'unknown') return value
  return 'unknown'
}

function normalizeSeverity(value: unknown): Severity {
  if (value === 'high' || value === 'critical') return 'high'
  if (value === 'medium' || value === 'moderate' || value === 'warning') return 'medium'
  return 'low'
}

function normalizeIndicators(value: unknown): SafeSkillIndicator[] {
  if (!Array.isArray(value)) return []
  const out: SafeSkillIndicator[] = []
  for (const raw of value) {
    if (raw === null || typeof raw !== 'object') continue
    const item = raw as Record<string, unknown>
    const indicator = asString(item.indicator)
    if (indicator === '') continue
    const sources: { file: string; lines: string }[] = []
    if (Array.isArray(item.sources)) {
      for (const src of item.sources) {
        if (src === null || typeof src !== 'object') continue
        const s = src as Record<string, unknown>
        sources.push({ file: asString(s.file), lines: asString(s.lines) })
      }
    }
    out.push({
      indicator,
      category: asString(item.category),
      severity: normalizeSeverity(item.severity),
      evidence: asString(item.evidence),
      sources,
    })
  }
  return out
}

function normalizeReport(skillName: string, sha256: string, permalink: string, data: Record<string, unknown>): SafeSkillReport {
  const summary = (data.summary ?? {}) as Record<string, unknown>
  const trustRaw = summary.trust_score
  const trustScore = typeof trustRaw === 'number' && Number.isFinite(trustRaw)
    ? Math.round(Math.min(100, Math.max(0, trustRaw)))
    : -1
  return {
    skillName,
    sha256,
    threatLevel: normalizeThreat(summary.threat_level),
    threatClassify: asString(summary.threat_classify),
    trustScore,
    multiVerdict: asRecord(data.multi_verdict),
    indicators: normalizeIndicators((data.llm_details as Record<string, unknown> | undefined)?.risk_indicators),
    permalink: asString(permalink),
  }
}

/** Poll the report endpoint until `multi_verdict` is present or the deadline hits. */
async function pollReport(skillName: string, sha256: string, permalink: string, apiKey: string): Promise<SafeSkillReport> {
  const deadline = Date.now() + SCAN_DEADLINE_MS
  for (;;) {
    const url = `${SAFESKILL_API}/api/v1/report?apikey=${encodeURIComponent(apiKey)}&sha256=${encodeURIComponent(sha256)}`
    const response = await fetch(url, {
      signal: AbortSignal.timeout(POLL_TIMEOUT_MS),
      headers: { accept: 'application/json', 'user-agent': USER_AGENT },
    })
    const payload = await readJson(response)
    const code = typeof payload.response_code === 'number' ? payload.response_code : undefined
    if (code !== undefined && code !== 0 && code !== 3) {
      throw new Error(safeSkillError(code, asString(payload.verbose_msg)))
    }
    const data = asObject(payload.data)
    if (data !== undefined && 'multi_verdict' in data) {
      return normalizeReport(skillName, sha256, permalink, data)
    }
    if (Date.now() > deadline) {
      throw new Error(`SafeSkill 扫描超时（${Math.round(SCAN_DEADLINE_MS / 60_000)} 分钟未出结果）`)
    }
    await sleep(POLL_INTERVAL_MS)
  }
}

/** Full single-skill scan: discover → pack → submit → poll → normalized verdict. */
export async function runSafeSkillScan(skillName: string, apiKey: string): Promise<SafeSkillReport> {
  if (apiKey === '') throw new Error('未配置 SafeSkill API Key')
  const root = skillsRoot()
  if (root === '') throw new Error('DSH_HOME 未设置，无法定位 skills 目录')
  if (!isSafePackageName(skillName)) throw new Error('非法的 skill 名称')
  const skillMd = join(root, skillName, SKILL_ENTRY)
  if (!existsSync(skillMd)) throw new Error(`skills/${skillName}/${SKILL_ENTRY} 不存在`)
  const files = collectSkillFiles(join(root, skillName))
  if (files.length === 0) throw new Error(`skill \"${skillName}\" 目录为空`)
  const { sha256, permalink } = await submitSkill(zipStored(files), `${skillName}.zip`, apiKey)
  return pollReport(skillName, sha256, permalink, apiKey)
}

// ── Search-first cache layer ───────────────────────────────────────────────
// Before uploading to SafeSkill, compute a SHA-256 of the skill's zip content
// and check the local cache. Matching content hash → skip submit+poll → return
// cached result immediately. On a cache miss the full scan runs and the result
// is persisted for the next lookup.

const CACHE_DIR = 'storages/dsh-plugin-guard'
const CACHE_FILE = 'safeskill-cache.json'

function cacheDir(): string {
  const home = process.env.DSH_HOME
  if (home === undefined || home === '') return ''
  return join(home, CACHE_DIR)
}

/** Compute a SHA-256 hex digest of the skill's zip content (same bytes submitted to SafeSkill). */
export function computeSkillContentHash(skillName: string): string {
  const root = skillsRoot()
  if (root === '') return ''
  const dir = join(root, skillName)
  try {
    if (!existsSync(dir)) return ''
  } catch {
    return ''
  }
  const files = collectSkillFiles(dir)
  if (files.length === 0) return ''
  return createHash('sha256').update(zipStored(files)).digest('hex')
}

/** Read the on-disk SafeSkill result cache, returning an empty object on any failure. */
export function loadSafeSkillCache(): Record<string, SafeSkillCacheEntry> {
  const dir = cacheDir()
  if (dir === '') return {}
  const file = join(dir, CACHE_FILE)
  try {
    if (!existsSync(file)) return {}
    const raw = JSON.parse(readFileSync(file, 'utf-8'))
    if (typeof raw !== 'object' || raw === null) return {}
    return raw as Record<string, SafeSkillCacheEntry>
  } catch {
    return {}
  }
}

/** Persist the SafeSkill result cache atomically. Silently swallows IO errors. */
export function saveSafeSkillCache(cache: Record<string, SafeSkillCacheEntry>): void {
  const dir = cacheDir()
  if (dir === '') return
  try {
    mkdirSync(dir, { recursive: true })
    writeFileSync(join(dir, CACHE_FILE), JSON.stringify(cache, null, 2), 'utf-8')
  } catch {
    // best-effort cache — a miss means a re-scan next time
  }
}

/**
 * Cache-aware single-skill scan: checks the local content-hash cache first,
 * falls back to a full SafeSkill submit+poll cycle on miss, and caches the
 * result for future lookups.
 */
export async function scanSkillWithCache(
  skillName: string,
  apiKey: string,
): Promise<{ report: SafeSkillReport; fromCache: boolean }> {
  const contentHash = computeSkillContentHash(skillName)
  if (contentHash !== '') {
    const cache = loadSafeSkillCache()
    const cached = cache[contentHash]
    if (cached !== undefined) return { report: cached.report, fromCache: true }
  }

  const report = await runSafeSkillScan(skillName, apiKey)

  if (contentHash !== '') {
    const cache = loadSafeSkillCache()
    cache[contentHash] = { contentHash, safeSkillSha256: report.sha256, report, cachedAt: Date.now(), skillName }
    saveSafeSkillCache(cache)
  }

  return { report, fromCache: false }
}

/** Return every currently-cached scan result (for the panel snapshot restore RPC). */
export function getCachedResults(): SkillScanResult[] {
  const cache = loadSafeSkillCache()
  return Object.values(cache).map(entry => ({
    skillName: entry.skillName,
    report: entry.report,
    fromCache: true,
    cachedAt: entry.cachedAt,
    error: null,
  }))
}