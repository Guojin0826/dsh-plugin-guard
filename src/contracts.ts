/**
 * dsh-plugin-guard wire contract, shared verbatim by the host manifest
 * (`ctx.typert.register` in typert.ts) and the client contribution
 * (`ctx.remote.$mount` in client/remote.ts). It carries the audit report
 * shape plus its strict zod codecs, and the single `guard.getReport` wire
 * descriptor. No Node-only imports live in this module, so the browser bundle
 * can share it without pulling `node:fs`/`node:path`.
 */
import { z } from 'zod'
import type { InvocationDescriptor } from '@deepseek-ai/dsh-typert-protocol'

export type Severity = 'high' | 'medium' | 'low'
export type RiskLevel = 'red' | 'yellow' | 'green'

/** One dangerous-pattern match, aggregated per rule across files. */
export interface ScanFlag {
  /** Stable rule code, e.g. `child-process`. */
  readonly code: string
  readonly severity: Severity
  /** Human-readable label, e.g. "子进程执行". */
  readonly label: string
  /** Plugin-relative source files where the pattern matched (bounded). */
  readonly files: string[]
}

/** One reviewed dependency of an audited plugin. */
export interface DepFinding {
  readonly name: string
  readonly version: string
  readonly suspicious: boolean
  readonly reason?: string
}

/** One declared host-service dependency (`inject` entry) with its power tier. */
export interface PermissionFinding {
  /** Raw service name / package id as declared, e.g. `llm` or `@deepseek-ai/dsh-api-remotes`. */
  readonly name: string
  readonly severity: Severity
  /** Plain-language note on what this grants. */
  readonly label: string
}

/** Per-plugin audit result. */
export interface PluginAudit {
  readonly name: string
  readonly version: string
  /** Whether the package is an active profile layer (`dsh.profile.bundles`). */
  readonly active: boolean
  /** Raw dependency spec from the profile manifest (npm range / link / file / git). */
  readonly source: string
  readonly risk: RiskLevel
  /** 0–100, higher = riskier. */
  readonly score: number
  readonly flags: ScanFlag[]
  readonly dependencies: DepFinding[]
  readonly scannedFiles: number
  /** Declared host-service dependencies (`entry.inject` + `dsh.client.inject`), each power-tiered. */
  readonly permissions: PermissionFinding[]
  /** 0–100 weighted score of declared host-service power (same weights as the static score). */
  readonly permScore: number
  /** True when code has high-severity capabilities but the plugin only declares low-power services. */
  readonly capabilityMismatch: boolean
  readonly errors: string[]
}

/** What changed for one plugin since the previous scan's baseline (version-diff alerting). */
export interface PluginDelta {
  readonly name: string
  /** True when the plugin was absent from the previous baseline (newly installed). */
  readonly isNew: boolean
  readonly previousVersion: string
  readonly currentVersion: string
  /** Rule codes present now but not in the baseline. */
  readonly addedFlags: string[]
  /** Declared host services added since the baseline. */
  readonly addedPerms: string[]
}

/** The full audit report returned by `guard.getReport`. */
export interface SecurityReport {
  readonly generatedAt: string
  readonly dshHome: string
  readonly profile: string
  readonly pluginCount: number
  readonly redCount: number
  readonly yellowCount: number
  readonly greenCount: number
  readonly plugins: PluginAudit[]
  /** Per-plugin changes since the previous scan (empty on the first scan). */
  readonly deltas: PluginDelta[]
}

export const severitySchema = z.enum(['high', 'medium', 'low'])
export const riskLevelSchema = z.enum(['red', 'yellow', 'green'])

export const scanFlagSchema = z.object({
  code: z.string().min(1),
  severity: severitySchema,
  label: z.string().min(1),
  files: z.array(z.string().min(1)),
}).readonly()

export const depFindingSchema = z.object({
  name: z.string().min(1),
  version: z.string(),
  suspicious: z.boolean(),
  reason: z.string().optional(),
}).readonly()

export const permissionFindingSchema = z.object({
  name: z.string().min(1),
  severity: severitySchema,
  label: z.string().min(1),
}).readonly()

export const pluginAuditSchema = z.object({
  name: z.string().min(1),
  version: z.string(),
  active: z.boolean(),
  source: z.string(),
  risk: riskLevelSchema,
  score: z.number(),
  flags: z.array(scanFlagSchema),
  dependencies: z.array(depFindingSchema),
  scannedFiles: z.number(),
  permissions: z.array(permissionFindingSchema),
  permScore: z.number(),
  capabilityMismatch: z.boolean(),
  errors: z.array(z.string()),
}).readonly()

export const pluginDeltaSchema = z.object({
  name: z.string().min(1),
  isNew: z.boolean(),
  previousVersion: z.string(),
  currentVersion: z.string(),
  addedFlags: z.array(z.string()),
  addedPerms: z.array(z.string()),
}).readonly()

export const securityReportSchema = z.object({
  generatedAt: z.string().min(1),
  dshHome: z.string().min(1),
  profile: z.string().min(1),
  pluginCount: z.number().int().min(0),
  redCount: z.number().int().min(0),
  yellowCount: z.number().int().min(0),
  greenCount: z.number().int().min(0),
  plugins: z.array(pluginAuditSchema),
  deltas: z.array(pluginDeltaSchema),
}).readonly()

/** The model's security verdict for one plugin. */
export type AiVerdict = 'safe' | 'suspicious' | 'malicious' | 'inconclusive'

/** The model-produced assessment portion of an AI audit (metadata is added by the Host). */
export interface AiAssessment {
  readonly verdict: AiVerdict
  readonly risk: RiskLevel
  /** One or two sentences of human-readable risk assessment. */
  readonly summary: string
  readonly concerns: string[]
  readonly recommendations: string[]
}

/** GitHub repository + owner intelligence gathered to judge fake/sockpuppet/fresh repos. */
export interface GithubEvidence {
  /** Parsed `owner/repo` full name; empty when no GitHub repo resolved. */
  fullName: string
  /** Repo html url; empty when none. */
  htmlUrl: string
  description: string
  /** Total stars; -1 unknown. */
  stars: number
  forks: number
  /** Whether the repo is archived. */
  archived: boolean
  /** Repo created_at ISO; empty unknown. */
  createdAt: string
  /** Repo pushed_at ISO; empty unknown. */
  pushedAt: string
  /** Owner account created_at ISO (account age); empty unknown. */
  ownerCreatedAt: string
  /** Owner's public repo count; -1 unknown. */
  ownerPublicRepos: number
  /** Owner's followers; -1 unknown. */
  ownerFollowers: number
  /** Human-readable lookup failures (rate limit etc.). */
  note: string
}

/** One web-search hit gathered while looking for reports of a plugin being malicious. */
export interface WebSearchHit {
  readonly title: string
  /** Result URL (http/https only; empty when the engine did not expose one). */
  readonly url: string
  /** Search-engine snippet describing the result. */
  readonly snippet: string
}

/** One known-advisory record (vulnerability or malicious-package report) from OSV.dev. */
export interface AdvisoryFinding {
  /** Advisory id, e.g. `GHSA-…` or `MAL-2025-…`. */
  readonly id: string
  readonly summary: string
  /** True when the entry is explicitly a malicious-code report (id prefix `MAL-` or "malicious" summary). */
  readonly malicious: boolean
  /** Cross-referenced CVE/GHSA ids. */
  readonly aliases: string[]
  /** Advisory source label, e.g. `OSV.dev`. */
  readonly source: string
}

/** Internet-reputation evidence gathered for the model, returned verbatim with the verdict. */
export interface ReputationEvidence {
  npmDescription: string
  npmLatest: string
  npmHomepage: string
  npmRepository: string
  npmMaintainers: string[]
  npmCreated: string
  npmModified: string
  /** npm deprecation message for the latest version; empty when not deprecated. */
  npmDeprecated: string
  /** Weekly npm downloads; -1 when unknown. */
  weeklyDownloads: number
  /** Structured web-search hits from the malicious/attack-report lookup (title/url/snippet). */
  webSearchHits: WebSearchHit[]
  /** Known vulnerability / malicious-package advisories from OSV.dev (authoritative, keyless). */
  advisories: AdvisoryFinding[]
  /** GitHub repo + owner evidence. */
  github: GithubEvidence
  /** Human-readable lookup failures, e.g. "npm 未收录该包名". */
  note: string
}

/** The full AI audit result returned by `guard.getAiAudit`. */
export interface AiAuditResult extends AiAssessment {
  readonly pluginName: string
  readonly provider: string
  readonly model: string
  readonly generatedAt: string
  readonly reputation: ReputationEvidence
}

export const aiVerdictSchema = z.enum(['safe', 'suspicious', 'malicious', 'inconclusive'])

/** Lenient on `risk`: the Host derives it from the verdict when the model omits it. */
export const aiAssessmentSchema = z.object({
  verdict: aiVerdictSchema,
  risk: riskLevelSchema.optional(),
  summary: z.string().min(1),
  concerns: z.array(z.string()),
  recommendations: z.array(z.string()),
}).readonly()

export const githubEvidenceSchema = z.object({
  fullName: z.string(),
  htmlUrl: z.string(),
  description: z.string(),
  stars: z.number(),
  forks: z.number(),
  archived: z.boolean(),
  createdAt: z.string(),
  pushedAt: z.string(),
  ownerCreatedAt: z.string(),
  ownerPublicRepos: z.number(),
  ownerFollowers: z.number(),
  note: z.string(),
}).readonly()

export const webSearchHitSchema = z.object({
  title: z.string(),
  url: z.string(),
  snippet: z.string(),
}).readonly()

export const advisoryFindingSchema = z.object({
  id: z.string(),
  summary: z.string(),
  malicious: z.boolean(),
  aliases: z.array(z.string()),
  source: z.string(),
}).readonly()

export const reputationEvidenceSchema = z.object({
  npmDescription: z.string(),
  npmLatest: z.string(),
  npmHomepage: z.string(),
  npmRepository: z.string(),
  npmMaintainers: z.array(z.string()),
  npmCreated: z.string(),
  npmModified: z.string(),
  npmDeprecated: z.string(),
  weeklyDownloads: z.number(),
  webSearchHits: z.array(webSearchHitSchema),
  advisories: z.array(advisoryFindingSchema),
  github: githubEvidenceSchema,
  note: z.string(),
}).readonly()

export const aiAuditResultSchema = z.object({
  pluginName: z.string().min(1),
  provider: z.string().min(1),
  model: z.string().min(1),
  verdict: aiVerdictSchema,
  risk: riskLevelSchema,
  summary: z.string().min(1),
  concerns: z.array(z.string()),
  recommendations: z.array(z.string()),
  generatedAt: z.string().min(1),
  reputation: reputationEvidenceSchema,
}).readonly()

/** Phases an AI audit passes through; surfaced to the client for live progress. */
export type AuditPhase = 'collecting' | 'researching' | 'calling' | 'parsing' | 'done' | 'error'

/** Live progress of one AI audit, polled by the client while its RPC is in flight. */
export interface AuditProgress {
  readonly pluginName: string
  readonly phase: AuditPhase
  /** Phase-specific detail: evidence count, model id, or an error message. */
  readonly detail: string
  readonly startedAt: string
}

export const auditPhaseSchema = z.enum(['collecting', 'researching', 'calling', 'parsing', 'done', 'error'])
export const auditProgressSchema = z.object({
  pluginName: z.string().min(1),
  phase: auditPhaseSchema,
  detail: z.string(),
  startedAt: z.string().min(1),
}).readonly()

/** `null` when no audit is running for the requested plugin. */
export const auditStatusSchema = z.nullable(auditProgressSchema)

/**
 * Masked GitHub-token state surfaced to the panel. The token string itself
 * never crosses the wire — only whether one is configured.
 */
export interface GithubTokenStatus {
  readonly configured: boolean
}

export const githubTokenStatusSchema = z.object({
  configured: z.boolean(),
}).readonly()

/** The plugin-guard Remote namespace's strict invocation descriptors. */
export const GUARD_INVOCATIONS: readonly InvocationDescriptor[] = [
  {
    id: 'dsh-plugin-guard#guard/getReport',
    service: 'guard',
    namespace: 'guard',
    method: 'getReport',
    invocation: { kind: 'direct' },
    parameters: [],
    result: {
      mode: 'strict',
      typeSymbol: 'dsh-plugin-guard#SecurityReport',
      schema: securityReportSchema,
    },
  },
  {
    id: 'dsh-plugin-guard#guard/getAiAudit',
    service: 'guard',
    namespace: 'guard',
    method: 'getAiAudit',
    invocation: { kind: 'direct' },
    parameters: [
      {
        name: 'pluginName',
        wire: 'pluginName',
        source: 'json',
        codec: {
          mode: 'strict',
          typeSymbol: 'dsh-plugin-guard#guard/getAiAudit:pluginName',
          schema: z.string().min(1),
        },
      },
    ],
    result: {
      mode: 'strict',
      typeSymbol: 'dsh-plugin-guard#AiAuditResult',
      schema: aiAuditResultSchema,
    },
  },
  {
    id: 'dsh-plugin-guard#guard/getAiAuditStatus',
    service: 'guard',
    namespace: 'guard',
    method: 'getAiAuditStatus',
    invocation: { kind: 'direct' },
    parameters: [
      {
        name: 'pluginName',
        wire: 'pluginName',
        source: 'json',
        codec: {
          mode: 'strict',
          typeSymbol: 'dsh-plugin-guard#guard/getAiAuditStatus:pluginName',
          schema: z.string().min(1),
        },
      },
    ],
    result: {
      mode: 'strict',
      typeSymbol: 'dsh-plugin-guard#AuditProgress | null',
      schema: auditStatusSchema,
    },
  },
  {
    id: 'dsh-plugin-guard#guard/getGithubTokenStatus',
    service: 'guard',
    namespace: 'guard',
    method: 'getGithubTokenStatus',
    invocation: { kind: 'direct' },
    parameters: [],
    result: {
      mode: 'strict',
      typeSymbol: 'dsh-plugin-guard#GithubTokenStatus',
      schema: githubTokenStatusSchema,
    },
  },
  {
    id: 'dsh-plugin-guard#guard/setGithubToken',
    service: 'guard',
    namespace: 'guard',
    method: 'setGithubToken',
    invocation: { kind: 'direct' },
    parameters: [
      {
        name: 'token',
        wire: 'token',
        source: 'json',
        codec: {
          mode: 'strict',
          typeSymbol: 'dsh-plugin-guard#guard/setGithubToken:token',
          schema: z.string(),
        },
      },
    ],
    result: {
      mode: 'strict',
      typeSymbol: 'dsh-plugin-guard#GithubTokenStatus',
      schema: githubTokenStatusSchema,
    },
  },
]