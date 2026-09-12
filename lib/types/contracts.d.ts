/**
 * dsh-plugin-guard wire contract, shared verbatim by the host manifest
 * (`ctx.typert.register` in typert.ts) and the client contribution
 * (`ctx.remote.$mount` in client/remote.ts). It carries the audit report
 * shape plus its strict zod codecs, and the single `guard.getReport` wire
 * descriptor. No Node-only imports live in this module, so the browser bundle
 * can share it without pulling `node:fs`/`node:path`.
 */
import { z } from 'zod';
import type { InvocationDescriptor } from '@deepseek-ai/dsh-typert-protocol';
export type Severity = 'high' | 'medium' | 'low';
export type RiskLevel = 'red' | 'yellow' | 'green';
/** One dangerous-pattern match, aggregated per rule across files. */
export interface ScanFlag {
    /** Stable rule code, e.g. `child-process`. */
    readonly code: string;
    readonly severity: Severity;
    /** Human-readable label, e.g. "子进程执行". */
    readonly label: string;
    /** Plugin-relative source files where the pattern matched (bounded). */
    readonly files: string[];
}
/** One reviewed dependency of an audited plugin. */
export interface DepFinding {
    readonly name: string;
    readonly version: string;
    readonly suspicious: boolean;
    readonly reason?: string;
}
/** One declared host-service dependency (`inject` entry) with its power tier. */
export interface PermissionFinding {
    /** Raw service name / package id as declared, e.g. `llm` or `@deepseek-ai/dsh-api-remotes`. */
    readonly name: string;
    readonly severity: Severity;
    /** Plain-language note on what this grants. */
    readonly label: string;
}
/** Per-plugin audit result. */
export interface PluginAudit {
    readonly name: string;
    readonly version: string;
    /** Whether the package is an active profile layer (`dsh.profile.bundles`). */
    readonly active: boolean;
    /** Raw dependency spec from the profile manifest (npm range / link / file / git). */
    readonly source: string;
    readonly risk: RiskLevel;
    /** 0–100, higher = riskier. */
    readonly score: number;
    readonly flags: ScanFlag[];
    readonly dependencies: DepFinding[];
    readonly scannedFiles: number;
    /** Declared host-service dependencies (`entry.inject` + `dsh.client.inject`), each power-tiered. */
    readonly permissions: PermissionFinding[];
    /** 0–100 weighted score of declared host-service power (same weights as the static score). */
    readonly permScore: number;
    /** True when code has high-severity capabilities but the plugin only declares low-power services. */
    readonly capabilityMismatch: boolean;
    readonly errors: string[];
}
/** What changed for one plugin since the previous scan's baseline (version-diff alerting). */
export interface PluginDelta {
    readonly name: string;
    /** True when the plugin was absent from the previous baseline (newly installed). */
    readonly isNew: boolean;
    readonly previousVersion: string;
    readonly currentVersion: string;
    /** Rule codes present now but not in the baseline. */
    readonly addedFlags: string[];
    /** Declared host services added since the baseline. */
    readonly addedPerms: string[];
}
/** The full audit report returned by `guard.getReport`. */
export interface SecurityReport {
    readonly generatedAt: string;
    readonly dshHome: string;
    readonly profile: string;
    readonly pluginCount: number;
    readonly redCount: number;
    readonly yellowCount: number;
    readonly greenCount: number;
    readonly plugins: PluginAudit[];
    /** Per-plugin changes since the previous scan (empty on the first scan). */
    readonly deltas: PluginDelta[];
}
export declare const severitySchema: z.ZodEnum<{
    high: "high";
    medium: "medium";
    low: "low";
}>;
export declare const riskLevelSchema: z.ZodEnum<{
    red: "red";
    yellow: "yellow";
    green: "green";
}>;
export declare const scanFlagSchema: z.ZodReadonly<z.ZodObject<{
    code: z.ZodString;
    severity: z.ZodEnum<{
        high: "high";
        medium: "medium";
        low: "low";
    }>;
    label: z.ZodString;
    files: z.ZodArray<z.ZodString>;
}, z.core.$strip>>;
export declare const depFindingSchema: z.ZodReadonly<z.ZodObject<{
    name: z.ZodString;
    version: z.ZodString;
    suspicious: z.ZodBoolean;
    reason: z.ZodOptional<z.ZodString>;
}, z.core.$strip>>;
export declare const permissionFindingSchema: z.ZodReadonly<z.ZodObject<{
    name: z.ZodString;
    severity: z.ZodEnum<{
        high: "high";
        medium: "medium";
        low: "low";
    }>;
    label: z.ZodString;
}, z.core.$strip>>;
export declare const pluginAuditSchema: z.ZodReadonly<z.ZodObject<{
    name: z.ZodString;
    version: z.ZodString;
    active: z.ZodBoolean;
    source: z.ZodString;
    risk: z.ZodEnum<{
        red: "red";
        yellow: "yellow";
        green: "green";
    }>;
    score: z.ZodNumber;
    flags: z.ZodArray<z.ZodReadonly<z.ZodObject<{
        code: z.ZodString;
        severity: z.ZodEnum<{
            high: "high";
            medium: "medium";
            low: "low";
        }>;
        label: z.ZodString;
        files: z.ZodArray<z.ZodString>;
    }, z.core.$strip>>>;
    dependencies: z.ZodArray<z.ZodReadonly<z.ZodObject<{
        name: z.ZodString;
        version: z.ZodString;
        suspicious: z.ZodBoolean;
        reason: z.ZodOptional<z.ZodString>;
    }, z.core.$strip>>>;
    scannedFiles: z.ZodNumber;
    permissions: z.ZodArray<z.ZodReadonly<z.ZodObject<{
        name: z.ZodString;
        severity: z.ZodEnum<{
            high: "high";
            medium: "medium";
            low: "low";
        }>;
        label: z.ZodString;
    }, z.core.$strip>>>;
    permScore: z.ZodNumber;
    capabilityMismatch: z.ZodBoolean;
    errors: z.ZodArray<z.ZodString>;
}, z.core.$strip>>;
export declare const pluginDeltaSchema: z.ZodReadonly<z.ZodObject<{
    name: z.ZodString;
    isNew: z.ZodBoolean;
    previousVersion: z.ZodString;
    currentVersion: z.ZodString;
    addedFlags: z.ZodArray<z.ZodString>;
    addedPerms: z.ZodArray<z.ZodString>;
}, z.core.$strip>>;
export declare const securityReportSchema: z.ZodReadonly<z.ZodObject<{
    generatedAt: z.ZodString;
    dshHome: z.ZodString;
    profile: z.ZodString;
    pluginCount: z.ZodNumber;
    redCount: z.ZodNumber;
    yellowCount: z.ZodNumber;
    greenCount: z.ZodNumber;
    plugins: z.ZodArray<z.ZodReadonly<z.ZodObject<{
        name: z.ZodString;
        version: z.ZodString;
        active: z.ZodBoolean;
        source: z.ZodString;
        risk: z.ZodEnum<{
            red: "red";
            yellow: "yellow";
            green: "green";
        }>;
        score: z.ZodNumber;
        flags: z.ZodArray<z.ZodReadonly<z.ZodObject<{
            code: z.ZodString;
            severity: z.ZodEnum<{
                high: "high";
                medium: "medium";
                low: "low";
            }>;
            label: z.ZodString;
            files: z.ZodArray<z.ZodString>;
        }, z.core.$strip>>>;
        dependencies: z.ZodArray<z.ZodReadonly<z.ZodObject<{
            name: z.ZodString;
            version: z.ZodString;
            suspicious: z.ZodBoolean;
            reason: z.ZodOptional<z.ZodString>;
        }, z.core.$strip>>>;
        scannedFiles: z.ZodNumber;
        permissions: z.ZodArray<z.ZodReadonly<z.ZodObject<{
            name: z.ZodString;
            severity: z.ZodEnum<{
                high: "high";
                medium: "medium";
                low: "low";
            }>;
            label: z.ZodString;
        }, z.core.$strip>>>;
        permScore: z.ZodNumber;
        capabilityMismatch: z.ZodBoolean;
        errors: z.ZodArray<z.ZodString>;
    }, z.core.$strip>>>;
    deltas: z.ZodArray<z.ZodReadonly<z.ZodObject<{
        name: z.ZodString;
        isNew: z.ZodBoolean;
        previousVersion: z.ZodString;
        currentVersion: z.ZodString;
        addedFlags: z.ZodArray<z.ZodString>;
        addedPerms: z.ZodArray<z.ZodString>;
    }, z.core.$strip>>>;
}, z.core.$strip>>;
/** The model's security verdict for one plugin. */
export type AiVerdict = 'safe' | 'suspicious' | 'malicious' | 'inconclusive';
/** The model-produced assessment portion of an AI audit (metadata is added by the Host). */
export interface AiAssessment {
    readonly verdict: AiVerdict;
    readonly risk: RiskLevel;
    /** 0–100 overall risk score assigned by the model after the audit (higher = riskier). */
    readonly score: number;
    /** One or two sentences of human-readable risk assessment. */
    readonly summary: string;
    readonly concerns: string[];
    readonly recommendations: string[];
}
/** GitHub repository + owner intelligence gathered to judge fake/sockpuppet/fresh repos. */
export interface GithubEvidence {
    /** Parsed `owner/repo` full name; empty when no GitHub repo resolved. */
    fullName: string;
    /** Repo html url; empty when none. */
    htmlUrl: string;
    description: string;
    /** Total stars; -1 unknown. */
    stars: number;
    forks: number;
    /** Whether the repo is archived. */
    archived: boolean;
    /** Repo created_at ISO; empty unknown. */
    createdAt: string;
    /** Repo pushed_at ISO; empty unknown. */
    pushedAt: string;
    /** Owner account created_at ISO (account age); empty unknown. */
    ownerCreatedAt: string;
    /** Owner's public repo count; -1 unknown. */
    ownerPublicRepos: number;
    /** Owner's followers; -1 unknown. */
    ownerFollowers: number;
    /** Open issue count; -1 unknown. */
    openIssues: number;
    /** SPDX license id (e.g. `MIT`); empty when the repo declares none. */
    license: string;
    /** Whether the repo ships a SECURITY.md (maintenance security hygiene). */
    hasSecurityPolicy: boolean;
    /** Human-readable lookup failures (rate limit etc.). */
    note: string;
}
/** One web-search hit gathered while looking for reports of a plugin being malicious. */
export interface WebSearchHit {
    readonly title: string;
    /** Result URL (http/https only; empty when the engine did not expose one). */
    readonly url: string;
    /** Search-engine snippet describing the result. */
    readonly snippet: string;
}
/** One known-advisory record (vulnerability or malicious-package report) from OSV.dev. */
export interface AdvisoryFinding {
    /** Advisory id, e.g. `GHSA-…` or `MAL-2025-…`. */
    readonly id: string;
    readonly summary: string;
    /** True when the entry is explicitly a malicious-code report (id prefix `MAL-` or "malicious" summary). */
    readonly malicious: boolean;
    /** Cross-referenced CVE/GHSA ids. */
    readonly aliases: string[];
    /** Advisory source label, e.g. `OSV.dev`. */
    readonly source: string;
}
/** One resolved direct dependency and the advisories found for it (empty = clean). */
export interface DependencyFinding {
    readonly name: string;
    readonly version: string;
    readonly advisories: AdvisoryFinding[];
}
/** Internet-reputation evidence gathered for the model, returned verbatim with the verdict. */
export interface ReputationEvidence {
    npmDescription: string;
    npmLatest: string;
    npmHomepage: string;
    npmRepository: string;
    npmMaintainers: string[];
    npmCreated: string;
    npmModified: string;
    /** npm deprecation message for the latest version; empty when not deprecated. */
    npmDeprecated: string;
    /** Weekly npm downloads; -1 when unknown. */
    weeklyDownloads: number;
    /** Structured web-search hits from the malicious/attack-report lookup (title/url/snippet). */
    webSearchHits: WebSearchHit[];
    /** Known vulnerability / malicious-package advisories from OSV.dev (authoritative, keyless). */
    advisories: AdvisoryFinding[];
    /** GitHub repo + owner evidence. */
    github: GithubEvidence;
    /** Known vulnerabilities in the plugin's resolved direct dependencies (OSV.dev batch). */
    dependencyAdvisories: DependencyFinding[];
    /** Human-readable lookup failures, e.g. "npm 未收录该包名". */
    note: string;
}
/** The full AI audit result returned by `guard.getAiAudit`. */
export interface AiAuditResult extends AiAssessment {
    readonly pluginName: string;
    readonly provider: string;
    readonly model: string;
    readonly generatedAt: string;
    /** True when served from the content-fingerprint cache rather than a fresh model call. */
    readonly cached: boolean;
    readonly reputation: ReputationEvidence;
}
export declare const aiVerdictSchema: z.ZodEnum<{
    suspicious: "suspicious";
    safe: "safe";
    malicious: "malicious";
    inconclusive: "inconclusive";
}>;
/** Lenient on `risk`: the Host derives it from the verdict when the model omits it. */
export declare const aiAssessmentSchema: z.ZodReadonly<z.ZodObject<{
    verdict: z.ZodEnum<{
        suspicious: "suspicious";
        safe: "safe";
        malicious: "malicious";
        inconclusive: "inconclusive";
    }>;
    risk: z.ZodOptional<z.ZodEnum<{
        red: "red";
        yellow: "yellow";
        green: "green";
    }>>;
    score: z.ZodOptional<z.ZodNumber>;
    summary: z.ZodString;
    concerns: z.ZodArray<z.ZodString>;
    recommendations: z.ZodArray<z.ZodString>;
}, z.core.$strip>>;
export declare const githubEvidenceSchema: z.ZodReadonly<z.ZodObject<{
    fullName: z.ZodString;
    htmlUrl: z.ZodString;
    description: z.ZodString;
    stars: z.ZodNumber;
    forks: z.ZodNumber;
    archived: z.ZodBoolean;
    createdAt: z.ZodString;
    pushedAt: z.ZodString;
    ownerCreatedAt: z.ZodString;
    ownerPublicRepos: z.ZodNumber;
    ownerFollowers: z.ZodNumber;
    openIssues: z.ZodNumber;
    license: z.ZodString;
    hasSecurityPolicy: z.ZodBoolean;
    note: z.ZodString;
}, z.core.$strip>>;
export declare const webSearchHitSchema: z.ZodReadonly<z.ZodObject<{
    title: z.ZodString;
    url: z.ZodString;
    snippet: z.ZodString;
}, z.core.$strip>>;
export declare const advisoryFindingSchema: z.ZodReadonly<z.ZodObject<{
    id: z.ZodString;
    summary: z.ZodString;
    malicious: z.ZodBoolean;
    aliases: z.ZodArray<z.ZodString>;
    source: z.ZodString;
}, z.core.$strip>>;
export declare const dependencyFindingSchema: z.ZodReadonly<z.ZodObject<{
    name: z.ZodString;
    version: z.ZodString;
    advisories: z.ZodArray<z.ZodReadonly<z.ZodObject<{
        id: z.ZodString;
        summary: z.ZodString;
        malicious: z.ZodBoolean;
        aliases: z.ZodArray<z.ZodString>;
        source: z.ZodString;
    }, z.core.$strip>>>;
}, z.core.$strip>>;
export declare const reputationEvidenceSchema: z.ZodReadonly<z.ZodObject<{
    npmDescription: z.ZodString;
    npmLatest: z.ZodString;
    npmHomepage: z.ZodString;
    npmRepository: z.ZodString;
    npmMaintainers: z.ZodArray<z.ZodString>;
    npmCreated: z.ZodString;
    npmModified: z.ZodString;
    npmDeprecated: z.ZodString;
    weeklyDownloads: z.ZodNumber;
    webSearchHits: z.ZodArray<z.ZodReadonly<z.ZodObject<{
        title: z.ZodString;
        url: z.ZodString;
        snippet: z.ZodString;
    }, z.core.$strip>>>;
    advisories: z.ZodArray<z.ZodReadonly<z.ZodObject<{
        id: z.ZodString;
        summary: z.ZodString;
        malicious: z.ZodBoolean;
        aliases: z.ZodArray<z.ZodString>;
        source: z.ZodString;
    }, z.core.$strip>>>;
    github: z.ZodReadonly<z.ZodObject<{
        fullName: z.ZodString;
        htmlUrl: z.ZodString;
        description: z.ZodString;
        stars: z.ZodNumber;
        forks: z.ZodNumber;
        archived: z.ZodBoolean;
        createdAt: z.ZodString;
        pushedAt: z.ZodString;
        ownerCreatedAt: z.ZodString;
        ownerPublicRepos: z.ZodNumber;
        ownerFollowers: z.ZodNumber;
        openIssues: z.ZodNumber;
        license: z.ZodString;
        hasSecurityPolicy: z.ZodBoolean;
        note: z.ZodString;
    }, z.core.$strip>>;
    dependencyAdvisories: z.ZodArray<z.ZodReadonly<z.ZodObject<{
        name: z.ZodString;
        version: z.ZodString;
        advisories: z.ZodArray<z.ZodReadonly<z.ZodObject<{
            id: z.ZodString;
            summary: z.ZodString;
            malicious: z.ZodBoolean;
            aliases: z.ZodArray<z.ZodString>;
            source: z.ZodString;
        }, z.core.$strip>>>;
    }, z.core.$strip>>>;
    note: z.ZodString;
}, z.core.$strip>>;
export declare const aiAuditResultSchema: z.ZodReadonly<z.ZodObject<{
    pluginName: z.ZodString;
    provider: z.ZodString;
    model: z.ZodString;
    verdict: z.ZodEnum<{
        suspicious: "suspicious";
        safe: "safe";
        malicious: "malicious";
        inconclusive: "inconclusive";
    }>;
    risk: z.ZodEnum<{
        red: "red";
        yellow: "yellow";
        green: "green";
    }>;
    score: z.ZodNumber;
    summary: z.ZodString;
    concerns: z.ZodArray<z.ZodString>;
    recommendations: z.ZodArray<z.ZodString>;
    generatedAt: z.ZodString;
    cached: z.ZodBoolean;
    reputation: z.ZodReadonly<z.ZodObject<{
        npmDescription: z.ZodString;
        npmLatest: z.ZodString;
        npmHomepage: z.ZodString;
        npmRepository: z.ZodString;
        npmMaintainers: z.ZodArray<z.ZodString>;
        npmCreated: z.ZodString;
        npmModified: z.ZodString;
        npmDeprecated: z.ZodString;
        weeklyDownloads: z.ZodNumber;
        webSearchHits: z.ZodArray<z.ZodReadonly<z.ZodObject<{
            title: z.ZodString;
            url: z.ZodString;
            snippet: z.ZodString;
        }, z.core.$strip>>>;
        advisories: z.ZodArray<z.ZodReadonly<z.ZodObject<{
            id: z.ZodString;
            summary: z.ZodString;
            malicious: z.ZodBoolean;
            aliases: z.ZodArray<z.ZodString>;
            source: z.ZodString;
        }, z.core.$strip>>>;
        github: z.ZodReadonly<z.ZodObject<{
            fullName: z.ZodString;
            htmlUrl: z.ZodString;
            description: z.ZodString;
            stars: z.ZodNumber;
            forks: z.ZodNumber;
            archived: z.ZodBoolean;
            createdAt: z.ZodString;
            pushedAt: z.ZodString;
            ownerCreatedAt: z.ZodString;
            ownerPublicRepos: z.ZodNumber;
            ownerFollowers: z.ZodNumber;
            openIssues: z.ZodNumber;
            license: z.ZodString;
            hasSecurityPolicy: z.ZodBoolean;
            note: z.ZodString;
        }, z.core.$strip>>;
        dependencyAdvisories: z.ZodArray<z.ZodReadonly<z.ZodObject<{
            name: z.ZodString;
            version: z.ZodString;
            advisories: z.ZodArray<z.ZodReadonly<z.ZodObject<{
                id: z.ZodString;
                summary: z.ZodString;
                malicious: z.ZodBoolean;
                aliases: z.ZodArray<z.ZodString>;
                source: z.ZodString;
            }, z.core.$strip>>>;
        }, z.core.$strip>>>;
        note: z.ZodString;
    }, z.core.$strip>>;
}, z.core.$strip>>;
/** Phases an AI audit passes through; surfaced to the client for live progress. */
export type AuditPhase = 'collecting' | 'researching' | 'calling' | 'parsing' | 'done' | 'error';
/** Live progress of one AI audit, polled by the client while its RPC is in flight. */
export interface AuditProgress {
    readonly pluginName: string;
    readonly phase: AuditPhase;
    /** Phase-specific detail: evidence count, model id, or an error message. */
    readonly detail: string;
    readonly startedAt: string;
}
export declare const auditPhaseSchema: z.ZodEnum<{
    error: "error";
    collecting: "collecting";
    researching: "researching";
    calling: "calling";
    parsing: "parsing";
    done: "done";
}>;
export declare const auditProgressSchema: z.ZodReadonly<z.ZodObject<{
    pluginName: z.ZodString;
    phase: z.ZodEnum<{
        error: "error";
        collecting: "collecting";
        researching: "researching";
        calling: "calling";
        parsing: "parsing";
        done: "done";
    }>;
    detail: z.ZodString;
    startedAt: z.ZodString;
}, z.core.$strip>>;
/** `null` when no audit is running for the requested plugin. */
export declare const auditStatusSchema: z.ZodNullable<z.ZodReadonly<z.ZodObject<{
    pluginName: z.ZodString;
    phase: z.ZodEnum<{
        error: "error";
        collecting: "collecting";
        researching: "researching";
        calling: "calling";
        parsing: "parsing";
        done: "done";
    }>;
    detail: z.ZodString;
    startedAt: z.ZodString;
}, z.core.$strip>>>;
/**
 * Masked GitHub-token state surfaced to the panel. The token string itself
 * never crosses the wire — only whether one is configured.
 */
export interface GithubTokenStatus {
    readonly configured: boolean;
}
export declare const githubTokenStatusSchema: z.ZodReadonly<z.ZodObject<{
    configured: z.ZodBoolean;
}, z.core.$strip>>;
/** Cache settings for the AI-audit result cache (content fingerprint + version + TTL). */
export interface AuditCacheConfig {
    /** Hours a cached verdict stays fresh before a forced re-audit; 0 disables the cache. */
    readonly ttlHours: number;
}
export declare const auditCacheConfigSchema: z.ZodReadonly<z.ZodObject<{
    ttlHours: z.ZodNumber;
}, z.core.$strip>>;
/** SafeSkill threat level, normalized from the API's `summary.threat_level`. */
export type SafeSkillThreat = 'malicious' | 'suspicious' | 'unknown' | 'clean';
/** One risk indicator surfaced by SafeSkill's multi-engine analysis. */
export interface SafeSkillIndicator {
    readonly indicator: string;
    readonly category: string;
    readonly severity: Severity;
    readonly evidence: string;
    readonly sources: readonly {
        file: string;
        lines: string;
    }[];
}
/** Normalized single-skill SafeSkill verdict returned by `guard.scanSkill`. */
export interface SafeSkillReport {
    readonly skillName: string;
    readonly sha256: string;
    readonly threatLevel: SafeSkillThreat;
    /** Malware family / classification label, e.g. `Trojan`; empty when none. */
    readonly threatClassify: string;
    /** 0–100 trust score; -1 when the API did not return one. */
    readonly trustScore: number;
    readonly multiVerdict: Record<string, string>;
    readonly indicators: SafeSkillIndicator[];
    readonly permalink: string;
}
/** Masked SafeSkill API-key state (the key itself is never returned). */
export interface SafeSkillStatus {
    readonly configured: boolean;
}
/** One locally installed DSH skill discovered under `$DSH_HOME/skills`. */
export interface SkillEntry {
    readonly name: string;
    readonly description: string;
}
export declare const safeSkillThreatSchema: z.ZodEnum<{
    unknown: "unknown";
    suspicious: "suspicious";
    malicious: "malicious";
    clean: "clean";
}>;
export declare const safeSkillIndicatorSchema: z.ZodReadonly<z.ZodObject<{
    indicator: z.ZodString;
    category: z.ZodString;
    severity: z.ZodEnum<{
        high: "high";
        medium: "medium";
        low: "low";
    }>;
    evidence: z.ZodString;
    sources: z.ZodArray<z.ZodObject<{
        file: z.ZodString;
        lines: z.ZodString;
    }, z.core.$strip>>;
}, z.core.$strip>>;
export declare const safeSkillReportSchema: z.ZodReadonly<z.ZodObject<{
    skillName: z.ZodString;
    sha256: z.ZodString;
    threatLevel: z.ZodEnum<{
        unknown: "unknown";
        suspicious: "suspicious";
        malicious: "malicious";
        clean: "clean";
    }>;
    threatClassify: z.ZodString;
    trustScore: z.ZodNumber;
    multiVerdict: z.ZodRecord<z.ZodString, z.ZodString>;
    indicators: z.ZodArray<z.ZodReadonly<z.ZodObject<{
        indicator: z.ZodString;
        category: z.ZodString;
        severity: z.ZodEnum<{
            high: "high";
            medium: "medium";
            low: "low";
        }>;
        evidence: z.ZodString;
        sources: z.ZodArray<z.ZodObject<{
            file: z.ZodString;
            lines: z.ZodString;
        }, z.core.$strip>>;
    }, z.core.$strip>>>;
    permalink: z.ZodString;
}, z.core.$strip>>;
export declare const safeSkillStatusSchema: z.ZodReadonly<z.ZodObject<{
    configured: z.ZodBoolean;
}, z.core.$strip>>;
export declare const skillEntrySchema: z.ZodReadonly<z.ZodObject<{
    name: z.ZodString;
    description: z.ZodString;
}, z.core.$strip>>;
/** The plugin-guard Remote namespace's strict invocation descriptors. */
export declare const GUARD_INVOCATIONS: readonly InvocationDescriptor[];
