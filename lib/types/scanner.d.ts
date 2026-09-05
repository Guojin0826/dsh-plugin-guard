import type { SecurityReport, Severity } from './contracts.ts';
/** One extracted source line that matched a danger rule, for AI-audit evidence. */
export interface EvidenceSnippet {
    /** Plugin-relative file path. */
    readonly file: string;
    /** 1-based line number. */
    readonly line: number;
    readonly severity: Severity;
    /** Rule code, e.g. `child-process`. */
    readonly code: string;
    /** Rule label, e.g. "子进程执行". */
    readonly label: string;
    /** The matched line, trimmed and bounded. */
    readonly text: string;
}
/**
 * Extract bounded source-line evidence for AI auditing: walks one plugin's
 * source and, for each danger-rule match, records the file, line number, and
 * trimmed line text. Purely additive to the aggregate report — the Line/column
 * granularity here feeds the model's reasoning, not the static score.
 */
export declare function collectEvidence(pluginDir: string, maxSnippets: number): EvidenceSnippet[];
/** A plugin's self-declared purpose and publish metadata, for AI-audit consistency judgment. */
export interface PluginMetadata {
    /** package.json description (the plugin's stated purpose). */
    description: string;
    keywords: string[];
    author: string;
    repository: string;
    homepage: string;
    /** Install/postinstall scripts verbatim (supply-chain attack surface). */
    scripts: string;
    /** First ~3KB of README — the plugin's own documentation of what it does. */
    readmeExcerpt: string;
    /** dsh.plugin.json description when present. */
    manifestDescription: string;
}
/**
 * Read a plugin's self-description without executing it: package.json
 * (description/keywords/author/repository/homepage/scripts), the README's
 * first bytes, and the dsh.plugin.json description. The model uses this to
 * judge whether the dangerous capabilities match the plugin's stated job —
 * a file-manager plugin writing files is expected, a calculator that reads
 * SSH keys is not.
 */
export declare function collectPluginMetadata(pluginDir: string): PluginMetadata;
/** Run a full audit over one profile directory (contains package.json + node_modules). */
export declare function runAudit(profileDir: string, maxScanFiles: number): SecurityReport;
