import type { PluginAudit, PluginDelta, SecurityReport, Severity } from './contracts.ts';
export declare function isSafePackageName(name: string): boolean;
/** A plugin dependency resolved to an installed name + version. */
export interface InstalledDependency {
    name: string;
    version: string;
}
/**
 * Read the plugin's RESOLVED direct runtime dependencies by walking its own
 * `node_modules` (one level, plus scoped `@scope/pkg`). With pnpm these top-level
 * entries are symlinks into the store, and reading their package.json follows the
 * symlink to the real exact version. Cross-filtered against the declared
 * `dependencies` / `optionalDependencies` / `peerDependencies` so a dev-checkout's
 * toolchain (typescript, esbuild, …) does not masquerade as runtime dependencies.
 */
export declare function readInstalledDependencies(pluginDir: string): InstalledDependency[];
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
    /** GitHub repo URLs found anywhere in the FULL README (drives repo resolution, not the prompt). */
    readmeGithubUrls: string[];
    /** dsh.plugin.json description when present. */
    manifestDescription: string;
}
/** All github.com owner/repo URLs mentioned in arbitrary text (README, homepage, etc.). */
export declare function findGithubUrls(text: string): string[];
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
/** One plugin's persisted state from the previous scan, for version-diff alerting. */
export interface BaselineEntry {
    readonly version: string;
    readonly flags: readonly string[];
    readonly perms: readonly string[];
}
/** The persisted baseline snapshot: plugin name → its last-seen state. */
export type BaselineSnapshot = Record<string, BaselineEntry>;
/** Build the baseline snapshot to persist from a fresh audit. */
export declare function buildBaseline(plugins: PluginAudit[]): BaselineSnapshot;
/**
 * Diff a fresh audit against the previous baseline: one delta per plugin that is
 * newly installed, changed version, or gained flags/permissions. An empty
 * baseline (first scan) yields no deltas — there is nothing to compare against.
 */
export declare function computePluginDeltas(plugins: PluginAudit[], baseline: BaselineSnapshot): PluginDelta[];
/**
 * Content fingerprint of everything the AI audit actually reads for one plugin:
 * version, package.json, dsh.plugin.json, README, and every scanned source file.
 * Equal fingerprints mean identical audit inputs, so a cached verdict stays valid.
 * Hashing is content-based (not flag-based), so even a one-byte source change
 * invalidates the fingerprint and forces a re-audit.
 */
export declare function computePluginFingerprint(pluginDir: string, version: string, modelKey?: string): string;
