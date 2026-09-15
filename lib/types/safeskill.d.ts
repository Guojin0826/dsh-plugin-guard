import type { SafeSkillReport, SkillEntry, SafeSkillCacheEntry, SkillScanResult } from './contracts.ts';
/** Enumerate installed skills: every `$DSH_HOME/skills/<name>` with a SKILL.md. */
export declare function listLocalSkills(): SkillEntry[];
/** Full single-skill scan: discover → pack → submit → poll → normalized verdict. */
export declare function runSafeSkillScan(skillName: string, apiKey: string): Promise<SafeSkillReport>;
/**
 * Read one skill's files as UTF-8 text for the AI fallback audit — the same
 * walk (symlinks / VCS / dep dirs skipped, size-capped) the SafeSkill upload
 * uses, so the AI sees exactly what would have been submitted.
 *
 * Binary payloads are not decoded: dumping a PNG as text burns the prompt
 * budget on replacement characters and tells the model nothing. They are kept
 * as a one-line placeholder instead, because a binary blob inside a skill that
 * claims to be a Markdown instruction bundle is itself a finding worth judging.
 */
export declare function readSkillSources(skillName: string): {
    path: string;
    text: string;
}[];
/** Compute a SHA-256 hex digest of the skill's zip content (same bytes submitted to SafeSkill). */
export declare function computeSkillContentHash(skillName: string): string;
/** Read the on-disk SafeSkill result cache, returning an empty object on any failure. */
export declare function loadSafeSkillCache(): Record<string, SafeSkillCacheEntry>;
/** Persist the SafeSkill result cache atomically. Silently swallows IO errors. */
export declare function saveSafeSkillCache(cache: Record<string, SafeSkillCacheEntry>): void;
/**
 * Cache-aware single-skill scan: checks the local content-hash cache first,
 * falls back to a full SafeSkill submit+poll cycle on miss, and caches the
 * result for future lookups.
 */
export declare function scanSkillWithCache(skillName: string, apiKey: string): Promise<{
    report: SafeSkillReport;
    fromCache: boolean;
}>;
/** Return every currently-cached scan result (for the panel snapshot restore RPC). */
export declare function getCachedResults(): SkillScanResult[];
