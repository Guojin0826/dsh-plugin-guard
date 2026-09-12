import type { SafeSkillReport, SkillEntry } from './contracts.ts';
/** Enumerate installed skills: every `$DSH_HOME/skills/<name>` with a SKILL.md. */
export declare function listLocalSkills(): SkillEntry[];
/** Full single-skill scan: discover → pack → submit → poll → normalized verdict. */
export declare function runSafeSkillScan(skillName: string, apiKey: string): Promise<SafeSkillReport>;
