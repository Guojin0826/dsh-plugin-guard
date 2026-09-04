/**
 * dsh-plugin-guard host plugin: mounts the `guard` Typert Remote service
 * (static source + dependency audit of the profile's installed plugins) and
 * registers its strict Typert manifest. On load it performs an initial audit
 * and logs a summary; the Web client renders the full report on demand.
 */
import type { Context } from '@deepseek-ai/cordis';
import z from '@deepseek-ai/schemastery';
/** Cordis plugin name (the Loader entry and client bundle id). */
export declare const name = "dsh-plugin-guard";
/** Services required before load: the Typert registry, plus the LLM runtime and default-model selection for AI audit. */
export declare const inject: string[];
/** Host plugin configuration, validated at load by the Loader. */
export interface Config {
    /** Profile name under `$DSH_HOME/profiles` to audit. */
    profile: string;
    /** Hard cap on source files scanned per plugin. */
    maxScanFiles: number;
    /** Optional GitHub PAT for authenticated repo/owner lookups (raises the 60/h limit to 5000/h). */
    githubToken: string;
}
/** Configuration schema: defaults apply when the callable schema is invoked with `{}`. */
export declare const Config: z<Schemastery.ObjectS<{
    profile: z<string, string>;
    maxScanFiles: z<number, number>;
    githubToken: z<string, string>;
}>, Schemastery.ObjectT<{
    profile: z<string, string>;
    maxScanFiles: z<number, number>;
    githubToken: z<string, string>;
}>>;
/**
 * Mount the guard service, register its Typert manifest, and log an initial
 * audit summary. The Remote re-runs the audit per call, so the client's
 * "rescan" button always reflects the current install state.
 * @param ctx - host cordis context.
 * @param config - validated plugin configuration (schema defaults applied).
 */
export declare function apply(ctx: Context, config?: Config): void;
