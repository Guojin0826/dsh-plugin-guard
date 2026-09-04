/**
 * The hand-written host Typert manifest for the guard Remote. Registered
 * through `ctx.typert.register` in the plugin body, it claims the wire
 * endpoint through the strict registry — the same path generated `./typert`
 * artifacts use. Keeping it hand-written (and decorator-independent) matters
 * in the harness's source-launch development environment, where the tsx-loaded
 * gateway and a profile-loaded plugin bundle can hold separate copies of the
 * decorator module state.
 */
import type { TypertContribution } from '@deepseek-ai/dsh-typert-registry/types';
/** The guard namespace's host manifest (strict codecs shared with the client). */
export declare const TYPERT_MANIFEST: TypertContribution;
