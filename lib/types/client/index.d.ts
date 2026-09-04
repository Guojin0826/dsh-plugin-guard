import type { Context as ClientContext } from '@deepseek-ai/cordis';
/** Required services: the Remote face, the slot registry, and locale. */
export declare const inject: string[];
/** Compose the security-report surface. */
export declare function apply(ctx: ClientContext): void;
