export declare const NS = "dsh-plugin-guard";
export declare const zh: Record<string, string>;
export declare const en: Record<string, string>;
/** The guard locale namespace's dictionary key domain. */
export type GuardKey = keyof typeof zh;
declare module '@deepseek-ai/dsh-client-ui-slots' {
    interface LocaleNamespaceMap {
        [NS]: GuardKey;
    }
}
