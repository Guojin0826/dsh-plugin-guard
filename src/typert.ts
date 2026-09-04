/**
 * The hand-written host Typert manifest for the guard Remote. Registered
 * through `ctx.typert.register` in the plugin body, it claims the wire
 * endpoint through the strict registry — the same path generated `./typert`
 * artifacts use. Keeping it hand-written (and decorator-independent) matters
 * in the harness's source-launch development environment, where the tsx-loaded
 * gateway and a profile-loaded plugin bundle can hold separate copies of the
 * decorator module state.
 */
import type { TypertContribution } from '@deepseek-ai/dsh-typert-registry/types'
import { GUARD_INVOCATIONS } from './contracts.ts'

/** The guard namespace's host manifest (strict codecs shared with the client). */
export const TYPERT_MANIFEST: TypertContribution = {
  package: 'dsh-plugin-guard',
  face: 'host',
  schemas: [],
  model: {
    services: [
      {
        key: 'guard',
        exportName: 'GuardRuntime',
        description: 'Static security audit of installed plugins (source + dependency review).',
        tags: [],
        members: [
          {
            kind: 'method',
            name: 'getReport',
            signature: 'getReport(): Promise<SecurityReport>',
          },
          {
            kind: 'method',
            name: 'getAiAudit',
            signature: 'getAiAudit(pluginName: string): Promise<AiAuditResult>',
          },
          {
            kind: 'method',
            name: 'getAiAuditStatus',
            signature: 'getAiAuditStatus(pluginName: string): Promise<AuditProgress | null>',
          },
          {
            kind: 'method',
            name: 'getGithubTokenStatus',
            signature: 'getGithubTokenStatus(): Promise<GithubTokenStatus>',
          },
          {
            kind: 'method',
            name: 'setGithubToken',
            signature: 'setGithubToken(token: string): Promise<GithubTokenStatus>',
          },
        ],
        types: [],
      },
    ],
    events: [],
    objects: [],
  },
  invocations: GUARD_INVOCATIONS,
}