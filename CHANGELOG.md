# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - unreleased

### Added

- Static source audit of installed third-party plugins: 13 dangerous-API rule
  classes (`child-process`, `eval`, `vm`, `shell`, filesystem, network,
  exfiltration URLs, obfuscation, install scripts, …) with severity scoring and
  a green / yellow / red risk level.
- Dependency review flagging non-registry sources (`git:` / `file:` / `link:` /
  URLs) and suspicious package names, plus install-script surface reporting.
- AI online audit through the DSH default model: static evidence + plugin
  self-description + internet reputation (npm / GitHub / DuckDuckGo), returning
  a strict-JSON `safe / suspicious / malicious / inconclusive` verdict with
  concerns and recommendations, including a one-shot JSON retry.
- GitHub Personal Access Token support for raising the GitHub API rate limit
  (60/h anonymous → 5000/h authenticated), persisted host-locally and never
  echoed to the client.
- Strict shared wire contract (`contracts.ts`) + hand-written Typert host
  manifest exposing `guard.{getReport, getAiAudit, getAiAuditStatus,
  getGithubTokenStatus, setGithubToken}` to the web client.
- Web settings panel (`设置 → 插件安全体检`) with summary counters, per-plugin
  rows, expandable AI audit progress and reputation evidence, and a bilingual
  zh/en locale dictionary.
- Commit-ready npm/GitHub packaging: `files` whitelist, `prepublishOnly`
  build, CI and GitHub Release workflows.

### Changed

- `@deepseek-ai/*` peer/dev dependencies pinned to the published `0.1.2-rc.1`
  (npm `next` dist-tag); the install no longer relies on a machine-local DSH
  checkout (`link:` specs removed from the lockfile).

### Fixed

- Removed machine-specific `tsconfig.verify.json` (absolute `npx` cache paths).
- Regenerated `pnpm-lock.yaml` so a clean `pnpm install` resolves entirely from
  the npm registry.