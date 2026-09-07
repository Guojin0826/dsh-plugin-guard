# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Declared host-service permission scoring**: the static audit now reads each
  plugin's declared `inject` services (`dsh.plugin.json` `entry.inject` and
  `package.json` `dsh.client.inject`), tiers each one (model / network / file /
  process / secret / browser access = high; UI / i18n / config = low; unknown =
  medium "review it"), and reports a 0–100 `permScore` alongside the listed
  services. The tiering is a documented heuristic — an unrecognized service is
  never defaulted to "ok".
- **Capability / declaration mismatch flag**: when a plugin's code hits
  high-severity capabilities but every declared service is low-power, the panel
  and the AI prompt raise a "high capability vs. light declared surface"
  warning. It does not fire when nothing is declared, so absence of a manifest
  is never treated as evidence.

### Changed

- The AI audit prompt now receives the declared-permission list, the permission
  score, and the mismatch flag, grounding its "capability vs. claimed purpose"
  judgment in the plugin's own declared host-service surface.
- Internal cleanup: removed the dead `searchResults` reputation field and the
  duplicated empty-GitHub literal (no behavior change).

### Fixed

- Reasoning models (e.g. `deepseek-v4-pro`) that emit a ` thinking…` block
  before the JSON no longer trigger a first-parse failure: reasoning blocks
  (` thinking` / `<thinking>` / `<reasoning>` / `<scratchpad>`) are stripped
  before locating the JSON object, so the first pass parses directly instead of
  burning a strict-retry round.

## [0.2.0] - 2026-09-05

### Added

- AI audit reputation layer: **OSV.dev** advisory lookup (authoritative,
  keyless) surfaces known npm vulnerabilities and malicious-package records;
  `MAL-*` / "Malicious" entries are tagged and strongly bias the verdict toward
  `malicious`.
- AI audit reputation layer: **internet malicious/attack report search**
  (Bing primary, DuckDuckGo fallback; Chinese + English queries anchored on the
  package name) replaces the old single DuckDuckGo snapshot.
- Security panel: dedicated **Advisories** and **Web reports** boxes under the
  reputation evidence, with clickable source links and zh/en locale strings.

### Changed

- Web-search hits are **relevance-filtered**: a hit is surfaced only when it
  mentions the plugin name AND a malicious/attack term, so unrelated scrape
  noise is never shown; when nothing relevant is found the panel reports "none"
  instead of listing junk URLs.
- GitHub repo resolution now **prefers the plugin's own declared URL**
  (package.json `repository` / `homepage`, then README/docs) and only falls back
  to an npm-by-name lookup when the plugin states none; that fallback is flagged
  as a possible same-named repo, and the AI prompt is told to discount it.

## [0.1.0]

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