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
- **Version-diff alerting (continuous monitoring)**: each scan persists a
  baseline (`$DSH_HOME/storages/dsh-plugin-guard/baseline.json`) and the next
  scan diffs against it — the panel badges any plugin that is newly installed,
  changed version, or *gained* risk flags / declared permissions since last
  time. This turns the report from a one-off snapshot into a change detector:
  the classic supply-chain attack (a trusted package shipping a malicious new
  version) now surfaces as "changed since last scan: +install-script".
- **Three high-signal static rules**:
  - `high-entropy` — a long, whitespace-free string literal with Shannon
    entropy ≥ 4.3 (not a data URI / URL / hex hash) flags an encoded or
    encrypted payload regardless of how it is later decoded; the existing
    `obfuscation` rule only catches the decode call itself.
  - `env-exfil` — when one file both reads `process.env.*` and spawns/execs or
    makes a network call, a cheap same-file taint approximation for credential
    exfiltration (GuardDog does this with CodeQL; this is the lightweight
    co-occurrence proxy).
  - package age / deprecation — the reputation layer now derives the package's
    age from its npm publish date (new packages < 30 days are flagged, per the
    "cool-down" insight that malware is published → exploited → removed within
    days) and surfaces the npm `deprecated` message; both feed the AI prompt as
    legitimacy priors and are shown in the panel.
- **AI-audit verdict cache (content fingerprint + version + TTL, live reputation)**:
  each completed *verdict* is persisted (`$DSH_HOME/storages/dsh-plugin-guard/ai-cache.json`)
  keyed by a SHA-256 fingerprint of everything the audit reads (version,
  package.json, dsh.plugin.json, README, scanned source). On re-run the live
  reputation layer (npm / OSV / web / GitHub) is **always re-fetched fresh**; the
  cached verdict is reused only while the fingerprint is unchanged, under the
  TTL (default 72 h), and the fresh reputation carries **no new negative signal**
  (a new OSV advisory, a new malicious/attack web report, or a new deprecation).
  Any such addition discards the cache and forces a full re-audit. The panel
  exposes the TTL (0 disables the cache) and marks served verdicts "from cache".
- **Per-plugin force re-audit**: a 强制重审 / Force re-audit button next to each
  plugin's AI audit bypasses that plugin's cached verdict for one run, without
  changing the global TTL or audit config.
- **Model identity in the verdict fingerprint**: the cache key now folds in the
  default model (`provider/model`), so switching the default model invalidates an
  otherwise-matching fingerprint within TTL instead of reusing another model's verdict.
- **Hardcoded secret/token scan**: a new high-severity rule flags known key formats
  (AWS / GitHub / Slack / Stripe / OpenAI / PRIVATE KEY) plus quoted long-value API-key
  assignments.
- **Download-and-execute rule**: flags the `curl | sh` / `wget | bash` / `| iex` chain
  in source and inside install scripts.

### Changed

- The AI audit prompt now receives the declared-permission list, the permission
  score, and the mismatch flag, grounding its "capability vs. claimed purpose"
  judgment in the plugin's own declared host-service surface.
- Internal cleanup: removed the dead `searchResults` reputation field and the
  duplicated empty-GitHub literal (no behavior change).
- Static scans are now **deterministic**: the source walk is sorted, so
  `maxFiles` truncation and the per-rule 8-file cap sample the same files every
  run — a plugin with unchanged code produces an identical report, so
  version-diff never flags spurious "changes" caused by flapping scan order.

### Fixed

- Reasoning models (e.g. `deepseek-v4-pro`) that emit a ` thinking…` block
  before the JSON no longer trigger a first-parse failure: reasoning blocks
  (` thinking` / `<thinking>` / `<reasoning>` / `<scratchpad>`) are stripped
  before locating the JSON object, so the first pass parses directly instead of
  burning a strict-retry round.
- GitHub repo detection no longer misses the repo when the plugin's own README
  mentions its `github.com` link near the end: metadata collection now scans the
  FULL README for repo URLs (the prompt still keeps only the capped 3 KB excerpt).

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