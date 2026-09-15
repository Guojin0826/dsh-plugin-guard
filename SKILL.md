---
name: dsh-plugin-guard
description: >-
  Audit installed DeepSeek Harness plugins and skills for security risk — static
  source and dependency review, an AI (default-model) verdict, and a ThreatBook
  SafeSkill multi-engine skill scan — and interpret the green/yellow/red report.
whenToUse: >-
  Use when the user asks to check, audit, review, or assess the security or
  trustworthiness of installed DSH plugins or skills, or wants to understand what
  an installed plugin actually does and how risky it is.
---

# Plugin security audit

`dsh-plugin-guard` is a **detective control** for the DeepSeek Harness web GUI.
It never executes plugin code — it reads each installed third-party plugin's
source and metadata, then produces a green / yellow / red report, optionally
backed by a default-model AI verdict and a SafeSkill multi-engine scan of
installed skills.

## Capabilities

- **Static scan** — 17 rules over dangerous capability: child processes, `eval`,
  `vm`, shell, file read/write, network, environment variables, system probing,
  obfuscation, exfiltration URLs, high-entropy payloads, credential exfiltration,
  hardcoded secrets, and download-then-execute chains.
- **Dependency review** — non-registry sources (`git:` / `file:` / `link:` / URL),
  suspicious package names, and OSV.dev-known vulnerabilities in direct deps.
- **Install-script review** — `preinstall` / `install` / `postinstall`.
- **Declared-permission scoring** — tiers each host-service the plugin declares
  it injects into a 0–100 permission score; a capability/declaration mismatch is
  flagged as the strongest over-permission signal.
- **Version-diff alerting** — persists a baseline and badges newly installed,
  version-changed, or newly gained risk flags / permissions since the last scan.
- **AI audit** — a `safe` / `suspicious` / `malicious` / `inconclusive` verdict
  with concerns, recommendations, and reputation evidence (npm / OSV / web
  search / GitHub). Verdicts are cached by content fingerprint + model + version
  + TTL (default 72 h), with reputation re-fetched live each run.
- **SafeSkill skill audit** — one-click upload of installed skills to ThreatBook
  SafeSkill for multi-engine detection (threat level, trust score, classification,
  risk indicators), with a content-hash cache and batch "scan all" support.
- **Dark / light theme** — the report panel follows the app's theme.

## How to use (web GUI)

Open **Settings → Plugin Security** (中文「插件安全体检」). Use **Rescan** to
refresh; each plugin row expands to show flags, dependencies, permissions, and
errors. The per-row **AI Audit** button runs a live verdict with progress. The
**Skill Audit** block sets a SafeSkill API key and scans installed skills.

## Remote service (`guard` namespace)

The host exposes a Typert Remote under the `guard` namespace for programmatic
access:

- `getReport()` — static audit of the profile's installed plugins
- `getAiAudit(pluginName)` — run the AI verdict for one plugin
- `forceAiAudit(pluginName)` — bypass the cached verdict for one run
- `getAiAuditStatus(pluginName)` — poll in-flight audit progress
- `getAiAuditCacheSnapshot()` — restore still-valid cached verdicts
- `getAuditConfig()` / `setAuditTtl(ttlHours)` — read / set the verdict-cache TTL
- `getGithubTokenStatus()` / `setGithubToken(token)` — optional GitHub token
  (raises the GitHub API limit 60 → 5000 requests/hour)
- `getSafeSkillStatus()` / `setSafeSkillKey(key)` — SafeSkill API key state
- `listSkills()` — enumerate locally installed skills
- `scanSkill(skillName)` — cache-aware SafeSkill scan of one skill
- `getSafeSkillCacheSnapshot()` — restore cached SafeSkill results
- `scanAllSkills()` — serial batch scan of every installed skill
- `auditSkill(skillName)` — AI-audit one skill with the harness default model
  (the offline fallback when SafeSkill cannot run; cached by skill content hash)
- `getSkillAiAuditSnapshot()` — restore cached skill AI verdicts after a refresh

## Interpreting results

- **Scoring**: high = 40, medium = 18, low = 6; the static risk score = code-flag
  score + declared-permission score, capped at 100.
- **Red** = any high rule hit or a code-flag score ≥ 40. **Yellow** = score ≥ 15.
  Otherwise **green**. After the AI audit, the verdict re-classifies the level
  (`malicious` → red, `suspicious` → yellow, `safe` → green) and the 0–100 score
  is assigned by the model.
- **Verdicts**: `safe` / `suspicious` / `malicious` / `inconclusive`.
- **Principle**: a dangerous capability by itself is not proof of malice — weigh
  it against the plugin's claimed purpose (a file manager that reads files is
  expected; a calculator that exfiltrates SSH keys is not).

## Caveats

- It is a **post-hoc** control: it cannot intercept code already executed at
  `import()`.
- Static regex matching produces false positives and false negatives.
- Treat the report, AI verdict, and SafeSkill results as supporting evidence, not
  a substitute for manual review.