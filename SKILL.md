---
name: dsh-plugin-guard
description: >-
  Audit installed DeepSeek Harness plugins for security risk — static source and
  dependency review plus an AI (default-model) verdict — and interpret the
  green/yellow/red report.
whenToUse: >-
  Use when the user asks to check, audit, review, or assess the security or
  trustworthiness of installed DSH plugins, or wants to understand what an
  installed plugin actually does and how risky it is.
---

# Plugin security audit

`dsh-plugin-guard` is a **detective control** for the DeepSeek Harness web GUI.
It never executes plugin code — it reads each installed third-party plugin's
source and metadata, then produces a green / yellow / red report, optionally
backed by a default-model AI verdict.

## Capabilities

- **Static scan** — 13 rules over dangerous capability: child processes, `eval`,
  `vm`, shell, file read/write, network, environment variables, system probing,
  obfuscation, and exfiltration URLs.
- **Dependency review** — non-registry sources (`git:` / `file:` / `link:` / URL)
  and package names hitting suspicious keywords.
- **Install-script review** — `preinstall` / `install` / `postinstall`.
- **AI audit** — a `safe` / `suspicious` / `malicious` / `inconclusive` verdict
  with concerns, recommendations, and reputation evidence (npm / GitHub / search).

## How to use (web GUI)

Open **Settings → Plugin Security** (中文「插件安全体检」). Use **Rescan** to
refresh; each plugin row expands to show flags, dependencies, and errors. The
per-row **AI Audit** button runs a live verdict with progress.

## Remote service (`guard` namespace)

The host exposes a Typert Remote under the `guard` namespace for programmatic
access:

- `getReport()` — static audit of the profile's installed plugins
- `getAiAudit(pluginName)` — run the AI verdict for one plugin
- `getAiAuditStatus(pluginName)` — poll in-flight audit progress
- `getGithubTokenStatus()` / `setGithubToken(token)` — optional GitHub token
  (raises the GitHub API limit 60 → 5000 requests/hour)

## Interpreting results

- **Scoring**: high = 40, medium = 18, low = 6, total capped at 100.
- **Red** = any high hit or score ≥ 40. **Yellow** = any medium hit or ≥ 15.
  Otherwise **green**.
- **Verdicts**: `safe` / `suspicious` / `malicious` / `inconclusive`.
- **Principle**: a dangerous capability by itself is not proof of malice — weigh
  it against the plugin's claimed purpose (a file manager that reads files is
  expected; a calculator that exfiltrates SSH keys is not).

## Caveats

- It is a **post-hoc** control: it cannot intercept code already executed at
  `import()`.
- Static regex matching produces false positives and false negatives.
- Treat the report and AI verdict as supporting evidence, not a substitute for
  manual review.