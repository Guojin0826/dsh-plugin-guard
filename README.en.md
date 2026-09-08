# dsh-plugin-guard

> DeepSeek Harness plugin security checkup: static source audit + dependency review + AI online audit of installed third-party plugins, rendered as a green / yellow / red report panel.

[中文](README.md) | English

## What it is

`dsh-plugin-guard` is a plugin security inspector for the DeepSeek Harness (DSH) web GUI. Without ever executing plugin code, it reads the source and metadata of installed third-party plugins to answer one question — *"What does this plugin actually do, and does it go beyond the features it claims?"* — then presents a green / yellow / red report.

## Features

- **Static scanning**: a file-by-file inspection of third-party plugin source that flags 15 categories of dangerous capability (child processes, `eval`, `vm`, shell, file read/write, network, environment variables, system probing, obfuscation, suspicious exfiltration URLs, high-entropy payloads, credential-exfiltration patterns, and more), scored by severity.
- **Dependency review**: flags dependencies that come from outside the npm registry (`git:` / `file:` / `link:` / URL) and packages whose names hit suspicious keywords.
- **Install-script review**: calls out `preinstall` / `install` / `postinstall` scripts — a common supply-chain attack surface.
- **Declared-permission scoring**: reads the host services each plugin declares it needs (`dsh.plugin.json` `entry.inject` and `package.json` `dsh.client.inject`), tiers each one — model / network / file / process / secret / browser access = high, UI / i18n / config = low, unknown = medium "review it" — and shows a 0–100 permission score with each service listed.
- **Capability / declaration mismatch flag**: when the code hits high-severity capabilities but every declared service is low-power, the panel and the AI prompt raise a "high capability vs. light declared surface" warning — the strongest over-permission signal, computed deterministically instead of left for the model to infer.
- **Version-diff alerting (continuous monitoring)**: each scan persists a baseline (`$DSH_HOME/storages/dsh-plugin-guard/baseline.json`) and the next scan diffs against it — the panel badges any plugin that is newly installed, changed version, or gained risk flags / declared permissions since last time. This turns a one-off snapshot into a change detector: the classic supply-chain attack (a trusted package shipping a malicious new version) surfaces directly as "changed since last scan: +install-script".
- **AI online audit**: uses the default model to re-judge each plugin from "claimed features + static code evidence + layered internet reputation", returning a `safe / suspicious / malicious / inconclusive` verdict with recommendations. The **verdict** is cached by **content fingerprint + version + TTL**, while the **reputation layer (npm / OSV / web / GitHub) is re-fetched fresh on every run** — the last verdict is reused (marked "from cache") only when source / manifest / README are byte-identical, within TTL (default 3 days), and the fresh reputation has no new negative signal (a new advisory, a new malicious report, or a new deprecation); any such change forces a re-audit.
- **Reputation evidence** (multi-source online verification; every lookup is best-effort and degrades gracefully, never blocking the audit):
  - **npm registry metadata**: description, maintainers, publish/update dates, weekly downloads, **package age** (new packages < 30 days are flagged red — malware is often published → exploited → removed within days) and the **deprecated** notice (an authoritative "do not trust" signal from the maintainer);
  - **OSV.dev authoritative records**: whether the package is listed in the official vulnerability / malicious-package database — `MAL-*` or "Malicious" entries are highlighted as malicious and are a strong signal;
  - **Internet malicious/attack report search**: Bing-primary with a DuckDuckGo fallback, Chinese + English queries for "is this plugin reported as malicious / a backdoor / a supply-chain attack". Hits are **relevance-filtered** — only results that actually mention the plugin name AND a malicious/attack term are shown; when there is no relevant report it simply states "no malicious/attack reports found for this plugin" and never lists unrelated content or links;
  - **GitHub repo signals**: stars, forks, archived status, author account age, public repo count. The repo URL is taken **first from the plugin's own declaration** (package.json `repository` / `homepage`, README/docs); only when the plugin states none is it inferred from npm by package name, clearly flagged as "possibly a same-named repo — verify manually".
- **GitHub Token**: optionally enter a Personal Access Token in the panel to raise the GitHub API limit from 60 to 5000 requests/hour.

## Install & enable

### Prerequisites

- A machine with DSH installed and a working `dsh web`.
- `pnpm` on PATH (`dsh plugin` uses it internally to install plugins).

### Install

```bash
dsh plugin --profile <name> add @guojin-ai/dsh-plugin-guard
```

Replace `<name>` with the profile you want to audit (defaults to `web`). After installing, restart dsh (run `dsh web` again).

### Opening the panel

Once running, open **Settings → Plugin Security** in the web GUI.

> Uninstall: `dsh plugin --profile <name> remove @guojin-ai/dsh-plugin-guard`
>
> Note: DSH identifies this plugin internally as `dsh-plugin-guard` (different from the npm package name `@guojin-ai/dsh-plugin-guard` — this is expected).

## Usage guide

### Report overview

The top of the panel shows an `N ok · N warn · N high` summary plus a **Rescan** button to refresh the current install state at any time.

### Reading a plugin row

Each third-party plugin gets one row with:

- a **risk badge** (green / yellow / red);
- the plugin name, version, and whether it is active;
- its **risk score**, flags, **declared permissions**, dependencies, and number of files scanned.

Expanding a row reveals **what changed since the last scan** (if anything: version bump, newly gained risk flags / declared permissions), every matched rule with the files that triggered it, the **declared host-service permissions** (with a mismatch warning), suspicious dependencies, and any scan errors.

### AI audit

Every plugin row has an **AI Audit** button. Clicking it:

1. shows live progress (collect evidence → reputation lookup → model call → parse result);
2. returns a verdict (`Safe` / `Suspicious` / `Malicious` / `Inconclusive`), concerns, recommendations, and reputation evidence.

Audit results persist: closing and reopening the settings panel still shows finished (or in-flight) results.

**Result cache**: the *verdict* is written to a local cache (content fingerprint + version + TTL, default 72 h = 3 days), while the **reputation evidence (npm / OSV / web / GitHub) is re-fetched fresh on every run**. The cached verdict is reused — marked "from cache" — only while source, manifest, and README are unchanged, within TTL, and the fresh reputation has no new negative signal (a new advisory, a new malicious report, or a new deprecation); any new signal discards the cache and forces a re-audit. The panel has an **AI cache TTL** field to change the hours; setting it to 0 disables the cache.

### GitHub Token (optional)

The top of the panel provides a password-style Token field (never echoed back):

- **Save / Clear**: save a token to show a "configured" state, or clear it.
- With a token, the AI audit's GitHub lookups go from 60 to 5000 requests/hour.
- The token is stored only on this machine (`$DSH_HOME/storages/dsh-plugin-guard/github-token.txt`) — it never enters the session or the UI.

## What it checks

### Static risk rules

| Rule | Severity | What it matches |
| --- | --- | --- |
| `child-process` | High | `child_process` exec / spawn / fork, etc. |
| `eval` | High | `eval(...)` / `new Function(...)` |
| `vm-module` | High | imports of the `vm` module (sandbox-escape surface) |
| `shell` | High | `shell: true` or command-line concatenation (rm -rf / curl / sh -c, etc.) |
| `fs-write` | Medium | file writes / deletes |
| `fs-read` | Medium | file reads |
| `network` | Medium | net / dgram / dns / tls / ws / undici, etc. |
| `exfil-url` | Medium | pastebin / webhook.site / ngrok / tg bot / onion and similar exfiltration URLs |
| `env-exfil` | Medium | one file reads `process.env.*` and also spawns/execs or makes a network call (suspected credential exfiltration) |
| `high-entropy` | Medium | a long high-entropy string (suspected base64 / encrypted payload, regardless of decode method) |
| `http` | Low | fetch / axios / request and other HTTP calls |
| `env` | Low | reads of `process.env.*` |
| `system-info` | Low | hostname / user / CPU / NIC and other system probing |
| `obfuscation` | Low | `atob` / base64 and other obfuscation hints |
| `install-script` | High | a `package.json` declaring install scripts |

### Dependency review

- **Non-registry sources**: dependencies using `git+ / git: / github: / http(s) / file: / link: / relative paths` are flagged.
- **Suspicious names**: dependencies whose names hit keywords such as `miner / stealer / keylogger / ransomware / trojan / backdoor / infostealer / credential-steal / exfil` are marked.

### Declared-permission scoring

A plugin declares the host services it needs via `dsh.plugin.json` `entry.inject` and `package.json` `dsh.client.inject`. This plugin treats those declarations as a "permission surface" and scores them:

| Tier | Meaning | Typical services |
| --- | --- | --- |
| High | can reach the model / network / files / processes / secrets / browser | `llm`, `typert`, `remote`, `api`, `agentDefaultModel`, … |
| Medium | unrecognized service, defaults to "review it" | any name not in the table above |
| Low | UI / i18n / config / data-flow only | `locale`, `slots`, `ui-settings`, `renderer`, … |

- **Permission score**: High 40 / Medium 18 / Low 6, capped at 100 (the same weights as the static risk score), **independent of** the green / yellow / red risk level — a supplementary signal only.
- **Capability / declaration mismatch**: fires when the code hits any high-severity capability AND every declared service is low (it does NOT fire when nothing is declared, to avoid false positives). This is the strongest over-permission signal and is also fed to the AI audit.

### Scan boundaries

For accuracy and performance, the scan skips `node_modules`, `.git`, and `.pnpm`, skips `.map` / `.d.ts` / `.min.js`, and skips individual files over 1 MiB as well as overly deep directories.

## How risks are scored

- **Scoring**: High = 40, Medium = 18, Low = 6, total capped at 100.
- **Risk level**:
  - any **High** hit, or a total ≥ 40 → **red**;
  - any **Medium** hit, or a total ≥ 15 → **yellow**;
  - otherwise → **green**.

The AI audit's guiding principle: **dangerous capability by itself is not malicious**. It weighs whether a plugin's *claimed features* match what it *actually does* — a file manager reading and writing files, or a code runner executing commands, is expected; a calculator quietly reading SSH keys, or an unknown new package phoning data home, is the real signal.

## FAQ

**Q: Some plugins show "npm: not found" in the reputation panel. Is something broken?**

No. Plugins installed via local `link:` / `file:` / direct GitHub, or packages never published to npm, simply have no npm record. This is expected behavior, and the AI audit treats missing reputation as "unknown, not fabricated".

**Q: Does green mean safe and red mean malicious?**

No. This is a detective-control plus static-analysis combination, so it can over- or under-report. Always combine the AI verdict with your own review before deciding.

## Limitations & disclaimer

- It is a **detective control**: it reads source and manifests, and cannot intercept code the loader already executed at `import()`.
- Static regex matching has false positives and negatives: a hit does not prove malice, and no hit does not prove safety.
- Reputation and AI verdicts are **supporting evidence**, not a substitute for your own judgment about whether to trust a plugin.

## License

[MIT](./LICENSE)