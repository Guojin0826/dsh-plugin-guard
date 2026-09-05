# dsh-plugin-guard

> DeepSeek Harness plugin security checkup: static source audit + dependency review + AI online audit of installed third-party plugins, rendered as a green / yellow / red report panel.

[中文](README.md) | English

## What it is

`dsh-plugin-guard` is a plugin security inspector for the DeepSeek Harness (DSH) web GUI. Without ever executing plugin code, it reads the source and metadata of installed third-party plugins to answer one question — *"What does this plugin actually do, and does it go beyond the features it claims?"* — then presents a green / yellow / red report.

## Features

- **Static scanning**: a file-by-file inspection of third-party plugin source that flags 13 categories of dangerous capability (child processes, `eval`, `vm`, shell, file read/write, network, environment variables, system probing, obfuscation, suspicious exfiltration URLs, and more), scored by severity.
- **Dependency review**: flags dependencies that come from outside the npm registry (`git:` / `file:` / `link:` / URL) and packages whose names hit suspicious keywords.
- **Install-script review**: calls out `preinstall` / `install` / `postinstall` scripts — a common supply-chain attack surface.
- **AI online audit**: uses the default model to re-judge each plugin from "claimed features + static code evidence + internet reputation", returning a `safe / suspicious / malicious / inconclusive` verdict with recommendations.
- **Reputation evidence**: npm registry metadata (description, maintainers, publish dates, weekly downloads), GitHub repo signals (stars, forks, archived status, author account age), and search snapshots.
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
- its **risk score**, flags, dependencies, and number of files scanned.

Expanding a row reveals every matched rule with the files that triggered it, suspicious dependencies, and any scan errors.

### AI audit

Every plugin row has an **AI Audit** button. Clicking it:

1. shows live progress (collect evidence → reputation lookup → model call → parse result);
2. returns a verdict (`Safe` / `Suspicious` / `Malicious` / `Inconclusive`), concerns, recommendations, and reputation evidence.

Audit results persist: closing and reopening the settings panel still shows finished (or in-flight) results.

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
| `http` | Low | fetch / axios / request and other HTTP calls |
| `env` | Low | reads of `process.env.*` |
| `system-info` | Low | hostname / user / CPU / NIC and other system probing |
| `obfuscation` | Low | `atob` / base64 and other obfuscation hints |
| `install-script` | High | a `package.json` declaring install scripts |

### Dependency review

- **Non-registry sources**: dependencies using `git+ / git: / github: / http(s) / file: / link: / relative paths` are flagged.
- **Suspicious names**: dependencies whose names hit keywords such as `miner / stealer / keylogger / ransomware / trojan / backdoor / infostealer / credential-steal / exfil` are marked.

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