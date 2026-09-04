# dsh-plugin-guard

> DeepSeek Harness 插件安全体检：对已安装的第三方插件做「静态代码审计 + 依赖审查 + AI 在线审计」，并以绿 / 黄 / 红三级报告面板呈现。
>
> Plugin security inspector for the DeepSeek Harness web GUI: statically audits installed plugins (dangerous API patterns + dependency review), then layer an AI (default-model) audit on top, rendered as a green / yellow / red report panel.

## 它能做什么

`dsh-plugin-guard` 是一个**事后检测**（detective control）插件：它在**不执行插件代码**的前提下，读取插件源码与元数据，帮你判断「安装的这个插件到底在干什么、有没有超出它自称功能的风险」。

- **静态扫描**：逐文件正则扫描第三方插件源码，命中 13 类危险能力（子进程、`eval`、`vm`、shell、文件读写、网络、环境变量、系统探测、混淆、可疑外联地址等），并按严重度打分。
- **依赖审查**：标记「非 npm registry 来源」（`git:` / `file:` / `link:` / URL）和「包名命中可疑关键词」的依赖。
- **安装脚本审查**：单独标出 `preinstall` / `install` / `postinstall` 脚本（供应链攻击面）。
- **AI 在线审计**：调用默认模型，结合「插件自称的功能 + 静态代码证据 + 互联网声誉（npm / GitHub / 搜索）」二次判定，输出 `safe / suspicious / malicious / inconclusive` 结论、关注点与处置建议。
- **声誉佐证**：npm registry 元数据（描述、维护者、首次/最近发布、周下载量）、GitHub 仓库信号（star / fork / 是否归档 / 创建与推送时间 / 作者账号年龄与公开仓库数）、DuckDuckGo 搜索结果。
- **GitHub Token**：支持在面板里填写 Personal Access Token，把 GitHub API 限额从 60 次/小时提升到 5000 次/小时。

## 界面与入口

安装并启用后，打开 DSH Web GUI 的 **设置 → 插件安全体检**，即可看到：

- 顶部：GitHub Token（可选）填写区——密码框输入、保存 / 清除，状态显示「已配置 / 未配置」，Token 不回显。
- 汇总：`N 正常 · N 警告 · N 高危` 统计。
- 插件列表：每个第三方插件一行，显示版本、启用状态、风险分、风险标记、依赖、扫描文件数。
- 每行可展开「AI 在线审计」：实时进度（采集 / 声誉查询 / 调用模型 / 解析）、判定结论、关注点、处置建议与声誉佐证。

## 安装

npm 包名：`@guojin-ai/dsh-plugin-guard`；DSH 内部插件 id 为 `dsh-plugin-guard`。它同时声明了三处装载契约：`package.json` `dsh.bundle.patch`（指向 `cordis.patch.yml`，插入主机端插件行）、`dsh.client`（`platform: web` + `./client` 浏览器 bundle）、以及 `main`/`exports`（`lib/index.js` / `lib/client.js`）。

用 DSH 自带的插件命令把包装进你要审计的 profile（`$DSH_HOME/profiles/<profile>`）：

```bash
dsh plugin --profile <name> add @guojin-ai/dsh-plugin-guard
```

`dsh plugin` 会转发给 pnpm 在该 profile 目录内安装，并把声明了 `dsh.bundle` 的包自动纳入该 profile 的组合层（需要机器上有 `pnpm`）。

> 仓库已提交构建产物 `lib/`（`lib/index.js` 为主机端 ESM、`lib/client.js` 为客户端 bundle，`lib/types/` 为对应 `.d.ts`），因此**无需重新构建**即可被加载器直接装载。若想自行构建可参考下方「开发」一节。

启用后需**重启 dsh**（重新 `dsh web`）使主机端插件与客户端 bundle 生效。

## 配置

主机端插件配置由 Loader 校验，全部有默认值（见 `src/index.ts` 的 `Config` schema）：

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `profile` | `web` | 要审计的 profile 名，位于 `$DSH_HOME/profiles/<profile>` |
| `maxScanFiles` | `5000` | 单个插件最多扫描的源码文件数（上限保护） |
| `githubToken` | `""` | 可选的 GitHub Personal Access Token（`secret` 角色）；用于 AI 审计的 GitHub 仓库/作者查询，匿名时限额 60/h，填写后 5000/h |

`githubToken` 也可直接在面板里填写：运行时优先取 Loader 配置（`config.githubToken`），否则读面板保存的持久化值，二者都在启动/保存时生效。面板保存的 Token 持久化到：

```
$DSH_HOME/storages/dsh-plugin-guard/github-token.txt
```

> 安全说明：Token 只保存在本机、不进会话、不回传界面。若你更希望走 harness 的 settings 命名空间 / 加密存储，可在 `runtime.ts` 中替换该持久化实现。

## 审计原理

### 静态扫描规则（`src/scanner.ts`）

| 规则代码 | 严重度 | 命中内容 |
| --- | --- | --- |
| `child-process` | high | `child_process` 的 exec / spawn / fork 等 |
| `eval` | high | `eval(...)` / `new Function(...)` |
| `vm-module` | high | 引用 `vm` 模块（沙箱逃逸面） |
| `shell` | high | `shell: true` 或命令行拼接（rm -rf / curl / sh -c 等） |
| `fs-write` | medium | 文件写入 / 删除 |
| `fs-read` | medium | 文件读取 |
| `network` | medium | net / dgram / dns / tls / ws / undici 等 |
| `exfil-url` | medium | pastebin / webhook.site / ngrok / tg bot / onion 等待外联地址 |
| `http` | low | fetch / axios / request 等 HTTP 请求 |
| `env` | low | 读取 `process.env.*` |
| `system-info` | low | 主机名 / 用户 / CPU / 网卡等系统探测 |
| `obfuscation` | low | `atob` / base64 编码等混淆迹象 |
| `install-script` | high | package.json 声明安装脚本 |

计分：`high = 40`、`medium = 18`、`low = 6`，总分上限 100。风险等级：命中任一 `high` 或总分 ≥ 40 → **红**；命中任一 `medium` 或总分 ≥ 15 → **黄**；否则 → **绿**。

依赖审查：`git+ / git: / github: / http(s) / file: / link: / 相对路径` 视为「非 npm registry 来源」；包名命中 `miner|stealer|keylogger|ransomware|trojan|backdoor|infostealer|credential-steal|exfil` 视为可疑。

扫描边界：跳过 `node_modules / .git / .pnpm`，跳过 `.map` / `.d.ts` / `.min.js`，单文件超过 1 MiB 跳过，目录深度 ≤ 5。

### AI 在线审计（`src/ai-audit.ts`）

1. 采集三层信息：① 插件自称的功能（package.json 描述 / 关键词 / README 摘要 / 安装脚本）；② 静态扫描结果与命中的源码片段；③ 互联网声誉（npm → GitHub → 搜索，三者并行、有失败标注）。
2. 拼装系统提示 + 用户提示，要求模型只返回严格 JSON（`verdict / risk / summary / concerns / recommendations`）。
3. 流式接收、组装文本块，做括号闭合提取 + zod 校验；失败则**携带完整上下文重试**一次（要求仅输出 JSON）。
4. 结果附上声誉佐证一并返回面板。

判定口径（提示词内强制）：危险能力本身不是恶意证据，需与插件「自称的功能」做一致性判断——文件管理器读写文件、代码执行器跑命令是本职，而计算器偷读 SSH 密钥、无名新包外联回传才是恶意。

### 声誉查询为空的说明

本地 `link:` / `file:` / GitHub 直连安装、或未发布到 npm 的包，npm 声誉栏会如实显示「npm 未收录该包名」。这是**预期行为**，不是报错——AI 审计会以「声誉信息缺失时不臆造」原则处理。

## 架构

```
src/
├─ index.ts                  # 主机入口：挂 guard 服务 + 注册 Typert 清单 + 启动审计摘要
├─ runtime.ts                # GuardRuntime：getReport / getAiAudit / getAiAuditStatus
│                            #   + getGithubTokenStatus / setGithubToken（Token 存储）
├─ scanner.ts                # 静态扫描 + 源码证据提取 + 元数据采集（纯 Node，可测）
├─ ai-audit.ts               # AI 审计：三层证据拼装、流式解析、严格 JSON + 重试
├─ contracts.ts              # 前后端共享的 wire 契约 + zod codec（无 Node 依赖）
├─ typert.ts                 # 手写 Typert host manifest（声明 5 个 guard 方法）
└─ client/
   ├─ index.tsx              # 客户端入口：$mount guard Remote + 注册设置面板
   ├─ remote.ts              # 客户端 Remote contribution + 类型声明
   ├─ SecurityReportPanel.tsx# 报告面板 UI（含 GitHub Token 表单）
   └─ locales.ts             # 中 / 英文案
```

主机端与客户端共享同一份 `contracts.ts` 严格契约：主机通过 `ctx.typert.register` 注册清单，客户端通过 `ctx.remote.$mount` 挂载，两端 codec 一致，避免线上不一致。

## 开发

```bash
# 安装依赖（@deepseek-ai/* 全部从 npm registry 安装，无需本机 DSH 检出）
pnpm install

# 构建（esbuild 单文件打包）
pnpm run build

# 生成类型声明 / 类型检查
pnpm run build:types
pnpm run typecheck
```

构建产物：

- `lib/index.js` —— 主机端 ESM bundle（外部化 `@deepseek-ai/*`，打包 zod / schemastery）。
- `lib/client.js` —— 客户端 CJS bundle（外部化 react 与 `@deepseek-ai/*`，用 `window.__ModuleLoader__` 包裹）。
- `lib/types/` —— 主机端 + 客户端的 `.d.ts` 声明（`tsc -p tsconfig.json` 生成）。

> 依赖说明：`@deepseek-ai/*` 系列（cordis、dsh-llm、dsh-typert-*、dsh-client-* 等）以 `0.1.2-rc.1` 作为 peer/dev 依赖版本，发布在 npm 的 `next` dist-tag 下（`npm view @deepseek-ai/dsh-llm dist-tags` 可见）。运行时依赖只有 `zod`；`peerDependencies` 全部标记为可选，由 DSH 本体在运行时提供这些 SDK 包。

## 发布

发布到 npm：

```bash
# prepublishOnly 会自动执行 build + build:types
npm publish
```

发布 GitHub Release：推送一个 `v*` 标签（如 `v0.1.0`），`.github/workflows/release.yml` 会自动构建、`npm publish`（带 provenance）并创建 GitHub Release。

> 仓库地址：<https://github.com/Guojin0826/dsh-plugin-guard>。

## 局限与免责

- 这是**事后检测**：它读取源码和清单，无法拦截加载器在 `import()` 时已经执行的代码。
- 静态正则匹配存在误报 / 漏报：命中不代表恶意，未命中也不代表安全；请结合 AI 审计与人工复核。
- 声誉与 AI 结论只是**佐证与参考**，最终是否信任某个插件仍需人工判断。

## 许可证

[MIT](./LICENSE)