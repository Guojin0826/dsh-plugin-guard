# dsh-plugin-guard

> DeepSeek Harness 插件安全体检：对已安装的第三方插件做「静态代码审计 + 依赖审查 + AI 在线审计」，并以绿 / 黄 / 红三级报告面板呈现。
>
> Plugin security inspector for the DeepSeek Harness web GUI: statically audits installed plugins (dangerous API patterns + dependency review), then layers an AI (default-model) audit on top, rendered as a green / yellow / red report panel.

中文 | [English](README.en.md)

## 这是什么

`dsh-plugin-guard` 是 DeepSeek Harness（DSH）Web GUI 的一款**插件安全体检**插件。它在**不执行插件代码**的前提下，读取已安装第三方插件的源码与元数据，帮你判断「装上的这个插件到底在做什么、是否超出了它自称的功能范围、风险有多高」，最后给出一份绿 / 黄 / 红三级的报告。

## 主要功能

- **静态扫描**：逐文件检查第三方插件源码，识别 13 类危险能力（子进程、`eval`、`vm`、shell、文件读写、网络、环境变量、系统探测、混淆、可疑外联地址等），并按严重度打分。
- **依赖审查**：标出「非 npm registry 来源」（`git:` / `file:` / `link:` / URL）以及「包名命中可疑关键词」的依赖。
- **安装脚本审查**：单独标出 `preinstall` / `install` / `postinstall` 脚本——这是常见的供应链攻击面。
- **AI 在线审计**：调用默认模型，结合「插件自称的功能 + 静态代码证据 + 互联网声誉」二次判定，输出 `safe / suspicious / malicious / inconclusive` 结论及处置建议。
- **声誉佐证**：npm registry 元数据（描述、维护者、发布时间、周下载量）、GitHub 仓库信号（star / fork / 是否归档 / 作者账号年龄）、搜索快照。
- **GitHub Token**：可在面板中填写 Personal Access Token，把 GitHub API 限额从 60 次/小时提升到 5000 次/小时。

## 安装与启用

### 前提

- 一台已安装 DSH、能正常 `dsh web` 的机器。
- 机器上装有 `pnpm`（`dsh plugin` 内部需要它来安装插件）。

### 安装

```bash
dsh plugin --profile <name> add @guojin-ai/dsh-plugin-guard
```

把 `<name>` 换成你要审计的 profile（默认可填 `web`）。安装完成后，**重启 dsh**（重新运行 `dsh web`）。

### 打开面板

启动后打开 Web GUI 的 **设置 → 插件安全体检**，即可看到安全报告。

> 卸载：`dsh plugin --profile <name> remove @guojin-ai/dsh-plugin-guard`
>
> 说明：DSH 内部识别此插件的 id 是 `dsh-plugin-guard`（与 npm 包名 `@guojin-ai/dsh-plugin-guard` 不同，属正常现象）。

## 使用指南

### 报告总览

面板顶部给出汇总统计「N 正常 · N 警告 · N 高危」，并有一个「重新扫描」按钮，可随时刷新当前安装状态。

### 看懂单个插件

每个第三方插件一行，展示：

- **风险等级徽章**（绿 / 黄 / 红）；
- 插件名与版本、是否启用；
- **风险分**、命中规则、依赖、扫描文件数。

展开某一行可以看到：所有命中的风险规则及对应文件、可疑依赖、以及扫描过程中出现的错误。

### AI 在线审计

每个插件行内都有一个「AI 审计」按钮。点击后：

1. 实时显示进度（采集证据 → 声誉查询 → 调用模型 → 解析结果）；
2. 输出判定结论（safe / suspicious / malicious / inconclusive）、关注点、处置建议与声誉佐证。

审计结果会保留：关闭设置面板再打开，已完成的（或仍在进行中的）结果仍然可见。

### GitHub Token（可选）

面板顶部提供 Token 填写区（密码框，不回显）：

- **保存 / 清除**：填写后保存，状态显示「已配置 / 未配置」；
- 填写 Token 后，AI 审计的 GitHub 查询限额从 60 次/小时提升到 5000 次/小时；
- Token 只保存在本机（`$DSH_HOME/storages/dsh-plugin-guard/github-token.txt`），不进会话、不上传。

## 它会检查什么

### 静态风险规则

| 规则代码 | 严重度 | 命中内容 |
| --- | --- | --- |
| `child-process` | 高 | `child_process` 的 exec / spawn / fork 等 |
| `eval` | 高 | `eval(...)` / `new Function(...)` |
| `vm-module` | 高 | 引用 `vm` 模块（沙箱逃逸面） |
| `shell` | 高 | `shell: true` 或命令行拼接（rm -rf / curl / sh -c 等） |
| `fs-write` | 中 | 文件写入 / 删除 |
| `fs-read` | 中 | 文件读取 |
| `network` | 中 | net / dgram / dns / tls / ws / undici 等 |
| `exfil-url` | 中 | pastebin / webhook.site / ngrok / tg bot / onion 等外联地址 |
| `http` | 低 | fetch / axios / request 等 HTTP 请求 |
| `env` | 低 | 读取 `process.env.*` |
| `system-info` | 低 | 主机名 / 用户 / CPU / 网卡等系统探测 |
| `obfuscation` | 低 | `atob` / base64 编码等混淆迹象 |
| `install-script` | 高 | package.json 声明安装脚本 |

### 依赖审查

- **非 npm registry 来源**：`git+ / git: / github: / http(s) / file: / link: / 相对路径` 的依赖会被标出；
- **可疑包名**：命中 `miner / stealer / keylogger / ransomware / trojan / backdoor / infostealer / credential-steal / exfil` 等关键词的依赖会被标记。

### 扫描边界

为提高准确度与性能，扫描会跳过 `node_modules`、`.git`、`.pnpm`，跳过 `.map` / `.d.ts` / `.min.js`，超过 1 MiB 的单个文件与过深目录也会跳过。

## 判定标准

- **计分**：高危 40 分、中危 18 分、低危 6 分，总分上限 100。
- **风险等级**：
  - 命中任一**高危**规则、或总分 ≥ 40 → **红**；
  - 命中任一**中危**规则、或总分 ≥ 15 → **黄**；
  - 其余 → **绿**。

AI 审计的判定口径：**危险能力本身不等于恶意**。它更看重「这个插件自称的功能」与「它实际做的」是否一致——文件管理器读写文件、代码执行器跑命令是本职；但计算器偷读 SSH 密钥、无名新包外联回传，才是真正的恶意信号。

## 常见问题

**问：有些插件的 npm 声誉栏显示「npm 未收录该包名」，是出问题了吗？**

不是。本地 `link:` / `file:` / GitHub 直连安装、或未发布到 npm 的包，npm 侧本来就没有记录，这是**预期行为**。AI 审计会以「声誉信息缺失时不臆造」的原则处理。

**问：绿色就一定安全、红色就一定是恶意吗？**

不是。这是**事后检测** + 静态分析的组合，会有误报和漏报。请结合 AI 结论与人工复核后再做决定。

## 局限与免责

- 这是**事后检测**：它读取源码与清单，无法拦截加载器在 `import()` 时已经执行的代码。
- 静态正则匹配存在误报 / 漏报：命中不代表恶意，未命中也不代表安全。
- 声誉与 AI 结论只是**佐证与参考**，最终是否信任某个插件仍需人工判断。

## 许可证

[MIT](./LICENSE)