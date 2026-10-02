<!--
  v2ray-configs — 仓库主页
  发布前：替换 YOUR_GITHUB_USERNAME / YOUR_TELEGRAM_CHANNEL，
  确认生成的订阅文件名，并添加下文提及的资源文件。
-->

<div align="center">

# 🌐 v2ray-configs

### 精选社区提供的连接配置索引，并持续进行自动检查。

<!-- 请将此占位图替换为项目原始的头图素材。 -->
<picture>
  <img src="assets/readme-hero.png" alt="v2ray-configs — 精选连接、清晰状态、简便订阅" width="900">
</picture>

<br>

[![CI pipeline](https://github.com/YOUR_GITHUB_USERNAME/v2ray-configs/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_GITHUB_USERNAME/v2ray-configs/actions/workflows/ci.yml)
[![Auto-update](https://img.shields.io/badge/auto--update-enabled-29a36a?logo=dependabot&logoColor=white)](#architecture)
[![GitHub stars](https://img.shields.io/github/stars/YOUR_GITHUB_USERNAME/v2ray-configs?style=flat&logo=github&label=stars)](https://github.com/YOUR_GITHUB_USERNAME/v2ray-configs/stargazers)
[![Telegram](https://img.shields.io/badge/Telegram-community-26A5E4?logo=telegram&logoColor=white)](https://t.me/YOUR_TELEGRAM_CHANNEL)
[![Dashboard](https://img.shields.io/badge/dashboard-live-6857d5?logo=githubpages)](https://YOUR_GITHUB_USERNAME.github.io/v2ray-configs/)

<!-- 实时数值通过 Shields.io 从仓库中的 JSON 数据文件读取。 -->
[![Total indexed configs](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2FYOUR_GITHUB_USERNAME%2Fv2ray-configs%2Fmain%2Findex.json&query=%24.total&label=indexed%20configs&color=5470c6&logo=serverfault)](index.json)
[![Currently healthy](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2FYOUR_GITHUB_USERNAME%2Fv2ray-configs%2Fmain%2Fhealth.json&query=%24.online&label=healthy%20now&color=2e9d68&logo=activity)](health.json)
[![Last health check](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2FYOUR_GITHUB_USERNAME%2Fv2ray-configs%2Fmain%2Fhealth.json&query=%24.checked_at&label=last%20check&color=718096)](health.json)

**[⚡ 获取 Top 100](https://raw.githubusercontent.com/YOUR_GITHUB_USERNAME/v2ray-configs/main/top100.txt)** · **[📊 打开仪表盘](https://YOUR_GITHUB_USERNAME.github.io/v2ray-configs/)** · **[💬 加入 Telegram](https://t.me/YOUR_TELEGRAM_CHANNEL)** · **[⭐ 为项目加星](https://github.com/YOUR_GITHUB_USERNAME/v2ray-configs)**

[🇬🇧 English](README.md) · [🇮🇷 فارسی](README_FA.md) · [🇷🇺 Русский](README_RU.md) · [🇨🇳 中文](README_ZH.md)

</div>

---

## 👋 这个仓库是什么？

`v2ray-configs` 用于整理社区提交的 V2Ray 兼容连接配置，并为受支持的客户端发布订阅文件。项目通过自动检查并按实用的质量等级整理结果，让用户更容易发现可用配置。

**订阅链接**是添加到兼容客户端中的 URL。客户端会从该 URL 下载当前列表；列表更新后，无需逐个导入配置。可用性和兼容性可能发生变化，因此检查通过仅代表某一时刻的状态，并不保证持续在线、速度、安全性或在所有地区均可访问。

> **请负责任地使用。** 遵守适用于你的法律和网络政策。配置由社区提供，流量可能经由第三方运营者转发。请勿将不可信的配置用于敏感活动。本项目并不运营索引中的所有服务器，也不为每台服务器背书。

## 🚀 快速开始

1. 为你的平台安装兼容 V2Ray 的客户端，例如 v2rayNG、V2RayN，或支持标准订阅 URL 的客户端。
2. 复制下方的订阅 URL。
3. 在客户端中选择 **添加订阅 / 从 URL 导入**，粘贴链接，然后更新订阅并选择一个配置。

### Top 100 订阅

```text
https://raw.githubusercontent.com/YOUR_GITHUB_USERNAME/v2ray-configs/main/top100.txt
```

[**⚡ 打开或复制 top100.txt**](https://raw.githubusercontent.com/YOUR_GITHUB_USERNAME/v2ray-configs/main/top100.txt)

Top 100 列表是从仓库当前符合条件的结果中挑选出的便捷集合。每次更新后，排名和可用性都可能变化。如果客户端无法导入该列表，请确认客户端所需的订阅格式，并在下方等级表中尝试相应格式。

## 🧭 订阅等级

根据你的需求选择列表。这些标签描述的是仓库采用的筛选和选择规则，并不保证实际性能或匿名性。

| 等级 | 适用对象 | 通用订阅 (`.txt`) | JSON 包 (`.json`) | Clash 兼容格式 (`.yaml`) |
|---|---|---|---|---|
| ✅ **已验证** | 通过已配置的校验和健康检查的配置 | [打开](subscriptions/verified.txt) | [打开](subscriptions/verified.json) | [打开](subscriptions/verified.yaml) |
| ⚡ **快速** | 根据最新响应测量结果排名靠前的配置 | [打开](subscriptions/fast.txt) | [打开](subscriptions/fast.json) | [打开](subscriptions/fast.yaml) |
| 🛡️ **安全** | 符合项目已配置的安全导向规则的配置 | [打开](subscriptions/secure.txt) | [打开](subscriptions/secure.json) | [打开](subscriptions/secure.yaml) |
| 🌍 **全部** | 当前可用的最完整集合，包括未进入专项等级的条目 | [打开](subscriptions/all.txt) | [打开](subscriptions/all.json) | [打开](subscriptions/all.yaml) |

> **格式说明：** 根据生成器的不同，`.txt` 订阅通常采用 Base64 编码，或使用受支持 URI 的纯文本列表。JSON 和 Clash YAML 是不同的客户端格式，不能互换。只保留发布流水线实际生成的格式链接；如果输出目录或文件名不同，请更新此表。

## 📱 扫码订阅

使用兼容的移动客户端扫描二维码，或在手机上打开 Top 100 链接。二维码应编码上方的完整订阅 URL，而不是某个单独服务器配置的链接。

<div align="center">

<!-- 确定规范 URL 后，请在此添加生成的二维码图片。 -->
<img src="assets/qr/top100.png" alt="Top 100 订阅 URL 的二维码" width="220" height="220">

**Top 100 · 移动端订阅**  
[打开订阅 URL](https://raw.githubusercontent.com/YOUR_GITHUB_USERNAME/v2ray-configs/main/top100.txt)

</div>

## 🧪 筛选流程

该流程逐步缩小配置集合范围。具体测试和阈值应与本仓库的自动化流程保持一致。

| 阶段 | 名称 | 含义 |
|---|---|---|
| **L0** | 收集 | 收集候选条目，规范化受支持的 URI/配置格式，并剔除格式错误或重复的记录。 |
| **L1** | 校验 | 在候选项进入可用索引前，检查必需字段、受支持协议、可解析性和基本策略规则。 |
| **L2** | 可达性 | 运行已配置的连接/健康探测，并记录带时间戳的结果。探测失败也可能由暂时性的网络状况导致。 |
| **L3** | 排名与发布 | 应用等级规则；在有测量数据时为符合条件的条目排序；生成订阅文件和仪表盘数据。 |

```text
社区来源 → L0 收集 → L1 校验 → L2 健康检查 → L3 选择 → 订阅
```

如果配置在后续运行中检查失败，它可能被调整到其他等级，也可能从列表中移除。自动检查只是参考信号，并非完整的安全审计。除所选协议本身提供的保护外，仓库不承诺额外加密；“安全”标签也不应被理解为独立的安全认证。

## 🏗️ 架构一览

```text
来源
  └─► 收集器 / 规范化处理
        └─► L0–L1：去重、解析、校验
              └─► L2：定期健康探测
                    └─► L3：分类与排名
                          ├─► top100.txt
                          ├─► subscriptions/{verified,fast,secure,all}.{txt,json,yaml}
                          ├─► index.json + health.json
                          └─► 仪表盘
```

- **自动化：** 定时 workflow 会刷新来源数据、执行已配置的检查，并发布生成的产物。运行历史请参阅 [Actions](https://github.com/YOUR_GITHUB_USERNAME/v2ray-configs/actions)。
- **单一事实来源：** `index.json` 应通过 `total` 提供当前条目总数；`health.json` 应通过 `online` 提供当前健康条目数，并在 `checked_at` 中提供 ISO-8601 时间戳。
- **实时 badges：** 上方的 Shields.io 动态 JSON badges 会直接从 `main` 分支的原始 JSON 文件读取这些字段。更改数据模型时，请保留此 schema，或相应更新 badge 查询。要正确显示 badges，公开文件必须无需身份验证即可访问，且内容为有效 JSON。
- **生成的输出：** 订阅文件和仪表盘数据应由流水线生成，而不是手动编辑。如果实际输出目录或文件名不同，请调整等级表中的链接。
- **仪表盘：** badge 指向 GitHub Pages 地址 `https://YOUR_GITHUB_USERNAME.github.io/v2ray-configs/`。如果项目使用其他托管平台，请将其改为已部署仪表盘的 URL。

## 🤝 参与贡献

欢迎提交 Issues 和 Pull Requests。你可以帮助改进解析器、提高健康检查的可靠性、补充受支持客户端的文档，或报告过期及格式错误的条目。请勿提交凭据、私钥、个人数据，或未经授权分享的配置。

提交 Pull Request 前，请说明变更内容；报告问题时请附上复现步骤，并避免提交生成的密钥或敏感日志。自动检查不能替代维护者的审核。

## 📌 项目链接

<div align="center">

[⚡ **Top 100 订阅**](https://raw.githubusercontent.com/YOUR_GITHUB_USERNAME/v2ray-configs/main/top100.txt)　
[📦 **全部配置**](subscriptions/all.txt)　
[📊 **仪表盘**](https://YOUR_GITHUB_USERNAME.github.io/v2ray-configs/)　
[💬 **Telegram**](https://t.me/YOUR_TELEGRAM_CHANNEL)　
[⭐ **在 GitHub 上加星**](https://github.com/YOUR_GITHUB_USERNAME/v2ray-configs/stargazers)

</div>

---

<div align="center">

旨在让发现配置更容易，但不保证连接可用。**保持好奇，核实来源，并负责任地使用。**

</div>
