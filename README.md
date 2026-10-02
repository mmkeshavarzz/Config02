<!--
  v2ray-configs — repository landing page
  Before publishing: replace YOUR_GITHUB_USERNAME / YOUR_TELEGRAM_CHANNEL,
  confirm the generated subscription filenames, and add the assets noted below.
-->

<div align="center">

# 🌐 v2ray-configs

### A curated, continuously checked index of community-provided connection configurations.

<!-- Replace this placeholder with the project’s original hero artwork. -->
<picture>
  <img src="assets/readme-hero.png" alt="v2ray-configs — curated connections, clear status, simple subscriptions" width="900">
</picture>

<br>

[![CI pipeline](https://github.com/YOUR_GITHUB_USERNAME/v2ray-configs/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_GITHUB_USERNAME/v2ray-configs/actions/workflows/ci.yml)
[![Auto-update](https://img.shields.io/badge/auto--update-enabled-29a36a?logo=dependabot&logoColor=white)](#architecture)
[![GitHub stars](https://img.shields.io/github/stars/YOUR_GITHUB_USERNAME/v2ray-configs?style=flat&logo=github&label=stars)](https://github.com/YOUR_GITHUB_USERNAME/v2ray-configs/stargazers)
[![Telegram](https://img.shields.io/badge/Telegram-community-26A5E4?logo=telegram&logoColor=white)](https://t.me/YOUR_TELEGRAM_CHANNEL)
[![Dashboard](https://img.shields.io/badge/dashboard-live-6857d5?logo=githubpages)](https://YOUR_GITHUB_USERNAME.github.io/v2ray-configs/)

<!-- Live values are read from the repository's JSON data files via Shields.io. -->
[![Total indexed configs](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2FYOUR_GITHUB_USERNAME%2Fv2ray-configs%2Fmain%2Findex.json&query=%24.total&label=indexed%20configs&color=5470c6&logo=serverfault)](index.json)
[![Currently healthy](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2FYOUR_GITHUB_USERNAME%2Fv2ray-configs%2Fmain%2Fhealth.json&query=%24.online&label=healthy%20now&color=2e9d68&logo=activity)](health.json)
[![Last health check](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2FYOUR_GITHUB_USERNAME%2Fv2ray-configs%2Fmain%2Fhealth.json&query=%24.checked_at&label=last%20check&color=718096)](health.json)

**[⚡ Get the Top 100](https://raw.githubusercontent.com/YOUR_GITHUB_USERNAME/v2ray-configs/main/top100.txt)** · **[📊 Open dashboard](https://YOUR_GITHUB_USERNAME.github.io/v2ray-configs/)** · **[💬 Join Telegram](https://t.me/YOUR_TELEGRAM_CHANNEL)** · **[⭐ Star this project](https://github.com/YOUR_GITHUB_USERNAME/v2ray-configs)**

[🇬🇧 English](README.md) · [🇮🇷 فارسی](README_FA.md) · [🇷🇺 Русский](README_RU.md) · [🇨🇳 中文](README_ZH.md)

</div>

---

## 👋 What is this repository?

`v2ray-configs` organizes community-submitted V2Ray-compatible connection profiles and publishes subscription files for supported clients. The project aims to make discovery easier by applying automated checks and separating results into useful quality tiers.

A **subscription link** is a URL you add to a compatible client. The client downloads the current list from that URL; when the list is refreshed, you do not need to import every profile one by one. Availability and compatibility can change, so a passing check is only a point-in-time signal—not a promise of uptime, speed, security, or access in every region.

> **Use responsibly.** Follow the laws and network policies that apply to you. Configurations are community-provided and may route traffic through third-party operators. Do not use an untrusted profile for sensitive activity. This project does not operate or endorse every server in its index.

## 🚀 Quick start

1. Install a V2Ray-compatible client for your platform, such as v2rayNG, V2RayN, or a client that supports standard subscription URLs.
2. Copy the subscription URL below.
3. In your client, choose **Add subscription / Import from URL**, paste the link, then update the subscription and select a profile.

### Top 100 subscription

```text
https://raw.githubusercontent.com/YOUR_GITHUB_USERNAME/v2ray-configs/main/top100.txt
```

[**⚡ Open or copy top100.txt**](https://raw.githubusercontent.com/YOUR_GITHUB_USERNAME/v2ray-configs/main/top100.txt)

The Top 100 list is a convenience selection from the repository’s current eligible results. Ranking and availability may change after each update. If your client cannot import the list, check the client’s expected subscription format and try the matching format in the tier table below.

## 🧭 Subscription tiers

Choose a list based on your priorities. These labels describe the repository’s filtering and selection policy; they are not guarantees of real-world performance or anonymity.

| Tier | Intended for | Universal subscription (`.txt`) | JSON bundle (`.json`) | Clash-compatible (`.yaml`) |
|---|---|---|---|---|
| ✅ **Verified** | Profiles that pass the configured validation and health checks | [Open](subscriptions/verified.txt) | [Open](subscriptions/verified.json) | [Open](subscriptions/verified.yaml) |
| ⚡ **Fast** | Profiles ranked highly by the latest measured response checks | [Open](subscriptions/fast.txt) | [Open](subscriptions/fast.json) | [Open](subscriptions/fast.yaml) |
| 🛡️ **Secure** | Profiles meeting the project’s configured security-oriented rules | [Open](subscriptions/secure.txt) | [Open](subscriptions/secure.json) | [Open](subscriptions/secure.yaml) |
| 🌍 **All** | The broadest available collection, including entries not in the focused tiers | [Open](subscriptions/all.txt) | [Open](subscriptions/all.json) | [Open](subscriptions/all.yaml) |

> **Format note:** A `.txt` subscription is commonly Base64-encoded or a plain list of supported URIs, depending on the generator. JSON and Clash YAML are separate client formats, not interchangeable files. Keep only links for formats the publishing pipeline actually produces; update this table if output paths differ.

## 📱 Scan to subscribe

Scan the QR code with a compatible mobile client, or open the Top 100 link on your phone. The QR should encode the exact subscription URL above—not an individual server profile.

<div align="center">

<!-- Add the generated QR image here after the canonical URL is finalized. -->
<img src="assets/qr/top100.png" alt="QR code for the Top 100 subscription URL" width="220" height="220">

**Top 100 · mobile subscription**  
[Open the subscription URL](https://raw.githubusercontent.com/YOUR_GITHUB_USERNAME/v2ray-configs/main/top100.txt)

</div>

## 🧪 How filtering works

The funnel progressively narrows the collection. Exact tests and thresholds should be kept in sync with the automation in this repository.

| Stage | Name | What it means |
|---|---|---|
| **L0** | Intake | Collect candidate entries, normalize supported URI/config formats, and discard malformed or duplicate records. |
| **L1** | Validation | Check required fields, supported protocols, parseability, and basic policy rules before a candidate enters the usable index. |
| **L2** | Reachability | Run configured connection/health probes and record a timestamped result. A failed probe can also reflect temporary network conditions. |
| **L3** | Ranking & publication | Apply tier rules, rank eligible entries where measurements exist, and generate the published subscription files and dashboard data. |

```text
Community sources → L0 intake → L1 validation → L2 health checks → L3 selection → subscriptions
```

A profile may move between tiers—or disappear—when it fails a later run. Checks are automated signals, not a full security audit. The repository does not promise encryption beyond what the selected protocol provides, and a “secure” label must not be interpreted as an independent security certification.

## 🏗️ Architecture at a glance

```text
Sources
  └─► Collector / normalizer
        └─► L0–L1: deduplicate, parse, validate
              └─► L2: scheduled health probes
                    └─► L3: classify and rank
                          ├─► top100.txt
                          ├─► subscriptions/{verified,fast,secure,all}.{txt,json,yaml}
                          ├─► index.json + health.json
                          └─► dashboard
```

- **Automation:** A scheduled workflow refreshes source data, performs configured checks, and publishes generated artifacts. See [Actions](https://github.com/YOUR_GITHUB_USERNAME/v2ray-configs/actions) for run history.
- **Single source of truth:** `index.json` should expose the current aggregate count at `total`; `health.json` should expose the current healthy count at `online` and an ISO-8601 timestamp at `checked_at`.
- **Live badges:** The Shields.io dynamic JSON badges above read those fields directly from the raw `main`-branch JSON files. Preserve this schema (or update the badge queries) when changing the data model. Public files must be accessible without authentication and valid JSON for the badges to render.
- **Generated outputs:** Subscription files and dashboard data should be produced by the pipeline rather than edited by hand. Adjust the tier links if the actual output directory or filenames differ.
- **Dashboard:** The badge points to GitHub Pages at `https://YOUR_GITHUB_USERNAME.github.io/v2ray-configs/`. Change it to the deployed dashboard URL if the project uses another host.

## 🤝 Contribute

Issues and pull requests are welcome. Useful contributions include improving parsers, making health checks more reliable, documenting supported clients, and reporting stale or malformed entries. Please do not submit credentials, private keys, personal data, or configurations you do not have permission to share.

Before opening a pull request, describe the change, include reproduction steps for bugs, and avoid committing generated secrets or sensitive logs. Automated checks do not replace maintainer review.

## 📌 Project links

<div align="center">

[⚡ **Top 100 subscription**](https://raw.githubusercontent.com/YOUR_GITHUB_USERNAME/v2ray-configs/main/top100.txt)　
[📦 **All configurations**](subscriptions/all.txt)　
[📊 **Dashboard**](https://YOUR_GITHUB_USERNAME.github.io/v2ray-configs/)　
[💬 **Telegram**](https://t.me/YOUR_TELEGRAM_CHANNEL)　
[⭐ **Star on GitHub**](https://github.com/YOUR_GITHUB_USERNAME/v2ray-configs/stargazers)

</div>

---

<div align="center">

Made for easier discovery—not guaranteed connectivity. **Stay curious, verify your sources, and use responsibly.**

</div>
