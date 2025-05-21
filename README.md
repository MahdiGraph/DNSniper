# DNSniper | Domain-based Threat Mitigation Firewall

[🇮🇷 فارسی](README.fa.md)

<p align="center">
  <img src="https://img.shields.io/badge/Version-1.3.6--beta.1-brightgreen?logo=go&logoColor=white" alt="Version">
  <img src="https://img.shields.io/badge/Platform-Linux-blue?logo=linux&logoColor=white" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-success?logo=opensourceinitiative&logoColor=white" alt="License">
  <img src="https://img.shields.io/github/stars/MahdiGraph/DNSniper?style=social" alt="Stars">
  <img src="https://img.shields.io/github/forks/MahdiGraph/DNSniper?style=social" alt="Forks">
</p>

---

## 📌 Quick Install

```bash
bash <(curl -sSL https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/scripts/installer.sh)
````

---

## 📖 What is DNSniper?

**DNSniper** is a modern domain-based firewall written in Go. It periodically resolves domain names, identifies abusive or CDN-backed targets, and blocks them automatically using `iptables`. It’s designed to prevent abuse, protect infrastructure, and allow full control via a lightweight CLI.

### ✨ Key Features

* ⚡ Written in Go for performance and stability
* 📦 SQLite-powered domain/IP history tracking
* 🔄 Detects CDN-based hosting patterns
* 🔥 Automatically injects/removes firewall rules (IPv4 & IPv6)
* 📅 Built-in scheduler with cron
* 🧠 Self-contained agent for background operation
* 🛠️ Clean uninstall & easy management menu

### 🧰 Requirements

* Go (for building from source) or download binaries
* `iptables`, `ip6tables`
* `curl`
* `sqlite3`
* `cron`

### 💡 Supported Distros

* Debian / Ubuntu
* CentOS / RHEL
* Fedora / Arch / Alpine (manual dependency install may be needed)

---

## 💻 Usage

```bash
dnsniper            # Launch interactive menu
sudo dnsniper run   # Run immediately and apply block rules
```

### Menu Options:

* Run Now
* Update Default Domain List
* Schedule Runs (via cron)
* Configure Max IPs
* Add/Remove Domains
* View Status & Logs
* Clear Rules
* Uninstall DNSniper

---

## 📥 Releases

Grab precompiled binaries or use the installer above. Each release contains:

* Binary (per platform/arch)
* .sha256 file for integrity check

---

## 🙌 Contribute

We welcome suggestions, PRs and issue reports. If you’ve got a list of abusive domains, share it!

---

**Protect your infrastructure. Let DNSniper watch the domains for you.**