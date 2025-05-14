# DNSniper | Domain-based Threat Mitigation

<p align="center">
  <img src="https://img.shields.io/badge/Version-1.0.0-brightgreen?logo=bash&logoColor=white" alt="Version">
  <img src="https://img.shields.io/badge/Platform-Linux-blue?logo=linux&logoColor=white" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-success?logo=opensourceinitiative&logoColor=white" alt="License">
  <img src="https://img.shields.io/github/stars/MahdiGraph/DNSniper?style=social" alt="Stars">
  <img src="https://img.shields.io/github/forks/MahdiGraph/DNSniper?style=social" alt="Forks">
</p>

> **نسخهٔ فارسی:** به [README.fa.md](README.fa.md) مراجعه کنید.

---

## 📖 What is DNSniper?

DNSniper is a lightweight Bash script designed to mitigate DNS-based threats by:

* Periodically resolving a list of suspicious domains
* Blocking the resolved IPs using `iptables` and `ip6tables`
* Storing the last N IPs per domain in an SQLite database
* Detecting CDN usage by comparing recent IP changes
* Providing an interactive CLI menu for scheduling, limits, and domain management
* One-line installation via `installer.sh`, supporting major Linux distributions

### ✨ Key Features

* **Dual-Stack Support**: IPv4 & IPv6
* **CDN Detection**: Compares the last two resolves for IP changes
* **History Database**: SQLite stores up to N records per domain (configurable)
* **Safe Firewall Rules**: Uses comments (`DNSniper`) for clean removal
* **Interactive Menu**: Run, update, schedule, max IPs, add/remove domain, status, clear, uninstall
* **Automated Cron Job**: Runs periodically (`--run`), configurable via the menu

### 🔧 Requirements

* `bash` shell
* `iptables`, `ip6tables`
* `curl`
* `dnsutils` (for `dig`)
* `sqlite3`
* `cron` or `crontab`

**Supported Distributions:** Debian/Ubuntu, CentOS/RHEL, Fedora

### 🚀 Quick Install

```bash
curl -sSL https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/installer.sh | bash
```

### 💻 Usage

1. **Interactive Mode**:

   ```bash
   dnsniper
   ```
2. **Menu Options**:

   * Run Now, Update Defaults, Set Schedule, Max IPs
   * Add/Remove Domain, View Status, Clear Rules, Uninstall

<p align="center">
  **Keep your servers safe — block abusive domains automatically!**
</p>
