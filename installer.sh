#!/usr/bin/env bash
# DNSniper Installer
# Usage: curl -sSL https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/installer.sh | bash

set -e

echo "
=== DNSniper Installer ===
"

# 1) Ensure running as root
if [[ $EUID -ne 0 ]]; then
  echo "Error: This installer must be run as root." >&2
  exit 1
fi

# 2) Detect package manager
if   command -v apt   &>/dev/null; then
  PKG_UPDATE="apt update"
  PKG_INSTALL="apt install -y"
elif command -v yum   &>/dev/null; then
  PKG_UPDATE="yum makecache"
  PKG_INSTALL="yum install -y"
elif command -v dnf   &>/dev/null; then
  PKG_UPDATE="dnf makecache"
  PKG_INSTALL="dnf install -y"
else
  echo "Error: Unsupported package manager. Please install dependencies manually: iptables, curl, dnsutils, sqlite3, cron." >&2
  exit 1
fi

# 3) Install dependencies
echo "Updating package lists..."
$PKG_UPDATE

echo "Installing dependencies: iptables, curl, dnsutils, sqlite3, cron"
$PKG_INSTALL iptables curl dnsutils sqlite3 cron

# 4) Download the DNSniper script
echo "Downloading DNSniper..."
curl -sfL https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/dnsniper.sh \
     -o /usr/local/bin/dnsniper
chmod +x /usr/local/bin/dnsniper

# 5) First-time initialization (creates configs, DB, cron job, etc.)
echo "Initializing DNSniper..."
/usr/local/bin/dnsniper

echo "
🎉 Installation complete! 🎉

• To open the interactive menu:
    dnsniper

A cron job has been set up to run DNSniper automatically every hour.
"
