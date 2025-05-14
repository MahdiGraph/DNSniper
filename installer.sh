#!/usr/bin/env bash
# DNSniper Installer
# Usage: curl -sSL https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/installer.sh | bash

set -e

echo "
=== DNSniper Installer ===
" 

# Ensure root
if [[ $EUID -ne 0 ]]; then
  echo "Error: This installer must be run as root." >&2
  exit 1
fi

# Detect package manager
if command -v apt &>/dev/null; then
  PKG_UPDATE="apt update -y"
  PKG_INSTALL="apt install -y"
elif command -v yum &>/dev/null; then
  PKG_UPDATE="yum makecache"
  PKG_INSTALL="yum install -y"
elif command -v dnf &>/dev/null; then
  PKG_UPDATE="dnf makecache"
  PKG_INSTALL="dnf install -y"
else
  echo "Error: Unsupported package manager. Install dependencies manually: iptables, ip6tables, curl, dnsutils, sqlite3, cron." >&2
  exit 1
fi

# Install dependencies
echo "Updating package lists..."
$PKG_UPDATE

echo "Installing dependencies: iptables, ip6tables, curl, dnsutils, sqlite3, cron"
$PKG_INSTALL iptables ip6tables curl dnsutils sqlite3 cron

# Download DNSniper script
echo "Downloading DNSniper..."
curl -sfL https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/dnsniper.sh -o /usr/local/bin/dnsniper.sh
chmod +x /usr/local/bin/dnsniper.sh

# Run initialization
echo "Initializing DNSniper..."
/usr/local/bin/dnsniper.sh

echo "
Installation complete! DNSniper is ready.
Run 'dnsniper.sh' to open the interactive menu, or it will run automatically per schedule.
"
