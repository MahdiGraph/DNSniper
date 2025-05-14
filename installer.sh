#!/usr/bin/env bash
# DNSniper Installer
# Usage: curl -sSL https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/installer.sh | bash

set -e

echo "
=== DNSniper Installer ===
"

# 1) root check
if [[ $EUID -ne 0 ]]; then
  echo "Error: Run as root." >&2
  exit 1
fi

# 2) detect package manager
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
  echo "Error: Unsupported package manager. Install: iptables, curl, dnsutils, sqlite3, cron." >&2
  exit 1
fi

# 3) install deps
echo "Updating package lists..."
$PKG_UPDATE
echo "Installing: iptables curl dnsutils sqlite3 cron"
$PKG_INSTALL iptables curl dnsutils sqlite3 cron

# 4) fetch script into BASE_DIR
BASE_DIR="/etc/dnsniper"
BIN_PATH="$BASE_DIR/dnsniper.sh"
echo "Setting up directory $BASE_DIR..."
mkdir -p "$BASE_DIR"

echo "Downloading DNSniper core script..."
curl -sfL https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/dnsniper.sh \
     -o "$BIN_PATH"
chmod +x "$BIN_PATH"

# 5) create symlink
echo "Creating symlink /usr/local/bin/dnsniper → $BIN_PATH"
ln -sf "$BIN_PATH" /usr/local/bin/dnsniper

# 6) initialize (config, DB, cron)
echo "Initializing DNSniper..."
dnsniper