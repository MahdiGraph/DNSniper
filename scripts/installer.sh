#!/bin/bash

# DNSniper Installation Script

# Check for root access
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root"
    exit 1
fi

# Detect OS
if [ -f /etc/debian_version ]; then
    OS="debian"
    apt-get update
    apt-get install -y curl iptables iptables-persistent
elif [ -f /etc/redhat-release ]; then
    OS="redhat"
    if command -v dnf &> /dev/null; then
        dnf install -y curl iptables iptables-services
    else
        yum install -y curl iptables iptables-services
    fi
else
    echo "Unsupported OS"
    exit 1
fi

# Check for existing installation
if [ -d /etc/dnsniper ]; then
    echo "DNSniper installation found. What would you like to do?"
    echo "1) Reinstall with existing settings"
    echo "2) Clean install (remove existing installation)"
    echo "3) Uninstall DNSniper"
    echo "4) Cancel"
    read -p "Enter choice [1-4]: " choice
    case $choice in
        1)
            echo "Reinstalling with existing settings..."
            ;;
        2)
            echo "Performing clean install..."
            systemctl stop dnsniper-agent.service
            systemctl disable dnsniper-agent.service
            rm -rf /etc/dnsniper
            ;;
        3)
            echo "Uninstalling DNSniper..."
            systemctl stop dnsniper-agent.service
            systemctl disable dnsniper-agent.service
            rm -f /usr/local/bin/dnsniper
            rm -f /usr/local/bin/dnsniper-agent
            rm -rf /etc/dnsniper
            rm -f /etc/systemd/system/dnsniper-agent.service
            systemctl daemon-reload
            echo "DNSniper has been uninstalled."
            exit 0
            ;;
        4)
            echo "Operation cancelled."
            exit 0
            ;;
        *)
            echo "Invalid choice. Exiting."
            exit 1
            ;;
    esac
else
    echo "No existing installation found. Proceeding with fresh install."
fi

# Create necessary directories
mkdir -p /etc/dnsniper
mkdir -p /var/log/dnsniper

# Download binaries
LATEST_VERSION=$(curl -s https://api.github.com/repos/MahdiGraph/DNSniper/releases/latest | grep "tag_name" | cut -d'"' -f4)
DOWNLOAD_URL="https://github.com/MahdiGraph/DNSniper/releases/download/${LATEST_VERSION}"
echo "Downloading DNSniper ${LATEST_VERSION}..."
curl -L "${DOWNLOAD_URL}/dnsniper" -o /usr/local/bin/dnsniper
curl -L "${DOWNLOAD_URL}/dnsniper-agent" -o /usr/local/bin/dnsniper-agent

# Set permissions
chmod +x /usr/local/bin/dnsniper
chmod +x /usr/local/bin/dnsniper-agent

# Create systemd service
cat > /etc/systemd/system/dnsniper-agent.service << EOF
[Unit]
Description=DNSniper Agent Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/dnsniper-agent
Restart=on-failure
RestartSec=10
LockPersonality=true

[Install]
WantedBy=multi-user.target
EOF

# Start service
systemctl daemon-reload
systemctl enable dnsniper-agent.service
systemctl start dnsniper-agent.service

# Setup iptables
iptables -N DNSniper 2>/dev/null || iptables -F DNSniper
iptables -I INPUT -j DNSniper
iptables -I OUTPUT -j DNSniper
ip6tables -N DNSniper6 2>/dev/null || ip6tables -F DNSniper6
ip6tables -I INPUT -j DNSniper6
ip6tables -I OUTPUT -j DNSniper6

# Save iptables rules
if [ "$OS" == "debian" ]; then
    iptables-save > /etc/iptables/rules.v4
    ip6tables-save > /etc/iptables/rules.v6
else
    service iptables save
    service ip6tables save
fi

echo "DNSniper installation completed successfully!"
echo "Run 'dnsniper' to start the interactive menu."