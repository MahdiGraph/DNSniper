#!/usr/bin/env bash
# DNSniper Simplified Installer 
# Version: 2.0.0

# Enable error reporting
set -e

# ANSI color codes
RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[33m'
BLUE='\e[34m'
NC='\e[0m'

echo -e "${BLUE}DNSniper Simplified Installer${NC}"

# Paths
BASE_DIR="/etc/dnsniper"
BIN_PATH="/usr/local/bin/dnsniper"

# Check root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error: This installer must be run as root (sudo).${NC}"
    exit 1
fi

# Check for previous installation
if [[ -f "$BIN_PATH" || -d "$BASE_DIR" ]]; then
    echo -e "${YELLOW}Previous installation detected.${NC}"
    read -p "Would you like to (1) upgrade or (2) clean install? [1/2]: " choice
    
    case "$choice" in
        1)
            echo -e "${YELLOW}Upgrading DNSniper...${NC}"
            # We'll keep existing files
            ;;
        2)
            echo -e "${YELLOW}Performing clean install...${NC}"
            echo "Removing old files..."
            rm -f "$BIN_PATH" 2>/dev/null || echo "Could not remove $BIN_PATH"
            rm -rf "$BASE_DIR" 2>/dev/null || echo "Could not remove $BASE_DIR"
            ;;
        *)
            echo -e "${RED}Invalid choice. Exiting.${NC}"
            exit 1
            ;;
    esac
fi

echo -e "${YELLOW}Step 1: Creating directories${NC}"
mkdir -p "$BASE_DIR" || { echo "Failed to create $BASE_DIR"; exit 1; }
echo "Created directory: $BASE_DIR"

echo -e "${YELLOW}Step 2: Installing main script${NC}"
# Download main script
echo "Downloading DNSniper script..."
if curl -s -o "$BIN_PATH" "https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/dnsniper.sh"; then
    chmod +x "$BIN_PATH"
    echo "Downloaded and installed main script to $BIN_PATH"
else
    echo -e "${RED}Failed to download main script.${NC}"
    exit 1
fi

echo -e "${YELLOW}Step 3: Creating default configuration${NC}"
# Create basic config file
cat > "$BASE_DIR/config.conf" << EOF
# DNSniper Configuration
max_ips=10
timeout=30
update_url='https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/domains-default.txt'
auto_update=1
block_source=1
block_destination=1
logging_enabled=1
EOF
echo "Created configuration file"

echo -e "${YELLOW}Step 4: Creating empty domain lists${NC}"
# Create empty domain files
touch "$BASE_DIR/domains-default.txt" "$BASE_DIR/domains-add.txt" "$BASE_DIR/domains-remove.txt"
touch "$BASE_DIR/ips-add.txt" "$BASE_DIR/ips-remove.txt"
echo "Created empty domain lists"

echo -e "${YELLOW}Step 5: Setting up scheduling${NC}"
# Set up basic scheduling
if command -v systemctl &>/dev/null; then
    echo "Using systemd for scheduling..."
    
    # Create systemd service
    cat > /etc/systemd/system/dnsniper.service << EOF
[Unit]
Description=DNSniper Domain Threat Mitigation
After=network.target

[Service]
Type=oneshot
ExecStart=$BIN_PATH --run
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

    # Create systemd timer
    cat > /etc/systemd/system/dnsniper.timer << EOF
[Unit]
Description=Run DNSniper hourly
Requires=dnsniper.service

[Timer]
Unit=dnsniper.service
OnBootSec=60
OnUnitActiveSec=1h

[Install]
WantedBy=timers.target
EOF

    # Enable and start timer
    systemctl daemon-reload
    systemctl enable dnsniper.timer
    echo "Systemd timer enabled"
else
    echo "Using cron for scheduling..."
    (crontab -l 2>/dev/null | grep -v "$BIN_PATH"; echo "0 * * * * $BIN_PATH --run > /dev/null 2>&1") | crontab -
    echo "Cron job created"
fi

echo -e "${YELLOW}Step 6: Running initial setup${NC}"
# Run initial setup
echo "Running DNSniper for initial setup..."
"$BIN_PATH" --run &
echo "DNSniper is now running in the background"

echo -e "${GREEN}Installation completed successfully!${NC}"
echo "You can now use 'sudo dnsniper' to manage DNSniper."
