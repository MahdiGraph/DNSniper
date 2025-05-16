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
    systemctl start dnsniper.timer
    echo -e "${GREEN}DNSniper scheduled with systemd timer (runs hourly)${NC}"
    
    # Update config to reflect enabled status
    if [[ -f "$BASE_DIR/config.conf" ]]; then
        sed -i '/^automatic_execution=/d' "$BASE_DIR/config.conf" 2>/dev/null || true
    else
        touch "$BASE_DIR/config.conf"
    fi
    echo "automatic_execution=1" >> "$BASE_DIR/config.conf"
fi

# Initialize database
echo -e ""
echo -e "${CYAN}${BOLD}INITIALIZING DATABASE${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"

# Create default config if it doesn't exist
if [[ ! -f "$BASE_DIR/config.conf" ]]; then
    cat > "$BASE_DIR/config.conf" << EOF
# DNSniper Configuration
max_ips=10
timeout=30
update_url='https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/domains-default.txt'
auto_update=1
expire_enabled=1
expire_multiplier=5
block_source=1
block_destination=1
logging_enabled=1
log_max_size=10
log_rotate_count=5
automatic_execution=$([[ "$sched_choice" == "1" ]] && echo "1" || echo "0")
EOF
fi

# Initialize database
if command -v sqlite3 &>/dev/null; then
    sqlite3 "$BASE_DIR/history.db" <<EOF
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS history(
    domain TEXT,
    ips    TEXT,
    ts     INTEGER
);
CREATE INDEX IF NOT EXISTS idx_history_domain ON history(domain);
CREATE TABLE IF NOT EXISTS expired_domains(
    domain TEXT PRIMARY KEY,
    last_seen TEXT,
    source TEXT
);
EOF
    echo -e "${GREEN}Database initialized successfully${NC}"
else
    echo -e "${YELLOW}Warning: sqlite3 not found, database functionality will be limited${NC}"
fi

# Set initial status
echo "READY" > "$BASE_DIR/status.txt"

# Ask about running initial update
echo -e ""
echo -e "${CYAN}${BOLD}INITIAL SETUP${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"
echo -e "${YELLOW}Do you want to run an initial update and domain blocking now?${NC}"
echo -e "1) Yes - Run in background now"
echo -e "2) No - I'll do it later"
read -rp "Choose an option [1-2]: " run_choice

# Wait for valid input
while [[ ! "$run_choice" =~ ^[1-2]$ ]]; do
    echo -e "${RED}Invalid selection. Please enter 1 or 2${NC}"
    read -rp "Choose an option [1-2]: " run_choice
done

if [[ "$run_choice" == "1" ]]; then
    echo -e "${YELLOW}Starting initial domain update and blocking (runs in background)...${NC}"
    
    # Run the service once manually
    systemctl start dnsniper.service
    
    echo -e "${GREEN}Initial setup triggered. It will run in the background.${NC}"
    echo -e "${YELLOW}You can check status with:${NC} sudo dnsniper --status"
else
    echo -e "${YELLOW}Skipping initial setup. You can run it later with:${NC}"
    echo -e "  ${GREEN}sudo systemctl start dnsniper.service${NC}"
    echo -e "  or"
    echo -e "  ${GREEN}sudo dnsniper --run${NC}"
fi

# Final instructions
echo -e ""
echo -e "${CYAN}${BOLD}INSTALLATION COMPLETE!${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"
echo -e "${YELLOW}DNSniper is now installed.${NC}"
echo -e ""
echo -e "${YELLOW}Commands:${NC}"
echo -e "  ${GREEN}sudo dnsniper${NC}           - Open the interactive menu"
echo -e "  ${GREEN}sudo dnsniper --status${NC}  - Check current status"
echo -e "  ${GREEN}sudo dnsniper --help${NC}    - Show all available commands"
echo -e ""

if [[ "$sched_choice" == "1" ]]; then
    echo -e "${YELLOW}The service will automatically update and run in the background.${NC}"
    echo -e "${YELLOW}You don't need to manually run it unless you want to make changes.${NC}"
else
    echo -e "${YELLOW}Automatic scheduling is disabled. Use these commands to run manually:${NC}"
    echo -e "  ${GREEN}sudo systemctl start dnsniper.service${NC}"
    echo -e "  or"
    echo -e "  ${GREEN}sudo dnsniper --run${NC}"
fi

echo -e ""
echo -e "${BLUE}${BOLD}Protect your servers against malicious domains with DNSniper!${NC}"
echo -e ""
echo -e "${YELLOW}Installation log saved to: $LOG_FILE${NC}"