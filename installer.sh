#!/usr/bin/env bash
# DNSniper Installer
# Usage: curl -sSL https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/installer.sh | bash
set -e

# ANSI color codes
RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[33m'
BLUE='\e[34m'
CYAN='\e[36m'
MAGENTA='\e[35m'
WHITE='\e[97m'
BOLD='\e[1m'
NC='\e[0m'

# Display banner
echo -e "${BLUE}${BOLD}"
echo -e "    ____  _   _ ____       _                 "
echo -e "   |   _\\| \\ | /_ __|_ __ (_)_ __   ___ _ __ "
echo -e "   | | | |  \\| \\___ \\ '_ \\| | '_ \\ / _\\ '__|"
echo -e "   | |_| | |\\  |___) | | | | | |_) |  __/ |  "
echo -e "   |____/|_| \\_|____/|_| |_|_| .__/ \\___|_|  "
echo -e "                             |_|              "
echo -e "${GREEN}${BOLD} Domain-based Network Threat Mitigation v1.4.0 ${NC}"
echo -e ""

# Paths
BASE_DIR="/etc/dnsniper"
BIN_PATH="/usr/local/bin/dnsniper"
TMP_SCRIPT="/tmp/dnsniper.sh"
BACKUP_DIR="/tmp/dnsniper-backup-$(date +%Y%m%d-%H%M%S)"
LOG_FILE="/tmp/dnsniper-install.log"
GITHUB_URL="https://raw.githubusercontent.com/MahdiGraph/DNSniper/main"

# Check root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}${BOLD}Error:${NC} This installer must be run as root (sudo)." >&2
    exit 1
fi

# Setup logging
exec > >(tee -a "$LOG_FILE") 2>&1

echo -e "${CYAN}${BOLD}CHECKING PREVIOUS INSTALLATION${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"

# Check for previous installation
if [[ -f "$BIN_PATH" || -d "$BASE_DIR" ]]; then
    echo -e "${YELLOW}${BOLD}Previous installation detected!${NC}"
    echo -e "1) Upgrade (keeps your configurations)"
    echo -e "2) Clean install (removes all configurations)"
    echo -e "3) Cancel installation"
    
    read -rp "Choose an option [1-3]: " choice
    
    case "$choice" in
        1)
            echo -e "${YELLOW}Upgrading DNSniper...${NC}"
            
            # Create backup directory
            mkdir -p "$BACKUP_DIR"
            
            # Stop any running processes and services
            echo -e "${BLUE}Stopping DNSniper services...${NC}"
            
            # Kill any running DNSniper processes
            pkill -f "/usr/local/bin/dnsniper" 2>/dev/null || true
            
            # Disable and stop systemd services if they exist
            if command -v systemctl &>/dev/null; then
                systemctl stop dnsniper.timer 2>/dev/null || true
                systemctl stop dnsniper.service 2>/dev/null || true
                systemctl stop dnsniper-firewall.service 2>/dev/null || true
                
                systemctl disable dnsniper.timer 2>/dev/null || true
                systemctl disable dnsniper.service 2>/dev/null || true
                systemctl disable dnsniper-firewall.service 2>/dev/null || true
            fi
            
            # Remove cron jobs
            echo -e "${BLUE}Removing cron jobs...${NC}"
            crontab -l 2>/dev/null | grep -v "dnsniper" | crontab - 2>/dev/null || true
            
            # Backup configuration
            if [[ -d "$BASE_DIR" ]]; then
                echo -e "${YELLOW}Backing up configuration...${NC}"
                cp -r "$BASE_DIR"/* "$BACKUP_DIR/" 2>/dev/null || true
                echo -e "${GREEN}Configuration backed up to: $BACKUP_DIR${NC}"
            fi
            
            # Remove binary
            rm -f "$BIN_PATH" 2>/dev/null || true
            ;;
        2)
            echo -e "${YELLOW}Performing clean install...${NC}"
            
            # Kill any running DNSniper processes
            pkill -f "/usr/local/bin/dnsniper" 2>/dev/null || true
            
            # Clean up systemd services
            if command -v systemctl &>/dev/null; then
                systemctl stop dnsniper.timer 2>/dev/null || true
                systemctl stop dnsniper.service 2>/dev/null || true
                systemctl stop dnsniper-firewall.service 2>/dev/null || true
                
                systemctl disable dnsniper.timer 2>/dev/null || true
                systemctl disable dnsniper.service 2>/dev/null || true
                systemctl disable dnsniper-firewall.service 2>/dev/null || true
                
                rm -f /etc/systemd/system/dnsniper.service 2>/dev/null || true
                rm -f /etc/systemd/system/dnsniper.timer 2>/dev/null || true
                rm -f /etc/systemd/system/dnsniper-firewall.service 2>/dev/null || true
                
                systemctl daemon-reload 2>/dev/null || true
            fi
            
            # Remove cron jobs
            crontab -l 2>/dev/null | grep -v "dnsniper" | crontab - 2>/dev/null || true
            
            # Clean up firewall rules if DNSniper binary exists
            if [[ -f "$BIN_PATH" ]]; then
                echo -e "${YELLOW}Cleaning firewall rules...${NC}"
                "$BIN_PATH" --clean-rules 2>/dev/null || true
            fi
            
            # Remove files
            rm -f "$BIN_PATH" 2>/dev/null || true
            rm -rf "$BASE_DIR" 2>/dev/null || true
            
            echo -e "${GREEN}Previous installation completely removed.${NC}"
            ;;
        3|*)
            echo -e "${RED}Installation cancelled.${NC}"
            exit 0
            ;;
    esac
fi

echo -e "${CYAN}${BOLD}SYSTEM DETECTION${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"

# Detect package manager and set command variables
if command -v apt &>/dev/null; then
    PKG_MANAGER="apt"
    PKG_UPDATE="apt update"
    PKG_INSTALL="apt install -y"
    DEPS="iptables iptables-persistent curl dnsutils sqlite3 cron procps"
elif command -v dnf &>/dev/null; then
    PKG_MANAGER="dnf"
    PKG_UPDATE="dnf check-update || true"
    PKG_INSTALL="dnf install -y"
    DEPS="iptables iptables-services curl bind-utils sqlite crontabs procps-ng"
elif command -v yum &>/dev/null; then
    PKG_MANAGER="yum"
    PKG_UPDATE="yum check-update || true"
    PKG_INSTALL="yum install -y"
    DEPS="iptables iptables-services curl bind-utils sqlite crontabs procps-ng"
else
    echo -e "${YELLOW}${BOLD}Warning:${NC} Unsupported package manager."
    echo -e "You'll need to manually install these dependencies:"
    echo -e "- iptables\n- ip6tables\n- curl\n- bind-utils/dnsutils (for dig)\n- sqlite3\n- cron/crontabs\n- procps"
    read -rp "Continue anyway? [y/N]: " response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        echo -e "${RED}Installation cancelled.${NC}"
        exit 1
    fi
    PKG_MANAGER="manual"
fi

echo -e "${GREEN}Detected system: ${PKG_MANAGER}${NC}"

# Check system compatibility
if ! command -v iptables &>/dev/null; then
    echo -e "${RED}${BOLD}Error:${NC} iptables not found. DNSniper requires iptables."
    exit 1
fi

# Install dependencies
if [[ "$PKG_MANAGER" != "manual" ]]; then
    echo -e ""
    echo -e "${CYAN}${BOLD}DEPENDENCIES${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    echo -e "${YELLOW}Updating package lists...${NC}"
    
    # Use a timeout to prevent hanging on package updates
    timeout 120 bash -c "$PKG_UPDATE" || {
        echo -e "${YELLOW}Package update timed out, continuing anyway...${NC}"
    }
    
    echo -e "${YELLOW}Installing required packages:${NC} ${DEPS}"
    
    # Install packages with error handling
    if ! $PKG_INSTALL $DEPS; then
        echo -e "${YELLOW}Some packages failed to install. Continuing anyway...${NC}"
        echo -e "${YELLOW}You may need to manually install missing dependencies.${NC}"
    else
        echo -e "${GREEN}Dependencies successfully installed.${NC}"
    fi
else
    echo -e ""
    echo -e "${CYAN}${BOLD}DEPENDENCIES CHECK${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    missing=()
    for cmd in iptables ip6tables curl dig sqlite3 crontab ps; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${RED}${BOLD}Missing dependencies:${NC} ${missing[*]}"
        echo -e "${YELLOW}Please install these dependencies and run the installer again.${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}All dependencies present.${NC}"
fi

# Create directories
echo -e ""
echo -e "${CYAN}${BOLD}DIRECTORY SETUP${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"

mkdir -p "$BASE_DIR/logs"
echo -e "${GREEN}Directory created: $BASE_DIR${NC}"

# Setup firewall persistence according to system type
echo -e ""
echo -e "${CYAN}${BOLD}FIREWALL PERSISTENCE${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"

# Detect OS type
if [[ -f /etc/debian_version ]]; then
    OS_TYPE="debian"
    echo -e "${GREEN}Debian/Ubuntu detected, using iptables-persistent${NC}"
    
    # Make sure iptables-persistent is installed
    if ! dpkg -l | grep -q iptables-persistent; then
        echo -e "${YELLOW}Installing iptables-persistent...${NC}"
        # Preseeding debconf to avoid interactive prompts
        echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections
        echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections
        apt install -y iptables-persistent
    fi
    
    mkdir -p /etc/iptables
elif [[ -f /etc/redhat-release ]]; then
    OS_TYPE="redhat"
    echo -e "${GREEN}RHEL/CentOS detected, using iptables-services${NC}"
    
    # Make sure iptables-services is enabled
    if command -v systemctl &>/dev/null; then
        systemctl enable iptables ip6tables &>/dev/null || true
    fi
elif [[ -f /etc/fedora-release ]]; then
    OS_TYPE="fedora"
    echo -e "${GREEN}Fedora detected, using iptables-services${NC}"
    
    # Make sure iptables-services is enabled
    if command -v systemctl &>/dev/null; then
        systemctl enable iptables ip6tables &>/dev/null || true
    fi
else
    OS_TYPE="unknown"
    echo -e "${YELLOW}Unknown OS, will create systemd service for persistence${NC}"
fi

# Download script
echo -e ""
echo -e "${CYAN}${BOLD}SCRIPT DOWNLOAD${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"

# Download with retry logic
MAX_RETRIES=3
retry_count=0
download_success=false

while [[ $retry_count -lt $MAX_RETRIES && $download_success == false ]]; do
    echo -e "${YELLOW}Downloading DNSniper script (attempt $((retry_count+1))/$MAX_RETRIES)...${NC}"
    
    if curl -sfL --connect-timeout 30 --max-time 60 "$GITHUB_URL/dnsniper.sh" -o "$TMP_SCRIPT"; then
        download_success=true
    else
        retry_count=$((retry_count+1))
        
        if [[ $retry_count -lt $MAX_RETRIES ]]; then
            echo -e "${YELLOW}Download failed, retrying in 3 seconds...${NC}"
            sleep 3
        else
            echo -e "${RED}${BOLD}Error:${NC} Failed to download DNSniper script after $MAX_RETRIES attempts."
            exit 1
        fi
    fi
done

# Verify script health
if [[ ! -s "$TMP_SCRIPT" ]]; then
    echo -e "${RED}${BOLD}Error:${NC} Downloaded script is empty."
    exit 1
fi

# Make sure script is executable
chmod +x "$TMP_SCRIPT"

# Test the script with a simple command
if ! "$TMP_SCRIPT" --version &>/dev/null; then
    echo -e "${RED}${BOLD}Warning:${NC} Script test failed. Installing anyway, but there might be issues."
fi

# Check for backup to restore
if [[ -d "$BACKUP_DIR" && $(ls -A "$BACKUP_DIR" 2>/dev/null) ]]; then
    echo -e "${YELLOW}Found backup from previous installation.${NC}"
    read -rp "Restore configuration from backup? [Y/n]: " restore_backup
    
    if [[ ! "$restore_backup" =~ ^[Nn]$ ]]; then
        echo -e "${BLUE}Restoring configuration from backup...${NC}"
        mkdir -p "$BASE_DIR"
        cp -r "$BACKUP_DIR"/* "$BASE_DIR/" 2>/dev/null || true
        echo -e "${GREEN}Configuration restored.${NC}"
    else
        echo -e "${YELLOW}Skipping backup restoration.${NC}"
    fi
fi

# Move script to final location
echo -e "${BLUE}Installing DNSniper...${NC}"
cp "$TMP_SCRIPT" "$BASE_DIR/dnsniper.sh"
ln -sf "$BASE_DIR/dnsniper.sh" "$BIN_PATH"
chmod +x "$BASE_DIR/dnsniper.sh" "$BIN_PATH"

# Clean up
rm -f "$TMP_SCRIPT"

echo -e "${GREEN}DNSniper script installed to: $BIN_PATH${NC}"

# Initialize DNSniper
echo -e ""
echo -e "${CYAN}${BOLD}INITIALIZATION${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"

if "$BIN_PATH" --version &>/dev/null; then
    echo -e "${GREEN}DNSniper successfully initialized.${NC}"
    
    # Add default empty block list file if not exists
    if [[ ! -s "$BASE_DIR/domains-default.txt" ]]; then
        echo "# Default domains to block" > "$BASE_DIR/domains-default.txt"
        echo "# One domain per line" >> "$BASE_DIR/domains-default.txt"
        echo "" >> "$BASE_DIR/domains-default.txt"
        echo -e "${YELLOW}Created empty default domains file. Use 'Update Lists' to populate it.${NC}"
    fi
    
    # Set up automatic updates
    echo -e ""
    echo -e "${CYAN}${BOLD}SCHEDULING${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    
    # Ask user about schedule preference
    echo -e "${YELLOW}How would you like to schedule DNSniper?${NC}"
    echo -e "1) Using cron (default)"
    echo -e "2) Using systemd timer"
    echo -e "3) No automatic scheduling"
    read -rp "Choose an option [1-3]: " sched_choice
    
    case "$sched_choice" in
        2)
            # Use systemd timer
            if command -v systemctl &>/dev/null; then
                echo -e "${YELLOW}Setting up systemd timer...${NC}"
                
                # Configure to use systemd (will be picked up when service runs)
                sed -i "s|^use_systemd=.*|use_systemd=1|" "$BASE_DIR/config.conf" 2>/dev/null || true
                
                # Enable systemd timer
                "$BIN_PATH" --status > /dev/null 2>&1
                
                echo -e "${GREEN}DNSniper scheduled with systemd timer (runs hourly)${NC}"
            else
                echo -e "${RED}Systemd not available. Falling back to cron.${NC}"
                
                # Create cron job for hourly execution
                (crontab -l 2>/dev/null | grep -v "$BIN_PATH"; echo "0 * * * * $BIN_PATH --run-service >/dev/null 2>&1") | crontab - 2>/dev/null || true
                
                echo -e "${GREEN}DNSniper scheduled with cron (runs hourly)${NC}"
            fi
            ;;
        3)
            # No scheduling
            echo -e "${YELLOW}Not setting up automatic scheduling.${NC}"
            echo -e "${YELLOW}You can manually run DNSniper with: ${NC}sudo dnsniper --run"
            # Set cron to disabled in config
            sed -i "s|^cron=.*|cron='# DNSniper disabled'|" "$BASE_DIR/config.conf" 2>/dev/null || true
            ;;
        *)
            # Default: Use cron
            echo -e "${YELLOW}Setting up cron job...${NC}"
            
            # Create cron job for hourly execution
            (crontab -l 2>/dev/null | grep -v "$BIN_PATH"; echo "0 * * * * $BIN_PATH --run-service >/dev/null 2>&1") | crontab - 2>/dev/null || true
            
            echo -e "${GREEN}DNSniper scheduled with cron (runs hourly)${NC}"
            ;;
    esac
    
    # Ask about initial run
    echo -e ""
    echo -e "${CYAN}${BOLD}INITIAL RUN${NC}"
    echo -e "${MAGENTA}───────────────────────────────────────${NC}"
    read -rp "Would you like to run DNSniper now to update domain lists? [Y/n]: " run_now
    
    if [[ ! "$run_now" =~ ^[Nn]$ ]]; then
        echo -e "${YELLOW}Running DNSniper for initial setup in background...${NC}"
        
        # Run DNSniper in background
        nohup "$BIN_PATH" --update > /dev/null 2>&1 &
        
        echo -e "${GREEN}DNSniper update started in background.${NC}"
        echo -e "${YELLOW}Domain block lists will be downloaded and applied automatically.${NC}"
        echo -e "${YELLOW}You can check status later with 'sudo dnsniper --status'${NC}"
    else
        echo -e "${YELLOW}Skipping initial run. You can run DNSniper manually with 'sudo dnsniper'${NC}"
    fi
else
    echo -e "${RED}${BOLD}Error:${NC} Failed to initialize DNSniper. Please run 'sudo dnsniper' to check for errors."
fi

# Final instructions
echo -e ""
echo -e "${CYAN}${BOLD}INSTALLATION COMPLETE!${NC}"
echo -e "${MAGENTA}───────────────────────────────────────${NC}"
echo -e "${YELLOW}To start using DNSniper:${NC}"
echo -e "  ${BOLD}Command:${NC} sudo dnsniper"
echo -e ""
echo -e "${YELLOW}To view help:${NC}"
echo -e "  ${BOLD}Command:${NC} sudo dnsniper --help"
echo -e ""
echo -e "${YELLOW}To run manually:${NC}"
echo -e "  ${BOLD}Command:${NC} sudo dnsniper --run"
echo -e ""
echo -e "${YELLOW}To check status:${NC}"
echo -e "  ${BOLD}Command:${NC} sudo dnsniper --status"
echo -e ""
echo -e "${BLUE}${BOLD}Protect your servers against malicious domains with DNSniper!${NC}"
echo -e ""
echo -e "${YELLOW}Installation log saved to: $LOG_FILE${NC}"