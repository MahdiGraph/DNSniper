#!/usr/bin/env bash
# DNSniper - Domain-based threat mitigation via iptables/ip6tables
# Repository: https://github.com/MahdiGraph/DNSniper

# ANSI color codes
RED='\e[31m' GREEN='\e[32m' YELLOW='\e[33m' BLUE='\e[34m' CYAN='\e[36m' BOLD='\e[1m' NC='\e[0m'

# Paths
BASE_DIR="/etc/dnsniper"
DEFAULT_FILE="$BASE_DIR/domains-default.txt"
ADD_FILE="$BASE_DIR/domains-add.txt"
REMOVE_FILE="$BASE_DIR/domains-remove.txt"
CONFIG_FILE="$BASE_DIR/config.conf"
DB_FILE="$BASE_DIR/history.db"
BINARY_PATH="/usr/local/bin/dnsniper.sh"

# Defaults
DEFAULT_CRON="0 * * * * $BINARY_PATH --run"
DEFAULT_MAX_IPS=10

# Dependencies
dependencies=(iptables ip6tables curl dig sqlite3 crontab)

enhanced_echo(){ printf "%b\n" "$1"; }

# Ensure environment: dirs, files, DB
ensure_environment(){
  mkdir -p "$BASE_DIR"
  touch "$DEFAULT_FILE" "$ADD_FILE" "$REMOVE_FILE" "$CONFIG_FILE"
  # create config with defaults if missing
  if ! grep -q '^cron=' "$CONFIG_FILE"; then
    echo "cron='$DEFAULT_CRON'" >> "$CONFIG_FILE"
  fi
  if ! grep -q '^max_ips=' "$CONFIG_FILE"; then
    echo "max_ips=$DEFAULT_MAX_IPS" >> "$CONFIG_FILE"
  fi
  # init DB
  sqlite3 "$DB_FILE" "CREATE TABLE IF NOT EXISTS history(domain TEXT, ips TEXT, ts DATETIME DEFAULT CURRENT_TIMESTAMP);"
}

# Check root and deps
check_root(){ [[ $EUID -ne 0 ]] && enhanced_echo "${RED}Error:${NC} Must run as root." && exit 1; }
check_dependencies(){ local miss=(); for cmd in "${dependencies[@]}"; do command -v "$cmd" &>/dev/null||miss+=("$cmd"); done; [[ ${#miss[@]} -gt 0 ]] && enhanced_echo "${RED}Missing:${NC} ${miss[*]}" && exit 1; }

# Install binary
install_binary(){ enhanced_echo "${BLUE}Installing to $BINARY_PATH...${NC}"; cp "$0" "$BINARY_PATH" && chmod +x "$BINARY_PATH"; }

# Update default domains
update_default(){ enhanced_echo "${BLUE}Fetching defaults...${NC}"; curl -sfL "https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/domains-default.txt" -o "$DEFAULT_FILE" && enhanced_echo "${GREEN}OK${NC}" || enhanced_echo "${RED}Fail${NC}"; }

# Merge lists
merge_domains(){ mapfile -t d1 < "$DEFAULT_FILE"; mapfile -t d2 < "$ADD_FILE"; mapfile -t d3 < "$REMOVE_FILE"; merged=(); for d in "${d1[@]}"; do [[ -z "$d" ]]|| printf "%s\n" "${d3[@]}"|grep -Fxq "$d"&&continue;merged+=("$d"); done; for d in "${d2[@]}"; do [[ -n "$d" ]]&&merged+=("$d"); done; }

# Record history and trim
record_history(){ local dom="$1" ips_csv="$2" max=$(grep '^max_ips=' "$CONFIG_FILE"|cut -d= -f2); sqlite3 "$DB_FILE" "INSERT INTO history(domain,ips) VALUES('$dom','$ips_csv');"; sqlite3 "$DB_FILE" "DELETE FROM history WHERE rowid NOT IN (SELECT rowid FROM history WHERE domain='$dom' ORDER BY ts DESC LIMIT $max);"; }

# Detect CDN
detect_cdn(){ warnings=(); for dom in "${merged[@]}"; do rows=$(sqlite3 -separator '|' "$DB_FILE" "SELECT ips FROM history WHERE domain='$dom' ORDER BY ts DESC LIMIT 2;"); [[ -z "$rows" ]]&&continue; readarray -t last <<< "$(echo "$rows"| head -n1)"; readarray -t prev <<< "$(echo "$rows"| tail -n1)"; IFS=',' read -ra la <<< "${last[*]}"; IFS=',' read -ra pa <<< "${prev[*]}"; for ip in "${la[@]}"; do printf "%s\n" "${pa[@]}"|grep -Fxq "$ip"||{ warnings+=("$dom"); break; }; done; done; [[ ${#warnings[@]} -gt 0 ]]&&enhanced_echo "${YELLOW}${BOLD}[!] Domains may use CDN: ${warnings[*]}${NC}"; }

# Resolve & block
declare -A current_ips
resolve_block(){ enhanced_echo "${BLUE}Resolving...${NC}"; merge_domains; for dom in "${merged[@]}"; do enhanced_echo "${BOLD}Domain:${NC} ${GREEN}$dom${NC}"; mapfile -t v4 < <(dig +short A "$dom"); mapfile -t v6 < <(dig +short AAAA "$dom"); all=("${v4[@]}" "${v6[@]}"); unique=($(printf "%s\n" "${all[@]}"|sort -u)); ips_csv=$(IFS=,; echo "${unique[*]}"); record_history "$dom" "$ips_csv"; for ip in "${unique[@]}"; do if [[ "$ip"==*":"* ]]; then tbl=ip6tables; else tbl=iptables; fi; if $tbl -C INPUT -d "$ip" -j DROP &>/dev/null; then enhanced_echo "  - ${YELLOW}Exists${NC}: $ip"; else $tbl -A INPUT -d "$ip" -m comment --comment "DNSniper" -j DROP && enhanced_echo "  - ${RED}Blocked${NC}: $ip"; fi; done; current_ips["$dom"]="$ips_csv"; echo; done; enhanced_echo "${GREEN}Done.${NC}"; detect_cdn; }

# Cron setup
set_cron(){ expr="$1"; crontab -l 2>/dev/null|grep -v "$BINARY_PATH --run"|crontab -; (crontab -l 2>/dev/null; echo "$expr")|crontab -; }
# Menu actions
set_schedule(){ read -rp "Interval minutes (default hourly):" m; m=${m:-60}; expr="*/$m * * * * $BINARY_PATH --run"; set_cron "$expr"; sed -i "s|^cron=.*|cron='$expr'|" "$CONFIG_FILE"; enhanced_echo "${GREEN}Set to every $m minutes.${NC}"; }
set_max_ips(){ read -rp "Max IPs per domain (default $DEFAULT_MAX_IPS):" n; n=${n:-$DEFAULT_MAX_IPS}; sed -i "s|^max_ips=.*|max_ips=$n|" "$CONFIG_FILE"; enhanced_echo "${GREEN}Max IPs now $n.${NC}"; }
add_dom(){ read -rp "Domain to add:" d; echo "$d">>"$ADD_FILE"; enhanced_echo "${GREEN}Added $d.${NC}"; }
rem_dom(){ read -rp "Domain to remove:" d; echo "$d">>"$REMOVE_FILE"; enhanced_echo "${GREEN}Removed $d.${NC}"; }
display_status(){ merge_domains; enhanced_echo "\n${BOLD}Domains(${#merged[@]}):${NC}"; for dom in "${merged[@]}";do enhanced_echo "  - ${GREEN}$dom${NC}: ${CYAN}${current_ips[$dom]:-N/A}${NC}"; done; sched=$(grep '^cron=' "$CONFIG_FILE"|cut -d"'" -f2); max=$(grep '^max_ips=' "$CONFIG_FILE"|cut -d= -f2); enhanced_echo "\n${BOLD}Schedule:${NC} ${BLUE}$sched${NC}\n${BOLD}Max IPs:${NC} ${BLUE}$max${NC}"; }
clear_rules(){ read -rp "Clear all rules? [y/N]:" a; [[ $a =~ ^[Yy] ]]&&{ enhanced_echo "${BLUE}Flushing...${NC}"; iptables-save|grep -v DNSniper|iptables-restore; ip6tables-save|grep -v DNSniper|ip6tables-restore;enhanced_echo "${GREEN}Cleared.${NC}";}||enhanced_echo "${YELLOW}Cancelled.${NC}"; }
uninstall(){ read -rp "Uninstall DNSniper? [y/N]:" a; [[ $a =~ ^[Yy] ]]&&{ enhanced_echo "${BLUE}Removing...${NC}"; crontab -l|grep -v "$BINARY_PATH --run"|crontab -; rm -rf "$BASE_DIR" "$BINARY_PATH"; clear_rules; enhanced_echo "${GREEN}Removed.${NC}"; exit;}||enhanced_echo "${YELLOW}Cancelled.${NC}"; }

# Main menu
main_menu(){ while :; do enhanced_echo "\n${BOLD}=== DNSniper Menu ===${NC}"; echo -e "${YELLOW}1)${NC} Run now  2) Update  3) Schedule  4) MaxIPs"; echo -e "5) Add   6) Remove 7) Status  8) Clear"; echo -e "9) Uninstall 0) Exit"; read -rp "Choice:" c; case $c in 1) resolve_block;;2) update_default;;3) set_schedule;;4) set_max_ips;;5) add_dom;;6) rem_dom;;7) display_status;;8) clear_rules;;9) uninstall;;0)exit;;*)enhanced_echo "${RED}Bad${NC}";; esac; done; }

# Entry
case "$1" in --run) check_root; check_dependencies; ensure_environment; install_binary; resolve_block;; *) check_root; check_dependencies; ensure_environment; install_binary; main_menu;; esac
