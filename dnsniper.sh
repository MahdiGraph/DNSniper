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
BINARY_PATH="/usr/local/bin/dnsniper"

# Defaults
DEFAULT_CRON="0 * * * * $BINARY_PATH"
DEFAULT_MAX_IPS=10

# Dependencies
dependencies=(iptables ip6tables curl dig sqlite3 crontab)

enhanced_echo(){ printf "%b\n" "$1"; }

# 1) Ensure env: dirs, files, DB, cron & config
ensure_environment(){
  mkdir -p "$BASE_DIR"
  touch "$DEFAULT_FILE" "$ADD_FILE" "$REMOVE_FILE" "$CONFIG_FILE"
  # config defaults
  grep -q '^cron=' "$CONFIG_FILE" || echo "cron='$DEFAULT_CRON'" >> "$CONFIG_FILE"
  grep -q '^max_ips=' "$CONFIG_FILE" || echo "max_ips=$DEFAULT_MAX_IPS" >> "$CONFIG_FILE"
  # init DB
  sqlite3 "$DB_FILE" \
    "CREATE TABLE IF NOT EXISTS history(domain TEXT, ips TEXT, ts DATETIME DEFAULT CURRENT_TIMESTAMP);"
  # ensure cron job
  cron_expr=$(grep '^cron=' "$CONFIG_FILE" | cut -d"'" -f2)
  ( crontab -l 2>/dev/null | grep -vF "$BINARY_PATH" || true; echo "$cron_expr" ) | crontab -
}

# 2) Root & deps
check_root(){
  [[ $EUID -ne 0 ]] && enhanced_echo "${RED}Error:${NC} Must run as root." && exit 1
}
check_dependencies(){
  local miss=()
  for cmd in "${dependencies[@]}"; do
    command -v "$cmd" &>/dev/null || miss+=("$cmd")
  done
  [[ ${#miss[@]} -gt 0 ]] && enhanced_echo "${RED}Missing:${NC} ${miss[*]}" && exit 1
}

# 3) Install/update binary
install_binary(){
  enhanced_echo "${BLUE}Installing symlink...${NC}"
  ln -sf "$0" "$BINARY_PATH"
  chmod +x "$BINARY_PATH"
}

# 4) Fetch default domains
update_default(){
  enhanced_echo "${BLUE}Fetching defaults...${NC}"
  curl -sfL "https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/domains-default.txt" \
    -o "$DEFAULT_FILE" && enhanced_echo "${GREEN}OK${NC}" || enhanced_echo "${RED}Fail${NC}"
}

# 5) Merge domain lists
merge_domains(){
  mapfile -t d1 < "$DEFAULT_FILE"
  mapfile -t d2 < "$ADD_FILE"
  mapfile -t d3 < "$REMOVE_FILE"
  merged=()
  for d in "${d1[@]}"; do
    [[ -z "$d" ]] && continue
    printf "%s\n" "${d3[@]}" | grep -Fxq "$d" && continue
    merged+=("$d")
  done
  for d in "${d2[@]}"; do
    [[ -n "$d" ]] && merged+=("$d")
  done
}

# 6) Record resolve history, trim to max_ips
record_history(){
  local dom="$1" ips_csv="$2"
  max=$(grep '^max_ips=' "$CONFIG_FILE" | cut -d= -f2)
  sqlite3 "$DB_FILE" \
    "INSERT INTO history(domain,ips) VALUES('$dom','$ips_csv');"
  sqlite3 "$DB_FILE" \
    "DELETE FROM history WHERE rowid NOT IN (
       SELECT rowid FROM history
       WHERE domain='$dom'
       ORDER BY ts DESC LIMIT $max
     );"
}

# 7) Detect CDN by comparing last two entries
detect_cdn(){
  warnings=()
  for dom in "${merged[@]}"; do
    rows=$(sqlite3 -separator '|' "$DB_FILE" \
      "SELECT ips FROM history WHERE domain='$dom' ORDER BY ts DESC LIMIT 2;")
    [[ $(wc -l <<<"$rows") -lt 2 ]] && continue
    IFS='|' read -r last prev <<< "$rows"
    IFS=',' read -ra la <<< "$last"
    IFS=',' read -ra pa <<< "$prev"
    for ip in "${la[@]}"; do
      printf "%s\n" "${pa[@]}" | grep -Fxq "$ip" || { warnings+=("$dom"); break; }
    done
  done
  if [[ ${#warnings[@]} -gt 0 ]]; then
    enhanced_echo "${YELLOW}${BOLD}[!] Domains may use CDN:${NC} ${warnings[*]}"
  fi
}

# 8) Resolve and block
resolve_block(){
  enhanced_echo "${BLUE}Resolving...${NC}"
  merge_domains
  for dom in "${merged[@]}"; do
    enhanced_echo "${BOLD}Domain:${NC} ${GREEN}$dom${NC}"
    mapfile -t v4 < <(dig +short A "$dom")
    mapfile -t v6 < <(dig +short AAAA "$dom")
    all=( "${v4[@]}" "${v6[@]}" )
    unique=( $(printf "%s\n" "${all[@]}" | sort -u) )
    ips_csv=$(IFS=,; echo "${unique[*]}")
    record_history "$dom" "$ips_csv"
    for ip in "${unique[@]}"; do
      tbl=iptables
      [[ "$ip" == *:* ]] && tbl=ip6tables
      if $tbl -C INPUT -d "$ip" -j DROP &>/dev/null; then
        enhanced_echo "  - ${YELLOW}Exists${NC}: $ip"
      else
        $tbl -A INPUT -d "$ip" -m comment --comment "DNSniper" -j DROP
        enhanced_echo "  - ${RED}Blocked${NC}: $ip"
      fi
    done
    current_ips["$dom"]="$ips_csv"
    echo
  done
  enhanced_echo "${GREEN}Done.${NC}"
  detect_cdn
}

# 9) Menu actions
set_schedule(){
  read -rp "Interval minutes (default 60): " m
  m=${m:-60}
  expr="*/$m * * * * $BINARY_PATH"
  sed -i "s|^cron=.*|cron='$expr'|" "$CONFIG_FILE"
  ensure_environment
  enhanced_echo "${GREEN}Scheduled every $m minutes.${NC}"
}
set_max_ips(){
  read -rp "Max IPs per domain (default $DEFAULT_MAX_IPS): " n
  n=${n:-$DEFAULT_MAX_IPS}
  sed -i "s|^max_ips=.*|max_ips=$n|" "$CONFIG_FILE"
  enhanced_echo "${GREEN}Max IPs set to $n.${NC}"
}
add_dom(){
  read -rp "Domain to add: " d
  echo "$d" >> "$ADD_FILE"
  enhanced_echo "${GREEN}Added $d.${NC}"
}
rem_dom(){
  read -rp "Domain to remove: " d
  echo "$d" >> "$REMOVE_FILE"
  enhanced_echo "${GREEN}Removed $d.${NC}"
}
display_status(){
  merge_domains
  enhanced_echo "\n${BOLD}Domains (${#merged[@]}):${NC}"
  for dom in "${merged[@]}"; do
    enhanced_echo "  - ${GREEN}$dom${NC}: ${CYAN}${current_ips[$dom]:-N/A}${NC}"
  done
  sched=$(grep '^cron=' "$CONFIG_FILE" | cut -d"'" -f2)
  max=$(grep '^max_ips=' "$CONFIG_FILE" | cut -d= -f2)
  enhanced_echo "\n${BOLD}Schedule:${NC} ${BLUE}$sched${NC}"
  enhanced_echo "${BOLD}Max IPs:${NC} ${BLUE}$max${NC}"
}
clear_rules(){
  read -rp "Clear all DNSniper rules? [y/N]: " a
  if [[ $a =~ ^[Yy] ]]; then
    enhanced_echo "${BLUE}Flushing rules...${NC}"
    iptables-save | grep -v 'DNSniper' | iptables-restore
    ip6tables-save | grep -v 'DNSniper' | ip6tables-restore
    enhanced_echo "${GREEN}Cleared.${NC}"
  else
    enhanced_echo "${YELLOW}Cancelled.${NC}"
  fi
}
uninstall(){
  read -rp "Uninstall DNSniper? [y/N]: " a
  if [[ $a =~ ^[Yy] ]]; then
    enhanced_echo "${BLUE}Removing DNSniper...${NC}"
    crontab -l | grep -vF "$BINARY_PATH" | crontab -
    rm -rf "$BASE_DIR" "$BINARY_PATH"
    clear_rules
    enhanced_echo "${GREEN}Uninstalled.${NC}"
    exit 0
  else
    enhanced_echo "${YELLOW}Cancelled.${NC}"
  fi
}

# 10) Main menu
main_menu(){
  while :; do
    enhanced_echo "\n${BOLD}=== DNSniper Menu ===${NC}"
    echo -e "${YELLOW}1)${NC} Run now   ${YELLOW}2)${NC} Update"
    echo -e "${YELLOW}3)${NC} Schedule  ${YELLOW}4)${NC} MaxIPs"
    echo -e "${YELLOW}5)${NC} Add       ${YELLOW}6)${NC} Remove"
    echo -e "${YELLOW}7)${NC} Status    ${YELLOW}8)${NC} Clear"
    echo -e "${YELLOW}9)${NC} Uninstall ${YELLOW}0)${NC} Exit"
    read -rp "Choice: " c
    case $c in
      1) resolve_block ;;
      2) update_default ;;
      3) set_schedule ;;
      4) set_max_ips ;;
      5) add_dom ;;
      6) rem_dom ;;
      7) display_status ;;
      8) clear_rules ;;
      9) uninstall ;;
      0) exit 0 ;;
      *) enhanced_echo "${RED}Invalid choice${NC}" ;;
    esac
  done
}

# 11) Entrypoint: interactive vs cron
if [[ -t 0 && -t 1 ]]; then
  check_root && check_dependencies && ensure_environment && install_binary && main_menu
else
  check_root && check_dependencies && ensure_environment && install_binary && resolve_block
fi

exit 0
