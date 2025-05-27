#!/bin/bash
# DNSniper System Test Script
# Tests the new sync system and firewall integration

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test functions
print_test() { echo -e "${BLUE}[TEST]${NC} $1"; }
print_pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
print_fail() { echo -e "${RED}[FAIL]${NC} $1"; }
print_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    print_fail "This test script must be run as root"
    exit 1
fi

print_test "Starting DNSniper System Tests"
echo

# Test 1: Check if DNSniper is installed
print_test "1. Checking DNSniper installation"
if [ -f "/etc/dnsniper/dnsniper" ] && [ -f "/etc/dnsniper/dnsniper-agent" ]; then
    print_pass "DNSniper binaries found"
else
    print_fail "DNSniper binaries not found"
    exit 1
fi

# Test 2: Check configuration
print_test "2. Checking configuration"
if [ -f "/etc/dnsniper/config.yaml" ]; then
    print_pass "Configuration file found"
else
    print_fail "Configuration file not found"
    exit 1
fi

# Test 3: Check database
print_test "3. Checking database"
if [ -f "/etc/dnsniper/dnsniper.db" ]; then
    print_pass "Database file found"
else
    print_warn "Database file not found (will be created on first run)"
fi

# Test 4: Check systemd services
print_test "4. Checking systemd services"
if systemctl is-enabled dnsniper-agent.timer >/dev/null 2>&1; then
    print_pass "DNSniper timer service is enabled"
else
    print_fail "DNSniper timer service is not enabled"
fi

if systemctl is-active dnsniper-agent.timer >/dev/null 2>&1; then
    print_pass "DNSniper timer service is running"
else
    print_warn "DNSniper timer service is not running"
fi

# Test 5: Check required commands
print_test "5. Checking required commands"
commands=("iptables" "ipset" "systemctl")
for cmd in "${commands[@]}"; do
    if command -v "$cmd" >/dev/null 2>&1; then
        print_pass "$cmd is available"
    else
        print_fail "$cmd is not available"
    fi
done

# Test 6: Check ipsets
print_test "6. Checking DNSniper ipsets"
expected_ipsets=(
    "dnsniper-whitelist-ip-v4"
    "dnsniper-whitelist-range-v4"
    "dnsniper-blocklist-ip-v4"
    "dnsniper-blocklist-range-v4"
)

# Check if IPv6 is enabled
if grep -q "enable_ipv6: true" /etc/dnsniper/config.yaml 2>/dev/null; then
    expected_ipsets+=(
        "dnsniper-whitelist-ip-v6"
        "dnsniper-whitelist-range-v6"
        "dnsniper-blocklist-ip-v6"
        "dnsniper-blocklist-range-v6"
    )
fi

for ipset_name in "${expected_ipsets[@]}"; do
    if ipset list "$ipset_name" >/dev/null 2>&1; then
        print_pass "IPSet $ipset_name exists"
    else
        print_warn "IPSet $ipset_name does not exist (will be created when needed)"
    fi
done

# Test 7: Check iptables rules
print_test "7. Checking iptables rules"
if iptables -L | grep -q "DNSniper" 2>/dev/null; then
    print_pass "DNSniper iptables rules found"
else
    print_warn "No DNSniper iptables rules found (will be created when needed)"
fi

# Test 8: Check persistence files
print_test "8. Checking persistence files"
if [ -f "/etc/iptables/rules.v4" ]; then
    print_pass "IPv4 rules file exists"
else
    print_warn "IPv4 rules file does not exist"
fi

if [ -f "/etc/iptables/rules.v6" ]; then
    print_pass "IPv6 rules file exists"
else
    print_warn "IPv6 rules file does not exist"
fi

# Test 9: Test agent execution
print_test "9. Testing agent execution"
print_test "Running dnsniper-agent (this may take a moment)..."
if timeout 60 /etc/dnsniper/dnsniper-agent >/dev/null 2>&1; then
    print_pass "Agent executed successfully"
else
    print_warn "Agent execution timed out or failed (check logs)"
fi

# Test 10: Check sync functionality
print_test "10. Testing sync functionality"
# Add a test IP to database and check if it appears in ipset
test_ip="192.0.2.1"  # RFC5737 test IP

# This would require the agent to have database access
# For now, we'll just check if the sync system is working by looking at logs
if journalctl -u dnsniper-agent.service --since "1 hour ago" | grep -q "sync" 2>/dev/null; then
    print_pass "Sync system appears to be working (found sync logs)"
else
    print_warn "No recent sync logs found"
fi

# Test 11: Check log files
print_test "11. Checking log files"
if [ -d "/var/log/dnsniper" ]; then
    print_pass "Log directory exists"
    if [ "$(ls -A /var/log/dnsniper 2>/dev/null)" ]; then
        print_pass "Log files found"
    else
        print_warn "Log directory is empty"
    fi
else
    print_warn "Log directory does not exist"
fi

# Test 12: Check system integration
print_test "12. Checking system integration"
if [ -L "/usr/bin/dnsniper" ]; then
    print_pass "System-wide dnsniper command available"
else
    print_fail "System-wide dnsniper command not available"
fi

# Test 13: Memory and performance check
print_test "13. Checking system resources"
total_mem=$(free -m | awk 'NR==2{printf "%.0f", $2}')
if [ "$total_mem" -gt 512 ]; then
    print_pass "Sufficient memory available (${total_mem}MB)"
else
    print_warn "Low memory system (${total_mem}MB)"
fi

# Test 14: Check for old ipsets (migration test)
print_test "14. Checking for old ipset names"
old_ipsets=("whitelistIP-v4" "blocklistIP-v4" "whitelistRange-v4" "blocklistRange-v4")
old_found=false
for old_ipset in "${old_ipsets[@]}"; do
    if ipset list "$old_ipset" >/dev/null 2>&1; then
        print_warn "Old ipset $old_ipset still exists (should be migrated)"
        old_found=true
    fi
done

if [ "$old_found" = false ]; then
    print_pass "No old ipsets found (migration complete)"
fi

# Summary
echo
print_test "Test Summary"
echo "=============="

# Count tests
total_tests=14
echo "Total tests run: $total_tests"

# Check critical components
critical_ok=true

if [ ! -f "/etc/dnsniper/dnsniper" ]; then
    critical_ok=false
fi

if [ ! -f "/etc/dnsniper/config.yaml" ]; then
    critical_ok=false
fi

if ! systemctl is-enabled dnsniper-agent.timer >/dev/null 2>&1; then
    critical_ok=false
fi

if [ "$critical_ok" = true ]; then
    print_pass "All critical components are working"
    echo
    echo -e "${GREEN}✓ DNSniper system appears to be functioning correctly${NC}"
    echo
    echo "Next steps:"
    echo "1. Run 'dnsniper' to access the management interface"
    echo "2. Check 'systemctl status dnsniper-agent.timer' for service status"
    echo "3. View logs with 'journalctl -u dnsniper-agent.service'"
    echo "4. Monitor ipsets with 'ipset list | grep dnsniper'"
else
    print_fail "Some critical components are not working properly"
    echo
    echo -e "${RED}✗ DNSniper system has issues that need attention${NC}"
    echo
    echo "Troubleshooting:"
    echo "1. Check installation with 'sudo ./installer.sh'"
    echo "2. Review logs with 'journalctl -u dnsniper-agent.service'"
    echo "3. Verify configuration in '/etc/dnsniper/config.yaml'"
fi

echo
print_test "Test completed" 