package firewall

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// IPSetManager handles ipset operations
type IPSetManager struct {
	enableIPv6 bool
}

// IPTablesManager handles iptables operations
type IPTablesManager struct {
	enableIPv6 bool
}

// NewIPSetManager creates a new ipset manager
func NewIPSetManager(enableIPv6 bool) (*IPSetManager, error) {
	return &IPSetManager{
		enableIPv6: enableIPv6,
	}, nil
}

// NewIPTablesManager creates a new iptables manager
func NewIPTablesManager(enableIPv6 bool) (*IPTablesManager, error) {
	return &IPTablesManager{
		enableIPv6: enableIPv6,
	}, nil
}

// FirewallManager provides a unified interface for firewall operations
type FirewallManager struct {
	ipsetManager    *IPSetManager
	iptablesManager *IPTablesManager
	validator       *RuleValidator
	errorRecovery   *ErrorRecovery
	monitor         *FirewallMonitor
	chains          []string
	enableIPv6      bool
	mu              sync.RWMutex // For thread-safe operations
}

// NewFirewallManager creates a new firewall manager
func NewFirewallManager(
	enableIPv6 bool,
	chains []string,
	backupPath string,
	logFile string,
) (*FirewallManager, error) {
	// Create ipset manager
	ipsetManager, err := NewIPSetManager(enableIPv6)
	if err != nil {
		return nil, fmt.Errorf("failed to create ipset manager: %w", err)
	}

	// Create iptables manager
	iptablesManager, err := NewIPTablesManager(enableIPv6)
	if err != nil {
		return nil, fmt.Errorf("failed to create iptables manager: %w", err)
	}

	// Create validator
	validator := NewRuleValidator(enableIPv6)

	// Create error recovery
	errorRecovery := NewErrorRecovery(backupPath)

	// Parse chains
	parsedChains := parseChains(chains)

	// Verify commands are available
	if err := verifyCommandsAvailable(); err != nil {
		return nil, err
	}

	// Create monitor
	ipsetNames := ipsetManager.GetSetNames()
	monitor := NewFirewallMonitor(ipsetNames, enableIPv6)

	return &FirewallManager{
		ipsetManager:    ipsetManager,
		iptablesManager: iptablesManager,
		validator:       validator,
		errorRecovery:   errorRecovery,
		monitor:         monitor,
		chains:          parsedChains,
		enableIPv6:      enableIPv6,
	}, nil
}

// verifyCommandsAvailable checks that required commands are installed
func verifyCommandsAvailable() error {
	requiredCommands := []string{"ipset", "iptables"}

	for _, cmd := range requiredCommands {
		if _, err := exec.LookPath(cmd); err != nil {
			return fmt.Errorf("required command %s not found: %w", cmd, err)
		}
	}
	return nil
}

// parseChains converts string chains to a standardized format
func parseChains(chains []string) []string {
	// If empty or contains "ALL", use all chains
	if len(chains) == 0 {
		return []string{"INPUT", "OUTPUT", "FORWARD"}
	}

	for _, chain := range chains {
		if chain == "ALL" {
			return []string{"INPUT", "OUTPUT", "FORWARD"}
		}
	}

	// Validate and normalize chains
	validChains := make([]string, 0, len(chains))
	for _, chain := range chains {
		upperChain := strings.ToUpper(chain)
		switch upperChain {
		case "INPUT", "OUTPUT", "FORWARD":
			// Only add if not already present
			if !contains(validChains, upperChain) {
				validChains = append(validChains, upperChain)
			}
		}
	}

	// If no valid chains, use all
	if len(validChains) == 0 {
		return []string{"INPUT", "OUTPUT", "FORWARD"}
	}

	return validChains
}

// Reload regenerates and applies firewall rules
func (m *FirewallManager) Reload() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Create backup before making changes
	if err := m.errorRecovery.BackupRules(); err != nil {
		return fmt.Errorf("failed to backup rules: %w", err)
	}

	// Ensure ipsets exist (recreate if missing)
	if err := m.ipsetManager.EnsureSetsExist(); err != nil {
		return fmt.Errorf("failed to ensure ipsets exist: %w", err)
	}

	// Validate all ipsets
	for _, setName := range m.ipsetManager.GetSetNames() {
		if err := m.validator.ValidateIPSet(setName); err != nil {
			// Try to restore from backup
			m.errorRecovery.RestoreRules(time.Now().Format("20060102-150405"))
			return fmt.Errorf("ipset validation failed: %w", err)
		}
	}

	// Remove existing DNSniper rules to prevent duplications
	if err := m.RemoveDNSniperRules(); err != nil {
		// Try to restore from backup
		m.errorRecovery.RestoreRules(time.Now().Format("20060102-150405"))
		return fmt.Errorf("failed to remove existing rules: %w", err)
	}

	// Get ipset names
	ipsetNames := m.ipsetManager.GetSetNames()

	// Generate rules files
	if err := m.iptablesManager.GenerateRulesFile(m.chains, ipsetNames, false); err != nil {
		// Try to restore from backup
		m.errorRecovery.RestoreRules(time.Now().Format("20060102-150405"))
		return fmt.Errorf("failed to generate IPv4 rules file: %w", err)
	}

	if m.enableIPv6 {
		if err := m.iptablesManager.GenerateRulesFile(m.chains, ipsetNames, true); err != nil {
			// Try to restore from backup
			m.errorRecovery.RestoreRules(time.Now().Format("20060102-150405"))
			return fmt.Errorf("failed to generate IPv6 rules file: %w", err)
		}
	}

	// Apply rules
	if err := m.iptablesManager.ApplyRules(false); err != nil {
		// Try to restore from backup
		m.errorRecovery.RestoreRules(time.Now().Format("20060102-150405"))
		return fmt.Errorf("failed to apply IPv4 rules: %w", err)
	}

	if m.enableIPv6 {
		if err := m.iptablesManager.ApplyRules(true); err != nil {
			// Try to restore from backup
			m.errorRecovery.RestoreRules(time.Now().Format("20060102-150405"))
			return fmt.Errorf("failed to apply IPv6 rules: %w", err)
		}
	}

	// Validate applied rules
	for _, chain := range m.chains {
		for _, setName := range ipsetNames {
			if err := m.validator.ValidateIPTablesRule(chain, setName, false); err != nil {
				// Try to restore from backup
				m.errorRecovery.RestoreRules(time.Now().Format("20060102-150405"))
				return fmt.Errorf("iptables validation failed: %w", err)
			}
			if m.enableIPv6 {
				if err := m.validator.ValidateIPTablesRule(chain, setName, true); err != nil {
					// Try to restore from backup
					m.errorRecovery.RestoreRules(time.Now().Format("20060102-150405"))
					return fmt.Errorf("ip6tables validation failed: %w", err)
				}
			}
		}
	}

	return nil
}

// ClearAll clears all firewall rules
func (m *FirewallManager) ClearAll() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Flush all ipsets
	if err := m.ipsetManager.FlushAll(); err != nil {
		return fmt.Errorf("failed to flush ipsets: %w", err)
	}

	// Remove DNSniper rules from iptables
	if err := m.RemoveDNSniperRules(); err != nil {
		return fmt.Errorf("failed to remove iptables rules: %w", err)
	}

	return nil
}

// CleanupAll performs a complete cleanup (useful for reinstalls)
func (m *FirewallManager) CleanupAll() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Remove all DNSniper ipsets completely
	if err := m.ipsetManager.CleanupAllSets(); err != nil {
		return fmt.Errorf("failed to cleanup ipsets: %w", err)
	}

	// Remove DNSniper rules from iptables
	if err := m.RemoveDNSniperRules(); err != nil {
		return fmt.Errorf("failed to remove iptables rules: %w", err)
	}

	return nil
}

// RemoveDNSniperRules removes all DNSniper-related iptables rules
func (m *FirewallManager) RemoveDNSniperRules() error {
	// Get ipset names to remove rules referencing them
	ipsetNames := m.ipsetManager.GetSetNames()

	// Remove rules from each chain
	for _, chain := range m.chains {
		for _, setName := range ipsetNames {
			// Remove IPv4 rules
			m.removeRuleIfExists("iptables", chain, setName, "src", "ACCEPT")
			m.removeRuleIfExists("iptables", chain, setName, "src", "DROP")
			m.removeRuleIfExists("iptables", chain, setName, "dst", "ACCEPT")
			m.removeRuleIfExists("iptables", chain, setName, "dst", "DROP")

			// Remove IPv6 rules if enabled
			if m.enableIPv6 {
				m.removeRuleIfExists("ip6tables", chain, setName, "src", "ACCEPT")
				m.removeRuleIfExists("ip6tables", chain, setName, "src", "DROP")
				m.removeRuleIfExists("ip6tables", chain, setName, "dst", "ACCEPT")
				m.removeRuleIfExists("ip6tables", chain, setName, "dst", "DROP")
			}
		}
	}

	return nil
}

// removeRuleIfExists removes a specific iptables rule if it exists (prevents duplication errors)
func (m *FirewallManager) removeRuleIfExists(command, chain, setName, direction, action string) {
	// Try to remove the rule (ignore errors if rule doesn't exist)
	removeCmd := exec.Command(command, "-D", chain, "-m", "set", "--match-set", setName, direction, "-j", action)
	removeCmd.Run() // Ignore errors - rule might not exist
}

// BlockIP blocks an IP address
func (m *FirewallManager) BlockIP(ip string, user string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Validate IP
	if !m.IsValidIP(ip) {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	// Add to blocklist
	if err := m.ipsetManager.AddToBlocklist(ip); err != nil {
		return fmt.Errorf("failed to add IP to blocklist: %w", err)
	}

	return nil
}

// WhitelistIP whitelists an IP address
func (m *FirewallManager) WhitelistIP(ip string, user string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Validate IP
	if !m.IsValidIP(ip) {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	// Add to whitelist
	if err := m.ipsetManager.AddToWhitelist(ip); err != nil {
		return fmt.Errorf("failed to add IP to whitelist: %w", err)
	}

	return nil
}

// UnblockIP removes an IP from the blocklist
func (m *FirewallManager) UnblockIP(ip string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Validate IP address
	if !m.IsValidIP(ip) {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	// Remove from blocklist
	if err := m.ipsetManager.RemoveFromBlocklist(ip); err != nil {
		return fmt.Errorf("failed to remove IP from blocklist: %w", err)
	}
	return nil
}

// UnwhitelistIP removes an IP from the whitelist
func (m *FirewallManager) UnwhitelistIP(ip string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Validate IP address
	if !m.IsValidIP(ip) {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	// Remove from whitelist
	if err := m.ipsetManager.RemoveFromWhitelist(ip); err != nil {
		return fmt.Errorf("failed to remove IP from whitelist: %w", err)
	}
	return nil
}

// BlockIPRange blocks a CIDR range
func (m *FirewallManager) BlockIPRange(cidr string, user string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Validate CIDR
	if !m.IsValidCIDR(cidr) {
		return fmt.Errorf("invalid CIDR range: %s", cidr)
	}

	// Add to blocklist
	if err := m.ipsetManager.AddRangeToBlocklist(cidr); err != nil {
		return fmt.Errorf("failed to add range to blocklist: %w", err)
	}

	return nil
}

// WhitelistIPRange whitelists a CIDR range
func (m *FirewallManager) WhitelistIPRange(cidr string, user string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Validate CIDR
	if !m.IsValidCIDR(cidr) {
		return fmt.Errorf("invalid CIDR range: %s", cidr)
	}

	// Add to whitelist
	if err := m.ipsetManager.AddRangeToWhitelist(cidr); err != nil {
		return fmt.Errorf("failed to add range to whitelist: %w", err)
	}

	return nil
}

// UnblockIPRange removes an IP range from the blocklist
func (m *FirewallManager) UnblockIPRange(cidr string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Validate CIDR
	if !m.IsValidCIDR(cidr) {
		return fmt.Errorf("invalid CIDR notation: %s", cidr)
	}

	// Remove from blocklist
	if err := m.ipsetManager.RemoveRangeFromBlocklist(cidr); err != nil {
		return fmt.Errorf("failed to remove IP range from blocklist: %w", err)
	}
	return nil
}

// UnwhitelistIPRange removes an IP range from the whitelist
func (m *FirewallManager) UnwhitelistIPRange(cidr string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Validate CIDR
	if !m.IsValidCIDR(cidr) {
		return fmt.Errorf("invalid CIDR notation: %s", cidr)
	}

	// Remove from whitelist
	if err := m.ipsetManager.RemoveRangeFromWhitelist(cidr); err != nil {
		return fmt.Errorf("failed to remove IP range from whitelist: %w", err)
	}
	return nil
}

// IsValidIP checks if a string is a valid IP address
func (m *FirewallManager) IsValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// IsValidCIDR checks if a string is a valid CIDR notation
func (m *FirewallManager) IsValidCIDR(cidr string) bool {
	// Full validation using net package
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}

// isIPv6 checks if an IP address is IPv6
func (m *FirewallManager) isIPv6(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	// Check if it's IPv6 by seeing if To4() returns nil
	return parsedIP.To4() == nil
}

// isIPv6CIDR checks if a CIDR is IPv6
func (m *FirewallManager) isIPv6CIDR(cidr string) bool {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	// Check if it's IPv6 by seeing if To4() returns nil
	return ip.To4() == nil
}

// SaveIPSetRules saves the current ipset rules to a file
func (m *FirewallManager) SaveIPSetRules(path string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.ipsetManager.SaveSets(path)
}

// GetMetrics returns the current firewall metrics
func (m *FirewallManager) GetMetrics() (Metrics, error) {
	if err := m.monitor.UpdateMetrics(); err != nil {
		return Metrics{}, fmt.Errorf("failed to update metrics: %w", err)
	}
	return m.monitor.GetMetrics(), nil
}

// HealthCheck performs a health check of the firewall
func (m *FirewallManager) HealthCheck() error {
	return m.monitor.HealthCheck()
}

// GetRuleStats returns statistics about firewall rules
func (m *FirewallManager) GetRuleStats() (map[string]int, error) {
	return m.monitor.GetRuleStats()
}

// GetMemoryUsage returns memory usage of firewall rules
func (m *FirewallManager) GetMemoryUsage() (map[string]int64, error) {
	return m.monitor.GetMemoryUsage()
}

// GetRulesStats returns statistics about the firewall rules
func (m *FirewallManager) GetRulesStats() (map[string]int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := make(map[string]int)

	// Get ipset names
	ipsetNames := m.ipsetManager.GetSetNames()

	// Count entries in each ipset
	for _, setName := range ipsetNames {
		entries, err := m.ipsetManager.listSet(setName)
		if err != nil {
			return nil, fmt.Errorf("failed to list ipset %s: %w", setName, err)
		}
		stats[setName] = len(entries)
	}

	return stats, nil
}

// Helper function to check if a slice contains a string
func contains(slice []string, str string) bool {
	for _, item := range slice {
		if item == str {
			return true
		}
	}
	return false
}

// IPSetManager methods
func (m *IPSetManager) EnsureSetsExist() error {
	// Define set names based on IPv4/IPv6 support with dnsniper prefix
	setNames := []string{
		"dnsniper-whitelist-ip-v4", "dnsniper-whitelist-range-v4",
		"dnsniper-blocklist-ip-v4", "dnsniper-blocklist-range-v4",
	}
	if m.enableIPv6 {
		setNames = append(setNames,
			"dnsniper-whitelist-ip-v6", "dnsniper-whitelist-range-v6",
			"dnsniper-blocklist-ip-v6", "dnsniper-blocklist-range-v6",
		)
	}

	// Create each set if it doesn't exist
	for _, setName := range setNames {
		// Check if set exists
		checkCmd := exec.Command("ipset", "list", setName)
		if err := checkCmd.Run(); err != nil {
			// Set doesn't exist, create it
			var createCmd *exec.Cmd
			if strings.Contains(setName, "IP") {
				// IP sets use hash:ip
				createCmd = exec.Command("ipset", "create", setName, "hash:ip", "family", "inet")
				if strings.Contains(setName, "v6") {
					createCmd = exec.Command("ipset", "create", setName, "hash:ip", "family", "inet6")
				}
			} else {
				// Range sets use hash:net
				createCmd = exec.Command("ipset", "create", setName, "hash:net", "family", "inet")
				if strings.Contains(setName, "v6") {
					createCmd = exec.Command("ipset", "create", setName, "hash:net", "family", "inet6")
				}
			}

			if err := createCmd.Run(); err != nil {
				return fmt.Errorf("failed to create ipset %s: %w", setName, err)
			}
		}
	}

	return nil
}

func (m *IPSetManager) GetSetNames() []string {
	setNames := []string{
		"dnsniper-whitelist-ip-v4", "dnsniper-whitelist-range-v4",
		"dnsniper-blocklist-ip-v4", "dnsniper-blocklist-range-v4",
	}
	if m.enableIPv6 {
		setNames = append(setNames,
			"dnsniper-whitelist-ip-v6", "dnsniper-whitelist-range-v6",
			"dnsniper-blocklist-ip-v6", "dnsniper-blocklist-range-v6",
		)
	}
	return setNames
}

func (m *IPSetManager) FlushAll() error {
	for _, setName := range m.GetSetNames() {
		cmd := exec.Command("ipset", "flush", setName)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to flush ipset %s: %w", setName, err)
		}
	}
	return nil
}

func (m *IPSetManager) CleanupAllSets() error {
	for _, setName := range m.GetSetNames() {
		// First flush the set
		flushCmd := exec.Command("ipset", "flush", setName)
		if err := flushCmd.Run(); err != nil {
			return fmt.Errorf("failed to flush ipset %s: %w", setName, err)
		}

		// Then destroy it
		destroyCmd := exec.Command("ipset", "destroy", setName)
		if err := destroyCmd.Run(); err != nil {
			return fmt.Errorf("failed to destroy ipset %s: %w", setName, err)
		}
	}
	return nil
}

func (m *IPSetManager) AddToBlocklist(ip string) error {
	// Determine if it's IPv4 or IPv6 using proper validation
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	isIPv6 := parsedIP.To4() == nil
	setName := "dnsniper-blocklist-ip-v4"
	if isIPv6 {
		if !m.enableIPv6 {
			return fmt.Errorf("IPv6 is disabled but received IPv6 address: %s", ip)
		}
		setName = "dnsniper-blocklist-ip-v6"
	}

	cmd := exec.Command("ipset", "add", setName, ip)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add IP %s to blocklist: %w", ip, err)
	}
	return nil
}

func (m *IPSetManager) AddToWhitelist(ip string) error {
	// Determine if it's IPv4 or IPv6 using proper validation
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	isIPv6 := parsedIP.To4() == nil
	setName := "dnsniper-whitelist-ip-v4"
	if isIPv6 {
		if !m.enableIPv6 {
			return fmt.Errorf("IPv6 is disabled but received IPv6 address: %s", ip)
		}
		setName = "dnsniper-whitelist-ip-v6"
	}

	cmd := exec.Command("ipset", "add", setName, ip)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add IP %s to whitelist: %w", ip, err)
	}
	return nil
}

func (m *IPSetManager) RemoveFromBlocklist(ip string) error {
	// Determine if it's IPv4 or IPv6 using proper validation
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	isIPv6 := parsedIP.To4() == nil
	setName := "dnsniper-blocklist-ip-v4"
	if isIPv6 {
		setName = "dnsniper-blocklist-ip-v6"
	}

	cmd := exec.Command("ipset", "del", setName, ip)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to remove IP %s from blocklist: %w", ip, err)
	}
	return nil
}

func (m *IPSetManager) RemoveFromWhitelist(ip string) error {
	// Determine if it's IPv4 or IPv6 using proper validation
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	isIPv6 := parsedIP.To4() == nil
	setName := "dnsniper-whitelist-ip-v4"
	if isIPv6 {
		setName = "dnsniper-whitelist-ip-v6"
	}

	cmd := exec.Command("ipset", "del", setName, ip)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to remove IP %s from whitelist: %w", ip, err)
	}
	return nil
}

func (m *IPSetManager) AddRangeToBlocklist(cidr string) error {
	// Validate and determine if it's IPv4 or IPv6
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %s", cidr)
	}

	isIPv6 := ip.To4() == nil
	setName := "dnsniper-blocklist-range-v4"
	if isIPv6 {
		if !m.enableIPv6 {
			return fmt.Errorf("IPv6 is disabled but received IPv6 CIDR: %s", cidr)
		}
		setName = "dnsniper-blocklist-range-v6"
	}

	cmd := exec.Command("ipset", "add", setName, cidr)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add range %s to blocklist: %w", cidr, err)
	}
	return nil
}

func (m *IPSetManager) AddRangeToWhitelist(cidr string) error {
	// Validate and determine if it's IPv4 or IPv6
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %s", cidr)
	}

	isIPv6 := ip.To4() == nil
	setName := "dnsniper-whitelist-range-v4"
	if isIPv6 {
		if !m.enableIPv6 {
			return fmt.Errorf("IPv6 is disabled but received IPv6 CIDR: %s", cidr)
		}
		setName = "dnsniper-whitelist-range-v6"
	}

	cmd := exec.Command("ipset", "add", setName, cidr)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add range %s to whitelist: %w", cidr, err)
	}
	return nil
}

func (m *IPSetManager) RemoveRangeFromBlocklist(cidr string) error {
	// Validate and determine if it's IPv4 or IPv6
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %s", cidr)
	}

	isIPv6 := ip.To4() == nil
	setName := "dnsniper-blocklist-range-v4"
	if isIPv6 {
		setName = "dnsniper-blocklist-range-v6"
	}

	cmd := exec.Command("ipset", "del", setName, cidr)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to remove range %s from blocklist: %w", cidr, err)
	}
	return nil
}

func (m *IPSetManager) RemoveRangeFromWhitelist(cidr string) error {
	// Validate and determine if it's IPv4 or IPv6
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %s", cidr)
	}

	isIPv6 := ip.To4() == nil
	setName := "dnsniper-whitelist-range-v4"
	if isIPv6 {
		setName = "dnsniper-whitelist-range-v6"
	}

	cmd := exec.Command("ipset", "del", setName, cidr)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to remove range %s from whitelist: %w", cidr, err)
	}
	return nil
}

func (m *IPSetManager) SaveSets(path string) error {
	cmd := exec.Command("ipset", "save", "-f", path)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to save ipset rules to %s: %w", path, err)
	}
	return nil
}

func (m *IPSetManager) listSet(setName string) ([]string, error) {
	cmd := exec.Command("ipset", "list", setName)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list ipset %s: %w", setName, err)
	}

	// Parse the output to extract entries
	var entries []string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		// Skip header lines and empty lines
		if strings.HasPrefix(line, "Name:") || strings.HasPrefix(line, "Type:") ||
			strings.HasPrefix(line, "Revision:") || strings.HasPrefix(line, "Header:") ||
			strings.HasPrefix(line, "Size in memory:") || strings.HasPrefix(line, "References:") ||
			strings.TrimSpace(line) == "" {
			continue
		}
		entries = append(entries, strings.TrimSpace(line))
	}

	return entries, nil
}

// IPTablesManager methods
func (m *IPTablesManager) GenerateRulesFile(chains []string, ipsetNames []string, isIPv6 bool) error {
	// Determine target file path
	var targetFile string
	if isIPv6 {
		targetFile = "/etc/iptables/rules.v6"
	} else {
		targetFile = "/etc/iptables/rules.v4"
	}

	// Ensure directory exists
	if err := os.MkdirAll("/etc/iptables", 0755); err != nil {
		return fmt.Errorf("failed to create iptables directory: %w", err)
	}

	// Read existing rules to preserve non-DNSniper rules
	existingRules := []string{}
	if content, err := os.ReadFile(targetFile); err == nil {
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			// Skip DNSniper rules and empty lines
			if !strings.Contains(line, "DNSniper") && !strings.Contains(line, "dnsniper") && strings.TrimSpace(line) != "" {
				existingRules = append(existingRules, line)
			}
		}
	}

	// Generate new DNSniper rules
	var newRules []string

	// Add header
	newRules = append(newRules, "# DNSniper firewall rules")
	newRules = append(newRules, fmt.Sprintf("# Generated at: %s", time.Now().Format("2006-01-02 15:04:05")))
	newRules = append(newRules, "# WARNING: Do not edit manually - these rules are auto-generated")
	newRules = append(newRules, "")

	// Separate whitelist and blocklist sets
	whitelistSets := []string{}
	blocklistSets := []string{}

	for _, setName := range ipsetNames {
		// Filter by IPv4/IPv6 compatibility
		if isIPv6 && !strings.Contains(setName, "v6") {
			continue
		}
		if !isIPv6 && strings.Contains(setName, "v6") {
			continue
		}

		if strings.Contains(setName, "whitelist") {
			whitelistSets = append(whitelistSets, setName)
		} else if strings.Contains(setName, "blocklist") {
			blocklistSets = append(blocklistSets, setName)
		}
	}

	// Generate whitelist rules first (higher priority)
	if len(whitelistSets) > 0 {
		newRules = append(newRules, "# Whitelist rules (priority protection)")
		for _, chain := range chains {
			for _, setName := range whitelistSets {
				// Only add rules for sets that actually exist
				if m.ipsetExists(setName) {
					newRules = append(newRules, fmt.Sprintf("-A %s -m set --match-set %s src -j ACCEPT -m comment --comment \"DNSniper whitelist\"", chain, setName))
					newRules = append(newRules, fmt.Sprintf("-A %s -m set --match-set %s dst -j ACCEPT -m comment --comment \"DNSniper whitelist\"", chain, setName))
				}
			}
		}
		newRules = append(newRules, "")
	}

	// Generate blocklist rules after whitelist
	if len(blocklistSets) > 0 {
		newRules = append(newRules, "# Blocklist rules")
		for _, chain := range chains {
			for _, setName := range blocklistSets {
				// Only add rules for sets that actually exist
				if m.ipsetExists(setName) {
					newRules = append(newRules, fmt.Sprintf("-A %s -m set --match-set %s src -j DROP -m comment --comment \"DNSniper blocklist\"", chain, setName))
					newRules = append(newRules, fmt.Sprintf("-A %s -m set --match-set %s dst -j DROP -m comment --comment \"DNSniper blocklist\"", chain, setName))
				}
			}
		}
		newRules = append(newRules, "")
	}

	// Combine existing rules with new DNSniper rules
	var finalRules []string

	// Add standard iptables-save header if not present
	hasHeader := false
	for _, rule := range existingRules {
		if strings.HasPrefix(rule, "*") {
			hasHeader = true
			break
		}
	}

	if !hasHeader {
		finalRules = append(finalRules, "*filter")
		finalRules = append(finalRules, ":INPUT ACCEPT [0:0]")
		finalRules = append(finalRules, ":FORWARD ACCEPT [0:0]")
		finalRules = append(finalRules, ":OUTPUT ACCEPT [0:0]")
	}

	// Add existing rules
	finalRules = append(finalRules, existingRules...)

	// Add new DNSniper rules
	finalRules = append(finalRules, newRules...)

	// Add COMMIT if not present
	hasCommit := false
	for _, rule := range finalRules {
		if strings.TrimSpace(rule) == "COMMIT" {
			hasCommit = true
			break
		}
	}

	if !hasCommit {
		finalRules = append(finalRules, "COMMIT")
	}

	// Write to target file
	content := strings.Join(finalRules, "\n") + "\n"
	if err := os.WriteFile(targetFile, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write rules to %s: %w", targetFile, err)
	}

	return nil
}

// ipsetExists checks if an ipset exists
func (m *IPTablesManager) ipsetExists(setName string) bool {
	cmd := exec.Command("ipset", "list", setName)
	return cmd.Run() == nil
}

func (m *IPTablesManager) ApplyRules(isIPv6 bool) error {
	// Determine command and file paths
	var cmd, rulesFile string
	if isIPv6 {
		cmd = "ip6tables"
		rulesFile = "/etc/iptables/rules.v6"
	} else {
		cmd = "iptables"
		rulesFile = "/etc/iptables/rules.v4"
	}

	// Check if rules file exists
	if _, err := os.Stat(rulesFile); os.IsNotExist(err) {
		return fmt.Errorf("rules file %s does not exist", rulesFile)
	}

	// Create backup of current rules
	backupFile := fmt.Sprintf("/tmp/dnsniper-backup-%s.rules", cmd)
	backupCmd := exec.Command(cmd + "-save")
	backupOutput, err := backupCmd.Output()
	if err != nil {
		return fmt.Errorf("failed to backup current %s rules: %w", cmd, err)
	}

	if err := os.WriteFile(backupFile, backupOutput, 0644); err != nil {
		return fmt.Errorf("failed to write backup file: %w", err)
	}

	// Apply new rules using iptables-restore
	applyCmd := exec.Command(cmd+"-restore", rulesFile)
	if err := applyCmd.Run(); err != nil {
		// If application fails, try to restore from backup
		restoreCmd := exec.Command(cmd+"-restore", backupFile)
		if restoreErr := restoreCmd.Run(); restoreErr != nil {
			return fmt.Errorf("failed to apply rules and failed to restore backup: apply error: %w, restore error: %v", err, restoreErr)
		}
		return fmt.Errorf("failed to apply %s rules, backup restored: %w", cmd, err)
	}

	// Save rules to persistence files if netfilter-persistent is available
	if command_exists("netfilter-persistent") {
		saveCmd := exec.Command("netfilter-persistent", "save")
		if err := saveCmd.Run(); err != nil {
			// Log warning but don't fail
			fmt.Printf("Warning: failed to save rules with netfilter-persistent: %v\n", err)
		}
	}

	// Clean up backup file after successful application
	os.Remove(backupFile)

	return nil
}

// command_exists checks if a command exists in PATH
func command_exists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}
