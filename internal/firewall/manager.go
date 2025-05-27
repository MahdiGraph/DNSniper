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

	// Check for IPv6 commands (these are optional but warn if missing)
	optionalCommands := []string{"ip6tables", "ip6tables-save", "ip6tables-restore"}
	for _, cmd := range optionalCommands {
		if _, err := exec.LookPath(cmd); err != nil {
			fmt.Printf("Warning: optional IPv6 command %s not found, IPv6 support may be limited\n", cmd)
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

	// Ensure ipsets exist (create only if they don't exist)
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
			// Just log a warning for IPv6 apply errors, don't fail the whole process
			fmt.Printf("Warning: Failed to apply IPv6 rules: %v\nIPv4 rules were applied successfully.\n", err)
		}
	}

	// Validate applied rules with proper IPv4/IPv6 filtering
	for _, chain := range m.chains {
		for _, setName := range ipsetNames {
			// Validate IPv4 rules only for IPv4 sets
			isSetIPv6 := strings.HasSuffix(setName, "-v6")
			if !isSetIPv6 {
				if err := m.validator.ValidateIPTablesRule(chain, setName, false); err != nil {
					// Try to restore from backup
					m.errorRecovery.RestoreRules(time.Now().Format("20060102-150405"))
					return fmt.Errorf("iptables validation failed: %w", err)
				}
			}

			// Validate IPv6 rules only for IPv6 sets - but don't fail if validation fails
			if m.enableIPv6 && isSetIPv6 {
				if err := m.validator.ValidateIPTablesRule(chain, setName, true); err != nil {
					// Log warning but continue - IPv4 is the priority
					fmt.Printf("Warning: IPv6 rules validation failed for %s: %v\nIPv4 rules are working correctly.\n", setName, err)
				}
			}
		}
	}

	return nil
}

// EnsureSetsExist ensures that all required ipsets exist
func (m *FirewallManager) EnsureSetsExist() error {
	return m.ipsetManager.EnsureSetsExist()
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
	setDefs := []struct {
		Name   string
		Type   string
		Family string
	}{
		{"dnsniper-whitelist-ip-v4", "hash:ip", "inet"},
		{"dnsniper-whitelist-range-v4", "hash:net", "inet"},
		{"dnsniper-blocklist-ip-v4", "hash:ip", "inet"},
		{"dnsniper-blocklist-range-v4", "hash:net", "inet"},
	}
	if m.enableIPv6 {
		setDefs = append(setDefs,
			struct{ Name, Type, Family string }{"dnsniper-whitelist-ip-v6", "hash:ip", "inet6"},
			struct{ Name, Type, Family string }{"dnsniper-whitelist-range-v6", "hash:net", "inet6"},
			struct{ Name, Type, Family string }{"dnsniper-blocklist-ip-v6", "hash:ip", "inet6"},
			struct{ Name, Type, Family string }{"dnsniper-blocklist-range-v6", "hash:net", "inet6"},
		)
	}

	for _, def := range setDefs {
		// Check if set exists
		checkCmd := exec.Command("ipset", "list", def.Name)
		output, err := checkCmd.CombinedOutput()
		if err != nil {
			// Set doesn't exist, create it
			createCmd := exec.Command("ipset", "create", def.Name, def.Type, "family", def.Family)
			if out, err := createCmd.CombinedOutput(); err != nil {
				return fmt.Errorf("failed to create ipset %s: %v, output: %s", def.Name, err, string(out))
			}
			continue
		}

		// Set already exists, don't try to recreate it to avoid conflicts
		// We'll just check and log if the type or family doesn't match
		outStr := string(output)
		if !strings.Contains(outStr, "Type: "+def.Type) || !strings.Contains(outStr, "Family: "+def.Family) {
			fmt.Printf("Warning: Existing ipset %s has incorrect type or family. Expected Type: %s, Family: %s\n",
				def.Name, def.Type, def.Family)
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
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to add IP %s to %s: %v, output: %s", ip, setName, err, string(out))
	}
	verifyCmd := exec.Command("ipset", "test", setName, ip)
	if err := verifyCmd.Run(); err != nil {
		return fmt.Errorf("ipset test failed for %s %s: %v", setName, ip, err)
	}
	return nil
}

func (m *IPSetManager) AddToWhitelist(ip string) error {
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
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to add IP %s to %s: %v, output: %s", ip, setName, err, string(out))
	}
	verifyCmd := exec.Command("ipset", "test", setName, ip)
	if err := verifyCmd.Run(); err != nil {
		return fmt.Errorf("ipset test failed for %s %s: %v", setName, ip, err)
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
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to add range %s to %s: %v, output: %s", cidr, setName, err, string(out))
	}
	verifyCmd := exec.Command("ipset", "test", setName, cidr)
	if err := verifyCmd.Run(); err != nil {
		return fmt.Errorf("ipset test failed for %s %s: %v", setName, cidr, err)
	}
	return nil
}

func (m *IPSetManager) AddRangeToWhitelist(cidr string) error {
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
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to add range %s to %s: %v, output: %s", cidr, setName, err, string(out))
	}
	verifyCmd := exec.Command("ipset", "test", setName, cidr)
	if err := verifyCmd.Run(); err != nil {
		return fmt.Errorf("ipset test failed for %s %s: %v", setName, cidr, err)
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

// GenerateRulesFile generates iptables rules file for IPv4 or IPv6
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

	// Get current rules using iptables-save to preserve existing rules
	var cmd string
	if isIPv6 {
		cmd = "ip6tables-save"
	} else {
		cmd = "iptables-save"
	}

	saveCmd := exec.Command(cmd)
	currentRules, err := saveCmd.Output()

	// برای IPv6 اگر خروجی خالی بود یک ساختار کامل بساز
	if err != nil || len(currentRules) == 0 {
		if isIPv6 {
			// ساختار کامل برای IPv6 با تمام table ها
			currentRules = []byte(`# Generated by ip6tables-save
*raw
:PREROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
COMMIT
*mangle
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
COMMIT
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
COMMIT
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
COMMIT
`)
		} else {
			// ساختار ساده برای IPv4
			currentRules = []byte(`# Generated by iptables-save
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
COMMIT
`)
		}
	}

	// Parse existing rules and remove DNSniper rules
	lines := strings.Split(string(currentRules), "\n")
	var cleanedRules []string

	for _, line := range lines {
		// Skip DNSniper rules but keep everything else
		if !strings.Contains(line, "DNSniper") && !strings.Contains(line, "dnsniper") {
			cleanedRules = append(cleanedRules, line)
		}
	}

	// Find where to insert new rules (in filter table, after chain definitions, before COMMIT)
	var finalRules []string
	insertIndex := -1
	inFilterTable := false
	filterTableIndex := -1

	for i, line := range cleanedRules {
		finalRules = append(finalRules, line)

		// Check if we're entering filter table
		if line == "*filter" {
			inFilterTable = true
			filterTableIndex = i
		} else if strings.HasPrefix(line, "*") {
			inFilterTable = false
		}

		// Find insertion point in filter table
		if inFilterTable && strings.HasPrefix(line, ":") && insertIndex == -1 {
			insertIndex = i + 1
		}

		if inFilterTable && strings.TrimSpace(line) == "COMMIT" {
			// Insert DNSniper rules before COMMIT in filter table
			if insertIndex == -1 {
				insertIndex = i
			}

			// Generate DNSniper rules
			dnsniperRules := m.generateDNSniperRules(chains, ipsetNames, isIPv6)

			// Only insert rules if we have any
			if len(dnsniperRules) > 0 {
				// Insert at the right position
				finalRules = append(finalRules[:insertIndex], append(dnsniperRules, finalRules[insertIndex:]...)...)
			}
			break
		}
	}

	// If no filter table found, create one with DNSniper rules
	if filterTableIndex == -1 {
		// Add filter table before final COMMIT or at the end
		filterSection := []string{
			"*filter",
			":INPUT ACCEPT [0:0]",
			":FORWARD ACCEPT [0:0]",
			":OUTPUT ACCEPT [0:0]",
		}

		// Add DNSniper rules
		dnsniperRules := m.generateDNSniperRules(chains, ipsetNames, isIPv6)
		filterSection = append(filterSection, dnsniperRules...)
		filterSection = append(filterSection, "COMMIT")

		// Find where to insert (before last line if it's empty, otherwise at end)
		if len(finalRules) > 0 && strings.TrimSpace(finalRules[len(finalRules)-1]) == "" {
			finalRules = append(finalRules[:len(finalRules)-1], filterSection...)
			finalRules = append(finalRules, "")
		} else {
			finalRules = append(finalRules, filterSection...)
		}
	}

	// Write to target file
	content := strings.Join(finalRules, "\n")

	// اطمینان از اینکه فایل با newline تمام میشه
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}

	// Log the content for debugging (especially for IPv6)
	if isIPv6 {
		// Count DNSniper rules for verification
		dnsniperRuleCount := strings.Count(content, "dnsniper")
		if dnsniperRuleCount == 0 {
			return fmt.Errorf("no DNSniper rules generated for IPv6 - check ipset names and compatibility")
		}
		fmt.Printf("Generated %d DNSniper rules for IPv6\n", dnsniperRuleCount)
	}

	if err := os.WriteFile(targetFile, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write rules to %s: %w", targetFile, err)
	}

	// برای IPv6، بررسی اضافی که فایل واقعا نوشته شده
	if isIPv6 {
		if stat, err := os.Stat(targetFile); err != nil {
			return fmt.Errorf("failed to verify IPv6 rules file: %w", err)
		} else if stat.Size() == 0 {
			return fmt.Errorf("IPv6 rules file is empty after writing")
		}
	}

	return nil
}

func (m *IPTablesManager) generateDNSniperRules(chains []string, ipsetNames []string, isIPv6 bool) []string {
	var rules []string

	// Add header comment
	rules = append(rules, "# DNSniper firewall rules")
	rules = append(rules, fmt.Sprintf("# Generated at: %s", time.Now().Format("2006-01-02 15:04:05")))
	if isIPv6 {
		rules = append(rules, "# IPv6 rules")
	} else {
		rules = append(rules, "# IPv4 rules")
	}

	// اضافه کردن debug logging دقیق‌تر
	rules = append(rules, fmt.Sprintf("# Debug: Processing %d total ipset names for %s", len(ipsetNames),
		map[bool]string{true: "IPv6", false: "IPv4"}[isIPv6]))

	// Log all input ipset names
	rules = append(rules, "# Debug: Input ipset names:")
	for i, setName := range ipsetNames {
		rules = append(rules, fmt.Sprintf("#   %d. %s", i+1, setName))
	}

	// Separate whitelist and blocklist sets with proper IPv4/IPv6 filtering
	whitelistSets := []string{}
	blocklistSets := []string{}

	// بررسی دقیق‌تر ipset ها
	var availableIPSets []string
	var missingIPSets []string
	var skippedIPSets []string

	for _, setName := range ipsetNames {
		// Check if set exists first
		exists := m.ipsetExists(setName)
		rules = append(rules, fmt.Sprintf("# Debug: Checking ipset %s - exists: %v", setName, exists))

		if !exists {
			missingIPSets = append(missingIPSets, setName)
			rules = append(rules, fmt.Sprintf("#   -> %s does NOT exist, skipping", setName))
			continue
		}

		availableIPSets = append(availableIPSets, setName)

		// Debug logging
		isSetIPv6 := strings.HasSuffix(setName, "-v6")
		rules = append(rules, fmt.Sprintf("#   -> %s exists (isIPv6=%v, needIPv6=%v)", setName, isSetIPv6, isIPv6))

		// Filter by IPv4/IPv6 compatibility
		if isIPv6 {
			// For IPv6 rules, only include v6 sets
			if !strings.HasSuffix(setName, "-v6") {
				rules = append(rules, fmt.Sprintf("#   -> Skipping %s (IPv4 set, need IPv6)", setName))
				skippedIPSets = append(skippedIPSets, setName)
				continue
			}
		} else {
			// For IPv4 rules, only include v4 sets (exclude v6)
			if strings.HasSuffix(setName, "-v6") {
				rules = append(rules, fmt.Sprintf("#   -> Skipping %s (IPv6 set, need IPv4)", setName))
				skippedIPSets = append(skippedIPSets, setName)
				continue
			}
		}

		// Categorize sets
		if strings.Contains(setName, "whitelist") {
			whitelistSets = append(whitelistSets, setName)
			rules = append(rules, fmt.Sprintf("#   -> Added %s to whitelistSets", setName))
		} else if strings.Contains(setName, "blocklist") {
			blocklistSets = append(blocklistSets, setName)
			rules = append(rules, fmt.Sprintf("#   -> Added %s to blocklistSets", setName))
		}
	}

	// گزارش نهایی وضعیت
	rules = append(rules, "# Debug Summary:")
	rules = append(rules, fmt.Sprintf("#   Total input ipsets: %d", len(ipsetNames)))
	rules = append(rules, fmt.Sprintf("#   Available ipsets: %d", len(availableIPSets)))
	rules = append(rules, fmt.Sprintf("#   Missing ipsets: %d", len(missingIPSets)))
	rules = append(rules, fmt.Sprintf("#   Skipped ipsets: %d", len(skippedIPSets)))
	rules = append(rules, fmt.Sprintf("#   Final whitelist sets: %d", len(whitelistSets)))
	rules = append(rules, fmt.Sprintf("#   Final blocklist sets: %d", len(blocklistSets)))

	// گزارش ipset های missing
	if len(missingIPSets) > 0 {
		rules = append(rules, fmt.Sprintf("# WARNING: Missing ipsets: %s", strings.Join(missingIPSets, ", ")))
	}

	// گزارش ipset های skipped
	if len(skippedIPSets) > 0 {
		rules = append(rules, fmt.Sprintf("# INFO: Skipped ipsets: %s", strings.Join(skippedIPSets, ", ")))
	}

	// لیست نهایی ipset ها
	for _, setName := range whitelistSets {
		rules = append(rules, fmt.Sprintf("# Final whitelist set: %s", setName))
	}
	for _, setName := range blocklistSets {
		rules = append(rules, fmt.Sprintf("# Final blocklist set: %s", setName))
	}

	// Generate whitelist rules first (higher priority)
	if len(whitelistSets) > 0 {
		rules = append(rules, "# Whitelist rules (priority protection)")
		rules = append(rules, fmt.Sprintf("# Generating rules for %d chains and %d whitelist sets", len(chains), len(whitelistSets)))
		for _, chain := range chains {
			for _, setName := range whitelistSets {
				// Add both source and destination rules
				srcRule := fmt.Sprintf("-A %s -m set --match-set %s src -j ACCEPT", chain, setName)
				dstRule := fmt.Sprintf("-A %s -m set --match-set %s dst -j ACCEPT", chain, setName)
				rules = append(rules, srcRule)
				rules = append(rules, dstRule)
				rules = append(rules, fmt.Sprintf("# Added whitelist rules for %s in chain %s", setName, chain))
			}
		}
	} else {
		rules = append(rules, "# No whitelist sets available for rules generation")
	}

	// Generate blocklist rules after whitelist
	if len(blocklistSets) > 0 {
		rules = append(rules, "# Blocklist rules")
		rules = append(rules, fmt.Sprintf("# Generating rules for %d chains and %d blocklist sets", len(chains), len(blocklistSets)))
		for _, chain := range chains {
			for _, setName := range blocklistSets {
				// Add both source and destination rules
				srcRule := fmt.Sprintf("-A %s -m set --match-set %s src -j DROP", chain, setName)
				dstRule := fmt.Sprintf("-A %s -m set --match-set %s dst -j DROP", chain, setName)
				rules = append(rules, srcRule)
				rules = append(rules, dstRule)
				rules = append(rules, fmt.Sprintf("# Added blocklist rules for %s in chain %s", setName, chain))
			}
		}
	} else {
		rules = append(rules, "# No blocklist sets available for rules generation")
	}

	// Add warning if no rules generated
	if len(whitelistSets) == 0 && len(blocklistSets) == 0 {
		if isIPv6 {
			rules = append(rules, "# WARNING: No IPv6 ipsets found for DNSniper rules!")
			rules = append(rules, "# This might indicate that:")
			rules = append(rules, "#   1. IPv6 ipsets are not created")
			rules = append(rules, "#   2. IPv6 is disabled in configuration")
			rules = append(rules, "#   3. ipset creation failed")
			rules = append(rules, "#   4. ipset command is not available (Windows/non-Linux system)")
			rules = append(rules, "# Check with: ipset list | grep v6")
		} else {
			rules = append(rules, "# WARNING: No IPv4 ipsets found for DNSniper rules!")
		}
	}

	rules = append(rules, fmt.Sprintf("# Final rule count: %d rules generated", len(rules)))
	return rules
}

// ipsetExists checks if an ipset exists
func (m *IPTablesManager) ipsetExists(setName string) bool {
	// First check if ipset command is available
	if _, err := exec.LookPath("ipset"); err != nil {
		// ipset command not found (likely Windows or system without ipset)
		fmt.Printf("Warning: ipset command not found, assuming %s doesn't exist\n", setName)
		return false
	}

	cmd := exec.Command("ipset", "list", setName)
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Debug: ipset %s check failed: %v\n", setName, err)
		return false
	}
	fmt.Printf("Debug: ipset %s exists\n", setName)
	return true
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

	// If the required binary is not present (common on systems without IPv6), skip applying but keep the file.
	if _, err := exec.LookPath(cmd); err != nil {
		fmt.Printf("Warning: %s binary not found, skipping apply for %s (rules file will still be saved)\n", cmd, rulesFile)
		return nil
	}

	// Check if rules file exists
	if _, err := os.Stat(rulesFile); os.IsNotExist(err) {
		return fmt.Errorf("rules file %s does not exist", rulesFile)
	}

	// Read the rules file to check its content
	content, err := os.ReadFile(rulesFile)
	if err != nil {
		return fmt.Errorf("failed to read rules file %s: %w", rulesFile, err)
	}

	// Validate rules file content
	if len(content) == 0 {
		return fmt.Errorf("rules file %s is empty", rulesFile)
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

	// For IPv6, try first with a safer approach (just the filter table)
	if isIPv6 {
		// Extract just the filter table rules
		filterStart := strings.Index(string(content), "*filter")
		if filterStart >= 0 {
			filterEnd := strings.Index(string(content)[filterStart:], "COMMIT")
			if filterEnd > 0 {
				filterTable := string(content)[filterStart : filterStart+filterEnd+6] // include "COMMIT"
				// Apply just the filter table
				tempFile := fmt.Sprintf("/tmp/dnsniper-filter-%s.rules", cmd)
				if err := os.WriteFile(tempFile, []byte(filterTable), 0644); err == nil {
					filterCmd := exec.Command(cmd+"-restore", "-n", tempFile)
					filterOut, filterErr := filterCmd.CombinedOutput()
					if filterErr == nil {
						// Filter table looks good, try to apply full rules
						fmt.Printf("IPv6 filter table validated successfully, applying full rules\n")
					} else {
						fmt.Printf("Warning: IPv6 filter table validation failed: %v\nOutput: %s\n", filterErr, string(filterOut))
						// We'll still try the full apply below
					}
					os.Remove(tempFile)
				}
			}
		}
	}

	// Apply new rules using iptables-restore
	// For IPv6, we use -n flag which means only check the rules but don't apply yet
	if isIPv6 {
		// Test first without applying
		testCmd := exec.Command(cmd+"-restore", "-t")
		testOutput, testErr := testCmd.CombinedOutput()
		if testErr != nil {
			fmt.Printf("Warning: %s-restore test failed: %v\nOutput: %s\n", cmd, testErr, string(testOutput))
			// We'll still try to apply with the regular command
		}
	}

	applyCmd := exec.Command(cmd+"-restore", rulesFile)
	output, err := applyCmd.CombinedOutput()
	if err != nil {
		// If application fails, try to restore from backup
		restoreCmd := exec.Command(cmd+"-restore", backupFile)
		if restoreErr := restoreCmd.Run(); restoreErr != nil {
			return fmt.Errorf("failed to apply rules and failed to restore backup: apply error: %w (output: %s), restore error: %v", err, string(output), restoreErr)
		}
		return fmt.Errorf("failed to apply %s rules, backup restored: %w (output: %s)", cmd, err, string(output))
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

// CheckIPv6Support checks IPv6 support and configuration
func (m *FirewallManager) CheckIPv6Support() error {
	fmt.Println("=== IPv6 Support Check ===")

	// Check if IPv6 is enabled in config
	fmt.Printf("IPv6 enabled in config: %v\n", m.enableIPv6)

	// Check if ipset command exists
	if _, err := exec.LookPath("ipset"); err != nil {
		fmt.Printf("ipset command: NOT FOUND (%v)\n", err)
		return fmt.Errorf("ipset command not available")
	}
	fmt.Println("ipset command: FOUND")

	// Check if ip6tables command exists
	if _, err := exec.LookPath("ip6tables"); err != nil {
		fmt.Printf("ip6tables command: NOT FOUND (%v)\n", err)
	} else {
		fmt.Println("ip6tables command: FOUND")
	}

	// List all DNSniper ipsets
	fmt.Println("\n=== Current DNSniper ipsets ===")
	allSets := m.ipsetManager.GetSetNames()
	for _, setName := range allSets {
		exists := m.iptablesManager.ipsetExists(setName)
		isIPv6Set := strings.HasSuffix(setName, "-v6")
		fmt.Printf("  %s: exists=%v, isIPv6=%v\n", setName, exists, isIPv6Set)
	}

	// Check IPv6 kernel support
	fmt.Println("\n=== IPv6 Kernel Support ===")
	if _, err := os.Stat("/proc/net/if_inet6"); err != nil {
		fmt.Println("IPv6 kernel support: NOT AVAILABLE")
	} else {
		fmt.Println("IPv6 kernel support: AVAILABLE")
	}

	// Try to create a test IPv6 ipset
	fmt.Println("\n=== Test IPv6 ipset creation ===")
	testSetName := "dnsniper-test-v6"

	// Clean up any existing test set
	cleanupCmd := exec.Command("ipset", "destroy", testSetName)
	cleanupCmd.Run() // Ignore error

	// Try to create test set
	createCmd := exec.Command("ipset", "create", testSetName, "hash:ip", "family", "inet6")
	if err := createCmd.Run(); err != nil {
		fmt.Printf("Test IPv6 ipset creation: FAILED (%v)\n", err)
	} else {
		fmt.Println("Test IPv6 ipset creation: SUCCESS")

		// Clean up test set
		destroyCmd := exec.Command("ipset", "destroy", testSetName)
		destroyCmd.Run()
	}

	fmt.Println("=== End IPv6 Support Check ===")
	return nil
}
