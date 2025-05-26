package firewall

import (
	"fmt"
	"net"
	"os/exec"
)

// FirewallManager provides a unified interface for firewall operations
type FirewallManager struct {
	ipsetManager    *IPSetManager
	iptablesManager *IPTablesManager
	chains          []string
	enableIPv6      bool
}

// NewFirewallManager creates a new firewall manager
func NewFirewallManager(
	enableIPv6 bool,
	chains []string,
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

	// Parse chains
	parsedChains := parseChains(chains)

	return &FirewallManager{
		ipsetManager:    ipsetManager,
		iptablesManager: iptablesManager,
		chains:          parsedChains,
		enableIPv6:      enableIPv6,
	}, nil
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
		switch chain {
		case "INPUT", "OUTPUT", "FORWARD":
			// Only add if not already present
			if !contains(validChains, chain) {
				validChains = append(validChains, chain)
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
	// Ensure ipsets exist (recreate if missing)
	if err := m.ipsetManager.EnsureSetsExist(); err != nil {
		return fmt.Errorf("failed to ensure ipsets exist: %w", err)
	}

	// Remove existing DNSniper rules to prevent duplications
	if err := m.RemoveDNSniperRules(); err != nil {
		return fmt.Errorf("failed to remove existing rules: %w", err)
	}

	// Get ipset names
	ipsetNames := m.ipsetManager.GetSetNames()

	// Generate rules files
	if err := m.iptablesManager.GenerateRulesFile(m.chains, ipsetNames, false); err != nil {
		return fmt.Errorf("failed to generate IPv4 rules file: %w", err)
	}

	if m.enableIPv6 {
		if err := m.iptablesManager.GenerateRulesFile(m.chains, ipsetNames, true); err != nil {
			return fmt.Errorf("failed to generate IPv6 rules file: %w", err)
		}
	}

	// Apply rules
	if err := m.iptablesManager.ApplyRules(false); err != nil {
		return fmt.Errorf("failed to apply IPv4 rules: %w", err)
	}

	if m.enableIPv6 {
		if err := m.iptablesManager.ApplyRules(true); err != nil {
			return fmt.Errorf("failed to apply IPv6 rules: %w", err)
		}
	}

	// Apply rules using persistent service
	if err := m.iptablesManager.ApplyRulesFromPersistentService(); err != nil {
		return fmt.Errorf("failed to apply persistent rules: %w", err)
	}

	return nil
}

// ClearAll clears all firewall rules
func (m *FirewallManager) ClearAll() error {
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

// BlockIP adds an IP to the blocklist
func (m *FirewallManager) BlockIP(ip string) error {
	if err := m.ipsetManager.AddToBlocklist(ip); err != nil {
		return fmt.Errorf("failed to add IP to blocklist: %w", err)
	}
	return nil
}

// WhitelistIP adds an IP to the whitelist
func (m *FirewallManager) WhitelistIP(ip string) error {
	if err := m.ipsetManager.AddToWhitelist(ip); err != nil {
		return fmt.Errorf("failed to add IP to whitelist: %w", err)
	}
	return nil
}

// UnblockIP removes an IP from the blocklist
func (m *FirewallManager) UnblockIP(ip string) error {
	if err := m.ipsetManager.RemoveFromBlocklist(ip); err != nil {
		return fmt.Errorf("failed to remove IP from blocklist: %w", err)
	}
	return nil
}

// UnwhitelistIP removes an IP from the whitelist
func (m *FirewallManager) UnwhitelistIP(ip string) error {
	if err := m.ipsetManager.RemoveFromWhitelist(ip); err != nil {
		return fmt.Errorf("failed to remove IP from whitelist: %w", err)
	}
	return nil
}

// BlockIPRange adds an IP range to the blocklist
func (m *FirewallManager) BlockIPRange(cidr string) error {
	if err := m.ipsetManager.AddRangeToBlocklist(cidr); err != nil {
		return fmt.Errorf("failed to add IP range to blocklist: %w", err)
	}
	return nil
}

// WhitelistIPRange adds an IP range to the whitelist
func (m *FirewallManager) WhitelistIPRange(cidr string) error {
	if err := m.ipsetManager.AddRangeToWhitelist(cidr); err != nil {
		return fmt.Errorf("failed to add IP range to whitelist: %w", err)
	}
	return nil
}

// UnblockIPRange removes an IP range from the blocklist
func (m *FirewallManager) UnblockIPRange(cidr string) error {
	if err := m.ipsetManager.RemoveRangeFromBlocklist(cidr); err != nil {
		return fmt.Errorf("failed to remove IP range from blocklist: %w", err)
	}
	return nil
}

// UnwhitelistIPRange removes an IP range from the whitelist
func (m *FirewallManager) UnwhitelistIPRange(cidr string) error {
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
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}

// SaveIPSetRules saves the current ipset rules to a file
func (m *FirewallManager) SaveIPSetRules(path string) error {
	return m.ipsetManager.SaveSets(path)
}

// GetRulesStats returns statistics about firewall rules
func (m *FirewallManager) GetRulesStats() (map[string]int, error) {
	stats := make(map[string]int)

	// Count entries in each set
	sets := m.ipsetManager.GetSetNames()
	for _, set := range sets {
		entries, err := m.ipsetManager.listSet(set)
		if err != nil {
			continue
		}
		stats[set] = len(entries)
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
