package firewall

import (
	"fmt"
	"net"
)

// FirewallManager provides a unified interface for firewall operations
type FirewallManager struct {
	ipsetManager    *IPSetManager
	iptablesManager *IPTablesManager
	chains          []string
	ipsetPath       string
	ipTablesPath    string
	ip6TablesPath   string
	enableIPv6      bool
}

// NewFirewallManager creates a new firewall manager
func NewFirewallManager(
	ipsetPath, ipTablesPath, ip6TablesPath string,
	enableIPv6 bool,
	chains []string,
) (*FirewallManager, error) {
	// Create ipset manager
	ipsetManager, err := NewIPSetManager(ipsetPath, enableIPv6)
	if err != nil {
		return nil, fmt.Errorf("failed to create ipset manager: %w", err)
	}

	// Create iptables manager
	iptablesManager, err := NewIPTablesManager(ipTablesPath, ip6TablesPath, enableIPv6)
	if err != nil {
		return nil, fmt.Errorf("failed to create iptables manager: %w", err)
	}

	// Parse chains
	parsedChains := parseChains(chains)

	return &FirewallManager{
		ipsetManager:    ipsetManager,
		iptablesManager: iptablesManager,
		chains:          parsedChains,
		ipsetPath:       ipsetPath,
		ipTablesPath:    ipTablesPath,
		ip6TablesPath:   ip6TablesPath,
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

	// Regenerate empty rules files
	if err := m.Reload(); err != nil {
		return fmt.Errorf("failed to reload empty rules: %w", err)
	}

	return nil
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
