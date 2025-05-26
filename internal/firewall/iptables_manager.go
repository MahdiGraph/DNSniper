package firewall

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
)

// IPTablesManager handles iptables rules
type IPTablesManager struct {
	enableIPv6  bool
	rulesV4Path string
	rulesV6Path string
	mu          sync.Mutex
}

// NewIPTablesManager creates a new iptables manager
func NewIPTablesManager(enableIPv6 bool) (*IPTablesManager, error) {
	manager := &IPTablesManager{
		enableIPv6:  enableIPv6,
		rulesV4Path: "/etc/iptables/rules.v4",
		rulesV6Path: "/etc/iptables/rules.v6",
	}

	// Ensure iptables is available
	cmd := exec.Command("iptables", "-V")
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("iptables not available: %w", err)
	}

	// Ensure ip6tables is available if IPv6 is enabled
	if enableIPv6 {
		cmd = exec.Command("ip6tables", "-V")
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("ip6tables not available: %w", err)
		}
	}

	// Create iptables rules directory if it doesn't exist
	if err := os.MkdirAll("/etc/iptables", 0755); err != nil {
		return nil, fmt.Errorf("failed to create iptables directory: %w", err)
	}

	return manager, nil
}

// GenerateRulesFile generates the iptables rules file for the given chains
func (m *IPTablesManager) GenerateRulesFile(chains []string, ipsetNames []string, isPv6 bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Choose appropriate paths
	iptablesPath := "iptables"
	rulesPath := m.rulesV4Path
	if isPv6 {
		if !m.enableIPv6 {
			return nil // Skip if IPv6 is disabled
		}
		iptablesPath = "ip6tables"
		rulesPath = m.rulesV6Path
	}

	// Get current rules and parse them properly
	cmd := exec.Command(iptablesPath + "-save")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to save current rules: %w", err)
	}

	// Parse current rules and remove DNSniper rules
	lines := strings.Split(string(output), "\n")
	var cleanedRules []string
	var inFilterTable bool
	var commitSeen bool

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Track table sections
		if strings.HasPrefix(line, "*filter") {
			inFilterTable = true
			cleanedRules = append(cleanedRules, line)
			continue
		}

		if line == "COMMIT" && inFilterTable {
			commitSeen = true
			// Don't add COMMIT yet - we'll add our rules first
			continue
		}

		if strings.HasPrefix(line, "*") && line != "*filter" {
			// If we were in filter table and haven't seen COMMIT, add it
			if inFilterTable && !commitSeen {
				// Add our rules here before COMMIT
				cleanedRules = append(cleanedRules, m.generateDNSniperRules(chains, isPv6)...)
				cleanedRules = append(cleanedRules, "COMMIT")
			}
			inFilterTable = false
			commitSeen = false
			cleanedRules = append(cleanedRules, line)
			continue
		}

		// Skip DNSniper rules
		if containsAny(line, ipsetNames) {
			continue
		}

		cleanedRules = append(cleanedRules, line)
	}

	// If we ended in filter table without COMMIT, add our rules and COMMIT
	if inFilterTable && !commitSeen {
		cleanedRules = append(cleanedRules, m.generateDNSniperRules(chains, isPv6)...)
		cleanedRules = append(cleanedRules, "COMMIT")
	}

	// If no filter table was found, create one
	if !inFilterTable && len(cleanedRules) == 0 {
		cleanedRules = append(cleanedRules, "*filter")
		cleanedRules = append(cleanedRules, ":INPUT ACCEPT [0:0]")
		cleanedRules = append(cleanedRules, ":FORWARD ACCEPT [0:0]")
		cleanedRules = append(cleanedRules, ":OUTPUT ACCEPT [0:0]")
		cleanedRules = append(cleanedRules, m.generateDNSniperRules(chains, isPv6)...)
		cleanedRules = append(cleanedRules, "COMMIT")
	}

	// Join all rules
	fileContent := strings.Join(cleanedRules, "\n") + "\n"

	// Write to file
	if err := os.WriteFile(rulesPath, []byte(fileContent), 0644); err != nil {
		return fmt.Errorf("failed to write rules file: %w", err)
	}

	return nil
}

// generateDNSniperRules generates DNSniper-specific iptables rules
func (m *IPTablesManager) generateDNSniperRules(chains []string, isPv6 bool) []string {
	var rules []string

	// Determine IP version suffix
	ipSuffix := "v4"
	if isPv6 {
		ipSuffix = "v6"
	}

	for _, chain := range chains {
		// Only handle valid chains
		if chain != "INPUT" && chain != "OUTPUT" && chain != "FORWARD" {
			continue
		}

		// Order is critical: whitelist rules must come before blacklist rules

		// Whitelist rules for source traffic
		rules = append(rules, fmt.Sprintf("-A %s -m set --match-set whitelistIP-%s src -j ACCEPT", chain, ipSuffix))
		rules = append(rules, fmt.Sprintf("-A %s -m set --match-set whitelistRange-%s src -j ACCEPT", chain, ipSuffix))

		// Blacklist rules for source traffic
		rules = append(rules, fmt.Sprintf("-A %s -m set --match-set blacklistIP-%s src -j DROP", chain, ipSuffix))
		rules = append(rules, fmt.Sprintf("-A %s -m set --match-set blacklistRange-%s src -j DROP", chain, ipSuffix))

		// For OUTPUT and FORWARD chains, also check destination
		if chain == "OUTPUT" || chain == "FORWARD" {
			rules = append(rules, fmt.Sprintf("-A %s -m set --match-set whitelistIP-%s dst -j ACCEPT", chain, ipSuffix))
			rules = append(rules, fmt.Sprintf("-A %s -m set --match-set whitelistRange-%s dst -j ACCEPT", chain, ipSuffix))
			rules = append(rules, fmt.Sprintf("-A %s -m set --match-set blacklistIP-%s dst -j DROP", chain, ipSuffix))
			rules = append(rules, fmt.Sprintf("-A %s -m set --match-set blacklistRange-%s dst -j DROP", chain, ipSuffix))
		}
	}

	return rules
}

// ApplyRules applies the iptables rules from the rules file
func (m *IPTablesManager) ApplyRules(isPv6 bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Choose appropriate paths
	iptablesPath := "iptables"
	rulesPath := m.rulesV4Path
	if isPv6 {
		if !m.enableIPv6 {
			return nil // Skip if IPv6 is disabled
		}
		iptablesPath = "ip6tables"
		rulesPath = m.rulesV6Path
	}

	// Check if file exists
	if _, err := os.Stat(rulesPath); os.IsNotExist(err) {
		return fmt.Errorf("rules file %s does not exist", rulesPath)
	}

	// Apply rules from file
	cmd := exec.Command(iptablesPath+"-restore", rulesPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to apply rules: %w (%s)", err, output)
	}

	return nil
}

// ApplyRulesFromPersistentService applies rules using netfilter-persistent
func (m *IPTablesManager) ApplyRulesFromPersistentService() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Try with systemctl first
	cmd := exec.Command("systemctl", "restart", "netfilter-persistent")
	err := cmd.Run()
	if err == nil {
		return nil
	}

	// If systemctl failed, try directly with the service
	cmd = exec.Command("service", "netfilter-persistent", "reload")
	err = cmd.Run()
	if err == nil {
		return nil
	}

	// If that failed too, try with the script directly
	cmd = exec.Command("/usr/sbin/netfilter-persistent", "reload")
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to reload netfilter-persistent: %w", err)
	}

	return nil
}

// Helper function to check if a string contains any of the given substrings
func containsAny(s string, substrings []string) bool {
	for _, substring := range substrings {
		if strings.Contains(s, substring) {
			return true
		}
	}
	return false
}
