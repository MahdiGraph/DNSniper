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
	ipTablesPath  string
	ip6TablesPath string
	enableIPv6    bool
	rulesV4Path   string
	rulesV6Path   string
	mu            sync.Mutex
}

// NewIPTablesManager creates a new iptables manager
func NewIPTablesManager(ipTablesPath, ip6TablesPath string, enableIPv6 bool) (*IPTablesManager, error) {
	manager := &IPTablesManager{
		ipTablesPath:  ipTablesPath,
		ip6TablesPath: ip6TablesPath,
		enableIPv6:    enableIPv6,
		rulesV4Path:   "/etc/iptables/rules.v4",
		rulesV6Path:   "/etc/iptables/rules.v6",
	}

	// Ensure iptables is available
	cmd := exec.Command(ipTablesPath, "-V")
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("iptables not available: %w", err)
	}

	// Ensure ip6tables is available if IPv6 is enabled
	if enableIPv6 {
		cmd = exec.Command(ip6TablesPath, "-V")
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
	iptablesPath := m.ipTablesPath
	rulesPath := m.rulesV4Path
	if isPv6 {
		if !m.enableIPv6 {
			return nil // Skip if IPv6 is disabled
		}
		iptablesPath = m.ip6TablesPath
		rulesPath = m.rulesV6Path
	}

	// Get current rules
	cmd := exec.Command(iptablesPath + "-save")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to save current rules: %w", err)
	}

	// Convert to lines
	lines := strings.Split(string(output), "\n")

	// Extract non-DNSniper lines (keep headers, tables, etc.)
	var cleanLines []string
	for _, line := range lines {
		// Keep all lines except those that reference our ipsets
		if !containsAny(line, ipsetNames) {
			cleanLines = append(cleanLines, line)
		}
	}

	// Prepare new file content
	var fileContent strings.Builder

	// Add clean lines
	for _, line := range cleanLines {
		if line == "" {
			continue
		}
		fileContent.WriteString(line + "\n")
	}

	// Ensure we have the filter table
	if !strings.Contains(fileContent.String(), "*filter") {
		fileContent.WriteString("*filter\n")
	}

	// Add our rules
	for _, chain := range chains {
		// Only handle valid chains
		if chain != "INPUT" && chain != "OUTPUT" && chain != "FORWARD" {
			continue
		}

		// Order is critical: whitelist rules must come before blocklist rules
		// For IPv4
		if !isPv6 {
			// Whitelist rules
			fileContent.WriteString(fmt.Sprintf("-A %s -m set --match-set whitelistIP-v4 src -j ACCEPT\n", chain))
			fileContent.WriteString(fmt.Sprintf("-A %s -m set --match-set whitelistRange-v4 src -j ACCEPT\n", chain))

			// Blocklist rules
			fileContent.WriteString(fmt.Sprintf("-A %s -m set --match-set blocklistIP-v4 src -j DROP\n", chain))
			fileContent.WriteString(fmt.Sprintf("-A %s -m set --match-set blocklistRange-v4 src -j DROP\n", chain))

			// For OUTPUT chain, also check destination
			if chain == "OUTPUT" {
				fileContent.WriteString(fmt.Sprintf("-A %s -m set --match-set whitelistIP-v4 dst -j ACCEPT\n", chain))
				fileContent.WriteString(fmt.Sprintf("-A %s -m set --match-set whitelistRange-v4 dst -j ACCEPT\n", chain))
				fileContent.WriteString(fmt.Sprintf("-A %s -m set --match-set blocklistIP-v4 dst -j DROP\n", chain))
				fileContent.WriteString(fmt.Sprintf("-A %s -m set --match-set blocklistRange-v4 dst -j DROP\n", chain))
			}

			// For FORWARD chain, also check destination
			if chain == "FORWARD" {
				fileContent.WriteString(fmt.Sprintf("-A %s -m set --match-set whitelistIP-v4 dst -j ACCEPT\n", chain))
				fileContent.WriteString(fmt.Sprintf("-A %s -m set --match-set whitelistRange-v4 dst -j ACCEPT\n", chain))
				fileContent.WriteString(fmt.Sprintf("-A %s -m set --match-set blocklistIP-v4 dst -j DROP\n", chain))
				fileContent.WriteString(fmt.Sprintf("-A %s -m set --match-set blocklistRange-v4 dst -j DROP\n", chain))
			}
		} else { // IPv6
			// Whitelist rules
			fileContent.WriteString(fmt.Sprintf("-A %s -m set --match-set whitelistIP-v6 src -j ACCEPT\n", chain))
			fileContent.WriteString(fmt.Sprintf("-A %s -m set --match-set whitelistRange-v6 src -j ACCEPT\n", chain))

			// Blocklist rules
			fileContent.WriteString(fmt.Sprintf("-A %s -m set --match-set blocklistIP-v6 src -j DROP\n", chain))
			fileContent.WriteString(fmt.Sprintf("-A %s -m set --match-set blocklistRange-v6 src -j DROP\n", chain))

			// For OUTPUT chain, also check destination
			if chain == "OUTPUT" {
				fileContent.WriteString(fmt.Sprintf("-A %s -m set --match-set whitelistIP-v6 dst -j ACCEPT\n", chain))
				fileContent.WriteString(fmt.Sprintf("-A %s -m set --match-set whitelistRange-v6 dst -j ACCEPT\n", chain))
				fileContent.WriteString(fmt.Sprintf("-A %s -m set --match-set blocklistIP-v6 dst -j DROP\n", chain))
				fileContent.WriteString(fmt.Sprintf("-A %s -m set --match-set blocklistRange-v6 dst -j DROP\n", chain))
			}

			// For FORWARD chain, also check destination
			if chain == "FORWARD" {
				fileContent.WriteString(fmt.Sprintf("-A %s -m set --match-set whitelistIP-v6 dst -j ACCEPT\n", chain))
				fileContent.WriteString(fmt.Sprintf("-A %s -m set --match-set whitelistRange-v6 dst -j ACCEPT\n", chain))
				fileContent.WriteString(fmt.Sprintf("-A %s -m set --match-set blocklistIP-v6 dst -j DROP\n", chain))
				fileContent.WriteString(fmt.Sprintf("-A %s -m set --match-set blocklistRange-v6 dst -j DROP\n", chain))
			}
		}
	}

	// Ensure we end the filter table if we added rules
	if !strings.Contains(fileContent.String(), "COMMIT") {
		fileContent.WriteString("COMMIT\n")
	}

	// Write to file
	if err := os.WriteFile(rulesPath, []byte(fileContent.String()), 0644); err != nil {
		return fmt.Errorf("failed to write rules file: %w", err)
	}

	return nil
}

// ApplyRules applies the iptables rules from the rules file
func (m *IPTablesManager) ApplyRules(isPv6 bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Choose appropriate paths
	iptablesPath := m.ipTablesPath
	rulesPath := m.rulesV4Path
	if isPv6 {
		if !m.enableIPv6 {
			return nil // Skip if IPv6 is disabled
		}
		iptablesPath = m.ip6TablesPath
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
