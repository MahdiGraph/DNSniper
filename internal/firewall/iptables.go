package firewall

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"

	"github.com/MahdiGraph/DNSniper/internal/config"
	"github.com/MahdiGraph/DNSniper/internal/ipset"
	"github.com/coreos/go-iptables/iptables"
	"github.com/sirupsen/logrus"
)

var log = logrus.New()

// FirewallManager interface for firewall operations
type FirewallManager interface {
	BlockIP(ip string, blockType string) error
	UnblockIP(ip string) error
	BlockIPRange(cidr string, blockType string) error
	UnblockIPRange(cidr string) error
	ClearRules() error
	SaveRulesToPersistentFiles() error
}

// IPTablesManager implements FirewallManager using iptables and ipset
type IPTablesManager struct {
	ipv4     *iptables.IPTables
	ipv6     *iptables.IPTables
	ipsetMgr *ipset.IPSetManager
	mu       sync.Mutex // Mutex for thread-safe operations
}

// Constants for iptables chains
const (
	// Chain name for IPv4 rules
	ChainNameIPv4 = "DNSniper"
	// Chain name for IPv6 rules
	ChainNameIPv6 = "DNSniper6"
)

// NewIPTablesManager creates a new iptables manager
func NewIPTablesManager() (*IPTablesManager, error) {
	ipv4, err := iptables.New()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize IPv4 iptables: %w", err)
	}

	ipv6, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize IPv6 iptables: %w", err)
	}

	// Initialize ipset manager
	ipsetMgr, err := ipset.NewIPSetManager()
	if err != nil {
		log.Warnf("Failed to initialize ipset: %v", err)
		return nil, fmt.Errorf("failed to initialize ipset manager: %w", err)
	}

	manager := &IPTablesManager{
		ipv4:     ipv4,
		ipv6:     ipv6,
		ipsetMgr: ipsetMgr,
	}

	// Ensure iptables tools are properly configured
	if err := manager.ensureIPTablesTools(); err != nil {
		log.Warnf("Failed to ensure iptables tools: %v", err)
	}

	// Make sure the iptables chains exist
	if err := manager.ensureChain(); err != nil {
		log.Warnf("Failed to ensure iptables chains: %v", err)
	}

	// Setup ipset rules based on current block rule type
	if err := manager.ensureIPSetRules(); err != nil {
		log.Warnf("Failed to ensure ipset iptables rules: %v", err)
	}

	return manager, nil
}

// ensureIPTablesTools ensures that necessary iptables tools are available and configured
func (m *IPTablesManager) ensureIPTablesTools() error {
	// Check if we have netfilter-persistent service active
	cmd := exec.Command("systemctl", "status", "netfilter-persistent")
	if err := cmd.Run(); err != nil {
		log.Warn("netfilter-persistent service might not be running or installed")
		// Try to reconfigure and restart it if installed
		cmd = exec.Command("sh", "-c", "systemctl restart netfilter-persistent")
		_ = cmd.Run() // Ignore error as it might not be installed
	}

	// Ensure directories exist
	if err := os.MkdirAll("/etc/iptables", 0755); err != nil {
		return fmt.Errorf("failed to create iptables directory: %w", err)
	}

	return nil
}

func (m *IPTablesManager) HasRule(chain, setName, direction string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	rules, err := m.ipv4.List("filter", chain)
	if err != nil {
		return false, fmt.Errorf("failed to list rules in chain %s: %w", chain, err)
	}

	// Look for rule containing the set name and direction (src/dst)
	for _, rule := range rules {
		if strings.Contains(rule, setName) && strings.Contains(rule, direction) {
			return true, nil
		}
	}

	return false, nil
}

// Helper function to parse chains from string
func parseChainsFromString(chainsStr string) []string {
	if chainsStr == "ALL" || chainsStr == "" {
		return []string{"INPUT", "OUTPUT", "FORWARD"}
	}

	chains := []string{}
	for _, chain := range strings.Split(chainsStr, ",") {
		chain = strings.TrimSpace(strings.ToUpper(chain))
		if chain == "INPUT" || chain == "OUTPUT" || chain == "FORWARD" {
			chains = append(chains, chain)
		}
	}

	// If no valid chains, default to all
	if len(chains) == 0 {
		return []string{"INPUT", "OUTPUT", "FORWARD"}
	}

	return chains
}

// Updated ensureIPSetRules method
func (m *IPTablesManager) ensureIPSetRules() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Get current settings
	settings, err := config.GetSettings()
	if err != nil {
		log.Warnf("Failed to get settings, using defaults: %v", err)
		settings.BlockChains = "ALL"
	}

	// Parse chains to apply rules to
	chains := parseChainsFromString(settings.BlockChains)

	log.Infof("Setting up ipset rules for chains: %v", chains)

	// Remove all existing ipset rules first
	allChains := []string{"INPUT", "OUTPUT", "FORWARD"}
	for _, ipt := range []*iptables.IPTables{m.ipv4, m.ipv6} {
		for _, chain := range allChains {
			rules, err := ipt.List("filter", chain)
			if err != nil {
				continue
			}

			for _, rule := range rules {
				if strings.Contains(rule, "match-set dnsniper-") {
					args := parseRuleForDelete(rule)
					if len(args) > 0 {
						ipt.Delete("filter", chain, args...)
					}
				}
			}
		}
	}

	// CRITICAL: Whitelist rules MUST come before blocklist rules
	// This ensures that whitelisted IPs/ranges take precedence

	priority := 1
	for _, chain := range chains {
		// First add whitelist rules based on chain type
		if chain == "INPUT" {
			m.ipv4.Insert("filter", chain, priority, "-m", "set", "--match-set", "dnsniper-whitelist", "src", "-j", "ACCEPT")
			m.ipv6.Insert("filter", chain, priority, "-m", "set", "--match-set", "dnsniper-whitelist", "src", "-j", "ACCEPT")
			priority++
			m.ipv4.Insert("filter", chain, priority, "-m", "set", "--match-set", "dnsniper-range-whitelist", "src", "-j", "ACCEPT")
			m.ipv6.Insert("filter", chain, priority, "-m", "set", "--match-set", "dnsniper-range-whitelist", "src", "-j", "ACCEPT")
			priority++
		} else if chain == "OUTPUT" {
			m.ipv4.Insert("filter", chain, priority, "-m", "set", "--match-set", "dnsniper-whitelist", "dst", "-j", "ACCEPT")
			m.ipv6.Insert("filter", chain, priority, "-m", "set", "--match-set", "dnsniper-whitelist", "dst", "-j", "ACCEPT")
			priority++
			m.ipv4.Insert("filter", chain, priority, "-m", "set", "--match-set", "dnsniper-range-whitelist", "dst", "-j", "ACCEPT")
			m.ipv6.Insert("filter", chain, priority, "-m", "set", "--match-set", "dnsniper-range-whitelist", "dst", "-j", "ACCEPT")
			priority++
		} else if chain == "FORWARD" {
			// For FORWARD, check both src and dst for whitelist
			m.ipv4.Insert("filter", chain, priority, "-m", "set", "--match-set", "dnsniper-whitelist", "src", "-j", "ACCEPT")
			m.ipv6.Insert("filter", chain, priority, "-m", "set", "--match-set", "dnsniper-whitelist", "src", "-j", "ACCEPT")
			priority++
			m.ipv4.Insert("filter", chain, priority, "-m", "set", "--match-set", "dnsniper-whitelist", "dst", "-j", "ACCEPT")
			m.ipv6.Insert("filter", chain, priority, "-m", "set", "--match-set", "dnsniper-whitelist", "dst", "-j", "ACCEPT")
			priority++
			m.ipv4.Insert("filter", chain, priority, "-m", "set", "--match-set", "dnsniper-range-whitelist", "src", "-j", "ACCEPT")
			m.ipv6.Insert("filter", chain, priority, "-m", "set", "--match-set", "dnsniper-range-whitelist", "src", "-j", "ACCEPT")
			priority++
			m.ipv4.Insert("filter", chain, priority, "-m", "set", "--match-set", "dnsniper-range-whitelist", "dst", "-j", "ACCEPT")
			m.ipv6.Insert("filter", chain, priority, "-m", "set", "--match-set", "dnsniper-range-whitelist", "dst", "-j", "ACCEPT")
			priority++
		}
	}

	// Now add blocklist rules (lower priority than whitelist)
	blockPriority := 10 // Start with a higher number to ensure it's after whitelist
	for _, chain := range chains {
		if chain == "INPUT" {
			m.ipv4.Insert("filter", chain, blockPriority, "-m", "set", "--match-set", "dnsniper-blocklist", "src", "-j", "DROP")
			m.ipv4.Insert("filter", chain, blockPriority+1, "-m", "set", "--match-set", "dnsniper-range-blocklist", "src", "-j", "DROP")
			m.ipv6.Insert("filter", chain, blockPriority, "-m", "set", "--match-set", "dnsniper-blocklist", "src", "-j", "DROP")
			m.ipv6.Insert("filter", chain, blockPriority+1, "-m", "set", "--match-set", "dnsniper-range-blocklist", "src", "-j", "DROP")
		} else if chain == "OUTPUT" {
			m.ipv4.Insert("filter", chain, blockPriority, "-m", "set", "--match-set", "dnsniper-blocklist", "dst", "-j", "DROP")
			m.ipv4.Insert("filter", chain, blockPriority+1, "-m", "set", "--match-set", "dnsniper-range-blocklist", "dst", "-j", "DROP")
			m.ipv6.Insert("filter", chain, blockPriority, "-m", "set", "--match-set", "dnsniper-blocklist", "dst", "-j", "DROP")
			m.ipv6.Insert("filter", chain, blockPriority+1, "-m", "set", "--match-set", "dnsniper-range-blocklist", "dst", "-j", "DROP")
		} else if chain == "FORWARD" {
			// For FORWARD, add rules for both directions
			m.ipv4.Insert("filter", chain, blockPriority, "-m", "set", "--match-set", "dnsniper-blocklist", "src", "-j", "DROP")
			m.ipv4.Insert("filter", chain, blockPriority+1, "-m", "set", "--match-set", "dnsniper-blocklist", "dst", "-j", "DROP")
			m.ipv4.Insert("filter", chain, blockPriority+2, "-m", "set", "--match-set", "dnsniper-range-blocklist", "src", "-j", "DROP")
			m.ipv4.Insert("filter", chain, blockPriority+3, "-m", "set", "--match-set", "dnsniper-range-blocklist", "dst", "-j", "DROP")
			m.ipv6.Insert("filter", chain, blockPriority, "-m", "set", "--match-set", "dnsniper-blocklist", "src", "-j", "DROP")
			m.ipv6.Insert("filter", chain, blockPriority+1, "-m", "set", "--match-set", "dnsniper-blocklist", "dst", "-j", "DROP")
			m.ipv6.Insert("filter", chain, blockPriority+2, "-m", "set", "--match-set", "dnsniper-range-blocklist", "src", "-j", "DROP")
			m.ipv6.Insert("filter", chain, blockPriority+3, "-m", "set", "--match-set", "dnsniper-range-blocklist", "dst", "-j", "DROP")
		}
	}

	log.Info("IPSet rules setup completed with proper priority ordering")
	return nil
}

// Add a method to verify and fix rule ordering
func (m *IPTablesManager) VerifyRuleOrdering() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if whitelist rules come before blocklist rules
	chains := []string{"INPUT", "OUTPUT", "FORWARD"}

	for _, chain := range chains {
		rules, err := m.ipv4.List("filter", chain)
		if err != nil {
			continue
		}

		whitelistIndex := -1
		blocklistIndex := -1

		for i, rule := range rules {
			if strings.Contains(rule, "dnsniper-whitelist") || strings.Contains(rule, "dnsniper-range-whitelist") {
				if whitelistIndex == -1 {
					whitelistIndex = i
				}
			}
			if strings.Contains(rule, "dnsniper-blocklist") || strings.Contains(rule, "dnsniper-range-blocklist") {
				if blocklistIndex == -1 {
					blocklistIndex = i
				}
			}
		}

		if whitelistIndex > blocklistIndex && blocklistIndex != -1 {
			log.Warnf("Rule ordering issue detected in chain %s: whitelist rules come after blocklist rules", chain)
			// Re-apply rules to fix ordering
			return m.RefreshIPSetRules()
		}
	}

	return nil
}

// Helper function to parse a rule string into args for deletion
func parseRuleForDelete(rule string) []string {
	if !strings.Contains(rule, "match-set dnsniper-") {
		return nil
	}

	// Example rule: "-A INPUT -m set --match-set dnsniper-blocklist src -j DROP"
	parts := strings.Fields(rule)
	var args []string

	// Find the "-m" until "-j" sequence
	startFound := false
	for i := 0; i < len(parts); i++ {
		if parts[i] == "-m" && i+1 < len(parts) && parts[i+1] == "set" {
			startFound = true
			args = append(args, "-m", "set")
			i++ // Skip "set"
			continue
		}

		if startFound {
			if parts[i] == "-j" {
				// Add the target
				if i+1 < len(parts) {
					args = append(args, "-j", parts[i+1])
				}
				break
			}

			// Add other parameters
			if parts[i] == "--match-set" && i+2 < len(parts) {
				args = append(args, "--match-set", parts[i+1], parts[i+2])
				i += 2 // Skip the next two parts
			}
		}
	}

	return args
}

// hasJumpRule checks if a jump rule to the target chain already exists
func (m *IPTablesManager) hasJumpRule(ipt *iptables.IPTables, chain, target string) (bool, error) {
	rules, err := ipt.List("filter", chain)
	if err != nil {
		return false, fmt.Errorf("failed to list rules in chain %s: %w", chain, err)
	}
	for _, rule := range rules {
		if strings.Contains(rule, "-j "+target) {
			return true, nil
		}
	}
	return false, nil
}

// ensureChain ensures that the DNSniper chain exists and is properly linked
func (m *IPTablesManager) ensureChain() error {
	// Check if IPv4 chain exists, create if it doesn't
	exists, err := m.ipv4.ChainExists("filter", ChainNameIPv4)
	if err != nil {
		return err
	}
	if !exists {
		if err := m.ipv4.NewChain("filter", ChainNameIPv4); err != nil {
			return err
		}
	}

	// Check for and handle duplicate jump rules in INPUT, OUTPUT, and FORWARD chains for IPv4
	for _, chain := range []string{"INPUT", "OUTPUT", "FORWARD"} {
		// Get all rules in the chain
		rules, err := m.ipv4.List("filter", chain)
		if err != nil {
			return fmt.Errorf("failed to list %s chain rules: %w", chain, err)
		}

		// Count how many times the jump rule appears
		jumpRuleCount := 0
		for _, rule := range rules {
			if strings.Contains(rule, "-j "+ChainNameIPv4) {
				jumpRuleCount++
			}
		}

		// If there are duplicate rules, remove all and add one
		if jumpRuleCount > 1 {
			log.Infof("Found %d duplicate jump rules to %s in %s chain. Fixing...",
				jumpRuleCount, ChainNameIPv4, chain)
			// Remove all jump rules to this target
			for i := 0; i < jumpRuleCount; i++ {
				if err := m.ipv4.Delete("filter", chain, "-j", ChainNameIPv4); err != nil {
					if isRuleNotExistsError(err) {
						break
					}
					return fmt.Errorf("failed to delete duplicate rule: %w", err)
				}
			}
			// Add one jump rule back
			if err := m.ipv4.Insert("filter", chain, 1, "-j", ChainNameIPv4); err != nil {
				return fmt.Errorf("failed to re-add jump rule: %w", err)
			}
		} else if jumpRuleCount == 0 {
			// If no rule exists, add one
			if err := m.ipv4.Insert("filter", chain, 1, "-j", ChainNameIPv4); err != nil {
				return fmt.Errorf("failed to add jump rule: %w", err)
			}
		}
		// If exactly one rule exists, do nothing
	}

	// Same for IPv6
	exists, err = m.ipv6.ChainExists("filter", ChainNameIPv6)
	if err != nil {
		return err
	}
	if !exists {
		if err := m.ipv6.NewChain("filter", ChainNameIPv6); err != nil {
			return err
		}
	}

	// Check for and handle duplicate jump rules in INPUT, OUTPUT and FORWARD chains for IPv6
	for _, chain := range []string{"INPUT", "OUTPUT", "FORWARD"} {
		// Get all rules in the chain
		rules, err := m.ipv6.List("filter", chain)
		if err != nil {
			return fmt.Errorf("failed to list %s chain rules: %w", chain, err)
		}

		// Count how many times the jump rule appears
		jumpRuleCount := 0
		for _, rule := range rules {
			if strings.Contains(rule, "-j "+ChainNameIPv6) {
				jumpRuleCount++
			}
		}

		// If there are duplicate rules, remove all and add one
		if jumpRuleCount > 1 {
			log.Infof("Found %d duplicate jump rules to %s in %s chain. Fixing...",
				jumpRuleCount, ChainNameIPv6, chain)
			// Remove all jump rules to this target
			for i := 0; i < jumpRuleCount; i++ {
				if err := m.ipv6.Delete("filter", chain, "-j", ChainNameIPv6); err != nil {
					if isRuleNotExistsError(err) {
						break
					}
					return fmt.Errorf("failed to delete duplicate rule: %w", err)
				}
			}
			// Add one jump rule back
			if err := m.ipv6.Insert("filter", chain, 1, "-j", ChainNameIPv6); err != nil {
				return fmt.Errorf("failed to re-add jump rule: %w", err)
			}
		} else if jumpRuleCount == 0 {
			// If no rule exists, add one
			if err := m.ipv6.Insert("filter", chain, 1, "-j", ChainNameIPv6); err != nil {
				return fmt.Errorf("failed to add jump rule: %w", err)
			}
		}
		// If exactly one rule exists, do nothing
	}

	return nil
}

// BlockIP now uses new settings
func (m *IPTablesManager) BlockIP(ip string, blockType string) error {
	// blockType parameter is now ignored, we use the new settings
	m.mu.Lock()
	defer m.mu.Unlock()

	// First check if the IP is whitelisted
	if m.ipsetMgr != nil {
		if m.ipsetMgr.IsWhitelisted(ip) {
			log.Infof("IP %s is whitelisted, not adding to blocklist", ip)
			return nil
		}

		// Add to ipset only
		if err := m.ipsetMgr.AddToBlocklist(ip); err != nil {
			return err
		}

		log.Debugf("IP %s added to blocklist", ip)
		return nil
	}

	return fmt.Errorf("ipset manager not available, cannot block IP %s", ip)
}

// UnblockIP removes blocking rules for an IP
func (m *IPTablesManager) UnblockIP(ip string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Only use ipset, return error if not available
	if m.ipsetMgr != nil {
		return m.ipsetMgr.RemoveFromBlocklist(ip)
	}

	// If ipset is not available, return error
	return fmt.Errorf("ipset manager not available, cannot unblock IP %s", ip)
}

// WhitelistIP adds an IP to the whitelist
func (m *IPTablesManager) WhitelistIP(ip string) error {
	// If ipset is available, use it
	if m.ipsetMgr != nil {
		return m.ipsetMgr.AddToWhitelist(ip)
	}

	// If ipset is not available, return error
	return fmt.Errorf("ipset manager not available, cannot whitelist IP %s", ip)
}

// UnwhitelistIP removes an IP from the whitelist
func (m *IPTablesManager) UnwhitelistIP(ip string) error {
	// If ipset is available, use it
	if m.ipsetMgr != nil {
		return m.ipsetMgr.RemoveFromWhitelist(ip)
	}

	// If ipset is not available, return error
	return fmt.Errorf("ipset manager not available, cannot unwhitelist IP %s", ip)
}

// BlockIPRange blocks an IP range using ipset only
func (m *IPTablesManager) BlockIPRange(cidr string, blockType string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Only use ipset, return error if not available
	if m.ipsetMgr != nil {
		// Add to ipset only
		if err := m.ipsetMgr.AddRangeToBlocklist(cidr); err != nil {
			return err
		}
		// Rules are already set up by ensureIPSetRules based on blockType
		log.Debugf("IP Range %s added to blocklist", cidr)
		return nil
	}

	// If ipset is not available, return error
	return fmt.Errorf("ipset manager not available, cannot block IP range %s", cidr)
}

// UnblockIPRange removes blocking rules for an IP range
func (m *IPTablesManager) UnblockIPRange(cidr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Only use ipset, return error if not available
	if m.ipsetMgr != nil {
		return m.ipsetMgr.RemoveRangeFromBlocklist(cidr)
	}

	// If ipset is not available, return error
	return fmt.Errorf("ipset manager not available, cannot unblock IP range %s", cidr)
}

// WhitelistIPRange adds an IP range to the whitelist
func (m *IPTablesManager) WhitelistIPRange(cidr string) error {
	// If ipset is available, use it
	if m.ipsetMgr != nil {
		return m.ipsetMgr.AddRangeToWhitelist(cidr)
	}

	// If ipset is not available, return error
	return fmt.Errorf("ipset manager not available, cannot whitelist IP range %s", cidr)
}

// UnwhitelistIPRange removes an IP range from the whitelist
func (m *IPTablesManager) UnwhitelistIPRange(cidr string) error {
	// If ipset is available, use it
	if m.ipsetMgr != nil {
		return m.ipsetMgr.RemoveRangeFromWhitelist(cidr)
	}

	// If ipset is not available, return error
	return fmt.Errorf("ipset manager not available, cannot unwhitelist IP range %s", cidr)
}

// RemoveAllIPSetRules removes all iptables rules that reference DNSniper ipsets
func (m *IPTablesManager) RemoveAllIPSetRules() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// List of chains to check
	chains := []string{"INPUT", "OUTPUT", "FORWARD"}

	// Remove from IPv4
	for _, chain := range chains {
		rules, err := m.ipv4.List("filter", chain)
		if err != nil {
			log.Warnf("Failed to list IPv4 %s rules: %v", chain, err)
			continue
		}

		// Remove in reverse order to avoid index issues
		for i := len(rules) - 1; i >= 0; i-- {
			rule := rules[i]
			if strings.Contains(rule, "dnsniper-") && strings.Contains(rule, "match-set") {
				// Parse and delete the rule
				args := parseRuleForDeletion(rule, chain)
				if len(args) > 0 {
					if err := m.ipv4.Delete("filter", chain, args...); err != nil {
						if !isRuleNotExistsError(err) {
							log.Warnf("Failed to delete IPv4 rule from %s: %v", chain, err)
						}
					}
				}
			}
		}
	}

	// Remove from IPv6
	for _, chain := range chains {
		rules, err := m.ipv6.List("filter", chain)
		if err != nil {
			log.Warnf("Failed to list IPv6 %s rules: %v", chain, err)
			continue
		}

		// Remove in reverse order
		for i := len(rules) - 1; i >= 0; i-- {
			rule := rules[i]
			if strings.Contains(rule, "dnsniper-") && strings.Contains(rule, "match-set") {
				// Parse and delete the rule
				args := parseRuleForDeletion(rule, chain)
				if len(args) > 0 {
					if err := m.ipv6.Delete("filter", chain, args...); err != nil {
						if !isRuleNotExistsError(err) {
							log.Warnf("Failed to delete IPv6 rule from %s: %v", chain, err)
						}
					}
				}
			}
		}
	}

	log.Info("All ipset-related iptables rules removed")
	return nil
}

// ClearRules clears all rules in ipsets and DNSniper chains
func (m *IPTablesManager) ClearRules() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Only flush ipsets, don't remove iptables rules here
	if m.ipsetMgr != nil {
		if err := m.ipsetMgr.FlushSets(); err != nil {
			log.Warnf("Failed to flush ipsets: %v", err)
			return err
		}
		log.Info("All ipset entries cleared")
	} else {
		return fmt.Errorf("ipset manager not available, cannot clear rules")
	}

	// Clear DNSniper chains (legacy)
	if err := m.ipv4.ClearChain("filter", ChainNameIPv4); err != nil {
		if !isChainNotExistsError(err) {
			log.Warnf("Failed to clear IPv4 chain: %v", err)
		}
	}

	if err := m.ipv6.ClearChain("filter", ChainNameIPv6); err != nil {
		if !isChainNotExistsError(err) {
			log.Warnf("Failed to clear IPv6 chain: %v", err)
		}
	}

	return nil
}

// saveRulesToPersistentFilesInternal is the internal implementation
// without locking (used by methods that already have a lock)
func (m *IPTablesManager) saveRulesToPersistentFilesInternal() error {
	// Create directories if they don't exist
	if err := os.MkdirAll("/etc/iptables", 0755); err != nil {
		return fmt.Errorf("failed to create iptables directory: %w", err)
	}

	// If ipset is available, save ipset configuration
	if m.ipsetMgr != nil {
		if err := m.ipsetMgr.SaveSets(); err != nil {
			log.Warnf("Failed to save ipsets: %v", err)
		}
	}

	// Use direct command instead of package functions to ensure we get all rules
	// Save IPv4 rules - ensure we're getting all rules
	cmdIPv4 := exec.Command("iptables-save")
	ipv4Rules, err := cmdIPv4.Output()
	if err != nil {
		return fmt.Errorf("failed to execute iptables-save: %w", err)
	}

	// Write directly to file
	if err := os.WriteFile("/etc/iptables/rules.v4", ipv4Rules, 0644); err != nil {
		return fmt.Errorf("failed to write IPv4 rules file: %w", err)
	}

	// Save IPv6 rules - ensure we're getting all rules
	cmdIPv6 := exec.Command("ip6tables-save")
	ipv6Rules, err := cmdIPv6.Output()
	if err != nil {
		return fmt.Errorf("failed to execute ip6tables-save: %w", err)
	}

	// Write directly to file
	if err := os.WriteFile("/etc/iptables/rules.v6", ipv6Rules, 0644); err != nil {
		return fmt.Errorf("failed to write IPv6 rules file: %w", err)
	}

	// Apply the rules using netfilter-persistent if available
	cmd := exec.Command("sh", "-c", "systemctl is-active netfilter-persistent >/dev/null && systemctl restart netfilter-persistent || true")
	if err := cmd.Run(); err != nil {
		log.Warnf("Failed to restart netfilter-persistent, rules may not persist after reboot: %v", err)
	}

	log.Info("Saved firewall rules to persistent files")
	return nil
}

// RefreshIPSetRules completely rebuilds ipset iptables rules based on current settings
func (m *IPTablesManager) RefreshIPSetRules() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Get current block rule type
	settings, err := config.GetSettings()
	if err != nil {
		log.Warnf("Failed to get settings, using default block rule type 'both': %v", err)
		// Default to 'both' if we can't get settings
		settings.BlockRuleType = "both"
	}

	log.Infof("Refreshing IPSet rules with block rule type: %s", settings.BlockRuleType)

	// Remove all existing ipset rules from iptables (IPv4)
	log.Info("Removing all existing IPv4 IPSet rules")
	rulesInput, _ := m.ipv4.List("filter", "INPUT")
	rulesOutput, _ := m.ipv4.List("filter", "OUTPUT")

	// Remove all rules that contain the ipset match
	for _, rule := range rulesInput {
		if strings.Contains(rule, "match-set dnsniper-") {
			args := parseRuleForDeletion(rule, "INPUT")
			if len(args) > 0 {
				m.ipv4.Delete("filter", "INPUT", args...)
			}
		}
	}
	for _, rule := range rulesOutput {
		if strings.Contains(rule, "match-set dnsniper-") {
			args := parseRuleForDeletion(rule, "OUTPUT")
			if len(args) > 0 {
				m.ipv4.Delete("filter", "OUTPUT", args...)
			}
		}
	}

	// Same for IPv6
	log.Info("Removing all existing IPv6 IPSet rules")
	rulesInputV6, _ := m.ipv6.List("filter", "INPUT")
	rulesOutputV6, _ := m.ipv6.List("filter", "OUTPUT")

	// Remove all rules that contain the ipset match for IPv6
	for _, rule := range rulesInputV6 {
		if strings.Contains(rule, "match-set dnsniper-") {
			args := parseRuleForDeletion(rule, "INPUT")
			if len(args) > 0 {
				m.ipv6.Delete("filter", "INPUT", args...)
			}
		}
	}
	for _, rule := range rulesOutputV6 {
		if strings.Contains(rule, "match-set dnsniper-") {
			args := parseRuleForDeletion(rule, "OUTPUT")
			if len(args) > 0 {
				m.ipv6.Delete("filter", "OUTPUT", args...)
			}
		}
	}

	// Now add the rules back in the correct order
	// Whitelist rules for IPv4 (always apply)
	log.Info("Adding whitelist rules for IPv4")
	m.ipv4.Insert("filter", "INPUT", 1, "-m", "set", "--match-set", "dnsniper-whitelist", "src", "-j", "ACCEPT")
	m.ipv4.Insert("filter", "OUTPUT", 1, "-m", "set", "--match-set", "dnsniper-whitelist", "dst", "-j", "ACCEPT")
	m.ipv4.Insert("filter", "INPUT", 2, "-m", "set", "--match-set", "dnsniper-range-whitelist", "src", "-j", "ACCEPT")
	m.ipv4.Insert("filter", "OUTPUT", 2, "-m", "set", "--match-set", "dnsniper-range-whitelist", "dst", "-j", "ACCEPT")

	// Blocklist rules based on block rule type for IPv4
	log.Infof("Adding blocklist rules for IPv4 with type: %s", settings.BlockRuleType)
	switch settings.BlockRuleType {
	case "source":
		m.ipv4.Insert("filter", "INPUT", 3, "-m", "set", "--match-set", "dnsniper-blocklist", "src", "-j", "DROP")
		m.ipv4.Insert("filter", "INPUT", 4, "-m", "set", "--match-set", "dnsniper-range-blocklist", "src", "-j", "DROP")
		log.Info("IPv4 source-only blocking rules added")
	case "destination":
		m.ipv4.Insert("filter", "OUTPUT", 3, "-m", "set", "--match-set", "dnsniper-blocklist", "dst", "-j", "DROP")
		m.ipv4.Insert("filter", "OUTPUT", 4, "-m", "set", "--match-set", "dnsniper-range-blocklist", "dst", "-j", "DROP")
		log.Info("IPv4 destination-only blocking rules added")
	default:
		// Default to "both"
		m.ipv4.Insert("filter", "INPUT", 3, "-m", "set", "--match-set", "dnsniper-blocklist", "src", "-j", "DROP")
		m.ipv4.Insert("filter", "OUTPUT", 3, "-m", "set", "--match-set", "dnsniper-blocklist", "dst", "-j", "DROP")
		m.ipv4.Insert("filter", "INPUT", 4, "-m", "set", "--match-set", "dnsniper-range-blocklist", "src", "-j", "DROP")
		m.ipv4.Insert("filter", "OUTPUT", 4, "-m", "set", "--match-set", "dnsniper-range-blocklist", "dst", "-j", "DROP")
		log.Info("IPv4 both source and destination blocking rules added")
	}

	// Now do the same for IPv6 (with error handling)
	// Whitelist rules for IPv6
	log.Info("Adding whitelist rules for IPv6")
	if err := m.ipv6.Insert("filter", "INPUT", 1, "-m", "set", "--match-set", "dnsniper-whitelist", "src", "-j", "ACCEPT"); err != nil {
		log.Warnf("Failed to add IPv6 whitelist rule to INPUT: %v", err)
	}
	if err := m.ipv6.Insert("filter", "OUTPUT", 1, "-m", "set", "--match-set", "dnsniper-whitelist", "dst", "-j", "ACCEPT"); err != nil {
		log.Warnf("Failed to add IPv6 whitelist rule to OUTPUT: %v", err)
	}
	if err := m.ipv6.Insert("filter", "INPUT", 2, "-m", "set", "--match-set", "dnsniper-range-whitelist", "src", "-j", "ACCEPT"); err != nil {
		log.Warnf("Failed to add IPv6 whitelist range rule to INPUT: %v", err)
	}
	if err := m.ipv6.Insert("filter", "OUTPUT", 2, "-m", "set", "--match-set", "dnsniper-range-whitelist", "dst", "-j", "ACCEPT"); err != nil {
		log.Warnf("Failed to add IPv6 whitelist range rule to OUTPUT: %v", err)
	}

	// Blocklist rules based on block rule type for IPv6
	log.Infof("Adding blocklist rules for IPv6 with type: %s", settings.BlockRuleType)
	switch settings.BlockRuleType {
	case "source":
		if err := m.ipv6.Insert("filter", "INPUT", 3, "-m", "set", "--match-set", "dnsniper-blocklist", "src", "-j", "DROP"); err != nil {
			log.Warnf("Failed to add IPv6 blocklist rule to INPUT: %v", err)
		}
		if err := m.ipv6.Insert("filter", "INPUT", 4, "-m", "set", "--match-set", "dnsniper-range-blocklist", "src", "-j", "DROP"); err != nil {
			log.Warnf("Failed to add IPv6 blocklist range rule to INPUT: %v", err)
		}
		log.Info("IPv6 source-only blocking rules added")
	case "destination":
		if err := m.ipv6.Insert("filter", "OUTPUT", 3, "-m", "set", "--match-set", "dnsniper-blocklist", "dst", "-j", "DROP"); err != nil {
			log.Warnf("Failed to add IPv6 blocklist rule to OUTPUT: %v", err)
		}
		if err := m.ipv6.Insert("filter", "OUTPUT", 4, "-m", "set", "--match-set", "dnsniper-range-blocklist", "dst", "-j", "DROP"); err != nil {
			log.Warnf("Failed to add IPv6 blocklist range rule to OUTPUT: %v", err)
		}
		log.Info("IPv6 destination-only blocking rules added")
	default:
		// Default to "both"
		if err := m.ipv6.Insert("filter", "INPUT", 3, "-m", "set", "--match-set", "dnsniper-blocklist", "src", "-j", "DROP"); err != nil {
			log.Warnf("Failed to add IPv6 blocklist rule to INPUT: %v", err)
		}
		if err := m.ipv6.Insert("filter", "OUTPUT", 3, "-m", "set", "--match-set", "dnsniper-blocklist", "dst", "-j", "DROP"); err != nil {
			log.Warnf("Failed to add IPv6 blocklist rule to OUTPUT: %v", err)
		}
		if err := m.ipv6.Insert("filter", "INPUT", 4, "-m", "set", "--match-set", "dnsniper-range-blocklist", "src", "-j", "DROP"); err != nil {
			log.Warnf("Failed to add IPv6 blocklist range rule to INPUT: %v", err)
		}
		if err := m.ipv6.Insert("filter", "OUTPUT", 4, "-m", "set", "--match-set", "dnsniper-range-blocklist", "dst", "-j", "DROP"); err != nil {
			log.Warnf("Failed to add IPv6 blocklist range rule to OUTPUT: %v", err)
		}
		log.Info("IPv6 both source and destination blocking rules added")
	}

	// Save the rules to persistently store them
	return m.saveRulesToPersistentFilesInternal()
}

// Helper function to parse an iptables rule string into arguments for deletion
func parseRuleForDeletion(rule, chain string) []string {
	if !strings.Contains(rule, "match-set") {
		return nil
	}
	var args []string
	if match := regexp.MustCompile(`-m set --match-set ([\w-]+) (src|dst) -j (ACCEPT|DROP)`).FindStringSubmatch(rule); len(match) == 4 {
		args = []string{"-m", "set", "--match-set", match[1], match[2], "-j", match[3]}
	}
	return args
}

// SaveRulesToPersistentFiles saves the current iptables rules to persistent files
func (m *IPTablesManager) SaveRulesToPersistentFiles() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.saveRulesToPersistentFilesInternal()
}

// Helper function to check for "rule not exists" error
func isRuleNotExistsError(err error) bool {
	if err == nil {
		return false
	}
	// iptables returns different error messages depending on the version
	errorStrings := []string{
		"No chain/target/match by that name",
		"Bad rule (does a matching rule exist in that chain?)",
	}
	for _, str := range errorStrings {
		if strings.Contains(fmt.Sprint(err), str) {
			return true
		}
	}
	return false
}

// Helper function to check for "chain not exists" error
func isChainNotExistsError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(fmt.Sprint(err), "No chain/target/match by that name")
}
