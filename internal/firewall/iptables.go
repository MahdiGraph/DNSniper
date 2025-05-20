package firewall

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"

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

// IPTablesManager implements FirewallManager using iptables
type IPTablesManager struct {
	ipv4 *iptables.IPTables
	ipv6 *iptables.IPTables
	mu   sync.Mutex // Mutex for thread-safe operations
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

	manager := &IPTablesManager{
		ipv4: ipv4,
		ipv6: ipv6,
	}

	// Ensure iptables tools are properly configured
	if err := manager.ensureIPTablesTools(); err != nil {
		log.Warnf("Failed to ensure iptables tools: %v", err)
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

	// Check if jump rules already exist in INPUT and OUTPUT chains
	hasInputJump, err := m.hasJumpRule(m.ipv4, "INPUT", ChainNameIPv4)
	if err != nil {
		return err
	}

	hasOutputJump, err := m.hasJumpRule(m.ipv4, "OUTPUT", ChainNameIPv4)
	if err != nil {
		return err
	}

	// Add jump rules only if they don't exist
	if !hasInputJump {
		if err := m.ipv4.Insert("filter", "INPUT", 1, "-j", ChainNameIPv4); err != nil {
			return err
		}
	}

	if !hasOutputJump {
		if err := m.ipv4.Insert("filter", "OUTPUT", 1, "-j", ChainNameIPv4); err != nil {
			return err
		}
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

	// Check if jump rules already exist for IPv6
	hasInputJump, err = m.hasJumpRule(m.ipv6, "INPUT", ChainNameIPv6)
	if err != nil {
		return err
	}

	hasOutputJump, err = m.hasJumpRule(m.ipv6, "OUTPUT", ChainNameIPv6)
	if err != nil {
		return err
	}

	// Add jump rules only if they don't exist
	if !hasInputJump {
		if err := m.ipv6.Insert("filter", "INPUT", 1, "-j", ChainNameIPv6); err != nil {
			return err
		}
	}

	if !hasOutputJump {
		if err := m.ipv6.Insert("filter", "OUTPUT", 1, "-j", ChainNameIPv6); err != nil {
			return err
		}
	}

	return nil
}

// BlockIP blocks an IP address using iptables
func (m *IPTablesManager) BlockIP(ip string, blockType string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Ensure chain exists
	if err := m.ensureChain(); err != nil {
		return err
	}

	// Determine if IPv4 or IPv6
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	var ipt *iptables.IPTables
	var chain string

	if parsedIP.To4() != nil {
		ipt = m.ipv4
		chain = ChainNameIPv4
	} else {
		ipt = m.ipv6
		chain = ChainNameIPv6
	}

	// Apply rules based on block type
	switch blockType {
	case "source":
		if err := ipt.AppendUnique("filter", chain, "-s", ip, "-j", "DROP"); err != nil {
			return err
		}
	case "destination":
		if err := ipt.AppendUnique("filter", chain, "-d", ip, "-j", "DROP"); err != nil {
			return err
		}
	case "both":
		if err := ipt.AppendUnique("filter", chain, "-s", ip, "-j", "DROP"); err != nil {
			return err
		}
		if err := ipt.AppendUnique("filter", chain, "-d", ip, "-j", "DROP"); err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid block type: %s", blockType)
	}

	// Save persistent rules after changes
	return m.saveRulesToPersistentFilesInternal()
}

// UnblockIP removes blocking rules for an IP
func (m *IPTablesManager) UnblockIP(ip string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Determine if IPv4 or IPv6
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	var ipt *iptables.IPTables
	var chain string

	if parsedIP.To4() != nil {
		ipt = m.ipv4
		chain = ChainNameIPv4
	} else {
		ipt = m.ipv6
		chain = ChainNameIPv6
	}

	// Remove source and destination rules
	if err := ipt.Delete("filter", chain, "-s", ip, "-j", "DROP"); err != nil {
		// Ignore error if rule doesn't exist
		if !isRuleNotExistsError(err) {
			return err
		}
	}

	if err := ipt.Delete("filter", chain, "-d", ip, "-j", "DROP"); err != nil {
		// Ignore error if rule doesn't exist
		if !isRuleNotExistsError(err) {
			return err
		}
	}

	// Save persistent rules after changes
	return m.saveRulesToPersistentFilesInternal()
}

// BlockIPRange blocks an IP range using iptables
func (m *IPTablesManager) BlockIPRange(cidr string, blockType string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Ensure chain exists
	if err := m.ensureChain(); err != nil {
		return err
	}

	// Determine if IPv4 or IPv6
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR notation: %w", err)
	}

	var ipt *iptables.IPTables
	var chain string

	if ipNet.IP.To4() != nil {
		ipt = m.ipv4
		chain = ChainNameIPv4
	} else {
		ipt = m.ipv6
		chain = ChainNameIPv6
	}

	// Apply rules based on block type
	switch blockType {
	case "source":
		if err := ipt.AppendUnique("filter", chain, "-s", cidr, "-j", "DROP"); err != nil {
			return err
		}
	case "destination":
		if err := ipt.AppendUnique("filter", chain, "-d", cidr, "-j", "DROP"); err != nil {
			return err
		}
	case "both":
		if err := ipt.AppendUnique("filter", chain, "-s", cidr, "-j", "DROP"); err != nil {
			return err
		}
		if err := ipt.AppendUnique("filter", chain, "-d", cidr, "-j", "DROP"); err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid block type: %s", blockType)
	}

	// Save persistent rules after changes
	return m.saveRulesToPersistentFilesInternal()
}

// UnblockIPRange removes blocking rules for an IP range
func (m *IPTablesManager) UnblockIPRange(cidr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Determine if IPv4 or IPv6
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR notation: %w", err)
	}

	var ipt *iptables.IPTables
	var chain string

	if ipNet.IP.To4() != nil {
		ipt = m.ipv4
		chain = ChainNameIPv4
	} else {
		ipt = m.ipv6
		chain = ChainNameIPv6
	}

	// Remove source and destination rules
	if err := ipt.Delete("filter", chain, "-s", cidr, "-j", "DROP"); err != nil {
		// Ignore error if rule doesn't exist
		if !isRuleNotExistsError(err) {
			return err
		}
	}

	if err := ipt.Delete("filter", chain, "-d", cidr, "-j", "DROP"); err != nil {
		// Ignore error if rule doesn't exist
		if !isRuleNotExistsError(err) {
			return err
		}
	}

	// Save persistent rules after changes
	return m.saveRulesToPersistentFilesInternal()
}

// ClearRules clears all rules in the DNSniper chains
func (m *IPTablesManager) ClearRules() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Clear IPv4 rules
	if err := m.ipv4.ClearChain("filter", ChainNameIPv4); err != nil {
		if !isChainNotExistsError(err) {
			return err
		}
	}

	// Clear IPv6 rules
	if err := m.ipv6.ClearChain("filter", ChainNameIPv6); err != nil {
		if !isChainNotExistsError(err) {
			return err
		}
	}

	// Save changes to persistent files
	return m.saveRulesToPersistentFilesInternal()
}

// saveRulesToPersistentFilesInternal is the internal implementation
// without locking (used by methods that already have a lock)
func (m *IPTablesManager) saveRulesToPersistentFilesInternal() error {
	// Create directories if they don't exist
	if err := os.MkdirAll("/etc/iptables", 0755); err != nil {
		return fmt.Errorf("failed to create iptables directory: %w", err)
	}

	// Save IPv4 rules - use Output() to capture the output instead of redirect
	cmdIPv4 := exec.Command("iptables-save")
	ipv4Rules, err := cmdIPv4.Output()
	if err != nil {
		return fmt.Errorf("failed to execute iptables-save: %w", err)
	}

	// Write directly to file
	if err := os.WriteFile("/etc/iptables/rules.v4", ipv4Rules, 0644); err != nil {
		return fmt.Errorf("failed to write IPv4 rules file: %w", err)
	}

	// Save IPv6 rules - use Output() to capture the output instead of redirect
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
