package firewall

import (
	"fmt"
	"net"

	"github.com/coreos/go-iptables/iptables"
)

// FirewallManager interface for firewall operations
type FirewallManager interface {
	BlockIP(ip string, blockType string) error
	UnblockIP(ip string) error
	ClearRules() error
}

// IPTablesManager implements FirewallManager using iptables
type IPTablesManager struct {
	ipv4 *iptables.IPTables
	ipv6 *iptables.IPTables
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

	return &IPTablesManager{
		ipv4: ipv4,
		ipv6: ipv6,
	}, nil
}

// ensureChain ensures that the DNSniper chain exists
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

		// Add jump rules from INPUT and OUTPUT to DNSniper chain
		if err := m.ipv4.Insert("filter", "INPUT", 1, "-j", ChainNameIPv4); err != nil {
			return err
		}

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

		// Add jump rules from INPUT and OUTPUT to DNSniper6 chain
		if err := m.ipv6.Insert("filter", "INPUT", 1, "-j", ChainNameIPv6); err != nil {
			return err
		}

		if err := m.ipv6.Insert("filter", "OUTPUT", 1, "-j", ChainNameIPv6); err != nil {
			return err
		}
	}

	return nil
}

// BlockIP blocks an IP address using iptables
func (m *IPTablesManager) BlockIP(ip string, blockType string) error {
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
		return ipt.AppendUnique("filter", chain, "-s", ip, "-j", "DROP")
	case "destination":
		return ipt.AppendUnique("filter", chain, "-d", ip, "-j", "DROP")
	case "both":
		if err := ipt.AppendUnique("filter", chain, "-s", ip, "-j", "DROP"); err != nil {
			return err
		}
		return ipt.AppendUnique("filter", chain, "-d", ip, "-j", "DROP")
	default:
		return fmt.Errorf("invalid block type: %s", blockType)
	}
}

// UnblockIP removes blocking rules for an IP
func (m *IPTablesManager) UnblockIP(ip string) error {
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

	return nil
}

// ClearRules clears all rules in the DNSniper chains
func (m *IPTablesManager) ClearRules() error {
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

	return nil
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
		if fmt.Sprint(err) == str {
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

	return fmt.Sprint(err) == "No chain/target/match by that name"
}
