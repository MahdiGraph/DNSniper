package ipset

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
)

var log = logrus.New()

// IPSetManager handles interaction with ipset
type IPSetManager struct {
	whitelistName      string
	blocklistName      string
	whitelistRangeName string
	blocklistRangeName string
	mu                 sync.Mutex
}

// NewIPSetManager creates a new ipset manager
func NewIPSetManager() (*IPSetManager, error) {
	m := &IPSetManager{
		whitelistName:      "dnsniper-whitelist",
		blocklistName:      "dnsniper-blocklist",
		whitelistRangeName: "dnsniper-range-whitelist",
		blocklistRangeName: "dnsniper-range-blocklist",
	}

	// Ensure ipset is installed and available
	if err := m.checkIPSetInstalled(); err != nil {
		return nil, err
	}

	// Ensure all required sets exist
	if err := m.EnsureSets(); err != nil {
		return nil, err
	}

	return m, nil
}

// checkIPSetInstalled verifies if ipset is installed
func (m *IPSetManager) checkIPSetInstalled() error {
	cmd := exec.Command("ipset", "--version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ipset is not installed or not in PATH: %w", err)
	}
	return nil
}

// EnsureSets makes sure all required sets exist
func (m *IPSetManager) EnsureSets() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if sets already exist
	sets, err := m.ListSets()
	if err != nil {
		return err
	}

	// Helper function to create set if it doesn't exist
	createIfNotExists := func(name, ipsetType string) error {
		if !containsString(sets, name) {
			// Create the set with appropriate type
			cmd := exec.Command("ipset", "create", name, ipsetType, "hashsize", "4096", "-exist")
			output, err := cmd.CombinedOutput()
			if err != nil {
				return fmt.Errorf("failed to create %s (%s): %w - %s", name, ipsetType, err, output)
			}
			log.Infof("Created ipset %s of type %s", name, ipsetType)
		}
		return nil
	}

	// Create all required sets
	if err := createIfNotExists(m.whitelistName, "hash:ip"); err != nil {
		return err
	}
	if err := createIfNotExists(m.blocklistName, "hash:ip"); err != nil {
		return err
	}
	if err := createIfNotExists(m.whitelistRangeName, "hash:net"); err != nil {
		return err
	}
	if err := createIfNotExists(m.blocklistRangeName, "hash:net"); err != nil {
		return err
	}

	return nil
}

// ListSets returns a list of all existing ipsets
func (m *IPSetManager) ListSets() ([]string, error) {
	cmd := exec.Command("ipset", "list", "-n")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list ipsets: %w", err)
	}

	// Split output by newline and remove empty lines
	var sets []string
	for _, line := range strings.Split(string(output), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			sets = append(sets, line)
		}
	}

	return sets, nil
}

// AddToWhitelist adds an IP to the whitelist
func (m *IPSetManager) AddToWhitelist(ip string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Add to whitelist set
	cmd := exec.Command("ipset", "add", m.whitelistName, ip, "-exist")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add IP %s to whitelist: %w - %s", ip, err, output)
	}

	// Remove from blocklist if it exists there
	m.RemoveFromBlocklist(ip)

	return nil
}

// AddToBlocklist adds an IP to the blocklist
func (m *IPSetManager) AddToBlocklist(ip string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if IP is in whitelist first
	cmd := exec.Command("ipset", "test", m.whitelistName, ip)
	if cmd.Run() == nil {
		// IP is whitelisted, don't add to blocklist
		log.Infof("IP %s is whitelisted, not adding to blocklist", ip)
		return nil
	}

	// Add to blocklist set
	cmd = exec.Command("ipset", "add", m.blocklistName, ip, "-exist")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add IP %s to blocklist: %w - %s", ip, err, output)
	}

	return nil
}

// AddRangeToWhitelist adds a network range to the whitelist
func (m *IPSetManager) AddRangeToWhitelist(cidr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Add to whitelist range set
	cmd := exec.Command("ipset", "add", m.whitelistRangeName, cidr, "-exist")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add CIDR %s to whitelist: %w - %s", cidr, err, output)
	}

	// Remove from blocklist range if it exists there
	m.RemoveRangeFromBlocklist(cidr)

	return nil
}

// AddRangeToBlocklist adds a network range to the blocklist
func (m *IPSetManager) AddRangeToBlocklist(cidr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if range is in whitelist first
	cmd := exec.Command("ipset", "test", m.whitelistRangeName, cidr)
	if cmd.Run() == nil {
		// CIDR is whitelisted, don't add to blocklist
		log.Infof("CIDR %s is whitelisted, not adding to blocklist", cidr)
		return nil
	}

	// Add to blocklist range set
	cmd = exec.Command("ipset", "add", m.blocklistRangeName, cidr, "-exist")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add CIDR %s to blocklist: %w - %s", cidr, err, output)
	}

	return nil
}

// RemoveFromWhitelist removes an IP from the whitelist
func (m *IPSetManager) RemoveFromWhitelist(ip string) error {
	cmd := exec.Command("ipset", "del", m.whitelistName, ip, "-exist")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove IP %s from whitelist: %w - %s", ip, err, output)
	}
	return nil
}

// RemoveFromBlocklist removes an IP from the blocklist
func (m *IPSetManager) RemoveFromBlocklist(ip string) error {
	cmd := exec.Command("ipset", "del", m.blocklistName, ip, "-exist")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove IP %s from blocklist: %w - %s", ip, err, output)
	}
	return nil
}

// RemoveRangeFromWhitelist removes a network range from the whitelist
func (m *IPSetManager) RemoveRangeFromWhitelist(cidr string) error {
	cmd := exec.Command("ipset", "del", m.whitelistRangeName, cidr, "-exist")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove CIDR %s from whitelist: %w - %s", cidr, err, output)
	}
	return nil
}

// RemoveRangeFromBlocklist removes a network range from the blocklist
func (m *IPSetManager) RemoveRangeFromBlocklist(cidr string) error {
	cmd := exec.Command("ipset", "del", m.blocklistRangeName, cidr, "-exist")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove CIDR %s from blocklist: %w - %s", cidr, err, output)
	}
	return nil
}

// IsWhitelisted checks if an IP is in the whitelist
func (m *IPSetManager) IsWhitelisted(ip string) bool {
	cmd := exec.Command("ipset", "test", m.whitelistName, ip)
	err := cmd.Run()
	return err == nil
}

// IsBlocked checks if an IP is in the blocklist
func (m *IPSetManager) IsBlocked(ip string) bool {
	// First check if IP is whitelisted
	if m.IsWhitelisted(ip) {
		return false
	}

	// Then check if it's in the blocklist
	cmd := exec.Command("ipset", "test", m.blocklistName, ip)
	err := cmd.Run()
	return err == nil
}

// IsRangeWhitelisted checks if a network range is in the whitelist
func (m *IPSetManager) IsRangeWhitelisted(cidr string) bool {
	cmd := exec.Command("ipset", "test", m.whitelistRangeName, cidr)
	err := cmd.Run()
	return err == nil
}

// IsRangeBlocked checks if a network range is in the blocklist
func (m *IPSetManager) IsRangeBlocked(cidr string) bool {
	// First check if range is whitelisted
	if m.IsRangeWhitelisted(cidr) {
		return false
	}

	// Then check if it's in the blocklist
	cmd := exec.Command("ipset", "test", m.blocklistRangeName, cidr)
	err := cmd.Run()
	return err == nil
}

// FlushSets clears all entries in the ipsets
func (m *IPSetManager) FlushSets() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, set := range []string{m.whitelistName, m.blocklistName, m.whitelistRangeName, m.blocklistRangeName} {
		cmd := exec.Command("ipset", "flush", set)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to flush ipset %s: %w - %s", set, err, output)
		}
	}
	return nil
}

// SaveSets saves the ipset configuration to a file
func (m *IPSetManager) SaveSets() error {
	cmd := exec.Command("sh", "-c", "ipset save > /etc/ipset.conf")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to save ipsets: %w - %s", err, output)
	}
	return nil
}

// RestoreSets restores ipset configuration from a file
func (m *IPSetManager) RestoreSets() error {
	cmd := exec.Command("sh", "-c", "ipset restore < /etc/ipset.conf")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to restore ipsets: %w - %s", err, output)
	}
	return nil
}

// Helper function to check if a slice contains a string
func containsString(slice []string, str string) bool {
	for _, item := range slice {
		if item == str {
			return true
		}
	}
	return false
}
