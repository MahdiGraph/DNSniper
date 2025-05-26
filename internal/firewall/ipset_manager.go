package firewall

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
)

// IPSetManager handles ipset operations
type IPSetManager struct {
	whitelistIPv4      string
	whitelistRangeIPv4 string
	blacklistIPv4      string
	blacklistRangeIPv4 string

	whitelistIPv6      string
	whitelistRangeIPv6 string
	blacklistIPv6      string
	blacklistRangeIPv6 string

	ipsetPath  string
	enableIPv6 bool

	mu sync.Mutex
}

// NewIPSetManager creates a new ipset manager
func NewIPSetManager(ipsetPath string, enableIPv6 bool) (*IPSetManager, error) {
	manager := &IPSetManager{
		whitelistIPv4:      "whitelistIP-v4",
		whitelistRangeIPv4: "whitelistRange-v4",
		blacklistIPv4:      "blacklistIP-v4",
		blacklistRangeIPv4: "blacklistRange-v4",

		whitelistIPv6:      "whitelistIP-v6",
		whitelistRangeIPv6: "whitelistRange-v6",
		blacklistIPv6:      "blacklistIP-v6",
		blacklistRangeIPv6: "blacklistRange-v6",

		ipsetPath:  ipsetPath,
		enableIPv6: enableIPv6,
	}

	// Test ipset availability
	cmd := exec.Command(ipsetPath, "--version")
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ipset not available: %w", err)
	}

	// Create ipset sets if they don't exist
	if err := manager.createSets(); err != nil {
		return nil, err
	}

	return manager, nil
}

// createSets ensures all required ipset sets exist
func (m *IPSetManager) createSets() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Create IPv4 sets
	if err := m.createSet(m.whitelistIPv4, "hash:ip", "inet"); err != nil {
		return err
	}
	if err := m.createSet(m.whitelistRangeIPv4, "hash:net", "inet"); err != nil {
		return err
	}
	if err := m.createSet(m.blacklistIPv4, "hash:ip", "inet"); err != nil {
		return err
	}
	if err := m.createSet(m.blacklistRangeIPv4, "hash:net", "inet"); err != nil {
		return err
	}

	// Create IPv6 sets if enabled
	if m.enableIPv6 {
		if err := m.createSet(m.whitelistIPv6, "hash:ip", "inet6"); err != nil {
			return err
		}
		if err := m.createSet(m.whitelistRangeIPv6, "hash:net", "inet6"); err != nil {
			return err
		}
		if err := m.createSet(m.blacklistIPv6, "hash:ip", "inet6"); err != nil {
			return err
		}
		if err := m.createSet(m.blacklistRangeIPv6, "hash:net", "inet6"); err != nil {
			return err
		}
	}

	return nil
}

// createSet creates a single ipset if it doesn't exist
func (m *IPSetManager) createSet(name, setType, family string) error {
	// First, try to destroy existing set to ensure clean state
	destroyCmd := exec.Command(m.ipsetPath, "destroy", name)
	destroyCmd.Run() // Ignore errors - set might not exist

	// Create the set with proper error handling
	cmd := exec.Command(m.ipsetPath, "create", name, setType, "family", family, "hashsize", "4096", "maxelem", "65536")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// If creation fails, try to get more details about the error
		if strings.Contains(string(output), "already exists") {
			// Set already exists, try to flush it instead
			flushCmd := exec.Command(m.ipsetPath, "flush", name)
			if flushErr := flushCmd.Run(); flushErr == nil {
				return nil // Successfully flushed existing set
			}
		}
		return fmt.Errorf("failed to create ipset %s: %w (output: %s)", name, err, string(output))
	}
	return nil
}

// AddToWhitelist adds an IP to the whitelist
func (m *IPSetManager) AddToWhitelist(ip string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Determine if IPv4 or IPv6
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	// Add to appropriate set
	var setName string
	if parsedIP.To4() != nil {
		setName = m.whitelistIPv4
	} else if m.enableIPv6 {
		setName = m.whitelistIPv6
	} else {
		return fmt.Errorf("IPv6 support is disabled")
	}

	// Add to ipset
	cmd := exec.Command(m.ipsetPath, "add", setName, ip, "-exist")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add IP %s to %s: %w (%s)", ip, setName, err, output)
	}

	// If IP is in blacklist, remove it
	if parsedIP.To4() != nil {
		m.removeFromSet(m.blacklistIPv4, ip)
	} else if m.enableIPv6 {
		m.removeFromSet(m.blacklistIPv6, ip)
	}

	return nil
}

// AddToBlocklist adds an IP to the blocklist
func (m *IPSetManager) AddToBlocklist(ip string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Determine if IPv4 or IPv6
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	// Check if IP is whitelisted
	if m.isWhitelisted(ip) {
		return nil // Skip blocking whitelisted IPs
	}

	// Add to appropriate set
	var setName string
	if parsedIP.To4() != nil {
		setName = m.blacklistIPv4
	} else if m.enableIPv6 {
		setName = m.blacklistIPv6
	} else {
		return fmt.Errorf("IPv6 support is disabled")
	}

	// Add to ipset
	cmd := exec.Command(m.ipsetPath, "add", setName, ip, "-exist")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add IP %s to %s: %w (%s)", ip, setName, err, output)
	}

	return nil
}

// AddRangeToWhitelist adds a network range to the whitelist
func (m *IPSetManager) AddRangeToWhitelist(cidr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Validate CIDR
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR notation: %w", err)
	}

	// Add to appropriate set
	var setName string
	if ipNet.IP.To4() != nil {
		setName = m.whitelistRangeIPv4
	} else if m.enableIPv6 {
		setName = m.whitelistRangeIPv6
	} else {
		return fmt.Errorf("IPv6 support is disabled")
	}

	// Add to ipset
	cmd := exec.Command(m.ipsetPath, "add", setName, cidr, "-exist")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add CIDR %s to %s: %w (%s)", cidr, setName, err, output)
	}

	// If range is in blacklist, remove it
	if ipNet.IP.To4() != nil {
		m.removeFromSet(m.blacklistRangeIPv4, cidr)
	} else if m.enableIPv6 {
		m.removeFromSet(m.blacklistRangeIPv6, cidr)
	}

	return nil
}

// AddRangeToBlocklist adds a network range to the blocklist
func (m *IPSetManager) AddRangeToBlocklist(cidr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Validate CIDR
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR notation: %w", err)
	}

	// Check if range is whitelisted
	if m.isRangeWhitelisted(cidr) {
		return nil // Skip blocking whitelisted ranges
	}

	// Add to appropriate set
	var setName string
	if ipNet.IP.To4() != nil {
		setName = m.blacklistRangeIPv4
	} else if m.enableIPv6 {
		setName = m.blacklistRangeIPv6
	} else {
		return fmt.Errorf("IPv6 support is disabled")
	}

	// Add to ipset
	cmd := exec.Command(m.ipsetPath, "add", setName, cidr, "-exist")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add CIDR %s to %s: %w (%s)", cidr, setName, err, output)
	}

	return nil
}

// RemoveFromWhitelist removes an IP from the whitelist
func (m *IPSetManager) RemoveFromWhitelist(ip string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Determine if IPv4 or IPv6
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	// Remove from appropriate set
	var setName string
	if parsedIP.To4() != nil {
		setName = m.whitelistIPv4
	} else if m.enableIPv6 {
		setName = m.whitelistIPv6
	} else {
		return fmt.Errorf("IPv6 support is disabled")
	}

	return m.removeFromSet(setName, ip)
}

// RemoveFromBlocklist removes an IP from the blocklist
func (m *IPSetManager) RemoveFromBlocklist(ip string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Determine if IPv4 or IPv6
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}

	// Remove from appropriate set
	var setName string
	if parsedIP.To4() != nil {
		setName = m.blacklistIPv4
	} else if m.enableIPv6 {
		setName = m.blacklistIPv6
	} else {
		return fmt.Errorf("IPv6 support is disabled")
	}

	return m.removeFromSet(setName, ip)
}

// RemoveRangeFromWhitelist removes a network range from the whitelist
func (m *IPSetManager) RemoveRangeFromWhitelist(cidr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Validate CIDR
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR notation: %w", err)
	}

	// Remove from appropriate set
	var setName string
	if ipNet.IP.To4() != nil {
		setName = m.whitelistRangeIPv4
	} else if m.enableIPv6 {
		setName = m.whitelistRangeIPv6
	} else {
		return fmt.Errorf("IPv6 support is disabled")
	}

	return m.removeFromSet(setName, cidr)
}

// RemoveRangeFromBlocklist removes a network range from the blocklist
func (m *IPSetManager) RemoveRangeFromBlocklist(cidr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Validate CIDR
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR notation: %w", err)
	}

	// Remove from appropriate set
	var setName string
	if ipNet.IP.To4() != nil {
		setName = m.blacklistRangeIPv4
	} else if m.enableIPv6 {
		setName = m.blacklistRangeIPv6
	} else {
		return fmt.Errorf("IPv6 support is disabled")
	}

	return m.removeFromSet(setName, cidr)
}

// Helper method to remove an entry from a set
func (m *IPSetManager) removeFromSet(setName, entry string) error {
	cmd := exec.Command(m.ipsetPath, "del", setName, entry, "-exist")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove %s from %s: %w (%s)", entry, setName, err, output)
	}
	return nil
}

// FlushSet removes all entries from a set
func (m *IPSetManager) FlushSet(setName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cmd := exec.Command(m.ipsetPath, "flush", setName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to flush %s: %w (%s)", setName, err, output)
	}
	return nil
}

// FlushAll removes all entries from all sets
func (m *IPSetManager) FlushAll() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	sets := []string{
		m.whitelistIPv4, m.whitelistRangeIPv4, m.blacklistIPv4, m.blacklistRangeIPv4,
	}

	if m.enableIPv6 {
		sets = append(sets, m.whitelistIPv6, m.whitelistRangeIPv6, m.blacklistIPv6, m.blacklistRangeIPv6)
	}

	for _, set := range sets {
		if err := m.FlushSet(set); err != nil {
			return err
		}
	}

	return nil
}

// SaveSets saves all ipsets to a file for persistence
func (m *IPSetManager) SaveSets(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cmd := exec.Command("sh", "-c", fmt.Sprintf("%s save > %s", m.ipsetPath, path))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to save ipsets: %w (%s)", err, output)
	}
	return nil
}

// RestoreSets restores ipsets from a file
func (m *IPSetManager) RestoreSets(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cmd := exec.Command("sh", "-c", fmt.Sprintf("%s restore < %s", m.ipsetPath, path))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to restore ipsets: %w (%s)", err, output)
	}
	return nil
}

// isWhitelisted checks if an IP is in the whitelist
func (m *IPSetManager) isWhitelisted(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// Check direct whitelist
	var setName string
	if parsedIP.To4() != nil {
		setName = m.whitelistIPv4
	} else if m.enableIPv6 {
		setName = m.whitelistIPv6
	} else {
		return false
	}

	cmd := exec.Command(m.ipsetPath, "test", setName, ip)
	if cmd.Run() == nil {
		return true
	}

	// Check whitelist ranges
	if parsedIP.To4() != nil {
		ranges, err := m.listSet(m.whitelistRangeIPv4)
		if err == nil {
			for _, cidr := range ranges {
				_, ipNet, err := net.ParseCIDR(cidr)
				if err != nil {
					continue
				}
				if ipNet.Contains(parsedIP) {
					return true
				}
			}
		}
	} else if m.enableIPv6 {
		ranges, err := m.listSet(m.whitelistRangeIPv6)
		if err == nil {
			for _, cidr := range ranges {
				_, ipNet, err := net.ParseCIDR(cidr)
				if err != nil {
					continue
				}
				if ipNet.Contains(parsedIP) {
					return true
				}
			}
		}
	}

	return false
}

// isRangeWhitelisted checks if a CIDR range is in the whitelist
func (m *IPSetManager) isRangeWhitelisted(cidr string) bool {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}

	// Check direct range whitelist
	var setName string
	if ipNet.IP.To4() != nil {
		setName = m.whitelistRangeIPv4
	} else if m.enableIPv6 {
		setName = m.whitelistRangeIPv6
	} else {
		return false
	}

	cmd := exec.Command(m.ipsetPath, "test", setName, cidr)
	return cmd.Run() == nil
}

// listSet lists all entries in a set
func (m *IPSetManager) listSet(setName string) ([]string, error) {
	cmd := exec.Command(m.ipsetPath, "list", setName)
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var entries []string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// Parse out actual entries (not header lines)
		if strings.Contains(line, "/") || net.ParseIP(line) != nil {
			entries = append(entries, line)
		}
	}

	return entries, nil
}

// GetSetNames returns the names of all ipset sets used by this manager
func (m *IPSetManager) GetSetNames() []string {
	sets := []string{
		m.whitelistIPv4, m.whitelistRangeIPv4, m.blacklistIPv4, m.blacklistRangeIPv4,
	}

	if m.enableIPv6 {
		sets = append(sets, m.whitelistIPv6, m.whitelistRangeIPv6, m.blacklistIPv6, m.blacklistRangeIPv6)
	}

	return sets
}

// CleanupAllSets removes all DNSniper-related ipsets (useful for clean reinstalls)
func (m *IPSetManager) CleanupAllSets() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	sets := []string{
		m.whitelistIPv4, m.whitelistRangeIPv4, m.blacklistIPv4, m.blacklistRangeIPv4,
	}

	if m.enableIPv6 {
		sets = append(sets, m.whitelistIPv6, m.whitelistRangeIPv6, m.blacklistIPv6, m.blacklistRangeIPv6)
	}

	for _, set := range sets {
		// First flush, then destroy
		flushCmd := exec.Command(m.ipsetPath, "flush", set)
		flushCmd.Run() // Ignore errors

		destroyCmd := exec.Command(m.ipsetPath, "destroy", set)
		destroyCmd.Run() // Ignore errors
	}

	return nil
}

// EnsureSetsExist checks and recreates sets if they don't exist
func (m *IPSetManager) EnsureSetsExist() error {
	return m.createSets()
}
