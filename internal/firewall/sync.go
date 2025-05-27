package firewall

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/MahdiGraph/DNSniper/internal/database"
	"github.com/MahdiGraph/DNSniper/pkg/logger"
)

// SyncManager handles synchronization between database and ipsets
type SyncManager struct {
	firewallManager *FirewallManager
	db              database.DatabaseStore
	logger          *logger.Logger
	mu              sync.RWMutex
	lastSyncTime    time.Time
}

// NewSyncManager creates a new sync manager
func NewSyncManager(
	firewallManager *FirewallManager,
	db database.DatabaseStore,
	logger *logger.Logger,
) *SyncManager {
	return &SyncManager{
		firewallManager: firewallManager,
		db:              db,
		logger:          logger,
		lastSyncTime:    time.Now(),
	}
}

// SyncDatabaseToIPSets synchronizes database data to ipsets
func (s *SyncManager) SyncDatabaseToIPSets() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.logger.Info("Starting database to ipset synchronization...")

	// Get all active IPs from database
	activeIPs, err := s.db.GetActiveIPs()
	if err != nil {
		return fmt.Errorf("failed to get active IPs from database: %w", err)
	}

	// Get all whitelisted IPs and ranges
	whitelistedIPs, err := s.db.GetWhitelistedIPs()
	if err != nil {
		return fmt.Errorf("failed to get whitelisted IPs: %w", err)
	}

	whitelistedRanges, err := s.db.GetWhitelistedRanges()
	if err != nil {
		return fmt.Errorf("failed to get whitelisted ranges: %w", err)
	}

	// Get current ipset contents
	currentIPSets, err := s.getCurrentIPSetContents()
	if err != nil {
		return fmt.Errorf("failed to get current ipset contents: %w", err)
	}

	// Sync whitelist IPs first (priority)
	if err := s.syncWhitelistIPs(whitelistedIPs, currentIPSets); err != nil {
		return fmt.Errorf("failed to sync whitelist IPs: %w", err)
	}

	// Sync whitelist ranges
	if err := s.syncWhitelistRanges(whitelistedRanges, currentIPSets); err != nil {
		return fmt.Errorf("failed to sync whitelist ranges: %w", err)
	}

	// Sync blocklist IPs (exclude whitelisted ones)
	if err := s.syncBlocklistIPs(activeIPs, whitelistedIPs, currentIPSets); err != nil {
		return fmt.Errorf("failed to sync blocklist IPs: %w", err)
	}

	// Clean up orphaned entries in ipsets
	if err := s.cleanupOrphanedEntries(activeIPs, whitelistedIPs, whitelistedRanges, currentIPSets); err != nil {
		s.logger.Warnf("Failed to cleanup orphaned entries: %v", err)
	}

	s.lastSyncTime = time.Now()
	s.logger.Infof("Database to ipset synchronization completed successfully")

	return nil
}

// getCurrentIPSetContents gets current contents of all DNSniper ipsets
func (s *SyncManager) getCurrentIPSetContents() (map[string][]string, error) {
	contents := make(map[string][]string)
	setNames := s.firewallManager.ipsetManager.GetSetNames()

	for _, setName := range setNames {
		entries, err := s.getIPSetEntries(setName)
		if err != nil {
			// If ipset doesn't exist, create it
			if strings.Contains(err.Error(), "does not exist") {
				s.logger.Infof("IPSet %s doesn't exist, will be created", setName)
				contents[setName] = []string{}
				continue
			}
			return nil, fmt.Errorf("failed to get entries for ipset %s: %w", setName, err)
		}
		contents[setName] = entries
	}

	return contents, nil
}

// getIPSetEntries gets entries from a specific ipset
func (s *SyncManager) getIPSetEntries(setName string) ([]string, error) {
	cmd := exec.Command("ipset", "list", setName, "-o", "plain")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var entries []string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Name:") ||
			strings.HasPrefix(line, "Type:") || strings.HasPrefix(line, "Revision:") ||
			strings.HasPrefix(line, "Header:") || strings.HasPrefix(line, "Size") ||
			strings.HasPrefix(line, "References:") || strings.HasPrefix(line, "Number") {
			continue
		}
		entries = append(entries, line)
	}

	return entries, nil
}

// syncWhitelistIPs syncs whitelist IPs to ipsets
func (s *SyncManager) syncWhitelistIPs(whitelistedIPs []string, currentIPSets map[string][]string) error {
	for _, ip := range whitelistedIPs {
		if !s.firewallManager.IsValidIP(ip) {
			s.logger.Warnf("Invalid whitelisted IP: %s", ip)
			continue
		}

		// Determine IPv4 or IPv6
		parsedIP := net.ParseIP(ip)
		isIPv6 := parsedIP.To4() == nil

		setName := "dnsniper-whitelist-ip-v4"
		if isIPv6 {
			if !s.firewallManager.enableIPv6 {
				continue // Skip IPv6 if disabled
			}
			setName = "dnsniper-whitelist-ip-v6"
		}

		// Check if IP is already in the set
		if !contains(currentIPSets[setName], ip) {
			if err := s.firewallManager.WhitelistIP(ip, "system"); err != nil {
				s.logger.Warnf("Failed to add IP %s to whitelist: %v", ip, err)
			}
		}
	}

	return nil
}

// syncWhitelistRanges syncs whitelist ranges to ipsets
func (s *SyncManager) syncWhitelistRanges(whitelistedRanges []string, currentIPSets map[string][]string) error {
	for _, cidr := range whitelistedRanges {
		if !s.firewallManager.IsValidCIDR(cidr) {
			s.logger.Warnf("Invalid whitelisted CIDR: %s", cidr)
			continue
		}

		// Determine IPv4 or IPv6
		ip, _, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		isIPv6 := ip.To4() == nil

		setName := "dnsniper-whitelist-range-v4"
		if isIPv6 {
			if !s.firewallManager.enableIPv6 {
				continue // Skip IPv6 if disabled
			}
			setName = "dnsniper-whitelist-range-v6"
		}

		// Check if range is already in the set
		if !contains(currentIPSets[setName], cidr) {
			if err := s.firewallManager.WhitelistIPRange(cidr, "system"); err != nil {
				s.logger.Warnf("Failed to add range %s to whitelist: %v", cidr, err)
			}
		}
	}

	return nil
}

// syncBlocklistIPs syncs blocklist IPs to ipsets (excluding whitelisted ones)
func (s *SyncManager) syncBlocklistIPs(activeIPs, whitelistedIPs []string, currentIPSets map[string][]string) error {
	// Create a map for fast whitelist lookup
	whitelistMap := make(map[string]bool)
	for _, ip := range whitelistedIPs {
		whitelistMap[ip] = true
	}

	for _, ip := range activeIPs {
		// Skip if whitelisted (priority protection)
		if whitelistMap[ip] {
			continue
		}

		if !s.firewallManager.IsValidIP(ip) {
			s.logger.Warnf("Invalid active IP: %s", ip)
			continue
		}

		// Determine IPv4 or IPv6
		parsedIP := net.ParseIP(ip)
		isIPv6 := parsedIP.To4() == nil

		setName := "dnsniper-blocklist-ip-v4"
		if isIPv6 {
			if !s.firewallManager.enableIPv6 {
				continue // Skip IPv6 if disabled
			}
			setName = "dnsniper-blocklist-ip-v6"
		}

		// Check if IP is already in the set
		if !contains(currentIPSets[setName], ip) {
			if err := s.firewallManager.BlockIP(ip, "system"); err != nil {
				s.logger.Warnf("Failed to add IP %s to blocklist: %v", ip, err)
			}
		}
	}

	return nil
}

// cleanupOrphanedEntries removes entries from ipsets that are no longer in database
func (s *SyncManager) cleanupOrphanedEntries(activeIPs, whitelistedIPs, whitelistedRanges []string, currentIPSets map[string][]string) error {
	// Create maps for fast lookup
	activeIPMap := make(map[string]bool)
	for _, ip := range activeIPs {
		activeIPMap[ip] = true
	}

	whitelistIPMap := make(map[string]bool)
	for _, ip := range whitelistedIPs {
		whitelistIPMap[ip] = true
	}

	whitelistRangeMap := make(map[string]bool)
	for _, cidr := range whitelistedRanges {
		whitelistRangeMap[cidr] = true
	}

	// Check blocklist IP sets
	blocklistIPSets := []string{
		"dnsniper-blocklist-ip-v4",
		"dnsniper-blocklist-ip-v6",
	}

	for _, setName := range blocklistIPSets {
		if entries, exists := currentIPSets[setName]; exists {
			for _, ip := range entries {
				// Remove if not in active IPs or if whitelisted
				if !activeIPMap[ip] || whitelistIPMap[ip] {
					if err := s.removeFromIPSet(setName, ip); err != nil {
						s.logger.Warnf("Failed to remove orphaned IP %s from %s: %v", ip, setName, err)
					}
				}
			}
		}
	}

	// Check whitelist IP sets
	whitelistIPSets := []string{
		"dnsniper-whitelist-ip-v4",
		"dnsniper-whitelist-ip-v6",
	}

	for _, setName := range whitelistIPSets {
		if entries, exists := currentIPSets[setName]; exists {
			for _, ip := range entries {
				// Remove if not in whitelist
				if !whitelistIPMap[ip] {
					if err := s.removeFromIPSet(setName, ip); err != nil {
						s.logger.Warnf("Failed to remove orphaned IP %s from %s: %v", ip, setName, err)
					}
				}
			}
		}
	}

	// Check whitelist range sets
	whitelistRangeSets := []string{
		"dnsniper-whitelist-range-v4",
		"dnsniper-whitelist-range-v6",
	}

	for _, setName := range whitelistRangeSets {
		if entries, exists := currentIPSets[setName]; exists {
			for _, cidr := range entries {
				// Remove if not in whitelist ranges
				if !whitelistRangeMap[cidr] {
					if err := s.removeFromIPSet(setName, cidr); err != nil {
						s.logger.Warnf("Failed to remove orphaned range %s from %s: %v", cidr, setName, err)
					}
				}
			}
		}
	}

	return nil
}

// removeFromIPSet removes an entry from an ipset
func (s *SyncManager) removeFromIPSet(setName, entry string) error {
	cmd := exec.Command("ipset", "del", setName, entry)
	return cmd.Run()
}

// GetLastSyncTime returns the last sync time
func (s *SyncManager) GetLastSyncTime() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastSyncTime
}

// ValidateSync validates that database and ipsets are in sync
func (s *SyncManager) ValidateSync() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Get database data
	activeIPs, err := s.db.GetActiveIPs()
	if err != nil {
		return fmt.Errorf("failed to get active IPs: %w", err)
	}

	whitelistedIPs, err := s.db.GetWhitelistedIPs()
	if err != nil {
		return fmt.Errorf("failed to get whitelisted IPs: %w", err)
	}

	// Get ipset data
	currentIPSets, err := s.getCurrentIPSetContents()
	if err != nil {
		return fmt.Errorf("failed to get ipset contents: %w", err)
	}

	// Validate blocklist
	blocklistV4 := currentIPSets["dnsniper-blocklist-ip-v4"]
	blocklistV6 := currentIPSets["dnsniper-blocklist-ip-v6"]

	// Create whitelist map for exclusion check
	whitelistMap := make(map[string]bool)
	for _, ip := range whitelistedIPs {
		whitelistMap[ip] = true
	}

	// Check if all active IPs (non-whitelisted) are in ipsets
	for _, ip := range activeIPs {
		if whitelistMap[ip] {
			continue // Skip whitelisted IPs
		}

		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			continue
		}

		isIPv6 := parsedIP.To4() == nil
		var targetList []string
		if isIPv6 {
			targetList = blocklistV6
		} else {
			targetList = blocklistV4
		}

		if !contains(targetList, ip) {
			return fmt.Errorf("IP %s is in database but not in ipset", ip)
		}
	}

	s.logger.Info("Sync validation passed")
	return nil
}
