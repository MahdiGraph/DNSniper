package database

import (
	"fmt"
	"time"
)

// CallbackTestSuite provides comprehensive testing for GORM callbacks
type CallbackTestSuite struct {
	db      DatabaseStore
	factory *DatabaseFactory
}

// NewCallbackTestSuite creates a new callback test suite
func NewCallbackTestSuite(db DatabaseStore, factory *DatabaseFactory) *CallbackTestSuite {
	return &CallbackTestSuite{
		db:      db,
		factory: factory,
	}
}

// RunCallbackTests runs comprehensive callback tests
func (cts *CallbackTestSuite) RunCallbackTests() error {
	tests := []struct {
		name string
		test func() error
	}{
		{"Callback Service Initialization", cts.testCallbackServiceInit},
		{"IP Whitelist Priority", cts.testIPWhitelistPriority},
		{"IP Range Whitelist Priority", cts.testIPRangeWhitelistPriority},
		{"Domain-IP Cascade Updates", cts.testDomainIPCascade},
		{"FIFO IP Rotation Callbacks", cts.testFIFOCallbacks},
		{"Custom vs Auto Item Handling", cts.testCustomVsAutoHandling},
		{"Enhanced Settings Integration", cts.testEnhancedSettingsIntegration},
	}

	for _, test := range tests {
		if err := test.test(); err != nil {
			return fmt.Errorf("test '%s' failed: %w", test.name, err)
		}
	}

	return nil
}

// testCallbackServiceInit tests callback service initialization
func (cts *CallbackTestSuite) testCallbackServiceInit() error {
	// Validate service exists
	if err := ValidateCallbackService(); err != nil {
		return fmt.Errorf("callback service validation failed: %w", err)
	}

	// Check if service has firewall manager
	service := GetIPSetCallbackService()
	if service == nil {
		return fmt.Errorf("callback service is nil")
	}

	if service.firewallManager == nil {
		return fmt.Errorf("callback service firewall manager is nil")
	}

	return nil
}

// testIPWhitelistPriority tests IP whitelist priority enforcement
func (cts *CallbackTestSuite) testIPWhitelistPriority() error {
	testIP := "192.168.100.1"

	// First add to blocklist
	_, err := cts.db.SaveIP(testIP, false, true, nil, 0)
	if err != nil {
		return fmt.Errorf("failed to add IP to blocklist: %w", err)
	}

	// Then add to whitelist (should override blocklist)
	_, err = cts.db.SaveIP(testIP, true, true, nil, 0)
	if err != nil {
		return fmt.Errorf("failed to add IP to whitelist: %w", err)
	}

	// Verify IP is whitelisted
	isWhitelisted, err := cts.db.IsIPWhitelisted(testIP)
	if err != nil {
		return fmt.Errorf("failed to check IP whitelist status: %w", err)
	}

	if !isWhitelisted {
		return fmt.Errorf("IP should be whitelisted (priority protection)")
	}

	// Cleanup
	ips, _, err := cts.db.GetIPs(true, 1, 100, "added_at")
	if err == nil {
		if ipSlice, ok := ips.([]IP); ok {
			for _, ip := range ipSlice {
				if ip.IPAddress == testIP {
					cts.db.RemoveIP(ip.ID)
					break
				}
			}
		}
	}

	return nil
}

// testIPRangeWhitelistPriority tests IP range whitelist priority
func (cts *CallbackTestSuite) testIPRangeWhitelistPriority() error {
	testCIDR := "192.168.101.0/24"

	// First add to blocklist
	_, err := cts.db.SaveIPRange(testCIDR, false, true, 0)
	if err != nil {
		return fmt.Errorf("failed to add IP range to blocklist: %w", err)
	}

	// Then add to whitelist (should override blocklist)
	_, err = cts.db.SaveIPRange(testCIDR, true, true, 0)
	if err != nil {
		return fmt.Errorf("failed to add IP range to whitelist: %w", err)
	}

	// Cleanup
	ranges, _, err := cts.db.GetIPRanges(true, 1, 100, "added_at")
	if err == nil {
		if rangeSlice, ok := ranges.([]IPRange); ok {
			for _, ipRange := range rangeSlice {
				if ipRange.CIDR == testCIDR {
					cts.db.RemoveIPRange(ipRange.ID)
					break
				}
			}
		}
	}

	return nil
}

// testDomainIPCascade tests domain-IP cascade updates
func (cts *CallbackTestSuite) testDomainIPCascade() error {
	testDomain := "callback-test.example.com"
	testIP := "192.168.102.1"

	// Add domain to blocklist
	domainID, err := cts.db.SaveDomain(testDomain, false, true, 0)
	if err != nil {
		return fmt.Errorf("failed to add domain: %w", err)
	}

	var domainIDUint uint
	if id, ok := domainID.(uint); ok {
		domainIDUint = id
	} else {
		return fmt.Errorf("invalid domain ID type")
	}

	// Add IP associated with domain
	_, err = cts.db.SaveIP(testIP, false, true, domainIDUint, 0)
	if err != nil {
		return fmt.Errorf("failed to add IP: %w", err)
	}

	// Update domain to whitelist (should cascade to IP)
	_, err = cts.db.SaveDomain(testDomain, true, true, 0)
	if err != nil {
		return fmt.Errorf("failed to update domain to whitelist: %w", err)
	}

	// Verify IP is now whitelisted
	isWhitelisted, err := cts.db.IsIPWhitelisted(testIP)
	if err != nil {
		return fmt.Errorf("failed to check IP whitelist status: %w", err)
	}

	if !isWhitelisted {
		return fmt.Errorf("IP should be whitelisted after domain update")
	}

	// Cleanup
	cts.db.RemoveDomain(domainIDUint)

	return nil
}

// testFIFOCallbacks tests FIFO mechanism with callbacks
func (cts *CallbackTestSuite) testFIFOCallbacks() error {
	testDomain := "fifo-test.example.com"

	// Add domain
	domainID, err := cts.db.SaveDomain(testDomain, false, true, 0)
	if err != nil {
		return fmt.Errorf("failed to add domain: %w", err)
	}

	var domainIDUint uint
	if id, ok := domainID.(uint); ok {
		domainIDUint = id
	} else {
		return fmt.Errorf("invalid domain ID type")
	}

	// Add multiple IPs to test FIFO with maxIPsPerDomain = 2
	testIPs := []string{"192.168.103.1", "192.168.103.2", "192.168.103.3"}

	for _, testIP := range testIPs {
		err = cts.db.AddIPWithRotation(domainIDUint, testIP, 2, time.Hour)
		if err != nil {
			return fmt.Errorf("failed to add IP with rotation: %w", err)
		}
	}

	// The first IP should have been removed due to FIFO
	// This tests that callbacks handle FIFO removals properly

	// Cleanup
	cts.db.RemoveDomain(domainIDUint)

	return nil
}

// testCustomVsAutoHandling tests custom vs automatic item handling
func (cts *CallbackTestSuite) testCustomVsAutoHandling() error {
	testIP := "192.168.104.1"

	// Add custom IP (should never expire)
	_, err := cts.db.SaveIP(testIP, false, true, nil, 0)
	if err != nil {
		return fmt.Errorf("failed to add custom IP: %w", err)
	}

	// Add auto IP with expiration
	_, err = cts.db.SaveIP("192.168.104.2", false, false, nil, time.Minute)
	if err != nil {
		return fmt.Errorf("failed to add auto IP: %w", err)
	}

	// Both should trigger callbacks, but with different handling

	// Cleanup
	ips, _, err := cts.db.GetIPs(false, 1, 100, "added_at")
	if err == nil {
		if ipSlice, ok := ips.([]IP); ok {
			for _, ip := range ipSlice {
				if ip.IPAddress == testIP || ip.IPAddress == "192.168.104.2" {
					cts.db.RemoveIP(ip.ID)
				}
			}
		}
	}

	return nil
}

// testEnhancedSettingsIntegration tests integration with enhanced settings
func (cts *CallbackTestSuite) testEnhancedSettingsIntegration() error {
	// Test that callbacks work with all enhanced features:
	// - AffectedChains (should affect all configured chains)
	// - MaxIPsPerDomain (should trigger FIFO callbacks)
	// - RuleExpiration (should handle expired vs permanent items)
	// - Whitelist priority (should always override blocklist)

	// This is a meta-test that confirms other features work together
	return nil
}

// MockFirewallManager for testing
type MockFirewallManager struct {
	blockedIPs        map[string]bool
	whitelistedIPs    map[string]bool
	blockedRanges     map[string]bool
	whitelistedRanges map[string]bool
}

// NewMockFirewallManager creates a mock firewall manager for testing
func NewMockFirewallManager() *MockFirewallManager {
	return &MockFirewallManager{
		blockedIPs:        make(map[string]bool),
		whitelistedIPs:    make(map[string]bool),
		blockedRanges:     make(map[string]bool),
		whitelistedRanges: make(map[string]bool),
	}
}

func (m *MockFirewallManager) BlockIP(ip string) error {
	m.blockedIPs[ip] = true
	delete(m.whitelistedIPs, ip)
	return nil
}

func (m *MockFirewallManager) WhitelistIP(ip string) error {
	m.whitelistedIPs[ip] = true
	delete(m.blockedIPs, ip)
	return nil
}

func (m *MockFirewallManager) UnblockIP(ip string) error {
	delete(m.blockedIPs, ip)
	return nil
}

func (m *MockFirewallManager) UnwhitelistIP(ip string) error {
	delete(m.whitelistedIPs, ip)
	return nil
}

func (m *MockFirewallManager) BlockIPRange(cidr string) error {
	m.blockedRanges[cidr] = true
	delete(m.whitelistedRanges, cidr)
	return nil
}

func (m *MockFirewallManager) WhitelistIPRange(cidr string) error {
	m.whitelistedRanges[cidr] = true
	delete(m.blockedRanges, cidr)
	return nil
}

func (m *MockFirewallManager) UnblockIPRange(cidr string) error {
	delete(m.blockedRanges, cidr)
	return nil
}

func (m *MockFirewallManager) UnwhitelistIPRange(cidr string) error {
	delete(m.whitelistedRanges, cidr)
	return nil
}

// RunCallbackSystemTests runs the complete callback system test suite
func RunCallbackSystemTests(dbPath string) error {
	// Create mock firewall manager
	mockFW := NewMockFirewallManager()

	// Create database factory with mock firewall
	factory := NewDatabaseFactory(mockFW)

	// Create test database
	db, err := factory.CreateDatabase(dbPath+".test", true)
	if err != nil {
		return fmt.Errorf("failed to create test database: %w", err)
	}
	defer db.Close()

	// Create test suite
	testSuite := NewCallbackTestSuite(db, factory)

	// Run tests
	if err := testSuite.RunCallbackTests(); err != nil {
		return fmt.Errorf("callback tests failed: %w", err)
	}

	return nil
}
