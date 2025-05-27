package firewall

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Metrics represents firewall metrics
type Metrics struct {
	BlockedIPs        int
	WhitelistedIPs    int
	BlockedRanges     int
	WhitelistedRanges int
	RuleCount         int
	LastUpdate        time.Time
	mu                sync.RWMutex
}

// FirewallMonitor handles monitoring of firewall rules
type FirewallMonitor struct {
	metrics    *Metrics
	ipsetNames []string
	enableIPv6 bool
}

// NewFirewallMonitor creates a new firewall monitor
func NewFirewallMonitor(ipsetNames []string, enableIPv6 bool) *FirewallMonitor {
	return &FirewallMonitor{
		metrics: &Metrics{
			LastUpdate: time.Now(),
		},
		ipsetNames: ipsetNames,
		enableIPv6: enableIPv6,
	}
}

// UpdateMetrics updates the current metrics
func (m *FirewallMonitor) UpdateMetrics() error {
	m.metrics.mu.Lock()
	defer m.metrics.mu.Unlock()

	// Reset counters
	m.metrics.BlockedIPs = 0
	m.metrics.WhitelistedIPs = 0
	m.metrics.BlockedRanges = 0
	m.metrics.WhitelistedRanges = 0
	m.metrics.RuleCount = 0

	// Count entries in each set
	for _, setName := range m.ipsetNames {
		cmd := exec.Command("ipset", "list", setName)
		output, err := cmd.Output()
		if err != nil {
			return fmt.Errorf("failed to list ipset %s: %w", setName, err)
		}

		// Parse output to count entries
		lines := strings.Split(string(output), "\n")
		entryCount := 0
		for _, line := range lines {
			if !strings.HasPrefix(line, "Name:") && !strings.HasPrefix(line, "Type:") &&
				!strings.HasPrefix(line, "Revision:") && !strings.HasPrefix(line, "Header:") &&
				!strings.HasPrefix(line, "Size in memory:") && !strings.HasPrefix(line, "References:") &&
				strings.TrimSpace(line) != "" {
				entryCount++
			}
		}

		// Update appropriate counter
		switch {
		case strings.Contains(setName, "blocklistIP"):
			m.metrics.BlockedIPs += entryCount
		case strings.Contains(setName, "whitelistIP"):
			m.metrics.WhitelistedIPs += entryCount
		case strings.Contains(setName, "blocklistRange"):
			m.metrics.BlockedRanges += entryCount
		case strings.Contains(setName, "whitelistRange"):
			m.metrics.WhitelistedRanges += entryCount
		}
	}

	// Count iptables rules
	cmd := exec.Command("iptables", "-L", "-n")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to list iptables rules: %w", err)
	}
	m.metrics.RuleCount = strings.Count(string(output), "\n") - 3 // Subtract header lines

	if m.enableIPv6 {
		cmd = exec.Command("ip6tables", "-L", "-n")
		output, err = cmd.Output()
		if err != nil {
			return fmt.Errorf("failed to list ip6tables rules: %w", err)
		}
		m.metrics.RuleCount += strings.Count(string(output), "\n") - 3 // Subtract header lines
	}

	m.metrics.LastUpdate = time.Now()
	return nil
}

// GetMetrics returns the current metrics
func (m *FirewallMonitor) GetMetrics() Metrics {
	m.metrics.mu.RLock()
	defer m.metrics.mu.RUnlock()

	// Return a copy without the mutex to avoid copying lock value
	return Metrics{
		BlockedIPs:        m.metrics.BlockedIPs,
		WhitelistedIPs:    m.metrics.WhitelistedIPs,
		BlockedRanges:     m.metrics.BlockedRanges,
		WhitelistedRanges: m.metrics.WhitelistedRanges,
		RuleCount:         m.metrics.RuleCount,
		LastUpdate:        m.metrics.LastUpdate,
		// Don't copy the mutex
	}
}

// HealthCheck performs a health check of the firewall
func (m *FirewallMonitor) HealthCheck() error {
	// Check if required commands are available
	requiredCommands := []string{"ipset", "iptables"}
	if m.enableIPv6 {
		requiredCommands = append(requiredCommands, "ip6tables")
	}

	for _, cmd := range requiredCommands {
		if _, err := exec.LookPath(cmd); err != nil {
			return fmt.Errorf("required command %s not found: %w", cmd, err)
		}
	}

	// Check if all ipsets exist
	for _, setName := range m.ipsetNames {
		cmd := exec.Command("ipset", "list", setName)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("ipset %s not found: %w", setName, err)
		}
	}

	// Check if iptables is working
	cmd := exec.Command("iptables", "-L")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("iptables not working: %w", err)
	}

	if m.enableIPv6 {
		cmd = exec.Command("ip6tables", "-L")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("ip6tables not working: %w", err)
		}
	}

	return nil
}

// GetRuleStats returns statistics about firewall rules
func (m *FirewallMonitor) GetRuleStats() (map[string]int, error) {
	stats := make(map[string]int)

	// Get stats for each ipset
	for _, setName := range m.ipsetNames {
		cmd := exec.Command("ipset", "list", setName)
		output, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("failed to list ipset %s: %w", setName, err)
		}

		// Count entries
		lines := strings.Split(string(output), "\n")
		entryCount := 0
		for _, line := range lines {
			if !strings.HasPrefix(line, "Name:") && !strings.HasPrefix(line, "Type:") &&
				!strings.HasPrefix(line, "Revision:") && !strings.HasPrefix(line, "Header:") &&
				!strings.HasPrefix(line, "Size in memory:") && !strings.HasPrefix(line, "References:") &&
				strings.TrimSpace(line) != "" {
				entryCount++
			}
		}

		stats[setName] = entryCount
	}

	// Get iptables rule count
	cmd := exec.Command("iptables", "-L", "-n")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list iptables rules: %w", err)
	}
	stats["iptables"] = strings.Count(string(output), "\n") - 3

	if m.enableIPv6 {
		cmd = exec.Command("ip6tables", "-L", "-n")
		output, err = cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("failed to list ip6tables rules: %w", err)
		}
		stats["ip6tables"] = strings.Count(string(output), "\n") - 3
	}

	return stats, nil
}

// GetMemoryUsage returns memory usage of firewall rules
func (m *FirewallMonitor) GetMemoryUsage() (map[string]int64, error) {
	usage := make(map[string]int64)

	// Get memory usage for each ipset
	for _, setName := range m.ipsetNames {
		cmd := exec.Command("ipset", "list", setName)
		output, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("failed to list ipset %s: %w", setName, err)
		}

		// Parse memory usage
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "Size in memory:") {
				parts := strings.Split(line, ":")
				if len(parts) != 2 {
					continue
				}
				memoryStr := strings.TrimSpace(parts[1])
				memoryStr = strings.TrimSuffix(memoryStr, " bytes")
				memory, err := strconv.ParseInt(memoryStr, 10, 64)
				if err != nil {
					continue
				}
				usage[setName] = memory
				break
			}
		}
	}

	return usage, nil
}
