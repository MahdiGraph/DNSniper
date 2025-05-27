package firewall

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

// ValidationError represents a validation error
type ValidationError struct {
	Message string
	Details string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Message, e.Details)
}

// RuleValidator handles validation of firewall rules
type RuleValidator struct {
	enableIPv6 bool
}

// NewRuleValidator creates a new rule validator
func NewRuleValidator(enableIPv6 bool) *RuleValidator {
	return &RuleValidator{
		enableIPv6: enableIPv6,
	}
}

// ValidateIPSet validates an ipset configuration
func (v *RuleValidator) ValidateIPSet(setName string) error {
	// Check if set exists
	checkCmd := exec.Command("ipset", "list", setName)
	if err := checkCmd.Run(); err != nil {
		return &ValidationError{
			Message: "IPSet validation failed",
			Details: fmt.Sprintf("Set %s does not exist", setName),
		}
	}

	// Check set type
	output, err := exec.Command("ipset", "list", setName).Output()
	if err != nil {
		return &ValidationError{
			Message: "IPSet validation failed",
			Details: fmt.Sprintf("Failed to get set info: %v", err),
		}
	}

	// Validate set type
	outputStr := string(output)
	if strings.Contains(setName, "IP") && !strings.Contains(outputStr, "Type: hash:ip") {
		return &ValidationError{
			Message: "IPSet validation failed",
			Details: fmt.Sprintf("Set %s has incorrect type", setName),
		}
	}
	if strings.Contains(setName, "Range") && !strings.Contains(outputStr, "Type: hash:net") {
		return &ValidationError{
			Message: "IPSet validation failed",
			Details: fmt.Sprintf("Set %s has incorrect type", setName),
		}
	}

	return nil
}

// ValidateIPTablesRule validates an iptables rule
func (v *RuleValidator) ValidateIPTablesRule(chain, setName string, isIPv6 bool) error {
	cmd := "iptables"
	if isIPv6 {
		cmd = "ip6tables"
	}

	// Determine expected action based on set type
	var expectedAction string
	if strings.Contains(setName, "whitelist") {
		expectedAction = "ACCEPT"
	} else if strings.Contains(setName, "blocklist") {
		expectedAction = "DROP"
	} else {
		return &ValidationError{
			Message: "IPTables validation failed",
			Details: fmt.Sprintf("Unknown set type for %s", setName),
		}
	}

	// Check if both src and dst rules exist
	srcCmd := exec.Command(cmd, "-C", chain, "-m", "set", "--match-set", setName, "src", "-j", expectedAction)
	if err := srcCmd.Run(); err != nil {
		return &ValidationError{
			Message: "IPTables validation failed",
			Details: fmt.Sprintf("Source rule for set %s in chain %s not found (expected action: %s)", setName, chain, expectedAction),
		}
	}

	dstCmd := exec.Command(cmd, "-C", chain, "-m", "set", "--match-set", setName, "dst", "-j", expectedAction)
	if err := dstCmd.Run(); err != nil {
		return &ValidationError{
			Message: "IPTables validation failed",
			Details: fmt.Sprintf("Destination rule for set %s in chain %s not found (expected action: %s)", setName, chain, expectedAction),
		}
	}

	return nil
}

// ErrorRecovery handles recovery from firewall errors
type ErrorRecovery struct {
	backupPath string
}

// NewErrorRecovery creates a new error recovery handler
func NewErrorRecovery(backupPath string) *ErrorRecovery {
	return &ErrorRecovery{
		backupPath: backupPath,
	}
}

// BackupRules creates a backup of current firewall rules
func (r *ErrorRecovery) BackupRules() error {
	timestamp := time.Now().Format("20060102-150405")

	// Ensure backup directory exists
	if err := os.MkdirAll(r.backupPath, 0755); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Backup ipset rules
	ipsetBackup := fmt.Sprintf("%s/ipset-%s.rules", r.backupPath, timestamp)
	cmd := exec.Command("sh", "-c", fmt.Sprintf("ipset save > %s", ipsetBackup))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to backup ipset rules: %w", err)
	}

	// Backup iptables rules
	iptablesBackup := fmt.Sprintf("%s/iptables-%s.rules", r.backupPath, timestamp)
	cmd = exec.Command("sh", "-c", fmt.Sprintf("iptables-save > %s", iptablesBackup))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to backup iptables rules: %w", err)
	}

	// Backup ip6tables rules if IPv6 is enabled
	ip6tablesBackup := fmt.Sprintf("%s/ip6tables-%s.rules", r.backupPath, timestamp)
	cmd = exec.Command("sh", "-c", fmt.Sprintf("ip6tables-save > %s", ip6tablesBackup))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to backup ip6tables rules: %w", err)
	}

	return nil
}

// RestoreRules restores firewall rules from backup
func (r *ErrorRecovery) RestoreRules(timestamp string) error {
	// Restore ipset rules
	ipsetBackup := fmt.Sprintf("%s/ipset-%s.rules", r.backupPath, timestamp)
	cmd := exec.Command("sh", "-c", fmt.Sprintf("ipset restore < %s", ipsetBackup))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to restore ipset rules: %w", err)
	}

	// Restore iptables rules
	iptablesBackup := fmt.Sprintf("%s/iptables-%s.rules", r.backupPath, timestamp)
	cmd = exec.Command("sh", "-c", fmt.Sprintf("iptables-restore < %s", iptablesBackup))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to restore iptables rules: %w", err)
	}

	// Restore ip6tables rules
	ip6tablesBackup := fmt.Sprintf("%s/ip6tables-%s.rules", r.backupPath, timestamp)
	cmd = exec.Command("sh", "-c", fmt.Sprintf("ip6tables-restore < %s", ip6tablesBackup))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to restore ip6tables rules: %w", err)
	}

	return nil
}

// ValidateIP validates an IP address
func ValidateIP(ip string) error {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return &ValidationError{
			Message: "IP validation failed",
			Details: fmt.Sprintf("Invalid IP address: %s", ip),
		}
	}
	return nil
}

// ValidateCIDR validates a CIDR notation
func ValidateCIDR(cidr string) error {
	_, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return &ValidationError{
			Message: "CIDR validation failed",
			Details: fmt.Sprintf("Invalid CIDR notation: %s", cidr),
		}
	}
	return nil
}

// ValidateChain validates an iptables chain
func ValidateChain(chain string) error {
	validChains := map[string]bool{
		"INPUT":   true,
		"OUTPUT":  true,
		"FORWARD": true,
	}

	if !validChains[strings.ToUpper(chain)] {
		return &ValidationError{
			Message: "Chain validation failed",
			Details: fmt.Sprintf("Invalid chain: %s", chain),
		}
	}
	return nil
}
