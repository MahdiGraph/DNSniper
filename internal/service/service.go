package service

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/MahdiGraph/DNSniper/internal/database"
	"github.com/MahdiGraph/DNSniper/internal/models"
)

// GetAgentStatus returns the current status of the DNSniper agent
func GetAgentStatus() (models.AgentStatus, error) {
	var status models.AgentStatus

	// Get service status
	serviceStatus, err := getSystemdServiceStatus("dnsniper-agent")
	if err != nil {
		return status, err
	}
	status.ServiceStatus = serviceStatus

	// Get last run info
	lastRun, err := database.GetLastRunInfo()
	if err != nil {
		status.LastRun = "Never"
	} else {
		if lastRun.CompletedAt.Valid {
			status.LastRun = lastRun.CompletedAt.Time.Format(time.RFC1123)
		} else {
			status.LastRun = lastRun.StartedAt.Format(time.RFC1123) + " (running)"
		}
	}

	// Get domain stats
	domainStats, err := database.GetDomainsCount()
	if err == nil {
		status.BlockedDomains = domainStats.Blocked
		status.WhitelistedDomains = domainStats.Whitelisted
	}

	// Get IP stats
	ipStats, err := database.GetIPsCount()
	if err == nil {
		status.BlockedIPs = ipStats.Blocked
		status.WhitelistedIPs = ipStats.Whitelisted
	}

	return status, nil
}

// UpdateServiceLogging updates the systemd service file to enable/disable logging
func UpdateServiceLogging(enable bool) error {
	// Path to the systemd service file
	serviceFile := "/etc/systemd/system/dnsniper-agent.service"

	// Read the current content
	content, err := os.ReadFile(serviceFile)
	if err != nil {
		return fmt.Errorf("failed to read service file: %w", err)
	}

	// Convert to string for easier manipulation
	contentStr := string(content)

	// Look for ExecStart line
	execStartIdx := strings.Index(contentStr, "ExecStart=")
	if execStartIdx == -1 {
		return fmt.Errorf("could not find ExecStart line in service file")
	}

	// Find the end of the line
	lineEndIdx := strings.Index(contentStr[execStartIdx:], "\n")
	if lineEndIdx == -1 {
		lineEndIdx = len(contentStr) - execStartIdx
	} else {
		lineEndIdx += execStartIdx
	}

	// Extract the current ExecStart line
	execStartLine := contentStr[execStartIdx:lineEndIdx]

	// Check if it already has the logging flag
	hasLogFlag := strings.Contains(execStartLine, "-log")

	// Prepare the new line
	var newLine string
	if enable && !hasLogFlag {
		// Add the log flag
		newLine = execStartLine + " -log"
	} else if !enable && hasLogFlag {
		// Remove the log flag
		newLine = strings.Replace(execStartLine, " -log", "", -1)
	} else {
		// No change needed
		return nil
	}

	// Replace the line in the content
	newContent := contentStr[:execStartIdx] + newLine + contentStr[lineEndIdx:]

	// Write back to the file
	if err := os.WriteFile(serviceFile, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("failed to write service file: %w", err)
	}

	// Reload systemd daemon
	cmd := exec.Command("systemctl", "daemon-reload")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to reload systemd: %w", err)
	}

	// Restart the service if it's running
	isActive, err := isServiceActive("dnsniper-agent.service")
	if err != nil {
		return fmt.Errorf("failed to check service status: %w", err)
	}

	if isActive {
		cmd = exec.Command("systemctl", "restart", "dnsniper-agent.service")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to restart service: %w", err)
		}
	}

	return nil
}

func isServiceActive(serviceName string) (bool, error) {
	cmd := exec.Command("systemctl", "is-active", serviceName)
	output, err := cmd.Output()
	if err != nil {
		// If the command failed but we got output, check it
		if exitErr, ok := err.(*exec.ExitError); ok && len(exitErr.Stderr) > 0 {
			return false, nil
		}
		return false, err
	}

	return strings.TrimSpace(string(output)) == "active", nil
}

// getSystemdServiceStatus returns the status of a systemd service
func getSystemdServiceStatus(serviceName string) (string, error) {
	cmd := exec.Command("systemctl", "is-active", serviceName)
	output, err := cmd.Output()
	if err != nil {
		// If the command fails, check if it's because the service is inactive
		if _, ok := err.(*exec.ExitError); ok {
			return "inactive", nil
		}
		return "", fmt.Errorf("failed to get service status: %w", err)
	}

	status := strings.TrimSpace(string(output))
	return status, nil
}

// RunAgentOnce runs the agent once
func RunAgentOnce() error {
	cmd := exec.Command("/usr/local/bin/dnsniper-agent")
	return cmd.Run()
}

// StartAgent starts the DNSniper agent service
func StartAgent() error {
	cmd := exec.Command("systemctl", "start", "dnsniper-agent")
	return cmd.Run()
}

// StopAgent stops the DNSniper agent service
func StopAgent() error {
	cmd := exec.Command("systemctl", "stop", "dnsniper-agent")
	return cmd.Run()
}

// RestartAgent restarts the DNSniper agent service
func RestartAgent() error {
	cmd := exec.Command("systemctl", "restart", "dnsniper-agent")
	return cmd.Run()
}

// EnableAgent enables the DNSniper agent service to start at boot
func EnableAgent() error {
	cmd := exec.Command("systemctl", "enable", "dnsniper-agent")
	return cmd.Run()
}

// DisableAgent disables the DNSniper agent service from starting at boot
func DisableAgent() error {
	cmd := exec.Command("systemctl", "disable", "dnsniper-agent")
	return cmd.Run()
}
