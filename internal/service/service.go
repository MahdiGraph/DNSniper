package service

import (
	"fmt"
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
