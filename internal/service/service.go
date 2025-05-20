package service

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/MahdiGraph/DNSniper/internal/database"
	"github.com/MahdiGraph/DNSniper/internal/models"
)

// GetAgentStatus returns the current status of the DNSniper agent
func GetAgentStatus() (models.AgentStatus, error) {
	var status models.AgentStatus

	// Check if the timer is active first
	cmd := exec.Command("systemctl", "is-active", "dnsniper-agent.timer")
	output, err := cmd.Output()
	if err == nil && strings.TrimSpace(string(output)) == "active" {
		status.ServiceStatus = "active"
	} else {
		// If timer isn't active, check if the service is currently running
		if running, _ := IsAgentRunning(); running {
			status.ServiceStatus = "active"
		} else {
			status.ServiceStatus = "inactive"
		}
	}

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

// IsAgentRunning checks if the agent process is currently running
func IsAgentRunning() (bool, error) {
	// Check for active agent run in database
	lastRun, err := database.GetLastRunInfo()
	if err != nil {
		return false, fmt.Errorf("failed to get last run info: %w", err)
	}

	// If there's no last run record, agent is not running
	if lastRun.ID == 0 {
		return false, nil
	}

	// If the last run has a completion time, agent is not running
	if lastRun.CompletedAt.Valid {
		return false, nil
	}

	// If the last run started less than 10 minutes ago and has no completion time, assume it's running
	if time.Since(lastRun.StartedAt) < 10*time.Minute {
		return true, nil
	}

	// Check active processes as a backup method
	cmd := exec.Command("pgrep", "-f", "dnsniper-agent")
	output, err := cmd.Output()
	if err != nil {
		// If command returns non-zero exit status, no matching processes found
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return false, nil
		}
		return false, fmt.Errorf("failed to check agent process: %w", err)
	}

	return len(output) > 0, nil
}

// UpdateServiceLogging updates the systemd service file to enable/disable logging
// Note: This uses systemctl commands that might require sudo permissions
func UpdateServiceLogging(enable bool) error {
	// Path to the systemd service file
	serviceFile := "/etc/systemd/system/dnsniper-agent.service"

	// Read the current content
	content, err := ioutil.ReadFile(serviceFile)
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
	if err := ioutil.WriteFile(serviceFile, []byte(newContent), 0644); err != nil {
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

// DirectlyUpdateServiceLogging updates the service file directly without systemctl commands
func DirectlyUpdateServiceLogging(enable bool) error {
	// Path to the systemd service file
	serviceFile := "/etc/systemd/system/dnsniper-agent.service"

	// Check if file exists
	if _, err := os.Stat(serviceFile); os.IsNotExist(err) {
		return fmt.Errorf("service file does not exist: %s", serviceFile)
	}

	// Read the current content
	contentBytes, err := os.ReadFile(serviceFile)
	if err != nil {
		return fmt.Errorf("failed to read service file: %w", err)
	}

	contentStr := string(contentBytes)

	// Use regex to find and replace the ExecStart line
	re := regexp.MustCompile(`(ExecStart=.*?dnsniper-agent)(\s+-log)?(.*)`)

	if enable {
		// Add -log flag if not present
		if re.MatchString(contentStr) {
			contentStr = re.ReplaceAllString(contentStr, "$1 -log$3")
		} else {
			// If regex doesn't match, try a simple string replacement as a fallback
			execStartPos := strings.Index(contentStr, "ExecStart=")
			if execStartPos != -1 {
				// Find the end of the line
				lineEndPos := strings.Index(contentStr[execStartPos:], "\n")
				if lineEndPos != -1 {
					lineEndPos += execStartPos
					// Check if -log is already present
					execStartLine := contentStr[execStartPos:lineEndPos]
					if !strings.Contains(execStartLine, "-log") {
						// Insert -log before the end of the line
						contentStr = contentStr[:lineEndPos] + " -log" + contentStr[lineEndPos:]
					}
				}
			}
		}
	} else {
		// Remove -log flag if present
		contentStr = re.ReplaceAllString(contentStr, "$1$3")
	}

	// Write back to the file
	err = os.WriteFile(serviceFile, []byte(contentStr), 0644)
	if err != nil {
		return fmt.Errorf("failed to write service file: %w", err)
	}

	// Execute systemctl commands using a shell script since we might not have permissions
	script := `
#!/bin/sh
systemctl daemon-reload
# Only restart if currently running
if systemctl is-active --quiet dnsniper-agent; then
    systemctl restart dnsniper-agent
fi
`

	tempFile, err := os.CreateTemp("", "dnsniper_service_update_*.sh")
	if err != nil {
		return fmt.Errorf("failed to create temp script: %w", err)
	}
	defer os.Remove(tempFile.Name())

	if _, err := tempFile.Write([]byte(script)); err != nil {
		return fmt.Errorf("failed to write temp script: %w", err)
	}

	if err := tempFile.Chmod(0755); err != nil {
		return fmt.Errorf("failed to make script executable: %w", err)
	}

	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp script: %w", err)
	}

	// Run the script
	cmd := exec.Command("sh", tempFile.Name())
	if err := cmd.Run(); err != nil {
		// Ignore errors from the script, as we may not have permissions
		// The file was successfully updated, which is the important part
		fmt.Printf("Note: Could not reload service due to permissions, but file was updated. You may need to run 'sudo systemctl daemon-reload'\n")
	}

	return nil
}

// GetAgentTimerInterval gets the current interval for the agent timer
func GetAgentTimerInterval() (string, error) {
	timerFile := "/etc/systemd/system/dnsniper-agent.timer"

	// Make sure the file exists
	if _, err := os.Stat(timerFile); os.IsNotExist(err) {
		return "", fmt.Errorf("timer file does not exist: %s", timerFile)
	}

	// Read the timer file
	content, err := os.ReadFile(timerFile)
	if err != nil {
		return "", fmt.Errorf("failed to read timer file: %w", err)
	}

	// Look for the OnUnitActiveSec line which contains the interval
	re := regexp.MustCompile(`OnUnitActiveSec=([^\n\r\s]+)`)
	matches := re.FindSubmatch(content)

	if len(matches) < 2 {
		return "", fmt.Errorf("could not find timer interval in file")
	}

	return string(matches[1]), nil
}

// DirectlyUpdateAgentTimerInterval updates the agent timer interval directly
func DirectlyUpdateAgentTimerInterval(interval string) error {
	timerFile := "/etc/systemd/system/dnsniper-agent.timer"

	// Make sure the file exists
	if _, err := os.Stat(timerFile); os.IsNotExist(err) {
		return fmt.Errorf("timer file does not exist: %s", timerFile)
	}

	// Read the current content
	contentBytes, err := os.ReadFile(timerFile)
	if err != nil {
		return fmt.Errorf("failed to read timer file: %w", err)
	}

	contentStr := string(contentBytes)

	// Prepare regex to find and replace the interval
	re := regexp.MustCompile(`(OnUnitActiveSec=)[^\n\r\s]+`)

	if !re.MatchString(contentStr) {
		return fmt.Errorf("could not find OnUnitActiveSec line in timer file")
	}

	// Replace the interval
	newContent := re.ReplaceAllString(contentStr, "${1}"+interval)

	// Write the modified content back to the file
	err = os.WriteFile(timerFile, []byte(newContent), 0644)
	if err != nil {
		return fmt.Errorf("failed to write timer file: %w", err)
	}

	// Execute systemctl commands using a shell script since we might not have permissions
	script := `
#!/bin/sh
systemctl daemon-reload
systemctl restart dnsniper-agent.timer
`

	tempFile, err := os.CreateTemp("", "dnsniper_timer_update_*.sh")
	if err != nil {
		return fmt.Errorf("failed to create temp script: %w", err)
	}
	defer os.Remove(tempFile.Name())

	if _, err := tempFile.Write([]byte(script)); err != nil {
		return fmt.Errorf("failed to write temp script: %w", err)
	}

	if err := tempFile.Chmod(0755); err != nil {
		return fmt.Errorf("failed to make script executable: %w", err)
	}

	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp script: %w", err)
	}

	// Run the script
	cmd := exec.Command("sh", tempFile.Name())
	if err := cmd.Run(); err != nil {
		// Ignore errors from the script, as we may not have permissions
		// The file was successfully updated, which is the important part
		fmt.Printf("Note: Could not reload service due to permissions, but file was updated. You may need to run 'sudo systemctl daemon-reload'\n")
	}

	return nil
}

// UpdateAgentTimerInterval updates the agent timer interval
func UpdateAgentTimerInterval(interval string) error {
	timerFile := "/etc/systemd/system/dnsniper-agent.timer"

	// Read the current content
	content, err := ioutil.ReadFile(timerFile)
	if err != nil {
		return fmt.Errorf("failed to read timer file: %w", err)
	}

	// Prepare regex to find and replace the interval
	re := regexp.MustCompile(`(OnUnitActiveSec=)[^\s]+`)
	newContent := re.ReplaceAll(content, []byte("$1"+interval))

	// Write the modified content back to the file
	if err := ioutil.WriteFile(timerFile, newContent, 0644); err != nil {
		return fmt.Errorf("failed to write timer file: %w", err)
	}

	// Reload systemd daemon
	cmd := exec.Command("systemctl", "daemon-reload")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to reload systemd: %w", err)
	}

	// Restart the timer
	cmd = exec.Command("systemctl", "restart", "dnsniper-agent.timer")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to restart timer: %w", err)
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
	cmd := exec.Command("/usr/bin/dnsniper-agent")
	return cmd.Run()
}

// RestartAgent restarts the DNSniper agent service
func RestartAgent() error {
	cmd := exec.Command("systemctl", "restart", "dnsniper-agent.service")
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
