package utils

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"
)

// DownloadDomainList downloads and processes a list of domains from the given URL
func DownloadDomainList(url string) ([]string, error) {
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to download domain list: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to download domain list: HTTP %d", resp.StatusCode)
	}

	var domains []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Process lines and filter comments
		if line != "" && !strings.HasPrefix(line, "#") {
			domains = append(domains, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error scanning domain list: %w", err)
	}

	return domains, nil
}

// IsValidIPToBlock checks if an IP is valid to block
func IsValidIPToBlock(ip string) (bool, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false, fmt.Errorf("invalid IP address: %s", ip)
	}

	// Check non-blockable addresses
	// Loopback
	if parsedIP.IsLoopback() {
		return false, nil
	}

	// Private networks
	privateNets := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}

	for _, netStr := range privateNets {
		_, ipNet, err := net.ParseCIDR(netStr)
		if err != nil {
			continue
		}
		if ipNet.Contains(parsedIP) {
			return false, nil
		}
	}

	// Multicast addresses
	if parsedIP.IsMulticast() {
		return false, nil
	}

	// Check configured DNS servers
	dnsServers := GetDNSServers()
	for _, dns := range dnsServers {
		if ip == dns {
			return false, nil
		}
	}

	return true, nil
}

// GetDNSServers gets the list of DNS servers from /etc/resolv.conf
func GetDNSServers() []string {
	file, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return []string{"8.8.8.8", "8.8.4.4"} // Default to Google DNS if can't read resolv.conf
	}
	defer file.Close()

	var servers []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "nameserver") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				servers = append(servers, fields[1])
			}
		}
	}

	if len(servers) == 0 {
		return []string{"8.8.8.8", "8.8.4.4"} // Default to Google DNS if no servers found
	}

	return servers
}

// ProcessExists checks if a process with the given PID exists
func ProcessExists(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	// On Unix systems, we need to send a signal to check if process exists
	err = process.Signal(syscall.Signal(0))
	return err == nil
}
