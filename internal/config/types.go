package config

import (
	"os"
	"runtime"
	"time"
)

// Settings represents the application configuration
type Settings struct {
	// DNS configuration
	DNSResolvers []string `yaml:"dns_resolvers"`

	// Firewall configuration
	AffectedChains []string `yaml:"affected_chains"` // INPUT, OUTPUT, FORWARD or combination (affects both whitelist and blacklist)
	EnableIPv6     bool     `yaml:"enable_ipv6"`     // Whether to enable IPv6 support

	// Update configuration
	UpdateURLs     []string      `yaml:"update_urls"`     // URLs to fetch domain lists from
	UpdateInterval time.Duration `yaml:"update_interval"` // How often to update

	// Domain handling
	RuleExpiration  time.Duration `yaml:"rule_expiration"`    // How long rules last before expiring
	MaxIPsPerDomain int           `yaml:"max_ips_per_domain"` // Maximum IPs to track per domain

	// Logging
	LoggingEnabled bool   `yaml:"logging_enabled"` // Whether to enable logging
	LogLevel       string `yaml:"log_level"`       // debug, info, warn, error

	// Paths
	ConfigPath    string `yaml:"-"` // Path to config file (not stored in config)
	DatabasePath  string `yaml:"database_path"`
	LogPath       string `yaml:"log_path"`
	IPTablesPath  string `yaml:"iptables_path"`
	IP6TablesPath string `yaml:"ip6tables_path"`
	IPSetPath     string `yaml:"ipset_path"`
}

// DefaultSettings returns the default configuration with OS-specific paths
func DefaultSettings() *Settings {
	// Get OS-specific paths
	iptablesPath, ip6tablesPath, ipsetPath := getOSSpecificPaths()

	return &Settings{
		DNSResolvers:   []string{"8.8.8.8", "1.1.1.1"},
		AffectedChains: []string{"INPUT", "OUTPUT", "FORWARD"},
		EnableIPv6:     true,

		UpdateURLs: []string{
			"https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/domains-default.txt",
		},
		UpdateInterval: 3 * time.Hour,

		RuleExpiration:  12 * time.Hour, // 12 hours (as requested)
		MaxIPsPerDomain: 5,

		LoggingEnabled: false,
		LogLevel:       "info",

		DatabasePath:  "/etc/dnsniper/dnsniper.db",
		LogPath:       "/var/log/dnsniper",
		IPTablesPath:  iptablesPath,
		IP6TablesPath: ip6tablesPath,
		IPSetPath:     ipsetPath,
	}
}

// getOSSpecificPaths returns OS-specific default paths for iptables and ipset
func getOSSpecificPaths() (iptablesPath, ip6tablesPath, ipsetPath string) {
	// Default paths that work on most systems
	iptablesPath = "/sbin/iptables"
	ip6tablesPath = "/sbin/ip6tables"
	ipsetPath = "/sbin/ipset"

	// Check if we're on Linux and can detect the distribution
	if runtime.GOOS == "linux" {
		// Try to detect distribution and adjust paths accordingly
		if isUbuntuDebian() {
			// Ubuntu/Debian typically have these in /sbin or /usr/sbin
			if fileExists("/usr/sbin/iptables") {
				iptablesPath = "/usr/sbin/iptables"
			}
			if fileExists("/usr/sbin/ip6tables") {
				ip6tablesPath = "/usr/sbin/ip6tables"
			}
			if fileExists("/usr/sbin/ipset") {
				ipsetPath = "/usr/sbin/ipset"
			}
		} else if isRHELCentOS() {
			// RHEL/CentOS typically use /usr/sbin
			if fileExists("/usr/sbin/iptables") {
				iptablesPath = "/usr/sbin/iptables"
			}
			if fileExists("/usr/sbin/ip6tables") {
				ip6tablesPath = "/usr/sbin/ip6tables"
			}
			if fileExists("/usr/sbin/ipset") {
				ipsetPath = "/usr/sbin/ipset"
			}
		}

		// Final fallback - check common locations
		for _, path := range []string{"/usr/sbin/iptables", "/sbin/iptables", "/bin/iptables"} {
			if fileExists(path) {
				iptablesPath = path
				break
			}
		}
		for _, path := range []string{"/usr/sbin/ip6tables", "/sbin/ip6tables", "/bin/ip6tables"} {
			if fileExists(path) {
				ip6tablesPath = path
				break
			}
		}
		for _, path := range []string{"/usr/sbin/ipset", "/sbin/ipset", "/bin/ipset"} {
			if fileExists(path) {
				ipsetPath = path
				break
			}
		}
	}

	return iptablesPath, ip6tablesPath, ipsetPath
}

// isUbuntuDebian checks if the system is Ubuntu or Debian
func isUbuntuDebian() bool {
	// Check for existence of characteristic files
	return fileExists("/etc/debian_version") ||
		fileExists("/etc/lsb-release")
}

// isRHELCentOS checks if the system is RHEL, CentOS, or Fedora
func isRHELCentOS() bool {
	// Check for existence of characteristic files
	return fileExists("/etc/redhat-release") ||
		fileExists("/etc/centos-release") ||
		fileExists("/etc/fedora-release")
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
