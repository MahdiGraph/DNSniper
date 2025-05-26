package config

import (
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
	ConfigPath   string `yaml:"-"` // Path to config file (not stored in config)
	DatabasePath string `yaml:"database_path"`
	LogPath      string `yaml:"log_path"`
}

// DefaultSettings returns the default configuration with OS-specific paths
func DefaultSettings() *Settings {
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

		DatabasePath: "/etc/dnsniper/dnsniper.db",
		LogPath:      "/var/log/dnsniper",
	}
}
