package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	DefaultConfigPath = "/etc/dnsniper/config.yaml"
)

// LoadConfig loads the configuration from file and environment variables
func LoadConfig(configPath string) (*Settings, error) {
	if configPath == "" {
		configPath = DefaultConfigPath
	}

	// Load default settings
	config := DefaultSettings()
	config.ConfigPath = configPath

	// Create config directory if it doesn't exist
	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create config directory: %w", err)
	}

	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Create default config file
		if err := SaveConfig(config, configPath); err != nil {
			return nil, fmt.Errorf("failed to create default config: %w", err)
		}
	} else {
		// Load from file
		data, err := os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}

		if err := yaml.Unmarshal(data, config); err != nil {
			return nil, fmt.Errorf("failed to parse config file: %w", err)
		}
	}

	// Override with environment variables
	applyEnvironmentOverrides(config)

	return config, nil
}

// SaveConfig saves the configuration to file
func SaveConfig(config *Settings, configPath string) error {
	if configPath == "" {
		configPath = DefaultConfigPath
	}

	// Ensure directory exists
	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Marshal to YAML
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Write to file
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// applyEnvironmentOverrides applies environment variable overrides to the config
func applyEnvironmentOverrides(config *Settings) {
	// DNS resolvers
	if dnsResolvers := os.Getenv("DNSNIPER_DNS_RESOLVERS"); dnsResolvers != "" {
		config.DNSResolvers = strings.Split(dnsResolvers, ",")
	}

	// Block chains
	if blockChains := os.Getenv("DNSNIPER_BLOCK_CHAINS"); blockChains != "" {
		config.BlockChains = strings.Split(blockChains, ",")
	}

	// IPv6 support
	if enableIPv6 := os.Getenv("DNSNIPER_ENABLE_IPV6"); enableIPv6 != "" {
		config.EnableIPv6 = enableIPv6 == "true" || enableIPv6 == "1" || enableIPv6 == "yes"
	}

	// Update URLs
	if updateURLs := os.Getenv("DNSNIPER_UPDATE_URLS"); updateURLs != "" {
		config.UpdateURLs = strings.Split(updateURLs, ",")
	}

	// Update interval
	if interval := os.Getenv("DNSNIPER_UPDATE_INTERVAL"); interval != "" {
		if duration, err := time.ParseDuration(interval); err == nil {
			config.UpdateInterval = duration
		}
	}

	// Rule expiration
	if expiration := os.Getenv("DNSNIPER_RULE_EXPIRATION"); expiration != "" {
		if duration, err := time.ParseDuration(expiration); err == nil {
			config.RuleExpiration = duration
		}
	}

	// Max IPs per domain
	if maxIPs := os.Getenv("DNSNIPER_MAX_IPS_PER_DOMAIN"); maxIPs != "" {
		if val, err := strconv.Atoi(maxIPs); err == nil && val > 0 {
			config.MaxIPsPerDomain = val
		}
	}

	// Logging enabled
	if loggingEnabled := os.Getenv("DNSNIPER_LOGGING_ENABLED"); loggingEnabled != "" {
		config.LoggingEnabled = loggingEnabled == "true" || loggingEnabled == "1" || loggingEnabled == "yes"
	}

	// Log level
	if logLevel := os.Getenv("DNSNIPER_LOG_LEVEL"); logLevel != "" {
		config.LogLevel = logLevel
	}

	// Paths
	if dbPath := os.Getenv("DNSNIPER_DATABASE_PATH"); dbPath != "" {
		config.DatabasePath = dbPath
	}
	if logPath := os.Getenv("DNSNIPER_LOG_PATH"); logPath != "" {
		config.LogPath = logPath
	}
	if ipTablesPath := os.Getenv("DNSNIPER_IPTABLES_PATH"); ipTablesPath != "" {
		config.IPTablesPath = ipTablesPath
	}
	if ip6TablesPath := os.Getenv("DNSNIPER_IP6TABLES_PATH"); ip6TablesPath != "" {
		config.IP6TablesPath = ip6TablesPath
	}
	if ipSetPath := os.Getenv("DNSNIPER_IPSET_PATH"); ipSetPath != "" {
		config.IPSetPath = ipSetPath
	}
}
