package config

import (
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/MahdiGraph/DNSniper/internal/models"
)

// Global DB connection - would typically be passed from database package
var db *sql.DB

// SetDatabase sets the database connection for the config package
func SetDatabase(database *sql.DB) {
	db = database
}

// GetSettings retrieves all application settings
func GetSettings() (models.Settings, error) {
	if db == nil {
		return models.Settings{}, fmt.Errorf("database connection not initialized")
	}

	var settings models.Settings

	// Default values in case settings retrieval fails
	settings = models.Settings{
		DNSResolver:     "8.8.8.8",
		BlockRuleType:   "both", // Deprecated but kept for compatibility
		BlockChains:     "ALL",  // New default
		BlockDirection:  "both", // New default
		LoggingEnabled:  false,
		RuleExpiration:  30 * 24 * time.Hour,
		UpdateURL:       "https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/domains-default.txt",
		MaxIPsPerDomain: 5,
	}

	// Retrieve settings from database
	rows, err := db.Query("SELECT key, value FROM settings")
	if err != nil {
		return settings, fmt.Errorf("failed to query settings: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return settings, fmt.Errorf("failed to scan setting: %w", err)
		}

		// Apply setting value based on key
		switch key {
		case "dns_resolver":
			settings.DNSResolver = value
		case "block_rule_type":
			settings.BlockRuleType = value // Keep for backward compatibility
		case "block_chains":
			settings.BlockChains = value
		case "block_direction":
			settings.BlockDirection = value
		case "logging_enabled":
			settings.LoggingEnabled = (value == "true")
		case "rule_expiration":
			settings.RuleExpiration = parseExpiration(value)
		case "update_url":
			settings.UpdateURL = value
		case "max_ips_per_domain":
			maxIPs, err := strconv.Atoi(value)
			if err == nil && maxIPs > 0 {
				settings.MaxIPsPerDomain = maxIPs
			}
		}
	}

	if err := rows.Err(); err != nil {
		return settings, fmt.Errorf("error iterating settings: %w", err)
	}

	return settings, nil
}

// SaveSetting saves a single setting to the database
func SaveSetting(key, value string) error {
	if db == nil {
		return fmt.Errorf("database connection not initialized")
	}

	_, err := db.Exec("UPDATE settings SET value = ? WHERE key = ?", value, key)
	return err
}

// parseExpiration parses a string like "30d", "24h", or "60m" to a duration
func parseExpiration(expStr string) time.Duration {
	expStr = strings.TrimSpace(expStr)

	// Default to 24 hours if empty
	if expStr == "" {
		return 24 * time.Hour
	}

	// Try to parse direct duration first
	duration, err := time.ParseDuration(expStr)
	if err == nil {
		return duration
	}

	// Parse different formats
	lastChar := expStr[len(expStr)-1]
	valueStr := expStr[:len(expStr)-1]

	value, err := strconv.Atoi(valueStr)
	if err != nil || value <= 0 {
		// Default to 24 hours if parsing fails
		return 24 * time.Hour
	}

	switch lastChar {
	case 'd':
		return time.Duration(value) * 24 * time.Hour
	case 'h':
		return time.Duration(value) * time.Hour
	case 'm':
		return time.Duration(value) * time.Minute
	default:
		// Default to 24 hours if unit is unknown
		return 24 * time.Hour
	}
}

// IsLoggingEnabled checks if logging is enabled
func IsLoggingEnabled() bool {
	settings, err := GetSettings()
	if err != nil {
		// Default to false if can't determine
		return false
	}

	return settings.LoggingEnabled
}

// GetLogFile opens the log file for writing
func GetLogFile() (*os.File, error) {
	// Ensure log directory exists
	err := os.MkdirAll("/var/log/dnsniper", 0755)
	if err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	// Open log file with append mode
	file, err := os.OpenFile("/var/log/dnsniper/dnsniper.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	return file, nil
}
