package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/MahdiGraph/DNSniper/internal/models"
	_ "github.com/mattn/go-sqlite3"
)

const (
	dbPath = "/etc/dnsniper/dnsniper.db"
)

var db *sql.DB

// Initialize creates the database and tables if they don't exist
func Initialize() (*sql.DB, error) {
	// Ensure directory exists
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	var err error
	db, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Create tables if they don't exist
	if err := createTables(); err != nil {
		return nil, fmt.Errorf("failed to create tables: %w", err)
	}

	// Initialize default settings if not present
	if err := initializeDefaultSettings(); err != nil {
		return nil, fmt.Errorf("failed to initialize default settings: %w", err)
	}

	return db, nil
}

// createTables creates the necessary database tables
func createTables() error {
	// Create domains table
	_, err := db.Exec(`
    CREATE TABLE IF NOT EXISTS domains (
        id INTEGER PRIMARY KEY,
        domain TEXT NOT NULL UNIQUE,
        is_whitelisted BOOLEAN NOT NULL DEFAULT 0,
        is_custom BOOLEAN NOT NULL DEFAULT 0,
        flagged_as_cdn BOOLEAN NOT NULL DEFAULT 0,
        added_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NULL,
        source TEXT DEFAULT 'custom',
        last_checked TIMESTAMP NULL
    )`)
	if err != nil {
		return err
	}

	// Create ips table
	_, err = db.Exec(`
    CREATE TABLE IF NOT EXISTS ips (
        id INTEGER PRIMARY KEY,
        ip_address TEXT NOT NULL UNIQUE,
        is_whitelisted BOOLEAN NOT NULL DEFAULT 0,
        is_custom BOOLEAN NOT NULL DEFAULT 0,
        added_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NULL,
        source TEXT DEFAULT 'custom',
        domain_id INTEGER NULL,
        FOREIGN KEY (domain_id) REFERENCES domains(id)
    )`)
	if err != nil {
		return err
	}

	// Create settings table
	_, err = db.Exec(`
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        description TEXT NULL
    )`)
	if err != nil {
		return err
	}

	// Create agent_runs table
	_, err = db.Exec(`
    CREATE TABLE IF NOT EXISTS agent_runs (
        id INTEGER PRIMARY KEY,
        started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        completed_at TIMESTAMP NULL,
        domains_processed INTEGER DEFAULT 0,
        ips_blocked INTEGER DEFAULT 0,
        status TEXT DEFAULT 'running',
        error_message TEXT NULL
    )`)
	if err != nil {
		return err
	}

	// Create agent_logs table
	_, err = db.Exec(`
    CREATE TABLE IF NOT EXISTS agent_logs (
        id INTEGER PRIMARY KEY,
        run_id INTEGER NOT NULL,
        action_type TEXT NOT NULL,
        target TEXT NOT NULL,
        result TEXT NOT NULL,
        timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        details TEXT NULL,
        FOREIGN KEY (run_id) REFERENCES agent_runs(id)
    )`)
	if err != nil {
		return err
	}

	return nil
}

// initializeDefaultSettings sets up default settings if they don't exist
func initializeDefaultSettings() error {
	defaultSettings := map[string]struct {
		value       string
		description string
	}{
		"dns_resolver":       {"8.8.8.8", "DNS resolver to use for domain resolution"},
		"block_rule_type":    {"both", "Type of blocking rule (source, destination, both)"},
		"logging_enabled":    {"true", "Whether to enable logging"},
		"rule_expiration":    {"30d", "Expiration time for rules (e.g., 30d for 30 days)"},
		"update_url":         {"https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/domains-default.txt", "URL to download domain list from"},
		"max_ips_per_domain": {"5", "Maximum number of IPs to track per domain"},
	}

	for key, setting := range defaultSettings {
		var count int
		err := db.QueryRow("SELECT COUNT(*) FROM settings WHERE key = ?", key).Scan(&count)
		if err != nil {
			return err
		}

		if count == 0 {
			_, err = db.Exec("INSERT INTO settings (key, value, description) VALUES (?, ?, ?)",
				key, setting.value, setting.description)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// IsDomainWhitelisted checks if a domain is whitelisted
func IsDomainWhitelisted(domain string) (bool, error) {
	var isWhitelisted bool
	err := db.QueryRow("SELECT is_whitelisted FROM domains WHERE domain = ?", domain).Scan(&isWhitelisted)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return isWhitelisted, err
}

// IsIPWhitelisted checks if an IP is whitelisted
func IsIPWhitelisted(ip string) (bool, error) {
	var isWhitelisted bool
	err := db.QueryRow("SELECT is_whitelisted FROM ips WHERE ip_address = ?", ip).Scan(&isWhitelisted)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return isWhitelisted, err
}

// SaveDomain saves a domain to the database
func SaveDomain(domain string, expiration time.Duration) (int64, error) {
	// Check if domain already exists
	var id int64
	err := db.QueryRow("SELECT id FROM domains WHERE domain = ?", domain).Scan(&id)
	if err == nil {
		// Domain exists, update last_checked
		_, err = db.Exec("UPDATE domains SET last_checked = CURRENT_TIMESTAMP WHERE id = ?", id)
		return id, err
	} else if err != sql.ErrNoRows {
		return 0, err
	}

	// Calculate expiration time
	expiresAt := time.Now().Add(expiration)

	// Insert new domain
	result, err := db.Exec(
		"INSERT INTO domains (domain, expires_at, source, is_custom) VALUES (?, ?, ?, ?)",
		domain, expiresAt, "auto", false)
	if err != nil {
		return 0, err
	}

	return result.LastInsertId()
}

// AddIPWithRotation adds an IP with rotation mechanism
func AddIPWithRotation(domainID int64, ip string, maxIPsPerDomain int) error {
	// Check if IP already exists
	var id int64
	err := db.QueryRow("SELECT id FROM ips WHERE ip_address = ?", ip).Scan(&id)
	if err == nil {
		// IP exists, update domain_id
		_, err = db.Exec("UPDATE ips SET domain_id = ? WHERE id = ?", domainID, id)
		return err
	} else if err != sql.ErrNoRows {
		return err
	}

	// Check current IP count
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM ips WHERE domain_id = ? AND is_custom = 0", domainID).Scan(&count)
	if err != nil {
		return err
	}

	// If max IPs reached, remove oldest
	if count >= maxIPsPerDomain {
		_, err := db.Exec(`
            DELETE FROM ips
            WHERE id = (
                SELECT id FROM ips
                WHERE domain_id = ? AND is_custom = 0
                ORDER BY added_at ASC LIMIT 1
            )
        `, domainID)
		if err != nil {
			return err
		}
	}

	// Add new IP
	_, err = db.Exec(
		"INSERT INTO ips (ip_address, domain_id, source, is_custom) VALUES (?, ?, ?, ?)",
		ip, domainID, "auto", false)
	return err
}

// CheckForCDN checks if a domain might be a CDN
func CheckForCDN(domainID int64, maxIPsPerDomain int) (bool, error) {
	// Count unique IPs for domain
	var count int
	err := db.QueryRow("SELECT COUNT(DISTINCT ip_address) FROM ips WHERE domain_id = ?", domainID).Scan(&count)
	if err != nil {
		return false, err
	}

	isCDN := count > maxIPsPerDomain
	if isCDN {
		// Update domain status in database
		_, err := db.Exec("UPDATE domains SET flagged_as_cdn = 1 WHERE id = ?", domainID)
		if err != nil {
			return true, err
		}
	}

	return isCDN, nil
}

// CleanupExpiredRecords removes expired records
func CleanupExpiredRecords() error {
	// Delete expired domains
	_, err := db.Exec("DELETE FROM domains WHERE expires_at < CURRENT_TIMESTAMP AND is_custom = 0")
	if err != nil {
		return err
	}

	// Delete expired IPs
	_, err = db.Exec("DELETE FROM ips WHERE expires_at < CURRENT_TIMESTAMP AND is_custom = 0")
	if err != nil {
		return err
	}

	// Optimize database
	_, err = db.Exec("VACUUM")
	return err
}

// LogAgentStart logs the start of an agent run
func LogAgentStart() (int64, error) {
	result, err := db.Exec("INSERT INTO agent_runs DEFAULT VALUES")
	if err != nil {
		return 0, err
	}

	return result.LastInsertId()
}

// LogAgentCompletion logs the completion of an agent run
func LogAgentCompletion(runID int64) error {
	// Count processed domains and blocked IPs
	var domainsProcessed, ipsBlocked int
	err := db.QueryRow("SELECT COUNT(*) FROM agent_logs WHERE run_id = ? AND action_type = 'process'", runID).Scan(&domainsProcessed)
	if err != nil {
		return err
	}

	err = db.QueryRow("SELECT COUNT(*) FROM agent_logs WHERE run_id = ? AND action_type = 'block'", runID).Scan(&ipsBlocked)
	if err != nil {
		return err
	}

	// Update agent run record
	_, err = db.Exec(
		"UPDATE agent_runs SET completed_at = CURRENT_TIMESTAMP, status = 'completed', domains_processed = ?, ips_blocked = ? WHERE id = ?",
		domainsProcessed, ipsBlocked, runID)
	return err
}

// LogAgentError logs an error during an agent run
func LogAgentError(runID int64, err error) error {
	_, dbErr := db.Exec(
		"UPDATE agent_runs SET completed_at = CURRENT_TIMESTAMP, status = 'error', error_message = ? WHERE id = ?",
		err.Error(), runID)
	return dbErr
}

// LogAction logs an action performed by the agent
func LogAction(runID int64, actionType string, target string, result string, details string) error {
	_, err := db.Exec(
		"INSERT INTO agent_logs (run_id, action_type, target, result, details) VALUES (?, ?, ?, ?, ?)",
		runID, actionType, target, result, details)
	return err
}

// GetDomainsCount returns the count of blocked and whitelisted domains
func GetDomainsCount() (models.DomainStats, error) {
	var stats models.DomainStats
	err := db.QueryRow("SELECT COUNT(*) FROM domains WHERE is_whitelisted = 0").Scan(&stats.Blocked)
	if err != nil {
		return stats, err
	}

	err = db.QueryRow("SELECT COUNT(*) FROM domains WHERE is_whitelisted = 1").Scan(&stats.Whitelisted)
	return stats, err
}

// GetIPsCount returns the count of blocked and whitelisted IPs
func GetIPsCount() (models.IPStats, error) {
	var stats models.IPStats
	err := db.QueryRow("SELECT COUNT(*) FROM ips WHERE is_whitelisted = 0").Scan(&stats.Blocked)
	if err != nil {
		return stats, err
	}

	err = db.QueryRow("SELECT COUNT(*) FROM ips WHERE is_whitelisted = 1").Scan(&stats.Whitelisted)
	return stats, err
}

// GetLastRunInfo gets information about the last agent run
func GetLastRunInfo() (models.AgentRun, error) {
	var run models.AgentRun
	err := db.QueryRow(`
        SELECT id, started_at, completed_at, domains_processed, ips_blocked, status, error_message
        FROM agent_runs
        ORDER BY started_at DESC
        LIMIT 1
    `).Scan(&run.ID, &run.StartedAt, &run.CompletedAt, &run.DomainsProcessed, &run.IPsBlocked, &run.Status, &run.ErrorMessage)

	return run, err
}
