package database

import (
	"database/sql"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
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

	// Create update_urls table
	_, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS update_urls (
            id INTEGER PRIMARY KEY,
            url TEXT NOT NULL UNIQUE,
            added_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_used TIMESTAMP NULL,
            enabled BOOLEAN NOT NULL DEFAULT 1
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
		"logging_enabled":    {"false", "Whether to enable logging"},
		"rule_expiration":    {"30d", "Expiration time for rules (e.g., 30d for 30 days)"},
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

	// Add default update URL if none exists
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM update_urls").Scan(&count)
	if err != nil {
		return err
	}

	if count == 0 {
		_, err = db.Exec("INSERT INTO update_urls (url) VALUES (?)",
			"https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/domains-default.txt")
		if err != nil {
			return err
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
func SaveDomain(domain string, expiration time.Duration, sourceURL string) (int64, error) {
	// Check if domain already exists
	var id int64
	var isCustom bool
	err := db.QueryRow("SELECT id, is_custom FROM domains WHERE domain = ?", domain).Scan(&id, &isCustom)

	if err == nil {
		// Domain exists, update last_checked and expires_at if not custom
		if !isCustom {
			expiresAt := time.Now().Add(expiration)
			_, err = db.Exec(
				"UPDATE domains SET last_checked = CURRENT_TIMESTAMP, expires_at = ?, source = ? WHERE id = ?",
				expiresAt, sourceURL, id)
		} else {
			// Just update last_checked for custom domains
			_, err = db.Exec("UPDATE domains SET last_checked = CURRENT_TIMESTAMP WHERE id = ?", id)
		}
		return id, err
	} else if err != sql.ErrNoRows {
		return 0, err
	}

	// Calculate expiration time for new domains
	expiresAt := time.Now().Add(expiration)

	// Insert new domain
	result, err := db.Exec(
		"INSERT INTO domains (domain, expires_at, source, is_custom) VALUES (?, ?, ?, ?)",
		domain, expiresAt, sourceURL, false)
	if err != nil {
		return 0, err
	}

	return result.LastInsertId()
}

// SaveCustomDomain saves a custom domain to the database
func SaveCustomDomain(domain string, isWhitelisted bool) (int64, error) {
	// Check if domain already exists
	var id int64
	err := db.QueryRow("SELECT id FROM domains WHERE domain = ?", domain).Scan(&id)

	if err == nil {
		// Domain exists, update it
		_, err = db.Exec(
			"UPDATE domains SET is_whitelisted = ?, is_custom = 1, source = 'custom', expires_at = NULL WHERE id = ?",
			isWhitelisted, id)
		return id, err
	} else if err != sql.ErrNoRows {
		return 0, err
	}

	// Insert new domain
	result, err := db.Exec(
		"INSERT INTO domains (domain, is_whitelisted, is_custom, source) VALUES (?, ?, 1, 'custom')",
		domain, isWhitelisted)
	if err != nil {
		return 0, err
	}

	return result.LastInsertId()
}

// RemoveDomain removes a domain from the database
func RemoveDomain(domain string, isWhitelisted bool) error {
	// Check if domain exists
	var id int64
	err := db.QueryRow(
		"SELECT id FROM domains WHERE domain = ? AND is_whitelisted = ?",
		domain, isWhitelisted).Scan(&id)

	if err == sql.ErrNoRows {
		return fmt.Errorf("domain not found: %s", domain)
	} else if err != nil {
		return err
	}

	// Delete domain's IPs first (to maintain referential integrity)
	_, err = db.Exec("DELETE FROM ips WHERE domain_id = ?", id)
	if err != nil {
		return err
	}

	// Delete the domain
	_, err = db.Exec("DELETE FROM domains WHERE id = ?", id)
	return err
}

// AddIPWithRotation adds an IP with rotation mechanism
func AddIPWithRotation(domainID int64, ip string, maxIPsPerDomain int, expiration time.Duration) error {
	// Check if IP already exists
	var id int64
	var isCustom bool
	err := db.QueryRow("SELECT id, is_custom FROM ips WHERE ip_address = ?", ip).Scan(&id, &isCustom)

	if err == nil {
		// IP exists
		if isCustom {
			// Don't update custom IPs
			return nil
		}

		// Update expiration for auto IPs
		expiresAt := time.Now().Add(expiration)
		_, err = db.Exec(
			"UPDATE ips SET domain_id = ?, expires_at = ? WHERE id = ?",
			domainID, expiresAt, id)
		return err
	} else if err != sql.ErrNoRows {
		return err
	}

	// Check current IP count for this domain
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

	// Calculate expiration time
	expiresAt := time.Now().Add(expiration)

	// Add new IP
	_, err = db.Exec(
		"INSERT INTO ips (ip_address, domain_id, source, is_custom, expires_at) VALUES (?, ?, 'auto', 0, ?)",
		ip, domainID, expiresAt)

	return err
}

// SaveCustomIP saves a custom IP to the database
func SaveCustomIP(ip string, isWhitelisted bool) error {
	// Check if IP already exists
	var id int64
	err := db.QueryRow("SELECT id FROM ips WHERE ip_address = ?", ip).Scan(&id)

	if err == nil {
		// IP exists, update it
		_, err = db.Exec(
			"UPDATE ips SET is_whitelisted = ?, is_custom = 1, source = 'custom', expires_at = NULL WHERE id = ?",
			isWhitelisted, id)
		return err
	} else if err != sql.ErrNoRows {
		return err
	}

	// Insert new IP
	_, err = db.Exec(
		"INSERT INTO ips (ip_address, is_whitelisted, is_custom, source) VALUES (?, ?, 1, 'custom')",
		ip, isWhitelisted)

	return err
}

// RemoveIP removes an IP from the database
func RemoveIP(ip string, isWhitelisted bool) error {
	result, err := db.Exec(
		"DELETE FROM ips WHERE ip_address = ? AND is_whitelisted = ?",
		ip, isWhitelisted)
	if err != nil {
		return err
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if affected == 0 {
		return fmt.Errorf("IP not found: %s", ip)
	}

	return nil
}

// CheckForCDN checks if a domain might be a CDN
func CheckForCDN(domainID int64, maxIPsPerDomain int) (bool, error) {
	// Count unique IPs for domain
	var count int
	err := db.QueryRow("SELECT COUNT(DISTINCT ip_address) FROM ips WHERE domain_id = ?", domainID).Scan(&count)
	if err != nil {
		return false, err
	}

	isCDN := count >= maxIPsPerDomain
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
	// Get IPs to unblock first
	rows, err := db.Query("SELECT ip_address FROM ips WHERE expires_at < CURRENT_TIMESTAMP AND is_custom = 0")
	if err != nil {
		return err
	}
	defer rows.Close()

	var expiredIPs []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return err
		}
		expiredIPs = append(expiredIPs, ip)
	}

	if err := rows.Err(); err != nil {
		return err
	}

	// Delete expired domains
	_, err = db.Exec("DELETE FROM domains WHERE expires_at < CURRENT_TIMESTAMP AND is_custom = 0")
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

// GetDomainsList returns a paginated list of domains
func GetDomainsList(isWhitelisted bool, page, itemsPerPage int) ([]models.Domain, int, error) {
	// Calculate offset
	offset := (page - 1) * itemsPerPage

	// Get total count
	var totalCount int
	err := db.QueryRow("SELECT COUNT(*) FROM domains WHERE is_whitelisted = ?", isWhitelisted).Scan(&totalCount)
	if err != nil {
		return nil, 0, err
	}

	// Get domains for current page
	rows, err := db.Query(`
        SELECT id, domain, is_whitelisted, is_custom, flagged_as_cdn, added_at, expires_at, source, last_checked 
        FROM domains 
        WHERE is_whitelisted = ? 
        ORDER BY added_at DESC 
        LIMIT ? OFFSET ?
    `, isWhitelisted, itemsPerPage, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	// Parse rows
	var domains []models.Domain
	for rows.Next() {
		var domain models.Domain
		if err := rows.Scan(
			&domain.ID, &domain.Domain, &domain.IsWhitelisted,
			&domain.IsCustom, &domain.FlaggedAsCDN, &domain.AddedAt,
			&domain.ExpiresAt, &domain.Source, &domain.LastChecked); err != nil {
			return nil, 0, err
		}
		domains = append(domains, domain)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	return domains, totalCount, nil
}

// GetIPsList returns a paginated list of IPs
func GetIPsList(isWhitelisted bool, page, itemsPerPage int) ([]models.IP, int, error) {
	// Calculate offset
	offset := (page - 1) * itemsPerPage

	// Get total count
	var totalCount int
	err := db.QueryRow("SELECT COUNT(*) FROM ips WHERE is_whitelisted = ?", isWhitelisted).Scan(&totalCount)
	if err != nil {
		return nil, 0, err
	}

	// Get IPs for current page
	rows, err := db.Query(`
        SELECT id, ip_address, is_whitelisted, is_custom, added_at, expires_at, source, domain_id 
        FROM ips 
        WHERE is_whitelisted = ? 
        ORDER BY added_at DESC 
        LIMIT ? OFFSET ?
    `, isWhitelisted, itemsPerPage, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	// Parse rows
	var ips []models.IP
	for rows.Next() {
		var ip models.IP
		if err := rows.Scan(
			&ip.ID, &ip.IPAddress, &ip.IsWhitelisted,
			&ip.IsCustom, &ip.AddedAt, &ip.ExpiresAt,
			&ip.Source, &ip.DomainID); err != nil {
			return nil, 0, err
		}
		ips = append(ips, ip)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	return ips, totalCount, nil
}

// GetAllBlockedIPs returns all non-whitelisted IPs
func GetAllBlockedIPs() ([]string, error) {
	rows, err := db.Query("SELECT ip_address FROM ips WHERE is_whitelisted = 0")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return ips, nil
}

// IsValidIP checks if the provided string is a valid IP address
func IsValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// GetUpdateURLs returns all update URLs
func GetUpdateURLs() ([]string, error) {
	rows, err := db.Query("SELECT url FROM update_urls WHERE enabled = 1")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var urls []string
	for rows.Next() {
		var url string
		if err := rows.Scan(&url); err != nil {
			return nil, err
		}
		urls = append(urls, url)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return urls, nil
}

// AddUpdateURL adds a new update URL
func AddUpdateURL(url string) error {
	_, err := db.Exec("INSERT OR IGNORE INTO update_urls (url) VALUES (?)", url)
	return err
}

// RemoveUpdateURL removes an update URL
func RemoveUpdateURL(url string) error {
	result, err := db.Exec("DELETE FROM update_urls WHERE url = ?", url)
	if err != nil {
		return err
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if affected == 0 {
		return fmt.Errorf("URL not found: %s", url)
	}

	return nil
}

// ExpireUnseenDomains updates expiration for domains not seen in current run
func ExpireUnseenDomains(seenDomains map[string]bool) error {
	// Get all non-custom domains
	rows, err := db.Query("SELECT id, domain FROM domains WHERE is_custom = 0")
	if err != nil {
		return err
	}
	defer rows.Close()

	// Collect domains that were not seen
	var unseenDomainIDs []int64
	for rows.Next() {
		var id int64
		var domain string
		if err := rows.Scan(&id, &domain); err != nil {
			return err
		}

		if !seenDomains[domain] {
			unseenDomainIDs = append(unseenDomainIDs, id)
		}
	}

	if err := rows.Err(); err != nil {
		return err
	}

	// Update expiration for unseen domains if needed
	if len(unseenDomainIDs) > 0 {
		// Prepare a query with placeholders for all domain IDs
		placeholders := make([]string, len(unseenDomainIDs))
		args := make([]interface{}, len(unseenDomainIDs))

		for i, id := range unseenDomainIDs {
			placeholders[i] = "?"
			args[i] = id
		}

		// Execute update - shorten expiration time for unseen domains
		query := fmt.Sprintf(
			"UPDATE domains SET expires_at = datetime('now', '+1 day') WHERE id IN (%s) AND expires_at > datetime('now', '+1 day')",
			strings.Join(placeholders, ","))

		_, err = db.Exec(query, args...)
		if err != nil {
			return err
		}
	}

	return nil
}

// GetStatistics returns statistics for the dashboard
func GetStatistics() (*models.Statistics, error) {
	stats := &models.Statistics{}

	// Get counts for last 24 hours
	err := db.QueryRow(`
        SELECT COUNT(DISTINCT target) FROM agent_logs 
        WHERE action_type = 'process' AND timestamp > datetime('now', '-1 day')
    `).Scan(&stats.DomainsProcessed24h)
	if err != nil {
		return nil, err
	}

	err = db.QueryRow(`
        SELECT COUNT(*) FROM agent_logs 
        WHERE action_type = 'block' AND timestamp > datetime('now', '-1 day')
    `).Scan(&stats.IPsBlocked24h)
	if err != nil {
		return nil, err
	}

	// Get counts for last 7 days
	err = db.QueryRow(`
        SELECT COUNT(DISTINCT target) FROM agent_logs 
        WHERE action_type = 'process' AND timestamp > datetime('now', '-7 days')
    `).Scan(&stats.DomainsProcessed7d)
	if err != nil {
		return nil, err
	}

	err = db.QueryRow(`
        SELECT COUNT(*) FROM agent_logs 
        WHERE action_type = 'block' AND timestamp > datetime('now', '-7 days')
    `).Scan(&stats.IPsBlocked7d)
	if err != nil {
		return nil, err
	}

	// Get recent blocked domains
	rows, err := db.Query(`
        SELECT DISTINCT d.domain FROM domains d
        JOIN ips i ON d.id = i.domain_id
        WHERE d.is_whitelisted = 0 AND i.is_whitelisted = 0
        ORDER BY d.added_at DESC LIMIT 10
    `)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return nil, err
		}
		stats.RecentBlockedDomains = append(stats.RecentBlockedDomains, domain)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return stats, nil
}
