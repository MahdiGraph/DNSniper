package database

import (
	"database/sql"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Store provides database operations
type Store struct {
	db       *sql.DB
	migrator *MigrationRunner
}

// NewStore creates a new database store
func NewStore(dbPath string) (*Store, error) {
	// Create directory if it doesn't exist
	dbDir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	// Open database connection
	db, err := sql.Open("sqlite3", dbPath+"?_journal=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure database
	db.SetMaxOpenConns(1)

	// Create store
	store := &Store{
		db:       db,
		migrator: NewMigrationRunner(db),
	}

	// Run migrations
	if err := store.migrator.Run(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	return store, nil
}

// Close closes the database connection
func (s *Store) Close() error {
	return s.db.Close()
}

// CleanupExpired removes expired records
func (s *Store) CleanupExpired() error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	// Delete expired domains
	_, err = tx.Exec(`
        DELETE FROM domains 
        WHERE expires_at IS NOT NULL 
        AND expires_at < datetime('now') 
        AND is_custom = 0
    `)
	if err != nil {
		return fmt.Errorf("failed to delete expired domains: %w", err)
	}

	// Delete expired IPs
	_, err = tx.Exec(`
        DELETE FROM ips 
        WHERE expires_at IS NOT NULL 
        AND expires_at < datetime('now') 
        AND is_custom = 0
    `)
	if err != nil {
		return fmt.Errorf("failed to delete expired IPs: %w", err)
	}

	// Delete expired IP ranges
	_, err = tx.Exec(`
        DELETE FROM ip_ranges 
        WHERE expires_at IS NOT NULL 
        AND expires_at < datetime('now') 
        AND is_custom = 0
    `)
	if err != nil {
		return fmt.Errorf("failed to delete expired IP ranges: %w", err)
	}

	// Optimize database occasionally
	_, err = tx.Exec("PRAGMA optimize")
	if err != nil {
		return fmt.Errorf("failed to optimize database: %w", err)
	}

	return tx.Commit()
}

// Domain methods

// SaveDomain saves a domain to the database
func (s *Store) SaveDomain(domain string, isWhitelist bool, isCustom bool, expiration time.Duration) (int64, error) {
	// Normalize domain
	domain = strings.ToLower(strings.TrimSpace(domain))

	// Check if domain already exists
	var id int64
	var existingWhitelist bool
	err := s.db.QueryRow(
		"SELECT id, is_whitelisted FROM domains WHERE domain = ?",
		domain,
	).Scan(&id, &existingWhitelist)

	if err == nil {
		// Domain exists
		if existingWhitelist == isWhitelist {
			// Just update expiration if not custom
			if !isCustom {
				var expiresAt interface{} = nil
				if expiration > 0 {
					expiresAt = time.Now().Add(expiration)
				}
				_, err := s.db.Exec(
					"UPDATE domains SET last_checked = CURRENT_TIMESTAMP, expires_at = ?, is_custom = ? WHERE id = ?",
					expiresAt, isCustom, id,
				)
				return id, err
			}
			return id, nil
		}

		// Update whitelist status
		_, err := s.db.Exec(
			"UPDATE domains SET is_whitelisted = ?, is_custom = ?, expires_at = NULL WHERE id = ?",
			isWhitelist, isCustom, id,
		)
		return id, err
	} else if err != sql.ErrNoRows {
		return 0, err
	}

	// Insert new domain
	var expiresAt interface{} = nil
	if !isCustom && expiration > 0 {
		expiresAt = time.Now().Add(expiration)
	}

	result, err := s.db.Exec(
		"INSERT INTO domains (domain, is_whitelisted, is_custom, expires_at) VALUES (?, ?, ?, ?)",
		domain, isWhitelist, isCustom, expiresAt,
	)
	if err != nil {
		return 0, err
	}

	return result.LastInsertId()
}

// GetDomain gets a domain by name
func (s *Store) GetDomain(domainName string) (*Domain, error) {
	domain := &Domain{}
	err := s.db.QueryRow(`
        SELECT id, domain, is_whitelisted, is_custom, flagged_as_cdn, 
               added_at, expires_at, source, last_checked 
        FROM domains 
        WHERE domain = ?
    `, domainName).Scan(
		&domain.ID, &domain.Domain, &domain.IsWhitelisted,
		&domain.IsCustom, &domain.FlaggedAsCDN, &domain.AddedAt,
		&domain.ExpiresAt, &domain.Source, &domain.LastChecked,
	)
	if err != nil {
		return nil, err
	}
	return domain, nil
}

// IsDomainWhitelisted checks if a domain is whitelisted
func (s *Store) IsDomainWhitelisted(domain string) (bool, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	var isWhitelisted bool
	err := s.db.QueryRow(
		"SELECT is_whitelisted FROM domains WHERE domain = ?",
		domain,
	).Scan(&isWhitelisted)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return isWhitelisted, err
}

// RemoveDomain removes a domain from the database
func (s *Store) RemoveDomain(domainID int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	// Remove associated IPs
	_, err = tx.Exec("DELETE FROM ips WHERE domain_id = ?", domainID)
	if err != nil {
		return err
	}

	// Remove domain
	_, err = tx.Exec("DELETE FROM domains WHERE id = ?", domainID)
	if err != nil {
		return err
	}

	return tx.Commit()
}

// GetDomains gets domains with pagination
func (s *Store) GetDomains(isWhitelist bool, page, perPage int, sortBy string) ([]Domain, int, error) {
	// Validate sort field
	orderBy := "is_custom DESC, added_at DESC" // default
	switch sortBy {
	case "name":
		orderBy = "domain ASC"
	case "date":
		orderBy = "added_at DESC"
	}

	// Get total count
	var total int
	err := s.db.QueryRow(
		"SELECT COUNT(*) FROM domains WHERE is_whitelisted = ?",
		isWhitelist,
	).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	// Calculate pagination
	offset := (page - 1) * perPage
	if offset < 0 {
		offset = 0
	}

	// Get domains
	query := fmt.Sprintf(`
        SELECT id, domain, is_whitelisted, is_custom, flagged_as_cdn, 
               added_at, expires_at, source, last_checked 
        FROM domains 
        WHERE is_whitelisted = ? 
        ORDER BY %s
        LIMIT ? OFFSET ?
    `, orderBy)

	rows, err := s.db.Query(query, isWhitelist, perPage, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var domains []Domain
	for rows.Next() {
		var d Domain
		err := rows.Scan(
			&d.ID, &d.Domain, &d.IsWhitelisted, &d.IsCustom,
			&d.FlaggedAsCDN, &d.AddedAt, &d.ExpiresAt, &d.Source,
			&d.LastChecked,
		)
		if err != nil {
			return nil, 0, err
		}
		domains = append(domains, d)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	return domains, total, nil
}

// IP methods

// SaveIP saves an IP to the database
func (s *Store) SaveIP(ipAddress string, isWhitelist bool, isCustom bool, domainID sql.NullInt64, expiration time.Duration) (int64, error) {
	// Check if IP already exists
	var id int64
	var existingWhitelist bool
	err := s.db.QueryRow(
		"SELECT id, is_whitelisted FROM ips WHERE ip_address = ?",
		ipAddress,
	).Scan(&id, &existingWhitelist)

	if err == nil {
		// IP exists
		if existingWhitelist == isWhitelist {
			// Just update domain and expiration
			var expiresAt interface{} = nil
			if !isCustom && expiration > 0 {
				expiresAt = time.Now().Add(expiration)
			}
			_, err := s.db.Exec(
				"UPDATE ips SET domain_id = ?, last_checked = CURRENT_TIMESTAMP, expires_at = ?, is_custom = ? WHERE id = ?",
				domainID, expiresAt, isCustom, id,
			)
			return id, err
		}

		// Update whitelist status
		_, err := s.db.Exec(
			"UPDATE ips SET is_whitelisted = ?, domain_id = ?, is_custom = ?, expires_at = NULL WHERE id = ?",
			isWhitelist, domainID, isCustom, id,
		)
		return id, err
	} else if err != sql.ErrNoRows {
		return 0, err
	}

	// Insert new IP
	var expiresAt interface{} = nil
	if !isCustom && expiration > 0 {
		expiresAt = time.Now().Add(expiration)
	}

	result, err := s.db.Exec(
		"INSERT INTO ips (ip_address, is_whitelisted, is_custom, domain_id, expires_at) VALUES (?, ?, ?, ?, ?)",
		ipAddress, isWhitelist, isCustom, domainID, expiresAt,
	)
	if err != nil {
		return 0, err
	}

	return result.LastInsertId()
}

// GetIPsForDomain gets all IPs associated with a domain
func (s *Store) GetIPsForDomain(domainID int64) ([]IP, error) {
	rows, err := s.db.Query(`
        SELECT id, ip_address, is_whitelisted, is_custom, 
               added_at, expires_at, source, domain_id, last_checked 
        FROM ips 
        WHERE domain_id = ?
    `, domainID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ips []IP
	for rows.Next() {
		var ip IP
		err := rows.Scan(
			&ip.ID, &ip.IPAddress, &ip.IsWhitelisted, &ip.IsCustom,
			&ip.AddedAt, &ip.ExpiresAt, &ip.Source, &ip.DomainID,
			&ip.LastChecked,
		)
		if err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return ips, nil
}

// IsIPWhitelisted checks if an IP is whitelisted
func (s *Store) IsIPWhitelisted(ipAddress string) (bool, error) {
	// First check direct IP whitelist
	var count int
	err := s.db.QueryRow(
		"SELECT COUNT(*) FROM ips WHERE ip_address = ? AND is_whitelisted = 1",
		ipAddress,
	).Scan(&count)
	if err != nil {
		return false, err
	}
	if count > 0 {
		return true, nil
	}

	// Check if IP falls within a whitelisted range
	parsedIP := net.ParseIP(ipAddress)
	if parsedIP == nil {
		return false, fmt.Errorf("invalid IP address: %s", ipAddress)
	}

	rows, err := s.db.Query("SELECT cidr FROM ip_ranges WHERE is_whitelisted = 1")
	if err != nil {
		return false, err
	}
	defer rows.Close()

	for rows.Next() {
		var cidr string
		if err := rows.Scan(&cidr); err != nil {
			return false, err
		}

		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}

		if ipNet.Contains(parsedIP) {
			return true, nil
		}
	}
	if err := rows.Err(); err != nil {
		return false, err
	}

	return false, nil
}

// IsIPBlocked checks if an IP is blocked
func (s *Store) IsIPBlocked(ipAddress string) (bool, error) {
	// First check if IP is whitelisted
	isWhitelisted, err := s.IsIPWhitelisted(ipAddress)
	if err != nil {
		return false, err
	}
	if isWhitelisted {
		return false, nil
	}

	// Check direct IP blocklist
	var count int
	err = s.db.QueryRow(
		"SELECT COUNT(*) FROM ips WHERE ip_address = ? AND is_whitelisted = 0",
		ipAddress,
	).Scan(&count)
	if err != nil {
		return false, err
	}
	if count > 0 {
		return true, nil
	}

	// Check if IP falls within a blocked range
	parsedIP := net.ParseIP(ipAddress)
	if parsedIP == nil {
		return false, fmt.Errorf("invalid IP address: %s", ipAddress)
	}

	rows, err := s.db.Query("SELECT cidr FROM ip_ranges WHERE is_whitelisted = 0")
	if err != nil {
		return false, err
	}
	defer rows.Close()

	for rows.Next() {
		var cidr string
		if err := rows.Scan(&cidr); err != nil {
			return false, err
		}

		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}

		if ipNet.Contains(parsedIP) {
			return true, nil
		}
	}
	if err := rows.Err(); err != nil {
		return false, err
	}

	return false, nil
}

// RemoveIP removes an IP from the database
func (s *Store) RemoveIP(ipID int64) error {
	_, err := s.db.Exec("DELETE FROM ips WHERE id = ?", ipID)
	return err
}

// AddIPWithRotation adds an IP with rotation mechanism
func (s *Store) AddIPWithRotation(domainID int64, ipAddress string, maxIPsPerDomain int, expiration time.Duration) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	// Check if domain is custom
	var isCustomDomain bool
	err = tx.QueryRow("SELECT is_custom FROM domains WHERE id = ?", domainID).Scan(&isCustomDomain)
	if err != nil {
		return err
	}

	// Check if IP already exists
	var ipID int64
	var isCustomIP bool
	err = tx.QueryRow(
		"SELECT id, is_custom FROM ips WHERE ip_address = ?",
		ipAddress,
	).Scan(&ipID, &isCustomIP)

	if err == nil {
		// IP exists, just update domain and expiration
		if isCustomIP {
			// Don't modify custom IPs
			return nil
		}

		var expiresAt interface{} = nil
		if !isCustomDomain && expiration > 0 {
			expiresAt = time.Now().Add(expiration)
		}

		_, err = tx.Exec(
			"UPDATE ips SET domain_id = ?, last_checked = CURRENT_TIMESTAMP, expires_at = ? WHERE id = ?",
			domainID, expiresAt, ipID,
		)
		if err != nil {
			return err
		}
	} else if err != sql.ErrNoRows {
		return err
	} else {
		// Count existing IPs for this domain
		var ipCount int
		err = tx.QueryRow(
			"SELECT COUNT(*) FROM ips WHERE domain_id = ? AND is_custom = 0",
			domainID,
		).Scan(&ipCount)
		if err != nil {
			return err
		}

		// If max IPs reached, remove oldest IPs
		if ipCount >= maxIPsPerDomain {
			// Find oldest IPs to remove
			rows, err := tx.Query(`
                SELECT id FROM ips 
                WHERE domain_id = ? AND is_custom = 0 
                ORDER BY added_at ASC 
                LIMIT ?
            `, domainID, ipCount-(maxIPsPerDomain-1))
			if err != nil {
				return err
			}
			defer rows.Close()

			var idsToRemove []int64
			for rows.Next() {
				var id int64
				if err := rows.Scan(&id); err != nil {
					return err
				}
				idsToRemove = append(idsToRemove, id)
			}
			if err := rows.Err(); err != nil {
				return err
			}

			// Remove oldest IPs
			for _, id := range idsToRemove {
				_, err := tx.Exec("DELETE FROM ips WHERE id = ?", id)
				if err != nil {
					return err
				}
			}
		}

		// Add new IP
		var expiresAt interface{} = nil
		if !isCustomDomain && expiration > 0 {
			expiresAt = time.Now().Add(expiration)
		}

		_, err = tx.Exec(`
            INSERT INTO ips (ip_address, is_whitelisted, is_custom, domain_id, expires_at) 
            VALUES (?, 0, ?, ?, ?)
        `, ipAddress, isCustomDomain, domainID, expiresAt)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// IP Range methods

// SaveIPRange saves an IP range to the database
func (s *Store) SaveIPRange(cidr string, isWhitelist bool, isCustom bool, expiration time.Duration) (int64, error) {
	// Validate CIDR
	_, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, fmt.Errorf("invalid CIDR: %w", err)
	}

	// Check if range already exists
	var id int64
	var existingWhitelist bool
	err = s.db.QueryRow(
		"SELECT id, is_whitelisted FROM ip_ranges WHERE cidr = ?",
		cidr,
	).Scan(&id, &existingWhitelist)

	if err == nil {
		// Range exists
		if existingWhitelist == isWhitelist {
			// Just update expiration
			var expiresAt interface{} = nil
			if !isCustom && expiration > 0 {
				expiresAt = time.Now().Add(expiration)
			}
			_, err := s.db.Exec(
				"UPDATE ip_ranges SET expires_at = ?, is_custom = ? WHERE id = ?",
				expiresAt, isCustom, id,
			)
			return id, err
		}

		// Update whitelist status
		_, err := s.db.Exec(
			"UPDATE ip_ranges SET is_whitelisted = ?, is_custom = ?, expires_at = NULL WHERE id = ?",
			isWhitelist, isCustom, id,
		)
		return id, err
	} else if err != sql.ErrNoRows {
		return 0, err
	}

	// Insert new range
	var expiresAt interface{} = nil
	if !isCustom && expiration > 0 {
		expiresAt = time.Now().Add(expiration)
	}

	result, err := s.db.Exec(
		"INSERT INTO ip_ranges (cidr, is_whitelisted, is_custom, expires_at) VALUES (?, ?, ?, ?)",
		cidr, isWhitelist, isCustom, expiresAt,
	)
	if err != nil {
		return 0, err
	}

	return result.LastInsertId()
}

// RemoveIPRange removes an IP range from the database
func (s *Store) RemoveIPRange(rangeID int64) error {
	_, err := s.db.Exec("DELETE FROM ip_ranges WHERE id = ?", rangeID)
	return err
}

// GetAllBlockedIPs gets all IPs and IP ranges that should be blocked
func (s *Store) GetAllBlockedIPs() ([]string, []string, error) {
	// Get individual IPs
	ipRows, err := s.db.Query(`
        SELECT ip.ip_address 
        FROM ips ip 
        WHERE ip.is_whitelisted = 0 
        AND NOT EXISTS (
            SELECT 1 FROM ips wip 
            WHERE wip.ip_address = ip.ip_address AND wip.is_whitelisted = 1
        )
    `)
	if err != nil {
		return nil, nil, err
	}
	defer ipRows.Close()

	var ips []string
	for ipRows.Next() {
		var ip string
		if err := ipRows.Scan(&ip); err != nil {
			return nil, nil, err
		}
		ips = append(ips, ip)
	}
	if err := ipRows.Err(); err != nil {
		return nil, nil, err
	}

	// Get IP ranges
	rangeRows, err := s.db.Query(`
        SELECT cidr 
        FROM ip_ranges 
        WHERE is_whitelisted = 0 
        AND NOT EXISTS (
            SELECT 1 FROM ip_ranges 
            WHERE is_whitelisted = 1 AND cidr = ip_ranges.cidr
        )
    `)
	if err != nil {
		return nil, nil, err
	}
	defer rangeRows.Close()

	var ranges []string
	for rangeRows.Next() {
		var cidr string
		if err := rangeRows.Scan(&cidr); err != nil {
			return nil, nil, err
		}
		ranges = append(ranges, cidr)
	}
	if err := rangeRows.Err(); err != nil {
		return nil, nil, err
	}

	return ips, ranges, nil
}

// GetAllWhitelistedIPs gets all IPs and IP ranges that are whitelisted
func (s *Store) GetAllWhitelistedIPs() ([]string, []string, error) {
	// Get individual IPs
	ipRows, err := s.db.Query("SELECT ip_address FROM ips WHERE is_whitelisted = 1")
	if err != nil {
		return nil, nil, err
	}
	defer ipRows.Close()

	var ips []string
	for ipRows.Next() {
		var ip string
		if err := ipRows.Scan(&ip); err != nil {
			return nil, nil, err
		}
		ips = append(ips, ip)
	}
	if err := ipRows.Err(); err != nil {
		return nil, nil, err
	}

	// Get IP ranges
	rangeRows, err := s.db.Query("SELECT cidr FROM ip_ranges WHERE is_whitelisted = 1")
	if err != nil {
		return nil, nil, err
	}
	defer rangeRows.Close()

	var ranges []string
	for rangeRows.Next() {
		var cidr string
		if err := rangeRows.Scan(&cidr); err != nil {
			return nil, nil, err
		}
		ranges = append(ranges, cidr)
	}
	if err := rangeRows.Err(); err != nil {
		return nil, nil, err
	}

	return ips, ranges, nil
}

// Agent run methods

// LogAgentStart logs the start of an agent run
func (s *Store) LogAgentStart() (int64, error) {
	result, err := s.db.Exec("INSERT INTO agent_runs DEFAULT VALUES")
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// LogAgentCompletion logs the completion of an agent run
func (s *Store) LogAgentCompletion(runID int64, domainsProcessed, ipsBlocked int) error {
	_, err := s.db.Exec(`
        UPDATE agent_runs 
        SET completed_at = CURRENT_TIMESTAMP, 
            status = 'completed', 
            domains_processed = ?, 
            ips_blocked = ? 
        WHERE id = ?
    `, domainsProcessed, ipsBlocked, runID)
	return err
}

// LogAgentError logs an error during an agent run
func (s *Store) LogAgentError(runID int64, errMsg string) error {
	_, err := s.db.Exec(`
        UPDATE agent_runs 
        SET completed_at = CURRENT_TIMESTAMP, 
            status = 'error', 
            error_message = ? 
        WHERE id = ?
    `, errMsg, runID)
	return err
}

// LogAction logs an action performed by the agent
func (s *Store) LogAction(runID int64, actionType, target, result, details string) error {
	_, err := s.db.Exec(`
        INSERT INTO agent_logs (run_id, action_type, target, result, details) 
        VALUES (?, ?, ?, ?, ?)
    `, runID, actionType, target, result, details)
	return err
}

// GetLastAgentRun gets information about the last agent run
func (s *Store) GetLastAgentRun() (*AgentRun, error) {
	var run AgentRun
	err := s.db.QueryRow(`
        SELECT id, started_at, completed_at, domains_processed, ips_blocked, status, error_message 
        FROM agent_runs 
        ORDER BY started_at DESC 
        LIMIT 1
    `).Scan(
		&run.ID, &run.StartedAt, &run.CompletedAt,
		&run.DomainsProcessed, &run.IPsBlocked, &run.Status, &run.ErrorMessage,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &run, nil
}

// Update URL methods

// GetUpdateURLs gets all update URLs
func (s *Store) GetUpdateURLs() ([]UpdateURL, error) {
	rows, err := s.db.Query(`
        SELECT id, url, added_at, last_used, enabled 
        FROM update_urls 
        WHERE enabled = 1
    `)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var urls []UpdateURL
	for rows.Next() {
		var u UpdateURL
		err := rows.Scan(&u.ID, &u.URL, &u.AddedAt, &u.LastUsed, &u.Enabled)
		if err != nil {
			return nil, err
		}
		urls = append(urls, u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return urls, nil
}

// AddUpdateURL adds a new update URL
func (s *Store) AddUpdateURL(url string) error {
	_, err := s.db.Exec("INSERT OR IGNORE INTO update_urls (url) VALUES (?)", url)
	return err
}

// RemoveUpdateURL removes an update URL
func (s *Store) RemoveUpdateURL(urlID int64) error {
	_, err := s.db.Exec("DELETE FROM update_urls WHERE id = ?", urlID)
	return err
}

// UpdateURLLastUsed updates the last_used timestamp for an update URL
func (s *Store) UpdateURLLastUsed(urlID int64) error {
	_, err := s.db.Exec(
		"UPDATE update_urls SET last_used = CURRENT_TIMESTAMP WHERE id = ?",
		urlID,
	)
	return err
}

// Statistics methods

// GetStatistics gets statistics for the dashboard
func (s *Store) GetStatistics() (*Statistics, error) {
	stats := &Statistics{}

	// Domain counts
	err := s.db.QueryRow("SELECT COUNT(*) FROM domains WHERE is_whitelisted = 0").Scan(&stats.BlockedDomainsCount)
	if err != nil {
		return nil, err
	}

	err = s.db.QueryRow("SELECT COUNT(*) FROM domains WHERE is_whitelisted = 1").Scan(&stats.WhitelistedDomains)
	if err != nil {
		return nil, err
	}

	// IP counts
	var blockedIPs, blockedRanges int
	err = s.db.QueryRow("SELECT COUNT(*) FROM ips WHERE is_whitelisted = 0").Scan(&blockedIPs)
	if err != nil {
		return nil, err
	}

	err = s.db.QueryRow("SELECT COUNT(*) FROM ip_ranges WHERE is_whitelisted = 0").Scan(&blockedRanges)
	if err != nil {
		return nil, err
	}
	stats.BlockedIPCount = blockedIPs + blockedRanges

	var whitelistedIPs, whitelistedRanges int
	err = s.db.QueryRow("SELECT COUNT(*) FROM ips WHERE is_whitelisted = 1").Scan(&whitelistedIPs)
	if err != nil {
		return nil, err
	}

	err = s.db.QueryRow("SELECT COUNT(*) FROM ip_ranges WHERE is_whitelisted = 1").Scan(&whitelistedRanges)
	if err != nil {
		return nil, err
	}
	stats.WhitelistedIPCount = whitelistedIPs + whitelistedRanges

	// Activity stats - last 24 hours
	err = s.db.QueryRow(`
        SELECT COUNT(DISTINCT domains.id) 
        FROM domains 
        JOIN agent_logs ON agent_logs.target = domains.domain 
        WHERE agent_logs.action_type = 'process' 
        AND agent_logs.timestamp > datetime('now', '-1 day')
    `).Scan(&stats.DomainsProcessed24h)
	if err != nil {
		stats.DomainsProcessed24h = 0 // Non-critical error
	}

	err = s.db.QueryRow(`
        SELECT COUNT(*) 
        FROM agent_logs 
        WHERE action_type = 'block' 
        AND timestamp > datetime('now', '-1 day')
    `).Scan(&stats.IPsBlocked24h)
	if err != nil {
		stats.IPsBlocked24h = 0 // Non-critical error
	}

	// Activity stats - last 7 days
	err = s.db.QueryRow(`
        SELECT COUNT(DISTINCT domains.id) 
        FROM domains 
        JOIN agent_logs ON agent_logs.target = domains.domain 
        WHERE agent_logs.action_type = 'process' 
        AND agent_logs.timestamp > datetime('now', '-7 days')
    `).Scan(&stats.DomainsProcessed7d)
	if err != nil {
		stats.DomainsProcessed7d = 0 // Non-critical error
	}

	err = s.db.QueryRow(`
        SELECT COUNT(*) 
        FROM agent_logs 
        WHERE action_type = 'block' 
        AND timestamp > datetime('now', '-7 days')
    `).Scan(&stats.IPsBlocked7d)
	if err != nil {
		stats.IPsBlocked7d = 0 // Non-critical error
	}

	// Get recently blocked domains
	rows, err := s.db.Query(`
        SELECT DISTINCT domains.domain 
        FROM domains 
        JOIN agent_logs ON agent_logs.target = domains.domain 
        WHERE agent_logs.action_type = 'block' 
        AND agent_logs.timestamp > datetime('now', '-7 days') 
        ORDER BY agent_logs.timestamp DESC 
        LIMIT 5
    `)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var domain string
			if err := rows.Scan(&domain); err != nil {
				continue
			}
			stats.RecentBlockedDomains = append(stats.RecentBlockedDomains, domain)
		}
	}

	// Get last run info
	lastRun, err := s.GetLastAgentRun()
	if err == nil && lastRun != nil {
		stats.LastRunTime = lastRun.CompletedAt
		stats.LastRunStatus = lastRun.Status
	}

	return stats, nil
}

// ExpireUnseenDomains updates expiration for domains not seen in current run
func (s *Store) ExpireUnseenDomains(runID int64) error {
	_, err := s.db.Exec(`
        UPDATE domains 
        SET expires_at = datetime('now', '+1 day') 
        WHERE is_custom = 0 
        AND expires_at > datetime('now', '+1 day') 
        AND id NOT IN (
            SELECT domain_id FROM ips 
            WHERE domain_id IS NOT NULL
            AND last_checked > (
                SELECT started_at FROM agent_runs WHERE id = ?
            )
        )
    `, runID)
	return err
}

// CheckForCDN determines if a domain might be a CDN based on number of IPs
func (s *Store) CheckForCDN(domainID int64, threshold int) (bool, error) {
	var ipCount int
	err := s.db.QueryRow(
		"SELECT COUNT(DISTINCT ip_address) FROM ips WHERE domain_id = ?",
		domainID,
	).Scan(&ipCount)
	if err != nil {
		return false, err
	}

	isCDN := ipCount >= threshold

	// Update domain if CDN status changed
	var currentlyCDN bool
	err = s.db.QueryRow(
		"SELECT flagged_as_cdn FROM domains WHERE id = ?",
		domainID,
	).Scan(&currentlyCDN)
	if err != nil {
		return false, err
	}

	if isCDN != currentlyCDN {
		_, err = s.db.Exec(
			"UPDATE domains SET flagged_as_cdn = ? WHERE id = ?",
			isCDN, domainID,
		)
		if err != nil {
			return isCDN, err
		}
	}

	return isCDN, nil
}
