package database

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// GormStore provides database operations using GORM
type GormStore struct {
	db *gorm.DB
}

// NewGormStore creates a new GORM-based database store
func NewGormStore(dbPath string) (*GormStore, error) {
	// Create directory if it doesn't exist
	dbDir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	// Configure GORM with SQLite
	config := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent), // Reduce log noise
	}

	db, err := gorm.Open(sqlite.Open(dbPath+"?_journal=WAL&_busy_timeout=5000"), config)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Get underlying SQL DB for configuration
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get underlying SQL DB: %w", err)
	}

	// Configure connection pool
	sqlDB.SetMaxOpenConns(1)

	store := &GormStore{db: db}

	// Run auto-migration
	if err := store.migrate(); err != nil {
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	return store, nil
}

// migrate runs auto-migration for all models
func (s *GormStore) migrate() error {
	return s.db.AutoMigrate(
		&Domain{},
		&IP{},
		&IPRange{},
		&AgentRun{},
		&AgentLog{},
		&UpdateURL{},
	)
}

// Close closes the database connection
func (s *GormStore) Close() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// CleanupExpired removes expired records
func (s *GormStore) CleanupExpired() error {
	now := time.Now()

	// Delete expired domains (only non-custom ones)
	if err := s.db.Where("expires_at IS NOT NULL AND expires_at < ? AND is_custom = ?", now, false).Delete(&Domain{}).Error; err != nil {
		return fmt.Errorf("failed to delete expired domains: %w", err)
	}

	// Delete expired IPs (only non-custom ones)
	if err := s.db.Where("expires_at IS NOT NULL AND expires_at < ? AND is_custom = ?", now, false).Delete(&IP{}).Error; err != nil {
		return fmt.Errorf("failed to delete expired IPs: %w", err)
	}

	// Delete expired IP ranges (only non-custom ones)
	if err := s.db.Where("expires_at IS NOT NULL AND expires_at < ? AND is_custom = ?", now, false).Delete(&IPRange{}).Error; err != nil {
		return fmt.Errorf("failed to delete expired IP ranges: %w", err)
	}

	return nil
}

// Domain methods

// SaveDomain saves a domain to the database
func (s *GormStore) SaveDomain(domain string, isWhitelist bool, isCustom bool, expiration time.Duration) (uint, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))

	var existingDomain Domain
	result := s.db.Where("domain = ?", domain).First(&existingDomain)

	if result.Error == nil {
		// Domain exists
		if existingDomain.IsWhitelisted == isWhitelist {
			// Just update expiration if not custom
			if !isCustom {
				var expiresAt *time.Time
				if expiration > 0 {
					expireTime := time.Now().Add(expiration)
					expiresAt = &expireTime
				}
				existingDomain.ExpiresAt = expiresAt
				existingDomain.IsCustom = isCustom
				now := time.Now()
				existingDomain.LastChecked = &now

				if err := s.db.Save(&existingDomain).Error; err != nil {
					return 0, err
				}
			}
			return existingDomain.ID, nil
		}

		// Update whitelist status
		existingDomain.IsWhitelisted = isWhitelist
		existingDomain.IsCustom = isCustom
		existingDomain.ExpiresAt = nil

		if err := s.db.Save(&existingDomain).Error; err != nil {
			return 0, err
		}
		return existingDomain.ID, nil
	}

	// Create new domain
	var expiresAt *time.Time
	if !isCustom && expiration > 0 {
		expireTime := time.Now().Add(expiration)
		expiresAt = &expireTime
	}

	newDomain := Domain{
		Domain:        domain,
		IsWhitelisted: isWhitelist,
		IsCustom:      isCustom,
		ExpiresAt:     expiresAt,
	}

	if err := s.db.Create(&newDomain).Error; err != nil {
		return 0, err
	}

	return newDomain.ID, nil
}

// GetDomain gets a domain by name
func (s *GormStore) GetDomain(domainName string) (*Domain, error) {
	var domain Domain
	if err := s.db.Where("domain = ?", domainName).First(&domain).Error; err != nil {
		return nil, err
	}
	return &domain, nil
}

// IsDomainWhitelisted checks if a domain is whitelisted
func (s *GormStore) IsDomainWhitelisted(domain string) (bool, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))

	var d Domain
	result := s.db.Where("domain = ?", domain).First(&d)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return false, nil
		}
		return false, result.Error
	}

	return d.IsWhitelisted, nil
}

// GetDomains gets paginated domains
func (s *GormStore) GetDomains(isWhitelist bool, page, perPage int, sortBy string) ([]Domain, int, error) {
	var domains []Domain
	var total int64

	query := s.db.Model(&Domain{}).Where("is_whitelisted = ?", isWhitelist)

	// Count total
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Apply sorting
	switch sortBy {
	case "domain":
		query = query.Order("domain ASC")
	case "added_at":
		query = query.Order("added_at DESC")
	default:
		query = query.Order("added_at DESC")
	}

	// Apply pagination
	offset := (page - 1) * perPage
	if err := query.Offset(offset).Limit(perPage).Find(&domains).Error; err != nil {
		return nil, 0, err
	}

	return domains, int(total), nil
}

// RemoveDomain removes a domain from the database
func (s *GormStore) RemoveDomain(domainID uint) error {
	return s.db.Delete(&Domain{}, domainID).Error
}

// IP methods

// SaveIP saves an IP to the database
func (s *GormStore) SaveIP(ipAddress string, isWhitelist bool, isCustom bool, domainID *uint, expiration time.Duration) (uint, error) {
	var existingIP IP
	result := s.db.Where("ip_address = ?", ipAddress).First(&existingIP)

	if result.Error == nil {
		// IP exists
		if existingIP.IsWhitelisted == isWhitelist {
			// Just update expiration if not custom
			if !isCustom {
				var expiresAt *time.Time
				if expiration > 0 {
					expireTime := time.Now().Add(expiration)
					expiresAt = &expireTime
				}
				existingIP.ExpiresAt = expiresAt
				existingIP.IsCustom = isCustom
				existingIP.DomainID = domainID
				now := time.Now()
				existingIP.LastChecked = &now

				if err := s.db.Save(&existingIP).Error; err != nil {
					return 0, err
				}
			}
			return existingIP.ID, nil
		}

		// Update whitelist status
		existingIP.IsWhitelisted = isWhitelist
		existingIP.IsCustom = isCustom
		existingIP.ExpiresAt = nil
		existingIP.DomainID = domainID

		if err := s.db.Save(&existingIP).Error; err != nil {
			return 0, err
		}
		return existingIP.ID, nil
	}

	// Create new IP
	var expiresAt *time.Time
	if !isCustom && expiration > 0 {
		expireTime := time.Now().Add(expiration)
		expiresAt = &expireTime
	}

	newIP := IP{
		IPAddress:     ipAddress,
		IsWhitelisted: isWhitelist,
		IsCustom:      isCustom,
		ExpiresAt:     expiresAt,
		DomainID:      domainID,
	}

	if err := s.db.Create(&newIP).Error; err != nil {
		return 0, err
	}

	return newIP.ID, nil
}

// AddIPWithRotation adds an IP with rotation mechanism
func (s *GormStore) AddIPWithRotation(domainID uint, ipAddress string, maxIPsPerDomain int, expiration time.Duration) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		// Check if domain is custom
		var domain Domain
		if err := tx.First(&domain, domainID).Error; err != nil {
			return err
		}

		// Check if IP already exists
		var existingIP IP
		result := tx.Where("ip_address = ?", ipAddress).First(&existingIP)

		if result.Error == nil {
			// IP exists, just update domain and expiration
			if existingIP.IsCustom {
				return nil // Don't modify custom IPs
			}

			var expiresAt *time.Time
			if !domain.IsCustom && expiration > 0 {
				expireTime := time.Now().Add(expiration)
				expiresAt = &expireTime
			}

			existingIP.DomainID = &domainID
			existingIP.ExpiresAt = expiresAt
			now := time.Now()
			existingIP.LastChecked = &now

			return tx.Save(&existingIP).Error
		}

		// Count existing IPs for this domain
		var ipCount int64
		if err := tx.Model(&IP{}).Where("domain_id = ? AND is_custom = ?", domainID, false).Count(&ipCount).Error; err != nil {
			return err
		}

		// If max IPs reached, remove oldest IPs
		if int(ipCount) >= maxIPsPerDomain {
			var oldestIPs []IP
			removeCount := int(ipCount) - (maxIPsPerDomain - 1)

			if err := tx.Where("domain_id = ? AND is_custom = ?", domainID, false).
				Order("added_at ASC").
				Limit(removeCount).
				Find(&oldestIPs).Error; err != nil {
				return err
			}

			for _, ip := range oldestIPs {
				if err := tx.Delete(&ip).Error; err != nil {
					return err
				}
			}
		}

		// Add new IP
		var expiresAt *time.Time
		if !domain.IsCustom && expiration > 0 {
			expireTime := time.Now().Add(expiration)
			expiresAt = &expireTime
		}

		newIP := IP{
			IPAddress:     ipAddress,
			IsWhitelisted: false,
			IsCustom:      domain.IsCustom,
			DomainID:      &domainID,
			ExpiresAt:     expiresAt,
		}

		return tx.Create(&newIP).Error
	})
}

// IsIPWhitelisted checks if an IP is whitelisted
func (s *GormStore) IsIPWhitelisted(ipAddress string) (bool, error) {
	var ip IP
	result := s.db.Where("ip_address = ? AND is_whitelisted = ?", ipAddress, true).First(&ip)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return false, nil
		}
		return false, result.Error
	}
	return true, nil
}

// GetIPs gets paginated IPs
func (s *GormStore) GetIPs(isWhitelist bool, page, perPage int, sortBy string) ([]IP, int, error) {
	var ips []IP
	var total int64

	query := s.db.Model(&IP{}).Where("is_whitelisted = ?", isWhitelist).Preload("Domain")

	// Count total
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Apply sorting
	switch sortBy {
	case "ip_address":
		query = query.Order("ip_address ASC")
	case "added_at":
		query = query.Order("added_at DESC")
	default:
		query = query.Order("added_at DESC")
	}

	// Apply pagination
	offset := (page - 1) * perPage
	if err := query.Offset(offset).Limit(perPage).Find(&ips).Error; err != nil {
		return nil, 0, err
	}

	return ips, int(total), nil
}

// RemoveIP removes an IP from the database
func (s *GormStore) RemoveIP(ipID uint) error {
	return s.db.Delete(&IP{}, ipID).Error
}

// IPRange methods

// SaveIPRange saves an IP range to the database
func (s *GormStore) SaveIPRange(cidr string, isWhitelist bool, isCustom bool, expiration time.Duration) (uint, error) {
	var existingRange IPRange
	result := s.db.Where("cidr = ?", cidr).First(&existingRange)

	if result.Error == nil {
		// Range exists
		if existingRange.IsWhitelisted == isWhitelist {
			// Just update expiration if not custom
			if !isCustom {
				var expiresAt *time.Time
				if expiration > 0 {
					expireTime := time.Now().Add(expiration)
					expiresAt = &expireTime
				}
				existingRange.ExpiresAt = expiresAt
				existingRange.IsCustom = isCustom

				if err := s.db.Save(&existingRange).Error; err != nil {
					return 0, err
				}
			}
			return existingRange.ID, nil
		}

		// Update whitelist status
		existingRange.IsWhitelisted = isWhitelist
		existingRange.IsCustom = isCustom
		existingRange.ExpiresAt = nil

		if err := s.db.Save(&existingRange).Error; err != nil {
			return 0, err
		}
		return existingRange.ID, nil
	}

	// Create new range
	var expiresAt *time.Time
	if !isCustom && expiration > 0 {
		expireTime := time.Now().Add(expiration)
		expiresAt = &expireTime
	}

	newRange := IPRange{
		CIDR:          cidr,
		IsWhitelisted: isWhitelist,
		IsCustom:      isCustom,
		ExpiresAt:     expiresAt,
	}

	if err := s.db.Create(&newRange).Error; err != nil {
		return 0, err
	}

	return newRange.ID, nil
}

// GetIPRanges gets paginated IP ranges
func (s *GormStore) GetIPRanges(isWhitelist bool, page, perPage int, sortBy string) ([]IPRange, int, error) {
	var ranges []IPRange
	var total int64

	query := s.db.Model(&IPRange{}).Where("is_whitelisted = ?", isWhitelist)

	// Count total
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Apply sorting
	switch sortBy {
	case "cidr":
		query = query.Order("cidr ASC")
	case "added_at":
		query = query.Order("added_at DESC")
	default:
		query = query.Order("added_at DESC")
	}

	// Apply pagination
	offset := (page - 1) * perPage
	if err := query.Offset(offset).Limit(perPage).Find(&ranges).Error; err != nil {
		return nil, 0, err
	}

	return ranges, int(total), nil
}

// RemoveIPRange removes an IP range from the database
func (s *GormStore) RemoveIPRange(rangeID uint) error {
	return s.db.Delete(&IPRange{}, rangeID).Error
}

// Agent methods

// LogAgentStart logs the start of an agent run
func (s *GormStore) LogAgentStart() (uint, error) {
	run := AgentRun{
		Status: "running",
	}

	if err := s.db.Create(&run).Error; err != nil {
		return 0, err
	}

	return run.ID, nil
}

// LogAgentCompletion logs the completion of an agent run
func (s *GormStore) LogAgentCompletion(runID uint, domainsProcessed, ipsBlocked int) error {
	now := time.Now()
	return s.db.Model(&AgentRun{}).Where("id = ?", runID).Updates(map[string]interface{}{
		"completed_at":      &now,
		"domains_processed": domainsProcessed,
		"ips_blocked":       ipsBlocked,
		"status":            "completed",
	}).Error
}

// LogAgentError logs an error in an agent run
func (s *GormStore) LogAgentError(runID uint, errMsg string) error {
	now := time.Now()
	return s.db.Model(&AgentRun{}).Where("id = ?", runID).Updates(map[string]interface{}{
		"completed_at":  &now,
		"status":        "error",
		"error_message": errMsg,
	}).Error
}

// LogAction logs an action performed by the agent
func (s *GormStore) LogAction(runID uint, actionType, target, result, details string) error {
	log := AgentLog{
		RunID:      runID,
		ActionType: actionType,
		Target:     target,
		Result:     result,
		Details:    details,
	}

	return s.db.Create(&log).Error
}

// GetLastAgentRun gets the last agent run
func (s *GormStore) GetLastAgentRun() (*AgentRun, error) {
	var run AgentRun
	if err := s.db.Order("started_at DESC").First(&run).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &run, nil
}

// UpdateURL methods

// GetUpdateURLs gets all update URLs
func (s *GormStore) GetUpdateURLs() ([]UpdateURL, error) {
	var urls []UpdateURL
	if err := s.db.Where("enabled = ?", true).Find(&urls).Error; err != nil {
		return nil, err
	}
	return urls, nil
}

// AddUpdateURL adds a new update URL
func (s *GormStore) AddUpdateURL(url string) error {
	updateURL := UpdateURL{
		URL:     url,
		Enabled: true,
	}
	return s.db.Create(&updateURL).Error
}

// RemoveUpdateURL removes an update URL
func (s *GormStore) RemoveUpdateURL(urlID uint) error {
	return s.db.Delete(&UpdateURL{}, urlID).Error
}

// UpdateURLLastUsed updates the last used timestamp for a URL
func (s *GormStore) UpdateURLLastUsed(urlID uint) error {
	now := time.Now()
	return s.db.Model(&UpdateURL{}).Where("id = ?", urlID).Update("last_used", &now).Error
}

// GetStatistics gets statistics for the dashboard
func (s *GormStore) GetStatistics() (*Statistics, error) {
	stats := &Statistics{}

	// Get domain counts
	var blockedDomains, whitelistedDomains int64
	s.db.Model(&Domain{}).Where("is_whitelisted = ?", false).Count(&blockedDomains)
	s.db.Model(&Domain{}).Where("is_whitelisted = ?", true).Count(&whitelistedDomains)
	stats.BlockedDomainsCount = int(blockedDomains)
	stats.WhitelistedDomains = int(whitelistedDomains)

	// Get IP counts
	var blockedIPs, whitelistedIPs int64
	s.db.Model(&IP{}).Where("is_whitelisted = ?", false).Count(&blockedIPs)
	s.db.Model(&IP{}).Where("is_whitelisted = ?", true).Count(&whitelistedIPs)
	stats.BlockedIPCount = int(blockedIPs)
	stats.WhitelistedIPCount = int(whitelistedIPs)

	// Get recent activity
	yesterday := time.Now().AddDate(0, 0, -1)
	var domainsProcessed24h, ipsBlocked24h int64
	s.db.Model(&AgentLog{}).Where("action_type = ? AND timestamp > ?", "process", yesterday).Count(&domainsProcessed24h)
	s.db.Model(&AgentLog{}).Where("action_type = ? AND timestamp > ?", "block", yesterday).Count(&ipsBlocked24h)
	stats.DomainsProcessed24h = int(domainsProcessed24h)
	stats.IPsBlocked24h = int(ipsBlocked24h)

	// Get last run info
	lastRun, _ := s.GetLastAgentRun()
	if lastRun != nil {
		stats.LastRunTime = lastRun.CompletedAt
		stats.LastRunStatus = lastRun.Status
	}

	return stats, nil
}

// CheckForCDN checks if a domain might be a CDN
func (s *GormStore) CheckForCDN(domainID uint, threshold int) (bool, error) {
	var count int64
	if err := s.db.Model(&IP{}).Where("domain_id = ?", domainID).Count(&count).Error; err != nil {
		return false, err
	}

	isCDN := int(count) >= threshold

	// Update the domain's CDN flag
	if isCDN {
		s.db.Model(&Domain{}).Where("id = ?", domainID).Update("flagged_as_cdn", true)
	}

	return isCDN, nil
}

// ExpireUnseenDomains marks domains as expired if they weren't seen in current run
func (s *GormStore) ExpireUnseenDomains(runID uint) error {
	// This would require more complex logic to track which domains were seen
	// For now, we'll implement a basic version
	return nil
}
