package database

import (
	"database/sql"
	"fmt"
	"time"
)

// DatabaseStore defines the interface that all database implementations must follow
type DatabaseStore interface {
	// Connection management
	Close() error
	CleanupExpired() error

	// Domain operations
	SaveDomain(domain string, isWhitelist bool, isCustom bool, expiration time.Duration) (interface{}, error)
	GetDomain(domainName string) (interface{}, error)
	IsDomainWhitelisted(domain string) (bool, error)
	GetDomains(isWhitelist bool, page, perPage int, sortBy string) (interface{}, int, error)
	RemoveDomain(domainID interface{}) error

	// IP operations
	SaveIP(ipAddress string, isWhitelist bool, isCustom bool, domainID interface{}, expiration time.Duration) (interface{}, error)
	AddIPWithRotation(domainID interface{}, ipAddress string, maxIPsPerDomain int, expiration time.Duration) error
	IsIPWhitelisted(ipAddress string) (bool, error)
	GetIPs(isWhitelist bool, page, perPage int, sortBy string) (interface{}, int, error)
	RemoveIP(ipID interface{}) error

	// IP Range operations
	SaveIPRange(cidr string, isWhitelist bool, isCustom bool, expiration time.Duration) (interface{}, error)
	GetIPRanges(isWhitelist bool, page, perPage int, sortBy string) (interface{}, int, error)
	RemoveIPRange(rangeID interface{}) error

	// Agent operations
	LogAgentStart() (interface{}, error)
	LogAgentCompletion(runID interface{}, domainsProcessed, ipsBlocked int) error
	LogAgentError(runID interface{}, errMsg string) error
	LogAction(runID interface{}, actionType, target, result, details string) error
	GetLastAgentRun() (interface{}, error)

	// Update URL operations
	GetUpdateURLs() (interface{}, error)
	AddUpdateURL(url string) error
	RemoveUpdateURL(urlID interface{}) error
	UpdateURLLastUsed(urlID interface{}) error

	// Statistics
	GetStatistics() (*Statistics, error)
	CheckForCDN(domainID interface{}, threshold int) (bool, error)
	ExpireUnseenDomains(runID interface{}) error

	// Sync operations for firewall integration
	GetActiveIPs() ([]string, error)
	GetWhitelistedIPs() ([]string, error)
	GetWhitelistedRanges() ([]string, error)
}

// Wrapper for the old Store to implement DatabaseStore interface
type StoreWrapper struct {
	*Store
}

func (s *StoreWrapper) SaveDomain(domain string, isWhitelist bool, isCustom bool, expiration time.Duration) (interface{}, error) {
	return s.Store.SaveDomain(domain, isWhitelist, isCustom, expiration)
}

func (s *StoreWrapper) GetDomain(domainName string) (interface{}, error) {
	return s.Store.GetDomain(domainName)
}

func (s *StoreWrapper) GetDomains(isWhitelist bool, page, perPage int, sortBy string) (interface{}, int, error) {
	return s.Store.GetDomains(isWhitelist, page, perPage, sortBy)
}

func (s *StoreWrapper) RemoveDomain(domainID interface{}) error {
	if id, ok := domainID.(int64); ok {
		return s.Store.RemoveDomain(id)
	}
	return fmt.Errorf("invalid domain ID type")
}

func (s *StoreWrapper) SaveIP(ipAddress string, isWhitelist bool, isCustom bool, domainID interface{}, expiration time.Duration) (interface{}, error) {
	var sqlDomainID sql.NullInt64
	if domainID != nil {
		if id, ok := domainID.(int64); ok {
			sqlDomainID = sql.NullInt64{Int64: id, Valid: true}
		}
	}
	return s.Store.SaveIP(ipAddress, isWhitelist, isCustom, sqlDomainID, expiration)
}

func (s *StoreWrapper) AddIPWithRotation(domainID interface{}, ipAddress string, maxIPsPerDomain int, expiration time.Duration) error {
	if id, ok := domainID.(int64); ok {
		return s.Store.AddIPWithRotation(id, ipAddress, maxIPsPerDomain, expiration)
	}
	return fmt.Errorf("invalid domain ID type")
}

func (s *StoreWrapper) GetIPs(isWhitelist bool, page, perPage int, sortBy string) (interface{}, int, error) {
	// Get IPs from the legacy store
	query := "SELECT id, ip_address, is_whitelisted, is_custom, added_at, expires_at, source, domain_id, last_checked FROM ips WHERE is_whitelisted = ?"

	// Add sorting
	switch sortBy {
	case "ip_address":
		query += " ORDER BY ip_address ASC"
	case "added_at":
		query += " ORDER BY added_at DESC"
	default:
		query += " ORDER BY added_at DESC"
	}

	// Add pagination
	offset := (page - 1) * perPage
	query += fmt.Sprintf(" LIMIT %d OFFSET %d", perPage, offset)

	rows, err := s.Store.db.Query(query, isWhitelist)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	// For legacy store, we need to use the legacy IP structure
	type LegacyIP struct {
		ID            int64
		IPAddress     string
		IsWhitelisted bool
		IsCustom      bool
		AddedAt       time.Time
		ExpiresAt     *time.Time
		Source        string
		DomainID      *int64
		LastChecked   *time.Time
	}

	var ips []LegacyIP
	for rows.Next() {
		var ip LegacyIP
		var domainID sql.NullInt64
		err := rows.Scan(
			&ip.ID, &ip.IPAddress, &ip.IsWhitelisted, &ip.IsCustom,
			&ip.AddedAt, &ip.ExpiresAt, &ip.Source, &domainID, &ip.LastChecked,
		)
		if err != nil {
			return nil, 0, err
		}

		// Convert domain ID if present
		if domainID.Valid {
			ip.DomainID = &domainID.Int64
		}

		ips = append(ips, ip)
	}

	// Get total count
	var total int
	err = s.Store.db.QueryRow("SELECT COUNT(*) FROM ips WHERE is_whitelisted = ?", isWhitelist).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	return ips, total, nil
}

func (s *StoreWrapper) RemoveIP(ipID interface{}) error {
	if id, ok := ipID.(int64); ok {
		return s.Store.RemoveIP(id)
	}
	return fmt.Errorf("invalid IP ID type")
}

func (s *StoreWrapper) SaveIPRange(cidr string, isWhitelist bool, isCustom bool, expiration time.Duration) (interface{}, error) {
	return s.Store.SaveIPRange(cidr, isWhitelist, isCustom, expiration)
}

func (s *StoreWrapper) GetIPRanges(isWhitelist bool, page, perPage int, sortBy string) (interface{}, int, error) {
	// Get IP ranges from the legacy store
	query := "SELECT id, cidr, is_whitelisted, is_custom, added_at, expires_at, source FROM ip_ranges WHERE is_whitelisted = ?"

	// Add sorting
	switch sortBy {
	case "cidr":
		query += " ORDER BY cidr ASC"
	case "added_at":
		query += " ORDER BY added_at DESC"
	default:
		query += " ORDER BY added_at DESC"
	}

	// Add pagination
	offset := (page - 1) * perPage
	query += fmt.Sprintf(" LIMIT %d OFFSET %d", perPage, offset)

	rows, err := s.Store.db.Query(query, isWhitelist)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	// For legacy store, we need to use the legacy IPRange structure
	type LegacyIPRange struct {
		ID            int64
		CIDR          string
		IsWhitelisted bool
		IsCustom      bool
		AddedAt       time.Time
		ExpiresAt     *time.Time
		Source        string
	}

	var ranges []LegacyIPRange
	for rows.Next() {
		var ipRange LegacyIPRange
		err := rows.Scan(
			&ipRange.ID, &ipRange.CIDR, &ipRange.IsWhitelisted, &ipRange.IsCustom,
			&ipRange.AddedAt, &ipRange.ExpiresAt, &ipRange.Source,
		)
		if err != nil {
			return nil, 0, err
		}
		ranges = append(ranges, ipRange)
	}

	// Get total count
	var total int
	err = s.Store.db.QueryRow("SELECT COUNT(*) FROM ip_ranges WHERE is_whitelisted = ?", isWhitelist).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	return ranges, total, nil
}

func (s *StoreWrapper) RemoveIPRange(rangeID interface{}) error {
	if id, ok := rangeID.(int64); ok {
		return s.Store.RemoveIPRange(id)
	}
	return fmt.Errorf("invalid range ID type")
}

func (s *StoreWrapper) LogAgentStart() (interface{}, error) {
	return s.Store.LogAgentStart()
}

func (s *StoreWrapper) LogAgentCompletion(runID interface{}, domainsProcessed, ipsBlocked int) error {
	if id, ok := runID.(int64); ok {
		return s.Store.LogAgentCompletion(id, domainsProcessed, ipsBlocked)
	}
	return fmt.Errorf("invalid run ID type")
}

func (s *StoreWrapper) LogAgentError(runID interface{}, errMsg string) error {
	if id, ok := runID.(int64); ok {
		return s.Store.LogAgentError(id, errMsg)
	}
	return fmt.Errorf("invalid run ID type")
}

func (s *StoreWrapper) LogAction(runID interface{}, actionType, target, result, details string) error {
	if id, ok := runID.(int64); ok {
		return s.Store.LogAction(id, actionType, target, result, details)
	}
	return fmt.Errorf("invalid run ID type")
}

func (s *StoreWrapper) GetLastAgentRun() (interface{}, error) {
	return s.Store.GetLastAgentRun()
}

func (s *StoreWrapper) GetUpdateURLs() (interface{}, error) {
	return s.Store.GetUpdateURLs()
}

func (s *StoreWrapper) RemoveUpdateURL(urlID interface{}) error {
	if id, ok := urlID.(int64); ok {
		return s.Store.RemoveUpdateURL(id)
	}
	return fmt.Errorf("invalid URL ID type")
}

func (s *StoreWrapper) UpdateURLLastUsed(urlID interface{}) error {
	if id, ok := urlID.(int64); ok {
		return s.Store.UpdateURLLastUsed(id)
	}
	return fmt.Errorf("invalid URL ID type")
}

func (s *StoreWrapper) CheckForCDN(domainID interface{}, threshold int) (bool, error) {
	if id, ok := domainID.(int64); ok {
		return s.Store.CheckForCDN(id, threshold)
	}
	return false, fmt.Errorf("invalid domain ID type")
}

func (s *StoreWrapper) ExpireUnseenDomains(runID interface{}) error {
	if id, ok := runID.(int64); ok {
		return s.Store.ExpireUnseenDomains(id)
	}
	return fmt.Errorf("invalid run ID type")
}

func (s *StoreWrapper) GetActiveIPs() ([]string, error) {
	query := "SELECT DISTINCT ip_address FROM ips WHERE is_whitelisted = 0 AND (expires_at IS NULL OR expires_at > datetime('now'))"
	rows, err := s.Store.db.Query(query)
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
	return ips, nil
}

func (s *StoreWrapper) GetWhitelistedIPs() ([]string, error) {
	query := "SELECT DISTINCT ip_address FROM ips WHERE is_whitelisted = 1 AND (expires_at IS NULL OR expires_at > datetime('now'))"
	rows, err := s.Store.db.Query(query)
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
	return ips, nil
}

func (s *StoreWrapper) GetWhitelistedRanges() ([]string, error) {
	query := "SELECT DISTINCT cidr FROM ip_ranges WHERE is_whitelisted = 1 AND (expires_at IS NULL OR expires_at > datetime('now'))"
	rows, err := s.Store.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ranges []string
	for rows.Next() {
		var cidr string
		if err := rows.Scan(&cidr); err != nil {
			return nil, err
		}
		ranges = append(ranges, cidr)
	}
	return ranges, nil
}

// Wrapper for the new GormStore to implement DatabaseStore interface
type GormStoreWrapper struct {
	*GormStore
}

func (s *GormStoreWrapper) SaveDomain(domain string, isWhitelist bool, isCustom bool, expiration time.Duration) (interface{}, error) {
	return s.GormStore.SaveDomain(domain, isWhitelist, isCustom, expiration)
}

func (s *GormStoreWrapper) GetDomain(domainName string) (interface{}, error) {
	return s.GormStore.GetDomain(domainName)
}

func (s *GormStoreWrapper) GetDomains(isWhitelist bool, page, perPage int, sortBy string) (interface{}, int, error) {
	return s.GormStore.GetDomains(isWhitelist, page, perPage, sortBy)
}

func (s *GormStoreWrapper) RemoveDomain(domainID interface{}) error {
	if id, ok := domainID.(uint); ok {
		return s.GormStore.RemoveDomain(id)
	}
	return fmt.Errorf("invalid domain ID type")
}

func (s *GormStoreWrapper) SaveIP(ipAddress string, isWhitelist bool, isCustom bool, domainID interface{}, expiration time.Duration) (interface{}, error) {
	var gormDomainID *uint
	if domainID != nil {
		if id, ok := domainID.(uint); ok {
			gormDomainID = &id
		}
	}
	return s.GormStore.SaveIP(ipAddress, isWhitelist, isCustom, gormDomainID, expiration)
}

func (s *GormStoreWrapper) AddIPWithRotation(domainID interface{}, ipAddress string, maxIPsPerDomain int, expiration time.Duration) error {
	if id, ok := domainID.(uint); ok {
		return s.GormStore.AddIPWithRotation(id, ipAddress, maxIPsPerDomain, expiration)
	}
	return fmt.Errorf("invalid domain ID type")
}

func (s *GormStoreWrapper) GetIPs(isWhitelist bool, page, perPage int, sortBy string) (interface{}, int, error) {
	return s.GormStore.GetIPs(isWhitelist, page, perPage, sortBy)
}

func (s *GormStoreWrapper) RemoveIP(ipID interface{}) error {
	if id, ok := ipID.(uint); ok {
		return s.GormStore.RemoveIP(id)
	}
	return fmt.Errorf("invalid IP ID type")
}

func (s *GormStoreWrapper) SaveIPRange(cidr string, isWhitelist bool, isCustom bool, expiration time.Duration) (interface{}, error) {
	return s.GormStore.SaveIPRange(cidr, isWhitelist, isCustom, expiration)
}

func (s *GormStoreWrapper) GetIPRanges(isWhitelist bool, page, perPage int, sortBy string) (interface{}, int, error) {
	return s.GormStore.GetIPRanges(isWhitelist, page, perPage, sortBy)
}

func (s *GormStoreWrapper) RemoveIPRange(rangeID interface{}) error {
	if id, ok := rangeID.(uint); ok {
		return s.GormStore.RemoveIPRange(id)
	}
	return fmt.Errorf("invalid range ID type")
}

func (s *GormStoreWrapper) LogAgentStart() (interface{}, error) {
	return s.GormStore.LogAgentStart()
}

func (s *GormStoreWrapper) LogAgentCompletion(runID interface{}, domainsProcessed, ipsBlocked int) error {
	if id, ok := runID.(uint); ok {
		return s.GormStore.LogAgentCompletion(id, domainsProcessed, ipsBlocked)
	}
	return fmt.Errorf("invalid run ID type")
}

func (s *GormStoreWrapper) LogAgentError(runID interface{}, errMsg string) error {
	if id, ok := runID.(uint); ok {
		return s.GormStore.LogAgentError(id, errMsg)
	}
	return fmt.Errorf("invalid run ID type")
}

func (s *GormStoreWrapper) LogAction(runID interface{}, actionType, target, result, details string) error {
	if id, ok := runID.(uint); ok {
		return s.GormStore.LogAction(id, actionType, target, result, details)
	}
	return fmt.Errorf("invalid run ID type")
}

func (s *GormStoreWrapper) GetLastAgentRun() (interface{}, error) {
	return s.GormStore.GetLastAgentRun()
}

func (s *GormStoreWrapper) GetUpdateURLs() (interface{}, error) {
	return s.GormStore.GetUpdateURLs()
}

func (s *GormStoreWrapper) RemoveUpdateURL(urlID interface{}) error {
	if id, ok := urlID.(uint); ok {
		return s.GormStore.RemoveUpdateURL(id)
	}
	return fmt.Errorf("invalid URL ID type")
}

func (s *GormStoreWrapper) UpdateURLLastUsed(urlID interface{}) error {
	if id, ok := urlID.(uint); ok {
		return s.GormStore.UpdateURLLastUsed(id)
	}
	return fmt.Errorf("invalid URL ID type")
}

func (s *GormStoreWrapper) CheckForCDN(domainID interface{}, threshold int) (bool, error) {
	if id, ok := domainID.(uint); ok {
		return s.GormStore.CheckForCDN(id, threshold)
	}
	return false, fmt.Errorf("invalid domain ID type")
}

func (s *GormStoreWrapper) ExpireUnseenDomains(runID interface{}) error {
	if id, ok := runID.(uint); ok {
		return s.GormStore.ExpireUnseenDomains(id)
	}
	return fmt.Errorf("invalid run ID type")
}

func (s *GormStoreWrapper) GetActiveIPs() ([]string, error) {
	return s.GormStore.GetActiveIPs()
}

func (s *GormStoreWrapper) GetWhitelistedIPs() ([]string, error) {
	return s.GormStore.GetWhitelistedIPs()
}

func (s *GormStoreWrapper) GetWhitelistedRanges() ([]string, error) {
	return s.GormStore.GetWhitelistedRanges()
}
