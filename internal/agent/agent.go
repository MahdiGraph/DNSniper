package agent

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MahdiGraph/DNSniper/internal/config"
	"github.com/MahdiGraph/DNSniper/internal/database"
	"github.com/MahdiGraph/DNSniper/internal/dns"
	"github.com/MahdiGraph/DNSniper/internal/firewall"
	"github.com/MahdiGraph/DNSniper/pkg/logger"
)

// Agent represents the DNSniper agent with GORM compatibility
type Agent struct {
	config          *config.Settings
	db              database.DatabaseStore // Use interface for GORM compatibility
	resolver        dns.Resolver
	firewallManager *firewall.FirewallManager
	logger          *logger.Logger

	// Rate limiting
	requestCount   int32
	lastResetTime  time.Time
	rateLimitMutex sync.Mutex

	// Statistics
	domainsProcessed int32
	ipsBlocked       int32
}

// NewAgent creates a new DNSniper agent with GORM interface
func NewAgent(
	config *config.Settings,
	db database.DatabaseStore, // Changed to interface
	resolver dns.Resolver,
	firewallManager *firewall.FirewallManager,
	logger *logger.Logger,
) *Agent {
	return &Agent{
		config:          config,
		db:              db,
		resolver:        resolver,
		firewallManager: firewallManager,
		logger:          logger,
		lastResetTime:   time.Now(),
	}
}

// Run executes the agent process with enhanced features
func (a *Agent) Run(ctx context.Context) error {
	// Clean up expired records
	a.logger.Info("Cleaning up expired records...")
	if err := a.db.CleanupExpired(); err != nil {
		a.logger.Warnf("Failed to clean up expired records: %v", err)
	}

	// Initialize sync manager for database-ipset synchronization
	syncManager := firewall.NewSyncManager(a.firewallManager, a.db, a.logger)

	// Perform initial sync to ensure ipsets match database
	a.logger.Info("Performing initial database-ipset synchronization...")
	if err := syncManager.SyncDatabaseToIPSets(); err != nil {
		a.logger.Warnf("Initial sync failed: %v", err)
	}

	// Log agent start and create run record
	a.logger.Info("Agent started")
	runIDInterface, err := a.db.LogAgentStart()
	if err != nil {
		return fmt.Errorf("failed to log agent start: %w", err)
	}

	// Convert run ID to the appropriate type (GORM uses uint)
	var runID uint
	switch id := runIDInterface.(type) {
	case uint:
		runID = id
	case int64:
		runID = uint(id)
	default:
		return fmt.Errorf("unexpected run ID type: %T", runIDInterface)
	}

	// Set the run ID for run-specific logging
	a.logger.SetRunID(int64(runID))

	// Process update URLs from configuration (not database)
	updateURLs := a.config.UpdateURLs
	if len(updateURLs) == 0 {
		a.logger.Warn("No update URLs configured in settings, using default")
		updateURLs = []string{"https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/domains-default.txt"}
	}

	// Process domains from update URLs
	totalDomains := 0
	seenDomains := make(map[string]bool)

	for _, updateURL := range updateURLs {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			a.logger.Infof("Processing update URL: %s", updateURL)

			// Download domain list with error handling and timeout
			domains, err := a.downloadDomainList(ctx, updateURL)
			if err != nil {
				a.logger.Warnf("Failed to download domain list from %s: %v", updateURL, err)
				continue
			}

			// Process domains
			a.logger.Infof("Downloaded %d domains from %s", len(domains), updateURL)
			totalDomains += len(domains)

			// Create worker pool with reasonable worker count
			workerCount := a.determineWorkerCount()
			pool := NewWorkerPool(workerCount)
			pool.Start(ctx)

			// Submit domains to worker pool
			for _, domain := range domains {
				// Skip if already seen
				if seenDomains[domain] {
					continue
				}
				seenDomains[domain] = true

				// Skip invalid domains
				if !isValidDomain(domain) {
					a.logger.Debugf("Skipping invalid domain: %s", domain)
					continue
				}

				// Submit to worker pool
				pool.Submit(&ProcessDomainItem{
					Domain: domain,
					RunID:  int64(runID),
					Agent:  a,
				})
			}

			// Process results with enhanced error handling
			resultsChan := pool.Results()
			errorCount := 0
			processedCount := 0

			for err := range resultsChan {
				processedCount++
				if err != nil {
					errorCount++
					a.logger.Warnf("Error processing domain: %v", err)

					// Log error to database if possible
					if runID > 0 {
						a.db.LogAgentError(uint(runID), fmt.Sprintf("Domain processing error: %v", err))
					}

					// If too many errors, consider stopping
					if errorCount > 100 && float64(errorCount)/float64(processedCount) > 0.5 {
						a.logger.Errorf("Too many errors (%d/%d), stopping processing for this URL", errorCount, processedCount)
						break
					}
				}
			}

			if errorCount > 0 {
				a.logger.Warnf("Completed processing %s with %d errors out of %d domains", updateURL, errorCount, processedCount)
			}

			// Stop worker pool
			pool.Stop()
		}
	}

	// Perform final sync to ensure all changes are reflected in ipsets
	a.logger.Info("Performing final database-ipset synchronization...")
	if err := syncManager.SyncDatabaseToIPSets(); err != nil {
		a.logger.Warnf("Final sync failed: %v", err)
	}

	// Validate sync to ensure consistency
	if err := syncManager.ValidateSync(); err != nil {
		a.logger.Warnf("Sync validation failed: %v", err)
	}

	// Update firewall rules to reflect changes
	a.logger.Info("Updating firewall rules...")
	if err := a.firewallManager.Reload(); err != nil {
		a.logger.Warnf("Failed to reload firewall rules: %v", err)
	}

	// Log agent completion
	a.logger.Infof("Agent completed successfully: %d domains processed, %d IPs blocked",
		atomic.LoadInt32(&a.domainsProcessed), atomic.LoadInt32(&a.ipsBlocked))

	if err := a.db.LogAgentCompletion(runID, int(atomic.LoadInt32(&a.domainsProcessed)),
		int(atomic.LoadInt32(&a.ipsBlocked))); err != nil {
		a.logger.Warnf("Failed to log agent completion: %v", err)
	}

	return nil
}

// downloadDomainList downloads a list of domains from the given URL with context and error handling
func (a *Agent) downloadDomainList(ctx context.Context, url string) ([]string, error) {
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Create request with context
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add User-Agent header to avoid being blocked
	req.Header.Set("User-Agent", "DNSniper/2.0")

	// Download domain list
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download domain list: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to download domain list: HTTP %d", resp.StatusCode)
	}

	// Read response body with size limit (10MB) to prevent memory exhaustion
	const maxResponseSize = 10 * 1024 * 1024 // 10MB
	limitedReader := io.LimitReader(resp.Body, maxResponseSize)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read domain list: %w", err)
	}

	// Process domains
	var domains []string
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Handle hosts file format (IP domain)
		fields := strings.Fields(line)
		if len(fields) > 1 && net.ParseIP(fields[0]) != nil {
			domains = append(domains, fields[1])
		} else {
			domains = append(domains, line)
		}
	}

	return domains, nil
}

// determineWorkerCount calculates the optimal number of workers
func (a *Agent) determineWorkerCount() int {
	// Start with a reasonable default
	workerCount := 10

	// Adjust based on configuration if needed
	if a.config.MaxIPsPerDomain > 0 && a.config.MaxIPsPerDomain < 10 {
		workerCount = a.config.MaxIPsPerDomain
	}

	// Ensure at least 2 workers
	if workerCount < 2 {
		workerCount = 2
	}

	return workerCount
}

// checkRateLimit checks if the current request is within rate limits
func (a *Agent) checkRateLimit() bool {
	if !a.config.RateLimitEnabled {
		return true
	}

	a.rateLimitMutex.Lock()
	defer a.rateLimitMutex.Unlock()

	now := time.Now()

	// Reset counter if window has passed
	if now.Sub(a.lastResetTime) >= a.config.RateLimitWindow {
		atomic.StoreInt32(&a.requestCount, 0)
		a.lastResetTime = now
	}

	// Check if we're within limits
	currentCount := atomic.LoadInt32(&a.requestCount)
	if currentCount >= int32(a.config.RateLimitCount) {
		return false
	}

	// Increment counter atomically
	atomic.AddInt32(&a.requestCount, 1)
	return true
}

// processDomain processes a single domain with enhanced features
func (a *Agent) processDomain(ctx context.Context, domain string, runID int64) error {
	// Check rate limit
	if !a.checkRateLimit() {
		waitTime := a.config.RateLimitWindow - time.Since(a.lastResetTime)
		a.logger.Debugf("Rate limit reached, waiting for %v", waitTime)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(waitTime):
			// Continue after waiting
		}
	}

	// Normalize domain
	domain = strings.ToLower(strings.TrimSpace(domain))

	// Skip empty domains
	if domain == "" {
		return fmt.Errorf("empty domain name")
	}

	// Check for context cancellation
	select {
	case <-ctx.Done():
		return fmt.Errorf("context cancelled: %w", ctx.Err())
	default:
		// Continue processing
	}

	// Log domain processing
	a.logger.Debugf("Processing domain: %s", domain)

	// Check if domain is whitelisted (priority check)
	isWhitelisted, err := a.db.IsDomainWhitelisted(domain)
	if err != nil {
		return fmt.Errorf("failed to check if domain is whitelisted: %w", err)
	}

	if isWhitelisted {
		a.logger.Debugf("Domain %s is whitelisted (priority protected), skipping", domain)
		return nil
	}

	// Save domain to database as auto-update (not custom)
	// This will reset expiration if domain appears again
	domainIDInterface, err := a.db.SaveDomain(domain, false, false, a.config.RuleExpiration)
	if err != nil {
		return fmt.Errorf("failed to save domain: %w", err)
	}

	// Convert domain ID to appropriate type
	var domainID uint
	switch id := domainIDInterface.(type) {
	case uint:
		domainID = id
	case int64:
		domainID = uint(id)
	default:
		return fmt.Errorf("unexpected domain ID type: %T", domainIDInterface)
	}

	// Resolve domain
	resolver := a.selectDNSResolver()
	ips, err := a.resolver.ResolveDomain(domain, resolver)
	if err != nil {
		// Log error but don't fail the entire process - just skip this domain
		a.logger.Debugf("Failed to resolve domain %s: %v", domain, err)
		return nil
	}

	// Check if domain resolved to any IPs
	if len(ips) == 0 {
		a.logger.Debugf("Domain %s resolved to no IPs, skipping", domain)
		return nil
	}

	// Process resolved IPs
	validIPsAdded := 0
	for _, ip := range ips {
		// Skip invalid IPs
		if ip == "" {
			continue
		}

		// Parse IP to validate and check if it's critical
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			a.logger.Debugf("Invalid IP %s for domain %s, skipping", ip, domain)
			continue
		}

		// Check if IP is critical/dangerous to block
		if a.isCriticalIP(parsedIP) {
			a.logger.Warnf("Skipping critical IP %s for domain %s (potential security risk)", ip, domain)
			continue
		}

		// Check if IP is whitelisted (priority protection)
		isIPWhitelisted, err := a.db.IsIPWhitelisted(ip)
		if err != nil {
			a.logger.Warnf("Failed to check if IP %s is whitelisted: %v", ip, err)
			continue
		}

		if isIPWhitelisted {
			a.logger.Debugf("IP %s is whitelisted (priority protected), skipping", ip)
			continue
		}

		// Add IP with rotation
		if err := a.db.AddIPWithRotation(domainID, ip, a.config.MaxIPsPerDomain, a.config.RuleExpiration); err != nil {
			a.logger.Warnf("Failed to add IP %s for domain %s: %v", ip, domain, err)
			continue
		}

		validIPsAdded++
		// Update statistics
		atomic.AddInt32(&a.ipsBlocked, 1)
	}

	if validIPsAdded == 0 {
		a.logger.Debugf("No valid IPs added for domain %s", domain)
	}

	// Update statistics
	atomic.AddInt32(&a.domainsProcessed, 1)

	return nil
}

// selectDNSResolver selects a DNS resolver with load balancing
func (a *Agent) selectDNSResolver() string {
	if len(a.config.DNSResolvers) == 0 {
		return "8.8.8.8" // Default to Google DNS if none configured
	}

	if len(a.config.DNSResolvers) == 1 {
		return a.config.DNSResolvers[0]
	}

	// Use a different resolver each time for load balancing
	// based on the current nanosecond timestamp
	return a.config.DNSResolvers[int(time.Now().UnixNano())%len(a.config.DNSResolvers)]
}

// isValidDomain performs basic domain validation
func isValidDomain(domain string) bool {
	// Length check
	if len(domain) == 0 || len(domain) > 255 {
		return false
	}

	// Basic format check using regex (RFC 1034, 1035)
	// This regex is simplified but catches most invalid domains
	domainRegex := regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
	return domainRegex.MatchString(domain)
}

// isCriticalIP checks if an IP is critical/dangerous to block (system protection)
func (a *Agent) isCriticalIP(ip net.IP) bool {
	// Check for null/invalid IP
	if ip == nil {
		return true
	}

	// Check for 0.0.0.0 (any address)
	if ip.Equal(net.IPv4zero) {
		return true
	}

	// Check for IPv6 unspecified address (::)
	if ip.Equal(net.IPv6zero) {
		return true
	}

	// Check for loopback addresses (127.0.0.1, ::1)
	if ip.IsLoopback() {
		return true
	}

	// Check for multicast addresses
	if ip.IsMulticast() {
		return true
	}

	// Check for link-local addresses
	if ip.IsLinkLocalUnicast() {
		return true
	}

	// Check for broadcast address (255.255.255.255)
	if ip.Equal(net.IPv4bcast) {
		return true
	}

	// Check for private IP ranges (could be local infrastructure)
	if isPrivateIP(ip) {
		return true
	}

	// Check for specific dangerous IPv4 ranges
	if ip4 := ip.To4(); ip4 != nil {
		// 0.0.0.0/8 (this network)
		if ip4[0] == 0 {
			return true
		}
		// 224.0.0.0/4 (multicast)
		if ip4[0] >= 224 && ip4[0] <= 239 {
			return true
		}
		// 240.0.0.0/4 (reserved)
		if ip4[0] >= 240 {
			return true
		}
		// 198.18.0.0/15 (benchmark testing)
		if ip4[0] == 198 && (ip4[1] == 18 || ip4[1] == 19) {
			return true
		}
		// 203.0.113.0/24 (documentation)
		if ip4[0] == 203 && ip4[1] == 0 && ip4[2] == 113 {
			return true
		}
	}

	// Check for IPv6 special addresses
	if ip.To4() == nil {
		// Check for documentation ranges (2001:db8::/32)
		if len(ip) >= 4 && ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x0d && ip[3] == 0xb8 {
			return true
		}
		// Check for 6to4 (2002::/16)
		if len(ip) >= 2 && ip[0] == 0x20 && ip[1] == 0x02 {
			return true
		}
	}

	// TODO: Add check for server's own IP addresses and gateway
	// This would require getting system network configuration
	// For now, we rely on the whitelist to protect critical IPs

	return false
}

// isPrivateIP checks if an IP is private with comprehensive checks
func isPrivateIP(ip net.IP) bool {
	// Check for loopback
	if ip.IsLoopback() {
		return true
	}

	// Check for multicast
	if ip.IsMulticast() {
		return true
	}

	// Check for link-local
	if ip.IsLinkLocalUnicast() {
		return true
	}

	// Check for private IPv4 ranges
	if ip4 := ip.To4(); ip4 != nil {
		// 10.0.0.0/8
		if ip4[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
		// 127.0.0.0/8 (loopback)
		if ip4[0] == 127 {
			return true
		}
		// 169.254.0.0/16 (link-local)
		if ip4[0] == 169 && ip4[1] == 254 {
			return true
		}
		// 100.64.0.0/10 (Carrier-grade NAT)
		if ip4[0] == 100 && (ip4[1] >= 64 && ip4[1] <= 127) {
			return true
		}
	}

	// Check for private IPv6 ranges using the built-in method
	if ip.IsPrivate() {
		return true
	}

	// Check for specific IPv6 ranges
	if ip.To4() == nil {
		// fc00::/7 (Unique Local Address)
		if ip[0] == 0xfc || ip[0] == 0xfd {
			return true
		}
		// fe80::/10 (Link-Local Address)
		if ip[0] == 0xfe && (ip[1]&0xc0) == 0x80 {
			return true
		}
	}

	return false
}
