package agent

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/MahdiGraph/DNSniper/internal/config"
	"github.com/MahdiGraph/DNSniper/internal/database"
	"github.com/MahdiGraph/DNSniper/internal/dns"
	"github.com/MahdiGraph/DNSniper/internal/firewall"
	"github.com/MahdiGraph/DNSniper/pkg/logger"
	"github.com/nightlyone/lockfile"
)

// Agent represents the DNSniper agent with GORM compatibility
type Agent struct {
	config          *config.Settings
	db              database.DatabaseStore // Use interface for GORM compatibility
	resolver        dns.Resolver
	firewallManager *firewall.FirewallManager
	logger          *logger.Logger

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
	}
}

// Run executes the agent process with enhanced features
func (a *Agent) Run(ctx context.Context) error {
	// Clean up expired records
	a.logger.Info("Cleaning up expired records...")
	if err := a.db.CleanupExpired(); err != nil {
		a.logger.Warnf("Failed to clean up expired records: %v", err)
	}

	// Acquire lock file to ensure only one agent runs at a time
	lockPath := "/var/run/dnsniper.lock"
	lock, err := lockfile.New(lockPath)
	if err != nil {
		return fmt.Errorf("failed to create lock: %w", err)
	}

	if err := lock.TryLock(); err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer lock.Unlock()

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

			// Download domain list
			domains, err := a.downloadDomainList(updateURL)
			if err != nil {
				a.logger.Warnf("Failed to download domain list from %s: %v", updateURL, err)
				continue
			}

			// Process domains
			a.logger.Infof("Downloaded %d domains from %s", len(domains), updateURL)
			totalDomains += len(domains)

			// Create worker pool with reasonable worker count
			workerCount := 10 // Balanced for concurrent processing
			if a.config.MaxIPsPerDomain > 0 && a.config.MaxIPsPerDomain < 10 {
				workerCount = a.config.MaxIPsPerDomain
			}
			pool := NewWorkerPool(workerCount)
			pool.Start(ctx)

			// Submit domains to worker pool
			for _, domain := range domains {
				// Skip if already seen
				if seenDomains[domain] {
					continue
				}
				seenDomains[domain] = true

				// Submit to worker pool
				pool.Submit(&ProcessDomainItem{
					Domain: domain,
					RunID:  int64(runID), // Convert to int64 for compatibility
					Agent:  a,
				})
			}

			// Process results
			go func() {
				for err := range pool.Results() {
					if err != nil {
						a.logger.Warnf("Error processing domain: %v", err)
					}
				}
			}()

			// Stop worker pool
			pool.Stop()
		}
	}

	// Update expiration for domains not seen in this run
	a.logger.Info("Updating expiration for unseen domains...")
	if err := a.db.ExpireUnseenDomains(runID); err != nil {
		a.logger.Warnf("Failed to update expiration for unseen domains: %v", err)
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

// downloadDomainList downloads a list of domains from the given URL
func (a *Agent) downloadDomainList(url string) ([]string, error) {
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Download domain list
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to download domain list: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to download domain list: HTTP %d", resp.StatusCode)
	}

	// Read response body
	body, err := ioutil.ReadAll(resp.Body)
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

// processDomain processes a single domain with enhanced features
func (a *Agent) processDomain(ctx context.Context, domain string, runID int64) error {
	// Normalize domain
	domain = strings.ToLower(strings.TrimSpace(domain))

	// Skip empty domains
	if domain == "" {
		return nil
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
	var domainID interface{}
	switch id := domainIDInterface.(type) {
	case uint:
		domainID = id
	case int64:
		domainID = id
	default:
		return fmt.Errorf("unexpected domain ID type: %T", domainIDInterface)
	}

	// Increment domains processed counter
	atomic.AddInt32(&a.domainsProcessed, 1)

	// Resolve domain using configured DNS resolvers
	resolver := a.config.DNSResolvers[0]
	if len(a.config.DNSResolvers) > 1 {
		// Use a different resolver each time for load balancing
		resolver = a.config.DNSResolvers[int(time.Now().UnixNano())%len(a.config.DNSResolvers)]
	}

	ips, err := a.resolver.ResolveDomain(domain, resolver)
	if err != nil {
		a.logger.Warnf("Failed to resolve domain %s: %v", domain, err)
		// Continue even if resolution fails
		return nil
	}

	// Process resolved IPs
	if len(ips) == 0 {
		a.logger.Debugf("No IPs found for domain %s", domain)
		return nil
	}

	a.logger.Debugf("Found %d IPs for domain %s", len(ips), domain)

	// Process each IP with enhanced validation and FIFO mechanism
	blocked := 0
	for _, ip := range ips {
		// Validate IP
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			a.logger.Warnf("Invalid IP address: %s", ip)
			continue
		}

		// Skip private IPs
		if isPrivateIP(parsedIP) {
			a.logger.Debugf("Skipping private IP: %s", ip)
			continue
		}

		// Check if IP is whitelisted (priority protection)
		isIPWhitelisted, err := a.db.IsIPWhitelisted(ip)
		if err != nil {
			a.logger.Warnf("Failed to check if IP is whitelisted: %v", err)
			continue
		}

		if isIPWhitelisted {
			a.logger.Debugf("IP %s is whitelisted (priority protected), skipping", ip)
			continue
		}

		// Add IP to database with FIFO rotation mechanism
		err = a.db.AddIPWithRotation(domainID, ip, a.config.MaxIPsPerDomain, a.config.RuleExpiration)
		if err != nil {
			a.logger.Warnf("Failed to add IP to database: %v", err)
			continue
		}

		// The IP is automatically added to ipset via GORM hooks
		// But we still increment our counter
		blocked++
		atomic.AddInt32(&a.ipsBlocked, 1)

		// Log action
		a.logger.Infof("Blocked IP %s for domain %s", ip, domain)
		a.db.LogAction(runID, "block", ip, "success", domain)
	}

	// Check if domain might be a CDN (based on IP count threshold)
	isCDN, err := a.db.CheckForCDN(domainID, 2) // Flag as CDN if >2 IPs
	if err != nil {
		a.logger.Warnf("Failed to check CDN status for domain %s: %v", domain, err)
	} else if isCDN {
		a.logger.Infof("Domain %s flagged as potential CDN (has multiple IPs)", domain)
	}

	return nil
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
	}

	// Check for private IPv6 ranges using the built-in method
	if ip.IsPrivate() {
		return true
	}

	return false
}
