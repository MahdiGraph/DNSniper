package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/MahdiGraph/DNSniper/internal/config"
	"github.com/MahdiGraph/DNSniper/internal/database"
	"github.com/MahdiGraph/DNSniper/internal/dns"
	"github.com/MahdiGraph/DNSniper/internal/firewall"
	"github.com/MahdiGraph/DNSniper/internal/models"
	"github.com/MahdiGraph/DNSniper/internal/utils"
	"github.com/nightlyone/lockfile"
	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

var log = logrus.New()
var enableLogging bool

func init() {
	// Parse command line flags
	flag.BoolVar(&enableLogging, "log", false, "Enable logging")
	flag.Parse()

	// Configure logger for basic formatting
	log.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	// By default, log to stderr with minimum info
	log.SetLevel(logrus.ErrorLevel)
}

// setupLogger configures the logger with proper rotation
func setupLogger(enabled bool) {
	if !enabled {
		log.SetOutput(os.Stderr)
		log.SetLevel(logrus.ErrorLevel)
		return
	}

	// Set to info level for detailed logging
	log.SetLevel(logrus.InfoLevel)

	// Ensure log directory exists
	err := os.MkdirAll("/var/log/dnsniper", 0755)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create log directory: %v\n", err)
		log.SetOutput(os.Stderr)
		return
	}

	// Set up lumberjack for log rotation
	logFile := &lumberjack.Logger{
		Filename:   "/var/log/dnsniper/agent.log",
		MaxSize:    10, // megabytes
		MaxBackups: 7,  // number of backups
		MaxAge:     30, // days
		Compress:   true,
	}

	// Create a multi-writer to log to both file and stderr
	multiWriter := io.MultiWriter(logFile, os.Stderr)
	log.SetOutput(multiWriter)

	// Add hook to log to a separate file for each run ID
	log.AddHook(&RunIDLogHook{basePath: "/var/log/dnsniper"})

	log.Info("Logging setup complete")
}

// RunIDLogHook is a custom hook that logs to a separate file for each run ID
type RunIDLogHook struct {
	basePath string
	runID    int64
	logFile  *os.File
	mu       sync.Mutex
}

// SetRunID sets the current run ID for logging
func (hook *RunIDLogHook) SetRunID(runID int64) {
	hook.mu.Lock()
	defer hook.mu.Unlock()

	hook.runID = runID

	// Close any existing file
	if hook.logFile != nil {
		hook.logFile.Close()
		hook.logFile = nil
	}

	// Open a new file for this run ID
	if runID > 0 {
		runLogDir := filepath.Join(hook.basePath, "runs")
		err := os.MkdirAll(runLogDir, 0755)
		if err != nil {
			log.Errorf("Failed to create run log directory: %v", err)
			return
		}

		filename := filepath.Join(runLogDir, fmt.Sprintf("run_%d.log", runID))
		f, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			log.Errorf("Failed to open run log file: %v", err)
			return
		}
		hook.logFile = f
	}
}

// Levels returns the log levels this hook should fire for
func (hook *RunIDLogHook) Levels() []logrus.Level {
	return []logrus.Level{
		logrus.PanicLevel,
		logrus.FatalLevel,
		logrus.ErrorLevel,
		logrus.WarnLevel,
		logrus.InfoLevel,
	}
}

// Fire is called when a log event occurs
func (hook *RunIDLogHook) Fire(entry *logrus.Entry) error {
	hook.mu.Lock()
	defer hook.mu.Unlock()

	if hook.logFile == nil || hook.runID <= 0 {
		return nil
	}

	// Format log entry
	line, err := entry.String()
	if err != nil {
		return err
	}

	// Write to run's log file
	if _, err := hook.logFile.WriteString(line); err != nil {
		return err
	}

	return nil
}

func main() {
	// Initialize database if not exists
	dbConn, err := database.Initialize()
	if err != nil {
		log.Errorf("Failed to initialize database: %v", err)
		fmt.Fprintf(os.Stderr, "Failed to initialize database: %v\n", err)
		os.Exit(1)
	}

	// Set database connection for config package
	config.SetDatabase(dbConn)

	// Check if logging is enabled in settings if not explicitly set by flag
	if !enableLogging {
		settings, err := config.GetSettings()
		if err == nil && settings.LoggingEnabled {
			enableLogging = true
		}
	}

	// Setup logging based on the final decision
	setupLogger(enableLogging)

	// Clean up expired records before acquiring lock
	if err := database.CleanupExpiredRecords(); err != nil {
		log.Warnf("Failed to cleanup expired records: %v", err)
	}

	// Acquire lock to ensure only one instance is running
	if err := acquireLock(); err != nil {
		if err == lockfile.ErrBusy {
			log.Error("Another instance of DNSniper agent is already running")
			fmt.Fprintf(os.Stderr, "Another instance of DNSniper agent is already running\n")
			os.Exit(1)
		}
		log.Errorf("Failed to acquire lock: %v", err)
		fmt.Fprintf(os.Stderr, "Failed to acquire lock: %v\n", err)
		os.Exit(1)
	}

	// Create context that can be cancelled
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle system signals
	setupSignalHandling(cancel)

	// Log agent start
	runID, err := database.LogAgentStart()
	if err != nil {
		log.Errorf("Failed to log agent start: %v", err)
		fmt.Fprintf(os.Stderr, "Failed to log agent start: %v\n", err)
		os.Exit(1)
	}

	// Set the run ID for per-run logging if hook exists
	for _, hook := range log.Hooks {
		if runIDHook, ok := hook.(*RunIDLogHook); ok {
			runIDHook.SetRunID(runID)
			break
		}
	}

	fmt.Println("DNSniper agent started")
	log.Info("DNSniper agent started")

	// Apply existing IP blocklist rules from database
	if err := applyExistingRules(); err != nil {
		log.Warnf("Failed to apply existing rules: %v", err)
	}

	// Run agent process
	if err := runAgentProcess(ctx, runID); err != nil {
		database.LogAgentError(runID, err)
		log.Errorf("Agent process failed: %v", err)
		fmt.Fprintf(os.Stderr, "Agent process failed: %v\n", err)
		os.Exit(1)
	}

	// Log agent completion
	if err := database.LogAgentCompletion(runID); err != nil {
		log.Errorf("Failed to log agent completion: %v", err)
		fmt.Fprintf(os.Stderr, "Failed to log agent completion: %v\n", err)
		os.Exit(1)
	}

	log.Info("DNSniper agent completed successfully")
	fmt.Println("DNSniper agent completed successfully")
}

func acquireLock() error {
	lockPath := "/var/run/dnsniper.lock"

	// Ensure directory exists
	if err := os.MkdirAll("/var/run", 0755); err != nil {
		return fmt.Errorf("failed to create lock directory: %w", err)
	}

	lock, err := lockfile.New(lockPath)
	if err != nil {
		return fmt.Errorf("failed to create lock: %w", err)
	}

	// Check current lock status
	if err := lock.TryLock(); err != nil {
		if err == lockfile.ErrBusy {
			// Try to get owner PID
			pidStr, err := lock.GetOwner()
			if err != nil {
				return fmt.Errorf("lock is busy but can't determine owner: %w", err)
			}

			// Check if PID exists
			pid := os.Process{Pid: pidStr.Pid}
			err = pid.Signal(syscall.Signal(0))

			// If process doesn't exist, try to unlock the stale lock
			if err != nil {
				log.Warn("Found stale lock, attempting to remove it")
				if err := os.Remove(lockPath); err != nil {
					return fmt.Errorf("failed to remove stale lock: %w", err)
				}
				// Try to lock again
				return lock.TryLock()
			}
			return lockfile.ErrBusy
		}
		return err
	}

	return nil
}

func setupSignalHandling(cancel context.CancelFunc) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Info("Received termination signal, shutting down gracefully...")
		cancel()
	}()
}

func applyExistingRules() error {
	// Get existing blocked IPs and IP ranges from database
	ips, ranges, err := database.GetAllBlockedIPs()
	if err != nil {
		return fmt.Errorf("failed to get blocked IPs: %w", err)
	}

	if len(ips) > 0 || len(ranges) > 0 {
		log.Infof("Applying rules for %d IPs and %d IP ranges", len(ips), len(ranges))

		// Get block rule type from settings
		settings, err := config.GetSettings()
		if err != nil {
			return fmt.Errorf("failed to get settings: %w", err)
		}

		// Initialize firewall manager
		fwManager, err := firewall.NewIPTablesManager()
		if err != nil {
			return fmt.Errorf("failed to initialize firewall manager: %w", err)
		}

		// First clear all existing rules to prevent duplicates
		if err := fwManager.ClearRules(); err != nil {
			return fmt.Errorf("failed to clear existing rules: %w", err)
		}

		// Apply individual IP rules
		appliedCount := 0
		for _, ip := range ips {
			if err := fwManager.BlockIP(ip, settings.BlockRuleType); err != nil {
				log.Warnf("Failed to block IP %s: %v", ip, err)
				continue
			}
			appliedCount++
		}

		// Apply IP range rules
		rangeCount := 0
		for _, cidr := range ranges {
			if err := fwManager.BlockIPRange(cidr, settings.BlockRuleType); err != nil {
				log.Warnf("Failed to block IP range %s: %v", cidr, err)
				continue
			}
			rangeCount++
		}

		log.Infof("Applied firewall rules for %d IPs and %d IP ranges", appliedCount, rangeCount)
	} else {
		log.Info("No existing rules to apply")
	}

	return nil
}

func runAgentProcess(ctx context.Context, runID int64) error {
	// Get settings
	settings, err := config.GetSettings()
	if err != nil {
		return fmt.Errorf("failed to get settings: %w", err)
	}

	// Get all update URLs
	urls, err := database.GetUpdateURLs()
	if err != nil {
		return fmt.Errorf("failed to get update URLs: %w", err)
	}
	if len(urls) == 0 {
		log.Warn("No update URLs configured. Adding default URL.")
		if err := database.AddUpdateURL("https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/domains-default.txt"); err != nil {
			return fmt.Errorf("failed to add default URL: %w", err)
		}
		urls = append(urls, "https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/domains-default.txt")
	}

	// Track domains we've seen this run
	seenDomains := make(map[string]bool)
	totalDomains := 0
	totalProcessed := 0
	totalBlocked := 0

	// Setup worker pool for concurrent domain processing
	workerCount := 5
	domainChan := make(chan string, 100)
	resultChan := make(chan Result, 100)
	errorChan := make(chan error, 100)

	// Set up a wait group for workers
	var wg sync.WaitGroup

	// Start worker goroutines
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range domainChan {
				// Process with timeout context
				procCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
				result, err := processDomain(procCtx, domain, settings, runID, "")
				cancel()

				if err != nil {
					// Don't break on error, just report it
					select {
					case errorChan <- fmt.Errorf("failed to process domain %s: %w", domain, err):
					default:
						// Channel is full, log instead
						log.Errorf("Failed to process domain %s: %v", domain, err)
					}
				} else {
					select {
					case resultChan <- result:
					default:
						// Channel is full, log instead
						log.Infof("Processed domain %s: %+v", domain, result)
					}
				}
			}
		}()
	}

	// Process each URL
	urlProcessed := 0
	for _, url := range urls {
		select {
		case <-ctx.Done():
			close(domainChan) // Tell workers to stop
			wg.Wait()         // Wait for them to finish
			return fmt.Errorf("processing interrupted")
		default:
			urlProcessed++
			log.Infof("Processing domains from URL %d/%d: %s", urlProcessed, len(urls), url)
			fmt.Printf("Processing domains from URL %d/%d: %s\n", urlProcessed, len(urls), url)

			// Download domain list from this URL
			domains, err := utils.DownloadDomainList(url)
			if err != nil {
				log.Errorf("Failed to download domain list from %s: %v", url, err)
				fmt.Printf("Failed to download domain list from %s: %v\n", url, err)
				continue // Try next URL
			}

			totalDomains += len(domains)
			log.Infof("Downloaded %d domains from %s", len(domains), url)
			fmt.Printf("Downloaded %d domains from %s\n", len(domains), url)

			// Add domains to processing channel
			domainsSent := 0
			batchSize := 50 // Process in batches to avoid overwhelming channels
			for _, domain := range domains {
				// Skip if we've already seen this domain in this run
				if seenDomains[domain] {
					continue
				}

				seenDomains[domain] = true

				// Send domain for processing
				select {
				case domainChan <- domain:
					domainsSent++

					// Process results after each batch
					if domainsSent%batchSize == 0 {
						processResults(resultChan, errorChan, &totalProcessed, &totalBlocked, totalDomains)

						// Small delay between batches to avoid overwhelming system
						time.Sleep(100 * time.Millisecond)
					}
				case <-ctx.Done():
					close(domainChan)
					wg.Wait()
					return fmt.Errorf("processing interrupted")
				}
			}

			// Process remaining results for this URL
			processResults(resultChan, errorChan, &totalProcessed, &totalBlocked, totalDomains)
		}
	}

	// Close the domain channel to signal no more domains will be sent
	close(domainChan)

	// Wait for all workers to finish
	wg.Wait()

	// Process any remaining results
	processResults(resultChan, errorChan, &totalProcessed, &totalBlocked, totalDomains)

	// Update expiration for domains that weren't seen in this run
	if err := database.ExpireUnseenDomains(seenDomains); err != nil {
		log.Warnf("Failed to update expiration for unseen domains: %v", err)
	}

	fmt.Printf("Completed: %d domains processed, %d IPs blocked\n", totalProcessed, totalBlocked)
	log.Infof("Completed: %d domains processed, %d IPs blocked", totalProcessed, totalBlocked)
	return nil
}

// processResults handles processing results and errors from channels
func processResults(resultChan chan Result, errorChan chan error, totalProcessed *int, totalBlocked *int, totalDomains int) {
	// Process all available results without blocking
	for {
		select {
		case result := <-resultChan:
			*totalProcessed++
			*totalBlocked += result.IPsBlocked
			if *totalProcessed%100 == 0 || *totalProcessed == totalDomains {
				fmt.Printf("Progress: %d/%d domains processed, %d IPs blocked\n", *totalProcessed, totalDomains, *totalBlocked)
			}
		case err := <-errorChan:
			log.Error(err)
		default:
			// No more results available at this moment
			return
		}
	}
}

// Result holds processing statistics
type Result struct {
	IPsBlocked int
}

// processDomain now accepts a context for timeout support
func processDomain(ctx context.Context, domain string, settings models.Settings, runID int64, sourceURL string) (Result, error) {
	result := Result{}

	// Check whitelist
	isWhitelisted, err := database.IsDomainWhitelisted(domain)
	if err != nil {
		return result, err
	}
	if isWhitelisted {
		log.Infof("Domain %s is whitelisted, skipping", domain)
		return result, nil
	}

	// Resolve domain with retry and timeout
	const maxRetries = 3
	var ips []string
	resolver := dns.NewStandardResolver()
	var lastErr error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		// Check if context has been canceled
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		// Resolve the domain - NOTE: Adjusted to work with the standard DNS resolver
		ips, err = resolver.ResolveDomain(domain, settings.DNSResolver)

		if err == nil {
			break
		}

		lastErr = err
		log.Warnf("Attempt %d: Failed to resolve domain %s: %v", attempt, domain, err)

		// Check context before sleeping
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
			// Only sleep if not the last attempt
			if attempt < maxRetries {
				time.Sleep(time.Duration(attempt) * 500 * time.Millisecond)
			}
		}
	}

	if lastErr != nil && len(ips) == 0 {
		log.Errorf("Failed to resolve domain %s after %d attempts: %v", domain, maxRetries, lastErr)
		// Still save the domain to database for tracking
		if _, err := database.SaveDomain(domain, settings.RuleExpiration, sourceURL); err != nil {
			return result, err
		}
		return result, nil
	}

	// Save domain in database (with source URL for auto-downloaded domains)
	domainID, err := database.SaveDomain(domain, settings.RuleExpiration, sourceURL)
	if err != nil {
		return result, err
	}

	// Get domain custom status
	var isCustomDomain bool
	err = database.GetDomainCustomStatus(domainID, &isCustomDomain)
	if err != nil {
		log.Warnf("Failed to get domain custom status: %v", err)
	}

	// Process IPs with batching to avoid overwhelming the database and firewall
	ipBatchSize := 10
	ipBatch := make([]string, 0, ipBatchSize)

	for _, ip := range ips {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		// Validate IP
		valid, err := utils.IsValidIPToBlock(ip)
		if err != nil || !valid {
			log.Warnf("Invalid IP %s for domain %s: %v", ip, domain, err)
			continue
		}

		// Check IP whitelist - skip if whitelisted
		isIPWhitelisted, err := database.IsIPWhitelisted(ip)
		if err != nil {
			log.Warnf("Error checking if IP %s is whitelisted: %v", ip, err)
			continue
		}

		if isIPWhitelisted {
			log.Infof("IP %s is whitelisted for domain %s, skipping", ip, domain)
			continue
		}

		// Add to the batch
		ipBatch = append(ipBatch, ip)

		// Process batch when it reaches the batch size
		if len(ipBatch) >= ipBatchSize {
			blockedCount := processIPBatch(ipBatch, domainID, domain, isCustomDomain, settings, runID)
			result.IPsBlocked += blockedCount
			ipBatch = ipBatch[:0] // Clear batch
		}
	}

	// Process any remaining IPs in the batch
	if len(ipBatch) > 0 {
		blockedCount := processIPBatch(ipBatch, domainID, domain, isCustomDomain, settings, runID)
		result.IPsBlocked += blockedCount
	}

	// Check for CDN status and update if needed
	isCDN, err := database.CheckForCDN(domainID, settings.MaxIPsPerDomain)
	if err != nil {
		log.Warnf("Failed to check CDN status for domain %s: %v", domain, err)
	}
	if isCDN {
		log.Infof("Domain %s flagged as potential CDN (has %d+ IPs)", domain, settings.MaxIPsPerDomain)
	}

	return result, nil
}

// processIPBatch processes a batch of IPs for efficient database and firewall updates
func processIPBatch(ips []string, domainID int64, domain string, isCustomDomain bool, settings models.Settings, runID int64) int {
	if len(ips) == 0 {
		return 0
	}

	blockedCount := 0
	var expirationToUse time.Duration

	if isCustomDomain {
		expirationToUse = 0 // No expiration for custom domains
	} else {
		expirationToUse = settings.RuleExpiration
	}

	// Initialize firewall manager once for the batch
	fwManager, err := firewall.NewIPTablesManager()
	if err != nil {
		log.Errorf("Failed to initialize firewall manager: %v", err)
		return 0
	}

	// Process each IP in the batch
	for _, ip := range ips {
		// Add IP to database with rotation mechanism
		if err := database.AddIPWithRotation(domainID, ip, settings.MaxIPsPerDomain, expirationToUse); err != nil {
			log.Warnf("Failed to add IP %s to database: %v", ip, err)
			continue
		}

		// Apply iptables rules
		if err := fwManager.BlockIP(ip, settings.BlockRuleType); err != nil {
			log.Warnf("Failed to block IP %s: %v", ip, err)
			continue
		}

		// Log action
		if settings.LoggingEnabled {
			database.LogAction(runID, "block", ip, "success", domain)
		}

		log.Infof("Blocked IP %s for domain %s", ip, domain)
		blockedCount++
	}

	// Save firewall changes after processing the batch
	if blockedCount > 0 {
		if err := fwManager.SaveRulesToPersistentFiles(); err != nil {
			log.Warnf("Failed to save firewall rules: %v", err)
		}
	}

	return blockedCount
}
