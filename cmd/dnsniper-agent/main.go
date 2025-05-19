package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

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
	log.SetOutput(&lumberjack.Logger{
		Filename:   "/var/log/dnsniper/agent.log",
		MaxSize:    10, // megabytes
		MaxBackups: 7,  // number of backups
		MaxAge:     30, // days
		Compress:   true,
	})
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
	if enableLogging {
		setupLogger(true)
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

	fmt.Println("DNSniper agent started")
	log.Info("DNSniper agent started")

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

func runAgentProcess(ctx context.Context, runID int64) error {
	// Get settings
	settings, err := config.GetSettings()
	if err != nil {
		return fmt.Errorf("failed to get settings: %w", err)
	}

	// Download domain list
	domains, err := utils.DownloadDomainList(settings.UpdateURL)
	if err != nil {
		return fmt.Errorf("failed to download domain list: %w", err)
	}

	log.Infof("Processing %d domains", len(domains))
	fmt.Printf("Processing %d domains...\n", len(domains))

	// Process domains with progress tracking
	totalDomains := len(domains)
	processedCount := 0
	blockedIPs := 0

	for _, domain := range domains {
		select {
		case <-ctx.Done():
			return fmt.Errorf("processing interrupted")
		default:
			processedCount++
			if processedCount%100 == 0 || processedCount == totalDomains {
				fmt.Printf("Progress: %d/%d domains processed\n", processedCount, totalDomains)
			}

			log.Infof("Processing domain %d/%d: %s", processedCount, totalDomains, domain)

			result, err := processDomain(domain, settings, runID)
			if err != nil {
				log.Errorf("Failed to process domain %s: %v", domain, err)
				// Continue with the next domain
				continue
			}

			blockedIPs += result.IPsBlocked
		}
	}

	// Cleanup expired records
	if err := database.CleanupExpiredRecords(); err != nil {
		return fmt.Errorf("cleanup failed: %w", err)
	}

	fmt.Printf("Completed: %d domains processed, %d IPs blocked\n", processedCount, blockedIPs)
	log.Infof("Completed: %d domains processed, %d IPs blocked", processedCount, blockedIPs)

	return nil
}

// Result holds processing statistics
type Result struct {
	IPsBlocked int
}

func processDomain(domain string, settings models.Settings, runID int64) (Result, error) {
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

	// Resolve domain
	resolver := dns.NewStandardResolver()
	ips, err := resolver.ResolveDomain(domain, settings.DNSResolver)
	if err != nil {
		return result, err
	}

	if len(ips) == 0 {
		log.Infof("No IPs found for domain %s", domain)
		return result, nil
	}

	// Save domain in database
	domainID, err := database.SaveDomain(domain, settings.RuleExpiration)
	if err != nil {
		return result, err
	}

	// Process IPs
	for _, ip := range ips {
		// Validate IP
		valid, err := utils.IsValidIPToBlock(ip)
		if err != nil || !valid {
			log.Warnf("Invalid IP %s for domain %s: %v", ip, domain, err)
			continue
		}

		// Check IP whitelist
		isIPWhitelisted, err := database.IsIPWhitelisted(ip)
		if err != nil {
			return result, err
		}
		if isIPWhitelisted {
			log.Infof("IP %s is whitelisted, skipping", ip)
			continue
		}

		// Add IP to database with rotation mechanism
		if err := database.AddIPWithRotation(domainID, ip, settings.MaxIPsPerDomain); err != nil {
			return result, err
		}

		// Apply iptables rules
		fwManager, err := firewall.NewIPTablesManager()
		if err != nil {
			return result, err
		}

		if err := fwManager.BlockIP(ip, settings.BlockRuleType); err != nil {
			return result, err
		}

		// Log action
		if settings.LoggingEnabled {
			database.LogAction(runID, "block", ip, "success", "")
		}

		log.Infof("Blocked IP %s for domain %s", ip, domain)
		result.IPsBlocked++
	}

	// Check for CDN
	isCDN, err := database.CheckForCDN(domainID, settings.MaxIPsPerDomain)
	if err != nil {
		return result, err
	}
	if isCDN {
		log.Infof("Domain %s flagged as potential CDN (has %d+ IPs)", domain, settings.MaxIPsPerDomain)
	}

	return result, nil
}
