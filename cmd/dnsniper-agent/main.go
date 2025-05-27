package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/MahdiGraph/DNSniper/internal/agent"
	"github.com/MahdiGraph/DNSniper/internal/dns"
	"github.com/MahdiGraph/DNSniper/internal/system"
	"github.com/nightlyone/lockfile"
)

func main() {
	// Parse command line flags
	var showHelp = flag.Bool("help", false, "Show help information")
	var showVersion = flag.Bool("version", false, "Show version information")
	var configPath = flag.String("config", "", "Path to configuration file")
	var verbose = flag.Bool("verbose", false, "Enable verbose logging (prints all logs to stdout)")
	flag.Parse()

	// Handle help flag
	if *showHelp {
		fmt.Println("DNSniper Agent v2.1")
		fmt.Println("Automated DNS firewall agent")
		fmt.Println("")
		fmt.Println("Usage: dnsniper-agent [options]")
		fmt.Println("")
		fmt.Println("Options:")
		fmt.Println("  --help     Show this help message")
		fmt.Println("  --version  Show version information")
		fmt.Println("  --config   Path to configuration file (optional)")
		fmt.Println("  --verbose  Enable verbose logging (prints all logs to stdout)")
		fmt.Println("")
		fmt.Println("Agent Features:")
		fmt.Println("• Complete system initialization (config, ipsets, rules)")
		fmt.Println("• GORM database integration with automatic callbacks")
		fmt.Println("• DNS resolution with load balancing")
		fmt.Println("• Whitelist priority protection system")
		fmt.Println("• CDN detection and handling")
		fmt.Println("• FIFO IP management per domain")
		fmt.Println("• Real-time firewall rule synchronization")
		fmt.Println("• Comprehensive error handling and logging")
		fmt.Println("")
		fmt.Println("Verbose Mode:")
		fmt.Println("  Use --verbose flag to see all logs in real-time")
		fmt.Println("  Useful for debugging and system testing")
		os.Exit(0)
	}

	// Handle version flag
	if *showVersion {
		fmt.Println("DNSniper Agent v2.1")
		fmt.Println("Automated DNS Firewall Agent")
		os.Exit(0)
	}

	// Initialize system with verbose logging if requested
	initializer := system.NewSystemInitializer(*verbose)

	if *verbose {
		fmt.Println("DNSniper Agent v2.1 - Verbose Mode Enabled")
		fmt.Println("========================================")
	}

	// Perform complete system initialization
	if err := initializer.Initialize(*configPath); err != nil {
		fmt.Fprintf(os.Stderr, "System initialization failed: %v\n", err)
		os.Exit(1)
	}

	// Get initialized components
	cfg := initializer.GetConfig()
	log := initializer.GetLogger()
	fwManager := initializer.GetFirewallManager()
	db := initializer.GetDatabase()

	// Ensure cleanup on exit
	defer func() {
		if err := initializer.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Cleanup error: %v\n", err)
		}
	}()

	// Log startup with configuration details
	log.Info("DNSniper Agent v2.1 starting")
	log.Infof("Configuration loaded from: %s", cfg.ConfigPath)
	log.Infof("Database path: %s", cfg.DatabasePath)
	log.Infof("Log path: %s", cfg.LogPath)
	log.Infof("DNS Resolvers: %v", cfg.DNSResolvers)
	log.Infof("Update interval: %v", cfg.UpdateInterval)
	log.Infof("Rule expiration: %v", cfg.RuleExpiration)
	log.Infof("Max IPs per domain: %d", cfg.MaxIPsPerDomain)
	log.Infof("IPv6 enabled: %v", cfg.EnableIPv6)
	log.Infof("Affected chains: %v", cfg.AffectedChains)
	log.Infof("Verbose logging: %v", *verbose)

	// Initialize DNS resolver
	log.Info("Initializing DNS resolver...")
	resolver := dns.NewStandardResolver()

	// Check for and acquire lock file to ensure only one agent runs at a time
	lockPath := filepath.Join(os.TempDir(), "dnsniper.lock")
	lock, err := lockfile.New(lockPath)
	if err != nil {
		log.Errorf("Failed to create lock: %v", err)
		fmt.Fprintf(os.Stderr, "Failed to create lock: %v\n", err)
		os.Exit(1)
	}

	// Try to acquire lock with timeout
	lockTimeout := 5 * time.Second
	lockCtx, lockCancel := context.WithTimeout(context.Background(), lockTimeout)
	defer lockCancel()

	// Try to acquire lock until timeout
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	lockAcquired := false
	for {
		select {
		case <-lockCtx.Done():
			if !lockAcquired {
				log.Errorf("Failed to acquire lock after %v: another instance may be running", lockTimeout)
				fmt.Fprintf(os.Stderr, "Failed to acquire lock: another instance may be running\n")
				os.Exit(1)
			}
		case <-ticker.C:
			err := lock.TryLock()
			if err == nil {
				lockAcquired = true
				lockCancel()
			}
		}
		if lockAcquired {
			break
		}
	}
	defer func() {
		if err := lock.Unlock(); err != nil {
			log.Warnf("Failed to release lock: %v", err)
		}
	}()

	// Create agent with GORM interface
	log.Info("Creating agent...")
	agentInstance := agent.NewAgent(cfg, db, resolver, fwManager, log)

	// Setup context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Infof("Received signal %v, stopping agent...", sig)
		if *verbose {
			fmt.Printf("[INFO] Received signal %v, stopping agent...\n", sig)
		}
		cancel()
	}()

	// Run the agent
	log.Info("Starting DNSniper agent...")
	if *verbose {
		fmt.Println("[INFO] Starting DNSniper agent...")
	}

	if err := agentInstance.Run(ctx); err != nil {
		if err == context.Canceled {
			log.Info("Agent stopped gracefully")
			if *verbose {
				fmt.Println("[INFO] Agent stopped gracefully")
			}
		} else {
			log.Errorf("Agent error: %v", err)
			fmt.Fprintf(os.Stderr, "Agent error: %v\n", err)
			os.Exit(1)
		}
	}

	log.Info("DNSniper agent completed successfully")
	if *verbose {
		fmt.Println("[INFO] DNSniper agent completed successfully")
	}
}
