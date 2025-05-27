package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/MahdiGraph/DNSniper/internal/config"
	"github.com/MahdiGraph/DNSniper/internal/database"
	"github.com/MahdiGraph/DNSniper/internal/dns"
	"github.com/MahdiGraph/DNSniper/internal/firewall"
	"github.com/MahdiGraph/DNSniper/pkg/logger"
)

// BatchProcessor handles batch processing of DNS requests
type BatchProcessor struct {
	config          *config.Settings
	db              database.DatabaseStore
	resolver        dns.Resolver
	firewallManager *firewall.FirewallManager
	logger          *logger.Logger
}

// NewBatchProcessor creates a new batch processor
func NewBatchProcessor(
	config *config.Settings,
	db database.DatabaseStore,
	resolver dns.Resolver,
	firewallManager *firewall.FirewallManager,
	logger *logger.Logger,
) *BatchProcessor {
	return &BatchProcessor{
		config:          config,
		db:              db,
		resolver:        resolver,
		firewallManager: firewallManager,
		logger:          logger,
	}
}

// Run executes the batch processor
func (b *BatchProcessor) Run(ctx context.Context) error {
	b.logger.Info("Starting DNSniper batch processor")

	// Clean up expired records first
	if err := b.db.CleanupExpired(); err != nil {
		b.logger.Errorf("Failed to cleanup expired records: %v", err)
		return fmt.Errorf("cleanup failed: %w", err)
	}

	// Reload firewall rules to ensure they're up to date
	if err := b.firewallManager.Reload(); err != nil {
		b.logger.Errorf("Failed to reload firewall rules: %v", err)
		return fmt.Errorf("firewall reload failed: %w", err)
	}

	b.logger.Info("DNSniper batch processor completed successfully")
	return nil
}

func main() {
	// Parse command line flags
	configPath := flag.String("config", "", "Path to configuration file")
	showHelp := flag.Bool("help", false, "Show help message")
	showVersion := flag.Bool("version", false, "Show version information")
	uninstall := flag.Bool("uninstall", false, "Uninstall DNSniper")
	flag.Parse()

	// Handle help flag
	if *showHelp {
		fmt.Println("DNSniper v2.0 - Automated DNS Firewall")
		fmt.Println("\nUsage:")
		fmt.Println("  dnsniper [options]")
		fmt.Println("\nOptions:")
		fmt.Println("  --config <path>    Path to configuration file")
		fmt.Println("  --help             Show this help message")
		fmt.Println("  --version          Show version information")
		fmt.Println("  --uninstall        Uninstall DNSniper")
		fmt.Println("\nFeatures:")
		fmt.Println("• GORM database integration with automatic callbacks")
		fmt.Println("• DNS resolution with load balancing")
		fmt.Println("• Whitelist priority protection system")
		fmt.Println("• CDN detection and handling")
		fmt.Println("• FIFO IP management per domain")
		fmt.Println("• Real-time firewall rule synchronization")
		fmt.Println("• Comprehensive error handling and logging")
		os.Exit(0)
	}

	// Handle version flag
	if *showVersion {
		fmt.Println("DNSniper v2.0")
		fmt.Println("Automated DNS Firewall")
		os.Exit(0)
	}

	// Handle uninstall flag
	if *uninstall {
		handleUninstall()
		os.Exit(0)
	}

	// Load configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Ensure log directory exists
	if cfg.LoggingEnabled {
		if err := os.MkdirAll(cfg.LogPath, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create log directory: %v\n", err)
			// Continue with logging disabled
			cfg.LoggingEnabled = false
		}
	}

	// Initialize logger
	logConfig := logger.Config{
		LogDir:     cfg.LogPath,
		EnableFile: cfg.LoggingEnabled,
		Level:      cfg.LogLevel,
		MaxSize:    10,
		MaxBackups: 5,
		MaxAge:     30,
		Compress:   true,
	}
	log := logger.New(logConfig)
	defer log.Close()

	// Log startup with configuration details
	log.Info("DNSniper v2.0 starting")
	log.Infof("Configuration loaded from: %s", cfg.ConfigPath)
	log.Infof("Database path: %s", cfg.DatabasePath)
	log.Infof("Log path: %s", cfg.LogPath)
	log.Infof("DNS Resolvers: %v", cfg.DNSResolvers)
	log.Infof("Update interval: %v", cfg.UpdateInterval)
	log.Infof("Rule expiration: %v", cfg.RuleExpiration)
	log.Infof("Max IPs per domain: %d", cfg.MaxIPsPerDomain)
	log.Infof("IPv6 enabled: %v", cfg.EnableIPv6)
	log.Infof("Affected chains: %v", cfg.AffectedChains)

	// Initialize firewall manager first (needed for database callbacks)
	log.Info("Initializing firewall manager...")
	fwManager, err := firewall.NewFirewallManager(
		cfg.EnableIPv6,
		cfg.AffectedChains,
		filepath.Join(cfg.LogPath, "firewall-backup"),
		filepath.Join(cfg.LogPath, "firewall.log"),
	)
	if err != nil {
		log.Errorf("Failed to initialize firewall manager: %v", err)
		fmt.Fprintf(os.Stderr, "Failed to initialize firewall manager: %v\n", err)
		os.Exit(1)
	}
	log.Info("Firewall manager initialized successfully")

	// Initialize database using enhanced factory system with callback integration
	log.Info("Initializing database...")
	dbFactory := database.NewDatabaseFactory(fwManager)
	db, err := dbFactory.CreateDatabaseWithAutoDetection(cfg.DatabasePath)
	if err != nil {
		log.Errorf("Failed to initialize database: %v", err)
		fmt.Fprintf(os.Stderr, "Failed to initialize database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// Initialize DNS resolver
	log.Info("Initializing DNS resolver...")
	resolver := dns.NewStandardResolver()

	// Create batch processor
	processor := NewBatchProcessor(cfg, db, resolver, fwManager, log)

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Run the batch processor
	if err := processor.Run(ctx); err != nil {
		log.Errorf("Batch processor failed: %v", err)
		fmt.Fprintf(os.Stderr, "Batch processor failed: %v\n", err)
		os.Exit(1)
	}
}

// handleUninstall handles the uninstallation process
func handleUninstall() {
	fmt.Println("🗑️  Starting DNSniper uninstallation process...")

	// Stop services first
	fmt.Println("Stopping DNSniper services...")
	stopCmd := exec.Command("systemctl", "stop", "dnsniper-agent.service")
	if err := stopCmd.Run(); err != nil {
		fmt.Printf("Warning: Failed to stop agent service: %v\n", err)
	}

	stopTimerCmd := exec.Command("systemctl", "stop", "dnsniper-agent.timer")
	if err := stopTimerCmd.Run(); err != nil {
		fmt.Printf("Warning: Failed to stop agent timer: %v\n", err)
	}

	// Disable services
	fmt.Println("Disabling DNSniper services...")
	disableCmd := exec.Command("systemctl", "disable", "dnsniper-agent.service")
	disableCmd.Run() // Ignore errors

	disableTimerCmd := exec.Command("systemctl", "disable", "dnsniper-agent.timer")
	disableTimerCmd.Run() // Ignore errors

	// Remove firewall rules
	fmt.Println("Removing firewall rules...")
	removeFirewallRules()

	// Remove service files
	fmt.Println("Removing service files...")
	os.Remove("/etc/systemd/system/dnsniper-agent.service")
	os.Remove("/etc/systemd/system/dnsniper-agent.timer")

	// Reload systemd
	reloadCmd := exec.Command("systemctl", "daemon-reload")
	reloadCmd.Run()

	// Remove binaries
	fmt.Println("Removing binaries...")
	os.Remove("/usr/bin/dnsniper")
	os.Remove("/usr/bin/dnsniper-agent")
	os.Remove("/usr/local/bin/dnsniper")
	os.Remove("/usr/local/bin/dnsniper-agent")

	// Remove configuration and data directories
	fmt.Println("Removing configuration and data...")
	os.RemoveAll("/etc/dnsniper")
	os.RemoveAll("/var/log/dnsniper")
	os.RemoveAll("/var/lib/dnsniper")

	fmt.Println("✅ DNSniper uninstallation completed successfully!")
	fmt.Println("Thank you for using DNSniper!")
}

// removeFirewallRules removes all DNSniper firewall rules
func removeFirewallRules() {
	// List of ipset names to remove
	ipsetNames := []string{
		"whitelistIP-v4", "whitelistRange-v4", "blocklistIP-v4", "blocklistRange-v4",
		"whitelistIP-v6", "whitelistRange-v6", "blocklistIP-v6", "blocklistRange-v6",
	}

	// Remove iptables rules first
	chains := []string{"INPUT", "OUTPUT", "FORWARD"}
	for _, chain := range chains {
		for _, setName := range ipsetNames {
			// Remove IPv4 rules
			removeCmd := exec.Command("iptables", "-D", chain, "-m", "set", "--match-set", setName, "src", "-j", "ACCEPT")
			removeCmd.Run() // Ignore errors
			removeCmd = exec.Command("iptables", "-D", chain, "-m", "set", "--match-set", setName, "src", "-j", "DROP")
			removeCmd.Run() // Ignore errors
			removeCmd = exec.Command("iptables", "-D", chain, "-m", "set", "--match-set", setName, "dst", "-j", "ACCEPT")
			removeCmd.Run() // Ignore errors
			removeCmd = exec.Command("iptables", "-D", chain, "-m", "set", "--match-set", setName, "dst", "-j", "DROP")
			removeCmd.Run() // Ignore errors

			// Remove IPv6 rules
			removeCmd = exec.Command("ip6tables", "-D", chain, "-m", "set", "--match-set", setName, "src", "-j", "ACCEPT")
			removeCmd.Run() // Ignore errors
			removeCmd = exec.Command("ip6tables", "-D", chain, "-m", "set", "--match-set", setName, "src", "-j", "DROP")
			removeCmd.Run() // Ignore errors
			removeCmd = exec.Command("ip6tables", "-D", chain, "-m", "set", "--match-set", setName, "dst", "-j", "ACCEPT")
			removeCmd.Run() // Ignore errors
			removeCmd = exec.Command("ip6tables", "-D", chain, "-m", "set", "--match-set", setName, "dst", "-j", "DROP")
			removeCmd.Run() // Ignore errors
		}
	}

	// Remove ipsets
	for _, setName := range ipsetNames {
		flushCmd := exec.Command("ipset", "flush", setName)
		flushCmd.Run() // Ignore errors
		destroyCmd := exec.Command("ipset", "destroy", setName)
		destroyCmd.Run() // Ignore errors
	}
}
