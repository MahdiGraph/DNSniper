package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"

	"github.com/MahdiGraph/DNSniper/internal/config"
	"github.com/MahdiGraph/DNSniper/internal/database"
	"github.com/MahdiGraph/DNSniper/internal/firewall"
	"github.com/MahdiGraph/DNSniper/internal/ui"
	"github.com/MahdiGraph/DNSniper/pkg/logger"
)

func main() {
	// Parse command line flags
	var showHelp = flag.Bool("help", false, "Show help information")
	var showVersion = flag.Bool("version", false, "Show version information")
	flag.Parse()

	// Handle help flag
	if *showHelp {
		fmt.Println("DNSniper v2.0 Enhanced Edition")
		fmt.Println("Linux DNS firewall with advanced features")
		fmt.Println("")
		fmt.Println("Usage: dnsniper [options]")
		fmt.Println("")
		fmt.Println("Options:")
		fmt.Println("  --help     Show this help message")
		fmt.Println("  --version  Show version information")
		fmt.Println("")
		fmt.Println("Enhanced Features:")
		fmt.Println("✅ GORM Database Integration with automatic firewall sync")
		fmt.Println("✅ Enhanced Firewall Management with rebuild fixes")
		fmt.Println("✅ Complete Blocklist Management with pagination")
		fmt.Println("✅ Whitelist Priority System with conflict resolution")
		fmt.Println("✅ Enhanced Clear/Rebuild with visual progress bars")
		fmt.Println("✅ Complete Settings Management")
		fmt.Println("✅ OS-Specific Path Management with auto-detection")
		fmt.Println("✅ Complete Agent Compatibility")
		fmt.Println("✅ Main Menu Full Compatibility with enhanced UI")
		os.Exit(0)
	}

	// Handle version flag
	if *showVersion {
		fmt.Println("DNSniper v2.0 Enhanced Edition")
		fmt.Println("Feature Compatibility Level: 8")
		fmt.Println("GORM Integration: Enabled")
		fmt.Println("Enhanced Features: All Active")
		os.Exit(0)
	}
	// Load configuration
	cfg, err := config.LoadConfig("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
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

	// Initialize firewall manager first (needed for database callbacks)
	fwManager, err := firewall.NewFirewallManager(
		cfg.IPSetPath,
		cfg.IPTablesPath,
		cfg.IP6TablesPath,
		cfg.EnableIPv6,
		cfg.AffectedChains,
	)
	if err != nil {
		// If initialization fails, try cleaning up and retry once
		log.Warnf("Initial firewall manager setup failed, attempting cleanup and retry: %v", err)

		// Try a basic cleanup before retrying
		cleanupFirewallRules(cfg)

		// Retry initialization
		fwManager, err = firewall.NewFirewallManager(
			cfg.IPSetPath,
			cfg.IPTablesPath,
			cfg.IP6TablesPath,
			cfg.EnableIPv6,
			cfg.AffectedChains,
		)
		if err != nil {
			log.Errorf("Failed to initialize firewall manager after cleanup: %v", err)
			fmt.Fprintf(os.Stderr, "Failed to initialize firewall manager: %v\n", err)
			os.Exit(1)
		}
		log.Info("Firewall manager initialized successfully after cleanup")
	}

	// Initialize database using enhanced factory system with callback integration
	dbFactory := database.NewDatabaseFactory(fwManager)
	db, err := dbFactory.CreateDatabaseWithAutoDetection(cfg.DatabasePath)
	if err != nil {
		log.Errorf("Failed to initialize database: %v", err)
		fmt.Fprintf(os.Stderr, "Failed to initialize database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// Validate callback service integration
	if err := database.ValidateCallbackService(); err != nil {
		log.Warnf("Callback service validation failed: %v", err)
		// Continue anyway - callbacks are optional for basic functionality
	} else {
		log.Info("GORM callback service initialized successfully")

		// Test callback functionality (non-intrusive)
		if err := database.TestCallbackFunctionality(db); err != nil {
			log.Warnf("Callback functionality test failed: %v", err)
		} else {
			log.Info("Callback functionality verified")
		}
	}

	// Main UI loop
	for {
		ui.ClearScreen()
		ui.PrintBanner()
		option := ui.PrintMenu()

		if !ui.DispatchOption(option, db, fwManager) {
			break
		}
	}
}

// cleanupFirewallRules performs basic cleanup of DNSniper firewall rules
func cleanupFirewallRules(cfg *config.Settings) {
	// List of DNSniper ipset names to clean up
	ipsetNames := []string{
		"whitelistIP-v4", "whitelistRange-v4", "blocklistIP-v4", "blocklistRange-v4",
		"whitelistIP-v6", "whitelistRange-v6", "blocklistIP-v6", "blocklistRange-v6",
	}

	// Cleanup ipsets
	for _, setName := range ipsetNames {
		// Try to flush and destroy each set (ignore errors)
		flushCmd := exec.Command(cfg.IPSetPath, "flush", setName)
		flushCmd.Run()

		destroyCmd := exec.Command(cfg.IPSetPath, "destroy", setName)
		destroyCmd.Run()
	}

	// Remove iptables rules that reference DNSniper ipsets
	chains := []string{"INPUT", "OUTPUT", "FORWARD"}
	for _, chain := range chains {
		for _, setName := range ipsetNames {
			// Remove IPv4 rules
			removeCmd := exec.Command(cfg.IPTablesPath, "-D", chain, "-m", "set", "--match-set", setName, "src", "-j", "ACCEPT")
			removeCmd.Run()

			removeCmd = exec.Command(cfg.IPTablesPath, "-D", chain, "-m", "set", "--match-set", setName, "src", "-j", "DROP")
			removeCmd.Run()

			removeCmd = exec.Command(cfg.IPTablesPath, "-D", chain, "-m", "set", "--match-set", setName, "dst", "-j", "ACCEPT")
			removeCmd.Run()

			removeCmd = exec.Command(cfg.IPTablesPath, "-D", chain, "-m", "set", "--match-set", setName, "dst", "-j", "DROP")
			removeCmd.Run()

			// Remove IPv6 rules if enabled
			if cfg.EnableIPv6 {
				removeCmd = exec.Command(cfg.IP6TablesPath, "-D", chain, "-m", "set", "--match-set", setName, "src", "-j", "ACCEPT")
				removeCmd.Run()

				removeCmd = exec.Command(cfg.IP6TablesPath, "-D", chain, "-m", "set", "--match-set", setName, "src", "-j", "DROP")
				removeCmd.Run()

				removeCmd = exec.Command(cfg.IP6TablesPath, "-D", chain, "-m", "set", "--match-set", setName, "dst", "-j", "ACCEPT")
				removeCmd.Run()

				removeCmd = exec.Command(cfg.IP6TablesPath, "-D", chain, "-m", "set", "--match-set", setName, "dst", "-j", "DROP")
				removeCmd.Run()
			}
		}
	}
}
