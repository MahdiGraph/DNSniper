package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/MahdiGraph/DNSniper/internal/config"
	"github.com/MahdiGraph/DNSniper/internal/database"
	"github.com/MahdiGraph/DNSniper/internal/firewall"
	"github.com/MahdiGraph/DNSniper/internal/ui"
	"github.com/MahdiGraph/DNSniper/pkg/logger"
)

func main() {
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

	// Ensure database directory exists
	dbDir := filepath.Dir(cfg.DatabasePath)
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		log.Errorf("Failed to create database directory: %v", err)
		fmt.Fprintf(os.Stderr, "Failed to create database directory: %v\n", err)
		os.Exit(1)
	}

	// Initialize database
	db, err := database.NewStore(cfg.DatabasePath)
	if err != nil {
		log.Errorf("Failed to initialize database: %v", err)
		fmt.Fprintf(os.Stderr, "Failed to initialize database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// Initialize firewall manager with cleanup for fresh start
	fwManager, err := firewall.NewFirewallManager(
		cfg.IPSetPath,
		cfg.IPTablesPath,
		cfg.IP6TablesPath,
		cfg.EnableIPv6,
		cfg.BlockChains,
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
			cfg.BlockChains,
		)
		if err != nil {
			log.Errorf("Failed to initialize firewall manager after cleanup: %v", err)
			fmt.Fprintf(os.Stderr, "Failed to initialize firewall manager: %v\n", err)
			os.Exit(1)
		}
		log.Info("Firewall manager initialized successfully after cleanup")
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
