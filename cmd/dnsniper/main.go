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
	"github.com/MahdiGraph/DNSniper/internal/ui"
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

	// Initialize firewall manager (needed for UI operations)
	fwManager, err := firewall.NewFirewallManager(
		cfg.EnableIPv6,
		cfg.AffectedChains,
		filepath.Join(cfg.LogPath, "firewall-backup"),
		filepath.Join(cfg.LogPath, "firewall.log"),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize firewall manager: %v\n", err)
		os.Exit(1)
	}

	// Initialize database
	dbFactory := database.NewDatabaseFactory(fwManager)
	db, err := dbFactory.CreateDatabaseWithAutoDetection(cfg.DatabasePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// Start UI menu
	menu := ui.NewMenu(cfg, db, fwManager)
	menu.Run()
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

	// Remove firewall rules and ipsets using firewall manager if possible
	fmt.Println("Removing firewall rules and ipsets...")

	// Try to use firewall manager for proper cleanup
	if fwManager, err := initializeFirewallManager(); err == nil {
		fmt.Println("Using firewall manager for cleanup...")
		if err := fwManager.CleanupAll(); err != nil {
			fmt.Printf("Firewall manager cleanup failed: %v\n", err)
			fmt.Println("Falling back to manual cleanup...")
			removeFirewallRules()
		} else {
			fmt.Println("Firewall cleanup completed successfully")
			updatePersistenceFiles()
		}
	} else {
		fmt.Printf("Could not initialize firewall manager: %v\n", err)
		fmt.Println("Using manual cleanup...")
		removeFirewallRules()
	}

	// Remove service files
	fmt.Println("Removing service files...")
	os.Remove("/etc/systemd/system/dnsniper-agent.service")
	os.Remove("/etc/systemd/system/dnsniper-agent.timer")

	// Reload systemd
	reloadCmd := exec.Command("systemctl", "daemon-reload")
	reloadCmd.Run()

	// Remove binaries
	fmt.Println("Removing binaries...")
	os.Remove("/usr/bin/dnsniper")             // symlink
	os.Remove("/etc/dnsniper/dnsniper")        // main binary
	os.Remove("/etc/dnsniper/dnsniper-agent")  // agent binary
	os.Remove("/usr/local/bin/dnsniper")       // legacy path (backward compatibility)
	os.Remove("/usr/local/bin/dnsniper-agent") // legacy path (backward compatibility)

	// Remove configuration and data directories
	fmt.Println("Removing configuration and data...")
	os.RemoveAll("/etc/dnsniper")
	os.RemoveAll("/var/log/dnsniper")
	os.RemoveAll("/var/lib/dnsniper")

	// Note: We intentionally do NOT remove the ipset service or /etc/ipset.conf
	// as these may be used by other applications or the system itself
	fmt.Println("Note: ipset service and /etc/ipset.conf are preserved for system compatibility")

	fmt.Println("✅ DNSniper uninstallation completed successfully!")
	fmt.Println("Thank you for using DNSniper!")
}

// removeFirewallRules removes all DNSniper firewall rules and ipsets
func removeFirewallRules() {
	// List of DNSniper ipset names
	ipsetNames := []string{
		"whitelistIP-v4", "whitelistRange-v4", "blocklistIP-v4", "blocklistRange-v4",
		"whitelistIP-v6", "whitelistRange-v6", "blocklistIP-v6", "blocklistRange-v6",
	}

	// List of iptables chains to clean
	chains := []string{"INPUT", "OUTPUT", "FORWARD"}

	fmt.Println("Removing iptables rules...")
	// Remove iptables rules first (before destroying ipsets)
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

	fmt.Println("Removing ipsets...")
	// Remove ipsets (flush first, then destroy)
	for _, setName := range ipsetNames {
		flushCmd := exec.Command("ipset", "flush", setName)
		flushCmd.Run() // Ignore errors
		destroyCmd := exec.Command("ipset", "destroy", setName)
		destroyCmd.Run() // Ignore errors
	}

	fmt.Println("Manual cleanup completed")
	updatePersistenceFiles()
}

// initializeFirewallManager creates a firewall manager for cleanup
func initializeFirewallManager() (*firewall.FirewallManager, error) {
	// Use default settings for cleanup
	return firewall.NewFirewallManager(
		true,                                   // enableIPv6
		[]string{"INPUT", "OUTPUT", "FORWARD"}, // chains
		"/tmp/dnsniper-backup",                 // backupPath
		"/tmp/dnsniper-cleanup.log",            // logFile
	)
}

// updatePersistenceFiles updates the persistence files after cleanup
func updatePersistenceFiles() {
	fmt.Println("Updating persistence files...")

	// Update iptables persistence files (if they exist)
	if _, err := exec.LookPath("iptables-save"); err == nil {
		// Check if /etc/iptables directory exists
		if _, err := os.Stat("/etc/iptables"); err == nil {
			// Save current IPv4 rules (without DNSniper rules)
			if cmd := exec.Command("iptables-save"); cmd.Run() == nil {
				if output, err := cmd.Output(); err == nil {
					os.WriteFile("/etc/iptables/rules.v4", output, 0644)
				}
			}
			// Save current IPv6 rules (without DNSniper rules)
			if cmd := exec.Command("ip6tables-save"); cmd.Run() == nil {
				if output, err := cmd.Output(); err == nil {
					os.WriteFile("/etc/iptables/rules.v6", output, 0644)
				}
			}
		}
	}

	// Update ipset configuration (if it exists)
	if _, err := exec.LookPath("ipset"); err == nil {
		if _, err := os.Stat("/etc/ipset.conf"); err == nil {
			// Save current ipset state (without DNSniper sets)
			if cmd := exec.Command("ipset", "save"); cmd.Run() == nil {
				if output, err := cmd.Output(); err == nil {
					os.WriteFile("/etc/ipset.conf", output, 0644)
				}
			}
		}
	}
}
