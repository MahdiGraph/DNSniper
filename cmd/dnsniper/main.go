package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"

	"github.com/MahdiGraph/DNSniper/internal/firewall"
	"github.com/MahdiGraph/DNSniper/internal/system"
	"github.com/MahdiGraph/DNSniper/internal/ui"
)

// BatchProcessor handles batch processing of DNS requests
type BatchProcessor struct {
	initializer *system.SystemInitializer
}

// NewBatchProcessor creates a new batch processor
func NewBatchProcessor(initializer *system.SystemInitializer) *BatchProcessor {
	return &BatchProcessor{
		initializer: initializer,
	}
}

// Run executes the batch processor
func (b *BatchProcessor) Run(ctx context.Context) error {
	db := b.initializer.GetDatabase()
	fwManager := b.initializer.GetFirewallManager()
	log := b.initializer.GetLogger()

	log.Info("Starting DNSniper batch processor")

	// Clean up expired records first
	if err := db.CleanupExpired(); err != nil {
		log.Errorf("Failed to cleanup expired records: %v", err)
		return fmt.Errorf("cleanup failed: %w", err)
	}

	// Reload firewall rules to ensure they're up to date
	if err := fwManager.Reload(); err != nil {
		log.Errorf("Failed to reload firewall rules: %v", err)
		return fmt.Errorf("firewall reload failed: %w", err)
	}

	log.Info("DNSniper batch processor completed successfully")
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
		fmt.Println("DNSniper v2.1 - Automated DNS Firewall")
		fmt.Println("\nUsage:")
		fmt.Println("  dnsniper [options]")
		fmt.Println("\nOptions:")
		fmt.Println("  --config <path>    Path to configuration file")
		fmt.Println("  --help             Show this help message")
		fmt.Println("  --version          Show version information")
		fmt.Println("  --uninstall        Uninstall DNSniper")
		fmt.Println("\nFeatures:")
		fmt.Println("• Complete system initialization (config, ipsets, rules)")
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
		fmt.Println("DNSniper v2.1")
		fmt.Println("Automated DNS Firewall")
		os.Exit(0)
	}

	// Handle uninstall flag
	if *uninstall {
		handleUninstall()
		os.Exit(0)
	}

	// Initialize system (without verbose logging for UI)
	initializer := system.NewSystemInitializer(false)

	// Perform complete system initialization
	if err := initializer.Initialize(*configPath); err != nil {
		fmt.Fprintf(os.Stderr, "System initialization failed: %v\n", err)
		os.Exit(1)
	}

	// Get initialized components
	cfg := initializer.GetConfig()
	db := initializer.GetDatabase()
	fwManager := initializer.GetFirewallManager()

	// Ensure cleanup on exit
	defer func() {
		if err := initializer.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Cleanup error: %v\n", err)
		}
	}()

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
	fmt.Println("Performing manual firewall cleanup...")

	// List of DNSniper ipset names
	ipsetNames := []string{
		"dnsniper-whitelist-ip-v4", "dnsniper-whitelist-range-v4",
		"dnsniper-blocklist-ip-v4", "dnsniper-blocklist-range-v4",
		"dnsniper-whitelist-ip-v6", "dnsniper-whitelist-range-v6",
		"dnsniper-blocklist-ip-v6", "dnsniper-blocklist-range-v6",
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

	// Save current iptables rules
	saveCmd := exec.Command("iptables-save")
	output, err := saveCmd.Output()
	if err == nil {
		os.WriteFile("/etc/iptables/rules.v4", output, 0644)
	}

	// Save current ip6tables rules
	saveCmd = exec.Command("ip6tables-save")
	output, err = saveCmd.Output()
	if err == nil {
		os.WriteFile("/etc/iptables/rules.v6", output, 0644)
	}

	// Save ipset state
	saveCmd = exec.Command("ipset", "save")
	output, err = saveCmd.Output()
	if err == nil {
		os.WriteFile("/etc/ipset.conf", output, 0644)
	}

	fmt.Println("Persistence files updated")
}
