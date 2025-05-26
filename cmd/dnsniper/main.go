package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

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
	var uninstall = flag.Bool("uninstall", false, "Uninstall DNSniper completely")
	flag.Parse()

	// Handle help flag
	if *showHelp {
		fmt.Println("DNSniper v2.0")
		fmt.Println("Linux DNS firewall with advanced protection")
		fmt.Println("")
		fmt.Println("Usage: dnsniper [options]")
		fmt.Println("")
		fmt.Println("Options:")
		fmt.Println("  --help       Show this help message")
		fmt.Println("  --version    Show version information")
		fmt.Println("  --uninstall  Uninstall DNSniper completely")
		fmt.Println("")
		fmt.Println("Features:")
		fmt.Println("• GORM Database with automatic firewall synchronization")
		fmt.Println("• Advanced firewall management with ipset technology")
		fmt.Println("• Blocklist/Whitelist management with pagination")
		fmt.Println("• Whitelist priority system (always overrides blocklist)")
		fmt.Println("• Progress indicators for long operations")
		fmt.Println("• Comprehensive settings management")
		fmt.Println("• OS-specific path detection")
		fmt.Println("• Multi-threaded agent with DNS load balancing")
		fmt.Println("• Interactive menu system")
		os.Exit(0)
	}

	// Handle version flag
	if *showVersion {
		fmt.Println("DNSniper v2.0")
		fmt.Println("DNS Firewall with Advanced Protection")
		os.Exit(0)
	}

	// Handle uninstall flag - do this before loading config
	if *uninstall {
		uninstallDNSniper()
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
		flushCmd := exec.Command("ipset", "flush", setName)
		flushCmd.Run()

		destroyCmd := exec.Command("ipset", "destroy", setName)
		destroyCmd.Run()
	}

	// Remove iptables rules that reference DNSniper ipsets
	chains := []string{"INPUT", "OUTPUT", "FORWARD"}
	for _, chain := range chains {
		for _, setName := range ipsetNames {
			// Remove IPv4 rules
			removeCmd := exec.Command("iptables", "-D", chain, "-m", "set", "--match-set", setName, "src", "-j", "ACCEPT")
			removeCmd.Run()

			removeCmd = exec.Command("iptables", "-D", chain, "-m", "set", "--match-set", setName, "src", "-j", "DROP")
			removeCmd.Run()

			removeCmd = exec.Command("iptables", "-D", chain, "-m", "set", "--match-set", setName, "dst", "-j", "ACCEPT")
			removeCmd.Run()

			removeCmd = exec.Command("iptables", "-D", chain, "-m", "set", "--match-set", setName, "dst", "-j", "DROP")
			removeCmd.Run()

			// Remove IPv6 rules if enabled
			if cfg.EnableIPv6 {
				removeCmd = exec.Command("ip6tables", "-D", chain, "-m", "set", "--match-set", setName, "src", "-j", "ACCEPT")
				removeCmd.Run()

				removeCmd = exec.Command("ip6tables", "-D", chain, "-m", "set", "--match-set", setName, "src", "-j", "DROP")
				removeCmd.Run()

				removeCmd = exec.Command("ip6tables", "-D", chain, "-m", "set", "--match-set", setName, "dst", "-j", "ACCEPT")
				removeCmd.Run()

				removeCmd = exec.Command("ip6tables", "-D", chain, "-m", "set", "--match-set", setName, "dst", "-j", "DROP")
				removeCmd.Run()
			}
		}
	}
}

// uninstallDNSniper completely removes DNSniper from the system
func uninstallDNSniper() {
	fmt.Println("🗑️  DNSniper Complete Uninstaller")
	fmt.Println("================================")

	// Check for root access
	if syscall.Getuid() != 0 {
		fmt.Printf("❌ Error: This operation requires root privileges\n")
		fmt.Printf("Please run with sudo: sudo dnsniper --uninstall\n")
		os.Exit(1)
	}

	// Confirm uninstall
	fmt.Printf("\n⚠️  WARNING: This will completely remove DNSniper from your system including:\n")
	fmt.Printf("   • All services and timers\n")
	fmt.Printf("   • All firewall rules and ipset sets\n")
	fmt.Printf("   • All configuration files\n")
	fmt.Printf("   • All database files\n")
	fmt.Printf("   • All log files\n")
	fmt.Printf("   • All binaries and directories\n")
	fmt.Printf("\nAre you absolutely sure you want to continue? (yes/no): ")

	reader := bufio.NewReader(os.Stdin)
	response, _ := reader.ReadString('\n')
	response = strings.TrimSpace(strings.ToLower(response))

	if response != "yes" && response != "y" {
		fmt.Printf("❌ Uninstall cancelled.\n")
		return
	}

	// Ask about firewall rules specifically
	fmt.Printf("\n🔥 Do you want to remove all DNSniper firewall rules? (yes/no): ")
	response, _ = reader.ReadString('\n')
	response = strings.TrimSpace(strings.ToLower(response))
	removeRules := (response == "yes" || response == "y")

	fmt.Printf("\n🔄 Starting uninstall process...\n")

	// Step 1: Stop and disable services
	fmt.Printf("1️⃣  Stopping and disabling services...\n")
	stopService("dnsniper-agent.service")
	stopService("dnsniper-agent.timer")
	disableService("dnsniper-agent.service")
	disableService("dnsniper-agent.timer")

	// Step 2: Remove firewall rules if requested
	if removeRules {
		fmt.Printf("2️⃣  Removing firewall rules and ipset sets...\n")
		removeFirewallRules()
	} else {
		fmt.Printf("2️⃣  Skipping firewall rules removal (as requested)...\n")
	}

	// Step 3: Remove systemd files
	fmt.Printf("3️⃣  Removing systemd service files...\n")
	removeFile("/etc/systemd/system/dnsniper-agent.service")
	removeFile("/etc/systemd/system/dnsniper-agent.timer")
	runCommand("systemctl", "daemon-reload")

	// Step 4: Remove binaries
	fmt.Printf("4️⃣  Removing binaries...\n")
	removeFile("/usr/bin/dnsniper")
	removeFile("/usr/bin/dnsniper-agent")
	removeFile("/usr/bin/dnsniper-installer")

	// Step 5: Remove directories
	fmt.Printf("5️⃣  Removing directories...\n")
	removeDirectory("/etc/dnsniper")
	removeDirectory("/var/log/dnsniper")

	// Step 6: Clean up persistence files
	fmt.Printf("6️⃣  Cleaning up persistence files...\n")
	cleanupPersistenceFiles()

	fmt.Printf("\n✅ DNSniper has been completely uninstalled!\n")
	fmt.Printf("🎯 All components removed successfully.\n")

	if !removeRules {
		fmt.Printf("\n⚠️  Note: Firewall rules were kept as requested.\n")
		fmt.Printf("   You can manually remove them if needed.\n")
	}
}

// Helper functions for uninstall
func stopService(serviceName string) {
	runCommand("systemctl", "stop", serviceName)
}

func disableService(serviceName string) {
	runCommand("systemctl", "disable", serviceName)
}

func removeFile(path string) {
	if _, err := os.Stat(path); err == nil {
		if err := os.Remove(path); err != nil {
			fmt.Printf("   ⚠️  Warning: Could not remove %s: %v\n", path, err)
		} else {
			fmt.Printf("   ✅ Removed: %s\n", path)
		}
	}
}

func removeDirectory(path string) {
	if _, err := os.Stat(path); err == nil {
		if err := os.RemoveAll(path); err != nil {
			fmt.Printf("   ⚠️  Warning: Could not remove directory %s: %v\n", path, err)
		} else {
			fmt.Printf("   ✅ Removed directory: %s\n", path)
		}
	}
}

func runCommand(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Run() // Ignore errors during cleanup
}

func removeFirewallRules() {
	// List of DNSniper ipset names
	ipsetNames := []string{
		"whitelistIP-v4", "whitelistRange-v4", "blocklistIP-v4", "blocklistRange-v4",
		"whitelistIP-v6", "whitelistRange-v6", "blocklistIP-v6", "blocklistRange-v6",
	}

	// Remove iptables rules first
	chains := []string{"INPUT", "OUTPUT", "FORWARD"}
	for _, chain := range chains {
		for _, setName := range ipsetNames {
			// IPv4 rules
			runCommand("iptables", "-D", chain, "-m", "set", "--match-set", setName, "src", "-j", "ACCEPT")
			runCommand("iptables", "-D", chain, "-m", "set", "--match-set", setName, "src", "-j", "DROP")
			runCommand("iptables", "-D", chain, "-m", "set", "--match-set", setName, "dst", "-j", "ACCEPT")
			runCommand("iptables", "-D", chain, "-m", "set", "--match-set", setName, "dst", "-j", "DROP")

			// IPv6 rules
			runCommand("ip6tables", "-D", chain, "-m", "set", "--match-set", setName, "src", "-j", "ACCEPT")
			runCommand("ip6tables", "-D", chain, "-m", "set", "--match-set", setName, "src", "-j", "DROP")
			runCommand("ip6tables", "-D", chain, "-m", "set", "--match-set", setName, "dst", "-j", "ACCEPT")
			runCommand("ip6tables", "-D", chain, "-m", "set", "--match-set", setName, "dst", "-j", "DROP")
		}
	}

	// Remove ipset sets
	for _, setName := range ipsetNames {
		runCommand("ipset", "flush", setName)
		runCommand("ipset", "destroy", setName)
		fmt.Printf("   ✅ Removed ipset: %s\n", setName)
	}
}

func cleanupPersistenceFiles() {
	// Remove saved iptables rules
	removeFile("/etc/iptables/rules.v4")
	removeFile("/etc/iptables/rules.v6")
	removeFile("/etc/sysconfig/iptables")
	removeFile("/etc/sysconfig/ip6tables")
	removeFile("/etc/ipset.conf")

	// Restart persistence services to apply changes
	runCommand("systemctl", "restart", "netfilter-persistent")
	runCommand("systemctl", "restart", "iptables")
	runCommand("systemctl", "restart", "ip6tables")
}
