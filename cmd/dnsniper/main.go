package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/MahdiGraph/DNSniper/internal/config"
	"github.com/MahdiGraph/DNSniper/internal/database"
	"github.com/MahdiGraph/DNSniper/internal/firewall"
	"github.com/MahdiGraph/DNSniper/internal/service"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var log = logrus.New()

func init() {
	// Configure logger
	log.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	// Check logging settings
	if config.IsLoggingEnabled() {
		logFile, err := config.GetLogFile()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening log file: %v\n", err)
			return
		}
		log.SetOutput(logFile)
	}
}

func main() {
	// Initialize database if not exists
	dbConn, err := database.Initialize()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize database: %v\n", err)
		os.Exit(1)
	}

	// Set the database connection for the config package
	config.SetDatabase(dbConn)

	var rootCmd = &cobra.Command{
		Use:   "dnsniper",
		Short: "DNSniper - Domain Threat Neutralizer",
		Long:  `DNSniper is a security tool that identifies suspicious domains and blocks their IPs.`,
		Run: func(cmd *cobra.Command, args []string) {
			showMainMenu()
		},
	}

	// Add subcommands
	rootCmd.AddCommand(createStatusCommand())
	rootCmd.AddCommand(createRunCommand())
	rootCmd.AddCommand(createDomainsCommand())
	rootCmd.AddCommand(createIPsCommand())
	rootCmd.AddCommand(createSettingsCommand())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// showMainMenu displays the main menu and handles user input
func showMainMenu() {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Println("\n===============================")
		fmt.Println("      D N S n i p e r")
		fmt.Println("  Domain Threat Neutralizer")
		fmt.Println("===============================")
		fmt.Println("1. Run agent now")
		fmt.Println("2. Show status")
		fmt.Println("3. Manage domain blocklist")
		fmt.Println("4. Manage domain whitelist")
		fmt.Println("5. Manage IP blocklist")
		fmt.Println("6. Manage IP whitelist")
		fmt.Println("7. Settings")
		fmt.Println("8. Clear firewall rules")
		fmt.Println("0. Exit")
		fmt.Println("U. Uninstall DNSniper")
		fmt.Print("\nSelect an option: ")

		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		switch input {
		case "1":
			runAgentNow()
			pressEnterToContinue(reader)
		case "2":
			showStatus()
			pressEnterToContinue(reader)
		case "3":
			manageDomainBlocklist(reader)
		case "4":
			manageDomainWhitelist(reader)
		case "5":
			manageIPBlocklist(reader)
		case "6":
			manageIPWhitelist(reader)
		case "7":
			manageSettings(reader)
		case "8":
			clearRules()
			pressEnterToContinue(reader)
		case "0":
			fmt.Println("Exiting DNSniper. Goodbye!")
			return
		case "u", "U":
			if confirmUninstall(reader) {
				return
			}
		default:
			fmt.Println("Invalid option. Please try again.")
			pressEnterToContinue(reader)
		}
	}
}

func pressEnterToContinue(reader *bufio.Reader) {
	fmt.Print("\nPress Enter to continue...")
	_, _ = reader.ReadString('\n')
}

func createStatusCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show DNSniper status",
		Run: func(cmd *cobra.Command, args []string) {
			showStatus()
		},
	}
}

func createRunCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "run",
		Short: "Run DNSniper agent now",
		Run: func(cmd *cobra.Command, args []string) {
			runAgentNow()
		},
	}
}

func createDomainsCommand() *cobra.Command {
	domainsCmd := &cobra.Command{
		Use:   "domains",
		Short: "Manage domain blocklists and whitelists",
	}

	domainsCmd.AddCommand(&cobra.Command{
		Use:   "block [domain]",
		Short: "Add a domain to blocklist",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			blockDomain(args[0])
		},
	})

	domainsCmd.AddCommand(&cobra.Command{
		Use:   "whitelist [domain]",
		Short: "Add a domain to whitelist",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			whitelistDomain(args[0])
		},
	})

	domainsCmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List blocked and whitelisted domains",
		Run: func(cmd *cobra.Command, args []string) {
			listDomains()
		},
	})

	return domainsCmd
}

func createIPsCommand() *cobra.Command {
	ipsCmd := &cobra.Command{
		Use:   "ips",
		Short: "Manage IP blocklists and whitelists",
	}

	ipsCmd.AddCommand(&cobra.Command{
		Use:   "block [ip]",
		Short: "Add an IP to blocklist",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			blockIP(args[0])
		},
	})

	ipsCmd.AddCommand(&cobra.Command{
		Use:   "whitelist [ip]",
		Short: "Add an IP to whitelist",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			whitelistIP(args[0])
		},
	})

	ipsCmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List blocked and whitelisted IPs",
		Run: func(cmd *cobra.Command, args []string) {
			listIPs()
		},
	})

	return ipsCmd
}

func createSettingsCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "settings",
		Short: "Manage DNSniper settings",
		Run: func(cmd *cobra.Command, args []string) {
			reader := bufio.NewReader(os.Stdin)
			manageSettings(reader)
		},
	}
}

func runAgentNow() {
	fmt.Println("Running DNSniper agent...")
	err := service.RunAgentOnce()
	if err != nil {
		fmt.Printf("Failed to run agent: %v\n", err)
		return
	}
	fmt.Println("Agent run completed successfully")
}

func showStatus() {
	status, err := service.GetAgentStatus()
	if err != nil {
		fmt.Printf("Failed to get status: %v\n", err)
		return
	}

	fmt.Println("\nDNSniper Status:")
	fmt.Println("================")
	fmt.Printf("Service status: %s\n", status.ServiceStatus)
	fmt.Printf("Last run: %s\n", status.LastRun)
	fmt.Printf("Blocked domains: %d\n", status.BlockedDomains)
	fmt.Printf("Blocked IPs: %d\n", status.BlockedIPs)
	fmt.Printf("Whitelisted domains: %d\n", status.WhitelistedDomains)
	fmt.Printf("Whitelisted IPs: %d\n", status.WhitelistedIPs)
}

func manageDomainBlocklist(reader *bufio.Reader) {
	for {
		fmt.Println("\nDomain Blocklist Management:")
		fmt.Println("1. List blocked domains")
		fmt.Println("2. Add domain to blocklist")
		fmt.Println("3. Remove domain from blocklist")
		fmt.Println("0. Back to main menu")
		fmt.Print("\nSelect an option: ")

		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		switch input {
		case "1":
			listBlockedDomains()
			pressEnterToContinue(reader)
		case "2":
			addDomainToBlocklist(reader)
			pressEnterToContinue(reader)
		case "3":
			removeDomainFromBlocklist(reader)
			pressEnterToContinue(reader)
		case "0":
			return
		default:
			fmt.Println("Invalid option. Please try again.")
		}
	}
}

func manageDomainWhitelist(reader *bufio.Reader) {
	for {
		fmt.Println("\nDomain Whitelist Management:")
		fmt.Println("1. List whitelisted domains")
		fmt.Println("2. Add domain to whitelist")
		fmt.Println("3. Remove domain from whitelist")
		fmt.Println("0. Back to main menu")
		fmt.Print("\nSelect an option: ")

		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		switch input {
		case "1":
			listWhitelistedDomains()
			pressEnterToContinue(reader)
		case "2":
			addDomainToWhitelist(reader)
			pressEnterToContinue(reader)
		case "3":
			removeDomainFromWhitelist(reader)
			pressEnterToContinue(reader)
		case "0":
			return
		default:
			fmt.Println("Invalid option. Please try again.")
		}
	}
}

func manageIPBlocklist(reader *bufio.Reader) {
	for {
		fmt.Println("\nIP Blocklist Management:")
		fmt.Println("1. List blocked IPs")
		fmt.Println("2. Add IP to blocklist")
		fmt.Println("3. Remove IP from blocklist")
		fmt.Println("0. Back to main menu")
		fmt.Print("\nSelect an option: ")

		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		switch input {
		case "1":
			listBlockedIPs()
			pressEnterToContinue(reader)
		case "2":
			addIPToBlocklist(reader)
			pressEnterToContinue(reader)
		case "3":
			removeIPFromBlocklist(reader)
			pressEnterToContinue(reader)
		case "0":
			return
		default:
			fmt.Println("Invalid option. Please try again.")
		}
	}
}

func manageIPWhitelist(reader *bufio.Reader) {
	for {
		fmt.Println("\nIP Whitelist Management:")
		fmt.Println("1. List whitelisted IPs")
		fmt.Println("2. Add IP to whitelist")
		fmt.Println("3. Remove IP from whitelist")
		fmt.Println("0. Back to main menu")
		fmt.Print("\nSelect an option: ")

		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		switch input {
		case "1":
			listWhitelistedIPs()
			pressEnterToContinue(reader)
		case "2":
			addIPToWhitelist(reader)
			pressEnterToContinue(reader)
		case "3":
			removeIPFromWhitelist(reader)
			pressEnterToContinue(reader)
		case "0":
			return
		default:
			fmt.Println("Invalid option. Please try again.")
		}
	}
}

func manageSettings(reader *bufio.Reader) {
	for {
		fmt.Println("\nSettings Management:")
		fmt.Println("1. View current settings")
		fmt.Println("2. Change DNS resolver")
		fmt.Println("3. Change block rule type")
		fmt.Println("4. Toggle logging")
		fmt.Println("5. Set rules expiration time")
		fmt.Println("6. Set update URL")
		fmt.Println("0. Back to main menu")
		fmt.Print("\nSelect an option: ")

		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		switch input {
		case "1":
			viewSettings()
			pressEnterToContinue(reader)
		case "2":
			changeDNSResolver(reader)
			pressEnterToContinue(reader)
		case "3":
			changeBlockRuleType(reader)
			pressEnterToContinue(reader)
		case "4":
			toggleLogging()
			pressEnterToContinue(reader)
		case "5":
			setRulesExpiration(reader)
			pressEnterToContinue(reader)
		case "6":
			setUpdateURL(reader)
			pressEnterToContinue(reader)
		case "0":
			return
		default:
			fmt.Println("Invalid option. Please try again.")
		}
	}
}

func clearRules() {
	fmt.Println("Clearing all firewall rules...")

	// Clear rules in memory
	fwManager, err := firewall.NewIPTablesManager()
	if err != nil {
		fmt.Printf("Error initializing firewall manager: %v\n", err)
		return
	}

	if err := fwManager.ClearRules(); err != nil {
		fmt.Printf("Error clearing rules: %v\n", err)
		return
	}

	// Save changes to persistent files
	if err := saveIPTablesRules(); err != nil {
		fmt.Printf("Error saving rules: %v\n", err)
		return
	}

	fmt.Println("Rules cleared successfully and saved permanently")
}

func saveIPTablesRules() error {
	// Detect OS
	_, err := os.Stat("/etc/debian_version")
	isDebian := err == nil

	if isDebian {
		// Debian/Ubuntu - Use shell command with proper redirection
		cmd := exec.Command("sh", "-c", "iptables-save > /etc/iptables/rules.v4")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to save IPv4 rules: %w", err)
		}

		cmd = exec.Command("sh", "-c", "ip6tables-save > /etc/iptables/rules.v6")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to save IPv6 rules: %w", err)
		}
	} else {
		// RHEL/CentOS
		if err := exec.Command("service", "iptables", "save").Run(); err != nil {
			return fmt.Errorf("failed to save IPv4 rules: %w", err)
		}

		if err := exec.Command("service", "ip6tables", "save").Run(); err != nil {
			return fmt.Errorf("failed to save IPv6 rules: %w", err)
		}
	}

	return nil
}

func confirmUninstall(reader *bufio.Reader) bool {
	fmt.Print("\nAre you sure you want to uninstall DNSniper? (yes/no): ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	if strings.ToLower(input) == "yes" {
		fmt.Println("Uninstalling DNSniper...")
		// Execute uninstall script
		cmd := exec.Command("sh", "-c", "cd /etc/dnsniper && ./scripts/installer.sh uninstall")
		if err := cmd.Run(); err != nil {
			fmt.Printf("Error during uninstallation: %v\n", err)
		} else {
			fmt.Println("DNSniper has been uninstalled.")
		}
		return true
	}

	fmt.Println("Uninstallation cancelled")
	return false
}

// Domain management functions
func listBlockedDomains() {
	fmt.Println("Listing blocked domains...")
	// Implementation would go here - query from database
	fmt.Println("Domain1.example.com")
	fmt.Println("Domain2.example.com")
}

func addDomainToBlocklist(reader *bufio.Reader) {
	fmt.Print("Enter domain to block: ")
	domain, _ := reader.ReadString('\n')
	domain = strings.TrimSpace(domain)

	if domain == "" {
		fmt.Println("Domain cannot be empty.")
		return
	}

	blockDomain(domain)
}

func blockDomain(domain string) {
	fmt.Printf("Blocking domain: %s\n", domain)
	// Implementation would go here - add to database
}

func removeDomainFromBlocklist(reader *bufio.Reader) {
	fmt.Print("Enter domain to remove from blocklist: ")
	domain, _ := reader.ReadString('\n')
	domain = strings.TrimSpace(domain)

	if domain == "" {
		fmt.Println("Domain cannot be empty.")
		return
	}

	fmt.Printf("Removing domain from blocklist: %s\n", domain)
	// Implementation would go here - remove from database
}

func listWhitelistedDomains() {
	fmt.Println("Listing whitelisted domains...")
	// Implementation would go here - query from database
	fmt.Println("trusted-domain1.com")
	fmt.Println("trusted-domain2.com")
}

func addDomainToWhitelist(reader *bufio.Reader) {
	fmt.Print("Enter domain to whitelist: ")
	domain, _ := reader.ReadString('\n')
	domain = strings.TrimSpace(domain)

	if domain == "" {
		fmt.Println("Domain cannot be empty.")
		return
	}

	whitelistDomain(domain)
}

func whitelistDomain(domain string) {
	fmt.Printf("Whitelisting domain: %s\n", domain)
	// Implementation would go here - add to database
}

func removeDomainFromWhitelist(reader *bufio.Reader) {
	fmt.Print("Enter domain to remove from whitelist: ")
	domain, _ := reader.ReadString('\n')
	domain = strings.TrimSpace(domain)

	if domain == "" {
		fmt.Println("Domain cannot be empty.")
		return
	}

	fmt.Printf("Removing domain from whitelist: %s\n", domain)
	// Implementation would go here - remove from database
}

// IP management functions
func listBlockedIPs() {
	fmt.Println("Listing blocked IPs...")
	// Implementation would go here - query from database
	fmt.Println("192.168.1.1")
	fmt.Println("10.0.0.1")
}

func addIPToBlocklist(reader *bufio.Reader) {
	fmt.Print("Enter IP to block: ")
	ip, _ := reader.ReadString('\n')
	ip = strings.TrimSpace(ip)

	if ip == "" {
		fmt.Println("IP cannot be empty.")
		return
	}

	blockIP(ip)
}

func blockIP(ip string) {
	fmt.Printf("Blocking IP: %s\n", ip)
	// Implementation would go here - add to database and iptables
}

func removeIPFromBlocklist(reader *bufio.Reader) {
	fmt.Print("Enter IP to remove from blocklist: ")
	ip, _ := reader.ReadString('\n')
	ip = strings.TrimSpace(ip)

	if ip == "" {
		fmt.Println("IP cannot be empty.")
		return
	}

	fmt.Printf("Removing IP from blocklist: %s\n", ip)
	// Implementation would go here - remove from database and iptables
}

func listWhitelistedIPs() {
	fmt.Println("Listing whitelisted IPs...")
	// Implementation would go here - query from database
	fmt.Println("8.8.8.8")
	fmt.Println("1.1.1.1")
}

func addIPToWhitelist(reader *bufio.Reader) {
	fmt.Print("Enter IP to whitelist: ")
	ip, _ := reader.ReadString('\n')
	ip = strings.TrimSpace(ip)

	if ip == "" {
		fmt.Println("IP cannot be empty.")
		return
	}

	whitelistIP(ip)
}

func whitelistIP(ip string) {
	fmt.Printf("Whitelisting IP: %s\n", ip)
	// Implementation would go here - add to database
}

func removeIPFromWhitelist(reader *bufio.Reader) {
	fmt.Print("Enter IP to remove from whitelist: ")
	ip, _ := reader.ReadString('\n')
	ip = strings.TrimSpace(ip)

	if ip == "" {
		fmt.Println("IP cannot be empty.")
		return
	}

	fmt.Printf("Removing IP from whitelist: %s\n", ip)
	// Implementation would go here - remove from database
}

// Settings functions
func viewSettings() {
	fmt.Println("\nCurrent settings:")
	settings, err := config.GetSettings()
	if err != nil {
		fmt.Printf("Failed to get settings: %v\n", err)
		return
	}

	fmt.Printf("DNS Resolver: %s\n", settings.DNSResolver)
	fmt.Printf("Block Rule Type: %s\n", settings.BlockRuleType)
	fmt.Printf("Logging Enabled: %v\n", settings.LoggingEnabled)
	fmt.Printf("Rule Expiration: %s\n", settings.RuleExpiration.String())
	fmt.Printf("Update URL: %s\n", settings.UpdateURL)
	fmt.Printf("Max IPs per Domain: %d\n", settings.MaxIPsPerDomain)
}

func changeDNSResolver(reader *bufio.Reader) {
	fmt.Print("Enter new DNS resolver (default 8.8.8.8): ")
	resolver, _ := reader.ReadString('\n')
	resolver = strings.TrimSpace(resolver)

	if resolver == "" {
		resolver = "8.8.8.8"
	}

	// Save to database
	err := config.SaveSetting("dns_resolver", resolver)
	if err != nil {
		fmt.Printf("Failed to save DNS resolver: %v\n", err)
		return
	}

	fmt.Printf("DNS resolver set to: %s\n", resolver)
}

func changeBlockRuleType(reader *bufio.Reader) {
	fmt.Println("Select block rule type:")
	fmt.Println("1. source (block as source only)")
	fmt.Println("2. destination (block as destination only)")
	fmt.Println("3. both (block as both source and destination)")
	fmt.Print("\nEnter choice [1-3]: ")

	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	var ruleType string
	switch input {
	case "1":
		ruleType = "source"
	case "2":
		ruleType = "destination"
	case "3":
		ruleType = "both"
	default:
		fmt.Println("Invalid choice. Using default (both).")
		ruleType = "both"
	}

	// Save to database
	err := config.SaveSetting("block_rule_type", ruleType)
	if err != nil {
		fmt.Printf("Failed to save block rule type: %v\n", err)
		return
	}

	fmt.Printf("Block rule type set to: %s\n", ruleType)
}

func toggleLogging() {
	// Get current logging state
	settings, err := config.GetSettings()
	if err != nil {
		fmt.Printf("Failed to get settings: %v\n", err)
		return
	}

	// Toggle logging
	newState := !settings.LoggingEnabled

	// Save to database
	err = config.SaveSetting("logging_enabled", strconv.FormatBool(newState))
	if err != nil {
		fmt.Printf("Failed to update logging setting: %v\n", err)
		return
	}

	// Update service file
	err = service.UpdateServiceLogging(newState)
	if err != nil {
		fmt.Printf("Failed to update service file: %v\n", err)
		return
	}

	if newState {
		fmt.Println("Logging has been enabled")
	} else {
		fmt.Println("Logging has been disabled")
	}
}

func setRulesExpiration(reader *bufio.Reader) {
	fmt.Print("Enter rules expiration time in days (default 30): ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	days := 30 // Default
	if input != "" {
		var err error
		days, err = strconv.Atoi(input)
		if err != nil || days <= 0 {
			fmt.Println("Invalid input. Using default (30 days).")
			days = 30
		}
	}

	// Save to database
	err := config.SaveSetting("rule_expiration", fmt.Sprintf("%dd", days))
	if err != nil {
		fmt.Printf("Failed to save rule expiration: %v\n", err)
		return
	}

	fmt.Printf("Rules expiration set to: %d days\n", days)
}

func setUpdateURL(reader *bufio.Reader) {
	fmt.Println("Enter update URL (default: https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/domains-default.txt):")
	url, _ := reader.ReadString('\n')
	url = strings.TrimSpace(url)

	if url == "" {
		url = "https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/domains-default.txt"
	}

	// Save to database
	err := config.SaveSetting("update_url", url)
	if err != nil {
		fmt.Printf("Failed to save update URL: %v\n", err)
		return
	}

	fmt.Printf("Update URL set to: %s\n", url)
}

func listDomains() {
	fmt.Println("Listing all domains...")
	listBlockedDomains()
	fmt.Println("\nWhitelisted domains:")
	listWhitelistedDomains()
}

func listIPs() {
	fmt.Println("Listing all IPs...")
	listBlockedIPs()
	fmt.Println("\nWhitelisted IPs:")
	listWhitelistedIPs()
}
