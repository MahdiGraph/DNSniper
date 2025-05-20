package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/MahdiGraph/DNSniper/internal/config"
	"github.com/MahdiGraph/DNSniper/internal/database"
	"github.com/MahdiGraph/DNSniper/internal/firewall"
	"github.com/MahdiGraph/DNSniper/internal/service"
	"github.com/fatih/color"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var log = logrus.New()

// Color definitions for UI
var (
	titleColor     = color.New(color.FgHiCyan, color.Bold)
	subtitleColor  = color.New(color.FgCyan)
	successColor   = color.New(color.FgGreen)
	errorColor     = color.New(color.FgRed)
	warningColor   = color.New(color.FgYellow)
	infoColor      = color.New(color.FgBlue)
	menuColor      = color.New(color.FgHiWhite)
	optionColor    = color.New(color.FgWhite)
	highlightColor = color.New(color.FgHiYellow)
	promptColor    = color.New(color.FgHiGreen)
)

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
		errorColor.Fprintf(os.Stderr, "Failed to initialize database: %v\n", err)
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
		errorColor.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// clearScreen clears the terminal screen
func clearScreen() {
	cmd := exec.Command("clear")
	cmd.Stdout = os.Stdout
	cmd.Run()
}

// showMainMenu displays the main menu and handles user input
func showMainMenu() {
	reader := bufio.NewReader(os.Stdin)
	for {
		clearScreen()
		titleColor.Println("\n===============================")
		titleColor.Println("      D N S n i p e r")
		subtitleColor.Println("  Domain Threat Neutralizer")
		titleColor.Println("===============================")

		menuColor.Println("1. Run agent now")
		menuColor.Println("2. Show status")
		menuColor.Println("3. Manage domain blocklist")
		menuColor.Println("4. Manage domain whitelist")
		menuColor.Println("5. Manage IP blocklist")
		menuColor.Println("6. Manage IP whitelist")
		menuColor.Println("7. Settings")
		menuColor.Println("8. Clear firewall rules")
		menuColor.Println("0. Exit")
		warningColor.Println("U. Uninstall DNSniper")

		promptColor.Print("\nSelect an option: ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		switch input {
		case "1":
			clearScreen()
			runAgentNow()
			pressEnterToContinue(reader)
		case "2":
			clearScreen()
			showStatus()
			pressEnterToContinue(reader)
		case "3":
			manageDomainList("Domain Blocklist", false, reader)
		case "4":
			manageDomainList("Domain Whitelist", true, reader)
		case "5":
			manageIPList("IP Blocklist", false, reader)
		case "6":
			manageIPList("IP Whitelist", true, reader)
		case "7":
			manageSettings(reader)
		case "8":
			clearScreen()
			clearRules()
			pressEnterToContinue(reader)
		case "0":
			clearScreen()
			successColor.Println("Exiting DNSniper. Goodbye!")
			return
		case "u", "U":
			if confirmUninstall(reader) {
				return
			}
		default:
			errorColor.Println("Invalid option. Please try again.")
			time.Sleep(1 * time.Second)
		}
	}
}

func pressEnterToContinue(reader *bufio.Reader) {
	promptColor.Print("\nPress Enter to continue...")
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
	infoColor.Println("Running DNSniper agent...")
	err := service.RunAgentOnce()
	if err != nil {
		errorColor.Printf("Failed to run agent: %v\n", err)
		return
	}
	successColor.Println("Agent run completed successfully")
}

func showStatus() {
	status, err := service.GetAgentStatus()
	if err != nil {
		errorColor.Printf("Failed to get status: %v\n", err)
		return
	}

	// Get statistics
	stats, err := database.GetStatistics()
	if err != nil {
		errorColor.Printf("Failed to get statistics: %v\n", err)
	}

	titleColor.Println("\nDNSniper Status:")
	titleColor.Println("================")

	// Service Status
	subtitleColor.Println("\nService Information:")
	fmt.Printf("Service status: ")
	if status.ServiceStatus == "active" {
		successColor.Println(status.ServiceStatus)
	} else {
		warningColor.Println(status.ServiceStatus)
	}
	fmt.Printf("Last run: %s\n", status.LastRun)

	// Protection Statistics
	subtitleColor.Println("\nProtection Statistics:")
	fmt.Printf("Blocked domains: %d\n", status.BlockedDomains)
	fmt.Printf("Blocked IPs: %d\n", status.BlockedIPs)
	fmt.Printf("Whitelisted domains: %d\n", status.WhitelistedDomains)
	fmt.Printf("Whitelisted IPs: %d\n", status.WhitelistedIPs)

	// Recent Activity
	if stats != nil {
		subtitleColor.Println("\nRecent Activity:")
		fmt.Printf("Domains processed in last 24h: %d\n", stats.DomainsProcessed24h)
		fmt.Printf("IPs blocked in last 24h: %d\n", stats.IPsBlocked24h)
		fmt.Printf("Domains processed in last 7d: %d\n", stats.DomainsProcessed7d)
		fmt.Printf("IPs blocked in last 7d: %d\n", stats.IPsBlocked7d)

		// Top 5 recently blocked domains
		if len(stats.RecentBlockedDomains) > 0 {
			subtitleColor.Println("\nRecently Blocked Domains:")
			for i, domain := range stats.RecentBlockedDomains {
				if i >= 5 {
					break
				}
				fmt.Printf("- %s\n", domain)
			}
		}
	}
}

// manageDomainList handles both blocklist and whitelist domains with pagination
func manageDomainList(listType string, isWhitelist bool, reader *bufio.Reader) {
	page := 1
	itemsPerPage := 10

	for {
		clearScreen()
		titleColor.Printf("\n%s Management:\n", listType)

		// Get domains for current page
		domains, totalDomains, err := database.GetDomainsList(isWhitelist, page, itemsPerPage)
		if err != nil {
			errorColor.Printf("Error retrieving domains: %v\n", err)
			pressEnterToContinue(reader)
			return
		}

		totalPages := (totalDomains + itemsPerPage - 1) / itemsPerPage

		if len(domains) == 0 {
			infoColor.Println("No domains found.")
		} else {
			// Display domains with their expiration time if applicable
			for i, domain := range domains {
				domainStr := domain.Domain
				if !domain.IsCustom && domain.ExpiresAt.Valid {
					expiresIn := time.Until(domain.ExpiresAt.Time).Round(time.Hour)
					if expiresIn > 0 {
						domainStr = fmt.Sprintf("%s (expires in %s)", domainStr, expiresIn)
					} else {
						domainStr = fmt.Sprintf("%s (expired)", domainStr)
					}
				} else if domain.IsCustom {
					domainStr = fmt.Sprintf("%s (custom)", domainStr)
				}

				if domain.FlaggedAsCDN {
					warningColor.Printf("%d. %s [CDN]\n", (page-1)*itemsPerPage+i+1, domainStr)
				} else {
					fmt.Printf("%d. %s\n", (page-1)*itemsPerPage+i+1, domainStr)
				}
			}

			if totalPages > 1 {
				infoColor.Printf("\nPage %d of %d (Total domains: %d)\n", page, totalPages, totalDomains)
			}
		}

		subtitleColor.Println("\nOptions:")
		if totalPages > 1 {
			menuColor.Println("1. Next page")
			menuColor.Println("2. Previous page")
			menuColor.Println("3. Add domain")
			menuColor.Println("4. Remove domain")
			menuColor.Println("0. Back to main menu")
		} else {
			menuColor.Println("1. Add domain")
			menuColor.Println("2. Remove domain")
			menuColor.Println("0. Back to main menu")
		}

		promptColor.Print("\nSelect an option: ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		if totalPages > 1 {
			switch input {
			case "1": // Next page
				if page < totalPages {
					page++
				}
			case "2": // Previous page
				if page > 1 {
					page--
				}
			case "3": // Add domain
				addDomainToList(isWhitelist, reader)
			case "4": // Remove domain
				removeDomainFromList(isWhitelist, reader)
			case "0": // Back
				return
			default:
				errorColor.Println("Invalid option. Please try again.")
				time.Sleep(1 * time.Second)
			}
		} else {
			switch input {
			case "1": // Add domain
				addDomainToList(isWhitelist, reader)
			case "2": // Remove domain
				removeDomainFromList(isWhitelist, reader)
			case "0": // Back
				return
			default:
				errorColor.Println("Invalid option. Please try again.")
				time.Sleep(1 * time.Second)
			}
		}
	}
}

// manageIPList handles both blocklist and whitelist IPs with pagination
func manageIPList(listType string, isWhitelist bool, reader *bufio.Reader) {
	page := 1
	itemsPerPage := 10

	for {
		clearScreen()
		titleColor.Printf("\n%s Management:\n", listType)

		// Get IPs for current page
		ips, totalIPs, err := database.GetIPsList(isWhitelist, page, itemsPerPage)
		if err != nil {
			errorColor.Printf("Error retrieving IPs: %v\n", err)
			pressEnterToContinue(reader)
			return
		}

		totalPages := (totalIPs + itemsPerPage - 1) / itemsPerPage

		if len(ips) == 0 {
			infoColor.Println("No IPs found.")
		} else {
			// Display IPs with their expiration time if applicable
			for i, ip := range ips {
				ipStr := ip.IPAddress
				if !ip.IsCustom && ip.ExpiresAt.Valid {
					expiresIn := time.Until(ip.ExpiresAt.Time).Round(time.Hour)
					if expiresIn > 0 {
						ipStr = fmt.Sprintf("%s (expires in %s)", ipStr, expiresIn)
					} else {
						ipStr = fmt.Sprintf("%s (expired)", ipStr)
					}
				} else if ip.IsCustom {
					ipStr = fmt.Sprintf("%s (custom)", ipStr)
				}

				fmt.Printf("%d. %s\n", (page-1)*itemsPerPage+i+1, ipStr)
			}

			if totalPages > 1 {
				infoColor.Printf("\nPage %d of %d (Total IPs: %d)\n", page, totalPages, totalIPs)
			}
		}

		subtitleColor.Println("\nOptions:")
		if totalPages > 1 {
			menuColor.Println("1. Next page")
			menuColor.Println("2. Previous page")
			menuColor.Println("3. Add IP")
			menuColor.Println("4. Remove IP")
			menuColor.Println("0. Back to main menu")
		} else {
			menuColor.Println("1. Add IP")
			menuColor.Println("2. Remove IP")
			menuColor.Println("0. Back to main menu")
		}

		promptColor.Print("\nSelect an option: ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		if totalPages > 1 {
			switch input {
			case "1": // Next page
				if page < totalPages {
					page++
				}
			case "2": // Previous page
				if page > 1 {
					page--
				}
			case "3": // Add IP
				addIPToList(isWhitelist, reader)
			case "4": // Remove IP
				removeIPFromList(isWhitelist, reader)
			case "0": // Back
				return
			default:
				errorColor.Println("Invalid option. Please try again.")
				time.Sleep(1 * time.Second)
			}
		} else {
			switch input {
			case "1": // Add IP
				addIPToList(isWhitelist, reader)
			case "2": // Remove IP
				removeIPFromList(isWhitelist, reader)
			case "0": // Back
				return
			default:
				errorColor.Println("Invalid option. Please try again.")
				time.Sleep(1 * time.Second)
			}
		}
	}
}

func manageSettings(reader *bufio.Reader) {
	for {
		clearScreen()
		titleColor.Println("\nSettings Management:")

		menuColor.Println("1. View current settings")
		menuColor.Println("2. Change DNS resolver")
		menuColor.Println("3. Change block rule type")
		menuColor.Println("4. Toggle logging")
		menuColor.Println("5. Set rules expiration time")
		menuColor.Println("6. Manage update URLs")
		menuColor.Println("0. Back to main menu")

		promptColor.Print("\nSelect an option: ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		switch input {
		case "1":
			clearScreen()
			viewSettings()
			pressEnterToContinue(reader)
		case "2":
			clearScreen()
			changeDNSResolver(reader)
			pressEnterToContinue(reader)
		case "3":
			clearScreen()
			changeBlockRuleType(reader)
			pressEnterToContinue(reader)
		case "4":
			clearScreen()
			toggleLogging()
			pressEnterToContinue(reader)
		case "5":
			clearScreen()
			setRulesExpiration(reader)
			pressEnterToContinue(reader)
		case "6":
			manageUpdateURLs(reader)
		case "0":
			return
		default:
			errorColor.Println("Invalid option. Please try again.")
			time.Sleep(1 * time.Second)
		}
	}
}

func clearRules() {
	infoColor.Println("Clearing all firewall rules...")
	// Clear rules in memory
	fwManager, err := firewall.NewIPTablesManager()
	if err != nil {
		errorColor.Printf("Error initializing firewall manager: %v\n", err)
		return
	}

	if err := fwManager.ClearRules(); err != nil {
		errorColor.Printf("Error clearing rules: %v\n", err)
		return
	}

	successColor.Println("Rules cleared successfully and saved permanently")
}

func confirmUninstall(reader *bufio.Reader) bool {
	clearScreen()
	warningColor.Println("\n⚠️  WARNING: You are about to uninstall DNSniper ⚠️")
	fmt.Println("This will remove all DNSniper components, including:")
	fmt.Println("- All executable files")
	fmt.Println("- All firewall rules")
	fmt.Println("- All systemd services")
	fmt.Println("- All configuration files")

	promptColor.Print("\nAre you sure you want to uninstall DNSniper? (yes/no): ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	if strings.ToLower(input) == "yes" {
		infoColor.Println("Uninstalling DNSniper...")
		// Execute uninstall script
		cmd := exec.Command("sh", "-c", "cd /etc/dnsniper && ./scripts/installer.sh uninstall")
		if err := cmd.Run(); err != nil {
			errorColor.Printf("Error during uninstallation: %v\n", err)
		} else {
			successColor.Println("DNSniper has been uninstalled.")
		}
		return true
	}

	infoColor.Println("Uninstallation cancelled")
	time.Sleep(1 * time.Second)
	return false
}

// Domain management functions
func addDomainToList(isWhitelist bool, reader *bufio.Reader) {
	clearScreen()
	if isWhitelist {
		subtitleColor.Println("Add Domain to Whitelist")
	} else {
		subtitleColor.Println("Add Domain to Blocklist")
	}

	promptColor.Print("Enter domain: ")
	domain, _ := reader.ReadString('\n')
	domain = strings.TrimSpace(domain)

	if domain == "" {
		errorColor.Println("Domain cannot be empty.")
		time.Sleep(1 * time.Second)
		return
	}

	// Save domain to database
	_, err := database.SaveCustomDomain(domain, isWhitelist)
	if err != nil {
		errorColor.Printf("Failed to add domain: %v\n", err)
		time.Sleep(2 * time.Second)
		return
	}

	if isWhitelist {
		successColor.Printf("Domain %s added to whitelist\n", domain)
	} else {
		successColor.Printf("Domain %s added to blocklist\n", domain)
	}

	time.Sleep(1 * time.Second)
}

func removeDomainFromList(isWhitelist bool, reader *bufio.Reader) {
	clearScreen()
	if isWhitelist {
		subtitleColor.Println("Remove Domain from Whitelist")
	} else {
		subtitleColor.Println("Remove Domain from Blocklist")
	}

	promptColor.Print("Enter domain: ")
	domain, _ := reader.ReadString('\n')
	domain = strings.TrimSpace(domain)

	if domain == "" {
		errorColor.Println("Domain cannot be empty.")
		time.Sleep(1 * time.Second)
		return
	}

	// Remove domain from database
	err := database.RemoveDomain(domain, isWhitelist)
	if err != nil {
		errorColor.Printf("Failed to remove domain: %v\n", err)
		time.Sleep(2 * time.Second)
		return
	}

	if isWhitelist {
		successColor.Printf("Domain %s removed from whitelist\n", domain)
	} else {
		successColor.Printf("Domain %s removed from blocklist\n", domain)
	}

	time.Sleep(1 * time.Second)
}

func blockDomain(domain string) {
	_, err := database.SaveCustomDomain(domain, false)
	if err != nil {
		errorColor.Printf("Failed to block domain: %v\n", err)
		return
	}

	successColor.Printf("Domain %s blocked\n", domain)
}

func whitelistDomain(domain string) {
	_, err := database.SaveCustomDomain(domain, true)
	if err != nil {
		errorColor.Printf("Failed to whitelist domain: %v\n", err)
		return
	}

	successColor.Printf("Domain %s whitelisted\n", domain)
}

// IP management functions
func addIPToList(isWhitelist bool, reader *bufio.Reader) {
	clearScreen()
	if isWhitelist {
		subtitleColor.Println("Add IP to Whitelist")
	} else {
		subtitleColor.Println("Add IP to Blocklist")
	}

	promptColor.Print("Enter IP address: ")
	ip, _ := reader.ReadString('\n')
	ip = strings.TrimSpace(ip)

	if ip == "" {
		errorColor.Println("IP cannot be empty.")
		time.Sleep(1 * time.Second)
		return
	}

	// Validate IP format
	if !database.IsValidIP(ip) {
		errorColor.Printf("Invalid IP address format: %s\n", ip)
		time.Sleep(2 * time.Second)
		return
	}

	// Save IP to database
	err := database.SaveCustomIP(ip, isWhitelist)
	if err != nil {
		errorColor.Printf("Failed to add IP: %v\n", err)
		time.Sleep(2 * time.Second)
		return
	}

	// If it's a blocklist IP, apply firewall rule
	if !isWhitelist {
		settings, err := config.GetSettings()
		if err != nil {
			errorColor.Printf("Failed to get settings: %v\n", err)
			time.Sleep(2 * time.Second)
			return
		}

		fwManager, err := firewall.NewIPTablesManager()
		if err != nil {
			errorColor.Printf("Failed to initialize firewall: %v\n", err)
			time.Sleep(2 * time.Second)
			return
		}

		if err := fwManager.BlockIP(ip, settings.BlockRuleType); err != nil {
			errorColor.Printf("Failed to apply firewall rule: %v\n", err)
			time.Sleep(2 * time.Second)
			return
		}
	}

	if isWhitelist {
		successColor.Printf("IP %s added to whitelist\n", ip)
	} else {
		successColor.Printf("IP %s added to blocklist\n", ip)
	}

	time.Sleep(1 * time.Second)
}

func removeIPFromList(isWhitelist bool, reader *bufio.Reader) {
	clearScreen()
	if isWhitelist {
		subtitleColor.Println("Remove IP from Whitelist")
	} else {
		subtitleColor.Println("Remove IP from Blocklist")
	}

	promptColor.Print("Enter IP address: ")
	ip, _ := reader.ReadString('\n')
	ip = strings.TrimSpace(ip)

	if ip == "" {
		errorColor.Println("IP cannot be empty.")
		time.Sleep(1 * time.Second)
		return
	}

	// Remove IP from database
	err := database.RemoveIP(ip, isWhitelist)
	if err != nil {
		errorColor.Printf("Failed to remove IP: %v\n", err)
		time.Sleep(2 * time.Second)
		return
	}

	// If it's a blocklist IP, remove firewall rule
	if !isWhitelist {
		fwManager, err := firewall.NewIPTablesManager()
		if err != nil {
			errorColor.Printf("Failed to initialize firewall: %v\n", err)
			time.Sleep(2 * time.Second)
			return
		}

		if err := fwManager.UnblockIP(ip); err != nil {
			errorColor.Printf("Failed to remove firewall rule: %v\n", err)
			time.Sleep(2 * time.Second)
			return
		}
	}

	if isWhitelist {
		successColor.Printf("IP %s removed from whitelist\n", ip)
	} else {
		successColor.Printf("IP %s removed from blocklist\n", ip)
	}

	time.Sleep(1 * time.Second)
}

func blockIP(ip string) {
	if err := database.SaveCustomIP(ip, false); err != nil {
		errorColor.Printf("Failed to add IP to database: %v\n", err)
		return
	}

	settings, err := config.GetSettings()
	if err != nil {
		errorColor.Printf("Failed to get settings: %v\n", err)
		return
	}

	fwManager, err := firewall.NewIPTablesManager()
	if err != nil {
		errorColor.Printf("Failed to initialize firewall: %v\n", err)
		return
	}

	if err := fwManager.BlockIP(ip, settings.BlockRuleType); err != nil {
		errorColor.Printf("Failed to block IP: %v\n", err)
		return
	}

	successColor.Printf("IP %s blocked\n", ip)
}

func whitelistIP(ip string) {
	if err := database.SaveCustomIP(ip, true); err != nil {
		errorColor.Printf("Failed to whitelist IP: %v\n", err)
		return
	}

	successColor.Printf("IP %s whitelisted\n", ip)
}

// Settings functions
func viewSettings() {
	subtitleColor.Println("\nCurrent settings:")

	settings, err := config.GetSettings()
	if err != nil {
		errorColor.Printf("Failed to get settings: %v\n", err)
		return
	}

	fmt.Printf("DNS Resolver: %s\n", settings.DNSResolver)
	fmt.Printf("Block Rule Type: %s\n", settings.BlockRuleType)
	fmt.Printf("Logging Enabled: %v\n", settings.LoggingEnabled)
	fmt.Printf("Rule Expiration: %s\n", settings.RuleExpiration.String())
	fmt.Printf("Max IPs per Domain: %d\n", settings.MaxIPsPerDomain)

	// Display update URLs
	urls, err := database.GetUpdateURLs()
	if err != nil {
		errorColor.Printf("Failed to get update URLs: %v\n", err)
	} else {
		subtitleColor.Println("\nUpdate URLs:")
		if len(urls) == 0 {
			fmt.Println("No update URLs configured")
		} else {
			for i, url := range urls {
				fmt.Printf("%d. %s\n", i+1, url)
			}
		}
	}
}

func changeDNSResolver(reader *bufio.Reader) {
	subtitleColor.Println("Change DNS Resolver")

	settings, err := config.GetSettings()
	if err != nil {
		errorColor.Printf("Failed to get current settings: %v\n", err)
		return
	}

	fmt.Printf("Current DNS resolver: %s\n", settings.DNSResolver)
	promptColor.Print("Enter new DNS resolver (default 8.8.8.8): ")

	resolver, _ := reader.ReadString('\n')
	resolver = strings.TrimSpace(resolver)

	if resolver == "" {
		resolver = "8.8.8.8"
	}

	// Save to database
	err = config.SaveSetting("dns_resolver", resolver)
	if err != nil {
		errorColor.Printf("Failed to save DNS resolver: %v\n", err)
		return
	}

	successColor.Printf("DNS resolver set to: %s\n", resolver)
}

func changeBlockRuleType(reader *bufio.Reader) {
	subtitleColor.Println("Change Block Rule Type")

	fmt.Println("Select block rule type:")
	fmt.Println("1. source (block as source only)")
	fmt.Println("2. destination (block as destination only)")
	fmt.Println("3. both (block as both source and destination)")

	promptColor.Print("\nEnter choice [1-3]: ")
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
		errorColor.Println("Invalid choice. Using default (both).")
		ruleType = "both"
	}

	// Save to database
	err := config.SaveSetting("block_rule_type", ruleType)
	if err != nil {
		errorColor.Printf("Failed to save block rule type: %v\n", err)
		return
	}

	successColor.Printf("Block rule type set to: %s\n", ruleType)
}

func toggleLogging() {
	subtitleColor.Println("Toggle Logging")

	// Get current logging state
	settings, err := config.GetSettings()
	if err != nil {
		errorColor.Printf("Failed to get settings: %v\n", err)
		return
	}

	// Toggle logging
	newState := !settings.LoggingEnabled

	// Save to database
	err = config.SaveSetting("logging_enabled", strconv.FormatBool(newState))
	if err != nil {
		errorColor.Printf("Failed to update logging setting: %v\n", err)
		return
	}

	// Update service file
	err = service.UpdateServiceLogging(newState)
	if err != nil {
		errorColor.Printf("Failed to update service file: %v\n", err)
		return
	}

	if newState {
		successColor.Println("Logging has been enabled")
	} else {
		successColor.Println("Logging has been disabled")
	}
}

func setRulesExpiration(reader *bufio.Reader) {
	subtitleColor.Println("Set Rules Expiration Time")

	settings, err := config.GetSettings()
	if err != nil {
		errorColor.Printf("Failed to get current settings: %v\n", err)
		return
	}

	fmt.Printf("Current rule expiration: %s\n", settings.RuleExpiration.String())
	promptColor.Print("Enter rules expiration time in days (default 30): ")

	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	days := 30 // Default
	if input != "" {
		var err error
		days, err = strconv.Atoi(input)
		if err != nil || days <= 0 {
			errorColor.Println("Invalid input. Using default (30 days).")
			days = 30
		}
	}

	// Save to database
	err = config.SaveSetting("rule_expiration", fmt.Sprintf("%dd", days))
	if err != nil {
		errorColor.Printf("Failed to save rule expiration: %v\n", err)
		return
	}

	successColor.Printf("Rules expiration set to: %d days\n", days)
}

func manageUpdateURLs(reader *bufio.Reader) {
	for {
		clearScreen()
		titleColor.Println("\nManage Update URLs:")

		// Get all URLs
		urls, err := database.GetUpdateURLs()
		if err != nil {
			errorColor.Printf("Failed to get update URLs: %v\n", err)
			pressEnterToContinue(reader)
			return
		}

		if len(urls) == 0 {
			infoColor.Println("No update URLs configured.")
		} else {
			for i, url := range urls {
				fmt.Printf("%d. %s\n", i+1, url)
			}
		}

		subtitleColor.Println("\nOptions:")
		menuColor.Println("1. Add update URL")
		menuColor.Println("2. Remove update URL")
		menuColor.Println("0. Back to settings")

		promptColor.Print("\nSelect an option: ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		switch input {
		case "1":
			addUpdateURL(reader)
		case "2":
			removeUpdateURL(reader)
		case "0":
			return
		default:
			errorColor.Println("Invalid option. Please try again.")
			time.Sleep(1 * time.Second)
		}
	}
}

func addUpdateURL(reader *bufio.Reader) {
	clearScreen()
	subtitleColor.Println("Add Update URL")

	promptColor.Println("Enter URL for domain list (e.g., https://example.com/domains.txt):")
	url, _ := reader.ReadString('\n')
	url = strings.TrimSpace(url)

	if url == "" {
		errorColor.Println("URL cannot be empty.")
		time.Sleep(1 * time.Second)
		return
	}

	// Add URL to database
	if err := database.AddUpdateURL(url); err != nil {
		errorColor.Printf("Failed to add update URL: %v\n", err)
		time.Sleep(2 * time.Second)
		return
	}

	successColor.Printf("Update URL added: %s\n", url)
	time.Sleep(1 * time.Second)
}

func removeUpdateURL(reader *bufio.Reader) {
	clearScreen()
	subtitleColor.Println("Remove Update URL")

	// Get all URLs
	urls, err := database.GetUpdateURLs()
	if err != nil {
		errorColor.Printf("Failed to get update URLs: %v\n", err)
		time.Sleep(2 * time.Second)
		return
	}

	if len(urls) == 0 {
		errorColor.Println("No update URLs to remove.")
		time.Sleep(1 * time.Second)
		return
	}

	for i, url := range urls {
		fmt.Printf("%d. %s\n", i+1, url)
	}

	promptColor.Print("\nEnter the number of the URL to remove (0 to cancel): ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	if input == "0" {
		return
	}

	index, err := strconv.Atoi(input)
	if err != nil || index < 1 || index > len(urls) {
		errorColor.Println("Invalid selection.")
		time.Sleep(1 * time.Second)
		return
	}

	urlToRemove := urls[index-1]

	// Check if this is the last URL
	if len(urls) == 1 {
		warningColor.Println("Warning: This is the last update URL. Removing it will mean no domains will be automatically blocked.")
		promptColor.Print("Are you sure you want to continue? (yes/no): ")
		confirm, _ := reader.ReadString('\n')
		confirm = strings.TrimSpace(confirm)

		if strings.ToLower(confirm) != "yes" {
			infoColor.Println("Operation cancelled.")
			time.Sleep(1 * time.Second)
			return
		}
	}

	// Remove URL from database
	if err := database.RemoveUpdateURL(urlToRemove); err != nil {
		errorColor.Printf("Failed to remove update URL: %v\n", err)
		time.Sleep(2 * time.Second)
		return
	}

	successColor.Printf("Update URL removed: %s\n", urlToRemove)
	time.Sleep(1 * time.Second)
}

func listDomains() {
	fmt.Println("Listing all domains...")

	// Get domains
	blockedDomains, _, err := database.GetDomainsList(false, 1, 1000)
	if err != nil {
		errorColor.Printf("Error retrieving blocked domains: %v\n", err)
		return
	}

	whitelistedDomains, _, err := database.GetDomainsList(true, 1, 1000)
	if err != nil {
		errorColor.Printf("Error retrieving whitelisted domains: %v\n", err)
		return
	}

	fmt.Println("\nBlocked domains:")
	if len(blockedDomains) == 0 {
		fmt.Println("No blocked domains")
	} else {
		for _, domain := range blockedDomains {
			fmt.Println(domain.Domain)
		}
	}

	fmt.Println("\nWhitelisted domains:")
	if len(whitelistedDomains) == 0 {
		fmt.Println("No whitelisted domains")
	} else {
		for _, domain := range whitelistedDomains {
			fmt.Println(domain.Domain)
		}
	}
}

func listIPs() {
	fmt.Println("Listing all IPs...")

	// Get IPs
	blockedIPs, _, err := database.GetIPsList(false, 1, 1000)
	if err != nil {
		errorColor.Printf("Error retrieving blocked IPs: %v\n", err)
		return
	}

	whitelistedIPs, _, err := database.GetIPsList(true, 1, 1000)
	if err != nil {
		errorColor.Printf("Error retrieving whitelisted IPs: %v\n", err)
		return
	}

	fmt.Println("\nBlocked IPs:")
	if len(blockedIPs) == 0 {
		fmt.Println("No blocked IPs")
	} else {
		for _, ip := range blockedIPs {
			fmt.Println(ip.IPAddress)
		}
	}

	fmt.Println("\nWhitelisted IPs:")
	if len(whitelistedIPs) == 0 {
		fmt.Println("No whitelisted IPs")
	} else {
		for _, ip := range whitelistedIPs {
			fmt.Println(ip.IPAddress)
		}
	}
}
