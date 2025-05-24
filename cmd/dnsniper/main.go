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
	"github.com/MahdiGraph/DNSniper/internal/dns"
	"github.com/MahdiGraph/DNSniper/internal/firewall"
	"github.com/MahdiGraph/DNSniper/internal/service"
	"github.com/MahdiGraph/DNSniper/internal/utils"
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
		// ASCII art banner for DNSniper
		titleColor.Println(`
 _____  _   _  _____       _                 
|   **\| \ | |/** __|     (_)                
| |  | |  \| | (___  _ __  _ _ __   ___ _ __
| |  | | . ' |\___ \| '_ \| | '_ \ / _\ '__|
| |__| | |\  |____) | | | | | |_) |  __/ |   
|_____/|_| \_|_____/|_| |_|_| .__/ \___|_|   
                             | |              
                             |_|              
`)
		titleColor.Println("version v1.3.6-beta.3")
		subtitleColor.Println("Lock onto threats, restore your peace of mind!")
		titleColor.Println("===============================================")
		menuColor.Println("1. Run agent now")
		menuColor.Println("2. Show status")
		menuColor.Println("3. Manage blocklist")
		menuColor.Println("4. Manage whitelist")
		menuColor.Println("5. Settings")
		menuColor.Println("6. Clear firewall rules")
		menuColor.Println("7. Rebuild firewall rules")
		menuColor.Println("H. Help / Quick Guide")
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
			manageBlocklist(reader)
		case "4":
			manageWhitelist(reader)
		case "5":
			manageSettings(reader)
		case "6":
			clearScreen()
			// Check if agent is running before clearing rules
			if isAgentRunning() {
				errorColor.Println("Cannot clear firewall rules while the agent is running.")
				errorColor.Println("Please wait for the agent to complete its current run and try again.")
				pressEnterToContinue(reader)
			} else {
				clearRules()
				pressEnterToContinue(reader)
			}
		case "7":
			clearScreen()
			// Check if agent is running before rebuilding rules
			if isAgentRunning() {
				errorColor.Println("Cannot rebuild firewall rules while the agent is running.")
				errorColor.Println("Please wait for the agent to complete its current run and try again.")
				pressEnterToContinue(reader)
			} else {
				rebuildFirewallRules()
				pressEnterToContinue(reader)
			}
		case "h", "H":
			showHelpGuide(reader)
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

// manageBlocklist displays a menu for managing the blocklist (both domains and IPs)
func manageBlocklist(reader *bufio.Reader) {
	for {
		clearScreen()
		titleColor.Println("\nBlocklist Management:")
		subtitleColor.Println("\nChoose what to manage:")
		menuColor.Println("1. Manage blocked domains")
		menuColor.Println("2. Manage blocked IP addresses")
		menuColor.Println("3. Add item to blocklist")
		menuColor.Println("0. Back to main menu")

		promptColor.Print("\nSelect an option: ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		switch input {
		case "1":
			manageDomainList("Domain Blocklist", false, reader)
		case "2":
			manageIPList("IP Blocklist", false, reader)
		case "3":
			addItemToBlocklist(reader)
		case "0":
			return
		default:
			errorColor.Println("Invalid option. Please try again.")
			time.Sleep(1 * time.Second)
		}
	}
}

// manageWhitelist displays a menu for managing the whitelist (both domains and IPs)
func manageWhitelist(reader *bufio.Reader) {
	for {
		clearScreen()
		titleColor.Println("\nWhitelist Management:")
		subtitleColor.Println("\nChoose what to manage:")
		menuColor.Println("1. Manage whitelisted domains")
		menuColor.Println("2. Manage whitelisted IP addresses")
		menuColor.Println("3. Add item to whitelist")
		menuColor.Println("0. Back to main menu")

		promptColor.Print("\nSelect an option: ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		switch input {
		case "1":
			manageDomainList("Domain Whitelist", true, reader)
		case "2":
			manageIPList("IP Whitelist", true, reader)
		case "3":
			addItemToWhitelist(reader)
		case "0":
			return
		default:
			errorColor.Println("Invalid option. Please try again.")
			time.Sleep(1 * time.Second)
		}
	}
}

// addItemToBlocklist handles adding either a domain or IP to the blocklist
func addItemToBlocklist(reader *bufio.Reader) {
	clearScreen()
	titleColor.Println("\nAdd Item to Blocklist:")
	menuColor.Println("1. Add domain")
	menuColor.Println("2. Add IP address or range")
	menuColor.Println("0. Back")

	promptColor.Print("\nSelect an option: ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	switch input {
	case "1":
		addDomainToList(false, reader)
	case "2":
		addIPToList(false, reader)
	case "0":
		return
	default:
		errorColor.Println("Invalid option. Please try again.")
		time.Sleep(1 * time.Second)
	}
}

// addItemToWhitelist handles adding either a domain or IP to the whitelist
func addItemToWhitelist(reader *bufio.Reader) {
	clearScreen()
	titleColor.Println("\nAdd Item to Whitelist:")
	menuColor.Println("1. Add domain")
	menuColor.Println("2. Add IP address or range")
	menuColor.Println("0. Back")

	promptColor.Print("\nSelect an option: ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	switch input {
	case "1":
		addDomainToList(true, reader)
	case "2":
		addIPToList(true, reader)
	case "0":
		return
	default:
		errorColor.Println("Invalid option. Please try again.")
		time.Sleep(1 * time.Second)
	}
}

// addDomainToList handles both blocklist and whitelist domains
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

	// Check if domain exists in the opposite list
	if isWhitelist {
		inBlocklist, err := database.IsDomainInBlocklist(domain)
		if err == nil && inBlocklist {
			warningColor.Printf("Warning: Domain %s is currently in the blocklist. Adding to whitelist will override the block.\n", domain)
			promptColor.Print("Continue? (y/n): ")
			confirm, _ := reader.ReadString('\n')
			confirm = strings.TrimSpace(confirm)
			if strings.ToLower(confirm) != "y" {
				infoColor.Println("Operation cancelled.")
				time.Sleep(1 * time.Second)
				return
			}

			// First remove from blocklist to prevent conflicts
			if err := database.RemoveDomain(domain, false); err != nil {
				errorColor.Printf("Failed to remove domain from blocklist: %v\n", err)
				// Continue anyway to try adding to whitelist
			}
		}
	} else {
		isWhitelisted, err := database.IsDomainWhitelisted(domain)
		if err == nil && isWhitelisted {
			warningColor.Printf("Warning: Domain %s is currently in the whitelist. Whitelist has priority over blocklist.\n", domain)
			promptColor.Print("Continue? (y/n): ")
			confirm, _ := reader.ReadString('\n')
			confirm = strings.TrimSpace(confirm)
			if strings.ToLower(confirm) != "y" {
				infoColor.Println("Operation cancelled.")
				time.Sleep(1 * time.Second)
				return
			}
		}
	}

	// Save domain to database
	_, err := database.SaveCustomDomain(domain, isWhitelist)
	if err != nil {
		errorColor.Printf("Failed to add domain: %v\n", err)
		time.Sleep(2 * time.Second)
		return
	}

	// For whitelisted domains, remove any existing blocking rules for IPs of this domain
	if isWhitelist {
		// Get all IPs associated with this domain
		ips, err := database.GetIPsForDomain(domain)
		if err == nil && len(ips) > 0 {
			fwManager, err := firewall.NewIPTablesManager()
			if err != nil {
				errorColor.Printf("Failed to initialize firewall: %v\n", err)
			} else {
				for _, ip := range ips {
					// First remove from blocklist
					if err := fwManager.UnblockIP(ip); err != nil {
						log.Warnf("Failed to unblock IP %s: %v", ip, err)
					}

					// Then add to whitelist
					if err := fwManager.WhitelistIP(ip); err != nil {
						log.Warnf("Failed to whitelist IP %s: %v", ip, err)
					} else {
						infoColor.Printf("Whitelisted IP %s for domain %s\n", ip, domain)
					}
				}

				// Save changes to firewall
				if err := fwManager.SaveRulesToPersistentFiles(); err != nil {
					log.Warnf("Failed to save firewall rules: %v", err)
				}
			}
		}
	} else {
		// For blocked domains, we need to handle whitelisted IPs carefully
		// Resolve the domain and add IPs to blocklist
		settings, err := config.GetSettings()
		if err != nil {
			errorColor.Printf("Failed to get settings: %v\n", err)
		} else {
			resolver := dns.NewStandardResolver()
			ips, err := resolver.ResolveDomain(domain, settings.DNSResolver)
			if err != nil {
				errorColor.Printf("Failed to resolve domain: %v\n", err)
				// Continue with operation but warn
			}

			if len(ips) > 0 {
				fwManager, err := firewall.NewIPTablesManager()
				if err != nil {
					errorColor.Printf("Failed to initialize firewall: %v\n", err)
				} else {
					for _, ip := range ips {
						// Skip invalid IPs
						valid, _ := utils.IsValidIPToBlock(ip)
						if !valid {
							continue
						}

						// Critical check: Skip whitelisted IPs
						isWhitelisted, _ := database.IsIPWhitelisted(ip)
						if isWhitelisted {
							infoColor.Printf("IP %s is whitelisted, not blocking\n", ip)
							continue
						}

						// Get domain ID
						var domainID int64
						err = database.GetDomainID(domain, &domainID)
						if err != nil {
							errorColor.Printf("Failed to get domain ID: %v\n", err)
							continue
						}

						// Add IP to database before blocking
						if err := database.AssociateIPWithDomain(domainID, ip, false); err != nil {
							errorColor.Printf("Failed to associate IP with domain: %v\n", err)
							continue
						}

						// Finally block the IP
						if err := fwManager.BlockIP(ip, settings.BlockRuleType); err != nil {
							errorColor.Printf("Failed to block IP %s: %v\n", ip, err)
						} else {
							successColor.Printf("Blocked IP %s for domain %s\n", ip, domain)
						}
					}

					// Save changes
					if err := fwManager.SaveRulesToPersistentFiles(); err != nil {
						log.Warnf("Failed to save firewall rules: %v", err)
					}
				}
			}
		}
	}

	if isWhitelist {
		successColor.Printf("Domain %s added to whitelist\n", domain)
	} else {
		successColor.Printf("Domain %s added to blocklist\n", domain)
	}
	time.Sleep(1 * time.Second)
}

// showHelpGuide displays a help and quick guide screen
func showHelpGuide(reader *bufio.Reader) {
	clearScreen()
	titleColor.Println("\nDNSniper - Quick Guide")
	titleColor.Println("=====================")

	subtitleColor.Println("\nMain Features:")
	fmt.Println("1. Run agent now - Start the DNSniper agent to process domains and block suspicious IPs")
	fmt.Println("2. Show status - Display the current status of DNSniper including statistics")
	fmt.Println("3. Manage blocklist - Add or remove domains and IPs from the blocklist")
	fmt.Println("4. Manage whitelist - Add or remove domains and IPs from the whitelist (will never be blocked)")

	subtitleColor.Println("\nAdvanced Options:")
	fmt.Println("5. Settings - Configure DNSniper settings (DNS resolver, block rule type, update URLs, etc.)")
	fmt.Println("6. Clear firewall rules - Remove all DNSniper rules from the firewall")
	fmt.Println("7. Rebuild firewall rules - Rebuild all firewall rules from the database")

	subtitleColor.Println("\nHow It Works:")
	fmt.Println("- DNSniper periodically checks domains from configured sources")
	fmt.Println("- It resolves these domains to IP addresses")
	fmt.Println("- Suspicious IPs are added to the firewall blocklist")
	fmt.Println("- Whitelisted domains and IPs are never blocked")

	subtitleColor.Println("\nIPSet Technology:")
	fmt.Println("- DNSniper uses ipset for efficient IP management")
	fmt.Println("- This allows for blocking millions of IPs with minimal performance impact")
	fmt.Println("- Both individual IPs and CIDR ranges are supported")

	subtitleColor.Println("\nTips:")
	fmt.Println("- The agent runs automatically according to your configured schedule")
	fmt.Println("- You can add custom domains/IPs to both block and whitelist")
	fmt.Println("- Use the whitelist to prevent false positives")
	fmt.Println("- Check status regularly to monitor protection statistics")

	pressEnterToContinue(reader)
}

// isAgentRunning checks if the agent is currently running
func isAgentRunning() bool {
	isRunning, err := service.IsAgentRunning()
	if err != nil {
		errorColor.Printf("Failed to check agent status: %v\n", err)
		return false // Assume not running in case of error
	}
	return isRunning
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
	// Check if agent is already running
	if already, _ := service.IsAgentRunning(); already {
		warningColor.Println("Agent is already running in background.")
		infoColor.Println("You can check its status with option 2 (Show status).")
		return
	}

	infoColor.Println("Starting DNSniper agent in background...")
	// Run the agent in background using & at the end
	cmd := exec.Command("sh", "-c", "systemctl start dnsniper-agent.service &")
	err := cmd.Run()
	if err != nil {
		errorColor.Printf("Failed to start agent: %v\n", err)
		return
	}
	successColor.Println("Agent started successfully in background")
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
	itemsPerPage := 20 // Увеличено с 10 до 20
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
	itemsPerPage := 20 // Увеличено с 10 до 20
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
				// Add an indicator if this is a range
				if ip.IsRange {
					ipStr = fmt.Sprintf("%s [RANGE]", ipStr)
				}

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
			menuColor.Println("3. Add IP or IP range")
			menuColor.Println("4. Remove IP or IP range")
			menuColor.Println("0. Back to main menu")
		} else {
			menuColor.Println("1. Add IP or IP range")
			menuColor.Println("2. Remove IP or IP range")
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
		menuColor.Println("7. Change agent timer interval")
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
			// Check if agent is running
			if isAgentRunning() {
				errorColor.Println("Cannot change block rule type while the agent is running.")
				errorColor.Println("Please wait for the agent to complete its current run and try again.")
				pressEnterToContinue(reader)
			} else {
				changeBlockRuleType(reader)
				// Automatically rebuild firewall rules
				infoColor.Println("\nRebuilding firewall rules with new block rule type...")
				rebuildFirewallRules()
				pressEnterToContinue(reader)
			}
		case "4":
			clearScreen()
			toggleLogging(reader)
			pressEnterToContinue(reader)
		case "5":
			clearScreen()
			setRulesExpiration(reader)
			pressEnterToContinue(reader)
		case "6":
			manageUpdateURLs(reader)
		case "7":
			clearScreen()
			changeAgentTimer(reader)
			pressEnterToContinue(reader)
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

func rebuildFirewallRules() {
	infoColor.Println("Rebuilding firewall rules...")
	// First, clear existing rules
	fwManager, err := firewall.NewIPTablesManager()
	if err != nil {
		errorColor.Printf("Error initializing firewall manager: %v\n", err)
		return
	}

	if err := fwManager.ClearRules(); err != nil {
		errorColor.Printf("Error clearing rules: %v\n", err)
		return
	}

	// Get all blocked IPs and IP ranges from database
	blockedIPs, blockedRanges, err := database.GetAllBlockedIPs()
	if err != nil {
		errorColor.Printf("Error getting blocked IPs: %v\n", err)
		return
	}

	// Get all whitelisted IPs and ranges
	whitelistedIPs, whitelistedRanges, err := database.GetAllWhitelistedIPs()
	if err != nil {
		errorColor.Printf("Error getting whitelisted IPs: %v\n", err)
		return
	}

	// Get settings (block rule type no longer used functionally, but kept for compatibility)
	settings, err := config.GetSettings()
	if err != nil {
		errorColor.Printf("Error getting settings: %v\n", err)
		return
	}

	// Apply rules for each IP
	successCount := 0
	failCount := 0
	skippedCount := 0

	// Process whitelist first (higher priority)
	infoColor.Printf("Processing whitelist rules for %d IPs and %d IP ranges...\n", len(whitelistedIPs), len(whitelistedRanges))

	for _, ip := range whitelistedIPs {
		if err := fwManager.WhitelistIP(ip); err != nil {
			errorColor.Printf("Error whitelisting IP %s: %v\n", ip, err)
			failCount++
		} else {
			successCount++
		}
	}

	for _, cidr := range whitelistedRanges {
		if err := fwManager.WhitelistIPRange(cidr); err != nil {
			errorColor.Printf("Error whitelisting IP range %s: %v\n", cidr, err)
			failCount++
		} else {
			successCount++
		}
	}

	// Process blocklist (lower priority)
	infoColor.Printf("Processing blocklist rules for %d IPs and %d IP ranges...\n", len(blockedIPs), len(blockedRanges))

	for _, ip := range blockedIPs {
		// Check if IP is whitelisted
		isWhitelisted, err := database.IsIPWhitelisted(ip)
		if err != nil {
			log.Warnf("Failed to check if IP %s is whitelisted: %v", ip, err)
			failCount++
			continue
		}

		if isWhitelisted {
			infoColor.Printf("Skipping IP %s as it is whitelisted\n", ip)
			skippedCount++
			continue
		}

		// BlockRuleType is now ignored internally but kept in the API for compatibility
		if err := fwManager.BlockIP(ip, settings.BlockRuleType); err != nil {
			errorColor.Printf("Error blocking IP %s: %v\n", ip, err)
			failCount++
		} else {
			successCount++
		}
	}

	// Apply rules for IP ranges
	for _, cidr := range blockedRanges {
		// Check if range is whitelisted
		isWhitelisted, err := database.IsIPRangeWhitelisted(cidr)
		if err != nil {
			log.Warnf("Failed to check if range %s is whitelisted: %v", cidr, err)
			failCount++
			continue
		}

		if isWhitelisted {
			infoColor.Printf("Skipping range %s as it is whitelisted\n", cidr)
			skippedCount++
			continue
		}

		// BlockRuleType is now ignored internally but kept in the API for compatibility
		if err := fwManager.BlockIPRange(cidr, settings.BlockRuleType); err != nil {
			errorColor.Printf("Error blocking IP range %s: %v\n", cidr, err)
			failCount++
		} else {
			successCount++
		}
	}

	// Save the changes to persistent files
	if err := fwManager.SaveRulesToPersistentFiles(); err != nil {
		errorColor.Printf("Error saving firewall rules: %v\n", err)
		return
	}

	successColor.Printf("Firewall rules rebuilt successfully.\n")
	infoColor.Printf("Applied rules: %d, Skipped (whitelisted): %d, Failed rules: %d\n",
		successCount, skippedCount, failCount)
}

func confirmUninstall(reader *bufio.Reader) bool {
	clearScreen()
	warningColor.Println("\n⚠️  WARNING: You are about to uninstall DNSniper ⚠️")
	fmt.Println("This will remove all DNSniper components, including:")
	fmt.Println("- All executable files")
	fmt.Println("- All firewall rules (including IPSet rules)")
	fmt.Println("- All systemd services")
	fmt.Println("- All configuration files")
	promptColor.Print("\nAre you sure you want to uninstall DNSniper? (yes/no): ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	if strings.ToLower(input) == "yes" {
		infoColor.Println("Uninstalling DNSniper...")

		// Stop and disable services
		exec.Command("systemctl", "stop", "dnsniper-agent.service").Run()
		exec.Command("systemctl", "disable", "dnsniper-agent.service").Run()
		exec.Command("systemctl", "stop", "dnsniper-agent.timer").Run()
		exec.Command("systemctl", "disable", "dnsniper-agent.timer").Run()

		// Remove service files
		exec.Command("rm", "-f", "/etc/systemd/system/dnsniper-agent.service").Run()
		exec.Command("rm", "-f", "/etc/systemd/system/dnsniper-agent.timer").Run()

		// Remove symlinks
		exec.Command("rm", "-f", "/usr/bin/dnsniper").Run()
		exec.Command("rm", "-f", "/usr/bin/dnsniper-agent").Run()

		// Clean up iptables rules
		infoColor.Println("Cleaning up iptables rules...")

		// First clean up any legacy direct DROP rules that might exist
		exec.Command("sh", "-c", "iptables-save | grep -v -- \"-A DNSniper .* -j DROP\" | iptables-restore").Run()
		exec.Command("sh", "-c", "ip6tables-save | grep -v -- \"-A DNSniper6 .* -j DROP\" | ip6tables-restore").Run()

		// Clean up traditional chains
		exec.Command("sh", "-c", "iptables -D INPUT -j DNSniper 2>/dev/null || true").Run()
		exec.Command("sh", "-c", "iptables -D OUTPUT -j DNSniper 2>/dev/null || true").Run()
		exec.Command("sh", "-c", "iptables -D FORWARD -j DNSniper 2>/dev/null || true").Run()
		exec.Command("sh", "-c", "iptables -F DNSniper 2>/dev/null || true").Run()
		exec.Command("sh", "-c", "iptables -X DNSniper 2>/dev/null || true").Run()

		// Same for IPv6
		exec.Command("sh", "-c", "ip6tables -D INPUT -j DNSniper6 2>/dev/null || true").Run()
		exec.Command("sh", "-c", "ip6tables -D OUTPUT -j DNSniper6 2>/dev/null || true").Run()
		exec.Command("sh", "-c", "ip6tables -D FORWARD -j DNSniper6 2>/dev/null || true").Run()
		exec.Command("sh", "-c", "ip6tables -F DNSniper6 2>/dev/null || true").Run()
		exec.Command("sh", "-c", "ip6tables -X DNSniper6 2>/dev/null || true").Run()

		// Clean up ipset rules
		infoColor.Println("Cleaning up ipset rules...")

		// Remove ipset rules from iptables
		exec.Command("sh", "-c", "iptables -D INPUT -m set --match-set dnsniper-whitelist src -j ACCEPT 2>/dev/null || true").Run()
		exec.Command("sh", "-c", "iptables -D OUTPUT -m set --match-set dnsniper-whitelist dst -j ACCEPT 2>/dev/null || true").Run()
		exec.Command("sh", "-c", "iptables -D INPUT -m set --match-set dnsniper-range-whitelist src -j ACCEPT 2>/dev/null || true").Run()
		exec.Command("sh", "-c", "iptables -D OUTPUT -m set --match-set dnsniper-range-whitelist dst -j ACCEPT 2>/dev/null || true").Run()
		exec.Command("sh", "-c", "iptables -D INPUT -m set --match-set dnsniper-blocklist src -j DROP 2>/dev/null || true").Run()
		exec.Command("sh", "-c", "iptables -D OUTPUT -m set --match-set dnsniper-blocklist dst -j DROP 2>/dev/null || true").Run()
		exec.Command("sh", "-c", "iptables -D INPUT -m set --match-set dnsniper-range-blocklist src -j DROP 2>/dev/null || true").Run()
		exec.Command("sh", "-c", "iptables -D OUTPUT -m set --match-set dnsniper-range-blocklist dst -j DROP 2>/dev/null || true").Run()

		// Same for IPv6
		exec.Command("sh", "-c", "ip6tables -D INPUT -m set --match-set dnsniper-whitelist src -j ACCEPT 2>/dev/null || true").Run()
		exec.Command("sh", "-c", "ip6tables -D OUTPUT -m set --match-set dnsniper-whitelist dst -j ACCEPT 2>/dev/null || true").Run()
		exec.Command("sh", "-c", "ip6tables -D INPUT -m set --match-set dnsniper-range-whitelist src -j ACCEPT 2>/dev/null || true").Run()
		exec.Command("sh", "-c", "ip6tables -D OUTPUT -m set --match-set dnsniper-range-whitelist dst -j ACCEPT 2>/dev/null || true").Run()
		exec.Command("sh", "-c", "ip6tables -D INPUT -m set --match-set dnsniper-blocklist src -j DROP 2>/dev/null || true").Run()
		exec.Command("sh", "-c", "ip6tables -D OUTPUT -m set --match-set dnsniper-blocklist dst -j DROP 2>/dev/null || true").Run()
		exec.Command("sh", "-c", "ip6tables -D INPUT -m set --match-set dnsniper-range-blocklist src -j DROP 2>/dev/null || true").Run()
		exec.Command("sh", "-c", "ip6tables -D OUTPUT -m set --match-set dnsniper-range-blocklist dst -j DROP 2>/dev/null || true").Run()

		// Destroy ipset sets
		exec.Command("sh", "-c", "ipset destroy dnsniper-whitelist 2>/dev/null || true").Run()
		exec.Command("sh", "-c", "ipset destroy dnsniper-blocklist 2>/dev/null || true").Run()
		exec.Command("sh", "-c", "ipset destroy dnsniper-range-whitelist 2>/dev/null || true").Run()
		exec.Command("sh", "-c", "ipset destroy dnsniper-range-blocklist 2>/dev/null || true").Run()

		// Delete ipset configuration file
		exec.Command("rm", "-f", "/etc/ipset.conf").Run()

		// Save iptables rules
		exec.Command("sh", "-c", "mkdir -p /etc/iptables").Run()
		exec.Command("sh", "-c", "iptables-save > /etc/iptables/rules.v4 2>/dev/null || true").Run()
		exec.Command("sh", "-c", "ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true").Run()
		exec.Command("sh", "-c", "systemctl restart netfilter-persistent 2>/dev/null || true").Run()

		// Confirm with user what to do with logs
		promptColor.Print("Would you like to keep log files? (y/n): ")
		keepLogs, _ := reader.ReadString('\n')
		keepLogs = strings.TrimSpace(keepLogs)

		// Remove installation directory
		exec.Command("rm", "-rf", "/etc/dnsniper").Run()

		// Remove logs if requested
		if strings.ToLower(keepLogs) == "n" || strings.ToLower(keepLogs) == "no" {
			exec.Command("rm", "-rf", "/var/log/dnsniper").Run()
			infoColor.Println("Log files removed")
		} else {
			infoColor.Println("Log files kept at /var/log/dnsniper")
		}

		successColor.Println("DNSniper has been uninstalled.")
		return true
	}

	infoColor.Println("Uninstallation cancelled")
	time.Sleep(1 * time.Second)
	return false
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

	// If removing from whitelist, check if domain is in blocklist
	if isWhitelist {
		inBlocklist, err := database.IsDomainInBlocklist(domain)
		if err != nil {
			log.Warnf("Failed to check if domain %s is in blocklist: %v", domain, err)
		} else if inBlocklist {
			// Domain is in blocklist, need to reapply block rules
			warningColor.Printf("Warning: Domain %s is also in the blocklist. Removing it from whitelist will cause it to be blocked.\n", domain)
			promptColor.Print("Continue? (y/n): ")
			confirm, _ := reader.ReadString('\n')
			confirm = strings.TrimSpace(confirm)
			if strings.ToLower(confirm) != "y" {
				infoColor.Println("Operation cancelled.")
				time.Sleep(1 * time.Second)
				return
			}

			// Get IPs for this domain
			ips, err := database.GetIPsForDomain(domain)
			if err != nil {
				log.Warnf("Failed to get IPs for domain %s: %v", domain, err)
			} else if len(ips) > 0 {
				// Block these IPs since domain is in blocklist
				settings, err := config.GetSettings()
				if err != nil {
					log.Warnf("Failed to get settings: %v", err)
				} else {
					fwManager, err := firewall.NewIPTablesManager()
					if err != nil {
						log.Warnf("Failed to initialize firewall: %v", err)
					} else {
						for _, ip := range ips {
							// Check if IP itself is whitelisted
							isIPWhitelisted, err := database.IsIPWhitelisted(ip)
							if err == nil && isIPWhitelisted {
								infoColor.Printf("IP %s is explicitly whitelisted, skipping\n", ip)
								continue
							}

							if err := fwManager.BlockIP(ip, settings.BlockRuleType); err != nil {
								log.Warnf("Failed to reblock IP %s: %v", ip, err)
							} else {
								infoColor.Printf("Reblocked IP %s for domain %s\n", ip, domain)
							}
						}

						// Save changes to firewall
						if err := fwManager.SaveRulesToPersistentFiles(); err != nil {
							log.Warnf("Failed to save firewall rules: %v", err)
						}
					}
				}
			}
		}
	}

	// Remove domain from database and associated firewall rules
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

// blockDomain blocks a domain
func blockDomain(domain string) {
	// Check if domain is already whitelisted
	isWhitelisted, err := database.IsDomainWhitelisted(domain)
	if err == nil && isWhitelisted {
		warningColor.Printf("Warning: Domain %s is already in the whitelist. Whitelist has priority over blocklist.\n", domain)
		return
	}

	domainID, err := database.SaveCustomDomain(domain, false)
	if err != nil {
		errorColor.Printf("Failed to block domain: %v\n", err)
		return
	}

	// Immediately apply firewall rules only if not whitelisted
	if !isWhitelisted {
		settings, err := config.GetSettings()
		if err != nil {
			errorColor.Printf("Failed to get settings: %v\n", err)
			return
		}

		resolver := dns.NewStandardResolver()
		ips, err := resolver.ResolveDomain(domain, settings.DNSResolver)
		if err != nil {
			errorColor.Printf("Failed to resolve domain: %v\n", err)
			// Continue even if resolution fails
		}

		// Apply firewall rules for resolved IPs
		if len(ips) > 0 {
			fwManager, err := firewall.NewIPTablesManager()
			if err != nil {
				errorColor.Printf("Failed to initialize firewall: %v\n", err)
				return
			}

			for _, ip := range ips {
				// Check if IP is valid to block
				valid, err := utils.IsValidIPToBlock(ip)
				if err != nil || !valid {
					continue
				}

				// Check if IP is whitelisted
				isIPWhitelisted, err := database.IsIPWhitelisted(ip)
				if err != nil || isIPWhitelisted {
					infoColor.Printf("IP %s is whitelisted, skipping\n", ip)
					continue
				}

				// Associate the IP with this domain in the database
				if err := database.AddIPWithRotation(domainID, ip, settings.MaxIPsPerDomain, 0); err != nil {
					errorColor.Printf("Failed to associate IP with domain: %v\n", err)
					continue
				}

				// Block IP - using the improved IPTables manager that leverages ipset
				if err := fwManager.BlockIP(ip, settings.BlockRuleType); err != nil {
					errorColor.Printf("Failed to block IP %s: %v\n", ip, err)
				} else {
					infoColor.Printf("Blocked IP %s for domain %s\n", ip, domain)
				}
			}
		}
	} else {
		infoColor.Printf("Domain %s is whitelisted, not applying block rules\n", domain)
	}

	successColor.Printf("Domain %s added to blocklist\n", domain)
}

// whitelistDomain whitelists a domain
func whitelistDomain(domain string) {
	// Check if domain is already in blocklist
	inBlocklist, err := database.IsDomainInBlocklist(domain)
	if err == nil && inBlocklist {
		warningColor.Printf("Warning: Domain %s is currently in the blocklist. Adding to whitelist will override the block.\n", domain)
	}

	_, err = database.SaveCustomDomain(domain, true)
	if err != nil {
		errorColor.Printf("Failed to whitelist domain: %v\n", err)
		return
	}

	// If domain was already in blocklist, unblock its IPs and add to whitelist
	if inBlocklist {
		ips, err := database.GetIPsForDomain(domain)
		if err == nil && len(ips) > 0 {
			fwManager, err := firewall.NewIPTablesManager()
			if err != nil {
				log.Warnf("Failed to initialize firewall: %v", err)
			} else {
				for _, ip := range ips {
					// First remove from blocklist
					if err := fwManager.UnblockIP(ip); err != nil {
						log.Warnf("Failed to unblock IP %s: %v", ip, err)
					}

					// Then add to whitelist
					if err := fwManager.WhitelistIP(ip); err != nil {
						log.Warnf("Failed to whitelist IP %s: %v", ip, err)
					} else {
						infoColor.Printf("Whitelisted IP %s because domain %s is now whitelisted\n", ip, domain)
					}
				}

				// Save changes to firewall
				if err := fwManager.SaveRulesToPersistentFiles(); err != nil {
					log.Warnf("Failed to save firewall rules: %v", err)
				}
			}
		}
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

	promptColor.Print("Enter IP address or IP range (CIDR notation, e.g. 192.168.1.0/24): ")
	ipInput, _ := reader.ReadString('\n')
	ipInput = strings.TrimSpace(ipInput)
	if ipInput == "" {
		errorColor.Println("Input cannot be empty.")
		time.Sleep(1 * time.Second)
		return
	}

	// Check if this is a CIDR range
	if strings.Contains(ipInput, "/") {
		// Validate CIDR format
		if !database.IsValidCIDR(ipInput) {
			errorColor.Printf("Invalid CIDR notation: %s\n", ipInput)
			time.Sleep(2 * time.Second)
			return
		}

		// Check if range exists in the opposite list
		if isWhitelist {
			inBlocklist, err := database.IsIPRangeInBlocklist(ipInput)
			if err == nil && inBlocklist {
				warningColor.Printf("Warning: IP range %s is currently in the blocklist. Adding to whitelist will override the block.\n", ipInput)
				promptColor.Print("Continue? (y/n): ")
				confirm, _ := reader.ReadString('\n')
				confirm = strings.TrimSpace(confirm)
				if strings.ToLower(confirm) != "y" {
					infoColor.Println("Operation cancelled.")
					time.Sleep(1 * time.Second)
					return
				}
			}
		} else {
			isRangeWhitelisted, err := database.IsIPRangeWhitelisted(ipInput)
			if err == nil && isRangeWhitelisted {
				warningColor.Printf("Warning: IP range %s is currently in the whitelist. Whitelist has priority over blocklist.\n", ipInput)
				promptColor.Print("Continue? (y/n): ")
				confirm, _ := reader.ReadString('\n')
				confirm = strings.TrimSpace(confirm)
				if strings.ToLower(confirm) != "y" {
					infoColor.Println("Operation cancelled.")
					time.Sleep(1 * time.Second)
					return
				}
			}
		}

		// Save IP range to database
		err := database.SaveCustomIPRange(ipInput, isWhitelist)
		if err != nil {
			errorColor.Printf("Failed to add IP range: %v\n", err)
			time.Sleep(2 * time.Second)
			return
		}

		// If it's a whitelist range, unblock it if it was previously blocked
		if isWhitelist {
			inBlocklist, err := database.IsIPRangeInBlocklist(ipInput)
			if err == nil && inBlocklist {
				fwManager, err := firewall.NewIPTablesManager()
				if err != nil {
					log.Warnf("Failed to initialize firewall: %v", err)
				} else {
					if err := fwManager.UnblockIPRange(ipInput); err != nil {
						log.Warnf("Failed to unblock IP range %s: %v", ipInput, err)
					} else {
						infoColor.Printf("Unblocked IP range %s because it's now whitelisted\n", ipInput)
					}
					// Save changes to firewall
					if err := fwManager.SaveRulesToPersistentFiles(); err != nil {
						log.Warnf("Failed to save firewall rules: %v", err)
					}
				}
			}
		} else {
			// If it's a blocklist range, apply firewall rule immediately IF not whitelisted
			isRangeWhitelisted, err := database.IsIPRangeWhitelisted(ipInput)
			if err != nil {
				log.Warnf("Failed to check if range %s is whitelisted: %v", ipInput, err)
			} else if isRangeWhitelisted {
				infoColor.Printf("IP range %s is whitelisted, not applying block rules\n", ipInput)
			} else {
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
				if err := fwManager.BlockIPRange(ipInput, settings.BlockRuleType); err != nil {
					errorColor.Printf("Failed to apply firewall rule: %v\n", err)
					time.Sleep(2 * time.Second)
					return
				}
			}
		}

		if isWhitelist {
			successColor.Printf("IP range %s added to whitelist\n", ipInput)
		} else {
			successColor.Printf("IP range %s added to blocklist\n", ipInput)
		}
	} else {
		// Regular IP address
		if !database.IsValidIP(ipInput) {
			errorColor.Printf("Invalid IP address format: %s\n", ipInput)
			time.Sleep(2 * time.Second)
			return
		}

		// Check if IP exists in the opposite list
		if isWhitelist {
			inBlocklist, err := database.IsIPInBlocklist(ipInput)
			if err == nil && inBlocklist {
				warningColor.Printf("Warning: IP %s is currently in the blocklist. Adding to whitelist will override the block.\n", ipInput)
				promptColor.Print("Continue? (y/n): ")
				confirm, _ := reader.ReadString('\n')
				confirm = strings.TrimSpace(confirm)
				if strings.ToLower(confirm) != "y" {
					infoColor.Println("Operation cancelled.")
					time.Sleep(1 * time.Second)
					return
				}
			}
		} else {
			isIPWhitelisted, err := database.IsIPWhitelisted(ipInput)
			if err == nil && isIPWhitelisted {
				warningColor.Printf("Warning: IP %s is currently in the whitelist. Whitelist has priority over blocklist.\n", ipInput)
				promptColor.Print("Continue? (y/n): ")
				confirm, _ := reader.ReadString('\n')
				confirm = strings.TrimSpace(confirm)
				if strings.ToLower(confirm) != "y" {
					infoColor.Println("Operation cancelled.")
					time.Sleep(1 * time.Second)
					return
				}
			}
		}

		// Save IP to database
		err := database.SaveCustomIP(ipInput, isWhitelist)
		if err != nil {
			errorColor.Printf("Failed to add IP: %v\n", err)
			time.Sleep(2 * time.Second)
			return
		}

		// If it's a whitelist IP, unblock it if it was previously blocked
		if isWhitelist {
			inBlocklist, err := database.IsIPInBlocklist(ipInput)
			if err == nil && inBlocklist {
				fwManager, err := firewall.NewIPTablesManager()
				if err != nil {
					log.Warnf("Failed to initialize firewall: %v", err)
				} else {
					if err := fwManager.UnblockIP(ipInput); err != nil {
						log.Warnf("Failed to unblock IP %s: %v", ipInput, err)
					} else {
						infoColor.Printf("Unblocked IP %s because it's now whitelisted\n", ipInput)
					}
					// Save changes to firewall
					if err := fwManager.SaveRulesToPersistentFiles(); err != nil {
						log.Warnf("Failed to save firewall rules: %v", err)
					}
				}
			}
		} else {
			// If it's a blocklist IP, apply firewall rule immediately IF not whitelisted
			isIPWhitelisted, err := database.IsIPWhitelisted(ipInput)
			if err != nil {
				log.Warnf("Failed to check if IP %s is whitelisted: %v", ipInput, err)
			} else if isIPWhitelisted {
				infoColor.Printf("IP %s is whitelisted, not applying block rules\n", ipInput)
			} else {
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
				if err := fwManager.BlockIP(ipInput, settings.BlockRuleType); err != nil {
					errorColor.Printf("Failed to apply firewall rule: %v\n", err)
					time.Sleep(2 * time.Second)
					return
				}
			}
		}

		if isWhitelist {
			successColor.Printf("IP %s added to whitelist\n", ipInput)
		} else {
			successColor.Printf("IP %s added to blocklist\n", ipInput)
		}
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

	promptColor.Print("Enter IP address or IP range (CIDR notation): ")
	ipInput, _ := reader.ReadString('\n')
	ipInput = strings.TrimSpace(ipInput)
	if ipInput == "" {
		errorColor.Println("Input cannot be empty.")
		time.Sleep(1 * time.Second)
		return
	}

	// Check if this is a CIDR range
	if strings.Contains(ipInput, "/") {
		// Validate CIDR format
		if !database.IsValidCIDR(ipInput) {
			errorColor.Printf("Invalid CIDR notation: %s\n", ipInput)
			time.Sleep(2 * time.Second)
			return
		}

		// If removing from whitelist, check if it's in blocklist first
		if isWhitelist {
			inBlocklist, err := database.IsIPRangeInBlocklist(ipInput)
			if err != nil {
				log.Warnf("Failed to check if range %s is in blocklist: %v", ipInput, err)
			} else if inBlocklist {
				// This range is in blocklist, we'll need to reapply block rules
				warningColor.Printf("Warning: IP range %s is also in the blocklist. Removing it from whitelist will cause it to be blocked.\n", ipInput)
				promptColor.Print("Continue? (y/n): ")
				confirm, _ := reader.ReadString('\n')
				confirm = strings.TrimSpace(confirm)
				if strings.ToLower(confirm) != "y" {
					infoColor.Println("Operation cancelled.")
					time.Sleep(1 * time.Second)
					return
				}

				settings, err := config.GetSettings()
				if err != nil {
					log.Warnf("Failed to get settings: %v", err)
				} else {
					fwManager, err := firewall.NewIPTablesManager()
					if err != nil {
						log.Warnf("Failed to initialize firewall: %v", err)
					} else {
						if err := fwManager.BlockIPRange(ipInput, settings.BlockRuleType); err != nil {
							log.Warnf("Failed to reblock IP range %s: %v", ipInput, err)
						} else {
							infoColor.Printf("Reblocked IP range %s because it was removed from whitelist\n", ipInput)
						}

						// Save changes to firewall
						if err := fwManager.SaveRulesToPersistentFiles(); err != nil {
							log.Warnf("Failed to save firewall rules: %v", err)
						}
					}
				}
			}
		}

		// Remove IP range from database
		err := database.RemoveIPRange(ipInput, isWhitelist)
		if err != nil {
			errorColor.Printf("Failed to remove IP range: %v\n", err)
			time.Sleep(2 * time.Second)
			return
		}

		if isWhitelist {
			successColor.Printf("IP range %s removed from whitelist\n", ipInput)
		} else {
			successColor.Printf("IP range %s removed from blocklist\n", ipInput)
		}
	} else {
		// Regular IP address
		if !database.IsValidIP(ipInput) {
			errorColor.Printf("Invalid IP address format: %s\n", ipInput)
			time.Sleep(2 * time.Second)
			return
		}

		// If removing from whitelist, check if it's in blocklist first
		if isWhitelist {
			inBlocklist, err := database.IsIPInBlocklist(ipInput)
			if err != nil {
				log.Warnf("Failed to check if IP %s is in blocklist: %v", ipInput, err)
			} else if inBlocklist {
				// This IP is in blocklist, we'll need to reapply block rules
				warningColor.Printf("Warning: IP %s is also in the blocklist. Removing it from whitelist will cause it to be blocked.\n", ipInput)
				promptColor.Print("Continue? (y/n): ")
				confirm, _ := reader.ReadString('\n')
				confirm = strings.TrimSpace(confirm)
				if strings.ToLower(confirm) != "y" {
					infoColor.Println("Operation cancelled.")
					time.Sleep(1 * time.Second)
					return
				}

				settings, err := config.GetSettings()
				if err != nil {
					log.Warnf("Failed to get settings: %v", err)
				} else {
					fwManager, err := firewall.NewIPTablesManager()
					if err != nil {
						log.Warnf("Failed to initialize firewall: %v", err)
					} else {
						if err := fwManager.BlockIP(ipInput, settings.BlockRuleType); err != nil {
							log.Warnf("Failed to reblock IP %s: %v", ipInput, err)
						} else {
							infoColor.Printf("Reblocked IP %s because it was removed from whitelist\n", ipInput)
						}

						// Save changes to firewall
						if err := fwManager.SaveRulesToPersistentFiles(); err != nil {
							log.Warnf("Failed to save firewall rules: %v", err)
						}
					}
				}
			}
		}

		// Remove IP from database
		err := database.RemoveIP(ipInput, isWhitelist)
		if err != nil {
			errorColor.Printf("Failed to remove IP: %v\n", err)
			time.Sleep(2 * time.Second)
			return
		}

		if isWhitelist {
			successColor.Printf("IP %s removed from whitelist\n", ipInput)
		} else {
			successColor.Printf("IP %s removed from blocklist\n", ipInput)
		}
	}
	time.Sleep(1 * time.Second)
}

// blockIP blocks an IP
func blockIP(ip string) {
	// Check if this is a CIDR range
	if strings.Contains(ip, "/") {
		if !database.IsValidCIDR(ip) {
			errorColor.Printf("Invalid CIDR notation: %s\n", ip)
			return
		}

		// Check if range is already whitelisted
		isWhitelisted, err := database.IsIPRangeWhitelisted(ip)
		if err == nil && isWhitelisted {
			warningColor.Printf("Warning: IP range %s is already in the whitelist. Whitelist has priority over blocklist.\n", ip)
			return
		}

		err = database.SaveCustomIPRange(ip, false)
		if err != nil {
			errorColor.Printf("Failed to add IP range to database: %v\n", err)
			return
		}

		// Only apply the rule if not whitelisted
		if !isWhitelisted {
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

			if err := fwManager.BlockIPRange(ip, settings.BlockRuleType); err != nil {
				errorColor.Printf("Failed to block IP range: %v\n", err)
				return
			}

			successColor.Printf("IP range %s blocked\n", ip)
		} else {
			infoColor.Printf("IP range %s is whitelisted, not applying block rules\n", ip)
			successColor.Printf("IP range %s added to blocklist\n", ip)
		}
	} else {
		if !database.IsValidIP(ip) {
			errorColor.Printf("Invalid IP address: %s\n", ip)
			return
		}

		// Check if IP is already whitelisted
		isWhitelisted, err := database.IsIPWhitelisted(ip)
		if err == nil && isWhitelisted {
			warningColor.Printf("Warning: IP %s is already in the whitelist. Whitelist has priority over blocklist.\n", ip)
			return
		}

		if err := database.SaveCustomIP(ip, false); err != nil {
			errorColor.Printf("Failed to add IP to database: %v\n", err)
			return
		}

		// Only apply the rule if not whitelisted
		if !isWhitelisted {
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
		} else {
			infoColor.Printf("IP %s is whitelisted, not applying block rules\n", ip)
			successColor.Printf("IP %s added to blocklist\n", ip)
		}
	}
}

// whitelistIP whitelists an IP
func whitelistIP(ip string) {
	// Check if this is a CIDR range
	if strings.Contains(ip, "/") {
		if !database.IsValidCIDR(ip) {
			errorColor.Printf("Invalid CIDR notation: %s\n", ip)
			return
		}

		// Check if range is already in blocklist
		inBlocklist, err := database.IsIPRangeInBlocklist(ip)
		if err == nil && inBlocklist {
			warningColor.Printf("Warning: IP range %s is currently in the blocklist. Adding to whitelist will override the block.\n", ip)
		}

		err = database.SaveCustomIPRange(ip, true)
		if err != nil {
			errorColor.Printf("Failed to whitelist IP range: %v\n", err)
			return
		}

		fwManager, err := firewall.NewIPTablesManager()
		if err != nil {
			errorColor.Printf("Failed to initialize firewall: %v\n", err)
			return
		}

		// If range was previously blocked, unblock it
		if inBlocklist {
			if err := fwManager.UnblockIPRange(ip); err != nil {
				log.Warnf("Failed to unblock IP range %s: %v", ip, err)
			}
		}

		// Add to whitelist
		if err := fwManager.WhitelistIPRange(ip); err != nil {
			errorColor.Printf("Failed to add IP range to whitelist: %v\n", err)
			return
		}

		// Save changes
		if err := fwManager.SaveRulesToPersistentFiles(); err != nil {
			log.Warnf("Failed to save firewall rules: %v", err)
		}

		successColor.Printf("IP range %s whitelisted\n", ip)
	} else {
		if !database.IsValidIP(ip) {
			errorColor.Printf("Invalid IP address: %s\n", ip)
			return
		}

		// Check if IP is already in blocklist
		inBlocklist, err := database.IsIPInBlocklist(ip)
		if err == nil && inBlocklist {
			warningColor.Printf("Warning: IP %s is currently in the blocklist. Adding to whitelist will override the block.\n", ip)
		}

		if err := database.SaveCustomIP(ip, true); err != nil {
			errorColor.Printf("Failed to whitelist IP: %v\n", err)
			return
		}

		fwManager, err := firewall.NewIPTablesManager()
		if err != nil {
			errorColor.Printf("Failed to initialize firewall: %v\n", err)
			return
		}

		// If IP was previously blocked, unblock it
		if inBlocklist {
			if err := fwManager.UnblockIP(ip); err != nil {
				log.Warnf("Failed to unblock IP %s: %v", ip, err)
			}
		}

		// Add to whitelist
		if err := fwManager.WhitelistIP(ip); err != nil {
			errorColor.Printf("Failed to add IP to whitelist: %v\n", err)
			return
		}

		// Save changes
		if err := fwManager.SaveRulesToPersistentFiles(); err != nil {
			log.Warnf("Failed to save firewall rules: %v", err)
		}

		successColor.Printf("IP %s whitelisted\n", ip)
	}
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

	// Display timer interval
	interval, err := service.GetAgentTimerInterval()
	if err != nil {
		// Just log the error but continue
		fmt.Println("Agent Timer Interval: Unknown (error reading timer file)")
	} else {
		fmt.Printf("Agent Timer Interval: %s\n", interval)
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
	settings, err := config.GetSettings()
	if err != nil {
		errorColor.Printf("Failed to get current settings: %v\n", err)
		return
	}

	fmt.Printf("Current block rule type: %s\n\n", settings.BlockRuleType)
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

	// If the rule type hasn't changed, no need to update
	if ruleType == settings.BlockRuleType {
		infoColor.Println("Block rule type unchanged.")
		return
	}

	// Save to database first
	err = config.SaveSetting("block_rule_type", ruleType)
	if err != nil {
		errorColor.Printf("Failed to save block rule type: %v\n", err)
		return
	}

	// Apply the changes immediately
	infoColor.Println("Applying changes to firewall rules...")
	fwManager, err := firewall.NewIPTablesManager()
	if err != nil {
		errorColor.Printf("Failed to initialize firewall manager: %v\n", err)
		return
	}

	// Completely refresh all ipset rules with the new block rule type
	// This will:
	// 1. Remove all existing ipset rules from iptables
	// 2. Add back all rules in the correct order based on the new rule type
	// 3. Save the changes to persistent files
	infoColor.Printf("Refreshing firewall rules with block type: %s\n", ruleType)
	if err := fwManager.RefreshIPSetRules(); err != nil {
		errorColor.Printf("Failed to refresh firewall rules: %v\n", err)
		warningColor.Println("Block rule type was saved to database but rules may not be applied correctly.")
		warningColor.Println("You may need to restart your system or run the rebuild firewall rules option.")
		pressEnterToContinue(reader)
		return
	}

	successColor.Printf("Block rule type changed to: %s\n", ruleType)
	successColor.Println("Firewall rules updated and saved successfully.")
}

// verifyRuleType checks if the applied rules match the expected block rule type
func verifyRuleType(ruleType string, fwManager *firewall.IPTablesManager) {
	// This is a simple verification by checking if specific rules exist
	// For a more thorough verification, we would need to add more checks

	// Check for source rules
	sourceRuleExists, err := fwManager.HasRule("INPUT", "dnsniper-blocklist", "src")
	if err != nil {
		warningColor.Printf("Could not verify source rule: %v\n", err)
		return
	}

	// Check for destination rules
	destRuleExists, err := fwManager.HasRule("OUTPUT", "dnsniper-blocklist", "dst")
	if err != nil {
		warningColor.Printf("Could not verify destination rule: %v\n", err)
		return
	}

	switch ruleType {
	case "source":
		if !sourceRuleExists || destRuleExists {
			warningColor.Println("Warning: Applied rules may not match 'source' rule type. Manual verification recommended.")
		}
	case "destination":
		if sourceRuleExists || !destRuleExists {
			warningColor.Println("Warning: Applied rules may not match 'destination' rule type. Manual verification recommended.")
		}
	case "both":
		if !sourceRuleExists || !destRuleExists {
			warningColor.Println("Warning: Applied rules may not match 'both' rule type. Manual verification recommended.")
		}
	}
}

func toggleLogging(reader *bufio.Reader) {
	subtitleColor.Println("Toggle Logging")
	// Get current logging state
	settings, err := config.GetSettings()
	if err != nil {
		errorColor.Printf("Failed to get settings: %v\n", err)
		return
	}

	// Show current status and ask for confirmation
	if settings.LoggingEnabled {
		fmt.Println("Logging is currently ENABLED")
		promptColor.Print("Do you want to disable logging? (yes/no): ")
	} else {
		fmt.Println("Logging is currently DISABLED")
		promptColor.Print("Do you want to enable logging? (yes/no): ")
	}

	confirm, _ := reader.ReadString('\n')
	confirm = strings.TrimSpace(confirm)
	if strings.ToLower(confirm) != "yes" {
		infoColor.Println("Logging settings unchanged.")
		return
	}

	// Toggle logging
	newState := !settings.LoggingEnabled
	// Save to database - this should be done first
	err = config.SaveSetting("logging_enabled", strconv.FormatBool(newState))
	if err != nil {
		errorColor.Printf("Failed to update logging setting in database: %v\n", err)
		return
	}

	// Direct file manipulation instead of using systemctl which might require sudo
	err = service.DirectlyUpdateServiceLogging(newState)
	if err != nil {
		errorColor.Printf("Failed to update service file: %v\n", err)
		errorColor.Println("Logging state was changed in database but not in service file.")
		errorColor.Println("You may need to manually edit /etc/systemd/system/dnsniper-agent.service and reload systemd.")
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

	fmt.Printf("Current rule expiration: %s\n\n", settings.RuleExpiration.String())
	fmt.Println("Select time unit:")
	fmt.Println("1. Minutes")
	fmt.Println("2. Hours (default: 24 hours)")
	fmt.Println("3. Days")

	promptColor.Print("\nEnter choice [1-3]: ")
	unitChoice, _ := reader.ReadString('\n')
	unitChoice = strings.TrimSpace(unitChoice)

	var unit string
	var defaultValue int
	var unitText string
	switch unitChoice {
	case "1":
		unit = "m"
		defaultValue = 1440 // 24 hours in minutes
		unitText = "minutes"
	case "3":
		unit = "d"
		defaultValue = 1 // 1 day
		unitText = "days"
	default:
		unit = "h"
		defaultValue = 24 // 24 hours
		unitText = "hours"
	}

	promptColor.Printf("Enter expiration time in %s (default: %d): ", unitText, defaultValue)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	value := defaultValue
	if input != "" {
		var err error
		value, err = strconv.Atoi(input)
		if err != nil || value <= 0 {
			errorColor.Printf("Invalid input. Using default (%d %s).\n", defaultValue, unitText)
			value = defaultValue
		}
	}

	// Save to database with appropriate unit
	expStr := fmt.Sprintf("%d%s", value, unit)
	err = config.SaveSetting("rule_expiration", expStr)
	if err != nil {
		errorColor.Printf("Failed to save rule expiration: %v\n", err)
		return
	}

	// Parse the setting to get the duration for display
	newSettings, err := config.GetSettings()
	if err != nil {
		successColor.Printf("Rules expiration set to: %s\n", expStr)
	} else {
		successColor.Printf("Rules expiration set to: %s\n", newSettings.RuleExpiration.String())
	}
}

func changeAgentTimer(reader *bufio.Reader) {
	subtitleColor.Println("Change Agent Timer Interval")
	// Get current interval
	currentInterval, err := service.GetAgentTimerInterval()
	if err != nil {
		// This is not a critical error, just display a message
		fmt.Println("Could not determine current timer interval.")
		currentInterval = "unknown"
	} else {
		fmt.Printf("Current timer interval: %s\n", currentInterval)
	}

	fmt.Println("\nSelect predefined interval or enter custom:")
	fmt.Println("1. Hourly")
	fmt.Println("2. Every 3 hours")
	fmt.Println("3. Every 6 hours")
	fmt.Println("4. Daily")
	fmt.Println("5. Custom interval")

	promptColor.Print("\nEnter choice [1-5]: ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	var newInterval string
	var friendlyText string
	switch input {
	case "1":
		newInterval = "1h"
		friendlyText = "1 hour"
	case "2":
		newInterval = "3h"
		friendlyText = "3 hours"
	case "3":
		newInterval = "6h"
		friendlyText = "6 hours"
	case "4":
		newInterval = "1d"
		friendlyText = "1 day"
	case "5":
		promptColor.Print("Enter custom interval (format: 30m, 1h, 2h30m, 1d, etc): ")
		newInterval, _ = reader.ReadString('\n')
		newInterval = strings.TrimSpace(newInterval)
		friendlyText = newInterval
	default:
		errorColor.Println("Invalid choice. Using default (3h).")
		newInterval = "3h"
		friendlyText = "3 hours"
	}

	// Update timer using direct file manipulation
	err = service.DirectlyUpdateAgentTimerInterval(newInterval)
	if err != nil {
		errorColor.Printf("Failed to update agent timer interval: %v\n", err)
		return
	}

	successColor.Printf("Agent timer interval set to: %s\n", friendlyText)
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
			if ip.IsRange {
				fmt.Printf("%s [RANGE]\n", ip.IPAddress)
			} else {
				fmt.Println(ip.IPAddress)
			}
		}
	}

	fmt.Println("\nWhitelisted IPs:")
	if len(whitelistedIPs) == 0 {
		fmt.Println("No whitelisted IPs")
	} else {
		for _, ip := range whitelistedIPs {
			if ip.IsRange {
				fmt.Printf("%s [RANGE]\n", ip.IPAddress)
			} else {
				fmt.Println(ip.IPAddress)
			}
		}
	}
}
