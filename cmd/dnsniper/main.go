package main

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/MahdiGraph/DNSniper/internal/config"
	"github.com/MahdiGraph/DNSniper/internal/database"
	"github.com/MahdiGraph/DNSniper/internal/dns"
	"github.com/MahdiGraph/DNSniper/internal/firewall"
	"github.com/MahdiGraph/DNSniper/internal/models"
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
		titleColor.Println("Add Domain to Whitelist")
		titleColor.Println(strings.Repeat("=", 40))
	} else {
		titleColor.Println("Add Domain to Blocklist")
		titleColor.Println(strings.Repeat("=", 40))
	}

	// Show input format help
	infoColor.Println("\nDomain format examples:")
	fmt.Println("  • example.com")
	fmt.Println("  • subdomain.example.com")
	fmt.Println("  • *.example.com (wildcard)")

	promptColor.Print("\nEnter domain: ")
	domain, _ := reader.ReadString('\n')
	domain = strings.TrimSpace(domain)
	domain = strings.ToLower(domain) // Normalize to lowercase

	if domain == "" {
		errorColor.Println("Domain cannot be empty.")
		time.Sleep(1 * time.Second)
		return
	}

	// Handle wildcard domains
	isWildcard := false
	if strings.HasPrefix(domain, "*.") {
		isWildcard = true
		// For validation, check the base domain
		baseDomain := strings.TrimPrefix(domain, "*.")
		if !isValidDomain(baseDomain) {
			errorColor.Printf("Invalid domain format: %s\n", domain)
			errorColor.Println("Wildcard domains should be in format: *.example.com")
			time.Sleep(2 * time.Second)
			return
		}
	} else {
		// Validate regular domain
		if !isValidDomain(domain) {
			errorColor.Printf("Invalid domain format: %s\n", domain)
			errorColor.Println("Please enter a valid domain name.")
			time.Sleep(2 * time.Second)
			return
		}
	}

	// Check if domain exists in the opposite list
	if isWhitelist {
		inBlocklist, err := database.IsDomainInBlocklist(domain)
		if err == nil && inBlocklist {
			warningColor.Printf("\n⚠️  Warning: Domain %s is currently in the blocklist.\n", domain)
			warningColor.Println("Adding to whitelist will override the block.")

			// Show IPs that will be affected
			ips, err := database.GetIPsForDomain(domain)
			if err == nil && len(ips) > 0 {
				infoColor.Printf("\nAffected IPs (%d):\n", len(ips))
				for i, ip := range ips {
					if i < 5 {
						fmt.Printf("  • %s\n", ip)
					}
				}
				if len(ips) > 5 {
					fmt.Printf("  ... and %d more\n", len(ips)-5)
				}
			}

			promptColor.Print("\nContinue? (y/n): ")
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
			warningColor.Printf("\n⚠️  Warning: Domain %s is currently in the whitelist.\n", domain)
			warningColor.Println("Whitelist has priority over blocklist.")
			warningColor.Println("The domain will be added to blocklist but won't take effect until removed from whitelist.")

			promptColor.Print("\nContinue? (y/n): ")
			confirm, _ := reader.ReadString('\n')
			confirm = strings.TrimSpace(confirm)
			if strings.ToLower(confirm) != "y" {
				infoColor.Println("Operation cancelled.")
				time.Sleep(1 * time.Second)
				return
			}
		}
	}

	// Check if domain already exists in the same list
	var existingID int64
	err := database.GetDomainID(domain, &existingID)
	if err == nil {
		// Domain already exists, check if it's in the same list
		existingWhitelisted, err := database.IsDomainWhitelisted(domain)
		if err == nil && existingWhitelisted == isWhitelist {
			warningColor.Printf("Domain %s already exists in this list.\n", domain)
			time.Sleep(1 * time.Second)
			return
		}
	}

	// Save domain to database
	domainID, err := database.SaveCustomDomain(domain, isWhitelist)
	if err != nil {
		errorColor.Printf("Failed to add domain: %v\n", err)
		time.Sleep(2 * time.Second)
		return
	}

	infoColor.Printf("\n🔍 Resolving domain %s...\n", domain)

	// Get DNS resolver from settings
	settings, err := config.GetSettings()
	if err != nil {
		errorColor.Printf("Failed to get settings: %v\n", err)
		settings.DNSResolver = "8.8.8.8" // fallback
	}

	// For whitelisted domains, handle existing blocked IPs
	if isWhitelist {
		// Get all IPs associated with this domain
		ips, err := database.GetIPsForDomain(domain)
		if err == nil && len(ips) > 0 {
			fwManager, err := firewall.NewIPTablesManager()
			if err != nil {
				errorColor.Printf("Failed to initialize firewall: %v\n", err)
			} else {
				unblocked := 0
				whitelisted := 0

				for _, ip := range ips {
					// First remove from blocklist
					if err := fwManager.UnblockIP(ip); err != nil {
						log.Warnf("Failed to unblock IP %s: %v", ip, err)
					} else {
						unblocked++
					}

					// Then add to whitelist
					if err := fwManager.WhitelistIP(ip); err != nil {
						log.Warnf("Failed to whitelist IP %s: %v", ip, err)
					} else {
						whitelisted++
						infoColor.Printf("  ✅ Whitelisted IP %s\n", ip)
					}
				}

				// Save changes to firewall
				if err := fwManager.SaveRulesToPersistentFiles(); err != nil {
					log.Warnf("Failed to save firewall rules: %v", err)
				}

				if whitelisted > 0 {
					successColor.Printf("\nWhitelisted %d existing IPs for domain %s\n", whitelisted, domain)
				}
			}
		}

		// Try to resolve and whitelist new IPs
		resolver := dns.NewStandardResolver()
		newIPs, err := resolver.ResolveDomain(domain, settings.DNSResolver)
		if err != nil {
			warningColor.Printf("Could not resolve domain (will be whitelisted when IPs are discovered): %v\n", err)
		} else if len(newIPs) > 0 {
			infoColor.Printf("Found %d IP(s) for domain\n", len(newIPs))

			fwManager, err := firewall.NewIPTablesManager()
			if err != nil {
				errorColor.Printf("Failed to initialize firewall: %v\n", err)
			} else {
				added := 0
				for _, ip := range newIPs {
					// Add IP to whitelist
					if err := database.SaveCustomIP(ip, true); err != nil {
						log.Warnf("Failed to save IP %s: %v", ip, err)
						continue
					}

					if err := fwManager.WhitelistIP(ip); err != nil {
						log.Warnf("Failed to whitelist IP %s: %v", ip, err)
					} else {
						added++
						infoColor.Printf("  ✅ Whitelisted IP %s\n", ip)
					}

					// Associate with domain
					database.AssociateIPWithDomain(domainID, ip, true)
				}

				if added > 0 {
					// Save changes
					if err := fwManager.SaveRulesToPersistentFiles(); err != nil {
						log.Warnf("Failed to save firewall rules: %v", err)
					}
				}
			}
		}

	} else {
		// For blocked domains, we need to handle whitelisted IPs carefully
		// Resolve the domain and add IPs to blocklist
		resolver := dns.NewStandardResolver()
		ips, err := resolver.ResolveDomain(domain, settings.DNSResolver)
		if err != nil {
			warningColor.Printf("Failed to resolve domain: %v\n", err)
			warningColor.Println("Domain added to blocklist, but no IPs were blocked.")
			warningColor.Println("IPs will be blocked when the domain is resolved successfully.")
		} else if len(ips) == 0 {
			warningColor.Println("No IPs found for this domain.")
		} else {
			infoColor.Printf("Found %d IP(s) for domain\n", len(ips))

			fwManager, err := firewall.NewIPTablesManager()
			if err != nil {
				errorColor.Printf("Failed to initialize firewall: %v\n", err)
			} else {
				blocked := 0
				skipped := 0

				for _, ip := range ips {
					// Skip invalid IPs
					valid, _ := utils.IsValidIPToBlock(ip)
					if !valid {
						log.Debugf("Skipping invalid IP %s", ip)
						continue
					}

					// Critical check: Skip whitelisted IPs
					isWhitelisted, _ := database.IsIPWhitelisted(ip)
					if isWhitelisted {
						infoColor.Printf("  ⚠️  IP %s is whitelisted, not blocking\n", ip)
						skipped++
						continue
					}

					// Associate IP with domain
					if err := database.AssociateIPWithDomain(domainID, ip, false); err != nil {
						errorColor.Printf("Failed to associate IP with domain: %v\n", err)
						continue
					}

					// Finally block the IP
					if err := fwManager.BlockIP(ip, settings.BlockDirection); err != nil {
						errorColor.Printf("Failed to block IP %s: %v\n", ip, err)
					} else {
						blocked++
						successColor.Printf("  ✅ Blocked IP %s\n", ip)
					}
				}

				// Save changes
				if blocked > 0 {
					if err := fwManager.SaveRulesToPersistentFiles(); err != nil {
						log.Warnf("Failed to save firewall rules: %v", err)
					}
				}

				// Summary
				if blocked > 0 || skipped > 0 {
					fmt.Println(strings.Repeat("-", 40))
					if blocked > 0 {
						successColor.Printf("Blocked %d IP(s)\n", blocked)
					}
					if skipped > 0 {
						warningColor.Printf("Skipped %d whitelisted IP(s)\n", skipped)
					}
				}
			}
		}
	}

	// Final success message
	fmt.Println(strings.Repeat("-", 40))
	if isWhitelist {
		successColor.Printf("✅ Domain %s added to whitelist\n", domain)
		if isWildcard {
			infoColor.Println("Note: Wildcard domains will whitelist all subdomains")
		}
	} else {
		successColor.Printf("✅ Domain %s added to blocklist\n", domain)
		if isWildcard {
			infoColor.Println("Note: Wildcard domains will block all subdomains when resolved")
		}
	}

	time.Sleep(2 * time.Second)
}

// Import domain list from file
func importDomainList(isWhitelist bool, reader *bufio.Reader) {
	clearScreen()
	if isWhitelist {
		titleColor.Println("Import Domain Whitelist")
	} else {
		titleColor.Println("Import Domain Blocklist")
	}

	infoColor.Println("\nFile format: One domain per line")
	infoColor.Println("Lines starting with # are treated as comments")

	promptColor.Print("\nEnter file path: ")
	filePath, _ := reader.ReadString('\n')
	filePath = strings.TrimSpace(filePath)

	if filePath == "" {
		errorColor.Println("File path cannot be empty.")
		pressEnterToContinue(reader)
		return
	}

	// Open file
	file, err := os.Open(filePath)
	if err != nil {
		errorColor.Printf("Failed to open file: %v\n", err)
		pressEnterToContinue(reader)
		return
	}
	defer file.Close()

	// Process domains
	scanner := bufio.NewScanner(file)
	imported := 0
	failed := 0
	duplicates := 0

	infoColor.Println("\nImporting domains...")

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Clean domain
		domain := strings.ToLower(line)

		// Validate domain format
		if !isValidDomain(domain) {
			log.Warnf("Invalid domain format: %s", domain)
			failed++
			continue
		}

		// Save to database
		_, err := database.SaveCustomDomain(domain, isWhitelist)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE constraint") {
				duplicates++
			} else {
				log.Warnf("Failed to import domain %s: %v", domain, err)
				failed++
			}
			continue
		}

		imported++

		// Show progress every 100 domains
		if imported%100 == 0 {
			fmt.Printf("\rImported: %d domains...", imported)
		}
	}

	if err := scanner.Err(); err != nil {
		errorColor.Printf("\nError reading file: %v\n", err)
	}

	// Summary
	fmt.Println()
	successColor.Printf("\nImport complete!\n")
	fmt.Printf("✅ Imported: %d domains\n", imported)
	if duplicates > 0 {
		warningColor.Printf("⚠️  Duplicates skipped: %d\n", duplicates)
	}
	if failed > 0 {
		errorColor.Printf("❌ Failed: %d\n", failed)
	}

	pressEnterToContinue(reader)
}

// Export domain list to file
func exportDomainList(isWhitelist bool, domains []models.Domain, reader *bufio.Reader) {
	clearScreen()
	if isWhitelist {
		titleColor.Println("Export Domain Whitelist")
	} else {
		titleColor.Println("Export Domain Blocklist")
	}

	// Get all domains if not provided
	if len(domains) == 0 {
		allDomains, _, err := database.GetDomainsList(isWhitelist, 1, 10000)
		if err != nil {
			errorColor.Printf("Failed to get domains: %v\n", err)
			pressEnterToContinue(reader)
			return
		}
		domains = allDomains
	}

	infoColor.Printf("\nTotal domains to export: %d\n", len(domains))

	promptColor.Print("\nEnter output file path: ")
	filePath, _ := reader.ReadString('\n')
	filePath = strings.TrimSpace(filePath)

	if filePath == "" {
		// Default filename
		timestamp := time.Now().Format("20060102_150405")
		if isWhitelist {
			filePath = fmt.Sprintf("dnsniper_whitelist_%s.txt", timestamp)
		} else {
			filePath = fmt.Sprintf("dnsniper_blocklist_%s.txt", timestamp)
		}
		infoColor.Printf("Using default filename: %s\n", filePath)
	}

	// Create file
	file, err := os.Create(filePath)
	if err != nil {
		errorColor.Printf("Failed to create file: %v\n", err)
		pressEnterToContinue(reader)
		return
	}
	defer file.Close()

	// Write header
	writer := bufio.NewWriter(file)
	fmt.Fprintf(writer, "# DNSniper Domain %s Export\n", strings.Title(strings.ToLower(fmt.Sprintf("%v", isWhitelist))))
	fmt.Fprintf(writer, "# Exported on: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(writer, "# Total domains: %d\n\n", len(domains))

	// Write domains
	customCount := 0
	autoCount := 0

	// Write custom domains first
	fmt.Fprintf(writer, "# Custom domains\n")
	for _, domain := range domains {
		if domain.IsCustom {
			fmt.Fprintf(writer, "%s\n", domain.Domain)
			customCount++
		}
	}

	// Write auto domains
	if autoCount > 0 {
		fmt.Fprintf(writer, "\n# Auto-managed domains\n")
		for _, domain := range domains {
			if !domain.IsCustom {
				comment := ""
				if domain.ExpiresAt.Valid {
					comment = fmt.Sprintf(" # expires: %s", domain.ExpiresAt.Time.Format("2006-01-02"))
				}
				fmt.Fprintf(writer, "%s%s\n", domain.Domain, comment)
				autoCount++
			}
		}
	}

	// Flush writer
	if err := writer.Flush(); err != nil {
		errorColor.Printf("Failed to write file: %v\n", err)
		pressEnterToContinue(reader)
		return
	}

	successColor.Printf("\n✅ Export completed successfully!\n")
	fmt.Printf("File: %s\n", filePath)
	fmt.Printf("Custom domains: %d\n", customCount)
	fmt.Printf("Auto domains: %d\n", autoCount)

	pressEnterToContinue(reader)
}

// در addIPToList function
func addIPRangeWithValidation(cidr string, isWhitelist bool, reader *bufio.Reader) error {
	// Parse the CIDR
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR notation: %w", err)
	}

	if isWhitelist {
		// Check for conflicts with existing blocklist ranges
		blockRanges, err := database.GetAllBlockedIPRanges()
		if err == nil {
			conflictingRanges := []string{}
			for _, blockRange := range blockRanges {
				_, blockNet, err := net.ParseCIDR(blockRange)
				if err != nil {
					continue
				}

				// Check if ranges overlap
				if rangesOverlap(ipNet, blockNet) {
					conflictingRanges = append(conflictingRanges, blockRange)
				}
			}

			if len(conflictingRanges) > 0 {
				warningColor.Printf("\n⚠️  This whitelist range overlaps with blocklist ranges:\n")
				for _, r := range conflictingRanges {
					fmt.Printf("   - %s\n", r)
				}
				infoColor.Println("\nWhitelist rules have priority and will override blocklist rules.")
				promptColor.Print("Continue? (y/n): ")
				confirm, _ := reader.ReadString('\n')
				if strings.ToLower(strings.TrimSpace(confirm)) != "y" {
					return fmt.Errorf("operation cancelled")
				}
			}
		}
	}

	// Save to database
	err = database.SaveCustomIPRange(cidr, isWhitelist)
	if err != nil {
		return err
	}

	// Apply to firewall
	fwManager, err := firewall.NewIPTablesManager()
	if err != nil {
		return fmt.Errorf("failed to initialize firewall: %w", err)
	}

	if isWhitelist {
		err = fwManager.WhitelistIPRange(cidr)
	} else {
		err = fwManager.BlockIPRange(cidr, "")
	}

	if err != nil {
		return fmt.Errorf("failed to apply firewall rule: %w", err)
	}

	// Force refresh of ipset rules to ensure proper ordering
	if err := fwManager.RefreshIPSetRules(); err != nil {
		log.Warnf("Failed to refresh ipset rules: %v", err)
	}

	return nil
}

// Helper function to check if two IP ranges overlap
func rangesOverlap(net1, net2 *net.IPNet) bool {
	// Check if net1 contains net2's base IP or vice versa
	return net1.Contains(net2.IP) || net2.Contains(net1.IP)
}

// Verify IP ranges for conflicts and issues
func verifyIPRanges(isWhitelist bool, reader *bufio.Reader) {
	clearScreen()
	if isWhitelist {
		titleColor.Println("Verify Whitelist IP Ranges")
	} else {
		titleColor.Println("Verify Blocklist IP Ranges")
	}

	infoColor.Println("\nAnalyzing IP ranges for conflicts and overlaps...")

	// Get all IP ranges
	ranges, err := database.GetAllIPRanges(isWhitelist)
	if err != nil {
		errorColor.Printf("Failed to get IP ranges: %v\n", err)
		pressEnterToContinue(reader)
		return
	}

	if len(ranges) == 0 {
		infoColor.Println("\nNo IP ranges found.")
		pressEnterToContinue(reader)
		return
	}

	fmt.Printf("\nTotal ranges: %d\n", len(ranges))

	// Parse all ranges
	type rangeInfo struct {
		cidr     string
		ipNet    *net.IPNet
		isCustom bool
	}

	parsedRanges := make([]rangeInfo, 0)
	for _, r := range ranges {
		_, ipNet, err := net.ParseCIDR(r.CIDR)
		if err != nil {
			errorColor.Printf("❌ Invalid CIDR: %s - %v\n", r.CIDR, err)
			continue
		}
		parsedRanges = append(parsedRanges, rangeInfo{
			cidr:     r.CIDR,
			ipNet:    ipNet,
			isCustom: r.IsCustom,
		})
	}

	// Check for overlaps
	overlaps := 0
	fmt.Println("\nChecking for overlapping ranges...")

	for i := 0; i < len(parsedRanges); i++ {
		for j := i + 1; j < len(parsedRanges); j++ {
			r1 := parsedRanges[i]
			r2 := parsedRanges[j]

			// Check if ranges overlap
			if rangesOverlap(r1.ipNet, r2.ipNet) {
				overlaps++
				warningColor.Printf("\n⚠️  Overlap detected:\n")
				fmt.Printf("   Range 1: %s", r1.cidr)
				if r1.isCustom {
					fmt.Print(" [CUSTOM]")
				}
				fmt.Println()
				fmt.Printf("   Range 2: %s", r2.cidr)
				if r2.isCustom {
					fmt.Print(" [CUSTOM]")
				}
				fmt.Println()

				// Determine which range is larger
				size1 := getRangeSize(r1.ipNet)
				size2 := getRangeSize(r2.ipNet)
				if size1 > size2 {
					infoColor.Printf("   → %s contains %s\n", r1.cidr, r2.cidr)
				} else if size2 > size1 {
					infoColor.Printf("   → %s contains %s\n", r2.cidr, r1.cidr)
				} else {
					infoColor.Println("   → Ranges are identical")
				}
			}
		}
	}

	// Check for conflicts with opposite list
	if isWhitelist {
		fmt.Println("\nChecking for conflicts with blocklist...")
		blockRanges, err := database.GetAllIPRanges(false)
		if err == nil {
			conflicts := 0
			for _, whiteRange := range parsedRanges {
				for _, blockRange := range blockRanges {
					_, blockNet, err := net.ParseCIDR(blockRange.CIDR)
					if err != nil {
						continue
					}

					if rangesOverlap(whiteRange.ipNet, blockNet) {
						conflicts++
						warningColor.Printf("\n⚠️  Whitelist/Blocklist conflict:\n")
						fmt.Printf("   Whitelist: %s", whiteRange.cidr)
						if whiteRange.isCustom {
							fmt.Print(" [CUSTOM]")
						}
						fmt.Println()
						fmt.Printf("   Blocklist: %s", blockRange.CIDR)
						if blockRange.IsCustom {
							fmt.Print(" [CUSTOM]")
						}
						fmt.Println()
						successColor.Println("   ✅ Whitelist takes priority")
					}
				}
			}

			if conflicts == 0 {
				successColor.Println("✅ No conflicts with blocklist")
			}
		}
	}

	// Summary
	fmt.Println("\n" + strings.Repeat("-", 40))
	fmt.Println("Summary:")
	fmt.Printf("Total ranges: %d\n", len(parsedRanges))
	if overlaps > 0 {
		warningColor.Printf("Overlapping ranges: %d\n", overlaps)
	} else {
		successColor.Println("No overlapping ranges found")
	}

	// Offer to clean up redundant ranges
	if overlaps > 0 {
		promptColor.Print("\nWould you like to see optimization suggestions? (y/n): ")
		response, _ := reader.ReadString('\n')
		if strings.ToLower(strings.TrimSpace(response)) == "y" {
			fmt.Println("\nOptimization suggestions:")
			fmt.Println("Consider removing smaller ranges that are fully contained in larger ones.")
			fmt.Println("This will improve performance without changing the blocking behavior.")
		}
	}

	pressEnterToContinue(reader)
}

// Helper function to get the size of an IP range
func getRangeSize(ipNet *net.IPNet) int {
	ones, bits := ipNet.Mask.Size()
	return bits - ones
}

// Add isValidDomain if not already present
func isValidDomain(domain string) bool {
	// Remove any whitespace
	domain = strings.TrimSpace(domain)

	// Basic validation
	if domain == "" || len(domain) > 253 {
		return false
	}

	// Check for invalid characters
	if strings.ContainsAny(domain, " \t\n\r") {
		return false
	}

	// More thorough validation
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return false
	}

	for _, part := range parts {
		if part == "" || len(part) > 63 {
			return false
		}
		// Check first and last character
		if !isAlphaNum(part[0]) || !isAlphaNum(part[len(part)-1]) {
			return false
		}
		// Check middle characters
		for i := 1; i < len(part)-1; i++ {
			if !isAlphaNum(part[i]) && part[i] != '-' {
				return false
			}
		}
	}

	return true
}

func isAlphaNum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
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

	// Start the agent using systemctl (proper way)
	cmd := exec.Command("systemctl", "start", "dnsniper-agent.service")
	if err := cmd.Run(); err != nil {
		errorColor.Printf("Failed to start agent: %v\n", err)
		return
	}

	// Give it a moment to start
	time.Sleep(2 * time.Second)

	// Verify it started successfully
	if running, _ := service.IsAgentRunning(); running {
		successColor.Println("Agent started successfully in background")
		infoColor.Println("Check progress with option 2 (Show status)")
	} else {
		errorColor.Println("Agent failed to start. Check logs for details.")
		infoColor.Println("Log location: /var/log/dnsniper/agent.log")
	}
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
		log.Warnf("Failed to get statistics: %v", err)
		// Don't return, continue with basic status
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

	// Show timer status as well
	timerStatus := "unknown"
	cmd := exec.Command("systemctl", "is-active", "dnsniper-agent.timer")
	if output, err := cmd.Output(); err == nil {
		timerStatus = strings.TrimSpace(string(output))
	}
	fmt.Printf("Timer status: ")
	if timerStatus == "active" {
		successColor.Println(timerStatus)
	} else {
		warningColor.Println(timerStatus)
	}

	fmt.Printf("Last run: %s\n", status.LastRun)

	// Check if agent is currently running
	if running, _ := service.IsAgentRunning(); running {
		infoColor.Println("Agent is currently running...")
	}

	// Protection Statistics
	subtitleColor.Println("\nProtection Statistics:")
	fmt.Printf("Blocked domains: %d\n", status.BlockedDomains)
	fmt.Printf("Blocked IPs: %d\n", status.BlockedIPs)
	fmt.Printf("Whitelisted domains: %d\n", status.WhitelistedDomains)
	fmt.Printf("Whitelisted IPs: %d\n", status.WhitelistedIPs)

	// Recent Activity - only show if stats available
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

	// Show next run time if timer is active
	if timerStatus == "active" {
		cmd := exec.Command("systemctl", "list-timers", "dnsniper-agent.timer", "--no-pager", "--no-legend")
		if output, err := cmd.Output(); err == nil {
			lines := strings.Split(string(output), "\n")
			if len(lines) > 0 && lines[0] != "" {
				fields := strings.Fields(lines[0])
				if len(fields) >= 5 {
					nextRun := strings.Join(fields[0:5], " ")
					infoColor.Printf("\nNext scheduled run: %s\n", nextRun)
				}
			}
		}
	}
}

// Enhanced domain list management with better UI
func manageDomainList(listType string, isWhitelist bool, reader *bufio.Reader) {
	page := 1
	itemsPerPage := 20
	sortBy := "custom" // "custom", "name", "date"

	for {
		clearScreen()
		titleColor.Printf("\n%s Management\n", listType)
		titleColor.Println(strings.Repeat("=", 40))

		// Get domains for current page with sorting
		domains, totalDomains, err := database.GetDomainsListSorted(isWhitelist, page, itemsPerPage, sortBy)
		if err != nil {
			errorColor.Printf("Error retrieving domains: %v\n", err)
			pressEnterToContinue(reader)
			return
		}

		totalPages := (totalDomains + itemsPerPage - 1) / itemsPerPage

		if len(domains) == 0 {
			infoColor.Println("\n📭 No domains found in this list.")
		} else {
			// Display header
			fmt.Println("\n# | Domain | Status | Added | Expires")
			fmt.Println(strings.Repeat("-", 80))

			// Display domains
			for i, domain := range domains {
				num := (page-1)*itemsPerPage + i + 1

				// Format status
				status := ""
				if domain.IsCustom {
					status = highlightColor.Sprint("[CUSTOM]")
				} else {
					status = "[AUTO]"
				}

				if domain.FlaggedAsCDN {
					status += warningColor.Sprint(" [CDN]")
				}

				// Format expiration
				expires := "Never"
				if !domain.IsCustom && domain.ExpiresAt.Valid {
					expiresIn := time.Until(domain.ExpiresAt.Time)
					if expiresIn > 0 {
						if expiresIn > 24*time.Hour {
							days := int(expiresIn.Hours() / 24)
							expires = fmt.Sprintf("%dd", days)
						} else {
							expires = fmt.Sprintf("%dh", int(expiresIn.Hours()))
						}
					} else {
						expires = errorColor.Sprint("Expired")
					}
				}

				// Format added date
				addedStr := domain.AddedAt.Format("2006-01-02")

				// Print the row
				fmt.Printf("%-3d | %-30s | %-15s | %-10s | %s\n",
					num, domain.Domain, status, addedStr, expires)
			}

			if totalPages > 1 {
				fmt.Println(strings.Repeat("-", 80))
				infoColor.Printf("Page %d of %d | Total: %d domains\n", page, totalPages, totalDomains)
			}
		}

		// Menu options
		fmt.Println("\n" + strings.Repeat("-", 40))
		menuColor.Println("Navigation & Actions:")

		if totalPages > 1 {
			fmt.Println("  [N] Next page     [P] Previous page")
			fmt.Println("  [G] Go to page    [S] Sort options")
		}
		fmt.Println("  [A] Add domain    [R] Remove domain")
		fmt.Println("  [I] Import list   [E] Export list")
		fmt.Println("  [0] Back to main menu")

		promptColor.Print("\nSelect option: ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(strings.ToUpper(input))

		switch input {
		case "N": // Next page
			if page < totalPages {
				page++
			}
		case "P": // Previous page
			if page > 1 {
				page--
			}
		case "G": // Go to page
			promptColor.Printf("Enter page number (1-%d): ", totalPages)
			pageStr, _ := reader.ReadString('\n')
			if pageNum, err := strconv.Atoi(strings.TrimSpace(pageStr)); err == nil {
				if pageNum >= 1 && pageNum <= totalPages {
					page = pageNum
				}
			}
		case "S": // Sort options
			fmt.Println("\nSort by:")
			fmt.Println("1. Custom first (default)")
			fmt.Println("2. Name (A-Z)")
			fmt.Println("3. Date added (newest first)")
			promptColor.Print("Select [1-3]: ")
			sortChoice, _ := reader.ReadString('\n')
			switch strings.TrimSpace(sortChoice) {
			case "2":
				sortBy = "name"
			case "3":
				sortBy = "date"
			default:
				sortBy = "custom"
			}
		case "A": // Add domain
			addDomainToList(isWhitelist, reader)
		case "R": // Remove domain
			removeDomainFromList(isWhitelist, reader)
		case "I": // Import list
			importDomainList(isWhitelist, reader)
		case "E": // Export list
			exportDomainList(isWhitelist, domains, reader)
		case "0": // Back
			return
		default:
			errorColor.Println("Invalid option. Please try again.")
			time.Sleep(1 * time.Second)
		}
	}
}

// Similar improvements for IP list management
func manageIPList(listType string, isWhitelist bool, reader *bufio.Reader) {
	page := 1
	itemsPerPage := 20
	showType := "all" // "all", "individual", "ranges"

	for {
		clearScreen()
		titleColor.Printf("\n%s Management\n", listType)
		titleColor.Println(strings.Repeat("=", 40))

		// Get IPs for current page
		ips, totalIPs, err := database.GetIPsListFiltered(isWhitelist, page, itemsPerPage, showType)
		if err != nil {
			errorColor.Printf("Error retrieving IPs: %v\n", err)
			pressEnterToContinue(reader)
			return
		}

		totalPages := (totalIPs + itemsPerPage - 1) / itemsPerPage

		if len(ips) == 0 {
			infoColor.Println("\n📭 No IPs found in this list.")
		} else {
			// Display header
			fmt.Println("\n# | IP/Range | Type | Status | Added | Expires")
			fmt.Println(strings.Repeat("-", 90))

			// Display IPs
			for i, ip := range ips {
				num := (page-1)*itemsPerPage + i + 1

				// Format type
				ipType := "IP"
				if ip.IsRange {
					ipType = highlightColor.Sprint("RANGE")
				}

				// Format status
				status := ""
				if ip.IsCustom {
					status = highlightColor.Sprint("[CUSTOM]")
				} else {
					status = "[AUTO]"
				}

				// Format expiration
				expires := "Never"
				if !ip.IsCustom && ip.ExpiresAt.Valid {
					expiresIn := time.Until(ip.ExpiresAt.Time)
					if expiresIn > 0 {
						if expiresIn > 24*time.Hour {
							days := int(expiresIn.Hours() / 24)
							expires = fmt.Sprintf("%dd", days)
						} else {
							expires = fmt.Sprintf("%dh", int(expiresIn.Hours()))
						}
					} else {
						expires = errorColor.Sprint("Expired")
					}
				}

				// Format added date
				addedStr := ip.AddedAt.Format("2006-01-02")

				// Print the row
				fmt.Printf("%-3d | %-20s | %-5s | %-10s | %-10s | %s\n",
					num, ip.IPAddress, ipType, status, addedStr, expires)
			}

			if totalPages > 1 {
				fmt.Println(strings.Repeat("-", 90))
				infoColor.Printf("Page %d of %d | Total: %d entries\n", page, totalPages, totalIPs)
			}
		}

		// Menu options
		fmt.Println("\n" + strings.Repeat("-", 40))
		menuColor.Println("Navigation & Actions:")

		if totalPages > 1 {
			fmt.Println("  [N] Next page      [P] Previous page")
			fmt.Println("  [G] Go to page     [F] Filter view")
		}
		fmt.Println("  [A] Add IP/Range   [R] Remove IP/Range")
		fmt.Println("  [V] Verify ranges  [T] Test IP")
		fmt.Println("  [0] Back to main menu")

		promptColor.Print("\nSelect option: ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(strings.ToUpper(input))

		switch input {
		case "N": // Next page
			if page < totalPages {
				page++
			}
		case "P": // Previous page
			if page > 1 {
				page--
			}
		case "G": // Go to page
			promptColor.Printf("Enter page number (1-%d): ", totalPages)
			pageStr, _ := reader.ReadString('\n')
			if pageNum, err := strconv.Atoi(strings.TrimSpace(pageStr)); err == nil {
				if pageNum >= 1 && pageNum <= totalPages {
					page = pageNum
				}
			}
		case "F": // Filter view
			fmt.Println("\nShow:")
			fmt.Println("1. All entries (default)")
			fmt.Println("2. Individual IPs only")
			fmt.Println("3. IP ranges only")
			promptColor.Print("Select [1-3]: ")
			filterChoice, _ := reader.ReadString('\n')
			switch strings.TrimSpace(filterChoice) {
			case "2":
				showType = "individual"
			case "3":
				showType = "ranges"
			default:
				showType = "all"
			}
			page = 1 // Reset to first page
		case "A": // Add IP/Range
			addIPToList(isWhitelist, reader)
		case "R": // Remove IP/Range
			removeIPFromList(isWhitelist, reader)
		case "V": // Verify ranges
			verifyIPRanges(isWhitelist, reader)
		case "T": // Test IP
			testIPAgainstRules(reader)
		case "0": // Back
			return
		default:
			errorColor.Println("Invalid option. Please try again.")
			time.Sleep(1 * time.Second)
		}
	}
}

// New function to test if an IP would be blocked or whitelisted
func testIPAgainstRules(reader *bufio.Reader) {
	clearScreen()
	titleColor.Println("Test IP Against Rules")
	titleColor.Println(strings.Repeat("=", 40))

	promptColor.Print("\nEnter IP address to test: ")
	testIP, _ := reader.ReadString('\n')
	testIP = strings.TrimSpace(testIP)

	if !database.IsValidIP(testIP) {
		errorColor.Println("Invalid IP address format.")
		pressEnterToContinue(reader)
		return
	}

	fmt.Println("\nChecking rules...")

	// Check whitelist first
	isWhitelisted, err := database.IsIPWhitelisted(testIP)
	if err != nil {
		errorColor.Printf("Error checking whitelist: %v\n", err)
	} else if isWhitelisted {
		successColor.Printf("\n✅ IP %s is WHITELISTED\n", testIP)

		// Check which whitelist rule matches
		if inList, _ := database.IsIPInWhitelist(testIP); inList {
			infoColor.Println("   - Matched in individual IP whitelist")
		}

		// Check ranges
		ranges, _ := database.GetWhitelistRangesContainingIP(testIP)
		for _, r := range ranges {
			infoColor.Printf("   - Matched in whitelist range: %s\n", r)
		}
	} else {
		// Check blocklist
		isBlocked, err := database.IsIPInBlocklist(testIP)
		if err != nil {
			errorColor.Printf("Error checking blocklist: %v\n", err)
		} else if isBlocked {
			errorColor.Printf("\n❌ IP %s is BLOCKED\n", testIP)

			// Check which blocklist rule matches
			if inList, _ := database.IsIPInBlocklistDirect(testIP); inList {
				infoColor.Println("   - Matched in individual IP blocklist")
			}

			// Check ranges
			ranges, _ := database.GetBlocklistRangesContainingIP(testIP)
			for _, r := range ranges {
				infoColor.Printf("   - Matched in blocklist range: %s\n", r)
			}
		} else {
			infoColor.Printf("\n➖ IP %s is neither whitelisted nor blocked\n", testIP)
		}
	}

	// Check if IP is in any range that conflicts
	fmt.Println("\nChecking for range conflicts...")
	whiteRanges, _ := database.GetWhitelistRangesContainingIP(testIP)
	blockRanges, _ := database.GetBlocklistRangesContainingIP(testIP)

	if len(whiteRanges) > 0 && len(blockRanges) > 0 {
		warningColor.Println("\n⚠️  Range Conflict Detected!")
		fmt.Println("IP is in both whitelist and blocklist ranges:")
		fmt.Println("\nWhitelist ranges:")
		for _, r := range whiteRanges {
			fmt.Printf("  - %s\n", r)
		}
		fmt.Println("\nBlocklist ranges:")
		for _, r := range blockRanges {
			fmt.Printf("  - %s\n", r)
		}
		successColor.Println("\n✅ Whitelist takes priority - IP would be ALLOWED")
	}

	pressEnterToContinue(reader)
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

	// First remove all iptables rules that reference ipsets
	infoColor.Println("Removing iptables rules...")
	if err := fwManager.RemoveAllIPSetRules(); err != nil {
		warningColor.Printf("Warning: Failed to remove some iptables rules: %v\n", err)
	}

	// Then clear the ipsets
	infoColor.Println("Clearing ipset entries...")
	if err := fwManager.ClearRules(); err != nil {
		errorColor.Printf("Error clearing rules: %v\n", err)
		return
	}

	// Save the cleaned state
	if err := fwManager.SaveRulesToPersistentFiles(); err != nil {
		errorColor.Printf("Error saving cleared rules: %v\n", err)
		return
	}

	successColor.Println("All firewall rules cleared successfully")
}

func rebuildFirewallRules() {
	infoColor.Println("Rebuilding firewall rules...")

	// First, clear existing rules
	fwManager, err := firewall.NewIPTablesManager()
	if err != nil {
		errorColor.Printf("Error initializing firewall manager: %v\n", err)
		return
	}

	// Remove all iptables rules first
	infoColor.Println("Removing existing iptables rules...")
	if err := fwManager.RemoveAllIPSetRules(); err != nil {
		warningColor.Printf("Warning: Failed to remove some existing rules: %v\n", err)
	}

	// Clear ipsets
	if err := fwManager.ClearRules(); err != nil {
		errorColor.Printf("Error clearing rules: %v\n", err)
		return
	}

	// Re-setup ipset rules in iptables
	infoColor.Println("Re-establishing iptables rules for ipsets...")
	if err := fwManager.RefreshIPSetRules(); err != nil {
		errorColor.Printf("Error setting up ipset rules: %v\n", err)
		return
	}

	// Get settings
	settings, err := config.GetSettings()
	if err != nil {
		errorColor.Printf("Error getting settings: %v\n", err)
		return
	}

	// Process whitelist first (higher priority)
	infoColor.Println("Processing whitelist entries...")

	// Get all whitelisted IPs and ranges
	whitelistedIPs, whitelistedRanges, err := database.GetAllWhitelistedIPs()
	if err != nil {
		errorColor.Printf("Error getting whitelisted IPs: %v\n", err)
		return
	}

	successCount := 0
	failCount := 0

	// Add whitelisted IPs
	for _, ip := range whitelistedIPs {
		if err := fwManager.WhitelistIP(ip); err != nil {
			errorColor.Printf("Error whitelisting IP %s: %v\n", ip, err)
			failCount++
		} else {
			successCount++
		}
	}

	// Add whitelisted ranges
	for _, cidr := range whitelistedRanges {
		if err := fwManager.WhitelistIPRange(cidr); err != nil {
			errorColor.Printf("Error whitelisting IP range %s: %v\n", cidr, err)
			failCount++
		} else {
			successCount++
		}
	}

	infoColor.Printf("Whitelist complete: %d entries added, %d failed\n", successCount, failCount)

	// Process blocklist (lower priority)
	infoColor.Println("Processing blocklist entries...")

	// Get all blocked IPs and IP ranges from database
	blockedIPs, blockedRanges, err := database.GetAllBlockedIPs()
	if err != nil {
		errorColor.Printf("Error getting blocked IPs: %v\n", err)
		return
	}

	blockSuccessCount := 0
	blockFailCount := 0
	skippedCount := 0

	// Create a map of whitelisted entries for faster lookup
	whitelistMap := make(map[string]bool)
	for _, ip := range whitelistedIPs {
		whitelistMap[ip] = true
	}

	// Process blocked IPs
	infoColor.Printf("Processing %d blocked IPs...\n", len(blockedIPs))
	for i, ip := range blockedIPs {
		// Show progress for large lists
		if i > 0 && i%1000 == 0 {
			infoColor.Printf("Progress: %d/%d IPs processed\n", i, len(blockedIPs))
		}

		// Quick check from our map first
		if whitelistMap[ip] {
			skippedCount++
			continue
		}

		// Double-check with database (for ranges that might whitelist this IP)
		isWhitelisted, err := database.IsIPWhitelisted(ip)
		if err != nil {
			log.Warnf("Failed to check if IP %s is whitelisted: %v", ip, err)
			blockFailCount++
			continue
		}

		if isWhitelisted {
			infoColor.Printf("Skipping IP %s as it is whitelisted\n", ip)
			skippedCount++
			continue
		}

		// Block the IP
		if err := fwManager.BlockIP(ip, settings.BlockRuleType); err != nil {
			if !strings.Contains(err.Error(), "already exists") {
				errorColor.Printf("Error blocking IP %s: %v\n", ip, err)
				blockFailCount++
			}
		} else {
			blockSuccessCount++
		}
	}

	// Process blocked ranges
	infoColor.Printf("Processing %d blocked IP ranges...\n", len(blockedRanges))
	for _, cidr := range blockedRanges {
		// Check if range is whitelisted
		isWhitelisted, err := database.IsIPRangeWhitelisted(cidr)
		if err != nil {
			log.Warnf("Failed to check if range %s is whitelisted: %v", cidr, err)
			blockFailCount++
			continue
		}

		if isWhitelisted {
			infoColor.Printf("Skipping range %s as it is whitelisted\n", cidr)
			skippedCount++
			continue
		}

		// Block the range
		if err := fwManager.BlockIPRange(cidr, settings.BlockRuleType); err != nil {
			if !strings.Contains(err.Error(), "already exists") {
				errorColor.Printf("Error blocking IP range %s: %v\n", cidr, err)
				blockFailCount++
			}
		} else {
			blockSuccessCount++
		}
	}

	// Save the changes to persistent files
	infoColor.Println("Saving firewall rules...")
	if err := fwManager.SaveRulesToPersistentFiles(); err != nil {
		errorColor.Printf("Error saving firewall rules: %v\n", err)
		return
	}

	// Summary
	successColor.Println("Firewall rules rebuilt successfully.")
	infoColor.Printf("Summary:\n")
	infoColor.Printf("  Whitelist: %d entries applied, %d failed\n", successCount, failCount)
	infoColor.Printf("  Blocklist: %d entries applied, %d skipped (whitelisted), %d failed\n",
		blockSuccessCount, skippedCount, blockFailCount)
	infoColor.Printf("  Total rules applied: %d\n", successCount+blockSuccessCount)
}

func confirmUninstall(reader *bufio.Reader) bool {
	clearScreen()
	warningColor.Println("\n⚠️  WARNING: You are about to uninstall DNSniper ⚠️")
	fmt.Println("\nThis will:")
	fmt.Println("• Stop all DNSniper services")
	fmt.Println("• Remove all firewall rules and ipset configurations")
	fmt.Println("• Delete all executable files")
	fmt.Println("• Remove all configuration files")
	fmt.Println("\nThis action cannot be undone!")

	errorColor.Print("\nType 'UNINSTALL' to confirm: ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	if input != "UNINSTALL" {
		infoColor.Println("Uninstallation cancelled")
		time.Sleep(1 * time.Second)
		return false
	}

	// Create uninstall script for complete cleanup
	uninstallScript := `#!/bin/bash
# Stop services
systemctl stop dnsniper-agent.service 2>/dev/null
systemctl stop dnsniper-agent.timer 2>/dev/null
systemctl disable dnsniper-agent.service 2>/dev/null
systemctl disable dnsniper-agent.timer 2>/dev/null

# Remove iptables rules
iptables -D INPUT -m set --match-set dnsniper-whitelist src -j ACCEPT 2>/dev/null
iptables -D OUTPUT -m set --match-set dnsniper-whitelist dst -j ACCEPT 2>/dev/null
iptables -D INPUT -m set --match-set dnsniper-range-whitelist src -j ACCEPT 2>/dev/null
iptables -D OUTPUT -m set --match-set dnsniper-range-whitelist dst -j ACCEPT 2>/dev/null
iptables -D INPUT -m set --match-set dnsniper-blocklist src -j DROP 2>/dev/null
iptables -D OUTPUT -m set --match-set dnsniper-blocklist dst -j DROP 2>/dev/null
iptables -D INPUT -m set --match-set dnsniper-range-blocklist src -j DROP 2>/dev/null
iptables -D OUTPUT -m set --match-set dnsniper-range-blocklist dst -j DROP 2>/dev/null

# Same for IPv6
ip6tables -D INPUT -m set --match-set dnsniper-whitelist src -j ACCEPT 2>/dev/null
ip6tables -D OUTPUT -m set --match-set dnsniper-whitelist dst -j ACCEPT 2>/dev/null
ip6tables -D INPUT -m set --match-set dnsniper-range-whitelist src -j ACCEPT 2>/dev/null
ip6tables -D OUTPUT -m set --match-set dnsniper-range-whitelist dst -j ACCEPT 2>/dev/null
ip6tables -D INPUT -m set --match-set dnsniper-blocklist src -j DROP 2>/dev/null
ip6tables -D OUTPUT -m set --match-set dnsniper-blocklist dst -j DROP 2>/dev/null
ip6tables -D INPUT -m set --match-set dnsniper-range-blocklist src -j DROP 2>/dev/null
ip6tables -D OUTPUT -m set --match-set dnsniper-range-blocklist dst -j DROP 2>/dev/null

# Clean chains
iptables -D INPUT -j DNSniper 2>/dev/null
iptables -D OUTPUT -j DNSniper 2>/dev/null
iptables -D FORWARD -j DNSniper 2>/dev/null
iptables -F DNSniper 2>/dev/null
iptables -X DNSniper 2>/dev/null

ip6tables -D INPUT -j DNSniper6 2>/dev/null
ip6tables -D OUTPUT -j DNSniper6 2>/dev/null
ip6tables -D FORWARD -j DNSniper6 2>/dev/null
ip6tables -F DNSniper6 2>/dev/null
ip6tables -X DNSniper6 2>/dev/null

# Destroy ipsets
ipset destroy dnsniper-whitelist 2>/dev/null
ipset destroy dnsniper-blocklist 2>/dev/null
ipset destroy dnsniper-range-whitelist 2>/dev/null
ipset destroy dnsniper-range-blocklist 2>/dev/null

# Save cleaned iptables
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4 2>/dev/null
ip6tables-save > /etc/iptables/rules.v6 2>/dev/null
systemctl restart netfilter-persistent 2>/dev/null

# Remove files
rm -f /etc/systemd/system/dnsniper-agent.service
rm -f /etc/systemd/system/dnsniper-agent.timer
rm -f /usr/bin/dnsniper
rm -f /usr/bin/dnsniper-agent
rm -rf /etc/dnsniper
rm -f /etc/ipset.conf

# Reload systemd
systemctl daemon-reload
`

	// Execute uninstall script
	tmpFile, err := os.CreateTemp("", "dnsniper-uninstall-*.sh")
	if err != nil {
		errorColor.Printf("Failed to create uninstall script: %v\n", err)
		return false
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(uninstallScript); err != nil {
		errorColor.Printf("Failed to write uninstall script: %v\n", err)
		return false
	}
	tmpFile.Close()

	cmd := exec.Command("bash", tmpFile.Name())
	if output, err := cmd.CombinedOutput(); err != nil {
		errorColor.Printf("Uninstall errors: %v\n%s\n", err, string(output))
	}

	// Ask about logs
	promptColor.Print("\nWould you like to keep log files? (y/n): ")
	keepLogs, _ := reader.ReadString('\n')
	keepLogs = strings.TrimSpace(keepLogs)

	if strings.ToLower(keepLogs) == "n" || strings.ToLower(keepLogs) == "no" {
		os.RemoveAll("/var/log/dnsniper")
		infoColor.Println("Log files removed")
	} else {
		infoColor.Println("Log files kept at /var/log/dnsniper")
	}

	successColor.Println("\nDNSniper has been uninstalled.")
	fmt.Println("\nThank you for using DNSniper!")
	return true
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
	fmt.Printf("Block Chains: %s\n", settings.BlockChains)
	fmt.Printf("Block Direction: %s\n", settings.BlockDirection)
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

	fmt.Printf("Current DNS resolver: %s\n\n", settings.DNSResolver)
	infoColor.Println("Popular DNS servers:")
	fmt.Println("1. Google DNS (8.8.8.8)")
	fmt.Println("2. Cloudflare DNS (1.1.1.1)")
	fmt.Println("3. Quad9 DNS (9.9.9.9)")
	fmt.Println("4. OpenDNS (208.67.222.222)")
	fmt.Println("5. Custom DNS server")

	promptColor.Print("Select an option [1-5]: ")
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	var resolver string
	switch choice {
	case "1":
		resolver = "8.8.8.8"
	case "2":
		resolver = "1.1.1.1"
	case "3":
		resolver = "9.9.9.9"
	case "4":
		resolver = "208.67.222.222"
	case "5":
		promptColor.Print("Enter custom DNS resolver IP: ")
		resolver, _ = reader.ReadString('\n')
		resolver = strings.TrimSpace(resolver)
	default:
		resolver = "8.8.8.8"
		warningColor.Println("Invalid choice, using default (8.8.8.8)")
	}

	// Validate IP address
	if net.ParseIP(resolver) == nil {
		errorColor.Println("Invalid IP address format. Using default (8.8.8.8)")
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
	subtitleColor.Println("Change Block Rule Configuration")

	settings, err := config.GetSettings()
	if err != nil {
		errorColor.Printf("Failed to get current settings: %v\n", err)
		return
	}

	// Show current configuration
	fmt.Printf("\nCurrent configuration:\n")
	fmt.Printf("  Chains: %s\n", settings.BlockChains)
	fmt.Printf("  Direction: %s\n\n", settings.BlockDirection)

	// Select chains
	fmt.Println("Select chains to apply blocking rules:")
	fmt.Println("1. ALL chains (INPUT + OUTPUT + FORWARD) [Default]")
	fmt.Println("2. INPUT only")
	fmt.Println("3. OUTPUT only")
	fmt.Println("4. FORWARD only")
	fmt.Println("5. INPUT + OUTPUT")
	fmt.Println("6. INPUT + FORWARD")
	fmt.Println("7. OUTPUT + FORWARD")
	fmt.Println("8. Custom selection")

	promptColor.Print("\nEnter choice [1-8]: ")
	chainChoice, _ := reader.ReadString('\n')
	chainChoice = strings.TrimSpace(chainChoice)

	var selectedChains string
	switch chainChoice {
	case "2":
		selectedChains = "INPUT"
	case "3":
		selectedChains = "OUTPUT"
	case "4":
		selectedChains = "FORWARD"
	case "5":
		selectedChains = "INPUT,OUTPUT"
	case "6":
		selectedChains = "INPUT,FORWARD"
	case "7":
		selectedChains = "OUTPUT,FORWARD"
	case "8":
		promptColor.Print("Enter chains (comma-separated, e.g., INPUT,OUTPUT): ")
		selectedChains, _ = reader.ReadString('\n')
		selectedChains = strings.TrimSpace(strings.ToUpper(selectedChains))
		// Validate
		validChains := []string{}
		for _, chain := range strings.Split(selectedChains, ",") {
			chain = strings.TrimSpace(chain)
			if chain == "INPUT" || chain == "OUTPUT" || chain == "FORWARD" {
				validChains = append(validChains, chain)
			}
		}
		if len(validChains) == 0 {
			errorColor.Println("No valid chains selected. Using ALL.")
			selectedChains = "ALL"
		} else {
			selectedChains = strings.Join(validChains, ",")
		}
	default:
		selectedChains = "ALL"
	}

	fmt.Printf("\nSelected chains: %s\n\n", selectedChains)

	// Select direction
	fmt.Println("Select blocking direction:")
	fmt.Println("1. Block as both source and destination [Default]")
	fmt.Println("2. Block as source only")
	fmt.Println("3. Block as destination only")

	promptColor.Print("\nEnter choice [1-3]: ")
	dirChoice, _ := reader.ReadString('\n')
	dirChoice = strings.TrimSpace(dirChoice)

	var direction string
	switch dirChoice {
	case "2":
		direction = "source"
	case "3":
		direction = "destination"
	default:
		direction = "both"
	}

	// Show summary
	fmt.Printf("\nNew configuration:\n")
	fmt.Printf("  Chains: %s\n", selectedChains)
	fmt.Printf("  Direction: %s\n", direction)

	// If configuration hasn't changed, no need to update
	if selectedChains == settings.BlockChains && direction == settings.BlockDirection {
		infoColor.Println("\nConfiguration unchanged.")
		return
	}

	// Confirm changes
	promptColor.Print("\nApply these changes? (y/n): ")
	confirm, _ := reader.ReadString('\n')
	if strings.ToLower(strings.TrimSpace(confirm)) != "y" {
		infoColor.Println("Changes cancelled.")
		return
	}

	// Save to database
	err = config.SaveSetting("block_chains", selectedChains)
	if err != nil {
		errorColor.Printf("Failed to save block chains: %v\n", err)
		return
	}

	err = config.SaveSetting("block_direction", direction)
	if err != nil {
		errorColor.Printf("Failed to save block direction: %v\n", err)
		return
	}

	// Apply the changes immediately
	infoColor.Println("\nApplying changes to firewall rules...")

	fwManager, err := firewall.NewIPTablesManager()
	if err != nil {
		errorColor.Printf("Failed to initialize firewall manager: %v\n", err)
		return
	}

	// Refresh all ipset rules with the new configuration
	infoColor.Printf("Refreshing firewall rules with new configuration...\n")
	if err := fwManager.RefreshIPSetRules(); err != nil {
		errorColor.Printf("Failed to refresh firewall rules: %v\n", err)
		warningColor.Println("Configuration was saved but rules may not be applied correctly.")
		warningColor.Println("You may need to restart your system or run the rebuild firewall rules option.")
		return
	}

	successColor.Println("\nBlock rule configuration updated successfully!")
	successColor.Printf("Chains: %s, Direction: %s\n", selectedChains, direction)
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
	infoColor.Println("Note: This only affects auto-downloaded domains, not custom entries.")
	fmt.Println("\nSelect time unit:")
	fmt.Println("1. Minutes")
	fmt.Println("2. Hours")
	fmt.Println("3. Days (recommended)")
	fmt.Println("4. Weeks")

	promptColor.Print("\nEnter choice [1-4]: ")
	unitChoice, _ := reader.ReadString('\n')
	unitChoice = strings.TrimSpace(unitChoice)

	var unit string
	var defaultValue int
	var unitText string
	var minValue, maxValue int

	switch unitChoice {
	case "1":
		unit = "m"
		defaultValue = 1440 // 24 hours in minutes
		unitText = "minutes"
		minValue = 30
		maxValue = 10080 // 1 week in minutes
	case "2":
		unit = "h"
		defaultValue = 24
		unitText = "hours"
		minValue = 1
		maxValue = 168 // 1 week in hours
	case "4":
		unit = "w"
		defaultValue = 4 // 4 weeks
		unitText = "weeks"
		minValue = 1
		maxValue = 52 // 1 year
	default:
		unit = "d"
		defaultValue = 30 // 30 days
		unitText = "days"
		minValue = 1
		maxValue = 365
	}

	promptColor.Printf("Enter expiration time in %s (min: %d, max: %d, default: %d): ",
		unitText, minValue, maxValue, defaultValue)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	value := defaultValue
	if input != "" {
		var err error
		value, err = strconv.Atoi(input)
		if err != nil || value < minValue || value > maxValue {
			errorColor.Printf("Invalid input. Using default (%d %s).\n", defaultValue, unitText)
			value = defaultValue
		}
	}

	// Convert weeks to days for storage
	expStr := ""
	if unit == "w" {
		expStr = fmt.Sprintf("%dd", value*7)
	} else {
		expStr = fmt.Sprintf("%d%s", value, unit)
	}

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
	infoColor.Println("The URL should point to a text file containing one domain per line.")
	promptColor.Println("Enter URL (e.g., https://example.com/domains.txt):")
	url, _ := reader.ReadString('\n')
	url = strings.TrimSpace(url)

	if url == "" {
		errorColor.Println("URL cannot be empty.")
		time.Sleep(1 * time.Second)
		return
	}

	// Validate URL format
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		errorColor.Println("URL must start with http:// or https://")
		time.Sleep(2 * time.Second)
		return
	}

	// Test URL accessibility
	infoColor.Printf("Testing URL accessibility...")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Head(url)
	if err != nil {
		errorColor.Printf("Failed to access URL: %v\n", err)
		promptColor.Print("Add anyway? (y/n): ")
		confirm, _ := reader.ReadString('\n')
		if strings.ToLower(strings.TrimSpace(confirm)) != "y" {
			return
		}
	} else {
		resp.Body.Close()
		if resp.StatusCode >= 400 {
			warningColor.Printf("URL returned status code: %d\n", resp.StatusCode)
			promptColor.Print("Add anyway? (y/n): ")
			confirm, _ := reader.ReadString('\n')
			if strings.ToLower(strings.TrimSpace(confirm)) != "y" {
				return
			}
		} else {
			successColor.Println("URL is accessible")
		}
	}

	// Add URL to database
	if err := database.AddUpdateURL(url); err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			errorColor.Println("This URL is already in the list.")
		} else {
			errorColor.Printf("Failed to add update URL: %v\n", err)
		}
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
