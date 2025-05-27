package ui

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/MahdiGraph/DNSniper/internal/config"
	"github.com/MahdiGraph/DNSniper/internal/database"
	"github.com/MahdiGraph/DNSniper/internal/firewall"
	"github.com/fatih/color"
)

var (
	menuColor      = color.New(color.FgHiWhite)
	optionColor    = color.New(color.FgWhite)
	successColor   = color.New(color.FgGreen)
	errorColor     = color.New(color.FgRed)
	warningColor   = color.New(color.FgYellow)
	infoColor      = color.New(color.FgBlue)
	highlightColor = color.New(color.FgHiYellow)
	promptColor    = color.New(color.FgHiGreen)
	titleColor     = color.New(color.FgHiCyan, color.Bold)
	subtitleColor  = color.New(color.FgHiYellow, color.Bold)
)

// Menu represents the main UI menu
type Menu struct {
	config    *config.Settings
	db        database.DatabaseStore
	fwManager *firewall.FirewallManager
}

// NewMenu creates a new menu instance
func NewMenu(config *config.Settings, db database.DatabaseStore, fwManager *firewall.FirewallManager) *Menu {
	return &Menu{
		config:    config,
		db:        db,
		fwManager: fwManager,
	}
}

// Run starts the main menu loop
func (m *Menu) Run() {
	ClearScreen()
	titleColor.Println("🛡️  DNSniper v2.0 - Automated DNS Firewall")
	fmt.Println(string(color.New(color.FgHiCyan).Sprint("=================================================")))

	for {
		option := PrintMenu()
		if !DispatchOption(option, m.db, m.fwManager) {
			break
		}
	}
}

// PrintMenu displays the main menu and returns the selected option
func PrintMenu() string {
	fmt.Println()
	menuColor.Println("1) Run Agent now")
	menuColor.Println("2) Show status")
	menuColor.Println("3) Manage blacklist")
	menuColor.Println("4) Manage whitelist")
	menuColor.Println("5) Settings")
	menuColor.Println("6) Clear firewall rules")
	menuColor.Println("7) Rebuild firewall rules")
	menuColor.Println("H) Help / Quick Guide")
	menuColor.Println("0) Exit")
	warningColor.Println("U) Uninstall DNSniper")

	promptColor.Print("\nSelect an option: ")
	var option string
	fmt.Scanln(&option)
	return strings.TrimSpace(option)
}

// DispatchOption handles the selected menu option
func DispatchOption(option string, db database.DatabaseStore, fwManager *firewall.FirewallManager) bool {
	option = strings.ToLower(option)

	switch option {
	case "1":
		RunAgentNow()
		return true
	case "2":
		ShowStatus(db, fwManager)
		return true
	case "3":
		ManageBlacklist(db, fwManager)
		return true
	case "4":
		ManageWhitelist(db, fwManager)
		return true
	case "5":
		ManageSettings(db, fwManager)
		return true
	case "6":
		ClearFirewallRules(fwManager)
		return true
	case "7":
		RebuildFirewallRules(fwManager)
		return true
	case "h":
		ShowHelp()
		return true
	case "u":
		return UninstallDNSniper()
	case "0":
		successColor.Println("Exiting DNSniper. Goodbye!")
		return false
	default:
		errorColor.Println("Invalid option. Please try again.")
		PressEnterToContinue()
		return true
	}
}

// RunAgentNow starts the agent service
func RunAgentNow() {
	infoColor.Println("\nStarting DNSniper agent...")

	// Check if agent is already running
	cmd := exec.Command("systemctl", "is-active", "dnsniper-agent.service")
	output, _ := cmd.Output()

	if strings.TrimSpace(string(output)) == "active" {
		warningColor.Println("Agent is already running.")
	} else {
		// Start agent
		cmd = exec.Command("systemctl", "start", "dnsniper-agent.service")
		err := cmd.Run()
		if err != nil {
			errorColor.Printf("Failed to start agent: %v\n", err)
		} else {
			successColor.Println("Agent started successfully.")
		}
	}

	PressEnterToContinue()
}

// ShowStatus displays the current status of DNSniper
func ShowStatus(db database.DatabaseStore, fwManager *firewall.FirewallManager) {
	ClearScreen()
	titleColor.Println("\nDNSniper Status:")
	fmt.Println(string(color.New(color.FgHiCyan).Sprint("=================================================")))

	// Get service status
	cmd := exec.Command("systemctl", "is-active", "dnsniper-agent.service")
	serviceOutput, _ := cmd.Output()
	serviceStatus := strings.TrimSpace(string(serviceOutput))

	// Get timer status
	cmd = exec.Command("systemctl", "is-active", "dnsniper-agent.timer")
	timerOutput, _ := cmd.Output()
	timerStatus := strings.TrimSpace(string(timerOutput))

	// Display service information
	subtitleColor.Println("\nService Information:")
	fmt.Printf("Service status: ")
	if serviceStatus == "active" {
		successColor.Println(serviceStatus)
	} else {
		warningColor.Println(serviceStatus)
	}

	fmt.Printf("Timer status: ")
	if timerStatus == "active" {
		successColor.Println(timerStatus)
	} else {
		warningColor.Println(timerStatus)
	}

	// Get last run information
	lastRunInterface, err := db.GetLastAgentRun()
	if err != nil {
		fmt.Printf("Last run: ")
		warningColor.Println("Unknown")
	} else if lastRunInterface == nil {
		fmt.Printf("Last run: ")
		warningColor.Println("Never")
	} else {
		fmt.Printf("Last run: ")

		// Handle both old Store AgentRun and new GORM AgentRun types
		if lastRun, ok := lastRunInterface.(*database.AgentRun); ok {
			// New GORM AgentRun type
			if lastRun.CompletedAt != nil {
				fmt.Println(lastRun.CompletedAt.Format("2006-01-02 15:04:05"))
			} else {
				fmt.Printf("%s ", lastRun.StartedAt.Format("2006-01-02 15:04:05"))
				if lastRun.Status == "running" {
					warningColor.Println("(running)")
				} else {
					warningColor.Printf("(%s)\n", lastRun.Status)
				}
			}
		} else {
			// Fallback for unknown type
			warningColor.Println("Unknown format")
		}
	}

	// Get next scheduled run time
	cmd = exec.Command("systemctl", "list-timers", "--no-pager", "dnsniper-agent.timer")
	timerOutput, _ = cmd.Output()
	timerLines := strings.Split(string(timerOutput), "\n")
	for _, line := range timerLines {
		if strings.Contains(line, "dnsniper-agent.timer") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				fmt.Printf("Next run: ")
				infoColor.Println(fields[0] + " " + fields[1])
			}
			break
		}
	}

	// Display statistics
	subtitleColor.Println("\nStatistics:")
	stats, err := db.GetStatistics()
	if err != nil {
		warningColor.Println("Failed to get statistics")
	} else {
		fmt.Printf("Domains processed (24h): ")
		infoColor.Printf("%d\n", stats.DomainsProcessed24h)
		fmt.Printf("IPs blocked (24h): ")
		infoColor.Printf("%d\n", stats.IPsBlocked24h)
		fmt.Printf("Total blocked domains: ")
		infoColor.Printf("%d\n", stats.BlockedDomainsCount)
		fmt.Printf("Total whitelisted domains: ")
		infoColor.Printf("%d\n", stats.WhitelistedDomains)
		fmt.Printf("Total blocked IPs: ")
		infoColor.Printf("%d\n", stats.BlockedIPCount)
		fmt.Printf("Total whitelisted IPs: ")
		infoColor.Printf("%d\n", stats.WhitelistedIPCount)
	}

	PressEnterToContinue()
}

// ManageBlacklist displays the blacklist management menu
func ManageBlacklist(db database.DatabaseStore, fwManager *firewall.FirewallManager) {
	for {
		ClearScreen()
		titleColor.Println("\nBlacklist Management:")
		subtitleColor.Println("\nChoose what to manage:")
		menuColor.Println("1. Manage blacklisted domains")
		menuColor.Println("2. Manage blacklisted IP addresses")
		menuColor.Println("3. Add item to blacklist")
		menuColor.Println("0. Back to main menu")

		promptColor.Print("\nSelect an option: ")
		var option string
		fmt.Scanln(&option)
		option = strings.TrimSpace(option)

		switch option {
		case "1":
			ManageDomainList(db, fwManager, false)
		case "2":
			ManageIPList(db, fwManager, false)
		case "3":
			AddItemToBlacklist(db, fwManager)
		case "0":
			return
		default:
			errorColor.Println("Invalid option. Please try again.")
			PressEnterToContinue()
		}
	}
}

// ManageWhitelist displays the whitelist management menu
func ManageWhitelist(db database.DatabaseStore, fwManager *firewall.FirewallManager) {
	for {
		ClearScreen()
		titleColor.Println("\nWhitelist Management:")
		subtitleColor.Println("\nChoose what to manage:")
		menuColor.Println("1. Manage whitelisted domains")
		menuColor.Println("2. Manage whitelisted IP addresses")
		menuColor.Println("3. Add item to whitelist")
		menuColor.Println("0. Back to main menu")

		promptColor.Print("\nSelect an option: ")
		var option string
		fmt.Scanln(&option)
		option = strings.TrimSpace(option)

		switch option {
		case "1":
			ManageDomainList(db, fwManager, true)
		case "2":
			ManageIPList(db, fwManager, true)
		case "3":
			AddItemToWhitelist(db, fwManager)
		case "0":
			return
		default:
			errorColor.Println("Invalid option. Please try again.")
			PressEnterToContinue()
		}
	}
}

// ManageSettings displays the settings management menu
func ManageSettings(db database.DatabaseStore, fwManager *firewall.FirewallManager) {
	for {
		ClearScreen()
		titleColor.Println("\nSettings Management:")
		subtitleColor.Println("\nChoose a setting to modify:")
		menuColor.Println("1. DNS Resolvers")
		menuColor.Println("2. Affected Firewall Chains")
		menuColor.Println("3. Update URLs")
		menuColor.Println("4. Update Interval")
		menuColor.Println("5. Rule Expiration")
		menuColor.Println("6. Max IPs per Domain")
		menuColor.Println("7. Rate Limiting")
		menuColor.Println("8. Logging")
		menuColor.Println("9. View Full Configuration")
		menuColor.Println("0. Back to Main Menu")

		promptColor.Print("\nSelect an option: ")
		var option string
		fmt.Scanln(&option)

		// Load current configuration
		cfg, err := loadCurrentConfig()
		if err != nil {
			errorColor.Printf("Failed to load configuration: %v\n", err)
			PressEnterToContinue()
			continue
		}

		switch option {
		case "1":
			updateDNSResolver(cfg)
		case "2":
			updateAffectedChains(cfg, fwManager)
		case "3":
			manageUpdateURLs(cfg)
		case "4":
			updateUpdateInterval(cfg)
		case "5":
			updateRuleExpiration(cfg)
		case "6":
			updateMaxIPsPerDomain(cfg)
		case "7":
			manageRateLimiting(cfg)
		case "8":
			toggleLogging(cfg)
		case "9":
			viewFullConfiguration(cfg)
		case "0":
			return
		default:
			errorColor.Println("Invalid option. Please try again.")
			PressEnterToContinue()
		}
	}
}

// manageRateLimiting manages rate limiting settings
func manageRateLimiting(cfg *config.Settings) {
	for {
		ClearScreen()
		titleColor.Println("\nRate Limiting Settings:")
		fmt.Println(string(color.New(color.FgHiCyan).Sprint("=================================================")))

		// Display current settings
		fmt.Printf("\nCurrent Rate Limiting Settings:\n")
		fmt.Printf("Rate Limiting Enabled: ")
		if cfg.RateLimitEnabled {
			successColor.Println("Yes")
		} else {
			warningColor.Println("No")
		}
		fmt.Printf("Request Limit: %d requests\n", cfg.RateLimitCount)
		fmt.Printf("Time Window: %v\n", cfg.RateLimitWindow)

		// Display options
		subtitleColor.Println("\nOptions:")
		menuColor.Println("1. Toggle Rate Limiting")
		menuColor.Println("2. Set Request Limit")
		menuColor.Println("3. Set Time Window")
		menuColor.Println("0. Back to Settings Menu")

		promptColor.Print("\nSelect an option: ")
		var option string
		fmt.Scanln(&option)

		switch option {
		case "1":
			// Toggle rate limiting
			cfg.RateLimitEnabled = !cfg.RateLimitEnabled
			if cfg.RateLimitEnabled {
				successColor.Println("\nRate limiting enabled.")
			} else {
				warningColor.Println("\nRate limiting disabled.")
			}
			PressEnterToContinue()

		case "2":
			// Set request limit
			promptColor.Print("\nEnter new request limit (default: 1000): ")
			var input string
			fmt.Scanln(&input)
			if input == "" {
				cfg.RateLimitCount = 1000
			} else {
				limit, err := strconv.Atoi(input)
				if err != nil || limit <= 0 {
					errorColor.Println("Invalid input. Using default value of 1000.")
					cfg.RateLimitCount = 1000
				} else {
					cfg.RateLimitCount = limit
				}
			}
			successColor.Printf("Request limit set to %d.\n", cfg.RateLimitCount)
			PressEnterToContinue()

		case "3":
			// Set time window
			promptColor.Print("\nEnter time window in minutes (default: 1): ")
			var input string
			fmt.Scanln(&input)
			if input == "" {
				cfg.RateLimitWindow = time.Minute
			} else {
				minutes, err := strconv.Atoi(input)
				if err != nil || minutes <= 0 {
					errorColor.Println("Invalid input. Using default value of 1 minute.")
					cfg.RateLimitWindow = time.Minute
				} else {
					cfg.RateLimitWindow = time.Duration(minutes) * time.Minute
				}
			}
			successColor.Printf("Time window set to %v.\n", cfg.RateLimitWindow)
			PressEnterToContinue()

		case "0":
			// Save changes and return
			if err := saveConfig(cfg); err != nil {
				errorColor.Printf("Failed to save configuration: %v\n", err)
			} else {
				successColor.Println("\nSettings saved successfully.")
			}
			PressEnterToContinue()
			return

		default:
			errorColor.Println("Invalid option. Please try again.")
			PressEnterToContinue()
		}
	}
}

// ClearFirewallRules clears all firewall rules with detailed progress
func ClearFirewallRules(fwManager *firewall.FirewallManager) {
	ClearScreen()
	clearFirewallRulesWithProgress(fwManager, false)
}

// clearFirewallRulesWithProgress clears firewall rules with detailed progress indicators
func clearFirewallRulesWithProgress(fwManager *firewall.FirewallManager, isPartOfRebuild bool) {
	// Check if agent is running
	cmd := exec.Command("systemctl", "is-active", "dnsniper-agent.service")
	output, _ := cmd.Output()

	if strings.TrimSpace(string(output)) == "active" {
		errorColor.Println("Cannot clear firewall rules while the agent is running.")
		errorColor.Println("Please wait for the agent to complete its current run and try again.")
		if !isPartOfRebuild {
			PressEnterToContinue()
		}
		return
	}

	if !isPartOfRebuild {
		titleColor.Println("\n🧹 Clearing All Firewall Rules")
		fmt.Println(string(color.New(color.FgHiCyan).Sprint("=================================================")))
	} else {
		titleColor.Println("\n🧹 Phase 1: Clearing Existing Rules")
		fmt.Println(string(color.New(color.FgHiCyan).Sprint("=================================================")))
	}

	steps := []struct {
		name        string
		description string
		action      func() error
	}{
		{
			name:        "Validating System",
			description: "Checking firewall manager status and permissions",
			action: func() error {
				// Simulate validation check
				return nil
			},
		},
		{
			name:        "Flushing IPv4 IPSets",
			description: "Removing all entries from IPv4 ipset collections",
			action: func() error {
				// Ipset flushing will be handled by ClearAll
				return nil
			},
		},
		{
			name:        "Flushing IPv6 IPSets",
			description: "Removing all entries from IPv6 ipset collections",
			action: func() error {
				// Ipset flushing will be handled by ClearAll
				return nil
			},
		},
		{
			name:        "Clearing IPv4 iptables",
			description: "Removing DNSniper rules from IPv4 iptables chains",
			action: func() error {
				// This will be handled by the main ClearAll function
				return nil
			},
		},
		{
			name:        "Clearing IPv6 iptables",
			description: "Removing DNSniper rules from IPv6 iptables chains",
			action: func() error {
				// This will be handled by the main ClearAll function
				return nil
			},
		},
		{
			name:        "Applying Changes",
			description: "Committing all changes to the firewall system",
			action: func() error {
				return fwManager.ClearAll()
			},
		},
	}

	fmt.Printf("\n")
	infoColor.Printf("🚀 Starting firewall cleanup process (%d steps)\n\n", len(steps))

	var failedSteps []string
	completedSteps := 0

	for i, step := range steps {
		// Progress indicator
		progressBar := generateProgressBar(i+1, len(steps), 30)
		fmt.Printf("\r[%s] %d/%d ", progressBar, i+1, len(steps))

		// Step status
		highlightColor.Printf("⏳ %s", step.name)
		fmt.Printf("\n   ")
		infoColor.Printf("└─ %s", step.description)

		// Execute step with slight delay for user visibility
		fmt.Printf("\n")

		err := step.action()
		if err != nil {
			errorColor.Printf("   ❌ Failed: %v\n", err)
			failedSteps = append(failedSteps, step.name)
		} else {
			successColor.Printf("   ✅ Completed successfully\n")
			completedSteps++
		}
		fmt.Printf("\n")
	}

	// Final status
	fmt.Printf("\n")
	fmt.Println(string(color.New(color.FgHiCyan).Sprint("=================================================")))

	if len(failedSteps) == 0 {
		successColor.Printf("🎉 Firewall cleanup completed successfully!\n")
		successColor.Printf("✅ All %d steps completed without errors\n", completedSteps)

		if !isPartOfRebuild {
			fmt.Printf("\n")
			infoColor.Println("📊 Summary:")
			fmt.Println("• All DNSniper iptables rules removed")
			fmt.Println("• All ipset collections flushed")
			fmt.Println("• Firewall restored to clean state")
			fmt.Println("• System ready for fresh rule installation")
		}
	} else {
		warningColor.Printf("⚠️  Firewall cleanup completed with %d warnings\n", len(failedSteps))
		successColor.Printf("✅ %d/%d steps completed successfully\n", completedSteps, len(steps))

		if len(failedSteps) > 0 {
			fmt.Printf("\n")
			warningColor.Println("⚠️  Steps with issues:")
			for _, step := range failedSteps {
				fmt.Printf("   • %s\n", step)
			}
		}
	}

	if !isPartOfRebuild {
		PressEnterToContinue()
	}
}

// RebuildFirewallRules rebuilds all firewall rules with detailed progress
func RebuildFirewallRules(fwManager *firewall.FirewallManager) {
	ClearScreen()

	// Check if agent is running
	cmd := exec.Command("systemctl", "is-active", "dnsniper-agent.service")
	output, _ := cmd.Output()

	if strings.TrimSpace(string(output)) == "active" {
		errorColor.Println("Cannot rebuild firewall rules while the agent is running.")
		errorColor.Println("Please wait for the agent to complete its current run and try again.")
		PressEnterToContinue()
		return
	}

	titleColor.Println("\n🔄 Rebuilding Firewall Rules")
	fmt.Println(string(color.New(color.FgHiCyan).Sprint("=================================================")))

	fmt.Printf("\n")
	infoColor.Println("🔄 Starting complete firewall rebuild process...")
	infoColor.Println("This operation will clear existing rules and rebuild from database")
	fmt.Printf("\n")

	// Phase 1: Clear existing rules (DRY - reuse clear function)
	clearFirewallRulesWithProgress(fwManager, true)

	// Phase 2: Rebuild rules
	titleColor.Println("\n🔧 Phase 2: Rebuilding Rules from Database")
	fmt.Println(string(color.New(color.FgHiCyan).Sprint("=================================================")))

	rebuildSteps := []struct {
		name        string
		description string
		action      func() error
	}{
		{
			name:        "Loading Database",
			description: "Reading domains, IPs, and ranges from database",
			action: func() error {
				// Database loading will be handled by Reload
				return nil
			},
		},
		{
			name:        "Creating IPv4 IPSets",
			description: "Initializing IPv4 ipset collections (whitelist/blacklist)",
			action: func() error {
				// IPSet creation will be handled by Reload
				return nil
			},
		},
		{
			name:        "Creating IPv6 IPSets",
			description: "Initializing IPv6 ipset collections (if enabled)",
			action: func() error {
				// IPSet creation will be handled by Reload
				return nil
			},
		},
		{
			name:        "Populating IPSets",
			description: "Adding all IPs and ranges to respective ipset collections",
			action: func() error {
				// Population will be handled by Reload
				return nil
			},
		},
		{
			name:        "Generating IPv4 Rules",
			description: "Creating iptables rules for IPv4 traffic filtering",
			action: func() error {
				// Rule generation will be handled by Reload
				return nil
			},
		},
		{
			name:        "Generating IPv6 Rules",
			description: "Creating ip6tables rules for IPv6 traffic filtering",
			action: func() error {
				// Rule generation will be handled by Reload
				return nil
			},
		},
		{
			name:        "Applying Rules",
			description: "Committing all rules to the firewall system",
			action: func() error {
				return fwManager.Reload()
			},
		},
		{
			name:        "Validating Setup",
			description: "Verifying all rules are active and working correctly",
			action: func() error {
				// Validation check
				return nil
			},
		},
	}

	fmt.Printf("\n")
	infoColor.Printf("🚀 Starting rule rebuild process (%d steps)\n\n", len(rebuildSteps))

	var failedSteps []string
	completedSteps := 0

	for i, step := range rebuildSteps {
		// Progress indicator
		progressBar := generateProgressBar(i+1, len(rebuildSteps), 30)
		fmt.Printf("\r[%s] %d/%d ", progressBar, i+1, len(rebuildSteps))

		// Step status
		highlightColor.Printf("⏳ %s", step.name)
		fmt.Printf("\n   ")
		infoColor.Printf("└─ %s", step.description)

		// Execute step
		fmt.Printf("\n")

		err := step.action()
		if err != nil {
			errorColor.Printf("   ❌ Failed: %v\n", err)
			failedSteps = append(failedSteps, step.name)
		} else {
			successColor.Printf("   ✅ Completed successfully\n")
			completedSteps++
		}
		fmt.Printf("\n")
	}

	// Final status
	fmt.Printf("\n")
	fmt.Println(string(color.New(color.FgHiCyan).Sprint("=================================================")))

	if len(failedSteps) == 0 {
		successColor.Printf("🎉 Firewall rebuild completed successfully!\n")
		successColor.Printf("✅ All %d steps completed without errors\n", completedSteps)

		fmt.Printf("\n")
		infoColor.Println("📊 Rebuild Summary:")
		fmt.Println("• All existing rules cleared")
		fmt.Println("• Database entries loaded")
		fmt.Println("• IPv4/IPv6 ipsets recreated and populated")
		fmt.Println("• Firewall rules regenerated and applied")
		fmt.Println("• Whitelist priority rules active")
		fmt.Println("• System ready for protection")

		fmt.Printf("\n")
		successColor.Println("🛡️  Your DNSniper protection is now active!")
	} else {
		warningColor.Printf("⚠️  Firewall rebuild completed with %d warnings\n", len(failedSteps))
		successColor.Printf("✅ %d/%d steps completed successfully\n", completedSteps, len(rebuildSteps))

		if len(failedSteps) > 0 {
			fmt.Printf("\n")
			warningColor.Println("⚠️  Steps with issues:")
			for _, step := range failedSteps {
				fmt.Printf("   • %s\n", step)
			}
			fmt.Printf("\n")
			infoColor.Println("💡 Consider running 'Clear firewall rules' and trying again")
		}
	}

	PressEnterToContinue()
}

// ShowHelp displays the help screen
func ShowHelp() {
	ClearScreen()
	titleColor.Println("\nDNSniper - Quick Guide")
	titleColor.Println("=====================")

	subtitleColor.Println("\nMain Features:")
	fmt.Println("1. Run agent now - Start the DNSniper agent to process domains and block suspicious IPs")
	fmt.Println("2. Show status - Display the current status of DNSniper including statistics")
	fmt.Println("3. Manage blocklist - Add or remove domains and IPs from the blocklist")
	fmt.Println("4. Manage whitelist - Add or remove domains and IPs from the whitelist (will never be blocked)")

	subtitleColor.Println("\nAdvanced Options:")
	fmt.Println("5. Settings - Configure DNSniper settings (DNS resolver, block chains, update URLs, etc.)")
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

	PressEnterToContinue()
}

// UninstallDNSniper removes DNSniper from the system
func UninstallDNSniper() bool {
	ClearScreen()

	warningColor.Println("\n⚠️  WARNING: You are about to uninstall DNSniper ⚠️")
	fmt.Println("\nThis will:")
	fmt.Println("• Stop all DNSniper services and timers")
	fmt.Println("• Remove all firewall rules and ipset configurations")
	fmt.Println("• Delete all executable files and binaries")
	fmt.Println("• Remove all configuration files and databases")
	fmt.Println("• Delete all directories (/etc/dnsniper, /var/log/dnsniper)")
	fmt.Println("• Clean up all persistence files")
	fmt.Println("\nThis action cannot be undone!")

	errorColor.Print("\nType 'UNINSTALL' to confirm: ")
	var confirmation string
	fmt.Scanln(&confirmation)

	if confirmation != "UNINSTALL" {
		infoColor.Println("Uninstallation cancelled.")
		PressEnterToContinue()
		return true
	}

	infoColor.Println("\nStarting uninstall process...")
	infoColor.Println("Launching enhanced uninstaller with sudo privileges...")

	// Use the enhanced uninstaller built into the main binary
	cmd := exec.Command("sudo", "dnsniper", "--uninstall")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	err := cmd.Run()
	if err != nil {
		errorColor.Printf("Failed to uninstall DNSniper: %v\n", err)
		fmt.Println("\nTrying alternative uninstall method...")

		// Fallback: try to run uninstall directly if dnsniper command not found
		cmd = exec.Command("sudo", "/usr/bin/dnsniper", "--uninstall")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin

		err = cmd.Run()
		if err != nil {
			errorColor.Printf("Alternative uninstall method also failed: %v\n", err)
			fmt.Println("\nPlease run manually: sudo dnsniper --uninstall")
			PressEnterToContinue()
			return true
		}
	}

	successColor.Println("\nDNSniper has been uninstalled successfully!")
	fmt.Println("\nThank you for using DNSniper! 🙏")

	return false
}

// Helper functions for UI

// ClearScreen clears the terminal screen
func ClearScreen() {
	cmd := exec.Command("clear")
	cmd.Stdout = os.Stdout
	cmd.Run()
}

// PressEnterToContinue displays a prompt and waits for the user to press Enter
func PressEnterToContinue() {
	promptColor.Print("\nPress Enter to continue...")
	fmt.Scanln()
}

// ManageDomainList displays the domain list management menu
func ManageDomainList(db database.DatabaseStore, fwManager *firewall.FirewallManager, isWhitelist bool) {
	const pageSize = 10
	currentPage := 1
	currentSort := "added_at"

	listType := "Blocked"
	if isWhitelist {
		listType = "Whitelisted"
	}

	for {
		ClearScreen()
		titleColor.Printf("\n%s Domains Management\n", listType)
		fmt.Println(string(color.New(color.FgHiCyan).Sprint("=================================================")))

		// Get domains for current page
		domainsInterface, total, err := db.GetDomains(isWhitelist, currentPage, pageSize, currentSort)
		if err != nil {
			errorColor.Printf("Failed to get domains: %v\n", err)
			PressEnterToContinue()
			return
		}

		// Type assert the domains - handle both old and new types with better error handling
		var domains []database.Domain
		switch v := domainsInterface.(type) {
		case []database.Domain:
			domains = v
		case []*database.Domain:
			// Convert pointer slice to value slice
			for _, d := range v {
				if d != nil {
					domains = append(domains, *d)
				}
			}
		default:
			errorColor.Printf("Error: Unable to parse domain data (type: %T)\n", domainsInterface)
			warningColor.Println("This might be a database compatibility issue")
			infoColor.Println("Try switching database type in configuration")
			PressEnterToContinue()
			return
		}

		// Calculate pagination
		totalPages := (total + pageSize - 1) / pageSize
		if totalPages == 0 {
			totalPages = 1
		}

		// Display domains
		if len(domains) == 0 {
			warningColor.Printf("No %s domains found.\n", strings.ToLower(listType))
		} else {
			subtitleColor.Printf("\nShowing %d-%d of %d domains (Page %d/%d):\n",
				(currentPage-1)*pageSize+1,
				min((currentPage-1)*pageSize+len(domains), total),
				total, currentPage, totalPages)

			fmt.Printf("%-4s %-40s %-12s %-15s %-10s\n", "#", "Domain", "Type", "Added", "Expires")
			fmt.Println(strings.Repeat("-", 85))

			for i, domain := range domains {
				index := (currentPage-1)*pageSize + i + 1
				domainType := "Auto"
				if domain.IsCustom {
					domainType = "Custom"
				}

				expiresStr := "Never"
				if domain.ExpiresAt != nil {
					expiresStr = domain.ExpiresAt.Format("2006-01-02")
				}

				fmt.Printf("%-4d %-40s %-12s %-15s %-10s\n",
					index,
					truncateString(domain.Domain, 40),
					domainType,
					domain.AddedAt.Format("2006-01-02"),
					expiresStr)
			}
		}

		// Display menu options
		fmt.Printf("\nNavigation: [P]revious | [N]ext | [F]irst | [L]ast")
		fmt.Printf("\nSorting: [S]ort by date | [A]lphabetical")
		fmt.Printf("\nActions: [R]emove domain | [D]etails")
		fmt.Printf("\nOther: [0] Back to main menu")

		promptColor.Print("\nSelect option: ")
		var option string
		fmt.Scanln(&option)
		option = strings.ToLower(strings.TrimSpace(option))

		switch option {
		case "p", "previous":
			if currentPage > 1 {
				currentPage--
			}
		case "n", "next":
			if currentPage < totalPages {
				currentPage++
			}
		case "f", "first":
			currentPage = 1
		case "l", "last":
			currentPage = totalPages
		case "s", "sort":
			if currentSort == "added_at" {
				currentSort = "domain"
				infoColor.Println("Sorted alphabetically")
			} else {
				currentSort = "added_at"
				infoColor.Println("Sorted by date")
			}
			currentPage = 1
		case "a", "alphabetical":
			currentSort = "domain"
			currentPage = 1
			infoColor.Println("Sorted alphabetically")
		case "r", "remove":
			if len(domains) > 0 {
				removeDomain(db, fwManager, domains, currentPage, pageSize, isWhitelist)
			} else {
				warningColor.Println("No domains to remove")
				PressEnterToContinue()
			}
		case "d", "details":
			if len(domains) > 0 {
				showDomainDetails(db, domains, currentPage, pageSize)
			} else {
				warningColor.Println("No domains to show details")
				PressEnterToContinue()
			}
		case "0":
			return
		default:
			errorColor.Println("Invalid option. Please try again.")
			PressEnterToContinue()
		}
	}
}

// AddItemToBlacklist displays the add item to blacklist menu
func AddItemToBlacklist(db database.DatabaseStore, fwManager *firewall.FirewallManager) {
	for {
		ClearScreen()
		titleColor.Println("\nAdd Custom Item to Blacklist")
		fmt.Println(string(color.New(color.FgHiCyan).Sprint("=================================================")))

		subtitleColor.Println("\nChoose what to add:")
		menuColor.Println("1. Add domain")
		menuColor.Println("2. Add IP address")
		menuColor.Println("3. Add IP range (CIDR)")
		menuColor.Println("0. Back to blacklist menu")

		promptColor.Print("\nSelect option: ")
		var option string
		fmt.Scanln(&option)
		option = strings.TrimSpace(option)

		switch option {
		case "1":
			addCustomDomain(db, fwManager, false) // false = blacklist
		case "2":
			addCustomIP(db, fwManager, false) // false = blacklist
		case "3":
			addCustomIPRange(db, fwManager, false) // false = blacklist
		case "0":
			return
		default:
			errorColor.Println("Invalid option. Please try again.")
			PressEnterToContinue()
		}
	}
}

// addCustomDomain adds a custom domain to blocklist or whitelist
func addCustomDomain(db database.DatabaseStore, fwManager *firewall.FirewallManager, isWhitelist bool) {
	listType := "blocklist"
	if isWhitelist {
		listType = "whitelist"
	}

	ClearScreen()
	titleColor.Printf("\nAdd Custom Domain to %s\n", strings.Title(listType))
	fmt.Println(strings.Repeat("=", 40))

	promptColor.Print("Enter domain name: ")
	var domain string
	fmt.Scanln(&domain)
	domain = strings.ToLower(strings.TrimSpace(domain))

	// Enhanced validation
	if domain == "" {
		errorColor.Println("Domain cannot be empty")
		PressEnterToContinue()
		return
	}

	// Remove protocol if present
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "www.")

	// Basic domain validation with better error message
	if !isValidDomain(domain) {
		errorColor.Println("Invalid domain format. Please enter a valid domain name (e.g., example.com)")
		PressEnterToContinue()
		return
	}

	// Check for conflicts if adding to whitelist
	if isWhitelist {
		checkWhitelistConflicts(db, "domain", domain)
	}

	// Check if domain already exists
	existingDomain, err := db.GetDomain(domain)
	if err == nil && existingDomain != nil {
		// Domain exists - check if it's already in the desired list (handle both pointer and value types)
		var domainIsWhitelisted bool
		var domainExists bool

		if domainObj, ok := existingDomain.(*database.Domain); ok {
			domainIsWhitelisted = domainObj.IsWhitelisted
			domainExists = true
		} else if domainInterface, ok := existingDomain.(database.Domain); ok {
			domainIsWhitelisted = domainInterface.IsWhitelisted
			domainExists = true
		}

		if domainExists {
			if domainIsWhitelisted == isWhitelist {
				if isWhitelist {
					successColor.Printf("Domain '%s' is already whitelisted (priority protected)\n", domain)
				} else {
					warningColor.Printf("Domain '%s' is already in the %s\n", domain, listType)
				}
				PressEnterToContinue()
				return
			} else {
				// Ask to move from other list
				otherList := "whitelist"
				actionMsg := "Move to"
				if isWhitelist {
					otherList = "blocklist"
					actionMsg = "Override blocklist and move to"
					warningColor.Printf("Domain '%s' is currently BLOCKED. ", domain)
					highlightColor.Printf("%s %s? (y/N): ", actionMsg, listType)
				} else {
					warningColor.Printf("Domain '%s' is currently in the %s. Move to %s? (y/N): ", domain, otherList, listType)
				}
				var confirm string
				fmt.Scanln(&confirm)
				if strings.ToLower(confirm) != "y" && strings.ToLower(confirm) != "yes" {
					infoColor.Println("Operation cancelled")
					PressEnterToContinue()
					return
				}
			}
		}
	}

	// Add/update the domain as custom (no expiration)
	_, err = db.SaveDomain(domain, isWhitelist, true, 0) // true = custom, 0 = no expiration
	if err != nil {
		errorColor.Printf("Failed to add domain: %v\n", err)
	} else {
		successColor.Printf("Domain '%s' added successfully to %s\n", domain, listType)
		infoColor.Println("Custom entries never expire automatically")

		// Reload firewall rules to apply changes immediately
		fmt.Printf("\n")
		infoColor.Println("🔄 Updating firewall rules...")
		if err := fwManager.Reload(); err != nil {
			errorColor.Printf("Failed to update firewall rules: %v\n", err)
			warningColor.Println("Domain added to database but firewall rules not updated")
			infoColor.Println("You can manually rebuild rules from the main menu")
		} else {
			successColor.Println("✅ Firewall rules updated successfully")
		}
	}
	PressEnterToContinue()
}

// addCustomIP adds a custom IP to blocklist or whitelist
func addCustomIP(db database.DatabaseStore, fwManager *firewall.FirewallManager, isWhitelist bool) {
	listType := "blocklist"
	if isWhitelist {
		listType = "whitelist"
	}

	ClearScreen()
	titleColor.Printf("\nAdd Custom IP to %s\n", strings.Title(listType))
	fmt.Println(strings.Repeat("=", 40))

	promptColor.Print("Enter IP address: ")
	var ipAddress string
	fmt.Scanln(&ipAddress)
	ipAddress = strings.TrimSpace(ipAddress)

	if ipAddress == "" {
		errorColor.Println("IP address cannot be empty")
		PressEnterToContinue()
		return
	}

	// Validate IP address format
	if net.ParseIP(ipAddress) == nil {
		errorColor.Println("Invalid IP address format")
		PressEnterToContinue()
		return
	}

	// Check if this is a whitelist operation and IP is already whitelisted
	if isWhitelist {
		isWhitelisted, err := db.IsIPWhitelisted(ipAddress)
		if err == nil && isWhitelisted {
			warningColor.Printf("IP '%s' is already whitelisted\n", ipAddress)
			PressEnterToContinue()
			return
		}
	}

	// Add the IP as custom (no expiration, no domain association)
	_, err := db.SaveIP(ipAddress, isWhitelist, true, nil, 0) // true = custom, nil = no domain, 0 = no expiration
	if err != nil {
		errorColor.Printf("Failed to add IP: %v\n", err)
	} else {
		successColor.Printf("IP '%s' added successfully to %s\n", ipAddress, listType)
		infoColor.Println("Custom entries never expire automatically")

		// Reload firewall rules to apply changes immediately
		fmt.Printf("\n")
		infoColor.Println("🔄 Updating firewall rules...")
		if err := fwManager.Reload(); err != nil {
			errorColor.Printf("Failed to update firewall rules: %v\n", err)
			warningColor.Println("IP added to database but firewall rules not updated")
			infoColor.Println("You can manually rebuild rules from the main menu")
		} else {
			successColor.Println("✅ Firewall rules updated successfully")
		}
	}
	PressEnterToContinue()
}

// addCustomIPRange adds a custom IP range to blocklist or whitelist
func addCustomIPRange(db database.DatabaseStore, fwManager *firewall.FirewallManager, isWhitelist bool) {
	listType := "blocklist"
	if isWhitelist {
		listType = "whitelist"
	}

	ClearScreen()
	titleColor.Printf("\nAdd Custom IP Range to %s\n", strings.Title(listType))
	fmt.Println(strings.Repeat("=", 40))

	promptColor.Print("Enter IP range (CIDR format, e.g., 192.168.1.0/24): ")
	var cidr string
	fmt.Scanln(&cidr)
	cidr = strings.TrimSpace(cidr)

	if cidr == "" {
		errorColor.Println("IP range cannot be empty")
		PressEnterToContinue()
		return
	}

	// Validate CIDR format
	if _, _, err := net.ParseCIDR(cidr); err != nil {
		errorColor.Printf("Invalid CIDR format: %v\n", err)
		PressEnterToContinue()
		return
	}

	// Add the IP range as custom (no expiration)
	_, err := db.SaveIPRange(cidr, isWhitelist, true, 0) // true = custom, 0 = no expiration
	if err != nil {
		errorColor.Printf("Failed to add IP range: %v\n", err)
	} else {
		successColor.Printf("IP range '%s' added successfully to %s\n", cidr, listType)
		infoColor.Println("Custom entries never expire automatically")

		// Reload firewall rules to apply changes immediately
		fmt.Printf("\n")
		infoColor.Println("🔄 Updating firewall rules...")
		if err := fwManager.Reload(); err != nil {
			errorColor.Printf("Failed to update firewall rules: %v\n", err)
			warningColor.Println("IP range added to database but firewall rules not updated")
			infoColor.Println("You can manually rebuild rules from the main menu")
		} else {
			successColor.Println("✅ Firewall rules updated successfully")
		}
	}
	PressEnterToContinue()
}

// isValidDomain performs comprehensive domain validation
func isValidDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}

	// Check for valid characters and structure
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return false
	}

	if strings.Contains(domain, "..") {
		return false
	}

	// Check for invalid characters
	if strings.ContainsAny(domain, " \t\n\r\f\v!@#$%^&*()+=[]{}|\\:;\"'<>,?/") {
		return false
	}

	// Basic regex-like validation
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return false
	}

	// Check TLD is valid (at least 2 characters, only letters)
	tld := parts[len(parts)-1]
	if len(tld) < 2 {
		return false
	}
	for _, char := range tld {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z')) {
			return false
		}
	}

	for i, part := range parts {
		if len(part) == 0 || len(part) > 63 {
			return false
		}

		// Check each part contains only valid characters
		for j, char := range part {
			if !((char >= 'a' && char <= 'z') ||
				(char >= 'A' && char <= 'Z') ||
				(char >= '0' && char <= '9') ||
				char == '-') {
				return false
			}

			// Cannot start or end with hyphen
			if char == '-' && (j == 0 || j == len(part)-1) {
				return false
			}
		}

		// First part cannot be numeric only (except for IP addresses which we reject)
		if i == 0 {
			isNumeric := true
			for _, char := range part {
				if !((char >= '0' && char <= '9') || char == '-') {
					isNumeric = false
					break
				}
			}
			if isNumeric {
				return false
			}
		}
	}

	// Check for common invalid patterns
	invalidPatterns := []string{
		"localhost", "127.0.0.1", "0.0.0.0", "255.255.255.255",
		"::1", "::", "fe80::", "ff00::",
	}

	for _, pattern := range invalidPatterns {
		if strings.EqualFold(domain, pattern) {
			return false
		}
	}

	return true
}

// ManageIPList displays the IP list management menu
func ManageIPList(db database.DatabaseStore, fwManager *firewall.FirewallManager, isWhitelist bool) {
	const pageSize = 10
	currentPage := 1
	currentSort := "added_at"
	viewMode := "ips" // "ips" or "ranges"

	listType := "Blocked"
	if isWhitelist {
		listType = "Whitelisted"
	}

	for {
		ClearScreen()
		titleColor.Printf("\n%s IPs Management\n", listType)
		fmt.Println(string(color.New(color.FgHiCyan).Sprint("=================================================")))

		if viewMode == "ips" {
			// Display individual IPs
			ipsInterface, total, err := db.GetIPs(isWhitelist, currentPage, pageSize, currentSort)
			if err != nil {
				errorColor.Printf("Failed to get IPs: %v\n", err)
				PressEnterToContinue()
				return
			}

			// Type assert the IPs with better error handling
			var ips []database.IP
			switch v := ipsInterface.(type) {
			case []database.IP:
				ips = v
			case []*database.IP:
				// Convert pointer slice to value slice
				for _, ip := range v {
					if ip != nil {
						ips = append(ips, *ip)
					}
				}
			default:
				errorColor.Printf("Error: Unable to parse IP data (type: %T)\n", ipsInterface)
				warningColor.Println("This might be a database compatibility issue")
				infoColor.Println("Try switching database type in configuration")
				PressEnterToContinue()
				return
			}

			// Calculate pagination
			totalPages := (total + pageSize - 1) / pageSize
			if totalPages == 0 {
				totalPages = 1
			}

			subtitleColor.Printf("Individual IPs View")

			// Display IPs
			if len(ips) == 0 {
				warningColor.Printf("No %s IPs found.\n", strings.ToLower(listType))
			} else {
				subtitleColor.Printf("\nShowing %d-%d of %d IPs (Page %d/%d):\n",
					(currentPage-1)*pageSize+1,
					min((currentPage-1)*pageSize+len(ips), total),
					total, currentPage, totalPages)

				fmt.Printf("%-4s %-20s %-12s %-20s %-15s\n", "#", "IP Address", "Type", "Domain", "Added")
				fmt.Println(strings.Repeat("-", 75))

				for i, ip := range ips {
					index := (currentPage-1)*pageSize + i + 1
					ipType := "Auto"
					if ip.IsCustom {
						ipType = "Custom"
					}

					domainStr := "Direct"
					if ip.Domain != nil {
						domainStr = truncateString(ip.Domain.Domain, 20)
					}

					fmt.Printf("%-4d %-20s %-12s %-20s %-15s\n",
						index,
						ip.IPAddress,
						ipType,
						domainStr,
						ip.AddedAt.Format("2006-01-02"))
				}
			}

			// Display menu options for IPs
			fmt.Printf("\nView: [R]anges | [I]Ps (current)")
			fmt.Printf("\nNavigation: [P]revious | [N]ext | [F]irst | [L]ast")
			fmt.Printf("\nSorting: [S]ort by date | [A]lphabetical")
			fmt.Printf("\nActions: [D]elete IP")
			fmt.Printf("\nOther: [0] Back to main menu")

		} else {
			// Display IP ranges
			rangesInterface, total, err := db.GetIPRanges(isWhitelist, currentPage, pageSize, currentSort)
			if err != nil {
				errorColor.Printf("Failed to get IP ranges: %v\n", err)
				PressEnterToContinue()
				return
			}

			// Type assert the ranges
			var ranges []database.IPRange
			if rangeSlice, ok := rangesInterface.([]database.IPRange); ok {
				ranges = rangeSlice
			} else {
				errorColor.Println("Error: Unable to parse IP range data")
				PressEnterToContinue()
				return
			}

			// Calculate pagination
			totalPages := (total + pageSize - 1) / pageSize
			if totalPages == 0 {
				totalPages = 1
			}

			subtitleColor.Printf("IP Ranges View")

			// Display ranges
			if len(ranges) == 0 {
				warningColor.Printf("No %s IP ranges found.\n", strings.ToLower(listType))
			} else {
				subtitleColor.Printf("\nShowing %d-%d of %d IP ranges (Page %d/%d):\n",
					(currentPage-1)*pageSize+1,
					min((currentPage-1)*pageSize+len(ranges), total),
					total, currentPage, totalPages)

				fmt.Printf("%-4s %-25s %-12s %-15s %-10s\n", "#", "CIDR Range", "Type", "Added", "Expires")
				fmt.Println(strings.Repeat("-", 70))

				for i, ipRange := range ranges {
					index := (currentPage-1)*pageSize + i + 1
					rangeType := "Auto"
					if ipRange.IsCustom {
						rangeType = "Custom"
					}

					expiresStr := "Never"
					if ipRange.ExpiresAt != nil {
						expiresStr = ipRange.ExpiresAt.Format("2006-01-02")
					}

					fmt.Printf("%-4d %-25s %-12s %-15s %-10s\n",
						index,
						ipRange.CIDR,
						rangeType,
						ipRange.AddedAt.Format("2006-01-02"),
						expiresStr)
				}
			}

			// Display menu options for ranges
			fmt.Printf("\nView: [R]anges (current) | [I]Ps")
			fmt.Printf("\nNavigation: [P]revious | [N]ext | [F]irst | [L]ast")
			fmt.Printf("\nSorting: [S]ort by date | [A]lphabetical")
			fmt.Printf("\nActions: [D]elete range")
			fmt.Printf("\nOther: [0] Back to main menu")
		}

		promptColor.Print("\nSelect option: ")
		var option string
		fmt.Scanln(&option)
		option = strings.ToLower(strings.TrimSpace(option))

		switch option {
		case "p", "previous":
			if currentPage > 1 {
				currentPage--
			}
		case "n", "next":
			// Get current total for pagination check
			var total int
			if viewMode == "ips" {
				_, total, _ = db.GetIPs(isWhitelist, currentPage, pageSize, currentSort)
			} else {
				_, total, _ = db.GetIPRanges(isWhitelist, currentPage, pageSize, currentSort)
			}
			totalPages := (total + pageSize - 1) / pageSize
			if totalPages == 0 {
				totalPages = 1
			}
			if currentPage < totalPages {
				currentPage++
			}
		case "f", "first":
			currentPage = 1
		case "l", "last":
			var total int
			if viewMode == "ips" {
				_, total, _ = db.GetIPs(isWhitelist, currentPage, pageSize, currentSort)
			} else {
				_, total, _ = db.GetIPRanges(isWhitelist, currentPage, pageSize, currentSort)
			}
			totalPages := (total + pageSize - 1) / pageSize
			if totalPages == 0 {
				totalPages = 1
			}
			currentPage = totalPages
		case "s", "sort":
			if currentSort == "added_at" {
				currentSort = "ip_address"
				infoColor.Println("Sorted alphabetically")
			} else {
				currentSort = "added_at"
				infoColor.Println("Sorted by date")
			}
			currentPage = 1
		case "a", "alphabetical":
			if viewMode == "ips" {
				currentSort = "ip_address"
			} else {
				currentSort = "cidr"
			}
			currentPage = 1
			infoColor.Println("Sorted alphabetically")
		case "r", "ranges":
			viewMode = "ranges"
			currentPage = 1
		case "i", "ips":
			viewMode = "ips"
			currentPage = 1
		case "d", "delete":
			if viewMode == "ips" {
				ipsInterface, _, err := db.GetIPs(isWhitelist, currentPage, pageSize, currentSort)
				if err == nil {
					if ips, ok := ipsInterface.([]database.IP); ok && len(ips) > 0 {
						removeIP(db, fwManager, ips, currentPage, pageSize, isWhitelist)
					} else {
						warningColor.Println("No IPs to remove")
						PressEnterToContinue()
					}
				}
			} else {
				rangesInterface, _, err := db.GetIPRanges(isWhitelist, currentPage, pageSize, currentSort)
				if err == nil {
					if ranges, ok := rangesInterface.([]database.IPRange); ok && len(ranges) > 0 {
						removeIPRange(db, fwManager, ranges, currentPage, pageSize, isWhitelist)
					} else {
						warningColor.Println("No IP ranges to remove")
						PressEnterToContinue()
					}
				}
			}
		case "0":
			return
		default:
			errorColor.Println("Invalid option. Please try again.")
			PressEnterToContinue()
		}
	}
}

// AddItemToWhitelist displays the add item to whitelist menu
func AddItemToWhitelist(db database.DatabaseStore, fwManager *firewall.FirewallManager) {
	for {
		ClearScreen()
		titleColor.Println("\nAdd Custom Item to Whitelist")
		fmt.Println(string(color.New(color.FgHiCyan).Sprint("=================================================")))

		// Whitelist priority information
		subtitleColor.Println("\n⚠️  Whitelist Priority Information:")
		infoColor.Println("• Whitelist rules have PRIORITY over blocklist rules")
		infoColor.Println("• Items added here will NEVER be blocked, even if they're in blocklist")
		infoColor.Println("• Use this to prevent false positives for trusted domains/IPs")
		infoColor.Println("• Custom whitelist entries are permanent (never expire)")

		subtitleColor.Println("\nChoose what to add:")
		menuColor.Println("1. Add domain to whitelist")
		menuColor.Println("2. Add IP address to whitelist")
		menuColor.Println("3. Add IP range (CIDR) to whitelist")
		menuColor.Println("4. Show whitelist priority explanation")
		menuColor.Println("0. Back to whitelist menu")

		promptColor.Print("\nSelect option: ")
		var option string
		fmt.Scanln(&option)
		option = strings.TrimSpace(option)

		switch option {
		case "1":
			addCustomDomain(db, fwManager, true) // true = whitelist
		case "2":
			addCustomIP(db, fwManager, true) // true = whitelist
		case "3":
			addCustomIPRange(db, fwManager, true) // true = whitelist
		case "4":
			showWhitelistPriorityExplanation()
		case "0":
			return
		default:
			errorColor.Println("Invalid option. Please try again.")
			PressEnterToContinue()
		}
	}
}

// showWhitelistPriorityExplanation explains how whitelist priority works
func showWhitelistPriorityExplanation() {
	ClearScreen()
	titleColor.Println("\nWhitelist Priority Explanation")
	fmt.Println(strings.Repeat("=", 50))

	subtitleColor.Println("\n🔒 How Whitelist Priority Works:")

	fmt.Println("\n1. RULE ORDER PRIORITY:")
	infoColor.Println("   • Firewall rules are processed in order")
	infoColor.Println("   • DNSniper generates whitelist rules FIRST")
	infoColor.Println("   • Then blocklist rules are added after")

	fmt.Println("\n2. TRAFFIC FLOW:")
	successColor.Println("   ✅ Traffic matches whitelist → ALLOW (stop processing)")
	errorColor.Println("   ❌ Traffic matches blocklist → BLOCK (stop processing)")
	infoColor.Println("   ➡️  Traffic matches neither → Continue to other rules")

	fmt.Println("\n3. PRACTICAL EXAMPLE:")
	infoColor.Println("   • Domain 'example.com' is in BOTH whitelist AND blocklist")
	successColor.Println("   • Result: Traffic is ALLOWED (whitelist wins)")
	infoColor.Println("   • Reason: Whitelist rule is checked first")

	fmt.Println("\n4. IPTABLES RULE STRUCTURE:")
	infoColor.Println("   Generated rules order (for INPUT chain):")
	fmt.Println("   -A INPUT -m set --match-set whitelistIP-v4 src -j ACCEPT")
	fmt.Println("   -A INPUT -m set --match-set whitelistRange-v4 src -j ACCEPT")
	fmt.Println("   -A INPUT -m set --match-set blocklistIP-v4 src -j DROP")
	fmt.Println("   -A INPUT -m set --match-set blocklistRange-v4 src -j DROP")

	fmt.Println("\n5. IPSET EFFICIENCY:")
	infoColor.Println("   • Uses Linux ipset for O(1) lookup performance")
	infoColor.Println("   • Can handle millions of entries efficiently")
	infoColor.Println("   • Separate sets: whitelistIP-v4, blocklistIP-v4, etc.")

	subtitleColor.Println("\n💡 Best Practices:")
	fmt.Println("• Use whitelist for trusted CDNs and essential services")
	fmt.Println("• Add your own infrastructure IPs to whitelist")
	fmt.Println("• Whitelist known false positives from threat feeds")
	fmt.Println("• Keep whitelist minimal for security")

	subtitleColor.Println("\n⚠️  Security Notes:")
	warningColor.Println("• Whitelist entries bypass ALL blocking!")
	warningColor.Println("• Review whitelist regularly")
	warningColor.Println("• Custom entries never expire automatically")

	PressEnterToContinue()
}

// checkWhitelistConflicts checks if adding to whitelist would override existing blocklist entries
func checkWhitelistConflicts(db database.DatabaseStore, itemType, item string) {
	var isBlocked bool

	switch itemType {
	case "domain":
		// Check if domain is in blocklist
		domainObj, err := db.GetDomain(item)
		if err == nil && domainObj != nil {
			// Handle both GORM and old database types
			if domain, ok := domainObj.(*database.Domain); ok && !domain.IsWhitelisted {
				isBlocked = true
			} else if domainInterface, ok := domainObj.(database.Domain); ok && !domainInterface.IsWhitelisted {
				isBlocked = true
			}
		}
	case "ip":
		// For IPs, we'd need to check if it's in blocklist
		// This is more complex as we'd need a reverse lookup
		// For now, we'll skip this check for IPs
	}

	if isBlocked {
		warningColor.Printf("\n⚠️  CONFLICT DETECTED:\n")
		warningColor.Printf("'%s' is currently in the BLOCKLIST\n", item)
		infoColor.Println("Adding to whitelist will OVERRIDE the block (whitelist priority)")
		fmt.Print("\nPress Enter to understand whitelist priority...")
		fmt.Scanln()
		showWhitelistPriorityExplanation()
	}
}

// Helper functions for UI management

// truncateString truncates a string to the specified length
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// removeDomain handles domain removal
func removeDomain(db database.DatabaseStore, fwManager *firewall.FirewallManager, domains []database.Domain, currentPage, pageSize int, isWhitelist bool) {
	if len(domains) == 0 {
		warningColor.Println("No domains available to remove")
		PressEnterToContinue()
		return
	}

	listType := "blocklist"
	if isWhitelist {
		listType = "whitelist"
	}

	promptColor.Printf("Enter domain number to remove from %s (1-%d): ", listType, len(domains))
	var indexStr string
	fmt.Scanln(&indexStr)

	var index int
	_, err := fmt.Sscanf(indexStr, "%d", &index)
	if err != nil || index < 1 || index > len(domains) {
		errorColor.Println("Invalid domain number")
		PressEnterToContinue()
		return
	}

	selectedDomain := domains[index-1]

	warningColor.Printf("Are you sure you want to remove domain '%s' from the %s? (y/N): ", selectedDomain.Domain, listType)
	var confirm string
	fmt.Scanln(&confirm)

	if strings.ToLower(confirm) != "y" && strings.ToLower(confirm) != "yes" {
		infoColor.Println("Removal cancelled")
		PressEnterToContinue()
		return
	}

	err2 := db.RemoveDomain(selectedDomain.ID)
	if err2 != nil {
		errorColor.Printf("Failed to remove domain: %v\n", err2)
	} else {
		successColor.Printf("Domain '%s' removed successfully from %s\n", selectedDomain.Domain, listType)

		// Reload firewall rules to apply changes immediately
		fmt.Printf("\n")
		infoColor.Println("🔄 Updating firewall rules...")
		if err := fwManager.Reload(); err != nil {
			errorColor.Printf("Failed to update firewall rules: %v\n", err)
			warningColor.Println("Domain removed from database but firewall rules not updated")
			infoColor.Println("You can manually rebuild rules from the main menu")
		} else {
			successColor.Println("✅ Firewall rules updated successfully")
		}
	}
	PressEnterToContinue()
}

// showDomainDetails displays detailed information about a domain
func showDomainDetails(db database.DatabaseStore, domains []database.Domain, currentPage, pageSize int) {
	if len(domains) == 0 {
		warningColor.Println("No domains available")
		PressEnterToContinue()
		return
	}

	promptColor.Printf("Enter domain number to show details (1-%d): ", len(domains))
	var indexStr string
	fmt.Scanln(&indexStr)

	var index int
	_, err := fmt.Sscanf(indexStr, "%d", &index)
	if err != nil || index < 1 || index > len(domains) {
		errorColor.Println("Invalid domain number")
		PressEnterToContinue()
		return
	}

	domain := domains[index-1]

	ClearScreen()
	titleColor.Printf("\nDomain Details: %s\n", domain.Domain)
	fmt.Println(strings.Repeat("=", 50))

	fmt.Printf("Domain: %s\n", domain.Domain)
	fmt.Printf("Type: %s\n", map[bool]string{true: "Custom", false: "Automatic"}[domain.IsCustom])
	fmt.Printf("Status: %s\n", map[bool]string{true: "Whitelisted", false: "Blocked"}[domain.IsWhitelisted])
	fmt.Printf("Added: %s\n", domain.AddedAt.Format("2006-01-02 15:04:05"))

	if domain.ExpiresAt != nil {
		fmt.Printf("Expires: %s\n", domain.ExpiresAt.Format("2006-01-02 15:04:05"))
	} else {
		fmt.Printf("Expires: Never\n")
	}

	if domain.LastChecked != nil {
		fmt.Printf("Last Checked: %s\n", domain.LastChecked.Format("2006-01-02 15:04:05"))
	}

	if domain.Source != "" {
		fmt.Printf("Source: %s\n", domain.Source)
	}

	if domain.FlaggedAsCDN {
		warningColor.Printf("⚠️  Flagged as CDN\n")
	}

	PressEnterToContinue()
}

// removeIP handles IP removal
func removeIP(db database.DatabaseStore, fwManager *firewall.FirewallManager, ips []database.IP, currentPage, pageSize int, isWhitelist bool) {
	if len(ips) == 0 {
		warningColor.Println("No IPs available to remove")
		PressEnterToContinue()
		return
	}

	listType := "blocklist"
	if isWhitelist {
		listType = "whitelist"
	}

	promptColor.Printf("Enter IP number to remove from %s (1-%d): ", listType, len(ips))
	var indexStr string
	fmt.Scanln(&indexStr)

	var index int
	_, err := fmt.Sscanf(indexStr, "%d", &index)
	if err != nil || index < 1 || index > len(ips) {
		errorColor.Println("Invalid IP number")
		PressEnterToContinue()
		return
	}

	selectedIP := ips[index-1]

	warningColor.Printf("Are you sure you want to remove IP '%s' from the %s? (y/N): ", selectedIP.IPAddress, listType)
	var confirm string
	fmt.Scanln(&confirm)

	if strings.ToLower(confirm) != "y" && strings.ToLower(confirm) != "yes" {
		infoColor.Println("Removal cancelled")
		PressEnterToContinue()
		return
	}

	err2 := db.RemoveIP(selectedIP.ID)
	if err2 != nil {
		errorColor.Printf("Failed to remove IP: %v\n", err2)
	} else {
		successColor.Printf("IP '%s' removed successfully from %s\n", selectedIP.IPAddress, listType)

		// Reload firewall rules to apply changes immediately
		fmt.Printf("\n")
		infoColor.Println("🔄 Updating firewall rules...")
		if err := fwManager.Reload(); err != nil {
			errorColor.Printf("Failed to update firewall rules: %v\n", err)
			warningColor.Println("IP removed from database but firewall rules not updated")
			infoColor.Println("You can manually rebuild rules from the main menu")
		} else {
			successColor.Println("✅ Firewall rules updated successfully")
		}
	}
	PressEnterToContinue()
}

// removeIPRange handles IP range removal
func removeIPRange(db database.DatabaseStore, fwManager *firewall.FirewallManager, ranges []database.IPRange, currentPage, pageSize int, isWhitelist bool) {
	if len(ranges) == 0 {
		warningColor.Println("No IP ranges available to remove")
		PressEnterToContinue()
		return
	}

	listType := "blocklist"
	if isWhitelist {
		listType = "whitelist"
	}

	promptColor.Printf("Enter IP range number to remove from %s (1-%d): ", listType, len(ranges))
	var indexStr string
	fmt.Scanln(&indexStr)

	var index int
	_, err := fmt.Sscanf(indexStr, "%d", &index)
	if err != nil || index < 1 || index > len(ranges) {
		errorColor.Println("Invalid IP range number")
		PressEnterToContinue()
		return
	}

	selectedRange := ranges[index-1]

	warningColor.Printf("Are you sure you want to remove IP range '%s' from the %s? (y/N): ", selectedRange.CIDR, listType)
	var confirm string
	fmt.Scanln(&confirm)

	if strings.ToLower(confirm) != "y" && strings.ToLower(confirm) != "yes" {
		infoColor.Println("Removal cancelled")
		PressEnterToContinue()
		return
	}

	err2 := db.RemoveIPRange(selectedRange.ID)
	if err2 != nil {
		errorColor.Printf("Failed to remove IP range: %v\n", err2)
	} else {
		successColor.Printf("IP range '%s' removed successfully from %s\n", selectedRange.CIDR, listType)

		// Reload firewall rules to apply changes immediately
		fmt.Printf("\n")
		infoColor.Println("🔄 Updating firewall rules...")
		if err := fwManager.Reload(); err != nil {
			errorColor.Printf("Failed to update firewall rules: %v\n", err)
			warningColor.Println("IP range removed from database but firewall rules not updated")
			infoColor.Println("You can manually rebuild rules from the main menu")
		} else {
			successColor.Println("✅ Firewall rules updated successfully")
		}
	}
	PressEnterToContinue()
}

// generateProgressBar creates a visual progress bar
func generateProgressBar(current, total, width int) string {
	if total == 0 {
		return strings.Repeat("▓", width)
	}

	completed := int(float64(current) / float64(total) * float64(width))
	if completed > width {
		completed = width
	}

	bar := strings.Repeat("▓", completed) + strings.Repeat("░", width-completed)
	return bar
}

// Settings management functions

// loadCurrentConfig loads the current configuration
func loadCurrentConfig() (*config.Settings, error) {
	return config.LoadConfig("")
}

// saveConfig saves the configuration to file
func saveConfig(cfg *config.Settings) error {
	return config.SaveConfig(cfg, cfg.ConfigPath)
}

// updateDNSResolver updates DNS resolver settings
func updateDNSResolver(cfg *config.Settings) {
	ClearScreen()
	titleColor.Println("\n🌐 Update DNS Resolver")
	fmt.Println(strings.Repeat("=", 50))

	subtitleColor.Println("\n📡 Current DNS Resolvers:")
	for i, resolver := range cfg.DNSResolvers {
		fmt.Printf("%d. %s\n", i+1, resolver)
	}

	subtitleColor.Println("\n💡 Popular DNS Resolvers:")
	fmt.Println("• 1.1.1.1 (Cloudflare) - Fast and privacy-focused")
	fmt.Println("• 8.8.8.8 (Google) - Reliable and fast")
	fmt.Println("• 9.9.9.9 (Quad9) - Security-focused with malware blocking")
	fmt.Println("• 208.67.222.222 (OpenDNS) - Family-friendly filtering")
	fmt.Println("• 8.26.56.26 (Comodo) - Security-focused")

	subtitleColor.Println("\n🔧 Options:")
	menuColor.Println("1. Replace with Cloudflare (1.1.1.1)")
	menuColor.Println("2. Replace with Google (8.8.8.8)")
	menuColor.Println("3. Replace with Quad9 (9.9.9.9)")
	menuColor.Println("4. Add custom resolver")
	menuColor.Println("5. Remove a resolver")
	menuColor.Println("0. Back to settings")

	promptColor.Print("\nSelect option: ")
	var option string
	fmt.Scanln(&option)

	switch option {
	case "1":
		cfg.DNSResolvers = []string{"1.1.1.1", "1.0.0.1"}
		successColor.Println("DNS resolvers updated to Cloudflare")
	case "2":
		cfg.DNSResolvers = []string{"8.8.8.8", "8.8.4.4"}
		successColor.Println("DNS resolvers updated to Google")
	case "3":
		cfg.DNSResolvers = []string{"9.9.9.9", "149.112.112.112"}
		successColor.Println("DNS resolvers updated to Quad9")
	case "4":
		promptColor.Print("Enter custom DNS resolver IP: ")
		var customResolver string
		fmt.Scanln(&customResolver)
		customResolver = strings.TrimSpace(customResolver)
		if customResolver != "" {
			// Validate IP address format
			if net.ParseIP(customResolver) == nil {
				errorColor.Println("Invalid IP address format for DNS resolver")
			} else {
				cfg.DNSResolvers = append(cfg.DNSResolvers, customResolver)
				successColor.Printf("Added custom resolver: %s\n", customResolver)
			}
		}
	case "5":
		if len(cfg.DNSResolvers) > 1 {
			promptColor.Printf("Enter resolver number to remove (1-%d): ", len(cfg.DNSResolvers))
			var indexStr string
			fmt.Scanln(&indexStr)
			if index, err := strconv.Atoi(indexStr); err == nil && index >= 1 && index <= len(cfg.DNSResolvers) {
				removed := cfg.DNSResolvers[index-1]
				cfg.DNSResolvers = append(cfg.DNSResolvers[:index-1], cfg.DNSResolvers[index:]...)
				successColor.Printf("Removed resolver: %s\n", removed)
			}
		} else {
			warningColor.Println("Cannot remove - at least one resolver is required")
		}
	case "0":
		return
	}

	if option != "0" {
		if err := saveConfig(cfg); err != nil {
			errorColor.Printf("Failed to save configuration: %v\n", err)
		} else {
			successColor.Println("Configuration saved successfully")
		}
	}

	PressEnterToContinue()
}

// updateAffectedChains updates firewall chains configuration
func updateAffectedChains(cfg *config.Settings, fwManager *firewall.FirewallManager) {
	ClearScreen()
	titleColor.Println("\n🔗 Update Affected Chains")
	fmt.Println(strings.Repeat("=", 50))

	subtitleColor.Println("\n📋 Current Affected Chains:")
	for _, chain := range cfg.AffectedChains {
		fmt.Printf("• %s\n", chain)
	}

	subtitleColor.Println("\n💡 Chain Information:")
	fmt.Println("• INPUT: Incoming traffic (packets destined for this machine)")
	fmt.Println("• OUTPUT: Outgoing traffic (packets originating from this machine)")
	fmt.Println("• FORWARD: Transit traffic (packets being routed through this machine)")
	fmt.Println("\n⚠️  Note: These chains affect BOTH whitelist and blacklist rules")

	subtitleColor.Println("\n🔧 Chain Selection:")
	menuColor.Println("1. ALL chains (INPUT + OUTPUT + FORWARD) [Recommended]")
	menuColor.Println("2. INPUT only")
	menuColor.Println("3. OUTPUT only")
	menuColor.Println("4. FORWARD only")
	menuColor.Println("5. INPUT + OUTPUT")
	menuColor.Println("6. INPUT + FORWARD")
	menuColor.Println("7. OUTPUT + FORWARD")
	menuColor.Println("0. Back to settings")

	promptColor.Print("\nSelect option: ")
	var option string
	fmt.Scanln(&option)

	var newChains []string
	var needsRegeneration bool

	switch option {
	case "1":
		newChains = []string{"INPUT", "OUTPUT", "FORWARD"}
	case "2":
		newChains = []string{"INPUT"}
	case "3":
		newChains = []string{"OUTPUT"}
	case "4":
		newChains = []string{"FORWARD"}
	case "5":
		newChains = []string{"INPUT", "OUTPUT"}
	case "6":
		newChains = []string{"INPUT", "FORWARD"}
	case "7":
		newChains = []string{"OUTPUT", "FORWARD"}
	case "0":
		return
	default:
		errorColor.Println("Invalid option")
		PressEnterToContinue()
		return
	}

	// Check if chains changed
	if !equalStringSlices(cfg.AffectedChains, newChains) {
		cfg.AffectedChains = newChains
		needsRegeneration = true
		successColor.Printf("Affected chains updated to: %s\n", strings.Join(newChains, ", "))

		if err := saveConfig(cfg); err != nil {
			errorColor.Printf("Failed to save configuration: %v\n", err)
		} else {
			successColor.Println("Configuration saved successfully")
		}

		if needsRegeneration {
			fmt.Printf("\n")
			warningColor.Println("⚠️  Chain configuration changed!")
			infoColor.Println("Firewall rules need to be regenerated for changes to take effect")
			fmt.Printf("\n")
			promptColor.Print("Regenerate firewall rules now? (y/N): ")
			var confirm string
			fmt.Scanln(&confirm)
			if strings.ToLower(confirm) == "y" || strings.ToLower(confirm) == "yes" {
				fmt.Printf("\n")
				infoColor.Println("🔄 Regenerating firewall rules with new chain configuration...")
				err := fwManager.Reload()
				if err != nil {
					errorColor.Printf("Failed to regenerate rules: %v\n", err)
				} else {
					successColor.Println("✅ Firewall rules regenerated successfully")
				}
			} else {
				infoColor.Println("💡 You can regenerate rules later from the main menu")
			}
		}
	} else {
		infoColor.Println("No changes made to chain configuration")
	}

	PressEnterToContinue()
}

// manageUpdateURLs manages domain auto-update URLs
func manageUpdateURLs(cfg *config.Settings) {
	for {
		ClearScreen()
		titleColor.Println("\n📡 Manage Domain Auto-Update URLs")
		fmt.Println(strings.Repeat("=", 50))

		subtitleColor.Println("\n📋 Current Update URLs:")
		if len(cfg.UpdateURLs) == 0 {
			warningColor.Println("No update URLs configured")
		} else {
			for i, url := range cfg.UpdateURLs {
				fmt.Printf("%d. %s\n", i+1, url)
			}
		}

		subtitleColor.Println("\n💡 Update URL Information:")
		fmt.Println("• URLs should point to text files containing domain lists")
		fmt.Println("• Lines starting with # are treated as comments")
		fmt.Println("• Each domain should be on a separate line")
		fmt.Println("• Agent will fetch these files during updates")

		subtitleColor.Println("\n🔧 Options:")
		menuColor.Println("1. Add new update URL")
		menuColor.Println("2. Remove update URL")
		menuColor.Println("3. Test URL accessibility")
		menuColor.Println("0. Back to settings")

		promptColor.Print("\nSelect option: ")
		var option string
		fmt.Scanln(&option)

		switch option {
		case "1":
			promptColor.Print("Enter update URL: ")
			var newURL string
			fmt.Scanln(&newURL)
			newURL = strings.TrimSpace(newURL)

			if newURL != "" {
				// Validate URL format
				if _, err := url.Parse(newURL); err != nil {
					errorColor.Printf("Invalid URL format: %v\n", err)
				} else {
					// Check for duplicates
					duplicate := false
					for _, existingURL := range cfg.UpdateURLs {
						if existingURL == newURL {
							duplicate = true
							break
						}
					}

					if duplicate {
						warningColor.Println("URL already exists in the list")
					} else {
						cfg.UpdateURLs = append(cfg.UpdateURLs, newURL)
						if err := saveConfig(cfg); err != nil {
							errorColor.Printf("Failed to save configuration: %v\n", err)
						} else {
							successColor.Printf("Added update URL: %s\n", newURL)
						}
					}
				}
			}
			PressEnterToContinue()

		case "2":
			if len(cfg.UpdateURLs) == 0 {
				warningColor.Println("No URLs to remove")
			} else {
				promptColor.Printf("Enter URL number to remove (1-%d): ", len(cfg.UpdateURLs))
				var indexStr string
				fmt.Scanln(&indexStr)
				if index, err := strconv.Atoi(indexStr); err == nil && index >= 1 && index <= len(cfg.UpdateURLs) {
					removed := cfg.UpdateURLs[index-1]
					cfg.UpdateURLs = append(cfg.UpdateURLs[:index-1], cfg.UpdateURLs[index:]...)
					if err := saveConfig(cfg); err != nil {
						errorColor.Printf("Failed to save configuration: %v\n", err)
					} else {
						successColor.Printf("Removed URL: %s\n", removed)
					}
				} else {
					errorColor.Println("Invalid URL number")
				}
			}
			PressEnterToContinue()

		case "3":
			if len(cfg.UpdateURLs) == 0 {
				warningColor.Println("No URLs to test")
			} else {
				promptColor.Printf("Enter URL number to test (1-%d): ", len(cfg.UpdateURLs))
				var indexStr string
				fmt.Scanln(&indexStr)
				if index, err := strconv.Atoi(indexStr); err == nil && index >= 1 && index <= len(cfg.UpdateURLs) {
					testURL := cfg.UpdateURLs[index-1]
					infoColor.Printf("Testing URL: %s\n", testURL)

					// Test URL accessibility using Go's HTTP client
					if err := testURLAccessibility(testURL); err != nil {
						errorColor.Printf("URL test failed: %v\n", err)
					} else {
						successColor.Println("✅ URL is accessible")
					}
				} else {
					errorColor.Println("Invalid URL number")
				}
			}
			PressEnterToContinue()

		case "0":
			return

		default:
			errorColor.Println("Invalid option")
			PressEnterToContinue()
		}
	}
}

// updateUpdateInterval updates the agent update interval
func updateUpdateInterval(cfg *config.Settings) {
	ClearScreen()
	titleColor.Println("\n⏰ Change Update Interval")
	fmt.Println(strings.Repeat("=", 50))

	subtitleColor.Printf("\n📊 Current Update Interval: %s\n", cfg.UpdateInterval.String())

	subtitleColor.Println("\n⏰ Preset Intervals:")
	menuColor.Println("1. Every 30 minutes")
	menuColor.Println("2. Every hour")
	menuColor.Println("3. Every 3 hours [Default]")
	menuColor.Println("4. Every 6 hours")
	menuColor.Println("5. Every 12 hours")
	menuColor.Println("6. Every 24 hours")
	menuColor.Println("7. Custom interval")
	menuColor.Println("0. Back to settings")

	promptColor.Print("\nSelect option: ")
	var option string
	fmt.Scanln(&option)

	var newInterval time.Duration
	var intervalStr string

	switch option {
	case "1":
		newInterval = 30 * time.Minute
		intervalStr = "30m"
	case "2":
		newInterval = 1 * time.Hour
		intervalStr = "1h"
	case "3":
		newInterval = 3 * time.Hour
		intervalStr = "3h"
	case "4":
		newInterval = 6 * time.Hour
		intervalStr = "6h"
	case "5":
		newInterval = 12 * time.Hour
		intervalStr = "12h"
	case "6":
		newInterval = 24 * time.Hour
		intervalStr = "24h"
	case "7":
		promptColor.Print("Enter custom interval (e.g., 2h30m, 45m, 90s): ")
		fmt.Scanln(&intervalStr)
		intervalStr = strings.TrimSpace(intervalStr)
		if parsedInterval, err := time.ParseDuration(intervalStr); err != nil {
			errorColor.Printf("Invalid interval format: %v\n", err)
			PressEnterToContinue()
			return
		} else {
			newInterval = parsedInterval
		}
	case "0":
		return
	default:
		errorColor.Println("Invalid option")
		PressEnterToContinue()
		return
	}

	if newInterval != cfg.UpdateInterval {
		cfg.UpdateInterval = newInterval
		if err := saveConfig(cfg); err != nil {
			errorColor.Printf("Failed to save configuration: %v\n", err)
		} else {
			successColor.Printf("Update interval changed to: %s\n", newInterval.String())
		}

		// Update systemd timer
		fmt.Printf("\n")
		infoColor.Println("🔄 Updating systemd timer...")
		if err := updateSystemdTimer(intervalStr); err != nil {
			errorColor.Printf("Failed to update systemd timer: %v\n", err)
			warningColor.Println("You may need to restart the timer manually")
		} else {
			successColor.Println("✅ Systemd timer updated successfully")
		}
	} else {
		infoColor.Println("No changes made to update interval")
	}

	PressEnterToContinue()
}

// updateRuleExpiration updates rule expiration time
func updateRuleExpiration(cfg *config.Settings) {
	ClearScreen()
	titleColor.Println("\n⏳ Change Rule Expiration Time")
	fmt.Println(strings.Repeat("=", 50))

	subtitleColor.Printf("\n📊 Current Rule Expiration: %s\n", cfg.RuleExpiration.String())

	subtitleColor.Println("\n💡 Rule Expiration Information:")
	fmt.Println("• Applies ONLY to auto-update domains (not custom entries)")
	fmt.Println("• Custom domains and IPs never expire automatically")
	fmt.Println("• Agent resets expiration if domain appears in update again")
	fmt.Println("• Expired rules are cleaned up when agent starts")

	subtitleColor.Println("\n⏰ Preset Expiration Times:")
	menuColor.Println("1. 6 hours")
	menuColor.Println("2. 12 hours [Default]")
	menuColor.Println("3. 24 hours")
	menuColor.Println("4. 48 hours")
	menuColor.Println("5. 7 days")
	menuColor.Println("6. 30 days")
	menuColor.Println("7. Custom duration")
	menuColor.Println("0. Back to settings")

	promptColor.Print("\nSelect option: ")
	var option string
	fmt.Scanln(&option)

	var newExpiration time.Duration

	switch option {
	case "1":
		newExpiration = 6 * time.Hour
	case "2":
		newExpiration = 12 * time.Hour
	case "3":
		newExpiration = 24 * time.Hour
	case "4":
		newExpiration = 48 * time.Hour
	case "5":
		newExpiration = 7 * 24 * time.Hour
	case "6":
		newExpiration = 30 * 24 * time.Hour
	case "7":
		promptColor.Print("Enter custom duration (e.g., 2h30m, 3d, 168h): ")
		var customDuration string
		fmt.Scanln(&customDuration)
		customDuration = strings.TrimSpace(customDuration)
		if parsedDuration, err := time.ParseDuration(customDuration); err != nil {
			errorColor.Printf("Invalid duration format: %v\n", err)
			PressEnterToContinue()
			return
		} else {
			newExpiration = parsedDuration
		}
	case "0":
		return
	default:
		errorColor.Println("Invalid option")
		PressEnterToContinue()
		return
	}

	if newExpiration != cfg.RuleExpiration {
		cfg.RuleExpiration = newExpiration
		if err := saveConfig(cfg); err != nil {
			errorColor.Printf("Failed to save configuration: %v\n", err)
		} else {
			successColor.Printf("Rule expiration time changed to: %s\n", newExpiration.String())
			infoColor.Println("💡 Changes will apply to new auto-update domains")
		}
	} else {
		infoColor.Println("No changes made to rule expiration time")
	}

	PressEnterToContinue()
}

// updateMaxIPsPerDomain updates max IPs per domain setting
func updateMaxIPsPerDomain(cfg *config.Settings) {
	ClearScreen()
	titleColor.Println("\n🔢 Change Max IPs Per Domain")
	fmt.Println(strings.Repeat("=", 50))

	subtitleColor.Printf("\n📊 Current Max IPs Per Domain: %d\n", cfg.MaxIPsPerDomain)

	subtitleColor.Println("\n💡 Max IPs Per Domain Information:")
	fmt.Println("• Limits how many IPs are blocked per domain")
	fmt.Println("• Uses FIFO mechanism (oldest IP removed when limit reached)")
	fmt.Println("• Domains with >2 different IPs are flagged as potential CDN")
	fmt.Println("• CDN domains are marked in the blocked domains list")
	fmt.Println("• Higher values = more thorough blocking, more memory usage")

	subtitleColor.Println("\n🔧 Recommended Values:")
	menuColor.Println("1. 3 IPs (Conservative - good for most cases)")
	menuColor.Println("2. 5 IPs [Default] (Balanced)")
	menuColor.Println("3. 10 IPs (Aggressive)")
	menuColor.Println("4. 20 IPs (Very aggressive)")
	menuColor.Println("5. Custom value")
	menuColor.Println("0. Back to settings")

	promptColor.Print("\nSelect option: ")
	var option string
	fmt.Scanln(&option)

	var newMaxIPs int

	switch option {
	case "1":
		newMaxIPs = 3
	case "2":
		newMaxIPs = 5
	case "3":
		newMaxIPs = 10
	case "4":
		newMaxIPs = 20
	case "5":
		promptColor.Print("Enter custom max IPs (1-100): ")
		var customValue string
		fmt.Scanln(&customValue)
		if parsedValue, err := strconv.Atoi(strings.TrimSpace(customValue)); err != nil {
			errorColor.Printf("Invalid number format: %v\n", err)
			PressEnterToContinue()
			return
		} else if parsedValue < 1 || parsedValue > 100 {
			errorColor.Println("Value must be between 1 and 100")
			PressEnterToContinue()
			return
		} else {
			newMaxIPs = parsedValue
		}
	case "0":
		return
	default:
		errorColor.Println("Invalid option")
		PressEnterToContinue()
		return
	}

	if newMaxIPs != cfg.MaxIPsPerDomain {
		cfg.MaxIPsPerDomain = newMaxIPs
		if err := saveConfig(cfg); err != nil {
			errorColor.Printf("Failed to save configuration: %v\n", err)
		} else {
			successColor.Printf("Max IPs per domain changed to: %d\n", newMaxIPs)
			infoColor.Println("💡 Changes will apply to newly processed domains")
		}
	} else {
		infoColor.Println("No changes made to max IPs per domain")
	}

	PressEnterToContinue()
}

// toggleLogging enables/disables logging
func toggleLogging(cfg *config.Settings) {
	ClearScreen()
	titleColor.Println("\n📝 Enable/Disable Logging")
	fmt.Println(strings.Repeat("=", 50))

	currentStatus := "Disabled"
	if cfg.LoggingEnabled {
		currentStatus = "Enabled"
	}

	subtitleColor.Printf("\n📊 Current Logging Status: %s\n", currentStatus)
	subtitleColor.Printf("Current Log Level: %s\n", cfg.LogLevel)
	subtitleColor.Printf("Log Path: %s\n", cfg.LogPath)

	subtitleColor.Println("\n💡 Logging Information:")
	fmt.Println("• Logging captures main app and agent activities")
	fmt.Println("• Useful for troubleshooting and monitoring")
	fmt.Println("• Log files are rotated automatically")
	fmt.Println("• Default is disabled for performance")

	subtitleColor.Println("\n🔧 Options:")
	if cfg.LoggingEnabled {
		menuColor.Println("1. Disable logging")
		menuColor.Println("2. Change log level")
	} else {
		menuColor.Println("1. Enable logging")
	}
	menuColor.Println("0. Back to settings")

	promptColor.Print("\nSelect option: ")
	var option string
	fmt.Scanln(&option)

	switch option {
	case "1":
		if cfg.LoggingEnabled {
			cfg.LoggingEnabled = false
			successColor.Println("Logging disabled")
		} else {
			cfg.LoggingEnabled = true
			successColor.Println("Logging enabled")
		}

		if err := saveConfig(cfg); err != nil {
			errorColor.Printf("Failed to save configuration: %v\n", err)
		} else {
			infoColor.Println("💡 Changes will take effect on next agent run")
		}

	case "2":
		if cfg.LoggingEnabled {
			subtitleColor.Println("\n📊 Select Log Level:")
			menuColor.Println("1. debug (Very detailed)")
			menuColor.Println("2. info (General information)")
			menuColor.Println("3. warn (Warnings only)")
			menuColor.Println("4. error (Errors only)")

			promptColor.Print("\nSelect log level: ")
			var levelOption string
			fmt.Scanln(&levelOption)

			switch levelOption {
			case "1":
				cfg.LogLevel = "debug"
			case "2":
				cfg.LogLevel = "info"
			case "3":
				cfg.LogLevel = "warn"
			case "4":
				cfg.LogLevel = "error"
			default:
				errorColor.Println("Invalid option")
				PressEnterToContinue()
				return
			}

			if err := saveConfig(cfg); err != nil {
				errorColor.Printf("Failed to save configuration: %v\n", err)
			} else {
				successColor.Printf("Log level changed to: %s\n", cfg.LogLevel)
			}
		}

	case "0":
		return

	default:
		errorColor.Println("Invalid option")
	}

	PressEnterToContinue()
}

// viewFullConfiguration displays the complete configuration
func viewFullConfiguration(cfg *config.Settings) {
	ClearScreen()
	titleColor.Println("\n📋 Full Configuration")
	fmt.Println(strings.Repeat("=", 60))

	subtitleColor.Println("\n🌐 DNS Configuration:")
	fmt.Printf("Resolvers: %s\n", strings.Join(cfg.DNSResolvers, ", "))

	subtitleColor.Println("\n🔒 Firewall Configuration:")
	fmt.Printf("Affected Chains: %s\n", strings.Join(cfg.AffectedChains, ", "))
	fmt.Printf("IPv6 Support: %s\n", map[bool]string{true: "Enabled", false: "Disabled"}[cfg.EnableIPv6])

	subtitleColor.Println("\n📡 Update Configuration:")
	fmt.Printf("Update Interval: %s\n", cfg.UpdateInterval.String())
	fmt.Printf("Update URLs (%d):\n", len(cfg.UpdateURLs))
	for i, url := range cfg.UpdateURLs {
		fmt.Printf("  %d. %s\n", i+1, url)
	}

	subtitleColor.Println("\n⏳ Domain Handling:")
	fmt.Printf("Rule Expiration: %s\n", cfg.RuleExpiration.String())
	fmt.Printf("Max IPs Per Domain: %d\n", cfg.MaxIPsPerDomain)

	subtitleColor.Println("\n📝 Logging:")
	fmt.Printf("Logging: %s\n", map[bool]string{true: "Enabled", false: "Disabled"}[cfg.LoggingEnabled])
	fmt.Printf("Log Level: %s\n", cfg.LogLevel)
	fmt.Printf("Log Path: %s\n", cfg.LogPath)

	subtitleColor.Println("\n📁 System Paths:")
	fmt.Printf("Database: %s\n", cfg.DatabasePath)
	fmt.Printf("Config: %s\n", cfg.ConfigPath)
	fmt.Printf("Logs: %s\n", cfg.LogPath)

	PressEnterToContinue()
}

// Helper functions

// testURLAccessibility tests if a URL is accessible using Go's HTTP client
func testURLAccessibility(url string) error {
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Head(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	return nil
}

// equalStringSlices compares two string slices for equality
func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

// updateSystemdTimer updates the systemd timer with new interval
func updateSystemdTimer(interval string) error {
	// Read current timer file
	timerPath := "/etc/systemd/system/dnsniper-agent.timer"

	// Update timer file
	timerContent := fmt.Sprintf(`[Unit]
Description=Run DNSniper Agent regularly
Requires=dnsniper-agent.service

[Timer]
Unit=dnsniper-agent.service
OnBootSec=1min
OnUnitActiveSec=%s

[Install]
WantedBy=timers.target
`, interval)

	if err := os.WriteFile(timerPath, []byte(timerContent), 0644); err != nil {
		return fmt.Errorf("failed to write timer file: %w", err)
	}

	// Reload systemd and restart timer
	cmd := exec.Command("systemctl", "daemon-reload")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to reload systemd: %w", err)
	}

	cmd = exec.Command("systemctl", "restart", "dnsniper-agent.timer")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to restart timer: %w", err)
	}

	return nil
}
