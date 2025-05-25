package ui

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

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
)

// PrintMenu displays the main menu and returns the selected option
func PrintMenu() string {
	fmt.Println()
	menuColor.Println("1) Run Agent now")
	menuColor.Println("2) Show status")
	menuColor.Println("3) Manage blocklist")
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
func DispatchOption(option string, db *database.Store, fwManager *firewall.FirewallManager) bool {
	option = strings.ToLower(option)

	switch option {
	case "1":
		RunAgentNow()
		return true
	case "2":
		ShowStatus(db, fwManager)
		return true
	case "3":
		ManageBlocklist(db, fwManager)
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
func ShowStatus(db *database.Store, fwManager *firewall.FirewallManager) {
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
	lastRun, err := db.GetLastAgentRun()
	if err != nil {
		fmt.Printf("Last run: ")
		warningColor.Println("Unknown")
	} else if lastRun == nil {
		fmt.Printf("Last run: ")
		warningColor.Println("Never")
	} else {
		fmt.Printf("Last run: ")
		if lastRun.CompletedAt.Valid {
			fmt.Println(lastRun.CompletedAt.Time.Format("2006-01-02 15:04:05"))
		} else {
			fmt.Printf("%s ", lastRun.StartedAt.Format("2006-01-02 15:04:05"))
			if lastRun.Status == "running" {
				warningColor.Println("(running)")
			} else {
				warningColor.Printf("(%s)\n", lastRun.Status)
			}
		}
	}

	// Get next scheduled run time
	if timerStatus == "active" {
		cmd = exec.Command("systemctl", "list-timers", "dnsniper-agent.timer", "--no-pager", "--no-legend")
		output, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			if len(lines) > 0 && lines[0] != "" {
				fields := strings.Fields(lines[0])
				if len(fields) >= 2 {
					nextRun := fields[1] + " " + fields[2]
					infoColor.Printf("Next scheduled run: %s\n", nextRun)
				}
			}
		}
	}

	// Display database statistics
	subtitleColor.Println("\nProtection Statistics:")

	// Get statistics
	stats, err := db.GetStatistics()
	if err != nil {
		errorColor.Printf("Failed to get statistics: %v\n", err)
	} else {
		fmt.Printf("Blocked domains: %d\n", stats.BlockedDomainsCount)
		fmt.Printf("Blocked IPs: %d\n", stats.BlockedIPCount)
		fmt.Printf("Whitelisted domains: %d\n", stats.WhitelistedDomains)
		fmt.Printf("Whitelisted IPs: %d\n", stats.WhitelistedIPCount)
	}

	// Display firewall statistics
	subtitleColor.Println("\nFirewall Statistics:")

	// Get firewall stats
	fwStats, err := fwManager.GetRulesStats()
	if err != nil {
		errorColor.Printf("Failed to get firewall statistics: %v\n", err)
	} else {
		for set, count := range fwStats {
			fmt.Printf("%s: %d entries\n", set, count)
		}
	}

	// Display recent activity if available
	if stats != nil && stats.IPsBlocked24h > 0 {
		subtitleColor.Println("\nRecent Activity:")
		fmt.Printf("Domains processed in last 24h: %d\n", stats.DomainsProcessed24h)
		fmt.Printf("IPs blocked in last 24h: %d\n", stats.IPsBlocked24h)

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

	PressEnterToContinue()
}

// ManageBlocklist displays the blocklist management menu
func ManageBlocklist(db *database.Store, fwManager *firewall.FirewallManager) {
	for {
		ClearScreen()
		titleColor.Println("\nBlocklist Management:")
		subtitleColor.Println("\nChoose what to manage:")
		menuColor.Println("1. Manage blocked domains")
		menuColor.Println("2. Manage blocked IP addresses")
		menuColor.Println("3. Add item to blocklist")
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
			AddItemToBlocklist(db, fwManager)
		case "0":
			return
		default:
			errorColor.Println("Invalid option. Please try again.")
			PressEnterToContinue()
		}
	}
}

// ManageWhitelist displays the whitelist management menu
func ManageWhitelist(db *database.Store, fwManager *firewall.FirewallManager) {
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
func ManageSettings(db *database.Store, fwManager *firewall.FirewallManager) {
	// TODO: Implement settings management
	errorColor.Println("Settings management not implemented yet.")
	PressEnterToContinue()
}

// ClearFirewallRules clears all firewall rules
func ClearFirewallRules(fwManager *firewall.FirewallManager) {
	// Check if agent is running
	cmd := exec.Command("systemctl", "is-active", "dnsniper-agent.service")
	output, _ := cmd.Output()

	if strings.TrimSpace(string(output)) == "active" {
		errorColor.Println("Cannot clear firewall rules while the agent is running.")
		errorColor.Println("Please wait for the agent to complete its current run and try again.")
		PressEnterToContinue()
		return
	}

	infoColor.Println("\nClearing all firewall rules...")

	err := fwManager.ClearAll()
	if err != nil {
		errorColor.Printf("Failed to clear firewall rules: %v\n", err)
	} else {
		successColor.Println("Firewall rules cleared successfully.")
	}

	PressEnterToContinue()
}

// RebuildFirewallRules rebuilds all firewall rules
func RebuildFirewallRules(fwManager *firewall.FirewallManager) {
	// Check if agent is running
	cmd := exec.Command("systemctl", "is-active", "dnsniper-agent.service")
	output, _ := cmd.Output()

	if strings.TrimSpace(string(output)) == "active" {
		errorColor.Println("Cannot rebuild firewall rules while the agent is running.")
		errorColor.Println("Please wait for the agent to complete its current run and try again.")
		PressEnterToContinue()
		return
	}

	infoColor.Println("\nRebuilding firewall rules...")

	err := fwManager.Reload()
	if err != nil {
		errorColor.Printf("Failed to rebuild firewall rules: %v\n", err)
	} else {
		successColor.Println("Firewall rules rebuilt successfully.")
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
	fmt.Println("• Stop all DNSniper services")
	fmt.Println("• Remove all firewall rules and ipset configurations")
	fmt.Println("• Delete all executable files")
	fmt.Println("• Remove all configuration files")
	fmt.Println("\nThis action cannot be undone!")

	errorColor.Print("\nType 'UNINSTALL' to confirm: ")
	var confirmation string
	fmt.Scanln(&confirmation)

	if confirmation != "UNINSTALL" {
		infoColor.Println("Uninstallation cancelled.")
		PressEnterToContinue()
		return true
	}

	infoColor.Println("\nUninstalling DNSniper...")

	// Call installer.sh with uninstall parameter
	cmd := exec.Command("bash", "/usr/local/bin/dnsniper-installer", "uninstall")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		errorColor.Printf("Failed to uninstall DNSniper: %v\n", err)
		PressEnterToContinue()
		return true
	}

	successColor.Println("\nDNSniper has been uninstalled.")
	fmt.Println("\nThank you for using DNSniper!")

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
func ManageDomainList(db *database.Store, fwManager *firewall.FirewallManager, isWhitelist bool) {
	// TODO: Implement domain list management
	errorColor.Println("Domain list management not implemented yet.")
	PressEnterToContinue()
}

// ManageIPList displays the IP list management menu
func ManageIPList(db *database.Store, fwManager *firewall.FirewallManager, isWhitelist bool) {
	// TODO: Implement IP list management
	errorColor.Println("IP list management not implemented yet.")
	PressEnterToContinue()
}

// AddItemToBlocklist displays the add item to blocklist menu
func AddItemToBlocklist(db *database.Store, fwManager *firewall.FirewallManager) {
	// TODO: Implement add item to blocklist
	errorColor.Println("Add item to blocklist not implemented yet.")
	PressEnterToContinue()
}

// AddItemToWhitelist displays the add item to whitelist menu
func AddItemToWhitelist(db *database.Store, fwManager *firewall.FirewallManager) {
	// TODO: Implement add item to whitelist
	errorColor.Println("Add item to whitelist not implemented yet.")
	PressEnterToContinue()
}
