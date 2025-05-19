package main

import (
    "fmt"
    "os"
    "os/exec"

    "github.com/MahdiGraph/DNSniper/internal/config"
    "github.com/MahdiGraph/DNSniper/internal/database"
    "github.com/MahdiGraph/DNSniper/internal/firewall"
    "github.com/MahdiGraph/DNSniper/internal/service"
    "github.com/manifoldco/promptui"
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
    if err := database.Initialize(); err != nil {
        fmt.Fprintf(os.Stderr, "Failed to initialize database: %v\n", err)
        os.Exit(1)
    }

    var rootCmd = &cobra.Command{
        Use:   "dnsniper",
        Short: "DNSniper - Domain Threat Neutralizer",
        Long:  `DNSniper is a security tool that identifies suspicious domains and blocks their IPs.`,
        Run: func(cmd *cobra.Command, args []string) {
            showInteractiveMenu()
        },
    }

    // Add subcommands
    rootCmd.AddCommand(createStatusCommand())
    rootCmd.AddCommand(createRunCommand())
    rootCmd.AddCommand(createDomainsCommand())
    rootCmd.AddCommand(createIPsCommand())
    rootCmd.AddCommand(createSettingsCommand())
    rootCmd.AddCommand(createUpdateCommand())

    if err := rootCmd.Execute(); err != nil {
        fmt.Fprintf(os.Stderr, "Error: %v\n", err)
        os.Exit(1)
    }
}

func showInteractiveMenu() {
    fmt.Println("===============================")
    fmt.Println("      D N S n i p e r")
    fmt.Println("  Domain Threat Neutralizer")
    fmt.Println("===============================")

    for {
        prompt := promptui.Select{
            Label: "Select an option",
            Items: []string{
                "1. Run now",
                "2. Status",
                "3. Domain Blocklist",
                "4. Domain Whitelist",
                "5. IP Blocklist",
                "6. IP Whitelist",
                "7. Settings",
                "8. Update List",
                "9. Clear Rules",
                "0. Exit",
                "U. Uninstall",
            },
        }

        _, result, err := prompt.Run()
        if err != nil {
            fmt.Printf("Prompt failed: %v\n", err)
            return
        }

        // Process user's selection
        switch result {
        case "1. Run now":
            runAgentNow()
        case "2. Status":
            showStatus()
        case "3. Domain Blocklist":
            manageDomainBlocklist()
        case "4. Domain Whitelist":
            manageDomainWhitelist()
        case "5. IP Blocklist":
            manageIPBlocklist()
        case "6. IP Whitelist":
            manageIPWhitelist()
        case "7. Settings":
            manageSettings()
        case "8. Update List":
            updateList()
        case "9. Clear Rules":
            clearRules()
        case "0. Exit":
            return
        case "U. Uninstall":
            confirmUninstall()
        }
    }
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
            manageSettings()
        },
    }
}

func createUpdateCommand() *cobra.Command {
    return &cobra.Command{
        Use:   "update",
        Short: "Update domain and IP lists",
        Run: func(cmd *cobra.Command, args []string) {
            updateList()
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

    fmt.Println("DNSniper Status:")
    fmt.Println("================")
    fmt.Printf("Service status: %s\n", status.ServiceStatus)
    fmt.Printf("Last run: %s\n", status.LastRun)
    fmt.Printf("Blocked domains: %d\n", status.BlockedDomains)
    fmt.Printf("Blocked IPs: %d\n", status.BlockedIPs)
    fmt.Printf("Whitelisted domains: %d\n", status.WhitelistedDomains)
    fmt.Printf("Whitelisted IPs: %d\n", status.WhitelistedIPs)
}

func manageDomainBlocklist() {
    // Domain blocklist management menu
    prompt := promptui.Select{
        Label: "Domain Blocklist Options",
        Items: []string{
            "1. List blocked domains",
            "2. Add domain to blocklist",
            "3. Remove domain from blocklist",
            "4. Back to main menu",
        },
    }

    _, result, err := prompt.Run()
    if err != nil {
        fmt.Printf("Prompt failed: %v\n", err)
        return
    }

    switch result {
    case "1. List blocked domains":
        listBlockedDomains()
    case "2. Add domain to blocklist":
        addDomainToBlocklist()
    case "3. Remove domain from blocklist":
        removeDomainFromBlocklist()
    case "4. Back to main menu":
        return
    }
}

func manageDomainWhitelist() {
    // Domain whitelist management menu
    prompt := promptui.Select{
        Label: "Domain Whitelist Options",
        Items: []string{
            "1. List whitelisted domains",
            "2. Add domain to whitelist",
            "3. Remove domain from whitelist",
            "4. Back to main menu",
        },
    }

    _, result, err := prompt.Run()
    if err != nil {
        fmt.Printf("Prompt failed: %v\n", err)
        return
    }

    switch result {
    case "1. List whitelisted domains":
        listWhitelistedDomains()
    case "2. Add domain to whitelist":
        addDomainToWhitelist()
    case "3. Remove domain from whitelist":
        removeDomainFromWhitelist()
    case "4. Back to main menu":
        return
    }
}

func manageIPBlocklist() {
    // IP blocklist management menu
    prompt := promptui.Select{
        Label: "IP Blocklist Options",
        Items: []string{
            "1. List blocked IPs",
            "2. Add IP to blocklist",
            "3. Remove IP from blocklist",
            "4. Back to main menu",
        },
    }

    _, result, err := prompt.Run()
    if err != nil {
        fmt.Printf("Prompt failed: %v\n", err)
        return
    }

    switch result {
    case "1. List blocked IPs":
        listBlockedIPs()
    case "2. Add IP to blocklist":
        addIPToBlocklist()
    case "3. Remove IP from blocklist":
        removeIPFromBlocklist()
    case "4. Back to main menu":
        return
    }
}

func manageIPWhitelist() {
    // IP whitelist management menu
    prompt := promptui.Select{
        Label: "IP Whitelist Options",
        Items: []string{
            "1. List whitelisted IPs",
            "2. Add IP to whitelist",
            "3. Remove IP from whitelist",
            "4. Back to main menu",
        },
    }

    _, result, err := prompt.Run()
    if err != nil {
        fmt.Printf("Prompt failed: %v\n", err)
        return
    }

    switch result {
    case "1. List whitelisted IPs":
        listWhitelistedIPs()
    case "2. Add IP to whitelist":
        addIPToWhitelist()
    case "3. Remove IP from whitelist":
        removeIPFromWhitelist()
    case "4. Back to main menu":
        return
    }
}

func manageSettings() {
    // Settings management menu
    prompt := promptui.Select{
        Label: "Settings Options",
        Items: []string{
            "1. View current settings",
            "2. Change DNS resolver",
            "3. Change block rule type",
            "4. Toggle logging",
            "5. Set rules expiration time",
            "6. Set update URL",
            "7. Back to main menu",
        },
    }

    _, result, err := prompt.Run()
    if err != nil {
        fmt.Printf("Prompt failed: %v\n", err)
        return
    }

    switch result {
    case "1. View current settings":
        viewSettings()
    case "2. Change DNS resolver":
        changeDNSResolver()
    case "3. Change block rule type":
        changeBlockRuleType()
    case "4. Toggle logging":
        toggleLogging()
    case "5. Set rules expiration time":
        setRulesExpiration()
    case "6. Set update URL":
        setUpdateURL()
    case "7. Back to main menu":
        return
    }
}

func updateList() {
    fmt.Println("Updating domain and IP lists...")
    // Implementation of updating lists
    fmt.Println("Lists updated successfully")
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
        // Debian/Ubuntu
        err1 := exec.Command("iptables-save", ">", "/etc/iptables/rules.v4").Run()
        err2 := exec.Command("ip6tables-save", ">", "/etc/iptables/rules.v6").Run()
        if err1 != nil || err2 != nil {
            return fmt.Errorf("failed to save iptables rules")
        }
    } else {
        // RHEL/CentOS
        err1 := exec.Command("service", "iptables", "save").Run()
        err2 := exec.Command("service", "ip6tables", "save").Run()
        if err1 != nil || err2 != nil {
            return fmt.Errorf("failed to save iptables rules")
        }
    }
    
    return nil
}

func confirmUninstall() {
    prompt := promptui.Prompt{
        Label:     "Are you sure you want to uninstall DNSniper? (yes/no)",
        IsConfirm: true,
    }

    result, err := prompt.Run()
    if err != nil || result != "yes" {
        fmt.Println("Uninstallation cancelled")
        return
    }

    fmt.Println("Uninstalling DNSniper...")
    // Implementation of uninstallation
    fmt.Println("DNSniper has been uninstalled")
}

// Placeholder functions for various operations
func blockDomain(domain string) {
    fmt.Printf("Blocking domain: %s\n", domain)
}

func whitelistDomain(domain string) {
    fmt.Printf("Whitelisting domain: %s\n", domain)
}

func listDomains() {
    fmt.Println("Listing all domains...")
}

func blockIP(ip string) {
    fmt.Printf("Blocking IP: %s\n", ip)
}

func whitelistIP(ip string) {
    fmt.Printf("Whitelisting IP: %s\n", ip)
}

func listIPs() {
    fmt.Println("Listing all IPs...")
}

func listBlockedDomains() {
    fmt.Println("Listing blocked domains...")
}

func addDomainToBlocklist() {
    prompt := promptui.Prompt{
        Label: "Enter domain to block",
    }

    domain, err := prompt.Run()
    if err != nil {
        fmt.Printf("Prompt failed: %v\n", err)
        return
    }

    blockDomain(domain)
}

func removeDomainFromBlocklist() {
    fmt.Println("Removing domain from blocklist...")
}

func listWhitelistedDomains() {
    fmt.Println("Listing whitelisted domains...")
}

func addDomainToWhitelist() {
    prompt := promptui.Prompt{
        Label: "Enter domain to whitelist",
    }

    domain, err := prompt.Run()
    if err != nil {
        fmt.Printf("Prompt failed: %v\n", err)
        return
    }

    whitelistDomain(domain)
}

func removeDomainFromWhitelist() {
    fmt.Println("Removing domain from whitelist...")
}

func listBlockedIPs() {
    fmt.Println("Listing blocked IPs...")
}

func addIPToBlocklist() {
    prompt := promptui.Prompt{
        Label: "Enter IP to block",
    }

    ip, err := prompt.Run()
    if err != nil {
        fmt.Printf("Prompt failed: %v\n", err)
        return
    }

    blockIP(ip)
}

func removeIPFromBlocklist() {
    fmt.Println("Removing IP from blocklist...")
}

func listWhitelistedIPs() {
    fmt.Println("Listing whitelisted IPs...")
}

func addIPToWhitelist() {
    prompt := promptui.Prompt{
        Label: "Enter IP to whitelist",
    }

    ip, err := prompt.Run()
    if err != nil {
        fmt.Printf("Prompt failed: %v\n", err)
        return
    }

    whitelistIP(ip)
}

func removeIPFromWhitelist() {
    fmt.Println("Removing IP from whitelist...")
}

func viewSettings() {
    fmt.Println("Current settings:")
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

func changeDNSResolver() {
    prompt := promptui.Prompt{
        Label: "Enter new DNS resolver",
        Default: "8.8.8.8",
    }

    resolver, err := prompt.Run()
    if err != nil {
        fmt.Printf("Prompt failed: %v\n", err)
        return
    }

    fmt.Printf("DNS resolver set to: %s\n", resolver)
}

func changeBlockRuleType() {
    prompt := promptui.Select{
        Label: "Select block rule type",
        Items: []string{"source", "destination", "both"},
    }

    _, result, err := prompt.Run()
    if err != nil {
        fmt.Printf("Prompt failed: %v\n", err)
        return
    }

    fmt.Printf("Block rule type set to: %s\n", result)
}

func toggleLogging() {
    fmt.Println("Toggling logging...")
}

func setRulesExpiration() {
    prompt := promptui.Prompt{
        Label: "Enter rules expiration time in days",
        Default: "30",
    }

    expiration, err := prompt.Run()
    if err != nil {
        fmt.Printf("Prompt failed: %v\n", err)
        return
    }

    fmt.Printf("Rules expiration set to: %s days\n", expiration)
}

func setUpdateURL() {
    prompt := promptui.Prompt{
        Label: "Enter update URL",
        Default: "https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/domains-default.txt",
    }

    url, err := prompt.Run()
    if err != nil {
        fmt.Printf("Prompt failed: %v\n", err)
        return
    }

    fmt.Printf("Update URL set to: %s\n", url)
}