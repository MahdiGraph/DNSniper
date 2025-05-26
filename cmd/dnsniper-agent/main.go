package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/MahdiGraph/DNSniper/internal/agent"
	"github.com/MahdiGraph/DNSniper/internal/config"
	"github.com/MahdiGraph/DNSniper/internal/database"
	"github.com/MahdiGraph/DNSniper/internal/dns"
	"github.com/MahdiGraph/DNSniper/internal/firewall"
	"github.com/MahdiGraph/DNSniper/pkg/logger"
)

func main() {
	// Parse command line flags
	var showHelp = flag.Bool("help", false, "Show help information")
	var showVersion = flag.Bool("version", false, "Show version information")
	flag.Parse()

	// Handle help flag
	if *showHelp {
		fmt.Println("DNSniper Agent v2.0")
		fmt.Println("Automated DNS firewall agent")
		fmt.Println("")
		fmt.Println("Usage: dnsniper-agent [options]")
		fmt.Println("")
		fmt.Println("Options:")
		fmt.Println("  --help     Show this help message")
		fmt.Println("  --version  Show version information")
		fmt.Println("")
		fmt.Println("Agent Features:")
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
		fmt.Println("DNSniper Agent v2.0")
		fmt.Println("Automated DNS Firewall Agent")
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
		log.Errorf("Failed to initialize firewall manager: %v", err)
		fmt.Fprintf(os.Stderr, "Failed to initialize firewall manager: %v\n", err)
		os.Exit(1)
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

	// Initialize DNS resolver
	resolver := dns.NewStandardResolver()

	// Create agent with GORM interface
	agent := agent.NewAgent(cfg, db, resolver, fwManager, log)

	// Setup context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Info("Received shutdown signal, stopping agent...")
		cancel()
	}()

	// Run the agent
	log.Info("Starting DNSniper agent...")
	if err := agent.Run(ctx); err != nil {
		if err == context.Canceled {
			log.Info("Agent stopped gracefully")
		} else {
			log.Errorf("Agent error: %v", err)
			fmt.Fprintf(os.Stderr, "Agent error: %v\n", err)
			os.Exit(1)
		}
	}

	log.Info("DNSniper agent completed successfully")
}
