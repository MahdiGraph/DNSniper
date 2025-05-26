package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/MahdiGraph/DNSniper/internal/agent"
	"github.com/MahdiGraph/DNSniper/internal/config"
	"github.com/MahdiGraph/DNSniper/internal/database"
	"github.com/MahdiGraph/DNSniper/internal/dns"
	"github.com/MahdiGraph/DNSniper/internal/firewall"
	"github.com/MahdiGraph/DNSniper/pkg/logger"
)

func main() {
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

	// Ensure database directory exists
	dbDir := filepath.Dir(cfg.DatabasePath)
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		log.Errorf("Failed to create database directory: %v", err)
		fmt.Fprintf(os.Stderr, "Failed to create database directory: %v\n", err)
		os.Exit(1)
	}

	// Initialize database
	db, err := database.NewStore(cfg.DatabasePath)
	if err != nil {
		log.Errorf("Failed to initialize database: %v", err)
		fmt.Fprintf(os.Stderr, "Failed to initialize database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// Initialize firewall manager with cleanup for fresh start
	fwManager, err := firewall.NewFirewallManager(
		cfg.IPSetPath,
		cfg.IPTablesPath,
		cfg.IP6TablesPath,
		cfg.EnableIPv6,
		cfg.BlockChains,
	)
	if err != nil {
		log.Errorf("Failed to initialize firewall manager: %v", err)
		fmt.Fprintf(os.Stderr, "Failed to initialize firewall manager: %v\n", err)
		os.Exit(1)
	}

	// Initialize DNS resolver
	resolver := dns.NewStandardResolver()

	// Create agent
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
