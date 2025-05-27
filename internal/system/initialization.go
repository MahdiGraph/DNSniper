package system

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/MahdiGraph/DNSniper/internal/config"
	"github.com/MahdiGraph/DNSniper/internal/database"
	"github.com/MahdiGraph/DNSniper/internal/firewall"
	"github.com/MahdiGraph/DNSniper/pkg/logger"
)

// SystemInitializer handles complete system initialization
type SystemInitializer struct {
	config          *config.Settings
	logger          *logger.Logger
	firewallManager *firewall.FirewallManager
	db              database.DatabaseStore
	verboseLogging  bool
}

// NewSystemInitializer creates a new system initializer
func NewSystemInitializer(verboseLogging bool) *SystemInitializer {
	return &SystemInitializer{
		verboseLogging: verboseLogging,
	}
}

// Initialize performs complete system initialization
func (s *SystemInitializer) Initialize(configPath string) error {
	// Step 1: Load or create configuration
	if err := s.initializeConfiguration(configPath); err != nil {
		return fmt.Errorf("failed to initialize configuration: %w", err)
	}

	// Step 2: Initialize logger
	if err := s.initializeLogger(); err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}

	// Step 3: Initialize firewall manager
	if err := s.initializeFirewallManager(); err != nil {
		return fmt.Errorf("failed to initialize firewall manager: %w", err)
	}

	// Step 4: Ensure ipsets exist
	if err := s.ensureIPSetsExist(); err != nil {
		return fmt.Errorf("failed to ensure ipsets exist: %w", err)
	}

	// Step 5: Initialize database
	if err := s.initializeDatabase(); err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}

	// Step 6: Ensure iptables rules exist
	if err := s.ensureIPTablesRulesExist(); err != nil {
		return fmt.Errorf("failed to ensure iptables rules exist: %w", err)
	}

	s.logInfo("System initialization completed successfully")
	return nil
}

// initializeConfiguration loads or creates configuration
func (s *SystemInitializer) initializeConfiguration(configPath string) error {
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return err
	}
	s.config = cfg

	// Create necessary directories
	dirs := []string{
		filepath.Dir(s.config.DatabasePath),
		s.config.LogPath,
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return nil
}

// initializeLogger sets up logging
func (s *SystemInitializer) initializeLogger() error {
	logConfig := logger.Config{
		LogDir:     s.config.LogPath,
		EnableFile: s.config.LoggingEnabled || s.verboseLogging,
		Level:      s.config.LogLevel,
		MaxSize:    10,
		MaxBackups: 5,
		MaxAge:     30,
		Compress:   true,
	}

	// Force debug level if verbose logging is enabled
	if s.verboseLogging {
		logConfig.Level = "debug"
		logConfig.EnableFile = true
	}

	s.logger = logger.New(logConfig)
	s.logInfo("Logger initialized successfully")
	return nil
}

// initializeFirewallManager sets up firewall manager
func (s *SystemInitializer) initializeFirewallManager() error {
	s.logInfo("Initializing firewall manager...")

	fwManager, err := firewall.NewFirewallManager(
		s.config.EnableIPv6,
		s.config.AffectedChains,
		filepath.Join(s.config.LogPath, "firewall-backup"),
		filepath.Join(s.config.LogPath, "firewall.log"),
	)
	if err != nil {
		return err
	}

	s.firewallManager = fwManager
	s.logInfo("Firewall manager initialized successfully")
	return nil
}

// ensureIPSetsExist creates ipsets if they don't exist
func (s *SystemInitializer) ensureIPSetsExist() error {
	s.logInfo("Ensuring ipsets exist...")

	if err := s.firewallManager.EnsureSetsExist(); err != nil {
		return err
	}

	s.logInfo("IPSets verified/created successfully")
	return nil
}

// initializeDatabase sets up database
func (s *SystemInitializer) initializeDatabase() error {
	s.logInfo("Initializing database...")

	dbFactory := database.NewDatabaseFactory(s.firewallManager)
	db, err := dbFactory.CreateDatabaseWithAutoDetection(s.config.DatabasePath)
	if err != nil {
		return err
	}

	s.db = db
	s.logInfo("Database initialized successfully")
	return nil
}

// ensureIPTablesRulesExist creates iptables rules if they don't exist
func (s *SystemInitializer) ensureIPTablesRulesExist() error {
	s.logInfo("Ensuring iptables rules exist...")

	// Check if rules files exist and have DNSniper rules
	rulesV4Path := "/etc/iptables/rules.v4"
	rulesV6Path := "/etc/iptables/rules.v6"

	needsRulesGeneration := false

	// Check IPv4 rules
	if content, err := os.ReadFile(rulesV4Path); err != nil || !containsDNSniperRules(string(content)) {
		needsRulesGeneration = true
		s.logInfo("IPv4 rules file missing or doesn't contain DNSniper rules")
	}

	// Check IPv6 rules if enabled
	if s.config.EnableIPv6 {
		if content, err := os.ReadFile(rulesV6Path); err != nil || !containsDNSniperRules(string(content)) {
			needsRulesGeneration = true
			s.logInfo("IPv6 rules file missing or doesn't contain DNSniper rules")
		}
	}

	if needsRulesGeneration {
		s.logInfo("Generating initial iptables rules...")
		if err := s.firewallManager.Reload(); err != nil {
			s.logInfo("Warning: Failed to generate initial rules, but ipsets are ready")
			s.logInfo("You can manually run 'dnsniper' menu option 7 to rebuild rules later")
			// Don't fail initialization just because rules couldn't be applied
			// The ipsets are created and the system can still work
			return nil
		}
		s.logInfo("Initial iptables rules generated successfully")
	} else {
		s.logInfo("IPTables rules already exist")
	}

	return nil
}

// containsDNSniperRules checks if content contains DNSniper rules
func containsDNSniperRules(content string) bool {
	if len(content) == 0 {
		return false
	}

	// Check for DNSniper-specific content
	return strings.Contains(content, "DNSniper") ||
		strings.Contains(content, "dnsniper") ||
		strings.Contains(content, "dnsniper-whitelist") ||
		strings.Contains(content, "dnsniper-blocklist")
}

// logInfo logs info message with proper handling for verbose mode
func (s *SystemInitializer) logInfo(message string) {
	if s.logger != nil {
		s.logger.Info(message)
	}

	// Always print to stdout if verbose logging is enabled
	if s.verboseLogging {
		fmt.Printf("[INFO] %s\n", message)
	}
}

// GetConfig returns the loaded configuration
func (s *SystemInitializer) GetConfig() *config.Settings {
	return s.config
}

// GetLogger returns the logger
func (s *SystemInitializer) GetLogger() *logger.Logger {
	return s.logger
}

// GetFirewallManager returns the firewall manager
func (s *SystemInitializer) GetFirewallManager() *firewall.FirewallManager {
	return s.firewallManager
}

// GetDatabase returns the database
func (s *SystemInitializer) GetDatabase() database.DatabaseStore {
	return s.db
}

// Close cleans up resources
func (s *SystemInitializer) Close() error {
	if s.db != nil {
		if err := s.db.Close(); err != nil {
			return err
		}
	}

	if s.logger != nil {
		s.logger.Close()
	}

	return nil
}
