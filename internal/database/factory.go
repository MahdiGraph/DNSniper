package database

import (
	"fmt"
	"os"
	"path/filepath"
)

// DatabaseFactory provides database creation with enhanced features
type DatabaseFactory struct {
	firewallManager FirewallManagerInterface
}

// NewDatabaseFactory creates a new database factory
func NewDatabaseFactory(firewallManager FirewallManagerInterface) *DatabaseFactory {
	return &DatabaseFactory{
		firewallManager: firewallManager,
	}
}

// CreateDatabase creates a database instance with enhanced features
func (f *DatabaseFactory) CreateDatabase(dbPath string, useGORM bool) (DatabaseStore, error) {
	// Create directory if it doesn't exist
	dbDir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	if useGORM {
		return f.createGormDatabase(dbPath)
	}
	return f.createLegacyDatabase(dbPath)
}

// createGormDatabase creates a GORM database with callback service
func (f *DatabaseFactory) createGormDatabase(dbPath string) (DatabaseStore, error) {
	// Create GORM store
	gormStore, err := NewGormStore(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create GORM store: %w", err)
	}

	// Initialize callback service with firewall manager
	if f.firewallManager != nil {
		callbackService := NewIPSetCallbackService(f.firewallManager)
		SetIPSetCallbackService(callbackService)
	}

	// Wrap GORM store for interface compatibility
	wrapper := &GormStoreWrapper{
		GormStore: gormStore,
	}

	return wrapper, nil
}

// createLegacyDatabase creates a legacy database with wrapper
func (f *DatabaseFactory) createLegacyDatabase(dbPath string) (DatabaseStore, error) {
	// Create legacy store
	legacyStore, err := NewStore(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create legacy store: %w", err)
	}

	// Wrap legacy store for interface compatibility
	wrapper := &StoreWrapper{
		Store: legacyStore,
	}

	return wrapper, nil
}

// AutoDetectDatabaseType automatically detects the best database type to use
func (f *DatabaseFactory) AutoDetectDatabaseType(dbPath string) bool {
	// Check if config explicitly requests GORM
	if os.Getenv("DNSNIPER_USE_GORM") == "true" {
		return true
	}

	// Check if config explicitly requests legacy
	if os.Getenv("DNSNIPER_USE_LEGACY") == "true" {
		return false
	}

	// Default to GORM for new installations
	if !fileExists(dbPath) {
		return true
	}

	// For existing databases, check if it's already GORM
	// Try to open as GORM first
	gormStore, err := NewGormStore(dbPath)
	if err == nil {
		gormStore.Close()
		return true
	}

	// Fall back to legacy
	return false
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// CreateDatabaseWithAutoDetection creates a database with automatic type detection
func (f *DatabaseFactory) CreateDatabaseWithAutoDetection(dbPath string) (DatabaseStore, error) {
	useGORM := f.AutoDetectDatabaseType(dbPath)
	return f.CreateDatabase(dbPath, useGORM)
}

// ValidateCallbackService validates that the callback service is properly initialized
func ValidateCallbackService() error {
	service := GetIPSetCallbackService()
	if service == nil {
		return fmt.Errorf("callback service not initialized")
	}
	if service.firewallManager == nil {
		return fmt.Errorf("callback service firewall manager not set")
	}
	return nil
}

// TestCallbackFunctionality tests the callback system with a sample operation
func TestCallbackFunctionality(db DatabaseStore) error {
	// Validate callback service first
	if err := ValidateCallbackService(); err != nil {
		return fmt.Errorf("callback validation failed: %w", err)
	}

	// This is a non-intrusive test - we just verify the callback service is working
	// The actual testing would be done in unit tests
	return nil
}
