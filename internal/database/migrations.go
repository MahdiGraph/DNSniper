package database

import (
	"database/sql"
	"fmt"
)

// migrations contains all database migrations
var migrations = []struct {
	name string
	sql  string
}{
	{
		name: "initial_schema",
		sql: `
        -- Domains table
        CREATE TABLE IF NOT EXISTS domains (
            id INTEGER PRIMARY KEY,
            domain TEXT NOT NULL UNIQUE,
            is_whitelisted BOOLEAN NOT NULL DEFAULT 0,
            is_custom BOOLEAN NOT NULL DEFAULT 0,
            flagged_as_cdn BOOLEAN NOT NULL DEFAULT 0,
            added_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NULL,
            source TEXT DEFAULT 'custom',
            last_checked TIMESTAMP NULL
        );

        -- IPs table
        CREATE TABLE IF NOT EXISTS ips (
            id INTEGER PRIMARY KEY,
            ip_address TEXT NOT NULL UNIQUE,
            is_whitelisted BOOLEAN NOT NULL DEFAULT 0,
            is_custom BOOLEAN NOT NULL DEFAULT 0,
            added_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NULL,
            source TEXT DEFAULT 'custom',
            domain_id INTEGER NULL,
            last_checked TIMESTAMP NULL,
            FOREIGN KEY (domain_id) REFERENCES domains(id)
        );

        -- IP ranges table
        CREATE TABLE IF NOT EXISTS ip_ranges (
            id INTEGER PRIMARY KEY,
            cidr TEXT NOT NULL UNIQUE,
            is_whitelisted BOOLEAN NOT NULL DEFAULT 0,
            is_custom BOOLEAN NOT NULL DEFAULT 0,
            added_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NULL,
            source TEXT DEFAULT 'custom'
        );

        -- Agent runs table
        CREATE TABLE IF NOT EXISTS agent_runs (
            id INTEGER PRIMARY KEY,
            started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP NULL,
            domains_processed INTEGER DEFAULT 0,
            ips_blocked INTEGER DEFAULT 0,
            status TEXT DEFAULT 'running',
            error_message TEXT NULL
        );

        -- Agent logs table
        CREATE TABLE IF NOT EXISTS agent_logs (
            id INTEGER PRIMARY KEY,
            run_id INTEGER NOT NULL,
            action_type TEXT NOT NULL,
            target TEXT NOT NULL,
            result TEXT NOT NULL,
            timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            details TEXT NULL,
            FOREIGN KEY (run_id) REFERENCES agent_runs(id)
        );

        -- Update URLs table
        CREATE TABLE IF NOT EXISTS update_urls (
            id INTEGER PRIMARY KEY,
            url TEXT NOT NULL UNIQUE,
            added_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_used TIMESTAMP NULL,
            enabled BOOLEAN NOT NULL DEFAULT 1
        );

        -- Migrations table to track applied migrations
        CREATE TABLE IF NOT EXISTS migrations (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        -- Create indexes for performance
        CREATE INDEX IF NOT EXISTS idx_domains_whitelisted ON domains(is_whitelisted);
        CREATE INDEX IF NOT EXISTS idx_domains_custom ON domains(is_custom);
        CREATE INDEX IF NOT EXISTS idx_domains_expires ON domains(expires_at);
        CREATE INDEX IF NOT EXISTS idx_ips_whitelisted ON ips(is_whitelisted);
        CREATE INDEX IF NOT EXISTS idx_ips_custom ON ips(is_custom);
        CREATE INDEX IF NOT EXISTS idx_ips_domain ON ips(domain_id);
        CREATE INDEX IF NOT EXISTS idx_ips_expires ON ips(expires_at);
        CREATE INDEX IF NOT EXISTS idx_ip_ranges_whitelisted ON ip_ranges(is_whitelisted);
        CREATE INDEX IF NOT EXISTS idx_agent_logs_run ON agent_logs(run_id);
        CREATE INDEX IF NOT EXISTS idx_agent_logs_timestamp ON agent_logs(timestamp);

        -- Add default update URL
        INSERT OR IGNORE INTO update_urls (url) VALUES ('https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/domains-default.txt');
        `,
	},
	{
		name: "add_cleanup_triggers",
		sql: `
        -- Trigger to clean up expired domains
        CREATE TRIGGER IF NOT EXISTS cleanup_expired_domains
        AFTER INSERT ON domains
        BEGIN
            DELETE FROM domains
            WHERE expires_at IS NOT NULL
            AND expires_at < datetime('now')
            AND is_custom = 0;
        END;

        -- Trigger to clean up expired IPs
        CREATE TRIGGER IF NOT EXISTS cleanup_expired_ips
        AFTER INSERT ON ips
        BEGIN
            DELETE FROM ips
            WHERE expires_at IS NOT NULL
            AND expires_at < datetime('now')
            AND is_custom = 0;
        END;

        -- Trigger to clean up expired IP ranges
        CREATE TRIGGER IF NOT EXISTS cleanup_expired_ip_ranges
        AFTER INSERT ON ip_ranges
        BEGIN
            DELETE FROM ip_ranges
            WHERE expires_at IS NOT NULL
            AND expires_at < datetime('now')
            AND is_custom = 0;
        END;
        `,
	},
}

// MigrationRunner handles database migrations
type MigrationRunner struct {
	db *sql.DB
}

// NewMigrationRunner creates a new migration runner
func NewMigrationRunner(db *sql.DB) *MigrationRunner {
	return &MigrationRunner{db: db}
}

// Run applies all pending migrations
func (m *MigrationRunner) Run() error {
	// Start a transaction
	tx, err := m.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	// Create migrations table if it doesn't exist
	_, err = tx.Exec(`
        CREATE TABLE IF NOT EXISTS migrations (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    `)
	if err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	// Get applied migrations
	rows, err := tx.Query("SELECT name FROM migrations")
	if err != nil {
		return fmt.Errorf("failed to query migrations: %w", err)
	}
	defer rows.Close()

	// Create a map of applied migrations
	appliedMigrations := make(map[string]bool)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return fmt.Errorf("failed to scan migration: %w", err)
		}
		appliedMigrations[name] = true
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating migrations: %w", err)
	}

	// Apply pending migrations
	for _, migration := range migrations {
		if appliedMigrations[migration.name] {
			continue // Skip already applied migrations
		}

		// Apply migration
		_, err = tx.Exec(migration.sql)
		if err != nil {
			return fmt.Errorf("failed to apply migration %s: %w", migration.name, err)
		}

		// Record that migration was applied
		_, err = tx.Exec("INSERT INTO migrations (name) VALUES (?)", migration.name)
		if err != nil {
			return fmt.Errorf("failed to record migration %s: %w", migration.name, err)
		}
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}
