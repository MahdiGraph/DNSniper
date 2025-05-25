package database

import (
	"database/sql"
	"time"
)

// Domain represents a domain in the blocklist or whitelist
type Domain struct {
	ID            int64
	Domain        string
	IsWhitelisted bool
	IsCustom      bool
	FlaggedAsCDN  bool
	AddedAt       time.Time
	ExpiresAt     sql.NullTime
	Source        string
	LastChecked   sql.NullTime
}

// IP represents an IP address in the blocklist or whitelist
type IP struct {
	ID            int64
	IPAddress     string
	IsWhitelisted bool
	IsCustom      bool
	AddedAt       time.Time
	ExpiresAt     sql.NullTime
	Source        string
	DomainID      sql.NullInt64
	LastChecked   sql.NullTime
}

// IPRange represents a CIDR IP range in the blocklist or whitelist
type IPRange struct {
	ID            int64
	CIDR          string
	IsWhitelisted bool
	IsCustom      bool
	AddedAt       time.Time
	ExpiresAt     sql.NullTime
	Source        string
}

// AgentRun represents a single execution of the agent
type AgentRun struct {
	ID               int64
	StartedAt        time.Time
	CompletedAt      sql.NullTime
	DomainsProcessed int
	IPsBlocked       int
	Status           string
	ErrorMessage     sql.NullString
}

// AgentLog represents a log entry from the agent
type AgentLog struct {
	ID         int64
	RunID      int64
	ActionType string
	Target     string
	Result     string
	Timestamp  time.Time
	Details    sql.NullString
}

// UpdateURL represents a URL to fetch domain lists from
type UpdateURL struct {
	ID       int64
	URL      string
	AddedAt  time.Time
	LastUsed sql.NullTime
	Enabled  bool
}

// Statistics contains summary statistics for the dashboard
type Statistics struct {
	DomainsProcessed24h  int
	IPsBlocked24h        int
	DomainsProcessed7d   int
	IPsBlocked7d         int
	RecentBlockedDomains []string
	BlockedDomainsCount  int
	WhitelistedDomains   int
	BlockedIPCount       int
	WhitelistedIPCount   int
	LastRunTime          sql.NullTime
	LastRunStatus        string
}
