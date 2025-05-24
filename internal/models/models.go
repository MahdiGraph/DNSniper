package models

import (
	"database/sql"
	"time"
)

// Settings represents application settings
type Settings struct {
	DNSResolver     string        // DNS resolver to use for domain resolution
	BlockRuleType   string        // DEPRECATED: Type of blocking rule (source, destination, both)
	BlockChains     string        // Chains to apply blocking rules (e.g., "INPUT,OUTPUT,FORWARD" or "ALL")
	BlockDirection  string        // Direction of blocking (source, destination, both)
	LoggingEnabled  bool          // Whether to enable logging
	RuleExpiration  time.Duration // Expiration time for rules
	UpdateURL       string        // URL to download domain list from (deprecated, kept for backward compatibility)
	MaxIPsPerDomain int           // Maximum number of IPs to track per domain
}

// Domain represents a domain entry in the database
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

// IP represents an IP entry in the database
type IP struct {
	ID            int64
	IPAddress     string
	IsWhitelisted bool
	IsCustom      bool
	AddedAt       time.Time
	ExpiresAt     sql.NullTime
	Source        string
	DomainID      sql.NullInt64
	IsRange       bool // Indicates if this is an IP range (CIDR)
}

// AgentRun represents an agent run entry in the database
type AgentRun struct {
	ID               int64
	StartedAt        time.Time
	CompletedAt      sql.NullTime
	DomainsProcessed int
	IPsBlocked       int
	Status           string
	ErrorMessage     sql.NullString
}

// AgentLog represents a log entry for agent actions
type AgentLog struct {
	ID         int64
	RunID      int64
	ActionType string
	Target     string
	Result     string
	Timestamp  time.Time
	Details    sql.NullString
}

// AgentStatus represents the status of the agent
type AgentStatus struct {
	ServiceStatus      string
	LastRun            string
	BlockedDomains     int
	BlockedIPs         int
	WhitelistedDomains int
	WhitelistedIPs     int
}

// DomainStats contains statistics about blocked and whitelisted domains
type DomainStats struct {
	Blocked     int
	Whitelisted int
}

// IPStats contains statistics about blocked and whitelisted IPs
type IPStats struct {
	Blocked     int
	Whitelisted int
}

// Statistics represents usage statistics for the dashboard
type Statistics struct {
	DomainsProcessed24h  int
	IPsBlocked24h        int
	DomainsProcessed7d   int
	IPsBlocked7d         int
	RecentBlockedDomains []string
}
