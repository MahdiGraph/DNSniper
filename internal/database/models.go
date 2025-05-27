package database

import (
	"context"
	"fmt"
	"sync"
	"time"

	"gorm.io/gorm"
)

// Domain represents a domain in the blocklist or whitelist
type Domain struct {
	ID            uint      `gorm:"primaryKey"`
	Domain        string    `gorm:"uniqueIndex;not null"`
	IsWhitelisted bool      `gorm:"default:false"`
	IsCustom      bool      `gorm:"default:false"`
	FlaggedAsCDN  bool      `gorm:"default:false"`
	AddedAt       time.Time `gorm:"autoCreateTime"`
	ExpiresAt     *time.Time
	Source        string `gorm:"default:''"`
	LastChecked   *time.Time
	IPs           []IP `gorm:"foreignKey:DomainID"`
}

// IP represents an IP address in the blocklist or whitelist
type IP struct {
	ID            uint      `gorm:"primaryKey"`
	IPAddress     string    `gorm:"uniqueIndex;not null"`
	IsWhitelisted bool      `gorm:"default:false"`
	IsCustom      bool      `gorm:"default:false"`
	AddedAt       time.Time `gorm:"autoCreateTime"`
	ExpiresAt     *time.Time
	Source        string `gorm:"default:''"`
	DomainID      *uint
	Domain        *Domain `gorm:"foreignKey:DomainID"`
	LastChecked   *time.Time
}

// IPRange represents a CIDR IP range in the blocklist or whitelist
type IPRange struct {
	ID            uint      `gorm:"primaryKey"`
	CIDR          string    `gorm:"uniqueIndex;not null"`
	IsWhitelisted bool      `gorm:"default:false"`
	IsCustom      bool      `gorm:"default:false"`
	AddedAt       time.Time `gorm:"autoCreateTime"`
	ExpiresAt     *time.Time
	Source        string `gorm:"default:''"`
}

// AgentRun represents a single execution of the agent
type AgentRun struct {
	ID               uint      `gorm:"primaryKey"`
	StartedAt        time.Time `gorm:"autoCreateTime"`
	CompletedAt      *time.Time
	DomainsProcessed int        `gorm:"default:0"`
	IPsBlocked       int        `gorm:"default:0"`
	Status           string     `gorm:"default:'running'"`
	ErrorMessage     string     `gorm:"default:''"`
	Logs             []AgentLog `gorm:"foreignKey:RunID"`
}

// AgentLog represents a log entry from the agent
type AgentLog struct {
	ID         uint      `gorm:"primaryKey"`
	RunID      uint      `gorm:"not null"`
	ActionType string    `gorm:"not null"`
	Target     string    `gorm:"not null"`
	Result     string    `gorm:"not null"`
	Timestamp  time.Time `gorm:"autoCreateTime"`
	Details    string    `gorm:"default:''"`
	Run        AgentRun  `gorm:"foreignKey:RunID"`
}

// UpdateURL represents a URL to fetch domain lists from
type UpdateURL struct {
	ID       uint      `gorm:"primaryKey"`
	URL      string    `gorm:"uniqueIndex;not null"`
	AddedAt  time.Time `gorm:"autoCreateTime"`
	LastUsed *time.Time
	Enabled  bool `gorm:"default:true"`
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
	LastRunTime          *time.Time
	LastRunStatus        string
}

// IPSetCallbackService handles synchronization with ipset rules
type IPSetCallbackService struct {
	firewallManager FirewallManagerInterface
	mu              sync.Mutex // For thread-safe operations
}

// FirewallManagerInterface defines the interface for firewall operations
type FirewallManagerInterface interface {
	BlockIP(ip string, user string) error
	WhitelistIP(ip string, user string) error
	UnblockIP(ip string) error
	UnwhitelistIP(ip string) error
	BlockIPRange(cidr string, user string) error
	WhitelistIPRange(cidr string, user string) error
	UnblockIPRange(cidr string) error
	UnwhitelistIPRange(cidr string) error
}

// sync.Mutex for thread safety
var mutex sync.Mutex

// GORM Hooks for automatic ipset synchronization

// AfterCreate hook for Domain
func (d *Domain) AfterCreate(tx *gorm.DB) error {
	// Domain creation doesn't directly affect ipset rules
	// IPs associated with domains handle their own synchronization
	return nil
}

// AfterUpdate hook for Domain
func (d *Domain) AfterUpdate(tx *gorm.DB) error {
	// Prevent infinite loops by checking if we're already in a callback
	if tx.Statement.Context.Value("dnsniper_callback_active") != nil {
		return nil
	}

	// If whitelist status changed, update all associated IPs
	if tx.Statement.Changed("IsWhitelisted") {
		// Set context to prevent infinite loops
		ctx := context.WithValue(tx.Statement.Context, "dnsniper_callback_active", true)

		// Use a new transaction with the protected context
		return tx.WithContext(ctx).Transaction(func(protectedTx *gorm.DB) error {
			var ips []IP
			if err := protectedTx.Where("domain_id = ?", d.ID).Find(&ips).Error; err != nil {
				return err
			}

			// Update all associated IPs to match domain whitelist status
			for _, ip := range ips {
				oldWhitelistStatus := ip.IsWhitelisted

				// Only update if status actually needs to change
				if oldWhitelistStatus != d.IsWhitelisted {
					// Use direct SQL update to avoid triggering hooks
					if err := protectedTx.Model(&IP{}).Where("id = ?", ip.ID).UpdateColumn("is_whitelisted", d.IsWhitelisted).Error; err != nil {
						return err
					}

					// Log the whitelist priority change
					if d.IsWhitelisted {
						// IP moved to whitelist (priority protection)
						logCallbackAction("domain_ip_whitelist", ip.IPAddress, "success",
							fmt.Sprintf("IP whitelisted due to domain %s whitelist status change", d.Domain))
					} else {
						// IP moved from whitelist to blocklist
						logCallbackAction("domain_ip_unwhitelist", ip.IPAddress, "success",
							fmt.Sprintf("IP moved to blocklist due to domain %s whitelist status change", d.Domain))
					}
				}
			}
			return nil
		})
	}
	return nil
}

// AfterCreate hook for IP
func (i *IP) AfterCreate(tx *gorm.DB) error {
	// Prevent infinite loops by checking if we're already in a callback
	if tx.Statement.Context.Value("dnsniper_callback_active") != nil {
		return nil
	}

	// Use goroutine to prevent blocking the transaction
	go func() {
		if err := i.syncIPSetRule("add"); err != nil {
			logCallbackAction("ip_create_error", i.IPAddress, "failed", fmt.Sprintf("Failed to sync IP on create: %v", err))
		}
	}()

	return nil
}

// AfterUpdate hook for IP
func (i *IP) AfterUpdate(tx *gorm.DB) error {
	// Prevent infinite loops by checking if we're already in a callback
	if tx.Statement.Context.Value("dnsniper_callback_active") != nil {
		return nil
	}

	// If whitelist status changed, sync with ipset
	if tx.Statement.Changed("IsWhitelisted") {
		// Use goroutine to prevent blocking the transaction
		go func() {
			if err := i.syncIPSetRule("update"); err != nil {
				logCallbackAction("ip_update_error", i.IPAddress, "failed", fmt.Sprintf("Failed to sync IP on update: %v", err))
			}
		}()
	}
	return nil
}

// AfterDelete hook for IP
func (i *IP) AfterDelete(tx *gorm.DB) error {
	// Prevent infinite loops by checking if we're already in a callback
	if tx.Statement.Context.Value("dnsniper_callback_active") != nil {
		return nil
	}

	// Use goroutine to prevent blocking the transaction
	go func() {
		if err := i.syncIPSetRule("remove_both"); err != nil {
			logCallbackAction("ip_delete_error", i.IPAddress, "failed", fmt.Sprintf("Failed to sync IP on delete: %v", err))
		}
	}()

	return nil
}

// AfterCreate hook for IPRange
func (r *IPRange) AfterCreate(tx *gorm.DB) error {
	// Prevent infinite loops by checking if we're already in a callback
	if tx.Statement.Context.Value("dnsniper_callback_active") != nil {
		return nil
	}

	// Use goroutine to prevent blocking the transaction
	go func() {
		if err := r.syncIPSetRule("add"); err != nil {
			logCallbackAction("range_create_error", r.CIDR, "failed", fmt.Sprintf("Failed to sync IP range on create: %v", err))
		}
	}()

	return nil
}

// AfterUpdate hook for IPRange
func (r *IPRange) AfterUpdate(tx *gorm.DB) error {
	// Prevent infinite loops by checking if we're already in a callback
	if tx.Statement.Context.Value("dnsniper_callback_active") != nil {
		return nil
	}

	if tx.Statement.Changed("IsWhitelisted") {
		// Use goroutine to prevent blocking the transaction
		go func() {
			if err := r.syncIPSetRule("remove_both"); err != nil {
				logCallbackAction("range_update_error", r.CIDR, "failed", fmt.Sprintf("Failed to remove IP range on update: %v", err))
				return
			}
			if err := r.syncIPSetRule("add"); err != nil {
				logCallbackAction("range_update_error", r.CIDR, "failed", fmt.Sprintf("Failed to add IP range on update: %v", err))
			}
		}()
	}
	return nil
}

// AfterDelete hook for IPRange
func (r *IPRange) AfterDelete(tx *gorm.DB) error {
	// Prevent infinite loops by checking if we're already in a callback
	if tx.Statement.Context.Value("dnsniper_callback_active") != nil {
		return nil
	}

	// Use goroutine to prevent blocking the transaction
	go func() {
		if err := r.syncIPSetRule("remove"); err != nil {
			logCallbackAction("range_delete_error", r.CIDR, "failed", fmt.Sprintf("Failed to sync IP range on delete: %v", err))
		}
	}()

	return nil
}

// Helper methods for ipset synchronization with enhanced whitelist priority
func (i *IP) syncIPSetRule(action string) error {
	service := GetIPSetCallbackService()
	if service == nil || service.firewallManager == nil {
		logCallbackAction("ip_sync_error", i.IPAddress, "failed", "Callback service not available")
		return nil // Don't fail the operation if callback service is not available
	}

	// Create whitelist priority manager for enhanced priority handling
	priorityManager := NewWhitelistPriorityManager(service)

	// Use service mutex for thread safety
	service.mu.Lock()
	defer service.mu.Unlock()

	switch action {
	case "add":
		// Use priority manager to ensure proper whitelist priority
		if err := priorityManager.EnforceWhitelistPriority(i.IPAddress, i.IsWhitelisted); err != nil {
			logCallbackAction("ip_add_error", i.IPAddress, "failed", fmt.Sprintf("Failed to add IP: %v", err))
			return err
		}
		logCallbackAction("ip_add", i.IPAddress, "success",
			fmt.Sprintf("IP added to %s", map[bool]string{true: "whitelist", false: "blocklist"}[i.IsWhitelisted]))
		return nil

	case "update":
		// For updates, remove from both sets first, then add to correct set
		service.firewallManager.UnwhitelistIP(i.IPAddress)
		service.firewallManager.UnblockIP(i.IPAddress)

		// Now add to the correct set
		if err := priorityManager.EnforceWhitelistPriority(i.IPAddress, i.IsWhitelisted); err != nil {
			logCallbackAction("ip_update_error", i.IPAddress, "failed", fmt.Sprintf("Failed to update IP: %v", err))
			return err
		}
		logCallbackAction("ip_update", i.IPAddress, "success",
			fmt.Sprintf("IP updated to %s", map[bool]string{true: "whitelist", false: "blocklist"}[i.IsWhitelisted]))
		return nil

	case "remove":
		if i.IsWhitelisted {
			if err := service.firewallManager.UnwhitelistIP(i.IPAddress); err != nil {
				logCallbackAction("ip_unwhitelist_error", i.IPAddress, "failed", fmt.Sprintf("Failed to remove IP from whitelist: %v", err))
				return err
			}
			logCallbackAction("ip_unwhitelist", i.IPAddress, "success", "IP removed from whitelist")
		} else {
			if err := service.firewallManager.UnblockIP(i.IPAddress); err != nil {
				logCallbackAction("ip_unblock_error", i.IPAddress, "failed", fmt.Sprintf("Failed to remove IP from blocklist: %v", err))
				return err
			}
			logCallbackAction("ip_unblock", i.IPAddress, "success", "IP removed from blocklist")
		}
		return nil

	case "remove_both":
		// Remove from both whitelist and blocklist (safe cleanup)
		service.firewallManager.UnwhitelistIP(i.IPAddress)
		service.firewallManager.UnblockIP(i.IPAddress)
		logCallbackAction("ip_remove_both", i.IPAddress, "success", "IP removed from both whitelist and blocklist")
		return nil
	}
	return nil
}

func (r *IPRange) syncIPSetRule(action string) error {
	service := GetIPSetCallbackService()
	if service == nil || service.firewallManager == nil {
		return nil
	}

	// Create whitelist priority manager for enhanced priority handling
	priorityManager := NewWhitelistPriorityManager(service)

	mutex.Lock()
	defer mutex.Unlock()

	switch action {
	case "add":
		// Use priority manager to ensure proper whitelist priority for ranges
		if err := priorityManager.EnforceWhitelistPriorityRange(r.CIDR, r.IsWhitelisted); err != nil {
			logCallbackAction("range_add_error", r.CIDR, "failed", fmt.Sprintf("Failed to add IP range: %v", err))
			return err
		}
		logCallbackAction("range_add", r.CIDR, "success",
			fmt.Sprintf("IP range added to %s", map[bool]string{true: "whitelist", false: "blocklist"}[r.IsWhitelisted]))
		return nil

	case "remove":
		if r.IsWhitelisted {
			if err := service.firewallManager.UnwhitelistIPRange(r.CIDR); err != nil {
				logCallbackAction("range_unwhitelist_error", r.CIDR, "failed", fmt.Sprintf("Failed to remove range from whitelist: %v", err))
				return err
			}
			logCallbackAction("range_unwhitelist", r.CIDR, "success", "IP range removed from whitelist")
		} else {
			if err := service.firewallManager.UnblockIPRange(r.CIDR); err != nil {
				logCallbackAction("range_unblock_error", r.CIDR, "failed", fmt.Sprintf("Failed to remove range from blocklist: %v", err))
				return err
			}
			logCallbackAction("range_unblock", r.CIDR, "success", "IP range removed from blocklist")
		}
		return nil

	case "remove_both":
		// Remove from both whitelist and blocklist (safe cleanup)
		service.firewallManager.UnwhitelistIPRange(r.CIDR)
		service.firewallManager.UnblockIPRange(r.CIDR)
		logCallbackAction("range_remove_both", r.CIDR, "success", "IP range removed from both whitelist and blocklist")
		return nil
	}
	return nil
}

// Global callback service instance
var globalCallbackService *IPSetCallbackService

// SetIPSetCallbackService sets the global callback service
func SetIPSetCallbackService(service *IPSetCallbackService) {
	mutex.Lock()
	defer mutex.Unlock()
	globalCallbackService = service
}

// GetIPSetCallbackService gets the global callback service
func GetIPSetCallbackService() *IPSetCallbackService {
	mutex.Lock()
	defer mutex.Unlock()
	return globalCallbackService
}

// NewIPSetCallbackService creates a new callback service
func NewIPSetCallbackService(firewallManager FirewallManagerInterface) *IPSetCallbackService {
	return &IPSetCallbackService{
		firewallManager: firewallManager,
	}
}

// Enhanced callback logging and whitelist priority handling

// logCallbackAction logs callback actions for debugging and monitoring
func logCallbackAction(actionType, target, result, details string) {
	// In a production environment, you might want to use a proper logger
	// For now, we'll use a simple approach that can be extended
	if service := GetIPSetCallbackService(); service != nil {
		// Could extend this to use a logger interface in the future
		// For now, this is a placeholder for callback action logging
	}
}

// WhitelistPriorityManager handles whitelist priority enforcement
type WhitelistPriorityManager struct {
	service *IPSetCallbackService
}

// NewWhitelistPriorityManager creates a new whitelist priority manager
func NewWhitelistPriorityManager(service *IPSetCallbackService) *WhitelistPriorityManager {
	return &WhitelistPriorityManager{service: service}
}

// EnforceWhitelistPriority ensures whitelist rules take priority over blocklist rules
func (w *WhitelistPriorityManager) EnforceWhitelistPriority(ip string, isWhitelisted bool) error {
	if w.service == nil || w.service.firewallManager == nil {
		return nil
	}

	if isWhitelisted {
		// Remove from blocklist first, then add to whitelist
		w.service.firewallManager.UnblockIP(ip)
		return w.service.firewallManager.WhitelistIP(ip, "system")
	} else {
		// Remove from whitelist, then add to blocklist
		w.service.firewallManager.UnwhitelistIP(ip)
		return w.service.firewallManager.BlockIP(ip, "system")
	}
}

// EnforceWhitelistPriorityRange ensures whitelist rules take priority for IP ranges
func (w *WhitelistPriorityManager) EnforceWhitelistPriorityRange(cidr string, isWhitelisted bool) error {
	if w.service == nil || w.service.firewallManager == nil {
		return nil
	}

	if isWhitelisted {
		// Remove from blocklist first, then add to whitelist
		w.service.firewallManager.UnblockIPRange(cidr)
		return w.service.firewallManager.WhitelistIPRange(cidr, "system")
	} else {
		// Remove from whitelist, then add to blocklist
		w.service.firewallManager.UnwhitelistIPRange(cidr)
		return w.service.firewallManager.BlockIPRange(cidr, "system")
	}
}
