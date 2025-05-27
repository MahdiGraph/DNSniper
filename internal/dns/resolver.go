package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// Resolver interface for domain resolution
type Resolver interface {
	ResolveDomain(domain string, resolver string) ([]string, error)
}

// StandardResolver implements domain resolution using the Go standard library
type StandardResolver struct {
	Timeout    time.Duration
	RetryCount int
	RetryDelay time.Duration
	MaxResults int
	QueryTypes []string
}

// NewStandardResolver creates a new standard resolver with default settings
func NewStandardResolver() *StandardResolver {
	return &StandardResolver{
		Timeout:    5 * time.Second,
		RetryCount: 2,
		RetryDelay: 500 * time.Millisecond,
		MaxResults: 50,
		QueryTypes: []string{"A", "AAAA"}, // Default to both IPv4 and IPv6
	}
}

// ResolveDomain resolves a domain to its IP addresses using the specified resolver
func (r *StandardResolver) ResolveDomain(domain string, resolver string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.Timeout)
	defer cancel()

	// If no resolver specified, use system default
	if resolver == "" {
		return r.resolveWithSystemDNS(ctx, domain)
	}

	// Use custom resolver
	return r.resolveWithCustomDNS(ctx, domain, resolver)
}

// resolveWithSystemDNS resolves a domain using system DNS settings
func (r *StandardResolver) resolveWithSystemDNS(ctx context.Context, domain string) ([]string, error) {
	var ips []string
	var lastErr error

	// Try multiple times with backoff
	for attempt := 0; attempt <= r.RetryCount; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ips, ctx.Err()
			case <-time.After(r.RetryDelay):
				// Continue with retry after delay
			}
		}

		// Perform lookup with context for timeout
		addrs, err := net.DefaultResolver.LookupHost(ctx, domain)
		if err == nil {
			// Extract valid IP addresses and enforce max results
			return r.processAddresses(addrs), nil
		}

		lastErr = err
	}

	if len(ips) > 0 {
		// Return partial results if we got any
		return ips, nil
	}

	return nil, fmt.Errorf("failed to resolve domain %s after %d attempts: %w",
		domain, r.RetryCount+1, lastErr)
}

// resolveWithCustomDNS resolves a domain using a custom DNS server
func (r *StandardResolver) resolveWithCustomDNS(ctx context.Context, domain string, dnsServer string) ([]string, error) {
	// Ensure DNS server has port
	if !strings.Contains(dnsServer, ":") {
		dnsServer = dnsServer + ":53"
	}

	// Create custom resolver
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{
				Timeout: r.Timeout,
			}
			return dialer.DialContext(ctx, "udp", dnsServer)
		},
	}

	var ips []string
	var lastErr error

	// Try multiple times with backoff
	for attempt := 0; attempt <= r.RetryCount; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ips, ctx.Err()
			case <-time.After(r.RetryDelay):
				// Continue with retry after delay
			}
		}

		// Perform lookup with context for timeout
		addrs, err := resolver.LookupHost(ctx, domain)
		if err == nil {
			// Extract valid IP addresses and enforce max results
			return r.processAddresses(addrs), nil
		}

		lastErr = err
	}

	if len(ips) > 0 {
		// Return partial results if we got any
		return ips, nil
	}

	return nil, fmt.Errorf("failed to resolve domain %s with DNS server %s after %d attempts: %w",
		domain, dnsServer, r.RetryCount+1, lastErr)
}

// processAddresses extracts valid IP addresses and enforces max results
func (r *StandardResolver) processAddresses(addrs []string) []string {
	var ips []string

	// Extract valid IP addresses
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip != nil {
			ips = append(ips, addr)

			// Enforce max results
			if r.MaxResults > 0 && len(ips) >= r.MaxResults {
				break
			}
		}
	}

	return ips
}

// MockResolver is a resolver implementation for testing
type MockResolver struct {
	Results map[string][]string
	Errors  map[string]error
}

// NewMockResolver creates a new mock resolver for testing
func NewMockResolver() *MockResolver {
	return &MockResolver{
		Results: make(map[string][]string),
		Errors:  make(map[string]error),
	}
}

// ResolveDomain implements the Resolver interface for testing
func (r *MockResolver) ResolveDomain(domain string, resolver string) ([]string, error) {
	if err, ok := r.Errors[domain]; ok {
		return nil, err
	}

	// Check for resolver-specific results
	key := domain
	if resolver != "" {
		key = domain + "@" + resolver
		if ips, ok := r.Results[key]; ok {
			return ips, nil
		}
	}

	// Return domain-only results or empty slice
	return r.Results[domain], nil
}

// SetResult sets the mock result for a domain
func (r *MockResolver) SetResult(domain string, ips []string) {
	r.Results[domain] = ips
}

// SetResolverResult sets mock result for a domain with a specific resolver
func (r *MockResolver) SetResolverResult(domain string, resolver string, ips []string) {
	r.Results[domain+"@"+resolver] = ips
}

// SetError sets the mock error for a domain
func (r *MockResolver) SetError(domain string, err error) {
	r.Errors[domain] = err
}

// ClearAll clears all mock data
func (r *MockResolver) ClearAll() {
	r.Results = make(map[string][]string)
	r.Errors = make(map[string]error)
}
