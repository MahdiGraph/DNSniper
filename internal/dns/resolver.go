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
	Timeout time.Duration
}

// NewStandardResolver creates a new standard resolver
func NewStandardResolver() *StandardResolver {
	return &StandardResolver{
		Timeout: 5 * time.Second,
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

	// Perform lookup with context for timeout
	addrs, err := net.DefaultResolver.LookupHost(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve domain %s: %w", domain, err)
	}

	// Extract valid IP addresses
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip != nil {
			ips = append(ips, addr)
		}
	}

	return ips, nil
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

	// Perform lookup with context for timeout
	addrs, err := resolver.LookupHost(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve domain %s with DNS server %s: %w", domain, dnsServer, err)
	}

	// Extract valid IP addresses
	var ips []string
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip != nil {
			ips = append(ips, addr)
		}
	}

	return ips, nil
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
	return r.Results[domain], nil
}

// SetResult sets the mock result for a domain
func (r *MockResolver) SetResult(domain string, ips []string) {
	r.Results[domain] = ips
}

// SetError sets the mock error for a domain
func (r *MockResolver) SetError(domain string, err error) {
	r.Errors[domain] = err
}
