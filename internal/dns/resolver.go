package dns

import (
	"context"
	"fmt"
	"net"
)

// Resolver interface for domain resolution
type Resolver interface {
	ResolveDomain(domain, dnsServer string) ([]string, error)
}

// StandardResolver implements the standard DNS resolver
type StandardResolver struct{}

// NewStandardResolver creates a new standard resolver
func NewStandardResolver() *StandardResolver {
	return &StandardResolver{}
}

// ResolveDomain resolves a domain to its IP addresses
func (r *StandardResolver) ResolveDomain(domain, dnsServer string) ([]string, error) {
	// If no custom DNS server is specified, use system default
	if dnsServer == "" {
		return resolveWithSystemDNS(domain)
	}

	// Using custom DNS server
	return resolveWithCustomDNS(domain, dnsServer)
}

// resolveWithSystemDNS resolves a domain using the system DNS settings
func resolveWithSystemDNS(domain string) ([]string, error) {
	// Resolve IPv4 addresses
	ipv4Addrs, err := net.LookupIP(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve domain %s: %w", domain, err)
	}

	// Extract IP addresses as strings
	var ips []string
	for _, ip := range ipv4Addrs {
		// We only want IPv4 addresses
		if ipv4 := ip.To4(); ipv4 != nil {
			ips = append(ips, ipv4.String())
		}
	}

	return ips, nil
}

// resolveWithCustomDNS resolves a domain using a custom DNS server
func resolveWithCustomDNS(domain, dnsServer string) ([]string, error) {
	// Create a custom resolver
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, "udp", dnsServer+":53")
		},
	}

	// Lookup addresses
	addrs, err := r.LookupHost(context.Background(), domain)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve domain %s with DNS server %s: %w", domain, dnsServer, err)
	}

	// Filter for IPv4 addresses
	var ips []string
	for _, addr := range addrs {
		if net.ParseIP(addr).To4() != nil {
			ips = append(ips, addr)
		}
	}

	return ips, nil
}

// MockResolver implements a mock resolver for testing
type MockResolver struct {
	Results map[string][]string
	Errors  map[string]error
}

// ResolveDomain implements the Resolver interface for testing
func (m *MockResolver) ResolveDomain(domain, dnsServer string) ([]string, error) {
	if err, ok := m.Errors[domain]; ok {
		return nil, err
	}
	return m.Results[domain], nil
}
