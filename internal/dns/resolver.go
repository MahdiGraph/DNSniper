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

// ResolveDomain resolves a domain to its IP addresses (both IPv4 and IPv6)
func (r *StandardResolver) ResolveDomain(domain, dnsServer string) ([]string, error) {
	var ips []string

	// If no custom DNS server is specified, use system default
	if dnsServer == "" {
		ipv4, ipv6, err := resolveWithSystemDNS(domain)
		if err != nil {
			return nil, err
		}
		ips = append(ips, ipv4...)
		ips = append(ips, ipv6...)
	} else {
		// Using custom DNS server
		ipv4, ipv6, err := resolveWithCustomDNS(domain, dnsServer)
		if err != nil {
			return nil, err
		}
		ips = append(ips, ipv4...)
		ips = append(ips, ipv6...)
	}

	return ips, nil
}

// resolveWithSystemDNS resolves a domain using the system DNS settings
func resolveWithSystemDNS(domain string) ([]string, []string, error) {
	// Resolve IP addresses
	allAddrs, err := net.LookupIP(domain)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve domain %s: %w", domain, err)
	}

	// Extract IP addresses as strings
	var ipv4s []string
	var ipv6s []string

	for _, ip := range allAddrs {
		if ipv4 := ip.To4(); ipv4 != nil {
			ipv4s = append(ipv4s, ipv4.String())
		} else {
			// This is an IPv6 address
			ipv6s = append(ipv6s, ip.String())
		}
	}

	return ipv4s, ipv6s, nil
}

// resolveWithCustomDNS resolves a domain using a custom DNS server
func resolveWithCustomDNS(domain, dnsServer string) ([]string, []string, error) {
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
		return nil, nil, fmt.Errorf("failed to resolve domain %s with DNS server %s: %w", domain, dnsServer, err)
	}

	// Separate IPv4 and IPv6 addresses
	var ipv4s []string
	var ipv6s []string

	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}

		if ip.To4() != nil {
			ipv4s = append(ipv4s, addr)
		} else {
			ipv6s = append(ipv6s, addr)
		}
	}

	return ipv4s, ipv6s, nil
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
