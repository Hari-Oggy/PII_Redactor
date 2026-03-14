// Package middleware — egress.go provides SSRF (Server-Side Request Forgery)
// prevention by validating that upstream requests only resolve to trusted
// external IPs. Blocks connections to private/internal IP ranges.
package middleware

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// SafeTransport returns an http.Transport with a custom DialContext that
// blocks connections to private/internal IP addresses. This prevents SSRF
// attacks where a compromised config file could route proxy traffic to
// internal services.
//
// allowedDomains is an optional list of domain suffixes that are always
// permitted (e.g., "api.openai.com", "api.anthropic.com").
func SafeTransport(allowedDomains []string) *http.Transport {
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}

	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("SSRF: invalid address %q: %w", addr, err)
			}

			// Check domain allowlist first (if configured).
			if len(allowedDomains) > 0 {
				allowed := false
				for _, domain := range allowedDomains {
					if strings.EqualFold(host, domain) || strings.HasSuffix(host, "."+domain) {
						allowed = true
						break
					}
				}
				if !allowed {
					return nil, fmt.Errorf("SSRF: domain %q not in allowlist", host)
				}
			}

			// Resolve the hostname to IP addresses.
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("SSRF: DNS resolution failed for %q: %w", host, err)
			}

			// Check each resolved IP against private/reserved ranges.
			for _, ip := range ips {
				if isPrivateIP(ip.IP) {
					return nil, fmt.Errorf("SSRF: blocked connection to private IP %s (resolved from %s)", ip.IP, host)
				}
			}

			// All IPs are safe — connect.
			return dialer.DialContext(ctx, network, net.JoinHostPort(host, port))
		},
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
}

// isPrivateIP checks if an IP address falls in a private, loopback,
// link-local, or otherwise reserved range that should not be accessed
// by the proxy.
func isPrivateIP(ip net.IP) bool {
	// Known private/reserved CIDR ranges.
	privateRanges := []string{
		"10.0.0.0/8",      // Private Class A
		"172.16.0.0/12",   // Private Class B
		"192.168.0.0/16",  // Private Class C
		"127.0.0.0/8",     // Loopback
		"169.254.0.0/16",  // Link-local
		"::1/128",         // IPv6 loopback
		"fc00::/7",        // IPv6 Unique Local
		"fe80::/10",       // IPv6 Link-local
		"0.0.0.0/8",       // This network
		"100.64.0.0/10",   // Shared address space (carrier NAT)
		"198.18.0.0/15",   // Benchmark testing
	}

	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}

	// Also block multicast and unspecified addresses.
	if ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}

	return false
}
