package recon

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Result holds a discovered subdomain with metadata.
type Result struct {
	Domain    string   `json:"domain"`
	IPs       []string `json:"ips,omitempty"`
	Source    string   `json:"source"`
	Timestamp int64    `json:"timestamp"`
}

// SubdomainEnumerator discovers subdomains using multiple techniques.
type SubdomainEnumerator struct {
	Resolvers   []string
	Timeout     time.Duration
	Concurrency int
	resolverIdx uint32
	pool        []*net.Resolver
}

func NewSubdomainEnumerator() *SubdomainEnumerator {
	resolvers := []string{"8.8.8.8:53", "1.1.1.1:53", "9.9.9.9:53", "64.6.64.6:53"}
	s := &SubdomainEnumerator{
		Resolvers:   resolvers,
		Timeout:     5 * time.Second,
		Concurrency: 50,
	}

	// Pre-create resolver pool
	for _, addr := range resolvers {
		addr := addr // capture
		s.pool = append(s.pool, &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: s.Timeout}
				return d.DialContext(ctx, "udp", addr)
			},
		})
	}
	return s
}

func (s *SubdomainEnumerator) getNextResolver() *net.Resolver {
	idx := atomic.AddUint32(&s.resolverIdx, 1)
	return s.pool[idx%uint32(len(s.pool))]
}

// BruteForce performs DNS brute-force against a wordlist.
func (s *SubdomainEnumerator) BruteForce(ctx context.Context, domain string, wordlist []string) <-chan Result {
	results := make(chan Result, s.Concurrency*2)
	sem := make(chan struct{}, s.Concurrency)
	var wg sync.WaitGroup

	go func() {
		defer close(results)
		for _, word := range wordlist {
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
			}
			wg.Add(1)
			go func(sub string) {
				defer wg.Done()
				defer func() { <-sem }()

				fqdn := fmt.Sprintf("%s.%s", sub, domain)
				ips, err := s.resolve(ctx, fqdn)
				if err == nil && len(ips) > 0 {
					// Validate discovered subdomain against ALLOWED_DOMAINS
					if err := checkScope(fqdn); err != nil {
						return // Skip domains not in allowed list
					}
					select {
					case results <- Result{
						Domain:    fqdn,
						IPs:       ips,
						Source:    "bruteforce",
						Timestamp: time.Now().Unix(),
					}:
					case <-ctx.Done():
						return
					}
				}
			}(word)
		}
		wg.Wait()
	}()

	return results
}

func (s *SubdomainEnumerator) resolve(ctx context.Context, domain string) ([]string, error) {
	// Try up to 2 different resolvers on failure
	var lastErr error
	for i := 0; i < 2; i++ {
		resolver := s.getNextResolver()
		addrs, err := resolver.LookupHost(ctx, domain)
		if err == nil {
			return addrs, nil
		}
		lastErr = err

		// If context cancelled, stop immediately
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, lastErr
}

// ParseWordlist splits newline-separated words.
func ParseWordlist(data string) []string {
	var words []string
	for _, line := range strings.Split(data, "\n") {
		w := strings.TrimSpace(line)
		if w != "" && !strings.HasPrefix(w, "#") {
			words = append(words, w)
		}
	}
	return words
}

// normalizeDomain extracts the host from a URL or returns the domain as-is
func normalizeDomain(target string) string {
	target = strings.TrimSpace(strings.ToLower(target))
	if strings.Contains(target, "://") {
		parts := strings.Split(target, "://")
		if len(parts) > 1 {
			target = parts[1]
		}
	}
	target = strings.Split(target, "/")[0]
	target = strings.Split(target, ":")[0]
	return strings.TrimLeft(target, ".")
}

// domainMatches checks if a domain matches an ALLOWED_DOMAINS pattern
func domainMatches(domain, pattern string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	pattern = strings.ToLower(strings.TrimSpace(pattern))

	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // .example.com
		return domain == pattern[2:] || strings.HasSuffix(domain, suffix)
	}
	return domain == pattern
}

// isDomainAllowed checks if a domain is in the ALLOWED_DOMAINS list
func isDomainAllowed(domain string) error {
	allowedStr := os.Getenv("ALLOWED_DOMAINS")
	if allowedStr == "" {
		return fmt.Errorf("ALLOWED_DOMAINS is not configured. Set it via environment variable before scanning")
	}

	allowedDomains := strings.Split(allowedStr, ",")
	for _, pattern := range allowedDomains {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if domainMatches(domain, pattern) {
			return nil
		}
	}

	return fmt.Errorf("domain %s is not in ALLOWED_DOMAINS", domain)
}

// CheckScope validates a domain against ALLOWED_DOMAINS policy
func CheckScope(domain string) error {
	normalized := normalizeDomain(domain)
	if normalized == "" {
		return fmt.Errorf("invalid or empty target")
	}

	// Check blocked domains first
	blockedStr := os.Getenv("BLOCKED_DOMAINS")
	if blockedStr != "" {
		blockedDomains := strings.Split(blockedStr, ",")
		for _, blocked := range blockedDomains {
			blocked = strings.TrimSpace(blocked)
			if blocked == "" {
				continue
			}
			if domainMatches(normalized, blocked) {
				return fmt.Errorf("target %s is blocked by BLOCKED_DOMAINS", normalized)
			}
		}
	}

	// Check allowed domains
	return isDomainAllowed(normalized)
}

// checkScope is an alias for CheckScope for internal use
func checkScope(domain string) error {
	return CheckScope(domain)
}
