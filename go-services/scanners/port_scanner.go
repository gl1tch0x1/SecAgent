package scanners

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/secagents/go-services/recon"
)

// PortResult holds port scan results.
type PortResult struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Open    bool   `json:"open"`
	Service string `json:"service,omitempty"`
	Banner  string `json:"banner,omitempty"`
}

// PortScanner performs TCP connect scans with banner grabbing.
type PortScanner struct {
	Timeout     time.Duration
	Concurrency int
}

func NewPortScanner() *PortScanner {
	return &PortScanner{
		Timeout:     3 * time.Second,
		Concurrency: 100,
	}
}

// Scan checks specified ports on a host and attempts banner grabbing.
func (ps *PortScanner) Scan(ctx context.Context, host string, ports []int) <-chan PortResult {
	results := make(chan PortResult, ps.Concurrency*2)
	sem := make(chan struct{}, ps.Concurrency)
	var wg sync.WaitGroup

	// Validate host against ALLOWED_DOMAINS before scanning
	if err := recon.CheckScope(host); err != nil {
		close(results)
		return results
	}

	go func() {
		defer close(results)
		for _, port := range ports {
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
			}
			wg.Add(1)
			go func(p int) {
				defer wg.Done()
				defer func() { <-sem }()

				addr := fmt.Sprintf("%s:%d", host, p)
				d := net.Dialer{Timeout: ps.Timeout}
				conn, err := d.DialContext(ctx, "tcp", addr)
				if err != nil {
					return
				}
				defer conn.Close()

				result := PortResult{Host: host, Port: p, Open: true}

				// Attempt banner grab
				conn.SetReadDeadline(time.Now().Add(ps.Timeout))
				banner, err := bufio.NewReader(conn).ReadString('\n')
				if err == nil {
					result.Banner = strings.TrimSpace(banner)
				}

				select {
				case results <- result:
				case <-ctx.Done():
				}
			}(port)
		}
		wg.Wait()
	}()

	return results
}

// CommonPorts returns a standard set of ports to scan.
func CommonPorts() []int {
	return []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
		993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443, 8888,
	}
}
