package recon

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// ProbeResult holds HTTP probe data for a host.
type ProbeResult struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Title      string `json:"title,omitempty"`
	Server     string `json:"server,omitempty"`
	TLS        bool   `json:"tls"`
	Latency    int64  `json:"latency_ms"`
}

// HTTPProber checks hosts for live HTTP services.
type HTTPProber struct {
	Client      *http.Client
	Ports       []int
	Concurrency int
}

func NewHTTPProber() *HTTPProber {
	return &HTTPProber{
		Client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:      100,
				DisableKeepAlives: false,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		Ports:       []int{80, 443, 8080, 8443},
		Concurrency: 30,
	}
}

// Probe checks multiple hosts for live HTTP services.
func (p *HTTPProber) Probe(ctx context.Context, hosts []string) <-chan ProbeResult {
	results := make(chan ProbeResult, 100)
	sem := make(chan struct{}, p.Concurrency)
	var wg sync.WaitGroup

	go func() {
		defer close(results)
		defer wg.Wait()
		for _, host := range hosts {
			// Validate host against ALLOWED_DOMAINS before probing
			if err := checkScope(host); err != nil {
				continue // Skip hosts not in allowed list
			}
			for _, port := range p.Ports {
				select {
				case <-ctx.Done():
					return
				case sem <- struct{}{}:
				}
				wg.Add(1)
				go func(h string, pt int) {
					defer wg.Done()
					defer func() { <-sem }()

					scheme := "http"
					if pt == 443 || pt == 8443 {
						scheme = "https"
					}
					url := fmt.Sprintf("%s://%s:%d", scheme, h, pt)

					start := time.Now()
					req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
					if err != nil {
						return
					}
					req.Header.Set("User-Agent", "SecAgent/1.0 (Authorized Security Scanner)")
					resp, err := p.Client.Do(req)
					if err != nil {
						return
					}
					defer resp.Body.Close()

					results <- ProbeResult{
						URL:        url,
						StatusCode: resp.StatusCode,
						Server:     resp.Header.Get("Server"),
						TLS:        scheme == "https",
						Latency:    time.Since(start).Milliseconds(),
					}
				}(host, port)
			}
		}
	}()

	return results
}
