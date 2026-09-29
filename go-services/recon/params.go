package recon

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ParamResult represents a discovered parameter.
type ParamResult struct {
	URL       string `json:"url"`
	Parameter string `json:"parameter"`
	Method    string `json:"method"`
	Source    string `json:"source"`
}

// ParamDiscovery finds parameters in URLs via reflection and common wordlists.
type ParamDiscovery struct {
	Client       *http.Client
	Concurrency  int
	CommonParams []string
}

func NewParamDiscovery() *ParamDiscovery {
	return &ParamDiscovery{
		Client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		Concurrency: 20,
		CommonParams: []string{
			"id", "page", "q", "search", "query", "url", "redirect",
			"file", "path", "dir", "action", "cmd", "exec", "callback",
			"next", "return", "token", "user", "email", "name",
		},
	}
}

// Discover tests common parameters against target URLs.
func (pd *ParamDiscovery) Discover(ctx context.Context, urls []string) <-chan ParamResult {
	results := make(chan ParamResult, 100)
	sem := make(chan struct{}, pd.Concurrency)
	var wg sync.WaitGroup

	go func() {
		defer close(results)
		for _, rawURL := range urls {
			for _, param := range pd.CommonParams {
				select {
				case <-ctx.Done():
					return
				case sem <- struct{}{}:
				}
				wg.Add(1)
				go func(u, p string) {
					defer wg.Done()
					defer func() { <-sem }()

					testURL := appendParam(u, p, "secagent_test")
					if testURL == "" {
						return
					}

					req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
					if err != nil {
						return
					}
					resp, err := pd.Client.Do(req)
					if err != nil {
						return
					}
					defer resp.Body.Close()

					// If reflected in response or different status, parameter is accepted
					if resp.StatusCode < 500 {
						results <- ParamResult{
							URL:       u,
							Parameter: p,
							Method:    "GET",
							Source:    "bruteforce",
						}
					}
				}(rawURL, param)
			}
		}
		wg.Wait()
	}()

	return results
}

func appendParam(rawURL, param, value string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	q := u.Query()
	q.Set(param, value)
	u.RawQuery = q.Encode()
	return u.String()
}

// ExtractParams extracts existing query parameters from URLs.
func ExtractParams(urls []string) []ParamResult {
	var results []ParamResult
	seen := make(map[string]bool)

	for _, rawURL := range urls {
		u, err := url.Parse(rawURL)
		if err != nil {
			continue
		}
		for param := range u.Query() {
			key := fmt.Sprintf("%s:%s:%s", u.Host, u.Path, param)
			if !seen[key] {
				seen[key] = true
				results = append(results, ParamResult{
					URL:       strings.Split(rawURL, "?")[0],
					Parameter: param,
					Method:    "GET",
					Source:    "extracted",
				})
			}
		}
	}
	return results
}
