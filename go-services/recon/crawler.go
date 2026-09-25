package recon

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// URLResult represents a discovered URL.
type URLResult struct {
	URL    string `json:"url"`
	Source string `json:"source"`
	Depth  int    `json:"depth"`
}

// Crawler discovers URLs by following links.
type Crawler struct {
	Client      *http.Client
	MaxDepth    int
	Concurrency int
	TraceID     string // For unified telemetry
	visited     sync.Map
}

func NewCrawler(maxDepth int, traceID ...string) *Crawler {
	tid := ""
	if len(traceID) > 0 {
		tid = traceID[0]
	}
	return &Crawler{
		Client: &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if err := checkScope(req.URL.String()); err != nil {
					return http.ErrUseLastResponse
				}
				if len(via) >= 3 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		MaxDepth:    maxDepth,
		Concurrency: 10,
		TraceID:     tid,
	}
}

var linkRe = regexp.MustCompile(`(?i)href=["']([^"']+)["']`)

// Crawl starts from a seed URL and discovers linked pages.
func (c *Crawler) Crawl(ctx context.Context, seed string) <-chan URLResult {
	results := make(chan URLResult, 200)
	sem := make(chan struct{}, c.Concurrency)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		c.crawlURL(ctx, seed, 0, results, sem, &wg)
		wg.Wait()
		close(results)
	}()

	return results
}

func (c *Crawler) crawlURL(ctx context.Context, url string, depth int, results chan<- URLResult, sem chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()

	if depth > c.MaxDepth {
		return
	}
	if _, loaded := c.visited.LoadOrStore(url, true); loaded {
		return
	}

	// Validate URL against ALLOWED_DOMAINS before crawling
	if err := checkScope(url); err != nil {
		return // Skip URLs not in allowed list
	}

	select {
	case <-ctx.Done():
		return
	case sem <- struct{}{}:
		defer func() { <-sem }()
	}

	results <- URLResult{URL: url, Source: "crawl", Depth: depth}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "SecAgent/1.0 (Authorized Security Scanner)")
	resp, err := c.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return
	}

	matches := linkRe.FindAllSubmatch(body, -1)
	for _, m := range matches {
		link := string(m[1])
		resolved := resolveURL(url, link)
		if resolved != "" && isSameHost(url, resolved) {
			wg.Add(1)
			go c.crawlURL(ctx, resolved, depth+1, results, sem, wg)
		}
	}
}

func resolveURL(base, href string) string {
	if strings.HasPrefix(href, "http://") || strings.HasPrefix(href, "https://") {
		return href
	}
	if strings.HasPrefix(href, "//") {
		return "https:" + href
	}
	if strings.HasPrefix(href, "/") {
		parts := strings.SplitN(base, "/", 4)
		if len(parts) >= 3 {
			return parts[0] + "//" + parts[2] + href
		}
	}
	return ""
}

func isSameHost(base, target string) bool {
	bParts := strings.SplitN(base, "/", 4)
	tParts := strings.SplitN(target, "/", 4)
	if len(bParts) < 3 || len(tParts) < 3 {
		return false
	}
	return bParts[2] == tParts[2]
}
