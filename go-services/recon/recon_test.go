package recon

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestParseWordlist(t *testing.T) {
	data := "www\napi\n# comment\nmail\n"
	words := ParseWordlist(data)
	if len(words) != 3 {
		t.Fatalf("expected 3 words, got %d", len(words))
	}
}

func TestExtractParams(t *testing.T) {
	urls := []string{
		"https://example.com/search?q=test&page=1",
		"https://example.com/search?q=other",
	}
	results := ExtractParams(urls)
	if len(results) != 2 { // q and page (deduplicated)
		t.Fatalf("expected 2 params, got %d", len(results))
	}
}

func TestCrawlerInit(t *testing.T) {
	c := NewCrawler(2)
	if c.MaxDepth != 2 {
		t.Fatal("unexpected max depth")
	}
}

func TestHTTPProberInit(t *testing.T) {
	p := NewHTTPProber()
	if len(p.Ports) != 4 {
		t.Fatal("expected 4 default ports")
	}
}

func TestCrawler(t *testing.T) {
	t.Setenv("ALLOWED_DOMAINS", "127.0.0.1,localhost")
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<html><body><a href="/page1">Page 1</a><a href="https://other.com">Other</a></body></html>`)
	})
	mux.HandleFunc("/page1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<html><body><a href="/page2">Page 2</a></body></html>`)
	})
	mux.HandleFunc("/page2", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<html><body>Done</body></html>`)
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	c := NewCrawler(2, "test-trace")
	results := c.Crawl(context.Background(), ts.URL)

	count := 0
	for range results {
		count++
	}

	// Should find /, /page1, and /page2
	if count != 3 {
		t.Errorf("expected 3 results, got %d", count)
	}
}

func TestSubdomainEnumeratorTimeout(t *testing.T) {
	e := NewSubdomainEnumerator()
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	ch := e.BruteForce(ctx, "nonexistent.invalid", []string{"www"})
	count := 0
	for range ch {
		count++
	}
	// Should complete without hanging
}
