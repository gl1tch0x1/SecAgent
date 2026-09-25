package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/secagents/go-services/recon"
	"github.com/secagents/go-services/scanners"
)

func main() {
	cmd := flag.String("cmd", "", "Command: subdomain|probe|crawl|portscan")
	target := flag.String("target", "", "Target domain or URL")
	timeout := flag.Duration("timeout", 60*time.Second, "Operation timeout")
	flag.Parse()

	if *cmd == "" || *target == "" {
		fmt.Fprintln(os.Stderr, "Usage: secagents-cli -cmd <command> -target <target>")
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	switch *cmd {
	case "subdomain":
		runSubdomain(ctx, *target)
	case "probe":
		runProbe(ctx, *target)
	case "crawl":
		runCrawl(ctx, *target)
	case "portscan":
		runPortScan(ctx, *target)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", *cmd)
		os.Exit(1)
	}
}

func runSubdomain(ctx context.Context, domain string) {
	// Validate target against ALLOWED_DOMAINS
	if err := recon.CheckScope(domain); err != nil {
		fmt.Fprintf(os.Stderr, "Scope violation: %v\n", err)
		os.Exit(1)
	}
	e := recon.NewSubdomainEnumerator()
	wordlist := recon.ParseWordlist("www\napi\nmail\ndev\nstaging\nadmin\napp\nportal")
	for r := range e.BruteForce(ctx, domain, wordlist) {
		printJSON(r)
	}
}

func runProbe(ctx context.Context, host string) {
	// Validate target against ALLOWED_DOMAINS
	if err := recon.CheckScope(host); err != nil {
		fmt.Fprintf(os.Stderr, "Scope violation: %v\n", err)
		os.Exit(1)
	}
	p := recon.NewHTTPProber()
	for r := range p.Probe(ctx, []string{host}) {
		printJSON(r)
	}
}

func runCrawl(ctx context.Context, url string) {
	// Validate target against ALLOWED_DOMAINS
	if err := recon.CheckScope(url); err != nil {
		fmt.Fprintf(os.Stderr, "Scope violation: %v\n", err)
		os.Exit(1)
	}
	c := recon.NewCrawler(3)
	for r := range c.Crawl(ctx, url) {
		printJSON(r)
	}
}

func runPortScan(ctx context.Context, host string) {
	// Validate target against ALLOWED_DOMAINS
	if err := recon.CheckScope(host); err != nil {
		fmt.Fprintf(os.Stderr, "Scope violation: %v\n", err)
		os.Exit(1)
	}
	s := scanners.NewPortScanner()
	for r := range s.Scan(ctx, host, scanners.CommonPorts()) {
		printJSON(r)
	}
}

func printJSON(v interface{}) {
	data, _ := json.Marshal(v)
	fmt.Println(string(data))
}
