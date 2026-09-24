// Command metrics calls GET /metrics: the Prometheus exposition, as a scraper sees it.
//
// docs/prometheus-metrics.md shows the body of run, between the snippet markers; this
// file adds where the inputs come from and what a failure prints.
//
// SIPNAB_URL sets the API base URL (default http://127.0.0.1:8080) and
// SIPNAB_API_KEY the bearer token (default my-secret-token).
package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
)

func main() {
	baseURL := getenv("SIPNAB_URL", "http://127.0.0.1:8080")
	token := getenv("SIPNAB_API_KEY", "my-secret-token")
	if err := run(baseURL, token); err != nil {
		fmt.Fprintln(os.Stderr, "metrics:", err)
		os.Exit(1)
	}
}

// getenv returns the named variable, or fallback when it is unset or empty.
func getenv(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func run(baseURL, token string) error {
	// snippet:start metrics
	req, err := http.NewRequest(http.MethodGet, baseURL+"/metrics", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET /metrics: %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	fmt.Print(string(body)) // Prometheus text format
	// snippet:end metrics
	return nil
}
