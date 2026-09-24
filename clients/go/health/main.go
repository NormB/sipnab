// Command health calls GET /health: is the REST API up? Prints ok.
//
// docs/rest-api.md shows the body of run, between the snippet markers; this
// file adds where the inputs come from and what a failure prints.
//
// SIPNAB_URL sets the API base URL (default http://127.0.0.1:8080).
package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
)

func main() {
	baseURL := getenv("SIPNAB_URL", "http://127.0.0.1:8080")
	if err := run(baseURL); err != nil {
		fmt.Fprintln(os.Stderr, "health:", err)
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

func run(baseURL string) error {
	// snippet:start health
	resp, err := http.Get(baseURL + "/health")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET /health: %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	fmt.Println(string(body)) // "ok"
	// snippet:end health
	return nil
}
