// Command stats calls GET /v1/stats: dialog totals and post-dial delay percentiles.
//
// docs/rest-api.md shows the body of run, between the snippet markers; this
// file adds where the inputs come from and what a failure prints.
//
// SIPNAB_URL sets the API base URL (default http://127.0.0.1:8080) and
// SIPNAB_API_KEY the bearer token (default my-secret-token).
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

func main() {
	baseURL := getenv("SIPNAB_URL", "http://127.0.0.1:8080")
	token := getenv("SIPNAB_API_KEY", "my-secret-token")
	if err := run(baseURL, token); err != nil {
		fmt.Fprintln(os.Stderr, "stats:", err)
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
	// snippet:start stats
	req, err := http.NewRequest(http.MethodGet, baseURL+"/v1/stats", nil)
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
		return fmt.Errorf("GET /v1/stats: %s", resp.Status)
	}

	var stats struct {
		Dialogs struct {
			Total  int `json:"total"`
			Active int `json:"active"`
			Failed int `json:"failed"`
		} `json:"dialogs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		return err
	}
	d := stats.Dialogs
	fmt.Printf("Dialogs: %d total, %d active, %d failed\n", d.Total, d.Active, d.Failed)
	// snippet:end stats
	return nil
}
