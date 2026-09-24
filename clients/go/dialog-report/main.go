// Command dialog-report calls GET /v1/dialogs/{call_id}/report: what the media diagnosis says about one call.
//
// docs/rest-api.md shows the body of run, between the snippet markers; this
// file adds where the inputs come from and what a failure prints.
//
// SIPNAB_URL sets the API base URL (default http://127.0.0.1:8080) and
// SIPNAB_API_KEY the bearer token (default my-secret-token).
// The first argument is the Call-ID (default 12013223@203.0.113.195).
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

func main() {
	baseURL := getenv("SIPNAB_URL", "http://127.0.0.1:8080")
	token := getenv("SIPNAB_API_KEY", "my-secret-token")
	callID := "12013223@203.0.113.195"
	if len(os.Args) > 1 {
		callID = os.Args[1]
	}
	if err := run(baseURL, token, callID); err != nil {
		fmt.Fprintln(os.Stderr, "dialog-report:", err)
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

func run(baseURL, token, callID string) error {
	// snippet:start dialog-report
	req, err := http.NewRequest(http.MethodGet,
		baseURL+"/v1/dialogs/"+url.PathEscape(callID)+"/report", nil)
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
		return fmt.Errorf("GET /v1/dialogs/%s/report: %s", callID, resp.Status)
	}

	// `diagnosis` carries four booleans plus `hints`; there is no `summary` field.
	var report struct {
		Diagnosis struct {
			Hints []string `json:"hints"`
		} `json:"diagnosis"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&report); err != nil {
		return err
	}
	if hints := report.Diagnosis.Hints; len(hints) > 0 {
		fmt.Println("Diagnosis: " + strings.Join(hints, "; "))
	} else {
		fmt.Println("Diagnosis: no issues detected")
	}
	// snippet:end dialog-report
	return nil
}
