// Command list-dialogs calls GET /v1/dialogs: list the failed dialogs.
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
		fmt.Fprintln(os.Stderr, "list-dialogs:", err)
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
	// snippet:start list-dialogs
	req, err := http.NewRequest(http.MethodGet,
		baseURL+"/v1/dialogs?state=Failed&limit=10", nil)
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
		return fmt.Errorf("GET /v1/dialogs: %s", resp.Status)
	}

	var result struct {
		Dialogs []struct {
			CallID   string `json:"call_id"`
			State    string `json:"state"`
			MsgCount int    `json:"msg_count"`
		} `json:"dialogs"`
		Total int `json:"total"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}
	for _, d := range result.Dialogs {
		fmt.Printf("%s: %s (%d msgs)\n", d.CallID, d.State, d.MsgCount)
	}
	fmt.Printf("%d dialogs (%d total)\n", len(result.Dialogs), result.Total)
	// snippet:end list-dialogs
	return nil
}
