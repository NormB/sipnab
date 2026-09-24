// Command get-dialog calls GET /v1/dialogs/{call_id}: one dialog's state and message count.
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
)

func main() {
	baseURL := getenv("SIPNAB_URL", "http://127.0.0.1:8080")
	token := getenv("SIPNAB_API_KEY", "my-secret-token")
	callID := "12013223@203.0.113.195"
	if len(os.Args) > 1 {
		callID = os.Args[1]
	}
	if err := run(baseURL, token, callID); err != nil {
		fmt.Fprintln(os.Stderr, "get-dialog:", err)
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
	// snippet:start get-dialog
	req, err := http.NewRequest(http.MethodGet,
		baseURL+"/v1/dialogs/"+url.PathEscape(callID), nil)
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
		return fmt.Errorf("GET /v1/dialogs/%s: %s", callID, resp.Status)
	}

	// REST returns an aggregated dialog: `msg_count`, not the messages themselves.
	var dialog struct {
		State    string `json:"state"`
		MsgCount int    `json:"msg_count"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&dialog); err != nil {
		return err
	}
	fmt.Printf("State: %s, Messages: %d\n", dialog.State, dialog.MsgCount)
	// snippet:end get-dialog
	return nil
}
