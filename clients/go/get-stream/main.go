// Command get-stream calls GET /v1/streams/{id}: one RTP stream's codec and packet count.
//
// docs/rest-api.md shows the body of run, between the snippet markers; this
// file adds where the inputs come from and what a failure prints.
//
// SIPNAB_URL sets the API base URL (default http://127.0.0.1:8080) and
// SIPNAB_API_KEY the bearer token (default my-secret-token).
// The first argument is the SSRC (default 0x1a2b3c4d).
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
	ssrc := "0x1a2b3c4d"
	if len(os.Args) > 1 {
		ssrc = os.Args[1]
	}
	if err := run(baseURL, token, ssrc); err != nil {
		fmt.Fprintln(os.Stderr, "get-stream:", err)
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

func run(baseURL, token, ssrc string) error {
	// snippet:start get-stream
	req, err := http.NewRequest(http.MethodGet,
		baseURL+"/v1/streams/"+url.PathEscape(ssrc), nil)
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
		return fmt.Errorf("GET /v1/streams/%s: %s", ssrc, resp.Status)
	}

	var stream struct {
		Codec   string `json:"codec"` // empty when no codec was identified
		Packets int    `json:"packets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&stream); err != nil {
		return err
	}
	fmt.Printf("Codec: %s, Packets: %d\n", stream.Codec, stream.Packets)
	// snippet:end get-stream
	return nil
}
