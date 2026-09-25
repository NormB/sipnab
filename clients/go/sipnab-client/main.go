// snippet:start sipnab-client
// Command sipnab-client lists every failed dialog, a page at a time, and
// prints the post-dial delay and NAT diagnosis of the first five.
//
// SIPNAB_URL sets the API base URL (default http://localhost:8080) and
// SIPNAB_API_KEY the bearer token, which is required.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"
)

type DialogSummary struct {
	CallID      string  `json:"call_id"`
	State       string  `json:"state"`
	FromUser    *string `json:"from_user"`
	ToUser      *string `json:"to_user"`
	DurationSec float64 `json:"duration_sec"`
	MsgCount    int     `json:"msg_count"`
}

type DialogTiming struct {
	PddMs       *int64 `json:"pdd_ms"`
	SetupMs     *int64 `json:"setup_ms"`
	Retransmits int    `json:"retransmits"`
}

type DialogDiagnosis struct {
	OneWayAudio bool `json:"one_way_audio"`
	NatMismatch bool `json:"nat_mismatch"`
	NoMedia     bool `json:"no_media"`
}

type FullDialog struct {
	CallID    string          `json:"call_id"`
	State     string          `json:"state"`
	Timing    DialogTiming    `json:"timing"`
	Diagnosis DialogDiagnosis `json:"diagnosis"`
}

type DialogsPage struct {
	Dialogs []DialogSummary `json:"dialogs"`
	Total   int             `json:"total"`
	Limit   int             `json:"limit"`
	Offset  int             `json:"offset"`
}

type Sipnab struct {
	Base   string
	Token  string
	Client *http.Client
}

func newSipnab() (*Sipnab, error) {
	base := os.Getenv("SIPNAB_URL")
	if base == "" {
		base = "http://localhost:8080"
	}
	token := os.Getenv("SIPNAB_API_KEY")
	if token == "" {
		return nil, fmt.Errorf("SIPNAB_API_KEY not set")
	}
	return &Sipnab{
		Base:   base,
		Token:  token,
		Client: &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (s *Sipnab) get(path string, params url.Values, out any) error {
	u, err := url.Parse(s.Base + path)
	if err != nil {
		return err
	}
	u.RawQuery = params.Encode()
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.Token)
	resp, err := s.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return fmt.Errorf("GET %s: 401 auth failed", path)
	case http.StatusServiceUnavailable:
		return fmt.Errorf("GET %s: 503 rate-limited or conn cap reached", path)
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("GET %s: HTTP %d", path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (s *Sipnab) ListDialogs(state string) ([]DialogSummary, error) {
	var all []DialogSummary
	offset := 0
	for {
		params := url.Values{"limit": {"100"}, "offset": {fmt.Sprint(offset)}}
		if state != "" {
			params.Set("state", state)
		}
		var page DialogsPage
		if err := s.get("/v1/dialogs", params, &page); err != nil {
			return nil, err
		}
		if len(page.Dialogs) == 0 {
			break
		}
		all = append(all, page.Dialogs...)
		offset += len(page.Dialogs)
		if len(all) >= page.Total {
			break
		}
	}
	return all, nil
}

// GetDialog fetches the full (aggregated) dialog. REST has no
// per-message detail — for that, use the CLI --json mode or the
// MCP get_dialog tool.
func (s *Sipnab) GetDialog(callID string) (*FullDialog, error) {
	var full FullDialog
	if err := s.get("/v1/dialogs/"+url.PathEscape(callID), nil, &full); err != nil {
		return nil, err
	}
	return &full, nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "sipnab-client:", err)
		os.Exit(1)
	}
}

func run() error {
	s, err := newSipnab()
	if err != nil {
		return err
	}
	failed, err := s.ListDialogs("Failed")
	if err != nil {
		return err
	}
	fmt.Printf("%d failed dialogs\n", len(failed))

	for i, d := range failed {
		if i >= 5 {
			break
		}
		full, err := s.GetDialog(d.CallID)
		if err != nil {
			return err
		}
		pdd := "—"
		if full.Timing.PddMs != nil {
			pdd = fmt.Sprintf("%dms", *full.Timing.PddMs)
		}
		fmt.Printf("  %s  state=%s  pdd=%s  nat_mismatch=%t\n",
			d.CallID, d.State, pdd, full.Diagnosis.NatMismatch)
	}
	return nil
}

// snippet:end sipnab-client
