# REST API & metrics

sipnab includes an optional REST API and Prometheus metrics endpoint, enabled with the `api` feature flag. The API runs as a thread inside the sipnab process, reading the same in-memory dialog/stream stores as the capture pipeline — read-only, and it never mutates capture state.

[CLI Reference](cli-reference.md#network-listeners) catalogues every API flag.

> **Looking for AI-agent access?** sipnab also exposes the same dialog / RTP / diagnostic data as a Model Context Protocol server. See [MCP Server](mcp.md) -- the MCP path uses the same in-memory stores as this REST API, so a running sipnab instance can serve both surfaces simultaneously.

## Getting started

### Step 1: Build with API support

sipnab's REST API requires the `api` feature flag:

```bash
cargo build --release --features api
```

That is additive to the default features, so it gives you the REST API on top of the TUI, audio, and the standalone metrics server. Build `full` instead when you also want the MCP server, HEP forwarding, and the TLS-gated features (STIR/SHAKEN claim reporting, SRTP decryption) in the same binary — the REST API itself is identical either way, so choose on what else you need:

```bash
cargo build --release --features full
```

### Step 2: Choose an API key

You create the API key yourself -- there's no registration. Pick any string:

```bash
export SIPNAB_API_KEY="my-secret-token-change-this"
```

> **Security:** Use a strong random string in production. Every request carries the key as a Bearer token. An environment variable keeps it out of `ps` output.

### Step 3: Start sipnab with the API

**Live capture:**

```bash
sudo sipnab --api 127.0.0.1:8080 --api-key "$SIPNAB_API_KEY"
```

**Analyze a pcap file:**

```bash
sipnab -N -I capture.pcap --api 127.0.0.1:8080 --api-key "$SIPNAB_API_KEY"
```

The process stays alive serving the API until you press Ctrl-C.

### Step 4: Query the API

```bash
curl -H "Authorization: Bearer $SIPNAB_API_KEY" http://127.0.0.1:8080/v1/dialogs
```

> **More client code and integrations:** ready-to-adapt clients in several languages live in [API Client Examples](https://sipnab.com/docs/api-clients/); HEP forwarding, event hooks, fail2ban, and syslog live in [Integrations](https://sipnab.com/docs/integrations/).

## Authentication

Credentials are always presented the same way — an `Authorization: Bearer`
header. sipnab takes nothing else: not an `X-API-Key` header, not a query
parameter, not HTTP Basic (Basic applies only to the standalone metrics server,
below).

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/v1/dialogs
```

There are **two kinds of credential**, and the server accepts either. For the
full lifecycle of the signed kind — minting with `--mint-token`, TTLs,
signing-key rotation, and revocation denylists — see
[Bearer-token authentication](auth.md).

### Method 1 — static API key

A shared secret with **no expiry**. Simplest to set up, and you revoke it by
restarting with a different key.

Both lines below are one procedure — the server reads the variable the first
line sets. Run the second on its own and `$SIPNAB_API_KEY` is empty, which on
this loopback bind starts an API that accepts every request unauthenticated:

```bash
# Run all of these, in order.
export SIPNAB_API_KEY="$(openssl rand -hex 32)"
sipnab --api 127.0.0.1:8080 --api-key "$SIPNAB_API_KEY"
```

| Setting | Purpose |
|---|---|
| `--api-key <KEY>` / `$SIPNAB_API_KEY` | The static secret. Prefer the environment variable — argv is visible in `ps`. |

### Method 2 — signed bearer tokens

Self-describing HMAC tokens that carry their own expiry and id, so you get
expiry, rotation, and revocation **without restarting the server**. Prefer this
for CI, automation, and anything multi-client.

The token format is:

```text
s2.<base64url(payload)>.<base64url(HMAC-SHA256)>
```

where `payload` is compact JSON
`{"id":"<jti>","exp":<unix_seconds>,"aud":"<api|mcp>"}` and the signature is
`HMAC-SHA256(signing_key, "s2." + base64url(payload))`. Verification is
stateless: the server recomputes the HMAC, compares it in constant time against
every configured signing key, then requires the audience to match, `exp > now`,
and that `id` is not revoked. A malformed token loses, every time (fail-closed).

**Audience binding.** `aud` names the surface the token belongs to, so the HTTP
MCP endpoint turns away a token minted from `--api-signing-key`, and vice versa —
**even when both carry the same signing key**. The
version prefix is part of the signed input, so an `s2` token cannot be rewritten
as `s1` to shed its binding. The pre-`aud` `s1` format is **no longer
accepted** — it carried no audience, so honoring it would have left this
binding best-effort. An `s1` token now returns `401`. Re-mint with
`--mint-token`. Note that **static** `--api-key` secrets carry no audience —
the binding applies to signed tokens only.

| Setting | Purpose |
|---|---|
| `--api-signing-key <KEY>` / `$SIPNAB_API_SIGNING_KEY` | HMAC signing key. **Repeatable** — the *first* key mints, *all* keys verify. |
| `--api-signing-key-file <FILE>` | Read one key from a file (contents trimmed). Prepended to any `--api-signing-key`, so it becomes the minting key. |
| `--api-token-ttl <SECS>` | Lifetime of a minted token. Default `3600`. |
| `--mint-token` | Sign a token with the first configured key, print it, and exit. Starts no capture and no server. |
| `--token-id <ID>` | The token's `id` (`jti`), used later for revocation. Defaults to a generated id. |
| `--token-scope <SCOPE>` | `full` (default) or `metrics`. See **Scope** below. |
| `--api-revoked-file <FILE>` | Denylist of revoked token ids, one per line (blanks and `#` comments ignored). |

**Scope.** `--token-scope metrics` mints a token that reaches `GET /metrics`
and nothing else. Every other route returns `401`. Mint one for a scrape job.

The reason to bother: this is a TLS-decrypting capture tool, so `/v1/dialogs`
and `/v1/streams` return message bodies — the call content itself. Without a
scope split, a monitoring system that needs one counter must hold the keys to
all of it.

```bash
# scrape-only credential for Prometheus
sipnab --api-signing-key "$KEY" --mint-token --token-scope metrics
```

Three properties worth knowing:

- **`full` is the default, and satisfies everything.** A `full` token still
  reaches `/metrics`, so adding this claim narrowed no existing deployment.
- **A token minted before the claim existed is `full`.** Absent `scope` means
  `full` — the opposite of `aud`, which fails closed when missing. Upgrading
  does not revoke credentials already in the field.
- **The signature covers the claim.** Stripping or editing `scope` invalidates
  the signature, so a holder cannot widen their own token.

Static `--api-key` secrets carry no claims at all and are therefore `full`.
Scoping requires a signed token. The scope applies to the REST API — the MCP
surface has no `/metrics`, so `--token-scope metrics` with `--mcp-signing-key`
fails at mint time rather than producing a token that can never
authenticate.

**Mint a token.** Generate the signing key first. Everything below reads it
from `$KEY`, including the server — mint against one key and serve with
another and every token you handed out returns `401`:

```bash
KEY="$(openssl rand -hex 32)"
```

Then mint one token, not both. A token on the default one-hour TTL:

```bash
sipnab --mint-token --api-signing-key "$KEY"
```

A 24-hour token with an explicit id — give one whenever the token may need
revoking before it expires, since the denylist matches on that id:

```bash
sipnab --mint-token --api-signing-key "$KEY" --api-token-ttl 86400 --token-id ci-runner-1
```

**Serve with that key, and honor a denylist:**

```bash
sipnab --api 127.0.0.1:8080 --api-signing-key "$KEY" \
  --api-revoked-file /etc/sipnab/revoked.txt
```

**Expiry** needs no server action — a token stops verifying once `exp <= now`.

**Rotation** comes in two independent forms. Rotate *tokens* by minting a new
one before the old lapses and migrating clients. Several tokens are valid at
once. Rotate *signing keys* by passing `--api-signing-key` more than once: add
the new key alongside the old, mint with the new one, migrate clients, then
drop the old key on the next restart.

**Revocation** kills a still-valid token before its `exp`:

```bash
echo "ci-runner-1" >> /etc/sipnab/revoked.txt
```

The file is re-read when its mtime changes, so the token stops working within
the next request — no restart.

### When sipnab requires authentication

**If you configure neither an API key nor a signing key, sipnab runs without
authentication** and serves every endpoint to anyone who asks. That is deliberate
only on a loopback bind. On a non-loopback bind with no credentials configured,
**the server refuses to start** rather than exposing an open API:

```text
REST API refuses to start: --api 0.0.0.0:8080 is non-loopback but no
--api-key / SIPNAB_API_KEY or --api-signing-key / SIPNAB_API_SIGNING_KEY was
supplied. Bind 127.0.0.1, or configure authentication.
```

Once you configure credentials, every endpoint **except `/health`** requires
them. `/health` is always unauthenticated. Missing, malformed, non-Bearer,
expired, or revoked credentials return `401 Unauthorized`. All comparisons are
constant-time, to prevent timing side channels.

Note that sipnab checks the rate limit *before* authentication, so a client over
its per-IP budget receives `503 Service Unavailable` even when its credentials
are invalid.

### Metrics endpoints use two different schemes

This catches people out, so it is worth stating plainly:

| Endpoint | Scheme |
|---|---|
| `/metrics` **on the REST API** (`--api`) | The same Bearer credential as every other REST endpoint. |
| The **standalone** metrics server (`--metrics <ADDR>`) | HTTP Basic, via `--metrics-auth <user:pass>` or `--metrics-auth-file <FILE>`. |

The standalone server applies the same fail-closed rule: a non-loopback bind
with no `--metrics-auth` / `--metrics-auth-file` refuses to start.

## API TLS

Direct TLS termination on the API endpoint is **not yet implemented** —
supplying `--api-tls-cert`/`--api-tls-key` makes sipnab refuse to start
with an explanatory error. Terminate TLS in a reverse proxy (nginx,
Caddy, HAProxy) in front of a loopback-bound API instead:

```bash
sipnab -d eth0 --api 127.0.0.1:8080 --api-key "secret"
# then proxy https://host/ -> http://127.0.0.1:8080 in your reverse proxy
```

## Bind address & connection limits

The base URL is whatever you pass to `--api` (e.g., `http://127.0.0.1:8080`). All network listeners bind to loopback by default. Bind a routable address (e.g. `0.0.0.0:8080`) only behind a token and a reverse proxy. Data endpoints use a `/v1/` prefix, and utility endpoints (`/health`, `/metrics`) have none.

`--api-max-conn` (default `100`) caps concurrent API connections to prevent resource exhaustion. Requests are additionally rate-limited to 100 per second per source IP. Requests rejected by the rate limiter or connection cap return **`503 Service Unavailable`** (not 429).

## Endpoint reference

The base URL is whatever you pass to `--api` (e.g., `http://127.0.0.1:8080`). Data endpoints use a `/v1/` prefix. Utility endpoints (`/health`, `/metrics`) have no prefix.

### GET /health

Health check endpoint. Returns `"ok"` with no authentication required.

**curl:**

```bash
curl http://127.0.0.1:8080/health
```

**Python:**

```python
import requests

resp = requests.get("http://127.0.0.1:8080/health")
print(resp.text)  # "ok"
```

**Go:**

```go
resp, _ := http.Get("http://127.0.0.1:8080/health")
defer resp.Body.Close()
body, _ := io.ReadAll(resp.Body)
fmt.Println(string(body)) // "ok"
```

**JavaScript (Node.js):**

```javascript
const resp = await fetch("http://127.0.0.1:8080/health");
console.log(await resp.text()); // "ok"
```

---

### GET /v1/dialogs

List all tracked SIP dialogs with optional filtering and pagination.

**Query parameters:**

| Parameter | Type   | Default | Description |
|-----------|--------|---------|-------------|
| `state`   | string | --      | Filter by dialog state (`Trying`, `Ringing`, `InCall`, `Completed`, `Failed`, `Cancelled`, `Redirected`, `Registered`, `Expired`, `Pending`, `Active`, `Terminated`, `Transferring`) |
| `from`    | string | --      | Filter by From user (regex pattern) |
| `limit`   | int    | 50      | Maximum results (capped at 1000) |
| `offset`  | int    | 0       | Pagination offset |

**curl:**

```bash
curl -s -H "Authorization: Bearer $SIPNAB_API_KEY" \
  "http://127.0.0.1:8080/v1/dialogs?state=Failed&limit=10" | jq .
```

**Python:**

```python
import requests

resp = requests.get(
    "http://127.0.0.1:8080/v1/dialogs",
    headers={"Authorization": "Bearer my-secret-token"},
    params={"state": "Failed", "limit": 10},
)
data = resp.json()
for d in data["dialogs"]:
    print(f"{d['call_id']}: {d['state']} ({d['msg_count']} msgs)")
```

**Go:**

```go
req, _ := http.NewRequest("GET",
    "http://127.0.0.1:8080/v1/dialogs?state=Failed&limit=10", nil)
req.Header.Set("Authorization", "Bearer my-secret-token")
resp, _ := http.DefaultClient.Do(req)
defer resp.Body.Close()

var result struct {
    Dialogs []map[string]interface{} `json:"dialogs"`
    Total   int                      `json:"total"`
}
json.NewDecoder(resp.Body).Decode(&result)
fmt.Printf("%d dialogs (%d total)\n", len(result.Dialogs), result.Total)
```

**JavaScript (Node.js):**

```javascript
const resp = await fetch(
  "http://127.0.0.1:8080/v1/dialogs?state=Failed&limit=10",
  { headers: { Authorization: "Bearer my-secret-token" } }
);
const { dialogs, total } = await resp.json();
dialogs.forEach(d => console.log(`${d.call_id}: ${d.state}`));
```

**Response:**

```json
{
  "schema_version": 1,
  "total": 47,
  "offset": 0,
  "limit": 10,
  "dialogs": [
    {
      "call_id": "12013223@203.0.113.195",
      "from_user": "alice",
      "to_user": "bob",
      "state": "Failed",
      "method": "INVITE",
      "duration_sec": 0.0,
      "msg_count": 4,
      "timing": {
        "pdd_ms": 847,
        "setup_ms": null,
        "retransmits": 2
      },
      "created_at": "2026-04-13T10:30:00Z",
      "updated_at": "2026-04-13T10:30:03Z",
      "frame": "capture.pcap#41@6f3a1c02b8d4e795"
    }
  ]
}
```

`frame` identifies the frame the dialog opened in, as
`<source>#<ordinal>@<digest>`: the capture it came from, the frame's position
within that file, and a digest of the frame's bytes. The ordinal is per source
file, so a frame keeps the same pointer whether sipnab read it on its own,
from a directory, or as one of a glob — which is what makes it usable for
comparing two runs over the same capture.

Follow one with `sipnab --show-frame`:

```bash
sipnab --show-frame 'capture.pcap#41@6f3a1c02b8d4e795'
```

The digest is what lets it tell you when the pointer no longer means what it
meant. A capture rotated, truncated or recompressed since the run yields a
mismatch, and `--show-frame` **refuses** rather than printing whatever now sits
at that position — nothing goes to stdout, so nobody can mistake a hexdump
for an answer. The short form `capture.pcap#41`, which is what a human types,
prints the frame and labels it `UNVERIFIED`, because there is nothing to check
it against.

The key is absent, not null, when the dialog has no frame: live capture has no
file to point back into. Absent means unknown, and a `frame` that is present is
always a real pointer.

The list rows carry `from_user`/`to_user`, not the `from`/`to` used by the
single-dialog and report endpoints below. The two shapes come from different
serializers -- list rows are the compact `DialogSummary` projection shared with
MCP and TUI save, the single-dialog document is the full-fidelity one -- so a
client that walks the list and then fetches a dialog has to read both spellings.

---

### GET /v1/dialogs/:call_id

Get full details for a single dialog by Call-ID, including associated RTP streams and media diagnosis.

**curl:**

```bash
curl -s -H "Authorization: Bearer $SIPNAB_API_KEY" \
  "http://127.0.0.1:8080/v1/dialogs/12013223@203.0.113.195" | jq .
```

**Python:**

```python
import requests
from urllib.parse import quote

call_id = "12013223@203.0.113.195"
resp = requests.get(
    f"http://127.0.0.1:8080/v1/dialogs/{quote(call_id, safe='')}",
    headers={"Authorization": "Bearer my-secret-token"},
)
dialog = resp.json()
# REST returns an aggregated dialog — `msg_count`, not the messages themselves.
print(f"State: {dialog['state']}, Messages: {dialog['msg_count']}")
```

**Go:**

```go
callID := url.PathEscape("12013223@203.0.113.195")
req, _ := http.NewRequest("GET",
    "http://127.0.0.1:8080/v1/dialogs/"+callID, nil)
req.Header.Set("Authorization", "Bearer my-secret-token")
resp, _ := http.DefaultClient.Do(req)
defer resp.Body.Close()

var dialog map[string]interface{}
json.NewDecoder(resp.Body).Decode(&dialog)
fmt.Printf("State: %s\n", dialog["state"])
```

**JavaScript (Node.js):**

```javascript
const callId = encodeURIComponent("12013223@203.0.113.195");
const resp = await fetch(
  `http://127.0.0.1:8080/v1/dialogs/${callId}`,
  { headers: { Authorization: "Bearer my-secret-token" } }
);
const dialog = await resp.json();
console.log(`State: ${dialog.state}`);
```

**Response:**

```json
{
  "schema_version": 1,
  "call_id": "12013223@203.0.113.195",
  "from": "alice",
  "to": "bob",
  "from_display": "Alice Smith",
  "to_display": "Bob Jones",
  "state": "Completed",
  "final_status_code": 200,
  "final_status_reason": "OK",
  "method": "INVITE",
  "msg_count": 8,
  "duration_sec": 45.2,
  "timing": {
    "pdd_ms": 847,
    "setup_ms": 2134,
    "ring_ms": 1287,
    "trying_delay_ms": 12,
    "teardown_ms": 45,
    "retransmits": 0
  },
  "sdp_timeline": [
    {
      "timestamp": "2026-04-13T10:30:00Z",
      "direction": "offer",
      "codecs": ["PCMU", "PCMA", "telephone-event"],
      "media_addr": "192.0.2.1",
      "media_port": 10000,
      "mode": "sendrecv"
    },
    {
      "timestamp": "2026-04-13T10:30:02Z",
      "direction": "answer",
      "codecs": ["PCMU", "telephone-event"],
      "media_addr": "192.0.2.2",
      "media_port": 20000,
      "mode": "sendrecv"
    }
  ],
  "diagnosis": {
    "one_way_audio": false,
    "nat_mismatch": false,
    "no_media": false,
    "hints": [
      "Asymmetric media may be due to comfort noise (42% CN frames)."
    ]
  },
  "streams": [
    {
      "schema_version": 1,
      "ssrc": "0x1a2b3c4d",
      "codec": "PCMU",
      "payload_type": 0,
      "src": "192.0.2.1:10000",
      "dst": "192.0.2.2:20000",
      "packets": 4820,
      "octets": 771200,
      "jitter_ms": 2.1,
      "loss_pct": 0.0,
      "orphaned": false,
      "associated_dialog": "12013223@203.0.113.195",
      "first_seen": "2026-04-13T10:30:02Z",
      "last_seen": "2026-04-13T10:30:47Z",
      "round_trip_ms": 96.0,
      "round_trip_source": "xr_voip_metrics",
      "quality_intervals": []
    }
  ]
}
```

`round_trip_ms` is the third of the three numbers that decide whether a call was
acceptable, and the only one sipnab cannot measure for itself: a passive tap
sees one point on the path, and a round trip is about two. Every figure here is
an endpoint's, and `round_trip_source` says which kind:

| `round_trip_source` | What it is |
|---|---|
| `xr_voip_metrics` | The reporting endpoint's own round trip between the two RTP interfaces, from an [RFC 3611](https://www.rfc-editor.org/rfc/rfc3611) XR block. This is the quantity [ITU-T G.114](https://www.itu.int/rec/T-REC-G.114) sets its guidance against. Accurate, and rare — most stacks never emit an XR |
| `sender_report_echo` | Derived from a receiver report's `LSR`/`DLSR` pair per [RFC 3550 §6.4.1](https://www.rfc-editor.org/rfc/rfc3550#section-6.4.1), anchored on when sipnab saw the report. The full round trip when the capture point sits with the sender of the SR, and a **lower bound** otherwise, because the leg beyond the tap is not in it. Available on almost every call |

**Both keys are absent when nobody reported a round trip**, and that is not the
same as zero. A stream with clean jitter, no loss and no `round_trip_ms` is a
stream with one unanswered question, not a healthy one — a call can be unusable
on delay alone.

**Fields drop out rather than reading `null`.** The example above is a healthy,
answered call, so it shows the fields such a call has. Anything sipnab did not
find is **absent from the object**, not present with a null value: `tags` when
empty, `from_display` / `to_display` when the headers carried no display name,
`final_status_code` / `final_status_reason` when there was no final INVITE
response, and `signaling_diagnosis` when the signalling detections found
nothing. Decode into a type with optional fields: a strict decoder that requires every
key above rejects most real dialogs.

A failed call adds the `signaling_diagnosis` object, which is where the answer
to "why" lives:

```json
{
  "call_id": "abc123@203.0.113.195",
  "state": "Failed",
  "final_status_code": 408,
  "final_status_reason": "Request Timeout",
  "signaling_diagnosis": {
    "final_failure": {
      "code": 408,
      "reason_phrase": "Request Timeout",
      "reason_header": null,
      "warning": null,
      "evidence": [2]
    },
    "auth_loop": null,
    "retransmissions": { "method": "INVITE", "count": 7, "span_sec": 32.0, "evidence": [0, 1, 3], "icmp_cause": "port unreachable" },
    "ack_missing": null,
    "abandoned": null,
    "post_dial_delay": null,
    "registration_failure": null,
    "icmp_unreachable": {
      "description": "port unreachable",
      "icmp_type": 3,
      "icmp_code": 3,
      "unreachable_endpoint": "192.0.2.10:5060",
      "reported_by": "198.51.100.1",
      "method": "INVITE",
      "errors": 2,
      "truncated": true,
      "evidence": [0, 1]
    },
    "hints": [
      "Call failed: 408 Request Timeout.",
      "No response to INVITE: 7 transmissions over 32.0s with nothing received — and ICMP says why: port unreachable. The count is how hard the sender tried; the ICMP finding is the cause.",
      "ICMP port unreachable: the network could not deliver the INVITE sent to 192.0.2.10:5060 (2 times), reported by 198.51.100.1. The host answered, so it is reachable — nothing was listening on that port. Check the service and the address it binds, not the network."
    ]
  }
}
```

Inside `signaling_diagnosis` the convention inverts: the seven always-checked
detections are present as `null` when they found nothing, so `null` there means
"checked, nothing found". `icmp_unreachable` is the one exception and drops out
entirely, because it cannot run at all unless the capture holds ICMP. [Output Formats](output-formats.md#one-object-per-dialog) covers every field
and the detection threshold behind each.

**Additional dialog fields:**

- **`final_status_code` / `final_status_reason`** -- read INVITE transactions only. A `REGISTER`, `OPTIONS` or `SUBSCRIBE` dialog omits both however it ended; `signaling_diagnosis.final_failure.code` carries the status for any dialog.
- **`diagnosis.hints`** -- Free-text diagnostic strings from the media analyzer: one-way audio, NAT mismatch (SDP `c=` address vs. actual RTP source), comfort-noise asymmetry (shown in the example above), codec / payload-type / ptime / duration asymmetry, and late media. Empty array when the analyzer found nothing.
- **STIR/SHAKEN** -- With `--stir-shaken` active (requires the `tls` build feature), sipnab writes the attestation level, orig/dest TNs, and verification status to the capture log. That status is `NotChecked` or `Expired` and never anything stronger: sipnab decodes the PASSporT but does not fetch the referenced certificate, so it checks no signature and the attestation remains the originator's claim rather than a confirmed fact. They are **not** part of the REST dialog JSON: there is no `stir_shaken` field, and the results do not appear in `diagnosis.hints`. sipnab marks a token `Expired` per [RFC 8224](https://www.rfc-editor.org/rfc/rfc8224) Section 4.4 when its `iat` (issued-at) claim sits more than 60 seconds from the current time.

Returns `404` if the Call-ID is not found.

---

### GET /v1/dialogs/:call_id/report

Get a structured call diagnosis report for a dialog in JSON format. Includes transaction timing, media quality, one-way audio detection, NAT mismatch analysis, and SDP timeline.

**curl:**

```bash
curl -s -H "Authorization: Bearer $SIPNAB_API_KEY" \
  "http://127.0.0.1:8080/v1/dialogs/12013223@203.0.113.195/report" | jq .
```

**Python:**

```python
import requests
from urllib.parse import quote

call_id = "12013223@203.0.113.195"
resp = requests.get(
    f"http://127.0.0.1:8080/v1/dialogs/{quote(call_id, safe='')}/report",
    headers={"Authorization": "Bearer my-secret-token"},
)
report = resp.json()
# `diagnosis` carries three booleans plus `hints` — there is no `summary` field.
hints = report["diagnosis"]["hints"]
print(f"Diagnosis: {'; '.join(hints) if hints else 'no issues detected'}")
```

**Go:**

```go
callID := url.PathEscape("12013223@203.0.113.195")
req, _ := http.NewRequest("GET",
    "http://127.0.0.1:8080/v1/dialogs/"+callID+"/report", nil)
req.Header.Set("Authorization", "Bearer my-secret-token")
resp, _ := http.DefaultClient.Do(req)
defer resp.Body.Close()

var report map[string]interface{}
json.NewDecoder(resp.Body).Decode(&report)
```

**JavaScript (Node.js):**

```javascript
const callId = encodeURIComponent("12013223@203.0.113.195");
const resp = await fetch(
  `http://127.0.0.1:8080/v1/dialogs/${callId}/report`,
  { headers: { Authorization: "Bearer my-secret-token" } }
);
const report = await resp.json();
console.log(JSON.stringify(report, null, 2));
```

**Response:**

In JSON format this endpoint returns **exactly the same document shape as
`GET /v1/dialogs/{call_id}`** — both serialize through the same internal
dialog projection (`generate_call_report(..., Json)` delegates to the one
dialog-to-JSON serializer). The text and Markdown report layouts are only
available via the MCP `get_dialog_report` tool and the CLI `--call-report`.

```json
{
  "schema_version": 1,
  "call_id": "12013223@203.0.113.195",
  "from": "alice",
  "to": "bob",
  "state": "Completed",
  "method": "INVITE",
  "msg_count": 8,
  "duration_sec": 45.2,
  "timing": {
    "pdd_ms": 847,
    "setup_ms": 2134,
    "ring_ms": 1287,
    "trying_delay_ms": 12,
    "teardown_ms": 45,
    "retransmits": 0
  },
  "sdp_timeline": [],
  "diagnosis": {
    "one_way_audio": false,
    "nat_mismatch": false,
    "no_media": false,
    "hints": []
  },
  "streams": []
}
```

For a call with negotiated media, `sdp_timeline[]` and `streams[]` carry the
same objects shown in the `GET /v1/dialogs/{call_id}` example above. Optional
fields (`from`, `to`, `from_display`, `to_display`, `tags`, per-timing values)
drop out entirely — they never appear as `null` — when absent.

Returns `404` if the Call-ID is not found.

---

### GET /v1/streams

List all tracked RTP streams with quality metrics.

**Query parameters:**

| Parameter  | Type  | Default | Description |
|------------|-------|---------|-------------|
| `orphaned` | bool  | --      | `true` keeps only streams no dialog claims, `false` only those one does. From 0.5.98 the test is the stream's dialog association; before it, a 30-second sweep decided, so `orphaned=true` missed short unclaimed streams |
| `mos_below`| float | --      | Filter streams with MOS below this threshold |
| `limit`    | int   | 50      | Maximum results (capped at 1000) |
| `offset`   | int   | 0       | Pagination offset |

**curl** — every tracked stream:

```bash
curl -s -H "Authorization: Bearer $SIPNAB_API_KEY" \
  http://127.0.0.1:8080/v1/streams | jq .
```

Or narrow it to the streams that are actually degraded, by asking for those
whose estimated MOS is below a threshold:

```bash
curl -s -H "Authorization: Bearer $SIPNAB_API_KEY" \
  "http://127.0.0.1:8080/v1/streams?mos_below=3.0" | jq .
```

**Python:**

```python
import requests

resp = requests.get(
    "http://127.0.0.1:8080/v1/streams",
    headers={"Authorization": "Bearer my-secret-token"},
    params={"mos_below": 3.0},
)
data = resp.json()
for s in data["streams"]:
    print(f"SSRC {s['ssrc']}: MOS={s['mos']:.1f}, loss={s['loss_pct']:.1f}%")
```

**Go:**

```go
req, _ := http.NewRequest("GET",
    "http://127.0.0.1:8080/v1/streams?mos_below=3.0", nil)
req.Header.Set("Authorization", "Bearer my-secret-token")
resp, _ := http.DefaultClient.Do(req)
defer resp.Body.Close()

var result struct {
    Streams []map[string]interface{} `json:"streams"`
    Total   int                      `json:"total"`
}
json.NewDecoder(resp.Body).Decode(&result)
for _, s := range result.Streams {
    fmt.Printf("SSRC %s: MOS=%.1f\n", s["ssrc"], s["mos"])
}
```

**JavaScript (Node.js):**

```javascript
const resp = await fetch(
  "http://127.0.0.1:8080/v1/streams?mos_below=3.0",
  { headers: { Authorization: "Bearer my-secret-token" } }
);
const { streams } = await resp.json();
streams.forEach(s =>
  console.log(`SSRC ${s.ssrc}: MOS=${s.mos.toFixed(1)}, loss=${s.loss_pct.toFixed(1)}%`)
);
```

**Response:**

```json
{
  "schema_version": 1,
  "total": 14,
  "offset": 0,
  "limit": 50,
  "streams": [
    {
      "ssrc": "0x1a2b3c4d",
      "codec": "PCMU",
      "src": "192.0.2.1:10000",
      "dst": "192.0.2.2:20000",
      "packets": 4820,
      "jitter_ms": 2.1,
      "loss_pct": 0.0,
      "orphaned": false,
      "associated_dialog": "12013223@203.0.113.195",
      "mos": 4.2
    }
  ]
}
```

---

### GET /v1/streams/:id

Get a single RTP stream by SSRC hex string (e.g., `0x1a2b3c4d` or `1a2b3c4d`).

**curl:**

```bash
curl -s -H "Authorization: Bearer $SIPNAB_API_KEY" \
  http://127.0.0.1:8080/v1/streams/0x1a2b3c4d | jq .
```

**Python:**

```python
import requests

resp = requests.get(
    "http://127.0.0.1:8080/v1/streams/0x1a2b3c4d",
    headers={"Authorization": "Bearer my-secret-token"},
)
stream = resp.json()
print(f"Codec: {stream['codec']}, Packets: {stream['packets']}")
```

**Go:**

```go
req, _ := http.NewRequest("GET",
    "http://127.0.0.1:8080/v1/streams/0x1a2b3c4d", nil)
req.Header.Set("Authorization", "Bearer my-secret-token")
resp, _ := http.DefaultClient.Do(req)
defer resp.Body.Close()

var stream map[string]interface{}
json.NewDecoder(resp.Body).Decode(&stream)
fmt.Printf("Codec: %s, Packets: %.0f\n", stream["codec"], stream["packets"])
```

**JavaScript (Node.js):**

```javascript
const resp = await fetch("http://127.0.0.1:8080/v1/streams/0x1a2b3c4d", {
  headers: { Authorization: "Bearer my-secret-token" },
});
const stream = await resp.json();
console.log(`Codec: ${stream.codec}, Packets: ${stream.packets}`);
```

**Response:** full RTP stream JSON including codec, packet counts, jitter, loss, MOS estimate, and associated dialog. Returns `400` for invalid SSRC format, `404` if not found.

---

### GET /v1/stats

Aggregate statistics across all dialogs and streams, including PDD percentiles.

**curl:**

```bash
curl -s -H "Authorization: Bearer $SIPNAB_API_KEY" \
  http://127.0.0.1:8080/v1/stats | jq .
```

**Python:**

```python
import requests

resp = requests.get(
    "http://127.0.0.1:8080/v1/stats",
    headers={"Authorization": "Bearer my-secret-token"},
)
stats = resp.json()
d = stats["dialogs"]
print(f"Dialogs: {d['total']} total, {d['active']} active, {d['failed']} failed")
t = stats["timing"]
print(f"PDD: p50={t['pdd_p50_ms']}ms, p95={t['pdd_p95_ms']}ms")
```

**Go:**

```go
req, _ := http.NewRequest("GET", "http://127.0.0.1:8080/v1/stats", nil)
req.Header.Set("Authorization", "Bearer my-secret-token")
resp, _ := http.DefaultClient.Do(req)
defer resp.Body.Close()

var stats map[string]interface{}
json.NewDecoder(resp.Body).Decode(&stats)
dialogs := stats["dialogs"].(map[string]interface{})
fmt.Printf("Total: %.0f, Active: %.0f\n", dialogs["total"], dialogs["active"])
```

**JavaScript (Node.js):**

```javascript
const resp = await fetch("http://127.0.0.1:8080/v1/stats", {
  headers: { Authorization: "Bearer my-secret-token" },
});
const stats = await resp.json();
const { dialogs, timing } = stats;
console.log(`Dialogs: ${dialogs.total} total, ${dialogs.active} active`);
console.log(`PDD p50: ${timing.pdd_p50_ms}ms, p95: ${timing.pdd_p95_ms}ms`);
```

**Response:**

```json
{
  "schema_version": 2,
  "dialogs": {
    "total": 1247,
    "active": 23,
    "in_call": 9,
    "completed": 1180,
    "failed": 32,
    "cancelled": 12
  },
  "streams": {
    "total": 46,
    "orphaned": 3
  },
  "timing": {
    "pdd_p50_ms": 120,
    "pdd_p95_ms": 850,
    "pdd_p99_ms": 2100
  },
  "capture_quality": {
    "kernel_dropped_packets": 0,
    "interface_dropped_packets": 0,
    "invalid_timestamps": 0,
    "undecodable_frames": 0,
    "degraded": false
  }
}
```

`capture_quality` says how much of the wire the rest of the response draws
from. Read it before the counts, not after: with `degraded` true, every number
above it is a floor rather than a total, and the `timing` percentiles may have
may rest on substituted clock readings.

The three counters stay apart because their remedies disagree:

- **`kernel_dropped_packets`** — the capture ring was full when the packet
  arrived. Raise `-B`/`--buffer`, narrow the BPF filter, or cut `--snaplen`.
- **`interface_dropped_packets`** — the NIC or its driver discarded the packet
  before libpcap saw it. Look at the NIC, the driver or the mirror: **a bigger
  buffer cannot recover these.**
- **`invalid_timestamps`** — the pcap timestamp was unusable, so the packet
  carries the wall clock instead. Nothing went missing, but treat post-dial delay,
  jitter, MOS and duration for this run as unreliable.

Summing them would name one problem where there are three, and "raise the
buffer" is the wrong answer to two of them.

`undecodable_frames` is a fourth channel and the only one that is about sipnab
rather than the host. Nothing dropped it and no byte is missing: the frames
arrived intact and no decoder here could read them, so the analysis saw none of
their contents. It is what separates *this capture holds no SIP* from *sipnab
could not read this capture* — both of which otherwise report `dialogs.total`
as `0`. Which link types, EtherTypes and IP protocols this covers appears in
`sipnab_capture_undecodable_frames_total{reason}` on `/metrics`, and the
proportion is `sipnab_capture_undecoded_fraction`.

It is **not** part of `degraded`, on purpose: ARP is an undecodable frame by
definition and is present on nearly every Ethernet capture, so a flag that
included it would be true always and useful never.

`degraded` is `true` when any of the three is non-zero. `false` means nothing
was *observed* to go wrong — not that the capture provably saw every packet.
Loss upstream of the capture point (an oversubscribed SPAN port, a tap
mirroring one direction, a filter that excluded the traffic) is invisible to
all three counters.

---

### GET /metrics

Prometheus-compatible metrics endpoint. Returns metrics in the Prometheus text exposition format (`text/plain; version=0.0.4`).

**curl:**

```bash
curl -s -H "Authorization: Bearer $SIPNAB_API_KEY" \
  http://127.0.0.1:8080/metrics
```

**Python:**

```python
import requests

resp = requests.get(
    "http://127.0.0.1:8080/metrics",
    headers={"Authorization": "Bearer my-secret-token"},
)
print(resp.text)  # Prometheus text format
```

**Go:**

```go
req, _ := http.NewRequest("GET", "http://127.0.0.1:8080/metrics", nil)
req.Header.Set("Authorization", "Bearer my-secret-token")
resp, _ := http.DefaultClient.Do(req)
defer resp.Body.Close()
body, _ := io.ReadAll(resp.Body)
fmt.Println(string(body))
```

**JavaScript (Node.js):**

```javascript
const resp = await fetch("http://127.0.0.1:8080/metrics", {
  headers: { Authorization: "Bearer my-secret-token" },
});
console.log(await resp.text()); // Prometheus text format
```

**Response** (text/plain):

```text
# HELP sipnab_dialogs_total Total dialogs by state
# TYPE sipnab_dialogs_total counter
sipnab_dialogs_total{state="completed"} 1180
sipnab_dialogs_total{state="failed"} 32
sipnab_dialogs_total{state="incall"} 23
# HELP sipnab_rtp_streams_total RTP streams by status
# TYPE sipnab_rtp_streams_total counter
sipnab_rtp_streams_total{status="established"} 43
sipnab_rtp_streams_total{status="orphaned"} 3
...
```

Metric names emitted by [`src/output/prometheus.rs`](https://github.com/NormB/sipnab/blob/main/src/output/prometheus.rs):

| Metric | Type | Notes |
|---|---|---|
| `sipnab_dialogs_total{state}` | counter | Tracked dialogs grouped by `DialogState` (`Trying`, `Ringing`, `InCall`, `Completed`, `Cancelled`, `Failed`, `Redirected`, `Registered`, `Expired`, `Pending`, `Active`, `Terminated`, `Transferring`). The `--api` server emits state values lowercased; the standalone `--metrics` server emits them as-cased — pick the right form for your queries. |
| `sipnab_dialogs_active` | gauge | Dialogs in one of six active states: `Trying`, `Ringing`, `InCall`, `Transferring`, `Pending`, `Active`. Two of those six are SUBSCRIBE dialogs carrying no media, so **this is not a count of calls** — a box serving presence traffic reports a non-zero value here with nothing on the phone. Graph it to see load on the dialog store; alert on `sipnab_calls_active` instead. |
| `sipnab_calls_active` | gauge | Calls that are up right now: dialogs in `InCall`, and nothing else. A dialog enters `InCall` on the 200 OK to its INVITE and leaves on the BYE, so this is the concurrent-call figure — channels in use, and the number to compare against a carrier's simultaneous-call limit. By construction never greater than `sipnab_dialogs_active`; the gap is calls still in setup plus subscriptions. |
| `sipnab_messages_total{method}` | counter | SIP messages by method (`INVITE`, `REGISTER`, …). |
| `sipnab_responses_total{code}` | counter | SIP responses in the tracked dialogs, grouped by class: `1xx`, `2xx`, `3xx`, `4xx`, `5xx`, `6xx`. Every class appears on every scrape, at `0` where the capture saw none, so a rule watching for the first `5xx` reads zero instead of no-data. |
| `sipnab_rtp_streams_active` | gauge | The two servers count different things under this one name. The `--api` server counts streams a dialog claims, however long ago the last packet arrived; the standalone `--metrics` server counts streams whose last packet arrived within the previous 30 seconds, whatever their dialog association. A call whose media died five minutes ago is still counted by `--api` and is not counted by `--metrics` — an alert threshold tuned on one scrape target does not carry over to the other. |
| `sipnab_rtp_streams_total{status}` | counter | RTP streams by status: `orphaned` when no dialog claims the stream, `established` when one does. From 0.5.98 the stream's dialog association decides this on every scrape. Before that, a sweep flagged a stream only once it had gone 30 seconds unclaimed, so a short unclaimed stream counted as `established`. `--api` only. The standalone `--metrics` server never populates the map, and an empty family drops out rather than reporting zero, so on `--metrics` the series does not exist at all — a panel built on it stays permanently blank. |
| `sipnab_kill_responses_sent_total{mode}` | counter | Scanner-kill responses sent, by source mode: `raw` (source-spoofed via a raw socket) or `ephemeral` (sipnab's own port). Alert on unexpected `ephemeral` to catch a silent spoof fallback. |
| `sipnab_capture_packets_total` | counter | Packets the capture handed to the processing pipeline since the process started. Counted before parsing, so a frame sipnab cannot parse still counts — it arrived. **This series says nothing about whether sipnab understood any of it**; a capture on a link type with no decoder climbs this counter exactly like a clean one. Pair it with `sipnab_capture_undecoded_fraction` before reading any zero elsewhere in the scrape as a finding. One process-wide total covering every input (`-I` files, live devices, HEP) and every worker of the parallel pipeline, identical on both servers. A line that stops climbing means packets stopped arriving. |
| `sipnab_reassembly_timeouts_total` | counter | IP fragments whose datagram never completed, plus TCP streams that went idle, dropped once older than the 30-second reassembly TTL. Capacity evictions stay out of this number: those say the entry cap is too small, not that a peer stopped sending. |
| `sipnab_capture_kernel_dropped_packets_total` | counter | Packets the kernel discarded because the capture ring buffer was full when they arrived (`ps_drop`). Non-zero means the analysis is incomplete: dialogs may be missing messages, and RTP loss figures overstate what was on the wire. The remedy is a larger `-B`/`--buffer`, a narrower BPF filter, or a smaller `--snaplen`. Always zero for a `-I` file replay, which has no ring. |
| `sipnab_capture_interface_dropped_packets_total` | counter | Packets the interface or its driver discarded before libpcap ever saw them (`ps_ifdrop`). Counted apart from the kernel drops because **a larger `-B` cannot recover these** — the link is delivering faster than the host accepts, so the answer is at the NIC, the driver, or the mirror. Alerting on a sum of the two drop counters points the operator at the wrong remedy half the time. |
| `sipnab_capture_invalid_timestamps_total` | counter | Packets whose pcap timestamp did not parse, which stamped with the wall clock instead. No packet goes missing, so the counts elsewhere in the scrape stay right — but every timing figure derived from the run is not: post-dial delay, [RFC 3550](https://www.rfc-editor.org/rfc/rfc3550) jitter, MOS and call duration all read from a substituted clock. |
| `sipnab_capture_undecodable_frames_total{reason}` | counter | Frames that reached the parser and produced no packet at all, grouped by why. **The reason label carries the number**, because the number is the whole deliverable: `unsupported_link_type_0` says the file is `DLT_NULL` and `editcap -T ether` converts it, where a bare "unsupported link type" names no format an operator can act on. Labels are `unsupported_link_type_<dlt>`, `not_ip_ethertype_0x<hhhh>`, `no_transport_ip_protocol_<n>`, `truncated_frame`, `decode_error`, the `_unrecorded` variants of the two numbered EtherType/protocol labels (the decoder did not hand the number out), and `reason_not_retained` for frames beyond the tally's slot cap — that last one exists so `sum()` over the family always equals the true total. Emitted by both the `--api` `/metrics` route and the standalone `--metrics` server. Absent entirely on a capture that decoded cleanly, so alert on the fraction below, not on this. |
| `sipnab_capture_undecoded_fraction` | gauge | Share of captured frames sipnab could not decode, `0`–`1`, emitted on **every** scrape including clean ones. This is the series that separates "this capture holds no SIP" from "sipnab could not read this capture" — both of which otherwise show `sipnab_messages_total` at zero and look identical. At `1` nothing in the rest of the scrape describes traffic sipnab read. A non-zero but small value is normal: ARP and other non-IP background is undecodable by definition on any Ethernet link, which is exactly why this is a proportion and not a flag. |
| `sipnab_capture_quality_degraded` | gauge | `1` when any of the three *loss* counters above exceeds zero, `0` otherwise. Undecodable frames are deliberately **not** folded in: ARP makes them non-zero on nearly every capture, so a flag including them would always be `1` and carry no information — use `sipnab_capture_undecoded_fraction` with a threshold instead. The one series to put on a dashboard or an alert rule to know whether the rest of the scrape describes the whole capture. `0` means nothing **surfaced** as wrong, not that the capture provably saw every packet: loss upstream of the capture point — an oversubscribed SPAN port, a tap mirroring one direction, a filter that excluded the traffic — is invisible to all three counters. |
| `sipnab_capture_queue_depth_packets` | gauge | Packets currently queued between the capture reader and the processing thread (standalone `--metrics` server). |
| `sipnab_capture_backpressure_blocks_total` | counter | Times the capture reader blocked on a full queue (standalone `--metrics` server). |
| `sipnab_diagnosis_total{type}` | counter | Tracked dialogs whose media diagnosis raises each finding: `one_way_audio`, `nat_mismatch`, `no_media`. A dialog with two findings counts under both. All three types appear on every scrape, at `0` where nothing raises them. Both servers run the diagnosis during the scrape, so scrape cost grows with the number of tracked dialogs (capped by `-l`/`--limit`). |
| `sipnab_security_alerts_total{type}` | counter | Security alerts by the detector that fired: `scanner`, `fraud`, `digest`, `reg_flood`. Only types that have fired appear, so the family is absent before the first alert. |
| `sipnab_pdd_seconds` | histogram | Post-dial delay distribution (buckets at 0.5/1/2/3/5/10s). Emits `sipnab_pdd_seconds_bucket{le}`, `_count`, `_sum`. |
| `sipnab_mos` | histogram | RTP MOS distribution (buckets at 1/2/2.5/3/3.5/4/4.5). |
| `sipnab_jitter_ms` | histogram | RTP jitter distribution (buckets at 5/10/20/50/100/200ms). |
| `sipnab_loss_percent` | histogram | RTP packet-loss distribution (buckets at 0.1/0.5/1/2/5/10%). |

Two shapes of counter share that table, and an alert rule has to know which one it reads. `sipnab_capture_packets_total`, `sipnab_reassembly_timeouts_total`, `sipnab_kill_responses_sent_total`, `sipnab_capture_backpressure_blocks_total`, `sipnab_capture_undecodable_frames_total` and the three capture-quality counters (`sipnab_capture_kernel_dropped_packets_total`, `sipnab_capture_interface_dropped_packets_total`, `sipnab_capture_invalid_timestamps_total`) count events since the process started and only ever climb, so `rate()` and `increase()` over them mean what they say. The rest — dialogs, messages, responses, streams, diagnosis findings — describe what sipnab tracks right now, and they fall as dialogs and streams age out of their stores. Alert on the current value or on a ratio there, never on `increase()`.

`sipnab_security_alerts_total{type}` reads differently from the rest, and the difference matters to an alert rule. `AlertEngine::fire` records each alert under its rule name, so the family carries only the types that have actually fired and stays absent from the scrape entirely until the first one does. An absent series therefore means "no alert of that type has fired since this process started", not "the metric is unavailable" — the reading it carried up to 0.5.74, when nothing fed the family at all. `firing_an_alert_moves_the_metric` in [`tests/metrics_alert_wiring_test.rs`](https://github.com/NormB/sipnab/blob/main/tests/metrics_alert_wiring_test.rs) holds the recording call to that behaviour.

## Status codes

| Code | When |
|------|------|
| `200` | Success |
| `400` | Malformed request (e.g. invalid SSRC on `/v1/streams/{id}`) |
| `401` | Missing/invalid/expired/revoked bearer token |
| `404` | Unknown `call_id` or stream id |
| `503` | Rejected by the rate limiter or the connection cap (**not** 429) |

## Recipes (curl + jq)

Every recipe here reads `$API`, and every one but the health check also reads
`$H`, so set them once first. The two lines are one unit — `$H` interpolates
`$KEY`, so running the second on its own builds an `Authorization` header with
no token in it and every authenticated recipe then returns `401`:

```bash
# Run all of these, in order.
API="http://127.0.0.1:8080"; KEY="my-secret-token"
H="-H 'Authorization: Bearer $KEY'"
```

Each recipe below is a complete command in its own right, and they are
alternatives rather than a sequence — run the one that answers your question:

- `curl -fsS $API/health` — health check; `/health` is the one endpoint that takes no credential
- `curl -fsS "$API/v1/dialogs?state=Failed&limit=20" $H | jq` — the most recent failed dialogs
- `curl -fsS "$API/v1/dialogs?from=alice&limit=20"   $H | jq` — dialogs from one user (`from=` is a regex)
- `curl -fsS "$API/v1/dialogs/abc123@host"        $H | jq` — one aggregated dialog by Call-ID
- `curl -fsS "$API/v1/dialogs/abc123@host/report" $H | jq` — the same dialog as a JSON call report
- `curl -fsS "$API/v1/streams?orphaned=false" $H | jq` — only streams already linked to a dialog
- `curl -fsS "$API/v1/streams?mos_below=3.5"  $H | jq` — only streams below a MOS threshold
- `curl -fsS "$API/v1/stats" $H | jq` — the aggregate counters and PDD percentiles

Two recipes are pipelines rather than one-liners. Export every dialog to CSV,
for a spreadsheet or a diff against the switch's own CDR:

```bash
curl -fsS "$API/v1/dialogs?limit=1000" $H \
  | jq -r '.dialogs[] | [.call_id, .method, .state, .from_user, .to_user, .duration_sec] | @csv'
```

Or print one line per poor-MOS stream, which is the shape to feed an alerting
hook — it stays silent while every stream is healthy:

```bash
curl -fsS "$API/v1/streams?mos_below=3.0" $H \
  | jq -r '.streams[] | "LOW MOS: SSRC=\(.ssrc) MOS=\(.mos) call=\(.associated_dialog)"'
```

For per-call response-code histograms (not exposed over REST), use the CLI NDJSON mode — `sipnab -N --json` emits one record per message. See [Output Formats](output-formats.md).

### Prometheus scrape config

```yaml
# prometheus.yml
scrape_configs:
  - job_name: sipnab
    bearer_token: your-api-key
    static_configs:
      - targets: ['127.0.0.1:8080']
    scrape_interval: 15s
```

The metrics endpoint is lightweight and suitable for 5–15 second scrape intervals. A sample Grafana dashboard JSON ships in the repo at [`contrib/grafana/sipnab-dashboard.json`](https://github.com/NormB/sipnab/blob/main/contrib/grafana/sipnab-dashboard.json).

## Client examples

Full end-to-end clients (bearer auth, pagination, `/metrics` scraping, error handling) in curl, Python (sync + async), Node/TypeScript, Rust, and Go are on the website's API Client Examples page: <https://sipnab.com/docs/api-clients/>.

## Security model

- The API thread only reads dialog/stream metadata: no capture fd access, no key material exposure
- All network listeners bind to localhost by default
- Rate limiting on all listener endpoints (100 RPS per source IP)
- Bearer token authentication required on every REST endpoint except `/health` — `/metrics` on the `--api` server sits on the same guarded router and takes the same credential (the *standalone* `--metrics` server is the one that uses HTTP Basic instead)
- Constant-time key comparison prevents timing attacks
- TLS not terminated in-process; run behind a reverse proxy (see [API TLS](#api-tls))
- Connection limits prevent resource exhaustion

> **Note:** The API runs as a thread in the sipnab process, sharing the in-memory dialog/stream stores read-only. It never touches capture file descriptors or TLS key material, and exposes only dialog/stream metadata — but it is not a separate OS process; treat the API bind address and key accordingly.
