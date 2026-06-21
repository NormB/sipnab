# Output formats

sipnab has four output modes: interactive TUI (default), per-message CLI
text (`-N`), structured NDJSON (`--json`), and the MCP server
([mcp-overview.md](./mcp-overview.md)). This page documents the
machine-readable formats.

## NDJSON (`--json`)

`--json` emits one JSON object per SIP message — newline-delimited, so
each line is independently parseable and the stream is pipe-friendly:

```bash
sipnab -N -I capture.pcap --json | jq .
```

Message record (fields with no value are omitted, not null):

```json
{
  "schema_version": 1,
  "timestamp": "2026-06-12T14:03:21.412345+00:00",
  "src": "10.0.0.1",
  "src_port": 5060,
  "dst": "10.0.0.2",
  "dst_port": 5060,
  "transport": "UDP",
  "is_request": true,
  "method": "INVITE",
  "call_id": "abc123@10.0.0.1",
  "cseq": { "number": 1, "method": "INVITE" },
  "from": "1001",
  "to": "1002",
  "ua": "FreePBX-16"
}
```

`cseq` (the parsed `CSeq` header — `{ number, method }`) is emitted on **every**
message, requests included, so re-requests within a dialog (e.g. two REGISTERs
with `CSeq` 1 and 2) stay distinguishable. It is omitted only when the `CSeq`
header is absent or unparseable.

Responses carry `status_code` and `reason` instead of `method`, plus
`response_context` (`"<num> <method>"`, what the response answers) — now
redundant with `cseq` and retained only for backward compatibility.

`malformed` is a list of structural-defect diagnostics, present **only** when a
message is malformed (a well-formed message omits the field). It surfaces crafted
or broken input rather than silently accepting it: missing mandatory headers
(`Call-ID`/`CSeq`/`From`/`To`/`Via`), an unparseable `CSeq`, a `Content-Length`
larger than the body actually present (truncated/lying length), and control/NUL
bytes in a header. Example: `"malformed": ["missing mandatory header: Call-ID"]`.

`schema_version` increments on breaking field changes — pin your
consumers to it.

### jq recipes

```bash
# Only INVITEs
sipnab -N -I capture.pcap --json | jq 'select(.method == "INVITE")'

# Calls from a specific user
sipnab -N -I capture.pcap --json | jq 'select(.from == "1001")'

# Count messages per method
sipnab -N -I capture.pcap --json \
  | jq -s 'group_by(.method) | map({method: .[0].method, n: length})'

# Failed responses (4xx/5xx/6xx) with their reason
sipnab -N -I capture.pcap --json \
  | jq 'select(.status_code != null and .status_code >= 400)
        | {ts: .timestamp, code: .status_code, reason, call_id}'

# Distinct Call-IDs seen (feed into --call-report)
sipnab -N -I capture.pcap --json | jq -r '.call_id' | sort -u
```

## Summary-only output

`--json` prints a line per message. For end-of-run summaries instead,
combine the report flags with `--no-cli-print` (which suppresses the
per-message stream but not the report):

```bash
# Aggregate report only
sipnab -N -I capture.pcap --report --no-cli-print

# Single-call deep dive only
sipnab -N -I capture.pcap --call-report 'abc123@10.0.0.1' --no-cli-print
```

## Dialog / stream JSON

The richer dialog object (state, timing with PDD/setup/ring/teardown
milliseconds, retransmit counts, SDP timeline, RTP streams with
jitter/loss/MOS, and media diagnosis flags like `one_way_audio`) is the
payload of:

- `SIPNAB_JSON` in `--on-dialog-exec` / `--on-quality-exec` hooks
- MCP tool responses ([mcp-tools.md](./mcp-tools.md))

## pcap / pcapng

`-O <file>` writes captured packets; `--pcapng` selects PCAP-NG. With TLS
decryption, `--pcap-export-mode` controls whether decryption secrets
(DSBs) are embedded for Wireshark. Rotation: `--split filesize:N` /
`--split duration:N`, or SIGUSR1 on demand.
