# Runnable client examples

These Python clients demonstrate multi-step operator tasks.

- Run commands from the repository root with Python 3.
- The programs use its standard library.
- A complete live run requires the services described in the
  [capture harness](vcon-harness.md).

| Program | What it does | Live prerequisites |
|---|---|---|
| [leg_correlate.py](../clients/python/leg_correlate.py) | Joins proxy dialogs and relay streams; refuses to treat one instance as two witnesses | Two sipnab REST endpoints |
| [mcp_probe.py](../clients/python/mcp_probe.py) | Queries both capture nodes over MCP and compares their identities | Two HTTP MCP endpoints |
| [vcon_view.py](../clients/python/vcon_view.py) | Lists stored vCons, renders one and extracts WAV audio | The harness conserver backend |

Inspect each program's options before a live run:

- `python3 clients/python/leg_correlate.py --help`
- `python3 clients/python/mcp_probe.py --help`
- `python3 clients/python/vcon_view.py --help`

Run the programs' own tests, which need no running sipnab:

```bash
# Run all of these, in order.
python3 -m venv .venv-client-tests
. .venv-client-tests/bin/activate
python3 -m pip install --require-hashes -r clients/python/requirements-test.txt
python3 -m compileall -q clients/python
python3 -m pytest clients/python/tests -q
```

## Languages and lifecycle

sipnab declares client examples in six languages:

- Rust,
- Python,
- Go,
- JavaScript (TypeScript counts as JavaScript),
- C,
- C++.

An operator's program walks through six steps. Each language should have one
program per step:

- **configure**: starts sipnab from a configuration it writes or chooses.
- **capture**: starts sipnab on a capture source and takes its output.
- **read**: reads captured data from a running sipnab.
- **command**: changes something through sipnab, such as banning a source.
- **process**: turns what it read into an answer an operator acts on.
- **stop**: stops a running sipnab through its own interface.

"Not yet" marks a step that language has no program for. Every program
listed exists in `clients/` and makes the call its step needs.

| Language | configure | capture | read | command | process | stop |
|---|---|---|---|---|---|---|
| Rust | Not yet | Not yet | [rust/src/main.rs](../clients/rust/src/main.rs) | Not yet | Not yet | Not yet |
| Python | Not yet | [python/agent_triage.py](../clients/python/agent_triage.py) | [python/list_dialogs.py](../clients/python/list_dialogs.py) | [python/scanner_ban.py](../clients/python/scanner_ban.py) | [python/failed_calls.py](../clients/python/failed_calls.py) | Not yet |
| Go | Not yet | Not yet | [go/list-dialogs/main.go](../clients/go/list-dialogs/main.go) | Not yet | Not yet | Not yet |
| JavaScript | Not yet | Not yet | [javascript/list-dialogs.mjs](../clients/javascript/list-dialogs.mjs) | Not yet | Not yet | Not yet |
| C | Not yet | Not yet | Not yet | Not yet | Not yet | Not yet |
| C++ | Not yet | Not yet | Not yet | Not yet | Not yet | Not yet |

## Reference-page programs

Each Python, Go, JavaScript and TypeScript example on these pages is the core
of one of these programs:

- [REST API](rest-api.md),
- [Prometheus metrics](prometheus-metrics.md),
- [MCP deployment](mcp-deploy.md).

Each page's example is the program's code, unchanged.

| Program | What it does | Go | JavaScript | Python |
|---|---|---|---|---|
| `health` | `GET /health` | [main.go](../clients/go/health/main.go) | [health.mjs](../clients/javascript/health.mjs) | [health.py](../clients/python/health.py) |
| `list-dialogs` | Lists failed dialogs | [main.go](../clients/go/list-dialogs/main.go) | [list-dialogs.mjs](../clients/javascript/list-dialogs.mjs) | [list_dialogs.py](../clients/python/list_dialogs.py) |
| `get-dialog` | One dialog's state and message count | [main.go](../clients/go/get-dialog/main.go) | [get-dialog.mjs](../clients/javascript/get-dialog.mjs) | [get_dialog.py](../clients/python/get_dialog.py) |
| `dialog-report` | One call's media diagnosis | [main.go](../clients/go/dialog-report/main.go) | [dialog-report.mjs](../clients/javascript/dialog-report.mjs) | [dialog_report.py](../clients/python/dialog_report.py) |
| `list-streams` | RTP streams with MOS below 3.0 | [main.go](../clients/go/list-streams/main.go) | [list-streams.mjs](../clients/javascript/list-streams.mjs) | [list_streams.py](../clients/python/list_streams.py) |
| `get-stream` | One stream's codec and packet count | [main.go](../clients/go/get-stream/main.go) | [get-stream.mjs](../clients/javascript/get-stream.mjs) | [get_stream.py](../clients/python/get_stream.py) |
| `stats` | Dialog totals and post-dial delay | [main.go](../clients/go/stats/main.go) | [stats.mjs](../clients/javascript/stats.mjs) | [stats.py](../clients/python/stats.py) |
| `metrics` | The Prometheus exposition | [main.go](../clients/go/metrics/main.go) | [metrics.mjs](../clients/javascript/metrics.mjs) | [metrics.py](../clients/python/metrics.py) |

- Each REST program reads:
  - the base URL from `SIPNAB_URL` (default `http://127.0.0.1:8080`),
  - the token from `SIPNAB_API_KEY`.
- `get-dialog`, `dialog-report` and `get-stream` take the Call-ID or SSRC as
  their first argument.

Run one against a sipnab started with `--api 127.0.0.1:8080`:

```bash
# Run all of these, in order.
export SIPNAB_API_KEY=my-secret-token
python3 clients/python/list_dialogs.py
(cd clients/go && go run ./list-dialogs)
node clients/javascript/list-dialogs.mjs
```

Against a sipnab replaying [`tests/pcap-samples/sip-problem-call.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-problem-call.pcap), the
Python program prints:

```text
busy-3a2b1c@192.0.2.30: Failed (4 msgs)
decline-7c6d5e@198.51.100.30: Failed (4 msgs)
notfound-1b2c3d@203.0.113.30: Failed (4 msgs)
unavail-4e5f60@192.0.2.50: Failed (4 msgs)
```

The MCP stdio clients start sipnab themselves. Both take a capture path.

- [`sipnab_mcp.py`](../clients/python/sipnab_mcp.py) needs the SDK from
  [`clients/python/requirements-mcp.txt`](https://github.com/NormB/sipnab/blob/main/clients/python/requirements-mcp.txt).
- [`sipnab-mcp.ts`](../clients/typescript/sipnab-mcp.ts) needs `npm ci` in
  `clients/typescript`.

The site's [Call the REST API from code](https://sipnab.com/docs/api-clients/)
page shows three whole REST clients, held the same way:

- [`clients/go/sipnab-client`](../clients/go/sipnab-client/main.go),
- [`clients/typescript/sipnab-client.ts`](../clients/typescript/sipnab-client.ts),
- [`clients/rust`](../clients/rust/src/main.rs), a member of the Cargo
  workspace.

Each lists the failed dialogs a page at a time and fetches each one. Run the
Rust one with `cargo run -p sipnab-client`.

## Capability examples

These four programs show what sipnab does that a single-capture SIP tool
does not. Each runs on loopback against captures in the repository.

| Example | What it shows | Example input |
|---|---|---|
| [leg_correlate.py](../clients/python/leg_correlate.py) | One call joined across a proxy's capture and a media relay's | Two sipnabs replaying the proxy's and the relay's view of one call |
| [vcon_validate.py](../clients/python/vcon_validate.py) | A vCon export checked against the working group's own schema file | A vCon file sipnab exported, checked by `jsonschema` |
| [hep_senders.py](../clients/python/hep_senders.py) | Who is feeding a HEP collector, and what it refused | One sipnab collecting, two more sending it HEP |
| [tls_plaintext_records.rs](../examples/tls_plaintext_records.rs) | What sipnab makes of the records its BPF TLS probe publishes | None: the program builds the records itself and needs no kernel |

### Join one call seen at two nodes

Each node sees only half of a call:

- A proxy sees a call's signaling and none of its media.
- A relay such as rtpengine sees the media and none of the signaling.

How the halves connect:

- The relay learns the Call-ID from its `ng` control plane. rtpengine can
  mirror that over HEP.
- sipnab records the Call-ID on each stream as `associated_dialog`.
- [`leg_correlate.py`](../clients/python/leg_correlate.py) makes the join. It
  groups the relay's streams by that field and pairs each group with the
  proxy's dialog:

<!-- snippet: clients/python/leg_correlate.py#leg-join -->
```python
by_call: dict[str, list[dict]] = {}
unnamed = []
for s in relay["streams"]:
    call_id = s.get("associated_dialog")
    if call_id:
        by_call.setdefault(call_id, []).append(s)
    else:
        unnamed.append(s)
```

- The program reports streams the relay could not name as `UNNAMED MEDIA`,
  rather than dropping them.
- It refuses two URLs that reach the same sipnab.

To try it, replay one call's two capture points into two sipnab servers:
[`tests/fixtures/opensips-proxy-signaling.pcap`](https://github.com/NormB/sipnab/raw/main/tests/fixtures/opensips-proxy-signaling.pcap)
is the proxy's view and
[`tests/fixtures/rtpengine-opensips-ng.pcap`](https://github.com/NormB/sipnab/raw/main/tests/fixtures/rtpengine-opensips-ng.pcap)
the relay's. Each server runs until you stop it, so start each in its own
terminal, with the same `SIPNAB_API_KEY` exported in each.

Start the proxy's sipnab:

```bash
sipnab -N --node-name proxy -I tests/fixtures/opensips-proxy-signaling.pcap --api 127.0.0.1:8083
```

Start the relay's sipnab:

```bash
sipnab -N --node-name relay -I tests/fixtures/rtpengine-opensips-ng.pcap --api 127.0.0.1:8084
```

Then write the key to a file and join the two:

```bash
# Run all of these, in order.
printf '%s\n' "$SIPNAB_API_KEY" > api.key
python3 clients/python/leg_correlate.py --key-file api.key --proxy http://127.0.0.1:8083 --relay http://127.0.0.1:8084
```

```text
proxy  proxy            http://127.0.0.1:8083
       dialogs=1     streams=0
relay  relay            http://127.0.0.1:8084
       dialogs=0     streams=2

Call-ID                  State       Code  Strm  Pkts    Codec      MOS   2-way
-------------------------------------------------------------------------------
1-4062@198.51.100.21     Completed   200   2     40      G722,PCMU  4.22  yes

  1 call(s) correlated across both nodes
```

Pointing both URLs at one sipnab exits `1`. The message names the capture
instance both answers carry, which differs on every run:

```text
proxy and relay report the same capture instance (9e22818dfa9f0a876b200-2) -- both URLs point at one sipnab, so there is nothing to correlate
```

The caller sent G.722 and the relay forwarded PCMU. So transcoding shows as
two codecs on one call.

- [Cookbook recipe "Compare the same call at two nodes"](examples.md#compare-the-same-call-at-two-nodes)
  compares one call's messages at two nodes.
- This example joins the halves that no single node holds.

### Check a vCon against the publisher's schema

[`vcon_validate.py`](../clients/python/vcon_validate.py) checks containers
against
[`tests/schemas/publisher/vcon_json_schema.json`](https://github.com/NormB/sipnab/blob/main/tests/schemas/publisher/vcon_json_schema.json).

- That is the vCon working group's schema file exactly as it stands in
  [ietf-wg-vcon/draft-ietf-vcon-vcon-core](https://github.com/ietf-wg-vcon/draft-ietf-vcon-vcon-core/blob/99589dd0b474d95c2feed52165fc2c95b1191d3d/vcon_json_schema.json)
  at commit `99589dd0`, the `draft-ietf-vcon-vcon-core-04` tag.
- The engine is `jsonschema`, not sipnab.
- A plain `jsonschema` install checks none of the three formats the schema
  uses. So the program:
  - brings a checker for each,
  - refuses a schema whose formats it cannot check:

<!-- snippet: clients/python/vcon_validate.py#vcon-validate -->
```python
unknown = formats_in(schema) - CHECKERS.keys()
if unknown:
    raise UncheckableFormat(
        f"the schema uses format(s) {sorted(unknown)} that nothing here checks"
    )
checker = FormatChecker(formats=())
for name, check in CHECKERS.items():
    checker.checks(name)(check)
validator = Draft7Validator(schema, format_checker=checker)
return sorted(
    ("/" + "/".join(str(p) for p in e.absolute_path), e.message)
    for e in validator.iter_errors(container)
)
```

Export a container and check it:

```bash
# Run all of these, in order.
sipnab -N -I tests/pcap-samples/sip-problem-call.pcap --export-vcon 'completed-9f8e7d@192.0.2.10' --vcon-out call.vcon
python3 clients/python/vcon_validate.py --schema tests/schemas/publisher/vcon_json_schema.json call.vcon
```

`--schema` names the schema file the program reads by default. Given as a
relative path, it prints that way:

```text
checked against https://ietf.org/vcon/schemas/unsigned-vcon.json (tests/schemas/publisher/vcon_json_schema.json)
valid    call.vcon
```

A failed call passes. So does a call that completed without exported media.

- sipnab writes its Dialog Object as the `recording` placeholder of
  [section 4.3 of draft-ietf-vcon-vcon-core-04](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3).
- That placeholder is a type and no content.

sipnab's own copy of the schema,
[`tests/schemas/vcon.schema.json`](https://github.com/NormB/sipnab/blob/main/tests/schemas/vcon.schema.json),
has the same bytes as the publisher's file.

A container from a sipnab release that wrote no Dialog Object `type` fails
the publisher's schema. Export the call again with the current sipnab:

```text
invalid  completed.vcon
  /dialog/0: 'type' is a required property
```

### See who feeds a HEP collector

A sipnab started with `--hep-listen` collects HEP from any number of agents:

- an SBC,
- a proxy,
- another sipnab running `--hep-send`.

[`hep_senders.py`](../clients/python/hep_senders.py) reads
`GET /v1/hep/senders`. It prints:

- one line per sender,
- one line per source the listener refused:

<!-- snippet: clients/python/hep_senders.py#hep-senders -->
```python
if not report["listening"]:
    raise SystemExit("hep_senders: this sipnab has no HEP listener (start it with --hep-listen)")
lines = []
for s in report["senders"]:
    silent = "  SILENT" if s["silent"] else ""
    lines.append(f"{s['source']}  capture id {s['capture_id']}  {s['packets']} packets{silent}")
for r in report["refused_sources"]:
    reasons = " ".join(f"{k}={v}" for k, v in sorted(r["by_reason"].items()))
    lines.append(f"refused {r['peer']}  {r['packets']} packets  {reasons}")
lines.append(
    f"{len(report['senders'])} sender(s), {report['packets_admitted']} packet(s) admitted, "
    f"{report['packets_refused']} refused"
)
return lines
```

To try it on one machine, start a collector, then replay two captures into
it under two capture IDs.

Start the collector in its own terminal, with `SIPNAB_API_KEY` exported. It
runs until you stop it:

```bash
sipnab -N --node-name collector --hep-listen 127.0.0.1:9061 --api 127.0.0.1:8085
```

Replay the first capture as capture ID 101:

```bash
sipnab -N -I tests/pcap-samples/sip-problem-call.pcap --hep-send 127.0.0.1:9061 --hep-id 101
```

Replay the second as capture ID 102:

```bash
sipnab -N -I tests/fixtures/sip_call.pcap --hep-send 127.0.0.1:9061 --hep-id 102
```

Read the roster:

```bash
SIPNAB_URL=http://127.0.0.1:8085 python3 clients/python/hep_senders.py
```

```text
hep:101@127.0.0.1  capture id 101  23 packets
hep:102@127.0.0.1  capture id 102  7 packets
2 sender(s), 30 packet(s) admitted, 0 refused
```

The roster counts what the collector has admitted so far. If a count is lower
than the capture holds, read it again a moment later: `packets_admitted` in
`GET /v1/hep/senders` reaches 30 for these two captures.

The capture ID is the sender's claim. Nothing proves it without `--hep-auth`.

[Cookbook recipe "Run sipnab as a HEP relay"](examples.md#run-sipnab-as-a-hep-relay) covers the
listener's flags.

### Read TLS without keys: the half that needs no kernel

`--uprobe-tls --uprobe-backend bpf` reads SIP out of the TLS library. It pairs
each write with the socket that sent it
([cookbook recipe "Read TLS *and* who the peer was"](examples.md#read-tls-and-who-the-peer-was)).

- The live half needs root and a kernel with BTF.
- [`tls_plaintext_records.rs`](../examples/tls_plaintext_records.rs) runs the
  other half:
  - It lays out records exactly as the BPF program publishes them.
  - It passes each one through the decode the backend runs:

```bash
cargo run --example tls_plaintext_records
```

```text
REGISTER   127.0.0.1:36160 -> 127.0.0.1:15061  TCP  uprobe:python3/349147#0
200 OK     127.0.0.1:15061 -> 127.0.0.1:36160  TCP  uprobe:python3/349147#1
OPTIONS    0.0.0.0:0 -> 0.0.0.0:0  TCP  uprobe:python3/349147#2
record 3 dropped: not a SIP message
```

- The TLS library buffered the third write rather than sending it.
  - So the program paired it with no socket.
  - sipnab reports no peer rather than guessing one.
- sipnab drops the fourth, which is not SIP.

## Operator tasks

Each of these programs carries out one multi-step recipe from the
[cookbook](examples.md).

- It runs the steps an operator would otherwise type one at a time.
- It ends with the answer the recipe is for.
- Single-command recipes stay recipes.

Each program exits non-zero and says why on a wrong token, a missing call or
customer, a capture with nothing to judge, or no TFPS.

| Program | Recipes | Example input |
|---|---|---|
| [triage.py](../clients/python/triage.py) | [1](examples.md#triage-a-pcap-fast), [16](examples.md#analyze-a-capture-into-one-machine-readable-verdict) | Four failed calls, one clean call, and a capture with no dialog to judge |
| [failed_calls.py](../clients/python/failed_calls.py) | [3](examples.md#find-every-failed-call-grouped-by-response-code), [30](examples.md#find-calls-that-answered-and-were-never-acknowledged) | A sipnab serving four failed calls and one answer nobody acknowledged |
| [one_way_audio.py](../clients/python/one_way_audio.py) | [4](examples.md#diagnose-a-one-way-audio-complaint), [11](examples.md#find-why-a-call-sounds-bad-in-one-direction-only), [22](examples.md#measure-whether-the-loss-is-yours-or-the-networks) | A phone behind NAT that hears the far end and is not heard |
| [scanner_ban.py](../clients/python/scanner_ban.py) | [10](examples.md#detect-sip-scanners-and-auto-block-via-fail2ban), [23](examples.md#find-the-device-flooding-register) | A scanner and two flooding sources, banned through a stand-in for `tfps_ctl` |
| [customer_export.py](../clients/python/customer_export.py) | [39](examples.md#collect-a-directory-of-rotated-captures-into-one-analysis), [32](examples.md#export-one-customers-calls-as-a-smaller-capture), [40](examples.md#open-the-same-evidence-in-wireshark) | Three rotated files, one export, opened by `tshark` and `capinfos` |

- The two programs that read a capture file, `triage.py` and
  `customer_export.py`, run sipnab themselves.
- `scanner_ban.py` does both. It reads the capture, then bans through a
  running sipnab.
- Each finds sipnab through `--sipnab`, else `SIPNAB_BIN`, else `PATH`.
- The REST programs read `SIPNAB_URL` and `SIPNAB_API_KEY`, like the
  reference-page programs.

### Triage a capture to one verdict

[`triage.py`](../clients/python/triage.py) runs `--json-analyze`. It turns
its one object into a verdict and an exit status:

- `0` clean,
- `1` problems,
- `2` inconclusive,
- `3` sipnab could not read the input.

The third verdict is the reason the program exists.

- A capture with no SIP in it analyzes to an empty list of findings.
- So does a capture with its SIP outside `--portrange`.
- An empty list reads as clean:

<!-- snippet: clients/python/triage.py#triage-verdict -->
```python
seen = (
    f"{analysis['frames_read']} frame(s), {analysis['dialogs_examined']} dialog(s), "
    f"{analysis['streams_examined']} stream(s)"
)
findings = analysis["findings"]
if not analysis["complete"]:
    head, result = f"inconclusive: sipnab did not analyze all of the capture ({seen})", "inconclusive"
elif findings:
    head, result = f"problems: {seen}", "problems"
elif analysis["dialogs_examined"] == 0 and analysis["streams_examined"] == 0:
    head = (
        f"inconclusive: {analysis['frames_read']} frame(s) and no SIP dialog or RTP "
        "stream to judge, so an empty finding list proves nothing"
    )
    result = "inconclusive"
else:
    head, result = f"clean: {seen}", "clean"
lines = [head]
for f in findings:
    lines.append(f"  {f['severity']}  {f['kind']}  {f['occurrences']} {f['unit']}(s)")
    lines.extend(evidence_lines(f))
return result, lines
```

```bash
python3 clients/python/triage.py capture.pcap
```

Against [`tests/pcap-samples/sip-problem-call.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-problem-call.pcap) it exits `1`:

```text
problems: 23 frame(s), 5 dialog(s), 0 stream(s)
  major  server_failure  2 call(s)
    decline-7c6d5e@198.51.100.30  Decline
    unavail-4e5f60@192.0.2.50  Service Unavailable
  minor  request_failure  2 call(s)
    busy-3a2b1c@192.0.2.30  Busy Here
    notfound-1b2c3d@203.0.113.30  Not Found
```

### Group failed calls by response code

The shell histogram in recipe "Find every failed call, grouped by response code" counts every response inside a failed call.
So the `100 Trying` before a `486` counts too.

[`failed_calls.py`](../clients/python/failed_calls.py) works differently:

- It counts each call once, under its final code, through `GET /v1/aggregate`.
- It names the calls in each group.
- A call answered and never acknowledged has not failed. So the grouping
  cannot show it.
- The program reads those calls from the capture's findings
  (`GET /v1/report`):

<!-- snippet: clients/python/failed_calls.py#failed-calls -->
```python
aggregate = get("/v1/aggregate", by="response_code", filter=FAILED)
calls = {}
for bucket in aggregate["buckets"]:
    code = bucket["value"]
    if code == "(none)":
        # No final code to filter on: counted, not listed.
        calls[code] = ([], bucket["count"])
        continue
    page = get("/v1/dialogs", filter=f"{FAILED} AND response_code == {code}")
    calls[code] = ([d["call_id"] for d in page["dialogs"]], page["total"])
report = get("/v1/report")
```

sipnab reports a missing `ACK` only once the answer has waited
`--ack-timeout`. That defaults to [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261.html) Timer H, 32 seconds.

To try it, serve the four failed calls and
[`tests/fixtures/sip-answered-never-acked.pcap`](https://github.com/NormB/sipnab/raw/main/tests/fixtures/sip-answered-never-acked.pcap),
whose answer waited 31.5 seconds. `--ack-timeout 5` makes that call count.
Start the server in its own terminal, with `SIPNAB_API_KEY` exported:

```bash
sipnab -N --ack-timeout 5 -I tests/pcap-samples/sip-problem-call.pcap -I tests/fixtures/sip-answered-never-acked.pcap --api 127.0.0.1:8086
```

Then run the program:

```bash
SIPNAB_URL=http://127.0.0.1:8086 python3 clients/python/failed_calls.py
```

```text
4 failed call(s), by final response code:
  404  1 call(s)
    notfound-1b2c3d@203.0.113.30
  486  1 call(s)
    busy-3a2b1c@192.0.2.30
  503  1 call(s)
    unavail-4e5f60@192.0.2.50
  603  1 call(s)
    decline-7c6d5e@198.51.100.30
1 call(s) answered and never acknowledged:
  noack-5d4c3b@192.0.2.70  31.5s elapsed with no ACK, answer sent 11 time(s)
```

### Diagnose one-way audio, and whose loss it is

[`one_way_audio.py`](../clients/python/one_way_audio.py) takes a Call-ID. It
prints:

- the call's diagnosis and streams (recipe "Diagnose a one-way audio complaint"),
- the asymmetry signals the filter language holds and the report does not
  (recipe "Find why a call sounds bad in one direction only"),
- whether the loss figures belong to the network or to the capture
  (recipe "Measure whether the loss is yours or the network's").

sipnab counts a packet the capture host dropped as network loss. So the last
line comes from `GET /v1/stats`:

<!-- snippet: clients/python/one_way_audio.py#whose-loss -->
```python
kernel = quality["kernel_dropped_packets"]
interface = quality["interface_dropped_packets"]
lines = []
if kernel:
    lines.append(
        f"capture: {kernel} packet(s) dropped by the kernel buffer on the capture host, "
        "counted above as network loss (raise -B/--buffer, narrow the BPF filter, "
        "or lower --snaplen)"
    )
if interface:
    lines.append(
        f"capture: {interface} packet(s) dropped by the interface or its driver, counted "
        "above as network loss (a bigger buffer cannot fix these: check the NIC)"
    )
if not lines:
    lines.append(
        "capture: no packet dropped by the kernel buffer or the interface, "
        "so the loss above is the network's"
    )
snapped, undecodable = quality["snapped_frames"], quality["undecodable_frames"]
if snapped or undecodable:
    lines.append(
        f"capture: {snapped} frame(s) cut short by the snaplen and {undecodable} frame(s) "
        "it could not decode; loss figures may be low as well as high"
    )
return lines
```

For the phone behind NAT in
[`tests/fixtures/stun_sdp_mismatch.pcap`](https://github.com/NormB/sipnab/raw/main/tests/fixtures/stun_sdp_mismatch.pcap):

- media flows both ways,
- the reply arrives from an address no SDP offered.

```text
stun-sdp-mismatch-1@192.168.10.50  Completed  200
one-way audio: yes
NAT mismatch: yes
  0x11223344  192.168.10.50:40000 -> 198.51.100.30:41000  PCMU  30 packets  loss 0.0%
  0x55667788  203.0.113.7:41000 -> 192.168.10.50:40000  PCMU  30 packets  loss 0.0%
hint: RTP flowed 192.168.10.50:40000 -> 198.51.100.30:41000 only (SSRC 0x11223344). No reverse media flow detected.
```

Three more hints follow. Then come `asymmetry: none` and the capture's verdict
on its own loss.

Loss upstream of the capture point is invisible to both counters. An example
is a SPAN port that mirrors one direction.

### Ban a scanner through TFPS, and verify it

sipnab recommends and applies nothing ([recipe "Block a scanner with a rule sipnab wrote, after reading the evidence"](examples.md#block-a-scanner-with-a-rule-sipnab-wrote-after-reading-the-evidence)).

[`scanner_ban.py`](../clients/python/scanner_ban.py):

- reads the accusations `--recommend-block` prints,
- bans through `POST /v1/tfps/ban` only the sources with no counter-evidence,
- counts a ban only once `GET /v1/tfps/banned` lists it as enforced.

The program withholds some sources:

- A source that completed a registration before its credentials went wrong is
  the device recipe "Find the device flooding REGISTER" finds.
- A ban would cut off a working peer.
- The program withholds that source and names it.

A ban changes another system. So sipnab takes it only:

- when started with `--allow-action tfps:rest`,
- from a token minted with `--token-scope actions`.

The program reads with `SIPNAB_API_KEY` and bans with `SIPNAB_ACTION_TOKEN`.
Every ban expires, after `--ttl` seconds (an hour by default):

<!-- snippet: clients/python/scanner_ban.py#tfps-ban -->
```python
failed, applied = False, []
for a in ban:
    body = {"ip": a["ip"], "ttl_secs": args.ttl}
    done = call("POST", "/v1/tfps/ban", body, ACTION_TOKEN)
    print(describe_action(done, a["ip"], a["rules"], args.ttl))
    if done["applied"]:
        applied.append(a["ip"])
    else:
        failed = True
for line in withheld:
    print(line)
missing = unverified(applied, call("GET", "/v1/tfps/banned")["rows"])
for ip in missing:
    print(f"NOT in TFPS's banned list: {ip}")
print(f"verified {len(applied) - len(missing)} of {len(applied)} ban(s) in TFPS's banned list")
```

```bash
# Run all of these, in order.
export SIPNAB_ACTION_TOKEN=$(sipnab --mint-token --token-scope actions --token-id scanner-ban \
  --api-signing-key-file /etc/sipnab/signing.key)
python3 clients/python/scanner_ban.py capture.pcap --ttl 600 --reg-flood-threshold 10
```

Against [`tests/fixtures/sip-scanner-and-register-flood.pcap`](https://github.com/NormB/sipnab/raw/main/tests/fixtures/sip-scanner-and-register-flood.pcap):

```text
banned 198.51.100.77 (reg_flood) for 600 s
banned 203.0.113.42 (scanner) for 600 s
withheld 192.0.2.10 (reg_flood): it also completed a registration or a call in this capture
verified 2 of 2 ban(s) in TFPS's banned list
```

To try the program without TFPS, which needs root to ban, point sipnab at
[`clients/python/tests/fake_tfps_ctl.py`](https://github.com/NormB/sipnab/blob/main/clients/python/tests/fake_tfps_ctl.py).
It answers as `tfps_ctl --json` does and keeps its block list in the file
`FAKE_TFPS_STATE` names. Start the server in its own terminal, with
`SIPNAB_API_KEY` exported and a signing key in `signing.key`:

```bash
FAKE_TFPS_STATE=tfps-block-list.json sipnab -N -I tests/fixtures/sip-scanner-and-register-flood.pcap --api 127.0.0.1:8087 --api-signing-key-file signing.key --allow-action tfps:rest --journal-dir journal --tfps-ctl clients/python/tests/fake_tfps_ctl.py
```

Mint the actions token from the same key and run the program:

```bash
# Run all of these, in order.
export SIPNAB_ACTION_TOKEN=$(sipnab --mint-token --token-scope actions --token-id scanner-ban --api-signing-key-file signing.key)
SIPNAB_URL=http://127.0.0.1:8087 python3 clients/python/scanner_ban.py tests/fixtures/sip-scanner-and-register-flood.pcap --ttl 600 --reg-flood-threshold 10
```

It prints the same four lines as above, and the stand-in's block list holds
the two banned addresses:

```bash
cat tfps-block-list.json
```

```json
{"198.51.100.77": 1792152463, "203.0.113.42": 1792152463}
```

The numbers are the Unix times each ban expires. Run the program against a
real TFPS before you rely on it for a production block list.

### Export the calls of one customer from rotated captures

[`customer_export.py`](../clients/python/customer_export.py) takes a
directory of rotated captures (recipe "Collect a directory of rotated captures into one analysis") and a SIP user.

- It exports that user's calls with `-O` and a BPF expression over their
  addresses (recipe "Export one customer's calls as a smaller capture").
- It prints the `tshark` command that opens the result (recipe "Open the same evidence in Wireshark").
- BPF selects addresses, not users. So the program reads the export back
  before it calls it done:

<!-- snippet: clients/python/customer_export.py#export-check -->
```python
problems = []
for call_id, call in sorted(wanted.items()):
    found = got.get(call_id)
    if found is None:
        problems.append(f"{call_id}: not in the export")
    elif found["messages"] != call["messages"]:
        problems.append(
            f"{call_id}: {found['messages']} of its {call['messages']} message(s) are in the export"
        )
for call_id in sorted(set(got) - set(wanted)):
    problems.append(
        f"{call_id}: another customer's call shares an address with this one, "
        "and BPF cannot separate them"
    )
return problems
```

When another customer's call shares an address:

- the program removes the export rather than handing it over,
- recipe "Export one customer's calls as a smaller capture"'s vCon export is the way to go.

Run it on a directory of rotated captures. Here `rotated/` holds
`sip-problem-call.pcap` cut into three files, `tg.pcap2`, `tg.pcap0` and
`tg.pcap1`, the way a wrapped `tcpdump -C -W` ring leaves them. The call
placed by `alice` crosses all three:

```bash
python3 clients/python/customer_export.py rotated --user alice --out alice.pcap
```

```text
alice: 1 call(s)
  completed-9f8e7d@192.0.2.10  7 message(s)
BPF: host 192.0.2.10 or host 192.0.2.20
wrote alice.pcap: 7 SIP message(s), every call whole, no other call
tshark -r 'alice.pcap' -Y 'sip.Call-ID == "completed-9f8e7d@192.0.2.10"' -V
```

## AI tasks

Each of these programs does what an agent does with sipnab over MCP. Each
ends with the answer the agent would act on.

They share [`mcp_calls.py`](../clients/python/mcp_calls.py). It reaches sipnab
over either:

- stdio, through the MCP SDK in
  [`clients/python/requirements-mcp.txt`](https://github.com/NormB/sipnab/blob/main/clients/python/requirements-mcp.txt),
- HTTP, through the client in
  [`mcp_probe.py`](../clients/python/mcp_probe.py).

Before asking anything else, each waits for `capture_status` to report the
file read to its end. An answer given earlier describes part of the capture.

| Program | What it does | Input |
|---|---|---|
| [agent_triage.py](../clients/python/agent_triage.py) | `list_dialogs` and `get_capture_report` to one verdict, and the calls to look at next | A capture path (stdio), or a server URL and a token file (HTTP) |
| [evidence_handoff.py](../clients/python/evidence_handoff.py) | An evidence package and a SIPp scenario per call, read back and checked | A capture path, a file root and a package name |
| [aggregate_for_model.py](../clients/python/aggregate_for_model.py) | A filter, `aggregate_dialogs`, and JSON cut to a byte budget | A capture path, a field to group by, a filter and a byte budget |

### Triage a capture over MCP, as an agent

[`agent_triage.py`](../clients/python/agent_triage.py):

- starts sipnab as an MCP stdio child,
- pages through `list_dialogs` with its cursor,
- asks `get_capture_report` for the findings.

The verdict is the one [`triage.py`](#triage-a-capture-to-one-verdict) gives,
with the same exit status. The program adds what an agent needs from two
answers:

- a check that both describe one capture,
- a summary by state,
- one `next:` line per call a finding names, with the tool to call next:

<!-- snippet: clients/python/agent_triage.py#agent-verdict -->
```python
result, lines = triage.verdict(report)
disagree = []
if len(rows) != total:
    disagree.append(
        f"inconclusive: list_dialogs reported {total} dialog(s) and paging returned {len(rows)}"
    )
if report["dialogs_examined"] != total:
    disagree.append(
        f"inconclusive: get_capture_report examined {report['dialogs_examined']} dialog(s) "
        f"and list_dialogs holds {total}, so the two answers are not about one capture"
    )
named = named_calls(report)
# A finding that omitted evidence counted calls it does not name, so a
# Failed dialog missing from the names may be one of those.
omitted = any(f.get("evidence_omitted") for f in report["findings"])
unexplained = [] if omitted else [
    r["call_id"] for r in rows if r["state"] == "Failed" and r["call_id"] not in named
]
if disagree or (unexplained and result == "clean"):
    result = "inconclusive"
by_state = collections.Counter(r["state"] for r in rows)
ordered = sorted(by_state.items(), key=lambda kv: (-kv[1], kv[0]))
summary = ", ".join(f"{n} {state}" for state, n in ordered)
lines = disagree + lines
lines.append(f"summary: {len(rows)} dialog(s) listed: {summary}" if rows else "summary: no dialog listed")
lines += [f"unexplained: {c} is Failed and no finding names it" for c in unexplained]
lines += [f"next: triage_call {c}" for c in named]
return result, lines
```

```bash
python3 clients/python/agent_triage.py capture.pcap
```

Against [`tests/pcap-samples/sip-problem-call.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-problem-call.pcap) it exits `1`:

```text
problems: 23 frame(s), 5 dialog(s), 0 stream(s)
  major  server_failure  2 call(s)
    decline-7c6d5e@198.51.100.30  Decline
    unavail-4e5f60@192.0.2.50  Service Unavailable
  minor  request_failure  2 call(s)
    busy-3a2b1c@192.0.2.30  Busy Here
    notfound-1b2c3d@203.0.113.30  Not Found
summary: 5 dialog(s) listed: 4 Failed, 1 Completed
next: triage_call decline-7c6d5e@198.51.100.30
next: triage_call unavail-4e5f60@192.0.2.50
next: triage_call busy-3a2b1c@192.0.2.30
next: triage_call notfound-1b2c3d@203.0.113.30
```

Take a dialog in the `Failed` state that no finding names, while the report
says clean. That makes the verdict inconclusive.

- One of the two answers is wrong.
- An agent that picked either would be guessing.

### Reach a production box over HTTP with a signed token

The same program takes `--url` and `--token-file` instead of a capture. It
asks a sipnab serving `--mcp-transport http`.

- The server holds a signing key.
- Each agent gets a short-lived token minted from it with
  `--mint-token --token-scope read`. This is the shape
  [cookbook recipe "Set up the MCP server for a hosted agent"](examples.md#set-up-the-mcp-server-for-a-hosted-agent)
  deploys.
- A `read` token reaches only the tools annotated read-only. That includes
  every tool this triage calls.
- The client is the one in `mcp_probe.py`:

<!-- snippet: clients/python/mcp_calls.py#signed-http -->
```python
node = mcp_probe.Mcp(url, token, "sipnab")
# A refused token fails here, as SystemExit naming the HTTP status:
# sipnab answers 401 before any session exists.
node.initialize()

async def call(name: str, arguments: dict):
    return node.call(name, arguments)
```

```bash
# Run all of these, in order.
sipnab --mint-token --token-scope read --token-id agent-a --mcp-signing-key-file /etc/sipnab/mcp.key --mcp-token-ttl 900 >agent.token
python3 clients/python/agent_triage.py --url http://127.0.0.1:8731 --token-file agent.token
```

- Over HTTP the program prints the same lines as over stdio.
- The server answers `401`, and the program exits naming that status, for a
  token signed with another key, a token minted from the same key for the
  REST API, or no token.
- A server started with `--mcp-tools core`, as recipe "Set up the MCP server
  for a hosted agent" deploys it, serves every tool this triage calls.

### Hand an agent an evidence package and a repro script

[`evidence_handoff.py`](../clients/python/evidence_handoff.py) takes the
calls the findings name. It then asks:

- `build_evidence_package` for one directory holding them,
- `generate_repro` for a SIPp scenario per call, pinning the Request-URI.

sipnab writes both under `--mcp-file-root`, and never over a name already
taken. The program reads the files back rather than trusting either answer:

<!-- snippet: clients/python/evidence_handoff.py#package-check -->
```python
pkg = root / name
problems = []
named = set(answer["files"])
on_disk = {p.name for p in pkg.iterdir()}
for f in sorted(named - on_disk):
    problems.append(f"{name}/{f}: named in the answer and not on disk")
for f in sorted(on_disk - named):
    problems.append(f"{name}/{f}: on disk and not named in the answer")
if "manifest.json" in on_disk:
    manifest = json.loads((pkg / "manifest.json").read_text())
    listed = [c["call_id"] for c in manifest["calls"]]
    if listed != call_ids:
        problems.append(f"{name}/manifest.json lists {listed}, not {call_ids}")
if "README.md" in on_disk and REBUILT not in (pkg / "README.md").read_text():
    problems.append(f"{name}/README.md does not say the frames were rebuilt, not copied")
return problems
```

Each scenario on disk must:

- be the text the answer returned,
- assert the final response the capture held.

The program prints one `sha256` line per file, relative to the file root:

```bash
python3 clients/python/evidence_handoff.py capture.pcap --file-root /var/lib/sipnab/evidence --name failed-calls
```

```text
package failed-calls: 4 call(s), 16 message(s)
repro failed-calls.call-01.xml  decline-7c6d5e@198.51.100.30  asserts 603  pinned request_uri
repro failed-calls.call-02.xml  unavail-4e5f60@192.0.2.50  asserts 503  pinned request_uri
repro failed-calls.call-03.xml  busy-3a2b1c@192.0.2.30  asserts 486  pinned request_uri
repro failed-calls.call-04.xml  notfound-1b2c3d@203.0.113.30  asserts 404  pinned request_uri
```

Two runs over one capture into two file roots print the same lines and write
byte-identical files.

- The package holds no clock time, host name or random value, so its files
  match across time zones and capture file paths.
- The program prints each path relative to its file root.
- The README and manifest name the sipnab version, so the hashes change
  between sipnab releases.

### Aggregate dialogs into bounded JSON for a model

[`aggregate_for_model.py`](../clients/python/aggregate_for_model.py) sends a
[filter-DSL](filter-dsl.md) expression to `aggregate_dialogs`. It prints one
line of JSON no longer than `--max-bytes`.

- sipnab bounds:
  - the number of buckets (`--mcp-max-rows`),
  - the length of each value taken from a packet (256 bytes, then a marker).
- It does not bound the answer as a whole. The budget belongs to the model
  reading it.
- So the program makes the cut, whole buckets at a time:

<!-- snippet: clients/python/aggregate_for_model.py#model-bound -->
```python
buckets = answer["buckets"]
if sum(b["count"] for b in buckets) + answer["other_count"] != answer["total_matched"]:
    raise ValueError(
        f"sipnab's buckets and other_count do not add up to total_matched "
        f"{answer['total_matched']}; refusing to pass on a wrong total"
    )

def doc(kept: int) -> str:
    return encode({
        "group_by": answer["group_by"],
        "filter": filter_expr,
        "total_matched": answer["total_matched"],
        "distinct_values": answer["distinct_values"],
        "buckets": [{"value": b["value"], "count": b["count"]} for b in buckets[:kept]],
        "other_count": answer["other_count"] + sum(b["count"] for b in buckets[kept:]),
        "omitted_buckets": len(buckets) - kept,
    })

def fits(kept: int) -> bool:
    return len(doc(kept).encode("utf-8")) <= max_bytes

if not fits(0):
    raise ValueError(
        f"the answer is {len(doc(0).encode('utf-8'))} byte(s) with no bucket at all, "
        f"over the {max_bytes}-byte budget"
    )
# Fewer buckets is never longer, so the most that fit is found by halving.
lo, hi = 0, len(buckets)
while lo < hi:
    mid = (lo + hi + 1) // 2
    lo, hi = (mid, hi) if fits(mid) else (lo, mid - 1)
return doc(lo), len(buckets) - lo
```

- A cut in the middle of a string leaves a model an unterminated value to
  complete.
- Dropping whole buckets into `other_count`:
  - keeps the JSON valid under every budget,
  - keeps the counts adding up to `total_matched`.
- Values sipnab took from packets keep its untrusted-data markers. That is why
  the budget counts bytes: each marker character is three.

```bash
python3 clients/python/aggregate_for_model.py capture.pcap --group-by response_code --filter "state == 'Failed'" --max-bytes 200
```

```text
{"group_by":"response_code","filter":"state == 'Failed'","total_matched":4,"distinct_values":4,"buckets":[{"value":"404","count":1},{"value":"486","count":1}],"other_count":2,"omitted_buckets":2}
```

## Run every example locally

Build sipnab with every feature and its examples. Then run the smoke script,
which starts the servers each program needs on loopback. The operator tasks
also need `tshark` and `capinfos`, from Ubuntu's `tshark` package:

```bash
# Run all of these, in order.
cargo build --all-features --bins --examples
scripts/smoke-clients.sh target/debug/sipnab
```

- For Rust, see the [library API](library.md) and its executable rustdoc examples.
- For individual CLI commands, use the [cookbook](examples.md).
- C and C++ have no client examples yet.
- The `c` blocks in [capture tuning](tuning-capture.md) quote libpcap's source.
  They are citations, not examples.
