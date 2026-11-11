# Answer questions about a capture

A ticket rarely asks about one call. It asks which failure dominated, whether
one carrier got worse, who flooded the proxy, when the trouble started, or
which of last night's files holds the call a customer named. sipnab answers
each of those with one command that reads the capture, prints a table and
exits.

This page takes one question per section. Each section gives the command, the
output it printed, how to read it, and the same question asked over the REST
API, over MCP and in the terminal interface.

## What you need

- A sipnab build with the default features. Every command on this page reads
  a capture file, so none needs root or `CAP_NET_RAW`.
- Nothing on any other system. These commands read what a capture already
  holds. They need no change to OpenSIPS, Kamailio, rtpengine or anything else.
- A capture. The examples read captures that ship with sipnab, in
  `tests/pcap-samples/` of a source checkout. `sip-problem-call.pcap` holds
  five calls: one answered, and four that failed with `486`, `603`, `404` and
  `503`.

Every query flag:

- counts the calls the run's filter admits: `--filter`, a
  [diagnostic alias](filter-dsl.md#named-aliases) such as `--problems`, and
  `--since`/`--until`;
- makes the run headless, so `-N` is optional;
- prints a table, or the same table in Markdown with `--markdown`;
- with `--json`, prints one JSON object on the last line of standard output.

`--no-cli-print` leaves out the per-message lines that come first, and
`--quiet` leaves out the summary on standard error. The examples use both.

## Which failure dominated

Count the calls by their final response code:

```sh
sipnab -I tests/pcap-samples/sip-problem-call.pcap --count-by response_code --no-cli-print --quiet
```

```text
Dialogs by response_code: 5 values, 5 dialogs
Value  Dialogs
--------------
200    1
404    1
486    1
503    1
603    1
```

- Values come largest first. Values with the same count come in order.
- A call with no value counts under `(none)`. A call still ringing when the
  capture ended has no final response code.

Narrow the run to ask about a subset. The failed calls, by who they were for:

```sh
sipnab -I tests/pcap-samples/sip-problem-call.pcap --count-by to.user --filter "state == 'Failed'" --no-cli-print --quiet
```

```text
Dialogs by to.user: 4 values, 4 dialogs
Value  Dialogs
--------------
dave   1
frank  1
heidi  1
judy   1
```

`--count-by` takes `state`, `response_code`, `method`, `from.user`, `to.user`,
`ua`, `src.ip`, `dst.ip` and `rtp.codec`. Keep the largest values with
`--top N` (50 by default). The last line sums the rest.

For a script, read the JSON. `capture_identity` names the run, so `jq` drops it
here:

```sh
sipnab -I tests/pcap-samples/sip-problem-call.pcap --count-by response_code --json --no-cli-print --quiet | jq -c 'del(.capture_identity)'
```

```json
{"schema_version":1,"group_by":"response_code","buckets":[{"value":"200","count":1},{"value":"404","count":1},{"value":"486","count":1},{"value":"503","count":1},{"value":"603","count":1}],"other_count":0,"distinct_values":5,"total_matched":5}
```

## Whether one route or carrier is doing worse

Print the carrier metrics for each destination address:

```sh
sipnab -I tests/pcap-samples/sip-problem-call.pcap --rates-by dst.ip --no-cli-print --quiet
```

```text
Carrier metrics by dst.ip: 5 values, 5 dialogs
Value          Dialogs  asr  ner  acd   pdd_p50  pdd_p95  mos_p10  retransmit_rate
----------------------------------------------------------------------------------
192.0.2.20     1        100  100  17.9  850      850      -        0
192.0.2.40     1        0    100  -     -        -        -        0
192.0.2.60     1        0    0    -     -        -        -        0
198.51.100.40  1        0    100  -     -        -        -        0
203.0.113.40   1        0    0    -     -        -        -        0
Units: asr percent, ner percent, acd seconds, pdd_p50 milliseconds, pdd_p95 milliseconds, mos_p10 mos, retransmit_rate retransmissions per dialog
-: the group's population could not support the figure; --json names why in not_grounded
```

Read the columns as a carrier would:

- `asr` (answer-seizure ratio): the share of INVITEs with a final response
  that the far end answered.
- `ner` (network effectiveness ratio): the same, also counting the outcomes
  the far end decided, such as busy and decline. So `ner` can exceed `asr`.
- `acd` (average call duration): the mean talk time of the calls answered and
  hung up inside the capture.
- `pdd_p50` and `pdd_p95`: post-dial delay, the median and the
  ninety-fifth percentile.
- `mos_p10`: the tenth-percentile MOS of the calls' audio. The capture must
  hold the RTP for a MOS.
- `-`: the group holds no call the figure can come from. `--json` says why in
  `not_grounded`.

`--rates-by` takes every `--count-by` dimension, plus `to_domain`, `hour` and
`next_hop`.

## Who is sending the most

Rank the addresses that took part in the most calls:

```sh
sipnab -I tests/pcap-samples/sip-problem-call.pcap --talkers ip --top 3 --no-cli-print --quiet
```

```text
Talkers by ip: 10 talkers, 5 dialogs
Talker      Dialogs  Messages  INVITEs  Answered  Failed  Share%
----------------------------------------------------------------
192.0.2.20  1        4         1        1         0       20
192.0.2.10  1        3         1        1         0       20
192.0.2.30  1        2         1        0         1       20
Other: 7 talkers past --top 3
```

- `Share%` is the share of the counted calls each address took part in. A call
  counts for every address in it, so the shares can add up to more than 100.
- `--talkers ua` ranks the `User-Agent` and `Server` banners instead, and
  `--talkers prefix` the dialed numbers' first digits (four, or
  `--prefix-digits N`).

A scanner shows up here as an address with many calls and no answers. To
judge it, read the scanner detector's findings: see
[Feed fail2ban from sipnab](fail2ban-sipnab.md).

## When the trouble started

Count the calls that started in each five-second interval:

```sh
sipnab -I tests/pcap-samples/sip-problem-call.pcap --timeline=5 --no-cli-print --quiet
```

```text
Call volume: 3 buckets of 5 s, 5 dialogs
Start                      Dialogs
----------------------------------
2023-11-14T22:13:20+00:00  2
2023-11-14T22:13:25+00:00  2
2023-11-14T22:13:30+00:00  1
```

- The intervals line up on the clock, not on the first call, so two captures
  of the same hour line up too.
- An interval with no call prints a zero. A gap in traffic is a run of zeros.
- A bare `--timeline` uses 60 seconds.

Combine it with a filter to see when the failures happened:

```sh
sipnab -I tests/pcap-samples/sip-problem-call.pcap --timeline=5 --problems --no-cli-print --quiet
```

```text
Call volume: 3 buckets of 5 s, 4 dialogs
Start                      Dialogs
----------------------------------
2023-11-14T22:13:20+00:00  1
2023-11-14T22:13:25+00:00  2
2023-11-14T22:13:30+00:00  1
```

Then scope every other command to the busy interval with `--since` and
`--until`. See [Narrow a capture to when the problem happened](examples.md#narrow-a-capture-to-when-the-problem-happened).

## What one phone or address did

Name an address to see everything it did:

```sh
sipnab -I tests/pcap-samples/sip-problem-call.pcap --endpoint-ip 192.0.2.30 --no-cli-print --quiet
```

```text
Endpoint ip 192.0.2.30: 1 dialog
Dialogs by method: INVITE 1
Dialogs by state: Failed 1
Messages: 2 sent, 2 received
Calls: 1 INVITE, 1 with a final response, 1 failed (100%); final responses: 486 x1
Banners: none
Signaling stack: not inferred
Media: 0 streams (0 orphaned), 0 packets, 0 lost, max jitter -, codecs none
Most recent dialogs (1 of 1):
Call-ID                 Method  State   Final  Started
------------------------------------------------------------------------
busy-3a2b1c@192.0.2.30  INVITE  Failed  486    2023-11-14T22:13:23+00:00
```

- `Messages` counts what the address sent and what it received.
- `Banners` are the `User-Agent` and `Server` values it sent.
- `Signaling stack` names the SIP library its requests look built by.
- `--filter` does not narrow the rollup. It covers every call the address took
  part in. `--top` bounds only the list of recent calls.

Name a SIP user instead, matched against the user part of each call's From and
To:

```sh
sipnab -I tests/pcap-samples/sip-problem-call.pcap --endpoint-user dave --no-cli-print --quiet
```

```text
Endpoint user dave: 1 dialog
Dialogs by method: INVITE 1
Dialogs by state: Failed 1
Calls: 1 INVITE, 1 with a final response, 1 failed (100%); final responses: 486 x1
Banners: none
Signaling stack: not inferred
Media: 0 streams (0 orphaned), 0 packets, 0 lost, max jitter -, codecs none
Most recent dialogs (1 of 1):
Call-ID                 Method  State   Final  Started
------------------------------------------------------------------------
busy-3a2b1c@192.0.2.30  INVITE  Failed  486    2023-11-14T22:13:23+00:00
```

A user has no message counts, because messages belong to an address.

## Why this call failed when that one worked

Put the two calls side by side:

```sh
sipnab -I tests/pcap-samples/sip-problem-call.pcap --compare-dialogs completed-9f8e7d@192.0.2.10 busy-3a2b1c@192.0.2.30 --no-cli-print --quiet
```

```text
Comparing completed-9f8e7d@192.0.2.10 (A) with busy-3a2b1c@192.0.2.30 (B): 4 fields differ
Field              A               B           Differs
------------------------------------------------------
state              Completed       Failed      differs
final_status_code  200             486         differs
msg_count          7               4           differs
methods            ACK,BYE,INVITE  ACK,INVITE  differs
Hints for A: none
Hints for B: Call failed: 486 Busy Here.
```

- `differs` marks each field that is not the same.
- The hints are each call's own diagnosis. sipnab lists them and does not
  compare them.
- Give the Call-IDs exactly. `--report` lists the ones the capture holds.

To see the two calls' messages, run `--call-report` on each. See
[Generate a call report](examples.md#generate-a-call-report-text--markdown--json).

## Whether a change made things better or worse

Hold the capture from after a change against the one from before:

```sh
sipnab --compare-captures tests/pcap-samples/sip-problem-call.pcap tests/pcap-samples/sip-rtp-g711.pcap
```

```text
A: tests/pcap-samples/sip-problem-call.pcap, 23 packets, 5 dialogs, 0 streams
B: tests/pcap-samples/sip-rtp-g711.pcap, 852 packets, 2 dialogs, 2 streams

By state:
Value      A  B  Change
-----------------------
Failed     4  0  -4
InCall     0  1  +1
Completed  1  1  0

By response_code:
Value  A  B  Change
-------------------
200    1  2  +1
404    1  0  -1
486    1  0  -1
503    1  0  -1
603    1  0  -1

'tests/pcap-samples/sip-problem-call.pcap' (5 dialogs) is the baseline; 'tests/pcap-samples/sip-rtp-g711.pcap' (2 dialogs) is held against it, so delta is b minus a.
```

- The first file is the baseline. `Change` is the second minus the first, so a
  negative number means that value became rarer.
- Each dimension lists the values that moved most first.
- sipnab reads both files and exits. Give no `-I`.

Choose what to compare with `--compare-dimensions`, from the `--count-by` set.
`state,response_code` is the default:

```sh
sipnab --compare-captures tests/pcap-samples/sip-problem-call.pcap tests/pcap-samples/sip-rtp-g711.pcap --compare-dimensions rtp.codec
```

```text
A: tests/pcap-samples/sip-problem-call.pcap, 23 packets, 5 dialogs, 0 streams
B: tests/pcap-samples/sip-rtp-g711.pcap, 852 packets, 2 dialogs, 2 streams

By rtp.codec:
Value   A  B  Change
--------------------
(none)  5  0  -5
PCMA    0  1  +1
PCMU    0  1  +1

'tests/pcap-samples/sip-problem-call.pcap' (5 dialogs) is the baseline; 'tests/pcap-samples/sip-rtp-g711.pcap' (2 dialogs) is held against it, so delta is b minus a.
```

Two captures compare well only when they cover the same kind of traffic for a
similar span. Use `--count-by` on each first if you are not sure.

## Which file holds the call

A customer names a Call-ID, and the capture host has rotated files for the
whole day. Search them:

```sh
sipnab --find-in-files tests/pcap-samples/sip-problem-call.pcap tests/pcap-samples/sip-rtp-g711.pcap tests/pcap-samples/sip-auth-failure.pcapng --filter "call_id == 'busy-3a2b1c@192.0.2.30'"
```

```text
Found in 1 of 3 files; every file was read.
File                   Dialogs  First Call-ID
------------------------------------------------------
sip-problem-call.pcap  1        busy-3a2b1c@192.0.2.30
```

- Any filter works: a Call-ID, a user, a diagnostic alias such as
  `--problems`, a time window.
- Each row is a file that held a match, how many of its calls matched, and the
  first matching Call-ID.
- A directory stands for the capture and vCon files directly in it.
- sipnab reads the files and exits. Give no `-I`.

Read the first line before trusting an empty answer. When sipnab could not read
every file, it says so, names each file it could not read, and exits 1. A call
it did not find may be in a file it did not read:

```sh
sipnab --find-in-files tests/pcap-samples --filter "call_id == 'busy-3a2b1c@192.0.2.30'"
```

```text
Found in 1 of 36 files; not complete: 34 of 36 read, so a file not read may hold a match.
File                   Dialogs  First Call-ID
------------------------------------------------------
sip-problem-call.pcap  1        busy-3a2b1c@192.0.2.30
Not read: c07-sip-r2.cap: Failed to open pcap file 'tests/pcap-samples/c07-sip-r2.cap': libpcap error: unknown file format
Not read: rtsp-packets.cap: Failed to open pcap file 'tests/pcap-samples/rtsp-packets.cap': libpcap error: unknown file format
```

Then open the file that holds the call, with `-I`, and work on it.

### Search from an agent, without losing the capture it holds

The MCP tool `find_in_captures` runs the same search over the files in the
server's `--mcp-file-root`. It reads each file into a separate store, so the
capture the agent is working on stays loaded.

Start the server with a file root. The root here holds 36 files, more than
the 20 one search opens by default, so the example raises that bound:

```sh
sipnab --mcp -N -I tests/pcap-samples/sip-rtp-g711.pcap --mcp-file-root tests/pcap-samples --mcp-sweep-max-files 40
```

The search runs as a background job:

1. `find_in_captures` starts it and waits up to `wait_seconds` (30 by
   default). When the search ends in that time, the answer holds the result
   under `sweep`. When it does not, the answer holds a `job_id` and
   `status: "running"`.
2. `find_in_captures_status` with that `job_id` reports progress, and the
   result once `status` is `done`.
3. `cancel_find_in_captures` stops it. `status` becomes `canceled`, and the
   result covers the files read so far.

A search that finished while the call waited, with the answer's lines
wrapped:

```jsonc
// find_in_captures { "filter": "call_id == 'busy-3a2b1c@192.0.2.30'" }
{"job_id":"sweep-1","limits":{"deadline_ms":30000,"max_files":40},
 "progress":{"cancel_requested":false,"elapsed_ms":301,"files_examined":34,"files_total":36},
 "schema_version":2,"source_exhausted":true,"source_stopped_early":false,"status":"done",
 "sweep":{"complete":false,"files_examined":34,"files_total":36,
  "matches":[{"dialogs_matched":1,"filename":"sip-problem-call.pcap","first_call_id":"busy-3a2b1c@192.0.2.30"}],
  "unreadable":[{"filename":"c07-sip-r2.cap","reason":"Failed to open pcap file 'tests/pcap-samples/c07-sip-r2.cap': libpcap error: unknown file format"},
                {"filename":"rtsp-packets.cap","reason":"Failed to open pcap file 'tests/pcap-samples/rtsp-packets.cap': libpcap error: unknown file format"}]}}
```

A search started without waiting, then stopped, wrapped the same way:

```jsonc
// find_in_captures { "filter": "state == 'Failed'", "wait_seconds": 0 }
{"job_id":"sweep-2","limits":{"deadline_ms":30000,"max_files":40},
 "progress":{"cancel_requested":false,"elapsed_ms":1,"files_examined":0,"files_total":36},
 "schema_version":2,"source_exhausted":true,"source_stopped_early":false,"status":"running"}
// cancel_find_in_captures { "job_id": "sweep-2" }
{"job_id":"sweep-2","limits":{"deadline_ms":30000,"max_files":40},
 "progress":{"cancel_requested":true,"elapsed_ms":4,"files_examined":0,"files_total":36},
 "schema_version":2,"source_exhausted":true,"source_stopped_early":false,"status":"canceled",
 "sweep":{"complete":false,"files_examined":0,"files_total":36,"matches":[],
  "stopped_because":"canceled","unreadable":[]}}
```

Read `complete` and `stopped_because` before you trust "not found". With the
default bound of 20 files, the first search above stopped with
`"stopped_because":"max-files"` and no match, because it had not yet opened
`sip-problem-call.pcap`.

The operator bounds the jobs: how many files one search opens
(`--mcp-sweep-max-files`, 20), how long it runs (`--mcp-sweep-deadline-ms`,
30000), how many run at once (`--mcp-sweep-max-running`, 4), and how long a
finished result waits for its poll (`--mcp-sweep-result-retention-secs`, 600).
[`find_in_captures`](mcp-tools-captures.md#find_in_captures) gives every bound
and the refusals.

## Ask the same question elsewhere

The command-line flags, the REST routes, the MCP tools and the terminal
interface give the same answers. REST and MCP answer about the capture the
server holds, and the terminal interface about the one it shows.

| Question | Command line | REST | MCP tool | Terminal interface |
|---|---|---|---|---|
| Calls by one value | `--count-by` | `GET /v1/aggregate` | `aggregate_dialogs` | — |
| Carrier metrics | `--rates-by` | `GET /v1/dialogs/rates` | `group_dialogs` | `m`, by destination address |
| Busiest participants | `--talkers` | `GET /v1/talkers` | `top_talkers` | `g`, by source address |
| Calls over time | `--timeline` | `GET /v1/timeline` | `timeline` | `b`, 60-second intervals |
| One address or user | `--endpoint-ip`, `--endpoint-user` | `GET /v1/endpoints` | `describe_endpoint` | `e`, the selected call's source |
| Two calls | `--compare-dialogs` | `GET /v1/dialogs/compare` | `compare_dialogs` | `c`, with two calls starred |
| Two captures | `--compare-captures` | `GET /v1/captures/compare` | `compare_captures` | — |
| Which file holds a call | `--find-in-files` | — | `find_in_captures` | — |

The terminal-interface keys work from the call list. See
[Keybindings](keybindings.md#call-list).

Over REST, the routes take the same names as query parameters. A server that
holds the capture, and the question asked of it:

```bash
# Run all of these, in order.
export SIPNAB_API_KEY="$(openssl rand -hex 32)"
sipnab -N -I tests/pcap-samples/sip-problem-call.pcap --api 127.0.0.1:8080 --no-cli-print --quiet &
sleep 2
curl -s -H "Authorization: Bearer $SIPNAB_API_KEY" "http://127.0.0.1:8080/v1/aggregate?by=response_code" | jq -c '.buckets'
kill %1
```

```json
[{"value":"200","count":1},{"value":"404","count":1},{"value":"486","count":1},{"value":"503","count":1},{"value":"603","count":1}]
```

[Set up authentication](auth.md) covers keys for a server that stays up.
`GET /v1/captures/compare` reads its two files from the server's
`--api-file-root`. [REST API](rest-api.md) lists every route's parameters.

## Check that it worked

A query counted every call when its total equals the number of dialogs in the
capture. Ask the query for its total:

```sh
sipnab -I tests/pcap-samples/sip-problem-call.pcap --count-by response_code --json --no-cli-print --quiet | jq .total_matched
```

```text
5
```

Then count the dialogs:

```sh
sipnab -N -I tests/pcap-samples/sip-problem-call.pcap --json-dialogs --no-cli-print --quiet | jq -s length
```

```text
5
```

With a filter or a time window on the query, `total_matched` is the number of
calls the filter admits, which can be lower. A query that read the capture
exits with status 0, with or without rows in its answer.

## When it does not work

| What you see | Why | What to do |
|---|---|---|
| Exit 2 and `invalid value 'code' for '--count-by <DIMENSION>'` | The dimension is not one the flag takes | Use a name from the list the message gives, such as `response_code` |
| Exit 1 and `Call-ID 'nope@x' not found in tracked dialogs` | `--compare-dialogs` matches each Call-ID exactly | Copy the Call-ID from `--report` or `--json-dialogs` |
| Every count is 0, or the answer has no rows | The filter or the time window admits no call, or the capture's SIP is outside `--portrange` | Run without the filter. If sipnab reports no SIP at all, see [Read a capture whose SIP is not on port 5060](examples.md#read-a-capture-whose-sip-is-not-on-port-5060) |
| `--find-in-files` exits 2 with `needs something to find` | It has no filter to search with | Give `--filter`, an alias such as `--problems`, or `--since`/`--until` |
| `--find-in-files` exits 1 with `not complete` | sipnab could not read one of the files | The `Not read:` lines name each file and the reason |
| `--timeline` exits 1 and names a width | The calls span more than 100,000 intervals of that width | Run it again with the width it suggests |
| `--compare-captures` exits 2 with `are the same file` | The two paths name one file | Give two different captures |
| `mos_p10` is `-` | The capture holds no RTP for those calls | Capture the media too. See [Tune capture on a busy server](tuning-capture.md) |

[Error messages](errors.md) explains every message these flags print.
