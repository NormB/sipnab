# CLI reference

> **Quick start:** `sipnab -I capture.pcap` to analyze a file, or `sudo sipnab` for live capture on the default interface. Add `-N` for non-interactive output.

Complete flag reference for sipnab. This page groups flags by function.

CLI flags always override config file values (see [config-reference.md](config-reference.md)). Boolean flags default to `off` (false) unless otherwise noted. For task-oriented recipes rather than a flag catalog, start with [examples.md](examples.md).

## Common Recipes

A few flag combinations to get productive fast. For the full task-oriented
collection — triage, filtering, recording, security, HEP — see the
[Cookbook](examples.md). For symptom-driven diagnostics see
[Troubleshooting](troubleshooting.md). This page is otherwise a flag
reference (grouped below).

### Debug a failed call

Start by listing every failed call in the pcap, which is where the Call-IDs
worth chasing come from.

```bash
sipnab -N -I capture.pcap --filter "state == 'Failed'"
```

With one of those Call-IDs in hand, print just that dialog's call flow.
`--no-cli-print` is what makes it *just* that: on its own, `--call-report`
appends the report to the whole capture's per-message dump, so the report you
came for arrives after every message in the file.

```bash
sipnab -N -I capture.pcap --call-report "abc123@host" --no-cli-print
```

When the finding belongs in a ticket, write the same report as Markdown to a
file instead of reading it on the terminal. Keep `--no-cli-print` here too, or
`report.md` opens with hundreds of lines of raw SIP before its first heading.

```bash
sipnab -N -I capture.pcap --call-report "abc123@host" --markdown --no-cli-print > report.md
```

### Monitor live SIP quality

Watch live traffic for calls that are already degraded — MOS below 3.0, or
audio flowing in only one direction.

```bash
sudo sipnab -N -d eth0 --filter "rtp.mos < 3.0 OR one_way == true"
```

Feed the same set of problem calls into a monitoring pipeline as NDJSON while
keeping a copy on disk.

```bash
sudo sipnab -N -d eth0 --problems --json | tee /var/log/sipnab/problems.ndjson
```

Hand each quality drop to an external alerting script rather than reading it
yourself. `--exec-rate-limit` bounds the invocations per second, so one bad
trunk cannot fork a process per stream.

```bash
sudo sipnab -d eth0 --on-quality-exec "/usr/local/bin/pagerduty-alert.sh" \
  --quality-threshold 3.0 --exec-rate-limit 5
```

### Measure post-dial delay across calls

Find the calls whose setup took longer than three seconds, as NDJSON for
whatever consumes it next.

```bash
sipnab -N -I capture.pcap --filter "pdd > 3.0" --json
```

The `--slow-setup` alias expands to that same threshold, so a quick check needs
no filter expression at all.

```bash
sipnab -N -I capture.pcap --slow-setup --report
```

### Security monitoring

Detect SIP scanning and append it in fail2ban's format to the log its jail
reads. `--kill-scanner` is what detects — `--fail2ban` only chooses the format,
so leaving it out leaves the log empty.

```bash
sudo sipnab -N -d eth0 --kill-scanner --fail2ban >> /var/log/sipnab/scanners.log
```

Before that log reaches a jail, run the same detectors over a capture of an
ordinary hour and read the list of addresses they would ban. On a carrier trunk
it routinely names your own SBCs, because the enumeration signature and a busy
hunt group look alike.

```bash
sipnab -N -I capture.pcap --kill-scanner --fail2ban \
  | grep -oE 'src=[^ ]+' | sort | uniq -c | sort -rn
```

Audit a capture for digest credentials that went out where anyone could read them.

```bash
sipnab -N -I capture.pcap --digest-leak
```

Run the whole sweep at once — scanners, fraud heuristics, and registration
floods — with alerts going to both syslog and structured JSON.

```bash
sudo sipnab -N -d eth0 --kill-scanner --fraud-detect --reg-flood \
  --alert syslog --alert json --syslog
```

### Export for Wireshark analysis

Hand the capture to Wireshark with a display filter already applied.

```bash
sipnab -I capture.pcap --wireshark
```

Or print a tshark-compatible filter string, when the next step is a shell
pipeline rather than the Wireshark GUI.

```bash
sipnab -I capture.pcap --tshark-filter "from.user == '1001'"
```

### Export call audio as WAV

Audio export is a TUI workflow — see [Keybindings](keybindings.md).

### Pipe through jq for custom analysis

Count failures by response code, so the dominant one is obvious.

```bash
sipnab -N -I capture.pcap --filter "state == 'Failed'" --json \
  | jq -r '.status_code' | sort | uniq -c | sort -rn
```

List every distinct User-Agent the capture saw, to find the odd endpoint out.

```bash
sipnab -N -I capture.pcap --json \
  | jq -r '.user_agent // empty' | sort -u
```

### Bound, split, and multi-interface captures

Stop after a fixed packet count and summarize the capture.

```bash
sipnab -N -d eth0 -n 1000 --report
```

Roll to a new pcapng every 50 MiB, so a long capture does not become one file
too large to open.

```bash
sipnab -d eth0 -O /var/captures/sip.pcapng --pcapng --split filesize:50
```

Capture across every interface at once, timestamping each message relative to
the one before it. On Linux the `any` pseudo-device is what makes this every
interface — `--multi-device` is for naming a specific list, as below.

```bash
sipnab -d any --delta-time
```

Capture on two named interfaces instead, one libpcap handle each.

```bash
sipnab -d eth0,eth1 --multi-device --delta-time
```

> **Tip:** Every output flag (`--json`, `--report`, `--fail2ban`, etc.) needs `-N`. Think of it as "non-interactive mode" -- it disables the TUI and writes to stdout instead.

---

## Capture

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `-d`, `--device` | `<IFACE>` | platform default | Network interface to capture on. With no `-d`, no `-I` file and no `-L` HEP listener, sipnab picks a default that differs by platform — see the note below |
| `-I`, `--input` | `<FILE\|DIR\|GLOB>` | -- | Read packets from a capture file, a directory of them, or a glob, instead of live capture. **Repeatable.** sipnab reads the files in capture order, never in filename order — see the note below |
| `--recursive` | -- | off | Descend into subdirectories when `-I` names a directory |
| `--input-name` | `<GLOB>` | -- | Read only files whose *name* matches this pattern when `-I` names a directory. Applies at every depth under `--recursive` |
| `-O`, `--output` | `<FILE>` | -- | Write captured packets to a pcap file |
| `-B`, `--buffer` | `<MIB>` | `64` | Kernel capture buffer size in MiB (per device). See [Tuning capture](tuning-capture.md) |
| `--buffer-budget` | `<MIB>` | `64` | Memory budget for the in-flight capture→processing queue. The queue grows under load up to this budget (capped, never OOM) and shrinks when idle; overrides `[capture] buffer_budget_mb` |
| `--snaplen` | `<BYTES>` | `65535` | Snapshot length for packet capture (bytes) |
| `-S`, `--limitlen` | `<BYTES>` | -- | Parse only the first N bytes of each packet (sipgrep `-S`). Caps what the SIP parser and matchers inspect, independent of `--snaplen` (capture length) and `--payload-limit` (display truncation) |
| `--no-reassembly` | -- | off | Disable IP-fragment and TCP-segment reassembly; sipnab parses every packet standalone (inverse of sipgrep `-a`). Useful for pure single-packet UDP scanning |
| `-x`, `--quiet-bad-parse` | -- | off | Suppress the per-packet "SIP parse error" diagnostic emitted when a SIP-looking packet fails to parse (sipgrep `-x`). sipnab drops the packet either way; this only silences the notice on a noisy link |
| `--portrange` | `<RANGE>` | `5060-5061` | SIP **signalling** port range. Media is never gated — RTP uses SDP-negotiated dynamic ports. The default is narrow and carriers routinely run SIP on 5070, 5080 and elsewhere, so widen it or analyse a fraction of the file — see the note below |
| `--multi-device` | -- | off | Open one capture per interface named in a comma-separated `-d` list, e.g. `-d eth0,docker0 --multi-device`. It does **not** enumerate interfaces for you: with a single `-d` (or none) it falls back to an ordinary single capture. On Linux the zero-argument default already sniffs every interface via the `any` pseudo-device |
| `--no-rtp` | -- | off | Disable RTP capture and analysis |
| `-p`, `--no-promisc` | -- | off | Do not put the interface into promiscuous mode (sipgrep `-p`). Promisc is on by default for a named device; the `any` pseudo-device is never promiscuous |
| `--bpf-file` | `<FILE>` | -- | Read BPF filter from a file |
| `--capture-tunnels` | `[<PORTS>]` | off | Also capture **all** traffic on the UDP tunnel ports, so SIP inside GTP-U, VXLAN or GENEVE reaches sipnab. Bare flag means `2152,4789,6081`; pass a list for non-standard ports (`--capture-tunnels=8472`). Off by default because it is not a narrowing filter — BPF cannot walk a GTP-U extension-header chain to the inner port, so covering these means taking the whole port, which on a mobile core is the entire user plane. Ignored when you supply your own filter |
| `-n`, `--count` | `<N>` | -- | Stop after receiving N packets (counts every packet received, including any a HEP listener later drops by allowlist, rate limit, or auth) |
| `--duration` | `<DURATION>` | -- | Stop after duration (e.g., `30s`, `5m`, `1h`) |
| `--autostop` | `<CONDITION>` | -- | Autostop condition (e.g., `filesize:100`, `duration:60`) |
| `--split` | `<CONDITION>` | -- | Split output files (e.g., `filesize:50` for 50 MiB chunks) |
| `--replay` | -- | off | Replay packets from a pcap file at original timing |
| `--pcapng` | -- | off | Use pcapng format for output files. [pcapng Metadata](#pcapng-metadata) covers the metadata sipnab writes into pcapng output |
| `<BPF_FILTER>...` | positional | -- | BPF display filter expression (trailing positional args) |

> **The auto-generated filter looks through VLAN, QinQ, PPPoE and MPLS.**
> On a live capture with no filter of your own, sipnab installs one built from
> `--portrange`. It is not a bare `portrange 5060-5061`: that one matches the
> outer headers only, so on a tagged trunk, a PPPoE access link or an MPLS
> core it matches **nothing**, and the kernel discards the frames where no
> sipnab counter, metric or report can see them. You get "No SIP traffic
> found" on a link carrying calls.
>
> The generated filter adds an encapsulated arm instead, covering one VLAN tag
> (802.1Q, 802.1ad or 0x9100), QinQ, PPPoE Session, VLAN over PPPoE, and one or
> two MPLS labels, for IPv4 and IPv6, UDP and TCP. The arm still demands a
> signalling port, so it matches more of the *same* traffic, not a new class of
> it: VLAN-tagged RTP reaches sipnab no more often than untagged RTP did.
>
> **It covers cooked captures too**, so omitting `-d` costs you nothing. The
> arm asks "does this frame carry an encapsulation?" through libpcap's
> `ether proto`, which resolves to the right byte offset for whatever link type
> the filter compiles against — offset 12 on Ethernet, 14 on Linux cooked v1,
> 0 on Linux cooked v2, and a constant false on raw IP and the two loopback
> link types, which carry no protocol field at all. Measured on a capture of
> each type with `tcpdump -d`.
>
> Asking the same question with a fixed `ether[12:2]` is the trap this avoids.
> That offset holds the EtherType on Ethernet and part of the link-layer
> address on a cooked capture, so an arm written that way compiles, runs and
> matches nothing there: 1 of 11 encapsulated SIP frames on cooked v1 and
> cooked v2, against 11 of 11 on Ethernet. Cooked is what Linux gives you when
> you name no interface, so that shape would have left the default invocation
> blind.
>
> Two limits worth knowing. On the encapsulated arm an IPv4 header carrying
> **options** stays unmatched. A BPF byte offset has to be a constant, so the
> arm cannot multiply the IHL nibble into the port offset the way libpcap's own
> `portrange` does. The untagged `portrange` handles those, so this costs you
> only IPv4-options traffic that is *also* encapsulated.
>
> And one filter string serving three link types has to carry all three sets of
> inner offsets, because BPF offers no way to ask which link type it compiled
> against. Seven offsets get probed on every link type, four of which belong to
> a different link header. Those four can fire only on a frame that already
> carries one of the six encapsulating protocols, and only if its bytes at the
> wrong offset spell a complete IPv4-or-IPv6 header with a signalling port —
> so the worst case is a stray tagged packet reaching userspace, where the
> parser rejects it. Ordinary traffic never reaches those probes, because the
> outer `ether proto` test is exact.
>
> **UDP tunnels are opt-in.** GTP-U, VXLAN and GENEVE are not covered by
> default and sipnab says so at startup. BPF cannot parse a variable-length
> GTP-U extension-header chain to reach the inner port, so the only way to
> cover them is to capture everything on the port — see `--capture-tunnels`.
>
> **A filter you supply is never rewritten.** It goes to `pcap_compile`
> exactly as typed. If it looks encapsulation-blind, sipnab says so once and
> still uses your expression.

> **What you get when you omit `-d`.** The default is not the same everywhere,
> and the difference decides whether you see loopback traffic:
>
> | Platform | Default | Scope |
> |---|---|---|
> | Linux | the `any` pseudo-device | **every interface at once**, loopback included |
> | macOS / BSD | libpcap's default device, from the routing table; otherwise the first non-loopback interface | **one interface** |
>
> On Linux this is deliberate and matches sngrep: a SIP proxy often talks to
> itself over loopback, so capturing only `eth0` silently misses it. Pass
> `-d any` to say so explicitly. Promiscuous mode does not apply to `any`, so
> `--no-promisc` changes nothing there.
>
> On macOS you get a *single* interface. If SIP is not on the one libpcap
> picked, you see nothing and the capture looks merely quiet — name `-d`
> explicitly.

> **Reading a set of files: order comes from the packets, not the names.**
> `tcpdump -C 100 -W 10` writes a ring buffer — `tg.pcap0` through `tg.pcap9` —
> and then **wraps**, overwriting the oldest file in place. A real set measured
> for this feature ran `tg.pcap7`, `tg.pcap8`, `tg.pcap9`, `tg.pcap0` …
> `tg.pcap6` in time order: the numeric suffix records where tcpdump was in its
> cycle, not when the packets arrived.
>
> So sipnab sorts by each file's **first packet timestamp**. Neither
> lexicographic nor natural-numeric filename order reconstructs that capture,
> and replaying it out of order corrupts every timing derivation — post-dial
> delay, setup time, retransmission detection, and the RFC 3261 Timer B/C/H
> bounds all assume timestamps only move forward.
>
> sipnab recognises a capture by **opening it**, not by its extension —
> `tg.pcap0` has the extension `pcap0`, and plenty of captures have none at
> all. It decompresses gzip members transparently, so a directory holding both
> `.pcap` and `.pcap.gz` needs nothing special.
>
> A file you name directly with `-I` that sipnab cannot read is an error. One
> it *discovers* by expanding a directory or glob it skips with a warning,
> because directories hold other things.
>
> **Why it matters beyond tidiness:** reading a split capture as a set is the
> only way to see a call whose INVITE lands in one file and whose BYE lands in
> the next. Analysed one file at a time, that call appears as one that never
> ends plus a stray BYE, and neither half is the truth. On the 10-file, 921 MB
> set above, 2271 of 20512 calls — **11%** — spanned a boundary.

> **`-I` and `-d` are alternatives, not companions.** sipnab accepts both, and the FILE wins: sipnab reads it, never opens the interface, and the output looks like a normal run. sipnab warns on stderr when you do this. To switch a file command to live capture, **remove `-I`** rather than adding `-d` beside it.

> **`--portrange` decides how much of the file you analyse.** The default,
> `5060-5061`, is narrow. SIP on other ports is ordinary: carriers and SBCs use
> 5070, 5080 and others routinely, and a capture from a real trunk commonly
> carries a large share of its signalling outside the default.
>
> Reading a file, sipnab skips any SIP message whose source **and** destination
> ports both fall outside the range. A skipped message reaches no message count,
> no dialog, and no output format — so every total you read, and every ratio you
> compute from one, describes the range and not the capture. sipnab counts what
> it skipped and says so on stderr and at the end of the run, naming the busiest
> ports so there is something to widen to:
>
> ```text
> NOT ANALYSED: 1 further SIP message(s) were seen on ports outside --portrange
> and are in none of the totals above. Busiest: 8090 (1). Re-run with
> --portrange 1-65535 to include them.
> ```
>
> `--portrange 1-65535` analyses everything the capture holds. Reach for it
> first on an unfamiliar capture, then narrow once you know what is in there.
>
> **Live capture is different, and worse.** With no explicit BPF filter sipnab
> compiles the range into the filter, so the kernel drops the traffic before
> sipnab sees it — nothing downstream, this counter included, can report what
> went missing. Set the range correctly *before* the capture, because no rerun
> recovers it.

> **`NOT DECODED` is the other line to read before the totals.** `--portrange`
> is about SIP sipnab chose not to analyse; this is about frames it could not
> read at all — an unsupported link type, an EtherType carrying no IP, an IP
> protocol that is no transport, a truncated frame, a decode error. Such a
> frame counts as a packet (it arrived) and reaches no message, dialog or
> stream, so on its own the summary reports the same thing whether the capture
> held no SIP or sipnab understood none of it:
>
> ```text
> NOT DECODED: 49 of 49 frame(s) (100.0%) produced nothing and are in none of
> the counts above. Reasons: unsupported link type 0 (49). NOTHING IN THIS
> CAPTURE WAS READ — every frame failed to decode, so the totals above describe
> no traffic whatsoever and a zero among them is not evidence of absence.
> ```
>
> Every reason carries the number that identifies it, because that number is
> what you act on: `unsupported link type 0` says the file is `DLT_NULL` and
> `editcap -T ether in.pcap out.pcap` converts it. A small count is normal —
> ARP is undecodable by definition and appears on any Ethernet capture — so
> read the share, not the count. When the share is high, sipnab additionally
> refuses to state "No SIP traffic found" as a finding, because it has no basis
> for one. The same breakdown appears as a `NOT DECODED (capture-wide)` section
> in `--report`, and as `sipnab_capture_undecodable_frames_total{reason}` plus
> `sipnab_capture_undecoded_fraction` on `/metrics`.
>
> `docs/troubleshooting.md` tables what each reason means and what to do about
> it.

**Examples**

- `sudo sipnab --device eth0 --output capture.pcap --portrange 5060-5080 --count 10000` — record up to 10000 packets from eth0 into a pcap, watching a widened SIP port range
- `sudo sipnab --device eth0 --buffer 16 --buffer-budget 128 --snaplen 2048 --quiet-bad-parse` — live-capture a busy link with bigger kernel and queue buffers, a capped snapshot length, and parse-error notices silenced (sipgrep -x)
- `sudo sipnab -N -d eth0,eth1 --multi-device --output capture.pcap --autostop filesize:100` — capture on two named interfaces at once, headlessly, stopping once the output file reaches 100 MiB. `--multi-device` needs the list; without one it is a no-op
- `sipnab -N --input capture.pcap --replay --no-rtp` — replay a pcap at its original timing with RTP capture and analysis disabled
- `sipnab -N --input /var/captures/ --json-dialogs --no-cli-print` — read every capture in a directory as one timeline, so a call split across the ring buffer resolves to one dialog instead of two fragments
- `sipnab -N --input /var/captures/ --recursive --input-name '*.pcap.gz' --json-dialogs --no-cli-print` — descend into per-day subdirectories and read only the compressed archives
- `sipnab -N --input 'captures/tg.pcap[0-4]' --report` — analyse the first five members of a ring buffer with a glob sipnab expands itself, no shell needed
- `sipnab -N --input a.pcap --input b.pcap --json-dialogs --no-cli-print` — read two named captures as a single set, ordered by their packets
- `sipnab -N --input /var/captures/ --input-name 'edge1-*' --recursive --json` — pick one host's captures out of a tree holding several
- `sipnab -N --input capture.pcap --limitlen 512 --no-reassembly --quiet-bad-parse` — scan a pcap sipgrep-style: parse only the first 512 bytes of each packet, every packet standalone (no reassembly), without parse-error noise
- `sudo sipnab --device eth0 --bpf-file sip.bpf --no-promisc --duration 5m` — capture for 5 minutes using a BPF filter read from sip.bpf, without putting the interface into promiscuous mode (sipgrep -p)
- `sudo sipnab -N --device eth0 --capture-tunnels --buffer 64 --duration 5m` — capture SIP travelling inside GTP-U, VXLAN or GENEVE as well as the encapsulations the auto-filter already covers. This takes **every** packet on ports 2152, 4789 and 6081, so the same command widens the kernel buffer; check the drop counters in the summary before trusting a long run
- `sudo sipnab -N --device eth0 --capture-tunnels=8472 --portrange 5060-5080 --report` — cover a Linux VXLAN fabric on its pre-IANA port 8472 instead of the three defaults, across a widened signalling range
- `sudo sipnab --device eth0 --portrange 5060-5090 --buffer 8 --buffer-budget 256 --duration 1h` — monitor an hour of traffic across a wide SIP port range with enlarged capture buffers
- `sipnab -N --input capture.pcap --replay --limitlen 1500 --no-rtp` — replay signaling only from a pcap, parsing at most 1500 bytes of each packet
- `sudo sipnab --device eth0 --bpf-file sip.bpf --no-promisc --snaplen 9000 --count 500` — stop after 500 packets that pass the sip.bpf filter, non-promiscuous, with the snapshot length sized for jumbo frames
- `sudo sipnab -N --device eth0 --output capture.pcap --autostop duration:60 --no-reassembly` — write a one-minute capture that treats every packet standalone (IP-fragment and TCP-segment reassembly off)


## Mode

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `-N`, `--no-tui` | -- | off | Non-interactive mode (no TUI). Required for batch/output flags |
| `-c`, `--calls-only` | -- | off | Show only SIP dialogs (calls), not standalone messages |
| `-t`, `--telephone-event` | -- | off | Decode telephone-event (DTMF) RTP payloads and log each event at `info`, digit value masked as `x` |
| `--dtmf-cleartext` | -- | off | Log the DTMF digit VALUES instead of the mask, at `debug`. Publishes PINs and card numbers |
| `-q`, `--quiet` | -- | off | Suppress informational output; only show results |

**Examples**

- `sipnab --no-tui -I capture.pcap --calls-only` — analyze a pcap headlessly, showing only complete SIP dialogs (calls), not standalone messages
- `sudo sipnab --no-tui -d eth0 --telephone-event` — headless live capture that decodes DTMF and logs each event with its duration and SSRC, digit value masked
- `sipnab --no-tui -I capture.pcap --calls-only --telephone-event` — read a capture headlessly, report only complete dialogs, and log how many DTMF events each one carried
- `sipnab --no-tui -I lab.pcap --telephone-event --dtmf-cleartext` — read a capture you own and disclose the digit values; also set `SIPNAB_LOG=debug`, or the run prints nothing but the mask
- `sudo sipnab --no-tui -d eth0 --telephone-event --dtmf-cleartext 2>dtmf.log` — capture live and steer the cleartext digits into a file whose permissions you control instead of a shared terminal or journald; again needs `SIPNAB_LOG=debug`

**Read this before using `--dtmf-cleartext`.** DTMF digits keyed after answer are
PINs, calling-card numbers, account numbers and credit-card numbers with their
CVVs, and RFC 4733 carries them in the clear no matter how well the signalling
layer protected the call. So `-t` alone logs everything you diagnose with — that an event
arrived, its duration, its SSRC, its timestamp — with the digit value replaced by
`x`:

`DTMF digit='x' duration=200ms ssrc=0xdeadbeef`

`--dtmf-cleartext` adds a second line carrying the value. It is not a display
setting. It puts a caller's PIN wherever this run's log goes — your terminal, a
redirected file, journald, and every aggregator downstream of journald. Turning
it on takes two deliberate acts, because sipnab writes the cleartext line at
`debug` while the masked line stays at `info`: pass the flag **and** raise the
level.
Either one alone shows you nothing but the mask. Both, in one copyable line:

```bash
SIPNAB_LOG=debug sipnab --no-tui -I lab.pcap --telephone-event --dtmf-cleartext 2>dtmf.log
```

**Where the events go.** sipnab writes one masked line per decoded event and
keeps a count. Nothing else carries the digits: no report, no JSON field, no MCP
tool. Two consequences follow, and both bite the obvious command lines. Adding
`-t` to a TUI session shows you nothing, because TUI mode floors the log level at
`error` to keep the alternate screen intact. Adding `--quiet` also hides them,
because it floors the level at `warn`. Use `-N` without `--quiet`.
`SIPNAB_LOG=info` does override the TUI floor, but sipnab sets that floor to
stop log lines corrupting the alternate screen, so redirect stderr if you do.


## Matching

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `-e`, `--match` | `<PATTERN>` | -- | SIP payload match-expression (the sngrep/sipgrep positional match expression). Regex tested against the whole raw message; once any message in a dialog matches, sipnab shows the rest of that dialog too (dialog-following). Honors `-i`/`-v`/`-w`/`--single-line`. Independent of the trailing `<BPF_FILTER>` positional |
| `-i`, `--ignore-case` | -- | off | Case-insensitive matching for header filters and patterns |
| `-v`, `--invert` | -- | off | Invert the match: show messages that do NOT match |
| `-w`, `--word` | -- | off | Match whole words only |
| `--single-line` | -- | off | Treat multi-line SIP headers as a single line for matching |
| `--from` | `<PATTERN>` | -- | Filter by SIP From header (regex pattern) |
| `--to` | `<PATTERN>` | -- | Filter by SIP To header (regex pattern) |
| `--contact` | `<PATTERN>` | -- | Filter by SIP Contact header (regex pattern) |
| `--ua` | `<PATTERN>` | -- | Filter by User-Agent header (regex pattern) |
| `--filter` | `<EXPR>` | -- | Filter DSL expression OR a diagnostic alias name (`codec-asym`, `late-media`, etc.) — see [filter-dsl.md](filter-dsl.md) |

**Examples**

- `sipnab -N -I capture.pcap --match "alice@example.com" --ignore-case` — show every dialog that mentions alice@example.com, case-insensitively (dialog-following payload match)
- `sipnab -N -I capture.pcap --match "486 Busy Here" --word --single-line` — whole-word match for 486 rejections, folding multi-line headers into one line before matching
- `sudo sipnab -d eth0 --match "REGISTER" --invert` — live view of everything except REGISTER traffic (inverted match)
- `sudo sipnab -d eth0 --ua "friendly-scanner" --contact "203\.0\.113\." --ignore-case` — flag scanner traffic live: a known scanner User-Agent (any case) with a Contact pointing into 203.0.113.0/24
- `sipnab -N -I capture.pcap --ua "sipcli" --contact "192\.0\.2\." --single-line` — filter a pcap by User-Agent and a Contact in 192.0.2.0/24, matching even when headers span folded lines
- `sipnab -N -I capture.pcap --match "OPTIONS" --word --invert` — suppress keep-alive noise: show messages that do not contain the whole word OPTIONS


## Name resolution

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `--resolve` | -- | off | Turn name resolution on (manual mappings + `/etc/hosts`). In the TUI, press `n` to cycle Off / Static / DNS; in headless `-O --pcapng` export it embeds a Name Resolution Block |
| `--reverse-dns` | -- | off | Also use reverse DNS (PTR) lookups. Implies `--resolve`. Emits DNS queries for captured IPs |
| `--names` | `<FILE>` | -- | Preload IP → name mappings from an `/etc/hosts`-format file. Repeatable |

See the [Name Resolution](keybindings.md#name-resolution) keys for in-TUI naming (`N`) and persistence.

**Examples**

- `sudo sipnab -d eth0 --resolve --names /etc/sipnab/hosts.map` — live capture with name resolution from a static hosts-format mapping file
- `sipnab -N -I capture.pcap --resolve --names /etc/sipnab/hosts.map --names ~/.config/sipnab/lab-names` — annotate an offline pcap with names, preloading two mapping files on top of /etc/hosts
- `sudo sipnab -d eth0 --reverse-dns` — live capture that also resolves captured IPs via reverse DNS (PTR) lookups
- `sipnab -N -I capture.pcap --reverse-dns --names ~/.config/sipnab/lab-names` — replay an offline pcap and resolve its addresses with reverse DNS, supplemented by a local mapping file


## pcapng metadata

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `--strip-secrets` | `<OUTPUT>` | -- | With `-I <input>`, write a copy of the input pcapng to `<OUTPUT>` with all Decryption Secrets Blocks removed (the `editcap --discard-all-secrets` analog), then exit. sipnab never touches the input and writes the output atomically. |
| `--show-frame` | `<POINTER>` | -- | Resolve a frame pointer from a previous run, print that frame, then exit. Takes `<source>#<ordinal>` or `<source>#<ordinal>@<digest>` — the form the `frame` field of `--json-dialogs`, `--report`, the REST API and MCP carries. With a digest, sipnab checks the bytes against it and refuses a capture that changed after sipnab minted the pointer, writing nothing to stdout. Without one, sipnab prints the frame and marks it `UNVERIFIED`. |

Note: with resolution active, sipnab saves name mappings into a pcapng Name
Resolution Block — on both the TUI save path and the headless `-O --pcapng`
export (whenever `--resolve`/`--names` apply). Headless pcapng exports also
describe themselves: the Section Header Block records the producing application
(`sipnab <version>`) and OS, and the Interface Description Block records the
capture source as the interface name. Opening a pcapng reads embedded NRB names
and DSB TLS secrets back, and decrypts with them. See
[the design doc](design/pcapng-metadata.md).

**Examples**

- `sipnab --show-frame 'capture.pcap#41@6f3a1c02b8d4e795'` — print the frame a dialog opened in, verifying the capture has not changed since
- `sipnab --show-frame 'capture.pcap#41'` — same frame, printed as `UNVERIFIED` because the short form carries nothing to check against
- `sipnab -N -I capture.pcapng --strip-secrets clean.pcapng` — write a sanitized copy of a pcapng with every Decryption Secrets Block removed
- `sipnab -N -I tls-call.pcapng --strip-secrets tls-call-clean.pcapng` — strip embedded TLS secrets from a decrypted-session capture before sharing it in a support ticket


## Diagnostic aliases

Shortcut flags that expand to predefined filter DSL expressions. See [filter-dsl.md](filter-dsl.md) for the exact expansion of each alias.

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `--problems` | -- | off | Show calls matching any diagnostic signal: failed state, one-way audio, RTP loss > 2%, jitter > 50 ms, NAT mismatch, more than 3 retransmits, PDD > 32 s, codec/ptime/payload/duration asymmetry, or late media — see [Named Aliases](filter-dsl.md#named-aliases) for the exact expansion. Orphaned RTP is **not** among them: an orphaned stream belongs to no dialog, so it cannot select one. Find it in the "Orphaned Streams" section of `--report`, or `/v1/streams?orphaned=true` |
| `--slow-setup` | -- | off | Show calls with post-dial delay > 3 seconds |
| `--short-calls` | -- | off | Show completed calls shorter than 5 seconds |
| `--one-way` | -- | off | Show calls with potential one-way audio issues |
| `--nat-issues` | -- | off | Show calls whose RTP arrived from an address no SDP advertised (NAT-rewritten media source) |

**Examples**

- `sipnab -N -I capture.pcap --short-calls --one-way` — flag completed calls under 5 seconds and calls with suspected one-way audio in a capture
- `sudo sipnab -d eth0 -N --one-way --nat-issues` — live-monitor for one-way audio and NAT-rewritten media sources
- `sipnab -N -I capture.pcap --short-calls --report` — summarize short completed calls from a capture in a post-run report


## Output

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `--json` | -- | off | Output as NDJSON (one JSON object per line, schema in [output-formats.md](output-formats.md)). Requires `-N` |
| `--json-pretty` | -- | off | Output each message as pretty-printed multi-line JSON (use `--json` for line-oriented NDJSON). Requires `-N` |
| `--json-dialogs` | -- | off | NDJSON, one object per **dialog**, emitted after capture (needs `-N`; pair with `--no-cli-print` to get only the objects). `--json` is per message: a dialog filter such as `state == 'Failed'` selects dialogs and then emits every message of them, provisional responses included. This is the per-call shape, carrying `final_status_code` and `final_status_reason` so a failed call says which code failed it — those two read INVITE transactions only and are `null` on a `REGISTER`/`OPTIONS`/`SUBSCRIBE` dialog, where `signaling_diagnosis.final_failure.code` carries it instead. |
| `--plugin` | `<PATH>` | -- | Load a WASM plugin that contributes its own dialog detections; repeatable. Findings appear under `plugin_findings`. Requires the `plugins` Cargo feature (**not** in the default set). A plugin runs with no imports — no filesystem, network or clock — but still sees each message's headers, so loading one is a trust decision. See [wasm-plugin-api.md](design/wasm-plugin-api.md) |
| `--report` | -- | off | Generate summary report after capture completes. Requires `-N` |
| `--call-report` | `<CALL-ID>` | -- | Generate a detailed report for a specific Call-ID. Implies non-interactive |
| `--markdown` | -- | off | Format report output as Markdown |
| `--hexdump` | -- | off | Include hex dump of SIP payloads. Requires `-N` |
| `--delta-time` | -- | off | Show delta time between consecutive messages |
| `-A`, `--after` | `<N>` | -- | Show N messages after each match (like `grep -A`) |
| `--show-empty` (`--full`) | -- | off | Show the full header block of bodyless messages (responses, OPTIONS, REGISTER, ACK, BYE); by default they show only the summary line |
| `--proto-number` | -- | off | Annotate the transport tag with the IANA IP protocol number, e.g. `UDP(17)` / `TCP(6)` (sipgrep `-N`). Long-only because `-N` is `--no-tui` here; TLS/WS report their TCP carrier's number (6) |
| `--line-buffer` | -- | off | Flush output after each line (useful for piping) |
| `--color` | `<WHEN>` | `auto` | Color output mode: `auto`, `always`, `never` |
| `--from-to-mode` | `<MODE>` | `default` | Default TUI From/To column display: `default` (user else host:port), `host-port`, `user`, `user-host-port`. Cycle at runtime with `u`. Overrides `[display] from_to` |
| `--payload-limit` | `<BYTES>` | -- | Maximum payload bytes to display |
| `-T`, `--text-dump` | -- | off | Dump raw SIP message text (like sipgrep `-T`) |
| `--no-cli-print` | -- | off | Suppress per-message CLI output (useful with `--report` / `--call-report` so only the post-capture summary reaches stdout) |
| `--wireshark` | -- | off | Launch Wireshark with a display filter for the current capture |
| `--tshark-filter` | `<EXPR>` | -- | Generate a tshark-compatible display filter string |
| `--fail2ban` | -- | off | Switch the per-message stream to fail2ban-readable log lines. Requires `-N`. It selects a **format**, not a detection: only two events ever reach it, and each needs its own detector armed beside it — `--kill-scanner` (or `--kill-ua`) produces `scanner_detected`, `--reg-flood` produces `reg_flood`. On its own it emits nothing, and warns on stderr about the coming silence, because an empty jail log reads as "nothing attacked me" |
| `--group-by` | `<FIELD>` | -- | Group output by field (e.g., `call-id`, `from`, `method`) |
| `--node-name` | `<NAME>` | hostname | Name this box reports as, in `capture_identity.node` on every MCP and REST answer. Lets an agent querying several servers at once tell WHICH one saw a given fact — "answered 407" is incomplete until you know where. Distinct from the capture instance, which rotates when a different capture loads; the node is the box and stays put, so a capture restart does not read as a topology change. **The default puts your hostname on the wire.** Clipped to 64 characters |

**Examples**

- `sipnab -N -I calls.pcap --lint --no-cli-print` — run the RFC conformance linter over every dialog in a capture and print each finding with the rule identifier and the RFC section it reads from. Informational: it leaves the exit code alone
- `sipnab -N -I calls.pcap --lint --lint-fail-on error --no-cli-print` — the CI gate. Exits 3 when any finding is at or above `error`, so a pipeline stops on a non-conformant capture. Exit 3 is not 1 or 2, so a failing gate is distinguishable from a failing tool and from a bad invocation
- `sipnab -N -I calls.pcap --lint --lint-fail-on warning --no-cli-print` — a stricter gate: stop on warnings as well as errors, for a pipeline that treats interop degradation as a build failure rather than a note
- `sipnab -N -I capture.pcap --json-dialogs --no-cli-print --plugin ./short-calls.wasm` — run a custom detection over every dialog and emit its findings beside sipnab's own
- `sudo sipnab -d eth0 -N --json-dialogs --no-cli-print --plugin ./site-rules.wasm --plugin ./fraud.wasm` — stack two site-specific detections over live traffic; each plugin is sandboxed and a failure in one never stops the capture
- `sipnab -N -I capture.pcap --json-dialogs --no-cli-print --quiet | jq -c 'select(.state == "Failed")'` — one line per failed call, each carrying the code that failed it, instead of every message of every failed dialog
- `sudo sipnab -d eth0 -N --json-dialogs --no-cli-print --line-buffer > calls.ndjson` — record one summary object per call from live traffic, flushed per line for a downstream collector
- `sudo sipnab -N -d eth0 --node-name sbc-edge-1 --mcp --mcp-transport http` — one node of a federated setup, naming itself so an agent can attribute each answer to this box rather than another
- `sudo sipnab -N -d eth0 --node-name pbx-core-2 --report` — override the hostname on a box whose real name should not travel, while still labelling the capture
- `sipnab -N -I capture.pcap --json-pretty --payload-limit 1000 > messages.json` — export every SIP message from a capture as pretty-printed JSON, truncating displayed payloads to 1000 bytes
- `sudo sipnab -d eth0 -N --json-pretty --group-by method --line-buffer > live.json` — stream live SIP traffic as pretty-printed JSON grouped by method, flushing after each line for downstream tooling
- `sipnab -N -I capture.pcap --text-dump --hexdump --proto-number --color never` — dump raw SIP text with hex payloads and IANA protocol numbers, uncolored for log archiving
- `sudo sipnab -d eth0 -N --match REGISTER --after 2 --text-dump --line-buffer --color always` — follow live REGISTER traffic in real time, printing raw text plus 2 messages of context after each match
- `sipnab -N -I capture.pcap --show-empty --delta-time --hexdump --group-by call-id` — review a capture with per-message delta times, empty-bodied messages included, and hex dumps grouped per call
- `sudo sipnab -d eth0 -N --match OPTIONS --after 5 --show-empty --proto-number --payload-limit 256` — inspect OPTIONS keepalives with 5 messages of trailing context, empty bodies shown, and display capped at 256 payload bytes
- `sudo sipnab -d eth0 --from-to-mode host-port --wireshark` — watch the live TUI with host:port From/To columns and hand the capture to Wireshark with a matching display filter
- `sipnab -I capture.pcap --from-to-mode user-host-port` — browse an existing capture in the TUI with full user@host:port From/To columns
- `sipnab -N -I capture.pcap --tshark-filter "method=INVITE"` — print a tshark-compatible display filter for the INVITE traffic in a capture


## Dialog

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `-l`, `--limit` | `<N>` | `100000` | Maximum dialogs held in TOTAL over the run. **Not a concurrency limit** — nothing removes a completed dialog, so this bound scales with uptime rather than load: a box carrying five concurrent calls still evicts once 100,000 have completed, oldest first. Lower it for untrusted/high-volume capture |
| `-R`, `--rotate` | -- | **on** | Evict the oldest dialog at `--limit` capacity (LRU). On by default; kept for back-compat/explicitness |
| `--no-rotate` | -- | off | Disable rotation: drop *new* dialogs at capacity instead of evicting the oldest (inverts the safe default) |
| `--dialog-track` | `<METHOD>` | `call-id` | Group messages by `call-id` (one unit per dialog) or `branch` (one per SIP transaction) |
| `--no-dialog` | -- | off | Disable dialog tracking entirely (message-only mode) |
| `--tag` | `<TAG>` | -- | Filter dialogs by tag value |

> **`branch` counts transactions, not calls.** RFC 3261 gives the ACK to a 2xx a
> new branch (§17.1.1.3) and the BYE another, so one ordinary call appears as
> three or more units. That is the transaction view working as intended. Use it
> when a capture reuses one Call-ID across many transactions — load generators,
> proxies under test — and note that `--limit` then counts transactions too.

**Examples**

- `sipnab -N -I loadtest.pcapng --dialog-track branch --report` — per-transaction view of a load-generator capture that reuses one Call-ID
- `sipnab -N -I loadtest.pcapng --dialog-track call-id --report` — same capture as dialogs (the default), for a per-call view
- `sudo sipnab -d eth0 --limit 5000 --rotate` — monitor a busy proxy with a tight 5000-dialog memory bound, explicitly evicting the oldest dialog at capacity
- `sipnab -N -I capture.pcap --limit 20000 --no-rotate` — analyze a capture keyed by Via branch, dropping new dialogs (instead of evicting old ones) past 20000 tracked
- `sipnab -N -I capture.pcap --tag 1928301774 --rotate` — show only dialogs carrying a specific From/To tag, with explicit LRU rotation
- `sudo sipnab -d eth0 --tag as7d60e14a --no-rotate` — live-follow dialogs matching a tag while refusing new dialogs once the tracker is full
- `sipnab -N -I capture.pcap --no-dialog` — scan a capture message-by-message with dialog tracking disabled entirely
- `sudo sipnab -d eth0 -N --no-dialog` — watch raw live SIP messages on an interface without keeping any per-dialog state


## RTP

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `--rtp-interval` | `<SECS>` | `1` | **Accepted and ignored.** Periodic RTP statistics reporting is not implemented, so no interval report appears. sipnab warns when you pass a non-default value, and reports stream statistics once, at end of capture |
| `--max-streams` | `<N>` | `50000` | Maximum number of RTP streams to track simultaneously |
| `--quality-threshold` | `<MOS>` | `3.0` | MOS quality threshold for alerts (1.0-5.0 scale) |

**Examples**

- `sudo sipnab -d eth0 --rtp-interval 5 --quality-threshold 3.5 --max-streams 10000` — monitor live RTP with MOS alerts below 3.5. sipnab accepts `--rtp-interval 5`, ignores it, and says so: expect no 5-second reports, only the end-of-capture statistics
- `sipnab -N -I capture.pcap --rtp-interval 2 --max-streams 100000` — batch-analyse RTP streams with a raised stream cap. Again `--rtp-interval 2` changes nothing; the statistics arrive once, when the capture ends


## Security

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `--kill-scanner` | -- | off | Detect SIP scanning (known UA signatures + behavioral rate/enumeration), alert on it, and send the kill response back to the scanner (sipgrep `-J`/`-j`) |
| `--kill-ua` | `<PATTERN>` | -- | Add a custom scanner User-Agent pattern (regex) to `--kill-scanner` detection |
| `--kill-response` | `<CODE>` | `200` | SIP response code for the kill response (100-699) |
| `-K`, `--kill-target` | `<ADDR[:PORT-RANGE]>` | -- | Targeted kill (sipgrep `-K`): send the kill response to any SIP request whose source matches ADDR and an optional port range (`192.0.2.1:5060-5090`, `[::1]:5060`), regardless of UA/behavioral detection. Repeatable; spawns the kill worker on its own (no `--kill-scanner` needed) |
| `--kill-spoof` | `<MODE>` | `auto` | Source-address strategy for the kill response (Linux only; other platforms always `ephemeral`). `auto` forges the victim's ip:port via a raw socket when `CAP_NET_RAW` is available (so the reply appears to come from the targeted SIP port), falling back to an ephemeral source otherwise; `raw` requires the spoof and errors when it cannot open the raw socket; `ephemeral` never spoofs |
| `--fraud-detect` | -- | off | Enable fraud detection heuristics |
| `--reg-flood` | -- | off | Detect registration flood attacks |
| `--digest-leak` | -- | off | Detect digest credential leaks in SIP messages |
| `--alert` | `<CHANNEL>` | -- | Alert channels (repeatable): `syslog`, `json`, `exec` |
| `--alert-exec` | `<CMD>` | -- | Execute this command when an alert fires |
| `--alert-json` | -- | off | Emit each security alert as a structured JSON line on stderr (in addition to the human `[ALERT]` line) |
| `--stir-shaken` | -- | off | Report STIR/SHAKEN Identity claims — decodes the PASSporT, does NOT verify the signature |

> **`--alert` takes a channel name, not a rule.** `syslog`, `json` or `exec`.
> `--syslog` and `--alert-json` are the equivalent boolean forms; naming the
> channel here does the same thing. A value containing `:` is instead parsed as
> an alert rule (`<name>:<threshold>/<window>[:<cooldown>]`, window needs an
> `s`/`m`/`h` suffix). An unrecognised bare word draws a warning naming the
> valid channels. It used to fail silently, so a documented `--alert syslog`
> enabled nothing at all.

**Examples**

- `sudo sipnab -d eth0 --kill-scanner --kill-ua 'friendly-scanner' --kill-response 486 --kill-spoof auto` — detect SIP scanners (plus a custom UA pattern) and reply 486 with the victim's spoofed source
- `sudo sipnab -d eth0 --kill-target 192.0.2.66:5060-5090 --kill-ua 'sipvicious' --kill-response 480 --kill-spoof raw` — targeted kill of a scanning host across a port range, plus a second scanner UA, replying 480 via raw-socket spoof
- `sudo sipnab -d eth0 --kill-target 198.51.100.77:5060 --kill-spoof ephemeral` — kill requests from one more source port using a non-spoofed ephemeral reply
- `sudo sipnab -N -d eth0 --reg-flood --digest-leak --fraud-detect --stir-shaken --alert json --alert-json --alert-exec '/usr/local/bin/notify.sh'` — live security monitoring: registration floods, digest leaks, fraud, STIR/SHAKEN, with JSON alerts and an exec hook
- `sipnab -N -I capture.pcap --stir-shaken --digest-leak --alert-json` — offline audit of a pcap for digest leaks and STIR/SHAKEN attestation claims (as the originator presented them — sipnab checks no signature), emitting structured JSON alerts


## Event execution

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `--on-dialog-exec` | `<CMD>` | -- | Execute command when a dialog state changes |
| `--on-quality-exec` | `<CMD>` | -- | Execute command when RTP quality drops below threshold |
| `--exec-rate-limit` | `<N>` | `10` | Maximum exec invocations per second |

## Network listeners

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `--metrics` | `<ADDR>` | -- | Prometheus metrics endpoint (e.g., `127.0.0.1:9090`). Serves in BOTH TUI and headless (`-N`) runs — headless is where a container or systemd unit uses it. sipnab **refuses** a non-loopback bind (e.g. `0.0.0.0:9090`) unless you also pass `--metrics-auth`/`--metrics-auth-file`. Note a file run (`-I`) exits as soon as it finishes the capture, so there is little to scrape; the endpoint is for long-lived runs — a live device, `--hep-listen`, or a served API/MCP. Not served on the `--cores N` parallel offline path, which finishes and exits before a scrape could land; sipnab warns when you combine them. Feature: `metrics` |
| `--metrics-auth` | `<USER:PASS>` | -- | HTTP Basic auth credentials (`user:pass`) required by the metrics endpoint; requests must send `Authorization: Basic <base64>`. Prefer `--metrics-auth-file`. Feature: `metrics` |
| `--metrics-auth-file` | `<FILE>` | -- | Read the metrics Basic-auth `user:pass` from a file (contents trimmed), keeping the secret out of the process list. Takes precedence over `--metrics-auth`. Feature: `metrics` |
| `--api` | `<ADDR>` | -- | REST API endpoint (e.g., `0.0.0.0:8080`). Feature: `api` |
| `--api-key` | `<KEY>` | -- | API key for REST API authentication. Also reads `$SIPNAB_API_KEY` Feature: `api` |
| `--api-tls-cert` | `<FILE>` | -- | **Not yet implemented** — nothing wires up built-in API TLS, and sipnab exits when you pass this. Terminate TLS at a reverse proxy instead. Feature: `api` |
| `--api-tls-key` | `<FILE>` | -- | **Not yet implemented** — see `--api-tls-cert`; terminate TLS at a reverse proxy. Feature: `api` |
| `--api-max-conn` | `<N>` | `100` | Maximum concurrent API connections Feature: `api` |
| `--api-signing-key` | `<KEY>` | -- | HMAC signing key for self-describing bearer tokens, taken as raw bytes (any string — not hex-decoded). Repeatable: the first mints, verification accepts every one, so keys can rotate with overlap. Also reads `$SIPNAB_API_SIGNING_KEY`. See [`auth.md`](./auth.md). Feature: `api` |
| `--api-signing-key-file` | `<FILE>` | -- | Read an API signing key from a file (contents trimmed); it becomes the minting key. Feature: `api` |
| `--api-revoked-file` | `<FILE>` | -- | Revocation denylist: one revoked token `id` per line; reloaded on mtime change. Feature: `api` |
| `--api-token-ttl` | `<SECS>` | `3600` | Default TTL (seconds) when minting API tokens with `--mint-token`. Feature: `api` |
| `-L`, `--hep-listen` | `<ADDR>` | -- | Listen for HEP (Homer Encapsulation Protocol) packets. Feature: `hep` |
| `-H`, `--hep-send` | `<ADDR>` | -- | Send captured packets via HEP to a remote collector. **On `-I <file>` this forwards the file's contents**: every SIP message sipnab reads out of the capture goes to `<ADDR>` as recorded, redacted in no way. sipnab announces that at startup, naming the flag, the destination and the capture files, before it reads the first packet. See [What `--hep-send` sends](#what---hep-send-sends). Feature: `hep` |
| `--hep-id` | `<ID>` | `1` | Capture-agent id (HEP `0x000c` chunk) stamped on packets sent via `--hep-send`. Feature: `hep` |
| `--hep-auth` | `<KEY>` | -- | Homer authenticate key (HEP `0x000e` chunk). On `--hep-send` sipnab stamps it on every outgoing packet; on `--hep-listen` it **enables receiver-side authentication** — incoming packets must carry a matching key, which sipnab compares in constant time, or it drops them. Also read from `SIPNAB_HEP_AUTH`. **Security note:** the key travels in cleartext inside the HEP datagram, so it defeats blind/off-path spoofing but an on-path sniffer can capture and replay it. Over an untrusted path, tunnel HEP through WireGuard/IPsec/stunnel (the same posture as terminating API TLS in a reverse proxy) rather than relying on the key alone. Feature: `hep` |
| `--hep-auth-file` | `<FILE>` | -- | Read the HEP shared secret from a file (contents trimmed), keeping it out of the process list. Takes precedence over `--hep-auth`. Feature: `hep` |
| `--hep-auth-mode` | `<plain\|hmac>` | `plain` | HEP auth mode. `plain` sends/expects the shared secret verbatim in the 0x000e chunk (Homer-compatible, but replayable by an on-path sniffer). `hmac` sends/expects a per-message token (timestamp + nonce + HMAC-SHA256 over the payload) that resists replay — **sipnab-to-sipnab only**; a stock Homer/Kamailio peer does not understand it. Feature: `hep` |
| `-E`, `--hep-parse` | -- | off | Parse incoming HEP packets (enable HEP decoding). Feature: `hep` |
| `--hep-allow` | `<ADDR>` | -- | Allowed source addresses for HEP input (repeatable). sipnab **refuses** a non-loopback `--hep-listen` bind unless you pass either this or `--hep-auth`/`--hep-auth-file`. Feature: `hep` |
| `--hep-rate-limit` | `<N>` | `50000` | Maximum HEP packets per second (global ceiling across all senders); `0` disables the global ceiling, consistent with `off` on the per-peer knob Feature: `hep` |
| `--hep-rate-limit-per-peer` | `<N\|auto\|off>` | `off` | Maximum HEP packets/second from any single source IP: a number, `off` (the default), or `auto`. Adds fairness so one flooding peer cannot exhaust the global `--hep-rate-limit`. `auto` divides the global ceiling evenly across the `--hep-allow` sources (stays off without an allowlist). The listener logs its active limiters at startup. Feature: `hep` |
| `--hep-allow-kill` | -- | off | Allow scanner-kill to send active responses for packets received via HEP. **Off by default**: a HEP sender asserts the inner src/dst, so absent `--hep-auth` an attacker could aim the kill at a victim of their choosing. Only enable with authenticated, trusted HEP input. Feature: `hep` |
| `--syslog` | -- | off | Send alerts to syslog |
| `--mint-token` | -- | off | Mint a signed bearer token from the first configured signing key (API or MCP), print it to stdout, and exit (no capture/servers). See [`auth.md`](./auth.md). |
| `--token-id` | `<ID>` | -- | Token id (`jti`) for `--mint-token`, used for revocation. Defaults to a generated id. |
| `--token-scope` | `<full\|metrics>` | `full` | Scope for `--mint-token`. `metrics` reaches `GET /metrics` and returns `401` everywhere else — mint one for a scrape job rather than a credential that also reads `/v1/dialogs` and the message bodies underneath. REST API only; the MCP surface has no `/metrics`. |

**Examples**

- `sudo sipnab -d eth0 --api 127.0.0.1:8080 --api-signing-key-file /etc/sipnab/signing.key --api-revoked-file /etc/sipnab/revoked.txt --api-token-ttl 7200 --api-max-conn 200 --metrics 127.0.0.1:9090 --metrics-auth alice:s3cret` — live capture serving a signed-token REST API, a revocation list, and a Basic-auth'd Prometheus endpoint (terminate TLS at a reverse proxy)
- `sudo sipnab -d eth0 --api 0.0.0.0:8080 --api-signing-key-file /etc/sipnab/signing.key --api-token-ttl 3600 --api-max-conn 100 --metrics 127.0.0.1:9090 --metrics-auth bob:hunter2` — public-facing API tuned to 100 connections and 1h token TTL, with its own auth'd metrics endpoint
- `sudo sipnab -N -d eth0 --mcp --mcp-transport http --mcp-bind 127.0.0.1:8731 --mcp-token t0ken-alice --mcp-signing-key-file /etc/sipnab/mcp-signing.key --mcp-revoked-file /etc/sipnab/mcp-revoked.txt --mcp-token-ttl 1800` — loopback HTTP MCP server with a bearer token, file-loaded signing key, revocation denylist, and a 30-minute mint TTL
- `sudo sipnab -N -d eth0 --mcp --mcp-transport http --mcp-bind 0.0.0.0:8731 --mcp-token t0ken-bob --mcp-signing-key-file /etc/sipnab/mcp-signing.key --mcp-revoked-file /etc/sipnab/mcp-revoked.txt --mcp-allowed-host mcp.example.com` — non-loopback HTTP MCP server (token required) accepting an extra Host header for named clients
- `sudo sipnab -N -d eth0 --hep-send 192.0.2.10:9060 --hep-id 42 --hep-auth s3cr3t-homer-key` — forward captured packets to a Homer collector, stamping capture-agent id 42 and an authenticate key
- `sudo sipnab -N -d eth0 --hep-send 198.51.100.20:9060 --hep-id 7 --hep-auth homerkey2` — forward to a second collector under a different agent id and auth key
- `sudo sipnab -N -d eth0 --hep-send 198.51.100.30:9060 --hep-auth-file /etc/sipnab/hep.key --hep-auth-mode hmac` — replay-resistant forwarding to another sipnab: HMAC-token auth over an untrusted path (both ends must set --hep-auth-mode hmac)
- `sipnab -N -I archive.pcap --hep-send 127.0.0.1:9060 --hep-id 9` — replay an archived capture into a collector on this host. sipnab warns at startup that the file's signalling leaves the machine, then forwards it
- `sipnab -N -L 0.0.0.0:9060 --hep-parse --hep-auth-file /etc/sipnab/hep.key --hep-auth-mode hmac` — the matching sipnab-to-sipnab HMAC collector: verifies the per-message token and rejects replays
- `sipnab -N -L 0.0.0.0:9060 --hep-parse --hep-allow 192.0.2.0/24 --hep-allow 198.51.100.20/32 --hep-rate-limit 20000` — run a HEP collector that parses incoming packets, only from two allowed CIDRs, capped at 20k pkts/sec
- `sipnab -N -L 0.0.0.0:9060 --hep-parse --hep-auth-file /etc/sipnab/hep.key --hep-rate-limit 40000 --hep-rate-limit-per-peer 5000` — authenticated HEP collector on a routable address: incoming packets must carry the shared secret, with a 5k/s per-peer fairness cap
- `sipnab -N -L 0.0.0.0:9060 --hep-parse --hep-auth-file /etc/sipnab/hep.key --hep-allow-kill --kill-scanner` — authenticated HEP collector that may also actively kill scanners seen in the HEP stream (only safe because the feed carries authentication)
- `sipnab -N -L 0.0.0.0:9060 --hep-parse --hep-auth s3cr3t-homer-key --hep-rate-limit-per-peer 2000 --hep-allow-kill --kill-target 198.51.100.7` — inline HEP secret (visible in the process list; prefer --hep-auth-file) with a tight per-peer cap for a busy multi-proxy fleet
- `sipnab -N -I capture.pcap --metrics 127.0.0.1:9090 --metrics-auth-file /etc/sipnab/metrics.cred` — loopback metrics endpoint reading its Basic-auth credential from a file (keeps user:pass out of the process list)
- `sudo sipnab -d eth0 --metrics 0.0.0.0:9090 --metrics-auth-file /etc/sipnab/metrics.cred` — routable metrics endpoint (non-loopback requires auth) using a file-backed credential; terminate TLS at a reverse proxy
- `sipnab --mint-token --token-id alice-2026 --api-signing-key-file /etc/sipnab/signing.key --api-token-ttl 3600` — mint a signed bearer token with a fixed id (for later revocation) and a 1-hour TTL, then exit
- `sipnab --mint-token --token-scope metrics --token-id prom-scraper --api-signing-key-file /etc/sipnab/signing.key --api-token-ttl 86400` — mint a scrape-only token for Prometheus: it reaches `/metrics`, and every `/v1/` route refuses it
- `sipnab --mint-token --token-scope full --token-id ops-oncall --api-signing-key-file /etc/sipnab/signing.key` — the default scope, stated explicitly: full access to the REST API surface

### What `--hep-send` sends

`--hep-send <ADDR>` forwards every SIP message sipnab reads to the collector at
`<ADDR>`, byte for byte as the capture holds it. On a live capture that matches
what the flag sounds like. Traffic passes the interface, and a copy reaches
Homer.

On `-I <file>` the same sentence carries a sharper meaning. The messages sipnab
reads come out of the capture file, so that file's signalling leaves the
machine: request lines, headers, URIs, and any message bodies it holds. sipnab
redacts nothing and drops nothing beyond what `--portrange` and the matching
flags already exclude. Testing a HEP pipeline against a customer capture
therefore ships that customer's signalling to whatever `<ADDR>` names.

sipnab announces this before it reads the first packet:

```text
WARN sipnab::app::bootstrap: --hep-send collector.example:9060 forwards every
SIP message this run reads to that address, and this run is reading a capture
FILE (customer.pcap). The signalling in those captures leaves this machine ...
```

That line is a warning rather than a refusal, because you chose the
destination. Replaying an archive into your own collector stays a supported
workflow. Two habits keep it uneventful:

- Name a collector you control. sipnab never takes the destination from the
  capture. The address always comes from your command line or your config file,
  and no code path exists that turns a recorded address into an export target.
- Read the startup warning before you walk away. It names the flag, the
  destination, and the capture files.

The scanner-kill path works the other way round and refuses to run offline. It
aims at addresses recorded *inside* the capture, which belong to third parties
who have nothing to do with your analysis, so `-I file` grants it nothing at
all. See [Security](#security).

## MCP server

Run sipnab as a Model Context Protocol server so an AI agent can drive
it. See [MCP Server](mcp.md) for the full guide. [Network Listeners](#network-listeners) lists the `--mint-token` /
`--token-id` pair that issues MCP bearer tokens — it serves the REST API too.

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `--mcp` | -- | off | Run sipnab as an MCP server. Requires `-N`/`--no-tui` (stdout carries the JSON-RPC wire) — sipnab exits with an error without it — and rejects stdout-writing flags (`--json`, `--report`, …). Feature: `mcp` (or `mcp-http` for HTTP transport). See [`mcp.md`](./mcp.md). |
| `--mcp-transport` | `stdio\|http` | `stdio` | MCP transport: `stdio` (default) or `http` (requires the `mcp-http` feature). Feature: `mcp` |
| `--mcp-bind` | `<ADDR>` | -- (defaults to `127.0.0.1:8731` at runtime when `--mcp-transport http` appears without an explicit bind) | HTTP MCP bind address. Non-loopback requires `--mcp-token`. Feature: `mcp-http` |
| `--mcp-token` | `<TOKEN>` | -- | Bearer token for HTTP MCP; required for non-loopback binds. Also reads `$SIPNAB_MCP_TOKEN`. Feature: `mcp-http` |
| `--mcp-token-file` | `<FILE>` | -- | Read bearer token from file (preferred over env in systemd units). Feature: `mcp-http` |
| `--mcp-signing-key` | `<KEY>` | -- | HMAC signing key for MCP bearer tokens, taken as raw bytes (any string — not hex-decoded). Repeatable: the first mints, verification accepts every one. Also reads `$SIPNAB_MCP_SIGNING_KEY`. See [`auth.md`](./auth.md). Feature: `mcp-http` |
| `--mcp-signing-key-file` | `<FILE>` | -- | Read an MCP signing key from a file (contents trimmed); it becomes the minting key. Feature: `mcp-http` |
| `--mcp-revoked-file` | `<FILE>` | -- | MCP revocation denylist (one token `id` per line; reloaded on mtime change). Feature: `mcp-http` |
| `--mcp-token-ttl` | `<SECS>` | `3600` | Default TTL (seconds) when minting MCP tokens with `--mint-token`. Feature: `mcp-http` |
| `--mcp-max-concurrent` | `<N>` | `100` | Maximum tool calls the MCP server runs at once (`0` = unlimited). sipnab refuses a call that cannot take a slot immediately, with a retry-shortly error, rather than queueing it — an unbounded backlog behind the cap is the exhaustion the cap prevents. The default mirrors `--api-max-conn` and bounds a flooding client without impeding an agent's ordinary parallel calls. Applies to both stdio and HTTP servers, though a network-exposed HTTP server is the case it matters for. Feature: `mcp` |
| `--mcp-rate-limit-per-peer` | `<N>` | `100` | Maximum tool calls one peer may make per second (`0` = unlimited). The other half of `--mcp-max-concurrent`: that caps calls *in flight*, this caps their *arrival rate*, and without it an agent that stays under the concurrency cap while looping as fast as sipnab answers has no bound at all. A call over the cap gets the same retry-shortly error, never a queue slot. A peer is the source IP over HTTP (the address, not the socket, so reconnecting mints no fresh allowance) and the pipe itself over stdio. Shares its per-peer accounting with `--hep-rate-limit-per-peer`. Feature: `mcp` |
| `--mcp-allowed-host` | `<HOST>` | -- | Additional `Host` header values the HTTP MCP server accepts (repeatable). rmcp's DNS-rebind protection defaults to `localhost`, `127.0.0.1`, `::1` only — add the public hostname or bind IP when clients connect via that name. Use `*` to disable host checking entirely (not recommended; pair the resulting open binding with a network-level source-IP allowlist). Feature: `mcp-http` |
| `--mcp-file-root` | `<DIR>` | -- | Directory the MCP file tools (`export_capture`, `export_audio`, `list_captures`) may read and write. Without it those tools refuse to run. They take a bare FILENAME, never a path — an agent cannot escape this directory. Feature: `mcp` |
| `--mcp-allow-shutdown` | -- | off | Permit the `shutdown_server` MCP tool to stop this process. Off by default, so an agent cannot stop a stock server. Even enabled, the tool dry-runs unless told otherwise and refuses to discard an unsaved live capture. Feature: `mcp` |
| `--mcp-allow-open-capture` | -- | off | Permit the `open_capture` MCP tool to load a different capture from `--mcp-file-root`, discarding every dialog and stream held. Off by default, so a stock server keeps the capture the command line named. The tool refuses while the source is live or still filling the stores, loads in the background, and mints a new capture identity every later answer carries. Feature: `mcp` |
| `--mcp-allow-save-findings` | -- | off | Permit the `save_findings` MCP tool to record an agent's conclusion. The only write verb on sipnab's network surface, and off by default. A finding goes to sipnab's log and nowhere else: no tool reads it back, it appears in no query result, and no analysis consumes it, so it cannot return as evidence in a later answer. Clipped at 500 characters of summary and bounded at 1000 findings per process, both reported rather than silent. Feature: `mcp` |
| `--retain-audio` | -- | off | Retain RTP audio payload in memory so the `export_audio` MCP tool can decode it. Off by default: call audio is content, not signalling, and holding it is an operator decision rather than a side effect of enabling MCP. Requires `--mcp` — the MCP server is the only batch-mode reader of these buffers. Costs a per-packet payload clone, bounded by `[limits] max_audio_frames` per stream across `--max-streams` streams. Without it `export_audio` refuses and names this flag. Feature: `mcp` |

## TLS / decryption

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `-k`, `--tls-key` | `<FILE>` | -- | RSA private key (PEM) for TLS 1.2 RSA-key-exchange decryption. Non-PFS RSA only; ECDHE/DHE handshakes need `--keylog`. Feature: `tls` |
| `--keylog` | `<FILE>` | -- | TLS key log file (NSS `SSLKEYLOGFILE` format). Feature: `tls` |
| `--keylog-watch` | -- | off | Watch key log file for new entries (live decryption). Feature: `tls` |
| `--dtls-keylog` | `<FILE>` | -- | DTLS key log (NSS `SSLKEYLOGFILE`); extracts SRTP keys from DTLS-SRTP handshakes (RFC 5764 exporter, AES-CM profiles). Feature: `tls` |
| `--srtp-keys` | `<FILE>` | -- | SRTP master-keys file for media decryption (AES-CM, RFC 3711); also honors SDES `a=crypto` keys from SDP. Feature: `tls` |
| `--pcap-export-mode` | `<MODE>` | `decrypted` | Pcap export mode for encrypted traffic: `decrypted` (plaintext payloads, no DSB), `raw` (original encrypted bytes, no DSB), `encrypted+dsb` (original encrypted bytes + Decryption Secrets Block so Wireshark can decrypt) |
| `--allow-coredump` | -- | off | Allow core dumps (do not call `prctl` to disable them) |

**Examples**

- `sipnab -N -I capture.pcap --mcp --mcp-file-root /var/spool/sipnab-exports` — let an agent save captures and audio, confined to one directory
- `sudo sipnab -N -d eth0 --mcp --mcp-file-root /var/spool/sipnab-exports --mcp-allow-shutdown` — a live capture an agent may export from and, deliberately, stop
- `sipnab -N -I capture.pcap --mcp --mcp-allow-shutdown` — a replay session an agent may end when it has finished; nothing to lose, since the file is already on disk
- `sipnab -N -I first.pcap --mcp --mcp-transport http --mcp-file-root /var/spool/sipnab-captures --mcp-allow-open-capture` — a long-lived service an agent may move through a corpus with, one capture at a time
- `sipnab -N -I capture.pcap --mcp --mcp-file-root /var/spool/sipnab-captures --mcp-allow-open-capture --mcp-allow-shutdown` — the same, plus the ability to end the session; both opt-ins are separate on purpose
- `sipnab -N -I capture.pcap --mcp --mcp-allow-save-findings` — let an agent write its conclusions into the log while it works through a capture; read them back with `journalctl -u sipnab`, never through a tool
- `sudo sipnab -N -d eth0 --mcp --mcp-transport http --mcp-allow-save-findings` — a live triage session whose findings survive in the journal after the agent disconnects, without granting it any other write
- `sipnab -N -I capture.pcap --mcp --mcp-file-root /var/spool/sipnab-exports --retain-audio` — hold call audio in memory so an agent can `export_audio` a WAV of a problem call
- `sudo sipnab -N -d eth0 "portrange 5060-5061 or portrange 10000-20000" --mcp --retain-audio --mcp-file-root /var/spool/sipnab-exports` — live capture with media in scope AND retained; without `--retain-audio` the same run measures quality but keeps no payload to export
- `sudo sipnab -N -d eth0 --mcp --mcp-transport http --mcp-bind 127.0.0.1:8731 --mcp-max-concurrent 8` — a network-facing MCP server that runs at most eight tool calls at once and refuses the ninth with a retry-shortly error rather than queueing it
- `sipnab -N -I capture.pcap --mcp --mcp-max-concurrent 0` — a stdio replay for one trusted agent with no concurrency cap (`0` = unlimited)
- `sudo sipnab -N -d eth0 --mcp --mcp-transport http --mcp-rate-limit-per-peer 20` — a network-facing MCP server where any one client may make twenty tool calls a second; sipnab answers the twenty-first that second with a retry-shortly error instead of serving it
- `sipnab -N -I capture.pcap --mcp --mcp-max-concurrent 8 --mcp-rate-limit-per-peer 0` — bound how many calls run at once but put no cap on the arrival rate (`0` = unlimited), for a scripted client that sweeps a capture as fast as it can
- `sipnab -N -I capture.pcap --tls-key /etc/sipnab/tls-rsa.key --keylog /etc/sipnab/keys.log --allow-coredump` — decrypt TLS 1.2 RSA-key-exchange SIP from a pcap using an RSA private key, with core dumps left enabled
- `sipnab -N -I capture.pcap --srtp-keys /etc/sipnab/srtp.keys --dtls-keylog /etc/sipnab/dtls.log` — decrypt SRTP media in an offline pcap from an SRTP master-keys file plus DTLS-SRTP handshake keys
- `sudo sipnab -d eth0 --tls-key /etc/sipnab/tls-rsa.key --srtp-keys /etc/sipnab/srtp.keys --keylog /etc/sipnab/keys.log --keylog-watch --allow-coredump` — live decrypt both SIP (RSA key) and SRTP media, watching the key log for new PFS session keys


## Privilege

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `--user` | `<USER>` | -- | Drop privileges to this user after opening capture devices |
| `--no-priv-drop` | -- | off | Do not drop privileges after opening capture devices |
| `--chroot` | `<DIR>` | -- | Chroot to this directory after initialization |
| `--setup-caps` | -- | off | Grant this binary the Linux capabilities for live capture (`cap_net_raw,cap_net_admin+ep` via `setcap`) so it runs without `sudo`, then exit. Re-invokes through `sudo` when not already root. Linux only. |

**Examples**

- `sudo sipnab -d eth0 --user sipnab` — live capture that drops root to the sipnab service user once the capture device is open
- `sudo sipnab -d eth0 --user nobody --chroot /var/empty` — long-running monitor that drops to nobody and confines itself to an empty chroot
- `sudo sipnab -d eth0 --chroot /var/empty --no-priv-drop` — chrooted capture that keeps root privileges for the whole run
- `sudo sipnab --setup-caps` — grant the binary the capture capabilities (cap_net_raw,cap_net_admin) so future runs work without sudo, then exit


## Resource limits

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `--max-reassembly` | `<N>` | `10000` | Maximum concurrent TCP/TLS reassembly sessions |
| `--cores` | `<N>` | `1` | CPU cores for offline pcap reconstruction (`-I`). 1 = single-threaded; >1 shards by host pair for multi-core throughput (dialog+RTP reconstruction, `--report`/`--json`) |

**Examples**

- `sudo sipnab -d eth0 --max-reassembly 50000` — live capture on a busy TCP/TLS trunk with a raised reassembly-session ceiling
- `sipnab -N -I capture.pcap --cores 4 --max-reassembly 2000` — offline reconstruction sharded across 4 cores, with a tight reassembly bound for an untrusted capture


## Config

| Flag | Value | Default | Description |
|------|-------|---------|-------------|
| `-f`, `--config` | `<FILE>` | -- | Path to configuration file (must exist) |
| `-F`, `--no-config` | -- | off | Skip loading any configuration file |
| `-D`, `--dump-config` | -- | off | Dump effective configuration and exit |
| `--completions` | `<SHELL>` | -- | Print a shell completion script (bash, zsh, fish, elvish, powershell) to stdout and exit |

**Examples**

- `sipnab --config /etc/sipnab/sipnab.toml --dump-config` — dump the effective configuration produced by a specific config file, then exit
- `sipnab --no-config --dump-config` — dump the built-in defaults, skipping any configuration file, then exit
- `sudo sipnab -d eth0 --config ~/.config/sipnab/config.toml` — live capture using a per-user configuration file
- `sipnab -N -I capture.pcap --no-config` — analyze an offline pcap with all configuration files ignored
- `sipnab --completions bash > sipnab.bash` — print a bash completion script into a file suitable for /etc/bash_completion.d
- `sipnab --completions zsh > _sipnab` — print a zsh completion script into a file suitable for the zsh fpath


## Validation rules

- Output flags (`--json`, `--json-pretty`, `--report`, `--hexdump`, `--fail2ban`) require `-N` / `--no-tui` mode, unless `--call-report` is also specified.
- `--kill-response` accepts values 100-699 only.
- Feature-gated flags (`tls`, `hep`, `api`, `mcp`, `mcp-http`) produce startup errors when the required feature is not compiled in.
- `--mcp` is incompatible with stdout-writing flags (`--json`, `--json-pretty`, `--report`, `--call-report`, `--hexdump`, `--wireshark`, `--tshark-filter`) on every transport, not just stdio — sipnab refuses to start. Combine `--mcp` with `--quiet` to suppress text-mode capture output.
- HTTP MCP transport (`--mcp --mcp-transport http`) on a non-loopback `--mcp-bind` requires `--mcp-token` / `--mcp-token-file` / `SIPNAB_MCP_TOKEN`; loopback binds need no token.

## Examples

- `sipnab -d eth0` — capture on eth0
- `sipnab -I capture.pcap` — read from pcap file
- `sipnab -N --json -I capture.pcap` — non-interactive JSON output
- `sipnab --problems` — show problematic calls
- `sipnab --kill-scanner -d eth0` — detect SIP scanners
- `sipnab --from alice --to bob` — filter by From/To headers
- `sipnab 'host 192.0.2.1 and port 5060'` — BPF display filter
- `sipnab --filter "method == 'INVITE' AND rtp.mos < 3.0"` — advanced filter DSL
- `sipnab -N -I capture.pcap --call-report "abc123@host" --markdown --no-cli-print` — generate detailed report for a call (drop `--no-cli-print` and the whole capture's message dump precedes it)
- `sipnab -d eth0 -H 192.0.2.50:9060` — capture with HEP mirror
- `sipnab -d eth0 --keylog /tmp/sslkeys.log --keylog-watch` — live TLS decryption

## Exit codes

Scripts can rely on these:

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Runtime failure — capture error, I/O error, or sipnab could not produce a requested report (e.g. `--call-report` Call-ID not found) |
| `2` | Invalid usage — bad flag value or combination, or a flag whose feature is not compiled into this binary |
| `3` | Lint gate tripped — `--lint --lint-fail-on <severity>` found a conformance finding at or above that severity. Distinct from `1` on purpose: the tool worked, the CAPTURE is non-conformant |
