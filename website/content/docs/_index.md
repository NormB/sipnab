+++
title = "Documentation"
sort_by = "weight"
template = "section.html"
page_template = "page.html"

[extra]
# Task cards rendered by section.html above the reference index: intent-titled
# entry points for people who arrive with a problem, not a topic.
tasks = [
  { title = "Analyze a pcap file", cmd = "sipnab -I capture.pcap", href = "/docs/cookbook/" },
  { title = "Capture live SIP traffic", cmd = "sudo sipnab -d eth0", href = "/docs/cookbook/#2-live-capture-narrow-to-a-single-user" },
  { title = "Diagnose one-way audio", cmd = "sipnab -I dump.pcap --one-way", href = "/docs/troubleshooting/" },
  { title = "Find failed calls", cmd = "sipnab -N -I dump.pcap --problems", href = "/docs/troubleshooting/" },
  { title = "Set up a HEP capture server", cmd = "sipnab --hep-listen 0.0.0.0:9060", href = "/docs/cookbook/" },
  { title = "Decrypt TLS / SRTP", cmd = "sipnab -I tls.pcap --keylog keys.log", href = "/docs/cookbook/" },
  { title = "Detect scanners & fraud", cmd = "sudo sipnab -N -d eth0 --fraud-detect", href = "/docs/cookbook/" },
  { title = "Drive sipnab from an AI agent", cmd = "sipnab --mcp", href = "/docs/mcp/" },
]

# Audience paths rendered by section.html underneath the task cards. The cards
# above are the TASK axis -- "what do I need to do right now". This is the
# AUDIENCE axis over the SAME pages: a reader who knows which job they hold,
# but not which of thirty-odd reference pages is theirs, gets an ordered route
# through the ones that are.
#
# Nothing here is a new page, deliberately. Every href points at a page that
# already exists, so the grouping costs one array and no registrations. The
# roles are the ones the "Who it is for" section below names, and
# `index_audience_paths_point_at_existing_pages` pins them to it -- two places
# describe the audience and prose is the one people edit, so without that pin
# this block keeps addressing a reader the page stopped claiming to serve.

[[extra.audiences]]
role = "VoIP engineers"
goal = "Work a ticket: a call that will not set up, audio only one way, a codec or NAT problem."
steps = [
  { title = "Install sipnab", href = "/docs/install/" },
  { title = "Open a capture in the TUI", href = "/docs/tui/" },
  { title = "Follow the recipe for your symptom", href = "/docs/cookbook/" },
  { title = "Chase one-way audio to its cause", href = "/docs/troubleshooting/#one-way-audio" },
  { title = "Read what a MOS score actually claims", href = "/docs/mos-and-codecs/" },
]

[[extra.audiences]]
role = "SRE and on-call teams"
goal = "Get an answer out of a pcap at 3 AM, or a headless run that exits non-zero when the call is not there."
steps = [
  { title = "Install sipnab", href = "/docs/install/" },
  { title = "Run it headless", href = "/docs/cli/" },
  { title = "Narrow the capture with the filter DSL", href = "/docs/filter-dsl/" },
  { title = "Pipe the output into your tooling", href = "/docs/output-formats/" },
  { title = "Scrape the metrics endpoint", href = "/docs/metrics/" },
  { title = "Stop a busy capture dropping packets", href = "/docs/tuning-capture/" },
  { title = "Let an agent read the capture for you", href = "/docs/mcp/" },
]

[[extra.audiences]]
role = "Security teams"
goal = "Audit SIP-facing infrastructure for scanners, registration floods, toll fraud, and leaked credentials."
steps = [
  { title = "Install sipnab", href = "/docs/install/" },
  { title = "Turn on the detectors", href = "/docs/cli/#security" },
  { title = "Read signaling that is encrypted", href = "/docs/tls-capture/" },
  { title = "Lint the traffic for conformance", href = "/docs/sip-lint-rules/" },
  { title = "Ban a source with fail2ban", href = "/docs/integrations/" },
  { title = "Write a detection of your own", href = "/docs/plugins/" },
]
+++

## What is sipnab?

sipnab is a network analysis tool for Voice over IP. It captures and decodes
**SIP** signaling — the protocol that sets up, modifies, and tears down calls —
alongside the **RTP** media streams carrying the audio, and correlates the two
so you can see a call as a call rather than as a pile of packets.

It is one Rust binary. The same executable gives you an interactive terminal
UI, a headless CLI for scripts and CI, a REST API, and an MCP server for AI
agents — no daemon, no database, no runtime to install.

## Who it is for

- **VoIP engineers** debugging call setup failures, one-way audio, and codec
  or NAT problems.
- **SRE and on-call teams** who need a fast answer from a pcap at 3 AM, or a
  headless run that exits non-zero when the Call-ID they asked about is not in
  the capture.
- **Security teams** auditing SIP-facing infrastructure for scanners,
  registration floods, toll fraud, and leaked credentials.

## What it does

**Capture and decode.** Live interfaces, pcap/pcapng files, or a
[HEP/EEP](/docs/cookbook/) listener fed by Kamailio, OpenSIPS, or FreeSWITCH.
sipnab parses SIP over UDP, TCP, TLS, SCTP, and WebSocket, including IP
fragmentation and TCP stream reassembly. All 19 RFC 3261 and IANA compact
header forms all resolve, so a message using `f:`/`t:`/`i:` is not a blind
spot.

**Cross-check the proxy against the wire.** One run can take a HEP mirror and
a live interface at once and report where the two disagree: messages the proxy
believes it sent that never reached the wire, traffic on the wire the tracing
never reported, and messages both saw carrying different SDP. A mirror answers
"what does the proxy think it did". The interface answers "what actually left
the box". Asking the suspect twice cannot tell you the proxy is misconfigured —
see the [Cookbook](/docs/cookbook/).

**Correlate calls.** sipnab follows dialogs across their lifetime and links them to
their media through SDP, then rendered as a call list, a ladder-style call
flow, and per-message detail.

**Analyze media.** sipnab finds RTP streams in the packets themselves, so
media is still analyzed when the signaling was never captured. sipnab computes
interarrival jitter (the RFC 3550 algorithm), loss, MOS estimates, and a
sequence-space loss map that distinguishes bursty loss from diffuse loss.
It decodes RFC 4733 DTMF, and exports G.711 (PCMU/PCMA) and Opus streams as audio.

**Decrypt.** With a TLS key log, sipnab decrypts TLS-carried SIP and SRTP
in place, so encrypted captures stay readable without terminating the session
elsewhere.

**Detect.** Opt-in detectors for SIP scanning (`--kill-scanner`), registration
floods (`--reg-flood`), fraud heuristics (`--fraud-detect`), and digest
credential leaks (`--digest-leak`), with alerts to syslog, JSON, or an external
command, plus a `fail2ban`-compatible output.

**Integrate.** JSON/NDJSON for pipelines, a REST API (`--api`), a Prometheus
endpoint (`--metrics`), and an MCP server (`--mcp`) over stdio or streamable
HTTP so an AI agent can query captures directly.

There is also a **browser analyzer** at [/analyze/](/analyze/) that runs the
same parsing core compiled to WebAssembly. It is a separate build from the CLI
binary, and your pcap never leaves your machine.

## Quick start

Analyze a pcap file in the TUI:

```bash
sipnab -I capture.pcap
```

Capture live on eth0. Live capture needs packet permissions — run
`sudo sipnab --setup-caps` once on Linux to grant them, and drop the `sudo`
afterwards:

```bash
sudo sipnab -d eth0
```

Headless, reporting only the calls that went wrong as NDJSON. `-N` is headless
mode and `--json` emits one JSON object per line, so this one drops straight
into `jq` or a log pipeline:

```bash
sipnab -N -I capture.pcap --problems --json
```

## What is in your build

sipnab's optional subsystems are Cargo features, so what a given binary
supports depends on how someone built it:

| Build | Included |
|---|---|
| Official Linux (glibc) and macOS releases | Everything: TUI, TLS/SRTP decryption, HEP, REST API, MCP (stdio + HTTP), Prometheus metrics, audio playback |
| Static musl binaries and the `-noaudio` `.deb` / `.rpm` | The same, **minus** audio playback. Everything else, WAV export included, stays the same |
| `cargo build` from source with no flags | TUI, audio, and metrics only — **no** TLS decryption, HEP, REST API, or MCP. Use `--features full` for everything |
| Any build, plus `--features plugins` | WASM plugin host (`--plugin`). Off by default so a stock binary carries no interpreter — see [WASM plugins](/docs/plugins/) |
| A build with `--features bpf`, on a BTF kernel | eBPF TLS capture, which reads plaintext with no key and no certificate — see the [uprobe walkthrough](/docs/uprobe-walkthrough/) |

`sipnab --version` prints the feature list compiled into your binary.

## Where to go next

- New here? [Installation](/docs/install/), then the
  [Cookbook](/docs/cookbook/) for copy-paste recipes.
- Driving the TUI: the [TUI walkthrough](/docs/tui/) and
  [keybindings](/docs/keybindings/).
- Scripting it: the [CLI reference](/docs/cli/),
  [filter DSL](/docs/filter-dsl/), and [output formats](/docs/output-formats/).
- Something misbehaves: [Troubleshooting](/docs/troubleshooting/).
- Automating it: the [REST API](/docs/api/) and [MCP server](/docs/mcp/).
- Extending it: [WASM plugins](/docs/plugins/) add your own detections.
