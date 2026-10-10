+++
title = "Features"
description = "What sipnab does, the flag or setting that turns each feature on, and the page that documents it."
template = "overview.html"
+++

sipnab captures and analyzes SIP signaling and RTP media. It is one binary: no database and no server to run. This page lists what it does, the flag or key that turns each feature on, and the documentation page that covers it.

Terms used on this page:

- **SDP** (Session Description Protocol) is the body of an INVITE or its answer that names each side's media address and codecs.
- **RTP** (Real-time Transport Protocol) carries the audio. **RTCP** is its control protocol, which carries the endpoints' own quality reports.
- **HEP** is the encapsulation a SIP proxy uses to copy each SIP message it handles to a remote collector.
- **MOS** (mean opinion score) is an estimate of how the audio sounded. sipnab derives it from loss, jitter, delay and the codec with the ITU-T G.107 E-model.
- **MCP** (Model Context Protocol) is the protocol an AI agent uses to call tools.
- **B2BUA** (back-to-back user agent) is a SIP element that ends a call on one side and starts a new call on the other, so each side (a leg) carries its own Call-ID.

## Capture inputs

- **Live capture from a network interface.** `-d <iface>`. On Linux, with no `-d`, sipnab captures on the `any` pseudo-device, which covers every interface including loopback. [Look up a command-line flag](/docs/cli/#capture)
- **Several named interfaces at once**, one capture handle per interface. `-d eth0,eth1 --multi-device`. [Look up a command-line flag](/docs/cli/#capture)
- **Capture files, directories and globs.** `-I <file|dir|glob>`, repeatable, with `--recursive` and `--input-name <glob>`. sipnab orders a set of files by each file's first packet timestamp, not by file name, so sipnab reads a call that spans two files of a rotated capture as one call. gzip-compressed captures open without unpacking. [Look up a command-line flag](/docs/cli/#capture)
- **Archives read like directories.** `-I` accepts `.tar`, `.tgz`, `.tar.gz` and `.zip` files, and 7z files in builds with the `archive` feature (every release binary). Nested layers unwrap up to four deep. [Archives read like directories](/docs/cli/#archives-read-like-directories)
- **Password-protected archives.** ZIP (WinZip AES and legacy ZipCrypto) and 7z (AES-256). Passwords come from `--archive-password-file`, `--archive-password-command`, `--archive-password-stdin`, a systemd credential, an environment variable, or a terminal prompt. [Archives](/docs/cli/#archives)
- **Receive HEP from SIP proxies.** `-L <addr>` (`--hep-listen`) accepts HEP v1, v2 and v3 over UDP, and HEP v3 over TCP or TLS (`--hep-listen-transport`). The proxy needs nothing installed. [HEP, fail2ban and syslog integrations](/docs/integrations/)
- **HEP signaling plus local media.** `-L` combined with `-d` takes SIP from the HEP feed and RTP from the interface, and links streams to dialogs by the SDP media address. [Look up a command-line flag](/docs/cli/#network-listeners)
- **HEP listener controls.** Source allowlist (`--hep-allow`), shared-key authentication (`--hep-auth`, `--hep-auth-file`), an HMAC mode that resists replay between two sipnab instances (`--hep-auth-mode hmac`), and global and per-peer rate limits (`--hep-rate-limit`, `--hep-rate-limit-per-peer`). [Look up a command-line flag](/docs/cli/#network-listeners)
- **HEP inside a capture file.** `-E` (`--hep-parse`) unwraps HEP packets found on the wire or in a file and uses the addresses and time the HEP header carries. [Look up a command-line flag](/docs/cli/#network-listeners)
- **SIP inside tunnels and tags.** VLAN (802.1Q, 802.1ad, QinQ), MPLS, PPPoE, IP-in-IP, GRE, GTP-U, VXLAN, GENEVE and Teredo. The generated live filter already looks inside VLAN, QinQ, PPPoE and MPLS; `--capture-tunnels` adds the UDP tunnel ports. A `NOT DECODED` line at the end of the run counts the frames sipnab cannot decode. [Read SIP inside tunnels](/docs/encapsulations/)
- **SIP over WebSocket** ([RFC 7118](https://www.rfc-editor.org/rfc/rfc7118)). Ports set with `--ws-portrange`. [Look up a command-line flag](/docs/cli/#capture)
- **IP fragment and TCP segment reassembly**, on by default; `--no-reassembly` turns it off. [Look up a command-line flag](/docs/cli/#capture)
- **Write the capture to a file.** `-O <file>` writes pcap, `--pcapng` writes pcapng. `--split filesize:N` rotates files, `--split-keep N` keeps only the newest N, and `-n`, `--duration` and `--autostop` end the run. [Look up a command-line flag](/docs/cli/#bound-split-and-multi-interface-captures)
- **Capture sizing.** `-B` sets the kernel capture buffer, and `--capture-profile signaling` keeps every SIP header while dropping most of each RTP payload. [Stop a capture dropping packets](/docs/tuning-capture/)

## Encrypted SIP and media

- **Decrypt SIP over TLS 1.2 and 1.3 with a key log.** `--keylog <file>` reads an `SSLKEYLOGFILE` (NSS key log format); the file may be a FIFO, and `--keylog-watch` keeps reading new entries during a live capture. [Capture SIP over TLS](/docs/tls-capture/)
- **TLS 1.2 RSA key exchange.** `-k <key.pem>` decrypts handshakes that used RSA key exchange, when you hold the server's private key. [Capture SIP over TLS](/docs/tls-capture/)
- **Read TLS plaintext without keys (eBPF).** `--uprobe-tls` uses kernel uprobes (probes the kernel attaches to a function inside a running program) to read SIP plaintext inside OpenSSL and wolfSSL on the same host, with no certificate, key or restart. It needs root and Linux. The eBPF backend also needs a kernel with BTF type information, and it is in the Linux gnu tarballs, `.deb` and `.rpm`, not the static musl builds. [Read TLS without keys (eBPF)](/docs/uprobe-walkthrough/)
- **SRTP media.** `--srtp-keys <file>` takes SRTP master keys (AES-CM), and sipnab also uses SDES `a=crypto` keys found in the SDP. `--dtls-keylog` extracts SRTP keys from DTLS-SRTP handshakes. [Look up a command-line flag](/docs/cli/#tls-decryption)

## SIP analysis

<img src="/demos/hero-static.webp?v=2" width="1200" height="700" loading="lazy" decoding="async" alt="sipnab terminal UI showing the call-flow ladder of a complete call, from the INVITE to the BYE, with the decoded INVITE in the detail pane">

- **Dialog tracking and call-flow ladders.** sipnab tracks every SIP dialog through its state machine and draws it as a ladder diagram of its transactions. [Walk through the terminal UI](/docs/tui/)
- **One call across a B2BUA.** sipnab correlates the two legs of a call that a B2BUA or session border controller split onto different Call-IDs, and reports which strategy matched them; when only timing tied them together it says so. The timing window is `--leg-correlation-window`. [Look up a command-line flag](/docs/cli/#dialog)
- **Filter language.** `--filter "<expr>"` selects dialogs and their RTP streams with fields, comparison operators and boolean logic, for example `state == 'Failed'` or `rtp.mos < 3.0`. The same language works in the REST API and the MCP tools. [Filter calls and streams](/docs/filter-dsl/)
- **Diagnostic shortcuts.** `--problems`, `--slow-setup`, `--short-calls`, `--one-way` and `--nat-issues` select the calls with that problem, without writing a filter. [Look up a command-line flag](/docs/cli/#diagnostic-aliases)
- **Text matching.** `-e <regex>` matches the raw message and then shows the rest of that dialog; `--from`, `--to`, `--contact` and `--ua` match single header fields. [Look up a command-line flag](/docs/cli/#matching)
- **Call-setup timing diagnosis.** Post-dial delay (the time from the INVITE to the first 180 Ringing or 183 Session Progress) over `--pdd-threshold`, a 2xx with no ACK after `--ack-timeout` ([RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) Timer H by default), and an INVITE with no final response after `--no-final-response-timeout` (RFC 3261 Timer C by default). [Look up a command-line flag](/docs/cli/#diagnosis-thresholds)
- **Ranked problem list for a whole capture.** `--analyze` prints every problem in the capture, worst first; `--json-analyze` gives the same result as one JSON object. [Look up a command-line flag](/docs/cli/#output)
- **RFC conformance linter.** `--lint` checks every dialog against rules that each cite an RFC section. `--lint-fail-on <severity>` makes sipnab exit with status 3 on a finding, for use in CI, and a `.sipnablint` file suppresses accepted findings. [Look up a SIP conformance rule](/docs/sip-lint-rules/)
- **STUN and TURN activity.** `--stun` reports each STUN and TURN transaction, whether the server answered, and the address it returned; `--json-stun` writes it as JSON. [Look up a command-line flag](/docs/cli/#output)
- **STIR/SHAKEN Identity headers.** `--stir-shaken` decodes the PASSporT token in the [RFC 8224](https://www.rfc-editor.org/rfc/rfc8224) Identity header and reports the attestation level, the originating and destination numbers and the origination ID. It does not verify the signature. [Look up a command-line flag](/docs/cli/#security)
- **DTMF digits.** `-t` decodes [RFC 4733](https://www.rfc-editor.org/rfc/rfc4733) telephone-event packets; sipnab masks the digit values unless you add `--dtmf-cleartext`. [Look up a command-line flag](/docs/cli/#mode)
- **Names instead of addresses.** `--names <hosts-file>` maps IP addresses to host names in every view. [Look up a command-line flag](/docs/cli/#name-resolution)

## RTP and media quality

<img src="/demos/08-rtp-tui.webp?v=9" width="1200" height="700" loading="lazy" decoding="async" alt="sipnab terminal UI listing RTP streams with per-stream jitter, loss and MOS">

- **Per-stream jitter, packet loss and estimated MOS.** MOS comes from the ITU-T G.107 E-model, with the G.107.1 wideband and G.107.2 fullband variants. The page lists which codecs have a published impairment factor behind the score. [Understand MOS and codecs](/docs/mos-and-codecs/)
- **Loss pattern.** Burst and gap analysis based on [RFC 3611](https://www.rfc-editor.org/rfc/rfc3611) tells loss that arrives in bursts from loss spread evenly across the call. [Look up a key binding](/docs/keybindings/#stream-detail)
- **RTCP and RTCP XR.** sipnab reads the endpoints' RTCP reports, including the RFC 3611 extended-report VoIP metrics block. [Look up a key binding](/docs/keybindings/#rtp-streams)
- **Quality over the life of the call.** A MOS, an R-factor and a verdict per interval of `--quality-interval` seconds. [Look up a command-line flag](/docs/cli/#rtp)
- **Media problems pointed out.** One-way audio, RTP from an address no SDP advertised (a NAT-rewritten source), media that starts later than `--late-media-ms` after the 200 OK, and legs whose durations differ. [Troubleshoot a call](/docs/troubleshooting/)
- **Your own quality bands.** `--jitter-warn-ms`, `--jitter-bad-ms`, `--loss-warn-pct`, `--loss-bad-pct`, `--mos-warn` and `--mos-bad` set where the quality column turns yellow and red. [Look up a command-line flag](/docs/cli/#quality-color-bands)
- **Quality dashboard.** In the terminal UI, `D` opens a live view of MOS, jitter and loss with the worst streams first. [Look up a key binding](/docs/keybindings/#quality-dashboard)
- **Listen to a stream or save it as WAV.** In the terminal UI, `F2` saves a stream's audio as WAV and `Shift+P` plays it (G.711, in builds with the `audio` feature). [Look up a key binding](/docs/keybindings/#rtp-streams)
- **Name the media on an rtpengine relay.** `--rtpengine-control <addr>` asks rtpengine which calls it holds, using its read-only `list` and `query` commands, so sipnab matches a stream on the relay to its call. [Let sipnab name rtpengine's media](/docs/rtpengine-sipnab/)
- **Relay statistics beside measured ones.** `--relay-stats` prints rtpengine's own counters, labeled `relay_reported`, and `--relay-compare <call-id>` puts the relay's packet count for a call beside the count sipnab measured. [Look up a command-line flag](/docs/cli/#rtp)
- **Name the media on an rtpproxy relay.** `--rtpproxy-control <addr:port>` reads rtpproxy's control traffic and pairs each relayed stream with its call. sipnab sends rtpproxy nothing. [Let sipnab name rtpproxy's media](/docs/rtpproxy-sipnab/)

## Security and attack detection

- **SIP scanner detection.** `--kill-scanner` detects scanners by known User-Agent signatures and by behavior (probe rate and extension enumeration), raises an alert, and sends the scanner a response. `--kill-ua` adds User-Agent patterns, and flags such as `--scanner-window` and `--scanner-unanswered-probes` set the thresholds. [Look up a command-line flag](/docs/cli/#security)
- **Toll-fraud heuristics.** `--fraud-detect` reports wangiri (short-call) patterns, sequential number scanning, call-volume spikes against a source's own baseline, calls to the countries named in `--fraud-destination`, and calls outside `--business-hours`. [Look up a command-line flag](/docs/cli/#security)
- **Registration floods.** `--reg-flood` reports a source whose REGISTER requests with credentials keep drawing 401 or 407, above `--reg-flood-threshold` per `--reg-flood-window`. [Look up a command-line flag](/docs/cli/#security)
- **Leaked digest credentials.** `--digest-leak` detects digest credential leaks in SIP messages. [Look up a command-line flag](/docs/cli/#security)
- **Alerts.** `--alert syslog|json|exec`, `--syslog` and `--alert-exec <cmd>` deliver security alerts, and alert rules take a threshold, window and cooldown. [Look up a command-line flag](/docs/cli/#security)
- **Findings for another system to act on.** `--evidence-out <path|->` writes every security finding that names a source as JSON Lines. sipnab takes no action on them. [Look up a command-line flag](/docs/cli/#security)
- **Firewall rules, recommended and not applied.** `--recommend-block fail2ban|nftables|iptables|all` prints a rule for every accused source, with the evidence for and against it. [Look up a command-line flag](/docs/cli/#security)
- **fail2ban output.** `--fail2ban` writes detections as lines a fail2ban jail reads; the filter and jail ship with sipnab. [Feed fail2ban from sipnab](/docs/fail2ban-sipnab/)
- **TFPS, read and controlled.** TFPS (a toll-fraud prevention system that blocks SIP sources in the kernel with XDP) answers queries through sipnab's REST API and MCP tools (`--tfps-ctl`). Bans through sipnab are off until `--allow-action` enables them, sipnab records every ban in a journal, `--journal-show` lists them and `--revert-actions` lifts them. [Let sipnab see and control TFPS](/docs/tfps-sipnab/)
- **Exports with pseudonyms.** `--redact` replaces identities, addresses and hostnames in an exported vCon with keyed pseudonyms that stay equal when the originals were equal, so patterns survive without the identities. [Look up a command-line flag](/docs/cli/#output)
- **Remove TLS secrets from a pcapng.** `--strip-secrets <output>` writes a copy of the input with every Decryption Secrets Block removed. [Look up a command-line flag](/docs/cli/#pcapng-metadata)
- **Reduced privileges.** Run as root, sipnab opens the capture device and then drops to `nobody` or the `--user` you name; `--chroot` and `--sandbox best-effort|required` (Linux Landlock file-access limits) restrict it further. `--setup-caps` grants the binary the capture capabilities so it runs without `sudo`. [Look up a command-line flag](/docs/cli/#privilege)

## Outputs and exports

- **Headless mode for scripts.** `-N` runs without the terminal UI and writes to standard output. [Triage a capture from the command line](/docs/first-cli-triage/)
- **NDJSON** (newline-delimited JSON, one object per line). `--json` writes one object per message, `--json-dialogs` one object per dialog. [Choose an output format](/docs/output-formats/)
- **Reports.** `--report` prints a summary after the capture, `--call-report <call-id>` a detailed report for one call, and `--markdown` formats either as Markdown. [Choose an output format](/docs/output-formats/)
- **YANG-encoded diagnosis.** `--yang-analyze` writes the `--analyze` result encoded per [RFC 7951](https://www.rfc-editor.org/rfc/rfc7951), validating against the `sipnab-diagnosis` YANG module. [Choose an output format](/docs/output-formats/#yang-export-yang-analyze)
- **Save from the terminal UI in several formats.** PCAP, PCAP-NG, TXT, JSON, NDJSON, CSV, Mermaid/HTML, Markdown, WAV, SIPp XML and RTP JSON, from the save dialog (`F2`). [Look up a key binding](/docs/keybindings/)
- **Mermaid sequence diagrams.** In a call's ladder, `E` copies the call as a Mermaid diagram. [Look up a key binding](/docs/keybindings/)
- **Group output.** `--group-by call-id|from|method` groups messages by a field. [Look up a command-line flag](/docs/cli/#output)
- **vCon export.** `--export-vcon <call-id>` writes one dialog as a vCon (a JSON container for one conversation, defined by IETF drafts); `--export-vcon-when "<filter>"` writes one for every matching dialog into `--export-vcon-dir`. Available in builds with the `vcon` feature (the gnu and macOS builds). [Export a call as a vCon](/docs/vcon/)
- **Frame pointers back to the bytes.** Dialog JSON, reports, the REST API and MCP carry a pointer to the frame each fact came from; `--show-frame <pointer>` prints that frame and, when the pointer carries a digest, refuses a capture that changed since. [Look up a command-line flag](/docs/cli/#pcapng-metadata)
- **Operator notes in the capture.** `C` in the terminal UI attaches a note to a message, and `--notes <file> --write-annotated <out>` writes a pcapng copy with each note as a packet comment. [Look up a command-line flag](/docs/cli/#operator-notes)
- **Run records.** `--run-provenance-file` records the command line that produced a run, and `--tui-audit-file` records what the operator did in the terminal UI, each as JSON Lines. [Look up a command-line flag](/docs/cli/#security)

## Integrations

- **Send HEP v3 to a collector.** `-H <addr>` (`--hep-send`) forwards SIP and RTCP over UDP, TCP or TLS (`--hep-send-transport`), with a capture-agent id (`--hep-id`) and an authentication key (`--hep-auth`). [HEP, fail2ban and syslog integrations](/docs/integrations/)
- **Prometheus metrics.** `--metrics <addr>` serves dialog and message counts, MOS, jitter, loss and post-dial delay histograms, and capture drop counters, with optional Basic authentication (`--metrics-auth-file`) and HTTPS (`--metrics-tls-cert`). [Scrape Prometheus metrics](/docs/metrics/)
- **Grafana dashboard.** An importable dashboard ships in the repository's `contrib` directory. [Add sipnab's metrics to Prometheus](/docs/prometheus-sipnab/)
- **Forward vCons to a vCon server.** `--vcon-forward <spool-dir>` delivers each container to `--vcon-forward-url` and sorts it by the server's answer; `--vcon-forward-compat vcon-store` adjusts the copy for vcon.store. `--vcon-fetch <uuid>` reads containers back. [Send sipnab's vCons to a vCon server](/docs/vcon-sipnab/)
- **Run a command on events.** `--on-dialog-exec <cmd>` runs on a dialog state change and `--on-quality-exec <cmd>` when RTP quality drops below `--quality-threshold`, bounded by `--exec-rate-limit`. [Look up a command-line flag](/docs/cli/#event-execution)
- **Beside OpenSIPS and Kamailio.** Step-by-step guides install sipnab on the proxy machine and follow one call through the proxy from both its legs. [Run sipnab beside OpenSIPS](/docs/opensips-sipnab/), [Run sipnab beside Kamailio](/docs/kamailio-sipnab/)
- **WASM plugins.** `--plugin <path>` loads your own dialog detections as sandboxed WebAssembly modules with no filesystem, network or clock access. In builds with the `plugins` feature (the gnu and macOS builds, not the static musl builds). [Add a detection with a WASM plugin](/docs/plugins/)
- **Rust library.** crates.io publishes the parser and analysis types as a library; its API is not stable. [Use sipnab as a Rust library](/docs/library/)

## Interfaces

- **Interactive terminal UI.** `sipnab -I capture.pcap` or `sudo sipnab -d eth0`: a dialog list, a call ladder with the parsed message beside it, and an RTP stream view (`Tab`). [Walk through the terminal UI](/docs/tui/)
- **Measure the gap between two messages.** `m` marks a message, and moving to another shows the time between them. [Look up a key binding](/docs/keybindings/)
- **Search and filter in the UI.** `/` searches Call-ID, method, From/To, addresses, state and the full message text; `F7` opens the filter dialog. [Look up a key binding](/docs/keybindings/)
- **Extended multi-leg flow.** `x` shows correlated B2BUA and session border controller legs in one ladder. [Look up a key binding](/docs/keybindings/)
- **Open another capture without restarting.** `O` opens the file dialog. [Look up a key binding](/docs/keybindings/)
- **Remappable keys and colors.** The `[keybindings]` and `[theme]` sections of the config file change the key bindings and the colors of the terminal UI. [Change the terminal UI colors](/docs/theme/)
- **REST API.** `--api <addr>` serves dialogs, streams and statistics over HTTP, with API-key or signed bearer-token authentication and optional HTTPS (`--api-tls-cert`). sipnab generates its OpenAPI 3.1 document from the request handlers. [Query the REST API](/docs/api/), [OpenAPI reference](/api-reference/)
- **MCP server for AI agents.** `--mcp` serves its tools over stdio, or over HTTP with `--mcp-transport http`, including beside the open terminal UI. The tools cover dialogs, call ladders, triage, RFC conformance, evidence pointers, leg correlation, RTP, security findings and vCon. [Connect an AI agent (MCP)](/docs/mcp/), [Look up an MCP tool](/docs/mcp-tools/)
- **MCP tool bundles.** `--mcp-tools core,media,...` registers only the bundles or tools an agent needs, which shortens the tool list it reads. [Look up an MCP tool](/docs/mcp-tools/#choosing-which-tools-load)
- **MCP write actions stay off by default.** Opening another capture, saving findings, kernel TLS capture and stopping the server each need their own flag (`--mcp-allow-open-capture`, `--mcp-allow-save-findings`, `--mcp-allow-tls-capture`, `--mcp-allow-shutdown`), and file tools work only inside `--mcp-file-root`. `--mcp-audit-file` records every tool call. [Check the MCP protocol contract](/docs/mcp-protocol/)
- **One server per capture host, many hosts per agent.** `--node-name` labels every MCP and REST answer with the machine that saw it. [Use MCP across many servers](/docs/mcp-estate/)
- **Token authentication.** `--mint-token` issues signed bearer tokens for the REST API and MCP with a scope (`full`, `metrics`, `read`, `actions`) and an expiry. [Authenticate API and MCP clients](/docs/auth/)
- **Analyze a capture in the browser.** The analyze page parses a pcap in the browser with WebAssembly. The page uploads nothing and needs nothing installed. [Analyze PCAP](/analyze/)

## Deployment and packaging

- **One-line install.** `curl -fsSL https://sipnab.com/install.sh | sh` installs the release binary and checks its sha256. [Install sipnab](/docs/install/)
- **Packages.** `.deb` and `.rpm` for x86_64 and aarch64 (with `-noaudio` variants for headless servers), Homebrew (`brew install NormB/tap/sipnab`), `cargo install sipnab --features full`, and a container image (`ghcr.io/normb/sipnab`). [Install sipnab](/docs/install/)
- **Static Linux binary.** The musl tarballs for x86_64 and aarch64 run on any Linux distribution and glibc version. They leave out audio playback, WASM plugins, vCon export and the eBPF uprobe backend. [Install sipnab](/docs/install/)
- **macOS.** Tarballs for Intel and Apple Silicon. [Install sipnab](/docs/install/)
- **Size ceiling enforced at release.** The release workflow fails if the stripped static musl binary is larger than its published size ceiling, which the install page states. [Install sipnab](/docs/install/)
- **Verifiable downloads.** Every release artifact is checksummed, carries signed build provenance, and ships with a CycloneDX SBOM (software bill of materials); the Linux gnu binary can be rebuilt from its tag to the same bytes. [Verify a download is genuine](/docs/install/#verify-a-download-is-genuine)
- **Multi-core file reading.** `--cores N` splits offline capture reading by host pair. [Check how fast sipnab is](/docs/benchmarks/)
- **TOML configuration.** `-f <file>` loads a config file, command-line flags override it, and `-D` prints the effective configuration. [Configure sipnab](/docs/config/)
- **Shell completions.** `--completions bash|zsh|fish|elvish|powershell`. [Look up a command-line flag](/docs/cli/#config)
