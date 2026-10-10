+++
title = "Compare"
description = "What sipnab and four other SIP and RTP tools do, cell by cell, from each tool's own documentation, and what sipnab does not do."
template = "overview.html"
+++

This page lists what sipnab and four other tools do for SIP and RTP
troubleshooting, as each tool's own documentation describes it. SIP (Session
Initiation Protocol) is the signaling protocol that sets up and ends voice
calls. RTP (Real-time Transport Protocol) carries the call audio, and RTCP (RTP
Control Protocol) carries reports about that audio. HEP (Homer Encapsulation
Protocol) is a format SIP proxies and capture agents use to copy packets to a
collector over the network.

Every cell comes from the tool's own documentation, man page, or source
repository, retrieved on 2026-10-09. A cell that reads "not documented" means
the official sources checked for this page do not state the capability either
way. It does not mean the tool lacks it. Corrections with a source are welcome.

## The tools

- **sipnab** reads SIP signaling "from a live network interface, a pcap
  (packet capture) file, or a HEP feed", and "is one binary with no database
  and no web UI to run".[^s-what]
- **Wireshark** "is a network packet analyzer"; **tshark** is its command-line
  form, described as "Dump and analyze network traffic".[^w-what]
- **sngrep** "is a terminal tool that groups SIP (Session Initiation Protocol)
  Messages by Call-Id, and displays them in arrow flows similar to the used in
  SIP RFCs".[^n-what]
- **Homer** (version 11, from the sipcapture project) is "the *all-in-one* HEP
  capture and API server monolith powering Homer 11.x data lake". Packets reach
  it from capture agents such as heplify, which captures packets "and send[s]
  them to Homer".[^h-what]
- **Pcaptix** is a product of Sevana that "turns a packet capture into clear
  VoLTE call quality analysis, and it handles ordinary VoIP just as
  well".[^p-what] VoLTE (Voice over LTE) is voice over a mobile operator's IMS
  (IP Multimedia Subsystem) network.

## Feature matrix

"Partial" cells carry a note in parentheses. Footnotes give the source and the
quoted text.

| Capability | sipnab | Wireshark / tshark | sngrep | Homer 11 | Pcaptix |
|---|---|---|---|---|---|
| Live capture from a network interface | yes[^s-live] | yes[^w-live] | yes[^n-live] | no (HEP agents such as heplify capture and send to Homer)[^h-live] | no (offline files; Sevana names a separate product for live traffic)[^p-live] |
| Read pcap or pcapng files | yes[^s-file] | yes[^w-file] | yes (pcap)[^n-file] | partial (heplify reads a pcap file and sends it to Homer; Homer exports SIP as pcap)[^h-file] | yes[^p-file] |
| Receive HEP | yes (v1, v2, v3)[^s-heprx] | not documented[^w-heprx] | yes (build option)[^n-heprx] | yes (UDP, TCP, TLS, HTTP, HTTPS)[^h-heprx] | not documented |
| Send HEP | yes (v3 over UDP, TCP or TLS)[^s-heptx] | no[^w-heptx] | yes (build option)[^n-heptx] | not documented for the server; heplify sends HEP[^h-heptx] | not documented |
| SIP call-flow (ladder) diagram | yes[^s-ladder] | yes[^w-ladder] | yes[^n-ladder] | yes[^h-ladder] | yes[^p-ladder] |
| RTP stream statistics (jitter, loss) | yes[^s-rtp] | yes[^w-rtp] | partial (captures RTP payload; statistics not documented)[^n-rtp] | not documented (stores HEP RTP and RTCP tables)[^h-rtp] | yes[^p-rtp] |
| MOS (mean opinion score) | yes (ITU-T G.107 E-model estimate)[^s-mos] | not documented[^w-mos] | not documented[^n-mos] | partial (stores MOS from endpoint RTCP-XR reports)[^h-mos] | yes (perceptual and network-estimated)[^p-mos] |
| RTCP | yes (including RTCP XR)[^s-rtcp] | yes (dissector)[^w-rtcp] | not documented[^n-mos] | yes[^h-rtcp] | not documented |
| Audio playback of RTP | yes[^s-play] | yes[^w-play] | not documented | not documented | yes[^p-play] |
| Decryption of encrypted SIP or media | yes (TLS key log, RSA key, SRTP, DTLS-SRTP)[^s-tls] | yes (TLS key log, RSA key)[^w-tls] | partial (RSA private key; "partially TLS")[^n-tls] | not documented (TLS is a HEP transport)[^h-heprx] | partial (IPsec ESP in the Desktop edition)[^p-tls] |
| Conformance lint against RFC sections | yes (rules cite RFC sections)[^s-lint] | partial (Expert Information flags protocol violations; no RFC section cited)[^w-lint] | not documented | not documented | not documented |
| Scanner or attack detection | yes[^s-scan] | no[^w-scan] | not documented | not documented | not documented |
| Calls from many hosts in one view | yes (one HEP listener, many senders)[^s-multi] | partial (remote capture over SSH with sshdump)[^w-multi] | partial (listens for HEP)[^n-heprx] | yes[^h-multi] | not documented |
| On-disk storage and retention | partial (in-memory store; pcap output with a file-count ring buffer)[^s-store] | partial (tshark ring buffer of capture files)[^w-store] | partial (writes pcap; reopens the file on SIGUSR1 for rotation)[^n-store] | yes (DuckLake/Parquet with age-based expiry)[^h-store] | not documented |
| Web UI | no (sipnab.com hosts a separate in-browser pcap reader)[^s-web] | not documented | no (terminal interface)[^n-what] | yes[^h-web] | yes (Web edition)[^p-web] |
| Multi-user accounts | no[^s-users] | not documented | not documented | yes (internal, LDAP, OAuth2)[^h-users] | not documented |
| Database required | no[^s-web] | not documented | not documented | yes (DuckDB / DuckLake)[^h-db] | not documented |
| Automation interface | yes (CLI, JSON, REST API)[^s-auto] | yes (tshark JSON and field output; embedded Lua)[^w-auto] | partial (no-interface mode)[^n-auto] | yes (REST API, search CLI, Lua correlation)[^h-auto] | partial (CSV and PDF export)[^p-auto] |
| AI-agent (MCP) interface | yes[^s-mcp] | not documented | not documented | yes[^h-mcp] | not documented (has an LLM assistant for OpenAI-compatible endpoints)[^p-mcp] |
| License | MIT or Apache-2.0[^s-lic] | GPL version 2[^w-lic] | GPL version 3 or later, with an OpenSSL exception[^n-lic] | AGPL-3.0[^h-lic] | free download; commercial licensing on request[^p-lic] |
| Platforms | Linux (x86_64, aarch64), macOS[^s-plat] | Windows, macOS, UNIX, Linux, BSD[^w-plat] | Linux distributions, macOS, OpenWrt[^n-plat] | Linux, macOS (x64, ARM64)[^h-plat] | Windows 10+, Ubuntu 20.04+, Debian 11+, browser[^p-plat] |

MOS (mean opinion score) is a 1-to-5 rating of how a call sounded. The ITU-T
G.107 E-model estimates it from network measurements. A perceptual score comes from the decoded audio. RTCP XR ([RFC 3611](https://www.rfc-editor.org/rfc/rfc3611)) is an RTCP extension that
carries extended reports, including quality metrics an endpoint computed itself.
MCP (Model Context Protocol) is a protocol through which an AI agent calls a
program's functions as tools.

## What sipnab does not do

These limits come from sipnab's positioning decision
([docs/design/positioning.md](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/docs/design/positioning.md))
and from its README, checked against the source at commit [`72219b46`](https://github.com/NormB/sipnab/tree/72219b460e6d8b4e4408c6fc80dbaa96cb377f09).

- **No database, web UI, multi-user authentication, dashboards or alert
  history.** The positioning decision rules these out: "if a feature requires
  sipnab to be _operated_ rather than _run_, it is out of position"
  ([`docs/design/positioning.md:99-102`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/docs/design/positioning.md#L99-L102)). Security alerts go to syslog, JSON or
  a command of the operator's choosing ([`README.md:245-247`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/README.md#L245-L247)).
- **No searchable on-disk history.** sipnab keeps what it sees in memory
  ([`README.md:21`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/README.md#L21)). The in-memory store holds 100,000 dialogs by default and
  evicts the oldest first ([`src/cli.rs:1728-1756`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/src/cli.rs#L1728-L1756)). `--split` rotates pcap
  output and `--split-keep N` keeps only the newest N files, which makes the
  output a ring buffer ([`src/cli.rs:815-829`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/src/cli.rs#L815-L829), released in 0.5.100). Nothing
  indexes those files for search.
- **No audio quality from a HEP feed alone.** A proxy's HEP feed carries SIP
  signaling, not call audio ([`README.md:151-152`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/README.md#L151-L152)). sipnab files an RTCP report
  only against a stream whose media it has already seen, so a listener fed
  only by HEP decodes RTCP but shows no quality figure
  ([`docs/design/positioning.md:73-80`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/docs/design/positioning.md#L73-L80)). For audio quality, sipnab must also see
  the media, on the same host as the media or from a capture file.
- **No RTP forwarding over HEP.** `--hep-send` sends "SIP as protocol type 1,
  RTCP as type 5, nothing else" ([`src/app/batch.rs:4286-4287`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/src/app/batch.rs#L4286-L4287)).
- **No Windows build.** Releases are for Linux (x86_64, aarch64) and macOS
  ([`README.md:31`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/README.md#L31), [`docs/install.md:100-105`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/docs/install.md#L100-L105)).
- **No session recording.** sipnab reads SIPREC recording metadata ([RFC 7866](https://www.rfc-editor.org/rfc/rfc7866))
  but "is not a recording client or server" ([`README.md:262-264`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/README.md#L262-L264)).

[^s-what]: sipnab [`README.md:9-11`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/README.md#L9-L11) and [`README.md:18`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/README.md#L18).
[^s-live]: sipnab [`src/cli.rs:573-577`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/src/cli.rs#L573-L577) (`-d`/`--device`); [`README.md:113`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/README.md#L113).
[^s-file]: sipnab [`src/cli.rs:592-597`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/src/cli.rs#L592-L597) (`-I`/`--input`); [`README.md:280`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/README.md#L280): "Reads and writes pcap and pcapng".
[^s-heprx]: sipnab [`src/cli.rs:3851-3856`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/src/cli.rs#L3851-L3856) (`-L`/`--hep-listen`); [`README.md:250`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/README.md#L250): "HEP v3 send over UDP, TCP or TLS, and HEP v1/v2/v3 receive".
[^s-heptx]: sipnab [`src/cli.rs:3857-3865`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/src/cli.rs#L3857-L3865) (`-H`/`--hep-send`); [`README.md:250`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/README.md#L250).
[^s-ladder]: sipnab [`README.md:293`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/README.md#L293): "Call flow ladder with color-coded arrows, SDP codecs, and PDD".
[^s-rtp]: sipnab [`README.md:240`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/README.md#L240): "RTP quality. Jitter, loss, MOS".
[^s-mos]: sipnab [`src/rtp/quality.rs:43`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/src/rtp/quality.rs#L43): "Estimate Mean Opinion Score using the simplified E-model (ITU-T G.107)."
[^s-rtcp]: sipnab [`README.md:243`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/README.md#L243): "RTCP XR (RFC 3611) reports"; [`src/rtp/stream_store.rs:931`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/src/rtp/stream_store.rs#L931) (`process_rtcp`); [`src/capture/hep.rs:69`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/src/capture/hep.rs#L69) (HEP protocol type "5=RTCP").
[^s-play]: sipnab [`README.md:300-301`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/README.md#L300-L301): "RTP streams with jitter, loss and MOS (Tab), audio playback, and WAV export (F2)".
[^s-tls]: sipnab [`README.md:251-255`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/README.md#L251-L255); [`src/cli.rs:4108-4119`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/src/cli.rs#L4108-L4119) (`--tls-key`, `--keylog`). Requires the `tls` build feature ([`README.md:339`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/README.md#L339)).
[^s-lint]: sipnab [`src/cli.rs:1590-1600`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/src/cli.rs#L1590-L1600) (`--lint`); [`docs/sip-lint-rules.md:1-9`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/docs/sip-lint-rules.md#L1-L9).
[^s-scan]: sipnab [`README.md:245`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/README.md#L245): "Scanner detection, registration floods, digest credential leaks, STIR/SHAKEN, and fraud heuristics"; [`src/cli.rs:2012-2014`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/src/cli.rs#L2012-L2014).
[^s-multi]: sipnab [`README.md:19-21`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/README.md#L19-L21): "have every proxy in a cluster send it HEP, so one listener sees calls across many nodes".
[^s-store]: sipnab [`README.md:21`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/README.md#L21); [`src/cli.rs:815-829`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/src/cli.rs#L815-L829) (`--split`, `--split-keep`); [`src/cli.rs:1728-1756`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/src/cli.rs#L1728-L1756) (`--limit`).
[^s-web]: sipnab [`README.md:18`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/README.md#L18): "one binary with no database and no web UI to run"; [`README.md:24-25`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/README.md#L24-L25): "sipnab.com/analyze reads a pcap in your browser without uploading it".
[^s-users]: sipnab [`docs/design/positioning.md:99`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/docs/design/positioning.md#L99): "A database. A web UI. Multi-user authentication. Dashboards. Alert history." (listed under what the position forbids).
[^s-auto]: sipnab [`README.md:22`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/README.md#L22): "its terminal view, a command line, a REST API, and an MCP server"; [`src/cli.rs:2799-2801`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/src/cli.rs#L2799-L2801) (`--api`).
[^s-mcp]: sipnab [`README.md:282`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/README.md#L282): "MCP server. 72 tools over stdio or HTTP"; [`src/cli.rs:2994-3000`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/src/cli.rs#L2994-L3000).
[^s-lic]: sipnab [`Cargo.toml:48`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/Cargo.toml#L48): `license = "MIT OR Apache-2.0"`.
[^s-plat]: sipnab [`README.md:31`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/README.md#L31); [`docs/install.md:100-105`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/docs/install.md#L100-L105).

<!-- vale off -->

<!-- The footnotes below quote other tools' documentation verbatim. -->

[^w-what]: Wireshark User's Guide, chapter 1, <https://www.wireshark.org/docs/wsug_html_chunked/ChapterIntroduction.html>; tshark man page, <https://www.wireshark.org/docs/man-pages/tshark.html>.
[^w-live]: <https://www.wireshark.org/docs/wsug_html_chunked/ChapterIntroduction.html>: "Capture live packet data from a network interface."
[^w-file]: Same page: "Open files containing packet data captured with tcpdump/WinDump, Wireshark, and many other packet capture programs."
[^w-heprx]: The Display Filter Reference index, <https://www.wireshark.org/docs/dfref/>, has no HEP or EEP protocol entry (checked 2026-10-09).
[^w-heptx]: <https://www.wireshark.org/docs/wsug_html_chunked/ChapterIntroduction.html>, section 1.1.8: "Wireshark doesn’t send packets on the network or do other active things".
[^w-ladder]: <https://www.wireshark.org/docs/wsug_html_chunked/ChTelSIPFlows.html>: "Session Initiation Protocol (SIP) Flows window shows the list of all captured SIP transactions"; <https://www.wireshark.org/docs/wsug_html_chunked/ChStatFlowGraph.html>: "Flow Graph window showing VoIP call sequences".
[^w-rtp]: <https://www.wireshark.org/docs/wsug_html_chunked/ChTelRTP.html>: "Jitter (ms)" and "Count of lost packets - calculated from sequence numbers".
[^w-mos]: The term MOS does not appear in ChTelRTP.html, ChTelVoipCalls.html or ChTelPlayingCalls.html of the Wireshark User's Guide (checked 2026-10-09).
[^w-rtcp]: <https://www.wireshark.org/docs/dfref/r/rtcp.html>: "Display Filter Reference: Real-time Transport Control Protocol".
[^w-play]: <https://www.wireshark.org/docs/wsug_html_chunked/ChTelRTP.html>: "The RTP Player function is a tool for playing VoIP calls."
[^w-tls]: Wireshark wiki, <https://wiki.wireshark.org/TLS>: "Key log file using per-session secrets" and "Decryption using an RSA private key."
[^w-lint]: <https://www.wireshark.org/docs/wsug_html_chunked/ChAdvExpert.html>: group "Protocol": "Violation of a protocol’s specification (e.g., invalid field values or illegal lengths)." The same page: "Expert information is only a hint".
[^w-scan]: <https://www.wireshark.org/docs/wsug_html_chunked/ChapterIntroduction.html>, section 1.1.8: "Wireshark isn’t an intrusion detection system."
[^w-multi]: <https://www.wireshark.org/docs/man-pages/sshdump.html>: "Provide interfaces to capture packets from a remote host through SSH using a remote capture binary."
[^w-store]: <https://www.wireshark.org/docs/man-pages/tshark.html>: "-b|--ring-buffer" and "With the files option it’s also possible to form a "ring buffer"."
[^w-auto]: <https://www.wireshark.org/docs/man-pages/tshark.html>: "-T ek|fields|json|jsonraw|pdml|ps|psml|tabs|text"; <https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm.html>: "Wireshark contains an embedded Lua interpreter".
[^w-lic]: <https://www.wireshark.org/docs/wsug_html_chunked/ChIntroMaintenance.html>: "released under the GNU General Public License (GPL) version 2".
[^w-plat]: <https://www.wireshark.org/docs/wsug_html_chunked/ChIntroPlatforms.html>: sections "1.3.1. Microsoft Windows", "1.3.2. macOS", "1.3.3. UNIX, Linux, and BSD".
[^n-what]: sngrep man page, <https://github.com/irontec/sngrep/blob/master/doc/sngrep.8>, DESCRIPTION.
[^n-live]: sngrep README, <https://github.com/irontec/sngrep/blob/master/README>: "It supports live capture".
[^n-file]: sngrep man page: `-I pcap_dump Read packets from pcap file instead of network devices.`
[^n-heprx]: sngrep man page: `-L Listen for encapsulated packets (udp:X.X.X.X:XXXX).` and `-E Enable parsing of captured HEP3 packets.`; README: `--enable-eep Enable EEP packet send/receive support.`
[^n-heptx]: sngrep man page: `-H Homer sipcapture url (udp:X.X.X.X:XXXX).`; README `--enable-eep` as above.
[^n-ladder]: sngrep man page, Call Flow Window: "a flow diagram of the selected dialogs' messages".
[^n-rtp]: sngrep man page: "-r Capture RTP packets payload." and "-t Capture and parse RTP telephone-event packets."
[^n-mos]: The terms MOS, RTCP and jitter do not appear in the sngrep man page (checked 2026-10-09).
[^n-tls]: sngrep man page: "It recognizes UDP, TCP and partially TLS SIP packets" and "-k keyfile RSA private keyfile to decrypt captured packets."
[^n-store]: sngrep man page: `-O pcap_dump Save all captured packets to a pcap file.` and `When receiving a SIGUSR1 signal sngrep will reopen the pcap file in order to facilitate pcap file rotation.`
[^n-auto]: sngrep man page: "-N Don't display sngrep interface, just capture."
[^n-lic]: sngrep README, License: "either version 3 of the License, or (at your option) any later version" and "as a special exception, the copyright holders give permission to link the code of portions of this program with the OpenSSL library".
[^n-plat]: sngrep README, Installing, Binaries: Debian / Ubuntu, CentOS / RedHat / Fedora, Alpine Linux, Gentoo, Arch, OSX, OpenWRT/LEDE.
[^h-what]: Homer README (branch homer11), <https://github.com/sipcapture/homer/blob/homer11/README.md>; heplify README, <https://github.com/sipcapture/heplify/blob/master/README.md>.
[^h-live]: Homer README: Ingest "Receives HEP packets via UDP/TCP/TLS/HTTP/HTTPS"; heplify README: "a single binary which you can run on Linux, macOS and Windows to capture IPv4 or IPv6 packets and send them to Homer".
[^h-file]: heplify README: "-rf string Read from pcap file"; Homer README: "Export SIP messages to a pcap file".
[^h-heprx]: Homer README, Modules table: "Receives HEP packets via UDP/TCP/TLS/HTTP/HTTPS".
[^h-heptx]: heplify README: "Heplify can send SIP, correlated RTCP, DNS, Diameter and Logs into homer."
[^h-ladder]: Homer README: a `homer search` example that passes `--format callflow`, with the comment "Search INVITE messages with call flow diagram".
[^h-rtp]: Homer [`docs/STORAGE_LAYOUT.md`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/docs/STORAGE_LAYOUT.md), <https://github.com/sipcapture/homer/blob/homer11/docs/STORAGE_LAYOUT.md>: "hep_proto_35_default/ # RTP".
[^h-mos]: Homer [`docs/VQRTCP.md`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/docs/VQRTCP.md), <https://github.com/sipcapture/homer/blob/homer11/docs/VQRTCP.md>: "Homer can accept SIP messages carrying `application/vq-rtcpxr` bodies on a dedicated SIP listener and store parsed QoS reports" with key column "`mos`". Disabled by default.
[^h-rtcp]: Homer [`docs/STORAGE_LAYOUT.md`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/docs/STORAGE_LAYOUT.md): "hep_proto_5_default/ # RTCP JSON".
[^h-multi]: Homer [`docs/LUA_CORRELATION.md`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/docs/LUA_CORRELATION.md), <https://github.com/sipcapture/homer/blob/homer11/docs/LUA_CORRELATION.md>: "merge related dialogs (B2B legs, retransmitted REGISTERs, cross-node transactions, …) into a single transaction view".
[^h-store]: Homer [`docs/RETENTION.md`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/docs/RETENTION.md), <https://github.com/sipcapture/homer/blob/homer11/docs/RETENTION.md>: "Delete data older than N days"; README: "Powered by DuckDB 1.5 and Apache Arrow/IPC/Parquet".
[^h-web]: Homer README: "Built-In User Interface for Humans".
[^h-users]: Homer [`docs/AUTH_LDAP_AND_OAUTH.md`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/docs/AUTH_LDAP_AND_OAUTH.md), <https://github.com/sipcapture/homer/blob/homer11/docs/AUTH_LDAP_AND_OAUTH.md>: "local (internal) authentication", "LDAP / Active Directory password login and OAuth2 redirects".
[^h-db]: Homer README: "Powered by DuckDB 1.5 and Apache Arrow/IPC/Parquet" and "Storage | Writes data to DuckLake (Parquet + catalog)".
[^h-auto]: Homer README: "Coordinator | REST API gateway for UI and external applications" and "homer search [flags] Search Homer data via coordinator API"; [`docs/LUA_CORRELATION.md`](https://github.com/NormB/sipnab/blob/72219b460e6d8b4e4408c6fc80dbaa96cb377f09/docs/LUA_CORRELATION.md): "coordinator-side Lua correlation engine".
[^h-mcp]: Homer README: "MCP support and LLM/Agent friendly design" and "homer mcp [flags] Start MCP stdio server".
[^h-lic]: Homer README: "Released under the [AGPL-3.0 License](LICENSE.md)".
[^h-plat]: Homer README: "for X64/ARM64 on Linux/MacOS".
[^p-what]: Sevana, Pcaptix product page, <https://sevana.biz/our-products-pcaptix/>. The page at <https://pcaptix.com/> returned only a title on 2026-10-09, so this page cites Sevana's product page.
[^p-live]: <https://sevana.biz/our-products-pcaptix/>: "For continuous monitoring of live traffic rather than offline captures, see VQ Monitor".
[^p-file]: Same page: "Pcaptix reconstructs calls from .pcap and .pcapng".
[^p-ladder]: Same page, on the Call Flow tab: "as a ladder between the discovered user agents and proxies".
[^p-rtp]: Same page: "reports a dual MOS alongside R-factor, jitter, delay, packet loss and illegal-packet counters".
[^p-mos]: Same page: "Sevana MOS reflects the decoded audio, whereas Network MOS estimates quality from loss, jitter and delay."
[^p-play]: Same page: "call flow, stream detail, dual MOS, timeline, waveform, markers, playback, and PDF or CSV export".
[^p-tls]: Same page: "The Desktop edition decrypts that traffic" (IPsec ESP on the Gm interface) and "ESP decryption is available in the Pcaptix Desktop edition from version 0.6.5".
[^p-web]: Same page: "Pcaptix ships as both a browser app and a native desktop build".
[^p-auto]: Same page: "PDF or CSV export".
[^p-mcp]: Same page: "point Pcaptix at any OpenAI-compatible backend, including a local one".
[^p-lic]: Same page: "The Windows installer and the Linux AppImage download free of charge" and "For commercial licensing or an online demo, simply get in touch."
[^p-plat]: Same page: "run without extra dependencies on Windows 10 or later and on Ubuntu 20.04+, Debian 11+ and compatible distributions"; "browser app".

<!-- vale on -->
