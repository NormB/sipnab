# Architecture

How sipnab turns captured packets into calls, media streams and findings, and
where each answer surface reads them from. Read this to understand what a
setting such as `--cores`, `--limit` or `--no-reassembly` changes.

Contributors changing the code want the [code map](internals/code-map.md):
the module layout, the design decisions and where to add things.

## One binary, two run modes

`sipnab` is a single binary. It runs in one of two modes:

- as a **TUI**, an interactive terminal interface (the default),
- or in **batch mode** with `-N`: read, print or export, then exit.

Both modes run the same analysis.

## Four ways to read the answer

The run mode decides who drives the capture. It does not decide who can ask
about it. The same analysis is readable over four surfaces at once:

| Surface | Flag | Who asks |
|---|---|---|
| Terminal | default | A person at a TUI, or a script reading text/JSON/NDJSON |
| REST API | `--api` | Another program, over HTTP |
| MCP | `--mcp`, plus `--mcp-transport http` to serve it over HTTP | An AI agent, calling Model Context Protocol tools |
| Prometheus | `--metrics` | A scraper |

- All four read the same dialog and stream tables, so they report the same
  calls.
- An MCP client or REST client can query a live capture while it is still
  running.
- No MCP tool changes the analysis.

## The processing pipeline

```text
capture sources                 per-packet path                         tables
───────────────                 ───────────────                         ──────
live device (-d) ─┐
capture file (-I)─┼──► decapsulation, IP fragment and ──► SIP, RTCP ──► dialogs ◄── SDP ──► RTP streams
HEP listener (-L)─┘    TCP reassembly, SIP framing         or RTP           ▲                     ▲
                                                                            └── terminal, REST, MCP, Prometheus
```

Each packet goes through these steps:

1. **Capture.** A live interface (`-d`), one or more capture files (`-I`), or
   a HEP listener (`-L`) that receives copies from Kamailio, OpenSIPS,
   Asterisk or rtpengine.
2. **Decapsulation.** sipnab strips the link layer, VLAN tags and the tunnels
   listed in [Encapsulations](encapsulations.md). A frame it cannot decode is
   counted in the `NOT DECODED` line at the end of the run.
3. **Reassembly.** sipnab joins IP fragments and TCP segments, so a SIP message
   split across packets reads as one message. `--no-reassembly` turns this off.
4. **Classification.** sipnab unwraps SIP over WebSocket, then reads the
   payload as SIP, RTCP or RTP.
5. **Tables.** SIP messages join dialogs by Call-ID. RTP packets join streams
   by SSRC. The SDP in a dialog links its streams to it. An RTP stream with
   no SIP in the capture still appears as a stream.
6. **Readers.** The terminal, the REST API, MCP and Prometheus read the two
   tables.

## Memory limits

The dialog and stream tables have fixed ceilings, so a flood of unique
Call-IDs or SSRCs cannot exhaust memory:

| Setting | Default | At the ceiling |
|---|---|---|
| `--limit` | 100000 dialogs over the run | sipnab evicts the oldest dialog. With `--no-rotate`, it drops new dialogs instead. |
| `--max-streams` | 50000 streams | sipnab evicts the oldest stream. |

`--limit` counts every dialog the run has seen, completed ones included, so a
long-running capture reaches it even at low call volume.
[Fault model](fault-model.md) lists every bound.

## Multiple cores

With `-I` and `--cores N`, sipnab reads the capture once and splits the
packets across N worker threads by host pair. Each worker builds its own
tables, and sipnab merges them at the end of the file. That mode prints the
whole-capture views (`--report`, `--json-dialogs`, `--analyze`,
`--call-report`) and no per-message lines. [Benchmarks](benchmarks.md)
measures how it scales.

Live capture and a file read without `--cores` use one processing thread.

## Privileges

- sipnab sets `PR_SET_NO_NEW_PRIVS` at startup in every run mode, so no child
  process it starts can gain privileges.
- When started as root, it drops root right after opening the capture socket.
  `--user` names the account it drops to.
- It disables core dumps whenever it holds decryption keys.
- `--chroot` confines a long-running daemon to one directory.
- The scanner-kill response runs in a separate process that holds the only
  sockets it sends through.
- The REST API and MCP servers run inside the main process, which also holds
  the capture data, TLS key material and bearer tokens. Treat the API bind
  address and key accordingly.

## Malformed input

A malformed packet or capture file never stops the run: sipnab marks the
message as a parse error and continues. The project fuzzes the parsers that
read captured bytes, with 20 targets. [Fault model](fault-model.md) describes each
failure class and how sipnab behaves under it.
