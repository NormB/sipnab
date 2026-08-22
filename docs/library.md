# Using sipnab as a library

sipnab is primarily a CLI/TUI tool, but its analysis engine is a
published Rust crate. The curated public API is re-exported at the crate
root. Anything under a `#[doc(hidden)]` module (`cli`, `tui`, `privilege`,
…) is binary-internal and carries **no** semver guarantee.

```toml
[dependencies]
sipnab = { version = "0.5", default-features = false, features = ["native"] }
```

## Crate-root surface

| Item | What it is |
|---|---|
| `PcapReader` | Pure-Rust pcap/pcapng reader (iterator of packets) |
| `decompress_capture` | Transparent, bounded gunzip for gzip-compressed captures |
| `sip::parser::parse_sip` / `parse_sip_bytes` | Parse raw bytes → `SipMessage` |
| `capture::parse::parse_packet` | Decode a captured `Packet` → `ParsedPacket` |
| `rtp::parser::parse_rtp_header` | Parse an RTP header |
| `sip::sdp::parse_sdp` | Parse an SDP body |
| `DialogStore` / `StreamStore` | Capped, indexed dialog / RTP-stream stores (both `Debug`) |
| `SipMessage`, `SipDialog`, `RtpStream` | Core value types |
| `FilterExpr` | Compiled filter-DSL expression |
| `estimate_mos` | E-model MOS from jitter/loss/codec |

`PcapReader` yields the capture file's own records. `parse_packet` decodes a
`Packet`, which is the same frame plus the facts only the caller can supply —
the timestamp at full resolution, the captured-vs-wire lengths, and the link
type, which a multi-interface pcapng varies **per packet** rather than per
file. Building that bridge is the one step between a path and a parsed frame:

```rust
use sipnab::PcapReader;
use sipnab::capture::Packet;
use sipnab::capture::parse::parse_packet;

fn payload_bytes(path: &str) -> Result<usize, Box<dyn std::error::Error>> {
    let data = std::fs::read(path)?;
    let mut total = 0;

    for pkt in PcapReader::new(&data)? {
        let timestamp = chrono::DateTime::from_timestamp(
            pkt.timestamp_secs as i64,
            pkt.timestamp_usecs * 1000,
        )
        .unwrap_or_default();
        let caplen = pkt.data.len();
        let origlen = pkt.orig_len as usize;
        let link_type = pkt.link_type as i32;

        let frame =
            Packet::new(timestamp, pkt.data, caplen, origlen, pkt.interface, link_type);

        // A capture holds frames sipnab does not decode — ARP, a truncated
        // header, an unsupported link type. That is an `Err` per frame, not a
        // failed read: skipping it silently is how a partial result comes to
        // look like a clean one.
        if let Ok(parsed) = parse_packet(&frame) {
            total += parsed.payload.len();
        }
    }

    Ok(total)
}
```

## Error handling

The parsing and capture entry points return **typed, matchable** error
enums — not `anyhow::Result`. All three are `#[non_exhaustive]`
`thiserror` enums (`std::error::Error`), so you can propagate them into
`anyhow`/`Box<dyn Error>` unchanged, or match on their variants.

| Function | Returns |
|---|---|
| `parse_sip`, `parse_sip_bytes`, `parse_rtp_header`, `parse_sdp` | `Result<_, ParseError>` |
| `parse_packet`, `PcapReader::new` | `Result<_, CaptureError>` |
| `config::Config::load`, address/rule/CIDR parsing | `Result<_, Error>` |

- **`ParseError`** — protocol parsers. Variants include
  `Empty { what }`, `TooShort { what, need, got }`, `InvalidUtf8 { what }`,
  `MissingCrlf`, `NotSip { line }`, `InvalidStatusCode { code }`,
  `BadRtpVersion { version }`, `SdpMissingVersion`,
  `BadSdpVersion { version }`.
- **`CaptureError`** — capture-file / packet decode. Variants include
  `TooShort { what, need, got }`, `UnsupportedLinkType(i32)`,
  `EncapTooDeep { kind, limit }`, `NotIp { what }`, `NoTransport`,
  `Icmp`, `NetMonFormat`, `UnknownFormat { magic }`.
- **`Error`** — config/CLI/validation surface. `ConfigRead` /
  `ConfigParse` chain the underlying `std::io::Error` / `toml::de::Error`
  via `#[source]`.

Match on variants rather than message text:

```rust
use sipnab::ParseError;
use sipnab::rtp::parser::parse_rtp_header;

match parse_rtp_header(&[0x80, 0x00]) {
    Err(ParseError::TooShort { need, got, .. }) => {
        eprintln!("need {need} bytes, got {got}");
    }
    Ok(header) => { /* use header */ }
    Err(e) => eprintln!("parse failed: {e}"),
}
```

Because every one of these enums is `#[non_exhaustive]`, a downstream
`match` **must** include a wildcard arm — sipnab can add a variant in a
minor release without it being a breaking change. Sixteen other public
enums (`TransportProto`, `RtcpPacket`, `FraudType`, `CipherSuite`, …) are
`#[non_exhaustive]` for the same reason.

## Worked examples

Three of the programs in [`examples/`](../examples/) take the library path:
they run against a real capture and print a real answer. Each exists because
it demonstrates something a doctest on this page structurally cannot — state
accumulated across a whole file. (The other two, `uprobe_discover` and
`uprobe_sock_offsets`, report on the host rather than a capture.)

| Example | Run it against | What it is for |
|---|---|---|
| [`call_summary.rs`](../examples/call_summary.rs) | any capture with SIP | The path above carried to its end: file → frame → message → **call**. Dialog state is what you learn from every packet in order, so one INVITE in a doctest can only ever print `Trying`. |
| [`rtp_quality.rs`](../examples/rtp_quality.rs) | `rtp-protocol.pcap`, then `invite-opus-bye.pcap` | Jitter, loss and MOS per stream — none of which exist in a packet. The second capture shows `StreamStore` **declining to score** a stream whose clock rate no `a=rtpmap` grounded. |
| [`filter_dialogs.rs`](../examples/filter_dialogs.rs) | any capture, plus an expression | `FilterExpr::parse` once, then `select_dialogs` — the join across both stores that `--report` and `--json-dialogs` also go through, and the reason those two never disagree about a capture. |

```sh
cargo run --features native --example call_summary -- tests/pcap-samples/register-invite-reinvite-bye.pcap
```

One difference bites before any other: the **binary** defaults to
`--portrange 5060-5061`, and the **library** applies no port policy at all.
Nothing in `parse_packet` or `parse_sip` filters by port. A capture signaling
on 5080 gives the library twelve SIP messages and the tool "No SIP signaling
found" until you pass `--portrange 1-65535`. Neither is wrong — they answer
different questions, and knowing that is cheaper than rediscovering it against
a capture you care about.

## Features

The crate is heavily feature-gated (see [`Cargo.toml`](https://github.com/NormB/sipnab/blob/main/Cargo.toml)). For pure parsing
you only need `native`. `tls`, `hep`, `api` and `mcp` pull in their respective
subsystems. See the feature table in
[install.md](install.md#feature-flags).
