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

```rust
use sipnab::PcapReader;

let data = std::fs::read("capture.pcap")?;
for pkt in PcapReader::new(&data)? {
    // pkt.data is the captured bytes; feed to parse_packet / parse_sip …
    let _ = pkt.data.len();
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

## Features

The crate is heavily feature-gated (see [`Cargo.toml`](https://github.com/NormB/sipnab/blob/main/Cargo.toml)). For pure parsing
you only need `native`. `tls`, `hep`, `api` and `mcp` pull in their respective
subsystems. See the feature table in
[install.md](install.md#feature-flags).
