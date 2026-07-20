# sipnab — open backlog

Forward-looking feature backlog only. Shipped work is recorded in
`CHANGELOG.md`; this file tracks what is *not* yet built.

## Capture

- [ ] **SCTP transport parsing** — SCTP is detected (proto 132) but its
  payload is discarded; parsing DATA chunks to extract SIP would enable
  SIGTRAN/Diameter (3GPP IMS) environments. Low priority — IMS/SIGTRAN only.

## TUI

- [ ] **Live call quality dashboard** — real-time MOS/jitter/loss graphs.
- [ ] **Call timeline visualization** — horizontal timeline of call states.
- [ ] **Packet loss map** — visual representation of RTP loss patterns.

## Long-term / exploratory

- [ ] WASM plugin API (design decision D7 rules out Lua; WASM is the path if
  plugins are ever needed).
- [ ] Machine-learning anomaly detection over SIP/RTP patterns.
- [ ] Distributed capture cluster management.
- [ ] Interactive pcap annotation and sharing.
- [ ] YANG/NETCONF machine-readable diagnosis export.

## Standing decisions

| Decision | Status | Notes |
|----------|--------|-------|
| wolfSSL/OpenSSL TLS backends | REMOVED | ring covers ~95% of cases; re-add only if FIPS demand arises. |
| gRPC API | REMOVED | REST API is complete; re-add only if streaming demand arises. |
| STIR/SHAKEN cert verification | DEFERRED | Would require HTTP cert fetching — added attack surface, intentionally skipped. |
| WASM plugins | FUTURE | D7 rules out Lua; WASM is the path if plugins are ever needed. |
