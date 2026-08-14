# Scanner-kill source-port spoofing — design scope

Follow-up to v0.5.11 (PR #134), which made `-K`/`--kill-target` and
`--kill-scanner` actually transmit the SIP kill response. The current send goes
out from an **ephemeral UDP source port** on a normal `UdpSocket`, so the reply
appears to come from `sipnab`'s own random port rather than from the SIP
listener the scanner targeted. Scanners that validate the response's transport
tuple (source IP + source port) against their request will drop it; only those
keying purely on the SIP transaction (Call-ID/branch/CSeq/To-tag) accept it.

**Goal:** send the kill response so it appears to originate from the exact
`ip:port` the scanner sent its request to (the "victim"), maximizing the chance
the scanner accepts and acts on it.

---

## 1. The core constraint: privilege timing

Spoofing the UDP source requires either a raw socket (`CAP_NET_RAW`) or libpcap
frame injection. sipnab's lifecycle (see [`src/privilege.rs`](https://github.com/NormB/sipnab/blob/main/src/privilege.rs), [`src/app/bootstrap.rs`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs)):

0. `privilege::block_privilege_escalation()` → (Linux) `set_no_new_privs()`,
   before anything else and whether or not this process is root.
1. `capture::start_capture()` opens the pcap handle — **privileged** (root or
   `cap_net_raw,cap_net_admin+ep`).
2. `privilege::drop_privileges()` → drops to `nobody`.
3. `batch.rs` spawns the scanner-kill worker — **already unprivileged**; its
   sockets bind here.

A raw send socket therefore **cannot be opened by the worker** — `CAP_NET_RAW`
is gone. It must be opened during step 1's privileged window and handed down.

---

## 2. Injection approach — two options

### Option A (recommended): raw `AF_INET`/`AF_INET6` socket with `IP_HDRINCL`

- Open `socket(AF_INET, SOCK_RAW, IPPROTO_RAW)` in bootstrap (privileged), set
  `IP_HDRINCL` so we supply the IP header. Wrap the fd in a `std::net::UdpSocket`-
  free raw handle (via `libc`, already a dep).
- The worker builds the full **IP + UDP** datagram: source = victim `ip:port`,
  dest = scanner `ip:port`, payload = the existing `build_scanner_response`
  bytes. The **kernel still does L2** (ARP, routing, egress iface) — we only
  forge L3/L4.
- Pros: no MAC/ARP handling; kernel routes correctly; smallest packet-builder
  (IP+UDP only); works for off-link scanners.
- Cons: need correct IP + UDP checksums by hand; IPv6 needs a parallel path
  (`IPV6_HDRINCL`, and the v6 UDP checksum is mandatory).

### Option B: `pcap::Capture::sendpacket()` (libpcap injection)

- Reuse/duplicate the pcap handle (opened privileged) and inject a complete
  **Ethernet + IP + UDP** frame.
- Pros: reuses existing capture infrastructure; one privileged resource.
- Cons: must build the **link layer** too — resolve the destination/gateway MAC
  (ARP or `/proc/net/arp` sniff), handle per-linktype framing (EN10MB vs
  loopback `DLT_NULL`/`DLT_LOOP` on `lo`), and the handle's `Send`-ness across
  the worker thread boundary is unproven. More moving parts.

**Recommendation: Option A.** L3 spoofing with kernel routing is the standard,
portable-within-Linux approach and keeps the byte-builder small and unit-
testable. Keep Option B noted as a fallback if raw sockets prove problematic in
some deployment.

---

## 3. Data-flow change: carry the spoof source

Today `KillRequest::SendResponse { dst_addr, dst_port, response_bytes }` only
carries the scanner (destination). Add the victim as the spoof source:

```rust
KillRequest::SendResponse {
    dst_addr, dst_port,            // scanner (unchanged)
    src_addr: IpAddr, src_port: u16, // victim = sniffed packet's dst — NEW
    response_bytes,
}
```

The dispatch site in `batch.rs` already has both: the request is
`sip_msg.src_addr:src_port` (scanner) and the victim is `sip_msg.dst_addr:dst_port`
(both fields exist on `SipMessage`, confirmed). No new capture data needed.

---

## 4. Packet construction (Option A, IPv4)

New module [`src/security/kill_packet.rs`](https://github.com/NormB/sipnab/blob/main/src/security/kill_packet.rs):

- `build_ipv4_udp(src: SocketAddrV4, dst: SocketAddrV4, payload: &[u8]) -> Vec<u8>`
  — 20-byte IPv4 header (IHL=5, TTL=64, proto=17, correct total-length, header
  checksum) + 8-byte UDP header (ports, length, checksum over pseudo-header +
  payload) + payload.
- Mirror for IPv6 (`build_ipv6_udp`): 40-byte v6 header + UDP with mandatory
  checksum over the v6 pseudo-header.
- Pure functions, no I/O — **fully unit-testable** against hand-computed golden
  bytes and independently-verified checksums.

The worker's `process_send` picks the raw socket by family, builds the datagram,
and `libc::sendto`s it to the scanner. All existing guards stay **in front** of
the send: broadcast/multicast reject, empty-response reject, global rate limit,
per-destination rate limit.

---

## 5. CLI / config surface

- Auto-select with graceful fallback: if a raw socket was successfully opened in
  the privileged window, spoof; otherwise fall back to today's ephemeral-port
  `UdpSocket` send and log the downgrade once. This keeps `-K` working with only
  the ephemeral path when run without `CAP_NET_RAW`.
- Optional explicit override `--kill-spoof {auto|raw|ephemeral}` (default
  `auto`) for operators who want to force or forbid spoofing.
- No behavioral change for existing users who don't grant extra caps.

---

## 6. Security considerations

- **Never spoof an arbitrary source.** The forged source is strictly the victim
  `ip:port` from the *sniffed* request — never attacker-controllable beyond what
  they already sent to. This is a targeted transaction reply, not a general
  spoofer.
- Keep both rate limiters (global 10/s default, per-dst 3/min) — spoofing does
  not change the amplification surface, and the response is ~200 bytes ≤ the
  request.
- Broadcast/multicast destinations already rejected; keep that.
- Document that raw-socket spoofing requires `cap_net_raw` (already granted for
  capture) and that egress-filtering (BCP38) upstream may drop spoofed-source
  packets — a deployment caveat, not a code bug.

---

## 7. Testing strategy (TDD, mandatory)

- **Unit (no privilege):** golden-byte tests for `build_ipv4_udp` /
  `build_ipv6_udp` — header fields, total length, and both checksums, including
  adversarial payloads (empty-after-guard, NUL/high bytes, max-size). Verify the
  UDP checksum with an independent reimplementation over the pseudo-header.
- **Integration (privileged, gated):** a test that opens the raw socket, sends a
  spoofed datagram to a bound loopback listener, and asserts `recv_from`'s
  reported source `ip:port` equals the *forged* victim tuple (not sipnab's).
  Gate behind `CAP_NET_RAW` detection so it's skipped (not failed) in
  unprivileged CI; run it under `sudo` locally, mirroring the v0.5.11 live e2e.
- **Regression:** existing worker tests (rate limit, reject paths, verbatim
  bytes) must stay green against the new request shape.

---

## 8. Platform / multi-arch

- Linux x86_64 + arm64: identical syscall path — the multi-arch requirement is
  satisfied by one Linux implementation.
- macOS: raw `IP_HDRINCL` behaves differently (BSD rewrites some fields) and the
  privilege drop is already skipped there. Scope macOS as **ephemeral-only**
  initially (feature-cfg the spoof path to Linux), with a note.
- `#[cfg(target_os = "linux")]` gates the raw path; other targets compile to the
  ephemeral fallback.

---

## 9. Effort & phasing

- **P1 — packet builders + unit tests** (~0.5 day): pure, no privilege, lands
  the risky checksum logic behind tests first.
- **P2 — privileged raw-socket open + handoff to worker** (~0.5 day): bootstrap
  wiring, `KillRequest` field, fallback logic.
- **P3 — worker send path + gated integration test + live e2e** (~0.5 day).
- **P4 — CLI flag, docs (man/CHANGELOG/help), IPv6** (~0.5 day).
- Total ≈ **2 days**, shippable as a single `fix/kill-target-spoof` PR or split
  P1–P2 / P3–P4.

---

## 10. Decisions (resolved) — implemented

1. **Default posture:** `auto` (spoof when `CAP_NET_RAW` is available, else
   ephemeral fallback), with an explicit `--kill-spoof {auto|raw|ephemeral}`
   override. `raw` fails loudly if the socket can't be opened.
2. **IPv6:** v4 shipped in 0.5.12; **IPv6 now implemented** (raw `AF_INET6` +
   `IPV6_HDRINCL`, `sin6_port` 0 on send). Both families spoof.
3. **macOS:** ephemeral-only, `#[cfg(target_os = "linux")]`-gated raw path.
4. **Metric:** added `sipnab_kill_responses_sent_total{mode="raw"|"ephemeral"}`.

Fully implemented (P1–P5): both IPv4 (0.5.12) and IPv6 source-port spoofing
ship, with the ephemeral fallback for platforms/permissions without raw
sockets.
