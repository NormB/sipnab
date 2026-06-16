# Design: pcapng metadata — name resolution (NRB) and decryption secrets (DSB)

Status: **proposal / spec** · 2026-06-16

This document analyzes storing sipnab metadata in pcapng blocks and specs the
work. Two block types are in scope, with **opposite risk profiles**:

- **Name Resolution Block (NRB)** — IP → host/FQDN mappings. *Low risk, high
  cross-tool value.* **Recommended to build.**
- **Decryption Secrets Block (DSB)** — keys that decrypt the captured traffic.
  *High risk.* **Recommended: external-by-default + sanitize tooling; embedding
  only as a guarded, explicit opt-in (or decline embedding entirely).**

Guiding principle, mirrored from Wireshark: **an NRB makes a file more useful to
share; a DSB makes a file more dangerous to share.** Wireshark exposes name
saving via a (default-off) preference, but only embeds secrets via an explicit
`editcap --inject-secrets`, and ships a dedicated `--discard-all-secrets` strip
flag. We copy that asymmetry.

---

## 1. Background — what pcapng can hold

pcapng (IETF `draft-ietf-opsawg-pcapng`) is a TLV block format. Only the Section
Header Block (SHB) and Interface Description Block (IDB) are mandatory; all
metadata blocks/options are optional, and unknown blocks are skipped via their
length field (so emitting them never breaks other tools).

Relevant blocks/options:

- **SHB options** — `shb_hardware` (2), `shb_os` (3), `shb_userappl` (4, the
  producing app → `"sipnab <version>"`), `opt_comment` (1).
- **IDB options** — `if_name`, `if_description`, `if_tsresol` (timestamp
  resolution), `if_filter`, `if_os`, …
- **Enhanced Packet Block (EPB) options** — `opt_comment` (packet comment),
  `epb_flags`, `epb_hash`, `epb_dropcount`.
- **Name Resolution Block (NRB)** — block type **`0x00000004`**. ← this doc, §2.
- **Interface Statistics Block (ISB)** — type `0x00000005` (capture stats).
- **Decryption Secrets Block (DSB)** — type `0x0000000A`. ← this doc, §3.
- **Custom Block / Custom Options** — vendor data under a Private Enterprise
  Number, for structured proprietary metadata beyond comments.

> Block-number note: NRB is `0x04`; `0x05` is the Interface Statistics Block.

---

## 2. Name Resolution Block (NRB) — spec

### 2.1 Verdict: build it (opt-in)

The NRB is the standardized container for exactly sipnab's IP→name mappings
(manual `N`, `/etc/hosts`, reverse DNS). **Wireshark/tshark read and write it**,
so names travel with the capture and resolve in other tools, and round-trip back
into sipnab. Three constraints shape the design:

1. **Opt-in.** Wireshark's "save resolved addresses to the file" preference is
   OFF by default; tools should not silently mutate capture files.
2. **It leaks internal topology** (internal FQDNs, DNS structure, resolver
   identity, in cleartext) — a sanitize-before-sharing concern.
3. **sipnab's current pcapng writer uses *synthetic* packets** (reconstructs
   Ethernet/IP/UDP from the SIP payload; original frames are not retained) and
   reads via libpcap (which ignores metadata). So attaching metadata to the
   *original* file needs a separate verbatim copy pass over the source.

### 2.2 Two operations

| | **A. Save-with-names** | **B. Annotate / convert original** |
|---|---|---|
| Packet source | in-memory dialogs (synthetic packets) | original file on disk, copied **verbatim** |
| Fidelity | lossy re-encode (today's F2 save) | forensically faithful |
| Use | "export what I'm viewing, with names" | "turn `call.pcap` into `call.pcapng` with names" |
| Effort | small (attach NRB to existing writer) | larger (new verbatim copy pass via `pcap-file`) |

Both write the same NRB; they differ only in packet provenance. **B is the
centerpiece** (the "save the original pcap as pcapng with metadata" request).

### 2.3 NRB on-the-wire (writer/reader reference)

Multi-byte integers use the SHB byte order; IP-address octets are raw (endianness
-independent). Records are a TLV stream terminated by `nrb_record_end`; an
optional option TLV stream follows.

- Record header: `u16 Record Type | u16 Record Value Length | Value | pad→32-bit`.
- `nrb_record_ipv4` (`0x0001`): 4 addr octets + one or more NUL-terminated UTF-8
  names. `nrb_record_ipv6` (`0x0002`): 16 addr octets + names.
- `nrb_record_end` (`0x0000`, length 0): mandatory terminator.
- Multiple names per record are allowed; **first string is treated as canonical**
  by Wireshark, the rest as aliases. There is **no "FQDN" type** — store the
  FQDN string directly; emit `pbx\0pbx.example.com\0` to carry both.
- NRB options: `opt_comment` (1), `ns_dnsname` (2), `ns_dnsIP4addr` (3),
  `ns_dnsIP6addr` (4) — describe the resolver, i.e. provenance.
- Limits: per-record/option value ≤ 65535 (u16); whole block ≤ ~4 GiB (u32) —
  split large sets across records/NRBs.
- **Placement: write the NRB *before* the packet blocks** so single-pass readers
  (`tshark` without `-2`) see it. Wireshark buffers the whole file and doesn't
  care.

### 2.4 Data model — what gets written

- Records from the resolver: **manual mappings + `/etc/hosts` by default**.
  **Reverse-DNS cache entries are opt-in** (`--with-dns-names`) — they're
  observed-at-analysis-time, not operator-asserted, and are the main topology
  leak to be deliberate about.
- Provenance: `shb_userappl = "sipnab <version>"`; NRB `opt_comment`
  `"name resolution added by sipnab"`; `ns_dnsname`/`ns_dnsIP4addr` only when DNS
  names are included. (All forgeable — provenance, not authentication.)

### 2.5 Round-trip (read-back)

On opening a pcapng, parse its NRB(s) via `pcap-file` and load names into the
resolver as a new **`File`** source, ranked **below manual mappings**. Treat
file-sourced names as **untrusted hints** (§2.9); never overwrite an operator's
manual mapping. This is what makes the feature feel complete (open a shared file
→ names already resolved).

### 2.6 Validation

**On write, per name:** non-empty; valid UTF-8; **no interior NUL**; length
within a DNS-sane cap (≤253; hard-reject >65535); reject control characters. Skip
(and count) invalid mappings rather than abort the whole file. If **zero** valid
mappings → write no NRB (and, for operation B with no other reason to convert,
no-op with a message).

**On read (untrusted input):** strict bounds-checking against block length;
require NUL-termination; cap per-record/per-block sizes and total name count;
skip malformed records without panicking. (The pcapng option-parser has real CVE
history — wnpa-sec-2018-11, GitLab #17755 — and a one-byte poisoned PTR has
corrupted files in the wild. Fuzz the parser.)

### 2.7 Success cases

1. Open pcap → name addresses (`N`) / load `/etc/hosts` → save as pcapng → output
   carries an NRB; reopening in sipnab **or Wireshark** shows the names.
2. Convert original pcap → pcapng, packets **verbatim** + NRB (B) — faithful
   upgrade; original untouched.
3. Source already pcapng → read existing NRB(s), **merge** with sipnab's names
   (dedupe by IP+name), write combined; never silently drop pre-existing names.
4. Round-trip → reopening the produced pcapng repopulates the resolver.

### 2.8 Failure / edge cases

1. **User opts out of metadata** → default OFF; explicit every time (Save-popup
   checkbox + CLI flag). No silent NRB.
2. **Disk full / write fails partway** → **atomic temp-then-rename, original
   never at risk.** Write to `NamedTempFile::new_in(<output's own dir>)` (same
   filesystem; cross-FS rename = `EXDEV`), `sync_all()` the temp, `persist()`/
   rename over the target, fsync the parent dir (Wireshark's "safe save"). On
   `ENOSPC`/I/O error: skip rename, drop the partial temp, surface a clear
   error — the target is byte-for-byte intact. *sipnab has no atomic-write helper
   today — prerequisite to build, and worth retrofitting onto the existing save
   paths (which currently lack ENOSPC safety).*
3. **Replace original (delete `.pcap`, keep `.pcapng`)** → only behind explicit
   `--replace`/`--in-place` + confirmation. Sequence: write new `.pcapng` to a
   temp in the same dir → fsync → sanity-reopen (verify openable/block count) →
   **only then** delete the original. Never delete first. Handle the extension
   change, a read-only original (refuse, keep both), and an existing
   `call.pcapng` collision.
4. **Source is gzipped** (`.pcap.gz`) → decompress via existing `open_offline`,
   then re-encode; output is plain `.pcapng`.
5. **Live capture, no source file** → only operation A; B errors "no source
   file."
6. **Empty mappings** → no NRB; B with nothing else to do is a no-op + message.
7. **Target not writable / perm denied / dir missing** → fail before touching the
   original (temp create fails cleanly).
8. **Oversized name set** → split across records/NRBs.
9. **Untrusted/malformed NRB on read** → validated & skipped per §2.6; shown
   low-trust.
10. **Timestamp precision** → preserve source resolution on pcap→pcapng (don't
    silently downgrade ns→µs); set `if_tsresol` to match.
11. **Odd link types** → pcap→pcapng is an upgrade; copy the link type into the
    IDB faithfully.

### 2.9 Security & privacy

- A shared NRB embeds internal hostnames/FQDNs/DNS topology in cleartext —
  **sanitize before external sharing** (cf. TraceWrangler, which targets exactly
  NRBs/interface names/comments).
- **Names from a file are attacker-controlled content, not observed truth** — a
  crafted file can label a C2 IP `windowsupdate.microsoft.com` and Wireshark will
  display it. Treat file/DNS-sourced names as **hints**, never overwrite manual
  mappings, verify identity from packet evidence.
- Harden the read path against malformed NRBs (bounds, NUL-termination, size
  caps, fuzzing).

### 2.10 UX

- **TUI:** Save popup gains **"Include name resolution (NRB)"** (default off);
  an action **"Convert open file → pcapng with names"** (confirm), and behind a
  second confirm **"…and replace original."** Status line reports counts.
- **CLI:** opt-in flags, e.g.
  `sipnab -I call.pcap --names hosts.txt --to-pcapng call.pcapng [--with-dns-names] [--replace]`.
- **Config:** `[names] write_nrb = false` (default), `include_dns_names = false`.

### 2.11 Implementation notes (grounded in the code)

- **Writer:** `pcap-file` v2 exposes
  `pcapng::blocks::name_resolution::{NameResolutionBlock, Record, NameResolutionOption}`
  (Wireshark-interop). Prefer the typed API over the raw-`UnknownBlock` trick
  sipnab uses for the DSB. Verify exact enum names against the vendored crate.
- **Operation B = new verbatim copy path:** read the source with `pcap-file`'s
  reader (not libpcap, which drops metadata), stream blocks through, inject the
  NRB up front, write with `PcapNgWriter`. This is the one genuinely new
  subsystem.
- **Atomic-write helper (new, shared):** `NamedTempFile::new_in(parent)` → write
  → `sync_all` → `persist`/rename → fsync dir. Reuse for existing save paths.
- **Resolver serialization:** `NameResolver::manual_entries()` already yields
  sorted `(IpAddr, String)`. Add `hosts_entries()`, an `nrb_records()` producer,
  and a `load_nrb(records, source = File)` for read-back.

### 2.12 Testing (TDD)

NRB encode/decode round-trips (v4/v6, multi-name, padding, endianness);
Wireshark-interop golden (`tshark -2 … -z` shows the names); name-validation
edge cases (NUL, non-UTF-8, empty, overlong, control chars); atomic-write fault
injection (`/dev/full`/ENOSPC leaves the original intact — extend the existing
`/dev/full` test); replace-original safety (original survives a mid-write
failure); malformed-NRB-on-read hardening (fuzz).

---

## 3. Decryption Secrets Block (DSB) — engineering analysis

### 3.1 Technical

DSB type `0x0000000A`: `Secrets Type (u32) | Secrets Length (u32) | Secrets Data
| pad`. Secrets Type namespaces the payload (TLS Key Log `"TLSK"`, SSH,
WireGuard `"WGKL"`, ZigBee, OPC-UA, DTLS). For TLS the data is the **NSS Key Log
format** (`CLIENT_RANDOM <cr> <master_secret>` for TLS 1.2; the
`*_TRAFFIC_SECRET*`/`EXPORTER_SECRET` lines for TLS 1.3) — the same thing apps
emit via `SSLKEYLOGFILE`. Wireshark consumes an embedded DSB **automatically**.

**Key property:** these are **per-session secrets from the handshake — not the
server's long-term private key.** A DSB decrypts only the sessions whose
client-random it contains.

### 3.2 Good vs. bad

- **Good:** a self-contained `.pcapng` an analyst opens and reads in cleartext,
  no side-channel key handoff, perfectly reproducible. Great for SIP-TLS
  debugging / handing off a case.
- **Bad:** the file **carries the keys to read its own payload** — anyone holding
  it reads plaintext, at rest, in backups, in ticket attachments, indefinitely.
- **Bounded but total:** session-scoped (does not decrypt *other* captures), but
  for the sessions present it is full plaintext recovery. **Never put long-term
  private keys in a DSB** — that would retro-decrypt all non-PFS sessions to that
  server.

### 3.3 Why SIP raises the stakes

SIP-TLS plaintext exposes Digest/Proxy auth material, caller/callee identity
(From/To/PAI/Contact), call-detail metadata, registration data, and **SDP media
keying** (SDES `a=crypto` SRTP keys, DTLS-SRTP fingerprints). A SIP-TLS DSB can
hand over voice-path keys and subscriber identities — more sensitive than a
generic HTTPS keylog.

### 3.4 Industry practice

Wireshark **never auto-embeds** secrets; the default keeps keys external via
`SSLKEYLOGFILE` (sidecar). `editcap --inject-secrets <type>,<file>` is the
explicit, manual embed; `editcap --discard-all-secrets` strips DSBs to sanitize.
The presence of a dedicated *strip* flag shows the ecosystem treats embedded
secrets as something you routinely remove.

### 3.5 Mitigation stances (ranked)

1. **Never embed (default)** — secrets in an external `SSLKEYLOGFILE`-compatible
   sidecar (`0600`). ← recommended default.
2. **Explicit opt-in embed** — distinct flag/command + interactive confirmation +
   prominent warning + in-file marker (`opt_comment`/`shb_userappl`). Never
   silent/default.
3. **Scope minimization** — only per-session secrets for sessions in the capture;
   never long-term keys; let the operator pick sessions.
4. **Protect at rest** — output `0600`; offer to encrypt the artifact or keep
   secrets in a separate *encrypted* sidecar.
5. **Awareness + stripping (build regardless of embed)** — detect a DSB on open
   and warn; provide a `strip-secrets` command (`--discard-all-secrets` analog).
6. **Provenance/audit** — record that sipnab embedded secrets, when, which
   sessions.
7. **Ephemeral-only** — never persist secrets; decrypt in memory and discard.

### 3.6 Recommendation

- **NRB (names): proceed** (low risk, high interop, opt-in) — §2.
- **DSB (secrets): default to NOT embedding.** Concretely:
  1. Keep secrets **external** (sidecar keylog) by default — stances 1 + 5.
  2. **Build the sanitize side first and unconditionally:** detect-DSB-on-open +
     a `strip-secrets` command + a visible "secrets present" marker. Pure upside,
     no embed risk.
  3. Treat **DSB embedding** as a *later*, explicit, heavily-guarded opt-in
     (stances 2+3+4) — or **decline embedding entirely** (external-only + strip),
     which is a defensible lower-liability posture given SIP's sensitivity.
  4. **Absolute rule:** never place long-term private keys in a DSB.

---

## 4. Recommended tracks

1. **Track 1 — NRB name metadata** (valuable, low-risk): operation A + B,
   read-back, atomic-write helper, validation, tests. Build first.
2. **Track 2 — DSB awareness/stripping** (sanitize-only, low-risk): detect on
   open, `strip-secrets`, "secrets present" marker.
3. **Track 3 — DSB embedding**: explicit later decision; default-off, guarded, or
   declined.

## 5. References

pcapng spec: `draft-ietf-opsawg-pcapng` (ietf.org) · github.com/pcapng/pcapng.
Wireshark: Name Resolution & Resolved Addresses user-guide sections; source
`wiretap/pcapng.c`, `epan/addr_resolv.c`, `file.h` ("safe save"); man pages
`editcap`/`mergecap`/`tshark`. Precedence/round-trip: GitLab #18075, #13425,
#18235, #17755; ask.wireshark.org #10846 (trailing NRB / `tshark -2`). Security:
wnpa-sec-2011-03, wnpa-sec-2018-11, CVE-2011-0024; TraceWrangler; Packet-Foo
(trace sanitization; NRB DoS). Atomic write: `rename(2)`, LWN 457667, Rust
`tempfile`/`std::fs::rename`. Conversion gotchas: Netresec PcapNG HowTo;
Wireshark timestamps section.

> The DSB section (§3) was written from established domain knowledge plus the
> format facts confirmed during research; its dedicated web-research pass failed
> on a transient API overload, so pin fresh citations before publishing externally.
