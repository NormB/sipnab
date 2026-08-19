# Deliberate outbound transmit as an explicit capability

**Status:** DESIGN, plus one defect found while writing it (section 3) that
should be filed and fixed regardless of whether anything in section 5 is built.
**Verified against:** `63b771b`, working tree.
**The constraint, stated first because it governs everything below.** The offline
transmit guard is not up for negotiation. No proposal on this page relaxes it,
widens `TransmitPermit::for_source`, adds a flag that overrides it, or introduces
a "the operator knows what they are doing" escape. A capability that wants to
send gets **its own permit type and its own opt-in**, and inherits none of the
kill path's authority.

## 1. What the guard is, and what makes it work

[`src/security/transmit_guard.rs`](../../src/security/transmit_guard.rs) states
the problem in its own words (`:11-19`):

> Applied to a capture FILE it is indefensible. `-I customer.pcap` is
> archaeology. The addresses in it belonged to somebody at some point in the
> past; they may have been reassigned since, they are usually not reachable
> from the analyst's laptop in any meaningful sense, and the third parties they
> do reach have nothing whatsoever to do with the analysis. […] nothing in
> `-I file.pcap` suggests the tool sends anything at all. The damage is done
> before any output is read.

And why the fix is a type rather than a check (`:21-29`):

> The failure is silent and irreversible, so it must not depend on anyone
> remembering. [`TransmitPermit`] has a private field, so the only way to obtain
> one anywhere in the crate is [`TransmitPermit::for_source`], which inspects the
> capture source. Every function in the kill path that reaches a socket takes
> one by reference. A new call site therefore cannot compile a send without
> first proving, from the capture source, that the run is live — there is no
> code path to forget, and no flag to get wrong.

Three properties make it hold, and a new capability must reproduce all three or
it is not the same guarantee:

1. **A private field.** `pub struct TransmitPermit(())`
   ([`:48`](https://github.com/NormB/sipnab/blob/main/src/security/transmit_guard.rs#L48)). No other module can construct
   one, so `for_source` ([`:61`](https://github.com/NormB/sipnab/blob/main/src/security/transmit_guard.rs#L61)) is the
   sole entry point. It returns `Some` for `Live` and `Hep` and `None` for
   `File`.
2. **The permit is a parameter of every send.** Five signatures take it —
   `RawKillSocket::send_to_v4` / `send_to_v6` in both the Linux and stub forms
   ([`process_isolation.rs:156`, `:193`, `:229`, `:242`](../../src/process_isolation.rs))
   and `KillUdpSocket::send_to` ([`:273`](https://github.com/NormB/sipnab/blob/main/src/process_isolation.rs#L273)) — plus
   `spawn_scanner_kill_worker` ([`:1009`](https://github.com/NormB/sipnab/blob/main/src/process_isolation.rs#L1009)) and
   `BatchRunner::new` ([`batch.rs:1802`](https://github.com/NormB/sipnab/blob/main/src/app/batch.rs#L1802)) by value, and the
   worker holds one in a field ([`:801`](https://github.com/NormB/sipnab/blob/main/src/process_isolation.rs#L801)). A new
   send that forgets it does not compile.
3. **A refusal the operator can read.** `offline_refusal`
   ([`:80`](https://github.com/NormB/sipnab/blob/main/src/security/transmit_guard.rs#L80)) names the flag, says what
   happens instead and says how to get what was asked for. It fires from
   `bootstrap::plan` ([`bootstrap.rs:245-263`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs#L245-L263)),
   which runs for every mode. The doc comment at `:31-36` is explicit that the
   pair is deliberate: a type-only guard leaves someone believing their defense
   is armed, and a message-only guard is one forgetful call site away from being
   no guard at all.

The permit is derived once, from the source the capture thread actually opened
rather than from the flags ([`batch.rs:480-481`](https://github.com/NormB/sipnab/blob/main/src/app/batch.rs#L480-L481)), with
the reasoning recorded above it — `-I` beating `-d`, device auto-detection and
`--hep-listen` are already resolved into `handle.source`, so re-deriving it from
`cli` would be a second copy of that precedence to get wrong.

## 2. Why the kill path's destination rule is the sharpest lesson here

The scanner-kill destination is **an address read out of a packet**:

```rust
let _ = handle.send_kill(KillRequest::SendResponse {
    dst_addr: sip_msg.src_addr,
    dst_port: sip_msg.src_port,
```

([`batch.rs:1879-1880`](https://github.com/NormB/sipnab/blob/main/src/app/batch.rs#L1879-L1880), and identically at
[`:1920-1921`](https://github.com/NormB/sipnab/blob/main/src/app/batch.rs#L1920-L1921) for the `-K` path.)

That is correct for its purpose — a scanner-kill reply must go back to the
scanner, and there is nowhere else for it to go. It is also the entire reason the
live guard exists: with a capture file as the source, `sip_msg.src_addr` is a
historical third party, and the tool would send SIP at them. So the kill path
takes the strictest available protection precisely because its destination is
capture-derived.

Generalising that gives the rule this document builds on:

> **A capture-derived destination requires a live source. An
> operator-configured destination does not — but it requires something else.**

The kill path pairs a capture-derived destination with a live-only permit. A
replay tool, an active prober or a telemetry exporter has an
operator-supplied destination, which changes the risk but does not remove it: the
*content* is still the capture, and the capture is still customer data.

## 3. A defect found while writing this: `--hep-send` transmits from a file

`--hep-send` is not gated by anything in section 1, and it sends while reading a
capture file.

The chain, verified:

- `HepSender::send` ([`hep.rs:2066`](https://github.com/NormB/sipnab/blob/main/src/capture/hep.rs#L2066)) builds a HEP v3
  packet around `msg.raw` and calls `self.socket.send(&pkt)`
  ([`:1759`](https://github.com/NormB/sipnab/blob/main/src/capture/hep.rs#L1759)). No permit parameter.
- It is constructed unconditionally from `cli.hep_send` inside `BatchRunner::new`
  ([`batch.rs:606-636`](https://github.com/NormB/sipnab/blob/main/src/app/batch.rs#L606-L636)). That constructor **receives**
  `transmit_permit: Option<TransmitPermit>` ([`:593`](https://github.com/NormB/sipnab/blob/main/src/app/batch.rs#L593)) and
  consumes it only for the kill worker
  ([`:731-734`](https://github.com/NormB/sipnab/blob/main/src/app/batch.rs#L731-L734)). The HEP sender block never looks at it.
- It fires once per matched SIP message in the run loop
  ([`batch.rs:1335`](https://github.com/NormB/sipnab/blob/main/src/app/batch.rs#L1335)).
- `bootstrap::plan`'s refusal tests only the kill flags —
  `cli.kill_scanner || !cli.kill_target.is_empty() || config.security.kill_scanner`
  ([`bootstrap.rs:245-247`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs#L245-L247)) — so no warning fires
  either.

So `sipnab -I customer.pcap --hep-send collector.example:9060` forwards every SIP
message in a customer capture to a network destination, with no permit, no
refusal and no warning.

This is a *different* failure from the kill path and should not be conflated with
it. The destination is operator-supplied, so sipnab is not spraying packets at
uninvolved third parties. What it does instead is **exfiltrate the capture**:
customer signaling, including whatever the capture holds, leaves the analyst's
machine because a flag that reads like a live-capture forwarding option was left
in a shell history and reused on a file.

Note it is not obviously *wrong* to want this — replaying an archived capture
into a Homer instance is a real workflow, and section 5 is partly about how to
support it deliberately. The defect is that it happens by default, unannounced,
on a flag whose name says nothing about files.

**Recommendation, independent of everything else on this page: give `--hep-send`
an explicit offline opt-in.** On a file source it should refuse by default,
through `offline_refusal`-shaped messaging naming `--hep-send`, and proceed only
when the operator adds a flag that says they mean it (section 5 names it
`--replay-to`). That is a small change and it does not need the rest of this
design to land.

### 3.1 Resolved — announce, do not refuse

The paragraph above proposed a refusal. The shipped fix announces instead, on
the project owner's standing rule that HEP and OpenTelemetry transmit are
permitted. Read section 3 with that correction in mind. The word
"exfiltrate" above also overstates the case, because the operator chose the
destination.

Refusing would break replaying an archived capture into a Homer instance, which
section 4 itself lists as a legitimate want. What was actually wrong was
narrower, and all three parts now have a fix:

1. **Nothing said a file source forwards the file's contents.**
   `capture::hep::file_export_notice` now says exactly that, and
   `bootstrap::plan` logs it beside the kill-path refusal, before the capture
   thread opens anything. It names the flag, the destination, and the capture
   files. [`docs/cli-reference.md`](https://github.com/NormB/sipnab/blob/main/docs/cli-reference.md) carries the same warning under
   "What `--hep-send` sends".
2. **The run described the socket, not the consequence.** "HEP sender targeting
   `<addr>`" stays, and the announcement above it supplies the meaning.
3. **The export sat outside the permit system.** It now has
   `capture::hep::HepExportPermit`, minted from a
   `capture::hep::OperatorDestination` and required by the one function that
   touches the socket. Per section 5.1 this is a second permit rather than a
   wider `TransmitPermit`, and neither converts into the other.
   [`tests/hep_send_file_export_test.rs`](https://github.com/NormB/sipnab/blob/main/tests/hep_send_file_export_test.rs) pins the absence of every conversion
   that would let a recorded address become a destination.

`OperatorDestination` lives in `capture/hep.rs` rather than in `security/`
because HEP export is its only caller today, which is recommendation 2 of
section 7. Promote it when a second capability needs it.

**A related, smaller one.** `--reverse-dns` calls `reverse_dns`
([`names.rs:637`](https://github.com/NormB/sipnab/blob/main/src/names.rs#L637)), whose own doc comment says *"Emits DNS
queries on the network"*. On a file source the addresses queried are the
capture's, so the analyst's resolver — and its upstream — learn the address set
of a customer capture. It is off by default
([`config.rs`](../../src/config.rs), `names.reverse_dns`), it is a legitimate
analysis aid, and PTR lookups are not the same order of exposure as forwarding
signaling. It is recorded here so the inventory is complete, not as a
recommendation to change it.

## 4. The three things someone legitimately wants to send

**Replay to a lab.** Take a capture and put it back on a wire — into a test SBC,
a Homer collector, a staging proxy — to reproduce a fault. Destination is
operator-supplied. Content is the capture.

**Active probes.** Send an OPTIONS ping to a peer and record what comes back, to
distinguish "the peer is down" from "the peer is rejecting us". Destination is
operator-supplied *or* named from the capture by the operator. Content is
synthesised.

**Telemetry export.** HEP to a collector, or OpenTelemetry spans. Destination is
operator-supplied. Content is derived from the capture. This is the category
`--hep-send` already occupies.

For the record, the inventory of what sipnab can currently emit is short:
the kill path (permit-gated), `--hep-send` (section 3), reverse DNS (section 3),
syslog from the alert engine ([`alerting.rs:445`](https://github.com/NormB/sipnab/blob/main/src/security/alerting.rs#L445),
local `AF_UNIX` by default but remotable by host configuration), and the
`sh -c` hooks — `--alert-exec`, `--on-dialog-exec`, `--on-quality-exec` — which
transmit nothing themselves but whose documented example is an outbound HTTP POST
([`event_exec.rs:82`](https://github.com/NormB/sipnab/blob/main/src/output/event_exec.rs#L82)). There is no HTTP client in
the dependency graph, no metrics push, no update check and no telemetry; the REST
API, the MCP HTTP transport, the Prometheus endpoint and the HEP receiver are all
inbound listeners. Any new exporter would be sipnab's first outbound client.

## 5. The design: a second permit, not a wider first one

### 5.1 The type

```rust
/// Proof that the operator asked, in this run, for sipnab to originate
/// traffic at a destination they named.
///
/// Distinct from `TransmitPermit`, which proves the packets came from a live
/// source and licenses replying to an address read out of one. This type
/// proves nothing about the source and licenses nothing about capture-derived
/// destinations. Neither converts into the other.
pub struct OriginatePermit(());
```

Private field, same as `TransmitPermit`. One constructor, and its signature is
the design:

```rust
impl OriginatePermit {
    pub fn for_destination(
        cli_destination: &OperatorDestination,
    ) -> Option<Self> { … }
}
```

**`OperatorDestination` is a newtype over a value parsed from a CLI flag or a
config file, and it has no constructor that takes an `IpAddr`, a `SocketAddr`, a
`SipMessage`, a `Packet` or a `ParsedPacket`.** That is the whole mechanism of
section 5.2, and it is worth more than any amount of validation logic.

The two permits must not be interconvertible in either direction, and there
should be a compile-fail or unit test asserting it. A live capture does not
license originating at an operator's collector, and an operator naming a
collector does not license replying to a scanner in a file.

### 5.2 What stops a recorded address becoming a destination

This is the question the whole capability turns on, and the answer is
**four layers, in decreasing order of how much I trust them.**

**Layer 1 — the type, and it is the only one that is a guarantee.** Destinations
are `OperatorDestination`. That type is constructible only by the CLI and config
parsers. There is no `From<IpAddr>`, no `From<SocketAddr>`, no
`From<&SipMessage>`. A future call site that wants to send to an address it read
out of a packet cannot express it: there is no function to call. This is the same
trick `TransmitPermit`'s private field plays, applied to the destination instead
of the source, and it is the reason to build the capability this way rather than
as a well-reviewed function.

Everything below is defense in depth. If layer 1 is right, none of it is load-bearing;
if layer 1 is wrong, none of it saves the design.

**Layer 2 — resolve once, at startup, before any packet is read.** The
destination is resolved to a `SocketAddr` during planning and stored. Nothing in
the packet loop resolves anything. This also removes a blocking DNS call from the
hot path, which `HepSender::new` currently performs at construction
([`hep.rs`](../../src/capture/hep.rs), `to_socket_addrs` on an operator-supplied
hostname) — acceptable at startup, and something a future exporter must not
repeat per-message.

**Layer 3 — a destination allowlist, checked at send.** One resolved address, or
a small configured set. A send to anything else is a bug, and it should be a
loud one: log at `error`, count it, refuse the packet. This layer exists to catch
a mistake in layer 1 rather than to be the guard.

**Layer 4 — announce it.** At startup, on a file source, print what will be sent
and where: *"replaying 84,882 SIP messages from 15 capture files to
collector.example:9060"*. The operator gets one chance to notice before anything
leaves. Section 1's own reasoning applies — the type is what makes the guarantee
and the message is what tells the operator what is armed, and neither substitutes
for the other.

There is one case layer 1 does not cover and it must be refused outright, not
mitigated. **Nothing may derive a destination from the capture, even when the
operator asks for it.** "Probe every peer this capture mentions" is a natural
request and it is exactly the failure `transmit_guard.rs:11-19` describes, with
an operator's consent attached to it — and the operator consenting to probe *a*
peer is not consent to probe the 180 peers a carrier capture names. If active
probing of capture-named peers is ever wanted, it goes through a separate
proposal, with the peer named one at a time on the command line, and it is out of
scope here.

### 5.3 Opt-in, and it is per capability

No umbrella flag. `--allow-transmit` would be exactly the escape hatch this
document opened by refusing, because its meaning grows every time a capability is
added and an operator who armed it for one purpose has armed it for all of them.

Each capability gets a flag that names what it does and where it goes:

| Capability | Flag | Source requirement | Destination |
|---|---|---|---|
| Scanner kill | `--kill-scanner`, `-K` | **Live only** — `TransmitPermit` | Capture-derived, by design |
| Replay a capture | `--replay-to <ADDR>` | File **or** live | `OperatorDestination` |
| HEP export | `--hep-send <ADDR>` on live; `--hep-send` + `--replay-to` semantics on file | see section 3 | `OperatorDestination` |
| Telemetry export | `--otlp-endpoint <URL>` | Either | `OperatorDestination` |
| Active probe | *out of scope* | — | — |

Every one off by default, matching the standing rule
([`cli.rs:645-798`](https://github.com/NormB/sipnab/blob/main/src/cli.rs#L645-L798)) that every arming flag starts off.

### 5.4 What the guard must never grow

Recorded so a future change can be recognized as crossing the line rather than
extending it:

- **`TransmitPermit::for_source` must keep returning `None` for `CaptureSource::File`.**
  The unit test at
  [`transmit_guard.rs:97-126`](https://github.com/NormB/sipnab/blob/main/src/security/transmit_guard.rs#L97-L126) pins it with
  the message *"reading a capture file must never grant permission to transmit"*.
  That test is the guard's specification. Changing it is changing the product.
- **No `OriginatePermit` may be accepted where a `TransmitPermit` is required**,
  and no conversion may exist between them.
- **No capability may take a bare `SocketAddr` destination.** The moment one
  does, layer 1 is gone for every capability, because the next call site copies
  the signature that already exists.
- **`offline_refusal`'s message stays accurate.** It currently promises
  *"offline analysis never transmits"*. Once `--replay-to` exists, that sentence
  is true of `--kill-scanner` and false of sipnab as a whole. The refusal is
  per-feature (it takes the flag name as an argument), so the fix is to keep it
  feature-specific and resist any edit that generalises it.

## 6. What goes wrong if someone builds it the obvious way

**The obvious way is a flag on the existing guard.** `--allow-offline-transmit`,
threaded into `for_source`. It is three lines and it destroys the property in
section 1: the guarantee stops being "there is no code path to forget" and
becomes "there is a flag, and the operator's shell history decides". Section 3 is
what a flag left in a shell history already does today with no guard at all.

**The second-obvious way is reusing `TransmitPermit` for the new capability.** It
compiles, it looks like consistency, and it silently licenses the new sender to
be called from anywhere the kill path can be called — including with a
capture-derived destination, since nothing in the type says otherwise. The
distinction between "may reply to an address in a live packet" and "may originate
at an address the operator named" is exactly what the two types exist to keep
apart, and collapsing them loses it with no compile error to mark the loss.

**The third is resolving destinations per message.** A hostname resolved inside
the packet loop is a blocking DNS call on the hot path and a destination that can
change mid-run. Layer 2 exists because of this.

## 7. Recommendation

1. **File and fix the `--hep-send` gap** (section 3). It is a live defect at
   `63b771b`, it needs no new design, and it is the one thing on this page with a
   customer-data consequence today.
2. **Do not build the general capability until something concrete needs it.**
   Nobody has asked for replay or OTLP export. Building `OriginatePermit` with no
   caller produces an abstraction shaped by guesses rather than by a use.
3. **When the first real request arrives, build section 5.1 and 5.2 with it, and
   nothing more.** One capability, one flag, one destination type. The table in
   5.3 is a shape to grow into, not a roadmap to implement.
4. **Never** reach the goal by widening `TransmitPermit`. If a proposal's diff
   touches
   [`transmit_guard.rs`](../../src/security/transmit_guard.rs) other than to add
   documentation, it is the wrong proposal.
