# Tuning capture on a busy server

sipnab defaults to a busy production link rather than a laptop
demo. This page is what to change when they are still not enough, in the order
worth changing them.

**Start here, always:** find out whether you are actually dropping packets. Every
other decision on this page depends on that number, and until v0.5.77 sipnab
could not tell you it.

---

## 1. Are you dropping packets?

sipnab polls libpcap's kernel counters once a second and reports two numbers.

```text
PACKETS ARE BEING DROPPED on 'eth0' (kernel buffer: 18432, interface/driver: 0).
The analysis for this run is INCOMPLETE — dialogs may be missing messages and
RTP loss figures will overstate what was on the wire.
```

You get that warning the moment the first drop happens, and a summary at the end
of the capture:

```text
Live capture on 'eth0' finished: 4821003 packets captured, but 18432 dropped by
the kernel buffer and 0 by the interface — THIS ANALYSIS IS INCOMPLETE
```

A clean run says so explicitly, so silence is never ambiguous:

```text
Live capture on 'eth0' finished: 4821003 packets, no drops
```

### The two counters mean different things

| Counter | libpcap field | What it means | What fixes it |
|---|---|---|---|
| **kernel buffer** | `ps_drop` | The ring was full when the packet arrived. sipnab was not draining fast enough. | §2 (`-B`), §3 (BPF), §4 (`--snaplen`), §5 (device) |
| **interface/driver** | `ps_ifdrop` | The NIC or its driver discarded the packet before libpcap ever saw it. | §7 — **a bigger buffer cannot fix this** |

That distinction is the single most useful thing on this page. Operators
routinely respond to *any* drop by raising `-B`, which does nothing at all for
interface drops and wastes memory while the real problem goes unaddressed.

> **Why a drop is not just "missing packets".** A dropped SIP message means a
> dialog reconstructs wrong — a missing `BYE` leaves a call that never ends, a
> missing `200 OK` leaves one that never answered. A dropped RTP packet is
> counted as **network loss that never happened**, so MOS and loss figures read
> worse than the call actually was. A lossy capture does not produce a smaller
> answer; it produces a *wrong* one.

---

## 2. The kernel capture buffer (`-B` / `--buffer`)

**Default: 64 MiB per capture device.**

This is the ring libpcap fills and sipnab drains. It absorbs the difference
between when packets arrive (bursty, driven by your traffic) and when sipnab
gets scheduled to read them (jittery, driven by your kernel). It is the setting
that matters most.

Busy trunk — give it room for a bigger burst:

```bash
sudo sipnab -N -d eth0 -B 256
```

Small or embedded host — cap the memory instead:

```bash
sudo sipnab -N -d eth0 -B 8
```

> **`-B` alone may buy less than you think.** libpcap divides the ring into
> fixed-size slots whose size comes from `--snaplen`, so how many *packets*
> 64 MiB holds depends on the snapshot length and on whether NIC offloads are
> on — anywhere from ~1,000 to ~41,000 — and on whether you named an interface
> at all. Read §4 and §5 before concluding that a bigger `-B` did not help; the
> three settings multiply.

Rules of thumb:

- **Raise it** when `kernel buffer` drops are non-zero and CPU is *not* pinned.
  Dropping with idle CPU means bursts, and bursts are exactly what a ring
  absorbs.
- **Do not raise it** when the drops persist and a core is at 100%. A bigger ring
  buys a longer burst, not more throughput — you are not keeping up on average,
  and no buffer size fixes that. Go to §3.
- **Lower it** on `--multi-device` runs. The cost is **per device**: eight
  interfaces at the default reserve half a gigabyte of kernel memory.

### It degrades rather than failing

Asking the kernel for a large ring can fail with `ENOMEM` on a small or loaded
host. sipnab does not treat that as fatal — it halves the request and retries,
down to a 2 MiB floor, and tells you when it settled for less:

```text
'eth0': the kernel refused a 64 MiB capture buffer; capturing with 16 MiB
instead. This host will tolerate a smaller burst before dropping — watch the
drop counters, and set -B/--buffer explicitly to pin a size.
```

sipnab honours an explicit small `-B` exactly and never promotes it upward: `-B 1` on a
constrained box means 1 MiB.

---

## 3. Capture less: BPF filters

The cheapest packet is the one the kernel never gives you. A BPF filter runs
**in the kernel**, before the ring, so filtered traffic costs no buffer space, no
copy, and no parse.

Only SIP signalling:

```bash
sudo sipnab -N -d eth0 "port 5060 or port 5061"
```

Signalling plus one media range:

```bash
sudo sipnab -N -d eth0 "port 5060 or (udp portrange 10000-20000)"
```

One customer's traffic:

```bash
sudo sipnab -N -d eth0 "host 203.0.113.10"
```

This is the correct first response to sustained drops with a busy CPU. Halving
the traffic that reaches userspace is worth more than any buffer size.

> **Careful with RTP.** Filtering to `port 5060` alone gives you signalling with
> no media, so every stream turns orphan and every MOS figure disappears. If you
> want quality metrics, the filter must admit the negotiated media ports too.

---

## 4. Snapshot length (`--snaplen`) — and why it decides your ring capacity

**Default: 65535** — the whole frame.

The obvious reading of `--snaplen` is "how many bytes of each packet get
copied", and on that reading it looks unimportant: a 1500-byte frame costs 1500
bytes whether the cap is 1600 or 65535. That reading is incomplete, and on a
busy server it is the expensive kind of incomplete.

**On Linux, snaplen also determines how many packets your ring can hold —
on the TPACKET_V2 ring.** Which ring you get depends on the run mode, and the
subsection at the end of this section is the rule. Read it before applying the
arithmetic here to a headless capture. libpcap's `create_ring()` sizes each slot
in the V2 ring from the snapshot length:

```c
frame_size = handle->snapshot;
/* ... clamped for Ethernet ... */
req.tp_frame_size = TPACKET_ALIGN(macoff + frame_size);
req.tp_frame_nr   = (handle->opt.buffer_size + req.tp_frame_size - 1)
                    / req.tp_frame_size;
```

The slots are **fixed size**, so `-B` buys you
`buffer_size / frame_size` *packets*, not bytes of useful queue. There is a
clamp that can rescue you — but read its guard carefully:

```c
if (handle->linktype == DLT_EN10MB) {
        ...
        if (offload)
                max_frame_len = MAX(mtu, 65535);
        else
                max_frame_len = mtu;
        max_frame_len += 18;
        if (frame_size > max_frame_len)
                frame_size = max_frame_len;
}
```

**The clamp only applies to `DLT_EN10MB` — real Ethernet.** sipnab's default
capture device on Linux is `any` (`src/capture/device.rs:38-40`, chosen because
SIP servers often listen on loopback), and `any` is `DLT_LINUX_SLL2`, not
`DLT_EN10MB`. So on the default configuration **no clamp runs at all** and the
slot stays at the full snaplen:

| Device | Link type | Offloads | Effective slot | 64 MiB ring holds |
|---|---|---|---|---|
| **`any` (sipnab's default)** | `LINUX_SLL2` | irrelevant — **clamp never runs** | ~65 KB | **~1,000 packets** |
| `eth0` | `EN10MB` | on (common default) | ~65 KB | **~1,000 packets** |
| `eth0` | `EN10MB` | off | MTU+18 ≈ 1518 B | **~41,000 packets** |

So out of the box — default device, default snaplen — a 64 MiB ring holds about
a thousand packets, **milliseconds of slack and roughly forty times less than
the same memory would buy at a smaller snaplen.** Before this raised the default
from 2 MiB, that same arithmetic gave **31 slots**.

Note what this means: naming an interface explicitly *and* disabling offloads is
worth far more than either alone, because only that combination reaches the
clamp. **§5 is the decision guide for the device half of that** — what leaving
`any` gains you, what it costs, and how to check you did not drop a call leg on
the way.

```bash
# Signalling-focused capture: ~36,000 slots in the same 64 MiB
sudo sipnab -N -d eth0 --snaplen 1600
```

Three ways out, and they compose:

1. **Cap the snaplen** (above) — immediate, no root beyond capture.
2. **Name the interface** (§5) — the only way to reach `DLT_EN10MB` at all, and
   the prerequisite for the clamp below. It is a coverage trade, so read §5
   before making it.
3. **Turn the offloads off** (§7) — which is independently correct for capture
   fidelity, because GRO/LRO hand you reassembled super-frames that were never
   on the wire.

> **Truncation is lossy, and not everything survives it.** A small `--snaplen`
> breaks audio reconstruction — the TUI's WAV save and the MCP `export_audio`
> tool both need whole RTP payloads — and it degrades `-O` capture re-emit to
> truncated frames. sipnab tracks captured versus original length per packet, so
> truncation is visible rather than inferred — but choose the value
> deliberately, not reflexively.

To limit only how much sipnab *parses* without truncating what it *captures*,
use `-S`/`--limitlen` instead. That is a parser bound, not a capture bound.

---

### Which ring you get: TPACKET_V2 for the TUI, V3 for everything else

Modern libpcap on Linux can use the block-based **TPACKET_V3** ring, which sizes
its blocks independently of the snapshot length and so does not have the
capacity cliff described above. One flag decides whether you get it, and
sipnab decides that flag for you.

The rule is in libpcap's `prepare_tpacket_socket()`:

```c
/*
 * The only mode in which buffering is done on PF_PACKET
 * sockets, so that packets might not be delivered
 * immediately, is TPACKET_V3 mode.
 *
 * The buffering cannot be disabled in that mode, so
 * if the user has requested immediate mode, we don't
 * use TPACKET_V3.
 */
if (!handle->opt.immediate) {
        ret = init_tpacket(handle, TPACKET_V3, "TPACKET_V3");
```

So immediate mode reads like a latency preference and is really a ring-format
choice. sipnab answers it by asking who consumes the packets
(`immediate_mode_for()` in `src/app/bootstrap.rs`):

| Run mode | Immediate | Ring | Why |
|---|---|---|---|
| TUI | yes | TPACKET_V2 | A person is watching messages appear. A message showing up a block late is exactly what makes an interactive tool feel wrong. |
| Batch, `--json`, `-O`, MCP, API | no | TPACKET_V3 | Throughput-bound with nobody watching. The buffering V3 does is precisely what keeps a burst off the floor. |

V3 is not free of its own trap, and sipnab pays for it explicitly rather than
inheriting it: libpcap copies the read timeout into `req.tp_retire_blk_tov` and
then polls with `-1`, so the timeout becomes **added delivery latency** rather
than a poll bound. The interactive 100 ms would have meant up to 100 ms before a
block retires. The batched path therefore uses its own
`BATCHED_READ_TIMEOUT_MS = 5` (`src/capture/live.rs`). Shutdown responsiveness
(`--duration`, Ctrl-C) never depended on either: the handle is non-blocking, an
empty ring returns `TimeoutExpired`, and the wait is sipnab's own bounded
`wait_readable()`.

**So the snaplen arithmetic above binds the TUI, not a headless capture.** On a
headless run `--snaplen` and the offload settings still matter for capture
fidelity and for copy cost, but they are no longer what decides how many packets
the ring holds.

**Unverified on hardware.** Whether the kernel selects V3, and what that is worth, rest on
reasoned from libpcap's source and not measured. `strace -e trace=setsockopt`
for `PACKET_VERSION`, and `KERNEL_DROPPED` under load against a V2 baseline, are
the two checks that would settle it.

---

## 5. Which interfaces: `any` versus named

**Default on Linux: `any` — every interface at once, loopback included.**

That default is deliberate, and it is a **correctness** choice, not a
performance one. `find_default_device()` returns `"any"` on Linux
(`src/capture/device.rs:35-40`), for the reason written beside it:

```text
// On Linux, "any" captures all interfaces — this is what sngrep does.
// SIP servers often listen on loopback, so capturing only eth0 misses traffic.
```

That is a real hazard, not a hypothetical one. A B2BUA talking to a registrar
over `127.0.0.1`, a containerised stack bridging SIP across `docker0`, a proxy
handing calls to a media server over a veth pair — capture `eth0` alone and
those legs are simply absent. A dialog missing one leg does not come back
smaller, it comes back **wrong**, exactly as §1 describes for dropped packets.
`any` is the setting that does not lose calls.

It is also the slowest and least capable device sipnab can open, on four
counts. Three are performance. One is a second correctness cost that runs the
other way.

### What `any` costs you

**1. It forfeits about 40x of your ring capacity — on the V2 ring, so on the
TUI.** §4 has the mechanism and the run-mode rule that scopes it:
libpcap's `create_ring()` sizes each TPACKET_V2 slot from the snaplen, and the
clamp that cuts a slot down to MTU+18 sits behind
`if (handle->linktype == DLT_EN10MB)`. **`any` reports `DLT_LINUX_SLL2`, so
that clamp never runs.** Every slot is the full 65535-byte snaplen regardless
of interface MTU, and no `ethtool` setting can reach it — the guard tests the
link type, not the offloads. At the 64 MiB default that is ~1,000 slots against
~41,000 for a named Ethernet interface with offloads off. Before the default
buffer still defaulted to 2 MiB, the same arithmetic gave `any` just **31 slots**.

**2. It cannot go promiscuous.** `capture_live()` in `src/capture/live.rs`
computes `let use_promisc = config.promisc && device != "any"` — the
pseudo-device does not support promiscuous mode, so sipnab does not ask for it. Promisc is on by default for a named
device and `--no-promisc` turns it off. On `any` there is nothing to turn off.
The consequence is that **`any` misses traffic not addressed to the host**,
which matters on precisely the deployment where you would want it: a SPAN port
or tap feeding mirrored calls the capture host is not a party to. That is a
correctness cost, and it points the opposite way from the loopback argument —
`any` sees every interface but only the host's own traffic on them.

**3. It runs one capture thread.** Naming devices unlocks `--multi-device`,
which spawns **one capture thread per interface** (`start_multi_capture()` and
`spawn_live_device()` in `src/capture/native.rs`), each with its own ring and
its own drain loop. `any` is one device, so it is one thread and one ring no
matter how many interfaces the traffic actually arrives on.

**4. It sweeps interfaces you never wanted.** `any` also picks up loopback,
`docker0`, veth pairs, tunnels and management interfaces. Every one of those
packets costs a BPF evaluation and, if it passes, a copy into the same
ring the traffic you *do* want is competing for.

### Side by side

| | `any` (the default) | Named — `-d eth0` / `-d eth0,eth1 --multi-device` |
|---|---|---|
| **Loopback / container legs** | Captured | **Missed unless you name those interfaces too** |
| **Link type** | `DLT_LINUX_SLL2` | `DLT_EN10MB` |
| **Snaplen slot clamp (§4)** | **Never runs** | Runs once offloads are off |
| **64 MiB ring holds** | ~1,000 packets | ~41,000 with offloads off (~1,000 with them on) |
| **Promiscuous mode** | **Unavailable** | On by default; `--no-promisc` to disable |
| **Capture threads** | 1 | 1 per named device under `--multi-device` |
| **Packets filtered and copied** | Every interface, `lo` and `docker0` included | Only the interfaces you named |

### Which one is right

**Stay on `any`** when any of these hold:

- You are diagnosing rather than monitoring.
- You do not yet know which interface carries the traffic.
- SIP genuinely crosses loopback or container bridges and you have not
  enumerated those interfaces.
- The drop counters from §1 read `no drops`. If it is not dropping, it is not
  costing you anything worth this trade.

**Name your interfaces** when any of these hold:

- §1 shows sustained `kernel buffer` drops.
- You are running a long-lived headless capture on a known topology.
- You need promiscuous mode because the switch mirrors the traffic to you
  rather than addressing it to you.
- You have several busy interfaces and one thread cannot drain them all.

### The recommendation for a busy server

Name what you need, open them in parallel, and turn the offloads off so the
clamp can run:

First disable the offloads, once per interface you intend to capture:

```bash
sudo ethtool -K eth0 gro off lro off gso off tso off
```

Then name those interfaces and open them in parallel:

```bash
sudo sipnab -N -d eth0,eth1 --multi-device -B 256 "port 5060 or port 5061"
```

Naming the devices buys all four counts at once: the slots are now clamped to
MTU+18 so the same 64 MiB holds tens of thousands of packets instead of ~1,000,
promiscuous mode is back, there is one capture thread per interface, and
nothing goes to `docker0`. Neither half works alone — `any` cannot reach
the clamp however you set `ethtool`, and a named device with offloads on is
still stuck at ~65 KB slots (§4).

**Verify you did not lose a leg.** This is a deliberate trade of coverage for
throughput, and the failure mode is silent — calls do not error, they just stop
being complete. Before you keep it, confirm the interface list is right:

```bash
ip -brief address
```

If any SIP endpoint answers on `127.0.0.1` or a container bridge, add `lo` or
`docker0` to the `-d` list rather than accepting the gap. `--multi-device`
costs `-B` **per device** (§2), so eight interfaces at the default reserve half
a gigabyte — name what you need and no more.

---

## 6. Give sipnab less work

- `--no-rtp` — skip RTP/RTCP entirely when you only care about signalling. RTP
  is ~93% of carrier traffic by packet count, so this is the largest single
  reduction available short of a BPF filter.
- `--no-dialog` — skip dialog reconstruction.
- `-N` / `--no-tui` — do not render a TUI you are not watching.
- `--quiet-bad-parse` — silence per-packet parse notices on dirty links.
- Avoid per-message output (`--json`, `--text-dump`) on a high-rate live capture
  unless you are consuming it. Formatting and writing every message is real work
  on the capture path.

---

## 7. Interface and driver drops

If `interface/driver` is non-zero, the packets never reached libpcap. `-B` is
irrelevant. Look outside sipnab:

- **NIC ring buffers** — `ethtool -g eth0` to inspect, `ethtool -G eth0 rx 4096`
  to raise. This is the NIC's own ring, distinct from libpcap's.
- **Offloads** — GRO/LRO/GSO make the kernel hand you reassembled super-frames
  that no longer match what was on the wire. For accurate capture:
  `ethtool -K eth0 gro off lro off gso off tso off`.
- **IRQ affinity and RPS** — a single core servicing all NIC interrupts is a
  common ceiling on a busy server.
- **A tap or SPAN port that is already oversubscribed** — if the mirror source is
  dropping, nothing on the capture host can recover it.

---

## 8. Offline: `--cores`

`--cores N` parallelises **offline** reconstruction (`-I`), not live capture.

```bash
sipnab -N -I /var/captures/ --cores 2 --report
```

Measured on the reference corpus ([benchmarks](benchmarks.md)), throughput peaks
at **two** cores and then declines: 1.06M pkts/s at 1, 2.32M at 2, 2.03M at 4,
1.89M at 8. The limit is the single sequential pcap reader, not the core count,
so **`--cores 2` is the sweet spot and higher values are usually worse.**

`--cores` is silently ignored on live capture — it requires `-I`.

---

## 9. A worked starting point

```bash
sudo sipnab -N -d eth0 \
  -B 256 \
  --snaplen 1600 \
  --no-tui \
  "port 5060 or port 5061 or (udp portrange 10000-20000)" \
  --report
```

Note that this already makes the §5 choice: it names `eth0` rather than taking
`any`, so confirm no SIP leg lives on loopback or a container bridge before
adopting it.

Then read the drop line at the end. If it says `no drops`, stop there — and
you can walk the settings *back* to recover fidelity. If it does not, work down
§2 → §3 → §5 → §6 → §7 in that order, and re-measure after each change rather
than applying all of them at once.

---

## Related

- [CLI reference](cli-reference.md) — every capture flag
- [Configuration](config-reference.md) — the `[capture]` section
- [Benchmarks](benchmarks.md) — measured throughput and method
- [Troubleshooting](troubleshooting.md)
