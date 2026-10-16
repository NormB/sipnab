# Tuning capture on a busy server

Use this page when a live capture drops packets.

- sipnab's defaults already suit a busy production link.
- So check first whether you are dropping anything at all.
- If you are, change the settings below in the order they appear. That is the
  order that helps most.

**Start here, always:** find out whether you are actually dropping packets.
Every other decision on this page depends on that number, and sipnab reports it.

---

## Are you dropping packets?

sipnab polls libpcap's kernel counters once a second and reports two numbers.

```text
PACKETS ARE BEING DROPPED on 'eth0' (kernel buffer: 18432, interface/driver: 0).
The analysis for this run is INCOMPLETE — dialogs may be missing messages and
RTP loss figures will overstate what was on the wire. This run's kernel capture
buffer is 64 MiB: raise it with -B/--buffer, narrow the capture with a BPF
filter, or reduce --snaplen. Interface drops are not fixed by a bigger buffer;
they point at the NIC or driver.
```

You get that warning the moment the first drop happens. You also get a summary
at the end of the capture:

```text
Live capture on 'eth0' finished: 4821003 packets captured, but 18432 dropped by
the kernel buffer and 0 by the interface — THIS ANALYSIS IS INCOMPLETE
```

A run with no drops ends with this line:

```text
Live capture on 'eth0' finished: 4821003 packets, no drops
```

### The two counters mean different things

| Counter | libpcap field | What it means | What fixes it |
|---|---|---|---|
| **kernel buffer** | `ps_drop` | The ring was full when the packet arrived. sipnab was not draining fast enough. | [The kernel capture buffer](#the-kernel-capture-buffer--b----buffer) (`-B`), [Capture less: BPF filters](#capture-less-bpf-filters) (BPF), [Snapshot length](#snapshot-length---snaplen--and-why-it-decides-your-ring-capacity) (`--snaplen`), [Which interfaces](#which-interfaces-any-versus-named) (device) |
| **interface/driver** | `ps_ifdrop` | The NIC or its driver discarded the packet before libpcap ever saw it. | ["Interface and driver drops"](#interface-and-driver-drops) — **a bigger buffer cannot fix this** |

Read the two counters before you change anything. A larger `-B` reduces
`kernel buffer` drops only. It has no effect on `interface/driver` drops.

### Both numbers describe a capture handle, not an interface

sipnab reads libpcap's counters for each capture handle this run opened.
libpcap keeps those counters per handle.

- A *handle* is one capture socket.
- An *interface* is the NIC every process on the host shares.

The difference changes what a zero means and what a total covers.

- **Zero drops means this run missed nothing.**
  - It says nothing about the interface.
  - Another sniffer on the same NIC keeps its own counters.
  - Neither run can read the other's.
- **One run can hold several handles.**
  - `--multi-device` opens one per named interface.
  - `--cores N` on a live device opens N sockets on one interface
    ([On a live device it means capture sockets, not workers](#on-a-live-device-it-means-capture-sockets-not-workers)).
  - sipnab adds each handle's increment to one process-wide pair. So the
    totals cover the whole run rather than any single socket.
  - The first-drop warning names the device that dropped. That tells you where
    to act.
- **The packet count beside them is sipnab's own tally**, not a libpcap
  counter.
  - It counts frames sipnab read.
  - The drop pair is what says how many more the wire carried.

### Where the two numbers appear

sipnab reports both counters on four surfaces. It keeps them apart on every one
of them. So whichever you are looking at can answer "which kind of drop is
this?"

| Surface | How they appear |
|---|---|
| Live warning | `PACKETS ARE BEING DROPPED on 'eth0' (kernel buffer: N, interface/driver: M)`, the moment the first drop happens |
| End-of-run summary | `... N dropped by the kernel buffer and M by the interface`, or `no drops` |
| `--report` | one sentence each, and each names only the fixes that apply to it |
| `--metrics` (Prometheus) | `sipnab_capture_kernel_dropped_packets_total` and `sipnab_capture_interface_dropped_packets_total`, as separate counters |

Alert on each Prometheus counter separately. Each one has its own fix, and a
sum of the two does not say which fix applies.

The REST API and MCP report the same pair on the capture-quality object:

- `kernel_dropped_packets` and `interface_dropped_packets`.
- They sit beside the `invalid_timestamps`, `undecodable_frames` and
  snapped-frame counts. Those make up the rest of a capture's quality.
- See [`GET /v1/stats`](rest-api.md#get-v1stats).

> **What a drop does to the analysis.**
>
> - A dropped SIP message means a dialog reconstructs wrong.
>   - A missing `BYE` leaves a call that never ends.
>   - A missing `200 OK` leaves one that never answered.
> - A dropped RTP packet counts as network loss that did not happen on the
>   wire. MOS and loss figures read worse than the call was.

---

## The kernel capture buffer (`-B` / `--buffer`)

**Default: 64 MiB per capture device.**

This is the ring libpcap fills and sipnab drains. It absorbs the difference
between two times:

- when packets arrive (bursty, driven by your traffic);
- when sipnab gets scheduled to read them (jittery, driven by your kernel).

Change it first.

Busy trunk — give it room for a bigger burst:

```bash
sudo sipnab -N -d eth0 -B 256
```

Small or embedded host — cap the memory instead:

```bash
sudo sipnab -N -d eth0 -B 8
```

> **The packet count a buffer holds depends on other settings.**
>
> - On the TUI's ring, libpcap divides the buffer into fixed-size slots. Their
>   size comes from `--snaplen`.
> - So how many *packets* 64 MiB holds depends on:
>   - the snapshot length;
>   - whether NIC offloads are on — anywhere from ~1,000 to ~41,000;
>   - whether you named an interface at all.
> - Read [Snapshot length](#snapshot-length---snaplen--and-why-it-decides-your-ring-capacity) and [Which interfaces: `any` versus named](#which-interfaces-any-versus-named) before concluding that a bigger `-B` did not help.

Rules of thumb:

- **Raise it** when `kernel buffer` drops are non-zero and CPU is *not* pinned.
  - Dropping with idle CPU means bursts.
  - Bursts are exactly what a ring absorbs.
- **Do not raise it** when the drops persist and a core is at 100%.
  - A bigger ring buys a longer burst, not more throughput.
  - You are not keeping up on average, and no buffer size fixes that.
  - Go to [Capture less: BPF filters](#capture-less-bpf-filters).
- **Lower it** on `--multi-device` runs.
  - The cost is **per device**.
  - Eight interfaces at the default reserve half a gigabyte of kernel memory.

### It degrades rather than failing

Asking the kernel for a large ring can fail with `ENOMEM` on a small or loaded
host. sipnab does not treat that as fatal. Instead it:

- halves the request and retries, down to a 2 MiB floor;
- tells you when it settled for less:

```text
'eth0': the kernel refused a 64 MiB capture buffer; capturing with 16 MiB
instead. This host will tolerate a smaller burst before dropping — watch the
drop counters, and set -B/--buffer explicitly to pin a size.
```

sipnab honors an explicit small `-B` exactly and never promotes it upward.
`-B 1` on a constrained box means 1 MiB.

### Request a buffer larger than 2047 MiB

The largest buffer sipnab can request is 2047 MiB. sipnab reduces a larger `-B`
to 2047 MiB and logs a warning before it opens the device:

```text
-B/--buffer 5000 MiB exceeds the 2047 MiB ceiling (pcap_set_buffer_size takes a
C int); capturing with 2047 MiB instead.
```

The run continues with 2047 MiB. To use more memory for capture, open more
than one ring: name several interfaces with `--multi-device`, or spread one
interface across sockets with
[`--cores`](#on-a-live-device-it-means-capture-sockets-not-workers).

### `--buffer-budget` is a different buffer

Two settings carry the word. They sit on opposite sides of the kernel boundary.

- `-B` sizes the kernel ring.
- `--buffer-budget` sizes the in-process queue between the capture thread and
  the processing loop.
  - It is in MiB, and it defaults to 64.
  - sipnab turns that budget into a packet count at an assumed 2 KiB average.
  - It then clamps the result to between 10,000 and 5,000,000 packets.

Raise it when processing lags behind a bursty capture the ring is already
absorbing. It does nothing for a ring that overflows. The kernel discards those
packets before this queue ever sees them.

---

## Capture less: BPF filters

A BPF (Berkeley Packet Filter) expression selects packets in the kernel.

- A BPF filter runs **in the kernel**, before the ring.
- So filtered traffic costs no buffer space, no copy, and no parse.

**A live capture already has one.** Give sipnab no expression of your own, and
it does this:

- It compiles one from `--portrange` (default 5060-5061).
- It then adds an arm that reaches SIP inside one VLAN tag, QinQ, a PPPoE
  Session header or an MPLS label stack.
- It logs the expression it installed. So `-v` shows you exactly what the
  kernel is running.

The baseline is therefore signaling-only already. This section is about
narrowing further or about letting media back in.

**Your expression replaces that one entirely.** sipnab never edits what you
typed.

- So an expression of your own drops the encapsulation arm.
- It also makes `--capture-tunnels` inert.
- Two warnings cover that:
  - one when a port-based expression shows no sign of handling encapsulation;
  - one naming `--capture-tunnels` as ignored when you passed it beside a
    filter of your own.

Careful with the flag name:

- `--filter` is sipnab's own matching language, applied to messages after
  capture.
- The BPF expression is the trailing argument, or a file named by
  `--bpf-file`.

Only SIP signaling, and nothing tagged:

```bash
sudo sipnab -N -d eth0 "port 5060 or port 5061"
```

Signaling plus one media range:

```bash
sudo sipnab -N -d eth0 "port 5060 or (udp portrange 10000-20000)"
```

One customer's traffic:

```bash
sudo sipnab -N -d eth0 "host 203.0.113.10"
```

Use a narrower filter first when drops persist while a core is at 100%. A
larger buffer does not raise the rate at which sipnab reads packets. A filter
lowers the number it has to read.

> **Careful with RTP.**
>
> - Filtering to `port 5060` alone gives you signaling with no media.
> - So every stream turns orphan and every MOS figure disappears.
> - If you want quality metrics, the filter must admit the negotiated media
>   ports too.

---

## Snapshot length (`--snaplen`) — and why it decides your ring capacity

**Default: 65535** — the whole frame.

`--snaplen` sets how many bytes of each packet sipnab captures. On Linux it
also sets how many packets the TUI's capture ring holds.

- The TUI uses libpcap's TPACKET_V2 ring. Every slot in that ring has the same
  size, set from the snapshot length. A buffer holds `buffer size ÷ slot size`
  packets, however small the packets are.
- libpcap reduces the slot to the interface MTU plus 18 bytes only on an
  Ethernet device (link type `EN10MB`) with NIC offloads off.
- `any`, sipnab's default device on Linux, has link type `LINUX_SLL2`. Its slot
  stays at the full snapshot length whatever the offload settings.
- Headless runs use a different ring. See
  "Which ring you get", below.

Slot size and capacity of the default 64 MiB buffer on the TUI's ring:

| Device | Link type | Offloads | Effective slot | 64 MiB ring holds |
|---|---|---|---|---|
| **`any` (sipnab's default)** | `LINUX_SLL2` | no effect | ~65 KB | **~1,000 packets** |
| `eth0` | `EN10MB` | on (common default) | ~65 KB | **~1,000 packets** |
| `eth0` | `EN10MB` | off | MTU+18 ≈ 1518 B | **~41,000 packets** |

With the default device and default snaplen, a 64 MiB TUI ring holds about a
thousand packets.

### Fit more packets in the ring

Three changes raise the packet count. Each one helps alone, and they combine.

- **Cap the snaplen.** A 1600-byte snaplen gives slots a little over 1.6 KB,
  so 64 MiB holds tens of thousands of packets:

  ```bash
  sudo sipnab -d eth0 --snaplen 1600
  ```

- **Name the interface.** Only a named Ethernet interface can use the
  MTU-sized slot. Read
  [Which interfaces: `any` versus named](#which-interfaces-any-versus-named)
  before you make that change, because a named device can miss call legs that
  `any` sees.
- **Turn the offloads off** ([Interface and driver drops](#interface-and-driver-drops)).
  With offloads on, the kernel delivers merged frames that were not on the
  wire, and the Ethernet slot stays at 65 KB.

**`--capture-profile` picks the number for you.**

- `signaling` asks for a snaplen of 1500 — one MTU.
  - That keeps a whole INVITE carrying a long `Record-Route` set, ISUP
    encapsulation or a fat SDP offer.
  - It drops the bulk of every RTP packet.
- `full` is 65535, the default.
- An explicit `--snaplen` takes precedence over the profile.

A snaplen shorter than a SIP message cuts the message, and sipnab cannot parse
the cut message. A single INVITE with a long `Record-Route` set, a long
`Contact`, ISUP encapsulation or a large SDP offer often exceeds 400 bytes.
`sipnab_capture_snapped_frames_total` counts how many frames arrived truncated.

```bash
sudo sipnab -N -d eth0 --capture-profile signaling
```

> **Truncation is lossy, and not everything survives it.**
>
> - A small `--snaplen` breaks audio reconstruction.
>   - `--retain-audio`, Opus decode, the TUI's WAV save and the MCP
>     `export_audio` tool all need whole RTP payloads.
> - It degrades `-O` capture re-emit to truncated frames.
> - sipnab records the captured and original length of each packet, so the
>   metrics count the truncated frames.

To limit only how much sipnab *parses* without truncating what it *captures*,
use `-S`/`--limitlen` instead. That is a parser bound, not a capture bound.

---

### Which ring you get: TPACKET_V2 for the TUI, V3 for everything else

sipnab picks the capture mode from the run mode:

| Run mode | Immediate mode | Ring libpcap uses |
|---|---|---|
| TUI | on | TPACKET_V2: fixed-size slots, sized from `--snaplen` |
| Every run without the TUI (`-N`) | off | TPACKET_V3: blocks sized independently of `--snaplen` |

- In the TUI, each packet reaches the screen as soon as it arrives.
- A headless run lets libpcap batch packets into blocks. sipnab sets the block
  timeout to 5 ms, so libpcap delivers a block that does not fill after that
  timeout.
- libpcap uses TPACKET_V3 only when its build includes it. Check the second line
  of `sipnab --version`:

```bash
sipnab --version
```

```text
…
libpcap version 1.10.4 (with TPACKET_V3); alternate capture backends named: none
```

On a headless run, `--snaplen` and the offload settings still decide how many
bytes of each packet sipnab copies. The slot arithmetic in
[Snapshot length](#snapshot-length---snaplen--and-why-it-decides-your-ring-capacity)
applies to the TUI.

---

## Which interfaces: `any` versus named

**Default on Linux: `any` — every interface at once, loopback included.**

sipnab defaults to `any` so that it captures every call leg. SIP servers often send
signaling over loopback or a container bridge. Capture `eth0` alone and these
legs are absent:

- a B2BUA talking to a registrar over `127.0.0.1`;
- a containerized stack bridging SIP across `docker0`;
- a proxy handing calls to a media server over a veth pair.

A dialog missing one leg reconstructs wrong, in the same way as
[Are you dropping packets?](#are-you-dropping-packets) describes for dropped
packets.

`any` has four costs: three in performance and one in coverage.

### What `any` costs you

- **The TUI's ring holds about 40 times fewer packets.**
  - Every slot stays at the full snapshot length, 65535 bytes by default,
    whatever the interface MTU or `ethtool` settings.
  - At the 64 MiB default that is about 1,000 slots, against about 41,000 for
    a named Ethernet interface with offloads off.
  - [Snapshot length](#snapshot-length---snaplen--and-why-it-decides-your-ring-capacity) explains the slot size.
- **It cannot capture in promiscuous mode.**
  - sipnab does not request promiscuous mode on `any`, because the
    pseudo-device does not support it.
  - Promiscuous mode is on by default for a named device, and `--no-promisc`
    turns it off.
  - So **`any` misses traffic not addressed to the host**. On a SPAN port or
    tap that mirrors calls the capture host is not a party to, name the
    interface.
- **It runs one capture thread.**
  - Naming devices allows `--multi-device`.
  - That starts one coordinator thread plus **one capture thread per
    interface**.
  - Each has its own ring and its own drain loop.
  - `any` is one device. So it is one thread and one ring no matter how many
    interfaces the traffic actually arrives on.
  - `--cores N` ([On a live device it means capture sockets, not workers](#on-a-live-device-it-means-capture-sockets-not-workers))
    is the other way to get more than one socket. It works on a single device
    rather than on a list.
- **It sweeps interfaces you never wanted.**
  - `any` also picks up loopback, `docker0`, veth pairs, tunnels and
    management interfaces.
  - Every one of those packets costs a BPF evaluation.
  - Each packet the filter passes also takes a slot in the same ring as the
    traffic you want.

### Side by side

| | `any` (the default) | Named — `-d eth0` / `-d eth0,eth1 --multi-device` |
|---|---|---|
| **Loopback / container legs** | Captured | **Missed unless you name those interfaces too** |
| **Link type** | `LINUX_SLL2` | `EN10MB` |
| **MTU-sized TUI ring slot ([Snapshot length](#snapshot-length---snaplen--and-why-it-decides-your-ring-capacity))** | **Never** | Once offloads are off |
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
- The drop counters from [Are you dropping packets?](#are-you-dropping-packets)
  read `no drops`.

**Name your interfaces** when any of these hold:

- [Are you dropping packets?](#are-you-dropping-packets) shows sustained
  `kernel buffer` drops.
- You are running a long-lived headless capture on a known topology.
- You need promiscuous mode, because the switch mirrors the traffic to you
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

Naming the devices addresses all four costs:

- The slots are now clamped to MTU+18. So the same 64 MiB holds tens of
  thousands of packets instead of ~1,000.
- Promiscuous mode is back.
- There is one capture thread per interface.
- Nothing goes to `docker0`.

The smaller slot needs both steps:

- On `any`, the slot stays at the full snapshot length whatever the `ethtool`
  settings.
- A named device with offloads on still has slots of about 65 KB
  ([Snapshot length](#snapshot-length---snaplen--and-why-it-decides-your-ring-capacity)).

**Check that no call leg is missing.** A leg on an interface you did not name
is not captured, and sipnab reports no error for it. List the interfaces and
their addresses:

```bash
ip -brief address
```

If any SIP endpoint answers on `127.0.0.1` or a container bridge, add `lo` or
`docker0` to the `-d` list rather than accepting the gap.

- `--multi-device` costs `-B` **per device** ([The kernel capture buffer](#the-kernel-capture-buffer--b----buffer)).
- So eight interfaces at the default reserve half a gigabyte.
- Name what you need and no more.

---

## Give sipnab less work

- `--no-rtp` — skip RTP/RTCP entirely when you only care about signaling.
  - A call with media carries far more RTP packets than SIP messages. In
    `sip-rtp-g711.pcap` from the test samples, 839 of the 852 packets are RTP.
  - So this is the largest single reduction available short of a BPF filter.
- `--no-dialog` — skip dialog reconstruction.
- `-N` / `--no-tui` — do not render a TUI you are not watching.
- `--quiet-bad-parse` — silence per-packet parse notices on dirty links.
- Avoid per-message output (`--json`, `--text-dump`) on a high-rate live
  capture unless you are consuming it.
  - Formatting and writing every message is real work on the capture path.

---

## Interface and driver drops

If `interface/driver` is non-zero, the packets never reached libpcap. `-B` is
irrelevant. Look outside sipnab:

- **NIC ring buffers**
  - `ethtool -g eth0` to inspect, `ethtool -G eth0 rx 4096` to raise.
  - This is the NIC's own ring, distinct from libpcap's.
- **Offloads**
  - GRO/LRO/GSO make the kernel hand you reassembled super-frames.
  - Those no longer match what was on the wire.
  - For accurate capture: `ethtool -K eth0 gro off lro off gso off tso off`.
- **IRQ affinity and RPS**
  - A single core servicing all NIC interrupts is a common ceiling on a busy
    server.
- **A tap or SPAN port that is already oversubscribed**
  - If the mirror source is dropping, nothing on the capture host can recover
    it.

### A different capture backend: `netmap:`

libpcap can read through netmap instead of the kernel's packet socket.

- The device name selects it: `--device netmap:eth0`.
- The libpcap behind a binary decides whether it can.
- That libpcap differs by artifact.

Where to check:

- [Which capture
  backends an artifact can
  reach](install.md#which-capture-backends-an-artifact-can-reach) has the
  table.
- The second line of `sipnab --version` names the libpcap your binary runs and
  the alternate backends its banner names.

That page also lists which sipnab versions support netmap on each artifact.

> **Warning:** use a `netmap:` device only on an interface dedicated to
> capture, such as a SPAN or mirror port. Never use it on one the host needs.
> netmap takes the interface's rings away from the kernel. So the host stops
> receiving that interface's traffic for as long as the capture runs. On the
> interface that carries your SIP service, that stops the service.

---

## Offline: `--cores`

`--cores N` names a different resource on each source. So read the one that
matches your run.

Reading files (`-I`), it is N parallel reconstruction workers.

- sipnab assigns packets to workers by host pair.
- Each worker has its own dialog and RTP-stream stores.

```bash
sipnab -N -I capture.pcap --cores 4 --report
```

```text
… INFO sipnab::parallel: Reading from 'capture.pcap'
… INFO sipnab::capture::file: Read 852 packets: 1 of 1 file(s) read in full
Call-ID                          From           To             State        Code   Duration   Msgs   PDD      Tags
-------------------------------------------------------------------------------------------------------------------------
1-1966@10.0.2.20                 sipp           test           Completed    200    8s         6      -        -
1-1968@10.0.2.20                 sipp           test           InCall       200    0s         4      -        -
…
… INFO sipnab::app::batch: sipnab: 852 packets, 10 SIP messages, 839 RTP packets across 2 streams (4 cores)
```

The closing line names the worker count. On the reference corpus, throughput
stops rising beyond four workers. Extra workers add memory without adding
speed. [Benchmarks](benchmarks.md) has the measured figures.

### On a live device it means capture sockets, not workers

`--cores N` on `-d <device>` asks the kernel to spread that interface across N
`AF_PACKET` sockets through `PACKET_FANOUT`.

- Each socket gets its own ring and its own drain loop.
- A bigger `-B` gives a deeper ring that one thread still empties alone.
- Linux only. Elsewhere sipnab captures on one socket and logs the reason.

Before you use it:

- **It widens capture, not analysis.**
  - Every socket feeds the same channel and the same processing loop.
  - So `--cores 8` is not eight cores of reconstruction.
- **`-B` is per socket.**
  - N sockets ask the kernel for N rings of that size.
  - So `--cores 8` at the 64 MiB default reserves half a gigabyte.
  - sipnab states the total out loud when it opens the group.
- **A kernel that refuses `PACKET_FANOUT` gets one socket.**
  - sipnab tests `PACKET_FANOUT` on one socket first. If the kernel refuses it, sipnab
    logs a warning and captures on a single socket.

```bash
sudo sipnab -N -d eth0 --cores 4 -B 32 "port 5060 or port 5061"
```

Reach for it when both of these hold:

- [Are you dropping packets?](#are-you-dropping-packets) shows sustained
  `kernel buffer` drops on ONE busy interface;
- [The kernel capture buffer](#the-kernel-capture-buffer--b----buffer) through [Which interfaces: `any` versus named](#which-interfaces-any-versus-named) have not cleared them.

Several interfaces is `--multi-device` ([Which interfaces: `any` versus named](#which-interfaces-any-versus-named)) instead.

---

## A worked starting point

```bash
sudo sipnab -N -d eth0 \
  -B 256 \
  --snaplen 1600 \
  "port 5060 or port 5061 or (udp portrange 10000-20000)" \
  --report
```

Note that this already makes the interface choice from [Which interfaces: `any` versus named](#which-interfaces-any-versus-named).

- It names `eth0` rather than taking `any`.
- So confirm no SIP leg lives on loopback or a container bridge before adopting
  it.

Then read the drop line at the end.

- If it says `no drops`, stop there. You can then undo settings one at a
  time, for example the snaplen, while the line still says `no drops`.

- If it does not, work down these in that order:
  - [The kernel capture buffer](#the-kernel-capture-buffer--b----buffer)
  - [Capture less: BPF filters](#capture-less-bpf-filters)
  - [Which interfaces: `any` versus named](#which-interfaces-any-versus-named)
  - [Give sipnab less work](#give-sipnab-less-work)
  - [Interface and driver drops](#interface-and-driver-drops)
- Re-measure after each change rather than applying all of them at once.

---

## Related

- [CLI reference](cli-reference.md#capture) — every capture flag
- [Configuration](config-reference.md#capture) — the `[capture]` section
- [Benchmarks](benchmarks.md) — measured throughput and method
- [Troubleshooting](troubleshooting.md)
