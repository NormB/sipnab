# Zero-copy packet payloads

## Problem

Every captured frame paid two heap copies on the hot path:

1. `parse_packet()` copied the transport payload out of `Packet.data`
   into `ParsedPacket.payload` (`udp.payload().to_vec()`).
2. `parse_sip()` copied the payload again into `SipMessage.raw`
   (`data.to_vec()`).

At capture rates this is thousands of allocations/second that exist only
to move ownership.

## Why not lifetimes

The obvious `ParsedPacket<'a>` borrowing from `Packet.data` does not fit
the architecture: `Packet`s cross a crossbeam channel from the capture
thread to the processing thread, `ParsedPacket`s outlive their `Packet`
inside the reassembler, and `SipMessage`s outlive everything inside the
dialog store. Borrowed payloads would force the backing buffer's lifetime
onto every downstream structure (and `SipMessage.raw` borrowing from a
sibling field is a self-referential struct).

## Design: refcounted slices (`bytes::Bytes`)

- `Packet.data: Bytes` — one `Vec -> Bytes` conversion at capture time
  (zero-copy take-over of the allocation).
- `ParsedPacket.payload: Bytes` — `data.slice(range)`: refcount bump +
  offset, no copy. Reassembled datagrams (which genuinely build new
  buffers) become `Bytes::from(vec)` — still no extra copy.
- `SipMessage.raw: Bytes` — shares the same backing buffer
  (`payload.clone()` is a refcount bump).

`Bytes` derefs to `[u8]`, so consumers that read `&pp.payload` compile
unchanged. Only construction sites changed. Buffers free when the last
clone drops — a stored `SipMessage` keeps its backing frame alive, which
is the same memory the old design held as an owned copy.

## Measured (criterion, dev host)

Same-binary A/B isolating the changed operation on a 160-byte payload:

- `payload_slice_zero_copy` (Bytes::slice): **15.6 ns**
- `payload_copy_to_vec` (heap copy):        **15.1 ns**

Honest conclusion: at typical SIP/RTP packet sizes the heap copy was
already as cheap as the refcounted slice — the analysis claim of a
20-30% hot-path win did not hold. The change costs nothing measurable on the
single-threaded hot path (`packet_decap/eth_ipv4_udp_160b` ~127 ns
total either way, within environment noise on a loaded host).

What the design actually buys:

- Large payloads stop costing linear copies (a TCP-reassembled 64 KB
  SIP message or max-size HEP packet is a ~1-2 microsecond copy; the slice
  stays ~15 ns).
- No per-packet allocate/free pair crossing the capture -> processing
  thread boundary (cross-thread free is the allocator's worst case;
  invisible to a single-threaded benchmark).
- Enables `SipMessage.raw`/`.body` to share the packet buffer (done:
  `parse_sip_bytes`), removing the second copy of every SIP message and
  making `SipMessage::clone` (dialog-store insertion) copy-free.

## The same lesson, one stage earlier: the offline reader

`crate::capture::mapped` applies this to the frame itself, and the result is
worth recording because the obvious version of it is a **regression**.

The offline `--cores` reader is one serial thread doing read, copy and
host-pair-peek for every packet while N workers wait. Reading through libpcap
costs it a `read` into libpcap's buffer *and* a copy out of it, because
`next_packet` invalidates what it returned on the next call. Mapping the file
removes the first of those.

Measured on the 535k corpus (median-of-7, idle host, same binary either way via
`SIPNAB_NO_MMAP`):

| cores | mapped | libpcap |      |
|-------|--------|---------|------|
| 1     | 1.59M  | 1.60M   | —    |
| 2     | 2.19M  | 2.19M   | —    |
| 4     | 3.27M  | 2.38M   | +37% |
| 8     | 3.30M  | 2.18M   | +51% |

Read the one-core row as a control: `--cores 1` and a run with no `--cores` use
the single-threaded reader in `crate::capture::file`, which does not map, so
that row is libpcap against itself and its spread is the harness noise floor.
Only `--cores 2` and up reach the mapped reader, and the gain arrives at four —
the point where the serial reader is what the workers wait on. The default
offline read therefore does not benefit yet.

**What failed, and why it looked right.** The natural design — hand each frame
out as a refcounted slice of the mapping, copying nothing at all — measures
**1.88M against libpcap's 2.33M at four cores**. One mapping is one atomic
refcount, so 535k frames cloned by the reader and dropped by the workers push
~1M atomic updates through a single cache line: free on one core, 21% on four.

An ablation that removed only the copy predicted +10.5% and was wrong, because
it aliased one small buffer that stayed in cache — it measured *no memory
traffic*, not *no copy*. Two further guesses also failed: `MAP_POPULATE` plus
`MADV_SEQUENTIAL` changed nothing (so page faults were not the cost either).

What made the mapping pay was keeping the block copy: it spreads refcounting
across one counter per ~270 frames. So the conclusion of this document holds at
every stage measured so far — **at these packet sizes the copy is not the cost.
The cross-thread refcount and allocator traffic is.** A change that removes a
copy and adds sharing is not obviously a win, and needs measuring at more than
one core count, because the whole effect is invisible at one.

Two things the mapping must do that libpcap did for free, both found by
comparing against it over the real corpus rather than against fixtures:

- Read **snapped** captures. `orig_len > snaplen` is the definition of
  snapping, not corruption, so the strict record parser rules out too much.
- Report a **truncated** file. Stopping quietly at the cut turns "this capture
  is incomplete" into "read in full".
