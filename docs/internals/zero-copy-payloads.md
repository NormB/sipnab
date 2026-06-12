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
unchanged; only construction sites changed. Buffers free when the last
clone drops — a stored `SipMessage` keeps its backing frame alive, which
is the same memory the old design held as an owned copy.

## Measured (criterion, dev host)

Same-binary A/B isolating the changed operation on a 160-byte payload:

- `payload_slice_zero_copy` (Bytes::slice): **15.6 ns**
- `payload_copy_to_vec` (heap copy):        **15.1 ns**

Honest conclusion: at typical SIP/RTP packet sizes the heap copy was
already as cheap as the refcounted slice — the analysis claim of a
20-30% hot-path win is refuted. The change is cost-neutral on the
single-threaded hot path (`packet_decap/eth_ipv4_udp_160b` ~127 ns
total either way, within environment noise on a loaded host).

What the design actually buys:

- Large payloads stop costing linear copies (a TCP-reassembled 64 KB
  SIP message or max-size HEP packet is a ~1-2 us copy; the slice
  stays ~15 ns).
- No per-packet allocate/free pair crossing the capture -> processing
  thread boundary (cross-thread free is the allocator's worst case;
  invisible to a single-threaded benchmark).
- Enables `SipMessage.raw` to share the packet buffer (follow-up),
  removing the second copy of every SIP message.
