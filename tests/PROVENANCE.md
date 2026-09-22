# Where the other committed captures came from

Every capture committed outside `tests/pcap-samples/` has an entry here: the
fuzz seeds, the fixtures under `tests/fixtures/`, the harness media and the
sample the website loads. `tests/pcap-samples/` keeps its own record in
[`pcap-samples/PROVENANCE.md`](pcap-samples/PROVENANCE.md), checked by its own
gate, and nothing from that directory belongs here.

**The rule.** The local corpus of real captures is never pushed. A committed
capture is one of two things:

- **public**: published by someone else, at a source anyone can check, under
  terms that allow redistributing it;
- **synthetic**: written by a generator tracked in this repository, so the
  capture's whole content is a reviewable diff.

A capture from a live network is neither. It belongs in the private corpus
that `SIPNAB_CORPUS` points at, where the corpus gates read it and nothing
publishes it.

`every_committed_capture_is_public_or_synthetic` in
[`committed_capture_provenance_test.rs`](committed_capture_provenance_test.rs)
enforces this. It reads the index, so a capture fails the moment it is staged,
and it recognizes captures by their leading bytes rather than their names:
classic pcap in either byte order and either timestamp precision, pcapng,
NetMon 2.x, and gzip wrapped around any of them. It fails when a capture has
no entry, when an entry names a file the index no longer holds, when a
generator is not tracked, and when a file's SHA-256 differs from its entry.
The hash is the point of that last check: replacing a fixture's bytes means
saying again where the new ones came from.

## Adding a capture

Prefer a generator. A builder in
[`support/synthetic_captures.rs`](support/synthetic_captures.rs), listed in its
`OWNED` table, is rebuilt and compared byte for byte by
[`synthetic_captures_test.rs`](synthetic_captures_test.rs), and
`cargo run --features native --bin gen_fixture` writes the file. Use [RFC 5737](https://www.rfc-editor.org/rfc/rfc5737)
addresses, [RFC 7042](https://www.rfc-editor.org/rfc/rfc7042) documentation MAC addresses and `example.*` host names.

Then add an entry below, headed by the capture's path from the repository
root, with these labels:

- **Category:** `synthetic` or `public`.
- **Generator:** for a synthetic capture, the tracked file that writes it, in
  backquotes.
- **Source:** for a public capture, the URL it was downloaded from.
- **License:** for a public capture, the terms it was published under.
- **SHA-256:** the hash of the committed bytes, in backquotes.
- **Holds:** what is in it and what the tests use it for.

A capture that is neither provably public nor synthetic today is listed in
`UNRESOLVED` in the test, with the reason. That list only shrinks: an entry
leaves it by gaining a real entry here, or by the file being deleted.

## Entries

### tests/fixtures/sip_call.pcap

- **Category:** synthetic
- **Generator:** `tests/support/synthetic_captures.rs` (`sip_call`)
- **SHA-256:** `113597350ef13c41d40023c855c22cd06b3c6341e46c1f3e7722698e2409595b`
- **Holds:** one complete call between 192.0.2.1 and 192.0.2.2, INVITE
  through BYE, seven messages and no media. The default capture for CLI,
  REST, MCP and TUI tests. Until September 2026 it used private [RFC 1918](https://www.rfc-editor.org/rfc/rfc1918)
  addresses; the frames are otherwise the ones `gen_fixture` wrote in April.

### tests/fixtures/udp_5060.pcap

- **Category:** synthetic
- **Generator:** `tests/support/synthetic_captures.rs` (`udp_5060`)
- **SHA-256:** `3e1c5ead0e8fdc174c8fae387c85a47b018e6778207ca3d17e357f18a27db797`
- **Holds:** ten bare `200 OK` datagrams from 192.0.2.1 to ten different
  addresses, one second apart. Packet counting, BPF filtering and file-reader
  tests.

### tests/fixtures/rtpengine-ng-hep.pcap

- **Category:** synthetic
- **Generator:** `tests/support/synthetic_captures.rs` (`rtpengine_ng_hep`)
- **SHA-256:** `c6d0baef8aa4ff5fe4ad72c9c8b42bd5f563b9529eabcfb32322dc820ca573ae`
- **Holds:** a standalone rtpengine relay's view with its `ng` control plane
  mirrored over HEP: offer, answer and delete with their replies, and forty
  relayed RTP packets on four sockets. No SIP. It proves relay media is
  attributed from the control plane alone. Rebuilt in September 2026 from a
  live rtpengine 12.5.1 capture, keeping its wire shapes and timing and
  replacing every address, MAC address and cookie; the generator's comments
  list what was kept.

### tests/fixtures/rtpengine-media-only.pcap

- **Category:** synthetic
- **Generator:** `tests/support/synthetic_captures.rs` (`rtpengine_media_only`)
- **SHA-256:** `e1d2bab40c1edfa26860fbd35fd7f2bc4a1d9ed74386a7c55183be3bd80b7a3c`
- **Holds:** `rtpengine-ng-hep.pcap` without its six HEP datagrams and
  nothing else changed. The control case: every stream is an orphan again.

### fuzz/corpus/pcap_reader/truncated-sip

- **Category:** synthetic
- **Generator:** `tests/support/synthetic_captures.rs` (`truncated_sip`)
- **SHA-256:** `06e533089c121d96a23a04ea1831aa15b0e0ff1aa67150cc8791734e30625092`
- **Holds:** a fuzz seed: a whole INVITE, a 180 snapped below its wire
  length, and a 200 OK the file ends inside. Until September 2026 this seed
  was a byte-for-byte copy of `tests/pcap-samples/metasploit-sip-invite-spoof.pcap`,
  a third-party capture.

### fuzz/corpus/pcap_reader/empty-classic

- **Category:** synthetic
- **Generator:** `tests/support/synthetic_captures.rs` (`empty_classic`)
- **SHA-256:** `08c3d02499871c6447d6cdbd4c6f96dce479a0070fb0707e4a1e30a93a594133`
- **Holds:** a fuzz seed: a classic pcap header with snaplen zero and no
  records.

### fuzz/corpus/pcap_reader/sip-register.pcap

- **Category:** synthetic
- **Generator:** `tests/gen-pcap-samples.py`
- **SHA-256:** `c625d04b63ff5504171c4c5001e01a9f7bba5cb577c7418c2ddb48f97328e337`
- **Holds:** a fuzz seed, the generator's copy of
  `tests/pcap-samples/sip-register.pcap`.
  `python3 tests/gen-pcap-samples.py --check` confirms both match it, and
  `the_fuzz_seed_matches_the_sample_it_copies` keeps the two identical.

### website/static/demos/sample-call.pcap

- **Category:** synthetic
- **Generator:** `demos/gen-sample-call.py`
- **SHA-256:** `f06fefa653d20a502876ab61f1977947e7de7896eb439842ff84166cf7869be8`
- **Holds:** the capture the browser analyzer and the demo recordings load:
  registrations, an answered call with media, and three subscriptions, all on
  RFC 5737 addresses. `python3 demos/gen-sample-call.py <out>` writes the same
  bytes.

### harness/sipp/scenarios/g711a.pcap

- **Category:** synthetic
- **Generator:** `tests/support/synthetic_captures.rs` (`g711a_media`)
- **SHA-256:** `f90e397973accbaddf0b1f102afc8d76cbb7d0471cf4ec6c5a5a72097177b37c`
- **Holds:** the audio `uac_hold.xml` hands SIPp's `play_pcap_audio`: 5,535
  G.711 A-law RTP packets, 20 ms apart, carrying a 500 Hz and a 1.5 kHz tone
  from `tests/support/codecs.rs`. SIPp sends only the RTP, so the addresses
  around it (192.0.2.10 to 192.0.2.20) never leave the file. Until September
  2026 this was a copy of a third-party capture that stated no license. The
  packet count, payload type and framing are the old file's.

### harness/sipp/scenarios/g722.pcap

- **Category:** synthetic
- **Generator:** `tests/support/synthetic_captures.rs` (`g722_media`)
- **SHA-256:** `776e6d8b224a380717111b56f63a186e6c787326e22c3bda745588e8573c54e4`
- **Holds:** the audio `uac_pcap_g722.xml` plays: 5,413 G.722 RTP packets, 20
  ms apart, carrying a 1 kHz and a 5 kHz tone. The G.722 encoder in
  `tests/support/codecs.rs` agrees byte for byte with spandsp and FFmpeg,
  which the suite checks on two vectors. Until September 2026 this was a copy
  of a third-party capture that stated no license. The packet count, payload
  type and framing are the old file's.

### tests/fixtures/rtpengine-opensips-ng.pcap

- **Category:** synthetic
- **Generator:** `tests/support/synthetic_captures.rs` (`rtpengine_opensips_ng`)
- **SHA-256:** `57bf2dbac100704d0701de611124d26fbc22015d844c2c3bd21d2ac3097aac40`
- **Holds:** a separate rtpengine relay's view of a call OpenSIPS set up: four
  HEP datagrams mirroring `offer` and `answer` with their replies, 21 G.722
  packets from the caller and 19 PCMU packets the relay transcoded from them,
  and no SIP. The caller's packets are the first 21 of `g722.pcap`, as SIPp
  replays them. It proves that the Call-ID `1-4062@198.51.100.21` reaches a
  host that captured no signaling. Rebuilt in September 2026 from a harness
  capture whose audio came from the third-party `g722.pcap`. The rebuild keeps
  that capture's control-plane shapes and timing and moves its addresses into
  198.51.100.0/24.

### tests/fixtures/rtpengine-opensips-media-only.pcap

- **Category:** synthetic
- **Generator:** `tests/support/synthetic_captures.rs` (`rtpengine_opensips_media_only`)
- **SHA-256:** `d72375dbf3660a5162f0d61b9d72267041125ee4d9a5aff356345f478f5433a4`
- **Holds:** `rtpengine-opensips-ng.pcap` without its four HEP datagrams and
  nothing else changed: the control case, in which nothing names the streams.

### tests/fixtures/ice_checks.pcap

- **Category:** synthetic
- **Generator:** `tests/support/synthetic_captures.rs` (`ice_checks`)
- **SHA-256:** `988ddf78642b76f11e18f711a39dd4cecaf1427ac1db991b1162476468bcd4e8`
- **Holds:** two ICE connectivity-check exchanges: one pair that succeeds, with
  a nominating check, and one that fails both ways with 487 Role Conflict. It
  was built by hand before any generator existed, and the generator
  reproduces it byte for byte, so the hash did not change.

### tests/fixtures/turn_relay.pcap

- **Category:** synthetic
- **Generator:** `tests/support/synthetic_captures.rs` (`turn_relay`)
- **SHA-256:** `09919edc9aaf3dd95aab2c72a6767f7ab8d0830b5f8b4db08194d6055b687da0`
- **Holds:** a TURN allocation, a permission, a channel binding, one Send
  indication and 152 ChannelData frames of RTP and RTCP between 192.0.2.10
  and a peer at 203.0.113.9. It was built by hand before any generator
  existed, and the generator reproduces it byte for byte, so the hash did not
  change.

### tests/fixtures/stun_nat_probe.pcap

- **Category:** synthetic
- **Generator:** `tests/support/synthetic_captures.rs` (`stun_nat_probe`)
- **SHA-256:** `24e5128c1063d6d5f457342f10308bbab02e0def33fd63552696ff3350a175b6`
- **Holds:** a STUN Binding request that goes unanswered and is retransmitted,
  and a second one answered with a reflexive address. Built by hand until
  September 2026. The generator reproduces the old frames except for the MAC
  addresses, which moved into the RFC 7042 documentation block.

### tests/fixtures/stun_sdp_mismatch.pcap

- **Category:** synthetic
- **Generator:** `tests/support/synthetic_captures.rs` (`stun_sdp_mismatch`)
- **SHA-256:** `33606c69d97fe2d79660a626815c87699ea8e58426490dd911f958aed524e6b9`
- **Holds:** a phone behind NAT that gets no STUN answer, then calls with its
  private address, 192.168.10.50, in its SDP, and receives media from
  203.0.113.7. The RFC 1918 address is deliberate: it is the mismatch the
  fixture exists to show, and the only address outside RFC 5737 in the file.
  Built by hand until September 2026. The generator reproduces the old frames
  except for the MAC addresses, now in the RFC 7042 block, and the two SDP
  bodies' `Content-Length`, which the original gave as 126 for a 134-byte
  body.
