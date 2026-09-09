# Where these capture fixtures came from

Each entry below describes one committed capture: the run that produced it, the
media anchor in force, and **the finding it pins**. That last line is the point
of the file. A fixture whose purpose nobody wrote down is one the next person
to change a parser cannot reason about, because they cannot tell whether its
assertion is load-bearing or incidental.

Entries are written by `harness/scripts/promote.sh` from the provenance record
`harness/scripts/capture.sh` wrote at the time of capture. Do not add one by
hand: the point is that the facts come from the running stack rather than from
memory, and `every_committed_capture_fixture_says_where_it_came_from` in
`tests/repo_hygiene_test.rs` checks that every entry carries every label.

**Most captures should never get here.** `LIVE4` in
[`docs/design/backlog.md`](../../docs/design/backlog.md) gives every capture
one of three homes, decided when it is taken: a committed fixture, the private
corpus reached through `SIPNAB_CORPUS`, or deletion — and **deletion is the
default**. A capture that sits undecided is one `git add -A` away from being
the wrong answer permanently.

**Fixtures that predate this file** are listed in that same test rather than
here. Most are third-party captures whose provenance nobody in this repository
can now establish, and inventing one would be worse than admitting the gap.
They come off that list by gaining a real entry, never by being described from
memory.

### opensips-direct-media-proxy-view.pcap

- **Taken:** 2026-09-09T14:24:03Z from the docker-compose harness, 110s
- **Media anchor:** none
- **Filter:** `udp`
- **Packets:** 13
- **SHA-256:** `d4174d6554b9f539dcd39dd091e29e5283e1bf7171734674a809b725c42dda09`
- **Pins:** the proxy-side view of a call with NO media anchor: OpenSIPS relays the signaling and the media goes endpoint-to-endpoint, so a capture at the proxy holds a complete dialog and ZERO RTP streams. The control case for stream attribution -- sipnab must report no streams rather than infer them from SDP
