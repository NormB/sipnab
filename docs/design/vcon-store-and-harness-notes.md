# vCon delivery pages: measurements and history

The engineering record behind three operator pages:
[`docs/vcon-store.md`](../vcon-store.md),
[`docs/vcon-harness.md`](../vcon-harness.md) and
[`docs/vcon-sipnab.md`](../vcon-sipnab.md). Those pages say what to run. This
page keeps the dated measurements and the history that explain why they read
as they do.

## vcon.store

### Status as recorded on 2026-10-11

vcon.store accepted the two forms it refused on 2026-10-07:

- `extensions` as the array of strings both vCon drafts define.
- the `recording` Dialog Object without `parties` that sipnab then wrote for a
  call whose container carried no audio. (sipnab 0.5.222 writes `parties` on
  that object; a recording that carries audio still has no `parties` when an
  audio channel came from an address no party advertised in its SDP.)

Not measured: a `recording` that carries audio but no `parties`.

The `vcon-store` forward kind is tested against two stand-ins in
[`tests/vcon_forward_test.rs`](../../tests/vcon_forward_test.rs), not against
vcon.store itself: one answers as the maintainer measured vcon.store answering
on 2026-10-11, the other as it did on 2026-10-07.

### The measurements

The maintainer measured these against vcon.store's API.

On 2026-10-09, the maintainer used the sipnab 0.5.209 release binary and a
container exported from
[`tests/pcap-samples/sip-rtp-g711.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-rtp-g711.pcap):

| Sent | vcon.store answered |
|---|---|
| `POST /v1/vcons`, the container with audio, `"extensions": ["sip-signaling", "CC"]`, sent unchanged | `201`; a `GET` returned `extensions` as the same array |
| the `recording` Dialog Object sipnab writes for a call without audio (no `parties`, no content) | `201`, stored as sent |
| a `POST` of a uuid the store already held | `500`, a problem document of type `https://vcon.store/errors/internal-error`, `An unexpected error occurred`, twice. Changed by 2026-10-11; see below |
| a `GET` with Python's default HTTP `User-Agent`, with Go's, with none, and with `sipnab/0.5.209` | `200` for each |
| a `GET` of a stored vCon | the content, with a top-level `_meta` member added |
| `DELETE /v1/vcons/{uuid}` | `200`, `{"deleted":true,...}`; a `GET` after it `404`, `{"error":"vCon not found"}` |

On 2026-10-11, with a container exported from the same capture, sent with curl:

| Sent | vcon.store answered |
|---|---|
| `POST /v1/vcons`, a new uuid | `201`, `{"uuid":...,"stored_at":...}` |
| a second `POST` of the same uuid | `409`, `{"error":"vCon already exists","details":[{"path":["uuid"],"message":"a vCon with uuid ... already exists; use PUT to replace it"}]}` |
| `PUT /v1/vcons/{uuid}` with a changed `subject`, same uuid | `200`; a `GET` returned the changed `subject` |
| the `recording` Dialog Object without `parties` and content | `201` |
| `DELETE /v1/vcons/{uuid}` | `200`; a `GET` after it `404` |

On 2026-10-07, kept as history:

| Sent | vcon.store answered |
|---|---|
| `POST /v1/vcons` with `"extensions": ["sip-signaling", "CC"]` | `400`, `extensions: Expected object, received array` |
| the same with `extensions` as an object of names mapped to `true` | `201`, stored as sent |
| a vCon with no audio, whose Dialog Object is `{}` | `400`: the store required `type` and `parties` |
| the same with `extensions` removed | `201` |
| a request with Python's default HTTP `User-Agent` | `403`, `error code: 1010`, from the Cloudflare front. The front accepted a curl `User-Agent` |

### What the store added, 2026-10-09

On each create the store wrote one entry to its transparency log (SCITT). The
entry held:

- the event `vcon_created`,
- a SHA-256 hash of the payload,
- a COSE signed statement,
- a receipt.

Each stored vCon also came back with a `_meta` envelope. It said:

- `form: unsigned`,
- `consentStatus: unknown`,
- `retentionAction: redact`.

The containers measured were unsigned `--export-vcon-dir` output. sipnab signs
a container only when a `[[vcon.rule]]` sets `sign_only = true` (a bare JWS)
or `encrypt_to` (signed, then encrypted). An earlier revision of the operator
page said sipnab never signs; that was wrong once `sign_only` existed.

### The fetch round trip, 2026-10-09

- sipnab exported a container from
  [`tests/pcap-samples/sip-rtp-g711.pcap`](../../tests/pcap-samples/sip-rtp-g711.pcap).
- `--vcon-forward-kind vcon-store` sent it (`201`).
- `--vcon-fetch` read it back. The file held `extensions` as the array and no
  `_meta`.
- A delete then removed it (`200`).
- A read after the delete answered `404`.

The 2026-10-07 `403` with `error code: 1010` came from the Cloudflare front,
which refused Python's default `User-Agent` and accepted curl's. The forwarder
sends `User-Agent: sipnab/<version>`.

## The capture-stack harness

### Why the harness separates namespaces

Two sipnabs on one interface read the same packets and return the same
answers. They are two copies of one capture point, and cannot show that a leg
seen at the proxy is the leg seen at the relay. Giving rtpengine its own
namespace makes them different.

The topology carries what a flag could: sipnab has `--no-rtp` for a
signaling-only capture and no counterpart for media, so nothing expresses
"watch only the relay half". Two instances in one namespace would work if
each could be told what it is for. The split is the current arrangement, not
a requirement.

### History behind two troubleshooting entries

- Before 0.5.128 sipnab typed a recording placeholder `incomplete`. The vCon
  draft defines that as a call that failed to reach conversation, so a
  signaling-only container reported every answered call as a failure. 0.5.128
  types it `recording`.
- Before 0.5.128, `--hep-parse` unwrapped the HEP datagram and discarded the
  wrapper that identifies mirrored rtpengine `ng`, so a relay with everything
  else correct named no stream.
- The harness's sample vCon from 0.5.127 showed a `recording-set` object and a
  30.0 s recording of an 89.988 s call. sipnab no longer writes
  `recording-set`; the operator page now shows a container exported from a
  committed capture.

### The stereo exporter

A relay sees each direction of a call arriving and leaving, so a two-party
call reaches an exporter as four stream records carrying two SSRCs, and the
two records of one leg can precede either record of the other. An exporter
that takes the first two streams it finds selects one voice twice and writes
a stereo file with byte-identical channels.

sipnab's exporter walks the exportable streams in first-seen order, keeps one
per SSRC, takes two, and falls back to mono when only one source is present.
The omission caveat counts sources, not records, for the same reason:
counting records would report two of four streams missing on a call where
sipnab captured both parties, and a caveat naming a loss that never happened
teaches readers to disregard caveats.

## The vCon server guide

[`docs/vcon-sipnab.md`](../vcon-sipnab.md) history:

- Up to 0.5.192 sipnab captured only the SIP ports by default; later versions
  capture the media too. The guide's capture filter names the media ports
  either way.
- `sipnab --vcon-forward` ships in releases after 0.5.204. The guide's tested
  steps use the Python forwarder, [`clients/python/vcon_forward.py`](https://github.com/NormB/sipnab/blob/main/clients/python/vcon_forward.py).
