# MOS and codecs

**What the quality number means, and when it means nothing.**

sipnab reports a MOS for every RTP stream. MOS means mean opinion score. It is
an estimate from 1.0 to 4.5 of how the call sounded. This page says:

- where that number comes from,
- which codecs have a published basis for it,
- **which codecs do not**, and how to tell from the output.

The short version:

| Codec | Basis | What sipnab reports |
|---|---|---|
| G.711 (PCMU / PCMA) | ITU-T G.113 Table I.1, `Ie = 0` | Narrowband MOS, grounded |
| G.729 | ITU-T G.113 Table I.1, `Ie = 10` | Narrowband MOS, grounded |
| Opus | Treated as G.711-equivalent | Narrowband MOS, grounded |
| **AMR-WB** (G.722.2) | ITU-T G.113 Tables IV.1 / IV.3 | **Wideband MOS — needs the mode** |
| **AMR narrowband** | **No published value** | Placeholder, flagged |
| **EVS** | Fullband only, SWB mode | Placeholder, flagged |
| G.722, G.726, iLBC, everything else | Not implemented | Placeholder, flagged |

Anything in the last three rows scores **4.216 at 10 ms jitter, no loss and the
assumed 100 ms one-way delay — the same value an unidentified stream gets.**
That is a placeholder, not a measurement.

Every door that publishes the number publishes what it is worth, in the same
words:

| Surface | How it says so |
|---------|----------------|
| MCP `rtp_stats` | `mos_grounded: false`, `mos_grounding: "unpublished"`, `mos_note` |
| `GET /v1/streams` | the same three keys on every row |
| `GET /v1/streams?mos_below=` | **never selects an ungrounded stream**, and reports `ungrounded_excluded` |
| MCP `rtp_stats` with `min_mos`/`max_mos` | the same refusal, and the same count |
| TUI stream detail | the score renders muted rather than in a quality band, annotated `no published Ie` |
| The in-browser analyzer on sipnab.com | the score renders dimmed and italic, outside the good/fair/poor scale entirely, and the summary counts what it could not score |

A placeholder is a number in the normal range that means "unknown". A MOS
bound applied without the grounding test would select streams sipnab could
not score, so the MOS filters never select an ungrounded stream.

## Tell a scored MOS from a placeholder

Read the stream rows of `--json-dialogs`. This capture carries one G.722
stream:

```sh
sipnab -N -I tests/pcap-samples/sip-rtp-g722.pcap --no-cli-print --json-dialogs | jq -c '.streams[] | {codec, mos, mos_grounded, mos_grounding, mos_note}'
```

```text
{"codec":"G722","mos":4.223031873799741,"mos_grounded":false,"mos_grounding":"unpublished","mos_note":"No published ITU-T G.113 impairment value for this codec, and none declared in [media.codec_ie]. The MOS is a placeholder meaning 'unknown', not an estimate."}
```

`mos_grounded: false` means the `mos` value is the placeholder. Disregard it,
or declare an impairment factor for the codec as the next section shows.

`--call-report` prints the same verdict in words. For a stream without a
grounded score its RTP line reads `mos=unknown (unpublished)`:

```sh
sipnab -N -I tests/pcap-samples/sip-rtp-g722.pcap --call-report 1-2161@10.0.2.20
```

```text
…
  RTP 10.0.2.15->10.0.2.20 G722 SSRC=0x043daaba pkts=425 jitter=0ms loss=0.0% mos=unknown (unpublished)
…
```

## Declare an impairment factor for a codec

If you know the `Ie` (equipment impairment factor) for a codec on your own
network, declare it in the config file and sipnab scores with it. Put this in
`ie.toml`:

```toml
[media.codec_ie]
G722 = 12.0
iLBC = 11.0
```

Keys match case-insensitively. Run with the file:

```sh
sipnab -N -f ie.toml -I tests/pcap-samples/sip-rtp-g722.pcap --no-cli-print --json-dialogs | jq -c '.streams[] | {codec, mos, mos_grounded, mos_grounding, mos_note}'
```

```text
{"codec":"G722","mos":3.9778406565751645,"mos_grounded":true,"mos_grounding":"operator_declared","mos_note":"ITU-T G.113 publishes no impairment value for this codec; this deployment declared the one used, in [media.codec_ie]. The MOS is an estimate on the operator's figure, not on a published one."}
```

A declared codec reports `mos_grounding: "operator_declared"`, never
`published`. When a declared score looks wrong, check the value in your
config file. When a `published` score looks wrong, check where the capture
point sits on the media path.

A declared value must be `>= 0` and `< 95`. sipnab refuses any other value,
names the codec, and exits 1:

```text
invalid config value: [media.codec_ie] G722 must be >= 0 and < 95 (at or above that the E-model's loss term goes negative and MORE packet loss would RAISE the score), got 95
```

A codec nobody declared still scores as the placeholder and still says so.

Declaring one does not rescue AMR-WB. Its published values are on the wideband
scale. The narrowband model cannot carry them. See [AMR-WB — published, and
mode-dependent](#amr-wb-published-and-mode-dependent) below.

## What sipnab computes the score from

The loss and jitter behind the score are sipnab's own measurements of the
captured media. The one-way delay comes from the first of these that exists:

1. the delay you declare, with `--one-way-delay` or `[media] one_way_delay_ms`;
2. half the round trip the far end reported in RTCP;
3. half the round trip sipnab derives from an RTCP receiver report's
   sender-report echo, which reads as a lower bound;
4. otherwise 100 ms, labeled `assumed`.

MCP `rtp_stats` names the delay's source in each row's `delay` member.

What the far end reported about loss, jitter and its own quality score never
moves sipnab's MOS. MCP `rtp_stats` returns it separately, under
`endpoint_reported`, omitted when no RTCP arrived:

| What the far end sent | Key under `endpoint_reported` | Carries |
|---|---|---|
| Reception report (SR/RR, [RFC 3550](https://www.rfc-editor.org/rfc/rfc3550.html)) | `reception_report` | Loss fraction, cumulative loss, interarrival jitter, round trip |
| VoIP Metrics (RTCP XR, [RFC 3611](https://www.rfc-editor.org/rfc/rfc3611.html) Section 4.7) | `voip_metrics` | The endpoint's own R-factor, MOS-LQ and MOS-CQ, burst and gap durations, round-trip and end-system delay, loss and discard rates |

The XR discard rate counts packets that arrived at the endpoint and that its
jitter buffer dropped. Those packets appear in the capture and never reached
the listener, so no capture can measure them.

sipnab keeps these apart for two reasons:

- Nothing authenticates RTCP. Anything that can reach the port can assert a
  loss figure.
- A reception report describes the path *from the sender to that reporter*.
  On a mid-path capture, that is a different segment from the one in front of
  sipnab.

So a stream's MOS may disagree with the far end's reported figures, and the
difference locates the fault:

- If the reporter sees loss and sipnab does not, the loss happened downstream
  of the capture point.
- If sipnab measures loss and the reporter does not, it happened upstream.

## Why there is more than one scale

The E-model produces an R-factor, which converts to MOS. There are three of
them, and they are **not interchangeable**:

| Model | Anchor | MOS symbol | For |
|---|---|---|---|
| ITU-T G.107 | `Ro = 93.2` | `MOS_CQE` | Narrowband |
| ITU-T G.107.1 | `Ro,WB = 129` | `MOS_CQEW` | Wideband |
| ITU-T G.107.2 | computed | `MOS_CQEF` | Fullband |

A wideband 4.42 and a narrowband 4.35 describe different things. **Do not
average them, plot them on one axis, or compare them against one threshold.**

A wideband `Ie,WB` in the narrowband equation is a 35.8-point scale error.
So sipnab scores AMR-WB on the wideband scale, not in the narrowband table
beside G.729.

## AMR-WB — published, and mode-dependent

G.113 publishes an impairment factor for all nine AMR-WB modes. The spread is
large. The mode outweighs most of the impairments this model accounts for:

### Monotic listening — handset or monaural headset

G.113 (09/2024) Table IV.1.

| kbit/s | `Ie,WB` | MOS at zero loss |
|---|---|---|
| 23.85 | 8 | 4.42 |
| 23.05 | 1 | 4.49 |
| 19.85 | 3 | 4.48 |
| 18.25 | 5 | 4.46 |
| 15.85 | 7 | 4.43 |
| 14.25 | 10 | 4.39 |
| 12.65 | 13 | 4.34 |
| 8.85 | 26 | 4.02 |
| 6.6 | 41 | 3.51 |

### Diotic listening — stereo headset or speakerphone

G.113 (09/2024) Table IV.3.

| kbit/s | `Ie,WB` | MOS at zero loss |
|---|---|---|
| 23.85 | 10 | 4.39 |
| 23.05 | 8 | 4.42 |
| 15.85 | 17 | 4.25 |
| 12.65 | 20 | 4.18 |
| 8.85 | 41 | 3.51 |
| 6.6 | 56 | 2.92 |

Three modes — 19.85, 18.25 and 14.25 — have **no published diotic value**.
sipnab returns no score for them and does not interpolate: the series they
sit in is not monotonic, so their neighbors do not bound them.

Two properties of these tables to keep in mind:

- **23.85 kbit/s scores worse than the slower 23.05.** `Ie,WB` is 8 against 1.
  - The inversion recurs across Tables IV.1, IV.3 and IV.4.
  - Do not rank AMR-WB modes by bitrate and expect quality to follow.
- **Listening context is worth up to 15 R-points** — about 0.59 MOS at
  6.6 kbit/s.
  - sipnab reads wideband scores as monotic (a handset) unless
    `[media] listening_context = "diotic"` says otherwise.
  - Every wideband score names the context sipnab read it in.

### Under packet loss, most of it is not computable

G.113 Table IV.4 publishes the loss-robustness factor `Bpl,wb` for **three
modes, diotic only, uniform loss only** — 23.85, 23.05 and 12.65. G.113 states
that no values exist for non-uniform loss or for monotic presentation.

So **sipnab cannot score AMR-WB with packet loss on a handset** from published
data. It reports that, and does not borrow the diotic figure.

### sipnab needs the mode, and the codec name does not carry it

`AMR-WB` alone spans `Ie,WB` 1 to 41 — roughly 4.49 down to 3.51. Two ways to
pin it:

- **SDP `a=fmtp` `mode-set` naming exactly one mode.**
  - [RFC 4867 section 8.1](https://www.rfc-editor.org/rfc/rfc4867.html#section-8.1)
    numbers the modes 0–8 in ascending bitrate. So `mode-set=2` is 12.65 kbit/s.
  - A multi-mode set says what the stream *may* do, not what it did.
  - Senders switch mode per frame under congestion.
- **The RTP payload header**, per frame.

Without one of those, sipnab flags the stream rather than guessing.

### Where the wideband score appears

| Surface | What it carries |
|---|---|
| `GET /v1/streams` | `mos_wideband`, `mos_wideband_context`, `mos_wideband_unavailable` |
| MCP `rtp_stats` | the same three fields |
| TUI stream detail | a `MOS_CQEW` row naming the scale, the mode and the listening context |

The terminal row carries no quality band and no color, because the bands
follow the narrowband scale.

- A stream sipnab did not score on the wideband scale gets no row.
- A stream sipnab cannot score says why in words.

The call report and the vCon export carry the narrowband score:

- `--call-report` prints `mos=<value> R=<value>` on each RTP line, or
  `mos=unknown (<grounding>)` when the score is not grounded.
- A vCon's `report` analysis lists each stream under `media_quality`, with
  `mos`, `mos_grounded` and `mos_grounding`, and the wideband fields when a
  wideband score exists.

## AMR narrowband — no published value

ITU-T G.113 (09/2024) has **no AMR-NB row**.

- Not in Table I.1, not in Table I.3.
- A whole-document search for "AMR" returns only G.722.2 (= AMR-WB) references.
- There is no 3GPP TS 26.071 or 26.090 citation anywhere.

Two codecs sit at coincident bitrates and are tempting substitutes:

- GSM-EFR at 12.2 kbit/s, `Ie = 5`
- TIA IS-641 at 7.4 kbit/s, `Ie = 10`

Both are close algorithmic relatives of AMR-NB modes. **sipnab does not
substitute them.**

- They are different codecs with different references.
- G.113 does not provide for transferring their values.
- sipnab does not E-model score a narrowband AMR call: no published ITU data
  supports one.

## EVS — fullband only

G.113 Appendix V publishes `Ie,fb` for EVS in **SWB mode, diotic**, on the
G.107.2 fullband scale:

| kbit/s | `Ie,fb` | `Bpl,fb` |
|---|---|---|
| 48 | 10.2 | 9.6 |
| 32 | 8.7 | 9.3 |
| 24.4 | 7.2 | 11.4 |
| 16.4 | 10.8 | 10.3 |
| 13.2 | 17.1 | 11.7 |
| 9.6 | 22.7 | 13 |

There is **no EVS `Ie,WB` and no EVS narrowband `Ie`**.

- EVS in NB, WB and AMR-WB-IO modes has no published value on any scale.
- G.113's bridge `Ie,fb ≈ Σ Ie,wb + 19` runs in one direction only.
- sipnab does not run it backwards to derive a wideband EVS value, which
  would also carry the diotic assumption across.

The second row is 32 kbit/s as ITU-T G.113 (2024) Erratum 1 (January 12,
2026) corrects it. The G.113 (09/2024) PDF prints it as 2 kbit/s.

## Provenance

- **ITU-T G.113 (09/2024)** Appendix I Table I.1; Appendix IV Tables IV.1,
  IV.3, IV.4; Appendix V Tables V.1, V.3 — **plus Erratum 1 (01/2026)**.
- **ITU-T G.107.1 (06/2019)** as amended by **Corrigendum 1 (01/2020)**. Use
  Cor.1: it is a complete-text publication, and the 06/2019 text alone carries
  a superseded Eq (7-6) written in terms of a quantity the wideband model never
  defines.
- **ITU-T G.107.2 (03/2023)** for the fullband scale.
- **[RFC 4867 section 8.1](https://www.rfc-editor.org/rfc/rfc4867.html#section-8.1)** for AMR / AMR-WB payload format and `mode-set`.

Any report built on these numbers carries this caveat:
<!-- The two phrases below quote G.113 verbatim; rewording them to satisfy the
     passive-voice rule would misquote a standard. -->
<!-- vale Google.Passive = NO -->
each G.113 appendix states *"This appendix does not form an integral part of
this Recommendation"* and labels its contents *"provisional planning values …
intended to be updated regularly"*.
<!-- vale Google.Passive = YES -->

They are planning figures for network design, not measurements of the call in
front of you. Only G.107.1 Annex A — the R-to-MOS conversion itself — is
normative.

## Using the model in code

`sipnab::rtp::emodel_wb` exposes the wideband model to anyone
[using sipnab as a library](library.md#crate-root-surface):

```rust
use sipnab::rtp::emodel_wb::{amr_wb_mos, amr_wb_kbps_from_fmtp, ListeningContext};

// Mode pinned by the SDP, no loss.
let kbps = amr_wb_kbps_from_fmtp("octet-align=1; mode-set=2").unwrap(); // 12.65
let mos = amr_wb_mos(kbps, ListeningContext::Monotic, 0.0);
// A computed MOS is a float: compare with a tolerance, never `==`.
assert!((mos.unwrap() - 4.3371).abs() < 5e-4);

// Same mode, monotic, with loss: not computable, and it says so.
assert_eq!(amr_wb_mos(kbps, ListeningContext::Monotic, 1.0), None);
```

Every lookup in that module returns `Option`. The lookups are `amr_wb_ie`,
`amr_wb_bpl`, `amr_wb_mos` and `amr_wb_kbps_from_fmtp`.

- Each returns `None` wherever G.113 publishes nothing, rather than
  interpolating into the gap.
- The three arithmetic steps beside them (`ie_eff_wb`, `r_wb`, `r_wb_to_mos`)
  take numbers you already have and return an `f64`.
