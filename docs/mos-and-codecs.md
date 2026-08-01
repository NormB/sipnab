# MOS and codecs

**What the quality number means, and when it means nothing.**

sipnab reports a MOS for every RTP stream. This page says where that number
comes from, which codecs have a published basis for it, and — the part that
matters during an incident — **which ones do not**.

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

Anything in the last three rows scores **4.216 at 10 ms jitter — the same value
an unidentified stream gets.** That is a placeholder, not a measurement. Tools
that publish it say so: the `rtp_stats` MCP tool carries `mos_grounded: false`
and a note.

## MOS comes from what sipnab measured, never from what the far end claimed

The jitter and loss behind the score come from sipnab's own observation of the
captured media. sipnab keeps RTCP reception reports separately — read them via
`StreamStore::remote_report` — and never feeds them to the score.

Two reasons. Nothing authenticates RTCP, so anything that can reach the port can
assert a loss figure. If that figure moved the MOS, an attacker would control the
quality number. And a reception report describes the path *from the sender to
that reporter*, which on a mid-path capture is a different segment from the one
in front of sipnab. The report may be perfectly true and still not describe the
traffic in the file.

So a stream's MOS may disagree with the far end's reported MOS. **That
disagreement is information, not an error** — it localises the fault. If the
reporter sees loss and sipnab does not, the loss happened downstream of the
capture point. If sipnab measures loss and the reporter does not, it happened
upstream.

## Why there is more than one scale

The E-model produces an R-factor, which converts to MOS. There are three of
them and they are **not interchangeable**:

| Model | Anchor | MOS symbol | For |
|---|---|---|---|
| ITU-T G.107 | `Ro = 93.2` | `MOS_CQE` | Narrowband |
| ITU-T G.107.1 | `Ro,WB = 129` | `MOS_CQEW` | Wideband |
| ITU-T G.107.2 | computed | `MOS_CQEF` | Fullband |

A wideband 4.42 and a narrowband 4.35 describe different things. **Do not
average them, plot them on one axis, or compare them against one threshold.**
Feeding a wideband `Ie,WB` into the narrowband equation is not a rough
approximation — it is a 35.8-point scale error that produces a plausible,
confidently wrong number.

This is why AMR-WB is not simply added to the narrowband table alongside G.729.

## AMR-WB — published, and mode-dependent

G.113 publishes an impairment factor for all nine AMR-WB modes. The spread is
large enough that the mode outweighs most of the impairments this model
accounts for:

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
sipnab returns nothing for them rather than interpolating, because the series
they sit in is not monotonic and neighbours do not bound them.

Two things about these tables surprise people, and both are real:

- **23.85 kbit/s scores worse than the slower 23.05.** `Ie,WB` is 8 against 1.
  The inversion recurs across Tables IV.1, IV.3 and IV.4, so it reflects
  published intent. Do not rank AMR-WB modes by bitrate and expect quality to follow.
- **Listening context is worth up to 15 R-points** — about 0.59 MOS at
  6.6 kbit/s. It is an explicit input with no default, because assuming one
  would be a bigger error than most impairments in the model.

### Under packet loss, most of it is not computable

G.113 Table IV.4 publishes the loss-robustness factor `Bpl,wb` for **three
modes, diotic only, uniform loss only** — 23.85, 23.05 and 12.65. G.113 states
that no values exist for non-uniform loss or for monotic presentation.

So **sipnab cannot score AMR-WB with packet loss on a handset** from published
data. It reports that rather than borrowing the diotic figure, which would
silently mix two listening contexts inside one equation.

### sipnab needs the mode, and the codec name does not carry it

`AMR-WB` alone spans `Ie,WB` 1 to 41 — roughly 4.49 down to 3.51. Two ways to
pin it:

1. **SDP `a=fmtp` `mode-set` naming exactly one mode.** RFC 4867 §8.1 numbers
   the modes 0–8 in ascending bitrate, so `mode-set=2` is 12.65 kbit/s.
   A multi-mode set says what the stream *may* do, not what it did — senders
   switch mode per frame under congestion.
2. **The RTP payload header**, per frame.

Without one of those, sipnab flags the stream rather than guessing.

## AMR narrowband — no published value

ITU-T G.113 (09/2024) has **no AMR-NB row**. Not in Table I.1, not in Table
I.3. A whole-document search for "AMR" returns only G.722.2 (= AMR-WB)
references. There is no 3GPP TS 26.071 or 26.090 citation anywhere.

Two codecs sit at coincident bitrates and are tempting substitutes:

- GSM-EFR at 12.2 kbit/s, `Ie = 5`
- TIA IS-641 at 7.4 kbit/s, `Ie = 10`

Both are close algorithmic relatives of AMR-NB modes. **sipnab does not
substitute them.** They are different codecs with different references, and
G.113 does not license transferring their values. A narrowband AMR call cannot
be E-model scored from published ITU data, and saying so is the honest answer.

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

There is **no EVS `Ie,WB` and no EVS narrowband `Ie`**. EVS in NB, WB and
AMR-WB-IO modes has no published value on any scale. G.113's bridge
`Ie,fb ≈ Σ Ie,wb + 19` runs in one direction only. Running it backwards to
manufacture a wideband EVS value counts as prohibited interpolation, and it
drags the diotic assumption across with it.

> **If you are transcribing this table yourself:** the G.113 (09/2024) PDF
> prints the second row as **2 kbit/s**. That is a typo, corrected by ITU-T
> G.113 (2024) Erratum 1 (January 12, 2026) to **32 kbit/s**. A pipeline built
> from the base PDF alone ships a mode that does not exist and omits one that
> does.

## Provenance

- **ITU-T G.113 (09/2024)** Appendix I Table I.1; Appendix IV Tables IV.1,
  IV.3, IV.4; Appendix V Tables V.1, V.3 — **plus Erratum 1 (01/2026)**.
- **ITU-T G.107.1 (06/2019)** as amended by **Corrigendum 1 (01/2020)**. Use
  Cor.1: it is a complete-text publication, and the 06/2019 text alone carries
  a superseded Eq (7-6) written in terms of a quantity the wideband model never
  defines.
- **ITU-T G.107.2 (03/2023)** for the fullband scale.
- **RFC 4867 §8.1** for AMR / AMR-WB payload format and `mode-set`.

One caveat that belongs in any operator-facing report built on these numbers:
<!-- The two phrases below quote G.113 verbatim; rewording them to satisfy the
     passive-voice rule would misquote a standard. -->
<!-- vale Google.Passive = NO -->
each G.113 appendix states *"This appendix does not form an integral part of
this Recommendation"* and labels its contents *"provisional planning values …
intended to be updated regularly"*. They are planning figures for network
design, not measurements of the call in front of you. Only G.107.1 Annex A —
the R-to-MOS conversion itself — is normative.
<!-- vale Google.Passive = YES -->

## Using the model in code

[`sipnab::rtp::emodel_wb`](library.md) exposes the wideband model:

```rust
use sipnab::rtp::emodel_wb::{amr_wb_mos, amr_wb_kbps_from_fmtp, ListeningContext};

// Mode pinned by the SDP, no loss.
let kbps = amr_wb_kbps_from_fmtp("octet-align=1; mode-set=2").unwrap(); // 12.65
let mos = amr_wb_mos(kbps, ListeningContext::Monotic, 0.0);
assert_eq!(mos, Some(4.337096));

// Same mode, monotic, with loss: not computable, and it says so.
assert_eq!(amr_wb_mos(kbps, ListeningContext::Monotic, 1.0), None);
```

Every function returns `Option` and returns `None` wherever G.113 publishes
nothing, rather than interpolating into the gap.
