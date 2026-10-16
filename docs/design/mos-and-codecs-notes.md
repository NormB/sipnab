# MOS scoring: implementation notes

The engineering record behind [`docs/mos-and-codecs.md`](../mos-and-codecs.md).
That page says what the score means and how to read it. This page names the
code and keeps the reasoning.

## Where the code lives

- [`src/rtp/quality.rs`](../../src/rtp/quality.rs): the narrowband E-model
  (ITU-T G.107). The codec impairment lookup, the operator's
  `[media.codec_ie]` declarations, and `resolve_one_way_delay`, which ranks
  the delay sources: declared, then reported by the endpoint, then derived
  from a receiver report's echo, then the 100 ms assumption.
  `MosProvenance` names the three kinds of MOS a surface can hold: a grounded
  sipnab estimate, a placeholder, and an endpoint's XR-reported score.
- [`src/rtp/stream_store.rs`](../../src/rtp/stream_store.rs):
  `StreamStore::remote_report` (SR/RR reception reports) and
  `StreamStore::remote_voip_metrics` (RTCP XR VoIP Metrics) hold what the far
  end asserted, apart from what sipnab measured.
- [`src/mcp/server.rs`](../../src/mcp/server.rs): `endpoint_reported_json`
  renders those side tables as `endpoint_reported` on MCP `rtp_stats`.
- [`src/rtp/emodel_wb.rs`](../../src/rtp/emodel_wb.rs): the wideband model
  (G.107.1) and the AMR-WB tables.

## The placeholder

ITU-T G.113 Table I.1 publishes `Ie` for a fixed list of codecs, and sipnab
knows three of them (G.711, G.729, and Opus treated as G.711-equivalent).
Every other codec scores identically to a stream whose codec was never
identified: `estimate_mos(10.0, 0.0, Some("AMR-WB"))` and
`estimate_mos(10.0, 0.0, None)` both return 4.216. A placeholder is a
high-looking number, so a MOS bound applied without the grounding test would
return every stream sipnab could not score as if it were a bad call. That is
why the MOS filters skip ungrounded streams and report `ungrounded_excluded`.

`[media.codec_ie]` refuses 95 and above because at that point the E-model's
loss term goes negative and more packet loss would raise the score.

A declared value is reported as `operator_declared`, never `published`,
because the remedies differ: a wrong published score points at the capture
point's position on the path, a wrong declared score at a file on the
operator's disk.

## Why RTCP never moves loss or jitter

RTCP is unauthenticated, so if a reported loss figure moved the MOS, anything
that could reach the port would control the quality number. And a reception
report describes the path from the sender to that reporter, which on a
mid-path capture is a different segment from the one in front of sipnab.

The one RTCP input the score uses is a round trip, for the delay term, and
only when the operator declared no delay. It is recorded as the delay's
source on every MOS so a score resting on a remote claim can be told apart.

## Wideband

- A wideband `Ie,WB` fed into the narrowband equation is a 35.8-point scale
  error (`Ro` 93.2 against `Ro,WB` 129), so AMR-WB is scored in
  `emodel_wb`, not added to the narrowband table.
- The library lookups (`amr_wb_ie`, `amr_wb_bpl`, `amr_wb_mos`) take the
  listening context as an explicit argument with no default, because at
  6.6 kbit/s the monotic and diotic tables differ by 15 R-points (about
  0.59 MOS). The surfaces read `[media] listening_context`, which defaults to
  monotic because a capture of mobile voice is a capture of handsets; every
  wideband score names the context it was read in.
- The TUI's `MOS_CQEW` row carries no quality band: the bands are calibrated
  on the narrowband scale, and painting a wideband score with them would
  repeat the scale error.
- Borrowing the diotic `Bpl,wb` for a monotic stream with loss would mix two
  listening contexts in one equation, so sipnab returns no score.

## Transcription hazard in G.113

The G.113 (09/2024) PDF prints the second EVS row of Appendix V as 2 kbit/s.
ITU-T G.113 (2024) Erratum 1 (January 12, 2026) corrects it to 32 kbit/s. A
table transcribed from the base PDF alone has a mode that does not exist and
lacks one that does.

## The library example

The example on the operator page compares with a tolerance of `5e-4`, the
crate's own `close()` bound in `emodel_wb.rs`. The exact value for 12.65
kbit/s, monotic, no loss is 4.33709615132886.
