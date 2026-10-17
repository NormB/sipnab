# Changelog

This file lists all notable changes to the `sipnab-g729` crate. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
crate follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.3] - 2026-10-17

### Security

- `zip` 9.0.4 replaces 8.6.0 for the `std` table importer, clearing RUSTSEC-2026-0367, RUSTSEC-2026-0368 and RUSTSEC-2026-0369. The importer reads archive members into memory by name and never calls `zip`'s `extract()` functions, which the advisories concern.

## [0.1.2] - 2026-10-16

### Changed

- The crate description names the G.729.1 core layer that 0.1.1 added.

## [0.1.1] - 2026-10-16

### Added

- `g7291`: G.729.1 RTP payloads ([RFC 4749](https://www.rfc-editor.org/rfc/rfc4749.html),
  [RFC 5459](https://www.rfc-editor.org/rfc/rfc5459.html)) read for their
  core layer. `split_rtp` splits a payload into its header (`Header`,
  `FrameType`, `Rate`), its whole frames, its SID and the octets it ignores;
  `core_frames` gives a frame's first 20 octets as two G.729 frames, and
  `core_sid` a SID's first 15 bits as a G.729 Annex B SID frame.
  `Decoder::decode_g7291_rtp` decodes a payload's core layer to 8 kHz (160
  samples per 20 ms frame) and `Decoder::decode_superframe` one 20 ms frame.
  The higher layers are not decoded. Tested against the ITU-T G.729.1
  test vectors.

## [0.1.0] - 2026-10-16

### Added

- A G.729 Annex A decoder with Annex B comfort noise: `Decoder::decode` for
  one frame, `Decoder::decode_rtp` for an RTP payload of 10-octet frames and
  an optional trailing 2-octet SID frame ([RFC 3551 section 4.5.6](https://www.rfc-editor.org/rfc/rfc3551.html#section-4.5.6)).
  `Frame::Erased` conceals a lost frame and `Frame::NoTx` continues the
  comfort noise for a frame the sender did not send. Bit-exact with the ITU-T reference
  decoder on the 16 ITU-T decoder test vectors. `no_std`, no `unsafe` code,
  no allocation while decoding.
- `import_from_itu` (feature `std`): builds the table file from the ITU-T
  G.729 software package, as a zip or an extracted directory, finding each
  source file by its pinned sha256 and checking the sha256 of the values.
- `Tables::from_bytes` (feature `std`): loads the table file, checking its
  layout and the pinned sha256 of its values; `TableError` names each
  refusal.
- `bitstream`: RFC 3551 frame unpacking, `split_rtp`, and an ITU-T G.192
  serial file reader (`g192_frames`), with `SerialFrame::frame` to turn each
  serial frame into the decoder's `Frame`.
- Examples: `import_tables`, `decode_bitstream` (G.192 file to WAV) and
  `decode_rtp_payloads` (a text file of RTP payloads, with lost packets, to
  WAV). `tests/examples.rs` runs them on the ITU-T test vectors and checks
  their output.
