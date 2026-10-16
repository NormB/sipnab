# sipnab-g729

A decoder for ITU-T G.729 speech as reduced by Annex A, with the Annex B
comfort-noise frames, written in Rust. It decodes only. There is no encoder.

- It decodes G.729 Annex A streams, with or without Annex B. It also decodes
  main-body G.729 streams, which are interoperable with Annex A
  ([RFC 3551 section 4.5.6](https://www.rfc-editor.org/rfc/rfc3551.html#section-4.5.6)).
- It decodes the core layer of G.729.1 streams ([RFC 4749](https://www.rfc-editor.org/rfc/rfc4749.html)): the first
  20 octets of each 20 ms frame are two G.729 frames, decoded to 8 kHz. The
  higher G.729.1 layers are not decoded (see
  [G.729.1 core layer](#g7291-core-layer)).
- Annex D and Annex E are not supported.
- Audio is 8000 Hz, 16-bit, mono: 80 samples per 10 ms frame. A speech
  frame is 10 octets; a SID (comfort-noise) frame is 2 octets.
- It is bit-exact with the ITU-T reference decoder on all 16 ITU-T decoder
  test vectors: the 10 for Annex A and the 6 for Annex A with Annex B.
- The decoder is `no_std`, has no `unsafe` code, and does not use the heap
  while decoding.

The library's name is `g729`, so code reads `use g729::...`.

## Getting the tables

The decoder needs one table file before it decodes anything. You build it
once from the ITU-T G.729 software package, then load it at run time.

### 1. Get the ITU-T package

Download the ITU-T G.729 (06/2012) software package, Release 3, from
<https://www.itu.int/rec/T-REC-G.729-201206-I/en> (the "Software" item, a
zip of 18,476,968 bytes). Its sha256 is
`979680ff3b52b13a5701453178efd32b53e340114638fd330fdb6669eec86620`. The
direct link needs no login:

```sh
curl -L -o 'T-REC-G.729-201206-I!!SOFT-ZST-E.zip' \
  'https://www.itu.int/rec/dologin_pub.asp?lang=e&id=T-REC-G.729-201206-I!!SOFT-ZST-E&type=items'
```

### 2. Build the table file

Any one of these methods writes the same file. Each finds the source files it
needs in the package by their pinned sha256, reads the numbers out of them as
text, and checks the sha256 of the result.

From the zip, in your own code, with the `std` feature:

```rust,no_run
let table_file = g729::import_from_itu(std::path::Path::new(
    "T-REC-G.729-201206-I!!SOFT-ZST-E.zip",
))?;
std::fs::write("g729-tables.bin", &table_file)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

From a directory you extracted from the zip (any directory that holds the
package's files, at any depth):

```rust,no_run
let table_file = g729::import_from_itu(std::path::Path::new("g729-package/"))?;
std::fs::write("g729-tables.bin", &table_file)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

With the `import_tables` example from this repository, which takes the zip or
a directory:

```sh
cargo run -p sipnab-g729 --features std --example import_tables -- \
  'T-REC-G.729-201206-I!!SOFT-ZST-E.zip' g729-tables.bin
```

With sipnab, which downloads the package from itu.int and installs the file:

```sh
sipnab g729 install
```

`sipnab g729 install --from PATH` takes the zip or an extracted directory
instead and opens no connection. It accepts a zip only when its sha256 is the
Release 3 package's above, and checks that before reading it; a directory it
accepts whenever the importer does. sipnab writes the file to
`$XDG_CONFIG_HOME/sipnab/g729-tables.bin`, else
`~/.config/sipnab/g729-tables.bin`. `--g729-tables PATH` names another path.
Building the file takes less than a second.

### 3. Load the table file

```rust,no_run
let tables = g729::Tables::from_bytes(&std::fs::read("g729-tables.bin")?)?;
let decoder = g729::Decoder::new(&tables);
# Ok::<(), Box<dyn std::error::Error>>(())
```

`Tables::from_bytes` checks the file's layout and the sha256 of its values,
and refuses any other file with a `TableError`:

| Refusal | Meaning |
|---|---|
| `Magic` | The file is not a table file. |
| `Version(v)` | A table file of another layout version, written for another release of this crate. Build it again. |
| `Length { expected, actual }` | The file is shorter than a table file, or has bytes appended. |
| `EntryCount { expected, actual }` | The header declares another number of entries than the layout has. |
| `EntryNumber { position, actual }` | An entry header carries another entry's number. |
| `Entry { index, expected, actual }` | An entry header declares another value count than the layout has. |
| `ValuesHash` | The layout is right, but the values are not the ones this crate pins: someone changed the file, or built it from another package. |

`import_from_itu` refuses with an `ImportError`:

| Refusal | Meaning |
|---|---|
| `Io(error)` | The importer cannot read the path, or a file below it. |
| `Zip(message)` | The path is a file but not a readable zip. |
| `MissingSource { file, sha256 }` | No file in the package has the pinned sha256 of a needed source file: the package is a modified or incomplete copy, or a release whose source files differ from Release 3's. The importer finds the files by their hashes, so a package of another release whose files match imports to the same table file. |
| `Shape { name, expected, found }` | The importer could not read an entry as recorded. Not expected from a package whose files match the pinned hashes. |
| `UnknownEntry(name)` | An entry has no locator. Not expected: it would be a defect in this crate. |
| `ValuesHash(actual)` | The values read do not have the pinned sha256. The importer returns no file. |

## Why the tables are not in this crate

The trained codebook values of G.729 are published in the reference C code
of the ITU-T G.729 software package, and that code's notice keeps its
authors' rights. So this crate reads them from your own copy of the
package instead of shipping them. Everything in this crate is MIT OR
Apache-2.0. This crate's code generates the tables that the Recommendation
defines by a formula. See
[PROVENANCE.md](https://github.com/NormB/sipnab/blob/main/crates/g729/PROVENANCE.md)
for the verbatim notices, the holders, the package hash and the clean-room
record.

## Worked example

The steps from a new project to a WAV file. The crate's tests compile each
snippet below. The `decode_bitstream` and `decode_rtp_payloads`
examples run the same steps, and the crate's tests check their output (see
[Examples](#examples)).

Add the crate with the `std` feature, which the table loader needs:

```sh
cargo add sipnab-g729 --features std
```

Get the package and build `g729-tables.bin` by one of the methods in
[Getting the tables](#getting-the-tables).

### Decode a sequence of frames

A file of raw G.729 frames holds 10 octets per 10 ms frame. Each one decodes
to 80 samples:

```rust,no_run
use g729::{Decoder, FRAME_SAMPLES, Frame, Tables};

let tables = Tables::from_bytes(&std::fs::read("g729-tables.bin")?)?;
let mut decoder = Decoder::new(&tables);

let stream = std::fs::read("speech.g729")?;
let (frames, rest) = stream.as_chunks::<10>();
assert!(rest.is_empty(), "not a whole number of frames");

let mut pcm: Vec<i16> = Vec::with_capacity(frames.len() * FRAME_SAMPLES);
let mut samples = [0i16; FRAME_SAMPLES];
for frame in frames {
    decoder.decode(Frame::Voice(frame), &mut samples);
    pcm.extend_from_slice(&samples);
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

### Decode an RTP payload

An RTP payload ([RFC 3551 section 4.5.6](https://www.rfc-editor.org/rfc/rfc3551.html#section-4.5.6)) is zero or more 10-octet frames,
optionally followed by one 2-octet SID frame. `Decoder::decode_rtp` splits it
and decodes every frame. It refuses any other length with
`Error::PayloadLength`, and then decodes nothing.

```rust,no_run
use g729::{Decoder, FRAME_SAMPLES, Tables};

let tables = Tables::from_bytes(&std::fs::read("g729-tables.bin")?)?;
let mut decoder = Decoder::new(&tables);

// Two speech frames and a SID frame: 22 octets.
let payload: [u8; 22] = [0x5a; 22];
let mut pcm: Vec<i16> = Vec::new();
let appended = decoder.decode_rtp(&payload, &mut pcm)?;
assert_eq!(appended, 3 * FRAME_SAMPLES);
# Ok::<(), Box<dyn std::error::Error>>(())
```

`bitstream::split_rtp` does the split alone, for code that handles the frames
itself:

```rust
use g729::bitstream::split_rtp;

let payload = [0u8; 22];
let (frames, sid) = split_rtp(&payload)?;
assert_eq!(frames.len(), 2);
assert!(sid.is_some());
# Ok::<(), g729::bitstream::PayloadLength>(())
```

### Lost frames and frames not sent

The output must still have 80 samples for every 10 ms. Decode a frame for
each 10 ms that no payload covers:

- `Frame::Erased` for a frame the network lost: a gap in the RTP sequence
  numbers. The decoder conceals it from the frames before it.
- `Frame::NoTx` for a frame that was not sent: after a SID frame, a sender
  using Annex B sends nothing until the noise or the speech changes, so the
  RTP timestamp jumps while the sequence numbers stay consecutive. The
  decoder continues the comfort noise.

After a SID frame or a frame not sent, the decoder treats an erased frame
as a frame not sent (Annex B clause B.4.5), so the two give the same
output there.

The RTP clock of G.729 is 8000 Hz, so each 10 ms frame is 80 timestamp units.

```rust,no_run
use g729::{Decoder, FRAME_SAMPLES, Frame, Tables};

/// Decode `missing` frames for a gap in the stream: `Frame::Erased` when
/// packets were lost, `Frame::NoTx` when the sender sent nothing.
fn fill_gap(decoder: &mut Decoder<'_>, missing: usize, lost: bool, pcm: &mut Vec<i16>) {
    let frame = if lost { Frame::Erased } else { Frame::NoTx };
    let mut samples = [0i16; FRAME_SAMPLES];
    for _ in 0..missing {
        decoder.decode(frame, &mut samples);
        pcm.extend_from_slice(&samples);
    }
}

let tables = Tables::from_bytes(&std::fs::read("g729-tables.bin")?)?;
let mut decoder = Decoder::new(&tables);
let mut pcm: Vec<i16> = Vec::new();

// The packet before covered timestamps 8000 to 8159 and had sequence number
// 10; this one has timestamp 8400 and sequence number 12.
let (expected_timestamp, timestamp) = (8160u32, 8400u32);
let (expected_sequence, sequence) = (11u16, 12u16);
let missing = (timestamp.wrapping_sub(expected_timestamp) / 80) as usize;
let lost = sequence != expected_sequence;
fill_gap(&mut decoder, missing, lost, &mut pcm);
assert_eq!(pcm.len(), 3 * FRAME_SAMPLES);
# Ok::<(), Box<dyn std::error::Error>>(())
```

### Write the PCM to a WAV file

A WAV file of 16-bit mono samples at 8000 Hz is a 44-byte header and the
samples, little-endian. This function is the one the examples use:

```rust
/// A 16-bit mono WAV file at 8000 Hz holding `samples`. Fails when the
/// sample data is too long for a WAV file (4 GiB).
pub fn wav_bytes(samples: &[i16]) -> Result<Vec<u8>, std::num::TryFromIntError> {
    let data_len = u32::try_from(samples.len() * 2)?;
    let mut wav = Vec::with_capacity(44 + samples.len() * 2);
    wav.extend_from_slice(b"RIFF");
    wav.extend_from_slice(&(36 + data_len).to_le_bytes());
    wav.extend_from_slice(b"WAVEfmt ");
    wav.extend_from_slice(&16u32.to_le_bytes()); // fmt chunk size
    wav.extend_from_slice(&1u16.to_le_bytes()); // PCM
    wav.extend_from_slice(&1u16.to_le_bytes()); // mono
    wav.extend_from_slice(&8000u32.to_le_bytes()); // sample rate
    wav.extend_from_slice(&16000u32.to_le_bytes()); // bytes per second
    wav.extend_from_slice(&2u16.to_le_bytes()); // bytes per sample frame
    wav.extend_from_slice(&16u16.to_le_bytes()); // bits per sample
    wav.extend_from_slice(b"data");
    wav.extend_from_slice(&data_len.to_le_bytes());
    for sample in samples {
        wav.extend_from_slice(&sample.to_le_bytes());
    }
    Ok(wav)
}

let pcm = vec![0i16; 160];
let wav = wav_bytes(&pcm)?;
assert_eq!(wav.len(), 44 + 320);
# Ok::<(), Box<dyn std::error::Error>>(())
```

Then `std::fs::write("speech.wav", wav_bytes(&pcm)?)?` writes the file.

## G.729.1 core layer

A G.729.1 RTP payload ([RFC 4749](https://www.rfc-editor.org/rfc/rfc4749.html),
[RFC 5459](https://www.rfc-editor.org/rfc/rfc5459.html)) is one header octet
(MBS in the high 4 bits, the frame type FT in the low 4), then zero or more
20 ms frames at the bit rate FT names (FT 0 to 11: 8 to 32 kbit/s, 20 to 80
octets a frame), then an optional SID of 2, 3 or 6 octets. FT 14 is a SID
alone, FT 15 no data, and FT 12 and 13 are reserved.

The first 20 octets of every frame are its core layer: two G.729 frames.
The first 15 bits of every SID are its core SID: a G.729 Annex B SID frame.
`g7291::split_rtp`, `g7291::core_frames` and `g7291::core_sid` read them:

```rust
use g729::g7291::{FrameType, core_frames, core_sid, split_rtp};

// FT 11 (32 kbit/s): one 80-octet frame, then a 3-octet SID.
let mut payload = vec![0xfb];
payload.extend_from_slice(&[0x11; 80]);
payload.extend_from_slice(&[0x4c, 0x91, 0xff]);
let split = split_rtp(&payload)?;
assert!(matches!(split.header.frame_type, FrameType::Speech(rate) if rate.kbps() == 32));
let frame = split.frames().next().ok_or("one frame")?;
let [first, second] = core_frames(frame).ok_or("a whole core")?;
assert_eq!((first, second), (&[0x11; 10], &[0x11; 10]));
assert_eq!(split.sid.and_then(core_sid), Some([0x4c, 0x90]));
# Ok::<(), Box<dyn std::error::Error>>(())
```

`Decoder::decode_g7291_rtp` decodes a payload's core layer: 160 samples at
8 kHz per frame, and 160 for a SID, which decodes as a SID frame and then an
untransmitted frame. FT 15 decodes nothing. Octets that are neither a whole
frame nor a SID are skipped, so no sample comes from a partial core. An empty
payload or a reserved FT is refused with `g7291::PayloadError` and decodes
nothing. `Decoder::decode_superframe` decodes one 20 ms frame, including a
lost (`Superframe::Erased`) or untransmitted (`Superframe::NoTx`) one, as two
G.729 frames of that kind. The G.729.1 RTP clock is 16 kHz, so a frame is
320 timestamp units.

```rust,no_run
use g729::g7291::SUPERFRAME_SAMPLES;
use g729::{Decoder, Tables};

let tables = Tables::from_bytes(&std::fs::read("g729-tables.bin")?)?;
let mut decoder = Decoder::new(&tables);
let mut pcm: Vec<i16> = Vec::new();
let mut payload = vec![0xf0]; // FT 0, 8 kbit/s
payload.extend_from_slice(&[0x5a; 40]); // two 20-octet frames
let decoded = decoder.decode_g7291_rtp(&payload, &mut pcm)?;
assert_eq!(decoded.samples, 2 * SUPERFRAME_SAMPLES);
# Ok::<(), Box<dyn std::error::Error>>(())
```

This is not G.729.1's own decoder output: the narrowband enhancement layer
(12 kbit/s) and the wideband layers (14 to 32 kbit/s) are skipped, and the
core is decoded by this crate's Annex A decoder at 8 kHz. Its tests check,
on the ITU-T G.729.1 test vectors, that the core layer of every frame is the
G.729 bitstream the same encoder wrote from the same input, that the two
decode to the same samples, and that the SIDs carry the same core SID.

## Examples

Each example runs with `cargo run -p sipnab-g729 --features std --example
NAME -- ARGS` from a checkout of the repository.

- `import_tables PACKAGE OUT`: builds the table file from the package zip or
  an extracted directory, and writes it to OUT.
- `decode_bitstream TABLES IN.BIT OUT.wav`: decodes an ITU-T G.192 serial
  file, the format of the package's test vectors, to a WAV file. On
  `SPEECH.BIT` its sample data equals `SPEECH.PST` byte for byte, and on
  `tstseq1a.bit` it equals `tstseq1a.out`.
- `decode_rtp_payloads TABLES PAYLOADS.txt OUT.wav`: decodes a text file of
  RTP payloads, one hexadecimal payload per line, where the word `LOST` marks
  a lost packet. It splits frames from a trailing SID frame and conceals each
  lost packet for the length of the packet before it.
  `examples/payloads.txt` is a sample.

`tests/examples.rs` runs all three on the ITU-T test vectors and checks their
output.

## Features

- `annex-b` (default): decodes Annex B SID frames into comfort noise.
  Without it, the decoder conceals SID frames and frames not sent as lost
  frames.
- `std`: `Tables::from_bytes` and `import_from_itu`. The decoder itself does
  not need it.

## Rust version

The minimum supported Rust version is 1.99.

## License

You may use the code in this crate under either of
[Apache License, Version 2.0](https://github.com/NormB/sipnab/blob/main/crates/g729/LICENSE-APACHE)
or [MIT license](https://github.com/NormB/sipnab/blob/main/crates/g729/LICENSE-MIT),
at your option. The tables you import from the ITU-T package are not covered
by this license.

## Provenance

The authors wrote the decoder as a clean room: one role read the ITU-T reference C
code and produced only numbers, and a second role wrote this crate from the
Recommendation text, those numbers and the test vectors, without reading the
ITU-T code or any other G.729 implementation.
[PROVENANCE.md](https://github.com/NormB/sipnab/blob/main/crates/g729/PROVENANCE.md)
records who read what, the hashes of every file involved, and the package's
notices in full.
