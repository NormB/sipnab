# G.722 decoder fixtures

Synthetic audio, generated with FFmpeg 6.1.1 (`adpcm_g722`), so the decoder in
`src/rtp/g722.rs` can be checked sample for sample against an independent
implementation of ITU-T G.722.

- `tone440.g722`: one second of a 440 Hz tone at half scale, 16 kHz mono,
  encoded to a raw G.722 bitstream at 64 kbit/s (8000 bytes):

  ```bash
  ffmpeg -f lavfi -i "sine=frequency=440:sample_rate=16000:duration=1" \
    -af "volume=0.5" -ac 1 -ar 16000 -c:a g722 -f g722 tone440.g722
  ```

- `tone440.s16le`: FFmpeg's decode of `tone440.g722`, 16-bit little-endian
  PCM at 16 kHz (16000 samples):

  ```bash
  ffmpeg -f g722 -i tone440.g722 -f s16le -ac 1 -ar 16000 tone440.s16le
  ```

- `noise-fullscale.g722` and `noise-fullscale.s16le`: one second of white
  noise driven past full scale, so the decode reaches both 16-bit limits (134
  samples do), encoded and decoded the same way:

  ```bash
  ffmpeg -f lavfi -i "anoisesrc=color=white:amplitude=1:sample_rate=16000:duration=1:seed=7" \
    -af "volume=4" -ac 1 -ar 16000 -c:a g722 -f g722 noise-fullscale.g722
  ```

  ```bash
  ffmpeg -f g722 -i noise-fullscale.g722 -f s16le -ac 1 -ar 16000 noise-fullscale.s16le
  ```
