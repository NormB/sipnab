+++
title = "Set the largest audio a vCon container may carry inline"
date = 2026-08-27
updated = 2026-10-16
description = "How to raise, keep or turn off the 5 MiB limit on audio sipnab writes inside a vCon container, how to read the record sipnab leaves when it refuses the audio, and how to keep the audio in a file beside the container."

[extra]
kind = "howto"
+++

## In short

A vCon is a file format for keeping a record of a phone call. sipnab can write
one per call, with the call's audio stored inside the file.

- Audio makes these files large.
- A vCon store can accept a large file and drop its audio without reporting an
  error.
- So by default sipnab refuses to put more than 5 MiB of encoded audio into one
  file. It says so inside the file.
- The `--vcon-max-inline-media` option changes that limit, or turns inline
  audio off.
- A `[[vcon.rule]]` with `audio = "url"` writes the audio to a WAV file beside
  the container instead, whatever its size.

## Who this is for

Operators who export vCon containers with sipnab and need to fit them to the
store or program that reads them.

## Before you start

- **Inline** means the vCon file itself holds the audio.
  - The audio is text in the base64url encoding. That is a way to write binary
    data as letters and digits.
  - It is not a link to a file stored elsewhere.
- The limit is in MiB (mebibytes; 1 MiB is 1,048,576 bytes).
  - It applies to the encoded text.
  - The default, 5 MiB, is 5,242,880 bytes.
  - Base64url makes data four thirds as large. So 5 MiB holds about 3.9 MB of
    WAV audio.
  - That is about four minutes of one-channel G.711 (the standard telephone
    codec) at 8 kHz.
- sipnab puts audio into a container only when the run keeps the audio of the
  RTP streams with `--retain-audio`. RTP streams are the packets that carry the
  voice.
  - Without it, there is no audio to carry. The limit has no effect.
- `--retain-audio` keeps at most `[limits] max_audio_frames` RTP frames per
  stream.
  - The default is 1500. That is about 30 seconds of G.711 at 50 packets per
    second.
  - To carry calls longer than that, raise that setting as well as this limit.
- The option needs sipnab 0.5.128 or later, built with the `vcon` feature.
  - The commands below run from the root of a sipnab checkout.
  - They read `tests/pcap-samples/sip-rtp-g711.pcap`. That capture holds two
    calls.
  - The condition `duration > 1` selects the one that lasts 8.5 seconds. It has
    one G.711 audio stream.


## Steps

- Export the call with the default 5 MiB limit, keeping the audio.
  - `--no-cli-print` stops sipnab printing every SIP message.
  - `-q` hides the progress log.

   ```bash
   sipnab -N -q -I tests/pcap-samples/sip-rtp-g711.pcap --export-vcon-when 'duration > 1' --export-vcon-dir ./calls/ --retain-audio --no-cli-print
   ```

   ```text
   Wrote 1 vCon container(s) to './calls/'.
   ```

- Confirm the audio is in the container. sipnab records what happened to the
  audio in `capture_completeness.media`. That is inside the container's
  `sipnab-dialog-diagnosis/1` analysis entry.

   ```bash
   jq -r '.analysis[] | select(.schema == "sipnab-dialog-diagnosis/1") | .body.capture_completeness.media' calls/*.vcon.json
   ```

   ```text
   carried
   ```

   The same run without `--retain-audio` prints `none-decodable`. sipnab saw
   audio packets but kept none of their content.

- To allow more audio, raise the limit.
  - Raise it only when you know the store or program that reads your
    containers accepts larger files.
  - This example sets 64 MiB.

   ```bash
   sipnab -N -q -I tests/pcap-samples/sip-rtp-g711.pcap --export-vcon-when 'duration > 1' --export-vcon-dir ./calls-64/ --retain-audio --vcon-max-inline-media 64 --no-cli-print
   ```

   ```text
   Wrote 1 vCon container(s) to './calls-64/'.
   ```

   The value is a whole number of MiB. sipnab rejects a fraction.
   `--vcon-max-inline-media 0.5` exits with code 2. It prints
   `error: invalid value '0.5' for '--vcon-max-inline-media <MIB>': invalid digit found in string`.

- To write containers with no audio at all, set the limit to `0`. The container
  still holds:
  - the parties,
  - timing,
  - the SIP message trace,
  - the statement of what is missing.

   ```bash
   sipnab -N -q -I tests/pcap-samples/sip-rtp-g711.pcap --export-vcon-when 'duration > 1' --export-vcon-dir ./calls-no-audio/ --retain-audio --vcon-max-inline-media 0 --no-cli-print
   ```

   ```text
   Wrote 1 vCon container(s) to './calls-no-audio/'.
   ```

- Check the media outcome of that container.

   ```bash
   jq -r '.analysis[] | select(.schema == "sipnab-dialog-diagnosis/1") | .body.capture_completeness.media' calls-no-audio/*.vcon.json
   ```

   ```text
   refused-over-budget
   ```

- Read the refusal. It names:
  - the audio length,
  - the WAV size,
  - the encoded size,
  - the limit that applied in this run (here 0 bytes, not the 5 MiB default).

  This command prints the part of the container's note that follows the dash
  before `INCOMPLETE`.

   ```bash
   jq -r '.analysis[] | select(.schema == "sipnab-dialog-diagnosis/1") | .body.capture_completeness.note | split(" — ")[1]' calls-no-audio/*.vcon.json
   ```

   ```text
   INCOMPLETE: sipnab decoded 8.5 second(s) of audio for this dialog and REFUSED to carry it: base64url of the 136516 byte WAV is 182022 bytes, over the 0 byte budget this emitter enforces because one probed vCon store answers 204 and drops the payload without telling the producer. The audio was NOT truncated and is not in this container; export it beside this file with the export_audio MCP tool. A capture-level analysis ran and ranked no blind spots.
   ```

   The same note, earlier, states: "No media is in this container because
   sipnab REFUSED to inline it: it decoded audio and the encoded body was over
   the budget below. The audio exists and was not truncated."

- To get the audio of one call as a separate WAV file on request, use the
  `export_audio` tool of sipnab's MCP server.
  - MCP is the interface an AI agent uses to query sipnab.
  - Start the server with `--retain-audio`.
  - To write the audio of every matching call as a file, use a rule, as the
    next section shows.

## Keep the audio in a file beside the container

A `[[vcon.rule]]` in the config file can write each call's audio to a WAV file
next to the container. The container then names that file by URL instead of
carrying the audio. The limit does not apply to it.

- Write the rule into a config file, here `vcon-url.toml`.
  - `audio_url_base` is the HTTPS address under which your own storage
    serves the files. sipnab writes the files and serves nothing.
  - `when` takes the same condition as `--export-vcon-when`.

   ```toml
   [[vcon.rule]]
   name           = "audio-beside"
   when           = "duration > 1"
   dir            = "./calls-url/"
   audio          = "url"
   audio_url_base = "https://media.example.com/calls/"
   ```

- Run sipnab with that config file. A rule with `audio = "url"` keeps the
  audio by itself, so `--retain-audio` is not needed.

   ```bash
   sipnab -N -q -I tests/pcap-samples/sip-rtp-g711.pcap --config vcon-url.toml --no-cli-print
   ```

   ```text
   [[vcon.rule]] 'audio-beside': Wrote 1 vCon container(s) to './calls-url/'.
   ```

- List the directory. Each container has a WAV file of the same name.

   ```bash
   ls calls-url/
   ```

   ```text
   1-1966_10.0.2.20-1cc03f180ff8a774.vcon.json
   1-1966_10.0.2.20-1cc03f180ff8a774.wav
   ```

- Read the recording entry. It names the file under `audio_url_base` and
  carries the file's hash, so a reader can check the file it fetches.

   ```bash
   jq -c '.dialog[] | {type, url, mediatype, content_hash}' calls-url/*.vcon.json
   ```

   ```text
   {"type":"recording","url":"https://media.example.com/calls/1-1966_10.0.2.20-1cc03f180ff8a774.wav","mediatype":"audio/x-wav","content_hash":"sha512-GVphUEyrsE9TSwxDIUBOUWDh1xEmmbHbpT5SqrtTVVVOQWy9JUPWgvOtxlFy1Rr-p8gcpy8pRosgohjHBa6uQg"}
   ```

   The container's `capture_completeness.media` reads `referenced`.

- Copy the WAV files to the storage that serves `audio_url_base`.

## Limits

- One value applies everywhere sipnab builds a container:
  - batch export (`--export-vcon-when`),
  - the REST server,
  - the MCP server.
  - The same call exported two ways gets the same decision.
- A `[[vcon.rule]]` with `audio = "inline"` can set its own limit with
  `max_inline_media_mib`. A rule that does not set it uses
  `--vcon-max-inline-media`.
- The limit counts the encoded audio only, not the whole container. The rest
  of the container (parties, message trace, completeness statement) has to fit
  under your store's own size limit as well.
- sipnab does not cut audio to fit.
  - sipnab leaves audio over the limit out whole. The container says so.
  - Audio that `--retain-audio` did not keep (over
    `[limits] max_audio_frames`) is a separate limit.
  - When it applied, the container adds a `recording-set` dialog entry. That
    entry carries the call's start and length.
  - The `recording` entry carries the shorter file's.

## Terms used here

- **vCon**: a JSON file format for a record of a conversation. It holds the
  parties, messages, audio and analysis.
- **Container**: one vCon file.
- **Inline**: stored inside the file rather than linked.
- **base64url**: an encoding that writes binary data as letters, digits, `-`
  and `_`. It makes data four thirds as large.
- **MiB**: mebibyte, 1,048,576 bytes.
- **SIP**: the signaling protocol that sets up and ends calls.
- **RTP**: the protocol that carries the audio of a call.
- **G.711**: the standard uncompressed telephone audio codec, 8,000 samples
  per second.
- **WAV**: a common uncompressed audio file format.
- **pcap**: a file of captured network packets. `-I` reads one.
- **MCP**: Model Context Protocol, the interface an AI agent uses to call
  sipnab's tools.
- **REST server**: sipnab's HTTP interface for programs.
- **Config file**: the TOML file `--config` names. `[[vcon.rule]]` entries in
  it choose which calls sipnab writes as vCon files, and how.
- **URL**: a web address. With `audio = "url"` the container holds the address
  of the audio file rather than the audio.

## Related guides

- [Produce one](@/docs/vcon.md#produce-one): the export options, including
  `--retain-audio`.
- [Read what a container says the capture missed](@/docs/vcon.md#read-what-a-container-says-the-capture-missed):
  how to read `capture_completeness`.
- [What this does not do](@/docs/vcon.md#what-this-does-not-do): the inline
  budget among the exporter's other limits.
- [`[limits]`](@/docs/config.md#limits): `max_audio_frames`.
- [`export_audio`](@/docs/mcp-tools-media.md#export-audio): the MCP tool that writes
  a call's audio to a WAV file.
- [Write calls by rule](@/docs/vcon.md#write-calls-by-rule): every
  `[[vcon.rule]]` key, including `audio = "url"` and `max_inline_media_mib`.
- [Fetch the audio a vCon names](@/docs/vcon.md#fetch-the-audio-a-vcon-names):
  reading back audio a container references by URL.
