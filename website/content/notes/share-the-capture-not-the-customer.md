+++
title = "Share a SIP capture with a vendor without sending subscriber data"
date = 2026-09-01
updated = 2026-10-16
description = "Export redacted vCon records for the calls in question, or a packet file narrowed by a capture filter with its TLS secrets removed, and know which sipnab options narrow what sipnab writes."

[extra]
kind = "howto"
+++

## In short

A capture file from a production link holds every call on that link. It holds
phone numbers, names, addresses and sometimes encryption keys.

- sipnab can write one record per selected call.
  - In each record, consistent substitutes replace those values.
  - So a vendor can still see that two failures came from the same caller.
  - The vendor does not see who the caller was.
- The vendor may need the packets themselves. Then sipnab can:
  - narrow the packet file with a capture filter,
  - remove embedded encryption keys.
- The call filter (`--filter`) does not narrow a packet file that sipnab
  writes.

## Who this is for

Operators who have to hand evidence about specific calls to a vendor, carrier
or support team. They must not send other subscribers' data with it.

## Steps

The commands below run from the root of a sipnab checkout. They use captures
that ship in `tests/pcap-samples/`.

- `--quiet` hides informational log lines.
- Warnings, errors and the run's results still print.

### Export a redacted record for each failed call

A vCon is a standard JSON container for one conversation. It holds:

- the parties,
- the SIP message trace,
- what sipnab concluded about the call.

SIP is the signaling protocol that sets up and ends calls.

```bash
sipnab -N -I tests/pcap-samples/sip-488-codec-reject.pcapng --export-vcon-when "state == 'Failed'" --export-vcon-dir ./out/ --redact --no-cli-print --quiet
```

```text
Wrote 1 vCon container(s) to './out/'.
Redaction: 6 classes, key ephemeral, 0 leading digit(s) retained.
```

`--export-vcon-when` takes a filter expression. It writes one container per
matching call into `--export-vcon-dir`.

`--redact` changes what goes into the container:

- Each identity (user name, number, Call-ID, host name) becomes a token.
  - Two tokens are equal exactly when the original values were equal.
  - So "these failures all came from one caller" is still readable from the
    output.
- Each IP address goes through a prefix-preserving map.
  - Two addresses that shared their first 24 bits still share them
    afterwards.
  - In one run, the originals `192.168.10.13` and `192.168.10.183` became
    `125.50.85.51` and `125.50.85.171`.
  - Without a key file (the next step), each run produces different
    substitutes.
- sipnab deletes some values rather than replacing them:
  - the digest authentication headers (`Authorization`,
    `Proxy-Authorization`, `WWW-Authenticate`, `Proxy-Authenticate`),
  - inline audio.
- sipnab leaves those four headers out of every vCon, with or without
  `--redact`.
  - An export of `tests/pcap-samples/sip-auth-failure.pcapng` without
    `--redact` contains none of them.

The six classes in the second output line are `identity`, `network`,
`credential`, `correlation-id`, `charging` and `media`.

`key ephemeral` means the run drew a fresh secret key from the operating
system. The key is for this run only.

Redaction applies only to the written container.

- The TUI (the interactive terminal view), the reports and the analysis in
  the same run keep the real values.
- A live capture (`-d` or `--hep-listen`) refuses `--redact`.
- Use it when reading a file with `-I`.

sipnab draws the substitute addresses from the whole IPv4 range.

- sipnab keeps only `0.0.0.0` as it is. In SDP it marks a call on hold.
- So a substitute can look like a real public address.
- A substitute can also fall in a reserved range such as multicast.
- Tell the recipient that the addresses are substitutes.

### Keep tokens stable across runs, when you need to

By default each run uses a new key. So the tokens of two runs are not
comparable.

You may want the same subscriber to produce the same token in today's export
and next week's. Then create a key file once:

```bash
head -c 32 /dev/urandom > redact.key
```

This command prints nothing. Then pass the file to every export:

```bash
sipnab -N -I tests/pcap-samples/sip-488-codec-reject.pcapng --export-vcon-when "state == 'Failed'" --export-vcon-dir ./out-keyed/ --redact --redact-key-file ./redact.key --no-cli-print --quiet
```

```text
Wrote 1 vCon container(s) to './out-keyed/'.
Redaction: 6 classes, key supplied, 0 leading digit(s) retained.
```

- Two runs of this command produced containers that differed only in
  `created_at`.
- The whole file is the key, trailing newline included.
- Keep it as private as the capture.
  - Anyone holding it can compare tokens across every export made with it.

### Write the table that reverses the tokens, and keep it

```bash
sipnab -N -I tests/pcap-samples/sip-488-codec-reject.pcapng --export-vcon-when "state == 'Failed'" --export-vcon-dir ./out-mapped/ --redact --redact-map ./map.tsv --no-cli-print --quiet
```

```text
Wrote 1 vCon container(s) to './out-mapped/'.
Redaction: 6 classes, key ephemeral, 0 leading digit(s) retained.
Wrote 7 token mapping(s) to './map.tsv' (mode 0600). It reverses every pseudonym in these containers, so it is as sensitive as the capture.
```

The map has one tab-separated line per token. The token comes first, then the
original value.

- sipnab creates it with mode `0600` (readable and writable by its owner
  only).
- One of the originals is the name of the host that ran sipnab.
  - The container names its observer.
  - So the number of mappings depends on the capture and the host.
- Keep the map. Do not send it with the containers.

sipnab does not write over an existing map:

```bash
sipnab -N -I tests/pcap-samples/sip-488-codec-reject.pcapng --export-vcon-when "state == 'Failed'" --export-vcon-dir ./out-again/ --redact --redact-map ./map.tsv --no-cli-print --quiet
```

```text
Wrote 1 vCon container(s) to './out-again/'.
Redaction: 6 classes, key ephemeral, 0 leading digit(s) retained.
--redact-map './map.tsv' already exists and sipnab will not write over it. That file may be the only way back from tokens already sent somewhere
```

The command exits with status 1. It still writes the container into
`--export-vcon-dir`, and no map records that container's tokens. Delete that
container, choose a map path that does not exist yet, and run the export
again.

`--redact-keep-prefix <N>` keeps the first N digits of each number unchanged.
This allows analysis by country code or number range.

- The default is `0`.
- Every kept digit is a digit of a real subscriber number.

### Narrow a packet file with a capture filter, not with `--filter`

- `-O` writes the packets sipnab read to a pcap file. pcap is the standard
  packet capture format.
- `--filter` selects calls for display and reports.
- It does not change what `-O` writes.

The two files below are byte for byte the same:

```bash
sipnab -N -I tests/pcap-samples/sip-rtp-g711.pcap -O all.pcap --no-cli-print --quiet
```

```bash
sipnab -N -I tests/pcap-samples/sip-rtp-g711.pcap -O filtered.pcap --filter "from.user == 'nobody'" --no-cli-print --quiet
```

Both commands print nothing.

```bash
sha256sum all.pcap filtered.pcap
```

```text
fa4471dda092bb0359aaec22f7b9a9ac7f0eb26b4025176b0f7b953f3490705b  all.pcap
fa4471dda092bb0359aaec22f7b9a9ac7f0eb26b4025176b0f7b953f3490705b  filtered.pcap
```

A BPF expression does narrow the file.

- BPF (Berkeley Packet Filter) is the packet filter language of libpcap and
  tcpdump.
- libpcap applies it before sipnab sees a packet.
- It goes last on the command line:

```bash
sipnab -N -I tests/pcap-samples/sip-rtp-g711.pcap -O signaling-only.pcap --no-cli-print --quiet 'udp port 5060'
```

This command prints nothing. Compare the result with the original:

```bash
capinfos -c -s signaling-only.pcap tests/pcap-samples/sip-rtp-g711.pcap
```

```text
File name:           signaling-only.pcap
Number of packets:   10
File size:           5,673 bytes

File name:           tests/pcap-samples/sip-rtp-g711.pcap
Number of packets:   852
File size:           198 kB
```

The narrowed file holds the SIP messages and none of the audio packets.

- It is not redacted. The numbers and addresses in it are the real ones.
- Open it with sipnab before you send it. Check that:
  - the calls you meant to include are there,
  - nothing else is.

### Remove embedded TLS keys from a pcapng file

A pcapng file (the newer capture format) can carry TLS decryption keys. It
carries them in Decryption Secrets Blocks.

- Anyone holding such a file can decrypt every TLS session in it.
- Write a copy without them:

```bash
sipnab -N -I tests/pcap-samples/sip-auth-failure.pcapng --strip-secrets ./shareable.pcapng
```

```text
2026-10-12T00:48:36.443562Z  INFO sipnab::app::bootstrap: Stripped 0 decryption secret(s): tests/pcap-samples/sip-auth-failure.pcapng -> ./shareable.pcapng
```

- sipnab leaves the input unchanged.
- It writes the copy with mode `0600`.
- This sample holds no secrets block. So the run reports 0 secrets stripped.

`-I` must name exactly one file. Given a pattern that matches several, sipnab
refuses and writes nothing:

```bash
sipnab -N -I "tests/pcap-samples/sip-*.pcapng" --strip-secrets ./set.pcapng
```

```text
2026-10-12T00:48:36.460816Z ERROR sipnab::app::bootstrap: --strip-secrets writes one sanitized copy, but -I resolved to 3 files: 'tests/pcap-samples/sip-auth-failure.pcapng', 'tests/pcap-samples/sip-routing-error.pcapng', 'tests/pcap-samples/sip-488-codec-reject.pcapng'. Run it once per file — stripping only one of them would ship the rest with their decryption secrets intact.
```

The command exits with status 1.

### Decide what to send

- For questions about specific calls, send the redacted containers.
  - They come from the export step or the stable-token step.
- When the recipient needs the packets, send the narrowed file from the
  capture-filter step.
  - Remove its secrets as in the TLS-key step.
  - It contains real numbers and addresses.
- Keep the key file and the map.
  - Do not send either with the data they reverse.

## Terms used here

- **SIP**: the signaling protocol that sets up, changes and ends calls.
- **SDP**: the part of a SIP message that says where and how to send audio.
- **vCon**: a JSON container format for one conversation, defined by an IETF
  working group draft.
- **Redaction token**: a substitute value computed from the original with a
  secret key. Equal originals give equal tokens.
- **Prefix-preserving map**: an address substitution in which two addresses
  that share leading bits still share them afterwards.
- **Digest authentication**: the SIP password challenge and response. Its
  headers carry values from which someone can guess a password offline.
- **pcap, pcapng**: the two standard packet capture file formats.
- **BPF**: the packet filter language used by libpcap and tcpdump.
- **TLS**: the encryption used for SIP over port 5061, among others.
- **Decryption Secrets Block**: a pcapng block that stores TLS keys inside the
  capture file.
- **SHA-256**: a hash. Two files with the same SHA-256 have the same bytes.
- **TUI**: sipnab's interactive terminal interface.

## Related guides

- [CLI reference: Capture](@/docs/cli.md#capture), the row for `-O`.
- [CLI reference: Output](@/docs/cli.md#output), the rows for `--redact`,
  `--redact-key-file`, `--redact-keep-prefix` and `--redact-map`.
- [CLI reference: pcapng metadata](@/docs/cli.md#pcapng-metadata), the row for
  `--strip-secrets`.
- [vCon: The message trace carries the headers, and strips the credentials](@/docs/vcon.md#the-message-trace-carries-the-headers-and-strips-the-credentials)
- [vCon: What sipnab refuses to put in a container](@/docs/vcon.md#what-sipnab-refuses-to-put-in-a-container)
- [Filter DSL: What a filter narrows](@/docs/filter-dsl.md#what-a-filter-narrows)
