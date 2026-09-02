+++
title = "Share the capture, not the customer"
date = 2026-09-01
description = "A vendor wants the packets and the file holds everybody's traffic. What sipnab redacts, what it deliberately does not, and the one narrowing that actually reaches the pcap writer."

[extra]
kind = "howto"
+++

A vendor needs the evidence, the file is four gigabytes of everyone's calls,
and sending it is both slow and a disclosure. "Redact the capture" is what
somebody asks for next, and the phrase covers three different jobs that sipnab
answers in three different ways. Two of them work well. The third does not
work the way most people assume, and assuming wrong hands over the whole file.

## Substitute, do not mask

```bash
sipnab -N -I capture.pcap --export-vcon-when "state == 'Failed'" --export-vcon-dir ./out/ --redact --no-cli-print
```

`--redact` is not masking. Every identity becomes a keyed token that is equal
exactly when the original was equal, and every address goes through a
prefix-preserving map. So "these forty failures came from one subscriber" and
"the media went to a subnet the SDP never advertised" both stay answerable on
the output. Masking answers neither, which is why a capture tool that masks has
thrown away the reason it captured.

Two things it removes rather than turning into tokens, because no pseudonym of
them carries diagnostic value: digest credentials, where a `nonce` and `response`
pair is an offline attack against the subscriber's password rather than a
privacy nit, and inline audio.

The run says what it did:

```text
Redaction: 6 classes, key ephemeral, 0 leading digit(s) retained.
```

**It affects the serialized container and nothing else.** The TUI, the reports
and every in-process analysis keep the real values, so a redacted export and a
live triage session read the same capture. You do not lose your own
investigation by exporting a safe copy of it.

## The addresses look real, and that is the cost

Prefix preservation is the property that keeps subnet questions answerable, and
it has a consequence worth stating out loud when you hand the file over. Two
addresses that shared a `/24` in the original still share one afterwards, and
the substitutes are ordinary-looking IPv4 addresses rather than reserved
documentation ranges. A reader cannot tell a pseudonym from a real allocation
by looking at it.

That matters twice. Nobody should chase one of these addresses as if it were a
host, and nobody should read a container as untouched because the addresses
look plausible. Say which it is in the covering note.

## Stable tokens, and what stability costs

By default every run draws its own key, which is the safe default: the tokens
join against nothing and nothing anywhere reverses them.

```bash
sipnab -N -I capture.pcap --export-vcon-when "state == 'Failed'" --export-vcon-dir ./out/ --redact --redact-key-file /etc/sipnab/redact.key --no-cli-print
```

Supply a key file when tokens have to stay stable — the same subscriber reading
the same across yesterday's containers and today's, or across two capture
hosts. Two runs over the same capture with the same key produce byte-identical
parties, right down to the container UUID.

Understand what that buys the holder of the file. The whole file is the secret,
trailing newline included, so a key from `head -c 32 /dev/urandom` and one
written by hand both work and neither gets silently truncated. Anyone holding
it can rebuild the mapping for any capture you redacted with it.

## The reversal table

```bash
sipnab -N -I capture.pcap --export-vcon-when "state == 'Failed'" --export-vcon-dir ./out/ --redact --redact-map ./map.tsv --no-cli-print
```

```text
Wrote 9 token mapping(s) to './map.tsv' (mode 0600). It reverses every
pseudonym in these containers, so it is as sensitive as the capture.
```

Tab-separated, token first, original second, created mode 0600 explicitly
rather than at whatever mode the environment would otherwise pick. It is
exactly as sensitive as the capture it came from, and it never travels with the
containers.

sipnab refuses to write over one that exists:

```text
--redact-map './map.tsv' already exists and sipnab will not write over it. That
file may be the only way back from tokens already sent somewhere
```

## Keep no digits unless you decided to

`--redact-keep-prefix` keeps that many leading digits of a number verbatim, and
it defaults to zero. The default is an argument rather than an oversight: every
retained digit is a digit of a real subscriber number published in the clear,
and sipnab has no basis for choosing how many. A country code runs one to three
digits, a NANP area code is three, and a national destination code is anything.
So nothing survives until you decide that route or number-range analysis is
worth those digits.

## The pcap, and the thing that surprises people

Now the third job: the vendor wants packets, not containers. The obvious move
is to narrow the read and let `-O` write what survived.

**The dialog filter does not reach the pcap writer.** `-O` writes every packet
the capture loop handled, and the loop feeds the writer before any dialog
filtering happens. Measured on a shipped capture: the file written under
`--filter "from.user == 'nobody'"` and the file written with no filter at all
have the same SHA-256. Not similar sizes — the same digest.

What DOES narrow it is the BPF expression, because libpcap applies that before
sipnab ever sees a packet:

```bash
sipnab -N -I capture.pcap -O signaling-only.pcap --no-cli-print 'udp port 5060'
```

On that same capture, the BPF form wrote 10 packets and 5,673 bytes against the
original's 852 packets and 198,831. Read the output back before sending it, and
check that the calls you meant to include reconstruct from it.

So for a pcap the narrowing tool is the BPF expression, not the DSL. If
what you actually need is per-call selection with identities removed, the
container export above is the surface that does that — a redacted container per
failed call carries the message trace a vendor needs without carrying anybody's
number.

## Secrets already inside the file

A pcapng can carry TLS decryption secrets in Decryption Secrets Blocks, which
travel with the file and open every session in it. Strip them before the file
leaves:

```bash
sipnab -I capture.pcapng --strip-secrets ./shareable.pcapng
```

The input stays untouched. `-I` has to resolve to exactly one capture, and
sipnab refuses a set: stripping only the first would hand over the rest with
their keys intact while reporting success.

## What to send

Send redacted containers plus their digests when the question is about specific
calls, which it usually is. Send a BPF-narrowed pcap when the far end genuinely
needs bytes on the wire, and strip the secrets first. Keep the map and the key
file, and never let either travel with what they reverse.
