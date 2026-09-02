+++
title = "Where an endpoint came from, and what that path is worth"
date = 2026-09-01
description = "Three tools answer what no other surface does: how sipnab learned a media endpoint, whether the path that carried it authenticated anybody, and whether anyone asked the relay at all."

[extra]
kind = "feature"
+++

Media with no signaling orphans. A relay control plane fixes that — sipnab
reads rtpengine's `ng` exchange and binds the streams to a call — but it
introduces a question the fix itself cannot answer. "Media anchored at
`192.0.2.40:38156`" renders identically whether the parties said so in SDP,
whether sipnab asked the relay over its control socket, or whether a datagram
that landed on the mirror port said so and nobody checked who sent it.

Those carry very different weight in an incident review. Three tools keep them
apart.

## The trust ladder

Ask it for a Call-ID and it returns each media endpoint with `asserted_by`
(`signaled` or `media-relay`), which capture source delivered it, and
`delivery_trust`. Strongest first:

| value | meaning |
|---|---|
| `asked` | sipnab asked the relay over its control socket, so no third party could answer |
| `hmac-verified` | delivered over HEP, authenticated with a token covering the datagram |
| `plain-secret` | delivered over HEP with a shared secret the token does not cover, so anyone who captures one packet can replay it |
| `port-gated-only` | accepted because it arrived on the expected port and for no other reason — **the source carries no authentication** |
| `not-relay-asserted` | the parties' own claim in SDP |

`unauthenticated_endpoints` rides alongside as a count, and each row carries a
`delivery_note` — one sentence an operator can act on, rather than a value they
have to look up.

The authentication answer comes from the run's configuration rather than a
per-packet record, and that is correct rather than a shortcut: ingest rejects
any datagram that fails authentication, so everything still in the store
arrived under whatever posture the run configured. With no posture configured
the tool reports the **weakest** reading. A tool whose job is telling you what
a claim is worth must not round up in the absence of information.

## Why the bottom of the ladder is where it is

Two paths deliver a `media-relay` assertion.

**Delivered.** rtpengine points its Homer destination at sipnab's
`--hep-listen` socket. Now the posture is whatever the operator configured:
`--hep-allow` restricts source addresses, `--hep-auth` requires a shared
secret, and `--hep-auth-mode hmac` requires a per-message token covering the
addresses the packet asserts.

```bash
sudo sipnab -N -d eth0 --hep-listen 0.0.0.0:9060 --hep-auth-file /etc/sipnab/hep.key --hep-auth-mode hmac
```

**Sniffed.** sipnab reads the mirror on its way to another team's collector,
which is the default because rtpengine takes exactly one Homer destination —
pointing it at sipnab takes it away from the collector it feeds, and a
diagnostic tool has no business in a production data path.

Nothing authenticates a sniffed assertion. The datagram never reaches a sipnab
socket, and anything able to transmit on the captured segment can produce one:
a Call-ID copied verbatim out of the HEP correlation-id chunk, a media address
copied out of the SDP, so a forged datagram can name a call of the sender's
choosing and bind it to a socket of the sender's choosing. sipnab therefore
believes a sniffed mirror only on UDP port 9060. That narrows the input without
authenticating anybody, and `--hep-allow` does not reach this path at all,
because there is no socket here to guard.

`decode_ng` reads one such control message back and reports the whole reason
rather than its conclusion: `delivery` (`hep` or `sniffed-udp`), the same
`delivery_trust` scale, and `on_believed_mirror_port` as a separate field,
because landing on that port is the ONLY reason anything believes a sniffed
message.

## Reaching the top of the ladder

`asked` is the one rung a passive decoder cannot reach on its own. A call
already in progress when sipnab started has no control exchange left to read,
and incident response usually begins mid-call.

`--rtpengine-control <ADDR>` closes that by asking, and construction rather
than convention holds the asking down. Only `list` and `query` have a
representation on the path that reaches the relay — `offer`, `answer`, `delete`
and `start recording` each change a production relay and none of them has a representation
there. sipnab asks at two moments and no others: once at startup,
before the capture opens, and again when a stream turns up that nothing
explains. sipnab asks about each relay-side socket at most once per run, and a per-run
ceiling of 66 control transactions caps the total however much traffic
arrives.

An agent reaches the same capability through the `query_relay` tool, which
needs `--mcp-allow-relay-query` on top of the relay address and a live source.
The offline run refuses on purpose: the addresses in a capture are historical
and belong to third parties who are not part of the analysis.

## Why a stream has no dialog

`rtp_stats` names which streams have no dialog. This says why each one has
none:

| verdict | what it means |
|---|---|
| `relay-asserted-but-no-dialog` | a relay named this endpoint and no captured dialog claims it — the **signaling** is missing, not the media |
| `signaled-but-no-dialog` | SDP named it and no dialog holds it |
| `never-named` | nothing in this capture named this endpoint at all |

`relay_was_consulted` rides beside the verdict and matters more than it looks.
A `never-named` verdict with `relay_was_consulted: false` means **nobody
asked** — an absence of evidence, not evidence of absence.

The same discipline runs through the whole feature. "Nothing came back" has
five meanings and sipnab keeps them apart: the relay refused the question, the
relay named calls sipnab could not read, the relay capped its own enumeration,
the run spent its transaction ceiling, or the relay genuinely does not hold the
port. Only the last one says anything about the relay. Reporting any of the
first four as the fifth would turn a run that never reached the relay into a
run that asked and heard the stream belongs to nobody.

## Telling it works

The closing summary names both halves of the arithmetic:

```text
rtpengine at 127.0.0.1:22222: 2 unexplained stream(s) offered, 0 attributed, 4 control transaction(s) spent of a ceiling of 66
```

Zero attributed with a reason line beside it is an honest answer rather than a
failure. Then ask `explain_attribution` for a call you care about and read
`delivery_trust` before you quote the address. [The rtpengine
page](@/docs/rtpengine.md) has the deployment shapes, including several relays
behind one proxy.
