# Relay control decoding

How sipnab reads a relay's control plane, and what it refuses to conclude from
it.

## Two relays, one seam

`src/relay/` defines what a relay implementation owes: decode a control message,
say whether a command creates media, yield endpoints carrying an
`EndpointAssertion`, and report its own authentication status. rtpengine's `ng`
protocol and rtpproxy's text protocol both sit behind it, and nothing above the
seam learns either vendor's name.

## rtpproxy is text, not bencode

A search of the rtpproxy tree for `bencode` returns nothing, so the `ng` decoder
covers none of this. The `protos/` directory is a false lead worth naming so
nobody re-investigates it: `rtpp_request.proto` describes an internal module
interface, not a second wire dialect.

## Direction decides, and content confirms

A command and a reply both begin with the same cookie. The destination port says
which way a datagram went, and the decoder parses the two grammars
separately.

The parser also refuses a reply on content, and both layers earn their place. A
live relay's `I` reply is five lines beginning `<cookie> sessions created: 0`.
`sessions` starts with `s`, the stop-play letter, so a content-blind reading made
it a confident `S` command carrying fourteen arguments. Three rules in
`rtpp_command_parse.c` refuse it: a command is one line, stop-play accepts no
modifiers, and it takes three or four arguments rather than fifteen.

## Bounds a caller can meet

Two ceilings bound what a sniffed datagram can make the decoder do. Both
refuse rather than truncate: the decoder drops a control message that exceeds
either, because a half-read command names a call from whatever sat in the
position it stopped at.

| Constant | Value | What it bounds |
|---|---:|---|
| `MAX_DATAGRAM` | 8192 | Longest control datagram the decoder examines. It drops anything larger unread. |
| `MAX_TOKEN` | 512 | Longest single token — a cookie, a verb, an argument. rtpproxy's own buffers are far smaller; this exists so an unterminated token cannot make the decoder allocate. |

A text protocol has denial-of-service shapes a length-prefixed binary one does
not, so these stay fixed rather than following the input.

## What rtpproxy's protocol does not carry

- **No SDP.** Unlike `ng`, the signaling element parses and rewrites SDP itself
  and tells the relay only addresses and ports. Reporting an SDP byte count would
  invent one.
- **No call-id on `V`, `I`, `X` or `G`.** Those carry `has_call_id = 0`. Reading
  the first argument as a call-id would name a call from whatever sat there.
- **No credential of any kind.** Nothing authenticates a sniffed control
  datagram, so the decoder reports it as a bare datagram and never as an
  encapsulated one.
- **No default UDP port.** rtpproxy documents a UNIX control socket, which a
  passive capture cannot see at all. An operator names the port or there is
  nothing to decode; guessing one would make every datagram on some arbitrary
  port a candidate control message.

## Recording streams are not legs

`R` and `C` create recording or forking streams. Attributing one as an ordinary
participant invents somebody the call never had, so the two are separate at the
type level rather than in a caller's memory. They are also kept out of the
unattributed-media tally, which the recording spool owns.
