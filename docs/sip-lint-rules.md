# SIP conformance rules

The conformance linter checks the SIP and SDP in a capture against the RFC
sections they must obey. This page shows how to run it, how to read and fix
what it reports, how to suppress a rule, and lists every rule.

Each rule carries a stable identifier such as
`SIP-3261-8.1.1.7-BRANCH-COOKIE`.

- Quote that identifier in a carrier ticket.
- Use it to suppress the rule in CI.
- Identifiers never change meaning.
- Nothing reuses a retired one.

The linter answers "does this traffic obey the specification". It does not
answer "why did this call fail": a call can complete over non-conformant
messages, and a conformant call can fail. For failed calls, start at
[Troubleshooting](troubleshooting.md).

The design reasoning behind each rule, and what the rules measured on a
validation corpus, are in
[Conformance linter design notes](internals/lint-rules.md).

## Lint a capture

Add `--lint` to an offline run. `--no-cli-print` hides the per-message lines,
and `-q` hides the log lines, so only the findings print.

```sh
sipnab -N -q -I tests/pcap-samples/sip-lint-findings.pcap --lint --no-cli-print
```

The capture ships with the repository. Output:

```text
warning: SIP-3261-8.1.1.6-MAX-FORWARDS-MISSING [lint-maxfwd@192.0.2.10] §8.1.1.6 makes a UAC insert one into every request it originates. Without it a routing loop has nothing to stop it, and RFC 3261 §16.6 leaves each proxy to invent its own starting value. (RFC 3261 §8.1.1.6) observed=no Max-Forwards header field expected=Max-Forwards: 70
error: SIP-3261-12.1.1-CONTACT-MISSING-IN-2XX [lint-maxfwd@192.0.2.10] §12.1.1 makes the UAS add a Contact to the response. It is the remote target for the dialog the 2xx creates, so without it the caller has nowhere to send the ACK and nowhere to send the BYE. The call answers and then cannot be hung up cleanly. (RFC 3261 §12.1.1) observed=2xx to INVITE with no Contact header field expected=Contact: <sip:user@host>
error: SIP-3261-20.14-CONTENT-LENGTH-MISMATCH [lint-clen@198.51.100.10] Over a stream transport the receiver frames the next message at the declared offset, so an overstated length consumes the message that follows it. Over a datagram transport the body is simply truncated. (RFC 3261 §20.14) observed=Content-Length 900, body 95 octets expected=Content-Length 95
warning: SIP-3261-19.1.1-URI-PARAM-DEMOTED [lint-brackets@203.0.113.10] §19.1.1 defines user as a URI parameter. Outside the brackets the receiver reads it as a header parameter and routes to the bare URI instead, which is how a call reaches the right host over the wrong transport or leaves the proxy loose-routing. (RFC 3261 §19.1.1) observed=To carries user outside angle brackets expected=To: <uri;user>
Lint: 4 finding(s) across 3 dialog(s)
```

`--lint` on its own never changes the exit status. This run exits `0`.

### Read a finding

Each line holds, in order:

| Part | Example | Meaning |
|---|---|---|
| Severity | `error` | How much attention the finding deserves. See [Severity and basis](#severity-and-basis). |
| Rule identifier | `SIP-3261-20.14-CONTENT-LENGTH-MISMATCH` | The rule. Look it up in the [rule catalog](#rule-catalog). |
| Call-ID | `[lint-clen@198.51.100.10]` | The dialog the finding came from. |
| Why it matters | `Over a stream transport …` | The effect of the defect on the equipment receiving it. |
| Citation | `(RFC 3261 §20.14)` | The RFC and section the rule reads. |
| `observed=` | `Content-Length 900, body 95 octets` | What the capture held. |
| `expected=` | `Content-Length 95` | What the cited section calls for. This is usually the fix. |

The last line counts the findings and the dialogs the linter read. The
summary lines print on standard error and the findings on standard output.

Over MCP, the [`lint_dialog`](mcp-tools-signaling.md#lint_dialog) and
[`validate_message`](mcp-tools-signaling.md#validate_message) tools return
the same findings as structured fields, and
[`explain_rule`](mcp-tools-signaling.md#explain_rule) returns one rule's
entry.

## Fail a CI job on a non-conformant capture

Add `--lint-fail-on` with the lowest severity that should fail the job.
It requires `--lint`.

```sh
sipnab -N -q -I tests/pcap-samples/sip-lint-findings.pcap --lint --no-cli-print --lint-fail-on error
```

The output is the same as above. The capture holds two `error` findings, so
the run exits `3`.

| Exit status | Meaning |
|---|---|
| `0` | No finding at or above the named severity. |
| `1` | sipnab failed, for example it could not read the capture. |
| `2` | sipnab refused the command line, or could not read the suppression file named with `--lint-suppress-file`. |
| `3` | At least one finding at or above the named severity. |

`--lint-fail-on` takes `info`, `notice`, `warning` (or `warn`) or `error`.

The [cookbook recipe "Check a capture against the RFCs"](examples.md#check-a-capture-against-the-rfcs)
shows the same gate in a CI job.

## Suppress a rule

List the rules to suppress in a file named `.sipnablint`. A pattern is an
exact rule identifier, or a prefix ending in `*`:

```text
# Our carrier omits Max-Forwards
SIP-3261-8.1.1.6-MAX-FORWARDS-MISSING

# No media in these captures, so the observation rules have nothing to read
OBS-*
```

Patterns separate on commas, spaces or newlines. `#` starts a comment.

Put the file beside the capture, or in any directory above it up to the
project root (the nearest directory holding `.git`). sipnab uses the first
`.sipnablint` it finds. A capture outside any project uses only a
`.sipnablint` in its own directory.

With the file above saved beside a copy of `sip-lint-findings.pcap` named
`calls.pcap`:

```sh
sipnab -N -q -I calls.pcap --lint --no-cli-print
```

Output, trimmed to the summary lines:

```text
…
Lint: 3 finding(s) across 3 dialog(s)
Lint: suppressions from ./.sipnablint (2 pattern(s)), 1 finding(s) silenced
```

The last line names the file applied and counts what it silenced.

To use a different file, for a CI job whose suppressions differ from the tree's:

```sh
sipnab -N -q -I calls.pcap --lint --no-cli-print --lint-suppress-file ci.sipnablint
```

If sipnab cannot read the named file, it stops and exits `2`:

```text
cannot read suppression file 'ci.sipnablint': No such file or directory (os error 2)
```

Create the file, or correct the path. sipnab does not fall back to linting
with every rule on.

To see every finding, including suppressed ones:

```sh
sipnab -N -q -I calls.pcap --lint --no-cli-print --lint-no-suppress
```

`--lint-no-suppress` overrides both `--lint-suppress-file` and a discovered
`.sipnablint`.

Over MCP, the lint tools take a `suppression_file` parameter and follow the
same discovery rule. Every response names the file it applied and how many
findings it silenced. The
[MCP tool reference](mcp-tools-signaling.md#lint_dialog) names the fields.

## Limit repeated findings

By default, one rule reports at most 25 findings per dialog. A dialog that
retransmits an `INVITE` eleven times trips a message rule eleven times, and
the cap keeps the other rules readable.

Set the cap with `--lint-max-per-rule N`, or with `[limits] lint_max_per_rule`
in the config file:

```sh
sipnab -N -q -I tests/pcap-samples/DTMFsipinfo.pcap --lint --no-cli-print --lint-max-per-rule 1
```

Output, trimmed:

```text
warning: SIP-4028-4-SESSION-EXPIRES-TOO-SMALL [2091060b-146f-e011-809a-0019cb53db77@admind-desktop] …
warning: SIP-4028-5-MIN-SE-TOO-SMALL [2091060b-146f-e011-809a-0019cb53db77@admind-desktop] …
warning: SIP-3261-8.1.1.7-BRANCH-COOKIE [2091060b-146f-e011-809a-0019cb53db77@admind-desktop] …
Lint: 3 finding(s) across 1 dialog(s)
Lint: 6 finding(s) dropped by the per-rule cap of 1
```

The last line counts what the cap dropped.

## Run a subset of the rules

The MCP [`lint_dialog`](mcp-tools-signaling.md#lint_dialog) tool takes a
`rulesets` parameter, and the Rust API takes `LintConfig::with_ruleset`. The
command line always runs every rule.

| Name | Contents |
|---|---|
| `all` | Every rule. The default. |
| `must` | Only MUST violations. |
| `rfc` | MUST and SHOULD. Excludes the interop rules and the observation rules. |
| `interop` | Only the rules for behavior that deployed equipment mishandles. |
| `observation` | Only the rules that compare SDP with captured media. `obs` is the same name, shortened. |
| `syntax` | Only the rules that read a single message with no dialog context. |

Over MCP, `rulesets` also accepts an RFC number such as `rfc3264`, which
selects every rule citing that RFC.

## Severity and basis

Severity says how much attention a finding deserves: `error`, `warning`,
`notice`, `info`.

Basis says what kind of claim the rule makes:

| Basis | Meaning |
|---|---|
| `must` | The cited section says MUST or MUST NOT, and the message disobeys it. |
| `should` | The cited section says SHOULD or RECOMMENDED. Deviating stays legal. |
| `interop` | No specification forbids this. Deployed equipment mishandles it anyway. |
| `observation` | The declaration and the observed media disagree. |

A `must` finding is a specification violation you can cite in a ticket. An
`interop` finding is legal SIP that some equipment handles badly.

## Fix the findings in the sample captures

Each example below runs on a capture that ships with the repository.

### Fix a missing Max-Forwards, a missing Contact, a wrong Content-Length and a demoted URI parameter

[`tests/pcap-samples/sip-lint-findings.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-lint-findings.pcap) produces the four findings shown
in [Lint a capture](#lint-a-capture). To fix each one at the element that sent
the message:

- `SIP-3261-8.1.1.6-MAX-FORWARDS-MISSING`: add `Max-Forwards: 70` to every
  request the user agent originates.
- `SIP-3261-12.1.1-CONTACT-MISSING-IN-2XX`: add a `Contact` header field to the
  2xx response to `INVITE`, naming the URI where the UAS receives in-dialog
  requests.
- `SIP-3261-20.14-CONTENT-LENGTH-MISMATCH`: set `Content-Length` to the body's
  size in octets. The finding gives the value in `expected=`.
- `SIP-3261-19.1.1-URI-PARAM-DEMOTED`: put the URI in angle brackets so its
  parameters stay with the URI.

The capture's `To` header field, corrected so `user=phone` stays with the URI:

```text
To: <sip:erin@203.0.113.20;user=phone>
```

### Fix session timers below 90 seconds and a branch without the magic cookie

```sh
sipnab -N -q -I tests/pcap-samples/DTMFsipinfo.pcap --lint --no-cli-print
```

Output, trimmed to one finding per rule:

```text
warning: SIP-4028-4-SESSION-EXPIRES-TOO-SMALL [2091060b-146f-e011-809a-0019cb53db77@admind-desktop] §4 puts the absolute minimum for Session-Expires at 90 seconds. Below it the refresh traffic costs more than the state it keeps alive, and equipment that enforces the floor answers 422 rather than accepting the session. (RFC 4028 §4) observed=Session-Expires: 60 expected=Session-Expires at least 90
…
warning: SIP-4028-5-MIN-SE-TOO-SMALL [2091060b-146f-e011-809a-0019cb53db77@admind-desktop] §5 makes the value MUST NOT be less than 90 seconds wherever it appears. A lower floor advertises a willingness the specification does not permit, and the far end may hold you to it. (RFC 4028 §5) observed=Min-SE: 5 expected=Min-SE at least 90
warning: SIP-3261-8.1.1.7-BRANCH-COOKIE [2091060b-146f-e011-809a-0019cb53db77@admind-desktop] §8.1.1.7 makes every compliant branch begin with z9hG4bK, so its absence identifies a stack predating RFC 3261 in one field. Transaction matching then falls back to the RFC 2543 rules, and CANCEL and ACK correlation stop being reliable. (RFC 3261 §8.1.1.7) observed=top Via branch without the z9hG4bK prefix expected=branch=z9hG4bK...
…
Lint: 9 finding(s) across 1 dialog(s)
```

To fix them:

- `SIP-4028-4-SESSION-EXPIRES-TOO-SMALL` and `SIP-4028-5-MIN-SE-TOO-SMALL`: raise
  the session-timer setting on the sending element to 90 seconds or more.
- `SIP-3261-8.1.1.7-BRANCH-COOKIE`: configure the element to generate `Via`
  branches that start with `z9hG4bK`. A stack that cannot do this predates
  [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261.html).

### Answer telephone-event when the offer carries it

```sh
sipnab -N -q -I tests/pcap-samples/h263-over-rtp.pcap --lint --no-cli-print
```

Output:

```text
warning: SDP-3264-7-TELEPHONE-EVENT-ONE-WAY [NmNhYWNhMjY0Y2M0OTc4YTI2MzgzZTNlYTRhZTMxNTE.] §7 lets the offerer stop listening for a format the answer left out, so RFC 4733 DTMF is not negotiated on this stream. What makes it a one-way fault rather than no DTMF at all is that equipment routinely sends the event anyway on the payload type it offered: the far end receives a payload type it never agreed to and either drops it or decodes it as audio, while DTMF in the other direction works. That asymmetry is the whole of every "the IVR cannot hear our digits" ticket. (RFC 3264 §7) observed=m=audio line 0 offered telephone-event, the answer omits it expected=a=rtpmap:<pt> telephone-event/8000 in the answer, or in-band DTMF on both sides
Lint: 1 finding(s) across 1 dialog(s)
```

To fix it, enable [RFC 4733](https://www.rfc-editor.org/rfc/rfc4733.html) DTMF on the answering element so its answer
carries `a=rtpmap:<pt> telephone-event/8000`, or configure both ends for
in-band DTMF.

### Read an answer that lists a format the offer did not

```sh
sipnab -N -q -I tests/pcap-samples/sip-rtp-g711.pcap --lint --no-cli-print
```

Output:

```text
info: SDP-3264-6.1-ANSWER-EXTRA-FORMAT [1-1966@10.0.2.20] §6.1 permits this and says why it rarely helps: the answerer cannot send with a format the offer never listed. Equipment that reads the answer as the negotiated set picks one of these and sends media the far end drops. (RFC 3264 §6.1) observed=m=audio line 0 answers with ["101"], absent from the offer expected=formats drawn from ["0"]
info: SDP-3264-6.1-ANSWER-EXTRA-FORMAT [1-1968@10.0.2.20] §6.1 permits this and says why it rarely helps: the answerer cannot send with a format the offer never listed. Equipment that reads the answer as the negotiated set picks one of these and sends media the far end drops. (RFC 3264 §6.1) observed=m=audio line 0 answers with ["101"], absent from the offer expected=formats drawn from ["8"]
Lint: 2 finding(s) across 2 dialog(s)
```

This is legal SIP. Act on it only if the far end sends media in a format the
offer never listed. Otherwise suppress `SDP-3264-6.1-ANSWER-EXTRA-FORMAT`.

### Fix an answer with no format in common with the offer

```sh
sipnab -N -q -I tests/fixtures/opensips-proxy-signaling.pcap --lint --no-cli-print
```

Output:

```text
error: SDP-3264-6.1-ANSWER-NO-COMMON-FORMAT [1-4062@198.51.100.21] §6.1 makes the answer list at least one format from the offer. With no format in common neither end can send anything the other decodes, and the correct answer was to decline the stream with port 0. (RFC 3264 §6.1) observed=m=audio line 0 answers ["9", "101"] with ["0"] expected=at least one of ["9", "101"]
Lint: 1 finding(s) across 1 dialog(s)
```

To fix it, give the two ends a codec in common, or have the answerer decline
the stream with port `0`.

## Rule catalog

The "How to fix" column says what to change on the element that sent the
message. To accept a rule's findings instead, [suppress the rule](#suppress-a-rule).

### Observation rules

These compare the SDP with the RTP and RTCP that sipnab attributed to the
dialog. A dialog with no attributed media produces no observation findings.

| Rule | Severity | Cites | Fires when | How to fix |
|---|---|---|---|---|
| `OBS-3264-6.1-PT-UNDECLARED` | error | [RFC 3264 section 6.1](https://www.rfc-editor.org/rfc/rfc3264.html#section-6.1) | The wire carries an RTP payload type that no offer or answer in the dialog declared. Comfort noise on payload type 13 ([RFC 3389](https://www.rfc-editor.org/rfc/rfc3389.html)) and on the reserved payload type 19 is exempt. | Send only payload types the offer/answer negotiated, or declare the payload type in use. |
| `OBS-4566-5.14-MEDIA-PORT-MISMATCH` | warning | [RFC 4566 section 5.14](https://www.rfc-editor.org/rfc/rfc4566.html#section-5.14) | RTP arrives at a declared media address on a port nobody advertised. The RTCP port one higher is exempt. | Send media to the port in the `m=` line, or correct the SDP to name the port in use. |
| `OBS-3264-6.1-DIRECTION-UNMET` | warning | [RFC 3264 section 6.1](https://www.rfc-editor.org/rfc/rfc3264.html#section-6.1) | Both ends negotiated `sendrecv`, media flowed, and one negotiated endpoint received none of it. | Check NAT and firewall rules on the path to the endpoint that received nothing. |
| `OBS-4566-6-PTIME-MISMATCH` | notice | [RFC 4566 section 6](https://www.rfc-editor.org/rfc/rfc4566.html#section-6) | The packetization on the wire differs from `a=ptime` by more than half. | Send packets at the declared `a=ptime` interval, or declare the interval in use. |
| `OBS-5761-5.1.1-RTCP-MUX-UNANSWERED` | error | [RFC 5761 section 5.1.1](https://www.rfc-editor.org/rfc/rfc5761.html#section-5.1.1) | An offer asked for `a=rtcp-mux`, the answer stayed silent, and RTCP arrived on the RTP port regardless. | Send RTCP on the separate RTCP port unless the answer accepts `a=rtcp-mux`. |
| `OBS-3551-4.2-FRAME-SIZE-IMPOSSIBLE` | warning | [RFC 3551 section 4.2](https://www.rfc-editor.org/rfc/rfc3551.html#section-4.2) | The payload size implies more media per packet than [RFC 3551 section 4.2](https://www.rfc-editor.org/rfc/rfc3551.html#section-4.2) asks a receiver to accept, or more media than the elapsed time between packets. | Reduce the media per packet to what the codec and `a=ptime` allow. |

The duration comparisons fire only in one direction: on packets that carry
more media than the declared or elapsed time. Packets that arrive late, or
gaps from silence suppression, do not trigger them.

`OBS-4566-6-PTIME-MISMATCH` and `OBS-3551-4.2-FRAME-SIZE-IMPOSSIBLE` read the
payload size, so they apply only to codecs with a fixed octet rate. These are
the five codecs they cover:

| Codec | Octets per millisecond | Frame |
|---|---|---|
| PCMU | 8 | sample-based |
| PCMA | 8 | sample-based |
| G722 | 8 | sample-based |
| G729 | 1 | 10 octets per 10 ms |
| GSM | 1.65 | 33 octets per 20 ms |

Both rules skip Opus, AMR and the other variable-rate codecs.

### Syntactic rules

These read one message on its own.

| Rule | Severity | Basis | Cites | Fires when | How to fix |
|---|---|---|---|---|---|
| `SIP-3261-8.1.1-MANDATORY-HEADER-MISSING` | error | must | [RFC 3261 section 8.1.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-8.1.1) | One of `Call-ID`, `CSeq`, `From`, `To` or `Via` is absent. | Add the missing header field. |
| `SIP-3261-20.16-CSEQ-MALFORMED` | error | must | [RFC 3261 section 20.16](https://www.rfc-editor.org/rfc/rfc3261.html#section-20.16) | A `CSeq` arrives that nothing can read as a number and a method. | Send `CSeq: <number> <method>`. |
| `SIP-3261-20.14-CONTENT-LENGTH-MISMATCH` | error | must | [RFC 3261 section 20.14](https://www.rfc-editor.org/rfc/rfc3261.html#section-20.14) | `Content-Length` exceeds the body that arrived. | Set `Content-Length` to the body size in octets. |
| `SIP-3261-25.1-HEADER-CONTROL-BYTE` | error | must | [RFC 3261 section 25.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-25.1) | A header name or value holds a control byte other than tab. | Remove the control byte at the element that inserts it. |
| `SIP-3261-20-URI-BRACKETS` | error | must | [RFC 3261 section 20](https://www.rfc-editor.org/rfc/rfc3261.html#section-20) | A `Contact`, `From` or `To` URI holds a comma or a question mark outside angle brackets. | Enclose the URI in angle brackets. |
| `SIP-3261-19.1.1-URI-PARAM-DEMOTED` | warning | interop | [RFC 3261 section 19.1.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-19.1.1) | A URI parameter (`transport`, `user`, `method`, `ttl`, `maddr` or `lr`) sits outside the angle brackets, where the receiver reads it as a header parameter. | Enclose the URI and its parameters in angle brackets. A bare URI followed by `;tag=` does not fire this rule. |
| `SIP-3261-8.1.1.6-MAX-FORWARDS-MISSING` | warning | must | [RFC 3261 section 8.1.1.6](https://www.rfc-editor.org/rfc/rfc3261.html#section-8.1.1.6) | A request carries no `Max-Forwards`. | Add `Max-Forwards: 70`. |
| `SIP-3261-20.22-MAX-FORWARDS-RANGE` | notice | should | [RFC 3261 section 20.22](https://www.rfc-editor.org/rfc/rfc3261.html#section-20.22) | `Max-Forwards` reads zero, exceeds the recommended 70, or holds no integer. | Start requests at `Max-Forwards: 70`. |
| `SIP-3261-8.1.1.7-BRANCH-COOKIE` | warning | must | [RFC 3261 section 8.1.1.7](https://www.rfc-editor.org/rfc/rfc3261.html#section-8.1.1.7) | A request's top `Via` branch lacks the `z9hG4bK` magic cookie, or carries no branch at all. | Generate branches that start with `z9hG4bK`. |
| `SIP-3261-8.1.1.5-CSEQ-METHOD-MISMATCH` | error | must | [RFC 3261 section 8.1.1.5](https://www.rfc-editor.org/rfc/rfc3261.html#section-8.1.1.5) | The `CSeq` method disagrees with the request line. | Make the `CSeq` method match the request method. |
| `SIP-3261-12.1.1-CONTACT-MISSING-IN-2XX` | error | must | [RFC 3261 section 12.1.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-12.1.1) | A 2xx answer to `INVITE` carries no `Contact`, so the dialog it creates has no remote target for the `ACK` or the `BYE`. | Add a `Contact` to the 2xx. |
| `SIP-3262-3-RELIABLE-PROVISIONAL-WITHOUT-RSEQ` | error | must | [RFC 3262 section 3](https://www.rfc-editor.org/rfc/rfc3262.html#section-3) | A provisional demands `100rel` and carries no `RSeq`, so the receiver has to acknowledge a response it cannot name. | Add `RSeq` to every reliable provisional response. |
| `SIP-4028-7.1-SESSION-EXPIRES-BELOW-MIN-SE` | error | must | [RFC 4028 section 7.1](https://www.rfc-editor.org/rfc/rfc4028.html#section-7.1) | One message carries a `Session-Expires` smaller than the `Min-SE` beside it. | Set `Session-Expires` at or above `Min-SE`. |
| `SIP-4028-4-SESSION-EXPIRES-TOO-SMALL` | warning | must | [RFC 4028 section 4](https://www.rfc-editor.org/rfc/rfc4028.html#section-4) | `Session-Expires` sits below the 90-second absolute minimum. | Set the session timer to 90 seconds or more. |
| `SIP-4028-5-MIN-SE-TOO-SMALL` | warning | must | [RFC 4028 section 5](https://www.rfc-editor.org/rfc/rfc4028.html#section-5) | `Min-SE` sits below 90 seconds, wherever it appears. | Set `Min-SE` to 90 seconds or more. |
| `SIP-4028-9-REFRESHER-MISSING` | warning | must | [RFC 4028 section 9](https://www.rfc-editor.org/rfc/rfc4028.html#section-9) | A 2xx answer to `INVITE` negotiates `Session-Expires` and names no `refresher`. Requests are not checked. | Add `refresher=uac` or `refresher=uas` to `Session-Expires` in the 2xx. |
| `SIP-7989-5-SESSION-ID-MALFORMED` | error | must | [RFC 7989 section 5](https://www.rfc-editor.org/rfc/rfc7989.html#section-5) | A `Session-ID` half is not 32 characters of `[0-9a-f]`. sipnab drops that half from correlation. | Generate `Session-ID` values as 32 lowercase hexadecimal characters. |
| `SIP-7989-5-SESSION-ID-UPPERCASE` | warning | must | [RFC 7989 section 5](https://www.rfc-editor.org/rfc/rfc7989.html#section-5) | A `Session-ID` UUID arrives in uppercase hexadecimal. sipnab still correlates on it. Elements comparing the header byte for byte see two identifiers for one session. | Send the UUID in lowercase. |
| `SIP-7989-11-SESSION-ID-LEGACY-FORM` | notice | interop | [RFC 7989 section 11](https://www.rfc-editor.org/rfc/rfc7989.html#section-11) | A `Session-ID` carries no `remote` parameter, the [RFC 7329](https://www.rfc-editor.org/rfc/rfc7329.html) single-UUID form. Correlation then works in one direction only. | Upgrade the element to send the RFC 7989 form with `remote`. |
| `SIP-3261-7.3.1-SINGULAR-HEADER-REPEATED` | error | must | [RFC 3261 section 7.3.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-7.3.1) | A header field whose value is not defined as a comma-separated list arrives on more than one row. Compact forms count, so `i:` beside `Call-ID:` fires. `WWW-Authenticate`, `Authorization`, `Proxy-Authenticate` and `Proxy-Authorization` are exempt. | Send the header field once. |
| `SIP-3261-16.6-RECORD-ROUTE-NOT-LOOSE` | error | must | [RFC 3261 section 16.6](https://www.rfc-editor.org/rfc/rfc3261.html#section-16.6) | A `Record-Route` URI carries no `lr` parameter, so the hop it records is a strict route. | Configure the proxy to add `;lr` to its `Record-Route` URI. |
| `SIP-3261-8.1.1.7-VIA-BRANCH-DUPLICATE` | error | must | [RFC 3261 section 8.1.1.7](https://www.rfc-editor.org/rfc/rfc3261.html#section-8.1.1.7) | Two `Via` header field values in one request carry the same `branch`, which indicates a request loop. Requests only. A repeated value reports once. | Find the proxy that forwards the request back to itself, and fix its routing. |

### Dialog rules

These read a dialog's messages against each other.

| Rule | Severity | Basis | Cites | Fires when | How to fix |
|---|---|---|---|---|---|
| `SIP-3261-8.1.1.2-TO-TAG-IN-INITIAL-REQUEST` | warning | must | [RFC 3261 section 8.1.1.2](https://www.rfc-editor.org/rfc/rfc3261.html#section-8.1.1.2) | A `REGISTER` carries a `To` tag, or the dialog's first request carries one and the response to that same transaction carries a different tag. | Send out-of-dialog requests without a `To` tag. |
| `SIP-3261-17.1.1.3-ACK-CSEQ-MISMATCH` | error | must | [RFC 3261 section 17.1.1.3](https://www.rfc-editor.org/rfc/rfc3261.html#section-17.1.1.3) | An `ACK` carries a sequence number belonging to no `INVITE` in the dialog. | Copy the `INVITE`'s `CSeq` number into the `ACK`. |
| `SDP-3264-6.1-ANSWER-NO-COMMON-FORMAT` | error | must | [RFC 3264 section 6.1](https://www.rfc-editor.org/rfc/rfc3264.html#section-6.1) | An answer shares no media format with the offer, on a stream it did not decline. | Give both ends a codec in common, or decline the stream with port `0`. |
| `SDP-3264-6.1-ANSWER-EXTRA-FORMAT` | info | interop | [RFC 3264 section 6.1](https://www.rfc-editor.org/rfc/rfc3264.html#section-6.1) | An answer lists a format the offer never carried. This is legal. | No change needed. Answer only with offered formats if the far end sends media in an extra one. |
| `SDP-3264-6.1-ANSWER-DIRECTION-ILLEGAL` | error | must | [RFC 3264 section 6.1](https://www.rfc-editor.org/rfc/rfc3264.html#section-6.1) | The answer's direction attribute contradicts what the offer's admits. | Answer `sendonly` with `recvonly` or `inactive`, `recvonly` with `sendonly` or `inactive`, and `inactive` with `inactive`. |
| `SIP-3262-4-PRACK-MISSING` | warning | must | [RFC 3262 section 4](https://www.rfc-editor.org/rfc/rfc3262.html#section-4) | A reliable provisional went unacknowledged in a dialog whose `INVITE` reached a final response. | Send a `PRACK` for every reliable provisional response. |
| `SDP-3264-8.4-HOLD-CONNECTION-ZERO` | warning | should | [RFC 3264 section 8.4](https://www.rfc-editor.org/rfc/rfc3264.html#section-8.4) | A re-offer sets the connection address to `0.0.0.0` to signal hold. The first SDP body in a dialog, and streams declined with port zero, are exempt. | Signal hold with `a=sendonly` or `a=inactive`. |
| `SIP-3261-17.1.1.3-ACK-BRANCH-MISMATCH` | error | must | [RFC 3261 section 17.1.1.3](https://www.rfc-editor.org/rfc/rfc3261.html#section-17.1.1.3) | An `ACK` to a final response between 300 and 699 carries a `branch` other than its `INVITE`'s. An `ACK` to a 2xx is a new transaction and is not checked. | Send the `ACK` for a non-2xx with the `INVITE`'s top `Via`. |
| `SIP-3261-12.1.1-RECORD-ROUTE-NOT-COPIED` | error | must | [RFC 3261 section 12.1.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-12.1.1) | A 2xx to the dialog-forming request drops or reorders a `Record-Route` value the request carried. A response carrying additional values does not fire it. | Copy every `Record-Route` value from the request into the response, in order. |
| `SDP-3264-8.3.2-DYNAMIC-PT-REBOUND` | error | must | [RFC 3264 section 8.3.2](https://www.rfc-editor.org/rfc/rfc3264.html#section-8.3.2) | A dynamic payload type (96-127) means one codec in one body and a different codec in a later body of the same `m=` line. | Keep each dynamic payload type bound to one codec for the life of the session. |
| `SDP-3264-7-TELEPHONE-EVENT-ONE-WAY` | warning | interop | [RFC 3264 section 7](https://www.rfc-editor.org/rfc/rfc3264.html#section-7) | An offer declares `telephone-event` on an audio stream the answer accepted and shares a codec with, and the answer omits it. | Enable RFC 4733 DTMF on the answerer, or use in-band DTMF on both ends. |
| `SDP-3264-8.2-REJECTED-STREAM-ATTRIBUTES` | notice | interop | [RFC 3264 section 8.2](https://www.rfc-editor.org/rfc/rfc3264.html#section-8.2) | A stream the answer declined with port zero still carries `a=rtpmap`, `a=fmtp`, `a=crypto`, `a=candidate`, `a=ptime`, `a=rtcp-mux` or `a=rtcp`. Streams the offer already set to port zero are exempt. | Omit the attributes from declined streams. An `a=crypto` there publishes key material for a stream that carries no media. |
| `SDP-7587-7-OPUS-RTPMAP-RATE` | error | must | [RFC 7587 section 7](https://www.rfc-editor.org/rfc/rfc7587.html#section-7) | An `a=rtpmap` names `opus` at a clock rate other than 48000, or with a channel count other than 2. | Write `a=rtpmap:<pt> opus/48000/2`, and signal a narrower band with `maxplaybackrate` in `a=fmtp`. |

## Use the linter from Rust

```rust
use sipnab::sip::lint::{LintConfig, Linter, ObservedMedia, Ruleset};

let config = LintConfig::new()
    .with_ruleset(Ruleset::Must)
    .suppress_list("OBS-*, SIP-3261-19.1.1-URI-PARAM-DEMOTED");
let linter = Linter::new(config);

// Signaling only.
// let findings = linter.lint_dialog(&dialog);

// Signaling against the media observed for it.
// let media = ObservedMedia::from_streams(streams.streams_for(&dialog.call_id));
// let findings = linter.lint_dialog_with_media(&dialog, &media);
```

`ObservedMedia::from_streams` projects the RTP that the stream store attributed
to the dialog. Pass RTCP separately with `ObservedMedia::with_rtcp`.

See [Library API](library.md) for the wider crate surface.
