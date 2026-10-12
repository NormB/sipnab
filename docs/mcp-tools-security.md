# MCP tool reference: security bundle

The `security` bundle answers who sent what: scanner and fraud findings, the
busiest sources, one endpoint's activity, registration problems, pass/fail
expectations, and fail2ban rules.

Load only these tools with `--mcp-tools security`, or combine bundles as
[Choosing which tools load](mcp-tools.md#choosing-which-tools-load) describes.
Every tool on this page follows the [rules every tool
follows](mcp-tools.md#rules-every-tool-follows), and each section states only
what its tool does differently. The [MCP tool reference](mcp-tools.md) lists
the other bundles and finds any tool by name.

| Tool | Parameters | Returns |
|---|---|---|
| [`top_talkers`](#top_talkers) | `by`, `limit?`, `filter?`, `prefix_digits?` | The busiest IPs, user agents or dialled prefixes, ranked, each share stated against the population behind it |
| [`describe_endpoint`](#describe_endpoint) | `ip?`, `user?`, `limit?` | Everything one participant did: dialogs by method and state, INVITE outcomes, REGISTER state, banners, streams, findings |
| [`diagnose_registration`](#diagnose_registration) | `call_id` | Whether an endpoint registered, hit a rejection, is looping on auth, or got a short expiry |
| [`evaluate_expectations`](#evaluate_expectations) | `rules?`, `rules_toml?`, `suppression_file?` | A pass/fail verdict per rule plus an exit code for a build. A rule whose population is empty fails rather than passing quietly |
| [`security_findings`](#security_findings) | `kinds?`, `since?`, `limit?` | Recent `scanner` / `fraud` / `digest` / `reg_flood` findings, plus the detectors this server runs |
| [`generate_fail2ban_rule`](#generate_fail2ban_rule) | `finding_id` | A fail2ban filter and jail derived from ONE recorded finding, with that finding attached as the evidence |


## Survey — what is in this capture

Start here when you have a capture and no particular suspect. These answer "what is in it", "how much", and "is the server even seeing traffic".

### `top_talkers`

Ranks the busiest participants: IPs, user agents, or dialled prefixes.

`aggregate_dialogs` and `group_dialogs` group DIALOGS, and a dialog has two
ends. Asking "who is busiest" of a dialog-shaped answer forces the caller to
pick one end and ignore the other, which reports a trunk's traffic as belonging
to whichever side the schema happened to name first. This counts PARTICIPANTS
instead.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `by` | string | `ip`, `ua` or `prefix`. Anything else fails with `invalid_params` naming the legal set. | Required. |
| `limit` | integer? | Bounded by `--mcp-max-rows`. | The usual row default. |
| `filter` | string? | Alias or DSL, the same vocabulary every other tool takes. | The whole store. |
| `prefix_digits` | integer? | How many leading digits make a prefix bucket. | 4. |

**Returns:**

| Field | Type | Description |
|---|---|---|
| `by` | string | Echo of the dimension ranked on, so an answer is self-describing. |
| `talkers` | object[] | Busiest first, bounded by `limit`. |
| `distinct_talkers` | usize | Talkers seen across the whole match, whether or not each got a row. |
| `total_matched` | usize | Dialogs the filter matched across the whole store. |
| `truncated` | bool | `true` when `distinct_talkers` exceeds the rows returned. |
| `capture_identity` | object | Which capture answered — see [`capture_status`](mcp-tools-core.md#capture_status). |
| `schema_version` | u32 | `1` for this shape. |

Each `talkers` row carries `key` (the address, banner or prefix), `dialogs`,
`messages`, `invites`, `answered`, `failed`, and `share_pct`. `messages` counts
what sipnab credits to the row: messages SENT for an `ip`, messages carrying
the banner for a `ua`, every message of the dialog for a `prefix`. `answered`
and `failed` are subsets of `invites`, so a dimension carrying no INVITE dialogs
reports zero for all three. `share_pct` is `null` — never `0` — when nothing
matched, because a zero there would read as a talker measured to be idle.

The example runs against [`tests/pcap-samples/sipp-branch-scenario.pcapng`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sipp-branch-scenario.pcapng),
whose 1334 REGISTER dialogs run between two addresses:

```jsonc
// top_talkers { "by": "ip", "limit": 3 }
{
  "schema_version": 1,
  "by": "ip",
  "talkers": [
    { "key": "192.0.2.20", "dialogs": 1334, "messages": 5082,
      "invites": 0, "answered": 0, "failed": 0, "share_pct": 100.0 },
    { "key": "192.0.2.10", "dialogs": 1334, "messages": 3907,
      "invites": 0, "answered": 0, "failed": 0, "share_pct": 100.0 }
  ],
  "distinct_talkers": 2,
  "total_matched": 1334,
  "truncated": false,
  "capture_identity": {
    "node": "capture-01",
    "instance": "eb70c18d2bf4734944323-2",
    "dialog_generation": 9015,
    "stream_generation": 0
  }
}
```

**The shares deliberately sum above 100%.** One dialog counts for every talker
in it, so a two-ended call adds to two rows — here both ends took part in all
1334 dialogs and both read 100%. `total_matched` is the number that partitions:
compare a row's `dialogs` against it rather than against the other rows.
`by: "prefix"` is the exception and does partition, because sipnab credits one
bucket per dialog and a call has one dialled number.

sipnab orders rows by `dialogs`, then by `messages`, then by `key`, so two
runs over one capture cannot disagree. `key` arrives fenced for `by: "ua"`
alone, because a banner is a string a stranger typed. An address and a prefix
bucket are values sipnab derived, and come back verbatim.

`ip` reads senders off the MESSAGES, not off the dialog's opening addresses: a
proxy that re-originates mid-dialog is invisible in the dialog record and would
otherwise never appear. `ua` reads `User-Agent` from requests and `Server` from
responses, both sender-written and therefore fenced. `prefix` strips a leading
`+` before taking digits, so `+15551234` and `15551234` are one destination
rather than two.


## Find — narrow to the calls that matter

You know something is wrong but not which call. These cut a capture down to the dialogs worth reading: by symptom, by text, by time, or by relationship to a call you already have.

### `describe_endpoint`

Everything the capture holds about one participant.

The rest of this surface keys on Call-ID, which is the right shape for "why did
this call fail" and the wrong shape for the question that comes first. An
operator handed a complaint holds a phone, a trunk or a subscriber — an address
or a name — and wants to know what that thing has been doing. Agents reason in
entities too. Answering from a dialog-centric surface meant listing every
dialog, filtering client-side, and re-deriving per-entity facts the stores
already hold.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `ip` | string? | The endpoint's address, v4 or v6. Mutually exclusive with `user`. An unparseable value fails with `ip '...' is not an address`. | Give `user` instead. |
| `user` | string? | The user part of a SIP URI — `alice` from `sip:alice@example.com`. Mutually exclusive with `ip`. | Give `ip` instead. |
| `limit` | u32? | Bounds `recent_dialogs`, `problem_call_ids` and `findings` only. Ceiling is `--mcp-max-rows` (1000 by default), `0` means the default. | 50. |

**Exactly one selector, and the tool refuses both.** A caller passing an address
and a name means either their intersection or their union, the two give
different answers, and picking one silently would answer a question nobody
asked:

```jsonc
{ "code": -32602,
  "message": "give exactly one of ip or user, not both: the two select different sets, and whether you meant their intersection or their union changes the answer" }
```

The example runs against
[`tests/pcap-samples/sip-rtp-g711.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-rtp-g711.pcap):

```jsonc
// describe_endpoint { "ip": "10.0.2.20", "limit": 1 }
{
  "schema_version": 1,
  "endpoint_kind": "ip",
  "endpoint": "10.0.2.20",
  "dialogs": 2,
  "by_method": { "INVITE": 2 },
  "by_state": { "Completed": 1, "InCall": 1 },
  "messages_sent": 5,
  "messages_received": 5,
  "calls": {
    "invites": 2, "with_final_status": 2, "failed": 0,
    "failure_rate_pct": 0.0, "by_final_status": { "200": 2 }
  },
  "registration": {
    "applicable": false, "dialogs": 0, "succeeded": 0, "failed": 0,
    "auth_loops": 0, "problem_call_ids": []
  },
  "user_agents": [],
  "stack": {
    "branch_cookie": "z9hG4bK", "branch_shape": "hex",
    "tag_shape": "other", "callid_has_host": true,
    "confidence": 0, "requests_read": 5, "mixed": false
  },
  "streams": {
    "count": 2, "orphaned": 0, "packets": 839, "lost_packets": 0,
    "max_jitter_ms": 0.0061987502747274615,
    "codecs": ["⟦untrusted-capture-data⟧PCMA⟦/untrusted-capture-data⟧",
               "⟦untrusted-capture-data⟧PCMU⟦/untrusted-capture-data⟧"]
  },
  "findings": {
    "selectable": true, "findings": [], "total_matched": 0, "armed_kinds": [],
    "note": "No detection rule is armed on this server, so no finding could have been recorded. ..."
  },
  "recent_dialogs": [ /* one fenced dialog summary */ ],
  "truncated": true
}
```

#### `contact_rewrite` — was the private Contact rewritten

A phone behind NAT puts its own private address in the `Contact` of a REGISTER.
The registrar must notice that the packet arrived from a public address the
header does not name, and route later requests to where it came from. When it
does, everything works. When it does not, every inbound call goes to an
unroutable host and the phone never rings.

**The observation is not the finding.** Measured against the private corpus on
2026-09-08, 1,660 of 2,226 REGISTER contacts carry a private host — 74.6% — and
that estate works. A rule firing on the observation alone would report three
quarters of a healthy fleet.

| Field | Type | Description |
|---|---|---|
| `observation.contact_host` | string? | The host the `Contact` named, as written. Absent for `Contact: *`, which [RFC 3261 section 10.2.2](https://www.rfc-editor.org/rfc/rfc3261#section-10.2.2) defines as every binding and which names no host |
| `observation.contact_host_private` | bool? | Whether that host is one the public internet does not route to. Absent when the `Contact` names a domain: a name resolves somewhere the capture cannot see, and judging it either way would be a guess |
| `observation.source_public` | bool | Whether the REGISTER arrived from a public address |
| `observation.rewrite_required` | bool | The two together — the shape that calls for a NAT rewrite |
| `verdict` | string | `rewritten`, `not-rewritten` or `no-later-requests` |
| `requests_to_contact` | usize | Later requests addressed to the private `Contact` host |
| `requests_to_source` | usize | Later requests addressed to where the REGISTER came from |
| `is_finding` | bool | The conjunction: the shape called for a rewrite and no rewrite happened. **This is the field to alert on** |

**Any request to the private host is a finding, not a majority of them.** A
proxy that sends some requests to the source and some to the header still sends
some nobody receives, and 99 deliverable requests do not make the hundredth
deliverable.

**Silence is not success.** A capture that ended before the first inbound call
reports `no-later-requests`, which is distinct from `rewritten` on purpose:
reading it as success is how a capture that stopped too early becomes a clean
bill of health.

**Corroborated against the registered AoR, not the address.** A request the
registrar sent to the private `Contact` carries no address belonging to the
endpoint — that is exactly what going to the wrong host means — so nothing
address-based can find it. The tie is the user part in the request URI and
`To`, matched case-sensitively per
[RFC 3261 section 19.1.4](https://www.rfc-editor.org/rfc/rfc3261#section-19.1.4).

[`diagnose_registration`](#diagnose_registration) reports the observation for a
single call. The corroborated finding lives here, because settling it needs
what happened across the endpoint's other dialogs.

#### `stack` — which library built these requests

A banner names a PRODUCT and one product ships more than one stack.
[`top_talkers`](#top_talkers) `by=ua` reports `Asterisk PBX 20.15.2` as a single
row at `share_pct: 100.0` across 507 dialogs, and `tshark` finds **18 distinct
source addresses** behind that one label — running two different stacks, which
need different configuration, different NAT handling and different re-INVITE
handling. The banner cannot tell them apart. The syntax can.

| Field | Type | Description |
|---|---|---|
| `branch_cookie` | string? | The `Via` branch's cookie: the mandatory `z9hG4bK` ([RFC 3261 section 8.1.1.7](https://www.rfc-editor.org/rfc/rfc3261#section-8.1.1.7)) plus any vendor extension before the per-transaction part. Echoed from the wire, bounded to `MAX_FINGERPRINT_CHARS` (32) |
| `branch_shape` | string? | What follows the cookie: `uuid`, `as-hex`, `hex` or `other` |
| `tag_shape` | string? | The same vocabulary, for the `From` tag |
| `callid_has_host` | bool? | Whether the `Call-ID` carries an `@host` part |
| `inference` | string? | The library the observations point at — `pjproject` or `chan_sip`. Absent when they point nowhere |
| `confidence` | u8 | How many of the three observations agree with `inference`, out of three. `0` when sipnab inferred nothing |
| `requests_read` | usize | The denominator. A fingerprint from one request and one from four hundred are different claims |
| `mixed` | bool | True when this endpoint's own requests disagreed. A shared address, or a proxy relaying for others, carries both populations |

**It names a library, never a product.** `z9hG4bKPj` is pjproject's, and
pjproject ships inside Asterisk's `res_pjsip`, Grandstream UCM and FreePBX
alike — so naming a vendor from the shape would be a guess wearing the shape of
a measurement. The same discipline [`find_correlated`](mcp-tools-signaling.md#find_correlated) applies
with `identifier_match`.

**Two observations are the floor for an inference.** The magic cookie alone is
mandatory for every compliant sender, so it distinguishes nothing, and
`callid_has_host` alone splits the world roughly in half. One agreeing
observation infers nothing, and an unrecognized stack reports its shapes with no
`inference` at all. sipnab does not force it into the nearest label.

**Read from requests only.** A response echoes the request's branch, `From` tag
and `Call-ID` verbatim, so reading one would fingerprint the party that SENT the
request as though it were the party that answered — and on any dialog those are
two different stacks. An endpoint that only answers reports `requests_read: 0`
and infers nothing.

**`limit` bounds the page and never the counts.** `dialogs`, `by_method`,
`by_state`, `calls` and `streams` describe every match, and only
`recent_dialogs` shortens — with `truncated` saying so. `recent_dialogs` runs
newest first, because an operator chasing a complaint wants what just happened,
and [`list_dialogs`](mcp-tools-core.md#list_dialogs) already pages the whole history oldest-first
for anyone sweeping it.

**An `ip` matches on MESSAGES, not on the dialog's opening addresses.** A dialog
records the socket pair its first message arrived on, so a proxy re-originating
mid-dialog, a re-INVITE from a second interface, and a BYE from the far side all
belong to the call while carrying different addresses. Matching the dialog
record alone would silently drop them, and the dropped ones are exactly the
transfers and hand-offs an operator is looking for.

**A `user` matches the From or To user part EXACTLY.** [RFC 3261
section 19.1.4](https://www.rfc-editor.org/rfc/rfc3261#section-19.1.4) makes the user
part case-sensitive, so `Alice` and `alice` name two URIs, and folding the case
here would file one endpoint's traffic under the name of a second.

Three fields answer differently for a `user`, and each says so rather than
inventing a number:

| Field | For a `user` | Why |
|---|---|---|
| `messages_sent`, `messages_received` | Always `0` | A URI user part names a party, not a socket. Which party sent a given message does not follow from it, and a count derived from something else under this name would be worse than zero. |
| `streams` | The streams linked to that user's dialogs | A user has no media identity of its own, so the Call-IDs are the only bridge. An `ip` matches the media 5-tuple directly and therefore sees orphans too. |
| `findings.selectable` | `false`, with a `note` | The alert engine files every finding against a source IP, so no key selects a user. Re-ask with the address. |

That `selectable` flag matters because an empty list has three readings, not
one. `selectable: false` means nobody could ask. An empty `armed_kinds` means
nothing was watching, and the `note` says so in the same words
[`security_findings`](#security_findings) uses. Only on a server with a detector
armed does an empty list mean the endpoint stayed clean.

`failure_rate_pct` guards its denominator: it comes back `null`, not `0.0`, when
nothing reached a final status. A zero there hands a clean bill of health to an
endpoint nobody has measured.

`registration.applicable` does the same job for
REGISTER — `false` means the endpoint sent none, so the four counts under it
read as "no input" rather than "no failures". A registration counts by the
REQUEST rather than by the dialog's method, because a REGISTER can arrive inside
a dialog something else opened once Call-ID reuse is in play, and a registration
nobody examined reports as a healthy one. The Call-IDs in `problem_call_ids` go
straight into [`diagnose_registration`](#diagnose_registration).

`user_agents` attributes a banner to whoever wrote it: `User-Agent` off requests
the address SENT and `Server` off responses it sent, per [RFC 3261
section 20.41](https://www.rfc-editor.org/rfc/rfc3261#section-20.41) and
[RFC 3261 section 20.35](https://www.rfc-editor.org/rfc/rfc3261#section-20.35). Reading them off
received messages would file the far end's software under this endpoint. For a
`user` only `User-Agent` on requests whose From user matches counts, the one
case where the URI identifies the party that wrote the header. Values arrive
fenced, and so do the summaries in `recent_dialogs`.


## Diagnose one call

You have a call-id. These explain what happened to that one call -- its signaling, its media, and the specific negotiations that tend to break.

### `diagnose_registration`

"Is this phone online?" — a different question from "why did this call fail?".

**Parameters:** `call_id` (string, required) — a Call-ID the store holds. No
optional parameters. The call need not carry a `REGISTER`, and the answer says
so when it does not.

**Read `applicable` first.** It is `false` for a dialog carrying no `REGISTER`,
and the response then holds only `call_id`, `reason` and `schema_version` — no
`hints`, no `registration_failure`. Reporting a healthy registration for a call
that never attempted one would be worse than admitting the question does not
apply:

```jsonc
// diagnose_registration { "call_id": "1-1966@10.0.2.20" }   — an INVITE dialog
{
  "schema_version": 1,
  "call_id": "1-1966@10.0.2.20",
  "applicable": false,
  "reason": "this dialog carries no REGISTER request"
}
```

When it does apply, `registration_failure` is `null` for a registration that
worked, and otherwise names the `kind` — `rejected`, `shortened_expiry` or an
auth loop reported through `auth_loop`. `evidence` lists the message indexes
behind the verdict, ready for [`get_message`](mcp-tools-signaling.md#get_message). The example runs
against
[`tests/pcap-samples/sip-auth-failure.pcapng`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-auth-failure.pcapng):

```jsonc
// diagnose_registration { "call_id": "auth-fail-register-synth@203.0.113.1" }
{
  "schema_version": 1,
  "call_id": "auth-fail-register-synth@203.0.113.1",
  "applicable": true,
  "final_status_code": null,
  "auth_loop": null,
  "registration_failure": {
    "kind": "rejected",
    "code": 403,
    "evidence": [0, 3],
    "requested_expiry_sec": null,
    "granted_expiry_sec": null
  },
  "contact_rewrite": {
    "contact_host": "203.0.113.1:42952",
    "contact_host_private": false,
    "source_public": true,
    "rewrite_required": false
  },
  "hints": [
    "Call failed: 403 Forbidden.",
    "Registration rejected: 403 Forbidden. The endpoint answered an authentication challenge and the registrar refused the credentials it offered, so the fault is in the account, its password or its permission to register — none of which is a reachability problem."
  ]
}
```

`final_status_code` is `null` here even though the registrar answered 403,
because the dialog never reached a state that records one. Read
`registration_failure.code` for the status that decided the verdict.

#### `contact_rewrite` — the observation, not the finding

A phone behind NAT registers its own private address, and the registrar must
notice the packet came from a public address the header does not name and route
later requests there instead. When it does not, every inbound call goes to an
unroutable host and the phone never rings.

`rewrite_required` is the conjunction that shape needs:
`contact_host_private && source_public`. The sample above reports `false` — a
public `Contact` from a public source needs nothing rewritten, which is the
honest reading and not a fault ruled out.

| Field | Type | Description |
|---|---|---|
| `contact_host` | string? | The host the `Contact` named, as written. Absent for `Contact: *`, which [RFC 3261 section 10.2.2](https://www.rfc-editor.org/rfc/rfc3261#section-10.2.2) defines as every binding and which names no host |
| `contact_host_private` | bool? | Whether that host is one the public internet does not route to. Absent when the `Contact` names a domain, which resolves somewhere the capture cannot see |
| `source_public` | bool | Whether the REGISTER arrived from a public address |
| `rewrite_required` | bool | The two together |

**This is deliberately not a finding.** 1,660 of 2,226 REGISTER contacts in the
private corpus carry a private host — 74.6%, measured 2026-09-08 — and that
estate works. What separates the working case from the broken one is which
address later requests actually used, and one dialog cannot see that. Ask
[`describe_endpoint`](#describe_endpoint), which crosses an endpoint's dialogs
and reports `verdict` and `is_finding`.

The block is absent when the dialog carries no `REGISTER` — the same
`applicable: false` case the top of this section describes.


## Conformance and rules

Whether the traffic obeys the RFCs, and which clause it broke. These turn "the call failed" into "12.1.1 requires a Contact and there is none".

### `evaluate_expectations`

A pass/fail verdict on the loaded capture, and an exit code for a build.

Every other tool here makes a bad day shorter. This one prevents it, and it
moves sipnab from something an operator reaches for during an incident to
something that runs on every commit. The rules live in a checked-in
`sipnab.expect.toml` beside the SBC config: that file is the UX, and this tool
is how an agent reasons about it.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `rules` | object[]? | The suite inline. Each rule is `{metric, op, value}` plus optional `name`, `scope`, `min_sample` and `grounded_only`. Mutually exclusive with `rules_toml`. | Give `rules_toml` instead. |
| `rules_toml` | string? | The verbatim text of a `sipnab.expect.toml`. Mutually exclusive with `rules`. | Give `rules` instead. |
| `suppression_file` | string? | A lint suppression file in `--mcp-file-root`, applied to the `lint_errors` rules. | Discovers a `.sipnablint` beside the capture, exactly as [`lint_dialog`](mcp-tools-signaling.md#lint_dialog) does. |

Passing the file's own bytes is the point of `rules_toml`: the agent then judges
the capture against exactly what CI judges it against, rather than against its
own transcription. Passing both, or neither, fails — two suites in one call have
no defined order, and a call with no suite would report a verdict on nothing.

One rule is a metric, a comparison, a threshold, and what it applies to:

| Field | Legal values |
|---|---|
| `metric` | `count` (dialogs matching the scope), `asr` (answered over seized, as a PERCENT from 0 to 100, the same unit `group_dialogs` reports), `lint_errors` (conformance findings at or above a severity floor), `mos_p<N>` (a MOS percentile, `mos_p0` worst to `mos_p100` best). |
| `op` | `>=`, `>`, `<=`, `<`, `==`, `!=` |
| `value` | The threshold, in the metric's own unit. |
| `scope` | `filter:<alias-or-DSL>` to narrow by dialog, or `severity:<info\|notice\|warning\|error>` to set the floor a `lint_errors` rule counts from. Omitted means the whole capture. |
| `min_sample` | Observations below which the rule reports `skipped` rather than a verdict. |
| `grounded_only` | MOS metrics only. Defaults to `true`. |

```jsonc
// evaluate_expectations { "rules": [
//   { "name": "no codec rejections", "metric": "count", "op": "==", "value": 0,
//     "scope": "filter:response_code == 488" },
//   { "name": "audio floor", "metric": "mos_p10", "op": ">=", "value": 4.0 },
//   { "name": "answer rate", "metric": "asr", "op": ">=", "value": 99, "min_sample": 50 } ] }
{
  "schema_version": 1,
  "verdict": "pass",
  "exit_code": 0,
  "rules_total": 3, "evaluated": 2, "passed": 2, "failed": 0, "skipped": 1,
  "dialogs_in_capture": 2,
  "streams_in_capture": 2,
  "suppressions_applied": false,
  "results": [
    { "index": 0, "name": "no codec rejections", "metric": "count",
      "unit": "dialogs", "op": "==", "threshold": 0.0,
      "scope": "filter:response_code == 488", "observed": 0.0, "sample": 2,
      "verdict": "pass", "reason": "0 is == 0 over 2 dialog(s)" },
    { "index": 1, "name": "audio floor", "metric": "mos_p10",
      "unit": "mos (1.0-5.0)", "op": ">=", "threshold": 4.0,
      "observed": 4.358100156401542, "sample": 2, "ungrounded_excluded": 0,
      "verdict": "pass", "reason": "4.3581 is >= 4 over 2 scored stream(s)" },
    { "index": 2, "name": "answer rate", "metric": "asr",
      "unit": "ratio (0.0-1.0)", "op": ">=", "threshold": 0.99,
      "observed": 1.0, "sample": 2, "min_sample": 50,
      "verdict": "skipped",
      "reason": "skipped: 2 seizure(s) is below the declared min_sample of 50" }
  ],
  "capture_identity": { "node": "capture-01", "instance": "1d1a718cb5c33b7c52754-1",
                        "dialog_generation": 13, "stream_generation": 2 }
}
```

**`unit` rides on every outcome, and reading it is not optional.** `asr` here is
a RATIO from 0.0 to 1.0, and the same name in
[`group_dialogs`](mcp-tools-signaling.md#group_dialogs) is a PERCENT. A threshold of `0.99` means 99%
under one reading and 1% under the other, so the answer names its unit rather
than leaving it to this page.

**An empty population FAILS, and the message says why.** Three failure modes get
a gate deleted rather than fixed, and each one has an answer here:

| Failure mode | What this tool does |
|---|---|
| Passing on data it never judged | A rule whose population is empty reports `fail` with `reason` beginning `unevaluable:`. A MOS threshold on a capture full of AMR-WB would otherwise score every stream off a placeholder and report green having measured nothing. |
| Failing on a sample too small to mean anything | `min_sample` is a declared floor. Below it a rule reports `skipped`, so a three-call smoke test never trips an ASR threshold on a Friday afternoon. |
| Lying about coverage | A suite where every rule skipped reports `not_evaluated` with exit code `2`, distinct from a pass. A file of rules that never run is exactly the thing that stays in a repository claiming to check something. |

Declaring `min_sample` of 1 or more is the ONLY way to have an empty population
tolerated, and that asymmetry carries weight: a gate goes quiet only where its
author wrote down that it may. `min_sample: 0` declares no floor at all, so it
leaves the empty case failing exactly as an absent one does.

```jsonc
// evaluate_expectations { "rules": [{ "metric": "asr", "op": ">=", "value": 95 }] }
// ... on a capture holding two REGISTER dialogs and no call attempt:
{ "verdict": "fail", "exit_code": 1, "evaluated": 1, "failed": 1,
  "results": [ { "index": 0, "metric": "asr", "observed": null, "sample": 0,
    "verdict": "fail",
    "reason": "unevaluable: no seizure was in scope, so 'asr >= 95' rests on nothing. Declare a min_sample of 1 or more to accept an empty population in writing; a gate does not pass on data it never judged" } ] }
```

The verdict tests the SAMPLE rather than whether a value came back. `count`
always produces a value — zero matches is zero — so checking the value alone let
`count == 0` pass on a capture holding no dialogs at all, which is the exact
"green on data it never judged" this design refuses.

`exit_code` is what a command line reports: `0` every rule that ran passed, `1`
at least one failed, `2` nothing ran. CI has to tell a green run from a run that
judged nothing, and a shell script comparing against `0` cannot.

Three more things the report says out loud. `sample` names how many observations
each figure rests on. `ungrounded_excluded` appears on MOS rules and counts the
streams whose codec has no published impairment value — with `grounded_only`
off, `notes` says instead that placeholder scores entered the percentile.
`suppressions_applied` says whether a lint suppression file was in force, so a
`lint_errors` count of zero cannot pass for one taken with every rule armed.

A defect in the RULES is a hard error rather than a per-rule failure: an unknown
metric, an unparseable filter, a `severity:` scope on a metric that reads no
findings, `grounded_only` on a metric that reads no MOS, or a percentile outside
0 to 100 all fail the whole call with `invalid_params` naming the rule's index.

A misspelled metric evaluating to "fail" would look identical to traffic that
genuinely broke the threshold, and one evaluating to "pass" would be a gate that
checks nothing while looking green. Half a gate reporting green is the outcome
this refuses to produce.

> Nothing on the CLI reaches this evaluator yet. It and `exit_code` both ship
> and both carry tests, and no flag runs them, so a checked-in
> `sipnab.expect.toml` cannot fail a build on its own today.


## Security

Scanner and abuse signals derived from the capture, and the one tool that turns them into something a firewall can act on.

### `security_findings`

Recent findings from active detection rules (scanner, fraud, digest,
reg-flood, etc.). Backed by the AlertEngine's bounded ring buffer
(default 1000 entries, kept in memory only).

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `kinds` | string[]? | Exactly four names: `scanner`, `fraud`, `digest`, `reg_flood`. Anything else fails with `invalid_params` naming all four — including `reg-flood` with a hyphen, which suggests the underscore spelling. | Findings of every kind. |
| `since` | string? | [RFC 3339](https://www.rfc-editor.org/rfc/rfc3339). Keeps findings recorded strictly after it. A malformed value fails with `since must be RFC 3339`. | The whole retained history. |
| `limit` | u32? | Ceiling is `--mcp-max-rows` (1000 by default). Higher clamps to it, `0` means the default. | 50 findings. |

**Returns** — a page object, not a bare array:

| Field | Type | Description |
|---|---|---|
| `findings` | object[] | This page of `{ rule_name, src_ip, detail, timestamp }`, newest first. |
| `returned` | usize | Rows in `findings`. |
| `total_matched` | usize | Findings matching `kinds` and `since` across the whole retained ring buffer. |
| `truncated` | bool | `true` when matches remain after this page. There is no cursor — narrow with `since`, or raise `limit`. |
| `armed_kinds` | string[] | The detectors this server runs. Empty means it runs none, so `findings` could only ever be empty. |
| `detection_armed` | bool | `false` when `armed_kinds` is empty, stated separately so a caller can branch on one field. |
| `note` | string? | Present **only** when no detector runs, saying so in words. |
| `observation_gaps` | object[] | What an armed detector says it **cannot establish** from this capture: `{ rule_name, reason, seen, unestablished, detail }`, narrowed by `kinds`. Always present, empty when there is nothing to say. See below. |
| `schema_version` | u32 | `1` for this shape. |

> **Read `armed_kinds` before you read `findings`.** An empty findings list
> means "nothing tripped" only on a server that armed something. On any other
> it means nothing was watching, and the two are opposite operational states.
> A `kinds` value outside the vocabulary fails rather than answering with an
> empty list, which would be a third way to read `[]`. Cross-checking
> [`server_capabilities`](mcp-tools-server.md#server_capabilities) is not necessary for this
> question: the answer is in the response.

The page fields carry the meanings they do everywhere else on this surface —
[`search_messages`](mcp-tools-core.md#search_messages) documents the same four. `armed_kinds` is
per detector, which is what makes it worth reading rather than a bare
"detection is on": a server started with `--kill-scanner` alone answers
"no fraud findings" for a capture full of toll fraud, and `armed_kinds:
["scanner"]` is what tells an agent that the question was never asked.

Arming a rule takes a flag on the server command line, such as `--kill-scanner`
or `--digest-leak`. Findings then land in a bounded in-memory ring buffer
(1000 entries by default, `--findings-history` to change it) and go nowhere
else — stopping the process discards them.

`timestamp` records when the rule **fired during analysis**, not when the packet
arrived. On a replayed pcap those differ by years, so a `since` value copied
from a dialog's `created_at` returns everything.

The example runs against
[`tests/pcap-samples/sip-auth-failure.pcapng`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-auth-failure.pcapng)
on a server started with `--digest-leak`:

```jsonc
// security_findings {}
{
  "schema_version": 1,
  "findings": [
    {
      "rule_name": "digest",
      "src_ip": "203.0.113.101",
      "detail": "WeakAlgorithm: challenge uses algorithm=MD5 (should be SHA-256+)",
      "timestamp": "2026-08-13T16:16:02.880725566+00:00"
    }
  ],
  "returned": 1,
  "total_matched": 1,
  "truncated": false,
  "armed_kinds": ["digest"],
  "detection_armed": true,
  "observation_gaps": []
}
```

**`observation_gaps` is the third reading of an empty list.** An armed detector
can still fail to see its evidence. `reg_flood` counts a failure only
when the registrar's `401`/`407` answers a credentialed REGISTER, so a capture
that holds the REGISTERs and not the answers, such as a one-way tap or a
request-only capture filter, leaves it nothing to count. It then files one
entry here instead of staying silent:

- `reason: "no_answers"`: the capture shows REGISTERs (`seen`) and no final
  response to any of them. sipnab cannot establish any outcome.
- `reason: "unanswered"`: some credentialed REGISTERs (`unestablished` of
  `seen`) drew no final response inside `--reg-flood-transaction-timeout`
  (RFC 3261 Timer F, 32 s by default), so they count as neither failures nor
  successes.

An entry names no source and never becomes a finding, an alert or a jail line:
a REGISTER count with no outcome behind it is a volume, and `reg_flood` does not
act on volume. A live server refreshes it every five seconds of capture time,
and the end of a file input settles it.

The same tool on a server started without a detection flag answers with an
empty `findings` list, `armed_kinds: []`, `detection_armed: false` and a `note`
saying that nothing was watching. `armed_kinds: ["digest"]` above says the
opposite in the same field: this server watched for digest weaknesses and for
nothing else, so it answers nothing about scanners either way.

### `generate_fail2ban_rule`

A fail2ban filter and jail derived from ONE recorded security finding.

Scoped to one finding, with that finding attached as the evidence. A rule
generated from a class of findings would be a policy this tool has no standing
to write. A rule generated from one, with the alert line it matches printed
beside it, is something an operator can read and decide on.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `finding_id` | string | `<rule_name>@<src_ip>@<timestamp>` — the three fields [`security_findings`](#security_findings) already returns for every finding. | Required — the call fails. |

The id derives from the finding rather than coming from a counter, because an
assigned id would have to survive eviction, restart and a second server reading
the same capture, and none of those hold for a position in a bounded ring
buffer. An agent holding "id 7" across a restart would act on a different
finding.

```jsonc
// generate_fail2ban_rule { "finding_id": "digest@203.0.113.101@2026-08-28T11:31:03.859034298+00:00" }
{
  "schema_version": 1,
  "finding_id": "digest@203.0.113.101@2026-08-28T11:31:03.859034298+00:00",
  "evidence": {
    "rule_name": "digest",
    "src_ip": "203.0.113.101",
    "detail": "⟦untrusted-capture-data⟧WeakAlgorithm: challenge uses algorithm=MD5 (should be SHA-256+)⟦/untrusted-capture-data⟧",
    "timestamp": "2026-08-28T11:31:03.859034298+00:00"
  },
  "filter_name": "sipnab-digest",
  "filter_path": "/etc/fail2ban/filter.d/sipnab-digest.conf",
  "filter_conf": "# Generated by sipnab from finding digest@203.0.113.101@...\n[Definition]\nfailregex = ^.*\\[ALERT\\] digest src=<HOST> .*$\nignoreregex =\n",
  "jail_path": "/etc/fail2ban/jail.d/sipnab-digest.conf",
  "jail_conf": "[sipnab-digest]\nenabled  = true\nfilter   = sipnab-digest\nlogpath  = /var/log/syslog\nport     = 5060,5061\nprotocol = udp\nmaxretry = 3\nfindtime = 600\nbantime  = 3600\n",
  "log_line_format": "[ALERT] <rule_name> src=<ip> <detail>",
  "caveats": [ /* three, below */ ]
}
```

**The `failregex` matches sipnab's own alert line**, the `[ALERT] <rule> src=<ip>
<detail>` form sipnab writes. So the jail sees nothing until sipnab runs with
`--alert syslog`, or something captures its stderr to the `logpath`. That is the
first caveat, and it is the one that makes an otherwise-correct jail inert.

The other two caveats say what the numbers are not. `maxretry`, `findtime` and
`bantime` are fail2ban's conventional starting values rather than figures sipnab
measured on this traffic — choose them from your own false-positive tolerance.
And one finding is evidence that this detector fired, not that every future
match is an attacker: the jail bans any source the detector reports, this one
included. A loopback `src_ip` adds a fourth caveat, because a jail acting on it
would ban the host from itself.

Two refusals. A server with no detector armed holds no findings at all, and says
so rather than reporting an unknown id:

```jsonc
{ "code": -32602,
  "message": "this server holds no findings: no detection rule was armed, so nothing could have been recorded. Arm one with --kill-scanner, --fraud-detect, --digest-leak or --reg-flood and re-run the capture." }
```

An id the server does not hold comes back with the ids it does hold, up to the
row cap, so a caller that mistyped a timestamp does not have to go back to
[`security_findings`](#security_findings). The scan walks the whole ring buffer
for that list, because a truncated scan cannot report what it truncated — and
here the truncated part is the vocabulary the caller gets offered.

`detail` arrives fenced: it quotes headers a sender wrote. `rule_name` does not,
because sipnab chose it — and the tool checks that name is a bare identifier
before writing it into a regular expression, since a name carrying a
regular-expression operator would produce a pattern the author never wrote.
