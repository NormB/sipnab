# The surface contract for relay statistics (ST-S3)

One document covering all four surfaces together, because writing them
separately is what produced the drift PAR exists for.

This gates ST5, ST6, ST7 and ST8. It assumes the tiers and the rendering rule
in [`docs/design/relay-statistics-vocabulary.md`](relay-statistics-vocabulary.md)
and the inventories in
[`docs/design/relay-statistics-inventory.md`](relay-statistics-inventory.md).

## The word "statistics" is already taken, three times

Before adding anything, what the four surfaces already call statistics:

| Surface | Name | What it answers | Tier |
|---|---|---|---|
| TUI | the `Statistics` view (`View::Statistics`) | Dialog-state and method distributions from this capture | `sipnab_measured` |
| REST | `GET /v1/stats` | Capture counters | `sipnab_measured` |
| REST | `GET /v1/runtime` | What sipnab costs the host | neither — about the process |
| MCP | `runtime_stats` | The same, for an agent | neither — about the process |
| MCP | `capture_health` | Capture-path counters, read twice | `sipnab_measured` |
| Prometheus | `/metrics` | Counters and gauges about sipnab itself | `sipnab_measured` |

**None of these is about a relay.** A fifth thing called "statistics" that is
about a relay, sitting beside four that are about sipnab, is a name collision an
operator pays for at three in the morning.

**Decision: the capability is spelled `relay-stats` / `relay_stats`, never bare
`stats`.** Every surface below carries the word `relay` in the name a user
types or an agent calls. The TUI's existing `Statistics` view is not renamed —
it is correct about what it shows, and renaming a shipped affordance to make
room for a new one costs every existing user for the benefit of a feature they
have not seen yet.

## The capabilities

Five, and every surface offers all five unless this table says otherwise.

| # | Capability | The operator's question |
|---|---|---|
| C1 | Relay global statistics | What has this relay counted since it started? |
| C2 | Relay per-call statistics | What does this relay hold for THIS call? |
| C3 | Which statistics this relay knows | What can I even ask for? |
| C4 | Compare relay against capture | Does the relay's view of this call match mine? |
| C5 | Poll on an interval | Keep asking, every N seconds (ST4) |

C3 exists because the key set is version-specific. Without it a caller has no
way to discover that `rtpa_nlost` is answerable on one build and refused on
another, and every surface would push that discovery onto a failed request.

## The contract, per capability

### C1 — relay global statistics

| Surface | Spelling |
|---|---|
| CLI | `--relay-stats` (flag, no value: all of them) and `--relay-stats <name>[,<name>…]` (repeatable) |
| REST | `GET /v1/relay/stats`, optional `?names=a,b` |
| MCP | `relay_stats` tool, `{ "names": ["…"] }` optional |
| TUI | `S` from the call list, opening a `RelayStats` view |

Payload, on every surface, one object per statistic:

```json
{
  "name": "npkts_relayed",
  "value": 9000,
  "tier": "relay_reported",
  "obtained_at": "2026-09-12T18:12:04Z",
  "relay": { "implementation": "rtpproxy", "delivery": "bare_datagram" }
}
```

`value` is the relay's own value uncoerced: an integer where the relay sent an
integer, a string where it sent a string. `uptime` on rtpengine is `"134"` and
stays `"134"`.

`relay` repeats per statistic rather than sitting once at the top, because a
future caller asking two relays in one request must not have to remember which
half of the array belonged to which. An estate with two relays is the case this
whole program is being shaped around.

### C2 — relay per-call statistics

| Surface | Spelling |
|---|---|
| CLI | `--relay-stats-call <CALL-ID>` |
| REST | `GET /v1/relay/stats/call/{call_id}` |
| MCP | `relay_stats` with `{ "call_id": "…" }` — the SAME tool, not a second one |
| TUI | `S` from within a call's flow view |

**One MCP tool for both C1 and C2, and for both relays.** RP2's acceptance test
already forbids a parallel `query_rtpproxy` beside `query_relay`: doubling the
agent surface per relay doubles what an agent must learn for no gain. The same
argument applies to splitting global from per-call.

A per-call request against rtpproxy must handle the tag suffix: OpenSIPS keys
sessions on a `;1` viabranch-suffixed tag and the capture sees the unsuffixed
one. sipnab holds both and must try what the relay holds, not what the wire
showed. An `E50` after that must NOT be reported as "the relay is not holding
this call" without saying which tags were tried.

### C3 — which statistics this relay knows

| Surface | Spelling |
|---|---|
| CLI | `--relay-stats-list` |
| REST | `GET /v1/relay/stats/names` |
| MCP | `relay_stats` with `{ "names_only": true }` |
| TUI | the `RelayStats` view's header line, and `?` within it |

### Why `S` and `K`, and not the obvious letters

Checked against the bindings rather than assumed. `R` is `ToggleSplit` in the
call flow view and `c` is `CycleColorMode` there, so the two letters this
document first proposed were both already taken — caught before the spec shipped
them, which is the only reason to write the spec first.

Of what is free, `S` is the shifted form of `s`, which already opens the
capture's own `Statistics` view. That pairing is deliberate: lower case asks
what sipnab saw, upper case asks what the relay says. The alternative was a
letter with no relationship to anything, which is harder to remember and no less
arbitrary.

`K` is free and has no competing meaning. The genuinely free lowercase letters
are `g` and `o`, and `o` is the lower case of the open-capture key, which is
exactly the confusion this section exists to avoid.

The answer is obtained by asking, never by a table compiled into sipnab. For
rtpengine that is the key set of a `statistics` reply. For rtpproxy there is no
list command, so the answer is the set of names that did not return `E68` when
asked — and the reply says that is how it was determined, because a name that
is refused today because the relay is busy is not the same as a name this build
does not have.

### C4 — compare relay against capture

| Surface | Spelling |
|---|---|
| CLI | `--relay-compare <CALL-ID>` |
| REST | `GET /v1/relay/compare/{call_id}` |
| MCP | `relay_compare` tool |
| TUI | `K` within the `RelayStats` view |

This is the one place two tiers appear in one answer, and it is a comparison,
never an aggregate. Both figures are shown, both tiers are named, and the
verdict is a word rather than a number:

```json
{
  "call_id": "…",
  "packets": {
    "relay_reported": { "value": 9000, "name": "npkts_relayed" },
    "sipnab_measured": { "value": 8994 },
    "verdict": "differ",
    "note": "sipnab saw 6 fewer; a capture on a mirror port under load undercounts, and capture_health says whether this run dropped any"
  }
}
```

The `note` is not optional decoration. A difference here has at least three
ordinary causes that are not a relay fault — capture drop, a window that does
not line up, a relay restart mid-call — and an operator handed a bare "differ"
will go looking at the relay first.

### C5 — poll on an interval

| Surface | Spelling |
|---|---|
| CLI | `--relay-stats-interval <SECONDS>` |
| REST | not offered |
| MCP | not offered |
| TUI | inherits whatever the run was started with; shows the interval in the header |

**REST and MCP deliberately omit it, and here is why.** A poll is a standing
instruction to transmit. On the CLI the operator who typed the flag is the
operator running the process, and stopping it is `Ctrl-C`. Over REST or MCP the
caller who starts a poll is not the one who owns the host, and nothing in either
protocol makes "this will keep transmitting after you disconnect" visible.
Every other MCP tool answers from bytes sipnab already holds; `query_relay` is
the one that transmits and it transmits once per call. A tool that installed a
timer would be a different kind of thing behind the same permit.

An omission with a reason is a decision. This is the only omission in this
document.

## What every surface must do identically

1. **Refuse the same way.** No relay configured, no transmit permit, a
   file-backed run, a relay that did not answer, a relay that refused: the same
   five conditions, distinguished the same five ways, on all four surfaces. The
   catalog is ST-S4's.
2. **Name the relay in the answer.** An estate with two relays makes an
   unattributed statistic worthless.
3. **Carry the tier on every value**, per ST-S1. No surface renders a bare
   number.
4. **Omit rather than zero.** A statistic not obtained is absent; a refusal
   carries the statistic's name and the relay's code.
5. **Say when it was obtained**, so a polled figure and a freshly asked one are
   distinguishable without asking how the run was started.

## What every surface may do differently

- **Layout.** A TUI column, a JSON field and a CLI table are different
  renderings of one fact and that is fine.
- **Default breadth.** The TUI may show a chosen dozen with the rest behind a
  key; the CLI with no names may print all of them; MCP returns what was asked
  for. None of these changes what a name means.
- **Refresh.** The TUI may re-render from the last answer without re-asking, as
  long as the displayed `obtained_at` is the answer's and not the render's.

## Acceptance, before any of ST5–ST8 is called done

- One capability matrix test asserting all five capabilities exist on all four
  surfaces, with C5's two omissions named in the test as expected and with
  their reason, so removing the reason fails the test rather than the omission
  passing silently.
- One test per surface asserting no bare `stats` spelling was introduced.
- The 50-test minimum per surface is drawn from ST-S4's catalog, not from
  whatever each surface's author thought of.
