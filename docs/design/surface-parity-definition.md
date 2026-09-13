# What parity means here (PAR-S1)

"All surfaces in sync" cannot be gated until it is defined. This spec is that
definition, and it gates PAR1 through PAR5. Without it PAR2's gate either
demands a REST route for every MCP tool or demands nothing.

## The four surfaces, and who uses each

| Surface | Driven by | What it is good at |
|---|---|---|
| CLI | a person at a shell, or a script | one answer, piped; batch; cron |
| TUI | a person exploring interactively | browsing, drilling, comparing by eye |
| REST | another program, over HTTP | polling, integration, a dashboard's backend |
| MCP | an AI agent | asking in words, following evidence, correlating |

Parity is NOT "every capability on every surface." It is "every capability on
every surface it belongs on, and a stated reason where it does not."

## The test a reviewer applies

A capability belongs on a surface unless it fails the surface's own question:

- **CLI** — can the answer be produced in one shot, without a human watching?
  A capability that only makes sense while stepping through a call by eye
  (mark-and-delta) fails this, and is TUI-only by nature.
- **TUI** — would a human at a terminal reach for it? A machine-to-machine
  detail an agent needs and a person never reads (a schema version, a cursor
  token) fails this.
- **REST** — would another program poll or integrate it? A one-shot
  interactive affordance fails this; a queryable fact passes.
- **MCP** — would an agent asking in words want it? Almost everything passes;
  the exceptions are affordances that only mean anything to a human looking at
  a screen.

A capability that passes a surface's question and is absent from it is a GAP.
A capability that fails a surface's question and is absent is a DECISION, and
the decision is recorded beside it. The difference between the two is the whole
content of this spec: a gate that cannot tell them apart reports either every
absence as a bug or none.

## Worked examples, so the test is not abstract

| Capability | CLI | TUI | REST | MCP | Why |
|---|:--:|:--:|:--:|:--:|---|
| List dialogs | yes | yes | yes | yes | Everyone wants it |
| Per-stream RTP quality | yes | yes | yes | yes | Everyone wants it |
| Mark a message, show the delta | no | **yes** | no | no | Only means something while a human steps through a ladder |
| Correlate B2BUA legs (`find_correlated`) | yes | yes | yes | yes | An agent wants it most, but a human and a script both have the question |
| Follow a frame pointer to its bytes | yes | yes | yes | yes | Evidence is everyone's |
| Schema version on a reply | no | no | **yes** | **yes** | A machine contract; a person reading a terminal never needs the integer |
| Live-narrow the dialog list as you type | no | **yes** | no | no | An interactive affordance with no one-shot meaning |

The two `no`-heavy rows are DECISIONS, and they are why PAR2 must not demand a
REST route per MCP tool. The all-`yes` rows are the default, and an absence
from one of them is a GAP that PAR3, PAR4 or PAR5 closes.

## What PAR2's gate must do

- Derive the capability-to-surface JOIN (PAR1), not a second hand-written
  table. The coverage matrix already enumerates flags, routes and tools
  separately; PAR1 is the join that says a capability is reachable three ways
  and not four.
- For each capability absent from a surface, require either a passing answer to
  that surface's question (making it a GAP the gate reports) or a recorded
  decision (making it expected). The decisions live in one place, each with its
  reason, the way the known-untested flag list and the surface-omission notes
  already do.
- Name the surfaces a capability is missing from, not merely that it is
  incomplete. "find_correlated is absent from REST and TUI" is actionable;
  "parity incomplete" is not.
- Carry an anti-vacuity floor, like every other source-scanning gate here: a
  join that stopped matching must fail loudly rather than certify silence.

## How this reads against the relay-statistics specs

ST-S3 already applied this test to the five statistics capabilities before they
exist: four surfaces each, with polling deliberately CLI-only and its reason
recorded. That is exactly the shape PAR-S1 generalizes — a capability present
everywhere it belongs, and every omission a decision with a reason rather than
a gap nobody noticed. ST-S3 is the worked instance; this is the rule it
followed.

## What this does not decide

- The closing of any specific gap. PAR3, PAR4 and PAR5 do that, each starting
  from the join PAR1 produces.
- Whether a borderline capability belongs on a surface. The reviewer applies
  the surface's question; this spec gives the question, not a verdict on every
  future capability.
