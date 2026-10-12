+++
title = "One filter language for the command line, the config file, vCon export and MCP tools"
date = 2026-09-01
updated = 2026-10-11
description = "Where sipnab accepts a filter expression, how to try one before you rely on it, and what a value the capture could not measure matches."

[extra]
kind = "feature"
+++

## In short

sipnab, a tool that reads recorded or live phone-call traffic, lets you pick
out the calls you care about with a short written condition such as "calls
that failed with code 488". The same condition works everywhere sipnab asks
which calls you mean: on the command line, in the settings file, when saving
call records, in automated pass/fail checks, and in the tools an AI assistant
uses. A value the recording does not contain, such as call quality on a call
that carried no audio, matches no condition at all.

## Who this is for

Anyone who writes a sipnab filter more than once, and anyone who keeps one in
a settings file, a test suite or an assistant's instructions.

## What it does

A filter selects **dialogs**: one dialog is one SIP call or other SIP
conversation, from its first request to its last reply (SIP is the signaling
protocol that sets up and ends phone calls). The filter language compares
fields of a dialog, such as `response_code`, `duration` or `rtp.mos`, and
combines comparisons with `AND`, `OR` and `NOT`.

sipnab accepts the same text in each of these places:

| Where | What you write |
|---|---|
| Command line | `--filter <EXPR>` |
| Settings file | `expression` under `[filter]` |
| Saving calls as vCon files | `--export-vcon-when <EXPR>` |
| Pass/fail rules for automated tests | `scope = "filter:<EXPR>"` in a rule read by the MCP tool `evaluate_expectations` |
| MCP tools that list dialogs | the `filter` parameter of `list_dialogs`, `find_problems` and others |

A vCon is a standard JSON file that holds one conversation's record. MCP
(Model Context Protocol) is the interface an AI assistant uses to call
sipnab's tools.

Ten names stand for preset expressions: `problems`, `slow-setup`,
`short-calls`, `one-way`, `nat-issues`, `codec-asym`, `ptime-asym`,
`payload-asym`, `duration-asym` and `late-media`. `--filter` first checks
whether its argument is one of these names and treats it as an expression only
when it is not. Five of the names also have their own flag (`--problems`,
`--slow-setup`, `--short-calls`, `--one-way`, `--nat-issues`), and the MCP
tool `find_problems` takes them in its `kinds` list.

## How to turn it on

Nothing needs enabling. The filter language is part of every sipnab build.
`--export-vcon-when` and the MCP tools need a build with the `vcon` and `mcp`
features. `sipnab --version` lists the features a binary carries.

## Example run

These commands use `tests/pcap-samples/sip-488-codec-reject.pcapng`, a
recording (pcap file) that ships in the sipnab repository and holds four
dialogs. `-N` selects command-line mode instead of the interactive screen, `-q`
hides informational log lines, and `--no-cli-print` suppresses the per-message output so sipnab
prints only the report. The output below has the trailing spaces at the ends
of the report lines removed.

1. Select the dialogs that failed with response code 488:

```bash
sipnab -N -q -I tests/pcap-samples/sip-488-codec-reject.pcapng --filter "response_code == 488" --report --no-cli-print
```

```text
Call-ID                          From           To             State        Code   Duration   Msgs   PDD      Tags
-------------------------------------------------------------------------------------------------------------------------
codec-reject-synth               caller         callee         Failed       488    0s         7      -        -
```

2. Save the same dialogs as vCon files, using the same expression. sipnab
   creates the directory `vcons` in the current directory:

```bash
sipnab -N -q -I tests/pcap-samples/sip-488-codec-reject.pcapng --export-vcon-when "response_code == 488" --export-vcon-dir vcons --no-cli-print
```

```text
Wrote 1 vCon container(s) to 'vcons'.
```

3. Use a preset name instead of an expression. `short-calls` expands to
   `duration < 3.0 AND state == 'Completed'` while the short-call threshold is
   at its default of 3 seconds:

```bash
sipnab -N -q -I tests/pcap-samples/sip-488-codec-reject.pcapng --filter short-calls --report --no-cli-print
```

```text
Call-ID                          From           To             State        Code   Duration   Msgs   PDD      Tags
-------------------------------------------------------------------------------------------------------------------------
options-ping-a-synth@192.16...   keepalive      keepalive      Completed    200    0s         2      -        -
options-ping-b-synth@192.16...   keepalive      keepalive      Completed    200    0s         2      -        -
options-ping-c-synth@198.51...   ping           probe          Completed    200    0s         2      -        -
```

`--short-calls` and `--filter "duration < 3.0 AND state == 'Completed'"`
print the same three dialogs on this file.

## Check an expression before you rely on it

The MCP tool `validate_filter` parses an expression, counts the dialogs it
matches, and returns no dialog rows. Run against the same file, a call with
`{"expr":"short-calls"}` returned:

```json
{"error":null,"expr":"short-calls","schema_version":1,"source_exhausted":true,"source_stopped_early":false,"total_dialogs":4,"total_matched":3,"valid":true}
```

An expression that does not parse is not an error for this tool. A call with
`{"expr":"response_code == == 5"}` returned `"valid":false`,
`"total_matched":null` and the parser's message in `error`, which names
position 17 and marks it with a caret. `total_matched` is `null` rather than
`0` so that no reader can take it as "parsed, and matched nothing". Other MCP
tools, such as `list_dialogs`, reject the same expression with a JSON-RPC
error (code `-32602`).

## Limits

- **A value the capture could not measure matches no comparison.** `pdd`
  (post-dial delay), `setup_time`, `rtp.mos` (call-quality score), `rtp.jitter`
  and `rtp.loss` are unknown when there is nothing to measure them from: no RTP
  (the packets that carry the audio) for the media fields, no captured INVITE
  or `200 OK` for the timing fields. An unknown value matches no numeric
  operator, `!=` included. `response_code` is unknown while a call is still in
  progress. On `tests/pcap-samples/b2bua-asterisk.pcapng`, which holds 12
  dialogs and media for 2 of them, `--filter "rtp.mos != 3.0"` selects only
  those 2. To select calls without media, use `rtp.packets == 0`, which is a
  real count, or the field `no_media`.
- **`rtp.orphaned` is not a field.** The parser rejects it with
  `hint: unknown field 'rtp.orphaned'` and exit code 2. An orphaned stream is
  an RTP stream that no dialog claims, so a dialog field cannot describe it.
  The "Orphaned Streams" section of `--report` and
  `GET /v1/streams?orphaned=true` on the REST API list orphaned streams.
- **`--call-report <CALL-ID>` is not narrowed by `--filter`.** It names one
  call, so it prints that call whatever the filter says.
- **The language has no comment syntax.** A line starting with `#` is a parse
  error.
- **String comparisons are case-sensitive.** `=~` takes a regular expression in
  Rust regex syntax.
- **The per-message match is a separate option.** `-e`/`--match` tests a
  regular expression against each raw SIP message and, once one message in a
  dialog matches, shows every later message of that dialog. Inside a filter
  expression, the `payload` field does the same test per dialog.

## Terms used here

- **SIP**: the protocol that sets up, changes and ends phone calls over IP.
- **Dialog**: one SIP conversation, such as one call, from first request to
  last reply.
- **RTP**: the protocol that carries the audio of a call.
- **pcap**: a file format for recorded network traffic.
- **INVITE / 200 OK**: the SIP request that starts a call, and the reply that
  accepts it.
- **Response code**: the three-digit number in a SIP reply; 400 and above means
  failure.
- **MOS**: Mean Opinion Score, an estimate of call quality from 1 to 5.
- **Post-dial delay (PDD)**: time from the call request to the first reply that
  shows the far end is ringing or answering.
- **vCon**: a standard JSON file format for one conversation's record.
- **MCP**: Model Context Protocol, the interface AI assistants use to call
  tools.
- **JSON-RPC error**: the error form MCP uses for a call it refuses.
- **REST API**: sipnab's HTTP interface for other programs.

## Related guides

- [What a filter narrows](@/docs/filter-dsl.md#what-a-filter-narrows)
- [Numeric fields, including unknown values](@/docs/filter-dsl.md#numeric-fields)
- [Named aliases and their expansions](@/docs/filter-dsl.md#named-aliases)
- [Parser constraints](@/docs/filter-dsl.md#parser-constraints)
- [The `[filter]` settings section](@/docs/config.md#filter)
- [`validate_filter`](@/docs/mcp-tools-signaling.md#validate-filter),
  [`find_problems`](@/docs/mcp-tools-core.md#find-problems),
  [`list_dialogs`](@/docs/mcp-tools-core.md#list-dialogs) and
  [`evaluate_expectations`](@/docs/mcp-tools-security.md#evaluate-expectations)
- [`GET /v1/streams`](@/docs/api.md#get-v1-streams)
