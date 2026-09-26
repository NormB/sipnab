# sipnab

**sipnab** captures and analyzes SIP signaling and the RTP media under it, with
security checks on both, in a single binary. It offers an interactive TUI, a
scriptable CLI, JSON and report output, a REST API, and an MCP server for AI
agents.

This index groups the pages by what you are trying to do, following
[Diátaxis](https://diataxis.fr/). The four groups answer four different
questions:

| If you are… | you want | start at |
|---|---|---|
| new to sipnab | a guided first run | [Tutorials](#tutorials) |
| trying to get something done | steps for your goal | [How-to guides](#how-to-guides) |
| looking something up | exact, complete facts | [Reference](#reference) |
| trying to understand it | why it works this way | [Explanation](#explanation) |

## Tutorials

Follow these in order on your first day. They assume nothing and show what you
should see at each step.

1. **[Install sipnab](install.md)**: the one-line installer, prebuilt
   binaries, packages, or a source build. Reading a capture file needs no
   privileges. Live capture needs root or `CAP_NET_RAW`, which
   `sudo sipnab --setup-caps` grants once.
2. **[Triage a capture from the command line](first-cli-triage.md)**: download
   a sample call, list its calls, find the failed ones, explain one, and pipe
   the answer into `jq`.
3. **[Your first analysis in the TUI](tui-walkthrough.md)**: open the same
   capture interactively, read the call-flow ladder, measure a delay, and
   inspect the audio quality.

The [Glossary](glossary.md) defines PDD, MOS, B2BUA and the other terms these
pages use.

## How-to guides

Each answers "how do I …?" and assumes you already know what you want.

**Find out what went wrong**

- **[Troubleshooting](troubleshooting.md)**: symptom to command. Failed calls,
  one-way audio, high loss, NAT issues: what to run and what to look for.
- **[Examples & recipes](examples.md)**: a recipe per task, each with the
  command and real output, from triage and filtering to HEP, TLS decryption
  and audio export, plus one-liners to copy.
- **[Worked examples from real captures](real-world-captures.md)**: twelve
  findings read out of live carrier and PBX traffic, each with the command,
  the output and what to do next.
- **[Narrow to the calls that matter](filter-dsl.md)**: the filter language
  (`method == 'INVITE' and rtp.mos < 3.5`) and the diagnostic aliases
  (`--filter codec-asym`), with its complete grammar and field list.

**Capture what you need**

- **[Tune capture on a busy server](tuning-capture.md)**: tell whether you
  are dropping packets, and what to change when you are.
- **[Read SIP inside a tunnel or tag](encapsulations.md)**: whether sipnab
  can read SIP wrapped in MPLS, PPPoE, GTP-U or VXLAN, and what it says when it
  cannot.
- **[Capture SIP over TLS](tls-capture.md)**: pick a method by the access
  you have, whether a key log, the process itself, or eBPF.
- **[Read SIP over TLS without keys](uprobe-walkthrough.md)**: the uprobe and
  eBPF backends step by step, what they cost in security, and whether your
  kernel supports them.
- **[Attribute media on an rtpengine relay](rtpengine.md)**: name the calls
  behind streams captured on a relay that carries no SIP.

**Connect sipnab to other tools**

- **[Connect an AI agent to sipnab](mcp-deploy.md)**: every deployment, from
  an agent on the same machine to a remote server running sipnab as a service.
- **[Run MCP across an estate](mcp-estate.md)**: several SIP servers feeding
  one capture host, agents outside the network, and one call followed across
  an SBC, a proxy and a PBX.
- **[Set up authentication](auth.md)**: signed bearer tokens for the API and
  MCP, with lifetimes, key rotation and revocation.
- **[Export a call as a vCon](vcon.md)**: write one observed dialog as a
  conversation container, and what an observer's record lets a consumer
  conclude.
- **[Build a vCon capture stack](vcon-harness.md)**: OpenSIPS, rtpengine,
  sipnab and a conserver on one node or two, and the failures that look like
  success.
- **[Add a vCon server to an OpenSIPS voice stack](vcon-server.md)**:
  vcon-server, Valkey and PostgreSQL, with OpenSIPS recording every call into
  it over SIPREC. No sipnab involved.
- **[Send sipnab's vCons to a vCon server](vcon-sipnab.md)**: a vCon for every
  finished call, forwarded to vcon-server on the same machine or another.
- **[Add TFPS to an OpenSIPS voice stack](tfps.md)**: block attacking SIP
  sources in the kernel before they reach OpenSIPS. No sipnab involved.
- **[Let sipnab see and control TFPS](tfps-sipnab.md)**: what TFPS blocks and
  why, and ban or unban on request, locally or over SSH.
- **[Add rtpengine to an OpenSIPS voice stack](rtpengine-relay.md)**: anchor
  every call's media on an rtpengine relay. No sipnab involved.
- **[Let sipnab name rtpengine's media](rtpengine-sipnab.md)**: tie the media
  on a relay to its call, from the relay's control plane or by asking it.
- **[Add Homer to an OpenSIPS voice stack](homer.md)**: a searchable history
  of every call, sent by OpenSIPS over HEP. No sipnab involved.
- **[Connect sipnab to Homer](homer-sipnab.md)**: sipnab as a second HEP
  receiver beside Homer, or as a source that forwards to it.
- **[Write a WASM plugin](plugins.md)**: add your own detection to sipnab's
  diagnosis without forking it.
- **[Recolor the TUI](theme-guide.md)**: colors and preset palettes.

## Reference

Complete and dry. Consult them rather than reading them through.

- [Glossary](glossary.md): the terms these pages use, one definition each.
- [CLI reference](cli-reference.md): every flag, grouped, with examples.
- [Config reference](config-reference.md): every `[section]` and key.
- [Keybindings](keybindings.md): every TUI key, per view.
- [Output formats](output-formats.md): JSON and NDJSON schemas, pcapng, jq.
- [MOS and codecs](mos-and-codecs.md): where the quality score comes from, and
  which codecs report a placeholder.
- [SIP header fields](sip-header-fields.md): every field in the IANA
  registry, with the nineteen compact forms.
- [SIP request methods](sip-methods.md): every method in the IANA registry and
  the dialog state machine it drives.
- [SIP response codes](sip-response-codes.md): every code in the IANA
  registry, the RFC section defining it, and whether it means the call failed.
- [SIP parameters](sip-parameters.md): every URI parameter, header-field
  parameter and option tag in the IANA registry, and which sipnab parses.
- [SIP conformance rules](sip-lint-rules.md): every linter rule, the RFC
  section behind it, and how to suppress it in CI.
- [REST API](rest-api.md): every endpoint and its response shape, status
  codes, authentication, and curl recipes.
- [Prometheus metrics](prometheus-metrics.md): every metric family, whether
  it is a counter or a gauge, and the scrape config.
- [MCP server](mcp.md): what an agent gets from sipnab, and a first working
  example.
- [MCP tool reference](mcp-tools.md): every tool, its arguments and its
  response.
- [MCP protocol](mcp-protocol.md): the wire contract, security model and error
  semantics.
- [Runnable client examples](client-examples.md): Python clients and their
  regression tests.
- [Library API](library.md): using sipnab as a Rust crate.

## Explanation

Read these when you want to know *why*, not *how*.

- [Architecture](architecture.md): the module layout, data flow, and the
  design decisions that still hold.
- [Fault model](fault-model.md): what sipnab does when things go wrong, and
  what it deliberately does not do.
- [Benchmarks](benchmarks.md): measured throughput and memory, where the
  numbers came from, and how to reproduce them.

## Contributing

Start with the **[Developer index](internals/README.md)**: a reading order
through the domain model, the subsystem walk, the invariants, the test tiers,
the change checklists, and the build, CI and release machinery. The narrower
pages cover [threading](internals/threading.md),
[zero-copy payloads](internals/zero-copy-payloads.md) and
[TUI testing](internals/tui-testing.md).

Supporting the project financially? See [Backers & Sponsors](backers.md).
