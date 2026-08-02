# sipnab

**sipnab** unifies SIP signaling and RTP media capture, analysis, and security
into one static binary — an interactive TUI, a scriptable CLI, JSON/NDJSON and
report output, a REST API, and an MCP server. One dependency (libpcap).

This tree groups documentation by what you are trying to do, following
[Diátaxis](https://diataxis.fr/). The four groups answer four different
questions, and mixing them is what makes docs hard to use:

| If you are… | you want | start at |
|---|---|---|
| new to sipnab | a guided first run | [Tutorials](#tutorials) |
| trying to get something done | steps for your goal | [How-to guides](#how-to-guides) |
| looking something up | exact, complete facts | [Reference](#reference) |
| trying to understand it | why it works this way | [Explanation](#explanation) |

## Tutorials

Learning-oriented. Follow these in order on your first day. They assume
nothing and they tell you what you should see at each step.

1. **[Install sipnab](install.md)** — one-line installer, prebuilt binaries,
   packages, or build from source. Live capture needs root or `CAP_NET_RAW`
   (`sudo sipnab --setup-caps` once); reading a pcap needs no privileges.
2. **[Your first capture](tui-walkthrough.md)** — read a pcap with
   `sipnab -I capture.pcap`, or watch an interface live with
   `sudo sipnab -d eth0`. Both open the TUI; the walkthrough takes you through
   your first analysis step by step.
3. **[Drive sipnab from an AI agent](mcp-walkthrough.md)** — deployment
   scenarios in order, from same-box stdio to a remote production server.

## How-to guides

Goal-oriented. Each answers "how do I …?" and assumes you already know what
you want.

- **[Cookbook](examples.md)** — recipes for triage, filtering, HEP, TLS
  decryption, MCP, observability, scanner blocking, and audio export, plus a
  quick-reference of one-liners.
- **[Troubleshooting](troubleshooting.md)** — symptom → command. Failed calls,
  one-way audio, high loss, NAT issues: what to run and what to look for.
- **[Filter and search](filter-dsl.md)** — narrow to what matters with the
  filter DSL (`method == 'INVITE' and rtp.mos < 3.5`) or the diagnostic
  aliases (`--filter codec-asym`).
- **[Set up authentication](auth.md)** — minting signed bearer tokens, TTLs,
  signing-key rotation, and revocation for the API and MCP.
- **[Recolor the TUI](theme-guide.md)** — colors and preset palettes.

## Reference

Information-oriented. Complete and dry. Consult them, do not read them
through.

- [CLI Reference](cli-reference.md) — every flag, grouped, with examples.
- [Config Reference](config-reference.md) — every `[section]` and key.
- [Filter DSL](filter-dsl.md) — grammar, fields, operators, aliases.
- [Keybindings](keybindings.md) — every TUI key, per view.
- [MOS and codecs](mos-and-codecs.md) — where the quality score comes from,
  which codecs have a published basis, and which report a placeholder.
- [Output Formats](output-formats.md) — JSON/NDJSON schemas, pcapng, jq.
- [SIP header fields](sip-header-fields.md) — every field in the IANA
  registry, with the nineteen compact forms.
- [SIP request methods](sip-methods.md) — every method in the IANA registry
  and the dialog state machine it drives.
- [SIP response codes](sip-response-codes.md) — every code in the IANA
  registry, the RFC section defining it, and whether it means the call failed.
- [SIP parameters](sip-parameters.md) — every URI parameter, header-field
  parameter and option tag in the IANA registry, and which sipnab parses.
- [SIP conformance rules](sip-lint-rules.md) — every linter rule, the RFC
  section behind it, and how to suppress it in CI.
- [REST API & Metrics](rest-api.md) — every endpoint and its response shape,
  status codes, Prometheus, curl recipes.
- [MCP server](mcp.md) — every tool, both transports, client configuration.
- [Library API](library.md) — using sipnab as a Rust crate.

## Explanation

Understanding-oriented. Read these when you want to know *why*, not *how*.

- [Architecture](architecture.md) — the codemap: module layout, data flow, and
  the design decisions that still hold.
- [Fault model](fault-model.md) — what sipnab does when things go wrong, and
  what it deliberately does not do.
- [Benchmarks](benchmarks.md) — measured throughput and memory, where the
  numbers came from, and how to reproduce them.

## Contributing

Start with the **[Developer index](internals/README.md)** — a reading order
through the domain model, the subsystem walk, the invariants, the test tiers,
the change checklists, and the build/CI/release machinery. The one-screen map
of the tree is [Architecture](architecture.md). The narrower pages cover
[threading](internals/threading.md),
[zero-copy payloads](internals/zero-copy-payloads.md) and
[TUI testing](internals/tui-testing.md).

Supporting the project financially? See [Backers & Sponsors](backers.md).
