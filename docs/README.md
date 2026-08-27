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
3. **[Drive sipnab from an AI agent](mcp-deploy.md)** — deployment
   scenarios in order, from same-box stdio to a remote production server.
4. **[Reading SIP over TLS without keys](uprobe-walkthrough.md)** — what uprobe
   and eBPF capture is and is **not**, its security implications, whether your
   kernel supports it at all, and both backends step by step.

## How-to guides

Goal-oriented. Each answers "how do I …?" and assumes you already know what
you want.

- **[Cookbook](examples.md)** — recipes for triage, filtering, HEP, TLS
  decryption, MCP, observability, scanner blocking, and audio export, plus a
  quick-reference of one-liners. Includes cross-checking a HEP mirror against
  the wire, where the DISAGREEMENT between the two is the finding.
- **[Drive sipnab from an AI agent](mcp.md)** — expose the analysis as 37
  Model Context Protocol tools over stdio or HTTP, so an agent queries a
  capture directly instead of shelling out and parsing text. What the tools
  return, what stays off unless you enable it, and why none of them write
  back. Deployment is a [tutorial of its own](mcp-deploy.md); the
  [tool reference](mcp-tools.md) is the complete list.
- **[Run MCP across an estate](mcp-estate.md)** — after one sipnab answers one
  agent: several SIP servers feeding one capture host over HEP, reaching it
  from outside the network, one agent holding many hosts, and following a
  single call across an SBC, a proxy and a PBX that each give it a different
  Call-ID.
- **[Troubleshooting](troubleshooting.md)** — symptom → command. Failed calls,
  one-way audio, high loss, NAT issues: what to run and what to look for.
- **[Tuning capture](tuning-capture.md)** — are you dropping packets, and what
  to change when you are. Kernel buffer, BPF, snaplen, driver drops, `--cores`.
- **[Encapsulations](encapsulations.md)** — MPLS, PPPoE, GTP-U or VXLAN wraps
  your SIP and you want to know whether sipnab can read it. What decodes, what
  does not, and what sipnab says when it cannot.
- **[Filter and search](filter-dsl.md)** — narrow to what matters with the
  filter DSL (`method == 'INVITE' and rtp.mos < 3.5`) or the diagnostic
  aliases (`--filter codec-asym`).
- **[Set up authentication](auth.md)** — minting signed bearer tokens, TTLs,
  signing-key rotation, and revocation for the API and MCP.
- **[Capture SIP over TLS](tls-capture.md)** — you have SIP on 5061 and see
  nothing. Picks the method by what access you have: a key log from the
  endpoint, plaintext read out of the process with no keys at all, eBPF
  with peer addresses, or eCapture — and says what does not work, so you
  stop trying it.
- **[Attribute media on an rtpengine relay](rtpengine.md)** — you captured on
  a media relay and every stream came back orphaned. A relay carries no SIP,
  so sipnab reads rtpengine's own control plane to name the calls: what to
  configure, how to verify it, and why a relay's forwarding mode makes no
  difference to what you capture.
- **[Export a call as a vCon](vcon.md)** — something downstream wants the call
  rather than the packets. Write one observed dialog as a vCon container: what
  the export carries, what it refuses to carry, and what an observer's record
  lets a consumer conclude.
- **[Build a vCon capture stack](vcon-harness.md)** — OpenSIPS routes, rtpengine
  carries the media, sipnab watches both, and a conserver keeps what comes out.
  How to stand that up on one node or two, operate it, prove a stored call
  carries its media, and recognize the failures that look like success.
- **[Write a WASM plugin](plugins.md)** — add your own detection to sipnab's
  diagnosis without forking it: what the sandbox does and does not bound,
  what trusting a `.wasm` costs you, and a worked example from crate to
  finding.
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
- [REST API](rest-api.md) — every endpoint and its response shape, status
  codes, authentication, curl recipes.
- [Prometheus Metrics](prometheus-metrics.md) — every metric family sipnab
  emits, what each one means, which are counters and which are gauges, and the
  scrape config. Split from the REST API page: a scrape target's reader needs
  none of the endpoint schemas, and this table sat 86% of the way down a
  1,195-line page.
- [MCP server](mcp.md) — what it is, and a first working example.
- [MCP deployment](mcp-deploy.md) — remote servers, live captures, running it as a service.
- [MCP tool reference](mcp-tools.md) — every tool, its arguments and its response.
- [MCP protocol](mcp-protocol.md) — the wire contract, security model and error semantics.
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
