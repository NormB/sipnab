# sipnab

**sipnab** unifies SIP signaling and RTP media capture, analysis, and security
into one static binary — an interactive TUI, a scriptable CLI, JSON/NDJSON and
report output, a REST API, and an MCP server. One dependency (libpcap).

New here? Follow the path below; each step links to the page with the detail.

## Getting started

1. **[Install sipnab](install.md)** — one-line installer, prebuilt binaries,
   packages, or build from source. Live capture needs root or `CAP_NET_RAW`
   (`sudo sipnab --setup-caps` once); reading a pcap needs no privileges.
2. **First capture** — read a pcap with `sipnab -I capture.pcap`, or watch an
   interface live with `sudo sipnab -d eth0`. Both open the TUI.
3. **[Learn the TUI](keybindings.md)** — browse dialogs, drill into the
   call-flow ladder, mark messages for delta timing, and switch to the RTP
   Streams view; the page covers every view and its keybindings. Recolor it
   with the [Theme Guide](theme-guide.md).
4. **[Filter and search](filter-dsl.md)** — narrow to what matters with the
   filter DSL (`method == 'INVITE' and rtp.mos < 3.5`) or the diagnostic
   aliases (`--filter codec-asym`).
5. **[Automate](cli-reference.md)** — run headless with `-N`, emit `--json` /
   `--report`, and wire results into other tools. Recipes in the
   [Cookbook](examples.md).
6. **Diagnose** — when something's wrong, the [Troubleshooting](troubleshooting.md)
   guide maps symptoms (failed calls, one-way audio, high loss, NAT issues) to
   the exact command and what to look for.

## Reference

- [CLI Reference](cli-reference.md) — every flag, grouped, with examples.
- [Config Reference](config-reference.md) — every `[section]` and key.
- [Filter DSL](filter-dsl.md) — grammar, fields, operators, aliases.
- [Keybindings](keybindings.md) — every TUI key, per view.
- [Output Formats](output-formats.md) — JSON/NDJSON schemas, pcapng, jq.
- [Theme Guide](theme-guide.md) — colors and preset palettes.

## Integrations

- [REST API & Metrics](rest-api.md) — endpoints, Prometheus, client examples.
- [Bearer-token authentication](auth.md) — signed tokens for the API and MCP.
- [MCP server](mcp.md) — expose sipnab as tools to an AI assistant.
- [MCP walkthrough](mcp-walkthrough.md) — step-by-step deployment scenarios,
  from same-box stdio to remote production servers and HEP capture hosts.

## Going deeper

- [Cookbook](examples.md) · [Benchmarks](benchmarks.md) ·
  [Library API](library.md) · [Fault model](fault-model.md)

Contributing to sipnab? Start with the
**[Developer index](internals/README.md)** — a reading order through the
domain model, the subsystem walk, the invariants, the test tiers, the
change checklists, and the build/CI/release machinery, plus the narrower
pages on [threading](internals/threading.md),
[zero-copy payloads](internals/zero-copy-payloads.md) and
[TUI testing](internals/tui-testing.md).
