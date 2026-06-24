+++
title = "Documentation"
sort_by = "weight"
template = "section.html"
page_template = "page.html"
+++

## What is sipnab?

sipnab is a network analysis tool for Voice over IP. It captures and decodes SIP signaling (the protocol that sets up, modifies, and tears down phone calls) alongside the RTP media streams that carry the actual audio. Whether you are debugging call quality problems, auditing a VoIP platform for security issues, or simply trying to understand what is happening on the wire, sipnab gives you one Rust binary that covers interactive TUI, CLI batch mode, REST API, and browser-based analysis.

## Documentation Overview

- [**Troubleshooting**](@/docs/troubleshooting.md) -- Real-world VoIP diagnostic workflows with exact commands
- [**Install**](@/docs/install.md) -- Build from source, binary downloads, Docker, feature flags
- [**CLI Reference**](@/docs/cli.md) -- Complete flag reference organized by functional group
- [**Filter DSL**](@/docs/filter-dsl.md) -- Query language for filtering calls and streams
- [**Configuration**](@/docs/config.md) -- TOML config file reference with all settings
- [**Keybindings**](@/docs/keybindings.md) -- TUI keyboard shortcuts and navigation
- [**Theme**](@/docs/theme.md) -- Color customization with preset themes
- [**REST API**](@/docs/api.md) -- HTTP API, Prometheus metrics, HEP integration
- [**MCP Server**](@/docs/mcp.md) -- Drive sipnab from an AI agent over stdio or HTTP
- [**Output Formats**](@/docs/output-formats.md) -- NDJSON, summary reports, dialog/stream JSON, and pcap/pcapng
- [**Cookbook**](@/docs/cookbook.md) -- Step-by-step recipes for triage, filtering, HEP wiring, TLS decryption, MCP, observability, security, and audio export
- [**Benchmarks**](@/docs/benchmarks.md) -- Reproducible throughput/memory numbers: multi-core scaling, and honest comparisons vs sngrep and voipmonitor

## Quick Start

```bash
# Analyze a pcap file
sipnab -I capture.pcap

# Live capture on eth0
sudo sipnab -d eth0

# Find problematic calls
sipnab -N -I capture.pcap --problems --json
```
