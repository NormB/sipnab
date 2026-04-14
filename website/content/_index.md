+++
title = "sipnab"
description = "SIP & RTP capture, analysis, and security. The modern replacement for sngrep + sipgrep, written in Rust."
template = "index.html"
+++

<section class="hero">
  <h1 class="hero-title">sip<span class="accent">nab</span></h1>
  <p class="hero-tagline">SIP & RTP capture, analysis, and security</p>
  <p class="hero-oneliner">The modern replacement for sngrep + sipgrep, written in Rust</p>
  <div class="hero-install">
    <pre><code>cargo install sipnab</code></pre>
  </div>
</section>

<section class="feature-highlights">
  <div class="feature-card">
    <h3>Interactive TUI</h3>
    <p>sngrep-compatible call list with multi-participant ladder diagrams, SDP inspection, RTP stream overlay, message diff, and Mermaid export.</p>
  </div>
  <div class="feature-card">
    <h3>First-Class RTP</h3>
    <p>Per-stream jitter, packet loss, MOS quality estimation, DTMF extraction, and one-way audio detection -- built in, on by default.</p>
  </div>
  <div class="feature-card">
    <h3>Security Analysis</h3>
    <p>Scanner detection and kill, registration flood alerting, digest credential leak detection, toll fraud heuristics, and STIR/SHAKEN validation.</p>
  </div>
</section>

<hr>

<section id="quickstart">

## Quick Start

```bash
# Capture live SIP traffic (opens interactive TUI)
sipnab

# Analyze a pcap file
sipnab -I capture.pcap

# CLI mode with JSON output
sipnab -N --json -I capture.pcap

# Filter specific calls
sipnab --filter "from.user == '1001' AND rtp.mos < 3.0"
```

Without arguments, sipnab opens the interactive TUI and captures on the default
interface. Add `-N` for non-interactive (CLI) mode, `-I` to read pcap files, or
combine both with `--json` for pipeline-friendly NDJSON output.

```bash
# Show only problematic calls (retransmits, timeouts, errors)
sipnab --problems

# Detect SIP scanners
sipnab --kill-scanner

# Export RTP quality metrics to Prometheus
sipnab --metrics 0.0.0.0:9090

# Filter by From/To with regex
sipnab --from alice --to bob

# Write capture to pcap while viewing
sipnab -O output.pcap
```

</section>

<hr>

## Features

<div class="feature-grid">
  <div class="feature-item"><span class="check">&#10003;</span> Zero-copy SIP parser</div>
  <div class="feature-item"><span class="check">&#10003;</span> Dialog state tracking</div>
  <div class="feature-item"><span class="check">&#10003;</span> Filter DSL (24 fields, 7 operators)</div>
  <div class="feature-item"><span class="check">&#10003;</span> TLS 1.2/1.3 decryption</div>
  <div class="feature-item"><span class="check">&#10003;</span> SRTP decryption (SDES)</div>
  <div class="feature-item"><span class="check">&#10003;</span> HEP v2/v3 support</div>
  <div class="feature-item"><span class="check">&#10003;</span> REST API + Prometheus</div>
  <div class="feature-item"><span class="check">&#10003;</span> Configurable theme + keybindings</div>
  <div class="feature-item"><span class="check">&#10003;</span> Multi-leg B2BUA correlation</div>
  <div class="feature-item"><span class="check">&#10003;</span> DTMF extraction (RFC 4733)</div>
  <div class="feature-item"><span class="check">&#10003;</span> RTCP XR (RFC 3611) parsing</div>
  <div class="feature-item"><span class="check">&#10003;</span> Mermaid diagram export</div>
</div>

<hr>

## Architecture

One parser, one dialog engine, one reassembly path. The mode flag only affects output:

- `sipnab` -- interactive TUI (ratatui + crossterm)
- `sipnab -N` -- CLI print mode (sipgrep-like)
- `sipnab -N --json` -- NDJSON streaming for pipelines

Capture threads own their reassembly state with no shared mutables. The main
thread is the sole writer to the dialog and stream stores. Security features
(scanner kill) run in isolated child processes. The API runs in its own process
with no access to capture file descriptors or key material.

<hr>

## Performance

| Metric | Target |
|--------|--------|
| SIP parse throughput | >= 100K pps |
| RTP parse throughput | >= 500K pps |
| 100K dialogs RSS | <= 500 MB |
| 50K streams RSS | <= 200 MB |
| TUI redraw (100K dialogs) | <= 5 ms |
| Idle CPU | < 0.5% core |
| Default binary (musl, stripped) | <= 5 MB |
