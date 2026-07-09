+++
title = "Documentation"
sort_by = "weight"
template = "section.html"
page_template = "page.html"

[extra]
# Task cards rendered by section.html above the reference index: intent-titled
# entry points for people who arrive with a problem, not a topic.
tasks = [
  { title = "Analyze a pcap file", cmd = "sipnab -I capture.pcap", href = "/docs/cookbook/" },
  { title = "Capture live SIP traffic", cmd = "sudo sipnab -d eth0", href = "/docs/cli/" },
  { title = "Diagnose one-way audio", cmd = "sipnab -I dump.pcap --one-way", href = "/docs/troubleshooting/" },
  { title = "Find failed calls", cmd = "sipnab -N -I dump.pcap --problems", href = "/docs/troubleshooting/" },
  { title = "Set up a HEP capture server", cmd = "sipnab --hep-listen 0.0.0.0:9060", href = "/docs/cookbook/" },
  { title = "Decrypt TLS / SRTP", cmd = "sipnab -I tls.pcap --keylog keys.log", href = "/docs/cookbook/" },
  { title = "Detect scanners & fraud", cmd = "sudo sipnab -N -d eth0 --fraud-detect", href = "/docs/cookbook/" },
  { title = "Drive sipnab from an AI agent", cmd = "sipnab --mcp", href = "/docs/mcp/" },
]
+++

## What is sipnab?

sipnab is a network analysis tool for Voice over IP. It captures and decodes SIP signaling (the protocol that sets up, modifies, and tears down phone calls) alongside the RTP media streams that carry the actual audio. Whether you are debugging call quality problems, auditing a VoIP platform for security issues, or simply trying to understand what is happening on the wire, sipnab gives you one Rust binary that covers interactive TUI, CLI batch mode, REST API, and browser-based analysis.

## Quick Start

```bash
# Analyze a pcap file
sipnab -I capture.pcap

# Live capture on eth0
sudo sipnab -d eth0

# Find problematic calls
sipnab -N -I capture.pcap --problems --json
```
