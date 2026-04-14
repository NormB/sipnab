+++
title = "Analyze PCAP"
template = "analyze.html"
description = "Analyze SIP & RTP traffic in your browser. Drag and drop a pcap file — nothing is uploaded."
+++

Analyze pcap files directly in your browser — no upload, no install, no server. Everything runs locally via WebAssembly.

**Drop a `.pcap`, `.pcapng`, or `.cap` file** below to get the same call flow visualization and SIP filtering you get from the CLI. Your capture data never leaves your machine.

### What you get

- **Call list** with sorting and filtering by method, status, caller, callee
- **Call flow ladder diagrams** showing the full SIP transaction sequence
- **Raw SIP message view** for every packet in the dialog
- **Export** to JSON, CSV, or Mermaid diagram format

### When to use this

Quick triage during on-call. Share a link with colleagues who don't have sipnab installed — they drop the same pcap and see the same view. Review captures from a phone or tablet without SSH access to your toolbox.

### Keyboard shortcuts

`h` help | `j`/`k` navigate | `Enter` expand | `f` search/filter | `e` export
