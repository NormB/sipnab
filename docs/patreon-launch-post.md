# Patreon launch post — sipnab

**Title:** Introducing sipnab — open-source SIP & RTP analysis, now on Patreon

**Suggested images to attach:** docs/screenshots/sipnab-02-message.png (cover),
sipnab-03-rtp-streams.png, sipnab-04-security.png

---

If you've ever stared at a SIP trace at 2am trying to figure out why a call
dropped, went one-way, or sounded terrible — **sipnab** is for you.

**sipnab** is a free, open-source tool that unifies the best of `sngrep` and
`sipgrep` into a single fast Rust binary, with first-class RTP quality
monitoring and security analysis built in:

- 📞 **See every call** — live dialog list, full SIP message ladder, decoded
  headers + SDP
- 🎚️ **RTP quality at a glance** — jitter, packet loss, MOS scoring, one-way
  audio and NAT detection
- 🩺 **Diagnostic shortcuts** — `--problems`, `--one-way`, `--nat-issues`,
  `--short-calls`, codec/ptime/payload asymmetry
- 🛡️ **Security analysis** — scanner detection, registration floods, digest
  leaks, STIR/SHAKEN checks, fraud heuristics
- 🤖 **Four ways to run it** — interactive TUI, scriptable CLI, JSON, and an
  **MCP server** so an AI agent can drive your packet analysis directly

sipnab is and always will be **free and open source** (MIT/Apache-2.0). Your
support funds new features, bug fixes, and ongoing maintenance — and keeps the
project independent.

👉 **Code:** https://github.com/NormB/sipnab
👉 **Support here on Patreon** to help shape the roadmap.

Thank you for being here at the start. 🙏

---

_sipnab is dual-licensed under MIT OR Apache-2.0. Copyright 2024-2026 Norm Brandinger._
