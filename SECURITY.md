# Security Policy

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Email **security@sipnab.com** with:

- Description of the vulnerability
- Steps to reproduce or proof of concept
- Impact assessment (what an attacker could achieve)
- Your name/handle for credit (optional)

Use the subject line: `[SECURITY] <brief description>`

## Response Timeline

| Stage | Target |
|-------|--------|
| Acknowledgment | 48 hours |
| Initial assessment | 7 days |
| Fix for critical issues | 30 days |
| Public disclosure | After fix is released |

## Scope

The following are in scope for security reports:

- **Parser crashes** -- malformed SIP/SDP/RTP input causing panics or undefined behavior
- **Key material leakage** -- TLS private keys, SRTP master keys, or credentials written to logs, pcap exports, or API responses
- **Privilege escalation** -- bypassing `--user` privilege drop or `--chroot` isolation
- **Scanner kill amplification** -- `--kill-scanner` logic exploitable for denial of service
- **API authentication bypass** -- accessing `--api`, `--metrics`, or `--mcp` (HTTP transport) endpoints without valid credentials, including bypass of the bearer-token check, the constant-time comparison, or the rate limiter
- **MCP DNS-rebind / host-header bypass** -- accepting requests with `Host` headers outside the configured allowlist, or any path that lets the HTTP MCP transport be reached without the `--mcp-token` / `--mcp-token-file` guard on a non-loopback bind
- **MCP read-only invariant violation** -- any MCP tool that mutates dialog/stream/alert state, sends SIP, or otherwise breaks the read-only design of the v0.4 tool surface
- **Command injection** -- `--alert-exec`, `--on-dialog-exec`, or `--on-quality-exec` command injection via crafted SIP fields

## Out of Scope

- Denial of service via high packet volume (expected operational concern, not a vulnerability)
- Issues requiring local root access on the capture host
- Bugs in dependencies without a demonstrated exploit path in sipnab

## Supported Versions

Only the latest release is supported with security fixes. There are no LTS branches.

## Credit

Reporters who follow responsible disclosure will be credited in the release notes unless they request otherwise.
