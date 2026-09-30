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
- **HEP ingest** -- forged or replayed HEP packets accepted by the listener, a `--hep-allow-kill` control accepted from an unauthenticated sender, or any path where the HMAC does not cover the field it is used to authorize
- **MCP read-only invariant violation** -- any MCP tool that sends SIP, or that mutates dialog/stream/alert state **while not in the capture-control group**, or that is reachable while its opt-in is off. `open_capture` clears the dialog and stream stores by design; it is in scope only if it can be called without being enabled server-side
- **Command injection** -- `--alert-exec`, `--on-dialog-exec`, or `--on-quality-exec` command injection via crafted SIP fields

## Out of Scope

- Denial of service via high packet volume (expected operational concern, not a vulnerability)
- Issues requiring local root access on the capture host
- Bugs in dependencies without a demonstrated exploit path in sipnab

## Supported Versions

Only the latest release is supported with security fixes. There are no LTS branches.

## Legacy Cryptography in Captured Traffic

sipnab parses and decrypts traffic that other systems produced, so it must read
whatever algorithms those systems used: MD5 in SIP digest authentication
([RFC 3261](https://www.rfc-editor.org/rfc/rfc3261)), TLS 1.2 CBC suites and RSA key exchange (`--tls-key`), and
HMAC-SHA1 in SRTP `AES_CM_128_HMAC_SHA1_*` suites. sipnab never selects these
for its own protection; its own endpoints use rustls (TLS 1.2/1.3, ECDHE,
AEAD only). Captures that rely on these algorithms are weaker than modern
alternatives, and seeing them in a capture is itself a finding worth
reporting to the system operator.

## Credit

Reporters who follow responsible disclosure will be credited in the release notes unless they request otherwise.
