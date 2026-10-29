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

This list says what to report. It is not a threat model. The assets, trust
boundaries, mitigations and known gaps are in the security assessment,
[docs/threat-model.md](docs/threat-model.md).

The following are in scope for security reports:

- **Parser crashes** -- malformed SIP/SDP/RTP input causing panics or undefined behavior
- **Key material leakage** -- TLS private keys, SRTP master keys, or credentials
  written to any of these:
  - logs,
  - pcap exports,
  - API responses.
- **Privilege escalation** -- bypassing `--user` privilege drop or `--chroot` isolation
- **Scanner kill amplification** -- `--kill-scanner` logic exploitable for denial of service
- **API authentication bypass** -- accessing `--api`, `--metrics`, or `--mcp`
  (HTTP transport) endpoints without valid credentials. This includes bypass
  of:
  - the bearer-token check,
  - the constant-time comparison,
  - the rate limiter.
- **MCP DNS-rebind / host-header bypass** -- either of these:
  - accepting requests with `Host` headers outside the configured allowlist,
  - any path that lets a client reach the HTTP MCP transport without the
    `--mcp-token` / `--mcp-token-file` guard on a non-loopback bind.
- **HEP ingest** -- any of these:
  - forged or replayed HEP packets accepted by the listener,
  - a `--hep-allow-kill` control accepted from an unauthenticated sender,
  - any path where the HMAC does not cover the field it authorizes.
- **MCP read-only invariant violation** -- any MCP tool that does one of these:
  - sends SIP,
  - mutates dialog/stream/alert state **while not in the capture-control group**,
  - is reachable while its opt-in is off.
  - `open_capture` clears the dialog and stream stores by design. It is in
    scope only if a client can call it when the server has not enabled it.
- **Command injection** -- `--alert-exec`, `--on-dialog-exec`, or `--on-quality-exec` command injection via crafted SIP fields

## Out of Scope

- Denial of service via high packet volume (expected operational concern, not a vulnerability)
- Issues requiring local root access on the capture host
- Bugs in dependencies without a demonstrated exploit path in sipnab

## Supported Versions

Only the latest release is supported with security fixes. There are no LTS branches.

## Legacy Cryptography in Captured Traffic

sipnab parses and decrypts traffic that other systems produced. So it must read
whatever algorithms those systems used:

- MD5 in SIP digest authentication
  ([RFC 3261](https://www.rfc-editor.org/rfc/rfc3261.html)),
- TLS 1.2 CBC suites and RSA key exchange (`--tls-key`),
- HMAC-SHA1 in SRTP `AES_CM_128_HMAC_SHA1_*` suites.

sipnab never selects these for its own protection. Its own endpoints use
rustls (TLS 1.2/1.3, ECDHE, AEAD only).

Captures that rely on these algorithms are weaker than modern alternatives.
Seeing them in a capture is itself a finding worth reporting to the system
operator.

## Secrets and credentials

The workflows use three stored secrets. Each is a GitHub Actions repository
secret. Each one is:

- encrypted by GitHub,
- readable only by the jobs that name it,
- never passed to workflows triggered from a fork,
- visible or changeable only by a repository admin (today, the maintainer
  listed in [MAINTAINERS.md](MAINTAINERS.md)).

| Secret | Used by | What it can do |
|---|---|---|
| `HOMEBREW_TAP_TOKEN` | `release.yml`, the `tap` job | Push the formula bump to the Homebrew tap repository |
| `CODECOV_TOKEN` | `quality.yml`, the coverage upload | Upload coverage reports to Codecov |
| `CLOUDFLARE_API_TOKEN` | `pages.yml`, the `csp` job | Update the site's Content-Security-Policy hashes at Cloudflare |

Each token reaches only the one job and the one service it serves.

The maintainer rotates a token in these cases:

- when anyone who could read it loses access,
- after any suspected exposure,
- at least once a year.

crates.io publishing stores no token at all.

- The `crates-io` job in `release.yml` uses crates.io trusted publishing.
- It exchanges the job's short-lived OpenID Connect identity for an upload
  token.
- crates.io revokes that token when the job ends.

Some accounts must have two-factor authentication turned on:

- every account that can change these secrets,
- every account that can sign in to the services they unlock.

The second factor is an authenticator app or a hardware security key, not
SMS. [MAINTAINERS.md](MAINTAINERS.md#getting-commit-access) states the rule
and how the maintainer checks it.

## Code scanning

`main` carries no open code-scanning alerts.

- CodeQL analyzes every pull request and push.
- The `Code scanning has no open alerts` job in `ci.yml` fails while any alert
  is open.
- The required `CI success` check depends on it. So a change that introduces
  an alert does not merge.
- The maintainer may dismiss an alert that is a false positive or does not
  apply.
- Every dismissal records a reason in GitHub's code-scanning history.

## Accepted advisories in VEX form

[`vex/sipnab.openvex.json`](vex/sipnab.openvex.json) publishes advisories in
OpenVEX form.

- It lists each advisory the dependency scanners report that does not affect
  sipnab, with the reason.
- [`deny.toml`](deny.toml) and [`osv-scanner.toml`](osv-scanner.toml)
  configure the same exceptions with the same reasons.
- A test holds all three to one list.

## Verifying a release

Releases after v0.5.231 attach two files that prove where the release came
from. The `release` job in `release.yml` makes both from its own short-lived
OpenID Connect identity. No signing key is stored anywhere.

| File | What it is |
|---|---|
| `SHA256SUMS.txt.sigstore.json` | A Sigstore signature over `SHA256SUMS.txt`, made without a stored key |
| `sipnab-<version>.intoto.jsonl` | The SLSA build provenance for every artifact, as a Sigstore bundle |

Check the signature with [cosign](https://docs.sigstore.dev/cosign/system_config/installation/),
then check your download against the signed list:

```bash
# Run all of these, in order.
cosign verify-blob SHA256SUMS.txt \
    --bundle SHA256SUMS.txt.sigstore.json \
    --certificate-identity-regexp '^https://github\.com/NormB/sipnab/\.github/workflows/release\.yml@refs/tags/v' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum -c SHA256SUMS.txt --ignore-missing
```

Check the provenance of one artifact against the attached file:

```bash
gh attestation verify "sipnab-$VERSION-x86_64-unknown-linux-gnu.tar.gz" \
    --bundle "sipnab-$VERSION.intoto.jsonl" --repo NormB/sipnab
```

The release job runs both checks before it creates the release, so a release
whose files do not verify is never published.
[docs/install.md](docs/install.md#verify-a-download-is-genuine) has the full
procedure.

## Credit

Reporters who follow responsible disclosure will be credited in the release notes unless they request otherwise.
