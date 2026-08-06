# OpenSSF Best Practices Badge — prepared answers (passing level)

**Status: registered and passing.** Project
[13931](https://www.bestpractices.dev/projects/13931) — the badge is live in
`README.md` and linked from the sipnab.com home page.

The badge is a self-certification questionnaire at
[bestpractices.dev](https://www.bestpractices.dev/). Submission requires signing
in as the project owner, so this page was the prepared answer sheet used for
that submission, not the submission form itself. Every "Met" below is grounded
in a file or a setting in this repo, cited so a reviewer can check it rather
than take it on trust.

This is distinct from the OpenSSF **Scorecard** workflow, which already runs in
CI. Scorecard is an automated scan; the badge is a questionnaire a human answers.
Passing one says nothing about the other.

## Status summary

| Category | Met | Needs a human answer | Genuine gap |
|---|---|---|---|
| Basics | 11 | 0 | 0 |
| Change control | 6 | 0 | 0 |
| Reporting | 5 | 0 | 0 |
| Quality | 6 | 0 | 0 |
| Security | 11 | 0 | 0 |
| Analysis | 2 | 0 | 0 |

No criterion is unmet.

## Basics

| Criterion | Answer | Evidence |
|---|---|---|
| `homepage_url` | Met | `https://sipnab.com` |
| `description_good` | Met | Site and `README.md` both open with what the tool does |
| `interact` | Met | `SUPPORT.md` routes questions, bugs and vulnerabilities |
| `contribution` | Met | `CONTRIBUTING.md` |
| `floss_license` | Met | MIT OR Apache-2.0, declared in `Cargo.toml` |
| `license_location` | Met | `LICENSE-MIT` and `LICENSE-APACHE` at the repo root |
| `documentation_basics` | Met | Install, usage and security are all published sections |
| `documentation_interface` | Met | CLI reference, REST API and MCP pages document every external surface |
| `sites_https` | Met | Site and repository are HTTPS only |
| `discussion` | Met | GitHub Discussions enabled (`has_discussions: true`) |
| `maintained` | Met | Active release cadence — 98 releases |

`contribution_requirements`, `floss_license_osi` and `english` (all SHOULD) are
met: MIT and Apache-2.0 are both OSI-approved, and everything is in English.

## Change control

| Criterion | Answer | Evidence |
|---|---|---|
| `repo_public` | Met | `https://github.com/NormB/sipnab` |
| `repo_track` | Met | Git |
| `repo_interim` | Met | Work lands on `main` continuously between releases |
| `version_unique` | Met | Crate version, currently 0.5.83 |
| `release_notes` | Met | `CHANGELOG.md`, Keep a Changelog format |
| `release_notes_vulns` | Met | The changelog calls out security-relevant fixes in the entry carrying them |

The three SUGGESTED items are also met: git is distributed, versioning is
semantic, and every release is tagged.

## Reporting

| Criterion | Answer | Evidence |
|---|---|---|
| `report_process` | Met | `.github/ISSUE_TEMPLATE/` with bug and feature templates |
| `report_archive` | Met | The GitHub issue tracker is public and searchable |
| `vulnerability_report_process` | Met | `SECURITY.md` |
| `vulnerability_report_private` | Met | Private advisories, linked from `ISSUE_TEMPLATE/config.yml` |
| `report_responses` | Met | Issues #226-229 were each triaged and closed the same day they were opened |
| `vulnerability_report_response` | Met | `SECURITY.md` defines the private channel; no external report received to date, and internally-found issues (e.g. #226) are fixed and disclosed in the changelog |

The last two ask how quickly reports get answered. When this sheet was first
drafted no issue had ever been filed, and the honest answer was to say so
rather than claim a response time the project had never had to meet. By the
time of registration four issues (#226-229) had been filed and each closed the
same day, which is now the cited evidence.

## Quality

| Criterion | Answer | Evidence |
|---|---|---|
| `build` | Met | `cargo build`, reproduced by CI on every push |
| `test` | Met | `cargo test --all-features`, ~4,600 tests, documented in `CONTRIBUTING.md` |
| `test_policy` | Met | `CONTRIBUTING.md` pull request step 4: "Add or update tests for new functionality" |
| `tests_are_added` | Met | Recent history shows tests landing with the change, not after |
| `warnings` | Met | `cargo clippy --all-features --all-targets -- -D warnings` |
| `warnings_fixed` | Met | That gate is deny-on-warning, so a warning cannot merge |

`build_floss_tools` is met — Rust, Cargo and the CI toolchain are all FLOSS.
Of the SUGGESTED items, continuous integration, standard invocation and
documented test requirements are all met.

## Security

| Criterion | Answer | Evidence |
|---|---|---|
| `know_secure_design` | Met | Privilege drop, chroot, and an explicitly documented threat model in `SECURITY.md` |
| `know_common_errors` | Met | The in-scope list names parser crashes, key-material leakage, privilege-drop escapes, authentication bypass and command injection |
| `crypto_published` | Met | TLS through `rustls`, no bespoke protocol |
| `crypto_floss` | Met | `rustls`, `ring`, `aes`, `hmac`, `sha2` |
| `crypto_keylength` | Met | Defaults come from `rustls` |
| `crypto_working` | Met | Broken algorithms appear only where reading existing captures requires it |
| `crypto_random` | Met | Supplied by `ring` |
| `crypto_call` | Met | No reimplemented primitives — every one is a vetted crate |
| `delivery_mitm` | Met | Releases over HTTPS from GitHub |
| `delivery_unsigned` | Met | No hash is ever fetched over plain HTTP |
| `vulnerabilities_fixed_60_days` | Met | `cargo audit` and `cargo deny` run in CI; Dependabot is configured |
| `no_leaked_credentials` | Met | No credentials in the repository |

A note for the crypto answers: sipnab **decrypts** SIP and RTP that other systems
encrypted, so it necessarily reads key material and must interoperate with
whatever the capture used. That is why "broken algorithms" can appear at all —
the badge's intent is that a project not *choose* weak crypto for its own
protection, and sipnab does not.

## Analysis

| Criterion | Answer | Evidence |
|---|---|---|
| `static_analysis` | Met | Clippy on every push, plus CodeQL Advanced |
| `static_analysis_fixed` | Met | Both gate the merge, so findings block rather than accumulate |

The SUGGESTED dynamic-analysis items are met beyond what the level asks:
15 fuzz targets under `fuzz/fuzz_targets/` — `sip_parser`, `sdp_parser`,
`rtp_parser`, `rtcp_parser`, `hep_parser`, `dtls`, `tls_records`, `srtp_keys`,
`stir_shaken`, `siprec`, `tcp_reassembly`, `websocket_frame`, `pcap_reader`,
`keylog_line` and `filter_dsl` — with `fuzz-check` keeping them compiling in CI
and `tests/smoke_fuzz_test.rs` running a no-nightly smoke tier.

Every one of those targets sits on an attack surface that eats
attacker-controlled bytes, which is the reason the coverage is this wide.

`dynamic_analysis_unsafe` asks for memory-safety tooling in memory-unsafe
languages. Safe Rust makes this N/A in the badge's terms, though the fuzz
targets cover the same ground.

## Done

Registered and submitted at project
[13931](https://www.bestpractices.dev/projects/13931), reading **passing**.
The badge markup is live in `README.md`:

```markdown
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13931/badge)](https://www.bestpractices.dev/projects/13931)
```

and linked (as a CSP-safe inline pill rather than the badge image, since the
site's `img-src 'self'` policy blocks an externally-hosted SVG) from the
sipnab.com home page.
