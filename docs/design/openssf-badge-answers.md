# OpenSSF Best Practices Badge — prepared answers (passing level)

The badge is a self-certification questionnaire at
[bestpractices.dev](https://www.bestpractices.dev/). Submission requires signing
in as the project owner, so this page is the prepared answer sheet, not the
submission. Every "Met" below is grounded in a file or a setting in this repo,
cited so a reviewer can check it rather than take it on trust.

This is distinct from the OpenSSF **Scorecard** workflow, which already runs in
CI. Scorecard is an automated scan; the badge is a questionnaire a human answers.
Passing one says nothing about the other.

## Status summary

| Category | Met | Needs a human answer | Genuine gap |
|---|---|---|---|
| Basics | 11 | 0 | 0 |
| Change control | 6 | 0 | 0 |
| Reporting | 3 | 2 | 0 |
| Quality | 6 | 0 | 0 |
| Security | 11 | 0 | 0 |
| Analysis | 2 | 0 | 0 |

No criterion is unmet. Two need an answer only the maintainer can give, and both
are about response history rather than about the code.

## Basics

| Criterion | Answer | Evidence |
|---|---|---|
| `homepage_url` | Met | `https://www.sipnab.com` |
| `description_good` | Met | Site and `README.md` both open with what the tool does |
| `interact` | Met | `SUPPORT.md` routes questions, bugs and vulnerabilities |
| `contribution` | Met | `CONTRIBUTING.md` |
| `floss_license` | Met | MIT OR Apache-2.0, declared in `Cargo.toml` |
| `license_location` | Met | `LICENSE-MIT` and `LICENSE-APACHE` at the repo root |
| `documentation_basics` | Met | Install, usage and security are all published sections |
| `documentation_interface` | Met | CLI reference, REST API and MCP pages document every external surface |
| `sites_https` | Met | Site and repository are HTTPS only |
| `discussion` | Met | GitHub Discussions enabled (`has_discussions: true`) |
| `maintained` | Met | Active release cadence — 30 releases |

`contribution_requirements`, `floss_license_osi` and `english` (all SHOULD) are
met: MIT and Apache-2.0 are both OSI-approved, and everything is in English.

## Change control

| Criterion | Answer | Evidence |
|---|---|---|
| `repo_public` | Met | `https://github.com/NormB/sipnab` |
| `repo_track` | Met | Git |
| `repo_interim` | Met | Work lands on `main` continuously between releases |
| `version_unique` | Met | Crate version, currently 0.5.68 |
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
| `report_responses` | **Maintainer answers** | No issue has ever been filed — 0 issues across all states |
| `vulnerability_report_response` | **Maintainer answers** | No vulnerability report has been received |

The last two ask how quickly reports get answered. With no reports to date there
is no history to cite, and the honest answer is to say so in the justification
field rather than claim a response time the project has never had to meet. The
badge accepts that; inventing a number would be the only wrong move here.

## Quality

| Criterion | Answer | Evidence |
|---|---|---|
| `build` | Met | `cargo build`, reproduced by CI on every push |
| `test` | Met | `cargo test --all-features`, 3149 tests, documented in `CONTRIBUTING.md` |
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

## What is left

Submitting it. That needs the maintainer's own bestpractices.dev session, and
once the project is registered the badge markup goes in `README.md`:

```markdown
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/PROJECT_ID/badge)](https://www.bestpractices.dev/projects/PROJECT_ID)
```

`PROJECT_ID` is assigned at registration, so the line cannot be written before
then — a badge pointing at a guessed ID renders as someone else's project.
