# Sipnab codebase and documentation improvement review

**Review date:** 2026-08-16  
**Reviewed version:** 0.5.101  
**Scope:** user documentation, examples, Rust implementation, operations, usage,
and developer documentation  
**Purpose:** a single, implementation-ready backlog for maintainers

**Adversarial review:** completed 2026-08-16. The adversarial pass challenged
severity, reproducibility, counter-evidence, portability, and whether each proposed
test could actually falsify the claim. Its corrections are incorporated below and
summarized in [Adversarial analysis](#adversarial-analysis).

## Executive summary

Sipnab has unusually strong documentation breadth and automated drift protection.
Its best practices are worth preserving: task-oriented navigation, source-to-site
generation, link and CLI drift tests, synthetic packet fixtures, extensive parser
fuzzing, explicit security boundaries, and detailed internal architecture guides.

The review nevertheless found four items that should be handled before relying on
the affected surfaces in production:

1. The packaged systemd service is unable to start successfully as shipped.
2. The published Docker live-capture command does not grant the non-root image the
   capabilities needed to capture.
3. Saving TUI columns or manual names can replace an existing configuration after
   a read error, potentially erasing unrelated settings.
4. `KeylogSource::from_fd` can change the caller's file descriptor to nonblocking
   despite promising not to do so.

The highest-value documentation work is to make the first-run path reproducible,
correct contradictory packaging claims, repair the MCP task card, and turn core
recipes into executable documentation. The highest-value structural work is to
bring all workspace crates under the lint gate and incrementally split several
5,000–11,000-line modules.

## Priority and effort scale

| Label | Meaning |
|---|---|
| P0 | Shipped package/runtime path that cannot work, or an immediate security/data-integrity blocker |
| P1 | Correctness, security, or major first-run/support gap |
| P2 | Reliability, maintainability, or meaningful clarity gap |
| P3 | Preventive improvement or lower-urgency cleanup |
| XS / S / M / L / XL | Less than a day / days / about a week / multiple weeks / program of work |

“Verified” means the current source or a command directly demonstrates the issue.
“Suggestion” means the current behavior is valid but has a material improvement
opportunity. Line references identify the reviewed revision and may move later.

## Adversarial analysis

This section treats the review itself as potentially wrong. It asks what a
skeptical maintainer would need to disprove each major claim, identifies where
static inspection is insufficient, and prevents recommendations from quietly
expanding beyond their evidence.

### Findings that survived direct challenge

| Claim | Strongest counterargument considered | Result and falsification test |
|---|---|---|
| OPS-01: packaged service is broken | `/usr/local/bin` could be intentional because the standalone installer uses it, and `%i` could be supplied by systemd. | Rejected. Both native package builders install `/usr/bin/sipnab` and install this same unit. Its filename is `sipnab.service`, not `sipnab@.service`, so it has no instance identifier. It also requests unauthenticated non-loopback listeners that code rejects. Falsify by installing each built package in a clean VM and showing `systemctl start sipnab` reaches active state without modifying the unit. |
| CODE-01: config persistence can erase content | Atomic rename might preserve the old file on read failure. | Rejected. The failure is converted to an empty string *before* the atomic writer is called, so atomicity safely commits the wrong replacement. Falsify with invalid UTF-8 or a deterministic read error and show the function returns `Err` while original bytes remain unchanged. |
| CODE-02: `dup` isolates `O_NONBLOCK` | The duplicate has a distinct descriptor number and is exclusively owned. | Rejected. Descriptor numbers are distinct, but `F_SETFL` modifies status flags on the shared open-file description. Falsify on Unix by checking `F_GETFL` on the original descriptor before and after `from_fd`. |
| CODE-03: CI misses a workspace crate | `--all-targets --all-features` sounds workspace-wide. | Rejected. From a package root those switches cover that package's targets/features, not every workspace package. The workspace-wide command reproducibly reaches the plugin example and reports its lint. Falsify by making the plugin example contain a denied lint and proving the current CI command fails on it. |
| DEV-01: developer test count is stale | “Fifty” might mean a curated subset rather than files. | Rejected. The page calls them integration-test binaries and Cargo treats top-level `tests/*.rs` files as integration-test targets; 132 were present in the reviewed tree. Falsify by documenting the excluded categories that make exactly fifty meaningful. |

### Claims retained with reduced confidence or narrower scope

| Item | Adversarial correction |
|---|---|
| DOC-01 | The command definitely fails validation without `-N`, but a broken task card is not equivalent to a broken shipped runtime. It is P1, not P0. A smoke test must also decide whether a source is required for the intended long-running MCP mode rather than assuming `-I` is universally correct. |
| DOC-04 | The MCP walkthrough openly labels old transcripts illustrative, which reduces deception risk. The problem is navigation and maintenance cost, not proof that protocol instructions are wrong; priority is P2 unless a current client procedure is reproduced as broken. |
| OPS-02 | Static evidence proves the image runs unprivileged and the recipe grants no capabilities. It does not prove the exact minimal capability set on every host/libpcap configuration. Treat `NET_RAW`/`NET_ADMIN` as hypotheses to measure, not cargo-cult flags. |
| OPS-03 | Dependency and tracing language is contradictory, but this is an operational-documentation defect, not a demonstrated runtime failure. Correct the text first; implementing tracing is an optional product decision. |
| OPS-04 | An unconditional liveness endpoint is valid if it is only promised as liveness. Readiness is a capability gap, not a defective `/health`; do not change `/health` semantics and break existing probes. |
| OPS-05 | Blanket symlink rejection can break Kubernetes projected secrets and other managed-secret layouts. The requirement is race-resistant resolution plus a documented trust policy. Validate the opened object with platform-appropriate APIs; allow explicitly supported managed-secret patterns or provide a compatibility mode. |
| CODE-04 | The concurrency cap is intentional fail-safe behavior and drops are visible. The verified weakness is lack of a deadline and descendant cleanup, not an unbounded fork bomb. Any timeout must avoid killing legitimate slow hooks and must manage process groups rather than only the shell PID. |
| CODE-06 | File length is a risk indicator, not proof of poor design. Extract only along cohesive ownership boundaries and require measured improvement in review/build/test isolation; do not impose an arbitrary line limit. |

### Important limitations

- The DEB and RPM artifacts were inspected but not installed under systemd in a
  clean VM. OPS-01 has three independent static failure mechanisms, but its final
  acceptance test remains the authoritative proof.
- Container live capture was not executed with alternate runtimes, rootless mode,
  seccomp profiles, or different host libpcap/kernel combinations. OPS-02 must
  discover the minimal capability/device configuration experimentally.
- No production traffic, hostile Wasm module, hung real-world alert hook, or
  credential manager was exercised. Resource and secret recommendations therefore
  require negative tests and compatibility tests before enforcement ships.
- Line counts and exact paths describe version 0.5.101; implementation should
  re-resolve symbols before opening issues or patches.
- Passing drift tests establishes internal consistency for their enumerated
  subjects, not behavioral correctness of every published command.

### Decision rules applied after challenge

1. A static mismatch is called “verified” only when code execution semantics are
   unambiguous; otherwise the report names the runtime experiment still required.
2. New behavior must preserve a compatibility contract or explicitly version the
   break. This especially applies to metrics, health endpoints, secret paths, and
   service files.
3. Acceptance tests must include a negative case and must observe the externally
   relevant result, not merely successful compilation or artifact construction.
4. Documentation-only corrections should ship before optional large feature work
   when they immediately stop misleading operators.
5. This review is an intake document, not a competing permanent backlog. GOV-01
   defines how accepted work moves into the canonical backlog.

## Recommended delivery order

| Wave | Work | Exit condition |
|---|---|---|
| 1 — stop breakage | OPS-01, OPS-02, CODE-01, CODE-02, CODE-03, DOC-01, GOV-01 | Packages, documented container capture, config persistence, FD behavior, workspace lint, and MCP entry point are correct and accepted work is reconciled with the canonical backlog. |
| 2 — secure operation | OPS-04, OPS-05, OPS-06, OPS-08, CODE-04, CODE-05 | Health distinguishes readiness; secret files and service identities are hardened; hooks and plugins have pre-execution resource bounds. |
| 3 — make success reproducible | DOC-02, DOC-03, DOC-04, DOC-06, DEV-01, DEV-02 | A new user and contributor can follow tested paths with precise packaging language and current inventories. |
| 4 — unify and simplify | OPS-03, OPS-07, OPS-09, DOC-05, DOC-07, CODE-06, CODE-07, DEV-03 | Operations contracts are coherent, compatibility/design status is explicit, and high-churn modules become easier to review. |

## Combined implementation backlog

### Documentation clarity and examples

#### DOC-01 — Fix the non-working MCP task-card command

**Priority / type / effort:** P1 / verified documentation defect / S

**Evidence:** [`website/content/docs/_index.md:18`](https://github.com/NormB/sipnab/blob/main/website/content/docs/_index.md#L18) advertises `sipnab --mcp`.
The canonical reference requires headless mode and demonstrates `--mcp -N`
([`docs/mcp.md:34-41`](https://github.com/NormB/sipnab/blob/main/docs/mcp.md#L34-L41)); the walkthrough explicitly says `--mcp` requires `-N`
([`docs/mcp-deploy.md:93-96`](https://github.com/NormB/sipnab/blob/main/docs/mcp-deploy.md#L93-L96)).

**Impact:** the prominent entry-point command fails instead of starting the
workflow it advertises.

**Recommendation:** replace it with a complete command such as
`sipnab -N --mcp -I capture.pcap`, or clearly label an incomplete skeleton.
First decide whether the card promises offline analysis or a persistent live
server; do not add `-I` merely to make parsing succeed if it changes that intent.
Extend the site journey tests to parse or smoke-test commands in hand-maintained
task cards, which the generated-page mirror gate does not cover.

**Acceptance criteria:**

- Every task-card command parses and starts the described mode in the appropriate
  feature build.
- The MCP card supplies both a capture source and `-N`.
- CI fails when a task-card command loses a required flag.

#### DOC-02 — Make the beginner tutorial self-contained and deterministic

**Priority / type / effort:** P1 / verified journey gap / M

**Evidence:** [`docs/README.md:20-29`](https://github.com/NormB/sipnab/blob/main/docs/README.md#L20-L29) promises tutorials that assume nothing and
state what to expect. [`docs/tui-walkthrough.md:11-24`](https://github.com/NormB/sipnab/blob/main/docs/tui-walkthrough.md#L11-L24) instead begins with an
unspecified `capture.pcap` or privileged live capture. The cookbook repeats the
placeholder and approximate output ([`docs/examples.md:47-89`](https://github.com/NormB/sipnab/blob/main/docs/examples.md#L47-L89)). A redistributable
fixture already exists at [`website/static/demos/sample-call.pcap`](https://github.com/NormB/sipnab/raw/main/website/static/demos/sample-call.pcap).

**Impact:** a first-time user cannot reproduce the tutorial without bringing
capture expertise, root access, or private data.

**Recommendation:** begin the CLI and TUI paths with downloading or locating the
official sample, including its size/checksum, then give exact stable observations
and keys. Use the same fixture in journey tests.

**Acceptance criteria:**

- A clean machine can complete install plus tutorial without root or a live network.
- The fixture opens and its expected calls, streams, and key transitions are tested.
- Sample acquisition works for both release-package and source-tree readers.

#### DOC-03 — Replace contradictory “one static binary” positioning

**Priority / type / effort:** P1 / verified clarity defect / S

**Evidence:** [`README.md:12`](https://github.com/NormB/sipnab/blob/main/README.md#L12) says “One static binary,” while [`README.md:51-57`](https://github.com/NormB/sipnab/blob/main/README.md#L51-L57)
documents dynamic libpcap and [`README.md:62-70`](https://github.com/NormB/sipnab/blob/main/README.md#L62-L70) a separate audio shared object.
[`docs/install.md:3`](https://github.com/NormB/sipnab/blob/main/docs/install.md#L3) says “one static binary with one runtime dependency,” while
[`docs/install.md:67-76`](https://github.com/NormB/sipnab/blob/main/docs/install.md#L67-L76) correctly distinguishes GNU and musl artifacts.
[`website/content/docs/_index.md:29-31`](https://github.com/NormB/sipnab/blob/main/website/content/docs/_index.md#L29-L31) similarly implies one binary and no runtime.

**Impact:** users can choose an incompatible artifact or deploy without required
libraries/plugins.

**Recommendation:** standardize on precise wording: one executable; the musl
Linux release is static; GNU Linux and macOS packages have stated runtime
requirements; audio is an optional plugin. Distinguish “no daemon/database” from
“no runtime dependency.”

**Acceptance criteria:** README, install guide, site pages, and artifact matrix use
the same terminology. A prose regression test rejects an unqualified “one static
binary” outside a musl-specific context.

#### DOC-04 — Split and refresh the MCP learning path

**Priority / type / effort:** P2 / verified usability and freshness gap / L

**Evidence:** [`docs/mcp-deploy.md`](https://github.com/NormB/sipnab/blob/main/docs/mcp-deploy.md) is 1,868 lines and [`docs/mcp.md`](https://github.com/NormB/sipnab/blob/main/docs/mcp.md) is 3,301
lines. The walkthrough warns that most transcripts were last run at 0.5.20 and
are illustrative ([`docs/mcp-deploy.md:10-18`](https://github.com/NormB/sipnab/blob/main/docs/mcp-deploy.md#L10-L18)), yet the docs index presents
it as a first-day tutorial ([`docs/README.md:30-31`](https://github.com/NormB/sipnab/blob/main/docs/README.md#L30-L31)).

**Impact:** beginners encounter a large, partly stale reference instead of a
short successful path; experienced operators cannot quickly find topology and
deployment material.

**Recommendation:** extract a 10–15 minute “first MCP analysis” tutorial. Move
client registration, deployment topology, federation, and diagnosis into focused
how-to pages; generate schema/tool reference where practical; execute core
transcripts in CI.

**Acceptance criteria:** the beginner path is roughly 200 lines or fewer, uses one
supported client and one fixture, and has exact initialize/tool-list expectations.
Every shell/config snippet is tested or labeled with its tested version/status.

#### DOC-05 — Publish an explicit sngrep/sipgrep compatibility matrix

**Priority / type / effort:** P2 / claim-clarity improvement / M

**Evidence:** `README.md:18-20,160` claims every sngrep keybinding and acceptance
of sipgrep flags. [`docs/keybindings.md:1-24`](https://github.com/NormB/sipnab/blob/main/docs/keybindings.md#L1-L24) documents Sipnab's mappings rather
than an upstream comparison, and CLI reference sections only label individual
compatible flags (`docs/cli-reference.md:224-231,476`). The `-N` collision is
notable ([`docs/cli-reference.md:576`](https://github.com/NormB/sipnab/blob/main/docs/cli-reference.md#L576)).

**Impact:** migration expectations are ambiguous and semantic differences can
cause incorrect automation or operator muscle memory.

**Recommendation:** provide a table of upstream key/flag, Sipnab equivalent,
semantic differences, and unsupported/reserved cases. Generate or test mappings
from CLI and TUI action definitions where practical; avoid absolute claims.

**Acceptance criteria:** no unqualified “every/all” remains; the matrix covers all
claimed compatibility and pins collisions/differences in tests.

#### DOC-06 — Turn core recipes into executable documentation

**Priority / type / effort:** P2 / test-coverage improvement / M–L

**Evidence:** [`docs/examples.md:47-180`](https://github.com/NormB/sipnab/blob/main/docs/examples.md#L47-L180) relies on arbitrary capture content and
[`docs/examples.md:83-89`](https://github.com/NormB/sipnab/blob/main/docs/examples.md#L83-L89) gives hypothetical output. Existing drift tests validate
flags and generated mirrors, but not most command outcomes
([`tests/docs_drift_test.rs`](https://github.com/NormB/sipnab/blob/main/tests/docs_drift_test.rs); [`tests/dev_docs_drift_test.rs:1627-1671`](https://github.com/NormB/sipnab/blob/main/tests/dev_docs_drift_test.rs#L1627-L1671)).

**Impact:** syntactically valid examples can still regress semantically.

**Recommendation:** tag a small supported recipe set—triage, failed-call `jq`,
call report, audio, and MCP—and execute the exact snippets against committed
synthetic fixtures. Normalize volatile fields and compare goldens or schemas.

**Acceptance criteria:** CI runs the displayed commands, checks exit status and
key output facts/schema, and keeps generated site copies byte-identical.

#### DOC-07 — Separate active design guidance from archives

**Priority / type / effort:** P3 / information-architecture improvement / M

**Evidence:** [`README.md:228`](https://github.com/NormB/sipnab/blob/main/README.md#L228) calls `implementation-plan-v6` a roadmap, while
[`docs/design/implementation-plan-v6.md:9-34`](https://github.com/NormB/sipnab/blob/main/docs/design/implementation-plan-v6.md#L9-L34) says it is superseded and historical.
[`docs/design/implementation-plan-phases-8-10.md:12-28`](https://github.com/NormB/sipnab/blob/main/docs/design/implementation-plan-phases-8-10.md#L12-L28) carries similar warnings.

**Impact:** unchecked historical plan items can be mistaken for current work.

**Recommendation:** add `docs/design/README.md` with standardized status and
last-reviewed metadata for each design document. Separate authoritative/current,
proposal, superseded, and historical groups; link the live backlog independently.

**Acceptance criteria:** every design page has a standard status; user navigation
and search do not present historical plans as active roadmaps.

### Code quality, correctness, and maintainability

#### CODE-01 — Preserve existing configuration on read errors

**Priority / type / effort:** P1 / verified correctness and data-loss risk / S

**Evidence:** `src/config.rs:1899-1901,1950-1955` uses
`read_to_string(path).unwrap_or_default()`. Permission errors, invalid UTF-8,
directories, and transient I/O therefore become an empty configuration that is
later atomically written over the target. This contradicts the documented errors
at `src/config.rs:1891-1898,1942-1949`.

**Impact:** saving TUI columns or manual names can erase unrelated configuration.

**Recommendation:** treat only `ErrorKind::NotFound` as empty. Map every other
failure to the existing typed configuration-read error, consistently carrying the
path, and do not enter the write/rename path.

**Acceptance criteria:** a missing target is created; unreadable and non-UTF-8
targets return `Err` and remain byte-identical. Tests cover deterministic read
failure and invalid UTF-8 for both save paths.

#### CODE-02 — Resolve `KeylogSource::from_fd` descriptor side effects

**Priority / type / effort:** P1 / verified API contract violation / M

**Evidence:** [`src/capture/keylog_source.rs:181-185`](https://github.com/NormB/sipnab/blob/main/src/capture/keylog_source.rs#L181-L185) promises duplication before
setting `O_NONBLOCK` leaves the caller descriptor unchanged. The implementation
duplicates then calls `F_SETFL` on the duplicate (`:188-200`). POSIX duplicated
descriptors share open-file-description status flags, so the original changes too.

**Impact:** library users or supervisors can unexpectedly receive `EAGAIN` on
reads from a descriptor Sipnab was only meant to borrow.

**Recommendation:** choose and document one honest contract: require and validate
an already-nonblocking descriptor; explicitly state mutation; or acquire a truly
independent open-file description using a safe platform-specific method. Do not
retain the current promise with `dup`.

**Acceptance criteria:** a Unix regression test compares `F_GETFL` before and
after. If the no-side-effect guarantee remains, caller flags never change; if the
API contract changes, validation and documentation make the mutation explicit.

#### CODE-03 — Lint every workspace member in CI

**Priority / type / effort:** P1 / verified gate gap / XS

**Evidence:** `cargo clippy --workspace --all-targets --all-features -- -D warnings`
fails at [`crates/sipnab-plugin-example/src/lib.rs:146`](https://github.com/NormB/sipnab/blob/main/crates/sipnab-plugin-example/src/lib.rs#L146) with
`manual_range_contains`. The CI command in [`.github/workflows/ci.yml:168-171`](https://github.com/NormB/sipnab/blob/main/.github/workflows/ci.yml#L168-L171)
omits `--workspace`, so the example crate escapes the lint gate.

**Recommendation:** use `(0..SHORT_CALL_MS).contains(&elapsed)` and change local
hook/CI documentation and the workflow to the workspace-wide command.

**Acceptance criteria:** the exact workspace-wide command exits zero and CI proves
both workspace members were linted.

#### CODE-04 — Bound and reap alert-hook process groups

**Priority / type / effort:** P2 / verified resource-lifecycle weakness / M–L

**Evidence:** [`src/security/alerting.rs:307-328`](https://github.com/NormB/sipnab/blob/main/src/security/alerting.rs#L307-L328) permits up to 100 children with no
deadline. Reaping only removes exited children (`:737-755`); once the set is full,
new work is refused. Drop (`:912+`) reports suppression but does not terminate and
wait for live children.

**Impact:** 100 wedged hooks permanently suppress later automated responses and
can leave descendant processes/resources behind.

**Recommendation:** add a configurable, opt-out or sufficiently conservative
deadline; isolate each hook in a
process group/session; use TERM then KILL escalation; reap and report timeout as a
distinct metric/reason while retaining concurrency and rate limits.

**Acceptance criteria:** a hanging fixture times out, leaves no process/group, frees
a slot, and permits a subsequent alert. A legitimate slow fixture completes under
the configured deadline. Shutdown performs bounded cleanup.

#### CODE-05 — Bound plugin module loading before compilation

**Priority / type / effort:** P2 / verified resource-bound gap / S–M

**Evidence:** runtime linear memory and output are capped
([`src/plugin/mod.rs:72-118`](https://github.com/NormB/sipnab/blob/main/src/plugin/mod.rs#L72-L118)), but loading performs unbounded `std::fs::read`
before validation/compilation ([`src/plugin/mod.rs:221-230`](https://github.com/NormB/sipnab/blob/main/src/plugin/mod.rs#L221-L230)).

**Impact:** an oversized or sparse Wasm file can force host allocation and compile
work before sandbox limits apply.

**Recommendation:** define a maximum module size, check metadata and use a bounded
read, reject unsuitable non-regular inputs where appropriate, and return a
distinct error before compilation.

**Acceptance criteria:** limit-sized input loads; limit+1 is rejected without
proportional allocation; the shipped plugin example still works.

#### CODE-06 — Incrementally split extreme compilation units

**Priority / type / effort:** P2 / maintainability suggestion / L–XL

**Evidence:** [`src/mcp/server.rs`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs) is 11,273 lines; [`src/capture/parse.rs`](https://github.com/NormB/sipnab/blob/main/src/capture/parse.rs) 6,601;
[`src/app/batch.rs`](https://github.com/NormB/sipnab/blob/main/src/app/batch.rs) 5,958; [`src/cli.rs`](https://github.com/NormB/sipnab/blob/main/src/cli.rs) 5,475; and
[`src/sip/dialog_store.rs`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs) 4,715 in the reviewed tree.

**Impact:** changes have large review surfaces, higher merge-conflict risk, and
poorly targeted unit-test boundaries.

**Recommendation:** preserve public facades while extracting MCP tool domains,
capture link/transport decoding, batch phases, CLI argument groups, and dialog
index/expiry responsibilities. Move their unit tests with them and keep dependency
direction explicit. Do this opportunistically, not as a flag-day rewrite.

**Acceptance criteria:** public API/output remains unchanged; all tests pass; new
modules have stated ownership and one-way dependencies; targeted test/build or
review ownership becomes demonstrably narrower. No extraction is accepted solely
to satisfy a line-count target.

#### CODE-07 — Add a truly featureless core build leg

**Priority / type / effort:** P3 / preventive suggestion / XS

**Evidence:** the feature matrix at [`.github/workflows/ci.yml:360-386`](https://github.com/NormB/sipnab/blob/main/.github/workflows/ci.yml#L360-L386) starts with
named features and does not run an empty `--no-default-features` build. During this
review, `cargo check --no-default-features --lib` succeeded.

**Recommendation:** add that exact core-only library command, and core-only tests
if supported, to the matrix.

**Acceptance criteria:** CI explicitly shows a green empty-feature core build and
catches future accidental dependencies on `native` or another default feature.

### Operations and usage

#### OPS-01 — Replace the broken packaged systemd service

**Priority / type / effort:** P0 / verified packaging defect / M

**Evidence:** DEB/RPM scripts install `/usr/bin/sipnab`
([`packaging/deb/build-deb.sh:63-70`](https://github.com/NormB/sipnab/blob/main/packaging/deb/build-deb.sh#L63-L70); [`packaging/rpm/build-rpm.sh:93-96`](https://github.com/NormB/sipnab/blob/main/packaging/rpm/build-rpm.sh#L93-L96)), while
[`packaging/sipnab.service:9`](https://github.com/NormB/sipnab/blob/main/packaging/sipnab.service#L9) executes `/usr/local/bin/sipnab`. The plain
`sipnab.service` passes `-d %i` despite not being an instance unit
(`packaging/sipnab.service:1,9`). It binds REST and standalone metrics
non-loopback without credentials (`:9`), which REST refuses
([`src/output/api.rs:443-465`](https://github.com/NormB/sipnab/blob/main/src/output/api.rs#L443-L465); [`docs/rest-api.md:210-217`](https://github.com/NormB/sipnab/blob/main/docs/rest-api.md#L210-L217)) and metrics documents as
fail-closed ([`docs/rest-api.md:229-239`](https://github.com/NormB/sipnab/blob/main/docs/rest-api.md#L229-L239)). Yet [`docs/install.md:222-224`](https://github.com/NormB/sipnab/blob/main/docs/install.md#L222-L224) promises a
packaged unit and service user.

**Impact:** `systemctl start sipnab` from either native package enters failure or
restart behavior instead of monitoring traffic.

**Recommendation:** choose a safe supported default: an inert example unit or a
proper `sipnab@.service`; use `/usr/bin/sipnab`; bind control endpoints to loopback
or provision credentials through `EnvironmentFile`/`LoadCredential`; resolve the
service identity as described in OPS-06.

**Acceptance criteria:** DEB and RPM VM tests install and start the unit, choose an
interface correctly, show healthy/authenticated endpoints, run with the intended
post-open identity, and show no startup refusal in the journal.

#### OPS-02 — Correct and test Docker live-capture capabilities

**Priority / type / effort:** P0 / verified published-workflow defect / S–M

**Evidence:** the runtime image switches to `USER sipnab`
([`Dockerfile:37-40`](https://github.com/NormB/sipnab/blob/main/Dockerfile#L37-L40)). The live-capture recipe supplies only host networking
([`docs/install.md:521-527`](https://github.com/NormB/sipnab/blob/main/docs/install.md#L521-L527)), while capture requires raw capability or root
(`docs/install.md:397-406,544-546`). Docker CI tests only an offline pcap
([`.github/workflows/docker.yml:121-139`](https://github.com/NormB/sipnab/blob/main/.github/workflows/docker.yml#L121-L139)).

**Impact:** the documented live-container command fails with permission denied.

**Recommendation:** experimentally determine and document the narrowest proven
capability/device set; treat `NET_RAW` and `NET_ADMIN` as candidates, not assumed
requirements. Cover host namespace/interface semantics. Do
not recommend privileged mode. Add a live-loopback smoke test or explicit device
open/capability probe and a negative missing-capability case.

**Acceptance criteria:** the exact documented non-root command captures on a
supported Linux host; omitting capabilities returns a diagnostic remediation;
CI covers success and failure.

#### OPS-03 — Correct observability dependency and tracing claims

**Priority / type / effort:** P2 / verified operational-doc mismatch / docs S, tracing L

**Evidence:** [`contrib/observability/README.md:124-138`](https://github.com/NormB/sipnab/blob/main/contrib/observability/README.md#L124-L138) says the full/audio binary
links libasound and refuses startup without it. The current install guide says
audio is lazily loaded and the executable starts without ALSA
([`docs/install.md:465-471`](https://github.com/NormB/sipnab/blob/main/docs/install.md#L465-L471)). The guide advertises Sipnab “metrics and traces”
([`contrib/observability/README.md:1-15`](https://github.com/NormB/sipnab/blob/main/contrib/observability/README.md#L1-L15)), but calls OpenTelemetry a future phase
and only proves the collector listens (`:13,86-91`), not that Sipnab emits spans.

**Recommendation:** document libpcap versus plugin dependencies correctly. Mark
Tempo/OpenTelemetry as scaffold until an exporter exists. Treat implementing an
exporter as a separate product decision; if accepted, validate an application span
end to end.

**Acceptance criteria:** a clean headless deployment starts without ALSA. The guide
either finds a Sipnab span in Tempo or explicitly says traces are unavailable.

#### OPS-04 — Add readiness separate from liveness

**Priority / type / effort:** P2 / capability improvement / M

**Evidence:** REST health always returns literal `ok`
([`src/output/api.rs:595-597`](https://github.com/NormB/sipnab/blob/main/src/output/api.rs#L595-L597); [`docs/rest-api.md:263-265`](https://github.com/NormB/sipnab/blob/main/docs/rest-api.md#L263-L265)), and MCP health is also
unconditional ([`src/mcp/transport.rs:269-272`](https://github.com/NormB/sipnab/blob/main/src/mcp/transport.rs#L269-L272)). Existing capture state is not
consulted by these probes.

**Impact:** an orchestrator can route to or retain a process whose worker/source
is absent or dead.

**Recommendation:** preserve `/health` as process liveness and add `/ready` (or a
structured deep probe) for initialization, source/worker state, store availability,
and shutdown. Define quiet-interface behavior so zero packets alone is not failure.

**Acceptance criteria:** liveness remains 200 while quiet; readiness is non-200
before initialization, after worker death, and during shutdown, with a stable
machine-readable reason. Deployment health checks use the appropriate endpoint.

#### OPS-05 — Validate permissions and ownership of secret files

**Priority / type / effort:** P1 / security hardening / M

**Evidence:** signing keys are read with `read_to_string`
([`src/app/servers.rs:469-485`](https://github.com/NormB/sipnab/blob/main/src/app/servers.rs#L469-L485)) and MCP token files likewise (`:547-567`). Docs
recommend `chmod 600` ([`docs/mcp.md:227-235`](https://github.com/NormB/sipnab/blob/main/docs/mcp.md#L227-L235)), but code accepts broad modes and
symlinked inputs.

**Impact:** accidental `0644` credentials can silently expose captured-call access.

**Recommendation:** define a threat model and open secret files race-resistently.
On Unix, validate the opened object is regular and has an allowed owner/mode; avoid
path-check-then-open TOCTOU. Do not categorically reject symlinks until compatibility
with Kubernetes projected secrets and other supported managers is decided. Make
any compatibility override explicit and noisy. Prefer `LoadCredential=` in
systemd examples.

**Acceptance criteria:** a regular `0600` file owned by the service user (or root
under the stated model) works; `0644`, ownership violations, and link-swap races
fail safely with exact remediation. Supported managed-secret layouts have positive
tests; unsupported symlink layouts fail explicitly. Tests cover every
credential-file type.

#### OPS-06 — Make the packaged service identity real and explicit

**Priority / type / effort:** P1 / verified privilege-model mismatch / M

**Evidence:** [`packaging/sipnab.service:9-13`](https://github.com/NormB/sipnab/blob/main/packaging/sipnab.service#L9-L13) runs as root and comments about
`--user sipnab`, but does not pass it. The documented default internal drop target
is `nobody` ([`docs/install.md:417-420`](https://github.com/NormB/sipnab/blob/main/docs/install.md#L417-L420); [`docs/config-reference.md:354`](https://github.com/NormB/sipnab/blob/main/docs/config-reference.md#L354)). Package
scripts create a dedicated `sipnab` user
([`packaging/deb/build-deb.sh:116-123`](https://github.com/NormB/sipnab/blob/main/packaging/deb/build-deb.sh#L116-L123); [`packaging/rpm/build-rpm.sh:101-105`](https://github.com/NormB/sipnab/blob/main/packaging/rpm/build-rpm.sh#L101-L105)).

**Recommendation:** prefer systemd `User=sipnab` with tightly bounded capture
capabilities if libpcap/device access permits; otherwise use root only for device
open and explicitly pass `--user sipnab`. Provide an unprivileged HEP-only unit.

**Acceptance criteria:** `/proc/$pid/status` shows the Sipnab UID after device open,
no root is retained, and HEP-only mode has an empty capability set.

#### OPS-07 — Define configuration and credential reload semantics

**Priority / type / effort:** P2 / lifecycle improvement / docs S, code L

**Evidence:** key rotation requires startup flags and restart to drop the old key
([`docs/auth.md:199-202`](https://github.com/NormB/sipnab/blob/main/docs/auth.md#L199-L202)); static credentials require restart ([`docs/auth.md:11`](https://github.com/NormB/sipnab/blob/main/docs/auth.md#L11)),
while only revocation files reload by mtime ([`docs/auth.md:204-220`](https://github.com/NormB/sipnab/blob/main/docs/auth.md#L204-L220)). Packaged and
observability units define no `ExecReload`
([`packaging/sipnab.service:7-28`](https://github.com/NormB/sipnab/blob/main/packaging/sipnab.service#L7-L28); [`contrib/observability/sipnab-hep.service:43-69`](https://github.com/NormB/sipnab/blob/main/contrib/observability/sipnab-hep.service#L43-L69)).

**Recommendation:** immediately publish a live-versus-restart matrix. Then add
SIGHUP atomic reload for safe config and credential files, retaining old state on
validation failure and recording success/failure in logs and metrics.

**Acceptance criteria:** every relevant setting is labeled live or restart-only.
Atomic credential replacement plus reload supports overlap without listener
downtime; invalid reload leaves the previous configuration active.

#### OPS-08 — Make the observability example safe by default

**Priority / type / effort:** P2 / security hardening / S

**Evidence:** [`contrib/observability/README.md:52-53`](https://github.com/NormB/sipnab/blob/main/contrib/observability/README.md#L52-L53) advertises Grafana
`admin/admin`. Compose defaults the password to `admin`, publishes Grafana,
Prometheus, and OTLP on all interfaces, and enables the Prometheus lifecycle API
(`contrib/observability/docker-compose.yml:16-22,35-37,57-63`).

**Recommendation:** bind host ports to `127.0.0.1` by default, require a generated
Grafana password via `.env`, make OTLP exposure opt-in, and explain firewall,
TLS/reverse-proxy, and lifecycle endpoint risks.

**Acceptance criteria:** the default stack listens only on loopback; a remote
profile fails fast without a non-default secret; a short exposure checklist is
part of the walkthrough.

#### OPS-09 — Unify the metrics contract across endpoints

**Priority / type / effort:** P2 / verified semantic inconsistency / L

**Evidence:** the docs acknowledge API versus standalone label-case differences
([`docs/rest-api.md:1078`](https://github.com/NormB/sipnab/blob/main/docs/rest-api.md#L1078)), different meanings for
`sipnab_rtp_streams_active` (`:1083`), and omission of
`sipnab_rtp_streams_total` from standalone metrics (`:1084`).

**Impact:** dashboards and alerts can silently change meaning when endpoint choice
changes.

**Recommendation:** define one canonical contract and share collector logic. Until
then, rename conflicting series or expose explicit collector/semantic names and
state which dashboards support which endpoint.

**Acceptance criteria:** a golden scrape comparison gives matching families,
labels, and values for the same input; bundled dashboard PromQL is exercised
against both endpoints.

### Developer documentation and contributor experience

#### DEV-01 — Remove or derive the stale integration-test count

**Priority / type / effort:** P1 / verified developer-doc drift / XS

**Evidence:** [`docs/internals/testing.md:3-6`](https://github.com/NormB/sipnab/blob/main/docs/internals/testing.md#L3-L6) says “Fifty integration-test
binaries,” while the reviewed repository has 132 top-level `tests/*.rs` files.
The paragraph explicitly avoids repeating the exact total elsewhere because it
changes frequently, making this remaining number internally inconsistent.

**Impact:** the first statement in the test architecture understates scope by more
than half and weakens confidence in the otherwise careful guide.

**Recommendation:** say “more than one hundred integration-test binaries” only if
that distinction matters, or remove the number entirely. Prefer a generated test
inventory/report for exact counts. Add this claim to the existing count ratchet if
an exact figure remains.

**Acceptance criteria:** no manually maintained exact count survives without a
drift test; the guide accurately explains Cargo's top-level integration targets.

#### DEV-02 — Provide a bootstrap command for the full contributor toolchain

**Priority / type / effort:** P2 / onboarding gap / M

**Evidence:** [`CONTRIBUTING.md:54-62`](https://github.com/NormB/sipnab/blob/main/CONTRIBUTING.md#L54-L62) lists Rust, libpcap, and fuzzing tools, but
later required/important workflows depend on Vale, codespell, Python, cargo-insta,
tmux, wasm-pack, and other CI/release tools ([`CONTRIBUTING.md:132-179`](https://github.com/NormB/sipnab/blob/main/CONTRIBUTING.md#L132-L179);
`docs/internals/testing.md:19,60,113-128`;
[`docs/internals/build-ci-release.md:131-169`](https://github.com/NormB/sipnab/blob/main/docs/internals/build-ci-release.md#L131-L169)). Instructions are dispersed and
some failures occur only at pre-push or CI.

**Impact:** a contributor can satisfy “Prerequisites” but still be unable to run
the documented preflight, snapshots, TUI E2E, Wasm, or release checks.

**Recommendation:** add a checked bootstrap or doctor command that reports tools,
versions, optional roles, and exact installation links/commands. Keep base,
documentation, TUI, Wasm, fuzz, benchmark, and release profiles separate so the
minimal path stays small.

**Acceptance criteria:** a fresh supported environment can install the declared
base profile and run formatting, preflight, lint, and default tests. `doctor`
distinguishes required from optional tools and CI checks its manifest against
workflows/hooks.

#### DEV-03 — Turn known unenforced contributor steps into backlog items

**Priority / type / effort:** P2 / developer-process improvement / M

**Evidence:** [`docs/internals/walkthroughs.md:3-20`](https://github.com/NormB/sipnab/blob/main/docs/internals/walkthroughs.md#L3-L20) deliberately labels steps that
are not enforced. Examples include exhaustive CLI default coverage (`:43-45`),
output behavior registration (`:210-219`), fuzz target registration and seed
replay (`:224-250`). The guide is admirably candid, but these are durable blind
spots rather than only reading notes.

**Recommendation:** create explicit issues for each feasible gate: enumerate CLI
fields for defaults, enumerate output selectors/serializers, compare
`fuzz_targets/*.rs` to `[[bin]]`, and replay the committed corpus in a bounded CI
job. Keep genuinely judgment-based steps labeled unenforced.

**Acceptance criteria:** mechanical additions fail automatically when their
registration/test is missing; the walkthrough's “unenforced” label remains only
where automation cannot make a reliable determination.

### Governance and implementation control

#### GOV-01 — Reconcile this intake review with the canonical backlog

**Priority / type / effort:** P1 / process and duplication risk / S

**Evidence:** [`docs/internals/README.md`](https://github.com/NormB/sipnab/blob/main/docs/internals/README.md) identifies [`docs/design/backlog.md`](https://github.com/NormB/sipnab/blob/main/docs/design/backlog.md) as
the live, priority-ranked working list. That backlog already contains historical
audit findings and uses a different P0–P5 definition. This review introduces its
own identifiers and priority scale, so leaving both independently active would
create two sources of truth and ambiguous closure status.

**Impact:** maintainers could implement duplicates, close only one copy, or compare
unlike priority labels as though they had the same meaning.

**Recommendation:** triage this document once. For every accepted item, create or
cross-reference exactly one canonical backlog/issue identifier, preserve this
review's evidence and acceptance criteria, and record `accepted`, `merged`,
`rejected`, `superseded`, or `deferred` here. Do not copy completed historical
entries back into the active backlog. State explicitly that priorities in this
review are local intake priorities.

**Acceptance criteria:** every DOC/CODE/OPS/DEV item has a disposition and, when
accepted, one canonical tracking link. A repository test or lightweight review
check rejects two active entries claiming the same review ID. The developer index
continues to name only one live backlog.

## Adversarial confidence ledger

This ledger prevents “verified” from being read as equal confidence across static
and runtime claims. “High” has direct source semantics or a reproduced command;
“medium” is strongly supported but still needs the named environment/journey test;
“proposal” is a product or maintainability choice rather than a defect.

| Confidence | Items | Remaining proof |
|---|---|---|
| High | DOC-01, DOC-03, CODE-01, CODE-02, CODE-03, CODE-05, OPS-01, OPS-03, OPS-06, OPS-08, OPS-09, DEV-01, GOV-01 | Add regression/integration tests so the demonstrated mismatch cannot recur. |
| Medium | DOC-02, DOC-04, DOC-05, DOC-06, DOC-07, CODE-04, OPS-02, OPS-05, DEV-02, DEV-03 | Run clean-machine journeys, container/secret-manager compatibility tests, or enumerate the claimed surface. |
| Proposal | CODE-06, CODE-07, OPS-04, OPS-07 | Approve the desired product/architecture contract before implementation; measure benefit and compatibility afterward. |

Priority and confidence answer different questions: a high-confidence P2 can be
clearly real but less urgent, while a medium-confidence P0 must receive immediate
reproduction before a release decision.

## Validation performed during this review

- `cargo test --test dev_docs_drift_test --test link_integrity_test \
  --test docs_drift_test --test doc_example_coverage_test` passed: 69 tests total.
- `cargo check --no-default-features --lib` passed.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` failed on
  the plugin-example lint described in CODE-03; this is a scope gap in the current
  CI command, not a general project build failure.
- Source, packaging scripts, workflows, generated documentation, tutorials,
  examples, internal guides, operational guides, and representative tests were
  inspected. No destructive actions or external services were used.

These results also show the boundary of the current gates: links, mirrors, flags,
and many enumerated facts are well protected, while hand-written task-card command
semantics, prose counts, package runtime behavior, and example outcomes need the
additional tests recommended above.

## Strengths to preserve while implementing the backlog

- The Diátaxis-style task routing in [`docs/README.md`](https://github.com/NormB/sipnab/blob/main/docs/README.md) and the symptom-first
  cookbook/troubleshooting organization.
- Canonical `docs/` sources with generated website mirrors and byte-for-byte drift
  tests; edit sources and regenerate rather than changing generated copies.
- Explicit warnings about stale transcripts and historical plans—improve their
  placement/status rather than deleting useful design history.
- CLI/config/keybinding/feature/documentation drift gates and synthetic packet
  fixtures.
- Always-on parser smoke fuzzing plus scheduled coverage-guided fuzzing.
- Typed errors, production-path unwrap restrictions, documented unsafe invariants,
  localhost listener defaults, privilege-drop design, and attacker-controlled
  resource caps.
- The internal guides' practice of linking claims directly to source symbols and
  candidly labeling unenforced steps.

## Completion checklist

The review can be considered implemented when:

- All P0 and P1 items are closed with their acceptance tests.
- Every affected command is tested from its canonical documentation source rather
  than only from a generated mirror.
- DEB, RPM, and container smoke tests exercise actual runtime startup, identity,
  capabilities, health, and authentication—not merely artifact construction.
- Security-sensitive inputs are bounded before allocation/execution and credential
  file policy is enforced rather than advisory.
- The tutorial and MCP first-run paths work on a clean, unprivileged environment
  using a published fixture.
- Exact inventories and compatibility claims are derived/tested or replaced with
  durable qualitative wording.
- Documentation mirrors are regenerated and all existing drift, link, test, lint,
  feature-matrix, and package checks pass.
