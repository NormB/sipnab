# Conditional content persistence

**Status:** approved 2026-08-26. Phase 1 (audio export) is unbuilt. Phase 2 is
under way, one task at a time, against the plan at the end of this document.

**Check:** `grep -rn 'export_audio_live' src/cli.rs` exits 1. It exits 0 the
day phase 1 ships, which is the day this Status line needs rewriting. The check
deliberately names a phase-1 flag rather than a phase-2 one, because a phase-2
marker would go false at the very next task and turn this line into a lie about
work that is going fine.

sipnab writes signaling to disk all day. It does not write call **content** —
audio, or a vCon container holding it — unless somebody asks. This document
covers what happens when somebody does, and the question underneath both
features: under what authority does a passive observer keep the contents of a
conversation it took no part in?

## The problem

Two capabilities are missing, and they share one decision.

**Audio has no CLI door.** [`src/rtp/audio_export.rs`](../../src/rtp/audio_export.rs)
decodes G.711 and Opus into WAV files today, and only the `export_audio` MCP
tool and the REST vCon path can reach it. The retention flag that fills the
buffers, `--retain-audio`, carries `requires = "mcp"`. So an operator holding a
capture of relayed media can attribute the streams to a call and still have no
way to save the audio without standing up an MCP server.

**vCon export names one call at a time.** `--export-vcon <CALL-ID>` produces
exactly one container for exactly one Call-ID. Nothing decides, per dialog,
whether a container should exist at all.

## The principle: every input may only narrow

Four things could decide whether a dialog produces content: conditions sipnab
measured, a flag in the signaling, an operator at runtime, and an emergency
stop. Four inputs deciding one boolean is ambiguous unless something says who
wins.

The rule is that **the command line is the only place persistence is
authorized, and every other input may only subtract.**

Nothing sipnab reads off the network, and nothing an operator does mid-run, can
cause it to keep content the invocation did not already permit. A capture
started without `--export-audio` writes no audio, whatever arrives on the wire
and whatever anyone posts to the API.

That rule resolves the hardest case on its own. A flag in the signaling saying
"record this session" is an assertion by whoever sent the request, and sipnab
already refuses to trust that class of claim: every party it emits carries
`validation: "none"`, and [`Party`](../../src/output/vcon.rs) has no `name`
field at all so a later edit cannot break the rule. Acting on such an assertion
to be **more** conservative costs at worst a container nobody kept. Acting on
one to **retain** content hands the retention decision to anyone who can set a
header.

So sipnab honors deny and never honors permit. A "please record" hint becomes
an observation recorded inside the container, which is what an observer does
with a claim it cannot verify. It never causes a container to exist.

## The ladder

Applied in order, first match wins:

| | Input | Effect |
|---|---|---|
| 1 | Runtime gate, over REST | Off means nothing further reaches disk. |
| 2 | Deny flag in the signaling | Suppresses that dialog, whatever the predicate says. |
| 3 | Predicate over observed conditions | Decides every dialog the two rows above did not settle. |

The original sketch had four rows. An operator "toggle" and an emergency "kill
switch" turned out to be one lever described twice, so they collapse into row 1,
and the narrowing rule removes the ambiguity that made two rows look necessary:
the gate can turn **off** what the command line authorized and can never turn on
what it did not. A run invoked without persistence flags has nothing for the API
to enable.

## Surface

### Audio

```
--export-audio <DIR>       write a WAV per dialog with decodable audio
--export-audio-live        additionally permit this during a live capture
```

`--export-audio` implies retention, so `--retain-audio` stops being the only
door and loses its `requires = "mcp"`. Passing `--export-audio` **is** the
deliberate operator decision that flag's documentation asks for.

Live capture needs the second flag because the two cases differ in kind rather
than degree. Extracting audio from a pcap changes nothing about what anyone
collected: whoever took the capture already made that decision. Turning a live
network feed into audio files on disk in real time is what a recorder does,
whatever the man page calls it, and sipnab stamps "passive observer; not a
recording system" on every container it emits. Two flags make an operator state
that intent twice.

One WAV per dialog. Stereo when both legs decode, with the caller left and the
callee right, and mono when only one leg survives. Both shapes exist in
`audio_export.rs` already.

### vCon

```
--export-vcon-when <EXPR>  emit a container for each dialog matching EXPR
--export-vcon-dir <DIR>    where the containers go
```

`EXPR` is the existing filter language, unchanged. [`docs/filter-dsl.md`](../filter-dsl.md)
already documents `state`, `response_code`, `response_class`, `duration`,
`msg_count`, `pdd`, `setup_time`, `retransmits` and `rtp.codec`, which is the
vocabulary a "should this call become a container?" question is made of.
`state == 'Failed'`, `duration > 30`, `response_code >= 400 and rtp.codec == 'PCMU'`
all work the day this lands.

Reusing the language rather than adding a flag per policy is deliberate.
`--export-vcon-failed`, `--export-vcon-with-media` and their successors would
enumerate the cases somebody thought of, which is the shape behind two defects
this repository fixed on 2026-08-26: a canonical-number rule that listed `i03e`
and `i-0e` but not `i+5e`, and a scanner exemption that handled the nesting its
author pictured. A predicate language has no such tail.

`--export-vcon-dir` exists because conditional emission produces N containers
and `--vcon-out` names one file.

### The deny flag

```
--content-deny-header <NAME>   a header whose presence suppresses the dialog
```

No default, and the feature stays inert until an operator names a header. sipnab
ships no opinion about which header your switches emit, and a built-in default
would either miss the header you use or silently match one you did not mean.

Presence suppresses. Value does not matter, because a rule keyed on a value
invites the question of what an unrecognized value means, and the only safe
answer to "I do not understand this deny flag" is to deny.

### Runtime gate

```
POST /persistence  {"enabled": false}     stop writing content
GET  /persistence                         report the current state
```

REST rather than MCP, behind the API's existing auth. A control that stops call
audio reaching disk should be reachable with `curl` at three in the morning by
somebody who does not have an agent session open.

`{"enabled": true}` restores writing **only** up to what the command line
authorized. On a run invoked without persistence flags it changes nothing and
says so, rather than reporting a success that enabled nothing.

## What a container says about itself

A run whose gate moved does not reproduce from the capture alone, and the
container has to say so rather than leave it silent. The completeness
attachment already carries this class of caveat — "a fact about this EXPORT,
not about the call" — and gains two more:

- the gate closed during this run, so containers are absent for reasons the
  capture does not explain
- this dialog carried a deny flag and produced no content, which is the one
  case where sipnab records that a container deliberately does not exist

The second matters because absence reading as "nothing happened" is the failure
the vCon module was built against.

## Audio inside a container

When a dialog produces both a WAV and a container, the audio travels inline as
base64 under [`MAX_INLINE_MEDIA_BYTES`](../../src/output/vcon.rs), and the WAV
lands on disk as well. Above the ceiling the container refuses the media out
loud and keeps the WAV.

The container never points at the file. sipnab emits no by-reference `url`
because it hosts nothing, and a path on the machine that ran a capture is not a
promise anybody can keep. A reader holding the container has the audio or knows
exactly why not.

## Testing

Per this repository's standard: a failing test first, and every gate
mutation-proven against a named mutant rather than counted.

The ladder needs one test per row and one per interaction:

- a deny flag suppresses a dialog the predicate selected
- the runtime gate suppresses a dialog the predicate selected and the signaling
  permitted
- a "please record" hint on a dialog the predicate rejected produces **no**
  container, and the hint appears as an observation where a container exists
- `{"enabled": true}` on a run without persistence flags writes nothing
- the completeness attachment names a gate that closed mid-run

The third is the one that matters most. Its mutant — honoring permit as well as
deny — passes every other test in the suite while handing retention to anyone
who can set a header.

Live audio export needs a test that `--export-audio` alone refuses on a live
source, and that the refusal names the missing flag rather than reporting an
empty result.

## Phases

1. **Audio.** `--export-audio`, `--export-audio-live`, retention decoupled from
   `--mcp`. Independently useful and touches no policy.
2. **Conditional vCon.** The predicate, the ladder, the deny header, the runtime
   gate, the completeness caveats.

## Not doing

- **A permit flag in the signaling.** Covered above. The asymmetry is the design.
- **Retroactive purge.** The gate stops new writes. Removing what already
  reached disk is a different tool with different failure modes, and a purge
  that half works is worse than none.
- **Per-dialog runtime decisions.** The gate is global. An operator deciding
  call by call at runtime is a recording console, which is a product this is not.
- **Surface parity for the export actions.** `surface_parity_test` binds quality
  **metrics**, so that every metric reaches every consumer. Writing a file is an
  action, and MCP already has `export_audio`.

---

# Implementation plan, phase 2

> Execute task by task. Steps use checkbox (`- [ ]`) syntax for tracking.
> Phase 1 (audio export) is independent and not planned here.

Every task's requirements implicitly include the design above, plus:

- **Feature gate:** every item lives behind `#[cfg(feature = "vcon")]`.
  `export_vcon` already has a paired `#[cfg(not(feature = "vcon"))]` stub at
  [`src/app/batch.rs:5501`](https://github.com/NormB/sipnab/blob/main/src/app/batch.rs#L5501), and a new entry point needs the same pairing or the
  crate stops building without the feature.
- **Toolchain:** Rust 1.97.1 exactly. No new dependencies.
- **Tests:** failing test first. Every gate mutation-proven against a named
  mutant, and a test that passes under its own mutant gets rewritten rather
  than counted.
- **Gates:** run `bash .githooks/pre-commit` against the staged index before
  every commit, and read its exit code by redirecting to a file. A pipe returns
  the exit status of its last stage and masks the hook's.
- **Ratchets:** a commit adding tests moves the homepage count in
  [`website/templates/index.html`](../../website/templates/index.html), both the stat card and the prose. Attribute
  the delta before moving it. This tree also counts tracked markdown files and
  markdown tables in [`tests/docs_drift_test.rs`](../../tests/docs_drift_test.rs).
- **US English.** A gate enforces it over `src/` as well as `docs/`, so a doc
  comment counts. Vale does not catch it.
- **Every flag needs two runnable examples** in [`docs/cli-reference.md`](https://github.com/NormB/sipnab/blob/main/docs/cli-reference.md), and a
  row in the generated testing matrix. Regenerate the matrix with
  `cargo build --features full && python3 scripts/coverage-matrix.py`. Task 1
  learned this the hard way: the gate fires the moment a flag parses, so
  documentation cannot trail the code by four tasks.
- **A documented command has to RUN.** The example gate proves an example
  exists, not that it works. Both commands Task 1 first shipped were invalid --
  the filter DSL needs quoted, case-sensitive values (`state == 'Failed'`, not
  `state == failed`). Assert every documented predicate parses.
- **Doc gates beyond Vale**, each with its own fixer named in the failure:
  tracked-markdown-file and table counts, symbol-naming citation counts,
  `scripts/fix-line-anchors.py --apply` for `#L` fragments,
  `scripts/check-line-drift.py --apply` when moving code shifts a cited line,
  absolute GitHub hrefs for line citations, no bare code spans naming tracked
  files, and no bracketed character classes inside a table cell.
- **A design doc claiming something is unbuilt needs a `grep` a reader can
  run**, and the gate re-runs it. Cite something that stays true for several
  tasks, or the line becomes a lie at the next commit.
- **Clippy demands a doc comment on every function.** Insert new code ABOVE the
  doc block of the function that follows, never between a doc block and its
  `fn` -- that steals the comment and leaves the original undocumented.

### Task 1: The predicate and the output directory

**Files:**
- Modify: [`src/cli.rs`](../../src/cli.rs) (new fields beside `export_vcon` at line 944)
- Modify: [`src/app/batch.rs:5501`](https://github.com/NormB/sipnab/blob/main/src/app/batch.rs#L5501) (`export_vcon`)
- Test: [`src/app/batch.rs`](../../src/app/batch.rs) tests module

**Interfaces:**
- Consumes: `FilterExpr::parse(input: &str) -> anyhow::Result<FilterExpr>` ([`src/sip/dsl.rs:597`](https://github.com/NormB/sipnab/blob/main/src/sip/dsl.rs#L597)); `select_dialogs<'a>(filter: Option<&FilterExpr>, dialog_store: &'a DialogStore, stream_store: &'a StreamStore) -> DialogSelection<'a>` ([`src/sip/dsl.rs:612`](https://github.com/NormB/sipnab/blob/main/src/sip/dsl.rs#L612)), whose `dialogs` field is `Vec<(&SipDialog, Vec<&RtpStream>)>` in store order.
- Produces: `fn vcon_selection<'a>(cli: &Cli, dialog_store: &'a DialogStore, stream_store: &'a StreamStore) -> anyhow::Result<DialogSelection<'a>>`.

**Correction, made by reading the API rather than the surrounding shape.** An
earlier draft of this task invented `vcon_selection`, walking
`dialog_store.iter()` and calling a `streams_for_dialog` that does not exist —
the real method is `streams_for`. More important, the function it planned to
write already exists as `select_dialogs` and does more than a hand-rolled loop
would: its body resolves this run's ICMP media evidence against the whole
stream store, and it is the point `--report` and `--json-dialogs` both pass
through. A parallel selection path would have produced containers whose streams
lacked evidence the report for the SAME call showed. Task 1 therefore parses
the predicate and calls `select_dialogs`, and writes no selection logic of its
own.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn a_predicate_selects_only_the_dialogs_that_match() {
    let (dialogs, streams) = two_dialogs_one_failed();
    let mut cli = test_cli();
    cli.output_args.export_vcon_when = Some("response_code >= 400".to_owned());

    let picked = vcon_selection(&cli, &dialogs, &streams).expect("a valid predicate");
    let ids: Vec<&str> = picked.dialogs.iter().map(|(d, _)| d.call_id.as_str()).collect();

    assert_eq!(ids, vec!["failed-call@example.com"],
        "only the failed dialog matches the predicate");
}
```

- [ ] **Step 2: Run it and watch it fail**

Run: `cargo test --features vcon --lib vcon_selection -- --nocapture`
Expected: FAIL — `cannot find function vcon_selection`.

- [ ] **Step 3: Add the flags**

In [`src/cli.rs`](../../src/cli.rs), beside `export_vcon`:

```rust
    /// Emit a vCon for every dialog matching this filter expression.
    ///
    /// The expression is the language `--filter` speaks, unchanged: see
    /// `docs/filter-dsl.md`. A container per matching dialog, which is why
    /// this needs `--export-vcon-dir` rather than `--vcon-out`.
    ///
    /// Parsed before the capture opens, so a malformed expression fails the
    /// run rather than producing an empty directory nobody questions.
    #[arg(
        help_heading = "Output",
        long = "export-vcon-when",
        value_name = "EXPR",
        conflicts_with = "export_vcon",
        requires = "export_vcon_dir"
    )]
    pub export_vcon_when: Option<String>,

    /// Directory for the containers `--export-vcon-when` produces.
    #[arg(
        help_heading = "Output",
        long = "export-vcon-dir",
        value_name = "DIR",
        requires = "export_vcon_when"
    )]
    pub export_vcon_dir: Option<std::path::PathBuf>,
```

- [ ] **Step 4: Implement the selection**

In [`src/app/batch.rs`](../../src/app/batch.rs), above `export_vcon`:

```rust
/// The dialogs `--export-vcon-when` selects, with their streams.
///
/// Delegates to `select_dialogs` rather than walking the store here. That
/// function resolves this run's ICMP media evidence against the whole stream
/// store, and `--report` and `--json-dialogs` both pass through it, so a
/// second selection path would hand containers a different view of one
/// capture from the one the report shows.
#[cfg(feature = "vcon")]
fn vcon_selection<'a>(
    cli: &Cli,
    dialog_store: &'a DialogStore,
    stream_store: &'a crate::rtp::stream_store::StreamStore,
) -> anyhow::Result<crate::sip::dsl::DialogSelection<'a>> {
    let Some(expr) = cli.output_args.export_vcon_when.as_deref() else {
        return Ok(crate::sip::dsl::select_dialogs(None, dialog_store, stream_store));
    };
    let parsed = crate::sip::dsl::FilterExpr::parse(expr).map_err(|e| {
        anyhow::anyhow!("--export-vcon-when is not a valid filter expression: {e}")
    })?;
    Ok(crate::sip::dsl::select_dialogs(
        Some(&parsed),
        dialog_store,
        stream_store,
    ))
}
```

- [ ] **Step 5: Run the test**

Run: `cargo test --features vcon --lib vcon_selection`
Expected: PASS.

- [ ] **Step 6: Add the parse-failure test**

A malformed expression must fail the run, not silently select nothing. The
`let Ok(parsed) = ... else { return Vec::new() }` above is deliberately wrong
and this test is what forces it to be replaced with startup validation.

```rust
#[test]
fn a_malformed_predicate_fails_the_run_rather_than_selecting_nothing() {
    let mut cli = test_cli();
    cli.output_args.export_vcon_when = Some("response_code >>> 400".to_owned());
    let err = validate_vcon_predicate(&cli).expect_err("a bad expression is an error");
    assert!(format!("{err:#}").contains("export-vcon-when"),
        "the message must name the flag the operator typed: {err:#}");
}
```

- [ ] **Step 7: Add startup validation and delete the silent fallback**

```rust
/// Parse the predicate before the capture opens.
///
/// A malformed expression that surfaced at export time would leave an
/// operator with a finished capture, an empty directory and no error.
#[cfg(feature = "vcon")]
pub fn validate_vcon_predicate(cli: &Cli) -> anyhow::Result<()> {
    let Some(expr) = cli.output_args.export_vcon_when.as_deref() else {
        return Ok(());
    };
    crate::sip::dsl::FilterExpr::parse(expr)
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("--export-vcon-when is not a valid filter expression: {e}"))
}
```

Call it from [`src/app/bootstrap.rs`](../../src/app/bootstrap.rs) where the other argument validation runs, and change `vcon_selection` to `.expect("validated at startup")` on the parse.

- [ ] **Step 8: Run both tests**

Run: `cargo test --features vcon --lib vcon_predicate`
Expected: 2 passed.

- [ ] **Step 9: Write the containers**

Extend `export_vcon` at [`src/app/batch.rs:5501`](https://github.com/NormB/sipnab/blob/main/src/app/batch.rs#L5501): when `export_vcon_when` is set, loop the selected Call-IDs, build each container with the existing single-call path, and write it to `<dir>/<sanitized-call-id>.vcon.json`. Sanitize by replacing every character outside `[A-Za-z0-9._-]` with `_`, because a Call-ID is attacker-influenced text and reaches a filesystem path here.

- [ ] **Step 10: Test the path sanitizer**

```rust
#[test]
fn a_call_id_cannot_escape_the_export_directory() {
    let name = vcon_file_name("../../etc/passwd@evil.example");
    assert!(!name.contains('/'), "no separator survives: {name}");
    assert!(!name.contains(".."), "no traversal survives: {name}");
}
```

- [ ] **Step 11: Run the gate and commit**

```bash
cargo fmt --all
git add src/cli.rs src/app/batch.rs src/app/bootstrap.rs
bash .githooks/pre-commit > /tmp/pc.txt 2>&1; echo "EXIT=$?"; tail -20 /tmp/pc.txt
git commit -F - <<'MSG'
Select vCon containers with the filter language, not a flag per policy
MSG
rm -f /tmp/pc.txt
```

---

### Task 2: The deny flag in the signaling

**Files:**
- Modify: [`src/cli.rs`](../../src/cli.rs)
- Modify: [`src/app/batch.rs`](../../src/app/batch.rs) (`vcon_selection`)
- Test: [`src/app/batch.rs`](../../src/app/batch.rs) tests module

**Interfaces:**
- Consumes: `vcon_selection` from Task 1.
- Produces: `fn dialog_carries_deny_header(dialog: &SipDialog, header: &str) -> bool`.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn a_deny_header_suppresses_a_dialog_the_predicate_selected() {
    let (dialogs, streams) = two_dialogs_one_failed();
    add_header(&dialogs, "failed-call@example.com", "X-No-Record", "1");
    let mut cli = test_cli();
    cli.output_args.export_vcon_when = Some("response_code >= 400".to_owned());
    cli.output_args.content_deny_header = Some("X-No-Record".to_owned());

    let picked = vcon_selection(&cli, &dialogs, &streams);

    assert!(picked.is_empty(),
        "the predicate selected it and the deny flag overrides that: {picked:?}");
}
```

- [ ] **Step 2: Run it and watch it fail**

Run: `cargo test --features vcon --lib deny_header`
Expected: FAIL — the field does not exist.

- [ ] **Step 3: Add the flag**

```rust
    /// Suppress content for any dialog carrying this header.
    ///
    /// No default. sipnab ships no opinion about which header your switches
    /// emit, and a built-in guess would either miss yours or silently match
    /// one you did not mean.
    ///
    /// PRESENCE suppresses and the value plays no part. A rule keyed on a
    /// value raises the question of what an unrecognized value means, and the
    /// only safe answer to "I do not understand this deny flag" is to deny.
    ///
    /// Deny only. A header asking sipnab to RECORD is an assertion by whoever
    /// sent the request, and honoring it would hand the retention decision to
    /// anyone who can set a header.
    #[arg(
        help_heading = "Output",
        long = "content-deny-header",
        value_name = "NAME"
    )]
    pub content_deny_header: Option<String>,
```

- [ ] **Step 4: Implement, matching case-insensitively**

```rust
/// Whether any message in this dialog carries the named header.
///
/// Case-insensitive: SIP header names are case-insensitive on the wire
/// (RFC 3261 section 7.3.1), and a filter keyed on exact case is a filter an
/// ordinary peer walks through.
#[cfg(feature = "vcon")]
fn dialog_carries_deny_header(dialog: &SipDialog, header: &str) -> bool {
    dialog.messages.iter().any(|m| {
        m.headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case(header))
    })
}
```

Add the check inside `vcon_selection`, before the predicate runs.

- [ ] **Step 5: Run the test**

Run: `cargo test --features vcon --lib deny_header`
Expected: PASS.

- [ ] **Step 6: Write the test that matters most**

```rust
#[test]
fn a_permit_header_never_causes_a_container_to_exist() {
    let (dialogs, streams) = two_dialogs_one_failed();
    add_header(&dialogs, "ok-call@example.com", "X-Record-Session", "yes");
    let mut cli = test_cli();
    // The predicate selects ONLY the failed call. The permit header sits on
    // the other one.
    cli.output_args.export_vcon_when = Some("response_code >= 400".to_owned());
    cli.output_args.content_deny_header = Some("X-No-Record".to_owned());

    let picked = vcon_selection(&cli, &dialogs, &streams);

    assert!(!picked.iter().any(|c| c == "ok-call@example.com"),
        "a header asking to be recorded must never add a dialog the predicate \
         rejected -- that hands retention to anyone who can set a header: {picked:?}");
}
```

- [ ] **Step 7: Mutation-verify the pair**

Apply each mutant, confirm the named test dies, revert.

| Mutant | Must kill |
|---|---|
| Delete the deny check from `vcon_selection` | `a_deny_header_suppresses_a_dialog_the_predicate_selected` |
| Add a permit branch that pushes the Call-ID when a permit header is present | `a_permit_header_never_causes_a_container_to_exist` |
| Change `eq_ignore_ascii_case` to `==` and test with a differently-cased header | `a_deny_header_suppresses_a_dialog_the_predicate_selected` |

If the third does not die, the fixture uses matching case — change the fixture to send `x-no-record` and re-run, because a test that cannot see the mutation is not testing the rule.

- [ ] **Step 8: Run the gate and commit**

```bash
cargo fmt --all
git add src/cli.rs src/app/batch.rs
bash .githooks/pre-commit > /tmp/pc.txt 2>&1; echo "EXIT=$?"; tail -20 /tmp/pc.txt
git commit -F - <<'MSG'
Honor a deny flag in the signaling, and never a permit
MSG
rm -f /tmp/pc.txt
```

---

### Task 3: The REST runtime gate

**Files:**
- Modify: [`src/output/api.rs`](../../src/output/api.rs) (router at line 252, handlers alongside `get_dialog_vcon`)
- Test: [`src/output/api.rs`](../../src/output/api.rs) tests module

**Interfaces:**
- Consumes: nothing from earlier tasks.
- The gate landed in [`src/output/persistence.rs`](https://github.com/NormB/sipnab/blob/main/src/output/persistence.rs) rather than inside
  [`src/output/api.rs`](https://github.com/NormB/sipnab/blob/main/src/output/api.rs) as planned. The exporter has to consult it, and the
  exporter exists in builds without the `api` feature; a type declared
  behind that feature would have made the check conditional on a REST
  server nobody started.
- The plan stopped at the routes, which would have shipped a control that
  reported a closed gate while `export_vcon` went on writing. The gate is
  threaded through `generate_reports` to `export_vcon`, above both export
  forms.
- Produces: `pub struct PersistenceGate { enabled: std::sync::atomic::AtomicBool, authorized: bool }` with `fn new(authorized: bool) -> Self`, `fn writes_permitted(&self) -> bool`, `fn set(&self, want: bool) -> bool` returning what the gate now reports.

- [x] **Step 1: Write the failing test**

```rust
#[test]
fn the_gate_can_close_what_the_command_line_opened() {
    let gate = PersistenceGate::new(true);
    assert!(gate.writes_permitted());
    assert!(!gate.set(false));
    assert!(!gate.writes_permitted(), "the gate closed");
}

#[test]
fn the_gate_cannot_open_what_the_command_line_never_authorized() {
    let gate = PersistenceGate::new(false);
    assert!(!gate.writes_permitted());
    assert!(!gate.set(true),
        "enabling on a run with no persistence flags must report that it \
         enabled nothing, not report success");
    assert!(!gate.writes_permitted());
}
```

- [x] **Step 2: Run and watch it fail**

Run: `cargo test --features api,vcon --lib persistence_gate`
Expected: FAIL — `cannot find type PersistenceGate`.

- [x] **Step 3: Implement**

```rust
/// Whether content may still reach disk on this run.
///
/// `authorized` comes from the command line and never changes. `enabled` is
/// what an operator can move. The gate narrows and never widens: a run
/// invoked without persistence flags has nothing for the API to switch on.
pub struct PersistenceGate {
    enabled: std::sync::atomic::AtomicBool,
    authorized: bool,
}

impl PersistenceGate {
    #[must_use]
    pub fn new(authorized: bool) -> Self {
        Self {
            enabled: std::sync::atomic::AtomicBool::new(authorized),
            authorized,
        }
    }

    #[must_use]
    pub fn writes_permitted(&self) -> bool {
        self.authorized && self.enabled.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Move the gate, returning what it now reports.
    pub fn set(&self, want: bool) -> bool {
        self.enabled
            .store(want && self.authorized, std::sync::atomic::Ordering::Relaxed);
        self.writes_permitted()
    }
}
```

- [x] **Step 4: Run the tests**

Run: `cargo test --features api,vcon --lib persistence_gate`
Expected: 2 passed.

- [x] **Step 5: Wire the routes**

At [`src/output/api.rs:262`](https://github.com/NormB/sipnab/blob/main/src/output/api.rs#L262), beside the existing feature-gated vCon route:

```rust
    let router = router
        .route("/v1/persistence", get(get_persistence).post(set_persistence));
```

`get_persistence` returns `{"enabled": <writes_permitted>, "authorized": <authorized>}`. `set_persistence` reads `{"enabled": bool}` and answers with the same shape, so a caller who tried to enable an unauthorized run sees `enabled: false, authorized: false` rather than a bare 200.

- [x] **Step 6: Test the route behind auth**

```rust
#[tokio::test]
async fn enabling_persistence_on_an_unauthorized_run_reports_that_it_did_nothing() {
    let app = test_app_with_gate(PersistenceGate::new(false));
    let res = post_json(&app, "/v1/persistence", r#"{"enabled":true}"#).await;
    assert_eq!(res.status(), 200);
    assert_eq!(res.json()["enabled"], false);
    assert_eq!(res.json()["authorized"], false);
}

#[tokio::test]
async fn the_persistence_route_requires_the_api_key() {
    let app = test_app_with_gate(PersistenceGate::new(true));
    let res = post_json_without_key(&app, "/v1/persistence", r#"{"enabled":false}"#).await;
    assert_eq!(res.status(), 401, "a control that stops content reaching disk is not public");
}
```

- [x] **Step 7: Run the gate and commit**

```bash
cargo fmt --all
git add src/output/api.rs
bash .githooks/pre-commit > /tmp/pc.txt 2>&1; echo "EXIT=$?"; tail -20 /tmp/pc.txt
git commit -F - <<'MSG'
Give an operator a gate that narrows and cannot widen
MSG
rm -f /tmp/pc.txt
```

---

### Task 4: The container says what it does not contain

**Files:**
- Modify: [`src/output/vcon.rs`](../../src/output/vcon.rs) (`CaptureCompleteness` at line 541, the prose builder near line 1618)
- Test: [`src/output/vcon.rs`](../../src/output/vcon.rs) tests module

**Interfaces:**
- Consumes: `PersistenceGate` from Task 3.
- The plan added two fields and a clause and stopped there, which left the
  values with no source. `PersistenceGate` gained a sticky
  `closed_during_run` -- the container is written at the end of a run, by
  which time the gate may be open again -- and `apply_deny_filter` now
  returns what it removed, a count that cannot be recovered later.
- Step 5 cited `no_container_emits_an_explicit_null` by name. That filter
  matched zero tests and reported success, which is what a filter matching
  nothing always does -- but the conclusion drawn from it, that no such test
  existed, was WRONG. The test is `a_written_container_emits_no_explicit_null`
  in [`src/app/batch.rs`](https://github.com/NormB/sipnab/blob/main/src/app/batch.rs),
  and the search that missed it looked only in [`src/output/vcon.rs`](https://github.com/NormB/sipnab/blob/main/src/output/vcon.rs) and
  `tests/`. CI found it by failing.
- That test read one arbitrary file out of the export directory, so its verdict
  depended on `read_dir` order. It passed for two releases because the file it
  drew was the ANSWERED dialog; Task 1's filename change moved the failed one
  first and the assertion fired. It now checks every container, and it checks
  the vCon module's own fields rather than raw-substring-matching a file that
  also carries a `SignalingDiagnosis` -- a model whose seven always-run
  detections document `null` as "checked, not found", the opposite convention
  for the same reason.
- Produces: two new `CaptureCompleteness` fields: `pub gate_closed_during_run: bool`, `pub dialogs_suppressed_by_deny: u64`.

- [x] **Step 1: Write the failing test**

```rust
#[test]
fn a_run_whose_gate_closed_says_so_in_the_completeness_caveat() {
    let mut facts = clean_facts();
    facts.gate_closed_during_run = true;
    let v = export_with(&dialog_with(&[response(200, "OK")]), &facts);
    let json = serde_json::to_string(&v).expect("serializes");
    assert!(json.contains("the operator closed the persistence gate"),
        "a run that stopped writing mid-capture does not reproduce from the \
         capture alone, and the container has to say so: {json}");
}

#[test]
fn a_deny_flag_is_recorded_rather_than_leaving_a_silent_absence() {
    let mut facts = clean_facts();
    facts.dialogs_suppressed_by_deny = 3;
    let v = export_with(&dialog_with(&[response(200, "OK")]), &facts);
    let json = serde_json::to_string(&v).expect("serializes");
    assert!(json.contains("3 dialog(s) carried a deny flag"),
        "absence reading as 'nothing happened' is the failure this module \
         exists to refuse: {json}");
}
```

- [x] **Step 2: Run and watch both fail**

Run: `cargo test --features vcon --lib completeness_caveat`
Expected: FAIL — unknown fields.

- [x] **Step 3: Add the fields and the prose**

Add both fields to `CaptureCompleteness`. In the note builder near line 1618, append:

```rust
    if completeness.gate_closed_during_run {
        note.push_str(
            " — INCOMPLETE: the operator closed the persistence gate during \
             this run, so containers are absent for reasons this capture does \
             not explain.",
        );
    }
    if completeness.dialogs_suppressed_by_deny > 0 {
        note.push_str(&format!(
            " {} dialog(s) carried a deny flag and produced no content. That is \
             a decision recorded here, not a gap in what sipnab saw.",
            completeness.dialogs_suppressed_by_deny
        ));
    }
```

- [x] **Step 4: Run the tests**

Run: `cargo test --features vcon --lib completeness_caveat`
Expected: 2 passed.

- [x] **Step 5: Confirm no explicit nulls appeared**

The module's standing contract is "absent, never null". Adding fields to a
serialized struct is exactly how a null arrives.

Run: `cargo test --features vcon --lib no_container_emits_an_explicit_null`
Expected: PASS. If it fails, the new fields need `#[serde(skip_serializing_if)]`.

- [x] **Step 6: Run the gate and commit**

```bash
cargo fmt --all
git add src/output/vcon.rs
bash .githooks/pre-commit > /tmp/pc.txt 2>&1; echo "EXIT=$?"; tail -20 /tmp/pc.txt
git commit -F - <<'MSG'
Record the two ways a container deliberately does not exist
MSG
rm -f /tmp/pc.txt
```

---

### Task 5: Documentation and the ratchet

**Files:**
- Modify: [`docs/cli-reference.md`](../../docs/cli-reference.md), [`docs/vcon.md`](../../docs/vcon.md), [`docs/rest-api.md`](../../docs/rest-api.md)
- Modify: [`website/templates/index.html`](../../website/templates/index.html)
- Modify: [`CHANGELOG.md`](../../CHANGELOG.md)

- [x] **Step 1: Document the three flags**

Add `--export-vcon-when`, `--export-vcon-dir` and `--content-deny-header` to
the [`docs/cli-reference.md`](../../docs/cli-reference.md) table, matching the existing row style. State on
`--content-deny-header` that it denies only and never permits, because a reader
who assumes symmetry will look for the permit flag.

- [x] **Step 2: Document the REST route**

Add `/v1/persistence` to [`docs/rest-api.md`](../../docs/rest-api.md), both verbs, with the
`{"enabled", "authorized"}` shape and the note that enabling cannot exceed what
the command line authorized.

- [x] **Step 3: Add the changelog entry**

Under `## [Unreleased]`, a `### Added` section describing conditional creation
and the narrowing rule.

- [x] **Step 4: Regenerate both mirrors**

```bash
python3 scripts/build-site-internals.py
python3 scripts/build-site-pages.py
```

- [x] **Step 5: Move the homepage ratchet with attribution**

```bash
git diff --cached | grep -c "^+.*#\[test\]"
```

Add that number to the current count and update BOTH places in
[`website/templates/index.html`](../../website/templates/index.html) — the `data-count` attribute and the prose. If
the delta does not match the number of tests you added, stop: a count moving
the wrong way is the alarm the gate exists for.

- [x] **Step 6: Run the prose gates directly**

```bash
vale $(sed 's/#.*//' .config/vale-paths.txt | tr '\n' ' ')
codespell docs/ README.md
```

Expected: 0 errors. Vale rejects passive voice and semicolons.

- [x] **Step 7: Run the gate and commit**

```bash
git add docs/cli-reference.md docs/vcon.md docs/rest-api.md CHANGELOG.md \
        website/templates/index.html website/content/ website/static/llms-full.txt
bash .githooks/pre-commit > /tmp/pc.txt 2>&1; echo "EXIT=$?"; tail -20 /tmp/pc.txt
git commit -F - <<'MSG'
Document conditional vCon creation and the narrowing rule
MSG
rm -f /tmp/pc.txt
```

---
