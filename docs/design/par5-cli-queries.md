# CLI query flags

How a one-shot CLI query flag is built, so that it answers exactly what the REST
route and the MCP tool for the same capability answer. The flags close the CLI
gaps in the [surface-capability matrix](surface-capability-matrix.md) (PAR5 in
[surface-parity-definition.md](surface-parity-definition.md)).

## The rule: one core function, three views

Every query capability has one core function that computes the answer from the
dialog and stream stores. The REST route and the MCP tool already call it and
serialize its result. A CLI query flag calls the same function and prints the
same value:

- by default, as a table for a person at a terminal;
- under `--markdown`, as the same table in Markdown;
- under `--json`, as **one JSON object on the last line of stdout**, with
  exactly the shape the REST route returns, `capture_identity` included: the
  CLI stamps the run's own identity (`QueryContext::capture_identity`), the
  one a server started by the same run would stamp;
- under `--json-pretty`, as the same object indented, the precedence
  `--call-report` applies.

So `sipnab -N -I x.pcap --<query> --json | tail -1` and
`curl …/v1/<route>` produce the same JSON for the same capture. A CLI flag never
computes its own answer; if a computation is not yet a shared function, the
first step is to move it out of the route or tool so all three call it. The
model is `--hep-senders`: `capture::hep_roster::senders_report` builds the
answer, `GET /v1/hep/senders` and the `hep_senders` tool serialize it, and
`app::batch::print_hep_senders` prints it.

Every query honors the one compiled filter: `--filter`, the diagnostic alias
flags (`--problems` and the rest) and the `--since`/`--until` window, ANDed by
`app::bootstrap::build_filter_expr` (the window through
`FilterExpr::with_time_window`, evaluated by `cursor::in_time_window`). A query reads its dialogs through
`QueryContext::selection`, which applies that filter, so it narrows a query
exactly as it narrows `--report`.

## Declaring a flag: the one-shot registry

[`src/cli/one_shot.rs`](https://github.com/NormB/sipnab/blob/main/src/cli/one_shot.rs) defines the declaration each query flag makes:

```rust
pub struct OneShot {
    pub name: &'static str,     // "--talkers", named in refusals
    pub active: bool,           // this command line set the flag
    pub implies_no_tui: bool,   // the flag makes the run headless by itself
    pub owns_stdout: bool,      // the answer is written to stdout
}
```

Each query group is a `clap::Args` struct in its own file, already flattened
into `Cli`, and each exposes:

```rust
pub fn one_shots(&self) -> Vec<OneShot>
```

`Cli::one_shots(&self) -> Vec<OneShot>` concatenates the four groups.
`Cli::normalize` and `Cli::validate` read that list and nothing else:

| Declaration | Effect | Where |
|---|---|---|
| `active && implies_no_tui` | the run is headless, as with `--call-report` | `normalize`, through `one_shot::any_implies_no_tui` |
| `active && !implies_no_tui` | refused without `-N`, as with `--report` | `validate`, through `one_shot::needing_no_tui` |
| `active && owns_stdout` | refused beside `--mcp` on stdio, whose wire is stdout | `validate`, through `one_shot::writing_stdout` |

Adding a flag is a field in the group's struct and one entry in its
`one_shots`. Nobody edits `Cli`, `normalize` or `validate`.

## Answering: the dispatcher

[`src/app/queries/mod.rs`](https://github.com/NormB/sipnab/blob/main/src/app/queries/mod.rs) holds the dispatcher. Two entry points, each called
from one place:

```rust
pub fn render(ctx: &QueryContext<'_>) -> bool;   // end of the report chain
pub fn startup(cli: &Cli) -> Option<i32>;        // run_startup_commands
```

`render` is the last link of the report chain in `app::batch::generate_reports`.
That chain runs on every headless path: `-I` files, live `-d` capture and
`--hep-listen` reach it through `BatchRunner::run_loop` and
`write_end_reports`, and `--cores` through `report_parallel_run`. It returns
`false` when a query that was asked for could not be answered or written, which
exits 1. `startup` runs before a capture opens, for the file jobs that read a
set of files rather than this run's stores; it returns the exit code when a job
ran.

A query renders from:

```rust
pub struct QueryContext<'a> {
    pub cli: &'a Cli,
    pub dialogs: &'a DialogStore,
    pub streams: &'a StreamStore,
    pub filter: Option<&'a FilterExpr>,   // the one compiled filter
    pub alias: AliasThresholds,           // cli.alias_thresholds(config)
}

impl<'a> QueryContext<'a> {
    pub fn selection(&self) -> DialogSelection<'a>;
    pub fn lint_suppressions(&self) -> Result<Option<SuppressionFile>, String>;
    pub fn capture_identity(&self) -> Option<CaptureEtag>;
    pub fn answer<T: Serialize>(
        &self,
        flag: &str,
        answer: &T,
        text: impl FnOnce(ReportFormat) -> String,
    ) -> bool;
}
```

`answer` is the output convention in one place: under `--json` it writes the
serialized answer as one line, under `--json-pretty` indented, otherwise the
table `text` renders in the `--markdown` or text format. `answer_form` reads
the flags and its pure half, `render_answer`, writes the text; both carry the
unit tests.

The answer types and the functions that build them live in
`src/output/query/`, one file per capability, outside the `api` feature so
the CLI has them in every build. `api::schema` re-exports each type under its
old name, so the OpenAPI document does not change when a type moves there.
`output::query::table` is the one table renderer the answers share.

A shared default lives beside its answer: `--timeline` with no width, REST's
`bucket_seconds` and the MCP tool's all use `DEFAULT_BUCKET_SECONDS` (60) in
`output::query::timeline`, and `bucket_width` refuses a zero width for all
three. A refusal the engine makes after reading the capture is the same on
each surface too: `sip::dialog_store::bucket_by_start` refuses a span of more
than `MAX_TIMELINE_BUCKETS` intervals, which REST answers 422, MCP refuses as
`limit_exceeded`, and `--timeline` writes to stderr before exiting 1.

A query that cannot answer prints its reason with `stderr_line!`, never through
`tracing`: the reason decides the exit code, so it must survive
`SIPNAB_LOG=off`, as `--call-report`'s unknown Call-ID does.

Under `--cores`, `--json` is refused as a per-message output unless a query
flag that writes stdout is active, because then it formats that answer.

## Which file each flag lives in

Each batch of flags owns its own files, so batches built in parallel never edit
the same lines.

| Batch | Flags | Args file | Dispatcher file |
|---|---|---|---|
| B1 aggregates | `--count-by`, `--rates-by`, `--talkers`, `--timeline`, and the shared `--top <N>` | [`src/cli/aggregate_args.rs`](https://github.com/NormB/sipnab/blob/main/src/cli/aggregate_args.rs) (`AggregateArgs`) | [`src/app/queries/b1.rs`](https://github.com/NormB/sipnab/blob/main/src/app/queries/b1.rs) |
| B2 single call | `--call-tree`, `--correlate`, `--compare-dialogs`, `--endpoint-ip`, `--endpoint-user`, `--export-audio` | [`src/cli/call_query_args.rs`](https://github.com/NormB/sipnab/blob/main/src/cli/call_query_args.rs) (`CallQueryArgs`) | [`src/app/queries/b2.rs`](https://github.com/NormB/sipnab/blob/main/src/app/queries/b2.rs) |
| B3 file jobs | `--find-in-files`, `--compare-captures`, `--vcon-validate` | [`src/cli/file_job_args.rs`](https://github.com/NormB/sipnab/blob/main/src/cli/file_job_args.rs) (`FileJobArgs`) | [`src/app/queries/b3.rs`](https://github.com/NormB/sipnab/blob/main/src/app/queries/b3.rs) (`startup`) |
| B4 gates and relay | `--expect`, `--relay-holdings` | [`src/cli/gate_args.rs`](https://github.com/NormB/sipnab/blob/main/src/cli/gate_args.rs) (`GateArgs`) | [`src/app/queries/b4.rs`](https://github.com/NormB/sipnab/blob/main/src/app/queries/b4.rs) |

`--top <N>` belongs in `AggregateArgs`, beside the ranked answers it bounds. It
arrived with its first reader, `--count-by`, and requires it, so the CLI never
carries a flag that nothing reads. A later ranked flag that reads
`cli.aggregate_args.top` widens that requirement to itself. The default, 50, is
`output::query::DEFAULT_ROWS`, the page REST returns when `top_n` is not given.
The order and the cut are `output::query::aggregate::rank_by_count`, which
`--count-by`, `GET /v1/aggregate`, `GET /v1/dialogs/rates` and the MCP
`aggregate_dialogs` and `group_dialogs` tools all apply. `--rates-by` and the
rates route and tool share `output::query::rates`: its dimension set, its
metric-list rule (`wanted_metrics`) and the answer. The CLI takes no metric
list and computes every metric, which a reader narrows with `jq`.
`--talkers` and the talkers route share `output::query::talkers`, whose
`rank` (dialogs, then messages, then the key) and `share_pct` the MCP
`top_talkers` tool also reads; `--prefix-digits` is held to the zero rule
`TalkerDimension::parse` applies to REST's `prefix_digits`.

A query about named calls (`--call-tree`, `--correlate`, `--compare-dialogs`) reads that call whatever the
run's filter admits, as `--call-report` does, and an unknown Call-ID fails the
run with `--call-report`'s message (`queries::call_not_found`). Where REST
caps a list by its row cap, the CLI applies the cap a server started by the
same run would (`QueryContext::row_cap`).

The endpoint rollup (`--endpoint-ip`, `--endpoint-user`) covers every dialog of
the capture, as `GET /v1/endpoints` and the MCP `describe_endpoint` tool do:
`crate::sip::endpoint::describe` reads the stores whole, so no surface narrows
it by a filter. Its answer is the untyped JSON the route returns
(`output::query::endpoint::EndpointAnswer`), and the CLI's text is drawn from
the report the JSON is built from.

`--export-audio` writes a file rather than printing an answer, so its JSON is
its own: the `path` and `summary` the MCP `export_audio` tool answers with, and
the `partial` and `dialog_seen` facts REST sends as headers beside the WAV.
The bytes come from `rtp::audio_export::decode_dialog_audio`, and the file and
its summary from `write_dialog_audio`, which the MCP tool's export uses too.
The flag is consent to retain audio for the run (`audio_retention_wanted`).

A file job (`--vcon-validate`) has no stores, so it writes its answer with
`queries::write_answer`, the convention `QueryContext::answer` delegates to.
Its exit status carries the verdict: `0` valid, `3` invalid (the lint gate's
"the tool worked, the input is non-conformant"), `1` not checked.

`--compare-captures` reads the config itself (`bootstrap::load_config`), so the
two files are read with the pipeline options a run started by the same command
line would use, which are the ones a REST server started by it would use. The
dialog and stream caps are `output::query::capture_compare::compare_files`'s,
shared with REST. The engine's summary has two forms: a server's adds that
neither file is the capture it holds (`NOT_THE_HELD_CAPTURE`), and the command
line's, which holds no capture, does not.

`--find-in-files` runs the sweep the MCP `find_in_captures` tool runs on a job
thread, `capture::sweep::sweep_files`, moved out of `mcp::sweep` so a build
without MCP has it; the tool's job keeps its cancel, deadline and file limit,
and the CLI stops only on the process's own stop. The filter is the run's
compiled filter (`bootstrap::build_filter_expr`), and each file's scratch
stores hold what an MCP server started by the same command line would hold
(`Cli::mcp_row_cap`).

Beyond those files, each flag edits only lines that belong to it:

- its own `gap:` cell in [`docs/design/surface-capability-matrix.md`](https://github.com/NormB/sipnab/blob/main/docs/design/surface-capability-matrix.md), flipped to
  the flag's spelling, and its own line in `GAP_LEDGER` in
  [`tests/surface_capability_matrix_test.rs`](https://github.com/NormB/sipnab/blob/main/tests/surface_capability_matrix_test.rs), deleted. The ledger is a list of
  `(capability, surface)` names rather than a count, so two batches never edit
  the same line, and the gate still fails, naming the row, when a gap appears or
  disappears without its line changing;
- its own `###` subsection under `## Queries` in [`docs/cli-reference.md`](https://github.com/NormB/sipnab/blob/main/docs/cli-reference.md), its
  rows, and its regenerated mirrors.

## Testing a query against REST and MCP

[`tests/support/surface_parity.rs`](../../tests/support/surface_parity.rs) runs
one capture through all three surfaces: the CLI binary, a
`sipnab -N -I <pcap> --api 127.0.0.1:0` server, and an MCP session. It
normalizes the MCP answer to the REST shape by dropping the fields only MCP
carries (`capture_identity`, `timing_clock`, and the untrusted-content note,
which is a second content block) and unwrapping fenced values. A query's parity
test asserts that the three agree on the same capture;
[`tests/cli_time_window_test.rs`](../../tests/cli_time_window_test.rs) is the
first one.
