# Large-capture memory and silent dialog loss

**Status:** DESIGN. Nothing here is implemented.
**Measured against:** `sipnab 0.5.71 (f9ae16ff-dirty)`, release build, on
`/home/gator/pcaps` — 15 files, 1,383 MB, 4,532,272 packets. Every number below
was produced by a command reproduced in the appendix.
**Scope:** offline analysis of capture sets larger than one file. Live capture
shares the stores and inherits the conclusions, but the pre-flight and two-pass
sections apply only to files.

## The claim this document exists to test

A 1.3 GB capture set analyses in 4 seconds and 297 MiB. That reads like
headroom. It is not: it is one point on a line whose slope has nothing to do
with the 1.3 GB, and the line runs out at a call volume this tool is expressly
built to handle. When it runs out, the tool discards the oldest calls, prints a
complete-looking report, and exits 0.

The rest of this document establishes the slope, says where the line ends, and
ranks what to do about it.

## 1. What was measured, and how

### 1.1 The corpus is two captures, not one

`capinfos` on the directory shows the set is two unrelated runs that happen to
share a directory:

| set | files | bytes | packets | span | dialogs | SIP messages | RTP streams |
|---|---|---|---|---|---|---|---|
| `tg.pcap0`–`tg.pcap9` | 10 | 921.4 MB | 3,406,114 | 11:43:54.272 → 11:45:41.405 (107.13 s) | 18,241 | 82,324 | 1,213 |
| `direct-01.pcap0`–`pcap4` | 5 | 461.9 MB | 1,126,158 | 13:35:49.518 → 13:40:48.259 (298.74 s) | 707 | 2,558 | 247 |
| both | 15 | 1,383.3 MB | 4,532,272 | — | 18,948 | 84,882 | 1,460 |

18,241 + 707 = 18,948 exactly, so the two sets share no Call-ID and the combined
figure is a clean sum. The `tg` ring buffer has wrapped — `tg.pcap7` holds the
oldest packets and `tg.pcap6` the newest — which is the case
`src/capture/input_set.rs` was written for and which its module doc describes at
lines 12–17.

That table is the first finding, and it is the one that dismantles "1.3 GB of
capture":

> **921 MB produced 18,241 dialogs. 462 MB produced 707.** Nineteen point eight
> dialogs per megabyte against one point five — a factor of thirteen at
> comparable file sizes.

The difference is not subtle or corpus-specific, and the packet mix says why.
Of `tg`'s 3,406,114 packets, 2,846,542 (83.6%) classified as RTP and 82,324
(2.4%) as SIP; of `direct-01`'s 1,126,158, 742,241 (65.9%) were RTP and 2,558
(0.2%) SIP. Capture files are overwhelmingly media, and media is bounded per
call: G.711 at 8,000 Hz (RFC 3551 §4.5.14) packetised at 20 ms is 50
packets/second/direction, which is what the `--report` stream table shows —
1,827 packets over 37 s and 3,407 over 68 s, both 49–50 pps. Signalling is a
handful of packets per call regardless of how long the call runs. **Bytes on
disk measure how long the calls were. Retention measures how many there were.**
Those are independent, and a pre-flight built on file size is predicting the
wrong quantity (section 5 returns to this).

### 1.2 Method for the memory model

Peak RSS is `Maximum resident set size` from `/usr/bin/time -v`, which is the
kernel's high-water mark for the process. Two sweeps were run, each holding
everything constant but one variable, so the coefficients are slopes rather than
ratios of a single point.

**Sweep A — vary the dialog cap, hold the input fixed.** `--limit N` for N from
500 to 100,000 over all 15 files, `--cores 1`:

| `--limit` | dialogs retained | peak RSS (KB) |
|---|---|---|
| 500 | 496 | 99,652 |
| 1,000 | 997 | 104,832 |
| 2,500 | 2,489 | 125,028 |
| 5,000 | 4,959 | 149,960 |
| 10,000 | 9,965 | 210,212 |
| 15,000 | 14,908 | 262,144 |
| 18,948 | 18,948 | 301,956 |
| 30,000 | 18,948 | 302,244 |
| 100,000 | 18,948 | 303,616 |

The retained count sits a little under the cap because `evict_oldest` drains in
batches of `max_dialogs / 100` — its doc comment at
`src/sip/dialog_store.rs:770-772` says so: "The store may briefly sit up to
cap/100 below the cap; the cap remains a hard upper bound". Above 18,948
the curve is flat, which confirms the cap is the only thing being varied.

Marginal cost across the linear region is **10.2 to 11.3 KB per retained
dialog**, consistent across every adjacent pair.

**Sweep B — vary the per-dialog message cap, hold the dialog count fixed.**
A config file setting `[limits] max_messages_per_dialog`, same 15 files, 18,948
dialogs every time. Retained messages are computed exactly as
`Σ min(msgs_in_dialog, cap)` from the `--report` table:

| `max_messages_per_dialog` | retained messages | peak RSS (KB) |
|---|---|---|
| 1 | 18,937 | 165,816 |
| 2 | 37,858 | 208,256 |
| 4 | 66,838 | 264,152 |
| 8 | 79,507 | 292,120 |
| 50 | 84,836 | 303,632 |
| 500 | 84,836 | 304,216 |

Least squares over those six points: `RSS_KB = 2.0726 × messages + 127,586`,
i.e. **2,122 bytes per retained message**. The two-point endpoint estimate
(cap 1 against cap 500) gives 2,151 bytes, so the fit is not being carried by
one point.

### 1.3 The model

Subtracting a run with `--no-dialog --no-rtp` (91,360 KB) and one with
`--no-dialog` alone (92,888 KB) separates the terms:

```
peak_RSS  ≈  pipeline
           + 1.83 KB × dialogs_retained
           + 2.07 KB × messages_retained
```

Checked against the full run: `92,888 + 1.83×18,948 + 2.072×84,836 = 303,342 KB`
against a measured 303,108–303,932 KB across repeats. Within 0.3%.

The `pipeline` term is not a constant — it is the cost of pulling packets
through the capture channel, and it scales with packets read, not with anything
retained. Adding the BPF filter `port 5060` (which libpcap applies before
sipnab sees a packet) drops the same run to a 9,088 KB floor with
`--no-dialog --no-rtp`, and the model then predicts the dialog store almost
exactly: measured 221,056 KB with dialogs on, predicted
`9,088 + 1.83×18,948 + 2.072×84,836 = 219,542 KB`. Within 0.7%.

**What the coefficients mean.** `SipDialog` holds
`pub messages: Vec<SipMessage>` (`src/sip/dialog.rs:111`), and `SipMessage`
(`src/sip/message.rs:34`) holds both the raw bytes —

```rust
    /// Full raw message bytes as captured (refcounted view of the
    /// packet payload buffer — cloning a SipMessage does not copy it).
    pub raw: bytes::Bytes,
```

— and an eagerly parsed `pub headers: Vec<SipHeader>` where each `SipHeader`
carries `value: String` (`src/sip/message.rs:20-26`). Every header value is
therefore resident twice: once inside `raw`, once as an owned `String` with its
own allocation. 2.1 KB per message for traffic whose median message is a few
hundred bytes is that duplication plus per-allocation overhead. This paragraph
is an explanation of the measurement, not a second derivation of it — no attempt
was made to attribute the 2.1 KB to individual fields, and doing so would need
an allocator profile that has not been run.

### 1.4 What did not matter

**`max_messages_per_dialog = 500` never engaged.** Across 18,948 dialogs the
mean is 4.48 messages and the maximum is 44. Sweep B flattens between cap 50 and
cap 500 for exactly that reason. The distribution is bimodal on registration and
call traffic — 4,406 dialogs at 2 messages, 10,850 at 4, 1,748 at 8 — and
nothing in this corpus comes within an order of magnitude of the cap. That cap
defends against a pathological single dialog (a load generator reusing one
Call-ID, a retransmission storm), which is a real threat, but it is not the
retention lever for ordinary traffic and tuning it down would be tuning the
wrong knob.

**RTP streams were negligible.** 1,460 streams cost 1,528 KB between the
`--no-dialog --no-rtp` and `--no-dialog` runs, roughly 1 KB each, against 1,460
streams at a 50,000 cap. In batch mode `src/app/batch.rs:512` sets
`ss.set_audio_capture(false)`, so no audio frames are retained. The
`max_audio_frames` limit (default 1,500/stream) applies only to the TUI path
(`src/app/tui_mode.rs:147`) and **its memory cost is unknown** — it was not
measured here and should not be assumed small.

**`--dialog-track branch` more than doubles retention.** The same input tracked
by transaction yields 40,941 units against 18,948 (RSS 340,048 KB against
302,188 KB). Anyone who switches modes to investigate a proxy has moved 2.16×
closer to the cap without changing a limit.

## 2. Where the caps actually are

The obvious answer — the shipped caps live in `src/config.rs` under `[limits]`,
where `dialog_limit` is the one to tune — is what the config file, the config
reference and the example `sipnabrc` all say. It is wrong, in a way that matters
more than any particular number.

**`[limits] dialog_limit` does nothing.** The field exists
(`src/config.rs:374`), is validated (`src/config.rs:401-405`, rejecting zero
with a message naming the key), is documented as the way to tune RAM
(`docs/config-reference.md:360`: `dialog_limit = 50000  # Max tracked dialogs
(tune for RAM)`), ships in `contrib/sipnabrc.example:50` as `dialog_limit =
10000` — and is never read. `src/app/bootstrap.rs:874-892` applies exactly three
`[limits]` keys, none of them this one:

```rust
    if let Some(v) = loaded.config.limits.max_header_line {
        crate::sip::parser::set_parser_limits(
    ...
    if let Some(v) = loaded.config.limits.max_messages_per_dialog {
        crate::sip::dialog_store::set_max_messages_per_dialog(v as usize);
    }
```

`max_audio_frames` is applied at `src/app/batch.rs:507` and
`src/app/tui_mode.rs:147`. That is the complete set. `dialog_limit`,
`max_streams`, `max_reassembly` and `hep_rate_limit` are parsed, validated,
documented and inert.

Demonstrated rather than inferred: a config containing `dialog_limit = 100` and
`max_streams = 10` loads (the run logs `Loaded config from cfg_dead.toml`) and
then reports `dialogs=18948 streams=1460`. Both keys were ignored.

**The real cap is `--limit`, default 100,000** (`src/cli.rs:636-643`):

```rust
    #[arg(
        help_heading = "Dialog",
        short = 'l',
        long = "limit",
        value_name = "N",
        default_value = "100000"
    )]
    pub limit: u64,
```

It reaches the store through `src/app/batch.rs:181` (`max_dialogs: cli.limit as
usize`). The RTP cap is `--max-streams`, default 50,000
(`src/cli.rs:685-687`). Rotation is on by default —
`src/cli.rs:1378-1379` is `pub fn rotate_enabled(&self) -> bool { !self.no_rotate }`
— so the default disposal policy is drop-oldest.

**`--limit` bounds cumulative dialogs, not concurrent ones.** Nothing removes a
completed dialog. `compact_idle` (`src/sip/dialog_store.rs:260`) trims an idle
dialog's *messages* to the last 20 but leaves the dialog itself; `retain` and
`clear` have no caller in `src/app/`. So in an offline run the store grows
monotonically with capture duration, and the cap is reached after N total calls
have been observed, not N simultaneous ones. This is the single most
counter-intuitive fact in this document: `--limit 100000` on a proxy carrying
200 concurrent calls does not mean "500× headroom", it means "the first drop
happens after the hundred-thousandth call".

### 2.1 When each cap engages

Combining the measured densities with the measured coefficients:

| cap | shipped value | engages at | RSS when it engages | wall-clock to reach it |
|---|---|---|---|---|
| `--limit` | 100,000 dialogs | 100,000 cumulative dialogs | ≈1.15 GiB | 9.8 min at `tg`'s 170.3 dialogs/s; 11.7 h at `direct-01`'s 2.37/s |
| `--limit` under `--dialog-track branch` | same | 100,000 tracked units | not measured | ≈4.5 min at `tg`'s rate, from the 2.16× unit ratio |
| `--max-streams` | 50,000 streams | 50,000 concurrent-ish streams | ≈50 MB at the measured ~1 KB/stream | not reached in this corpus |
| `max_messages_per_dialog` | 500 | any single dialog past 500 messages | — | never in this corpus (max 44) |

The RSS figure for `--limit` is the model extrapolated to 100,000 dialogs at
`tg`'s density of 4.51 messages/dialog:
`92,888 + 1.83×100,000 + 2.072×451,000 = 1,210,360 KB`. It is an extrapolation
roughly 5× beyond the measured range, so treat it as an order of magnitude, not
a budget. What it does establish confidently is the shape: **the default limit
is a ~1 GB commitment, and a 2 GB container will be killed by the OOM killer
before the eviction path is ever reached.** On that host the cap is not the
safety mechanism; the OOM killer is.

## 3. The central defect: the loss is invisible, and worse than reported

`evict_oldest` is `src/sip/dialog_store.rs:779-782`:

```rust
    fn evict_oldest(&mut self) {
        let batch = (self.max_dialogs / 100).max(1).min(self.dialogs.len());
        self.dialogs.drain(0..batch);
    }
```

`dialogs` is an `IndexMap` in insertion order (`src/sip/dialog_store.rs:136`),
so index 0 is the oldest dialog seen. Draining from the front discards the
earliest calls.

A reader grepping for instrumentation finds `capacity_dialogs_dropped` and
concludes eviction is counted but unreported. Counted-but-unreported is true as
far as it goes — the field is declared at `src/sip/dialog_store.rs:151`, the accessor
is `total_capacity_dialogs_dropped` at `:295`, and every one of its five callers
(`:1061`, `:1068`, `:1075`, `:1081`, `:1084`) sits after the single
`#[cfg(test)]` at `:886`. `docs/design/backlog.md:127` records it landing as
"[observability] no-rotate capacity drops are uncounted … **Done:** … a lifetime
`capacity_dialogs_dropped` counter with a public getter and merge accumulation",
and nothing ever consumed it.

But the situation is worse than "counted and unread", and the difference decides
the design. Look at where the increment sits (`src/sip/dialog_store.rs:421-430`):

```rust
            if self.dialogs.len() >= self.max_dialogs {
                if self.rotate {
                    self.evict_oldest();
                } else {
                    // Full and not rotating: this new Call-ID is dropped.
                    // Count it — the observability sibling of idle eviction.
                    self.capacity_dialogs_dropped += 1;
                    return;
                }
            }
```

The counter is in the `else`. It only ever moves under `--no-rotate`. **On the
default path — rotate on, drop the oldest — nothing is counted at all.** The
counter that exists measures the disposal policy nobody uses; the policy
everybody uses has no counter. A future contributor grepping for
`capacity_dialogs_dropped` and finding it incremented could reasonably conclude
eviction is instrumented. It is not.

The same holds for `total_idle_messages_evicted` (`:284`), read only at `:1246`
and `:1248` inside the test module. Its per-sweep sibling `CompactStats` does
reach production, but only as `tracing::debug!` at `src/app/batch.rs:963-967` —
invisible at the default log level.

`StreamStore` has no loss counter either. `src/rtp/stream_store.rs:98` tracks
`evict_shift_work`, which counts *entries shifted while evicting* — a cost probe
for a past O(n²) regression, not a count of what was lost. The batched
SDP-endpoint eviction at `src/rtp/stream_store.rs:423-426` increments nothing.

### 3.1 Demonstrated end-to-end

Running the same 15 files at `--limit 5000`: the store keeps 4,959 dialogs, the
report prints 4,959 rows, the three Call-IDs that head the unrestricted report
(`2f530b7f-…`, `7423e5f7-…`, `7d51bac0…`) are absent, stderr says nothing about
eviction, and the process exits 0. The summary line
(`src/app/batch.rs:1305-1309`) reports `4532272 packets captured, 84882 SIP
messages` — identical to the full run, because the packet counters are upstream
of the store. Every number an operator would sanity-check against agrees with a
complete analysis.

This is precisely the post-mortem failure: "what happened at 14:00?" is answered
from a dataset whose 14:00 was evicted first, and nothing in the output
distinguishes "no signalling matched" from "the signalling was thrown away".

### 3.2 A second, undocumented loss channel: speed-dependent results

`src/app/batch.rs:927` sets `let sweep_interval = std::time::Duration::from_secs(5);`
and `src/app/batch.rs:961` calls
`dialog_store.write().compact_idle(chrono::Utc::now())` on each sweep.
`compact_idle` compares that wall-clock `now` against `dialog.updated_at`, which
is a *packet* timestamp. When yesterday's capture is replayed today, every
dialog is more than `IDLE_COMPACT_AFTER` (10 minutes,
`src/sip/dialog_store.rs:170`) idle by that comparison, and each is trimmed to
`KEEP_MESSAGES_PER_IDLE_DIALOG` = 20 messages (`:173`).

Whether that fires at all depends on how fast the host reads the file, because
the 5-second interval is wall clock. Measured on the same input and the same
commit:

| build | wall | peak RSS | dialogs | retained messages | max messages in any dialog |
|---|---|---|---|---|---|
| release | 3.97 s | 303,108 KB | 18,948 | 84,836 | 44 |
| debug | 29.36 s | 318,768 KB | 18,948 | 84,522 | 24 |

The release run finishes before the first sweep. The debug run does not, loses
314 messages, and its longest ladder is truncated from 44 rungs to 24. **Same
bytes, same code, different answer, decided by CPU speed and page-cache state.**
For an offline analyser that is a reproducibility defect independent of
capacity: a colleague re-running the command on a slower laptop gets a different
call flow and has no way to know.

Rescuing this does not require a policy debate. Offline replay should compare
against the capture clock rather than the wall clock, or skip idle compaction
entirely when the source is a file — the whole point of `compact_idle` is
bounding a *long-running live process*, and a file read has a known end.

### 3.3 Two adjacent defects found while measuring — both since fixed

Neither was a memory problem and both were out of scope for this document, but
both lived on the large-capture path and both produced complete-looking wrong
answers, so they were put on the record here. **Both shipped fixes in 0.5.72**;
the record is kept, with the outcome, rather than deleted.

**`--cores N > 1` did not read a multi-file set. Fixed in 0.5.72.** With the
0.5.71 binary that produced the measurements above,
`-I /home/gator/pcaps --cores 4` failed with `multi-core reconstruction failed:
Failed to open pcap file '/home/gator/pcaps': … Is a directory` (exit 1, so at
least it was loud). Given two files explicitly, `-I tg.pcap7 -I tg.pcap8
--cores 4` reported 2,269 dialogs and 9,041 SIP messages — byte-identical to
reading `tg.pcap7` alone — where `--cores 1` reported 4,399 and 18,009. That
form exited 0, and was the genuinely dangerous one.

The cause was that `run_cores_file` reached for the first `-I` *argument*
rather than the resolved set, and `main.rs` dispatched the mode before
`bootstrap` — discarding the resolved, timestamp-ordered list it already held.
`run_offline_parallel_file` now takes a resolved `&[PathBuf]`
([`parallel.rs`](../../src/parallel.rs)) and feeds the whole set through **one**
worker pool, so a call split across two files still shards to one worker by
host pair and reconstructs as one dialog. Error policy matches
`capture_files`: the first file's open failure is fatal, later files are
skipped with a log. Covered by `tests/multi_input_test.rs`.

The measurements in this document are all `--cores 1` and are unaffected by
either the defect or the fix.

**`DialogStore::merge` ignored capacity. Fixed in 0.5.72.** The merge insert
was an unconditional `None => { self.dialogs.insert(cid, dialog); }`. Each
`--cores` worker enforced `max_dialogs` on its own shard and the merge target
then accepted every survivor, so the post-merge store could hold up to
N × `--limit` dialogs — the setting an operator uses to bound memory, silently
multiplied by the core count. `merge` now enforces the cap in both disposal
modes and counts what it discards
([`dialog_store.rs`](../../src/sip/dialog_store.rs)), guarded by
`merge_enforces_capacity_in_both_disposal_modes`.

## 4. Options, ranked

The intuitive ordering is: make the loss visible first, because it is cheap and
stops wrong conclusions immediately; change the retention policy second;
streaming or spill third, because it is a large change. **The measurements
support that ordering rather than qualifying it**, and add two refinements.

The first is that visibility is not merely cheapest, it is a *precondition*.
Every retention policy in section 4.2 is a choice about which data to lose, and
an operator cannot choose sensibly while the tool does not report that anything
was lost. Shipping a better policy silently would replace one invisible loss
with a different invisible loss.

The second is that a fourth item outranks the third: the pre-flight estimate
(section 5) costs less than the retention work and prevents the failure rather
than reporting it. The ranking is therefore visibility, then pre-flight, then
retention policy, then larger-than-memory processing.

### 4.1 Make the loss visible

Three pieces, in increasing cost.

**Count the default path.** Today the increment sits only in the no-rotate
branch. `evict_oldest` needs to add `batch` to a counter, and the counter's
meaning has to distinguish the two disposal modes, because "dropped the newest
40 calls" and "dropped the oldest 40 calls" are different facts for a
post-mortem. Two fields, or one field plus the mode, either is fine; one
undifferentiated `dialogs_dropped` is not, because it would make a `--no-rotate`
run and a default run indistinguishable in the output. Cost: a field, an
increment, an accessor, a test.

**Warn once at the end of the run.** The repository already has this idiom and
it should be copied rather than reinvented. `src/output/group.rs:172-184`:

```rust
    /// `true` when a cap refused at least one message, so the caller can warn.
    pub fn truncated(&self) -> bool {
        self.dropped > 0
    }

    /// A one-line description of what was dropped, for a warning.
    pub fn truncation_note(&self) -> String {
        format!(
            "--group-by buffer full: {} message(s) dropped ({} group(s) refused past the \
             {MAX_GROUPS}-group cap, {MAX_BUFFERED}-message total cap). Output is incomplete.",
            self.dropped, self.dropped_groups
        )
    }
```

consumed at `src/app/batch.rs:1187-1188` as
`if buf.truncated() { tracing::warn!("{}", buf.truncation_note()); }`. A
`DialogStore::truncated()` / `drop_note()` pair warned just before the summary
block at `src/app/batch.rs:1302` is the same shape, and the note must name the
flag that fixes it (`--limit`) and say which end was lost. The precedent for
warning loudly rather than counting quietly is also in the backlog:
`docs/design/backlog.md` records `src/sip/parser.rs:279 — [silent-loss] headers
beyond MAX_HEADERS_PER_MESSAGE silently dropped without parse_error. **Done:**
… so the truncation is visible.` This is the same class of defect one layer up.

**Put it in the structured outputs.** These are the surfaces and the exact
insertion points, each of which is a typed struct or a literal that a new field
slots into:

- MCP: `StatsResponse` at `src/mcp/server.rs:458-471` already has
  `dialog_count` / `stream_count` / `orphaned_stream_count`; built at `:1241`.
- REST: the `json!` literal at `src/output/api.rs:938-945` — a `"dropped"` key
  inside the existing `"dialogs"` object.
- Prometheus: `PrometheusMetrics` at `src/output/prometheus.rs:22`, alongside
  the existing `pub capture_backpressure_blocks_total: u64` at `:38`, which is
  the same species of "we could not keep up" counter. Note this needs the field
  populated in **both** `src/output/prometheus_server.rs` (`collect_metrics`)
  and `src/output/api.rs` (`get_metrics`), which build the struct independently.
- TUI: the counts string at `src/tui/render/status.rs:80`, with the width
  accounting in `line1_used_cols` at `:34` updated to match — that helper sizes
  the status background from the rendered text, so added text that skips it
  under-fills the bar. The honest-truncation idiom already
  exists here too — `src/tui/loss_map.rs:138-146` renders
  `"Showing most recent {} of {} losses"` in `theme.warning` when
  `LossMap::truncated` (`src/rtp/loss_map.rs:47`) is set.
- The `--report` table (`src/output/dialog_report.rs:29`) has no footer at all
  today; one is needed, because a report is exactly the artifact that gets
  pasted into a ticket without its stderr.

**Exit code: no.** `src/app/batch.rs:1357-1365` reserves a non-zero exit for
output-write failure, with the reasoning that "a partial capture is worth
looking at, it just must not be mistaken for a whole one by a script reading
`$?`". That reasoning argues *for* flagging eviction, but changing the exit code
of a run that completed is a breaking change to every wrapper script, and it
conflates "sipnab failed" with "your limit was too low". Better handled by a
separate opt-in (`--fail-on-truncation`) if it is wanted at all. That decision
is deferred; the warning and the structured fields are not.

### 4.2 Retention policy

**Drop-oldest (today).** The best policy for live monitoring and the worst for
forensics, and sipnab is used for both from one binary. Live, the newest calls
are the ones a TUI operator is watching and the oldest are already off-screen.
In a post-mortem the ordering is exactly inverted: the incident started before
someone noticed it, so the earliest retained data is the causally interesting
data. Drop-oldest deletes the answer first, and it deletes it *systematically*
rather than randomly, which is worse — a random 30% loss leaves the 14:00 window
30% thinner, whereas drop-oldest leaves it empty while everything after 14:20
looks pristine.

**Reject-newest (`--no-rotate` today).** Already implemented, already counted
(`src/sip/dialog_store.rs:427`), still unreported. Its virtue is that the
retained prefix is *contiguous and complete* — an unbroken window from the start
of the capture to wherever the cap hit — so every derived statistic over that
window is correct rather than biased. Its vice is that it is a cliff: analysis
silently stops at an arbitrary point determined by a memory limit, and a
capture-set feature whose whole purpose is stitching later files becomes a
feature that reads them and discards them. It is the right *default* for
forensics and the wrong thing to ship without the section 4.1 warning, because
"complete up to 11:44:31, nothing after" is only useful information if the tool
says so.

**Time-windowed.** Retain dialogs whose activity falls in an operator-named
window and never admit others. This is the policy that actually matches the
question ("what happened at 14:00?"): it bounds memory by a quantity the
operator understands, it is deterministic, and both the retained set and the
excluded set are describable in one sentence. It has no flag today — `--filter`
exists but is applied *after* the dialog is stored (`src/app/batch.rs:1579`,
comment: `// Apply DSL filter (evaluated after dialog update)`), so it cannot
bound memory. Measured: `--filter "method == 'INVITE'"` yields the same 18,948
dialogs and 302,552 KB as no filter at all. A time window has to be enforced at
admission, in `process_message`, or it is decoration.

The wrinkle that must be designed for rather than discovered: a dialog that
*starts* before the window and is still active inside it is exactly the dialog a
post-mortem wants, and a naive "first message inside the window" test excludes
it. The window has to admit on overlap, which means a dialog can only be
rejected once its whole lifetime is known — and in a single pass it is not.
Admitting on "any message inside the window" and accepting that a long call
drags its pre-window messages in with it is the honest compromise; it bounds
memory by window length plus one call duration.

**Operator-selected.** The strongest lever available today, and it needs no
code: a BPF filter is applied by libpcap before a packet reaches sipnab.
Measured — `port 5060` on the same 15 files yields all 18,948 dialogs, 0 RTP
streams, 221,056 KB instead of 303,108 KB, and 0.92 s instead of 3.97 s.
Twenty-seven percent less memory and four times faster with **zero** signalling
lost. This should be documented as the first thing to try on a large set, and
the pre-flight warning in section 5 should say it in words.

BPF cannot select by call, though, which is where a genuine operator-selected
retention would earn its cost: "keep dialogs matching this predicate, count and
report the rest". That is the DSL moved to admission time, and it shares its
whole implementation with the time window — the window is one predicate. Both
should be built as one thing.

**The recommendation.** Do not change the default policy on its own. Ship
visibility first, then make the policy selectable
(`--on-capacity=drop-oldest|reject-new|window:<range>`) with drop-oldest
remaining the default for live capture and the documentation stating plainly
that forensic work on a capped set wants one of the others. The reason not to
flip the default now is that eviction is currently silent, so any flip changes
answers without telling anyone — the same defect, differently shaped.

### 4.3 Processing sets larger than memory

The criterion that matters here is the one the multi-file feature exists for.
`src/capture/input_set.rs` orders files by first-packet timestamp specifically
so that a wrapped ring buffer replays in real time order, because — its module
doc, lines 20–25 — "replaying it by name feeds sipnab thirty-five seconds of
traffic before the thirty-four seconds preceding it … so a mis-ordered set does
not merely look odd, it produces confident wrong findings." A call whose INVITE
is in `tg.pcap7` and whose BYE is in `tg.pcap0` is reconstructed only because
the store spans both. **Eviction is the thing that breaks exactly that
guarantee**, and it breaks it silently, on the same axis (time) that the
ordering work was done to protect.

So each option below is judged first on whether cross-file stitching survives.

**Two-pass: index, then re-read for detail.** Pass one reads every file
retaining per-dialog *summaries* only — Call-ID, endpoints, state, timing
milestones, first and last timestamps, message count, file offsets — and no
`SipMessage` bodies. Pass two re-reads the files for the dialogs the operator
actually wants, materialising full ladders for those alone.

Stitching: **fully preserved**, and this is the only option here of which that
is true at arbitrary scale. Pass one sees every packet in time order exactly as
today; a dialog spanning ten files is stitched in the index because the index
entry is cheap enough to keep for all of them.

Cost model, from the measured coefficients: dropping the message vector removes
the 2.07 KB/message term entirely. At this corpus's 4.48 messages/dialog that is
9.3 KB of the 10.8 KB marginal cost — **a ~7× improvement in dialogs per byte**,
though the residual 1.83 KB/dialog is itself an unprofiled figure that a summary
struct would shrink further by an unknown amount. Extrapolating, 100,000 dialogs
of index costs on the order of 180 MB rather than 1.15 GB.

The second read is nearly free in the right circumstances and expensive in the
wrong ones: measured warm-cache, the full 4.5M-packet read is 4 s, and a
`--limit`-independent second pass would cost the same again. Cold cache on
spinning media it is a second full-file read. Both passes benefit from a BPF
filter, and pass two can narrow to the target dialog's host pairs.

This option also fits what already exists. `--call-report <CALL-ID>`
(`src/app/batch.rs`, report built by `src/output/call_report.rs:52`) is already
a "detail for one dialog" mode; today it needs the whole store in memory to find
that dialog, and two-pass is precisely the change that removes that requirement.
`--wireshark` and `--tshark-filter` already emit per-dialog filters, which is
the same index-then-narrow idea expressed for other tools.

**On-disk spill.** Evicted dialogs are serialised to a temp file rather than
dropped, and faulted back when the report needs them.

Stitching: preserved in principle, but the store has to be able to *find* a
spilled dialog when a later message arrives for it, which means the Call-ID
index stays resident and only the message vectors spill. That is a different and
much smaller change than it first sounds — and it is also, note, most of the
two-pass design with a temp file instead of the original capture as the backing
store.

The reason it ranks below two-pass is that the capture files are already a
perfectly good on-disk representation of the messages, already ordered, already
indexed by the file set. Spilling writes a second copy of data that has not
moved. It also needs a serialisation format for `SipMessage`, and there is no
embedded store in the dependency tree to lean on — `Cargo.toml` carries no
sqlite, sled or equivalent, and the project's posture on dependencies is not to
add one lightly. `tempfile` is present (optional, `native` feature) so the file
handling itself is solved. Reconsider spill if two-pass proves impractical
because re-reading is too expensive on the target storage; that is an empirical
question this document has not answered for cold-cache or network storage.

**Bounded time windows with explicit boundaries.** Analyse `[t0, t1)`, report
the boundary, then move on. This is section 4.2's time-windowed policy used as a
scaling strategy rather than a retention policy.

Stitching: **preserved within a window, broken at every boundary, and honestly
so.** A call crossing t1 appears truncated — but the output says where the
boundary is, so the operator knows to widen or shift rather than concluding the
call was abandoned. That honesty is the whole value and it is the property
eviction lacks. Cheapest of the four to implement given the admission-time
predicate from 4.2, and it composes with two-pass: the index pass finds which
window holds the interesting calls.

**Streaming aggregation keeping only summaries.** Never retain a message;
maintain per-dialog counters and roll dialogs out as they terminate.

Stitching: **preserved for anything expressible as an aggregate; destroyed for
anything else.** Constant memory in the number of concurrent calls, which is the
only option here that is genuinely unbounded-input-safe. But sipnab's value in a
post-mortem is the message ladder — `--call-report`, the TUI call flow, the
Wireshark filter, the SIPREC metadata all read stored messages — and an
aggregate cannot produce a ladder. This is the right answer for a long-running
metrics exporter and the wrong answer for forensics. It is best understood as
pass one of the two-pass design with the second pass deleted, which is another
argument for building two-pass first: streaming aggregation falls out of it as a
mode.

**Ranking.** Two-pass is the one to build: it is the only option that keeps
cross-file stitching at arbitrary scale without a new on-disk format, it makes
`--call-report` work on captures larger than memory, and streaming aggregation
and windowing both become configurations of it. Bounded windows are the cheap
partial answer to ship first if two-pass is too large for one change. Spill is a
fallback if re-reading proves too expensive on real storage. Streaming
aggregation alone is not a forensic tool.

## 5. Pre-flight estimate

It is tempting to say that `src/capture/input_set.rs` already visits every file
during resolution, so the total size is known before reading starts and a
size-based warning is nearly free. **Neither half of that holds: the size is not
collected, and the size is the wrong quantity anyway.**

What resolution does is open every file and read its first packet
(`src/capture/input_set.rs:234-247`), which doubles as the "is this a capture"
test:

```rust
fn first_packet_time(path: &Path) -> Result<Option<f64>> {
    let (mut cap, _gz_guard) = super::file::open_offline(path)?;
    match cap.next_packet() {
```

`ResolvedInput` (`:73-82`) carries only `path` and `first_packet`. There is no
`fs::metadata` call in the module and no size anywhere on the struct. Adding
size is trivial — one `metadata()` per resolved file, and the file is open
already — but section 1.1 measured what it would be worth: 921 MB gave 18,241
dialogs and 462 MB gave 707. A size-based warning would have shouted about the
quiet capture and stayed silent about the loud one. It is also not the size of
what gets read: `open_offline` transparently handles gzip members and
`compressed_and_uncompressed_mix_in_one_set`
(`src/capture/input_set.rs:460`) pins that a `.pcap.gz` sits in the same set as
a plain file, so `metadata().len()` understates a compressed member by its
compression ratio. Collect it anyway — it costs nothing and it bounds the second
pass's I/O — but it must not be the trigger.

Two better quantities are available at the same moment, for almost the same
cost.

**Capture span, free.** Resolution already holds every file's first packet
timestamp. The span from the first file's first packet to the last file's first
packet is a lower bound on the set's duration, available with no extra I/O, and
it is what turns a dialog rate into a dialog count. It also detects the case
this corpus is: two runs two hours apart in one directory. `warn_on_overlap`
(`:257`) already warns when consecutive files start at the same instant; the
inverse — a gap far larger than any file's span — is the same class of
"this is not one sequence" warning and would have flagged
`/home/gator/pcaps` correctly.

**Sampled signalling density, ~20 ms.** Read the first ~2,000 packets of each
file instead of one, count SIP-looking packets and distinct Call-IDs, and
extrapolate. Measured on this set with the page cache warm: reading 30,000
packets took 0.02 s and 300,000 took 0.24 s, against 3.97 s for the full
4.53M-packet run — the sample is 0.5% of the work. Resolution itself, opening 15
files and reading one packet from each, was below the 10 ms resolution of the
measurement. Cold cache these numbers are disk-bound and were **not measured**;
what is certain is that the sample reads a bounded prefix of each file and is
strictly cheaper than the read that follows it.

Sampling the *head* of each file is not a uniform sample and will misestimate a
set whose call rate ramps. That is acceptable for a warning — the purpose is to
distinguish 700 dialogs from 100,000, not to predict 18,948 — but the warning
should say it is an estimate.

**What to warn, and when.** After resolution, before the first packet is
delivered to the store, with everything needed already in hand:

> `15 files, 1,383 MB, spanning 11:43:54–13:40:48 (two runs, 1h 55m apart).
> Sampled ~1.9% SIP: estimated 19,000 dialogs, ~300 MB. Dialog limit 100,000
> (--limit).`

and, when the estimate exceeds the limit or a memory budget:

> `Estimated 260,000 dialogs against a --limit of 100,000: the oldest ~160,000
> will be discarded and the report will cover only the end of the capture.
> Raise --limit, narrow with a BPF filter (e.g. 'port 5060', measured here at
> 27% less memory with no signalling lost), or analyse a time window.`

Both are pre-flight, so they arrive while the operator is still at the keyboard
and before four seconds — or forty minutes — have been spent producing a wrong
answer. Neither can be exact and neither should pretend to be.

## 6. Recommended sequence

1. **Count eviction on the default path and warn once at the end of the run.**
   Reuse `truncated()` / `truncation_note()` from `src/output/group.rs`
   verbatim in shape. Distinguish drop-oldest from reject-newest in the count.
   This is small, and until it exists everything else changes answers silently.
2. **Fix the wall-clock idle compaction for offline runs** (section 3.2). Same
   defect class, unrelated cause, and it makes every subsequent measurement
   reproducible.
3. **Add the pre-flight estimate**: span and sampled density at resolution,
   warning before the read starts.
4. **Surface the count in the structured outputs** — MCP `StatsResponse`, REST
   `/v1/stats`, Prometheus, the TUI status line, and a footer on `--report`.
5. **Make the retention policy selectable**, admission-time, with the time
   window as one predicate. Keep drop-oldest as the live default.
6. **Two-pass**, index then re-read, with streaming aggregation as its
   degenerate one-pass mode.

Items 1–3 are the ones that stop wrong conclusions. Items 5–6 are the ones that
make large captures work.

## 7. What is not known

Stated explicitly, because none of these were measured and none should be
guessed at:

- **The 1.83 KB per-dialog fixed cost is unattributed.** It is a measured slope,
  not a sum of field sizes, and how much of it a summary-only struct would
  reclaim is unknown until one is built and measured.
- **The 1.15 GiB figure for 100,000 dialogs is an extrapolation** roughly 5×
  beyond the measured range.
- **`max_audio_frames` (1,500/stream, TUI only) has no measured cost.**
- **Cold-cache and network-storage read costs were not measured.** Every timing
  here is warm page cache on local storage, and the two-pass recommendation
  assumes re-reading is cheap — an assumption that has not been tested where it
  matters most.
- **Fragmentation and allocator retention were not separated from live heap.**
  Peak RSS is what the operator's cgroup limit sees, which is why it was used,
  but it is an upper bound on live data, not a measure of it.
- **Message-density figures are from this corpus.** Traffic with heavy SIP
  message-body use — large SDP, SIPREC multipart metadata, PIDF — will have a
  higher bytes-per-message figure than 2.1 KB, and the 500-message cap will
  engage on populations this corpus does not contain.

## Appendix: reproducing the measurements

All runs are `--cores 1`; `--cores > 1` is excluded for the reason in 3.3.
`SIPNAB_PERF_STATS=1` enables the `dialogs=`/`streams=` line at
`src/app/batch.rs:2093-2098`.

```sh
export SIPNAB_PERF_STATS=1
BIN=./target/release/sipnab

# Corpus shape.
capinfos -a -e -u -c -T -M /home/gator/pcaps/*.pcap*

# Baseline run (303,108-303,932 KB, 3.97-4.09 s, 18,948 dialogs).
/usr/bin/time -v $BIN -N -I /home/gator/pcaps --cores 1 --no-cli-print

# Sweep A: dialog cap against RSS.
for L in 500 1000 2500 5000 10000 15000 18948 30000 100000; do
  /usr/bin/time -f "$L %M %e" $BIN -N -I /home/gator/pcaps \
    --limit $L --cores 1 --no-cli-print >/dev/null
done

# Sweep B: message cap against RSS (one config file per cap).
printf '[limits]\nmax_messages_per_dialog = 4\n' > cfg_4.toml
/usr/bin/time -f "%M" $BIN -N -I /home/gator/pcaps --config cfg_4.toml \
  --limit 100000 --cores 1 --no-cli-print >/dev/null

# Term decomposition.
$BIN -N -I /home/gator/pcaps --cores 1 --no-dialog --no-rtp --no-cli-print   # 91,360 KB
$BIN -N -I /home/gator/pcaps --cores 1 --no-dialog          --no-cli-print   # 92,888 KB
$BIN -N -I /home/gator/pcaps --cores 1 --no-cli-print 'port 5060'            # 221,056 KB
$BIN -N -I /home/gator/pcaps --cores 1 --no-dialog --no-rtp \
     --no-cli-print 'port 5060'                                             #   9,088 KB

# Message distribution (Msgs column of the report table, rows 3..18950).
$BIN -N -I /home/gator/pcaps --report --no-cli-print 2>/dev/null > full_report.txt
awk 'NR>=3 && NR<=18950 {v=substr($0,95,6)+0; s+=v; n++; if(v>m)m=v}
     END{printf "dialogs=%d msgs=%d mean=%.2f max=%d\n", n, s, s/n, m}' full_report.txt

# The dead config keys: loads, then ignores both.
printf '[limits]\ndialog_limit = 100\nmax_streams = 10\n' > cfg_dead.toml
$BIN -N -I /home/gator/pcaps --config cfg_dead.toml --cores 1 --no-cli-print

# The DSL filter does not bound memory; BPF does.
$BIN -N -I /home/gator/pcaps --cores 1 --filter "method == 'INVITE'" --no-cli-print
$BIN -N -I /home/gator/pcaps --cores 1 --no-cli-print 'port 5060'

# Silent truncation, exit 0, no warning.
$BIN -N -I /home/gator/pcaps --limit 5000 --cores 1 --report --no-cli-print \
  > lim5000.txt 2> lim5000.err; echo "exit=$?"
grep -c 'evict\|drop\|truncat' lim5000.err   # 0

# Speed-dependent idle compaction (max messages 44 release, 24 debug).
./target/debug/sipnab -N -I /home/gator/pcaps --limit 100000 --cores 1 \
  --report --no-cli-print > dbg_report.txt

# Pre-flight sampling cost.
for N in 1 30000 300000; do
  /usr/bin/time -f "$N %e %M" $BIN -N -I /home/gator/pcaps -n $N \
    --no-cli-print --quiet >/dev/null
done
```
