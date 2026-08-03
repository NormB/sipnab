# WASM plugin API

**Status:** specced 2026-07-30. Supersedes the one-line backlog entry "WASM
plugin API (design decision D7 rules out Lua; WASM is the path if plugins are
ever needed)".

**Relates to:** [D7](./implementation-plan-v6.md) — *Filter DSL replaces embedded
scripting*, which this document has to answer to before proposing anything.

## Does D7 rule this out?

D7 rejects embedded scripting runtimes for three stated reasons. WASM is not
Lua, and the reasons land differently — so the honest thing is to take them one
at a time rather than lean on the backlog's cheerful "WASM is the path".

| D7's objection | Lua | WASM via `wasmi` |
|---|---|---|
| "unsafe FFI boundaries" | A C ABI, pointers both ways | No FFI. Linear memory the host owns, integers across the boundary |
| "sandbox escape risk" | Sandboxing Lua is opt-in and famously leaky | The sandbox *is* the execution model. `wasmi` is a pure-safe-Rust interpreter with no JIT, so no W^X pages |
| "supply chain dependencies disproportionate" | LuaJIT is C | **Measured: 15 transitive crates, +1.56 MB.** See below |

Two of the three objections weaken substantially. The third is a number, so it
was measured rather than argued:

```
empty Rust binary (LTO, strip, panic=abort)   0.32 MB
same + wasmi engine, module instantiated      1.88 MB
                                        delta +1.56 MB

sipnab release binary today                   5.00 MB
public claim on the homepage             "Under 12 MB static binary"
wasmi transitive crates                       15
sipnab dependency count (--all-features)     352
```

So the cost is real but bounded: 4% more crates, and a binary that would still
sit comfortably under the advertised ceiling.

**This does not make it a good idea on its own.** D7's actual conclusion was
that extensibility is served by three mechanisms that already exist — the filter
DSL, the NDJSON pipeline, and event exec hooks — and the backlog entry says
"**if** plugins are ever needed". That conditional is the real gate, and it is
answered in the next section rather than assumed.

## What the existing three mechanisms cannot do

| Want | Filter DSL | NDJSON pipe | Exec hooks | Gap |
|---|---|---|---|---|
| Select dialogs by known fields | ✅ | ✅ | ✅ | — |
| React to an event externally | — | ✅ | ✅ | — |
| Reshape output | — | ✅ | — | — |
| **Add a *detection* that reports through sipnab's own diagnosis surfaces** | ❌ not Turing-complete | ❌ findings live outside sipnab | ❌ fire-and-forget | **yes** |
| **Site-specific fault patterns without forking** | ❌ | partial, out-of-band | ❌ | **yes** |

The gap is narrow and specific: a user with a proprietary SIP profile or a
recurring site-specific fault can express *selection* today, but not
*diagnosis*. They can pipe NDJSON into Python and find the pattern — and then
their finding lives in their script, not in `--call-report`, not in the TUI
call-flow tags, not in `signaling_diagnosis`. The seven built-in detections get
evidence indices, hint text, and every surface for free; a user's own detection
gets none of it.

That is the whole justification. It is not "plugins are good"; it is one hole in
a surface that is otherwise complete.

## Scope

**One hook point: post-dialog analysis.**

A plugin is a pure function from one dialog to zero or more findings. It runs
after the built-in diagnosis, and its findings join `SignalingDiagnosis` through
the same shape the built-ins use, so every surface renders them with no
per-surface work.

One hook, chosen deliberately over a general event bus:

- It is where the demonstrated gap is.
- It is a **pure function** — no host state to corrupt, no ordering to reason
  about, no partial-failure semantics. A plugin that misbehaves affects its own
  findings and nothing else.
- It is trivially testable: feed a dialog, compare findings.

### Non-goals, and why

- **No packet-level hook.** The hot path takes no locks and does zero copies
  (WS1, D13); handing every packet to an interpreter would undo that, and the
  performance claims on the benchmarks page with it.
- **No mutation.** Plugins observe. A plugin that could rewrite a dialog makes
  every other surface's output unattributable.
- **No host imports at all** — no WASI, no clock, no filesystem, no network, no
  logging. A plugin gets bytes in and bytes out. This is the strongest possible
  answer to D7's sandbox-escape objection: there is nothing to escape *to*.
- **No plugin-supplied UI.** Findings render through existing surfaces.

## Safety model

The threat is a hostile or broken `.wasm` file, since a plugin is exactly the
kind of artifact people copy off the internet.

| Risk | Control |
|---|---|
| Infinite loop | `wasmi` fuel metering. Exhausted fuel = plugin error, capture continues |
| Memory exhaustion | `wasmi` `StoreLimits` installed on the store **before** instantiation |
| Escaping the sandbox | No imports whatsoever — nothing to call |
| Reading the host's data | Linear memory is the plugin's own; the host copies the dialog in |
| Crashing sipnab | Every trap is caught and reported as a plugin error against that dialog |
| Silent wrong answers | Findings are namespaced by plugin id, so a reader always sees *which* plugin said it |

**A plugin failure never fails the capture.** It is reported and the dialog is
otherwise analysed normally, for the same reason a malformed packet is logged
and skipped rather than fatal.

### The memory cap has to be a limiter, not an audit

The first implementation read `mem.size()` *after* `instantiate_and_start` and
refused anything over the cap. That is too late by construction: WASM allocates
a module's declared **minimum** linear memory at instantiation, so a module
declaring `(memory 32768)` was handed 2 GiB and only then rejected.

The regression test caught it by passing — in 25 seconds. A check that reliably
reports a problem after causing it is the shape worth naming, because it looks
exactly like a working control from the outside: the error message is right,
the test is green, and the host has already been made to allocate two
gigabytes. The cap is now a `StoreLimits` on the store, refused by the engine
during instantiation; the same test completes in 0.00s.

Loading a plugin is a deliberate act, so this is not a remote hole. It is still
a denial of service reachable by talking someone into a file, which is the
normal way plugins arrive.

## Feature gating

`plugins` is a **non-default Cargo feature**.

This is the point that keeps the whole proposal honest against D7. Someone who
does not want an interpreter in their capture tool does not get one: no wasmi,
no 15 crates, no +1.56 MB, no `--plugin` flag. The default build is byte-for-byte
what it is today, and the homepage's "under 12 MB" claim is unaffected because
the default binary does not change at all.

## ABI

Deliberately tiny — four exports, no imports. Small enough that a plugin can be
written in any language targeting WASM without a binding generator.

```
;; The plugin exports:
(func (export "sipnab_plugin_abi_version") (result i32))
(func (export "sipnab_alloc")   (param i32) (result i32))
(func (export "sipnab_dealloc") (param i32 i32))
(func (export "sipnab_analyze") (param i32 i32) (result i64))
```

- `sipnab_plugin_abi_version` returns `1`. The host refuses anything else, so a
  plugin built against a future ABI fails loudly at load rather than subtly at
  runtime.
- `sipnab_alloc`/`sipnab_dealloc` let the host place the input inside the
  plugin's own linear memory. The host never writes outside what the plugin
  handed it.
- `sipnab_analyze` receives `(ptr, len)` of UTF-8 JSON and returns a packed
  `(ptr << 32) | len` pointing at UTF-8 JSON output. Packing into one `i64`
  keeps the ABI to plain scalars, so no multi-value proposal and no memory64
  are required.

### The input document

```json
{ "dialog": { …exactly what --json-dialogs emits… },
  "messages": [ { "index": 0, "is_request": true, "method": "INVITE",
                  "status_code": null, "reason": null,
                  "offset_ms": 0, "cseq_number": 1, "cseq_method": "INVITE",
                  "headers": { "Call-ID": "…", "From": "…" } } ] }
```

**The `messages` array is why this is not simply the `--json-dialogs`
document.** The first draft of this spec said it was, and that was wrong in a
way worth recording: findings must cite evidence as indices into the dialog's
message list, and the dialog document contains no message list — only
`msg_count`. A plugin would have been required to produce indices it had no way
to compute. The rule and the payload contradicted each other, and the payload
was the half that had to move.

`offset_ms` is milliseconds from the dialog's first message, not a wall-clock
timestamp. A plugin that cannot see absolute time cannot make its findings
depend on when the capture happened, which keeps them reproducible from the
pcap — the same reason fuel is metered instead of wall-clock.

`headers` carries the message's headers verbatim, including `Authorization`.
That is safe to hand over precisely because a plugin has no imports: it cannot
write a file, open a socket, or otherwise take anything with it. It *can* copy a
credential into a finding's `summary`, which then prints — so a plugin is
trusted code in the same sense a fork would be, and the docs say so plainly
rather than implying the sandbox makes trust unnecessary.

### Output

```json
{ "findings": [ { "id": "...", "summary": "...", "evidence": [3, 7] } ] }
```

`evidence` carries message indices, matching the rule every built-in detection
follows: **no detection without evidence.** A plugin finding that cannot name
its messages is rejected at the boundary, so third-party findings cannot be
lower-quality citizens than built-in ones.

## Build order

1. Host: load, validate ABI version, instantiate with fuel and memory caps, call, decode. Feature-gated, no CLI yet.
2. `--plugin <path>` (repeatable), wired where `diagnose_signaling` runs.
3. Example plugin crate, built for `wasm32-unknown-unknown`, with a detection the built-ins do not do.
4. Round-trip test: build the example, run it against a fixture capture, assert the finding appears in `--json-dialogs`.
5. Docs page — writing a plugin start to finish.

Each step is independently useful; the sequence stops cleanly after any of them.

## Writing a plugin, start to finish

The worked example lives at `crates/sipnab-plugin-example` and detects **short
answered calls** — a call picked up and torn down within five seconds, which is
a bad route, a codec the far end rejects, or wangiri-style fraud dialling. It is
deliberately not a built-in: whether a three-second call is a problem depends
entirely on the traffic, which is the shape a plugin is for.

### 1. A crate that builds to WASM

```toml
[lib]
crate-type = ["cdylib"]
```

Target `wasm32-unknown-unknown`. `std` works there — a `no_std` plugin is
smaller but needs its own global allocator and panic handler, which is a lot of
ceremony for a detection.

### 2. The four exports

```rust
#[unsafe(no_mangle)]
pub extern "C" fn sipnab_plugin_abi_version() -> i32 { 1 }

#[unsafe(no_mangle)]
pub extern "C" fn sipnab_alloc(len: i32) -> i32 { /* host writes input here */ }

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sipnab_dealloc(ptr: i32, len: i32) { /* … */ }

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sipnab_analyze(ptr: i32, len: i32) -> i64 {
    // read UTF-8 JSON at (ptr, len), return (out_ptr << 32) | out_len
}
```

Import nothing. The host registers no host functions at all, so a module that
imports anything fails to instantiate — that is the sandbox, and
`a_plugin_that_imports_anything_cannot_instantiate` holds it.

### 3. Read the input, return findings

Inspect the input shape before writing code:

```sh
sipnab -N -I capture.pcap --json-dialogs --no-cli-print | head -1
```

That is the `dialog` half of what a plugin receives; the `messages` array is
added alongside it.

```json
{ "findings": [ { "id": "short-answered-call",
                  "summary": "Call answered and torn down after 2.2s …",
                  "evidence": [3, 5] } ] }
```

`evidence` is mandatory and rejected when empty. Every built-in detection names
the messages it is drawn from, and a third-party finding is held to the same
rule rather than being allowed in as a lesser citizen.

### 4. Build and run

```sh
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown -p sipnab-plugin-example

sipnab -N -I capture.pcap --json-dialogs --no-cli-print \
  --plugin target/wasm32-unknown-unknown/release/sipnab_plugin_example.wasm
```

Findings appear under a top-level `plugin_findings` array, separate from
`signaling_diagnosis` so a reader can always tell which findings sipnab stands
behind and which came from third-party code.

Requires a build with `--features plugins`, which is **not** in the default
feature set.

### 5. What it looks like on real traffic

Run against the sample captures in this repo, the example fires on five of
them — `sip-over-tcp.pcap` (2.2 s), `sip-proxy.pcap` (2.2 s),
`sip-sdp-example.pcap` (3.1 s), `rtp-protocol.pcap` (4.9 s) and
`sipp-branch-scenario.pcapng` — and stays quiet on `sip_call.pcap`, whose call
runs 60.1 s.

## Trust

The sandbox stops a plugin reaching your filesystem, your network, and the
host's memory. It does **not** make a plugin trustworthy: a plugin sees each
message's headers, `Authorization` included, and can copy anything it likes into
a `summary` that then prints.

So a `.wasm` is trusted code in the same sense a patch is. Read it, or get it
from someone you would accept a patch from. Saying this plainly is better than
letting the word "sandboxed" imply a guarantee it does not make.

## Not done yet

- **A published docs page.** This section is the guide; promoting it to
  `docs/plugins.md` means the seven-place registration every published page
  needs (wiki builder, site page table, site-internals map, docs index, both
  sidebar templates, header dropdown) plus the counter pins. Worth doing when
  the feature stops being non-default.
- **Surfaces other than `--json-dialogs`.** Findings reach the NDJSON output;
  the call report, TUI tags and REST API still render only built-in detections.
