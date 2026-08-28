# WASM plugins

Add your own detection to sipnab's diagnosis, without forking it.

A plugin is a small WebAssembly module that receives one reconstructed dialog
and returns findings. Those findings appear beside sipnab's built-in ones, in
the same shape, so every surface that renders a finding renders yours with no
extra work.

## When you want one

sipnab already lets you *select* dialogs — the [filter DSL](filter-dsl.md)
picks them by field, [NDJSON](output-formats.md) pipes them anywhere, and
`--alert exec` reacts to them. What none of those do is *diagnose*: express a
site-specific fault pattern and have sipnab report it as a finding, with
evidence, in `--call-report` and the TUI and the JSON alike.

That is the one hole a plugin fills. If you can already answer your question
with a filter or a `jq` pipeline, use those — they need no build step and no
trust decision.

## What it costs you to trust one

A plugin is a `.wasm` file, which is exactly the kind of artifact people copy
off the internet, so read this before loading one someone sent you.

**A plugin has no imports at all.** Not a restricted set — none. No WASI, no
filesystem, no network, no clock, not even logging. The only things crossing
the boundary are integers and the bytes sipnab copies into the plugin's own
linear memory. A module that imports anything fails to instantiate.

| Bounded | How |
|---|---|
| CPU | Fuel metering. A plugin that loops forever gets cut off and reported as a plugin error, and the capture continues |
| Memory at run time | 16 MiB linear-memory ceiling, refused by the engine at the point of growth |
| Memory at load time | sipnab reads the `.wasm` file through a 16 MiB bound, so it never allocates a length the file chose |
| Output size | 4 MiB per reply |
| Blast radius | A trap, an exhausted fuel budget or a malformed reply fails *that dialog's* plugin findings, and nothing else |

**What is not bounded is what it reads.** A plugin sees every dialog sipnab
reconstructs, including `Authorization` headers and `MESSAGE` bodies. It cannot
send them anywhere — it has no imports — but it can decide what to report, and
a finding's `summary` is a string it chose. Load a plugin the way you would run
a script: from someone you trust, or after reading it.

Plugins need a build with `--features plugins`, which is **not** in the default
feature set. A stock binary carries no interpreter at all, so `sipnab --version`
tells you whether the machine in front of you can load one.

## Writing one, start to finish

The worked example is [`crates/sipnab-plugin-example`](https://github.com/NormB/sipnab/tree/main/crates/sipnab-plugin-example).
It flags **short answered calls** — picked up and torn down inside five seconds,
which is a bad route, a codec the far end rejected, or wangiri-style fraud
dialling. It is deliberately not a built-in: whether three seconds is a problem
depends entirely on your traffic, which is the shape a plugin is for.

### 1. A crate that builds to WASM

```toml
[lib]
crate-type = ["cdylib"]
```

Target `wasm32-unknown-unknown`. `std` works there. A `no_std` plugin is
smaller but needs its own allocator and panic handler, which is a lot of
ceremony for a detection.

### 2. Four exports, and nothing imported

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

sipnab checks the ABI version at load rather than on first use: a plugin built
against a later ABI would misread its input and report confident nonsense,
which is worse than not loading.

### 3. Read the input, return findings

Look at the input before writing code — it is the same per-dialog JSON
`--json-dialogs` emits, with the `messages` array alongside it:

```sh
sipnab -N -I capture.pcap --json-dialogs --no-cli-print | head -1
```

Return findings in this shape:

```json
{ "findings": [ { "id": "short-answered-call",
                  "summary": "Call answered and torn down after 2.2s …",
                  "evidence": [3, 5] } ] }
```

`evidence` indexes the dialog's own message list and is **mandatory** — sipnab
rejects a finding that leaves it empty. Every built-in detection names the
messages behind it, and a third-party finding answers to the same rule rather
than entering as a lesser citizen.

### 4. Build and run it

```sh
# Run all of these, in order.
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown -p sipnab-plugin-example

sipnab -N -I capture.pcap --json-dialogs --no-cli-print \
  --plugin target/wasm32-unknown-unknown/release/sipnab_plugin_example.wasm
```

`--plugin` is repeatable. Each plugin gets its own sandbox, and a failure in
one never stops the capture or the others.

### 5. Where the findings come out

Under a top-level `plugin_findings` array, separate from `signaling_diagnosis`,
and each finding carries the plugin's own name — filled in by sipnab from the
file stem, never by the plugin, so a plugin cannot attribute a finding to
another plugin or to a built-in detection.

That separation is the point. A reader can always tell which findings sipnab
stands behind and which came from third-party code.

## Known limits

- Findings currently reach `--json-dialogs` only. The other surfaces render the
  shape but are not yet wired to it.
- One hook point: post-dialog analysis. There is deliberately no packet-level
  hook — handing every packet to an interpreter would undo the capture path's
  performance, and the [benchmarks](benchmarks.md) with it.
- Plugins observe rather than mutate. A plugin that could rewrite a dialog
  would make every other surface's output unattributable.

## See also

- [Design specification](https://github.com/NormB/sipnab/blob/main/docs/design/wasm-plugin-api.md)
  — the ABI in full, the safety model, and why WASM rather than an embedded
  scripting runtime.
- [CLI reference](cli-reference.md#output) — the `--plugin` flag.
- [Installation](install.md#feature-flags) — building with `--features plugins`.
