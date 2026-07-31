// SPDX-License-Identifier: MIT OR Apache-2.0

//! WASM plugin host — third-party dialog detections.
//!
//! Spec: `docs/design/wasm-plugin-api.md`, which measures the cost and argues
//! against [D7] before proposing anything rather than after.
//!
//! # What a plugin is
//!
//! A pure function from one dialog to zero or more findings. It receives the
//! same per-dialog JSON `--json-dialogs` emits, and returns findings that join
//! [`crate::sip::diagnosis::SignalingDiagnosis`] through the shape the built-in
//! detections already use — so every surface renders them with no per-surface
//! work.
//!
//! # Why this is not the sandbox risk D7 rejected
//!
//! **A plugin has no imports.** Not a restricted set: none. No WASI, no clock,
//! no filesystem, no network, not even logging. The only things crossing the
//! boundary are integers and bytes the host copies into the plugin's own linear
//! memory. There is no host function to call, which is a stronger statement
//! than any allowlist — it removes the question rather than answering it.
//!
//! `wasmi` is a pure-safe-Rust interpreter with no JIT, so the host never maps
//! writable-executable pages either.
//!
//! # Failure is never fatal
//!
//! A plugin that traps, runs out of fuel, exceeds its memory cap, or returns
//! nonsense produces a [`PluginError`](crate::plugin::PluginError) against
//! *that dialog* and nothing more.
//! The capture continues, the built-in diagnosis for that dialog is unaffected,
//! and every other plugin still runs. This matches how a malformed packet is
//! handled: recorded and skipped, never fatal, because a capture process that
//! dies on bad input is a denial of service against the thing it was watching.
//!
//! [D7]: ../../docs/design/implementation-plan-v6.md

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// ABI version this host speaks. A plugin reporting anything else is refused at
/// load time.
///
/// Loudly, and on purpose: a plugin built against a later ABI that got called
/// anyway would misread its input and report confident nonsense, which is worse
/// than not loading.
pub const ABI_VERSION: u32 = 1;

/// Instructions a plugin may execute per dialog before it is cut off.
///
/// Fuel, not wall-clock: wall-clock makes a capture's output depend on how busy
/// the machine was, so the same pcap could analyse differently twice. Fuel is
/// deterministic, which keeps a plugin's findings reproducible — the property
/// the whole tool is built around.
const FUEL_PER_DIALOG: u64 = 50_000_000;

/// Linear-memory ceiling per plugin instance, in 64 KiB pages. 256 pages =
/// 16 MiB, ample for a JSON document and a few findings.
const MAX_MEMORY_PAGES: u32 = 256;

/// Bytes in a WASM linear-memory page, fixed by the specification.
const WASM_PAGE_BYTES: usize = 64 * 1024;

/// Per-store state, existing only to hold the resource limiter.
///
/// `wasmi` applies limits through the store's data, so enforcing a memory cap
/// at instantiation time requires the store to carry the limiter rather than
/// the host checking sizes afterwards.
struct StoreState {
    /// Caps linear memory, memories and tables during instantiation and growth.
    limits: wasmi::StoreLimits,
}

/// Largest JSON document a plugin may return, in bytes.
///
/// Bounded because the length comes from the plugin, and an unbounded read of
/// plugin-controlled length is how a "sandboxed" component takes the host's
/// memory with it.
const MAX_OUTPUT_BYTES: u32 = 4 * 1024 * 1024;

/// One finding reported by a plugin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginFinding {
    /// Which plugin said so. Filled in by the host from the plugin's file stem,
    /// never by the plugin, so a plugin cannot attribute a finding to another
    /// plugin or to a built-in detection.
    #[serde(default)]
    pub plugin: String,
    /// Stable identifier for the kind of finding, chosen by the plugin author.
    pub id: String,
    /// One plain-language line, rendered beside the built-in hints.
    pub summary: String,
    /// Indices into the dialog's own message list.
    ///
    /// Required, and rejected when empty: "no detection without evidence" is
    /// the spec's first load-bearing rule, and a third-party finding gets held
    /// to it exactly as the built-ins are.
    pub evidence: Vec<usize>,
}

/// What a plugin returns.
#[derive(Debug, Clone, Default, Deserialize)]
struct PluginOutput {
    /// Findings the plugin reported, possibly empty.
    #[serde(default)]
    findings: Vec<PluginFinding>,
}

/// Everything that can go wrong with a plugin, kept distinct because the fixes
/// differ and "plugin error" alone tells an operator nothing.
#[derive(Debug)]
pub enum PluginError {
    /// The file could not be read.
    Read(String),
    /// Not valid WASM, or it failed validation.
    Invalid(String),
    /// A required export is missing or has the wrong signature.
    Abi(String),
    /// The plugin reports an ABI version this host does not speak.
    AbiVersion {
        /// Version the plugin reported.
        found: u32,
        /// Version this build speaks.
        expected: u32,
    },
    /// The plugin trapped, ran out of fuel, or hit its memory cap.
    Trap(String),
    /// The plugin returned something that was not the agreed shape.
    BadOutput(String),
}

impl std::fmt::Display for PluginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read(m) => write!(f, "cannot read plugin: {m}"),
            Self::Invalid(m) => write!(f, "not a valid WASM module: {m}"),
            Self::Abi(m) => write!(f, "plugin ABI mismatch: {m}"),
            Self::AbiVersion { found, expected } => write!(
                f,
                "plugin reports ABI version {found}, this build speaks {expected}"
            ),
            Self::Trap(m) => write!(f, "plugin trapped: {m}"),
            Self::BadOutput(m) => write!(f, "plugin returned malformed output: {m}"),
        }
    }
}

impl std::error::Error for PluginError {}

/// A loaded, validated plugin.
pub struct Plugin {
    /// Display name, from the file stem. Used to attribute findings.
    name: String,
    /// Where it was loaded from, for error messages.
    path: PathBuf,
    /// Engine the module was compiled against; must outlive it.
    engine: wasmi::Engine,
    /// The validated module, instantiated fresh per dialog.
    module: wasmi::Module,
}

impl std::fmt::Debug for Plugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Plugin")
            .field("name", &self.name)
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl Plugin {
    /// The plugin's display name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Load and validate a plugin from a `.wasm` file.
    ///
    /// Validation is deliberately eager: the ABI version is checked here, at
    /// load, rather than on first use. A capture that runs for an hour before
    /// discovering its plugin was never loadable has wasted the capture.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, PluginError> {
        let path = path.as_ref().to_path_buf();
        let bytes = std::fs::read(&path)
            .map_err(|e| PluginError::Read(format!("{}: {e}", path.display())))?;

        let mut config = wasmi::Config::default();
        config.consume_fuel(true);
        let engine = wasmi::Engine::new(&config);
        let module = wasmi::Module::new(&engine, &bytes[..])
            .map_err(|e| PluginError::Invalid(format!("{}: {e}", path.display())))?;

        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("plugin")
            .to_string();

        let plugin = Self {
            name,
            path,
            engine,
            module,
        };
        plugin.check_abi_version()?;
        Ok(plugin)
    }

    /// Instantiate with no imports at all, applying the fuel and memory caps.
    fn instantiate(&self) -> Result<(wasmi::Store<StoreState>, wasmi::Instance), PluginError> {
        let limits = wasmi::StoreLimitsBuilder::new()
            .memory_size(MAX_MEMORY_PAGES as usize * WASM_PAGE_BYTES)
            .memories(1)
            .tables(4)
            .build();
        let mut store = wasmi::Store::new(&self.engine, StoreState { limits });
        // The limiter must be installed BEFORE instantiation, not audited
        // after it.
        //
        // WASM allocates a module's declared *minimum* linear memory at
        // instantiation. The first version of this checked `mem.size()` once
        // the instance existed, by which point a module declaring 2 GiB had
        // already been given 2 GiB — a check that reliably reported the
        // problem after causing it. Loading a plugin is a deliberate act, but
        // "the file you downloaded OOMs your capture host on load" is still a
        // denial of service, and the engine is the only thing positioned to
        // refuse it in time.
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(FUEL_PER_DIALOG)
            .map_err(|e| PluginError::Trap(e.to_string()))?;

        // No Linker imports are registered, so a module that imports ANYTHING
        // fails here. That is the sandbox: not a filtered set of host calls, an
        // empty one.
        let linker = wasmi::Linker::<StoreState>::new(&self.engine);
        let instance = linker
            .instantiate_and_start(&mut store, &self.module)
            .map_err(|e| {
                PluginError::Abi(format!(
                    "instantiation failed (plugins must import nothing): {e}"
                ))
            })?;

        Ok((store, instance))
    }

    /// Read the plugin's ABI version and refuse anything this host cannot speak.
    fn check_abi_version(&self) -> Result<(), PluginError> {
        let (mut store, instance) = self.instantiate()?;
        let f = instance
            .get_typed_func::<(), i32>(&store, "sipnab_plugin_abi_version")
            .map_err(|e| PluginError::Abi(format!("sipnab_plugin_abi_version: {e}")))?;
        let found = f
            .call(&mut store, ())
            .map_err(|e| PluginError::Trap(e.to_string()))?;
        #[allow(clippy::cast_sign_loss)]
        let found = found as u32;
        if found != ABI_VERSION {
            return Err(PluginError::AbiVersion {
                found,
                expected: ABI_VERSION,
            });
        }
        Ok(())
    }

    /// Run the plugin against one dialog's JSON document.
    ///
    /// A fresh instance per dialog, deliberately. It costs an instantiation but
    /// buys the property the whole design rests on: a plugin cannot carry state
    /// between dialogs, so it cannot make dialog N's finding depend on dialog
    /// N-1. Findings stay a pure function of their dialog, which is what makes
    /// them reproducible from a pcap.
    pub fn analyze(&self, dialog_json: &str) -> Result<Vec<PluginFinding>, PluginError> {
        let (mut store, instance) = self.instantiate()?;

        let memory = instance
            .get_memory(&store, "memory")
            .ok_or_else(|| PluginError::Abi("plugin exports no `memory`".into()))?;
        let alloc = instance
            .get_typed_func::<i32, i32>(&store, "sipnab_alloc")
            .map_err(|e| PluginError::Abi(format!("sipnab_alloc: {e}")))?;
        let analyze = instance
            .get_typed_func::<(i32, i32), i64>(&store, "sipnab_analyze")
            .map_err(|e| PluginError::Abi(format!("sipnab_analyze: {e}")))?;

        let input = dialog_json.as_bytes();
        let len = i32::try_from(input.len())
            .map_err(|_| PluginError::BadOutput("dialog JSON exceeds i32".into()))?;

        let ptr = alloc
            .call(&mut store, len)
            .map_err(|e| PluginError::Trap(e.to_string()))?;
        if ptr <= 0 {
            return Err(PluginError::Trap("sipnab_alloc returned null".into()));
        }

        #[allow(clippy::cast_sign_loss)]
        memory
            .write(&mut store, ptr as usize, input)
            .map_err(|e| PluginError::Trap(format!("writing input: {e}")))?;

        let packed = analyze
            .call(&mut store, (ptr, len))
            .map_err(|e| PluginError::Trap(e.to_string()))?;

        // (ptr << 32) | len — plain scalars, so no multi-value or memory64.
        #[allow(clippy::cast_sign_loss)]
        let packed = packed as u64;
        let out_ptr = (packed >> 32) as u32;
        let out_len = (packed & 0xFFFF_FFFF) as u32;

        if out_len == 0 {
            return Ok(Vec::new());
        }
        if out_len > MAX_OUTPUT_BYTES {
            return Err(PluginError::BadOutput(format!(
                "output {out_len} bytes exceeds the {MAX_OUTPUT_BYTES}-byte cap"
            )));
        }

        let mut buf = vec![0u8; out_len as usize];
        memory
            .read(&store, out_ptr as usize, &mut buf)
            .map_err(|e| PluginError::Trap(format!("reading output: {e}")))?;

        let text = String::from_utf8(buf)
            .map_err(|e| PluginError::BadOutput(format!("output is not UTF-8: {e}")))?;
        let parsed: PluginOutput = serde_json::from_str(&text)
            .map_err(|e| PluginError::BadOutput(format!("{e}; got: {}", truncate(&text, 200))))?;

        let mut findings = parsed.findings;
        for f in &mut findings {
            // Attribution is the host's to assign. A plugin that could name
            // itself could name a different plugin, or a built-in detection.
            f.plugin = self.name.clone();
            if f.evidence.is_empty() {
                return Err(PluginError::BadOutput(format!(
                    "finding `{}` cites no evidence; every detection must name \
                     the messages it is drawn from",
                    f.id
                )));
            }
        }
        Ok(findings)
    }
}

/// Build the JSON document a plugin receives for one dialog.
///
/// `dialog_json` is whatever `--json-dialogs` emitted for this dialog; the
/// messages are added alongside it.
///
/// **The messages are the point.** Findings must cite evidence as indices into
/// the dialog's message list, and the dialog document carries only `msg_count`
/// — so a plugin given that alone would be required to produce indices it had
/// no way to compute. The rule and the payload contradicted each other and the
/// payload moved.
///
/// Times are milliseconds from the dialog's first message rather than
/// wall-clock. A plugin that cannot see absolute time cannot make a finding
/// depend on when the capture ran, which is what keeps plugin findings
/// reproducible from a pcap.
pub fn plugin_input_json(dialog: &crate::sip::dialog::SipDialog, dialog_json: &str) -> String {
    use serde_json::{Map, Value, json};

    let base: Value = serde_json::from_str(dialog_json).unwrap_or(Value::Null);
    let first = dialog.messages.first().map(|m| m.timestamp);

    let messages: Vec<Value> = dialog
        .messages
        .iter()
        .enumerate()
        .map(|(index, m)| {
            let offset_ms = first
                .map(|t0| (m.timestamp - t0).num_milliseconds())
                .unwrap_or_default();
            let mut headers = Map::new();
            for h in &m.headers {
                headers.insert(h.name.to_string(), Value::String(h.value.clone()));
            }
            let (cseq_number, cseq_method) = match m.cseq() {
                Some((n, meth)) => (json!(n), json!(meth)),
                None => (Value::Null, Value::Null),
            };
            json!({
                "index": index,
                "is_request": m.is_request,
                "method": m.method.as_ref().map(|x| x.as_str().to_string()),
                "status_code": m.status_code,
                "reason": m.reason,
                "offset_ms": offset_ms,
                "cseq_number": cseq_number,
                "cseq_method": cseq_method,
                "headers": Value::Object(headers),
            })
        })
        .collect();

    json!({ "dialog": base, "messages": messages }).to_string()
}

/// Shorten a string for an error message without splitting a character.
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal conforming plugin, written in WAT so the test does not depend
    /// on a wasm32 toolchain being installed.
    ///
    /// It stores a fixed JSON reply at offset 1024 and returns it regardless of
    /// input — enough to exercise the whole host path: alloc, write, call,
    /// unpack, read, parse, attribute.
    fn wat_plugin(abi: i32, reply: &str) -> Vec<u8> {
        let bytes: Vec<String> = reply.bytes().map(|b| format!("\\{b:02x}")).collect();
        let wat = format!(
            r#"(module
              (memory (export "memory") 2)
              (data (i32.const 1024) "{data}")
              (func (export "sipnab_plugin_abi_version") (result i32) (i32.const {abi}))
              (func (export "sipnab_alloc") (param i32) (result i32) (i32.const 2048))
              (func (export "sipnab_dealloc") (param i32 i32))
              (func (export "sipnab_analyze") (param i32 i32) (result i64)
                (i64.or
                  (i64.shl (i64.const 1024) (i64.const 32))
                  (i64.const {len}))))"#,
            data = bytes.join(""),
            len = reply.len()
        );
        wat::parse_str(&wat).expect("fixture WAT assembles")
    }

    fn write_plugin(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("sipnab-plugin-tests");
        std::fs::create_dir_all(&dir).expect("temp dir");
        let p = dir.join(format!("{name}.wasm"));
        std::fs::write(&p, bytes).expect("write fixture");
        p
    }

    #[test]
    fn a_conforming_plugin_returns_attributed_findings() {
        let reply = r#"{"findings":[{"id":"custom","summary":"found it","evidence":[2]}]}"#;
        let p = write_plugin("good", &wat_plugin(1, reply));
        let plugin = Plugin::load(&p).expect("loads");
        let found = plugin.analyze("{}").expect("analyses");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, "custom");
        assert_eq!(found[0].evidence, vec![2]);
        // Attribution comes from the host, not from the plugin's own output.
        assert_eq!(found[0].plugin, "good");
    }

    #[test]
    fn a_plugin_speaking_another_abi_is_refused_at_load() {
        let p = write_plugin("v99", &wat_plugin(99, r#"{"findings":[]}"#));
        match Plugin::load(&p) {
            Err(PluginError::AbiVersion { found, expected }) => {
                assert_eq!(found, 99);
                assert_eq!(expected, ABI_VERSION);
            }
            other => panic!("expected an ABI version refusal, got {other:?}"),
        }
    }

    /// The spec's first rule applies to third parties too.
    #[test]
    fn a_finding_without_evidence_is_rejected() {
        let reply = r#"{"findings":[{"id":"vague","summary":"something","evidence":[]}]}"#;
        let p = write_plugin("noevidence", &wat_plugin(1, reply));
        let plugin = Plugin::load(&p).expect("loads");
        match plugin.analyze("{}") {
            Err(PluginError::BadOutput(m)) => assert!(m.contains("evidence"), "{m}"),
            other => panic!("expected rejection, got {other:?}"),
        }
    }

    /// The sandbox claim, tested rather than asserted: a module that imports
    /// anything at all must fail to instantiate, because the host registers no
    /// imports whatsoever.
    #[test]
    fn a_plugin_that_imports_anything_cannot_instantiate() {
        let wat = r#"(module
            (import "env" "read_file" (func $rf (param i32) (result i32)))
            (memory (export "memory") 1)
            (func (export "sipnab_plugin_abi_version") (result i32) (i32.const 1))
            (func (export "sipnab_alloc") (param i32) (result i32) (i32.const 0))
            (func (export "sipnab_dealloc") (param i32 i32))
            (func (export "sipnab_analyze") (param i32 i32) (result i64) (i64.const 0)))"#;
        let p = write_plugin("importer", &wat::parse_str(wat).expect("assembles"));
        match Plugin::load(&p) {
            Err(PluginError::Abi(m)) => assert!(m.contains("import"), "{m}"),
            other => panic!("a plugin importing a host function must not load, got {other:?}"),
        }
    }

    /// An infinite loop must be cut off by fuel rather than hanging the capture.
    #[test]
    fn an_infinite_loop_runs_out_of_fuel() {
        let wat = r#"(module
            (memory (export "memory") 1)
            (func (export "sipnab_plugin_abi_version") (result i32) (i32.const 1))
            (func (export "sipnab_alloc") (param i32) (result i32) (i32.const 0))
            (func (export "sipnab_dealloc") (param i32 i32))
            (func (export "sipnab_analyze") (param i32 i32) (result i64)
              (loop $spin (br $spin))
              (i64.const 0)))"#;
        let p = write_plugin("spinner", &wat::parse_str(wat).expect("assembles"));
        let plugin = Plugin::load(&p).expect("loads — the loop is only reached in analyze");
        match plugin.analyze("{}") {
            Err(PluginError::Trap(_)) => {}
            other => panic!("expected fuel exhaustion, got {other:?}"),
        }
    }

    /// A plugin declaring a huge linear memory must be refused **before** the
    /// allocation happens.
    ///
    /// The first version of `instantiate` checked `mem.size()` after
    /// `instantiate_and_start`, which is too late: WASM allocates a module's
    /// declared minimum memory at instantiation, so a module declaring 2 GiB
    /// got 2 GiB before the check could object. On a capture host that is a
    /// remote-ish OOM triggered by loading a file someone was talked into
    /// downloading — the cap has to be enforced by the engine, not audited
    /// afterwards.
    #[test]
    fn a_plugin_declaring_huge_memory_is_refused_before_allocating() {
        // 32768 pages = 2 GiB, well over the 256-page (16 MiB) cap.
        let wat = r#"(module
            (memory (export "memory") 32768)
            (func (export "sipnab_plugin_abi_version") (result i32) (i32.const 1))
            (func (export "sipnab_alloc") (param i32) (result i32) (i32.const 0))
            (func (export "sipnab_dealloc") (param i32 i32))
            (func (export "sipnab_analyze") (param i32 i32) (result i64) (i64.const 0)))"#;
        let p = write_plugin("fatmem", &wat::parse_str(wat).expect("assembles"));
        match Plugin::load(&p) {
            Err(PluginError::Trap(m)) | Err(PluginError::Abi(m)) => {
                assert!(
                    m.to_lowercase().contains("memory") || m.to_lowercase().contains("limit"),
                    "expected a memory-limit refusal, got: {m}"
                );
            }
            other => panic!("a 2 GiB plugin must not instantiate, got {other:?}"),
        }
    }

    #[test]
    fn a_plugin_returning_garbage_is_reported_not_fatal() {
        let p = write_plugin("garbage", &wat_plugin(1, "not json at all"));
        let plugin = Plugin::load(&p).expect("loads");
        match plugin.analyze("{}") {
            Err(PluginError::BadOutput(_)) => {}
            other => panic!("expected BadOutput, got {other:?}"),
        }
    }

    #[test]
    fn a_missing_file_is_a_read_error() {
        match Plugin::load("/nonexistent/nope.wasm") {
            Err(PluginError::Read(_)) => {}
            other => panic!("expected Read, got {other:?}"),
        }
    }
}
