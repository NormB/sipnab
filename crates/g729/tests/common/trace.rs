// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The oracle's per-frame traces (`.git/g729-traces/*.jsonl.gz`, field
//! definitions in its README.md), parsed into compact records.
//!
//! The traces live only in the main checkout's `.git` and are never
//! committed; tests that read them are built only with the `g729_oracle`
//! cfg flag (`RUSTFLAGS='--cfg g729_oracle' cargo test -p sipnab-g729`). A missing trace fails the test.

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use serde_json::Value;

/// One field of a record.
#[derive(Debug, Clone)]
pub enum Val {
    /// JSON null.
    Null,
    /// An integer.
    Int(i64),
    /// An array of integers.
    Arr(Vec<i32>),
    /// A string.
    Str(String),
}

/// One `frame` or `subframe` record.
#[derive(Debug, Clone, Default)]
pub struct Rec {
    fields: HashMap<String, Val>,
}

impl Rec {
    /// Whether the field is present (present and null counts as present).
    pub fn has(&self, k: &str) -> bool {
        self.fields.contains_key(k)
    }
    /// An integer field; a test failure when absent or of another type.
    pub fn i(&self, k: &str) -> i64 {
        let v = self.oi(k);
        assert!(
            v.is_some(),
            "trace field {k}: expected integer, found {:?}",
            self.fields.get(k)
        );
        v.unwrap_or_default()
    }
    /// An integer field that may be absent or null.
    pub fn oi(&self, k: &str) -> Option<i64> {
        match self.fields.get(k) {
            Some(Val::Int(v)) => Some(*v),
            _ => None,
        }
    }
    /// An array field; a test failure when absent.
    pub fn a(&self, k: &str) -> &[i32] {
        let v = self.oa(k);
        assert!(
            v.is_some(),
            "trace field {k}: expected array, found {:?}",
            self.fields.get(k)
        );
        v.unwrap_or_default()
    }
    /// An array field that may be absent or null.
    pub fn oa(&self, k: &str) -> Option<&[i32]> {
        match self.fields.get(k) {
            Some(Val::Arr(v)) => Some(v),
            _ => None,
        }
    }
    /// A string field; a test failure when absent.
    pub fn s(&self, k: &str) -> &str {
        let v = match self.fields.get(k) {
            Some(Val::Str(v)) => Some(v.as_str()),
            _ => None,
        };
        assert!(
            v.is_some(),
            "trace field {k}: expected string, found {:?}",
            self.fields.get(k)
        );
        v.unwrap_or_default()
    }
    /// An array field as i16 values.
    pub fn a16(&self, k: &str) -> Vec<i16> {
        self.a(k).iter().map(|&v| v as i16).collect()
    }
}

/// One frame: its frame record and its two subframe records.
#[derive(Debug, Clone)]
pub struct Frame {
    /// The frame record.
    pub f: Rec,
    /// Subframe 0 and 1.
    pub s: [Rec; 2],
}

/// All 16 trace names, in the README's order.
pub const ALL: [&str; 16] = [
    "ALGTHM", "ERASURE", "FIXED", "LSP", "OVERFLOW", "PARITY", "PITCH", "SPEECH", "TAME", "TEST",
    "tstseq1a", "tstseq2a", "tstseq3a", "tstseq4a", "tstseq5", "tstseq6",
];

/// The Annex A traces.
pub const ANNEX_A: [&str; 10] = [
    "ALGTHM", "ERASURE", "FIXED", "LSP", "OVERFLOW", "PARITY", "PITCH", "SPEECH", "TAME", "TEST",
];

fn trace_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("G729_TRACES") {
        return PathBuf::from(d);
    }
    // When git cannot answer, the path below does not exist and every
    // loader reports it.
    let common = std::process::Command::new("git")
        .arg("-C")
        .arg(env!("CARGO_MANIFEST_DIR"))
        .args(["rev-parse", "--path-format=absolute", "--git-common-dir"])
        .env_remove("GIT_DIR")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();
    PathBuf::from(common.trim()).join("g729-traces")
}

/// The oracle's round-2 reference directory (`.git/g729-reference`), or
/// `$G729_REFERENCE`.
pub fn reference_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("G729_REFERENCE") {
        return PathBuf::from(d);
    }
    trace_dir().with_file_name("g729-reference")
}

fn convert(v: Value) -> Result<Rec, String> {
    let Value::Object(map) = v else {
        return Err("trace line is not an object".into());
    };
    let mut fields = HashMap::with_capacity(map.len());
    for (k, v) in map {
        let val = match v {
            Value::Null => Val::Null,
            Value::Number(n) => Val::Int(n.as_i64().ok_or_else(|| format!("{k}: not an integer"))?),
            Value::String(s) => Val::Str(s),
            Value::Array(a) => {
                let ints: Option<Vec<i32>> =
                    a.iter().map(|x| x.as_i64().map(|v| v as i32)).collect();
                Val::Arr(ints.ok_or_else(|| format!("{k}: an element is not an integer"))?)
            }
            other => return Err(format!("{k}: unexpected value {other:?}")),
        };
        fields.insert(k, val);
    }
    Ok(Rec { fields })
}

/// Every record of a gzip JSON Lines file.
fn records(path: &std::path::Path) -> Result<Vec<Rec>, String> {
    let file = std::fs::File::open(path)
        .map_err(|e| format!("oracle trace {} unreadable: {e}", path.display()))?;
    let mut out = Vec::new();
    for line in BufReader::new(flate2::read::GzDecoder::new(file)).lines() {
        let line = line.map_err(|e| format!("{}: {e}", path.display()))?;
        let value = serde_json::from_str(&line).map_err(|e| format!("{}: {e}", path.display()))?;
        out.push(convert(value)?);
    }
    Ok(out)
}

fn parse(name: &str) -> Result<Vec<Frame>, String> {
    let recs = records(&trace_dir().join(format!("{name}.jsonl.gz")))?;
    let (groups, rest) = recs.as_chunks::<3>();
    if !rest.is_empty() {
        return Err(format!("{name}: trailing records"));
    }
    let mut frames = Vec::with_capacity(groups.len());
    for [f, s0, s1] in groups {
        if f.oi("frame_index").is_none()
            || !matches!(f.fields.get("record"), Some(Val::Str(r)) if r == "frame")
        {
            return Err(format!("{name}: records out of order"));
        }
        frames.push(Frame {
            f: f.clone(),
            s: [s0.clone(), s1.clone()],
        });
    }
    Ok(frames)
}

/// The parsed trace, cached for the test binary.
pub fn load(name: &str) -> Result<Arc<Vec<Frame>>, String> {
    static CACHE: OnceLock<Mutex<HashMap<String, Arc<Vec<Frame>>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(t) = cache
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(name)
    {
        return Ok(t.clone());
    }
    let t = Arc::new(parse(name)?);
    cache
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(name.to_string(), t.clone());
    Ok(t)
}

/// The round-2 comfort-noise detail trace of an Annex A+B vector: one record
/// per comfort-noise subframe, plus one per lost-first-SID recovery
/// (`subframe` null).
pub fn load_cng(name: &str) -> Result<Vec<Rec>, String> {
    records(
        &reference_dir()
            .join("cng_traces")
            .join(format!("{name}.cng.jsonl.gz")),
    )
}
