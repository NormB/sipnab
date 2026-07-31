// SPDX-License-Identifier: MIT OR Apache-2.0

//! Worked example of a sipnab WASM plugin: **short answered calls**.
//!
//! A call that is answered and then torn down within a few seconds is a classic
//! operational signal — a bad route, a codec the far end hangs up on, or
//! wangiri-style fraud dialling. sipnab's seven built-in detections do not
//! cover it, because whether a short call is a problem depends entirely on the
//! traffic: on a click-to-call service three seconds is normal, on a wholesale
//! trunk it is a red flag. That is exactly the shape a plugin exists for — a
//! judgement the tool should not make for everybody.
//!
//! # The whole ABI, in one file
//!
//! Four exports, no imports:
//!
//! - `sipnab_plugin_abi_version` → `1`
//! - `sipnab_alloc` / `sipnab_dealloc` — so the host can place input inside
//!   this module's own linear memory
//! - `sipnab_analyze(ptr, len)` → `(ptr << 32) | len` of a JSON reply
//!
//! Uses `std`, which `wasm32-unknown-unknown` supports. A `no_std` plugin is
//! smaller but needs its own global allocator and panic handler, and an example
//! whose job is to teach the ABI should not spend a reader's attention on
//! either.
//!
//! # Why there is no serde here
//!
//! A plugin is a sandboxed leaf. It should stay small and auditable, and the
//! two fields this one needs are cheaper to read by hand than to derive. A
//! plugin doing real work should reach for `serde-json-core`, or `serde` with
//! `default-features = false` — this file is not arguing that hand-rolled
//! parsing is good, only that it is honest about what a 40-line detection
//! needs.
//!
//! Build:
//!
//! ```sh
//! cargo build --release --target wasm32-unknown-unknown \
//!   -p sipnab-plugin-example
//! ```

use std::alloc::{Layout, alloc as raw_alloc, dealloc as raw_dealloc};

/// Answered calls shorter than this are reported.
///
/// Deliberately a constant in the plugin rather than something the host
/// configures: the whole reason this is a plugin is that the right number is
/// site-specific, so a site edits and rebuilds. A host-configurable threshold
/// would be a built-in detection wearing a plugin's clothes.
const SHORT_CALL_MS: i64 = 5_000;

/// The ABI version this plugin is written against.
#[unsafe(no_mangle)]
pub extern "C" fn sipnab_plugin_abi_version() -> i32 {
    1
}

/// Allocate `len` bytes inside this module's linear memory for the host to
/// write into.
///
/// # Safety
/// The host writes exactly `len` bytes and passes the same pointer back.
#[unsafe(no_mangle)]
pub extern "C" fn sipnab_alloc(len: i32) -> i32 {
    if len <= 0 {
        return 0;
    }
    // Over-allocate by the length prefix so `dealloc` can reconstruct the
    // layout without the host having to remember it.
    let Ok(layout) = Layout::from_size_align(len as usize, 1) else {
        return 0;
    };
    // SAFETY: layout has non-zero size (len > 0 checked above).
    let p = unsafe { raw_alloc(layout) };
    p as i32
}

/// Release a buffer previously returned by [`sipnab_alloc`].
///
/// # Safety
/// `ptr`/`len` must be exactly what `sipnab_alloc` returned and was called with.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sipnab_dealloc(ptr: i32, len: i32) {
    if ptr <= 0 || len <= 0 {
        return;
    }
    if let Ok(layout) = Layout::from_size_align(len as usize, 1) {
        // SAFETY: caller contract — this pointer came from sipnab_alloc with
        // this same length.
        unsafe { raw_dealloc(ptr as *mut u8, layout) };
    }
}

/// Analyse one dialog.
///
/// # Safety
/// `ptr`/`len` must describe UTF-8 JSON the host wrote into this module's
/// memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sipnab_analyze(ptr: i32, len: i32) -> i64 {
    if ptr <= 0 || len <= 0 {
        return empty_reply();
    }
    // SAFETY: caller contract.
    let bytes = unsafe { std::slice::from_raw_parts(ptr as *const u8, len as usize) };
    let Ok(text) = std::str::from_utf8(bytes) else {
        return empty_reply();
    };

    let reply = match detect(text) {
        Some((answer_idx, bye_idx, ms)) => format!(
            r#"{{"findings":[{{"id":"short-answered-call","summary":"Call answered and torn down after {:.1}s (under {:.0}s) — check routing, codec negotiation, or dial fraud.","evidence":[{},{}]}}]}}"#,
            ms as f64 / 1000.0,
            SHORT_CALL_MS as f64 / 1000.0,
            answer_idx,
            bye_idx
        ),
        None => String::from(r#"{"findings":[]}"#),
    };

    leak_reply(reply)
}

/// Find a 2xx answer to an INVITE followed by a BYE inside the threshold.
///
/// Returns `(answer index, BYE index, elapsed ms)`.
fn detect(input: &str) -> Option<(usize, usize, i64)> {
    let mut answer: Option<(usize, i64)> = None;

    for msg in message_objects(input) {
        let index = field_int(msg, "\"index\":")? as usize;
        let offset = field_int(msg, "\"offset_ms\":")?;

        if answer.is_none()
            && field_int(msg, "\"status_code\":").is_some_and(|c| (200..300).contains(&c))
            && contains_field(msg, "\"cseq_method\":\"INVITE\"")
        {
            answer = Some((index, offset));
            continue;
        }
        if let Some((answer_idx, answered_at)) = answer
            && contains_field(msg, "\"method\":\"BYE\"")
        {
            let elapsed = offset - answered_at;
            if elapsed >= 0 && elapsed < SHORT_CALL_MS {
                return Some((answer_idx, index, elapsed));
            }
            return None;
        }
    }
    None
}

/// Split the `messages` array into per-object slices.
///
/// Brace-depth scanning rather than a JSON parser: the input shape is fixed and
/// host-generated, and this keeps the module small enough to read end to end.
/// A plugin consuming arbitrary JSON should use a real parser.
fn message_objects(input: &str) -> Vec<&str> {
    let Some(start) = input.find("\"messages\":[") else {
        return Vec::new();
    };
    let body = &input[start + "\"messages\":[".len()..];

    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut obj_start = 0usize;
    let mut in_string = false;
    let mut escaped = false;

    for (i, c) in body.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' if in_string => escaped = true,
            '"' => in_string = !in_string,
            '{' if !in_string => {
                if depth == 0 {
                    obj_start = i;
                }
                depth += 1;
            }
            '}' if !in_string => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    out.push(&body[obj_start..=i]);
                }
            }
            ']' if !in_string && depth == 0 => break,
            _ => {}
        }
    }
    out
}

/// Read an integer field, `None` when absent or `null`.
fn field_int(obj: &str, key: &str) -> Option<i64> {
    let rest = obj.get(obj.find(key)? + key.len()..)?.trim_start();
    let digits: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '-')
        .collect();
    digits.parse().ok()
}

/// Whether a `"key":"value"` pair appears, whitespace-insensitively enough for
/// host-generated JSON.
fn contains_field(obj: &str, needle: &str) -> bool {
    obj.contains(needle)
}

/// `(ptr << 32) | len` for an empty findings list.
fn empty_reply() -> i64 {
    leak_reply(String::from(r#"{"findings":[]}"#))
}

/// Hand a reply to the host as a packed pointer/length.
///
/// The buffer is deliberately leaked: the host reads it immediately, and the
/// whole instance is dropped after this dialog, so the "leak" lives for one
/// call. Freeing it before the host has read it would be the actual bug.
fn leak_reply(s: String) -> i64 {
    let bytes = s.into_bytes();
    let len = bytes.len() as i64;
    let boxed = bytes.into_boxed_slice();
    let ptr = Box::into_raw(boxed) as *mut u8 as i64;
    (ptr << 32) | len
}
