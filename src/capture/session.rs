//! Which capture a server is holding, behind one lock so a swap is atomic.
//!
//! Shared by REST and MCP so both doors name the same one.
//!
//! Lives here, outside both server modules, because **two doors must answer
//! with the same identity**. It was defined inside `src/mcp/server.rs` and
//! gated on the `mcp` feature, which left `GET /v1/stats` with no way to say
//! which capture its counts came from: an agent and an HTTP client polling one
//! process could not tell whether they were describing the same thing.
//!
//! Making REST hold its own copy would have been worse than the gap. The
//! identity ROTATES when `open_capture` swaps the file underneath, and two
//! copies would disagree from that moment on — a client comparing them would
//! be told the capture changed when it had not, or that it had not when it
//! did. One object, one lock, both doors.
//!
//! The two fields only MCP can populate are `#[cfg]`-gated rather than moved
//! out, the same shape
//! [`MediaDecrypt`](crate::pipeline::MediaDecrypt) uses for its `tls`-only
//! fields. An `api`-only build gets a struct without them and needs no
//! knowledge that they exist.

use std::sync::Arc;

/// Which capture this process holds, behind one lock so a swap is atomic.
///
/// Everything a swap changes lives here together on purpose. The identity and
/// the description have to move as one: an answer stamped with the old
/// instance and the new filename, or the reverse, is worse than either alone
/// because it looks self-consistent.
///
/// **Lock order: this lock, then the dialog store, then the stream store.**
/// `open_capture` clears both stores while holding this one, so a reader that
/// takes a store guard and then reaches for this lock deadlocks against it.
/// Every handler that stamps an answer with the identity holds all three
/// across the read for the same reason: releasing this lock first lets a swap
/// land between the id and the rows, and the answer then names a capture it
/// did not come from.
///
/// That rule now binds BOTH servers. `GET /v1/stats` takes the three in this
/// order for the same reason `capture_status` does, and because two doors
/// taking one set of locks in two orders is a deadlock waiting for load.
#[derive(Debug, Default)]
pub struct CaptureState {
    /// Identity of the capture currently loaded — see [`crate::provenance`].
    /// Rotated in the same critical section that clears the stores.
    pub identity: crate::provenance::CaptureIdentity,
    /// What this server is attached to, and when that capture began.
    ///
    /// An agent had no way to ask whether it was reading a live interface or
    /// replaying a file — so it could not tell whether "stop the capture"
    /// would lose anything, nor whether a quiet capture meant a quiet network
    /// or a finished file. Every downstream misjudgement traced back to that.
    pub context: Option<CaptureContext>,
    /// The background load filling this capture, while one is running.
    #[cfg(feature = "mcp")]
    pub load: Option<Arc<crate::mcp::load::CaptureLoad>>,
    /// The uprobe TLS capture feeding this server, while one is running.
    ///
    /// Held here rather than in a field of its own so that every check which
    /// already takes the capture lock — "is a live source running", "would
    /// stopping lose packets" — sees it without a second lock and a second
    /// chance to disagree with itself.
    #[cfg(feature = "mcp")]
    pub tls: Option<Arc<crate::mcp::tls_capture::TlsCapture>>,
    /// Holds the `Arc` import in builds that compile neither gated field.
    #[cfg(not(feature = "mcp"))]
    _marker: std::marker::PhantomData<Arc<()>>,
}

impl CaptureState {
    /// A state describing the capture named by `context`.
    ///
    /// A constructor rather than struct-update syntax at the call sites,
    /// because in a build without `mcp` this struct carries a PRIVATE
    /// `PhantomData` marker, and `..Default::default()` cannot reach a private
    /// field from another module. Callers would then compile under `full` and
    /// fail under `--features api` alone -- a combination only the pre-push
    /// hook and CI run, which is exactly where this was caught.
    #[must_use]
    pub fn describing(context: CaptureContext) -> Self {
        Self {
            context: Some(context),
            ..Default::default()
        }
    }
}

/// Where this server's packets come from.
#[derive(Debug, Clone)]
pub struct CaptureContext {
    /// `true` for a live interface, `false` for a file replay.
    pub live: bool,
    /// Interface name when live, file path when replaying.
    pub name: String,
    /// When capture began, for uptime.
    pub started: std::time::Instant,
    /// Path packets are being written to, when one was configured.
    ///
    /// `None` on a live capture means the packets exist only in memory: stop
    /// the process and they are gone. That is the fact `shutdown_server` has
    /// to consult before it agrees to stop anything.
    pub writing_to: Option<String>,
}

impl CaptureContext {
    /// How this capture describes itself: `live`, `file`, or `unknown` when
    /// there is no context at all.
    ///
    /// One spelling in one place, because both doors publish it and a client
    /// that learned `"live"` from one must not meet `"interface"` at the other.
    /// `unknown` is deliberately a real answer rather than a default: it is the
    /// field an agent consults before deciding whether stopping is destructive,
    /// and a wrong `"live"` would be worse than an admission of ignorance.
    #[must_use]
    pub fn source_label(ctx: Option<&Self>) -> &'static str {
        match ctx {
            Some(c) if c.live => "live",
            Some(_) => "file",
            None => "unknown",
        }
    }

    /// Whether stopping now would lose packets that exist nowhere else.
    ///
    /// True only for a LIVE capture with no output file. A file replay is by
    /// definition already on disk, and a live capture being written out is
    /// safe to stop.
    #[must_use]
    pub fn unsaved(ctx: Option<&Self>) -> bool {
        ctx.is_some_and(|c| c.live && c.writing_to.is_none())
    }
}

#[cfg(test)]
mod tests {
    use super::CaptureContext;

    fn ctx(live: bool, writing_to: Option<&str>) -> CaptureContext {
        CaptureContext {
            live,
            name: "eth0".into(),
            started: std::time::Instant::now(),
            writing_to: writing_to.map(ToString::to_string),
        }
    }

    /// `unknown` is a real answer, not a default that reads as a file replay.
    ///
    /// This is the field an agent consults before deciding whether stopping a
    /// capture is destructive. Answering `"file"` when nobody said would tell
    /// it the packets are already on disk.
    #[test]
    fn a_capture_with_no_context_says_unknown() {
        assert_eq!(CaptureContext::source_label(None), "unknown");
        assert_eq!(CaptureContext::source_label(Some(&ctx(true, None))), "live");
        assert_eq!(
            CaptureContext::source_label(Some(&ctx(false, None))),
            "file"
        );
    }

    /// Only a live capture with nowhere to write can lose packets.
    ///
    /// The three false cases matter as much as the true one: a file replay is
    /// already on disk, a live capture being written out is safe to stop, and
    /// an unknown source must not be reported as holding anything, because
    /// that would make every shutdown look destructive and train an operator
    /// to ignore the warning.
    #[test]
    fn only_a_live_capture_with_no_output_is_unsaved() {
        assert!(CaptureContext::unsaved(Some(&ctx(true, None))));
        assert!(!CaptureContext::unsaved(Some(&ctx(
            true,
            Some("/tmp/x.pcap")
        ))));
        assert!(!CaptureContext::unsaved(Some(&ctx(false, None))));
        assert!(!CaptureContext::unsaved(None));
    }
}
