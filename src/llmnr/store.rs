// SPDX-License-Identifier: MIT OR Apache-2.0

//! LLMNR host inventory.
//!
//! What LLMNR is worth in a VoIP capture is not the protocol — it is the
//! roster. Every query names a host that is *looking* for something, and every
//! response names a host that *owns* a name and says at which address. Between
//! them a capture taken anywhere on the LAN yields "these machines are here,
//! these are their hostnames", without sending a single packet.
//!
//! Two operator questions this answers directly:
//!
//!   * **Whose LAN is this?** A capture arrives with no topology notes. The
//!     hostnames tell you which segment it was taken on faster than reading
//!     the addresses does.
//!   * **Is LLMNR on at all?** It is the protocol the Responder tool abuses to
//!     harvest NTLM credentials — answer the broadcast, receive the hash — and
//!     it is normally disabled by policy for exactly that reason. Its presence
//!     in a capture is a security finding in its own right, independent of any
//!     call in the file.
//!
//! Process-global for the same reason `crate::stun::store` is: `--cores`
//! shards packets by outer host pair, and a broadcast name lookup shares a
//! pair with nothing. The lock is taken only when an LLMNR packet actually
//! arrives, and the read path checks one relaxed atomic first, so a capture
//! without LLMNR never touches it.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};

use chrono::{DateTime, Utc};
use indexmap::IndexMap;

use super::parser::LlmnrMessage;

/// One host seen speaking LLMNR, and what it said.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct LlmnrHost {
    /// The host's address, as seen on the wire.
    pub addr: IpAddr,
    /// Queries this host sent.
    pub queries: u64,
    /// Responses this host sent.
    pub responses: u64,
    /// Names this host asked about, first seen first.
    pub names_queried: Vec<String>,
    /// Names this host answered for — i.e. names it claims to own. This is
    /// the strongest identification in the protocol: a host only answers for
    /// itself.
    pub names_claimed: Vec<String>,
    /// First time this host was seen.
    pub first_seen: DateTime<Utc>,
    /// Most recent time this host was seen.
    pub last_seen: DateTime<Utc>,
}

/// Distinct hosts retained. A capture from a large flat network can hold
/// thousands; past this the totals stay exact and `dropped_hosts` says so.
pub const MAX_HOSTS: usize = 4_096;

/// Names retained per host, per direction. The thirty-third name a machine
/// looked up says nothing the first thirty-two did not, and an unbounded list
/// is a memory hole fed by a broadcast protocol (D17).
pub const MAX_NAMES_PER_HOST: usize = 32;

/// The inventory, plus counters that stay exact past the caps.
#[derive(Debug, Default)]
struct LlmnrStore {
    /// Hosts in first-seen order, keyed by address.
    hosts: IndexMap<IpAddr, LlmnrHost>,
    /// Every LLMNR packet recorded.
    packets: u64,
    /// Hosts never tracked because the store was at capacity.
    dropped_hosts: u64,
    /// Names never retained because a host was at its name cap.
    dropped_names: u64,
}

/// The inventory. `None` until the first LLMNR packet.
static LLMNR: parking_lot::Mutex<Option<Box<LlmnrStore>>> = parking_lot::Mutex::new(None);

/// Whether any LLMNR has been recorded, readable without the lock.
static LLMNR_SEEN: AtomicBool = AtomicBool::new(false);

/// What LLMNR revealed about this run.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct LlmnrReport {
    /// Hosts seen, first-seen first.
    pub hosts: Vec<LlmnrHost>,
    /// Total LLMNR packets classified.
    pub packets: u64,
    /// Hosts not tracked because the store was full. Non-zero means `hosts`
    /// is a sample rather than the roster.
    pub dropped_hosts: u64,
    /// Names not retained because a host hit its cap.
    pub dropped_names: u64,
}

impl LlmnrReport {
    /// Whether the run saw no LLMNR at all.
    pub fn is_empty(&self) -> bool {
        self.packets == 0
    }

    /// Every distinct name any host claimed ownership of, deduplicated. These
    /// are hostnames the capture proves are live on the segment.
    pub fn claimed_names(&self) -> Vec<&str> {
        let mut out: Vec<&str> = Vec::new();
        for name in self.hosts.iter().flat_map(|h| h.names_claimed.iter()) {
            if !out.contains(&name.as_str()) {
                out.push(name);
            }
        }
        out
    }

    /// Names that were asked about but that nothing in the capture ever
    /// answered for. Each is a lookup that failed on this segment — the reason
    /// the querying host fell back to LLMNR in the first place, still
    /// unresolved.
    pub fn unresolved_names(&self) -> Vec<&str> {
        let claimed = self.claimed_names();
        let mut out: Vec<&str> = Vec::new();
        for name in self.hosts.iter().flat_map(|h| h.names_queried.iter()) {
            let name = name.as_str();
            if !claimed.contains(&name) && !out.contains(&name) {
                out.push(name);
            }
        }
        out
    }
}

/// Record one parsed LLMNR message against the global inventory.
///
/// `src` is the sender: for a query that is the host looking something up, for
/// a response the host that owns the name.
///
/// # Side effects
///
/// Takes the process-global LLMNR lock and arms the fast path for readers.
pub fn record_llmnr(msg: &LlmnrMessage, src: IpAddr, timestamp: DateTime<Utc>) {
    let mut guard = LLMNR.lock();
    let store = guard.get_or_insert_with(Box::<LlmnrStore>::default);
    store.packets += 1;

    if !store.hosts.contains_key(&src) && store.hosts.len() >= MAX_HOSTS {
        store.dropped_hosts += 1;
        LLMNR_SEEN.store(true, Ordering::Release);
        return;
    }

    let host = store.hosts.entry(src).or_insert_with(|| LlmnrHost {
        addr: src,
        queries: 0,
        responses: 0,
        names_queried: Vec::new(),
        names_claimed: Vec::new(),
        first_seen: timestamp,
        last_seen: timestamp,
    });
    host.last_seen = timestamp;

    let mut dropped = 0u64;
    if msg.is_response {
        host.responses += 1;
        // A responder answers only for names it owns, so the answer section is
        // this host's own identity. The question section of a response is the
        // echoed query and says nothing about the responder.
        for answer in &msg.answers {
            dropped += push_capped(&mut host.names_claimed, &answer.name);
        }
    } else {
        host.queries += 1;
        for question in &msg.questions {
            dropped += push_capped(&mut host.names_queried, &question.name);
        }
    }
    store.dropped_names += dropped;

    // Release, paired with the Acquire in `llmnr_report`.
    LLMNR_SEEN.store(true, Ordering::Release);
}

/// Append a name if it is new and there is room. Returns 1 when the cap
/// refused it, so the caller can keep the count exact.
fn push_capped(names: &mut Vec<String>, name: &str) -> u64 {
    if name.is_empty() || names.iter().any(|n| n == name) {
        return 0;
    }
    if names.len() >= MAX_NAMES_PER_HOST {
        return 1;
    }
    names.push(name.to_string());
    0
}

/// The LLMNR inventory for this run.
///
/// Empty when the capture held none, answered by one relaxed load without
/// taking the lock.
pub fn llmnr_report() -> LlmnrReport {
    if !LLMNR_SEEN.load(Ordering::Acquire) {
        return LlmnrReport::default();
    }
    let guard = LLMNR.lock();
    let Some(store) = guard.as_ref() else {
        return LlmnrReport::default();
    };
    LlmnrReport {
        hosts: store.hosts.values().cloned().collect(),
        packets: store.packets,
        dropped_hosts: store.dropped_hosts,
        dropped_names: store.dropped_names,
    }
}

/// Discard the recorded inventory.
///
/// The store is process-global, so a process reading several captures in
/// sequence — and a test asserting on the counts — needs a way back to zero.
pub fn reset_llmnr() {
    *LLMNR.lock() = None;
    LLMNR_SEEN.store(false, Ordering::Release);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llmnr::parser::{LlmnrAnswer, LlmnrMessage, LlmnrQuestion};
    use serial_test::serial;

    fn ts(ms: i64) -> DateTime<Utc> {
        DateTime::from_timestamp_millis(ms).expect("valid timestamp")
    }

    fn query(name: &str) -> LlmnrMessage {
        LlmnrMessage {
            id: 0x8006,
            is_response: false,
            conflict: false,
            truncated: false,
            tentative: false,
            rcode: 0,
            questions: vec![LlmnrQuestion {
                name: name.to_string(),
                qtype: 1,
            }],
            answers: Vec::new(),
        }
    }

    fn response(name: &str, addr: &str) -> LlmnrMessage {
        LlmnrMessage {
            id: 0x8006,
            is_response: true,
            conflict: false,
            truncated: false,
            tentative: false,
            rcode: 0,
            questions: Vec::new(),
            answers: vec![LlmnrAnswer {
                name: name.to_string(),
                rtype: 1,
                ttl: 30,
                address: Some(addr.parse().expect("valid addr")),
            }],
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("valid addr")
    }

    #[test]
    #[serial(llmnr_store)]
    fn a_query_records_the_asking_host_and_the_name() {
        reset_llmnr();
        record_llmnr(&query("GHS08"), ip("192.0.2.79"), ts(0));

        let report = llmnr_report();
        assert_eq!(report.packets, 1);
        assert_eq!(report.hosts.len(), 1);
        assert_eq!(report.hosts[0].addr, ip("192.0.2.79"));
        assert_eq!(report.hosts[0].queries, 1);
        assert_eq!(report.hosts[0].names_queried, vec!["GHS08".to_string()]);
        reset_llmnr();
    }

    /// A responder answers only for itself, so its answer section is an
    /// identification: this address owns this hostname.
    #[test]
    #[serial(llmnr_store)]
    fn a_response_identifies_the_responding_host() {
        reset_llmnr();
        record_llmnr(&response("GHS08", "192.0.2.80"), ip("192.0.2.80"), ts(5));

        let report = llmnr_report();
        assert_eq!(report.hosts[0].names_claimed, vec!["GHS08".to_string()]);
        assert_eq!(report.claimed_names(), vec!["GHS08"]);
        reset_llmnr();
    }

    /// The operationally interesting case from the motivating capture: a host
    /// asks repeatedly and nothing on the segment ever answers.
    #[test]
    #[serial(llmnr_store)]
    fn a_name_nothing_answers_for_is_reported_unresolved() {
        reset_llmnr();
        record_llmnr(&query("GHS08"), ip("192.0.2.79"), ts(0));
        record_llmnr(&query("GHS08"), ip("192.0.2.79"), ts(100));

        let report = llmnr_report();
        assert_eq!(report.unresolved_names(), vec!["GHS08"]);
        assert!(report.claimed_names().is_empty());
        reset_llmnr();
    }

    #[test]
    #[serial(llmnr_store)]
    fn an_answered_name_is_not_reported_unresolved() {
        reset_llmnr();
        record_llmnr(&query("GHS08"), ip("192.0.2.79"), ts(0));
        record_llmnr(&response("GHS08", "192.0.2.80"), ip("192.0.2.80"), ts(5));

        let report = llmnr_report();
        assert!(report.unresolved_names().is_empty());
        assert_eq!(report.claimed_names(), vec!["GHS08"]);
        reset_llmnr();
    }

    #[test]
    #[serial(llmnr_store)]
    fn repeated_queries_do_not_duplicate_the_name() {
        reset_llmnr();
        for n in 0..5 {
            record_llmnr(&query("GHS08"), ip("192.0.2.79"), ts(n));
        }
        let report = llmnr_report();
        assert_eq!(report.hosts[0].queries, 5);
        assert_eq!(report.hosts[0].names_queried.len(), 1);
        reset_llmnr();
    }

    #[test]
    #[serial(llmnr_store)]
    fn the_name_cap_is_counted_rather_than_silently_swallowing() {
        reset_llmnr();
        for n in 0..(MAX_NAMES_PER_HOST + 4) {
            record_llmnr(&query(&format!("host{n}")), ip("192.0.2.79"), ts(n as i64));
        }
        let report = llmnr_report();
        assert_eq!(report.hosts[0].names_queried.len(), MAX_NAMES_PER_HOST);
        assert_eq!(report.dropped_names, 4);
        reset_llmnr();
    }

    #[test]
    #[serial(llmnr_store)]
    fn a_capture_without_llmnr_reports_empty() {
        reset_llmnr();
        assert!(llmnr_report().is_empty());
    }
}
