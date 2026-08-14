// SPDX-License-Identifier: MIT OR Apache-2.0

//! Name resolution for displayed addresses (Wireshark-style).
//!
//! A single [`NameResolver`] turns an IP address into a human-readable name
//! from three sources, in precedence order:
//!
//! 1. **Manual mappings** — operator-entered `IP -> name` pairs.
//! 2. **Hosts file** — entries parsed from an `/etc/hosts`-format file.
//! 3. **Reverse DNS** — PTR lookups, performed by a background worker so the
//!    UI never blocks; results are cached (including negative results).
//!
//! Resolution is gated by a [`NameMode`]: `Off` shows raw IPs, `Names` uses
//! the offline sources only (no network), and `Dns` additionally consults
//! reverse DNS. The resolver is cheap to share: wrap it in an `Arc` and hand
//! clones to the TUI and the output writers.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc::SyncSender;

use indexmap::{IndexMap, IndexSet};
use parking_lot::RwLock;

/// How aggressively addresses are resolved to names for display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NameMode {
    /// Show raw IP addresses (the default — no resolution).
    #[default]
    Off,
    /// Manual mappings + hosts file only. No network traffic.
    Names,
    /// Also consult reverse DNS (PTR lookups).
    Dns,
}

impl NameMode {
    /// Cycle to the next mode (Off -> Names -> Dns -> Off).
    pub fn next(self) -> Self {
        match self {
            Self::Off => Self::Names,
            Self::Names => Self::Dns,
            Self::Dns => Self::Off,
        }
    }

    /// Short status-line label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Off => "Names: Off",
            Self::Names => "Names: Static",
            Self::Dns => "Names: DNS",
        }
    }
}

/// Shared mutable state behind the resolver's lock: the three name
/// sources in precedence order, the reverse-DNS caches, and the
/// generation counter.
#[derive(Debug, Default)]
struct Inner {
    /// Operator-entered mappings (highest priority).
    manual: HashMap<IpAddr, String>,
    /// Entries loaded from a hosts file.
    hosts: HashMap<IpAddr, String>,
    /// Names read from a capture file's Name Resolution Block (untrusted hint).
    file: HashMap<IpAddr, String>,
    /// Reverse-DNS results: `Some(name)` resolved, `None` looked-up-but-no-name.
    /// Bounded to [`MAX_DNS_CACHE_ENTRIES`] with oldest-inserted-out eviction,
    /// so a long-running capture seeing endless unique IPs cannot grow it
    /// without limit.
    dns_cache: IndexMap<IpAddr, Option<String>>,
    /// IPs already handed to the DNS worker, so we enqueue each at most once.
    /// The marker is cleared when the result lands (or when a full queue drops
    /// the request), and the set itself is bounded to the same cap as the
    /// cache, so in-flight tracking can never starve `dns_cache`.
    dns_requested: IndexSet<IpAddr>,
    /// Mutation counter, bumped by every change that can alter a resolved
    /// label (manual/hosts/file edits, DNS results landing). Cache
    /// invalidation signal — see [`NameResolver::generation`].
    generation: u64,
}

/// Maximum reverse-DNS cache entries (positive and negative) retained; the
/// in-flight `dns_requested` set is held to the same cap. At capacity the
/// oldest-inserted entry is evicted (`IndexMap::shift_remove_index(0)` — the
/// same oldest-out pattern as `StreamStore::sdp_endpoints`). Sized to the
/// same order as `rate_limit::DEFAULT_MAX_TRACKED_PEERS`: a few thousand
/// IP→name entries covers any realistic active-host set.
const MAX_DNS_CACHE_ENTRIES: usize = 4096;

/// Capacity of the queue feeding the reverse-DNS worker. Lookups are enqueued
/// with `try_send` and DROPPED when the queue is full — the capture/render
/// path must never block on a slow resolver, and a dropped request is
/// harmless: the IP just displays unresolved and is re-requested on a later
/// lookup. PTR lookups can block for seconds each, so queueing more than this
/// buys nothing.
const DNS_QUEUE_CAPACITY: usize = 1024;

impl Inner {
    /// Record a completed reverse-DNS lookup, evicting the oldest cache entry
    /// at capacity, and clear the in-flight marker so the set stays in step
    /// with the cache. Bumps the generation counter (a label may change).
    fn cache_dns_result(&mut self, ip: IpAddr, name: Option<String>) {
        if self.dns_cache.len() >= MAX_DNS_CACHE_ENTRIES && !self.dns_cache.contains_key(&ip) {
            self.dns_cache.shift_remove_index(0);
        }
        self.dns_cache.insert(ip, name);
        self.dns_requested.shift_remove(&ip);
        self.generation += 1;
    }

    /// Mark `ip` as handed to the DNS worker. Returns `false` when it is
    /// already cached or already in flight (nothing to enqueue). Bounded: at
    /// capacity the oldest marker is evicted — worst case that IP is looked
    /// up twice, which is harmless.
    fn mark_requested(&mut self, ip: IpAddr) -> bool {
        if self.dns_cache.contains_key(&ip) {
            return false;
        }
        if self.dns_requested.len() >= MAX_DNS_CACHE_ENTRIES && !self.dns_requested.contains(&ip) {
            self.dns_requested.shift_remove_index(0);
        }
        self.dns_requested.insert(ip)
    }
}

/// Maximum length (in bytes) of a name we will store/emit. DNS names are
/// capped at 253 characters; we reject anything longer to keep records sane.
pub const MAX_NAME_LEN: usize = 253;

/// True if `name` is acceptable to store in a Name Resolution Block: non-empty,
/// no interior NUL, within [`MAX_NAME_LEN`], and free of control characters.
/// (UTF-8 validity is guaranteed by the `&str` type.)
pub fn is_valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && !name.bytes().any(|b| b == 0)
        && !name.chars().any(|c| c.is_control())
}

/// Thread-safe IP -> name resolver shared across the TUI and output writers.
#[derive(Debug, Default)]
pub struct NameResolver {
    /// Shared name tables and caches, behind a read-write lock.
    inner: Arc<RwLock<Inner>>,
    /// Bounded channel to the reverse-DNS worker ([`DNS_QUEUE_CAPACITY`]
    /// pending lookups); `None` when reverse DNS is disabled.
    dns_tx: Option<SyncSender<IpAddr>>,
}

impl NameResolver {
    /// A resolver with no reverse-DNS worker (offline sources only).
    pub fn new() -> Self {
        Self::default()
    }

    /// A resolver that performs reverse DNS on a background worker thread.
    ///
    /// When `enabled` is false this is equivalent to [`NameResolver::new`].
    ///
    /// # Side effects
    /// When enabled, spawns a detached `sipnab-dns` worker thread that
    /// serves PTR lookups until the resolver (the channel sender) is
    /// dropped; each completed lookup writes the (bounded) DNS cache and
    /// bumps the generation counter. The work queue holds at most
    /// `DNS_QUEUE_CAPACITY` pending lookups; overflow is dropped, never
    /// queued unbounded (see `enqueue_dns`).
    pub fn with_reverse_dns(enabled: bool) -> Self {
        if !enabled {
            return Self::new();
        }
        let inner: Arc<RwLock<Inner>> = Arc::default();
        let (tx, rx) = std::sync::mpsc::sync_channel::<IpAddr>(DNS_QUEUE_CAPACITY);
        let worker_inner = Arc::clone(&inner);
        // Detached worker: it exits when the sender is dropped (resolver gone).
        let _ = std::thread::Builder::new()
            .name("sipnab-dns".to_string())
            .spawn(move || {
                while let Ok(ip) = rx.recv() {
                    let name = reverse_dns(ip);
                    worker_inner.write().cache_dns_result(ip, name);
                }
            });
        Self {
            inner,
            dns_tx: Some(tx),
        }
    }

    /// Resolve `ip` to a name under `mode`, or `None` to use the raw IP.
    ///
    /// Sources are consulted in precedence order: manual, hosts, file,
    /// then (in `Dns` mode only) the reverse-DNS cache. In `Dns` mode an
    /// unknown IP is enqueued for the background worker as a side effect
    /// and `None` is returned for now; the name appears on a later lookup.
    /// A cached negative DNS result (no PTR record) also returns `None`.
    pub fn name(&self, ip: IpAddr, mode: NameMode) -> Option<String> {
        if mode == NameMode::Off {
            return None;
        }
        {
            let inner = self.inner.read();
            if let Some(n) = inner.manual.get(&ip) {
                return Some(n.clone());
            }
            if let Some(n) = inner.hosts.get(&ip) {
                return Some(n.clone());
            }
            if let Some(n) = inner.file.get(&ip) {
                return Some(n.clone());
            }
            if mode == NameMode::Dns {
                match inner.dns_cache.get(&ip) {
                    Some(Some(n)) => return Some(n.clone()),
                    Some(None) => return None, // looked up, no PTR record
                    None => {}                 // fall through to enqueue below
                }
            }
        }
        if mode == NameMode::Dns {
            self.enqueue_dns(ip);
        }
        None
    }

    /// Format `ip:port` for display, substituting a resolved name for the IP.
    pub fn label(&self, ip: IpAddr, port: u16, mode: NameMode) -> String {
        match self.name(ip, mode) {
            Some(n) => format!("{n}:{port}"),
            None => format!("{ip}:{port}"),
        }
    }

    /// Resolve `ip` to a name (no port) for display, falling back to the raw
    /// IP. Used by views that show a bare address (e.g. the call list).
    pub fn label_ip(&self, ip: IpAddr, mode: NameMode) -> String {
        self.name(ip, mode).unwrap_or_else(|| ip.to_string())
    }

    /// Like [`label`](Self::label) for a [`SocketAddr`]. Falls back to the
    /// socket's own formatting (which brackets IPv6) when unresolved.
    pub fn label_socket(&self, sa: SocketAddr, mode: NameMode) -> String {
        match self.name(sa.ip(), mode) {
            Some(n) => format!("{n}:{}", sa.port()),
            None => sa.to_string(),
        }
    }

    /// Enqueue an IP for reverse-DNS resolution (at most once per IP).
    ///
    /// No-op without a worker (`dns_tx` is `None`) or when the IP is
    /// already cached or already requested. Otherwise records the IP in
    /// `dns_requested` and hands it to the worker with a non-blocking
    /// `try_send`: when the bounded queue is full (or the worker is gone)
    /// the request is DROPPED and un-marked — the IP just displays
    /// unresolved and a later lookup retries it. The capture/render path
    /// must never block here.
    fn enqueue_dns(&self, ip: IpAddr) {
        let Some(tx) = &self.dns_tx else { return };
        if !self.inner.write().mark_requested(ip) {
            return;
        }
        if let Err(err) = tx.try_send(ip) {
            self.inner.write().dns_requested.shift_remove(&ip);
            if matches!(err, std::sync::mpsc::TrySendError::Full(_)) {
                tracing::debug!(
                    "reverse-DNS queue full ({DNS_QUEUE_CAPACITY}); dropping lookup for {ip}"
                );
            }
        }
    }

    // ── Manual mappings ────────────────────────────────────────────────

    /// Add or replace a manual mapping for `ip`; bumps the generation
    /// counter so cached labels re-derive.
    pub fn set_manual(&self, ip: IpAddr, name: String) {
        let mut inner = self.inner.write();
        inner.manual.insert(ip, name);
        inner.generation += 1;
    }

    /// Remove a manual mapping. Returns the previous name, if any.
    /// Bumps the generation counter only when an entry was actually
    /// removed, so a no-op remove leaves cached labels valid.
    pub fn remove_manual(&self, ip: &IpAddr) -> Option<String> {
        let mut inner = self.inner.write();
        let removed = inner.manual.remove(ip);
        if removed.is_some() {
            inner.generation += 1;
        }
        removed
    }

    /// Monotonic mutation counter: bumped by every change that can alter a
    /// resolved label — manual add/remove, hosts/file loads, and reverse-DNS
    /// results landing from the worker. Lookups never bump it. The TUI keys
    /// its cached ladder layout (whose participant labels come from this
    /// resolver) on the pair (generation, [`NameMode`]), so a late DNS
    /// answer re-derives the layout instead of leaving a stale label.
    pub fn generation(&self) -> u64 {
        self.inner.read().generation
    }

    /// Snapshot of all manual mappings, sorted by IP, for the manager UI.
    pub fn manual_entries(&self) -> Vec<(IpAddr, String)> {
        let mut v: Vec<(IpAddr, String)> = self
            .inner
            .read()
            .manual
            .iter()
            .map(|(ip, n)| (*ip, n.clone()))
            .collect();
        v.sort_by_key(|(ip, _)| *ip);
        v
    }

    // ── Name Resolution Block (pcapng) serialization ───────────────────

    /// Produce validated IP → names entries for a pcapng Name Resolution Block.
    ///
    /// One entry per IP, names ordered by source preference (manual, then
    /// hosts, then file, then — only when `include_dns` — reverse DNS), with
    /// duplicates and invalid names dropped. IPs with no valid name are omitted.
    /// Sorted by IP for deterministic output.
    pub fn nrb_entries(&self, include_dns: bool) -> Vec<(IpAddr, Vec<String>)> {
        let inner = self.inner.read();
        let mut ips: Vec<IpAddr> = inner
            .manual
            .keys()
            .chain(inner.hosts.keys())
            .chain(inner.file.keys())
            .copied()
            .collect();
        if include_dns {
            ips.extend(
                inner
                    .dns_cache
                    .iter()
                    .filter_map(|(ip, n)| n.as_ref().map(|_| *ip)),
            );
        }
        ips.sort_unstable();
        ips.dedup();

        let mut out = Vec::new();
        for ip in ips {
            let mut names: Vec<String> = Vec::new();
            let push = |candidate: Option<&String>, names: &mut Vec<String>| {
                if let Some(n) = candidate
                    && is_valid_name(n)
                    && !names.iter().any(|e| e == n)
                {
                    names.push(n.clone());
                }
            };
            push(inner.manual.get(&ip), &mut names);
            push(inner.hosts.get(&ip), &mut names);
            push(inner.file.get(&ip), &mut names);
            if include_dns {
                push(
                    inner.dns_cache.get(&ip).and_then(|n| n.as_ref()),
                    &mut names,
                );
            }
            if !names.is_empty() {
                out.push((ip, names));
            }
        }
        out
    }

    /// Load IP → name pairs read from a capture file's Name Resolution Block
    /// into the low-priority `file` source. Invalid names are skipped; the
    /// first valid name for each IP wins (already-present IPs are not
    /// replaced). Returns how many new entries were accepted. Bumps the
    /// generation counter.
    pub fn load_file_names<I>(&self, entries: I) -> usize
    where
        I: IntoIterator<Item = (IpAddr, String)>,
    {
        let mut inner = self.inner.write();
        let mut n = 0;
        for (ip, name) in entries {
            if is_valid_name(&name) {
                inner.file.entry(ip).or_insert_with(|| {
                    n += 1;
                    name
                });
            }
        }
        inner.generation += 1;
        n
    }

    /// Number of names currently loaded from capture files.
    pub fn file_name_count(&self) -> usize {
        self.inner.read().file.len()
    }

    // ── Hosts file ─────────────────────────────────────────────────────

    /// Replace the hosts table (in full) from `/etc/hosts`-format text.
    /// Bumps the generation counter.
    pub fn load_hosts_str(&self, text: &str) {
        let mut inner = self.inner.write();
        inner.hosts = parse_hosts(text);
        inner.generation += 1;
    }

    /// Load a hosts file from disk, replacing the hosts table.
    ///
    /// # Errors
    /// The file at `path` cannot be read.
    ///
    /// # Side effects
    /// Reads `path`; on success replaces the hosts table and bumps the
    /// generation counter.
    pub fn load_hosts_file(&self, path: &Path) -> std::io::Result<()> {
        let text = std::fs::read_to_string(path)?;
        self.load_hosts_str(&text);
        Ok(())
    }

    /// Load manual mappings from an `/etc/hosts`-format file (operator
    /// names). Unlike `load_hosts_file` this extends the manual table
    /// (replacing colliding IPs) rather than clearing it first.
    ///
    /// # Errors
    /// The file at `path` cannot be read.
    ///
    /// # Side effects
    /// Reads `path`; on success merges into the manual table and bumps
    /// the generation counter.
    pub fn load_manual_file(&self, path: &Path) -> std::io::Result<()> {
        let text = std::fs::read_to_string(path)?;
        let parsed = parse_hosts(&text);
        let mut inner = self.inner.write();
        inner.manual.extend(parsed);
        inner.generation += 1;
        Ok(())
    }

    /// Serialize manual mappings to `/etc/hosts` line format (one
    /// `IP<TAB>name` line per entry, sorted by IP). Entries whose name
    /// fails `is_valid_name` are skipped, never emitted.
    pub fn manual_to_hosts_format(&self) -> String {
        let mut out = String::new();
        for (ip, name) in self.manual_entries() {
            // Defense in depth: never emit a name that would corrupt the
            // hosts-format round-trip (an embedded newline injects a second
            // record; a tab/`#`/control char breaks the IP↔name split).
            if !is_valid_name(&name) {
                continue;
            }
            out.push_str(&format!("{ip}\t{name}\n"));
        }
        out
    }

    /// Persist manual mappings to `path` in `/etc/hosts` line format.
    ///
    /// Writes atomically (temp file in the same directory + rename) so an
    /// interrupted or failing write never truncates the operator's existing
    /// names file, and a symlink at `path` is replaced rather than written
    /// through. The atomic helper depends on `tempfile` (a `native` dep); the
    /// sole caller is the native TUI, but this method compiles in every feature
    /// combo, so non-native builds fall back to a plain write.
    ///
    /// # Errors
    /// The parent directory cannot be created, or the write/rename fails.
    ///
    /// # Side effects
    /// Creates `path`'s parent directory if missing and writes the file.
    pub fn save_manual_file(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let contents = self.manual_to_hosts_format();
        #[cfg(feature = "native")]
        {
            // `w` is `&mut dyn Write`; trait methods are callable on the trait
            // object without importing the trait.
            crate::capture::atomic::write_atomic(path, |w| w.write_all(contents.as_bytes()))
        }
        #[cfg(not(feature = "native"))]
        {
            std::fs::write(path, contents)
        }
    }
}

/// Parse `/etc/hosts`-format text into an IP -> first-name map.
///
/// Each non-comment line is `IP name [aliases...]`; `#` starts a comment. The
/// first name listed for an IP wins; later duplicates are ignored. Lines
/// with an unparsable IP or no name are skipped silently. Pure.
fn parse_hosts(text: &str) -> HashMap<IpAddr, String> {
    let mut map = HashMap::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut it = line.split_whitespace();
        let Some(ip_str) = it.next() else { continue };
        let Ok(ip) = ip_str.parse::<IpAddr>() else {
            continue;
        };
        if let Some(name) = it.next() {
            map.entry(ip).or_insert_with(|| name.to_string());
        }
    }
    map
}

/// Reverse-DNS (PTR) lookup via the system resolver (`getnameinfo`).
///
/// Returns `Some(hostname)` only when a name actually exists (`NI_NAMEREQD`);
/// a numeric/no-record result yields `None`.
///
/// # Side effects
/// Emits DNS queries on the network and blocks the calling thread until
/// the system resolver answers or times out — call from the worker
/// thread only.
#[cfg(all(unix, feature = "native"))]
fn reverse_dns(ip: IpAddr) -> Option<String> {
    use std::ffi::CStr;

    let mut host = [0 as libc::c_char; libc::NI_MAXHOST as usize];
    // SAFETY: we zero-initialize the sockaddr, set only valid fields, and pass
    // the matching length to getnameinfo. `host` is a fixed buffer of the
    // documented maximum size; getnameinfo NUL-terminates within it.
    let ret = unsafe {
        match ip {
            IpAddr::V4(v4) => {
                let mut sa: libc::sockaddr_in = std::mem::zeroed();
                sa.sin_family = libc::AF_INET as libc::sa_family_t;
                sa.sin_addr = libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.octets()),
                };
                libc::getnameinfo(
                    &sa as *const libc::sockaddr_in as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    host.as_mut_ptr(),
                    host.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
            IpAddr::V6(v6) => {
                let mut sa: libc::sockaddr_in6 = std::mem::zeroed();
                sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                sa.sin6_addr = libc::in6_addr {
                    s6_addr: v6.octets(),
                };
                libc::getnameinfo(
                    &sa as *const libc::sockaddr_in6 as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                    host.as_mut_ptr(),
                    host.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
        }
    };
    if ret != 0 {
        return None;
    }
    // SAFETY: getnameinfo NUL-terminated `host` on success.
    let cstr = unsafe { CStr::from_ptr(host.as_ptr()) };
    cstr.to_str()
        .ok()
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
}

/// Fallback when reverse DNS isn't available (non-unix or no `native` feature).
#[cfg(not(all(unix, feature = "native")))]
fn reverse_dns(_ip: IpAddr) -> Option<String> {
    None
}

/// Unit tests for name-mode cycling, source precedence, generation
/// tracking, name validation, NRB serialization, and persistence.
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Parse `s` into an `IpAddr`, panicking on invalid input (test helper).
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// `NameMode` defaults to Off, cycles Off→Names→Dns→Off, and each
    /// mode has its status-line label.
    #[test]
    fn mode_cycles_and_labels() {
        assert_eq!(NameMode::default(), NameMode::Off);
        assert_eq!(NameMode::Off.next(), NameMode::Names);
        assert_eq!(NameMode::Names.next(), NameMode::Dns);
        assert_eq!(NameMode::Dns.next(), NameMode::Off);
        assert_eq!(NameMode::Off.label(), "Names: Off");
        assert_eq!(NameMode::Names.label(), "Names: Static");
        assert_eq!(NameMode::Dns.label(), "Names: DNS");
    }

    /// In Off mode even a mapped IP stays raw.
    #[test]
    fn off_mode_never_resolves() {
        let r = NameResolver::new();
        r.set_manual(ip("10.0.0.2"), "sbc".into());
        assert_eq!(r.name(ip("10.0.0.2"), NameMode::Off), None);
        assert_eq!(
            r.label(ip("10.0.0.2"), 5060, NameMode::Off),
            "10.0.0.2:5060"
        );
    }

    /// A manual mapping wins over a hosts-file entry for the same IP.
    #[test]
    fn manual_takes_precedence_over_hosts() {
        let r = NameResolver::new();
        r.load_hosts_str("10.0.0.2 hosts-name\n");
        r.set_manual(ip("10.0.0.2"), "manual-name".into());
        assert_eq!(
            r.name(ip("10.0.0.2"), NameMode::Names).as_deref(),
            Some("manual-name")
        );
    }

    /// WS4.3c: the TUI keys its cached ladder layout on the resolver
    /// generation, so EVERY mutation that can change a label must bump it —
    /// and lookups must NOT, or the cache would never hit.
    #[test]
    fn generation_bumps_on_name_mutations_but_not_lookups() {
        let r = NameResolver::new();
        let g0 = r.generation();

        r.set_manual(ip("10.0.0.2"), "sbc".into());
        let g1 = r.generation();
        assert!(g1 > g0, "set_manual must bump the generation");

        r.load_hosts_str("10.0.0.3 pbx\n");
        let g2 = r.generation();
        assert!(g2 > g1, "load_hosts_str must bump the generation");

        r.load_file_names([(ip("10.0.0.4"), "nrb-host".to_string())]);
        let g3 = r.generation();
        assert!(g3 > g2, "load_file_names must bump the generation");

        r.remove_manual(&ip("10.0.0.2"));
        let g4 = r.generation();
        assert!(g4 > g3, "remove_manual must bump the generation");

        let _ = r.name(ip("10.0.0.3"), NameMode::Names);
        let _ = r.label(ip("10.0.0.4"), 5060, NameMode::Names);
        let _ = r.label(ip("10.0.0.99"), 5060, NameMode::Names);
        assert_eq!(r.generation(), g4, "lookups must not bump the generation");
    }

    /// A `remove_manual` that removes nothing must not bump the generation —
    /// otherwise it would needlessly invalidate the TUI's cached layout.
    #[test]
    fn remove_manual_noop_does_not_bump_generation() {
        let r = NameResolver::new();
        r.set_manual(ip("10.0.0.2"), "sbc".into());
        let g0 = r.generation();

        // Removing an IP with no manual mapping returns None and must be a
        // no-op for the generation counter.
        assert_eq!(r.remove_manual(&ip("10.0.0.99")), None);
        assert_eq!(
            r.generation(),
            g0,
            "a no-op remove_manual must not bump the generation"
        );

        // A real removal still bumps it.
        assert_eq!(r.remove_manual(&ip("10.0.0.2")).as_deref(), Some("sbc"));
        assert!(
            r.generation() > g0,
            "removing an existing mapping must bump the generation"
        );
    }

    /// Hosts-file entries resolve when no manual mapping exists;
    /// unknown IPs stay unresolved.
    #[test]
    fn hosts_used_when_no_manual() {
        let r = NameResolver::new();
        r.load_hosts_str("10.0.0.3  asterisk-01  alias\n# comment\n\n");
        assert_eq!(
            r.name(ip("10.0.0.3"), NameMode::Names).as_deref(),
            Some("asterisk-01")
        );
        assert_eq!(r.name(ip("10.0.0.9"), NameMode::Names), None);
    }

    /// `label` swaps the IP for its name but keeps the port; unknown IPs
    /// fall back to the raw `ip:port` form.
    #[test]
    fn label_preserves_port_and_substitutes_ip() {
        let r = NameResolver::new();
        r.set_manual(ip("10.0.0.2"), "sbc-edge".into());
        assert_eq!(
            r.label(ip("10.0.0.2"), 5060, NameMode::Names),
            "sbc-edge:5060"
        );
        // Unknown IP falls back to raw.
        assert_eq!(
            r.label(ip("10.0.0.9"), 5061, NameMode::Names),
            "10.0.0.9:5061"
        );
    }

    /// `label_socket` keeps the bracketed form for unresolved IPv6 and
    /// drops the brackets once a name resolves.
    #[test]
    fn label_socket_brackets_unresolved_ipv6() {
        let r = NameResolver::new();
        let sa: SocketAddr = "[2001:db8::1]:5060".parse().unwrap();
        // Unresolved IPv6 keeps the bracketed socket form.
        assert_eq!(r.label_socket(sa, NameMode::Names), "[2001:db8::1]:5060");
        r.set_manual(ip("2001:db8::1"), "v6host".into());
        assert_eq!(r.label_socket(sa, NameMode::Names), "v6host:5060");
    }

    /// `parse_hosts` skips comments, invalid IPs, and blank lines, and
    /// keeps the first name per IP.
    #[test]
    fn hosts_parsing_skips_comments_and_bad_lines() {
        let map = parse_hosts(
            "# header\n127.0.0.1 localhost\nnot-an-ip foo\n10.0.0.1\t\trouter\n  \n10.0.0.1 dup-ignored\n",
        );
        assert_eq!(
            map.get(&ip("127.0.0.1")).map(String::as_str),
            Some("localhost")
        );
        assert_eq!(map.get(&ip("10.0.0.1")).map(String::as_str), Some("router"));
        assert_eq!(map.len(), 2);
    }

    /// `manual_entries` sorts by IP, and the hosts-format serialization
    /// round-trips back through the hosts parser.
    #[test]
    fn manual_entries_sorted_and_round_trip() {
        let r = NameResolver::new();
        r.set_manual(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), "five".into());
        r.set_manual(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), "two".into());
        let entries = r.manual_entries();
        assert_eq!(entries[0].0, ip("10.0.0.2"));
        assert_eq!(entries[1].0, ip("10.0.0.5"));

        // Serialized form round-trips back through the hosts parser.
        let text = r.manual_to_hosts_format();
        let r2 = NameResolver::new();
        r2.load_hosts_str(&text);
        assert_eq!(
            r2.name(ip("10.0.0.2"), NameMode::Names).as_deref(),
            Some("two")
        );
        assert_eq!(
            r2.name(ip("10.0.0.5"), NameMode::Names).as_deref(),
            Some("five")
        );
    }

    /// `remove_manual` returns the removed name and the IP stops resolving.
    #[test]
    fn remove_manual_returns_previous() {
        let r = NameResolver::new();
        r.set_manual(ip("10.0.0.2"), "sbc".into());
        assert_eq!(r.remove_manual(&ip("10.0.0.2")).as_deref(), Some("sbc"));
        assert_eq!(r.name(ip("10.0.0.2"), NameMode::Names), None);
    }

    /// Dns mode on a resolver without a worker behaves like a cache miss.
    #[test]
    fn dns_mode_without_worker_does_not_panic() {
        // No reverse-DNS worker: Dns mode behaves like a cache miss (raw IP).
        let r = NameResolver::new();
        assert_eq!(r.name(ip("10.0.0.2"), NameMode::Dns), None);
        assert_eq!(
            r.label(ip("10.0.0.2"), 5060, NameMode::Dns),
            "10.0.0.2:5060"
        );
    }

    // ── Name validation (success + failure) ────────────────────────────

    /// Reasonable hostnames pass validation, including the length boundary.
    #[test]
    fn is_valid_name_accepts_reasonable_names() {
        assert!(is_valid_name("pbx"));
        assert!(is_valid_name("pbx.corp.example.com"));
        assert!(is_valid_name("a")); // 1 char
        assert!(is_valid_name(&"x".repeat(MAX_NAME_LEN))); // boundary
    }

    /// Empty, NUL-bearing, control-character, and over-length names fail
    /// validation.
    #[test]
    fn is_valid_name_rejects_bad_names() {
        assert!(!is_valid_name("")); // empty
        assert!(!is_valid_name("a\0b")); // interior NUL
        assert!(!is_valid_name("a\tb")); // control char (tab)
        assert!(!is_valid_name("a\nb")); // control char (newline)
        assert!(!is_valid_name(&"x".repeat(MAX_NAME_LEN + 1))); // too long
    }

    // ── NRB serialization (success + failure) ──────────────────────────

    /// NRB entries are sorted by IP with each IP's names in source-
    /// preference order (manual before hosts).
    #[test]
    fn nrb_entries_orders_sources_and_dedups() {
        let r = NameResolver::new();
        r.set_manual(ip("10.0.0.2"), "manual-name".into());
        r.load_hosts_str("10.0.0.2 hosts-name\n10.0.0.3 only-hosts\n");
        let e = r.nrb_entries(false);
        // Sorted by IP; .2 carries manual THEN hosts (preferred first), .3 hosts only.
        assert_eq!(e[0].0, ip("10.0.0.2"));
        assert_eq!(
            e[0].1,
            vec!["manual-name".to_string(), "hosts-name".to_string()]
        );
        assert_eq!(e[1].0, ip("10.0.0.3"));
        assert_eq!(e[1].1, vec!["only-hosts".to_string()]);
    }

    /// The same name in two sources is emitted once, not duplicated.
    #[test]
    fn nrb_entries_dedups_identical_names_across_sources() {
        let r = NameResolver::new();
        r.set_manual(ip("10.0.0.2"), "same".into());
        r.load_hosts_str("10.0.0.2 same\n");
        let e = r.nrb_entries(false);
        assert_eq!(e[0].1, vec!["same".to_string()]); // not duplicated
    }

    /// Cached DNS names appear in NRB output only when `include_dns` is set.
    #[test]
    fn nrb_entries_dns_gated_by_flag() {
        let r = NameResolver::new();
        r.load_file_names([(ip("10.0.0.9"), "fromfile".to_string())]);
        // Inject a DNS cache hit directly (no worker needed for the test).
        r.inner
            .write()
            .dns_cache
            .insert(ip("10.0.0.9"), Some("dnsname".into()));
        assert_eq!(r.nrb_entries(false)[0].1, vec!["fromfile".to_string()]);
        assert_eq!(
            r.nrb_entries(true)[0].1,
            vec!["fromfile".to_string(), "dnsname".to_string()]
        );
    }

    /// Invalid names are dropped from NRB output, and IPs left with no
    /// valid name are omitted entirely.
    #[test]
    fn nrb_entries_skips_invalid_names_and_empty_result() {
        let r = NameResolver::new();
        r.set_manual(ip("10.0.0.2"), "ok".into());
        r.set_manual(ip("10.0.0.3"), "bad\0name".into()); // invalid → skipped
        let e = r.nrb_entries(false);
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].0, ip("10.0.0.2"));

        // A resolver with only invalid names yields nothing.
        let empty = NameResolver::new();
        empty.set_manual(ip("10.0.0.4"), String::new());
        assert!(empty.nrb_entries(false).is_empty());
    }

    /// NRB output carries IPv4 and IPv6 entries side by side.
    #[test]
    fn nrb_entries_handles_ipv4_and_ipv6() {
        let r = NameResolver::new();
        r.set_manual(ip("10.0.0.2"), "v4".into());
        r.set_manual(ip("2001:db8::1"), "v6".into());
        let e = r.nrb_entries(false);
        assert_eq!(e.len(), 2);
        assert!(e.iter().any(|(i, n)| *i == ip("10.0.0.2") && n == &["v4"]));
        assert!(
            e.iter()
                .any(|(i, n)| *i == ip("2001:db8::1") && n == &["v6"])
        );
    }

    // ── Read-back (success + failure) ──────────────────────────────────

    /// `load_file_names` counts only accepted entries: invalid and empty
    /// names are skipped, and the first name per IP wins.
    #[test]
    fn load_file_names_accepts_valid_skips_invalid() {
        let r = NameResolver::new();
        let accepted = r.load_file_names([
            (ip("10.0.0.2"), "good".to_string()),
            (ip("10.0.0.3"), "bad\0".to_string()), // invalid → skipped
            (ip("10.0.0.4"), String::new()),       // empty → skipped
            (ip("10.0.0.2"), "dup".to_string()),   // first wins
        ]);
        assert_eq!(accepted, 1);
        assert_eq!(r.file_name_count(), 1);
        assert_eq!(
            r.name(ip("10.0.0.2"), NameMode::Names).as_deref(),
            Some("good")
        );
        assert_eq!(r.name(ip("10.0.0.3"), NameMode::Names), None);
    }

    /// Capture-file names rank below hosts, which rank below manual.
    #[test]
    fn file_source_ranks_below_manual_and_hosts() {
        let r = NameResolver::new();
        r.load_file_names([(ip("10.0.0.2"), "fromfile".to_string())]);
        assert_eq!(
            r.name(ip("10.0.0.2"), NameMode::Names).as_deref(),
            Some("fromfile")
        );
        r.load_hosts_str("10.0.0.2 fromhosts\n");
        assert_eq!(
            r.name(ip("10.0.0.2"), NameMode::Names).as_deref(),
            Some("fromhosts")
        );
        r.set_manual(ip("10.0.0.2"), "frommanual".into());
        assert_eq!(
            r.name(ip("10.0.0.2"), NameMode::Names).as_deref(),
            Some("frommanual")
        );
    }

    /// Names that would corrupt the hosts format (newline injection,
    /// tab/control chars) are skipped on serialization.
    #[test]
    fn manual_to_hosts_format_skips_invalid_names() {
        let r = NameResolver::new();
        r.set_manual(ip("10.0.0.1"), "good".into());
        // A newline-bearing name would inject a second hosts record on reload.
        r.set_manual(ip("10.0.0.2"), "evil\n6.6.6.6 attacker".into());
        // A tab/control char would corrupt the IP↔name split too.
        r.set_manual(ip("10.0.0.3"), "bad\tname".into());
        let out = r.manual_to_hosts_format();
        assert!(out.contains("good"), "valid name kept");
        assert!(
            !out.contains("6.6.6.6"),
            "newline-injected name must be skipped, not written"
        );
        assert!(!out.contains("bad\tname"));
        // Exactly one valid record emitted.
        assert_eq!(out.lines().count(), 1);
    }

    // ── Resource bounds (DNS cache/queue must not grow forever) ────────

    /// Test helper: the `i`-th unique IPv4 address (10.x.y.z range).
    fn nth_ip(i: u32) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i + 1))
    }

    /// The reverse-DNS cache is bounded: landing more results than
    /// `MAX_DNS_CACHE_ENTRIES` evicts the oldest-inserted entries while the
    /// most recent survive, so a long-running capture seeing endless unique
    /// IPs cannot grow the cache without limit.
    #[test]
    fn dns_cache_bounded_evicts_oldest() {
        let r = NameResolver::new();
        let extra = 16u32;
        let total = MAX_DNS_CACHE_ENTRIES as u32 + extra;
        {
            let mut inner = r.inner.write();
            for i in 0..total {
                inner.cache_dns_result(nth_ip(i), Some(format!("host-{i}")));
            }
            assert!(
                inner.dns_cache.len() <= MAX_DNS_CACHE_ENTRIES,
                "dns_cache grew past its cap: {} > {MAX_DNS_CACHE_ENTRIES}",
                inner.dns_cache.len()
            );
        }
        // The oldest entries were evicted (unresolved again)...
        for i in 0..extra {
            assert_eq!(
                r.name(nth_ip(i), NameMode::Dns),
                None,
                "entry {i} should be evicted"
            );
        }
        // ...and the most recently cached entries survive.
        let last = total - 1;
        let expect = format!("host-{last}");
        assert_eq!(
            r.name(nth_ip(last), NameMode::Dns).as_deref(),
            Some(expect.as_str())
        );
        let mid = total - extra; // oldest survivor
        let expect_mid = format!("host-{mid}");
        assert_eq!(
            r.name(nth_ip(mid), NameMode::Dns).as_deref(),
            Some(expect_mid.as_str())
        );
    }

    /// The in-flight `dns_requested` set is bounded too, and a landing result
    /// clears its marker — so request tracking can neither grow forever nor
    /// starve the cache.
    #[test]
    fn dns_requested_bounded_and_cleared_by_results() {
        let r = NameResolver::new();
        let mut inner = r.inner.write();
        for i in 0..(MAX_DNS_CACHE_ENTRIES as u32 + 16) {
            inner.mark_requested(nth_ip(i));
        }
        assert!(
            inner.dns_requested.len() <= MAX_DNS_CACHE_ENTRIES,
            "dns_requested grew past its cap: {} > {MAX_DNS_CACHE_ENTRIES}",
            inner.dns_requested.len()
        );
        // A completed lookup clears the in-flight marker.
        let ip = nth_ip(MAX_DNS_CACHE_ENTRIES as u32);
        assert!(inner.dns_requested.contains(&ip));
        inner.cache_dns_result(ip, Some("resolved".into()));
        assert!(
            !inner.dns_requested.contains(&ip),
            "landing a result must clear the in-flight marker"
        );
        // A cached IP is never re-marked for lookup.
        assert!(!inner.mark_requested(ip));
    }

    /// A burst of unique IPs beyond the DNS queue capacity must not block
    /// the lookup path and must not queue unbounded work: overflow requests
    /// are dropped (and un-marked, so they can be re-requested later).
    #[test]
    fn dns_queue_full_drops_instead_of_blocking() {
        // A resolver wired to a bounded queue with NO consumer draining it.
        let (tx, rx) = std::sync::mpsc::sync_channel::<IpAddr>(DNS_QUEUE_CAPACITY);
        let r = Arc::new(NameResolver {
            inner: Arc::default(),
            dns_tx: Some(tx),
        });
        let burst = {
            let r = Arc::clone(&r);
            std::thread::spawn(move || {
                for i in 0..(DNS_QUEUE_CAPACITY as u32 + 64) {
                    let _ = r.name(nth_ip(i), NameMode::Dns);
                }
            })
        };
        // The lookup path must finish promptly even though nothing reads rx.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !burst.is_finished() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(
            burst.is_finished(),
            "lookup path blocked on a full DNS queue"
        );
        burst.join().unwrap();
        // Exactly the queue capacity was accepted; the overflow was dropped.
        assert_eq!(rx.try_iter().count(), DNS_QUEUE_CAPACITY);
        // Dropped IPs were un-marked so a later lookup can retry them.
        assert_eq!(r.inner.read().dns_requested.len(), DNS_QUEUE_CAPACITY);
    }

    // ── Persistence (atomic, symlink-safe) ─────────────────────────────

    /// The atomic save replaces a symlink at the target path instead of
    /// writing through it onto the link's target.
    #[test]
    #[cfg(all(unix, feature = "native"))]
    fn save_manual_file_replaces_symlink_not_target() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real.txt");
        std::fs::write(&target, "DO NOT CLOBBER").unwrap();
        let link = dir.path().join("names_link");
        symlink(&target, &link).unwrap();

        let r = NameResolver::new();
        r.set_manual(ip("10.0.0.1"), "host-a".into());
        r.save_manual_file(&link).unwrap();

        // A plain `fs::write` follows the symlink and clobbers `target`; an
        // atomic temp-in-dir + rename replaces the link itself, so the original
        // target is left intact and the path becomes a regular file.
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "DO NOT CLOBBER");
        let meta = std::fs::symlink_metadata(&link).unwrap();
        assert!(
            meta.file_type().is_file(),
            "save should replace the symlink with a regular file"
        );
        assert!(std::fs::read_to_string(&link).unwrap().contains("host-a"));
    }
}
