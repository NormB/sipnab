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

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc::Sender;

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

#[derive(Debug, Default)]
struct Inner {
    /// Operator-entered mappings (highest priority).
    manual: HashMap<IpAddr, String>,
    /// Entries loaded from a hosts file.
    hosts: HashMap<IpAddr, String>,
    /// Names read from a capture file's Name Resolution Block (untrusted hint).
    file: HashMap<IpAddr, String>,
    /// Reverse-DNS results: `Some(name)` resolved, `None` looked-up-but-no-name.
    dns_cache: HashMap<IpAddr, Option<String>>,
    /// IPs already handed to the DNS worker, so we enqueue each at most once.
    dns_requested: HashSet<IpAddr>,
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
    inner: Arc<RwLock<Inner>>,
    /// Channel to the reverse-DNS worker; `None` when reverse DNS is disabled.
    dns_tx: Option<Sender<IpAddr>>,
}

impl NameResolver {
    /// A resolver with no reverse-DNS worker (offline sources only).
    pub fn new() -> Self {
        Self::default()
    }

    /// A resolver that performs reverse DNS on a background worker thread.
    ///
    /// When `enabled` is false this is equivalent to [`NameResolver::new`].
    pub fn with_reverse_dns(enabled: bool) -> Self {
        if !enabled {
            return Self::new();
        }
        let inner: Arc<RwLock<Inner>> = Arc::default();
        let (tx, rx) = std::sync::mpsc::channel::<IpAddr>();
        let worker_inner = Arc::clone(&inner);
        // Detached worker: it exits when the sender is dropped (resolver gone).
        let _ = std::thread::Builder::new()
            .name("sipnab-dns".to_string())
            .spawn(move || {
                while let Ok(ip) = rx.recv() {
                    let name = reverse_dns(ip);
                    worker_inner.write().dns_cache.insert(ip, name);
                }
            });
        Self {
            inner,
            dns_tx: Some(tx),
        }
    }

    /// Resolve `ip` to a name under `mode`, or `None` to use the raw IP.
    ///
    /// In `Dns` mode an unknown IP is enqueued for the background worker and
    /// `None` is returned for now; the name appears on a later lookup.
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
    fn enqueue_dns(&self, ip: IpAddr) {
        let Some(tx) = &self.dns_tx else { return };
        {
            let mut inner = self.inner.write();
            if inner.dns_cache.contains_key(&ip) || !inner.dns_requested.insert(ip) {
                return;
            }
        }
        let _ = tx.send(ip);
    }

    // ── Manual mappings ────────────────────────────────────────────────

    /// Add or replace a manual mapping.
    pub fn set_manual(&self, ip: IpAddr, name: String) {
        self.inner.write().manual.insert(ip, name);
    }

    /// Remove a manual mapping. Returns the previous name, if any.
    pub fn remove_manual(&self, ip: &IpAddr) -> Option<String> {
        self.inner.write().manual.remove(ip)
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
    /// first valid name for each IP wins. Returns how many were accepted.
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
        n
    }

    /// Number of names currently loaded from capture files.
    pub fn file_name_count(&self) -> usize {
        self.inner.read().file.len()
    }

    // ── Hosts file ─────────────────────────────────────────────────────

    /// Replace the hosts table from `/etc/hosts`-format text.
    pub fn load_hosts_str(&self, text: &str) {
        self.inner.write().hosts = parse_hosts(text);
    }

    /// Load a hosts file from disk into the hosts table.
    pub fn load_hosts_file(&self, path: &Path) -> std::io::Result<()> {
        let text = std::fs::read_to_string(path)?;
        self.load_hosts_str(&text);
        Ok(())
    }

    /// Load manual mappings from an `/etc/hosts`-format file (operator names).
    pub fn load_manual_file(&self, path: &Path) -> std::io::Result<()> {
        let text = std::fs::read_to_string(path)?;
        let parsed = parse_hosts(&text);
        self.inner.write().manual.extend(parsed);
        Ok(())
    }

    /// Serialize manual mappings to `/etc/hosts` line format.
    pub fn manual_to_hosts_format(&self) -> String {
        let mut out = String::new();
        for (ip, name) in self.manual_entries() {
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
/// first name listed for an IP wins; later duplicates are ignored.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

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

    #[test]
    fn label_socket_brackets_unresolved_ipv6() {
        let r = NameResolver::new();
        let sa: SocketAddr = "[2001:db8::1]:5060".parse().unwrap();
        // Unresolved IPv6 keeps the bracketed socket form.
        assert_eq!(r.label_socket(sa, NameMode::Names), "[2001:db8::1]:5060");
        r.set_manual(ip("2001:db8::1"), "v6host".into());
        assert_eq!(r.label_socket(sa, NameMode::Names), "v6host:5060");
    }

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

    #[test]
    fn remove_manual_returns_previous() {
        let r = NameResolver::new();
        r.set_manual(ip("10.0.0.2"), "sbc".into());
        assert_eq!(r.remove_manual(&ip("10.0.0.2")).as_deref(), Some("sbc"));
        assert_eq!(r.name(ip("10.0.0.2"), NameMode::Names), None);
    }

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

    #[test]
    fn is_valid_name_accepts_reasonable_names() {
        assert!(is_valid_name("pbx"));
        assert!(is_valid_name("pbx.corp.example.com"));
        assert!(is_valid_name("a")); // 1 char
        assert!(is_valid_name(&"x".repeat(MAX_NAME_LEN))); // boundary
    }

    #[test]
    fn is_valid_name_rejects_bad_names() {
        assert!(!is_valid_name("")); // empty
        assert!(!is_valid_name("a\0b")); // interior NUL
        assert!(!is_valid_name("a\tb")); // control char (tab)
        assert!(!is_valid_name("a\nb")); // control char (newline)
        assert!(!is_valid_name(&"x".repeat(MAX_NAME_LEN + 1))); // too long
    }

    // ── NRB serialization (success + failure) ──────────────────────────

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

    #[test]
    fn nrb_entries_dedups_identical_names_across_sources() {
        let r = NameResolver::new();
        r.set_manual(ip("10.0.0.2"), "same".into());
        r.load_hosts_str("10.0.0.2 same\n");
        let e = r.nrb_entries(false);
        assert_eq!(e[0].1, vec!["same".to_string()]); // not duplicated
    }

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

    // ── Persistence (atomic, symlink-safe) ─────────────────────────────

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
