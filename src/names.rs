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
    /// Reverse-DNS results: `Some(name)` resolved, `None` looked-up-but-no-name.
    dns_cache: HashMap<IpAddr, Option<String>>,
    /// IPs already handed to the DNS worker, so we enqueue each at most once.
    dns_requested: HashSet<IpAddr>,
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
    pub fn save_manual_file(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, self.manual_to_hosts_format())
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
}
