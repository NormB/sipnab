// SPDX-License-Identifier: MIT OR Apache-2.0

//! The `Host`-header allowlist both HTTP servers apply: the REST API
//! (`--api-allowed-host`) and the MCP HTTP transport (`--mcp-allowed-host`).
//!
//! # What it stops
//!
//! DNS rebinding (CWE-352 by another route). A web page the operator visits
//! at `http://evil.example:8080/` points `evil.example` at `127.0.0.1` once
//! the page has loaded. From the browser's point of view every later request
//! to `evil.example:8080` is same-origin, so the page may read what a
//! loopback server answers and send it state-changing requests, and a server
//! that trusts "the peer is loopback" or "no key is needed on loopback" has
//! no way to tell. The one thing the attacker cannot change is the name in
//! the URL: the browser sends it as `Host: evil.example:8080`. Refusing
//! names the operator never listed closes the door.
//!
//! # The rule
//!
//! A request is served when its `Host` (or, with no `Host` header, the
//! request target's authority) names:
//!
//! * `localhost`, `127.0.0.1` or `::1`, on any port -- the names rmcp's
//!   own allowlist starts from, which the MCP transport used before it
//!   shared this module;
//! * the address the server is bound to, on any port;
//! * any IP address, when the server is bound to every interface
//!   (`0.0.0.0` or `::`). Rebinding needs a NAME the attacker controls; a
//!   `Host` that is an address literal cannot have come from one, and a
//!   wildcard bind has no single address of its own to list;
//! * an entry the operator added. An entry with a port matches that port
//!   only; one without matches every port.
//!
//! A literal `*` among the additions turns the check off entirely.
//!
//! A request with neither a `Host` header nor an authority in its target
//! (an HTTP/1.0 client) is refused with `400`, as is a `Host` that is not a
//! valid authority: rmcp answers both that way, and a server that cannot
//! tell which name it was reached by cannot tell whether that name was
//! rebound. A `Host` that parses but is not on the list gets `403`, again
//! as rmcp does.
//!
//! # Why one implementation
//!
//! The MCP transport used to lean on rmcp's check while the REST API had
//! none. Two servers answering the same attack with two rules drift: one
//! learns the bound address and the other does not, and the operator who
//! reads one flag's documentation is wrong about the other. The matching
//! lives here; each server keeps only the shape of its own refusal.

use std::net::{IpAddr, SocketAddr};

/// The names every allowlist starts from, whatever the bind.
pub const LOOPBACK_HOSTS: [&str; 3] = ["localhost", "127.0.0.1", "::1"];

/// One allowlist entry, or one request's authority: a lowercased host
/// without IPv6 brackets, and a port when one was given.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Authority {
    /// Lowercased host name or address, IPv6 brackets removed.
    host: String,
    /// The port, when one was written.
    port: Option<u16>,
}

/// Why a request was not served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostRejection {
    /// No `Host` header and no authority in the request target: `400`.
    Missing,
    /// A `Host` value that is not a valid `host[:port]`: `400`.
    Malformed,
    /// A well-formed host that is not on the list: `403`. Carries the value
    /// the client sent, for the refusal's body.
    NotAllowed(String),
}

impl HostRejection {
    /// The HTTP status this rejection is answered with.
    #[must_use]
    pub fn status(&self) -> u16 {
        match self {
            Self::Missing | Self::Malformed => 400,
            Self::NotAllowed(_) => 403,
        }
    }

    /// The refusal's text: what was wrong, and for a host that is merely not
    /// listed, the flag that lists it.
    ///
    /// # Arguments
    ///
    /// * `flag` -- the server's own flag, `--api-allowed-host` or
    ///   `--mcp-allowed-host`.
    #[must_use]
    pub fn message(&self, flag: &str) -> String {
        match self {
            Self::Missing => "Bad Request: missing Host header".to_string(),
            Self::Malformed => "Bad Request: Invalid Host header".to_string(),
            Self::NotAllowed(host) => format!(
                "Forbidden: Host header is not allowed: {host}. If clients reach this \
                 server by that name, start sipnab with {flag} {name}.",
                name = host_part(host)
            ),
        }
    }
}

/// The host part of a `Host` value, for suggesting the flag's argument.
fn host_part(value: &str) -> &str {
    parse_authority(value).map_or(value, |_| {
        if let Some(rest) = value.strip_prefix('[') {
            rest.split(']').next().unwrap_or(value)
        } else {
            value.rsplit_once(':').map_or(value, |(h, _)| h)
        }
    })
}

/// The `Host` allowlist one server enforces. Built once at startup.
#[derive(Debug, Clone)]
pub struct HostAllowlist {
    /// `None`: `*` was given and every request is served.
    entries: Option<Vec<Authority>>,
    /// The server is bound to every interface, so any IP literal is its own.
    any_ip: bool,
}

impl HostAllowlist {
    /// The allowlist for a server bound to `bind`, with the operator's
    /// `extra` entries. A `*` among them disables the check.
    ///
    /// # Arguments
    ///
    /// * `bind` -- the address the server listens on.
    /// * `extra` -- the `--api-allowed-host` / `--mcp-allowed-host` values.
    #[must_use]
    pub fn new(bind: SocketAddr, extra: &[String]) -> Self {
        if extra.iter().any(|e| e.trim() == "*") {
            return Self {
                entries: None,
                any_ip: false,
            };
        }
        let mut entries: Vec<Authority> = LOOPBACK_HOSTS
            .iter()
            .filter_map(|h| parse_entry(h))
            .collect();
        let ip = bind.ip();
        if !ip.is_unspecified() {
            entries.push(Authority {
                host: ip.to_string(),
                port: None,
            });
        }
        entries.extend(extra.iter().filter_map(|e| parse_entry(e)));
        Self {
            entries: Some(entries),
            any_ip: ip.is_unspecified(),
        }
    }

    /// Whether the check is off (`*`).
    #[must_use]
    pub fn is_disabled(&self) -> bool {
        self.entries.is_none()
    }

    /// The effective list, for the startup log line.
    #[must_use]
    pub fn describe(&self) -> Vec<String> {
        let Some(entries) = &self.entries else {
            return vec!["*".to_string()];
        };
        let mut out: Vec<String> = entries
            .iter()
            .map(|a| match a.port {
                Some(p) if a.host.contains(':') => format!("[{}]:{p}", a.host),
                Some(p) => format!("{}:{p}", a.host),
                None => a.host.clone(),
            })
            .collect();
        if self.any_ip {
            out.push("any IP address (wildcard bind)".to_string());
        }
        out
    }

    /// Whether a request carrying `host_header` (the raw `Host` value) and
    /// `target_authority` (the request target's authority, present in
    /// absolute-form and HTTP/2 requests) may be served.
    ///
    /// # Errors
    ///
    /// The [`HostRejection`] the request is refused with.
    pub fn check(
        &self,
        host_header: Option<&[u8]>,
        target_authority: Option<&str>,
    ) -> Result<(), HostRejection> {
        let Some(entries) = &self.entries else {
            return Ok(());
        };
        // The header when there is one; the target's authority only in its
        // absence, as rmcp reads them.
        let raw = match (host_header, target_authority) {
            (Some(bytes), _) => std::str::from_utf8(bytes).map_err(|_| HostRejection::Malformed)?,
            (None, Some(authority)) => authority,
            (None, None) => return Err(HostRejection::Missing),
        };
        let asked = parse_authority(raw).ok_or(HostRejection::Malformed)?;
        let listed = entries.iter().any(|allowed| {
            allowed.host == asked.host && allowed.port.is_none_or(|p| asked.port == Some(p))
        });
        if listed || (self.any_ip && is_ip_literal(&asked.host)) {
            Ok(())
        } else {
            Err(HostRejection::NotAllowed(raw.to_string()))
        }
    }
}

/// Parse an allowlist entry. Lenient where [`parse_authority`] is strict: a
/// bare IPv6 address (`::1`) is accepted as a host with no port, as rmcp
/// accepts it. `None` for an empty entry.
fn parse_entry(entry: &str) -> Option<Authority> {
    let entry = entry.trim();
    if entry.is_empty() {
        return None;
    }
    parse_authority(entry).or_else(|| {
        Some(Authority {
            host: normalize_host(entry),
            port: None,
        })
    })
}

/// Parse a `Host` value (`host`, `host:port`, `[v6]`, `[v6]:port`).
/// `None` when it is not one.
fn parse_authority(value: &str) -> Option<Authority> {
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        // `[v6]` or `[v6]:port`: the brackets are only for IPv6 literals.
        let (inner, after) = rest.split_once(']')?;
        inner.parse::<std::net::Ipv6Addr>().ok()?;
        let port = match after {
            "" => None,
            p => Some(p.strip_prefix(':')?),
        };
        (inner, port)
    } else {
        match value.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (value, None),
        }
    };
    let port = match port {
        None => None,
        Some(p) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => Some(p.parse().ok()?),
        Some(_) => return None,
    };
    // A reg-name or an IPv4 literal (RFC 3986 section 3.2.2): unreserved
    // characters, sub-delims and percent-encoding. A second `:` means an
    // unbracketed IPv6 literal, which a Host may not carry.
    let valid = |b: u8| b.is_ascii_alphanumeric() || b"-._~%!$&'()*+,;=".contains(&b);
    if !value.starts_with('[') && (host.is_empty() || !host.bytes().all(valid)) {
        return None;
    }
    Some(Authority {
        host: normalize_host(host),
        port,
    })
}

/// Lowercase, brackets removed: the form entries and requests compare in.
fn normalize_host(host: &str) -> String {
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase()
}

/// Whether `host` (already normalized) is an IP address literal.
fn is_ip_literal(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestError = Box<dyn std::error::Error>;

    fn loopback() -> Result<SocketAddr, TestError> {
        Ok("127.0.0.1:8080"
            .parse()
            .map_err(|e| format!("addr: {e:?}"))?)
    }

    fn check(list: &HostAllowlist, host: &str) -> Result<(), HostRejection> {
        list.check(Some(host.as_bytes()), None)
    }

    /// The loopback names pass on any port, in any case, and with IPv6
    /// brackets.
    #[test]
    fn loopback_names_pass_on_any_port() -> Result<(), TestError> {
        let list = HostAllowlist::new(loopback()?, &[]);
        for host in [
            "localhost",
            "localhost:8080",
            "LOCALHOST:1",
            "127.0.0.1",
            "127.0.0.1:8080",
            "[::1]",
            "[::1]:8080",
        ] {
            assert_eq!(check(&list, host), Ok(()), "{host}");
        }
        Ok(())
    }

    /// A rebound attacker's name is refused with 403, with and without a
    /// port, and the refusal names both the host and the flag.
    #[test]
    fn a_foreign_name_is_refused_naming_the_flag() -> Result<(), TestError> {
        let list = HostAllowlist::new(loopback()?, &[]);
        for host in [
            "evil.example",
            "evil.example:8080",
            "127.0.0.1.evil.example",
            "localhost.evil.example:8080",
        ] {
            let err = check(&list, host).err().ok_or(host)?;
            assert_eq!(err.status(), 403, "{host}");
            let msg = err.message("--api-allowed-host");
            assert!(msg.contains(host), "{msg}");
            assert!(msg.contains("--api-allowed-host"), "{msg}");
        }
        Ok(())
    }

    /// An address literal that is not this server's, on a specific bind, is
    /// refused like a name.
    #[test]
    fn another_address_is_refused_on_a_specific_bind() -> Result<(), TestError> {
        let list = HostAllowlist::new(loopback()?, &[]);
        assert_eq!(
            check(&list, "10.0.0.5:8080").map_err(|e| e.status()),
            Err(403)
        );
        Ok(())
    }

    /// The bound address passes on a non-loopback bind; another address and
    /// a name do not.
    #[test]
    fn the_bound_address_passes() -> Result<(), TestError> {
        let list = HostAllowlist::new(
            "192.0.2.7:8080"
                .parse()
                .map_err(|e| format!("addr: {e:?}"))?,
            &[],
        );
        assert_eq!(check(&list, "192.0.2.7:8080"), Ok(()));
        assert_eq!(
            check(&list, "192.0.2.8:8080").map_err(|e| e.status()),
            Err(403)
        );
        assert_eq!(
            check(&list, "box.example:8080").map_err(|e| e.status()),
            Err(403)
        );
        let v6 = HostAllowlist::new(
            "[2001:db8::7]:8080"
                .parse()
                .map_err(|e| format!("addr: {e:?}"))?,
            &[],
        );
        assert_eq!(check(&v6, "[2001:db8::7]:8080"), Ok(()));
        Ok(())
    }

    /// A wildcard bind accepts any address literal, and still refuses names.
    #[test]
    fn a_wildcard_bind_accepts_address_literals_only() -> Result<(), TestError> {
        for bind in ["0.0.0.0:8080", "[::]:8080"] {
            let list = HostAllowlist::new(bind.parse().map_err(|e| format!("addr: {e:?}"))?, &[]);
            assert_eq!(check(&list, "192.0.2.7:8080"), Ok(()), "{bind}");
            assert_eq!(check(&list, "[2001:db8::7]:8080"), Ok(()), "{bind}");
            assert_eq!(
                check(&list, "evil.example:8080").map_err(|e| e.status()),
                Err(403),
                "{bind}"
            );
        }
        Ok(())
    }

    /// An added entry passes; with a port, on that port only.
    #[test]
    fn added_entries_pass_and_a_port_pins_them() -> Result<(), TestError> {
        let list = HostAllowlist::new(
            loopback()?,
            &["Proxy.Example".to_string(), "api.example:8443".to_string()],
        );
        assert_eq!(check(&list, "proxy.example"), Ok(()));
        assert_eq!(check(&list, "PROXY.example:443"), Ok(()));
        assert_eq!(check(&list, "api.example:8443"), Ok(()));
        assert_eq!(
            check(&list, "api.example:8080").map_err(|e| e.status()),
            Err(403)
        );
        assert_eq!(
            check(&list, "evil.example").map_err(|e| e.status()),
            Err(403)
        );
        Ok(())
    }

    /// `*` turns the check off: anything, even no Host at all, is served.
    #[test]
    fn a_star_disables_the_check() -> Result<(), TestError> {
        let list = HostAllowlist::new(loopback()?, &["proxy.example".into(), "*".into()]);
        assert!(list.is_disabled());
        assert_eq!(check(&list, "evil.example"), Ok(()));
        assert_eq!(list.check(None, None), Ok(()));
        assert_eq!(list.describe(), vec!["*".to_string()]);
        Ok(())
    }

    /// No Host and no target authority is a 400, as rmcp answers it; the
    /// target's authority stands in when the header is absent.
    #[test]
    fn a_missing_host_is_a_bad_request_unless_the_target_names_one() -> Result<(), TestError> {
        let list = HostAllowlist::new(loopback()?, &[]);
        let err = list.check(None, None).err().ok_or("no host")?;
        assert_eq!(err, HostRejection::Missing);
        assert_eq!(err.status(), 400);
        assert_eq!(list.check(None, Some("127.0.0.1:8080")), Ok(()));
        assert_eq!(
            list.check(None, Some("evil.example"))
                .map_err(|e| e.status()),
            Err(403)
        );
        // The header wins over the target when both are present.
        assert_eq!(
            list.check(Some(b"evil.example"), Some("127.0.0.1"))
                .map_err(|e| e.status()),
            Err(403)
        );
        Ok(())
    }

    /// A Host that is not a valid authority is a 400, not a pass.
    #[test]
    fn a_malformed_host_is_a_bad_request() -> Result<(), TestError> {
        let list = HostAllowlist::new(loopback()?, &[]);
        for bad in [
            &b""[..],
            b"localhost:notaport",
            b"localhost:99999",
            b"user@localhost",
            b"localhost/path",
            b"local host",
            b"[::1",
            b"::1",
            b"\xff\xfe",
        ] {
            assert_eq!(
                list.check(Some(bad), None),
                Err(HostRejection::Malformed),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
        Ok(())
    }

    /// The refusal suggests the host without its port as the flag value.
    #[test]
    fn the_refusal_suggests_the_bare_host() -> Result<(), TestError> {
        let msg =
            HostRejection::NotAllowed("evil.example:8080".into()).message("--mcp-allowed-host");
        assert!(msg.ends_with("--mcp-allowed-host evil.example."), "{msg}");
        assert!(
            msg.starts_with("Forbidden: Host header is not allowed"),
            "{msg}"
        );
        Ok(())
    }
}
