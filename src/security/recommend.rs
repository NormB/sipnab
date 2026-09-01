// SPDX-License-Identifier: MIT OR Apache-2.0

//! Turn an accusation into a rule the operator can run (BA2).
//!
//! [`sources::accused`](super::sources::accused) answers *who was named, and
//! by what*. That is where BA1 stopped, and it leaves the operator to do the
//! translation by hand — which is the step where the address is mistyped, the
//! port is guessed, and the dialect is wrong for the firewall actually
//! installed.
//!
//! # The line this module does not cross
//!
//! sipnab RECOMMENDS. It applies nothing, opens no connection to a firewall,
//! holds no credential and shells out to nothing. Every function here returns
//! a `String`; the operator reads it, decides, and runs it. That keeps this on
//! the same side of the line the transmit-permit rules already draw for
//! `--kill-scanner`, and it is stated in the generated text as well as here,
//! because a caveat one page away from a block of root-shell commands is a
//! caveat that was not read.
//!
//! # Counter-evidence is not a footnote
//!
//! A rule that blocks a customer is worse than the scan it stopped.
//! `AccusedSource::established` — did this source ever complete a registration
//! or a call — is therefore rendered in the SAME block as the accusation, and
//! in the address-specific dialects it does more than annotate: every command
//! is commented out, so the block cannot be pasted into a root shell and ban a
//! working peer by accident.
//!
//! fail2ban is treated differently on purpose, because it *is* different. A
//! jail does not ban an address; it watches a log and bans whoever trips the
//! filter. Commenting out a jail because one source has a relationship would
//! withhold protection against every other source for a reason that is not
//! about them. The counter-evidence lands in `ignoreip` instead, which is the
//! mechanism fail2ban already has for exactly this fact.

use std::fmt::Write as _;
use std::net::IpAddr;

use super::sources::AccusedSource;

/// Which firewall dialect a recommendation is written in.
///
/// `All` exists because the operator, not sipnab, knows which of these is
/// installed, and a run that emits the wrong one has told them nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "native", derive(clap::ValueEnum))]
pub enum BlockDialect {
    /// A fail2ban filter and jail matching sipnab's own `[ALERT]` line.
    #[default]
    Fail2ban,
    /// `nft` commands: a named set, a rule that drops from it, and an element.
    Nftables,
    /// `iptables`/`ip6tables` INPUT rules.
    Iptables,
    /// Every dialect above, in one block.
    All,
}

/// Ports the generated rules cover.
///
/// The IANA registrations for SIP and SIP-TLS, and NOT a measurement: a
/// `Finding` carries no port, so nothing here can know which one this traffic
/// actually arrived on. The generated text says so rather than letting the
/// numbers read as observed.
const SIP_PORTS: &[u16] = &[5060, 5061];

/// How long a generated nftables ban lasts.
///
/// fail2ban's own conventional `bantime`, borrowed so the two dialects do not
/// disagree with each other in the same block. Also not a measurement.
const BAN_SECONDS: u32 = 3600;

/// nftables table the generated commands build under.
///
/// Its own table rather than `inet filter`: a table sipnab named is one an
/// operator can delete in a single command when they are done with it, without
/// having to work out which rules in a shared table were theirs.
const NFT_TABLE: &str = "inet sipnab";

/// Render one accused source as text the operator can read and run.
///
/// # Arguments
///
/// * `a` — the accusation, including its counter-evidence.
/// * `dialect` — which firewall the commands are written for.
///
/// # Returns
///
/// A newline-terminated block. Every line is either a comment or a command;
/// nothing is executed and nothing is transmitted.
#[must_use]
pub fn recommend(a: &AccusedSource, dialect: BlockDialect) -> String {
    // The address is an `IpAddr`, so it cannot carry shell metacharacters,
    // quotes or a second command however hostile the packet that produced it
    // was. The rule NAMES cannot make that promise -- `--alert-rule` lets an
    // operator name a rule anything -- and `regex_safe_rules` is where that
    // difference is handled.
    let withheld = a.established == Some(true);
    let mut out = String::new();

    let _ = writeln!(
        out,
        "# ---- sipnab block recommendation ---- {} ----",
        a.src_ip
    );
    let _ = writeln!(
        out,
        "# sipnab RECOMMENDS. It has applied nothing, has reached no firewall\n\
         # and holds no credential. Read the commands, decide, run them yourself."
    );
    let _ = writeln!(
        out,
        "# EVIDENCE: {} finding(s), first {}, last {}",
        a.findings,
        a.first_seen.to_rfc3339(),
        a.last_seen.to_rfc3339()
    );
    let _ = writeln!(
        out,
        "# EVIDENCE: rule(s) tripped: {}",
        a.rules.iter().cloned().collect::<Vec<_>>().join(", ")
    );
    out.push_str(&counter_evidence(a));
    out.push_str(&not_measured());
    out.push_str(&address_caveats(a.src_ip));

    let (safe, rejected) = regex_safe_rules(a);
    match dialect {
        BlockDialect::Fail2ban => out.push_str(&fail2ban(a, &safe, &rejected)),
        BlockDialect::Nftables => out.push_str(&nftables(a.src_ip, withheld)),
        BlockDialect::Iptables => out.push_str(&iptables(a.src_ip, withheld)),
        BlockDialect::All => {
            out.push_str(&fail2ban(a, &safe, &rejected));
            out.push_str(&nftables(a.src_ip, withheld));
            out.push_str(&iptables(a.src_ip, withheld));
        }
    }
    out
}

/// What the whole capture says when it accused nobody.
///
/// An empty recommendation is the most dangerous thing a security tool can
/// print, because it reads as an all-clear. This says which silence it is: a
/// capture nothing was looked for in produces exactly the same emptiness as a
/// clean one.
#[must_use]
pub fn nothing_to_recommend() -> String {
    "# sipnab: no source was accused in this capture, so no block rule is\n\
     # recommended. If no detector was armed, that silence means nothing was\n\
     # LOOKED FOR, not that nothing happened -- arm one with --kill-scanner,\n\
     # --kill-ua, --fraud-detect, --reg-flood or --digest-leak.\n"
        .to_string()
}

/// The counter-evidence line, in all three of its honest states.
fn counter_evidence(a: &AccusedSource) -> String {
    match a.established {
        Some(true) => format!(
            "# COUNTER-EVIDENCE: {} also completed a registration or a call in\n\
             #   this capture. A rule that blocks a customer is worse than the scan\n\
             #   it stopped, so the address-specific commands below are COMMENTED\n\
             #   OUT. Uncomment them only after deciding this is not one of yours.\n",
            a.src_ip
        ),
        Some(false) => format!(
            "# COUNTER-EVIDENCE: none. {} completed no registration and no call in\n\
             #   this capture, so nothing here says a block would disconnect a\n\
             #   working peer. It is still only THIS capture.\n",
            a.src_ip
        ),
        // Nobody asked. Deliberately not collapsed into `Some(false)`: the
        // detector that answers this question is the scanner detector, and a
        // run armed only with `--reg-flood` never built one. "Asked and it had
        // not" and "never asked" are different evidence and only one of them
        // is a reason to feel safe.
        None => format!(
            "# COUNTER-EVIDENCE: UNKNOWN. No scanner detector was armed on this\n\
             #   run, so nothing asked whether {} ever completed a registration or\n\
             #   a call. That is not the same as asking and finding it had not.\n\
             #   Re-run with --kill-scanner before acting on this block.\n",
            a.src_ip
        ),
    }
}

/// The figures in the generated rules that sipnab did not measure.
fn not_measured() -> String {
    format!(
        "# NOT MEASURED: ports {} and the {BAN_SECONDS}s ban below are the IANA SIP\n\
         #   registrations and fail2ban's conventional bantime. A finding carries no\n\
         #   port, so sipnab cannot tell you which one this traffic arrived on.\n",
        SIP_PORTS
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(" and ")
    )
}

/// Warnings about the address itself, before any dialect renders it.
///
/// A generated rule is only as good as the address in it, and two classes of
/// address turn a block into an outage: the host's own loopback, and space
/// that belongs to the operator's own network. Neither is a reason to refuse
/// to render — a scanner really can be inside the LAN — so both are said
/// rather than enforced.
fn address_caveats(ip: IpAddr) -> String {
    let mut out = String::new();
    if ip.is_loopback() {
        let _ = writeln!(
            out,
            "# WARNING: {ip} is a loopback address. A rule on it bans this host from\n\
             #   itself, and the traffic almost certainly came from a process here."
        );
    }
    if is_private(ip) {
        let _ = writeln!(
            out,
            "# WARNING: {ip} is in private or link-local space, so it is an address on\n\
             #   your own network rather than an anonymous one on the internet."
        );
    }
    if ip.is_multicast() || ip.is_unspecified() {
        let _ = writeln!(
            out,
            "# WARNING: {ip} is not a unicast source address. A packet claiming it as a\n\
             #   source is spoofed or malformed, and a rule keyed on it blocks nobody."
        );
    }
    out
}

/// Whether the address belongs to space an operator routes themselves.
///
/// Carrier-grade NAT ([RFC 6598](https://www.rfc-editor.org/rfc/rfc6598)) is
/// deliberately NOT included, for the reason `private_media_address` excludes
/// it: it is routable within the carrier that assigned it, and a large share of
/// working mobile traffic arrives from it.
fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        // `is_unique_local` and `is_unicast_link_local` are still unstable on
        // the pinned toolchain, so the two prefixes are matched directly:
        // fc00::/7 and fe80::/10.
        IpAddr::V6(v6) => {
            let seg = v6.segments()[0];
            (seg & 0xfe00) == 0xfc00 || (seg & 0xffc0) == 0xfe80
        }
    }
}

/// Split the rules this source tripped into those that can be written into a
/// regular expression verbatim and those that cannot.
///
/// The built-in detectors all file under bare identifiers. `--alert-rule` does
/// not have to: a rule named `.*` would generate a failregex that bans every
/// source in the log, which is the one mistake this whole module exists to
/// prevent. A name that is not a bare identifier is REPORTED rather than
/// escaped, because a filter whose name is not the name the operator typed is
/// a filter they cannot correlate back to a rule.
fn regex_safe_rules(a: &AccusedSource) -> (Vec<String>, Vec<String>) {
    let mut safe = Vec::new();
    let mut rejected = Vec::new();
    for r in &a.rules {
        if !r.is_empty()
            && r.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            safe.push(r.clone());
        } else {
            rejected.push(r.clone());
        }
    }
    (safe, rejected)
}

/// A fail2ban filter and jail matching the rules this source tripped.
///
/// Not commented out for an established source, and that is the deliberate
/// difference from the two dialects below. A jail bans whoever trips the
/// filter, not the address this block is titled with, so withholding it would
/// withhold protection from every OTHER source for a reason that is about this
/// one. `ignoreip` is fail2ban's own mechanism for the fact, so the
/// counter-evidence goes there.
fn fail2ban(a: &AccusedSource, safe: &[String], rejected: &[String]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "#");
    let _ = writeln!(
        out,
        "# fail2ban. NOTE: a jail bans whoever trips the filter, not {} in\n\
         #   particular. It also reads sipnab's OWN log, so sipnab must be running\n\
         #   with --alert syslog (or its stderr captured to the logpath) or this\n\
         #   jail never sees a line.",
        a.src_ip
    );
    for r in rejected {
        let _ = writeln!(
            out,
            "# REFUSED: rule name {r:?} is not a bare identifier and is not written\n\
             #   into a failregex. A name containing regex metacharacters would ban\n\
             #   sources the detector never reported."
        );
    }
    let Some(name) = safe.first() else {
        let _ = writeln!(
            out,
            "# No rule this source tripped can be written into a failregex, so no\n\
             #   fail2ban stanza is offered. The nftables and iptables dialects key\n\
             #   on the address instead and are unaffected."
        );
        return out;
    };
    // One filter for every rule this source tripped, alternated, rather than
    // one jail per rule: separate jails would ban the same source three times
    // and expire on three different clocks.
    let jail = format!("sipnab-{name}");
    let alternation = safe.join("|");
    let _ = writeln!(out, "# /etc/fail2ban/filter.d/{jail}.conf");
    let _ = writeln!(out, "[Definition]");
    let _ = writeln!(
        out,
        "failregex = ^.*\\[ALERT\\] (?:{alternation}) src=<HOST> .*$"
    );
    let _ = writeln!(out, "ignoreregex =");
    let _ = writeln!(out, "# /etc/fail2ban/jail.d/{jail}.conf");
    let _ = writeln!(out, "[{jail}]");
    let _ = writeln!(out, "enabled  = true");
    let _ = writeln!(out, "filter   = {jail}");
    let _ = writeln!(out, "logpath  = /var/log/syslog");
    let _ = writeln!(
        out,
        "port     = {}",
        SIP_PORTS
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(",")
    );
    let _ = writeln!(out, "protocol = udp");
    let _ = writeln!(out, "maxretry = 3");
    let _ = writeln!(out, "findtime = 600");
    let _ = writeln!(out, "bantime  = {BAN_SECONDS}");
    if a.established == Some(true) {
        let _ = writeln!(
            out,
            "# The counter-evidence, as fail2ban's own mechanism for it: this jail\n\
             #   will NOT ban the source above, because it completed a registration\n\
             #   or a call. Delete the line to let it."
        );
        let _ = writeln!(out, "ignoreip = {}", a.src_ip);
    }
    out
}

/// nftables commands dropping SIP from one address.
fn nftables(ip: IpAddr, withheld: bool) -> String {
    let (family, set, addr_type) = match ip {
        IpAddr::V4(_) => ("ip", "blocked_v4", "ipv4_addr"),
        IpAddr::V6(_) => ("ip6", "blocked_v6", "ipv6_addr"),
    };
    let ports = SIP_PORTS
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let mut out = String::new();
    let _ = writeln!(out, "#");
    let _ = writeln!(
        out,
        "# nftables. The first three commands are idempotent; the rule is NOT --\n\
         #   running it twice adds a second copy. Check with\n\
         #   `nft list table {NFT_TABLE}` first."
    );
    let cmds = [
        format!("nft add table {NFT_TABLE}"),
        format!(
            "nft add chain {NFT_TABLE} input {{ type filter hook input priority 0 \\; policy accept \\; }}"
        ),
        format!("nft add set {NFT_TABLE} {set} {{ type {addr_type} \\; flags timeout \\; }}"),
        format!(
            "nft add rule {NFT_TABLE} input {family} saddr @{set} meta l4proto {{ tcp, udp }} th dport {{ {ports} }} drop"
        ),
        format!("nft add element {NFT_TABLE} {set} {{ {ip} timeout {BAN_SECONDS}s }}"),
    ];
    for c in cmds {
        let _ = writeln!(out, "{}{c}", if withheld { "# " } else { "" });
    }
    out
}

/// iptables commands dropping SIP from one address.
fn iptables(ip: IpAddr, withheld: bool) -> String {
    // The v6 binary is a different program with the same grammar, and aiming
    // `iptables` at a v6 address does not filter the wrong traffic -- it
    // refuses, which an operator running a generated block may not notice
    // among the lines that worked.
    let bin = match ip {
        IpAddr::V4(_) => "iptables",
        IpAddr::V6(_) => "ip6tables",
    };
    let ports = SIP_PORTS
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let mut out = String::new();
    let _ = writeln!(out, "#");
    let _ = writeln!(
        out,
        "# iptables. These do NOT expire and do NOT survive a reboot: remove one\n\
         #   with the same line and -D in place of -I, and persist the set with\n\
         #   iptables-save if you mean to keep it."
    );
    for proto in ["udp", "tcp"] {
        let _ = writeln!(
            out,
            "{}{bin} -I INPUT -s {ip} -p {proto} -m multiport --dports {ports} -j DROP",
            if withheld { "# " } else { "" }
        );
    }
    out
}

// ── Tests ────────────────────────────────────────────────────────────

/// Unit tests for the dialects, the counter-evidence states and the two
/// address families.
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::DateTime;
    use std::collections::BTreeSet;

    /// An accusation with one rule and a chosen counter-evidence state.
    fn accused(ip: &str, established: Option<bool>) -> AccusedSource {
        AccusedSource {
            src_ip: ip.parse().expect("test ip"),
            findings: 12,
            rules: BTreeSet::from(["scanner".to_string()]),
            first_seen: DateTime::from_timestamp(10, 0).expect("test timestamp"),
            last_seen: DateTime::from_timestamp(20, 0).expect("test timestamp"),
            established,
        }
    }

    /// The commands a block actually offers to run: every line that is not a
    /// comment and not blank.
    fn live_lines(block: &str) -> Vec<&str> {
        block
            .lines()
            .map(str::trim_end)
            .filter(|l| !l.is_empty() && !l.trim_start().starts_with('#'))
            .collect()
    }

    /// A source with no relationship gets commands it can run.
    #[test]
    fn an_unestablished_source_gets_runnable_commands() {
        let block = recommend(
            &accused("198.51.100.7", Some(false)),
            BlockDialect::Nftables,
        );
        assert!(
            live_lines(&block).iter().any(|l| l.starts_with("nft ")),
            "no runnable nft command in:\n{block}"
        );
        assert!(
            block.contains("198.51.100.7"),
            "the rule does not name its address:\n{block}"
        );
    }

    /// The counter-evidence withholds the address-specific commands.
    ///
    /// Asserted on the LIVE lines rather than on the presence of the warning
    /// text: a block that says "this is a customer" and still offers a
    /// pasteable `nft add element` has stated the fact and not acted on it,
    /// and the paste is what bans the customer.
    #[test]
    fn an_established_source_gets_no_runnable_command() {
        for dialect in [BlockDialect::Nftables, BlockDialect::Iptables] {
            let block = recommend(&accused("198.51.100.7", Some(true)), dialect);
            assert!(
                block.contains("also completed a registration or a call"),
                "{dialect:?} block carries no counter-evidence:\n{block}"
            );
            assert!(
                live_lines(&block).is_empty(),
                "{dialect:?} offers a runnable command for a source with a \
                 relationship: {:?}",
                live_lines(&block)
            );
        }
    }

    /// fail2ban is NOT withheld, and carries the fact as `ignoreip`.
    ///
    /// The one dialect where commenting the stanza out would be the wrong
    /// answer: a jail protects against every source that trips the filter, and
    /// this source's relationship is not a reason to stop protecting against
    /// the others.
    #[test]
    fn the_fail2ban_dialect_carries_counter_evidence_as_ignoreip() {
        let block = recommend(&accused("198.51.100.7", Some(true)), BlockDialect::Fail2ban);
        let live = live_lines(&block);
        assert!(
            live.iter().any(|l| l.starts_with("failregex =")),
            "the jail was withheld; a jail is not about one address:\n{block}"
        );
        assert!(
            live.contains(&"ignoreip = 198.51.100.7"),
            "the counter-evidence did not reach the mechanism fail2ban has \
             for it:\n{block}"
        );
    }

    /// Every state of the counter-evidence is said out loud, and "nobody
    /// asked" is not spelled the same as "asked and it had not".
    #[test]
    fn the_three_counter_evidence_states_are_distinguishable() {
        let yes = recommend(&accused("198.51.100.7", Some(true)), BlockDialect::Iptables);
        let no = recommend(
            &accused("198.51.100.7", Some(false)),
            BlockDialect::Iptables,
        );
        let unknown = recommend(&accused("198.51.100.7", None), BlockDialect::Iptables);

        let line = |b: &str| {
            b.lines()
                .find(|l| l.contains("COUNTER-EVIDENCE"))
                .expect("every block carries a counter-evidence line")
                .to_string()
        };
        assert_ne!(line(&yes), line(&no));
        assert_ne!(line(&no), line(&unknown));
        assert_ne!(line(&yes), line(&unknown));
        assert!(
            unknown.contains("UNKNOWN"),
            "an unasked question reads as an answer:\n{unknown}"
        );
        // An unknown state must not withhold the commands: nothing has said
        // this source has a relationship, and refusing to help on a question
        // nobody asked would make `--reg-flood` alone useless.
        assert!(
            !live_lines(&unknown).is_empty(),
            "an unasked question withheld the rule:\n{unknown}"
        );
    }

    /// The v6 dialects are the v6 dialects.
    ///
    /// The failure this pins is silent in both directions: `iptables` refuses
    /// a v6 address with an error the operator may miss among the lines that
    /// worked, and an `ip saddr` rule against a v6 set is rejected by nft.
    #[test]
    fn an_ipv6_source_gets_ipv6_commands() {
        let block = recommend(
            &accused("2001:db8::dead:beef", Some(false)),
            BlockDialect::All,
        );
        let live = live_lines(&block).join("\n");
        assert!(
            live.contains("ip6tables -I INPUT"),
            "a v6 source was given the v4 binary:\n{live}"
        );
        assert!(
            !live.contains("\niptables -I INPUT"),
            "a v6 source was ALSO given the v4 binary:\n{live}"
        );
        assert!(
            live.contains("ip6 saddr @blocked_v6"),
            "the nft rule does not match on the v6 family:\n{live}"
        );
        assert!(
            live.contains("type ipv6_addr"),
            "the nft set holds v4 addresses:\n{live}"
        );
    }

    /// And the v4 ones stay v4, so the test above cannot pass by accident on a
    /// generator that emits v6 for everybody.
    #[test]
    fn an_ipv4_source_gets_ipv4_commands() {
        let block = recommend(&accused("198.51.100.7", Some(false)), BlockDialect::All);
        let live = live_lines(&block).join("\n");
        assert!(
            live.contains("iptables -I INPUT") && !live.contains("ip6tables"),
            "a v4 source was given a v6 command:\n{live}"
        );
        assert!(
            live.contains("ip saddr @blocked_v4") && !live.contains("ip6 saddr"),
            "the nft rule does not match on the v4 family:\n{live}"
        );
    }

    /// A rule name that is not a bare identifier never reaches a failregex.
    ///
    /// `--alert-rule` names the rule, so the name is operator text rather than
    /// a fixed vocabulary. A rule called `.*` would generate a filter matching
    /// every alert line sipnab ever writes, which bans every source in the log
    /// — the exact outcome the counter-evidence exists to prevent, arrived at
    /// from the other direction.
    #[test]
    fn a_rule_name_that_is_a_regex_is_refused_not_escaped() {
        let mut a = accused("198.51.100.7", Some(false));
        a.rules = BTreeSet::from([".*".to_string()]);
        let block = recommend(&a, BlockDialect::Fail2ban);

        // On the LIVE lines: the refusal text below explains itself using the
        // word `failregex`, and a bare substring search over the whole block
        // reads that explanation as the defect it is explaining.
        assert!(
            !live_lines(&block)
                .iter()
                .any(|l| l.starts_with("failregex")),
            "a regex rule name was written into a filter:\n{block}"
        );
        assert!(
            block.contains("REFUSED"),
            "the refusal is silent, so the operator gets no fail2ban stanza \
             and no reason:\n{block}"
        );
    }

    /// A safe name beside a refused one still produces its filter.
    #[test]
    fn a_refused_name_does_not_take_the_safe_ones_with_it() {
        let mut a = accused("198.51.100.7", Some(false));
        a.rules = BTreeSet::from([".*".to_string(), "reg_flood".to_string()]);
        let block = recommend(&a, BlockDialect::Fail2ban);

        assert!(
            block.contains("(?:reg_flood) src=<HOST>"),
            "the safe rule lost its filter to the refused one:\n{block}"
        );
        assert!(
            !block.contains("|.*)") && !block.contains("(?:.*"),
            "the refused name reached the alternation anyway:\n{block}"
        );
    }

    /// Several safe rules become one filter, not one jail each.
    #[test]
    fn several_rules_share_one_filter() {
        let mut a = accused("198.51.100.7", Some(false));
        a.rules = BTreeSet::from(["reg_flood".to_string(), "scanner".to_string()]);
        let block = recommend(&a, BlockDialect::Fail2ban);
        assert_eq!(
            block.matches("failregex =").count(),
            1,
            "one source produced more than one jail:\n{block}"
        );
        assert!(
            block.contains("(?:reg_flood|scanner) src=<HOST>"),
            "the alternation does not carry both rules:\n{block}"
        );
    }

    /// The generated failregex matches the line sipnab actually writes.
    ///
    /// The pair this closes: the failregex is a copy of a format string that
    /// lives in `alerting.rs`, and a filter that no longer matches fails
    /// SILENTLY — the jail keeps running, keeps reporting zero bans, and looks
    /// exactly like a quiet network. Built from
    /// [`super::super::alerting::alert_log_line`] so the two cannot drift
    /// without this failing.
    #[test]
    fn the_failregex_matches_a_real_alert_line() {
        let block = recommend(
            &accused("198.51.100.7", Some(false)),
            BlockDialect::Fail2ban,
        );
        let failregex = block
            .lines()
            .find_map(|l| l.strip_prefix("failregex = "))
            .expect("the fail2ban dialect emits a failregex");
        // `<HOST>` is fail2ban's own template. Substituting a permissive
        // address pattern tests the LITERAL structure around it, which is the
        // half that drifts when the log line changes.
        let pattern = failregex.replace("<HOST>", "(?:[0-9a-fA-F:.]+)");
        let re = regex::Regex::new(&pattern).expect("the generated failregex compiles");

        let line = crate::security::alerting::alert_log_line(
            "scanner",
            "198.51.100.7".parse().expect("test ip"),
            "ua=friendly-scanner method=OPTIONS",
        );
        assert!(
            re.is_match(&line),
            "the generated failregex does not match the line sipnab writes.\n\
             regex: {pattern}\nline:  {line}"
        );
    }

    /// A different rule's alert line is NOT matched, so the filter is not a
    /// catch-all wearing a rule name.
    #[test]
    fn the_failregex_does_not_match_another_rules_line() {
        let block = recommend(
            &accused("198.51.100.7", Some(false)),
            BlockDialect::Fail2ban,
        );
        let failregex = block
            .lines()
            .find_map(|l| l.strip_prefix("failregex = "))
            .expect("the fail2ban dialect emits a failregex");
        let pattern = failregex.replace("<HOST>", "(?:[0-9a-fA-F:.]+)");
        let re = regex::Regex::new(&pattern).expect("the generated failregex compiles");

        let other = crate::security::alerting::alert_log_line(
            "reg_flood",
            "198.51.100.7".parse().expect("test ip"),
            "count=91",
        );
        assert!(
            !re.is_match(&other),
            "the filter for `scanner` also matches a `reg_flood` line: {other}"
        );
    }

    /// The bound is in the text, not only in the documentation.
    #[test]
    fn every_dialect_states_that_sipnab_applied_nothing() {
        for dialect in [
            BlockDialect::Fail2ban,
            BlockDialect::Nftables,
            BlockDialect::Iptables,
            BlockDialect::All,
        ] {
            let block = recommend(&accused("198.51.100.7", Some(false)), dialect);
            assert!(
                block.contains("has applied nothing"),
                "{dialect:?} does not say sipnab applied nothing:\n{block}"
            );
        }
    }

    /// The conventional figures are labeled as conventional.
    #[test]
    fn the_unmeasured_figures_say_they_were_not_measured() {
        let block = recommend(&accused("198.51.100.7", Some(false)), BlockDialect::All);
        assert!(
            block.contains("NOT MEASURED"),
            "the ports and bantime read as observations:\n{block}"
        );
    }

    /// A loopback address is called out before anyone pastes a rule banning
    /// the host from itself.
    #[test]
    fn a_loopback_source_is_warned_about() {
        let block = recommend(&accused("127.0.0.1", Some(false)), BlockDialect::Iptables);
        assert!(
            block.contains("loopback"),
            "a rule banning this host from itself carries no warning:\n{block}"
        );
    }

    /// So is an address inside the operator's own network.
    #[test]
    fn a_private_source_is_warned_about() {
        for ip in [
            "10.1.2.3",
            "192.168.4.5",
            "169.254.1.2",
            "fd00::1",
            "fe80::1",
        ] {
            let block = recommend(&accused(ip, Some(false)), BlockDialect::Iptables);
            assert!(
                block.contains("private or link-local"),
                "{ip} was not flagged as an address on the operator's own \
                 network:\n{block}"
            );
        }
    }

    /// And a public one is not, so the warning still means something.
    #[test]
    fn a_public_source_carries_no_private_warning() {
        for ip in ["198.51.100.7", "100.64.0.1", "2001:db8::1"] {
            let block = recommend(&accused(ip, Some(false)), BlockDialect::Iptables);
            assert!(
                !block.contains("private or link-local"),
                "{ip} was called private; the warning fires on everything and \
                 says nothing:\n{block}"
            );
        }
    }

    /// The empty answer says which silence it is.
    #[test]
    fn the_empty_recommendation_distinguishes_its_two_silences() {
        let text = nothing_to_recommend();
        assert!(text.contains("no source was accused"));
        assert!(
            text.contains("LOOKED FOR"),
            "an empty recommendation reads as an all-clear:\n{text}"
        );
    }
}
