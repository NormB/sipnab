// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! One complete SIP message per RFC 4475 and RFC 5118 torture case, run
//! through the parser, the linter and the dialog store.
//!
//! The messages in `tests/fixtures/sip-torture/` were written for sipnab. Each
//! has the property its RFC section tests and copies no RFC message text; every
//! name, address and number in them is a value reserved for documentation, and
//! `PROVENANCE.txt` there names, per file, the RFC section and the property.
//!
//! [`CASES`] holds what sipnab must report for each file. [`RFC_VERDICTS`]
//! holds the verdict the RFC's own message got: a local run on 2026-11-25 put
//! the byte-exact Appendix A archive member of each RFC section (RFC 5118's
//! with CRLF line ends) through [`verdict`], and each file here through the
//! same function, and all 61 pairs were equal. The archive members are not in
//! the repository, because they hold names, domains and addresses that are not
//! reserved, so that run cannot be repeated here; the table is its record.
//! [`verdict`] holds no value a message author chooses (no URI, Call-ID or
//! number), only what the RFC case is about.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use sha2::{Digest, Sha256};
use sipnab::net::TransportProto;
use sipnab::sip::dialog_store::DialogStore;
use sipnab::sip::lint::{LintConfig, Linter};
use sipnab::sip::message::SipMessage;
use sipnab::sip::method::SipMethod;
use sipnab::sip::parser::parse_sip;

type TestError = Box<dyn std::error::Error>;

const BRANCH_COOKIE: &str = "SIP-3261-8.1.1.7-BRANCH-COOKIE";
const BRANCH_NO_ID: &str = "SIP-3261-8.1.1.7-BRANCH-NO-IDENTIFIER";
const MF_RANGE: &str = "SIP-3261-20.22-MAX-FORWARDS-RANGE";
const MF_MISSING: &str = "SIP-3261-8.1.1.6-MAX-FORWARDS-MISSING";
const CL_MISMATCH: &str = "SIP-3261-20.14-CONTENT-LENGTH-MISMATCH";
const CL_INVALID: &str = "SIP-3261-20.14-CONTENT-LENGTH-INVALID";
const CSEQ_MALFORMED: &str = "SIP-3261-20.16-CSEQ-MALFORMED";
const CSEQ_METHOD: &str = "SIP-3261-8.1.1.5-CSEQ-METHOD-MISMATCH";
const URI_BRACKETS: &str = "SIP-3261-20-URI-BRACKETS";
const URI_PARAM_DEMOTED: &str = "SIP-3261-19.1.1-URI-PARAM-DEMOTED";
const RR_NOT_LOOSE: &str = "SIP-3261-16.6-RECORD-ROUTE-NOT-LOOSE";
const MANDATORY: &str = "SIP-3261-8.1.1-MANDATORY-HEADER-MISSING";
const SINGULAR: &str = "SIP-3261-7.3.1-SINGULAR-HEADER-REPEATED";
const LINE_SPACING: &str = "SIP-3261-7.1-REQUEST-LINE-SPACING";
const IPV6_UNBRACKETED: &str = "SIP-3261-25.1-IPV6-REFERENCE-UNBRACKETED";
const EMPTY_PARAM: &str = "SIP-3261-25.1-EMPTY-PARAMETER";
const QUOTE_OPEN: &str = "SIP-3261-25.1-QUOTED-STRING-UNTERMINATED";
const RURI_BRACKETED: &str = "SIP-3261-25.1-REQUEST-URI-BRACKETED";
const RURI_LWS: &str = "SIP-3261-25.1-REQUEST-URI-WHITESPACE";
const RURI_HEADERS: &str = "SIP-3261-19.1.1-REQUEST-URI-HEADERS";
const ADDR_SPEC_LWS: &str = "SIP-3261-25.1-ADDR-SPEC-WHITESPACE";
const DISPLAY_UNQUOTED: &str = "SIP-3261-25.1-DISPLAY-NAME-UNQUOTED";
const DATE_NOT_GMT: &str = "SIP-3261-20.17-DATE-NOT-GMT";

/// What sipnab must do with one fixture.
enum Want {
    /// `parse_sip` refuses it; the error's Debug form starts with this.
    Refused(&'static str),
    /// It parses, with exactly these lint rule ids, this `parse_error` flag,
    /// this start-line key, Call-ID and CSeq, and a dialog kept or not.
    Parsed {
        findings: &'static [&'static str],
        perr: bool,
        first: &'static str,
        call_id: Option<&'static str>,
        cseq: Option<(u32, &'static str)>,
        dialog: bool,
    },
}

struct Case {
    file: &'static str,
    want: Want,
}

const fn p(
    findings: &'static [&'static str],
    perr: bool,
    first: &'static str,
    call_id: Option<&'static str>,
    cseq: Option<(u32, &'static str)>,
) -> Want {
    Want::Parsed {
        findings,
        perr,
        first,
        call_id,
        cseq,
        dialog: call_id.is_some(),
    }
}

// rustfmt::skip: one case per line, so each fixture's row reads as one line.
#[rustfmt::skip]
const CASES: &[Case] = &[
    Case { file: "rfc4475/3.1.1.1-wsinv.dat", want: p(&[BRANCH_COOKIE], false, "INVITE sip:desk7@pbx.example.net;oddparam", Some("tortuous.qq81m3@192.0.2.40"), Some((42, "INVITE"))) },
    Case { file: "rfc4475/3.1.1.2-intmeth.dat", want: p(&[MF_RANGE], false, "~odd.Method_9+`'%!*-~ sip:x_1.y~(z!w)&q'r+s$/t?,/;;*:&pw+d=9,x!*y$z~_w.(v-u)@example.net", Some("twisted.q%ZZ_!*.+'-@q~`)(<>:\\/\"[]}{?"), Some((77, "~odd.Method_9+`'%!*-~"))) },
    Case { file: "rfc4475/3.1.1.3-esc01.dat", want: p(&[MF_RANGE], false, "INVITE sip:sip%3Aalt%40example.org@example.net", Some("esc01.p0q9r8s7"), Some((515, "INVITE"))) },
    Case { file: "rfc4475/3.1.1.4-escnull.dat", want: p(&[], false, "REGISTER sip:registrar.example.org", Some("escnull.z9q8w7e6"), Some((4004, "REGISTER"))) },
    Case { file: "rfc4475/3.1.1.5-esc02.dat", want: p(&[], false, "PU%42LI%53H sip:service.example.org", Some("esc02.k3j4h5g6"), Some((6006, "PU%42LI%53H"))) },
    Case { file: "rfc4475/3.1.1.6-lwsdisp.dat", want: p(&[], false, "OPTIONS sip:desk@example.org", Some("lwsdisp.m1n2b3"), Some((16, "OPTIONS"))) },
    Case { file: "rfc4475/3.1.1.7-longreq.dat", want: p(&[BRANCH_COOKIE], false, "INVITE sip:desk@example.org", Some("longreq.lengthylengthylengthylengthylengthylengthylengthylengthylengthylengthylengthylengthylengthylengthylengthylengthylengthylengthylengthylengthy"), Some((7007, "INVITE"))) },
    Case { file: "rfc4475/3.1.1.8-dblreq.dat", want: p(&[], false, "REGISTER sip:registrar.example.org", Some("dblreq.f9e8d7"), Some((18, "REGISTER"))) },
    Case { file: "rfc4475/3.1.1.9-semiuri.dat", want: p(&[], false, "OPTIONS sip:svc;key=v%40example.org@example.net", Some("semiuri.u7y6t5"), Some((29, "OPTIONS"))) },
    Case { file: "rfc4475/3.1.1.10-transports.dat", want: p(&[], false, "OPTIONS sip:desk@example.org", Some("transports.r4e3w2"), Some((110, "OPTIONS"))) },
    Case { file: "rfc4475/3.1.1.11-mpart01.dat", want: p(&[], false, "MESSAGE sip:desk@example.org", Some("mpart01.c3v4b5"), Some((1, "MESSAGE"))) },
    Case { file: "rfc4475/3.1.1.12-unreason.dat", want: p(&[], false, "200 ¿Sí? 3 + 4 = 7 — ταχύ και καλό (ok)", Some("unreason.p0o9i8"), Some((12, "INVITE"))) },
    Case { file: "rfc4475/3.1.1.13-noreason.dat", want: p(&[], false, "100 ", Some("noreason.l1k2j3"), Some((13, "INVITE"))) },
    Case { file: "rfc4475/3.1.2.1-badinv01.dat", want: p(&[BRANCH_COOKIE, EMPTY_PARAM], false, "INVITE sip:desk@example.org", Some("badinv01.h7g6f5"), Some((21, "INVITE"))) },
    Case { file: "rfc4475/3.1.2.2-clerr.dat", want: p(&[CL_MISMATCH, MF_RANGE], true, "INVITE sip:desk@example.org", Some("clerr.q2w3e4"), Some((22, "INVITE"))) },
    Case { file: "rfc4475/3.1.2.3-ncl.dat", want: p(&[CL_INVALID, MF_RANGE], true, "INVITE sip:desk@example.org", Some("ncl.r5t6y7"), Some((23, "INVITE"))) },
    Case { file: "rfc4475/3.1.2.4-scalar02.dat", want: p(&[CSEQ_MALFORMED, MF_RANGE], false, "REGISTER sip:registrar.example.org", Some("scalar02.u8i9o0"), None) },
    Case { file: "rfc4475/3.1.2.5-scalarlg.dat", want: Want::Parsed { findings: &[CSEQ_MALFORMED], perr: false, first: "503 Service Unavailable", call_id: Some("scalarlg.a9s8d7"), cseq: None, dialog: false } },
    Case { file: "rfc4475/3.1.2.6-quotbal.dat", want: p(&[QUOTE_OPEN], false, "INVITE sip:desk@example.org", Some("quotbal.f6g7h8"), Some((26, "INVITE"))) },
    Case { file: "rfc4475/3.1.2.7-ltgtruri.dat", want: p(&[BRANCH_COOKIE, RURI_BRACKETED], false, "INVITE <sip:desk@example.org>", Some("ltgtruri.j9k8l7"), Some((27, "INVITE"))) },
    Case { file: "rfc4475/3.1.2.8-lwsruri.dat", want: p(&[RURI_LWS], false, "INVITE sip:desk@example.org; transport=udp", Some("lwsruri.m3n4b5"), Some((28, "INVITE"))) },
    Case { file: "rfc4475/3.1.2.9-lwsstart.dat", want: p(&[LINE_SPACING], false, "INVITE sip:desk@example.org", Some("lwsstart.v5c6x7"), Some((29, "INVITE"))) },
    Case { file: "rfc4475/3.1.2.10-trws.dat", want: p(&[LINE_SPACING], false, "OPTIONS sip:desk@example.org", Some("trws.z1x2c3"), Some((30, "OPTIONS"))) },
    Case { file: "rfc4475/3.1.2.11-escruri.dat", want: p(&[RURI_HEADERS], false, "INVITE sip:desk@example.org?Subject=lunch%20plans", Some("escruri.b4n5m6"), Some((31, "INVITE"))) },
    Case { file: "rfc4475/3.1.2.12-baddate.dat", want: p(&[DATE_NOT_GMT], false, "INVITE sip:desk@example.org", Some("baddate.q7w8e9"), Some((32, "INVITE"))) },
    Case { file: "rfc4475/3.1.2.13-regbadct.dat", want: p(&[URI_BRACKETS], false, "REGISTER sip:registrar.example.org", Some("regbadct.r1t2y3@192.0.2.133"), Some((33, "REGISTER"))) },
    Case { file: "rfc4475/3.1.2.14-badaspec.dat", want: p(&[ADDR_SPEC_LWS], false, "OPTIONS sip:desk@example.org", Some("badaspec.u4i5o6"), Some((34, "OPTIONS"))) },
    Case { file: "rfc4475/3.1.2.15-baddn.dat", want: p(&[DISPLAY_UNQUOTED], true, "OPTIONS sip:desk@example.org", Some("baddn.p7a8s9@192.0.2.135"), Some((35, "OPTIONS"))) },
    Case { file: "rfc4475/3.1.2.16-badvers.dat", want: Want::Refused("NotSip") },
    Case { file: "rfc4475/3.1.2.17-mismatch01.dat", want: p(&[CSEQ_METHOD], false, "OPTIONS sip:desk@example.org", Some("mismatch01.h4j5k6"), Some((37, "INVITE"))) },
    Case { file: "rfc4475/3.1.2.18-mismatch02.dat", want: p(&[CSEQ_METHOD], false, "FROBNICATE sip:desk@example.org", Some("mismatch02.l7z8x9"), Some((38, "INVITE"))) },
    Case { file: "rfc4475/3.1.2.19-bigcode.dat", want: Want::Refused("InvalidStatusCode") },
    Case { file: "rfc4475/3.2.1-badbranch.dat", want: p(&[BRANCH_NO_ID], false, "OPTIONS sip:desk@example.org", Some("badbranch.n4m5q6"), Some((40, "OPTIONS"))) },
    Case { file: "rfc4475/3.3.1-insuf.dat", want: p(&[MANDATORY, MF_MISSING], false, "INVITE sip:desk@example.org", None, Some((41, "INVITE"))) },
    Case { file: "rfc4475/3.3.2-unkscm.dat", want: p(&[], false, "OPTIONS mysteryscheme:opaque-thing-42", Some("unkscm.w7e8r9"), Some((42, "OPTIONS"))) },
    Case { file: "rfc4475/3.3.3-novelsc.dat", want: p(&[], false, "OPTIONS im:desk@example.org", Some("novelsc.t1y2u3"), Some((43, "OPTIONS"))) },
    Case { file: "rfc4475/3.3.4-unksm2.dat", want: p(&[], false, "REGISTER sip:registrar.example.org", Some("unksm2.i4o5p6@reg.example.org"), Some((44, "REGISTER"))) },
    Case { file: "rfc4475/3.3.5-bext01.dat", want: p(&[], false, "OPTIONS sip:desk@example.org", Some("bext01.a7s8d9"), Some((45, "OPTIONS"))) },
    Case { file: "rfc4475/3.3.6-invut.dat", want: p(&[], false, "INVITE sip:desk@example.org", Some("invut.f1g2h3"), Some((46, "INVITE"))) },
    Case { file: "rfc4475/3.3.7-regaut01.dat", want: p(&[], false, "REGISTER sip:registrar.example.org", Some("regaut01.j4k5l6"), Some((47, "REGISTER"))) },
    Case { file: "rfc4475/3.3.8-multi01.dat", want: p(&[SINGULAR], false, "INVITE sip:desk@example.org", Some("multi01.first@192.0.2.148"), Some((48, "INVITE"))) },
    Case { file: "rfc4475/3.3.9-mcl01.dat", want: p(&[SINGULAR], false, "OPTIONS sip:desk@example.org", Some("mcl01.z4x5c6"), Some((49, "OPTIONS"))) },
    Case { file: "rfc4475/3.3.10-bcast.dat", want: p(&[], false, "200 OK", Some("bcast.v7b8n9"), Some((50, "INVITE"))) },
    Case { file: "rfc4475/3.3.11-zeromf.dat", want: p(&[MF_RANGE], false, "OPTIONS sip:desk@example.org", Some("zeromf.m1q2w3"), Some((51, "OPTIONS"))) },
    Case { file: "rfc4475/3.3.12-cparam01.dat", want: p(&[], false, "REGISTER sip:registrar.example.org", Some("cparam01.e4r5t6@192.0.2.152"), Some((52, "REGISTER"))) },
    Case { file: "rfc4475/3.3.13-cparam02.dat", want: p(&[], false, "REGISTER sip:registrar.example.org", Some("cparam02.y7u8i9@192.0.2.153"), Some((53, "REGISTER"))) },
    Case { file: "rfc4475/3.3.14-regescrt.dat", want: p(&[], false, "REGISTER sip:registrar.example.org", Some("regescrt.o1p2a3@192.0.2.154"), Some((54, "REGISTER"))) },
    Case { file: "rfc4475/3.3.15-sdp01.dat", want: p(&[], false, "INVITE sip:desk@example.org", Some("sdp01.s4d5f6"), Some((55, "INVITE"))) },
    Case { file: "rfc4475/3.4.1-inv2543.dat", want: p(&[BRANCH_COOKIE, MF_MISSING, RR_NOT_LOOSE, URI_PARAM_DEMOTED], false, "INVITE sip:DeskB@example.org", Some("inv2543.g7h8j9@client.example.net"), Some((61, "INVITE"))) },
    Case { file: "rfc5118/4.1-ipv6-good.dat", want: p(&[], false, "REGISTER sip:[2001:db8::42]", Some("good41.q1w2e3"), Some((41, "REGISTER"))) },
    Case { file: "rfc5118/4.2-ipv6-bad.dat", want: p(&[IPV6_UNBRACKETED], false, "REGISTER sip:2001:db8::42", Some("bad42.r4t5y6"), Some((42, "REGISTER"))) },
    Case { file: "rfc5118/4.3-port-ambiguous.dat", want: p(&[], false, "REGISTER sip:[2001:db8::42:5070]", Some("amb43.u7i8o9"), Some((43, "REGISTER"))) },
    Case { file: "rfc5118/4.4-port-unambiguous.dat", want: p(&[], false, "REGISTER sip:[2001:db8::42]:5070", Some("unamb44.p1a2s3"), Some((44, "REGISTER"))) },
    Case { file: "rfc5118/4.5-via-received-param-with-delim.dat", want: p(&[], false, "BYE sip:[2001:db8::42]", Some("withdelim45.d4f5g6"), Some((45, "BYE"))) },
    Case { file: "rfc5118/4.5-via-received-param-no-delim.dat", want: p(&[], false, "OPTIONS sip:[2001:db8::42]", Some("nodelim45.h7j8k9"), Some((46, "OPTIONS"))) },
    Case { file: "rfc5118/4.6-ipv6-in-sdp.dat", want: p(&[CL_MISMATCH], true, "INVITE sip:desk@[2001:db8::42]", Some("insdp46.l1z2x3"), Some((46, "INVITE"))) },
    Case { file: "rfc5118/4.7-mult-ip-in-header.dat", want: p(&[], false, "BYE sip:desk@edge.example.net", Some("multhdr47.c4v5b6"), Some((47, "BYE"))) },
    Case { file: "rfc5118/4.8-mult-ip-in-sdp.dat", want: p(&[], false, "INVITE sip:desk@[2001:db8::42]", Some("multsdp48.n7m8q9"), Some((48, "INVITE"))) },
    Case { file: "rfc5118/4.9-ipv4-mapped-ipv6.dat", want: p(&[], false, "INVITE sip:desk@example.org", Some("mapped49.w1e2r3"), Some((49, "INVITE"))) },
    Case { file: "rfc5118/4.10-ipv6-bug-abnf-3-colons.dat", want: p(&[], false, "OPTIONS sip:desk@[2001:db8:::192.0.2.60]", Some("three410.t4y5u6"), Some((410, "OPTIONS"))) },
    Case { file: "rfc5118/4.10-ipv6-correct-abnf-2-colons.dat", want: p(&[], false, "OPTIONS sip:desk@[2001:db8::192.0.2.60]", Some("two410.i7o8p9"), Some((410, "OPTIONS"))) },
];

/// The verdict each RFC section's own message got in the local run of
/// 2026-11-25 described in the module comment, as [`verdict`] writes it.
// rustfmt::skip: one verdict per line, aligned with CASES.
#[rustfmt::skip]
const RFC_VERDICTS: &[(&str, &str)] = &[
    ("rfc4475/3.1.1.1-wsinv.dat", r#"findings={"SIP-3261-8.1.1.7-BRANCH-COOKIE"} perr=false request=true method=Invite status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc4475/3.1.1.2-intmeth.dat", r#"findings={"SIP-3261-20.22-MAX-FORWARDS-RANGE"} perr=false request=true method=Custom status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc4475/3.1.1.3-esc01.dat", r#"findings={"SIP-3261-20.22-MAX-FORWARDS-RANGE"} perr=false request=true method=Invite status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc4475/3.1.1.4-escnull.dat", r#"findings={} perr=false request=true method=Register status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc4475/3.1.1.5-esc02.dat", r#"findings={} perr=false request=true method=Custom status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc4475/3.1.1.6-lwsdisp.dat", r#"findings={} perr=false request=true method=Options status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc4475/3.1.1.7-longreq.dat", r#"findings={"SIP-3261-8.1.1.7-BRANCH-COOKIE"} perr=false request=true method=Invite status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc4475/3.1.1.8-dblreq.dat", r#"findings={} perr=false request=true method=Register status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc4475/3.1.1.9-semiuri.dat", r#"findings={} perr=false request=true method=Options status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc4475/3.1.1.10-transports.dat", r#"findings={} perr=false request=true method=Options status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc4475/3.1.1.11-mpart01.dat", r#"findings={} perr=false request=true method=Message status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc4475/3.1.1.12-unreason.dat", r#"findings={} perr=false request=false method= status-class=2 call_id=true cseq=present mal=0 dialog=true"#),
    ("rfc4475/3.1.1.13-noreason.dat", r#"findings={} perr=false request=false method= status-class=1 call_id=true cseq=present mal=0 dialog=true"#),
    ("rfc4475/3.1.2.1-badinv01.dat", r#"findings={"SIP-3261-25.1-EMPTY-PARAMETER", "SIP-3261-8.1.1.7-BRANCH-COOKIE"} perr=false request=true method=Invite status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc4475/3.1.2.2-clerr.dat", r#"findings={"SIP-3261-20.14-CONTENT-LENGTH-MISMATCH", "SIP-3261-20.22-MAX-FORWARDS-RANGE"} perr=true request=true method=Invite status-class=0 call_id=true cseq=method-match=true mal=1 dialog=true"#),
    ("rfc4475/3.1.2.3-ncl.dat", r#"findings={"SIP-3261-20.14-CONTENT-LENGTH-INVALID", "SIP-3261-20.22-MAX-FORWARDS-RANGE"} perr=true request=true method=Invite status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc4475/3.1.2.4-scalar02.dat", r#"findings={"SIP-3261-20.16-CSEQ-MALFORMED", "SIP-3261-20.22-MAX-FORWARDS-RANGE"} perr=false request=true method=Register status-class=0 call_id=true cseq=none mal=1 dialog=true"#),
    ("rfc4475/3.1.2.5-scalarlg.dat", r#"findings={"SIP-3261-20.16-CSEQ-MALFORMED"} perr=false request=false method= status-class=5 call_id=true cseq=none mal=1 dialog=false"#),
    ("rfc4475/3.1.2.6-quotbal.dat", r#"findings={"SIP-3261-25.1-QUOTED-STRING-UNTERMINATED"} perr=false request=true method=Invite status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc4475/3.1.2.7-ltgtruri.dat", r#"findings={"SIP-3261-25.1-REQUEST-URI-BRACKETED", "SIP-3261-8.1.1.7-BRANCH-COOKIE"} perr=false request=true method=Invite status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc4475/3.1.2.8-lwsruri.dat", r#"findings={"SIP-3261-25.1-REQUEST-URI-WHITESPACE"} perr=false request=true method=Invite status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc4475/3.1.2.9-lwsstart.dat", r#"findings={"SIP-3261-7.1-REQUEST-LINE-SPACING"} perr=false request=true method=Invite status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc4475/3.1.2.10-trws.dat", r#"findings={"SIP-3261-7.1-REQUEST-LINE-SPACING"} perr=false request=true method=Options status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc4475/3.1.2.11-escruri.dat", r#"findings={"SIP-3261-19.1.1-REQUEST-URI-HEADERS"} perr=false request=true method=Invite status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc4475/3.1.2.12-baddate.dat", r#"findings={"SIP-3261-20.17-DATE-NOT-GMT"} perr=false request=true method=Invite status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc4475/3.1.2.13-regbadct.dat", r#"findings={"SIP-3261-20-URI-BRACKETS"} perr=false request=true method=Register status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc4475/3.1.2.14-badaspec.dat", r#"findings={"SIP-3261-25.1-ADDR-SPEC-WHITESPACE"} perr=false request=true method=Options status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc4475/3.1.2.15-baddn.dat", r#"findings={"SIP-3261-25.1-DISPLAY-NAME-UNQUOTED"} perr=true request=true method=Options status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc4475/3.1.2.16-badvers.dat", "refused NotSip"),
    ("rfc4475/3.1.2.17-mismatch01.dat", r#"findings={"SIP-3261-8.1.1.5-CSEQ-METHOD-MISMATCH"} perr=false request=true method=Options status-class=0 call_id=true cseq=method-match=false mal=0 dialog=true"#),
    ("rfc4475/3.1.2.18-mismatch02.dat", r#"findings={"SIP-3261-8.1.1.5-CSEQ-METHOD-MISMATCH"} perr=false request=true method=Custom status-class=0 call_id=true cseq=method-match=false mal=0 dialog=true"#),
    ("rfc4475/3.1.2.19-bigcode.dat", "refused InvalidStatusCode"),
    ("rfc4475/3.2.1-badbranch.dat", r#"findings={"SIP-3261-8.1.1.7-BRANCH-NO-IDENTIFIER"} perr=false request=true method=Options status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc4475/3.3.1-insuf.dat", r#"findings={"SIP-3261-8.1.1-MANDATORY-HEADER-MISSING", "SIP-3261-8.1.1.6-MAX-FORWARDS-MISSING"} perr=false request=true method=Invite status-class=0 call_id=false cseq=method-match=true mal=3 dialog=false"#),
    ("rfc4475/3.3.2-unkscm.dat", r#"findings={} perr=false request=true method=Options status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc4475/3.3.3-novelsc.dat", r#"findings={} perr=false request=true method=Options status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc4475/3.3.4-unksm2.dat", r#"findings={} perr=false request=true method=Register status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc4475/3.3.5-bext01.dat", r#"findings={} perr=false request=true method=Options status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc4475/3.3.6-invut.dat", r#"findings={} perr=false request=true method=Invite status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc4475/3.3.7-regaut01.dat", r#"findings={} perr=false request=true method=Register status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc4475/3.3.8-multi01.dat", r#"findings={"SIP-3261-7.3.1-SINGULAR-HEADER-REPEATED"} perr=false request=true method=Invite status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc4475/3.3.9-mcl01.dat", r#"findings={"SIP-3261-7.3.1-SINGULAR-HEADER-REPEATED"} perr=false request=true method=Options status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc4475/3.3.10-bcast.dat", r#"findings={} perr=false request=false method= status-class=2 call_id=true cseq=present mal=0 dialog=true"#),
    ("rfc4475/3.3.11-zeromf.dat", r#"findings={"SIP-3261-20.22-MAX-FORWARDS-RANGE"} perr=false request=true method=Options status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc4475/3.3.12-cparam01.dat", r#"findings={} perr=false request=true method=Register status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc4475/3.3.13-cparam02.dat", r#"findings={} perr=false request=true method=Register status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc4475/3.3.14-regescrt.dat", r#"findings={} perr=false request=true method=Register status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc4475/3.3.15-sdp01.dat", r#"findings={} perr=false request=true method=Invite status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc4475/3.4.1-inv2543.dat", r#"findings={"SIP-3261-16.6-RECORD-ROUTE-NOT-LOOSE", "SIP-3261-19.1.1-URI-PARAM-DEMOTED", "SIP-3261-8.1.1.6-MAX-FORWARDS-MISSING", "SIP-3261-8.1.1.7-BRANCH-COOKIE"} perr=false request=true method=Invite status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc5118/4.1-ipv6-good.dat", r#"findings={} perr=false request=true method=Register status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc5118/4.2-ipv6-bad.dat", r#"findings={"SIP-3261-25.1-IPV6-REFERENCE-UNBRACKETED"} perr=false request=true method=Register status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc5118/4.3-port-ambiguous.dat", r#"findings={} perr=false request=true method=Register status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc5118/4.4-port-unambiguous.dat", r#"findings={} perr=false request=true method=Register status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc5118/4.5-via-received-param-with-delim.dat", r#"findings={} perr=false request=true method=Bye status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc5118/4.5-via-received-param-no-delim.dat", r#"findings={} perr=false request=true method=Options status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc5118/4.6-ipv6-in-sdp.dat", r#"findings={"SIP-3261-20.14-CONTENT-LENGTH-MISMATCH"} perr=true request=true method=Invite status-class=0 call_id=true cseq=method-match=true mal=1 dialog=true"#),
    ("rfc5118/4.7-mult-ip-in-header.dat", r#"findings={} perr=false request=true method=Bye status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc5118/4.8-mult-ip-in-sdp.dat", r#"findings={} perr=false request=true method=Invite status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc5118/4.9-ipv4-mapped-ipv6.dat", r#"findings={} perr=false request=true method=Invite status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc5118/4.10-ipv6-bug-abnf-3-colons.dat", r#"findings={} perr=false request=true method=Options status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
    ("rfc5118/4.10-ipv6-correct-abnf-2-colons.dat", r#"findings={} perr=false request=true method=Options status-class=0 call_id=true cseq=method-match=true mal=0 dialog=true"#),
];

/// The fixture directory.
fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sip-torture")
}

/// The fuzz seed directory of one target.
fn corpus(target: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz/corpus")
        .join(target)
}

fn read(file: &str) -> Result<Vec<u8>, TestError> {
    std::fs::read(dir().join(file)).map_err(|e| format!("read {file}: {e}").into())
}

fn parse(data: &[u8]) -> Result<SipMessage, sipnab::ParseError> {
    let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    parse_sip(
        data,
        chrono::DateTime::from_timestamp(1_718_452_800, 0).unwrap_or_default(),
        ip,
        ip,
        5060,
        5060,
        TransportProto::Udp,
    )
}

fn rule_ids(m: &SipMessage) -> BTreeSet<&'static str> {
    Linter::new(LintConfig::new())
        .lint_message(m, 0)
        .iter()
        .map(|f| f.rule_id)
        .collect()
}

/// Whether the dialog store keeps a dialog for `m`.
fn dialog_kept(m: SipMessage) -> bool {
    let cid = m.call_id().map(str::to_string);
    let mut store = DialogStore::new(16, false);
    store.process_message(m);
    cid.as_deref().and_then(|c| store.get(c)).is_some()
}

fn first_key(m: &SipMessage) -> String {
    if m.is_request {
        format!(
            "{} {}",
            m.method
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default(),
            m.request_uri.as_deref().unwrap_or("")
        )
    } else {
        format!(
            "{} {}",
            m.status_code.unwrap_or(0),
            m.reason.as_deref().unwrap_or("")
        )
    }
}

/// Everything the RFC case is about, and nothing a message author chooses:
/// the refusal kind, or the rule ids, the `parse_error` flag, request or
/// response, the method (an extension method as `Custom`), the status class,
/// whether a Call-ID and a CSeq were read and whether the CSeq method matches,
/// the number of malformations, and whether a dialog is kept.
fn verdict(data: &[u8]) -> String {
    match parse(data) {
        Err(e) => {
            let d = format!("{e:?}");
            format!("refused {}", d.split([' ', '{', '(']).next().unwrap_or(""))
        }
        Ok(m) => {
            let cseq = match m.cseq() {
                None => "none".to_string(),
                Some((_, cm)) => match &m.method {
                    Some(sm) if m.is_request => format!("method-match={}", sm.as_str() == cm),
                    _ => "present".to_string(),
                },
            };
            let method = match &m.method {
                None => String::new(),
                Some(SipMethod::Custom(_)) => "Custom".to_string(),
                Some(other) => format!("{other:?}"),
            };
            let s = format!(
                "findings={:?} perr={} request={} method={method} status-class={} call_id={} cseq={cseq} mal={}",
                rule_ids(&m),
                m.parse_error,
                m.is_request,
                m.status_code.map_or(0, |c| c / 100),
                m.call_id().is_some(),
                m.malformations().len(),
            );
            format!("{s} dialog={}", dialog_kept(m))
        }
    }
}

/// How `case`'s fixture differs from what [`CASES`] wants, if it does.
fn check(case: &Case) -> Result<Vec<String>, TestError> {
    let got = parse(&read(case.file)?);
    let mut errs = Vec::new();
    match (&case.want, got) {
        (Want::Refused(v), Err(e)) => {
            let d = format!("{e:?}");
            if !d.starts_with(v) {
                errs.push(format!("refused as {d}, want {v}"));
            }
        }
        (Want::Refused(v), Ok(m)) => {
            errs.push(format!("parsed ({}), want refusal {v}", first_key(&m)))
        }
        (Want::Parsed { .. }, Err(e)) => errs.push(format!("refused as {e:?}, want parsed")),
        (
            Want::Parsed {
                findings,
                perr,
                first,
                call_id,
                cseq,
                dialog,
            },
            Ok(m),
        ) => {
            let got = rule_ids(&m);
            let want: BTreeSet<&str> = findings.iter().copied().collect();
            if got != want {
                errs.push(format!("findings {got:?}, want {want:?}"));
            }
            if m.parse_error != *perr {
                errs.push(format!("parse_error {}, want {perr}", m.parse_error));
            }
            let fk = first_key(&m);
            if fk != *first {
                errs.push(format!("start line {fk:?}, want {first:?}"));
            }
            if m.call_id() != *call_id {
                errs.push(format!("Call-ID {:?}, want {call_id:?}", m.call_id()));
            }
            if m.cseq() != *cseq {
                errs.push(format!("CSeq {:?}, want {cseq:?}", m.cseq()));
            }
            let kept = dialog_kept(m);
            if kept != *dialog {
                errs.push(format!("dialog kept {kept}, want {dialog}"));
            }
        }
    }
    Ok(errs)
}

#[test]
fn every_fixture_gets_the_handling_its_rfc_case_requires() -> Result<(), TestError> {
    let mut fails = Vec::new();
    for case in CASES {
        let errs = check(case)?;
        if !errs.is_empty() {
            fails.push(format!("{}: {}", case.file, errs.join("; ")));
        }
    }
    assert!(
        fails.is_empty(),
        "{} of {} fixtures disagree:\n{}",
        fails.len(),
        CASES.len(),
        fails.join("\n")
    );
    Ok(())
}

#[test]
fn every_fixture_gets_the_verdict_the_rfc_message_got() -> Result<(), TestError> {
    let mut diffs = Vec::new();
    for (file, want) in RFC_VERDICTS {
        let got = verdict(&read(file)?);
        if got != *want {
            diffs.push(format!("{file}:\n  fixture {got}\n  RFC     {want}"));
        }
    }
    assert!(
        diffs.is_empty(),
        "{} fixtures differ from the RFC message's verdict:\n{}",
        diffs.len(),
        diffs.join("\n")
    );
    Ok(())
}

/// The fixture files on disk, as `rfcNNNN/<name>.dat`.
fn on_disk() -> Result<BTreeSet<String>, TestError> {
    let mut out = BTreeSet::new();
    for sub in ["rfc4475", "rfc5118"] {
        for e in std::fs::read_dir(dir().join(sub))? {
            out.insert(format!("{sub}/{}", e?.file_name().to_string_lossy()));
        }
    }
    Ok(out)
}

#[test]
fn both_tables_name_every_fixture_exactly_once() -> Result<(), TestError> {
    let disk = on_disk()?;
    let cases: BTreeSet<String> = CASES.iter().map(|c| c.file.to_string()).collect();
    let verdicts: BTreeSet<String> = RFC_VERDICTS.iter().map(|(f, _)| (*f).to_string()).collect();
    assert_eq!(
        cases.len(),
        CASES.len(),
        "a fixture is listed twice in CASES"
    );
    assert_eq!(
        verdicts.len(),
        RFC_VERDICTS.len(),
        "a fixture is listed twice in RFC_VERDICTS"
    );
    assert_eq!(disk, cases, "the fixtures on disk and CASES disagree");
    assert_eq!(
        disk, verdicts,
        "the fixtures on disk and RFC_VERDICTS disagree"
    );
    assert_eq!(
        disk.iter().filter(|f| f.starts_with("rfc4475/")).count(),
        49,
        "RFC 4475 has 49 cases"
    );
    assert_eq!(
        disk.iter().filter(|f| f.starts_with("rfc5118/")).count(),
        12,
        "RFC 5118 has 12 cases"
    );
    Ok(())
}

/// `PROVENANCE.txt` entries: (file, RFC section, SHA-256).
fn provenance() -> Result<Vec<(String, String, String)>, TestError> {
    let text = std::fs::read_to_string(dir().join("PROVENANCE.txt"))?;
    let mut out = Vec::new();
    let mut file: Option<String> = None;
    let mut section: Option<String> = None;
    for line in text.lines() {
        if line.starts_with("rfc4475/") || line.starts_with("rfc5118/") {
            file = Some(line.trim().to_string());
            section = None;
        } else if let Some(s) = line.strip_prefix("  covers: ") {
            section = Some(s.trim().to_string());
        } else if let Some(h) = line.strip_prefix("  SHA-256: ") {
            let f = file.take().ok_or("a SHA-256 line before any file line")?;
            let s = section
                .take()
                .ok_or_else(|| format!("{f}: no covers line before its SHA-256"))?;
            out.push((f, s, h.trim().to_string()));
        }
    }
    Ok(out)
}

fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[test]
fn provenance_names_each_fixture_its_rfc_section_and_its_digest() -> Result<(), TestError> {
    let entries = provenance()?;
    let disk = on_disk()?;
    let listed: BTreeSet<String> = entries.iter().map(|(f, _, _)| f.clone()).collect();
    assert_eq!(
        listed.len(),
        entries.len(),
        "PROVENANCE.txt lists a fixture twice"
    );
    assert_eq!(
        listed, disk,
        "PROVENANCE.txt and the fixtures on disk disagree"
    );
    for (file, section, digest) in &entries {
        let (rfc, rest) = file.split_once('/').ok_or("no RFC directory")?;
        let number = rest
            .split('-')
            .next()
            .ok_or("no section in the file name")?;
        let want = format!("RFC {} section {number}", &rfc[3..]);
        assert_eq!(
            section, &want,
            "{file}: covers line does not name the section in its file name"
        );
        assert_eq!(
            &sha256_hex(&read(file)?),
            digest,
            "{file}: SHA-256 differs from PROVENANCE.txt"
        );
    }
    Ok(())
}

/// The fuzz seed name for a fixture: `<rfc>-<stem>`.
fn seed_name(file: &str) -> Option<String> {
    let (rfc, rest) = file.split_once('/')?;
    Some(format!("{rfc}-{}", rest.strip_suffix(".dat")?))
}

/// The body of a message whose headers name `application/sdp`.
fn sdp_body(data: &[u8]) -> Option<&[u8]> {
    let end = data.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = String::from_utf8_lossy(&data[..end]).to_ascii_lowercase();
    let sdp = head.lines().any(|l| {
        let l = l.trim_start();
        (l.starts_with("content-type") || l.starts_with("c:") || l.starts_with("c "))
            && l.contains("application/sdp")
    });
    let body = &data[end + 4..];
    (sdp && !body.is_empty()).then_some(body)
}

#[test]
fn the_fuzz_seeds_are_the_fixtures_and_their_sdp_bodies() -> Result<(), TestError> {
    let mut sdp_seeds = 0;
    for case in CASES {
        let data = read(case.file)?;
        let name = seed_name(case.file).ok_or("bad fixture name")?;
        let seed = std::fs::read(corpus("sip_parser").join(&name))
            .map_err(|e| format!("sip_parser seed {name}: {e}"))?;
        assert_eq!(
            seed, data,
            "sip_parser seed {name} differs from {}",
            case.file
        );
        let body_seed = corpus("sdp_parser").join(format!("{name}-body"));
        match sdp_body(&data) {
            Some(body) => {
                let seed = std::fs::read(&body_seed)
                    .map_err(|e| format!("sdp_parser seed {name}-body: {e}"))?;
                assert_eq!(
                    seed, body,
                    "sdp_parser seed {name}-body differs from the body of {}",
                    case.file
                );
                sdp_seeds += 1;
            }
            None => assert!(
                !body_seed.exists(),
                "sdp_parser seed {name}-body exists, but {} has no SDP body",
                case.file
            ),
        }
    }
    assert!(sdp_seeds > 0, "no fixture produced an sdp_parser seed");
    Ok(())
}

// ----------------------------------------------------------------------------
// Reserved values only.

/// Why `host` is not a name reserved for documentation (RFC 2606, RFC 6761),
/// if it is not one.
fn host_not_reserved(host: &str) -> Option<String> {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() || !h.contains('.') || h.parse::<Ipv4Addr>().is_ok() {
        return None;
    }
    if !h.chars().any(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    let ok = [
        "example.com",
        "example.net",
        "example.org",
        "example",
        "invalid",
        "test",
    ]
    .iter()
    .any(|s| h == *s || h.ends_with(&format!(".{s}")));
    (!ok).then(|| format!("host {host}"))
}

/// Why `a` is not an RFC 5737 address, if it is not one. 255.255.255.255
/// passes only where `bcast_ok`.
fn v4_not_reserved(a: Ipv4Addr, bcast_ok: bool) -> Option<String> {
    let o = a.octets();
    let doc = matches!(
        (o[0], o[1], o[2]),
        (192, 0, 2) | (198, 51, 100) | (203, 0, 113)
    );
    (!doc && !(bcast_ok && a == Ipv4Addr::BROADCAST)).then(|| format!("IPv4 {a}"))
}

/// Why `text` is not an RFC 3849 address (or an IPv4-mapped RFC 5737 one), if
/// it parses as IPv6 and is not.
fn v6_not_reserved(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    match lower.parse::<Ipv6Addr>() {
        Ok(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return v4_not_reserved(v4, false);
            }
            let s = a.segments();
            (s[0] != 0x2001 || s[1] != 0x0db8).then(|| format!("IPv6 {text}"))
        }
        // RFC 5118 section 4.10's three-colon form does not parse; its prefix
        // must still be the documentation one.
        Err(_) => (lower.contains("::") && !lower.starts_with("2001:db8:"))
            .then(|| format!("IPv6 {text}")),
    }
}

/// Every value in `data` that is not reserved for documentation: hosts,
/// IPv4 and IPv6 addresses and telephone numbers.
fn unreserved_values(data: &[u8], bcast_ok: bool) -> Result<Vec<String>, TestError> {
    let text = String::from_utf8_lossy(data);
    let mut out = Vec::new();
    let v4 = regex::Regex::new(r"(?:^|[^0-9.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:$|[^0-9.])")?;
    for c in v4.captures_iter(&text) {
        if let Ok(a) = c[1].parse::<Ipv4Addr>() {
            out.extend(v4_not_reserved(a, bcast_ok));
        }
    }
    let v6 = regex::Regex::new(r"(?i)(?:\[|IP6 |received=|sips?:)([0-9a-f]*:[0-9a-f:.]*)")?;
    for c in v6.captures_iter(&text) {
        if c[1].matches(':').count() >= 2 {
            out.extend(v6_not_reserved(c[1].trim_end_matches('.')));
        }
    }
    let host = regex::Regex::new(
        r"(?i)(?:@|SIP\s*/\s*2\.0\s*/\s*[a-z]+\s+|IN IP[46] |https?://|sips?:)([a-z0-9-]+(?:\.[a-z0-9-]+)+)",
    )?;
    for c in host.captures_iter(&text) {
        out.extend(host_not_reserved(&c[1]));
    }
    let phone = regex::Regex::new(r"\+(\d{7,15})")?;
    for c in phone.captures_iter(&text) {
        let d = &c[1];
        let fictional = d.len() >= 7 && d[d.len() - 7..].starts_with("55501");
        if !fictional {
            out.push(format!("telephone number +{d}"));
        }
    }
    Ok(out)
}

#[test]
fn the_scan_finds_each_kind_of_unreserved_value() -> Result<(), TestError> {
    // Each planted value is outside the documentation ranges, and none can
    // belong to anyone: private and link-local addresses, the .internal,
    // .lan and .corp names no registry delegates, and a telephone number
    // with the NANP area code 000, which is never assigned.
    let planted: &[(&str, &str)] = &[
        ("Via: SIP/2.0/UDP 10.1.2.3;branch=z9hG4bK1", "IPv4 10.1.2.3"),
        ("c=IN IP4 172.16.0.9", "IPv4 172.16.0.9"),
        (
            "Via: SIP/2.0/UDP 255.255.255.255;branch=z9hG4bK1",
            "IPv4 255.255.255.255",
        ),
        ("To: <sip:desk@[fe80::5]>", "IPv6 fe80::5"),
        ("c=IN IP6 ::ffff:10.0.0.7", "IPv4 10.0.0.7"),
        ("REGISTER sip:fd00::1 SIP/2.0", "IPv6 fd00::1"),
        ("From: <sip:desk@pbx.internal>;tag=1", "host pbx.internal"),
        (
            "Via: SIP/2.0/TCP relay.carrier.internal;branch=z9hG4bK1",
            "host relay.carrier.internal",
        ),
        (
            "o=- 1 1 IN IP4 media.provider.lan",
            "host media.provider.lan",
        ),
        (
            "From: <https://www.vendor.corp/>;tag=1",
            "host www.vendor.corp",
        ),
        (
            "Contact: <sip:+10005551234@gw.example.net>",
            "telephone number +10005551234",
        ),
    ];
    for (line, want) in planted {
        let got = unreserved_values(line.as_bytes(), false)?;
        assert!(
            got.iter().any(|g| g == want),
            "{line:?}: scan reported {got:?}, want {want:?}"
        );
    }
    let clean = b"Via: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK1\r\nTo: <sip:a@[2001:db8::1]>\r\n\
        From: <sip:+12125550142@gw.example.org>;tag=1\r\nc=IN IP6 ::ffff:198.51.100.4\r\n\
        Contact: <sip:b@host.example.invalid>\r\nCall-ID: x.y@203.0.113.9\r\n";
    let got = unreserved_values(clean, false)?;
    assert!(
        got.is_empty(),
        "reserved values reported as unreserved: {got:?}"
    );
    let bcast = b"Via: SIP/2.0/UDP 255.255.255.255;branch=z9hG4bK1";
    assert!(
        unreserved_values(bcast, true)?.is_empty(),
        "the broadcast address must pass where it is allowed"
    );
    Ok(())
}

/// `text` without RFC section numbers and fixture paths, which have the shape
/// of an IPv4 address ("section 3.1.1.1", "rfc4475/3.1.1.1-wsinv.dat") but
/// are not one. Everything else stays, so an address written in prose is
/// still scanned.
fn without_section_numbers(text: &str) -> Result<String, TestError> {
    let re =
        regex::Regex::new(r"(?i)(?:rfc\d+/)?\d+(?:\.\d+)+-[a-z0-9.-]+\.dat|section \d+(?:\.\d+)*")?;
    Ok(re.replace_all(text, " ").into_owned())
}

#[test]
fn section_numbers_are_not_addresses_but_prose_addresses_are() -> Result<(), TestError> {
    let text =
        "rfc4475/3.1.1.1-wsinv.dat\n  covers: RFC 4475 section 3.1.1.1\n  sent from 10.9.8.7\n";
    let got = unreserved_values(without_section_numbers(text)?.as_bytes(), false)?;
    assert_eq!(
        got,
        ["IPv4 10.9.8.7"],
        "only the prose address may be reported"
    );
    Ok(())
}

/// Every file the reserved-value rule covers: the fixtures, the provenance
/// file and the fuzz seeds made from them.
fn scanned_files() -> Result<Vec<(String, PathBuf)>, TestError> {
    let mut out = Vec::new();
    for f in on_disk()? {
        out.push((f.clone(), dir().join(&f)));
    }
    out.push(("PROVENANCE.txt".to_string(), dir().join("PROVENANCE.txt")));
    for target in ["sip_parser", "sdp_parser"] {
        for e in std::fs::read_dir(corpus(target))? {
            let name = e?.file_name().to_string_lossy().to_string();
            if name.starts_with("rfc4475-") || name.starts_with("rfc5118-") {
                out.push((
                    format!("fuzz/corpus/{target}/{name}"),
                    corpus(target).join(&name),
                ));
            }
        }
    }
    Ok(out)
}

#[test]
fn fixtures_and_seeds_hold_only_reserved_values() -> Result<(), TestError> {
    let files = scanned_files()?;
    assert!(
        files.len() > 2 * CASES.len(),
        "the scan reached only {} files",
        files.len()
    );
    let mut found = Vec::new();
    for (name, path) in &files {
        // RFC 4475 section 3.3.10 tests a Via of 255.255.255.255.
        let bcast_ok = name.contains("3.3.10-bcast") || name == "PROVENANCE.txt";
        let mut data = std::fs::read(path)?;
        if name == "PROVENANCE.txt" {
            data = without_section_numbers(&String::from_utf8(data)?)?.into_bytes();
        }
        for v in unreserved_values(&data, bcast_ok)? {
            found.push(format!("{name}: {v}"));
        }
    }
    assert!(
        found.is_empty(),
        "values not reserved for documentation:\n{}",
        found.join("\n")
    );
    Ok(())
}

#[test]
fn only_the_broadcast_case_holds_the_broadcast_address() -> Result<(), TestError> {
    let with: Vec<String> = on_disk()?
        .into_iter()
        .filter(|f| read(f).is_ok_and(|d| d.windows(15).any(|w| w == b"255.255.255.255")))
        .collect();
    assert_eq!(
        with,
        ["rfc4475/3.3.10-bcast.dat"],
        "255.255.255.255 must appear only where RFC 4475 section 3.3.10 needs it"
    );
    Ok(())
}
