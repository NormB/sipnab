//! Destination country of a dialed number: dial-plan stripping, E.164 digits, and a
//! longest-prefix lookup from calling code to ISO 3166-1 alpha-2.
//!
//! This is the one capability the cross-project review found sipnab genuinely lacks:
//! every fraud heuristic reasons about call *shape* and none could say where a call was
//! going. The logic here is ported from the TFPS project's `tfps-core` crate
//! (`crates/tfps-core/src/dialplan.rs` and `country.rs`, Apache-2.0,
//! <https://github.com/sippulse/tfps>) rather than taken as a dependency, because sipnab
//! never depends on peer software: a machine with no TFPS installed runs sipnab exactly as
//! before, and a shared crate would make one project's release cadence the other's problem.
//! TFPS's stable country *index* and novelty bitmaps are deliberately not ported — they
//! serve its anomaly detector, which is out of scope here.
//!
//! Two rules from the reference are load-bearing and kept as written. **Longest prefix
//! wins** at both stages: a plan with `0` (national trunk) and `00` (international) reads
//! `00212…` as international and `0212…` as national with no extra rule, and `1246…` is
//! Barbados, not the United States — matching short would file half the Caribbean under
//! `US` exactly where premium-rate fraud is common. And **"not international" is never a
//! failure**: a number that matches no prefix is out of scope and passes; the reference
//! records that denying everything unclassifiable became 39% of a predecessor's rejections.

/// Maximum digits in an E.164 number, without the `+` (ITU-T E.164 §6.2.1).
const E164_MAX_DIGITS: usize = 15;
/// Smallest plausible international number: calling code plus a subscriber part.
const E164_MIN_DIGITS: usize = 7;

/// How a site presents the numbers it dials.
///
/// `bare_e164` is an explicit flag rather than an empty prefix, because the two
/// readings are far apart: with it on, `2125551234` is Morocco; with it off, it is a
/// domestic North American number. Turning it on must be a declaration, not an accident.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DialPlan {
    /// International dialing prefixes, e.g. `+`, `00`, `011`. Order is irrelevant:
    /// matching is always longest first.
    prefixes: Vec<String>,
    /// Numbers arrive as plain E.164 with no prefix at all, as in wholesale.
    bare_e164: bool,
}

/// Country code plus subscriber digits, with the international prefix removed and no
/// `+`. Not yet validated against any numbering plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InternationalDigits(pub String);

/// A resolved destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Country {
    /// ISO 3166-1 alpha-2, or a `SAT-`/`NET-`/`INTL-` label for non-geographic ranges.
    pub iso: &'static str,
    /// The E.164 calling code that matched.
    pub calling_code: &'static str,
}

impl DialPlan {
    /// A plan with the given international prefixes and no bare-E.164 declaration.
    pub fn new(prefixes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            prefixes: prefixes.into_iter().map(Into::into).collect(),
            bare_e164: false,
        }
    }

    /// The prefixes an operator who configured nothing gets: `+`, `00` and `011`.
    ///
    /// Not bare E.164 — see [`DialPlan`] for why that must be explicit.
    pub fn common() -> Self {
        Self::new(["+", "00", "011"])
    }

    /// Declares that numbers arrive as plain E.164 with no prefix at all.
    pub fn with_bare_e164(mut self) -> Self {
        self.bare_e164 = true;
        self
    }

    /// The declared prefixes, in the order given.
    pub fn prefixes(&self) -> &[String] {
        &self.prefixes
    }

    /// The international digits of `dialed`, or `None` when it is not international
    /// for this plan — which is out of scope, never a failure.
    pub fn to_international(&self, dialed: &str) -> Option<InternationalDigits> {
        let cleaned = strip_visual_separators(dialed);
        // Longest match. This alone resolves the trunk-zero ambiguity: with `0` and
        // `00` both declared, `00212…` strips the longer prefix and `0212…` the shorter.
        let best = self
            .prefixes
            .iter()
            .filter(|p| !p.is_empty() && cleaned.starts_with(p.as_str()))
            .max_by_key(|p| p.len());
        let rest = match best {
            Some(p) => &cleaned[p.len()..],
            None if self.bare_e164 => cleaned.as_str(),
            None => return None,
        };
        if rest.chars().any(|c| !c.is_ascii_digit()) {
            // Something non-numeric survived the prefix: not a dialable number.
            return None;
        }
        if !(E164_MIN_DIGITS..=E164_MAX_DIGITS).contains(&rest.len()) {
            return None;
        }
        Some(InternationalDigits(rest.to_string()))
    }

    /// Whether `dialed` matches any declared prefix. Allocates nothing.
    pub fn looks_international(&self, dialed: &str) -> bool {
        if self.bare_e164 {
            return true;
        }
        self.prefixes
            .iter()
            .any(|p| !p.is_empty() && dialed.starts_with(p.as_str()))
    }
}

/// The destination country of `digits`, by longest matching calling code.
pub fn resolve(digits: &InternationalDigits) -> Option<Country> {
    let d = digits.0.as_str();
    let mut best: Option<&(&str, &str)> = None;
    for row in CODES {
        if d.starts_with(row.0) && best.is_none_or(|b| row.0.len() > b.0.len()) {
            best = Some(row);
        }
    }
    best.map(|(code, iso)| Country {
        iso,
        calling_code: code,
    })
}

/// Satellite and non-geographic network-service ranges. A signal, never a verdict on
/// its own: most premium-rate numbers observed in the wild are ordinary fixed and
/// mobile ranges.
pub fn is_non_geographic(c: &Country) -> bool {
    c.iso.starts_with("SAT-") || c.iso.starts_with("NET-") || c.iso.starts_with("INTL-")
}

/// Dial-plan stripping and country lookup in one step.
pub fn destination_of(dialed: &str, plan: &DialPlan) -> Option<Country> {
    plan.to_international(dialed).and_then(|d| resolve(&d))
}

/// Visual separators seen in real Request-URIs. `+` is a prefix, not a separator.
fn strip_visual_separators(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(c, '-' | '.' | ' ' | '(' | ')'))
        .collect()
}

/// E.164 calling code → label. Sorted by code for reading; matching is by longest
/// prefix, so order carries no meaning.
const CODES: &[(&str, &str)] = &[
    ("1", "NANP"),
    ("1242", "BS"),
    ("1246", "BB"),
    ("1264", "AI"),
    ("1268", "AG"),
    ("1284", "VG"),
    ("1340", "VI"),
    ("1345", "KY"),
    ("1441", "BM"),
    ("1473", "GD"),
    ("1649", "TC"),
    ("1658", "JM"),
    ("1664", "MS"),
    ("1670", "MP"),
    ("1671", "GU"),
    ("1684", "AS"),
    ("1721", "SX"),
    ("1758", "LC"),
    ("1767", "DM"),
    ("1784", "VC"),
    ("1787", "PR"),
    ("1809", "DO"),
    ("1829", "DO"),
    ("1849", "DO"),
    ("1868", "TT"),
    ("1869", "KN"),
    ("1876", "JM"),
    ("1939", "PR"),
    ("20", "EG"),
    ("211", "SS"),
    ("212", "MA"),
    ("213", "DZ"),
    ("216", "TN"),
    ("218", "LY"),
    ("220", "GM"),
    ("221", "SN"),
    ("222", "MR"),
    ("223", "ML"),
    ("224", "GN"),
    ("225", "CI"),
    ("226", "BF"),
    ("227", "NE"),
    ("228", "TG"),
    ("229", "BJ"),
    ("230", "MU"),
    ("231", "LR"),
    ("232", "SL"),
    ("233", "GH"),
    ("234", "NG"),
    ("235", "TD"),
    ("236", "CF"),
    ("237", "CM"),
    ("238", "CV"),
    ("239", "ST"),
    ("240", "GQ"),
    ("241", "GA"),
    ("242", "CG"),
    ("243", "CD"),
    ("244", "AO"),
    ("245", "GW"),
    ("246", "IO"),
    ("248", "SC"),
    ("249", "SD"),
    ("250", "RW"),
    ("251", "ET"),
    ("252", "SO"),
    ("253", "DJ"),
    ("254", "KE"),
    ("255", "TZ"),
    ("256", "UG"),
    ("257", "BI"),
    ("258", "MZ"),
    ("260", "ZM"),
    ("261", "MG"),
    ("262", "RE"),
    ("263", "ZW"),
    ("264", "NA"),
    ("265", "MW"),
    ("266", "LS"),
    ("267", "BW"),
    ("268", "SZ"),
    ("269", "KM"),
    ("27", "ZA"),
    ("290", "SH"),
    ("291", "ER"),
    ("297", "AW"),
    ("298", "FO"),
    ("299", "GL"),
    ("30", "GR"),
    ("31", "NL"),
    ("32", "BE"),
    ("33", "FR"),
    ("34", "ES"),
    ("350", "GI"),
    ("351", "PT"),
    ("352", "LU"),
    ("353", "IE"),
    ("354", "IS"),
    ("355", "AL"),
    ("356", "MT"),
    ("357", "CY"),
    ("358", "FI"),
    ("359", "BG"),
    ("36", "HU"),
    ("370", "LT"),
    ("371", "LV"),
    ("372", "EE"),
    ("373", "MD"),
    ("374", "AM"),
    ("375", "BY"),
    ("376", "AD"),
    ("377", "MC"),
    ("378", "SM"),
    ("379", "VA"),
    ("380", "UA"),
    ("381", "RS"),
    ("382", "ME"),
    ("383", "XK"),
    ("385", "HR"),
    ("386", "SI"),
    ("387", "BA"),
    ("389", "MK"),
    ("39", "IT"),
    ("40", "RO"),
    ("41", "CH"),
    ("420", "CZ"),
    ("421", "SK"),
    ("423", "LI"),
    ("43", "AT"),
    ("44", "GB"),
    ("45", "DK"),
    ("46", "SE"),
    ("47", "NO"),
    ("48", "PL"),
    ("49", "DE"),
    ("500", "FK"),
    ("501", "BZ"),
    ("502", "GT"),
    ("503", "SV"),
    ("504", "HN"),
    ("505", "NI"),
    ("506", "CR"),
    ("507", "PA"),
    ("508", "PM"),
    ("509", "HT"),
    ("51", "PE"),
    ("52", "MX"),
    ("53", "CU"),
    ("54", "AR"),
    ("55", "BR"),
    ("56", "CL"),
    ("57", "CO"),
    ("58", "VE"),
    ("590", "GP"),
    ("591", "BO"),
    ("592", "GY"),
    ("593", "EC"),
    ("594", "GF"),
    ("595", "PY"),
    ("596", "MQ"),
    ("597", "SR"),
    ("598", "UY"),
    ("599", "CW"),
    ("60", "MY"),
    ("61", "AU"),
    ("62", "ID"),
    ("63", "PH"),
    ("64", "NZ"),
    ("65", "SG"),
    ("66", "TH"),
    ("670", "TL"),
    ("672", "NF"),
    ("673", "BN"),
    ("674", "NR"),
    ("675", "PG"),
    ("676", "TO"),
    ("677", "SB"),
    ("678", "VU"),
    ("679", "FJ"),
    ("680", "PW"),
    ("681", "WF"),
    ("682", "CK"),
    ("683", "NU"),
    ("685", "WS"),
    ("686", "KI"),
    ("687", "NC"),
    ("688", "TV"),
    ("689", "PF"),
    ("690", "TK"),
    ("691", "FM"),
    ("692", "MH"),
    ("7", "RU"),
    ("800", "INTL-FREEPHONE"),
    ("808", "INTL-SHARED"),
    ("81", "JP"),
    ("82", "KR"),
    ("84", "VN"),
    ("850", "KP"),
    ("852", "HK"),
    ("853", "MO"),
    ("855", "KH"),
    ("856", "LA"),
    ("86", "CN"),
    ("870", "SAT-INMARSAT"),
    ("878", "NET-UPT"),
    ("880", "BD"),
    ("881", "SAT-GMSS"),
    ("882", "NET-INTL"),
    ("883", "NET-INTL"),
    ("886", "TW"),
    ("888", "INTL-DISASTER"),
    ("90", "TR"),
    ("91", "IN"),
    ("92", "PK"),
    ("93", "AF"),
    ("94", "LK"),
    ("95", "MM"),
    ("960", "MV"),
    ("961", "LB"),
    ("962", "JO"),
    ("963", "SY"),
    ("964", "IQ"),
    ("965", "KW"),
    ("966", "SA"),
    ("967", "YE"),
    ("968", "OM"),
    ("970", "PS"),
    ("971", "AE"),
    ("972", "IL"),
    ("973", "BH"),
    ("974", "QA"),
    ("975", "BT"),
    ("976", "MN"),
    ("977", "NP"),
    ("979", "INTL-PREMIUM"),
    ("98", "IR"),
    ("992", "TJ"),
    ("993", "TM"),
    ("994", "AZ"),
    ("995", "GE"),
    ("996", "KG"),
    ("998", "UZ"),
];

#[cfg(test)]
mod tests {
    use super::*;

    fn digits(s: &str) -> InternationalDigits {
        InternationalDigits(s.to_string())
    }

    // ── dial plan ────────────────────────────────────────────────────────────

    #[test]
    fn each_common_prefix_is_stripped_to_the_same_digits() {
        let plan = DialPlan::common();
        for dialed in ["+442079460000", "00442079460000", "011442079460000"] {
            assert_eq!(
                plan.to_international(dialed),
                Some(digits("442079460000")),
                "{dialed}"
            );
        }
    }

    #[test]
    fn the_longest_prefix_wins_so_a_trunk_zero_and_double_zero_coexist() {
        let plan = DialPlan::new(["0", "00"]);
        assert_eq!(
            plan.to_international("00212612345678"),
            Some(digits("212612345678"))
        );
        // `0` alone is the national trunk: what follows is a domestic number, and the
        // digits that remain are still handed back — the plan does not judge them.
        assert_eq!(
            plan.to_international("0212612345"),
            Some(digits("212612345"))
        );
    }

    #[test]
    fn visual_separators_are_ignored_but_a_plus_is_a_prefix() {
        let plan = DialPlan::common();
        assert_eq!(
            plan.to_international("+1 (809) 555-0100"),
            Some(digits("18095550100"))
        );
    }

    #[test]
    fn a_non_digit_surviving_the_prefix_is_not_a_number() {
        assert_eq!(DialPlan::common().to_international("+1809555abc"), None);
    }

    #[test]
    fn the_length_gate_rejects_too_short_and_too_long() {
        let plan = DialPlan::common();
        assert_eq!(plan.to_international("+123456"), None, "6 digits");
        assert_eq!(
            plan.to_international("+1234567890123456"),
            None,
            "16 digits"
        );
        assert!(plan.to_international("+1234567").is_some(), "7 digits");
        assert!(
            plan.to_international("+123456789012345").is_some(),
            "15 digits"
        );
    }

    #[test]
    fn no_prefix_means_out_of_scope_unless_the_plan_declares_bare_e164() {
        assert_eq!(DialPlan::common().to_international("2125551234"), None);
        assert_eq!(
            DialPlan::common()
                .with_bare_e164()
                .to_international("2125551234"),
            Some(digits("2125551234"))
        );
    }

    #[test]
    fn looks_international_is_the_cheap_gate() {
        let plan = DialPlan::common();
        assert!(plan.looks_international("+44"));
        assert!(!plan.looks_international("2125551234"));
        assert!(
            DialPlan::common()
                .with_bare_e164()
                .looks_international("2125551234")
        );
    }

    // ── country ──────────────────────────────────────────────────────────────

    #[test]
    fn the_nanp_split_resolves_by_longest_code_not_by_country_code_one() {
        assert_eq!(resolve(&digits("18095550100")).map(|c| c.iso), Some("DO"));
        assert_eq!(resolve(&digits("12845550100")).map(|c| c.iso), Some("VG"));
        assert_eq!(resolve(&digits("12465550100")).map(|c| c.iso), Some("BB"));
        let us = resolve(&digits("12125550100")).expect("+1 212 resolves");
        assert_eq!(
            us.calling_code, "1",
            "a plain NANP number matches the bare code"
        );
    }

    #[test]
    fn ordinary_codes_resolve() {
        assert_eq!(resolve(&digits("442079460000")).map(|c| c.iso), Some("GB"));
        assert_eq!(resolve(&digits("212612345678")).map(|c| c.iso), Some("MA"));
    }

    #[test]
    fn a_code_not_in_the_table_is_none() {
        assert_eq!(resolve(&digits("9990000000")), None);
    }

    #[test]
    fn satellite_ranges_are_non_geographic_and_countries_are_not() {
        let sat = resolve(&digits("8816000000")).expect("881 is in the table");
        assert!(is_non_geographic(&sat), "{}", sat.iso);
        let gb = resolve(&digits("442079460000")).expect("GB");
        assert!(!is_non_geographic(&gb));
    }

    // ── end to end ───────────────────────────────────────────────────────────

    #[test]
    fn destination_of_strips_then_resolves() {
        assert_eq!(
            destination_of("00 44 20 7946 0000", &DialPlan::common()).map(|c| c.iso),
            Some("GB")
        );
        assert_eq!(
            destination_of("2125551234", &DialPlan::common()),
            None,
            "domestic: out of scope"
        );
    }

    /// POSITIVE CONTROL on the ported table: it is non-trivial and holds the NANP splits
    /// the reference documents, so a botched port cannot pass the tests above by luck.
    #[test]
    fn the_table_was_ported_whole() {
        assert!(CODES.len() > 200, "{} rows", CODES.len());
        for code in ["1", "1809", "1284", "1246", "44", "212", "881"] {
            assert!(CODES.iter().any(|(c, _)| *c == code), "missing {code}");
        }
    }
}
