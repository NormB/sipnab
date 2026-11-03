// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The call flow's one-line correlation summary: how many other legs sipnab
//! ties to the call, by how they were joined, and the topology-hiding status
//! of a callee-side OpenSIPS leg.
//!
//! The status bar shows it under the ladder, in the single-dialog view and in
//! the extended view (F4), so an operator sees whether the legs the extended
//! view merges were joined exactly or guessed.

use crate::sip::dialog_store::{CorrelationMethod, DialogStore};

/// The methods in the order the summary lists them: exact joins first, the
/// guess last.
const METHOD_ORDER: [CorrelationMethod; 4] = [
    CorrelationMethod::Decoded,
    CorrelationMethod::Header,
    CorrelationMethod::Sdp,
    CorrelationMethod::Timing,
];

/// The summary for `call_id`, for example `Legs: 1 decoded, 2 timing |
/// Topology hiding: decoded`. Empty when no leg is tied to the call and the
/// call is not a hidden leg, and when `call_id` is not in `store`.
#[must_use]
pub fn summary(store: &DialogStore, call_id: &str) -> String {
    if store.get(call_id).is_none() {
        return String::new();
    }
    let methods: Vec<CorrelationMethod> = store
        .find_correlated_scored(call_id)
        .iter()
        .map(|r| r.reason.method())
        .collect();
    let mut parts = Vec::with_capacity(2);
    let legs = render_counts(&methods);
    if !legs.is_empty() {
        parts.push(legs);
    }
    if let Some(status) = store.th_callid_status(call_id) {
        parts.push(format!("Topology hiding: {status}"));
    }
    parts.join(" | ")
}

/// `Legs: N method, ...` for the methods of the legs found, in
/// [`METHOD_ORDER`], or empty when there are none.
fn render_counts(methods: &[CorrelationMethod]) -> String {
    let counts: Vec<String> = METHOD_ORDER
        .iter()
        .filter_map(|m| {
            let n = methods.iter().filter(|x| *x == m).count();
            (n > 0).then(|| format!("{n} {m}"))
        })
        .collect();
    if counts.is_empty() {
        return String::new();
    }
    format!("Legs: {}", counts.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestError = Box<dyn std::error::Error>;

    /// A hidden call joined by decoding: the legs count names the method,
    /// and the hidden leg carries its status; the caller leg, which is not
    /// hidden, carries none.
    #[cfg(feature = "tls")]
    #[test]
    fn a_decoded_join_is_named_with_its_method_and_status() -> Result<(), TestError> {
        let (ds, caller, hidden) = crate::test_utils::th_hidden_call_store("right", Some("right"))?;
        assert_eq!(
            summary(&ds, &hidden),
            "Legs: 1 decoded | Topology hiding: decoded",
            "the hidden leg names its decoded leg and its status"
        );
        assert_eq!(
            summary(&ds, &caller),
            "Legs: 1 decoded",
            "the caller leg is not hidden, so it carries no status"
        );
        Ok(())
    }

    /// A wrong secret joins nothing by decoding: the leg the timing guess
    /// found is named as a guess, and the status names the failure.
    #[cfg(feature = "tls")]
    #[test]
    fn a_wrong_secret_shows_the_guess_and_the_failure() -> Result<(), TestError> {
        let (ds, _, hidden) = crate::test_utils::th_hidden_call_store("right", Some("wrong"))?;
        assert_eq!(
            summary(&ds, &hidden),
            "Legs: 1 timing | Topology hiding: undecodable",
            "a wrong secret leaves only the timing guess, and says why"
        );
        let (ds, _, hidden) = crate::test_utils::th_hidden_call_store("right", None)?;
        assert_eq!(
            summary(&ds, &hidden),
            "Legs: 1 timing | Topology hiding: no_secret",
            "no secret leaves only the timing guess, and says so"
        );
        Ok(())
    }

    /// Several methods are counted apart, exact joins first; a call with no
    /// leg and no hidden Call-ID, and an unknown call, give nothing.
    #[test]
    fn methods_are_counted_apart_and_nothing_gives_empty() -> Result<(), TestError> {
        use crate::sip::dialog_store::CorrelationMethod as M;
        assert_eq!(
            render_counts(&[M::Timing, M::Header, M::Timing, M::Sdp]),
            "Legs: 1 header, 1 sdp, 2 timing",
            "methods are counted apart, exact joins first"
        );
        assert_eq!(render_counts(&[]), "", "no legs is no text");
        let ds = DialogStore::new(10, false);
        assert_eq!(
            summary(&ds, "absent@example.com"),
            "",
            "a call the store does not hold has no summary"
        );
        Ok(())
    }
}
