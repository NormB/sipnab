// SPDX-License-Identifier: MIT OR Apache-2.0

//! The offer to install the G.729 codebook tables, made where the need
//! appears: the first time the terminal UI holds a G.729 stream and this host
//! has no tables.
//!
//! One keypress answers it. Yes downloads the ITU-T package from itu.int and
//! installs the tables as `sipnab g729 install --yes` would; no leaves the
//! stream undecoded, with the command named on the status line. With
//! `[g729] auto_install = true` the download starts without asking. The offer
//! is made once per session, so a refusal is not asked again. The command
//! line, REST, MCP and vCon export never download (docs/g729.md).

use crate::tui::{App, KeyCode, KeyEvent, Popup};

/// The question, word for word.
pub(in crate::tui) const QUESTION: &str =
    "This call uses G.729. Download the decoder tables from itu.int now? [y/N]";

/// How often the stream store is looked through for a G.729 stream while no
/// offer has been made: the look walks every stream.
const CHECK_EVERY: std::time::Duration = std::time::Duration::from_secs(1);

/// Where the offer stands this session.
#[derive(Debug, Default)]
pub(crate) struct G729Offer {
    /// The offer was made, or the download started without one. Never again
    /// this session.
    made: bool,
    /// The operator said yes, or `auto_install` did: the download runs after
    /// the next frame, which shows that it is running.
    pub(in crate::tui) pending_install: bool,
    /// When the stream store was last looked through.
    last_check: Option<std::time::Instant>,
}

/// What to do about G.729 on this tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::tui) enum Next {
    /// Nothing.
    Nothing,
    /// Ask the question.
    Ask,
    /// Download without asking (`[g729] auto_install = true`).
    Download,
}

/// The decision, from its inputs alone.
///
/// # Arguments
/// * `built` - this binary has the `g729` feature.
/// * `made` - the offer was already made this session.
/// * `available` - the tables load.
/// * `has_g729` - the stream store holds a G.729 stream.
/// * `auto` - `[g729] auto_install = true`.
#[must_use]
pub(in crate::tui) fn decide(
    built: bool,
    made: bool,
    available: bool,
    has_g729: bool,
    auto: bool,
) -> Next {
    if !built || made || available || !has_g729 {
        Next::Nothing
    } else if auto {
        Next::Download
    } else {
        Next::Ask
    }
}

/// Make the offer when it is due. Called once per tick.
///
/// # Side effects
/// Opens [`Popup::G729Install`], or queues the download and says so on the
/// status line. Takes a read lock on the stream store at most once a second
/// until the offer is made.
pub(in crate::tui) fn offer_if_due(app: &mut App) {
    if !cfg!(feature = "g729") || app.g729_offer.made || app.active_popup.is_some() {
        return;
    }
    let now = std::time::Instant::now();
    if app
        .g729_offer
        .last_check
        .is_some_and(|last| now.duration_since(last) < CHECK_EVERY)
    {
        return;
    }
    app.g729_offer.last_check = Some(now);
    let has_g729 = app
        .stream_store
        .read()
        .iter()
        .any(|s| needs_the_tables(s.codec.as_deref()));
    let next = decide(
        true,
        false,
        has_g729 && crate::rtp::g729_tables::available(),
        has_g729,
        crate::rtp::g729_tables::auto_install_allowed(),
    );
    apply(app, next);
}

/// Whether a stream of `codec` needs the G.729 tables to decode.
fn needs_the_tables(codec: Option<&str>) -> bool {
    codec.is_some_and(|c| crate::rtp::g729_family::g729_variant(c).is_some())
}

/// Act on a decision.
pub(in crate::tui) fn apply(app: &mut App, next: Next) {
    match next {
        Next::Nothing => {}
        Next::Ask => {
            app.g729_offer.made = true;
            app.active_popup = Some(Popup::G729Install);
        }
        Next::Download => {
            app.g729_offer.made = true;
            app.g729_offer.pending_install = true;
            app.status_error = Some(downloading());
        }
    }
}

/// The status line while the download runs.
fn downloading() -> String {
    "Downloading the G.729 decoder tables from itu.int...".to_string()
}

/// Handle keys while the question is open: `y`/`Y`/Enter downloads; `n`,
/// `N`, `q` and Esc decline. Every other key is ignored.
///
/// # Side effects
/// Closes the popup on an answer; a yes queues the download, a no puts the
/// command on the status line.
pub(in crate::tui) fn handle_g729_install_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Char('y' | 'Y') | KeyCode::Enter => {
            app.active_popup = None;
            app.g729_offer.pending_install = true;
            app.status_error = Some(downloading());
        }
        KeyCode::Char('n' | 'N' | 'q') | KeyCode::Esc => {
            app.active_popup = None;
            app.status_error = Some(crate::rtp::g729_tables::NOT_INSTALLED.to_string());
        }
        _ => {}
    }
}

/// Run the download the operator asked for, after the frame that says it is
/// running. Blocks the terminal UI for the download (18 MB).
///
/// # Side effects
/// Downloads from itu.int, writes the table file where this run reads it,
/// and puts the outcome on the status line.
pub(crate) fn run_pending_install(app: &mut App) {
    if !std::mem::take(&mut app.g729_offer.pending_install) {
        return;
    }
    #[cfg(feature = "g729")]
    {
        let location = crate::rtp::g729_tables::configured_location().unwrap_or_default();
        match crate::app::g729_install::install_download(
            &location,
            &crate::app::g729_install::download,
        ) {
            Ok(done) => app.status_error = Some(done.replace('\n', "; ")),
            Err(e) => app.set_status_error(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyModifiers;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    /// The offer is made only by a `g729` build, once, when a G.729 stream
    /// is present and the tables are not; `auto_install` downloads instead
    /// of asking.
    /// G.729 and G.729.1 streams need the tables; no other codec does.
    #[test]
    fn g729_and_g7291_streams_need_the_tables() {
        for codec in ["G729", "g729", "G7291", "g7291"] {
            assert!(needs_the_tables(Some(codec)), "{codec}");
        }
        for codec in [None, Some("PCMU"), Some("G722"), Some("opus")] {
            assert!(!needs_the_tables(codec), "{codec:?}");
        }
    }

    #[test]
    fn the_offer_is_made_once_where_the_need_appears() {
        assert_eq!(decide(true, false, false, true, false), Next::Ask);
        assert_eq!(decide(true, false, false, true, true), Next::Download);
        assert_eq!(
            decide(false, false, false, true, false),
            Next::Nothing,
            "no feature"
        );
        assert_eq!(
            decide(true, true, false, true, false),
            Next::Nothing,
            "already made"
        );
        assert_eq!(
            decide(true, false, true, true, false),
            Next::Nothing,
            "installed"
        );
        assert_eq!(
            decide(true, false, false, false, false),
            Next::Nothing,
            "no G.729"
        );
    }

    /// Asking opens the question; a download queues without one. Either way
    /// it is never made again.
    #[test]
    fn applying_the_decision() {
        let mut app = App::new_test();
        apply(&mut app, Next::Ask);
        assert_eq!(app.active_popup, Some(Popup::G729Install));
        assert!(app.g729_offer.made && !app.g729_offer.pending_install);

        let mut app = App::new_test();
        apply(&mut app, Next::Download);
        assert_eq!(app.active_popup, None);
        assert!(app.g729_offer.made && app.g729_offer.pending_install);
        assert!(
            app.status_error
                .as_deref()
                .is_some_and(|s| s.contains("itu.int"))
        );
    }

    /// Yes queues the download; no closes the question and names the command.
    #[test]
    fn one_key_answers() {
        for yes in [KeyCode::Char('y'), KeyCode::Char('Y'), KeyCode::Enter] {
            let mut app = App::new_test();
            app.active_popup = Some(Popup::G729Install);
            crate::tui::controllers::handle_popup_key(&mut app, key(yes));
            assert_eq!(app.active_popup, None);
            assert!(app.g729_offer.pending_install, "{yes:?}");
        }
        for no in [KeyCode::Char('n'), KeyCode::Esc, KeyCode::Char('q')] {
            let mut app = App::new_test();
            app.active_popup = Some(Popup::G729Install);
            crate::tui::controllers::handle_popup_key(&mut app, key(no));
            assert_eq!(app.active_popup, None);
            assert!(!app.g729_offer.pending_install, "{no:?}");
            assert_eq!(
                app.status_error.as_deref(),
                Some(crate::rtp::g729_tables::NOT_INSTALLED)
            );
        }
        let mut app = App::new_test();
        app.active_popup = Some(Popup::G729Install);
        crate::tui::controllers::handle_popup_key(&mut app, key(KeyCode::Char('x')));
        assert_eq!(
            app.active_popup,
            Some(Popup::G729Install),
            "a stray key is ignored"
        );
    }

    /// With nothing queued, running the install does nothing.
    #[test]
    fn nothing_queued_nothing_downloaded() {
        let mut app = App::new_test();
        run_pending_install(&mut app);
        assert_eq!(app.status_error, None);
    }
}
