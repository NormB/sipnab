// SPDX-License-Identifier: MIT OR Apache-2.0

//! The TUI's archive password popup, and the handshake that lets a load
//! running on its own thread ask for a password and wait for the answer.
//!
//! # The handshake
//!
//! A capture load runs on the `pcap-load` thread. When it meets an encrypted
//! member that no configured or remembered password opens, the keyring that
//! load's thread uses (the session's, borrowed for the load) asks its
//! prompter, which here is a [`PopupPrompter`]. That sends a
//! [`PasswordAsk`] to the UI thread and parks on the reply. The event loop
//! sees the ask on its next tick, opens [`crate::tui::state::Popup::ArchivePassword`],
//! and the operator's Enter or Esc sends the reply that resumes the load. It
//! is the `UnsavedNotes` pattern, a load waiting on an answer, across a
//! thread.
//!
//! A reply is always sent: [`PasswordEntry`] answers "skip" when it drops
//! unanswered, and a prompter whose UI is gone answers "skip" itself, so no
//! load can park forever.
//!
//! # What the popup shows
//!
//! Masked by default (CWE-549), one dot per character so a missed keystroke
//! shows. Ctrl-R reveals what was typed until the next attempt: every ask
//! opens masked, so a wrong password re-masks. The password is held in a
//! [`zeroize::Zeroizing`] buffer sized before the first keystroke, and
//! nothing in this module writes it anywhere but into the reply.

use std::sync::mpsc;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use zeroize::Zeroizing;

use crate::capture::archive::password::{
    ArchivePassword, MAX_PASSWORD_BYTES, PromptAnswer, PromptRequest, Prompter,
};

/// One question from a load thread, and where its answer goes.
#[derive(Debug)]
pub(crate) struct PasswordAsk {
    /// What the load needs a password for.
    pub(crate) request: PromptRequest,
    /// The parked load, waiting on this.
    pub(crate) reply: mpsc::SyncSender<PromptAnswer>,
}

/// The prompter a TUI load uses: it asks the UI thread and waits.
#[derive(Debug)]
pub(crate) struct PopupPrompter {
    /// Where questions go.
    tx: mpsc::Sender<PasswordAsk>,
}

impl PopupPrompter {
    /// A prompter, and the receiver the UI thread polls for its questions.
    pub(crate) fn channel() -> (Self, mpsc::Receiver<PasswordAsk>) {
        let (tx, rx) = mpsc::channel();
        (Self { tx }, rx)
    }
}

impl Prompter for PopupPrompter {
    fn ask(&mut self, request: &PromptRequest) -> PromptAnswer {
        let (reply, answer) = mpsc::sync_channel(1);
        if self
            .tx
            .send(PasswordAsk {
                request: request.clone(),
                reply,
            })
            .is_err()
        {
            return PromptAnswer::Skip;
        }
        answer.recv().unwrap_or(PromptAnswer::Skip)
    }
}

/// The popup's state: the question, what has been typed, and whether it is
/// shown.
#[derive(Debug)]
pub(crate) struct PasswordEntry {
    /// The question.
    request: PromptRequest,
    /// What has been typed, never grown past its first allocation.
    typed: Zeroizing<Vec<u8>>,
    /// Whether more was typed than a password may hold.
    too_long: bool,
    /// Whether Ctrl-R has revealed the entry.
    revealed: bool,
    /// Where the answer goes; `None` once sent.
    reply: Option<mpsc::SyncSender<PromptAnswer>>,
}

impl PasswordEntry {
    /// A masked, empty entry for `ask`.
    pub(crate) fn new(ask: PasswordAsk) -> Self {
        Self {
            request: ask.request,
            typed: Zeroizing::new(Vec::with_capacity(MAX_PASSWORD_BYTES)),
            too_long: false,
            revealed: false,
            reply: Some(ask.reply),
        }
    }

    /// The question being asked.
    pub(crate) fn request(&self) -> &PromptRequest {
        &self.request
    }

    /// Whether the entry is revealed.
    #[cfg(test)]
    pub(crate) fn revealed(&self) -> bool {
        self.revealed
    }

    /// The popup title, which says when the password is visible.
    pub(crate) fn title(&self) -> &'static str {
        if self.revealed {
            " Archive password (password visible) "
        } else {
            " Archive password "
        }
    }

    /// The entry field as drawn: one dot per character, or the text itself
    /// while revealed.
    pub(crate) fn field(&self) -> String {
        let text = String::from_utf8_lossy(&self.typed);
        if self.revealed {
            text.into_owned()
        } else {
            "\u{2022}".repeat(text.chars().count())
        }
    }

    /// Append `bytes`, up to the buffer's first allocation.
    fn append(&mut self, bytes: &[u8]) {
        for b in bytes {
            if self.typed.len() < self.typed.capacity() {
                self.typed.push(*b);
            } else {
                self.too_long = true;
            }
        }
    }

    /// A paste: the whole text as one entry, never read as keystrokes.
    pub(crate) fn paste(&mut self, text: &str) {
        let line = text.split(['\r', '\n']).next().unwrap_or("");
        self.append(line.as_bytes());
    }

    /// Send `answer` to the parked load.
    fn send(&mut self, answer: PromptAnswer) {
        if let Some(reply) = self.reply.take() {
            let _ = reply.send(answer);
        }
    }

    /// One key. Returns `true` when the popup is done: the answer is sent.
    pub(crate) fn key(&mut self, key: KeyEvent) -> bool {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Enter => {
                let answer = if self.typed.is_empty() || self.too_long {
                    PromptAnswer::Skip
                } else {
                    match ArchivePassword::from_bytes(&self.typed) {
                        Ok(pw) => PromptAnswer::Password(pw),
                        Err(_) => PromptAnswer::Skip,
                    }
                };
                self.typed.clear();
                self.send(answer);
                true
            }
            KeyCode::Esc => {
                self.typed.clear();
                self.send(PromptAnswer::Skip);
                true
            }
            KeyCode::Char('r' | 'R') if ctrl => {
                self.revealed = !self.revealed;
                false
            }
            KeyCode::Char('u' | 'U') if ctrl => {
                self.typed.clear();
                self.too_long = false;
                false
            }
            KeyCode::Backspace => {
                // A whole character, not its last byte.
                let keep = String::from_utf8_lossy(&self.typed)
                    .char_indices()
                    .last()
                    .map_or(0, |(i, _)| i);
                self.typed.truncate(keep);
                false
            }
            KeyCode::Char(c) if !ctrl => {
                // Cleared on drop: it held a character of the password.
                let mut buf = Zeroizing::new([0u8; 4]);
                let n = c.encode_utf8(&mut *buf).len();
                self.append(&buf[..n]);
                false
            }
            _ => false,
        }
    }
}

impl Drop for PasswordEntry {
    fn drop(&mut self) {
        // An entry closed any other way still releases the load.
        self.send(PromptAnswer::Skip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ask() -> (PasswordEntry, mpsc::Receiver<PromptAnswer>) {
        let (reply, answer) = mpsc::sync_channel(1);
        let entry = PasswordEntry::new(PasswordAsk {
            request: PromptRequest {
                archive: "evidence.zip".into(),
                member: "voip/call3.pcap".into(),
                attempt: 1,
                of: 3,
                after_wrong: false,
            },
            reply,
        });
        (entry, answer)
    }

    fn press(entry: &mut PasswordEntry, code: KeyCode) -> bool {
        entry.key(KeyEvent::new(code, KeyModifiers::NONE))
    }

    fn ctrl(entry: &mut PasswordEntry, c: char) -> bool {
        entry.key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL))
    }

    fn type_str(entry: &mut PasswordEntry, s: &str) {
        for c in s.chars() {
            assert!(!press(entry, KeyCode::Char(c)));
        }
    }

    fn secret() -> &'static str {
        crate::test_material::key_str("tui-popup")
    }

    #[test]
    fn the_field_is_masked_one_dot_per_character() {
        let (mut e, _rx) = ask();
        type_str(&mut e, "\u{00fc}b");
        assert_eq!(e.field(), "\u{2022}\u{2022}");
        assert!(!e.revealed());
        assert_eq!(e.title(), " Archive password ");
    }

    #[test]
    fn ctrl_r_reveals_and_says_so_then_hides_again() {
        let (mut e, _rx) = ask();
        type_str(&mut e, &secret()[..8]);
        assert!(!ctrl(&mut e, 'r'));
        assert_eq!(e.field(), &secret()[..8]);
        assert!(e.title().contains("password visible"));
        assert!(!ctrl(&mut e, 'r'));
        assert_eq!(e.field(), "\u{2022}".repeat(8));
    }

    #[test]
    fn enter_sends_the_password_and_esc_skips() {
        let (mut e, rx) = ask();
        type_str(&mut e, secret());
        assert!(press(&mut e, KeyCode::Enter));
        match rx.try_recv().expect("answered") {
            PromptAnswer::Password(pw) => assert_eq!(pw.expose(), secret().as_bytes()),
            PromptAnswer::Skip => panic!("Enter with a password must send it"),
        }
        let (mut e, rx) = ask();
        type_str(&mut e, "abc");
        assert!(press(&mut e, KeyCode::Esc));
        assert!(matches!(rx.try_recv(), Ok(PromptAnswer::Skip)));
    }

    #[test]
    fn an_empty_enter_skips_and_ctrl_u_clears() {
        let (mut e, rx) = ask();
        type_str(&mut e, "abc");
        assert!(!ctrl(&mut e, 'u'));
        assert_eq!(e.field(), "");
        assert!(press(&mut e, KeyCode::Enter));
        assert!(matches!(rx.try_recv(), Ok(PromptAnswer::Skip)));
    }

    #[test]
    fn a_paste_arrives_as_one_entry_not_as_keys() {
        let (mut e, rx) = ask();
        // Letters that are keys elsewhere, and a trailing newline a password
        // manager adds: all text, up to the line end.
        e.paste("q/xR\n");
        assert_eq!(e.field(), "\u{2022}".repeat(4));
        assert!(press(&mut e, KeyCode::Enter));
        match rx.try_recv().expect("answered") {
            PromptAnswer::Password(pw) => assert_eq!(pw.expose(), b"q/xR"),
            PromptAnswer::Skip => panic!("the paste is the password"),
        }
    }

    #[test]
    fn backspace_removes_a_whole_character() {
        let (mut e, _rx) = ask();
        type_str(&mut e, "a\u{00fc}");
        press(&mut e, KeyCode::Backspace);
        ctrl(&mut e, 'r');
        assert_eq!(e.field(), "a");
    }

    #[test]
    fn an_entry_dropped_unanswered_releases_the_load() {
        let (e, rx) = ask();
        drop(e);
        assert!(matches!(rx.try_recv(), Ok(PromptAnswer::Skip)));
    }

    #[test]
    fn the_prompter_parks_until_the_ui_answers() {
        let (mut prompter, asks) = PopupPrompter::channel();
        let asker = std::thread::spawn(move || {
            let req = PromptRequest {
                archive: "a.zip".into(),
                member: "m".into(),
                attempt: 1,
                of: 3,
                after_wrong: false,
            };
            matches!(prompter.ask(&req), PromptAnswer::Skip)
        });
        let ask = asks
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the load asked");
        let mut entry = PasswordEntry::new(ask);
        assert!(entry.key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)));
        assert!(asker.join().expect("asker"), "the load resumed with a skip");
    }
}
