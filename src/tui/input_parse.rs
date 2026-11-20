// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors
// SPDX-FileCopyrightText: 2019 Timon and the crossterm contributors
//
// Adapted from crossterm 0.29.0, `src/event/sys/unix/parse.rs` and the
// `Parser` of `src/event/source/unix/mio.rs`, git commit
// 36d95b26a26e64b0f8c12edfe11f410a6d56a812
// (https://github.com/crossterm-rs/crossterm). The parts that come from
// crossterm are under crossterm's MIT License, whose notice follows and stays
// with them; sipnab offers the file as a whole under its own license.
//
// MIT License
//
// Copyright (c) 2019 Timon
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

//! Terminal input bytes to crossterm events, for the TUI's own terminal read.
//!
//! crossterm 0.29's Unix event source reads the terminal in a loop that a read
//! of 0 or an `EIO` never leaves, so a terminal that hangs up while crossterm
//! reads it spins the process at full CPU
//! (TUI-SPINS-IN-CROSSTERM-READ-AFTER-TERMINAL-LOSS). The TUI therefore reads
//! the terminal itself (`terminal_input::take_input`) and hands the bytes to
//! this parser, which is crossterm's own, so the events are the ones crossterm
//! produced. crossterm's parser is not public, hence the copy.
//!
//! What differs from crossterm's code:
//!
//! * The replies a terminal sends only when asked (cursor position, keyboard
//!   enhancement flags, primary device attributes) are recognized and
//!   dropped, as crossterm's `event::read` drops them, instead of being kept.
//! * Whether raw mode is on is a field of the [`Parser`], not a read of
//!   crossterm's global, so the parser is pure.
//! * A mouse or cursor coordinate of 0 (the terminal counts from 1) is a
//!   sequence that does not parse, where crossterm subtracts 1 from it, which
//!   wraps in a release build and panics in a debug build.
//! * The `assert!`s on each function's prefix are gone: the dispatch in
//!   [`parse_csi`] is what guarantees it.
//!
//! The rules of every function, as in crossterm: `Ok(None)` waits for more
//! bytes; `Err(_)` is a sequence that cannot be parsed, and the parser drops
//! the bytes it holds; `Ok(Some(_))` is a complete event.

use std::collections::VecDeque;
use std::io;

use crossterm::event::{
    Event, KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers, MediaKeyCode,
    ModifierKeyCode, MouseButton, MouseEvent, MouseEventKind,
};

/// What a complete sequence parsed to.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Parsed {
    /// An input event.
    Event(Event),
    /// A reply the terminal sends only when asked; the TUI asks for none.
    Reply,
}

/// The result of one parse: see the module's rules.
type ParseResult = io::Result<Option<Parsed>>;

/// The error of a sequence that cannot be parsed.
fn could_not_parse_event_error() -> io::Error {
    io::Error::other("Could not parse an event.")
}

/// A key event as a complete parse.
fn key(event: impl Into<KeyEvent>) -> ParseResult {
    Ok(Some(Parsed::Event(Event::Key(event.into()))))
}

/// Parse the bytes of one sequence. `input_available` says that more bytes
/// follow in the same read, which makes a lone ESC the start of a sequence
/// rather than the Esc key; `raw_mode` says whether the terminal is in raw
/// mode, where a line feed is Ctrl+J rather than Enter.
fn parse_event(buffer: &[u8], input_available: bool, raw_mode: bool) -> ParseResult {
    let Some(&first) = buffer.first() else {
        return Ok(None);
    };
    match first {
        b'\x1B' => parse_escape(buffer, input_available, raw_mode),
        b'\r' => key(KeyCode::Enter),
        // crossterm issue #371: in raw mode the terminal no longer turns a
        // carriage return into a line feed, so a line feed is Ctrl+J.
        b'\n' if !raw_mode => key(KeyCode::Enter),
        b'\t' => key(KeyCode::Tab),
        b'\x7F' => key(KeyCode::Backspace),
        c @ b'\x01'..=b'\x1A' => key(KeyEvent::new(
            KeyCode::Char(char::from(c - 0x1 + b'a')),
            KeyModifiers::CONTROL,
        )),
        c @ b'\x1C'..=b'\x1F' => key(KeyEvent::new(
            KeyCode::Char(char::from(c - 0x1C + b'4')),
            KeyModifiers::CONTROL,
        )),
        b'\0' => key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::CONTROL)),
        _ => parse_utf8_char(buffer).map(|maybe_char| {
            maybe_char
                .map(KeyCode::Char)
                .map(char_code_to_event)
                .map(Event::Key)
                .map(Parsed::Event)
        }),
    }
}

/// Parse a sequence that starts with ESC.
fn parse_escape(buffer: &[u8], input_available: bool, raw_mode: bool) -> ParseResult {
    match buffer.get(1) {
        None if input_available => Ok(None),
        None => key(KeyCode::Esc),
        Some(b'O') => parse_ss3(buffer),
        Some(b'[') => parse_csi(buffer, raw_mode),
        Some(b'\x1B') => key(KeyCode::Esc),
        Some(_) => parse_event(&buffer[1..], input_available, raw_mode).map(|parsed| {
            parsed.map(|parsed| match parsed {
                Parsed::Event(Event::Key(mut alt_key_event)) => {
                    alt_key_event.modifiers |= KeyModifiers::ALT;
                    Parsed::Event(Event::Key(alt_key_event))
                }
                other => other,
            })
        }),
    }
}

/// Parse `ESC O x`: arrows, Home, End and F1 to F4 in application mode.
fn parse_ss3(buffer: &[u8]) -> ParseResult {
    match buffer.get(2) {
        None => Ok(None),
        Some(b'D') => key(KeyCode::Left),
        Some(b'C') => key(KeyCode::Right),
        Some(b'A') => key(KeyCode::Up),
        Some(b'B') => key(KeyCode::Down),
        Some(b'H') => key(KeyCode::Home),
        Some(b'F') => key(KeyCode::End),
        Some(&val @ b'P'..=b'S') => key(KeyCode::F(1 + val - b'P')),
        Some(_) => Err(could_not_parse_event_error()),
    }
}

/// A character key, with Shift for an uppercase character.
fn char_code_to_event(code: KeyCode) -> KeyEvent {
    let modifiers = match code {
        KeyCode::Char(c) if c.is_uppercase() => KeyModifiers::SHIFT,
        _ => KeyModifiers::empty(),
    };
    KeyEvent::new(code, modifiers)
}

/// Parse a sequence that starts with `ESC [`.
fn parse_csi(buffer: &[u8], raw_mode: bool) -> ParseResult {
    let Some(&third) = buffer.get(2) else {
        return Ok(None);
    };
    let input_event = match third {
        b'[' => match buffer.get(3) {
            None => None,
            // crossterm: "cannot find when this occurs".
            Some(&val @ b'A'..=b'E') => Some(Event::Key(KeyCode::F(1 + val - b'A').into())),
            Some(_) => return Err(could_not_parse_event_error()),
        },
        b'D' => Some(Event::Key(KeyCode::Left.into())),
        b'C' => Some(Event::Key(KeyCode::Right.into())),
        b'A' => Some(Event::Key(KeyCode::Up.into())),
        b'B' => Some(Event::Key(KeyCode::Down.into())),
        b'H' => Some(Event::Key(KeyCode::Home.into())),
        b'F' => Some(Event::Key(KeyCode::End.into())),
        b'Z' => Some(Event::Key(KeyEvent::new_with_kind(
            KeyCode::BackTab,
            KeyModifiers::SHIFT,
            KeyEventKind::Press,
        ))),
        b'M' => return parse_csi_normal_mouse(buffer),
        b'<' => return parse_csi_sgr_mouse(buffer),
        b'I' => Some(Event::FocusGained),
        b'O' => Some(Event::FocusLost),
        b';' => return parse_csi_modifier_key_code(buffer),
        // P, Q and S for the Kitty keyboard protocol, which leaves out the 1
        // of `CSI 1 P` when no modifier is pressed.
        b'P' => Some(Event::Key(KeyCode::F(1).into())),
        b'Q' => Some(Event::Key(KeyCode::F(2).into())),
        b'S' => Some(Event::Key(KeyCode::F(4).into())),
        b'?' => match buffer.last() {
            Some(b'u') => return parse_csi_keyboard_enhancement_flags(buffer),
            Some(b'c') => return Ok(Some(Parsed::Reply)),
            _ => None,
        },
        b'0'..=b'9' => return parse_csi_numbered(buffer, raw_mode),
        _ => return Err(could_not_parse_event_error()),
    };
    Ok(input_event.map(Parsed::Event))
}

/// Parse `ESC [` followed by a digit: a numbered sequence, complete once
/// its final byte (64 to 126) has arrived.
fn parse_csi_numbered(buffer: &[u8], raw_mode: bool) -> ParseResult {
    if buffer.len() == 3 {
        return Ok(None);
    }
    let last_byte = buffer.last().copied().unwrap_or_default();
    if !(64..=126).contains(&last_byte) {
        return Ok(None);
    }
    if buffer.starts_with(b"\x1B[200~") {
        return parse_csi_bracketed_paste(buffer);
    }
    match last_byte {
        b'M' => parse_csi_rxvt_mouse(buffer),
        b'~' => parse_csi_special_key_code(buffer),
        b'u' => parse_csi_u_encoded_key_code(buffer, raw_mode),
        b'R' => parse_csi_cursor_position(buffer),
        _ => parse_csi_modifier_key_code(buffer),
    }
}

/// The next `;`-separated field, parsed as a `T`.
fn next_parsed<T>(iter: &mut dyn Iterator<Item = &str>) -> io::Result<T>
where
    T: std::str::FromStr,
{
    iter.next()
        .ok_or_else(could_not_parse_event_error)?
        .parse::<T>()
        .map_err(|_| could_not_parse_event_error())
}

/// The next field as a terminal coordinate, which counts from 1, made to
/// count from 0. A coordinate of 0 does not parse.
fn next_coordinate(iter: &mut dyn Iterator<Item = &str>) -> io::Result<u16> {
    next_parsed::<u16>(iter)?
        .checked_sub(1)
        .ok_or_else(could_not_parse_event_error)
}

/// The next field as `modifiers[:kind]`; the kind is 1 (a press) when it is
/// not there.
fn modifier_and_kind_parsed(iter: &mut dyn Iterator<Item = &str>) -> io::Result<(u8, u8)> {
    let mut sub_split = iter
        .next()
        .ok_or_else(could_not_parse_event_error)?
        .split(':');
    let modifier_mask = next_parsed::<u8>(&mut sub_split)?;
    if let Ok(kind_code) = next_parsed::<u8>(&mut sub_split) {
        Ok((modifier_mask, kind_code))
    } else {
        Ok((modifier_mask, 1))
    }
}

/// The text between `ESC [` (`skip` bytes) and the final byte.
fn csi_parameters(buffer: &[u8], skip: usize) -> io::Result<&str> {
    let end = buffer.len().saturating_sub(1).max(skip);
    let bytes = buffer.get(skip..end).unwrap_or_default();
    std::str::from_utf8(bytes).map_err(|_| could_not_parse_event_error())
}

/// Parse `ESC [ row ; column R`, a cursor position reply.
fn parse_csi_cursor_position(buffer: &[u8]) -> ParseResult {
    let mut split = csi_parameters(buffer, 2)?.split(';');
    next_coordinate(&mut split)?;
    next_coordinate(&mut split)?;
    Ok(Some(Parsed::Reply))
}

/// Parse `ESC [ ? flags u`, a keyboard enhancement flags reply.
fn parse_csi_keyboard_enhancement_flags(buffer: &[u8]) -> ParseResult {
    if buffer.len() < 5 {
        return Ok(None);
    }
    Ok(Some(Parsed::Reply))
}

/// The key modifiers of an xterm modifier parameter (1 plus a bit mask).
fn parse_modifiers(mask: u8) -> KeyModifiers {
    let modifier_mask = mask.saturating_sub(1);
    let mut modifiers = KeyModifiers::empty();
    for (bit, modifier) in [
        (1, KeyModifiers::SHIFT),
        (2, KeyModifiers::ALT),
        (4, KeyModifiers::CONTROL),
        (8, KeyModifiers::SUPER),
        (16, KeyModifiers::HYPER),
        (32, KeyModifiers::META),
    ] {
        if modifier_mask & bit != 0 {
            modifiers |= modifier;
        }
    }
    modifiers
}

/// The lock states of an xterm modifier parameter.
fn parse_modifiers_to_state(mask: u8) -> KeyEventState {
    let modifier_mask = mask.saturating_sub(1);
    let mut state = KeyEventState::empty();
    if modifier_mask & 64 != 0 {
        state |= KeyEventState::CAPS_LOCK;
    }
    if modifier_mask & 128 != 0 {
        state |= KeyEventState::NUM_LOCK;
    }
    state
}

/// The kind of a Kitty keyboard protocol event type.
fn parse_key_event_kind(kind: u8) -> KeyEventKind {
    match kind {
        2 => KeyEventKind::Repeat,
        3 => KeyEventKind::Release,
        _ => KeyEventKind::Press,
    }
}

/// Parse `ESC [ 1 ; modifiers x`: an arrow, Home, End or F1 to F4 with
/// modifiers.
fn parse_csi_modifier_key_code(buffer: &[u8]) -> ParseResult {
    let mut split = csi_parameters(buffer, 2)?.split(';');
    split.next();
    let (modifiers, kind) =
        if let Ok((modifier_mask, kind_code)) = modifier_and_kind_parsed(&mut split) {
            (
                parse_modifiers(modifier_mask),
                parse_key_event_kind(kind_code),
            )
        } else if buffer.len() > 3 {
            let digit = buffer
                .get(buffer.len() - 2)
                .and_then(|&b| char::from(b).to_digit(10))
                .ok_or_else(could_not_parse_event_error)?;
            (
                parse_modifiers(u8::try_from(digit).unwrap_or_default()),
                KeyEventKind::Press,
            )
        } else {
            (KeyModifiers::NONE, KeyEventKind::Press)
        };
    let keycode = match buffer.last() {
        Some(b'A') => KeyCode::Up,
        Some(b'B') => KeyCode::Down,
        Some(b'C') => KeyCode::Right,
        Some(b'D') => KeyCode::Left,
        Some(b'F') => KeyCode::End,
        Some(b'H') => KeyCode::Home,
        Some(b'P') => KeyCode::F(1),
        Some(b'Q') => KeyCode::F(2),
        Some(b'R') => KeyCode::F(3),
        Some(b'S') => KeyCode::F(4),
        _ => return Err(could_not_parse_event_error()),
    };
    key(KeyEvent::new_with_kind(keycode, modifiers, kind))
}

/// A keypad key of the Kitty keyboard protocol's private-use code points.
fn translate_keypad_code(codepoint: u32) -> Option<KeyCode> {
    Some(match codepoint {
        57399..=57408 => KeyCode::Char(char::from_digit(codepoint - 57399, 10)?),
        57409 => KeyCode::Char('.'),
        57410 => KeyCode::Char('/'),
        57411 => KeyCode::Char('*'),
        57412 => KeyCode::Char('-'),
        57413 => KeyCode::Char('+'),
        57414 => KeyCode::Enter,
        57415 => KeyCode::Char('='),
        57416 => KeyCode::Char(','),
        57417 => KeyCode::Left,
        57418 => KeyCode::Right,
        57419 => KeyCode::Up,
        57420 => KeyCode::Down,
        57421 => KeyCode::PageUp,
        57422 => KeyCode::PageDown,
        57423 => KeyCode::Home,
        57424 => KeyCode::End,
        57425 => KeyCode::Insert,
        57426 => KeyCode::Delete,
        57427 => KeyCode::KeypadBegin,
        _ => return None,
    })
}

/// A lock, function, media or modifier key of the Kitty keyboard protocol's
/// private-use code points.
fn translate_other_functional_code(codepoint: u32) -> Option<KeyCode> {
    Some(match codepoint {
        57358 => KeyCode::CapsLock,
        57359 => KeyCode::ScrollLock,
        57360 => KeyCode::NumLock,
        57361 => KeyCode::PrintScreen,
        57362 => KeyCode::Pause,
        57363 => KeyCode::Menu,
        57376..=57398 => KeyCode::F(u8::try_from(codepoint - 57376 + 13).ok()?),
        57428 => KeyCode::Media(MediaKeyCode::Play),
        57429 => KeyCode::Media(MediaKeyCode::Pause),
        57430 => KeyCode::Media(MediaKeyCode::PlayPause),
        57431 => KeyCode::Media(MediaKeyCode::Reverse),
        57432 => KeyCode::Media(MediaKeyCode::Stop),
        57433 => KeyCode::Media(MediaKeyCode::FastForward),
        57434 => KeyCode::Media(MediaKeyCode::Rewind),
        57435 => KeyCode::Media(MediaKeyCode::TrackNext),
        57436 => KeyCode::Media(MediaKeyCode::TrackPrevious),
        57437 => KeyCode::Media(MediaKeyCode::Record),
        57438 => KeyCode::Media(MediaKeyCode::LowerVolume),
        57439 => KeyCode::Media(MediaKeyCode::RaiseVolume),
        57440 => KeyCode::Media(MediaKeyCode::MuteVolume),
        57441 => KeyCode::Modifier(ModifierKeyCode::LeftShift),
        57442 => KeyCode::Modifier(ModifierKeyCode::LeftControl),
        57443 => KeyCode::Modifier(ModifierKeyCode::LeftAlt),
        57444 => KeyCode::Modifier(ModifierKeyCode::LeftSuper),
        57445 => KeyCode::Modifier(ModifierKeyCode::LeftHyper),
        57446 => KeyCode::Modifier(ModifierKeyCode::LeftMeta),
        57447 => KeyCode::Modifier(ModifierKeyCode::RightShift),
        57448 => KeyCode::Modifier(ModifierKeyCode::RightControl),
        57449 => KeyCode::Modifier(ModifierKeyCode::RightAlt),
        57450 => KeyCode::Modifier(ModifierKeyCode::RightSuper),
        57451 => KeyCode::Modifier(ModifierKeyCode::RightHyper),
        57452 => KeyCode::Modifier(ModifierKeyCode::RightMeta),
        57453 => KeyCode::Modifier(ModifierKeyCode::IsoLevel3Shift),
        57454 => KeyCode::Modifier(ModifierKeyCode::IsoLevel5Shift),
        _ => return None,
    })
}

/// A functional key of the Kitty keyboard protocol, with the state its code
/// point implies.
fn translate_functional_key_code(codepoint: u32) -> Option<(KeyCode, KeyEventState)> {
    if let Some(keycode) = translate_keypad_code(codepoint) {
        return Some((keycode, KeyEventState::KEYPAD));
    }
    translate_other_functional_code(codepoint).map(|keycode| (keycode, KeyEventState::empty()))
}

/// The key a `CSI u` code point that is a character names.
fn csi_u_char_key(c: char, modifiers: KeyModifiers, raw_mode: bool) -> KeyCode {
    match c {
        '\x1B' => KeyCode::Esc,
        '\r' => KeyCode::Enter,
        '\n' if !raw_mode => KeyCode::Enter,
        '\t' if modifiers.contains(KeyModifiers::SHIFT) => KeyCode::BackTab,
        '\t' => KeyCode::Tab,
        '\x7F' => KeyCode::Backspace,
        _ => KeyCode::Char(c),
    }
}

/// The modifier a modifier key itself holds down.
fn modifier_of(keycode: KeyCode) -> KeyModifiers {
    match keycode {
        KeyCode::Modifier(ModifierKeyCode::LeftAlt | ModifierKeyCode::RightAlt) => {
            KeyModifiers::ALT
        }
        KeyCode::Modifier(ModifierKeyCode::LeftControl | ModifierKeyCode::RightControl) => {
            KeyModifiers::CONTROL
        }
        KeyCode::Modifier(ModifierKeyCode::LeftShift | ModifierKeyCode::RightShift) => {
            KeyModifiers::SHIFT
        }
        KeyCode::Modifier(ModifierKeyCode::LeftSuper | ModifierKeyCode::RightSuper) => {
            KeyModifiers::SUPER
        }
        KeyCode::Modifier(ModifierKeyCode::LeftHyper | ModifierKeyCode::RightHyper) => {
            KeyModifiers::HYPER
        }
        KeyCode::Modifier(ModifierKeyCode::LeftMeta | ModifierKeyCode::RightMeta) => {
            KeyModifiers::META
        }
        _ => KeyModifiers::empty(),
    }
}

/// Parse `CSI codepoint[:alternates] ; modifiers[:kind] [; text] u`, the
/// `CSI u` ("fixterms") and Kitty keyboard protocol key encoding.
fn parse_csi_u_encoded_key_code(buffer: &[u8], raw_mode: bool) -> ParseResult {
    let mut split = csi_parameters(buffer, 2)?.split(';');
    let mut codepoints = split
        .next()
        .ok_or_else(could_not_parse_event_error)?
        .split(':');
    let codepoint = codepoints
        .next()
        .ok_or_else(could_not_parse_event_error)?
        .parse::<u32>()
        .map_err(|_| could_not_parse_event_error())?;
    let (mut modifiers, kind, state_from_modifiers) =
        if let Ok((modifier_mask, kind_code)) = modifier_and_kind_parsed(&mut split) {
            (
                parse_modifiers(modifier_mask),
                parse_key_event_kind(kind_code),
                parse_modifiers_to_state(modifier_mask),
            )
        } else {
            (KeyModifiers::NONE, KeyEventKind::Press, KeyEventState::NONE)
        };
    let (mut keycode, state_from_keycode) =
        if let Some(found) = translate_functional_key_code(codepoint) {
            found
        } else if let Some(c) = char::from_u32(codepoint) {
            (
                csi_u_char_key(c, modifiers, raw_mode),
                KeyEventState::empty(),
            )
        } else {
            return Err(could_not_parse_event_error());
        };
    modifiers |= modifier_of(keycode);
    // With "report alternate keys", a key pressed with Shift carries the
    // shifted character after a ':'.
    if modifiers.contains(KeyModifiers::SHIFT)
        && let Some(shifted_c) = codepoints
            .next()
            .and_then(|codepoint| codepoint.parse::<u32>().ok())
            .and_then(char::from_u32)
    {
        keycode = KeyCode::Char(shifted_c);
        modifiers.set(KeyModifiers::SHIFT, false);
    }
    key(KeyEvent::new_with_kind_and_state(
        keycode,
        modifiers,
        kind,
        state_from_keycode | state_from_modifiers,
    ))
}

/// Parse `ESC [ n [; modifiers[:kind]] ~`: Home, Insert, Delete, End, the
/// page keys and F1 to F20.
fn parse_csi_special_key_code(buffer: &[u8]) -> ParseResult {
    let mut split = csi_parameters(buffer, 2)?.split(';');
    let first = next_parsed::<u8>(&mut split)?;
    let (modifiers, kind, state) =
        if let Ok((modifier_mask, kind_code)) = modifier_and_kind_parsed(&mut split) {
            (
                parse_modifiers(modifier_mask),
                parse_key_event_kind(kind_code),
                parse_modifiers_to_state(modifier_mask),
            )
        } else {
            (KeyModifiers::NONE, KeyEventKind::Press, KeyEventState::NONE)
        };
    let keycode = match first {
        1 | 7 => KeyCode::Home,
        2 => KeyCode::Insert,
        3 => KeyCode::Delete,
        4 | 8 => KeyCode::End,
        5 => KeyCode::PageUp,
        6 => KeyCode::PageDown,
        v @ 11..=15 => KeyCode::F(v - 10),
        v @ 17..=21 => KeyCode::F(v - 11),
        v @ 23..=26 => KeyCode::F(v - 12),
        v @ 28..=29 => KeyCode::F(v - 15),
        v @ 31..=34 => KeyCode::F(v - 17),
        _ => return Err(could_not_parse_event_error()),
    };
    key(KeyEvent::new_with_kind_and_state(
        keycode, modifiers, kind, state,
    ))
}

/// A mouse event at a column and row.
fn mouse(kind: MouseEventKind, column: u16, row: u16, modifiers: KeyModifiers) -> ParseResult {
    Ok(Some(Parsed::Event(Event::Mouse(MouseEvent {
        kind,
        column,
        row,
        modifiers,
    }))))
}

/// Parse `ESC [ Cb ; Cx ; Cy M`, the rxvt mouse encoding.
fn parse_csi_rxvt_mouse(buffer: &[u8]) -> ParseResult {
    let mut split = csi_parameters(buffer, 2)?.split(';');
    let cb = next_parsed::<u8>(&mut split)?
        .checked_sub(32)
        .ok_or_else(could_not_parse_event_error)?;
    let (kind, modifiers) = parse_cb(cb)?;
    let cx = next_coordinate(&mut split)?;
    let cy = next_coordinate(&mut split)?;
    mouse(kind, cx, cy, modifiers)
}

/// Parse `ESC [ M Cb Cx Cy`, the normal (X10) mouse encoding: six bytes.
fn parse_csi_normal_mouse(buffer: &[u8]) -> ParseResult {
    let [_, _, _, cb, cx, cy, ..] = *buffer else {
        return Ok(None);
    };
    let cb = cb.checked_sub(32).ok_or_else(could_not_parse_event_error)?;
    let (kind, modifiers) = parse_cb(cb)?;
    // The terminal's upper left cell is 1,1, sent as 33,33.
    let column = u16::from(cx.saturating_sub(32))
        .checked_sub(1)
        .ok_or_else(could_not_parse_event_error)?;
    let row = u16::from(cy.saturating_sub(32))
        .checked_sub(1)
        .ok_or_else(could_not_parse_event_error)?;
    mouse(kind, column, row, modifiers)
}

/// Parse `ESC [ < Cb ; Cx ; Cy M` (a press) or `... m` (a release), the SGR
/// mouse encoding.
fn parse_csi_sgr_mouse(buffer: &[u8]) -> ParseResult {
    if !buffer.ends_with(b"m") && !buffer.ends_with(b"M") {
        return Ok(None);
    }
    let mut split = csi_parameters(buffer, 3)?.split(';');
    let cb = next_parsed::<u8>(&mut split)?;
    let (kind, modifiers) = parse_cb(cb)?;
    let cx = next_coordinate(&mut split)?;
    let cy = next_coordinate(&mut split)?;
    // SGR says which button was released: the sequence ends in `m`.
    let kind = if buffer.last() == Some(&b'm') {
        match kind {
            MouseEventKind::Down(button) => MouseEventKind::Up(button),
            other => other,
        }
    } else {
        kind
    };
    mouse(kind, cx, cy, modifiers)
}

/// The kind and modifiers of a mouse event's button byte. From the low bit:
/// two bits of button number, Shift, Meta (Alt), Control, dragging, two more
/// bits of button number.
fn parse_cb(cb: u8) -> io::Result<(MouseEventKind, KeyModifiers)> {
    let button_number = (cb & 0b0000_0011) | ((cb & 0b1100_0000) >> 4);
    let dragging = cb & 0b0010_0000 == 0b0010_0000;
    let kind = match (button_number, dragging) {
        (0, false) => MouseEventKind::Down(MouseButton::Left),
        (1, false) => MouseEventKind::Down(MouseButton::Middle),
        (2, false) => MouseEventKind::Down(MouseButton::Right),
        (0, true) => MouseEventKind::Drag(MouseButton::Left),
        (1, true) => MouseEventKind::Drag(MouseButton::Middle),
        (2, true) => MouseEventKind::Drag(MouseButton::Right),
        (3, false) => MouseEventKind::Up(MouseButton::Left),
        (3..=5, true) => MouseEventKind::Moved,
        (4, false) => MouseEventKind::ScrollUp,
        (5, false) => MouseEventKind::ScrollDown,
        (6, false) => MouseEventKind::ScrollLeft,
        (7, false) => MouseEventKind::ScrollRight,
        _ => return Err(could_not_parse_event_error()),
    };
    let mut modifiers = KeyModifiers::empty();
    if cb & 0b0000_0100 != 0 {
        modifiers |= KeyModifiers::SHIFT;
    }
    if cb & 0b0000_1000 != 0 {
        modifiers |= KeyModifiers::ALT;
    }
    if cb & 0b0001_0000 != 0 {
        modifiers |= KeyModifiers::CONTROL;
    }
    Ok((kind, modifiers))
}

/// The opening of a bracketed paste.
const PASTE_START: &[u8] = b"\x1B[200~";

/// The end of a bracketed paste.
const PASTE_END: &[u8] = b"\x1B[201~";

/// Parse `ESC [ 200 ~ text ESC [ 201 ~`, a bracketed paste.
fn parse_csi_bracketed_paste(buffer: &[u8]) -> ParseResult {
    if !buffer.ends_with(PASTE_END) {
        return Ok(None);
    }
    let text = buffer
        .get(PASTE_START.len()..buffer.len() - PASTE_END.len())
        .unwrap_or_default();
    Ok(Some(Parsed::Event(Event::Paste(
        String::from_utf8_lossy(text).into_owned(),
    ))))
}

/// The character `buffer` holds, `None` while more of its bytes are due.
fn parse_utf8_char(buffer: &[u8]) -> io::Result<Option<char>> {
    if let Ok(s) = std::str::from_utf8(buffer) {
        let ch = s.chars().next().ok_or_else(could_not_parse_event_error)?;
        return Ok(Some(ch));
    }
    let required_bytes = match buffer.first().copied().unwrap_or_default() {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF7 => 4,
        0x80..=0xBF | 0xF8..=0xFF => return Err(could_not_parse_event_error()),
    };
    // Every byte after the first must be a continuation byte, 10xxxxxx.
    if required_bytes > 1
        && buffer
            .iter()
            .skip(1)
            .any(|byte| byte & !0b0011_1111 != 0b1000_0000)
    {
        return Err(could_not_parse_event_error());
    }
    if buffer.len() < required_bytes {
        Ok(None)
    } else {
        Err(could_not_parse_event_error())
    }
}

/// Terminal input bytes in, events out: crossterm's `Parser`.
///
/// Bytes that do not yet make a sequence are kept for the next
/// [`Parser::advance`]; a sequence that cannot be parsed is dropped.
#[derive(Debug)]
pub(crate) struct Parser {
    /// The bytes of the sequence being read.
    buffer: Vec<u8>,
    /// The events parsed and not yet taken.
    events: VecDeque<Event>,
    /// Whether the terminal is in raw mode.
    raw_mode: bool,
    /// When the lone ESC held in `buffer` arrived, while one is held.
    escape_since: Option<std::time::Instant>,
}

/// How long a lone ESC at the end of a read waits for the rest of a key
/// sequence before it is the Esc key (25 ms, as a terminal UI's usual
/// short escape delay).
pub(crate) const ESC_DELAY: std::time::Duration = std::time::Duration::from_millis(25);

impl Parser {
    /// A parser for a terminal that is in raw mode when `raw_mode` is set.
    pub(crate) fn new(raw_mode: bool) -> Self {
        Parser {
            buffer: Vec::with_capacity(256),
            events: VecDeque::with_capacity(128),
            raw_mode,
            escape_since: None,
        }
    }

    /// Parse the bytes of one read. `more` says that the read filled its
    /// buffer, so more bytes may follow at once.
    ///
    /// A lone ESC that ends a read is held, not made the Esc key at once: an
    /// arrow key is `ESC [ B`, and over ssh or tmux its bytes can arrive in
    /// two reads. The held ESC joins the next read's bytes, or is the Esc key
    /// once [`ESC_DELAY`] has passed with nothing after it
    /// ([`Parser::flush_escape_if_due`]), as a terminal UI's escape delay does.
    pub(crate) fn advance(&mut self, bytes: &[u8], more: bool) {
        for (idx, byte) in bytes.iter().enumerate() {
            let more = idx + 1 < bytes.len() || more;
            self.buffer.push(*byte);
            if !more && self.buffer.as_slice() == b"\x1b" {
                self.escape_since
                    .get_or_insert_with(std::time::Instant::now);
                return;
            }
            self.escape_since = None;
            match parse_event(&self.buffer, more, self.raw_mode) {
                Ok(Some(parsed)) => {
                    if let Parsed::Event(event) = parsed {
                        self.events.push_back(event);
                    }
                    self.buffer.clear();
                }
                Ok(None) => {}
                Err(_) => self.buffer.clear(),
            }
        }
    }

    /// How long the next terminal wait may last before a held ESC is due:
    /// the rest of [`ESC_DELAY`], or `None` when no ESC is held.
    pub(crate) fn escape_wait(&self) -> Option<std::time::Duration> {
        self.escape_since
            .map(|since| ESC_DELAY.saturating_sub(since.elapsed()))
    }

    /// A held ESC that has waited [`ESC_DELAY`] with nothing after it is
    /// the Esc key.
    pub(crate) fn flush_escape_if_due(&mut self) {
        if self.escape_wait() == Some(std::time::Duration::ZERO) {
            self.flush_escape();
        }
    }

    /// A held ESC is the Esc key now, whatever time has passed.
    fn flush_escape(&mut self) {
        if self.escape_since.take().is_some() {
            self.buffer.clear();
            self.events.push_back(Event::Key(KeyCode::Esc.into()));
        }
    }

    /// The events parsed so far, oldest first, and none of them again.
    pub(crate) fn take(&mut self) -> Vec<Event> {
        self.events.drain(..).collect()
    }
}

/// Terminal input, one read per entry, in order: keys, modifiers, mouse,
/// paste, focus, replies, sequences that do not parse, and sequences split
/// over two reads. [`CROSSTERM_0_29`] holds what crossterm 0.29.0's own
/// reader produced for each read, in raw mode, recorded by
/// `terminal_input::tests::record_crossterm_events` on a pty.
#[cfg(test)]
pub(crate) const CORPUS: &[&[u8]] = &[
    b"a",
    b"A",
    "\u{e9}".as_bytes(),
    "\u{4e2d}".as_bytes(),
    "\u{1f600}".as_bytes(),
    b"\x01",
    b"\x1a",
    b"\x1c",
    b"\x1f",
    b"\0",
    b"\r",
    b"\n",
    b"\t",
    b"\x7f",
    b"\x1b",
    b"\x1b\x1b",
    b"\x1ba",
    b"\x1bA",
    b"\x1b\x01",
    b"\x1b[A",
    b"\x1b[B",
    b"\x1b[C",
    b"\x1b[D",
    b"\x1b[H",
    b"\x1b[F",
    b"\x1b[Z",
    b"\x1bOA",
    b"\x1bOH",
    b"\x1bOP",
    b"\x1bOS",
    b"\x1b[1;5A",
    b"\x1b[1;2D",
    b"\x1b[1;3H",
    b"\x1b[1;5P",
    b"\x1b[1;6R",
    b"\x1b[2~",
    b"\x1b[3~",
    b"\x1b[5~",
    b"\x1b[6~",
    b"\x1b[1~",
    b"\x1b[4~",
    b"\x1b[15~",
    b"\x1b[24~",
    b"\x1b[3;5~",
    b"\x1b[5;3~",
    b"\x1b[34~",
    b"\x1b[[A",
    b"\x1b[P",
    b"\x1b[Q",
    b"\x1b[S",
    b"\x1b[97u",
    b"\x1b[97;5u",
    b"\x1b[9;2u",
    b"\x1b[27u",
    b"\x1b[57399u",
    b"\x1b[57441;2u",
    b"\x1b[97:65;2u",
    b"\x1b[57428u",
    b"\x1b[57376u",
    b"\x1b[97;1:3u",
    b"\x1b[<0;10;5M",
    b"\x1b[<0;10;5m",
    b"\x1b[<32;11;5M",
    b"\x1b[<64;1;1M",
    b"\x1b[<65;1;1M",
    b"\x1b[<66;1;1M",
    b"\x1b[<67;1;1M",
    b"\x1b[<16;3;4M",
    b"\x1b[<35;2;2M",
    b"\x1b[<2;5;5M",
    b"\x1b[M\x20\x21\x21",
    b"\x1b[M\x23\x30\x30",
    b"\x1b[32;10;5M",
    b"\x1b[I",
    b"\x1b[O",
    b"\x1b[200~hello\x1b[201~",
    b"\x1b[200~a\nb\x1b[201~",
    b"\x1b[12;40R",
    b"\x1b[?1u",
    b"\x1b[X",
    b"z",
    b"\x1bOZ",
    b"y",
    b"\xff",
    b"\x80",
    b"\x1b[99~",
    b"\x1b[<99;1;1M",
    b"w",
    b"\x1b[1;5",
    b"A",
    b"\x1b[",
    b"B",
    b"\xe4\xb8",
    b"\xad",
    b"\x1b[200~par",
    b"tial\x1b[201~",
    b"\x1b[<0;1",
    b";1M",
    b"ab\x1b[Ac",
    b"q\x1b",
    // Last: crossterm's reader, recording, blocked in its next `poll` with
    // a timeout after this reply (2026-11-16, Linux).
    b"\x1b[?64;1c",
];

/// What crossterm 0.29.0's reader produced for each read of [`CORPUS`]: the
/// `Debug` text of the events of that read, `[]` for none.
#[cfg(test)]
pub(crate) const CROSSTERM_0_29: &[&str] = &[
    "[Key(KeyEvent { code: Char('a'), modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: Char('A'), modifiers: KeyModifiers(SHIFT), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: Char('é'), modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: Char('中'), modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: Char('😀'), modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: Char('a'), modifiers: KeyModifiers(CONTROL), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: Char('z'), modifiers: KeyModifiers(CONTROL), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: Char('4'), modifiers: KeyModifiers(CONTROL), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: Char('7'), modifiers: KeyModifiers(CONTROL), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: Char(' '), modifiers: KeyModifiers(CONTROL), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: Enter, modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: Char('j'), modifiers: KeyModifiers(CONTROL), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: Tab, modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: Backspace, modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: Esc, modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: Esc, modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: Char('a'), modifiers: KeyModifiers(ALT), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: Char('A'), modifiers: KeyModifiers(SHIFT | ALT), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: Char('a'), modifiers: KeyModifiers(CONTROL | ALT), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: Up, modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: Down, modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: Right, modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: Left, modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: Home, modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: End, modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: BackTab, modifiers: KeyModifiers(SHIFT), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: Up, modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: Home, modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: F(1), modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: F(4), modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: Up, modifiers: KeyModifiers(CONTROL), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: Left, modifiers: KeyModifiers(SHIFT), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: Home, modifiers: KeyModifiers(ALT), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: F(1), modifiers: KeyModifiers(CONTROL), kind: Press, state: KeyEventState(0x0) })]",
    "[]",
    "[Key(KeyEvent { code: Insert, modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: Delete, modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: PageUp, modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: PageDown, modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: Home, modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: End, modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: F(5), modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: F(12), modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: Delete, modifiers: KeyModifiers(CONTROL), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: PageUp, modifiers: KeyModifiers(ALT), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: F(17), modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: F(1), modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: F(1), modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: F(2), modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: F(4), modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: Char('a'), modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: Char('a'), modifiers: KeyModifiers(CONTROL), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: BackTab, modifiers: KeyModifiers(SHIFT), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: Esc, modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: Char('0'), modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(KEYPAD) })]",
    "[Key(KeyEvent { code: Modifier(LeftShift), modifiers: KeyModifiers(SHIFT), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: Char('A'), modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: Media(Play), modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: F(13), modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: Char('a'), modifiers: KeyModifiers(0x0), kind: Release, state: KeyEventState(0x0) })]",
    "[Mouse(MouseEvent { kind: Down(Left), column: 9, row: 4, modifiers: KeyModifiers(0x0) })]",
    "[Mouse(MouseEvent { kind: Up(Left), column: 9, row: 4, modifiers: KeyModifiers(0x0) })]",
    "[Mouse(MouseEvent { kind: Drag(Left), column: 10, row: 4, modifiers: KeyModifiers(0x0) })]",
    "[Mouse(MouseEvent { kind: ScrollUp, column: 0, row: 0, modifiers: KeyModifiers(0x0) })]",
    "[Mouse(MouseEvent { kind: ScrollDown, column: 0, row: 0, modifiers: KeyModifiers(0x0) })]",
    "[Mouse(MouseEvent { kind: ScrollLeft, column: 0, row: 0, modifiers: KeyModifiers(0x0) })]",
    "[Mouse(MouseEvent { kind: ScrollRight, column: 0, row: 0, modifiers: KeyModifiers(0x0) })]",
    "[Mouse(MouseEvent { kind: Down(Left), column: 2, row: 3, modifiers: KeyModifiers(CONTROL) })]",
    "[Mouse(MouseEvent { kind: Moved, column: 1, row: 1, modifiers: KeyModifiers(0x0) })]",
    "[Mouse(MouseEvent { kind: Down(Right), column: 4, row: 4, modifiers: KeyModifiers(0x0) })]",
    "[Mouse(MouseEvent { kind: Down(Left), column: 0, row: 0, modifiers: KeyModifiers(0x0) })]",
    "[Mouse(MouseEvent { kind: Up(Left), column: 15, row: 15, modifiers: KeyModifiers(0x0) })]",
    "[Mouse(MouseEvent { kind: Down(Left), column: 9, row: 4, modifiers: KeyModifiers(0x0) })]",
    "[FocusGained]",
    "[FocusLost]",
    "[Paste(\"hello\")]",
    "[Paste(\"a\\nb\")]",
    "[]",
    "[]",
    "[]",
    "[Key(KeyEvent { code: Char('z'), modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) })]",
    "[]",
    "[Key(KeyEvent { code: Char('y'), modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) })]",
    "[]",
    "[]",
    "[]",
    "[]",
    "[Key(KeyEvent { code: Char('w'), modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) })]",
    "[]",
    "[Key(KeyEvent { code: Up, modifiers: KeyModifiers(CONTROL), kind: Press, state: KeyEventState(0x0) })]",
    "[]",
    "[Key(KeyEvent { code: Down, modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) })]",
    "[]",
    "[Key(KeyEvent { code: Char('中'), modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) })]",
    "[]",
    "[Paste(\"partial\")]",
    "[]",
    "[Mouse(MouseEvent { kind: Down(Left), column: 0, row: 0, modifiers: KeyModifiers(0x0) })]",
    "[Key(KeyEvent { code: Char('a'), modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) }), Key(KeyEvent { code: Char('b'), modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) }), Key(KeyEvent { code: Up, modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) }), Key(KeyEvent { code: Char('c'), modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) })]",
    "[Key(KeyEvent { code: Char('q'), modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) }), Key(KeyEvent { code: Esc, modifiers: KeyModifiers(0x0), kind: Press, state: KeyEventState(0x0) })]",
    "[]",
];

#[cfg(test)]
mod tests {
    use super::*;

    /// A raw-mode parser, as the TUI's.
    fn raw() -> Parser {
        Parser::new(true)
    }

    /// The events of `bytes`, read at once into a new raw-mode parser.
    fn events_of(bytes: &[u8]) -> Vec<Event> {
        let mut parser = raw();
        parser.advance(bytes, false);
        parser.flush_escape();
        parser.take()
    }

    /// A key event with modifiers.
    fn key_with(code: KeyCode, modifiers: KeyModifiers) -> Event {
        Event::Key(KeyEvent::new(code, modifiers))
    }

    /// A key event with no modifier.
    fn plain(code: KeyCode) -> Event {
        Event::Key(code.into())
    }

    /// Every read of the corpus gives the events crossterm 0.29.0's own
    /// reader gave for it, read by read through one parser.
    #[test]
    fn success_the_corpus_parses_as_crossterm_0_29_read_it() {
        assert_eq!(
            CORPUS.len(),
            CROSSTERM_0_29.len(),
            "one recorded answer per read of the corpus"
        );
        let mut parser = raw();
        for (index, (bytes, recorded)) in CORPUS.iter().zip(CROSSTERM_0_29).enumerate() {
            parser.advance(bytes, false);
            // each recorded read was followed by a pause longer than ESC_DELAY
            parser.flush_escape();
            let got = format!("{:?}", parser.take());
            assert_eq!(
                &got, recorded,
                "read {index} of the corpus, {bytes:?}, parsed differently from crossterm"
            );
        }
    }

    /// Printable characters, ASCII and not, are character keys; an
    /// uppercase one carries Shift.
    #[test]
    fn success_characters_are_character_keys() {
        assert_eq!(events_of(b"a"), vec![plain(KeyCode::Char('a'))], "a");
        assert_eq!(
            events_of(b"A"),
            vec![key_with(KeyCode::Char('A'), KeyModifiers::SHIFT)],
            "A"
        );
        assert_eq!(
            events_of("\u{4e2d}".as_bytes()),
            vec![plain(KeyCode::Char('\u{4e2d}'))],
            "a three-byte character"
        );
    }

    /// Control bytes are Ctrl keys, and the named ones their own keys.
    #[test]
    fn success_control_bytes_are_control_keys() {
        assert_eq!(
            events_of(b"\x03"),
            vec![key_with(KeyCode::Char('c'), KeyModifiers::CONTROL)],
            "Ctrl+C"
        );
        assert_eq!(events_of(b"\r"), vec![plain(KeyCode::Enter)], "Enter");
        assert_eq!(events_of(b"\t"), vec![plain(KeyCode::Tab)], "Tab");
        assert_eq!(
            events_of(b"\x7f"),
            vec![plain(KeyCode::Backspace)],
            "Backspace"
        );
        assert_eq!(
            events_of(b"\0"),
            vec![key_with(KeyCode::Char(' '), KeyModifiers::CONTROL)],
            "Ctrl+Space"
        );
    }

    /// The arrow keys, in both of their encodings.
    #[test]
    fn success_arrows_in_both_encodings() {
        for (bytes, code) in [
            (&b"\x1b[A"[..], KeyCode::Up),
            (b"\x1b[B", KeyCode::Down),
            (b"\x1b[C", KeyCode::Right),
            (b"\x1b[D", KeyCode::Left),
            (b"\x1bOA", KeyCode::Up),
            (b"\x1bOD", KeyCode::Left),
        ] {
            assert_eq!(events_of(bytes), vec![plain(code)], "{bytes:?}");
        }
    }

    /// An arrow with modifiers carries them.
    #[test]
    fn success_an_arrow_with_modifiers() {
        assert_eq!(
            events_of(b"\x1b[1;5A"),
            vec![key_with(KeyCode::Up, KeyModifiers::CONTROL)],
            "Ctrl+Up"
        );
        assert_eq!(
            events_of(b"\x1b[1;4D"),
            vec![key_with(
                KeyCode::Left,
                KeyModifiers::SHIFT | KeyModifiers::ALT
            )],
            "Shift+Alt+Left"
        );
    }

    /// The `~` keys: Delete, the page keys and function keys.
    #[test]
    fn success_tilde_keys() {
        for (bytes, code) in [
            (&b"\x1b[3~"[..], KeyCode::Delete),
            (b"\x1b[5~", KeyCode::PageUp),
            (b"\x1b[6~", KeyCode::PageDown),
            (b"\x1b[15~", KeyCode::F(5)),
            (b"\x1b[24~", KeyCode::F(12)),
        ] {
            assert_eq!(events_of(bytes), vec![plain(code)], "{bytes:?}");
        }
    }

    /// ESC before a key is Alt with that key.
    #[test]
    fn success_escape_before_a_key_is_alt() {
        assert_eq!(
            events_of(b"\x1bx"),
            vec![key_with(KeyCode::Char('x'), KeyModifiers::ALT)],
            "Alt+x"
        );
        assert_eq!(
            events_of(b"\x1b\x01"),
            vec![key_with(
                KeyCode::Char('a'),
                KeyModifiers::ALT | KeyModifiers::CONTROL
            )],
            "Alt+Ctrl+A"
        );
    }

    /// SGR mouse: a press, its release and a scroll, counted from 0.
    #[test]
    fn success_sgr_mouse_events() {
        let at = |kind| {
            Event::Mouse(MouseEvent {
                kind,
                column: 9,
                row: 4,
                modifiers: KeyModifiers::NONE,
            })
        };
        assert_eq!(
            events_of(b"\x1b[<0;10;5M"),
            vec![at(MouseEventKind::Down(MouseButton::Left))],
            "press"
        );
        assert_eq!(
            events_of(b"\x1b[<0;10;5m"),
            vec![at(MouseEventKind::Up(MouseButton::Left))],
            "release"
        );
        assert_eq!(
            events_of(b"\x1b[<65;10;5M"),
            vec![at(MouseEventKind::ScrollDown)],
            "scroll"
        );
    }

    /// A bracketed paste is one paste event with its text.
    #[test]
    fn success_a_bracketed_paste() {
        assert_eq!(
            events_of(b"\x1b[200~line one\nline two\x1b[201~"),
            vec![Event::Paste("line one\nline two".into())],
            "the pasted text"
        );
    }

    /// Several events in one read come out in order.
    #[test]
    fn success_several_events_in_one_read_in_order() {
        assert_eq!(
            events_of(b"ab\x1b[Ac"),
            vec![
                plain(KeyCode::Char('a')),
                plain(KeyCode::Char('b')),
                plain(KeyCode::Up),
                plain(KeyCode::Char('c')),
            ],
            "a, b, Up, c"
        );
    }

    /// Focus reports are focus events.
    #[test]
    fn success_focus_reports() {
        assert_eq!(events_of(b"\x1b[I"), vec![Event::FocusGained], "gained");
        assert_eq!(events_of(b"\x1b[O"), vec![Event::FocusLost], "lost");
    }

    /// A Kitty keyboard protocol key: a character with Ctrl, and a release.
    #[test]
    fn success_csi_u_keys() {
        assert_eq!(
            events_of(b"\x1b[97;5u"),
            vec![key_with(KeyCode::Char('a'), KeyModifiers::CONTROL)],
            "Ctrl+a"
        );
        assert_eq!(
            events_of(b"\x1b[97;1:3u"),
            vec![Event::Key(KeyEvent::new_with_kind(
                KeyCode::Char('a'),
                KeyModifiers::NONE,
                KeyEventKind::Release
            ))],
            "a released"
        );
    }

    /// A sequence that does not parse is dropped, and the key after it is
    /// read.
    #[test]
    fn failure_an_unknown_csi_is_dropped_and_parsing_goes_on() {
        assert_eq!(
            events_of(b"\x1b[Xz"),
            vec![plain(KeyCode::Char('z'))],
            "ESC [ X is dropped, z is read"
        );
    }

    /// An unknown SS3 key is dropped.
    #[test]
    fn failure_an_unknown_ss3_key_is_dropped() {
        assert_eq!(events_of(b"\x1bOZy"), vec![plain(KeyCode::Char('y'))], "y");
    }

    /// Bytes that cannot start a character are dropped.
    #[test]
    fn failure_invalid_utf8_is_dropped() {
        assert_eq!(events_of(b"\xff"), vec![], "0xff");
        assert_eq!(events_of(b"\x80"), vec![], "a lone continuation byte");
        assert_eq!(
            events_of(b"\xc3\x28w"),
            vec![plain(KeyCode::Char('w'))],
            "a broken two-byte character is dropped with the byte that broke it"
        );
    }

    /// A `~` key number that names no key is dropped.
    #[test]
    fn failure_an_unknown_tilde_key_is_dropped() {
        assert_eq!(events_of(b"\x1b[99~"), vec![], "99~");
    }

    /// A mouse button byte that names no button is dropped.
    #[test]
    fn failure_an_unknown_mouse_button_is_dropped() {
        assert_eq!(events_of(b"\x1b[<99;1;1M"), vec![], "button 99");
    }

    /// A mouse coordinate of 0 is dropped: the terminal counts from 1, and
    /// crossterm's subtraction wrapped or panicked here.
    #[test]
    fn failure_a_mouse_coordinate_of_0_is_dropped() {
        assert_eq!(events_of(b"\x1b[<0;0;5M"), vec![], "SGR column 0");
        assert_eq!(events_of(b"\x1b[<0;5;0M"), vec![], "SGR row 0");
        assert_eq!(events_of(b"\x1b[32;0;5M"), vec![], "rxvt column 0");
        assert_eq!(events_of(b"\x1b[M\x20\x20\x21"), vec![], "X10 column 0");
    }

    /// A cursor position reply with a 0 is dropped without a panic.
    #[test]
    fn failure_a_cursor_reply_of_0_is_dropped() {
        assert_eq!(
            events_of(b"\x1b[0;0Rz"),
            vec![plain(KeyCode::Char('z'))],
            "z"
        );
    }

    /// A modifier parameter that is not a number is dropped.
    #[test]
    fn failure_a_modifier_that_is_not_a_number_is_dropped() {
        assert_eq!(events_of(b"\x1b[1;:A"), vec![], "1;:");
    }

    /// A lone ESC at the end of a read is the Esc key; with more bytes due
    /// it waits for them.
    #[test]
    fn edge_a_lone_escape_is_esc_unless_more_is_due() {
        assert_eq!(events_of(b"\x1b"), vec![plain(KeyCode::Esc)], "Esc");
        let mut parser = raw();
        parser.advance(b"\x1b", true);
        assert_eq!(
            parser.take(),
            vec![],
            "an ESC that may begin a sequence waits"
        );
        parser.advance(b"[A", false);
        assert_eq!(parser.take(), vec![plain(KeyCode::Up)], "and ends as Up");
    }

    /// A key, then ESC at the end of the same read: the key and Esc.
    #[test]
    fn edge_a_trailing_escape_in_a_read_is_esc() {
        assert_eq!(
            events_of(b"q\x1b"),
            vec![plain(KeyCode::Char('q')), plain(KeyCode::Esc)],
            "q, Esc"
        );
    }

    /// A line feed is Ctrl+J in raw mode and Enter out of it.
    #[test]
    fn edge_a_line_feed_depends_on_raw_mode() {
        assert_eq!(
            events_of(b"\n"),
            vec![key_with(KeyCode::Char('j'), KeyModifiers::CONTROL)],
            "raw: Ctrl+J"
        );
        let mut cooked = Parser::new(false);
        cooked.advance(b"\n", false);
        assert_eq!(cooked.take(), vec![plain(KeyCode::Enter)], "cooked: Enter");
    }

    /// A character split over two reads is one key.
    #[test]
    fn edge_a_character_split_over_reads() {
        let mut parser = raw();
        parser.advance(b"\xe4\xb8", false);
        assert_eq!(parser.take(), vec![], "two of three bytes");
        parser.advance(b"\xad", false);
        assert_eq!(
            parser.take(),
            vec![plain(KeyCode::Char('\u{4e2d}'))],
            "the third byte ends it"
        );
    }

    /// The replies a terminal sends when asked are dropped, and do not eat
    /// the key after them.
    #[test]
    fn edge_terminal_replies_are_dropped() {
        assert_eq!(
            events_of(b"\x1b[12;40Rz\x1b[?1uy\x1b[?64;1cx"),
            vec![
                plain(KeyCode::Char('z')),
                plain(KeyCode::Char('y')),
                plain(KeyCode::Char('x')),
            ],
            "only the keys"
        );
    }

    /// A paste whose text is not UTF-8 keeps it, with the bad bytes
    /// replaced.
    #[test]
    fn edge_a_paste_that_is_not_utf8() {
        assert_eq!(
            events_of(b"\x1b[200~a\xffb\x1b[201~"),
            vec![Event::Paste("a\u{fffd}b".into())],
            "a, the replacement character, b"
        );
    }

    /// An empty read changes nothing, and taking twice gives the events
    /// once.
    #[test]
    fn edge_an_empty_read_and_a_second_take() {
        let mut parser = raw();
        parser.advance(b"", false);
        assert_eq!(parser.take(), vec![], "nothing from nothing");
        parser.advance(b"k", false);
        assert_eq!(parser.take(), vec![plain(KeyCode::Char('k'))], "k");
        assert_eq!(parser.take(), vec![], "k is taken once");
    }

    /// The Kitty keypad and functional code points.
    #[test]
    fn edge_kitty_functional_code_points() {
        assert_eq!(
            events_of(b"\x1b[57399u"),
            vec![Event::Key(KeyEvent::new_with_kind_and_state(
                KeyCode::Char('0'),
                KeyModifiers::NONE,
                KeyEventKind::Press,
                KeyEventState::KEYPAD
            ))],
            "keypad 0"
        );
        assert_eq!(
            events_of(b"\x1b[57398u"),
            vec![plain(KeyCode::F(35))],
            "F35, the last functional key"
        );
        assert_eq!(
            events_of(b"\x1b[57441;2u"),
            vec![key_with(
                KeyCode::Modifier(ModifierKeyCode::LeftShift),
                KeyModifiers::SHIFT
            )],
            "left Shift alone"
        );
    }

    /// An arrow key whose ESC arrives in one read and `[B` in the
    /// next, inside ESC_DELAY, is the arrow key, not Esc then `[` and `B`
    /// (a short escape delay keeps them together).
    #[test]
    fn success_an_arrow_split_after_its_escape_is_the_arrow() {
        let mut parser = raw();
        parser.advance(b"\x1b", false);
        assert_eq!(
            parser.take(),
            vec![],
            "the lone ESC is held, not yet the Esc key"
        );
        assert!(
            parser.escape_wait().is_some(),
            "the held ESC bounds the next wait"
        );
        parser.flush_escape_if_due();
        parser.advance(b"[B", false);
        assert_eq!(
            parser.take(),
            vec![plain(KeyCode::Down)],
            "ESC + [B in two reads = Down"
        );
        assert_eq!(parser.escape_wait(), None, "nothing held after the arrow");
    }

    /// A lone Esc is the Esc key as soon as ESC_DELAY has passed with
    /// nothing after it, not later.
    #[test]
    fn success_a_lone_escape_is_the_esc_key_after_the_delay() {
        let mut parser = raw();
        parser.advance(b"\x1b", false);
        let wait = parser.escape_wait().unwrap_or_default();
        assert!(wait <= ESC_DELAY, "the wait is at most ESC_DELAY: {wait:?}");
        std::thread::sleep(ESC_DELAY + std::time::Duration::from_millis(5));
        assert_eq!(
            parser.escape_wait(),
            Some(std::time::Duration::ZERO),
            "due now"
        );
        parser.flush_escape_if_due();
        assert_eq!(
            parser.take(),
            vec![plain(KeyCode::Esc)],
            "the lone ESC is the Esc key"
        );
        assert_eq!(parser.escape_wait(), None, "nothing held after it");
    }

    /// An ESC followed by more bytes in the same read never waits.
    #[test]
    fn success_an_escape_inside_a_read_never_waits() {
        let mut parser = raw();
        parser.advance(b"\x1b[Bq", false);
        assert_eq!(parser.escape_wait(), None, "nothing held");
        assert_eq!(
            parser.take(),
            vec![plain(KeyCode::Down), plain(KeyCode::Char('q'))],
            "Down then q"
        );
    }
}
