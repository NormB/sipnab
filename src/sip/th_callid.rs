// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Decoding the Call-ID that OpenSIPS `topology_hiding("C")` puts on the
//! callee-side leg, so the two legs of a hidden call can be joined exactly.
//!
//! # The encoding, from the OpenSIPS source
//!
//! `modules/topology_hiding/topo_hiding_logic.c`, `th_get_encoded_callid`:
//!
//! 1. Take the caller-side Call-ID. With `th_callid_loop_protection` (OpenSIPS
//!    4.0 and later, off by default), append `|` and the caller's tag.
//! 2. XOR every byte with `th_callid_passwd`, the key repeating from index 0
//!    over the whole buffer.
//! 3. Encode as "word64": the base64 bit layout with the alphabet
//!    `A-Z a-z 0-9 + .` and `-` as padding (`ut.c`, `word64encode`).
//! 4. Prepend `th_callid_prefix` (default `DLGCH_`).
//!
//! The defaults are `th_callid_passwd = "OpenSIPS"` and `DLGCH_`.
//!
//! # Why a wrong secret cannot be detected by decoding alone
//!
//! The scheme has no MAC, nonce or checksum. Any key decodes any value to
//! SOME bytes. So [`ThCallid::decode`] only rejects output that cannot be a
//! Call-ID, and the join itself, [`joins`], also requires the From tag to match:
//! OpenSIPS does not rewrite From or To tags, so that check does not depend on
//! the secret at all. A wrong secret therefore never produces a join.
//!
//! # The secret
//!
//! Read once, from a file named in the config (`[sip] th_callid_secret_file`),
//! or the explicit opt-in `th_callid_secret = "opensips-default"`, which is
//! OpenSIPS's published default and hides nothing. It is never taken from the
//! command line or the environment, never logged, and held in memory that is
//! zeroed when it is dropped.

use std::fmt;
use std::path::Path;

use zeroize::Zeroizing;

/// The config value that opts in to OpenSIPS's published default secret.
pub const OPENSIPS_DEFAULT_SECRET_NAME: &str = "opensips-default";

/// OpenSIPS's default `th_callid_passwd` (`topology_hiding.c`). Public, so a
/// deployment that keeps it hides nothing from anyone who reads the source.
const OPENSIPS_DEFAULT_SECRET: &[u8] = b"OpenSIPS"; // material: fixture -- OpenSIPS's published default th_callid_passwd (topology_hiding.c), opted into by name

/// OpenSIPS's default `th_callid_prefix` (`topology_hiding.c`).
pub const DEFAULT_PREFIX: &str = "DLGCH_";

/// `TH_FROM_TAG_SEP` in `topo_hiding_logic.c`: separates the Call-ID from the
/// tag that loop protection appends. Not an RFC 3261 `word` character, so the
/// first one in the decoded bytes is the separator.
const TAG_SEPARATOR: u8 = b'|';

/// Largest secret file read. A `th_callid_passwd` is a short string; a larger
/// file is the wrong file.
const MAX_SECRET_FILE_BYTES: usize = 4096;

/// The word64 alphabet, in value order (`ut.c`, `word64digits`).
const WORD64_DIGITS: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+.";

/// The word64 padding character.
const WORD64_PAD: u8 = b'-';

/// The topology-hiding secret, in memory that is zeroed on drop.
///
/// No `Clone`, no `Serialize`, and a `Debug` that prints nothing of it.
pub struct ThCallidKey(Zeroizing<Vec<u8>>);

impl ThCallidKey {
    /// A key from raw bytes, refused when it is one OpenSIPS could never use.
    ///
    /// # Errors
    ///
    /// The secret is empty (OpenSIPS would divide by zero) or contains a NUL
    /// byte (OpenSIPS takes its length with `strlen`, so it could never match).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() {
            return Err("the topology-hiding Call-ID secret is empty".into());
        }
        if bytes.contains(&0) {
            return Err(
                "the topology-hiding Call-ID secret contains a NUL byte, which OpenSIPS \
                 cannot hold (it reads th_callid_passwd with strlen)"
                    .into(),
            );
        }
        let mut owned = Zeroizing::new(Vec::with_capacity(bytes.len()));
        owned.extend_from_slice(bytes);
        Ok(Self(owned))
    }

    /// The key bytes, for the XOR only.
    fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for ThCallidKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ThCallidKey(<redacted>)")
    }
}

/// Read the secret from `path`.
///
/// The rule is the one sipnab applies to a TLS private key
/// (`tls_files::pem_private_key`): a world-readable file is refused, and
/// group-readable is allowed, because `root:sipnab 0640` is how a secret is
/// handed to a service account. The file must also be a regular file, so a
/// FIFO cannot block startup. At most `MAX_SECRET_FILE_BYTES` (4096) are read, and
/// one trailing `\n` or `\r\n` is removed, since editors add one.
///
/// # Errors
///
/// Each names the path and the rule broken, never content or length: the file
/// cannot be read, is not a regular file, is world-readable, is too large, or
/// holds a secret [`ThCallidKey::from_bytes`] refuses.
pub fn load_secret_file(path: &Path) -> Result<ThCallidKey, String> {
    use std::io::Read;
    let shown = path.display();
    let meta = std::fs::metadata(path).map_err(|e| format!("{shown}: {e}"))?;
    if !meta.is_file() {
        return Err(format!(
            "{shown}: the topology-hiding Call-ID secret file is not a regular file"
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();
        if mode & 0o004 != 0 {
            return Err(format!(
                "{shown}: the topology-hiding Call-ID secret file is world-readable \
                 (mode {:04o}); chmod 600 it",
                mode & 0o7777
            ));
        }
    }
    let file = std::fs::File::open(path).map_err(|e| format!("{shown}: {e}"))?;
    let mut buf = Zeroizing::new(Vec::with_capacity(MAX_SECRET_FILE_BYTES + 1));
    file.take(MAX_SECRET_FILE_BYTES as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("{shown}: {e}"))?;
    if buf.len() > MAX_SECRET_FILE_BYTES {
        return Err(format!(
            "{shown}: the topology-hiding Call-ID secret file is larger than \
             {MAX_SECRET_FILE_BYTES} bytes"
        ));
    }
    ThCallidKey::from_bytes(strip_one_line_end(&buf)).map_err(|e| format!("{shown}: {e}"))
}

/// The decoder `[sip]` configures, or `None` when no secret is configured.
///
/// # Errors
///
/// The `[sip]` table fails [`crate::config::SipConfig::validate`], or the
/// secret file fails [`load_secret_file`], named with its key.
pub fn from_config(sip: &crate::config::SipConfig) -> Result<Option<ThCallid>, String> {
    sip.validate().map_err(|e| e.to_string())?;
    let prefix = sip.th_callid_prefix.as_deref().unwrap_or(DEFAULT_PREFIX);
    if let Some(path) = &sip.th_callid_secret_file {
        // Named by its key: the operator reading the refusal may not know
        // which setting pointed at the file.
        let key =
            load_secret_file(path).map_err(|e| format!("[sip] th_callid_secret_file: {e}"))?;
        return ThCallid::new(key, prefix, SecretSource::File).map(Some);
    }
    if sip
        .th_callid_secret
        .as_ref()
        .is_some_and(crate::config::ThCallidSecretName::is_opensips_default)
    {
        return ThCallid::opensips_default(prefix).map(Some);
    }
    Ok(None)
}

/// `bytes` without one trailing `\n` or `\r\n`.
fn strip_one_line_end(bytes: &[u8]) -> &[u8] {
    let b = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    if b.len() < bytes.len() {
        b.strip_suffix(b"\r").unwrap_or(b)
    } else {
        b
    }
}

/// What decoding one Call-ID found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decode {
    /// The Call-ID does not start with the prefix: not a hidden leg.
    NotHidden,
    /// It starts with the prefix, but is not word64, or decodes to bytes that
    /// cannot be a Call-ID. With a correct secret this does not happen, so it
    /// is the usual sign of a wrong one.
    Undecodable,
    /// It decoded to something shaped like a Call-ID. Not yet a join: see
    /// [`joins`].
    Decoded {
        /// The caller-side Call-ID this leg claims.
        call_id: String,
        /// The tag loop protection appended, when it did.
        embedded_tag: Option<String>,
    },
}

/// How a configured secret was given, for reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretSource {
    /// Read from `th_callid_secret_file`.
    File,
    /// The opt-in `th_callid_secret = "opensips-default"`.
    OpenSipsDefault,
}

/// A configured decoder: the secret, the prefix, and where the secret came from.
#[derive(Debug)]
pub struct ThCallid {
    /// The secret, OpenSIPS's `th_callid_passwd`.
    key: ThCallidKey,
    /// OpenSIPS's `th_callid_prefix`, which marks a hidden Call-ID.
    prefix: String,
    /// Where the secret came from.
    source: SecretSource,
}

impl ThCallid {
    /// A decoder from a loaded secret.
    ///
    /// # Errors
    ///
    /// The prefix is empty: every Call-ID would then look hidden.
    pub fn new(key: ThCallidKey, prefix: &str, source: SecretSource) -> Result<Self, String> {
        if prefix.is_empty() {
            return Err("[sip] th_callid_prefix must not be empty".into());
        }
        Ok(Self {
            key,
            prefix: prefix.to_string(),
            source,
        })
    }

    /// A decoder with OpenSIPS's published default secret.
    ///
    /// # Errors
    ///
    /// As [`Self::new`].
    pub fn opensips_default(prefix: &str) -> Result<Self, String> {
        let key = ThCallidKey::from_bytes(OPENSIPS_DEFAULT_SECRET)?;
        Self::new(key, prefix, SecretSource::OpenSipsDefault)
    }

    /// The prefix that marks a hidden Call-ID.
    #[must_use]
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// Where the secret came from.
    #[must_use]
    pub fn source(&self) -> SecretSource {
        self.source
    }

    /// Decode one Call-ID. See [`Decode`].
    #[must_use]
    pub fn decode(&self, call_id: &str) -> Decode {
        let Some(body) = call_id.as_bytes().strip_prefix(self.prefix.as_bytes()) else {
            return Decode::NotHidden;
        };
        let Some(mut plain) = word64_decode(body) else {
            return Decode::Undecodable;
        };
        xor_with_key(&mut plain, self.key.expose());
        split_decoded(&plain)
    }
}

/// Whether `call_id` carries `prefix`: a hidden leg, decodable or not.
#[must_use]
pub fn is_hidden(call_id: &str, prefix: &str) -> bool {
    !prefix.is_empty() && call_id.len() > prefix.len() && call_id.starts_with(prefix)
}

/// XOR `buf` with `key`, the key repeating from index 0 over the whole buffer,
/// separator and tag included, as `th_get_encoded_callid` does.
fn xor_with_key(buf: &mut [u8], key: &[u8]) {
    for (i, b) in buf.iter_mut().enumerate() {
        *b ^= key[i % key.len()];
    }
}

/// The value of one word64 digit, or `None` when it is not one.
fn word64_value(c: u8) -> Option<u8> {
    WORD64_DIGITS
        .iter()
        .position(|&d| d == c)
        .and_then(|p| u8::try_from(p).ok())
}

/// Strict word64 decode, `None` on anything `word64encode` cannot produce.
///
/// Stricter than OpenSIPS's own decoder, which skips stray characters: the
/// encoder always writes groups of four, `-` only as trailing padding, and
/// zero bits in the unused tail, so anything else is not an encoded Call-ID.
fn word64_decode(input: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let (chunks, rest) = input.as_chunks::<4>();
    if chunks.is_empty() || !rest.is_empty() {
        return None;
    }
    let mut out = Zeroizing::new(Vec::with_capacity(chunks.len() * 3));
    let groups = chunks.len();
    for (g, chunk) in chunks.iter().enumerate() {
        let last = g + 1 == groups;
        let pads = chunk.iter().rev().take_while(|&&c| c == WORD64_PAD).count();
        if pads > 2 || (pads > 0 && !last) {
            return None;
        }
        let mut v = [0u8; 4];
        for (slot, &c) in v.iter_mut().zip(&chunk[..4 - pads]) {
            *slot = word64_value(c)?;
        }
        out.push((v[0] << 2) | (v[1] >> 4));
        match pads {
            0 => {
                out.push((v[1] << 4) | (v[2] >> 2));
                out.push((v[2] << 6) | v[3]);
            }
            1 => {
                if v[2] & 0x03 != 0 {
                    return None;
                }
                out.push((v[1] << 4) | (v[2] >> 2));
            }
            _ => {
                if v[1] & 0x0f != 0 {
                    return None;
                }
            }
        }
    }
    Some(out)
}

/// RFC 3261 `token` characters: alphanum and `-.!%*_+`'~`.
fn is_token_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"-.!%*_+`'~".contains(&c)
}

/// Split decoded bytes at the first loop-protection separator and check each side.
fn split_decoded(plain: &[u8]) -> Decode {
    let (cid, tag) = match plain.iter().position(|&c| c == TAG_SEPARATOR) {
        Some(at) => (&plain[..at], Some(&plain[at + 1..])),
        None => (plain, None),
    };
    if !crate::sip::th_mapping::is_rfc3261_callid(cid) {
        return Decode::Undecodable;
    }
    if let Some(t) = tag
        && (t.is_empty() || !t.iter().all(|&c| is_token_char(c)))
    {
        return Decode::Undecodable;
    }
    // Both checks admit ASCII only, so these never fail.
    let Ok(call_id) = std::str::from_utf8(cid) else {
        return Decode::Undecodable;
    };
    let embedded_tag = match tag.map(std::str::from_utf8) {
        Some(Ok(t)) => Some(t.to_string()),
        Some(Err(_)) => return Decode::Undecodable,
        None => None,
    };
    Decode::Decoded {
        call_id: call_id.to_string(),
        embedded_tag,
    }
}

/// The parts of a leg that the join compares.
#[derive(Debug, Clone, Copy)]
pub struct Leg<'a> {
    /// The leg's Call-ID as seen on the wire.
    pub call_id: &'a str,
    /// The From tag.
    pub from_tag: Option<&'a str>,
    /// The remote tag, when the dialog has one.
    pub to_tag: Option<&'a str>,
}

/// Whether the hidden leg, decoded as `decoded`, is the callee side of `caller`.
///
/// Every check must hold:
///
/// 1. the decoded Call-ID equals the caller leg's Call-ID exactly;
/// 2. both legs have a From tag, and they are equal (OpenSIPS does not rewrite
///    tags, so this does not depend on the secret);
/// 3. where both legs have a To tag, they are equal;
/// 4. with loop protection, the embedded tag equals that From tag.
///
/// Which leg was seen first is not checked: two HEP agents with skewed
/// clocks, or a capture that starts mid-call, can show the hidden leg first,
/// and the order adds nothing to checks 1 and 2.
#[must_use]
pub fn joins(decoded: &Decode, hidden: Leg<'_>, caller: Leg<'_>) -> bool {
    let Decode::Decoded {
        call_id,
        embedded_tag,
    } = decoded
    else {
        return false;
    };
    if call_id != caller.call_id {
        return false;
    }
    let (Some(hidden_from), Some(caller_from)) = (hidden.from_tag, caller.from_tag) else {
        return false;
    };
    if hidden_from != caller_from {
        return false;
    }
    if let (Some(a), Some(b)) = (hidden.to_tag, caller.to_tag)
        && a != b
    {
        return false;
    }
    embedded_tag.as_deref().is_none_or(|tag| tag == caller_from)
}

#[cfg(test)]
/// The reference encoder, written from `th_get_encoded_callid` step by
/// step, used only to build vectors. Kept apart from the decoder so a
/// decoder bug cannot hide in a shared helper. The independent anchors are
/// the fixed vectors below (computed with Python's base64 module, with the
/// word64 substitutions) and the OpenSIPS-produced captures in the
/// end-to-end tests.
pub(crate) fn encode(call_id: &str, tag: Option<&str>, key: &[u8], prefix: &str) -> String {
    let mut plain = call_id.as_bytes().to_vec();
    if let Some(t) = tag {
        plain.push(b'|');
        plain.extend_from_slice(t.as_bytes());
    }
    for (i, b) in plain.iter_mut().enumerate() {
        *b ^= key[i % key.len()];
    }
    let mut out = prefix.to_string();
    for chunk in plain.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let d = |v: u8| WORD64_DIGITS[usize::from(v)] as char;
        out.push(d(b0 >> 2));
        out.push(d(((b0 << 4) & 0x30) | (b1 >> 4)));
        out.push(if chunk.len() > 1 {
            d(((b1 << 2) & 0x3c) | (b2 >> 6))
        } else {
            '-'
        });
        out.push(if chunk.len() > 2 { d(b2 & 0x3f) } else { '-' });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestError = Box<dyn std::error::Error>;

    fn th(key: &[u8], prefix: &str) -> Result<ThCallid, TestError> {
        Ok(ThCallid::new(
            ThCallidKey::from_bytes(key)?,
            prefix,
            SecretSource::File,
        )?)
    }

    fn decoded(call_id: &str, tag: Option<&str>) -> Decode {
        Decode::Decoded {
            call_id: call_id.into(),
            embedded_tag: tag.map(str::to_string),
        }
    }

    // T1: word64 vectors computed outside Rust. The first contains `.`, the
    // alphabet's 63rd digit, and ends in one pad; the last two cover the
    // one-byte (`--`) and two-byte (`-`) tails.
    #[test]
    fn t1_word64_vectors_from_an_independent_encoder() -> Result<(), TestError> {
        let d = th(b"OpenSIPS", "DLGCH_")?; // material: fixture -- OpenSIPS's default secret, which the known-answer vectors were encoded with
        assert_eq!(
            d.decode("DLGCH_LkhRDGcqZ2UqRlNZYnkQNjcRCB4.LH4wIB0-"),
            decoded("a84b4c76e66710@example.com", None),
            "a vector from an independent encoder, with the alphabet's `.` and one pad"
        );
        assert_eq!(
            d.decode("DLGCH_Nw--"),
            decoded("x", None),
            "a one-byte tail with two pads"
        );
        assert_eq!(
            d.decode("DLGCH_Nwk-"),
            decoded("xy", None),
            "a two-byte tail with one pad"
        );
        Ok(())
    }

    // T1: what `word64encode` can never write is refused, not guessed at.
    #[test]
    fn t1_word64_refuses_base64_alphabet_and_bad_padding() -> Result<(), TestError> {
        let d = th(b"OpenSIPS", "DLGCH_")?; // material: fixture -- OpenSIPS's default secret, which the known-answer vectors were encoded with
        // base64's `/` in place of word64's `.`
        assert_eq!(
            d.decode("DLGCH_LkhRDGcqZ2UqRlNZYnkQNjcRCB4/LH4wIB0-"),
            Decode::Undecodable,
            "base64's `/` is not a word64 digit"
        );
        // base64's `=` padding
        assert_eq!(
            d.decode("DLGCH_Nw=="),
            Decode::Undecodable,
            "base64's `=` is not word64 padding"
        );
        // not a multiple of four
        assert_eq!(
            d.decode("DLGCH_Nwk"),
            Decode::Undecodable,
            "word64 is written in groups of four"
        );
        // padding in the middle
        assert_eq!(
            d.decode("DLGCH_Nw--Nwk-"),
            Decode::Undecodable,
            "padding only at the end"
        );
        // nonzero bits in the unused tail
        assert_eq!(
            d.decode("DLGCH_Nx--"),
            Decode::Undecodable,
            "the unused tail bits of a padded group are zero"
        );
        Ok(())
    }

    // T2: the key index runs over the whole buffer from 0, so a Call-ID
    // longer than the key and a non-default key both round-trip.
    #[test]
    fn t2_key_cycles_from_index_zero_over_the_whole_buffer() -> Result<(), TestError> {
        let d = th(b"s3cret-th-0100", "SIPSSERT_")?; // material: fixture -- the secret the known-answer vector below was encoded with
        assert_eq!(
            d.decode("SIPSSERT_QAtXSldDG0ZRFQIDAAFLC1ZDVDRIDAlAQF1VHhBcDg--"),
            decoded("3848276298220188511@example.com", None),
            "the key repeats from index 0 over a Call-ID longer than the key"
        );
        let long = "0123456789abcdef0123456789abcdef@example.com";
        let k = crate::test_utils::th_test_secret("k3y");
        let enc = encode(long, Some("a1b2c3"), &k, "DLGCH_");
        let d = th(&k, "DLGCH_")?;
        assert_eq!(
            d.decode(&enc),
            decoded(long, Some("a1b2c3")),
            "a long Call-ID with a tag round-trips"
        );
        Ok(())
    }

    // T4: loop protection's tag comes back, split at the FIRST separator.
    #[test]
    fn t4_loop_protection_tag_is_split_off() -> Result<(), TestError> {
        let d = th(b"OpenSIPS", "DLGCH_")?; // material: fixture -- OpenSIPS's default secret, which the known-answer vectors were encoded with
        assert_eq!(
            d.decode("DLGCH_LkhRDGcqZ2UqRlNZYnkQNjcRCB4.LH4wIB0ZX2p7aGB.QVJZZw--"),
            decoded("a84b4c76e66710@example.com", Some("1928301774")),
            "loop protection's tag is split off at the separator"
        );
        // A second `|` in the tag part cannot be a tag: refused rather than
        // split at the last one.
        let enc = encode("abc@example.com", Some("t1|t2"), b"OpenSIPS", "DLGCH_");
        assert_eq!(
            d.decode(&enc),
            Decode::Undecodable,
            "a second separator cannot be in a tag"
        );
        Ok(())
    }

    // T5: prefixes.
    #[test]
    fn t5_prefix_is_exact_and_configurable() -> Result<(), TestError> {
        let d = th(b"OpenSIPS", "DLGCH_")?; // material: fixture -- OpenSIPS's default secret, which the known-answer vectors were encoded with
        assert_eq!(
            d.decode("a84b4c76e66710@example.com"),
            Decode::NotHidden,
            "a Call-ID without the prefix is not hidden"
        );
        assert_eq!(
            d.decode("dlgch_LkhRDGcqZ2UqRlNZYnkQNjcRCB4.LH4wIB0-"),
            Decode::NotHidden,
            "the prefix is compared exactly, case included"
        );
        let s = th(b"OpenSIPS", "SIPSSERT_")?; // material: fixture -- OpenSIPS's default secret, to show the prefix is configurable
        let enc = encode("abc@example.com", None, b"OpenSIPS", "SIPSSERT_");
        assert_eq!(
            s.decode(&enc),
            decoded("abc@example.com", None),
            "a configured prefix other than the default decodes"
        );
        assert!(
            ThCallid::new(ThCallidKey::from_bytes(b"k")?, "", SecretSource::File).is_err(),
            "an empty prefix would make every Call-ID look hidden"
        );
        assert!(
            is_hidden("DLGCH_x", "DLGCH_"),
            "the prefix and more is hidden"
        );
        assert!(
            !is_hidden("DLGCH_", "DLGCH_"),
            "the prefix alone carries nothing to decode"
        );
        assert!(
            !is_hidden("abc", ""),
            "an empty prefix marks nothing hidden"
        );
        Ok(())
    }

    // T6: a wrong secret on a real-shaped value never yields the right Call-ID.
    #[test]
    fn t6_wrong_secret_does_not_decode_to_the_call_id() -> Result<(), TestError> {
        let right = crate::test_utils::th_test_secret("right");
        let enc = encode("a84b4c76e66710@example.com", None, &right, "DLGCH_");
        let d = th(&crate::test_utils::th_test_secret("wrong"), "DLGCH_")?;
        assert_ne!(
            d.decode(&enc),
            decoded("a84b4c76e66710@example.com", None),
            "a wrong secret decoded the hidden Call-ID to the caller's"
        );
        Ok(())
    }

    fn leg<'a>(call_id: &'a str, from: Option<&'a str>, to: Option<&'a str>) -> Leg<'a> {
        Leg {
            call_id,
            from_tag: from,
            to_tag: to,
        }
    }

    // T6 / T7: the join's checks, each one alone enough to refuse.
    #[test]
    fn t7_join_requires_every_check() {
        let caller = leg("abc@example.com", Some("ft1"), Some("tt1"));
        let hidden = leg("DLGCH_x", Some("ft1"), Some("tt1"));
        let good = decoded("abc@example.com", None);
        assert!(
            joins(&good, hidden, caller),
            "every check holds, so the legs join"
        );
        // 1: a decoded value naming another call
        assert!(
            !joins(&decoded("other@example.com", None), hidden, caller),
            "a decoded value naming another call does not join"
        );
        // 2: From tag differs (the check a wrong secret cannot pass)
        assert!(
            !joins(&good, leg("DLGCH_x", Some("ft2"), Some("tt1")), caller),
            "another From tag does not join, whatever the secret"
        );
        // 2: From tag missing
        assert!(
            !joins(&good, leg("DLGCH_x", None, Some("tt1")), caller),
            "a leg with no From tag gives nothing to compare"
        );
        // 3: To tags both present and different
        assert!(
            !joins(&good, leg("DLGCH_x", Some("ft1"), Some("tt2")), caller),
            "two To tags that differ do not join"
        );
        // 3: a To tag on one side only is no evidence either way
        assert!(
            joins(&good, leg("DLGCH_x", Some("ft1"), None), caller),
            "a To tag on one side only is no evidence either way"
        );
        // 4: embedded tag differs
        assert!(
            !joins(&decoded("abc@example.com", Some("zz")), hidden, caller),
            "an appended tag that is not the From tag does not join"
        );
        assert!(
            joins(&decoded("abc@example.com", Some("ft1")), hidden, caller),
            "an appended tag equal to the From tag joins"
        );
        // not decoded at all
        assert!(
            !joins(&Decode::Undecodable, hidden, caller),
            "an undecodable value joins nothing"
        );
        assert!(
            !joins(&Decode::NotHidden, hidden, caller),
            "a Call-ID that is not hidden joins nothing by decoding"
        );
    }

    // T9: the secret file's rules.
    #[cfg(unix)]
    #[test]
    fn t9_secret_file_rules() -> Result<(), TestError> {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir()?;
        let write = |name: &str, body: &[u8], mode: u32| -> Result<std::path::PathBuf, TestError> {
            let p = dir.path().join(name);
            std::fs::write(&p, body)?;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode))?;
            Ok(p)
        };
        let enc = encode("abc@example.com", None, b"s3cret", "DLGCH_");
        let check = |p: &Path| -> Result<Decode, TestError> {
            Ok(ThCallid::new(load_secret_file(p)?, "DLGCH_", SecretSource::File)?.decode(&enc))
        };
        let want = decoded("abc@example.com", None);
        assert_eq!(
            check(&write("lf", b"s3cret\n", 0o600)?)?,
            want,
            "one trailing LF is removed"
        );
        assert_eq!(
            check(&write("crlf", b"s3cret\r\n", 0o640)?)?,
            want,
            "one trailing CRLF is removed, and group-readable is allowed"
        );
        assert_eq!(
            check(&write("bare", b"s3cret", 0o600)?)?,
            want,
            "a file with no line end is read as it is"
        );
        // Only ONE line end is removed: a second is part of the secret.
        assert_ne!(
            check(&write("two", b"s3cret\n\n", 0o600)?)?,
            want,
            "only one line end is removed: the second is part of the secret"
        );
        // Leading or trailing spaces are part of the secret, as in OpenSIPS.
        assert_ne!(
            check(&write("sp", b"s3cret \n", 0o600)?)?,
            want,
            "a trailing space is part of the secret, as in OpenSIPS"
        );

        let refused = |p: std::path::PathBuf, needle: &str| -> Result<(), TestError> {
            let err = load_secret_file(&p).err().ok_or("must be refused")?;
            assert!(err.contains(needle), "{err:?} lacks {needle:?}");
            assert!(!err.contains("s3cret"), "{err:?} shows the secret");
            Ok(())
        };
        refused(write("world", b"s3cret\n", 0o644)?, "world-readable")?;
        refused(write("empty", b"", 0o600)?, "empty")?;
        refused(write("nl", b"\n", 0o600)?, "empty")?;
        refused(write("nul", b"s3\0cret", 0o600)?, "NUL")?;
        refused(write("big", &[b'a'; 4097], 0o600)?, "larger than")?;
        assert!(
            load_secret_file(&write("max", &[b'a'; 4096], 0o600)?).is_ok(),
            "a file of exactly MAX_SECRET_FILE_BYTES is read"
        );
        refused(dir.path().to_path_buf(), "not a regular file")?;
        refused(dir.path().join("absent"), "absent")?;
        Ok(())
    }

    // T10: nothing of the secret in Debug output, at either level.
    #[test]
    fn t10_debug_shows_no_secret() -> Result<(), TestError> {
        let k = crate::test_utils::th_test_secret("debug");
        let d = th(&k, "DLGCH_")?;
        let as_text = String::from_utf8(k.clone())?;
        // The byte list a derived Debug would print for the first two bytes.
        let as_list = format!("{}, {}", k[0], k[1]);
        for text in [format!("{d:?}"), format!("{:?}", d.key), format!("{d:#?}")] {
            assert!(!text.contains(&as_text), "Debug shows the secret: {text}");
            assert!(
                !text.contains(&as_list),
                "Debug shows the secret's bytes: {text}"
            );
            assert!(
                text.contains("redacted"),
                "Debug does not say it hid the secret: {text}"
            );
        }
        Ok(())
    }

    // T11: the key and every buffer holding decoded bytes are zeroed on drop.
    // Checked through the types rather than by reading freed memory, which
    // would be undefined behavior: replacing `Zeroizing` with a plain `Vec`
    // in either place fails to compile here.
    #[test]
    fn t11_secret_storage_is_zeroizing() -> Result<(), TestError> {
        fn key_storage(k: &ThCallidKey) -> &Zeroizing<Vec<u8>> {
            &k.0
        }
        fn decode_buffer(b: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
            word64_decode(b)
        }
        let k = ThCallidKey::from_bytes(b"k")?;
        assert_eq!(
            key_storage(&k).as_slice(),
            b"k",
            "the key is held in Zeroizing storage"
        );
        assert_eq!(
            decode_buffer(b"Nw--").map(|v| v.len()),
            Some(1),
            "the decode buffer is Zeroizing storage"
        );
        Ok(())
    }

    // The opt-in default is OpenSIPS's real default and is labeled as such.
    #[test]
    fn opensips_default_decodes_default_vectors() -> Result<(), TestError> {
        let d = ThCallid::opensips_default(DEFAULT_PREFIX)?;
        assert_eq!(
            d.source(),
            SecretSource::OpenSipsDefault,
            "the opt-in is labeled as OpenSIPS's default"
        );
        assert_eq!(
            d.decode("DLGCH_LkhRDGcqZ2UqRlNZYnkQNjcRCB4.LH4wIB0-"),
            decoded("a84b4c76e66710@example.com", None),
            "OpenSIPS's default secret decodes the default vector"
        );
        Ok(())
    }

    // T9 (wiring): the config builds the decoder the store uses.
    #[cfg(unix)]
    #[test]
    fn t9_from_config_builds_each_source() -> Result<(), TestError> {
        use std::os::unix::fs::PermissionsExt;
        let none = crate::config::SipConfig::default();
        assert!(
            from_config(&none)?.is_none(),
            "no th_callid key configures no decoder"
        );

        let dir = tempfile::tempdir()?;
        let p = dir.path().join("th.secret");
        std::fs::write(&p, b"s3cret\n")?;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))?;
        let cfg: crate::config::Config = toml::from_str(&format!(
            "[sip]\nth_callid_secret_file = {:?}\nth_callid_prefix = \"SIPSSERT_\"\n",
            p.display().to_string()
        ))?;
        let th = from_config(&cfg.sip)?.ok_or("file must configure a decoder")?;
        assert_eq!(
            th.source(),
            SecretSource::File,
            "a secret file is reported as a file"
        );
        assert_eq!(th.prefix(), "SIPSSERT_", "the configured prefix is used");
        let enc = encode("abc@example.com", None, b"s3cret", "SIPSSERT_");
        assert_eq!(
            th.decode(&enc),
            decoded("abc@example.com", None),
            "the file's secret decodes what it encoded"
        );

        let cfg: crate::config::Config =
            toml::from_str("[sip]\nth_callid_secret = \"opensips-default\"\n")?;
        let th = from_config(&cfg.sip)?.ok_or("opt-in must configure a decoder")?;
        assert_eq!(
            th.source(),
            SecretSource::OpenSipsDefault,
            "the opt-in is reported as OpenSIPS's default"
        );
        assert_eq!(
            th.prefix(),
            DEFAULT_PREFIX,
            "with no prefix configured, OpenSIPS's default is used"
        );

        // A prefix alone has nothing to decode with, and is refused rather
        // than half-applied.
        let cfg: crate::config::Config = toml::from_str("[sip]\nth_callid_prefix = \"X_\"\n")?;
        let err = from_config(&cfg.sip)
            .err()
            .ok_or("prefix alone must be refused")?;
        assert!(err.contains("th_callid_prefix"), "{err}");

        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644))?;
        let cfg: crate::config::Config = toml::from_str(&format!(
            "[sip]\nth_callid_secret_file = {:?}\n",
            p.display().to_string()
        ))?;
        assert!(
            from_config(&cfg.sip).is_err(),
            "a world-readable secret file is refused"
        );
        Ok(())
    }
}
