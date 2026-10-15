// SPDX-License-Identifier: MIT OR Apache-2.0

//! `--vcon-audio-fetch`: get back the audio a vCon names by `url`.
//!
//! A `[[vcon.rule]]` with `audio = "url"` writes each recording beside its
//! container and names it in a `recording` Dialog Object by `url`,
//! `mediatype` and `content_hash`. With `encrypt_to`, the file is a JWE of
//! its own, and the `content_hash` covers the file as written, the
//! ciphertext. This command reads such a container in any form the readers
//! accept, and for each recording with a `url`:
//!
//! 1. reads the file: an `https://` GET through the fetcher's client
//!    (`crate::app::vcon_fetch::get_body`), or, with
//!    `--vcon-audio-fetch-local`, the file of that name beside the container;
//! 2. checks the `content_hash`
//!    ([draft-ietf-vcon-vcon-core-04 section 2.2](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-2.2))
//!    against those bytes, before anything else reads them;
//! 3. decrypts a JWE with the readers' key (`--vcon-key`), through the same
//!    JOSE code as the container;
//! 4. writes the audio to `<uuid>-dialog<N>.<wav|ogg>`, mode 0600, never
//!    replacing a file.
//!
//! [Section 2.4.1](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-2.4.1):
//! "HTTPS MUST be used for retrieval to protect the privacy of the contents
//! of the file", so a URL that is not `https://` is refused, not fetched.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// Exit code of a refused input, a recording not written, or an output that
/// exists.
const REFUSED: i32 = 1;

/// Exit code of settings that cannot be used: a key or CA file that does not
/// read, or an output directory that cannot be made.
const BAD_SETTINGS: i32 = 2;

/// What the audio fetch's trust refusals call its settings and its peer.
const AUDIO_TRUST: crate::tls_files::TrustNames<'static> = crate::tls_files::TrustNames {
    ca: "--vcon-audio-fetch-ca",
    extra: "--vcon-audio-fetch-extra-ca",
    issuer: "the audio server's CA",
};

/// One recording a container names by `url`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlRecording {
    /// Its index in the container's `dialog` array.
    pub index: usize,
    /// The `url`.
    pub url: String,
    /// The `content_hash`, as the container gives it.
    pub content_hash: Option<String>,
    /// The `mediatype` of the audio.
    pub mediatype: Option<String>,
}

/// Every `recording` Dialog Object in `container` that names a `url`, in
/// dialog order.
#[must_use]
pub fn url_recordings(container: &serde_json::Value) -> Vec<UrlRecording> {
    let text =
        |d: &serde_json::Value, k: &str| d.get(k).and_then(|v| v.as_str()).map(str::to_owned);
    container
        .get("dialog")
        .and_then(serde_json::Value::as_array)
        .map(|dialogs| {
            dialogs
                .iter()
                .enumerate()
                .filter(|(_, d)| d.get("type").and_then(|t| t.as_str()) == Some("recording"))
                .filter_map(|(index, d)| {
                    Some(UrlRecording {
                        index,
                        url: text(d, "url")?,
                        content_hash: text(d, "content_hash"),
                        mediatype: text(d, "mediatype"),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The file extension the audio of `mediatype` is written with: `wav` for
/// the WAV types, `ogg` for `audio/ogg`. `None` for anything else.
#[must_use]
pub fn extension_for(mediatype: &str) -> Option<&'static str> {
    match mediatype.to_ascii_lowercase().as_str() {
        "audio/x-wav" | "audio/wav" | "audio/wave" | "audio/vnd.wave" => Some("wav"),
        "audio/ogg" => Some("ogg"),
        _ => None,
    }
}

/// Check `body` against `content_hash`, the `sha512-` token of
/// [section 2.2](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-2.2).
///
/// # Errors
///
/// No `content_hash`, an algorithm other than `sha512`, or a hash that is
/// not `body`'s.
pub fn check_content_hash(body: &[u8], content_hash: Option<&str>) -> Result<(), String> {
    let Some(expected) = content_hash else {
        return Err("names no content_hash, so the file cannot be checked".into());
    };
    if !expected.starts_with(crate::output::vcon::CONTENT_HASH_PREFIX) {
        return Err(format!(
            "has content_hash {expected:?}, and sipnab checks sha512 only"
        ));
    }
    if crate::app::vcon_hash::token(body) != expected {
        return Err(
            "content_hash does not match the file: the file is not the one the vCon names".into(),
        );
    }
    Ok(())
}

/// The file name a spool holds `url`'s file under: the last path segment.
///
/// # Errors
///
/// A segment that is empty, starts with a dot, or holds anything but ASCII
/// letters, digits, `-`, `_` and `.`, so it cannot name a file outside the
/// directory.
pub fn local_name(url: &str) -> Result<&str, String> {
    let path = url.split(['?', '#']).next().unwrap_or_default();
    let name = path.rsplit('/').next().unwrap_or_default();
    let safe = !name.is_empty()
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    if safe {
        Ok(name)
    } else {
        Err(format!(
            "url {url:?} ends in no file name sipnab reads beside the container"
        ))
    }
}

/// The audio in `body`, already checked against its `content_hash`: a JWE
/// decrypted with `opener`, its `cty` the recording's `mediatype`; anything
/// else as it is. Either way the audio must start as `extension` says: `RIFF`
/// for a WAV, `OggS` for Ogg.
///
/// # Errors
///
/// A JWE that does not decrypt, a `cty` that is not the `mediatype`, or
/// audio that is not a WAV or Ogg file.
pub fn audio_of(
    body: &[u8],
    mediatype: &str,
    extension: &str,
    opener: &crate::output::vcon_jose::Opener,
) -> Result<Vec<u8>, String> {
    use crate::output::vcon_jose::{Form, form_of};
    let jwe = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .filter(|v| form_of(v) == Form::Encrypted);
    let audio = match jwe {
        Some(jwe) => {
            let cty = jwe
                .get("unprotected")
                .and_then(|h| h.get("cty"))
                .and_then(|c| c.as_str());
            if !cty.is_some_and(|c| c.eq_ignore_ascii_case(mediatype)) {
                return Err(format!(
                    "the file is a JWE whose cty is {cty:?}, not the mediatype {mediatype:?}"
                ));
            }
            opener
                .open_file(body)
                .map_err(|e| format!("the file is a JWE and did not decrypt: {e}"))?
        }
        None => body.to_vec(),
    };
    let magic: &[u8] = if extension == "ogg" { b"OggS" } else { b"RIFF" };
    if !audio.starts_with(magic) {
        return Err(format!(
            "the audio is not {} (it does not start with {:?})",
            if extension == "ogg" {
                "an Ogg file"
            } else {
                "a WAV file"
            },
            String::from_utf8_lossy(magic)
        ));
    }
    Ok(audio)
}

/// Where each recording's bytes come from.
enum Source {
    /// An `https://` GET with this client.
    Https(Arc<rustls::ClientConfig>),
    /// The file of the URL's name in this directory.
    Local(PathBuf),
}

/// Read every recording the container in `--vcon-audio-fetch` names by
/// `url`, and write the audio of each to `--vcon-audio-fetch-out`.
///
/// # Returns
///
/// The files written.
///
/// # Errors
///
/// The exit code and every reason, one line each: 2 for a key, CA or output
/// directory that cannot be used, before anything is read; 1 for a
/// container that does not open or names no recording by `url`, and when
/// any recording was not written. The recordings that were written stay
/// written.
pub fn run(args: &crate::cli::VconAudioFetchArgs) -> Result<Vec<PathBuf>, (i32, Vec<String>)> {
    let one = |code: i32, why: String| (code, vec![why]);
    let input = args
        .vcon_audio_fetch
        .as_ref()
        .ok_or_else(|| one(BAD_SETTINGS, "needs a file".into()))?;
    let out = args
        .vcon_audio_fetch_out
        .as_ref()
        .ok_or_else(|| one(BAD_SETTINGS, "needs --vcon-audio-fetch-out".into()))?;
    let opener = crate::capture::vcon_input::opener().map_err(|e| one(BAD_SETTINGS, e))?;
    let source = if args.vcon_audio_fetch_local {
        Source::Local(
            input
                .parent()
                .map_or_else(|| PathBuf::from("."), Path::to_path_buf),
        )
    } else {
        Source::Https(
            crate::app::vcon_forward::client_config(
                args.vcon_audio_fetch_ca.as_deref(),
                args.vcon_audio_fetch_extra_ca.as_deref(),
                &AUDIO_TRUST,
            )
            .map_err(|e| {
                let flag = if args.vcon_audio_fetch_extra_ca.is_some() {
                    AUDIO_TRUST.extra
                } else {
                    AUDIO_TRUST.ca
                };
                one(BAD_SETTINGS, format!("{flag}: {e}"))
            })?,
        )
    };
    crate::app::vcon_fetch::prepare_out_dir(out, "--vcon-audio-fetch-out")
        .map_err(|e| one(BAD_SETTINGS, e))?;
    let max_size = args
        .vcon_audio_fetch_max_size
        .unwrap_or(crate::config::FETCH_MAX_SIZE.default);
    let max_size = usize::try_from(max_size).unwrap_or(usize::MAX);

    let shown = input.display();
    let bytes = crate::app::vcon_resign::read_capped(
        input,
        crate::capture::vcon_input::MAX_CONTAINER_BYTES,
    )
    .map_err(|e| one(REFUSED, e))?;
    let (container, _) = crate::capture::vcon_input::open_bytes(&bytes)
        .map_err(|e| one(REFUSED, format!("'{shown}': {e}")))?;
    let uuid = container
        .get("uuid")
        .and_then(|u| u.as_str())
        .filter(|u| crate::app::vcon_forward::is_path_uuid(u))
        .ok_or_else(|| {
            one(
                REFUSED,
                format!("'{shown}': the vCon has no uuid to name a file by"),
            )
        })?
        .to_owned();
    let recordings = url_recordings(&container);
    if recordings.is_empty() {
        return Err(one(
            REFUSED,
            format!("'{shown}': no recording in the vCon names a url"),
        ));
    }
    let mut written = Vec::new();
    let mut refused = Vec::new();
    for recording in &recordings {
        match fetch_one(recording, &uuid, out, &source, max_size, &opener) {
            Ok(path) => written.push(path),
            Err(why) => refused.push(format!("dialog {}: {why}", recording.index)),
        }
    }
    if refused.is_empty() {
        Ok(written)
    } else {
        Err((REFUSED, refused))
    }
}

/// Read, check, decrypt and write one recording.
fn fetch_one(
    recording: &UrlRecording,
    uuid: &str,
    out: &Path,
    source: &Source,
    max_size: usize,
    opener: &crate::output::vcon_jose::Opener,
) -> Result<PathBuf, String> {
    let url = &recording.url;
    let mediatype = recording
        .mediatype
        .as_deref()
        .ok_or("names no mediatype, so sipnab cannot tell what audio it is")?;
    let extension = extension_for(mediatype).ok_or_else(|| {
        format!("mediatype {mediatype:?} is not audio sipnab writes (audio/x-wav, audio/ogg)")
    })?;
    let path = out.join(format!("{uuid}-dialog{}.{extension}", recording.index));
    if std::fs::symlink_metadata(&path).is_ok() {
        return Err(format!(
            "'{}' exists; sipnab never replaces it: name a new directory",
            path.display()
        ));
    }
    let body = match source {
        Source::Local(dir) => {
            let file = dir.join(local_name(url)?);
            crate::app::vcon_resign::read_capped(&file, max_size as u64)?
        }
        Source::Https(tls) => {
            let endpoint =
                crate::app::vcon_forward::Endpoint::parse(url).map_err(|e| format!("url {e}"))?;
            if !endpoint.tls {
                return Err(format!(
                    "url {url:?} is not https://, and draft-ietf-vcon-vcon-core-04 section \
                     2.4.1 says \"HTTPS MUST be used for retrieval\"; nothing was fetched"
                ));
            }
            crate::app::vcon_fetch::get_body(
                &endpoint,
                Duration::from_secs(crate::config::FETCH_TIMEOUT.default),
                tls,
                crate::app::vcon_fetch::FetchLimits {
                    response_head: usize::try_from(crate::config::FETCH_MAX_RESPONSE_HEAD.default)
                        .unwrap_or(usize::MAX),
                    max_size,
                },
                "--vcon-audio-fetch-max-size",
            )?
        }
    };
    check_content_hash(&body, recording.content_hash.as_deref())
        .map_err(|e| format!("{url}: {e}; nothing was written"))?;
    let audio = audio_of(&body, mediatype, extension, opener)
        .map_err(|e| format!("{url}: {e}; nothing was written"))?;
    crate::app::vcon_fetch::write_private(&path, &audio, false).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            format!(
                "'{}' exists; sipnab never replaces it: name a new directory",
                path.display()
            )
        } else {
            format!("cannot write '{}': {e}", path.display())
        }
    })?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn url_recordings_lists_only_recordings_with_a_url() {
        let c = json!({"dialog": [
            {"type": "text", "url": "https://a/x.txt"},
            {"type": "recording", "body": "AAAA"},
            {"type": "recording", "url": "https://a/b.wav", "content_hash": "sha512-x", "mediatype": "audio/x-wav"},
        ]});
        assert_eq!(
            url_recordings(&c),
            vec![UrlRecording {
                index: 2,
                url: "https://a/b.wav".into(),
                content_hash: Some("sha512-x".into()),
                mediatype: Some("audio/x-wav".into()),
            }]
        );
        assert!(url_recordings(&json!({})).is_empty());
    }

    #[test]
    fn extension_for_names_wav_and_ogg_only() {
        assert_eq!(extension_for("audio/x-wav"), Some("wav"));
        assert_eq!(extension_for("audio/WAV"), Some("wav"));
        assert_eq!(extension_for("audio/ogg"), Some("ogg"));
        assert_eq!(extension_for("video/mp4"), None);
    }

    #[test]
    fn check_content_hash_needs_the_file_s_sha512() {
        let token = crate::app::vcon_hash::token(b"audio");
        assert!(check_content_hash(b"audio", Some(&token)).is_ok());
        assert!(check_content_hash(b"audio!", Some(&token)).is_err());
        assert!(check_content_hash(b"audio", None).is_err());
        assert!(check_content_hash(b"audio", Some("sha256-abc")).is_err());
    }

    #[test]
    fn local_name_refuses_a_name_outside_the_directory() {
        assert_eq!(
            local_name("https://m/calls/ab-c_1.wav.jwe"),
            Ok("ab-c_1.wav.jwe")
        );
        assert_eq!(local_name("https://m/calls/a.wav?x=1"), Ok("a.wav"));
        for bad in [
            "https://m/calls/",
            "https://m/..",
            "https://m/.hidden",
            "https://m/a%2F..%2Fb",
        ] {
            assert!(local_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn audio_of_passes_a_wav_and_refuses_what_is_not_audio() {
        let opener = crate::output::vcon_jose::Opener::without_key();
        assert_eq!(
            audio_of(b"RIFF....WAVE", "audio/x-wav", "wav", &opener).ok(),
            Some(b"RIFF....WAVE".to_vec())
        );
        assert!(audio_of(b"OggS", "audio/x-wav", "wav", &opener).is_err());
        assert!(audio_of(b"OggS....", "audio/ogg", "ogg", &opener).is_ok());
    }

    #[test]
    fn audio_of_refuses_a_jwe_whose_cty_is_not_the_mediatype() {
        let opener = crate::output::vcon_jose::Opener::without_key();
        let jwe = json!({"ciphertext": "x", "recipients": [], "unprotected": {"cty": "audio/ogg"}});
        let err = audio_of(jwe.to_string().as_bytes(), "audio/x-wav", "wav", &opener)
            .err()
            .unwrap_or_default();
        assert!(err.contains("cty"), "{err}");
    }
}
