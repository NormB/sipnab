// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! One call's decoded RTP audio, written to a WAV file.
//!
//! The decode is [`crate::rtp::audio_export::decode_dialog_audio`]:
//! `GET /v1/dialogs/{call_id}/audio` serves its bytes, the MCP `export_audio`
//! tool writes them, and [`export_audio`] writes them for `--export-audio`,
//! through [`crate::rtp::audio_export::write_dialog_audio`], the same writer
//! and the same summary the tool's file gets. A Call-ID is found the way REST
//! finds it: by its streams, so a media-relay host that carries the streams
//! under the relay's Call-ID and never saw the dialog still exports them.

use std::path::{Path, PathBuf};

use crate::output::ReportFormat;
use crate::rtp::stream_store::StreamStore;
use crate::sip::dialog_store::DialogStore;

/// The written file and what it holds: the path and summary MCP's
/// `export_audio` answers with, and the facts REST sends as headers
/// (`sipnab-audio-partial`, `sipnab-dialog-seen`).
#[derive(Debug, Clone, serde::Serialize)]
pub struct AudioExport {
    /// Version of this answer's shape.
    pub schema_version: u32,
    /// Where the WAV was written.
    pub path: String,
    /// The export summary: the file, and every way it falls short of the
    /// call. The same text a note inside the WAV carries.
    pub summary: String,
    /// True when the file falls short of the call (a retention cap, a
    /// direction with no payload), as REST's `sipnab-audio-partial` says.
    pub partial: bool,
    /// Whether the capture held the SIP dialog, or only its streams, as
    /// REST's `sipnab-dialog-seen` says.
    pub dialog_seen: bool,
    /// How long the file plays, in seconds.
    pub duration_secs: f64,
    /// Samples per second per channel.
    pub sample_rate: u32,
    /// 1 for mono, 2 for stereo.
    pub channels: u16,
    /// The file's size in bytes.
    pub bytes: usize,
}

/// Where `--export-audio` writes `call_id`'s WAV when no path is named: the
/// filename REST offers in its `Content-Disposition`, in the current
/// directory.
#[must_use]
pub fn default_path(call_id: &str) -> PathBuf {
    PathBuf::from(format!(
        "{}.wav",
        crate::rtp::audio_export::wav_filename_stem(call_id)
    ))
}

/// Decode `call_id`'s audio and write it to `path`, which must not exist.
///
/// # Errors
///
/// The message REST's 404 carries when neither store holds `call_id`; the
/// decoder's when nothing in the call can be decoded (REST's 422); and the
/// open's or the write's, an existing file among them, which is never
/// replaced.
pub fn export_audio(
    ds: &DialogStore,
    ss: &StreamStore,
    call_id: &str,
    path: &Path,
) -> Result<AudioExport, String> {
    let streams: Vec<&crate::rtp::stream::RtpStream> = ss.streams_for(call_id).collect();
    let dialog_seen = ds.get(call_id).is_some();
    if !dialog_seen && streams.is_empty() {
        return Err(crate::rtp::stream_store::call_not_carried(call_id));
    }
    let audio =
        crate::rtp::audio_export::decode_dialog_audio(&streams).map_err(|e| e.to_string())?;
    let summary = crate::rtp::audio_export::write_dialog_audio(
        &audio,
        path,
        crate::new_file::CreateMode::NewOnly,
    )
    .map_err(|e| format!("{e:#}"))?;
    Ok(AudioExport {
        schema_version: 1,
        path: path.display().to_string(),
        summary,
        partial: !audio.partial.is_empty(),
        dialog_seen,
        duration_secs: audio.duration_secs,
        sample_rate: audio.sample_rate,
        channels: audio.channels,
        bytes: audio.wav.len(),
    })
}

/// The export as text: the summary line, then where a capture held only
/// the call's streams and not its dialog, a line saying so.
#[must_use]
pub fn render(answer: &AudioExport, _format: ReportFormat) -> String {
    let mut out = format!("{}\n", super::clean(&answer.summary));
    if !answer.dialog_seen {
        out.push_str("The capture holds this call's RTP streams but not its SIP dialog.\n");
    }
    out
}
