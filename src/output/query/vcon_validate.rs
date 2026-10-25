// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! A vCon container checked against the vendored schema.
//!
//! One answer, [`VconValidation`], built by [`validate_bytes`]:
//! `POST /v1/vcon/validate` serializes it and `--vcon-validate` prints it.
//! The check is [`crate::output::vcon_schema::validate`], which the MCP
//! `validate_vcon` tool also runs, after the readers' one step
//! ([`crate::capture::vcon_input::open_bytes`]) opens a signed or encrypted
//! container to the unsigned vCon inside.

use crate::output::ReportFormat;

/// One place a vCon container disagrees with the vendored schema.
#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct VconFinding {
    /// JSON Pointer to the offending value, `/dialog/2` shaped.
    pub instance_path: String,
    /// The schema keyword that refused it.
    pub keyword: String,
    /// What was wrong, in one sentence.
    pub detail: String,
}

/// The verdict on a vCon container checked against the vendored schema.
#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct VconValidation {
    /// Version of this response's shape.
    #[cfg_attr(feature = "api", schema(example = 2))]
    pub schema_version: u32,
    /// The one-word verdict: `valid` or `invalid`.
    pub verdict: String,
    /// The `$id` the vendored schema declares.
    pub schema_id: String,
    /// Where that schema lives in the repository.
    pub schema_path: String,
    /// Every finding. Empty on a clean pass.
    pub errors: Vec<VconFinding>,
}

/// Why a document could not be validated at all, as opposed to failing the
/// schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotValidated {
    /// The bytes are not JSON. REST answers 400.
    NotJson,
    /// The container could not be opened: a signature or an encryption the
    /// readers refuse. REST answers 422 with this message.
    Unopened(String),
    /// The JSON is not an object. REST answers 400.
    NotObject,
    /// A `critical` extension sipnab does not implement forbids reading it.
    /// REST answers 422.
    Critical(String),
}

impl std::fmt::Display for NotValidated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotJson => f.write_str("the body must be a JSON vCon container"),
            Self::Unopened(why) => f.write_str(why),
            Self::NotObject => f.write_str(
                "a vCon container is a JSON object; pass the container itself, not a \
                 string or array holding it",
            ),
            Self::Critical(why) => {
                write!(f, "sipnab must not validate this vCon container: {why}")
            }
        }
    }
}

/// Validate the container `bytes` hold. Needs the `vcon` feature, which
/// carries the vendored schema.
///
/// # Errors
///
/// [`NotValidated`] when the bytes cannot be validated: not JSON, a
/// container the readers will not open, JSON that is not an object, or a
/// `critical` extension sipnab does not implement.
#[cfg(feature = "vcon")]
pub fn validate_bytes(bytes: &[u8]) -> Result<VconValidation, NotValidated> {
    let container = match crate::capture::vcon_input::open_bytes(bytes) {
        Ok((container, _)) => container,
        Err(crate::capture::vcon_input::ContainerError::NotJson(_)) => {
            return Err(NotValidated::NotJson);
        }
        Err(e) => return Err(NotValidated::Unopened(e.to_string())),
    };
    if !container.is_object() {
        return Err(NotValidated::NotObject);
    }
    if let Some(why) = crate::capture::vcon_input::critical_refusal(&container) {
        return Err(NotValidated::Critical(why));
    }
    let report = crate::output::vcon_schema::validate(&container);
    Ok(VconValidation {
        // 2: the core-04 schema left nothing to excuse, so `deviations`,
        // `explanations` and the `valid-except-documented-deviation` verdict
        // are gone.
        schema_version: 2,
        verdict: report.verdict.as_str().to_string(),
        schema_id: report.schema_id.clone(),
        schema_path: report.schema_path.to_string(),
        errors: report
            .errors
            .iter()
            .map(|f| VconFinding {
                instance_path: f.instance_path.clone(),
                keyword: f.keyword.to_string(),
                detail: f.detail.clone(),
            })
            .collect(),
    })
}

/// The verdict as text: a line naming the document, the verdict and the
/// schema, then on an invalid document one row per finding.
#[must_use]
pub fn render(document: &str, answer: &VconValidation, format: ReportFormat) -> String {
    let document = super::clean(document);
    if answer.errors.is_empty() {
        return format!(
            "{document}: {} against {}\n",
            answer.verdict, answer.schema_id
        );
    }
    let mut out = format!(
        "{document}: {}: {} against {}\n",
        answer.verdict,
        super::plural(answer.errors.len() as u64, "finding"),
        answer.schema_id
    );
    let rows: Vec<Vec<String>> = answer
        .errors
        .iter()
        .map(|f| vec![f.instance_path.clone(), f.keyword.clone(), f.detail.clone()])
        .collect();
    out.push_str(&super::table(format, &["Path", "Keyword", "Detail"], &rows));
    out
}
