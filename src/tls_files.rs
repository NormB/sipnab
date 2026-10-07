// SPDX-License-Identifier: MIT OR Apache-2.0

//! Server-side TLS material shared by the listeners that terminate TLS
//! themselves: the HEP listener (`--hep-listen-transport tls`), the REST API
//! (`--api-tls-cert` / `--api-tls-key`), MCP over HTTP (`--mcp-tls-cert` /
//! `--mcp-tls-key`) and the metrics endpoint (`--metrics-tls-cert` /
//! `--metrics-tls-key`).
//!
//! One reader for a PEM certificate chain, one for a private key (refusing a
//! world-readable one), and one builder for a `rustls` server configuration,
//! so the listeners cannot drift apart on what they accept. Each caller
//! names its own surface (`"HEP TLS"`, `"API TLS"`, `"MCP TLS"`,
//! `"metrics TLS"`) so an error says which flags to look at.
//!
//! The vCon forwarder (`--vcon-forward`) is the one TLS client here: it reads
//! a CA file or the host's bundle with the same readers, through
//! [`host_ca_bundle`] and [`pem_certificates`].
//!
//! Named `tls_files` rather than `tls` because `tls` is the Cargo feature for
//! capture-side decryption, which this has nothing to do with.

use anyhow::{Context, Result, ensure};

/// The crypto provider every TLS configuration sipnab builds is based on.
///
/// Named explicitly rather than taken from the process default, which
/// `ClientConfig::builder()` panics on when no provider is installed. A capture
/// tool must not abort a run inside a builder.
pub(crate) fn provider() -> std::sync::Arc<rustls::crypto::CryptoProvider> {
    std::sync::Arc::new(rustls::crypto::ring::default_provider())
}

/// CA bundles a host may keep, tried in order when no CA file is named
/// (`--hep-tls-ca`, `--vcon-forward-ca`).
///
/// Reading the host's own bundle rather than compiling Mozilla's list in has
/// two consequences worth stating: an operator who adds their collector's
/// issuer to the system store does not also have to name it here, and a host
/// whose bundle sipnab cannot find is told to pass a CA file rather than
/// silently trusting nothing.
#[cfg(any(feature = "hep", feature = "vcon"))]
const SYSTEM_CA_BUNDLES: &[&str] = &[
    // Debian, Ubuntu, Arch
    "/etc/ssl/certs/ca-certificates.crt",
    // RHEL, Fedora, CentOS
    "/etc/pki/tls/certs/ca-bundle.crt",
    // openSUSE
    "/etc/ssl/ca-bundle.pem",
    // Alpine, and the OpenSSL default on the BSDs
    "/etc/ssl/cert.pem",
    // Homebrew's OpenSSL on macOS
    "/opt/homebrew/etc/openssl@3/cert.pem",
];

/// The host's CA bundle: `$SSL_CERT_FILE` if it names a file, else the first
/// of [`SYSTEM_CA_BUNDLES`] that exists, else `None`.
#[cfg(any(feature = "hep", feature = "vcon"))]
pub(crate) fn host_ca_bundle() -> Option<std::path::PathBuf> {
    std::env::var_os("SSL_CERT_FILE")
        .map(std::path::PathBuf::from)
        .filter(|p| p.is_file())
        .or_else(|| {
            SYSTEM_CA_BUNDLES
                .iter()
                .map(std::path::PathBuf::from)
                .find(|p| p.is_file())
        })
}

/// A `rustls` server configuration presenting the chain in `cert` with the
/// key in `key`.
///
/// Protocol versions are rustls's safe defaults, TLS 1.2 and TLS 1.3; no
/// client certificate is asked for.
///
/// # Arguments
///
/// * `cert` — PEM certificate chain, the leaf first.
/// * `key` — PEM private key for the leaf; refused when world-readable.
/// * `surface` — the listener being configured (`"HEP TLS"`, `"API TLS"`),
///   named in every error.
/// * `alpn` — the application protocols to offer, in preference order; empty
///   for none.
///
/// # Errors
///
/// Either file is unreadable, the certificate file holds no certificate, the
/// key file holds no private key or is world-readable, or the key is not the
/// certificate's (rustls checks the pair).
///
/// # Side effects
///
/// Reads and stats both files.
#[cfg(any(feature = "hep", feature = "api", feature = "metrics"))]
pub(crate) fn server_config(
    cert: &std::path::Path,
    key: &std::path::Path,
    surface: &str,
    alpn: Vec<Vec<u8>>,
) -> Result<std::sync::Arc<rustls::ServerConfig>> {
    let chain = pem_certificates(cert)?;
    let private = pem_private_key(key, surface)?;
    let mut config = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .with_context(|| format!("{surface} listener: no usable protocol versions"))?
        .with_no_client_auth()
        .with_single_cert(chain, private)
        .with_context(|| {
            format!(
                "{surface} listener: {} does not go with {}",
                cert.display(),
                key.display()
            )
        })?;
    config.alpn_protocols = alpn;
    Ok(std::sync::Arc::new(config))
}

/// Every `-----BEGIN <label>-----` block in a PEM file, as `(label, DER)`.
///
/// Written here rather than pulled in as a dependency because it is thirty
/// lines of base64 between two markers, and because the alternative that also
/// supplies the public trust roots — `webpki-roots` — is CDLA-Permissive-2.0,
/// which is not on `deny.toml`'s allow list. The HEP sender reads the host's
/// own CA bundle instead (`hep_tls_roots` in the HEP module).
///
/// # Arguments
///
/// * `pem` — the file's bytes.
///
/// # Errors
///
/// A block whose base64 body does not decode. A stray `BEGIN` with no `END` is
/// discarded rather than refused: a CA bundle routinely carries comments and
/// human-readable certificate dumps between its blocks.
pub(crate) fn pem_blocks(pem: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    use base64::Engine;
    let text = String::from_utf8_lossy(pem);
    let mut out = Vec::new();
    let mut label: Option<String> = None;
    let mut body = String::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("-----BEGIN ") {
            label = rest.strip_suffix("-----").map(str::to_string);
            body.clear();
            continue;
        }
        if let Some(rest) = line.strip_prefix("-----END ") {
            let ending = rest.strip_suffix("-----").unwrap_or_default();
            if let Some(open) = label.take()
                && open == ending
            {
                let der = base64::engine::general_purpose::STANDARD
                    .decode(body.as_bytes())
                    .with_context(|| format!("PEM block '{open}' is not valid base64"))?;
                out.push((open, der));
            }
            body.clear();
            continue;
        }
        if label.is_some() {
            body.push_str(line);
        }
    }
    Ok(out)
}

/// The certificates in a PEM file, in file order.
///
/// # Errors
///
/// The file cannot be read, a block does not decode, or it holds no
/// certificate at all. The last is deliberately an error rather than an empty
/// list: an empty chain and an empty trust store both "work" and then refuse
/// every peer, which reads as a broken far end rather than a typo in a path.
pub(crate) fn pem_certificates(
    path: &std::path::Path,
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let pem = std::fs::read(path).with_context(|| format!("{}", path.display()))?;
    let certs: Vec<_> = pem_blocks(&pem)
        .with_context(|| format!("{}", path.display()))?
        .into_iter()
        .filter(|(label, _)| label == "CERTIFICATE" || label == "X509 CERTIFICATE")
        .map(|(_, der)| rustls::pki_types::CertificateDer::from(der))
        .collect();
    ensure!(
        !certs.is_empty(),
        "{}: no certificate in this file",
        path.display()
    );
    Ok(certs)
}

/// The first private key in a PEM file, refusing one any other user can read.
///
/// A key file the world can read is not a private key, and a tool that loads
/// it anyway lets the operator believe the listener is authenticated when any
/// local account can impersonate it. Group-readable is allowed on purpose:
/// `root:sipnab 0640` is how a key is normally handed to a service account.
///
/// # Arguments
///
/// * `path` — the key file.
/// * `surface` — the listener the key is for (`"HEP TLS"`, `"API TLS"`),
///   named in the world-readable refusal.
///
/// # Errors
///
/// The file cannot be read or stat'd, it is world-readable, it holds no
/// private key, or a block does not decode.
#[cfg(any(feature = "hep", feature = "api", feature = "metrics"))]
pub(crate) fn pem_private_key(
    path: &std::path::Path,
    surface: &str,
) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path).with_context(|| format!("{}", path.display()))?;
        let mode = meta.permissions().mode();
        ensure!(
            mode & 0o004 == 0,
            "{}: the {surface} private key is world-readable (mode {:04o}); chmod 600 it",
            path.display(),
            mode & 0o7777
        );
    }
    let pem = std::fs::read(path).with_context(|| format!("{}", path.display()))?;
    for (label, der) in pem_blocks(&pem).with_context(|| format!("{}", path.display()))? {
        let key = match label.as_str() {
            "PRIVATE KEY" => rustls::pki_types::PrivateKeyDer::Pkcs8(der.into()),
            "RSA PRIVATE KEY" => rustls::pki_types::PrivateKeyDer::Pkcs1(der.into()),
            "EC PRIVATE KEY" => rustls::pki_types::PrivateKeyDer::Sec1(der.into()),
            _ => continue,
        };
        return Ok(key);
    }
    anyhow::bail!(
        "{}: no PRIVATE KEY, RSA PRIVATE KEY or EC PRIVATE KEY block in this file",
        path.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A PEM block whose body is not base64 is refused, and the error names
    /// the block, so an operator knows which part of the file is corrupt.
    #[test]
    fn a_pem_block_that_is_not_base64_is_refused_by_name() {
        let pem = b"-----BEGIN CERTIFICATE-----\nnot*base64!\n-----END CERTIFICATE-----\n";
        let err = pem_blocks(pem).expect_err("an undecodable body must be refused");
        assert!(
            format!("{err:#}").contains("PEM block 'CERTIFICATE' is not valid base64"),
            "got: {err:#}"
        );
    }

    /// A `BEGIN` with no matching `END` is dropped, not refused: CA bundles
    /// carry comments and text dumps between blocks. The valid block after it
    /// still comes through.
    #[test]
    fn a_stray_begin_is_dropped_and_the_next_block_still_parses() {
        let pem = b"-----BEGIN NOTE-----\ntext\n-----BEGIN CERTIFICATE-----\nAAEC\n-----END CERTIFICATE-----\n";
        let blocks = pem_blocks(pem).expect("parses");
        assert_eq!(blocks, vec![("CERTIFICATE".to_string(), vec![0, 1, 2])]);
    }
}
