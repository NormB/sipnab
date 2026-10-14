// SPDX-License-Identifier: MIT OR Apache-2.0

//! Certificate chains for a vCon signer: a root CA, an intermediate it
//! issued, and a signing certificate the intermediate issued for the
//! fixture RSA key `tests/fixtures/vcon-jose/fake_grp.key`. Each call makes
//! a fresh chain, so two calls give two CAs that do not trust each other.
//!
//! Included with `#[path]`.
#![allow(dead_code)]

/// One chain, as PEM text.
pub struct SignerPki {
    /// The root CA certificate.
    pub ca: String,
    /// The signing certificate, then the intermediate: what a signing rule's
    /// `sign_cert` holds.
    pub chain: String,
    /// The DER of the signing certificate.
    pub leaf_der: Vec<u8>,
}

/// A fresh chain whose certificates name `name`.
pub fn signer_pki(name: &str) -> Result<SignerPki, Box<dyn std::error::Error>> {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
    let ca_params = |cn: String| {
        let mut p = CertificateParams::default();
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.distinguished_name.push(DnType::CommonName, cn);
        p
    };
    let root_key = KeyPair::generate()?;
    let root_params = ca_params(format!("{name} test root"));
    let root = root_params.self_signed(&root_key)?;
    let mid_key = KeyPair::generate()?;
    let mid_params = ca_params(format!("{name} test intermediate"));
    let mid = mid_params.signed_by(&mid_key, &Issuer::new(root_params, &root_key))?;
    let leaf_key = KeyPair::from_pem(&std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/vcon-jose/fake_grp.key"
    ))?)?;
    let mut leaf_params = CertificateParams::default();
    leaf_params.is_ca = IsCa::ExplicitNoCa;
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, format!("{name} test signer"));
    let leaf = leaf_params.signed_by(&leaf_key, &Issuer::new(mid_params, &mid_key))?;
    Ok(SignerPki {
        ca: root.pem(),
        chain: format!("{}{}", leaf.pem(), mid.pem()),
        leaf_der: leaf.der().to_vec(),
    })
}
