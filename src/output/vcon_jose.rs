// SPDX-License-Identifier: MIT OR Apache-2.0

//! The signed and encrypted forms of a vCon.
//!
//! [draft-ietf-vcon-vcon-core-04 section 5.3](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-5.3)
//! says a vCon "MUST be signed first using JWS ... then encrypted using JWE".
//! So an encrypted container is two layers:
//!
//! - the signed form ([section 5.2](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-5.2)):
//!   a General JWS JSON Serialization ([RFC 7515 section 7.2.1](https://www.rfc-editor.org/rfc/rfc7515.html#section-7.2.1))
//!   whose payload is the unsigned container, signed `RS256` with the
//!   signer's certificate chain in `x5c`;
//! - the encrypted form: a General JWE JSON Serialization
//!   ([RFC 7516 section 7.2.1](https://www.rfc-editor.org/rfc/rfc7516.html#section-7.2.1))
//!   whose plaintext is that signed form, with the content key encrypted
//!   `RSA-OAEP` to the recipient's certificate and the content encrypted
//!   `A256CBC-HS512`, the algorithms the draft names.
//!
//! Header placement, as core-04 sections 5.2, 5.2.2, 5.3.1 and 5.3.2 and its
//! Appendix C CDDL place them. RFC 7515 and RFC 7516 require the protected
//! and unprotected header names to be disjoint.
//!
//! - The signed layer protects `alg` alone and carries `x5c` and `uuid` in
//!   each signature's unprotected `header`, where section 5.2 requires `x5c`.
//!   The CDDL also lists `alg` in that `header`; sipnab keeps `alg` in the
//!   protected header, so the signature covers it, and does not repeat it.
//!   `x5c` outside the protected header is not covered by the signature. A
//!   changed `x5c` either fails verification, because the signature is
//!   checked with the key of the certificate it names, or names the key that
//!   made a new signature; which signer that is, the reader learns from the
//!   fingerprint the fetcher logs and checks with [`SignerTrust`].
//! - The encrypted layer carries `cty`, `enc` and `uuid` in the shared
//!   `unprotected` object (section 5.3.1) and `alg` in each recipient's
//!   `header` (section 5.3.2). Nothing is left to protect, so the
//!   `protected` member is absent and the additional authenticated data is
//!   empty ([RFC 7516 section 5.1](https://www.rfc-editor.org/rfc/rfc7516.html#section-5.1), step 14). `alg` and `enc` are each read
//!   from wherever they are and must be `RSA-OAEP` and `A256CBC-HS512`, so a
//!   changed value fails rather than selects another algorithm.
//!
//! sipnab 0.5.217 and 0.5.218 wrote `x5c` in the JWS protected header and
//! `alg` and `enc` in the JWE protected header; the draft's Appendix A.7
//! example repeats `enc` in all three JWE headers. Both still read: a name
//! repeated with the same value is accepted, and one repeated with
//! different values is refused.
//!
//! [`verify`] checks the signature against the first certificate in `x5c`. It
//! does not check who issued that certificate: that is a trust decision for
//! whoever reads the container, which [`SignerTrust`] makes for
//! [`Opener::open`].

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ring::rand::SecureRandom as _;
use rsa::pkcs8::{DecodePrivateKey as _, DecodePublicKey as _};
use rsa::traits::PublicKeyParts as _;

/// JWE key encryption, the value core-04 section 5.3.3 names.
pub const JWE_ALG: &str = "RSA-OAEP";
/// JWE content encryption, the value core-04 section 5.3.1 names.
pub const JWE_ENC: &str = "A256CBC-HS512";
/// JWS signature algorithm, the value core-04 section 5.2.2 names.
pub const JWS_ALG: &str = "RS256";
/// The `cty` of the encrypted form when the vCon inside is not compressed:
/// the first value [core-04 section 5.3.1](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-5.3.1)
/// names. The draft's Appendix A.7 example writes `application/vcon+json`,
/// which section 5.3.1 does not list; [`decrypt`] reads any `cty`.
pub const CONTENT_TYPE: &str = "application/vcon";
/// The `cty` of the encrypted form when the vCon inside is gzip compressed:
/// the second value core-04 section 5.3.1 names.
pub const CONTENT_TYPE_GZIP: &str = "application/vcon+gzip";
/// The first two bytes of every gzip member, ID1 and ID2
/// ([RFC 1952 section 2.3.1](https://www.rfc-editor.org/rfc/rfc1952.html#section-2.3.1)).
pub const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];
/// The smallest RSA modulus accepted for signing or encryption, in bits:
/// [NIST SP 800-57 Part 1 Rev. 5](https://doi.org/10.6028/NIST.SP.800-57pt1r5)
/// table 2 gives 2048 bits as the minimum after 2030 for 112-bit security.
pub const MIN_RSA_BITS: usize = 2048;

/// The DER of the `rsaEncryption` object identifier, 1.2.840.113549.1.1.1.
const RSA_ENCRYPTION_OID: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
];

/// Which of the three forms a container is in, by the members
/// [core-04 section 5.4](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-5.4)
/// says identify each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Form {
    /// `parties`, `dialog`, `analysis` or `attachments` at the top level.
    Unsigned,
    /// `payload` and `signatures`.
    Signed,
    /// `ciphertext` and `recipients`.
    Encrypted,
    /// None of those.
    Unknown,
}

/// The form `value` is in.
pub fn form_of(value: &serde_json::Value) -> Form {
    let has = |key: &str| value.get(key).is_some();
    if has("ciphertext") && has("recipients") {
        Form::Encrypted
    } else if has("payload") && has("signatures") {
        Form::Signed
    } else if ["parties", "dialog", "analysis", "attachments"]
        .iter()
        .any(|k| has(k))
    {
        Form::Unsigned
    } else {
        Form::Unknown
    }
}

/// Whether the vCon inside a signed container is compressed: core-04
/// [section 5.2](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-5.2)
/// lets the JWS payload hold the unsigned vCon or its gzip
/// ([RFC 1952](https://www.rfc-editor.org/rfc/rfc1952.html)), and
/// [section 6.2](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-6.2)
/// defines the gzip format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Compression {
    /// The payload is the unsigned vCon as it is.
    #[default]
    None,
    /// The payload is the gzip of the unsigned vCon, and the encrypted
    /// form's `cty` is [`CONTENT_TYPE_GZIP`].
    Gzip,
}

impl Compression {
    /// The names a configuration file writes: `none` and `gzip`.
    pub const NAMES: [&'static str; 2] = crate::config::VCON_COMPRESSIONS;

    /// The compression `name` names.
    ///
    /// # Errors
    ///
    /// A name other than `none` or `gzip`.
    pub fn parse(name: &str) -> Result<Self, String> {
        match name {
            "none" => Ok(Self::None),
            "gzip" => Ok(Self::Gzip),
            other => Err(format!(
                "compress {other:?}: the values are {:?} and {:?}",
                Self::NAMES[0],
                Self::NAMES[1]
            )),
        }
    }
}

/// The key and certificate chain a container is signed with.
pub struct Signer {
    /// The RSA private key the signature is made with.
    key: ring::signature::RsaKeyPair,
    /// The chain as `x5c` carries it: standard base64 DER, leaf first
    /// ([RFC 7515 section 4.1.6](https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.6)).
    x5c: Vec<String>,
}

impl Signer {
    /// A signer from a PEM RSA private key (`PRIVATE KEY` or `RSA PRIVATE
    /// KEY`) and a PEM certificate chain, leaf first. The leaf must be the
    /// key's own certificate.
    pub fn from_pem(key_pem: &str, chain_pem: &str) -> Result<Self, String> {
        let key = pem_blocks(key_pem)
            .into_iter()
            .find_map(|(label, der)| match label.as_str() {
                "PRIVATE KEY" => Some(ring::signature::RsaKeyPair::from_pkcs8(&der)),
                "RSA PRIVATE KEY" => Some(ring::signature::RsaKeyPair::from_der(&der)),
                _ => None,
            })
            .ok_or("the signing key file holds no PEM `PRIVATE KEY` or `RSA PRIVATE KEY`")?
            .map_err(|e| {
                format!(
                    "the signing key is not an RSA key of {MIN_RSA_BITS} to 8192 bits that can sign: {e}"
                )
            })?;
        let chain = certificates(chain_pem);
        let leaf = chain
            .first()
            .ok_or("the signing certificate file holds no certificate (PEM `CERTIFICATE`)")?;
        if rsa_public_key(subject_public_key_info(leaf)?)? != key.public().as_ref() {
            return Err(
                "the signing certificate (the first in its file) does not match the signing key"
                    .into(),
            );
        }
        Ok(Self {
            key,
            x5c: chain.iter().map(|der| STANDARD.encode(der)).collect(),
        })
    }

    /// The `RS256` signature (RSASSA-PKCS1-v1_5 with SHA-256) over `input`.
    pub fn rs256(&self, input: &[u8]) -> Result<Vec<u8>, String> {
        let mut signature = vec![0; self.key.public().modulus_len()];
        self.key
            .sign(
                &ring::signature::RSA_PKCS1_SHA256,
                &ring::rand::SystemRandom::new(),
                input,
                &mut signature,
            )
            .map_err(|_| "RS256 signing failed".to_owned())?;
        Ok(signature)
    }
}

/// The certificate a container is encrypted to.
pub struct Recipient {
    /// The RSA public key the content key is encrypted to.
    key: rsa::RsaPublicKey,
}

impl Recipient {
    /// A recipient from a PEM certificate: the first `CERTIFICATE` in `pem`,
    /// which must carry an RSA key of at least [`MIN_RSA_BITS`].
    pub fn from_cert_pem(pem: &str) -> Result<Self, String> {
        let certificates = certificates(pem);
        let leaf = certificates
            .first()
            .ok_or("the recipient file holds no certificate (PEM `CERTIFICATE`)")?;
        let spki = subject_public_key_info(leaf)?;
        rsa_public_key(spki)?;
        let key = rsa::RsaPublicKey::from_public_key_der(spki)
            .map_err(|e| format!("the recipient certificate's RSA key does not parse: {e}"))?;
        let bits = key.size().saturating_mul(8);
        if bits < MIN_RSA_BITS {
            return Err(format!(
                "the recipient certificate's RSA key is {bits} bits; at least {MIN_RSA_BITS} are required"
            ));
        }
        Ok(Self { key })
    }
}

/// `A256CBC-HS512` encryption ([RFC 7518 section 5.2.5](https://www.rfc-editor.org/rfc/rfc7518.html#section-5.2.5)):
/// AES-256-CBC with PKCS #7 padding under the second half of `key`, and the
/// first 32 bytes of HMAC-SHA-512 under the first half over the AAD, the IV,
/// the ciphertext and the AAD's length in bits.
pub fn a256cbc_hs512_seal(
    key: &[u8; 64],
    iv: &[u8; 16],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 32]), String> {
    use cbc::cipher::{BlockModeEncrypt as _, KeyIvInit as _};
    use hmac::Mac as _;
    let (mac_key, enc_key) = key.split_at(32);
    let ciphertext = cbc::Encryptor::<aes::Aes256>::new_from_slices(enc_key, iv)
        .map_err(|e| format!("AES-256-CBC key: {e}"))?
        .encrypt_padded_vec::<cbc::cipher::block_padding::Pkcs7>(plaintext);
    let mac = cbc_hs512_mac(mac_key, iv, aad, &ciphertext)?;
    let mut tag = [0; 32];
    tag.copy_from_slice(&mac.finalize().into_bytes()[..32]);
    Ok((ciphertext, tag))
}

/// `A256CBC-HS512` decryption: the tag is checked, in constant time, before
/// anything is decrypted.
pub fn a256cbc_hs512_open(
    key: &[u8; 64],
    iv: &[u8; 16],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 32],
) -> Result<Vec<u8>, String> {
    use cbc::cipher::{BlockModeDecrypt as _, KeyIvInit as _};
    use hmac::Mac as _;
    let (mac_key, enc_key) = key.split_at(32);
    cbc_hs512_mac(mac_key, iv, aad, ciphertext)?
        .verify_truncated_left(tag)
        .map_err(|_| "the authentication tag does not match".to_owned())?;
    let mut buf = ciphertext.to_vec();
    let plaintext = cbc::Decryptor::<aes::Aes256>::new_from_slices(enc_key, iv)
        .map_err(|e| format!("AES-256-CBC key: {e}"))?
        .decrypt_padded::<cbc::cipher::block_padding::Pkcs7>(&mut buf)
        .map_err(|e| format!("AES-256-CBC: {e}"))?;
    Ok(plaintext.to_vec())
}

/// The HMAC-SHA-512 of [RFC 7518 section 5.2.2.1](https://www.rfc-editor.org/rfc/rfc7518.html#section-5.2.2.1), before truncation.
fn cbc_hs512_mac(
    mac_key: &[u8],
    iv: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<hmac::Hmac<sha2::Sha512>, String> {
    use hmac::{KeyInit as _, Mac as _};
    let aad_bits = u64::try_from(aad.len())
        .ok()
        .and_then(|n| n.checked_mul(8))
        .ok_or("the AAD is too long")?;
    let mut mac = hmac::Hmac::<sha2::Sha512>::new_from_slice(mac_key)
        .map_err(|e| format!("HMAC-SHA-512 key: {e}"))?;
    mac.update(aad);
    mac.update(iv);
    mac.update(ciphertext);
    mac.update(&aad_bits.to_be_bytes());
    Ok(mac)
}

/// The signed form of `unsigned`: a General JWS JSON Serialization.
pub fn sign(unsigned: &[u8], uuid: &str, signer: &Signer) -> Result<Vec<u8>, String> {
    let protected = URL_SAFE_NO_PAD.encode(serde_json::json!({ "alg": JWS_ALG }).to_string());
    let payload = URL_SAFE_NO_PAD.encode(unsigned);
    let signature = signer.rs256(format!("{protected}.{payload}").as_bytes())?;
    serde_json::to_vec(&serde_json::json!({
        "payload": payload,
        "signatures": [{
            "protected": protected,
            "header": { "x5c": signer.x5c, "uuid": uuid },
            "signature": URL_SAFE_NO_PAD.encode(signature),
        }],
    }))
    .map_err(|e| format!("the signed form: {e}"))
}

/// [`sign`], with the payload compressed as `compression` says: the
/// signature covers the payload as written, so it covers the gzip.
pub fn sign_compressed(
    unsigned: &[u8],
    uuid: &str,
    signer: &Signer,
    compression: Compression,
) -> Result<Vec<u8>, String> {
    match compression {
        Compression::None => sign(unsigned, uuid, signer),
        Compression::Gzip => {
            use std::io::Write as _;
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            encoder
                .write_all(unsigned)
                .map_err(|e| format!("gzip: {e}"))?;
            let packed = encoder.finish().map_err(|e| format!("gzip: {e}"))?;
            sign(&packed, uuid, signer)
        }
    }
}

/// The encrypted form of `signed`: a General JWE JSON Serialization with a
/// fresh content key and IV.
pub fn encrypt(signed: &[u8], uuid: &str, recipient: &Recipient) -> Result<Vec<u8>, String> {
    encrypt_compressed(signed, uuid, recipient, Compression::None)
}

/// [`encrypt`], with the `cty` that says whether the vCon inside `signed` is
/// compressed.
pub fn encrypt_compressed(
    signed: &[u8],
    uuid: &str,
    recipient: &Recipient,
    compression: Compression,
) -> Result<Vec<u8>, String> {
    let cty = match compression {
        Compression::None => CONTENT_TYPE,
        Compression::Gzip => CONTENT_TYPE_GZIP,
    };
    // core-04 sections 5.3.1 and 5.3.2: `cty`, `enc` and `uuid` shared and
    // unprotected, `alg` in the recipient's header. Nothing is protected, so
    // the `protected` member is absent (RFC 7516 section 7.2.1).
    let headers = JweHeaders {
        protected: None,
        unprotected: serde_json::json!({ "cty": cty, "enc": JWE_ENC, "uuid": uuid }),
        recipient: Some(serde_json::json!({ "alg": JWE_ALG })),
    };
    encrypt_under(signed, recipient, &headers)
}

/// The three header places of a General JWE JSON Serialization
/// ([RFC 7516 section 7.2.1](https://www.rfc-editor.org/rfc/rfc7516.html#section-7.2.1)).
struct JweHeaders {
    /// The JWE Protected Header; `None` writes no `protected` member, and
    /// the additional authenticated data is then empty.
    protected: Option<serde_json::Value>,
    /// The shared `unprotected` header.
    unprotected: serde_json::Value,
    /// The one recipient's `header`; `None` writes none.
    recipient: Option<serde_json::Value>,
}

/// Encrypt `signed` to `recipient` with `headers`, a fresh content key and
/// IV.
fn encrypt_under(
    signed: &[u8],
    recipient: &Recipient,
    headers: &JweHeaders,
) -> Result<Vec<u8>, String> {
    let random = ring::rand::SystemRandom::new();
    let fresh = || "the system random source failed".to_owned();
    let cek: [u8; 64] = ring::rand::generate(&random).map_err(|_| fresh())?.expose();
    let iv: [u8; 16] = ring::rand::generate(&random).map_err(|_| fresh())?.expose();
    let protected = headers
        .protected
        .as_ref()
        .map(|h| URL_SAFE_NO_PAD.encode(h.to_string()));
    let aad = protected.clone().unwrap_or_default();
    let (ciphertext, tag) = a256cbc_hs512_seal(&cek, &iv, aad.as_bytes(), signed)?;
    let mut seed = Prefilled::new(&random)?;
    let encrypted_key = recipient
        .key
        .encrypt(&mut seed, rsa::Oaep::new::<sha1_oaep::Sha1>(), &cek)
        .map_err(|e| format!("RSA-OAEP: {e}"))?;
    seed.finish()?;
    let mut one = serde_json::Map::new();
    if let Some(header) = &headers.recipient {
        one.insert("header".into(), header.clone());
    }
    one.insert(
        "encrypted_key".into(),
        URL_SAFE_NO_PAD.encode(encrypted_key).into(),
    );
    let mut jwe = serde_json::Map::new();
    if let Some(protected) = protected {
        jwe.insert("protected".into(), protected.into());
    }
    jwe.insert("unprotected".into(), headers.unprotected.clone());
    jwe.insert(
        "recipients".into(),
        vec![serde_json::Value::Object(one)].into(),
    );
    jwe.insert("iv".into(), URL_SAFE_NO_PAD.encode(iv).into());
    jwe.insert(
        "ciphertext".into(),
        URL_SAFE_NO_PAD.encode(ciphertext).into(),
    );
    jwe.insert("tag".into(), URL_SAFE_NO_PAD.encode(tag).into());
    serde_json::to_vec(&jwe).map_err(|e| format!("the encrypted form: {e}"))
}

/// Sign `unsigned`, then encrypt the signed form to `recipient`: the
/// encrypted form core-04 section 5.3 defines.
pub fn seal(
    unsigned: &[u8],
    uuid: &str,
    signer: &Signer,
    recipient: &Recipient,
) -> Result<Vec<u8>, String> {
    encrypt(&sign(unsigned, uuid, signer)?, uuid, recipient)
}

/// The plaintext of an encrypted container, which core-04 makes the signed
/// form, decrypted with the PEM RSA private key `key_pem`. Every recipient is
/// tried. When the container's unprotected `uuid` and the signed form's
/// `uuid` are both present they must agree.
pub fn decrypt(jwe: &[u8], key_pem: &str) -> Result<Vec<u8>, String> {
    let value: serde_json::Value =
        serde_json::from_slice(jwe).map_err(|e| format!("not JSON: {e}"))?;
    if form_of(&value) != Form::Encrypted {
        return Err("not an encrypted vCon: it has no `ciphertext` and `recipients`".into());
    }
    let key = private_key(key_pem)?;
    let protected_b64 = value
        .get("protected")
        .and_then(|p| p.as_str())
        .unwrap_or("");
    let protected = decode_header(protected_b64)?;
    let recipients = value["recipients"]
        .as_array()
        .ok_or("`recipients` is not an array")?;
    let iv: [u8; 16] = b64u_field(&value, "iv")?
        .try_into()
        .map_err(|_| "`iv` is not 16 bytes".to_owned())?;
    let tag: [u8; 32] = b64u_field(&value, "tag")?
        .try_into()
        .map_err(|_| "`tag` is not 32 bytes".to_owned())?;
    let ciphertext = b64u_field(&value, "ciphertext")?;
    let aad = match value.get("aad").and_then(|a| a.as_str()) {
        Some(extra) => format!("{protected_b64}.{extra}"),
        None => protected_b64.to_owned(),
    };
    // sipnab compresses inside the signed form, as core-04 section 5.2
    // says, and never writes a JWE `zip` (RFC 7516 section 4.1.3).
    if protected.get("zip").is_some()
        || value["unprotected"].get("zip").is_some()
        || recipients.iter().any(|r| r["header"].get("zip").is_some())
    {
        return Err(
            "the container has a JWE `zip` header; sipnab reads a vCon compressed inside \
             the signed form (draft-ietf-vcon-vcon-core-04 section 5.2), not with `zip`"
                .into(),
        );
    }
    let mut last = "the container has no recipients".to_owned();
    for recipient in recipients {
        let headers = [&protected, &value["unprotected"], &recipient["header"]];
        let alg = one_header(&headers, "alg")?;
        let enc = one_header(&headers, "enc")?;
        if alg.as_deref() != Some(JWE_ALG) || enc.as_deref() != Some(JWE_ENC) {
            last = format!(
                "a recipient uses alg {alg:?} and enc {enc:?}; sipnab reads {JWE_ALG} with {JWE_ENC}"
            );
            continue;
        }
        let Ok(cek) = key.decrypt(
            rsa::Oaep::new::<sha1_oaep::Sha1>(),
            &b64u_field(recipient, "encrypted_key")?,
        ) else {
            last = "no recipient's content key opens with this private key".into();
            continue;
        };
        let cek: [u8; 64] = cek
            .try_into()
            .map_err(|_| "the content key is not 64 bytes".to_owned())?;
        let plaintext = a256cbc_hs512_open(&cek, &iv, aad.as_bytes(), &ciphertext, &tag)?;
        check_uuid(value["unprotected"].get("uuid"), &plaintext)?;
        return Ok(plaintext);
    }
    Err(last)
}

/// The unprotected `uuid`, when present, is the uuid of the vCon inside.
fn check_uuid(outer: Option<&serde_json::Value>, signed: &[u8]) -> Result<(), String> {
    let Some(outer) = outer.and_then(|u| u.as_str()) else {
        return Ok(());
    };
    let inner: serde_json::Value =
        serde_json::from_slice(signed).map_err(|e| format!("the plaintext is not JSON: {e}"))?;
    let named = inner["signatures"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|s| s["header"]["uuid"].as_str());
    match named.into_iter().find(|u| *u != outer) {
        Some(inner) => Err(format!(
            "the container says uuid {outer} outside and {inner} inside"
        )),
        None => Ok(()),
    }
}

/// The unsigned container inside a signed one, once every signature verifies
/// as `RS256` against the first certificate of its `x5c`. A gzip payload is
/// inflated, up to the `--vcon-fetch-max-size` default ([`verify_capped`]).
pub fn verify(jws: &[u8]) -> Result<Vec<u8>, String> {
    let cap = usize::try_from(crate::config::FETCH_MAX_SIZE.default).unwrap_or(usize::MAX);
    verify_capped(jws, cap)
}

/// [`verify`], refusing a gzip payload that inflates to more than
/// `max_unsigned` bytes. The inflation stops there, so a small payload that
/// would inflate to far more is refused without the larger vCon ever being
/// held.
pub fn verify_capped(jws: &[u8], max_unsigned: usize) -> Result<Vec<u8>, String> {
    verify_with_signer(jws, max_unsigned).map(|(unsigned, _)| unsigned)
}

/// The gzip member ([RFC 1952](https://www.rfc-editor.org/rfc/rfc1952.html))
/// `source` holds, inflated, refused when it inflates to more than `cap`
/// bytes. At most `cap + 1` bytes are ever inflated, so a stream that
/// inflates without end is refused as soon as it passes `cap`.
pub fn gunzip_capped(source: impl std::io::Read, cap: usize) -> Result<Vec<u8>, String> {
    use std::io::Read as _;
    let limit = u64::try_from(cap).unwrap_or(u64::MAX).saturating_add(1);
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(source)
        .take(limit)
        .read_to_end(&mut out)
        .map_err(|e| format!("the gzip payload does not inflate: {e}"))?;
    if out.len() > cap {
        return Err(format!(
            "the gzip payload inflates to more than {cap} bytes, the limit"
        ));
    }
    Ok(out)
}

/// [`verify`], and the DER of the certificate the first signature verified
/// against.
fn verify_with_signer(jws: &[u8], max_unsigned: usize) -> Result<(Vec<u8>, Vec<Vec<u8>>), String> {
    let value: serde_json::Value =
        serde_json::from_slice(jws).map_err(|e| format!("not JSON: {e}"))?;
    if form_of(&value) != Form::Signed {
        return Err("not a signed vCon: it has no `payload` and `signatures`".into());
    }
    let payload_b64 = value["payload"]
        .as_str()
        .ok_or("`payload` is not a string")?;
    let signatures = value["signatures"]
        .as_array()
        .filter(|s| !s.is_empty())
        .ok_or("`signatures` is not a non-empty array")?;
    let mut signer: Option<Vec<Vec<u8>>> = None;
    for signature in signatures {
        let protected_b64 = signature
            .get("protected")
            .and_then(|p| p.as_str())
            .unwrap_or("");
        let protected = decode_header(protected_b64)?;
        let headers = [&protected, &signature["header"]];
        let alg = one_header(&headers, "alg")?;
        if alg.as_deref() != Some(JWS_ALG) {
            return Err(format!(
                "a signature uses alg {alg:?}; sipnab verifies {JWS_ALG}"
            ));
        }
        let placed: Vec<&serde_json::Value> = headers.iter().filter_map(|h| h.get("x5c")).collect();
        if placed.windows(2).any(|pair| pair[0] != pair[1]) {
            return Err(
                "header `x5c` is in the protected header and in `header` with different values"
                    .into(),
            );
        }
        let chain = placed
            .first()
            .and_then(|c| c.as_array())
            .filter(|c| !c.is_empty())
            .ok_or("a signature carries no `x5c` certificate")?
            .iter()
            .map(|c| {
                let text = c.as_str().ok_or("an `x5c` entry is not a string")?;
                STANDARD
                    .decode(text)
                    .map_err(|e| format!("`x5c` is not base64: {e}"))
            })
            .collect::<Result<Vec<Vec<u8>>, String>>()?;
        let leaf = chain
            .first()
            .ok_or("a signature carries no `x5c` certificate")?;
        let public = rsa_public_key(subject_public_key_info(leaf)?)?;
        ring::signature::UnparsedPublicKey::new(
            &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            public,
        )
        .verify(
            format!("{protected_b64}.{payload_b64}").as_bytes(),
            &b64u_field(signature, "signature")?,
        )
        .map_err(|_| "a signature does not verify against its certificate".to_owned())?;
        signer.get_or_insert(chain);
    }
    let payload = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| format!("`payload` is not base64url: {e}"))?;
    // core-04 section 5.2: the payload is the unsigned vCon or its gzip.
    // JSON never starts with the gzip magic, so the two bytes decide.
    let unsigned = if payload.starts_with(&GZIP_MAGIC) {
        gunzip_capped(payload.as_slice(), max_unsigned)?
    } else {
        payload
    };
    Ok((unsigned, signer.unwrap_or_default()))
}

/// A JOSE header that travels base64url-encoded; an absent one is empty.
fn decode_header(b64: &str) -> Result<serde_json::Value, String> {
    if b64.is_empty() {
        return Ok(serde_json::Value::Null);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(b64)
        .map_err(|e| format!("`protected` is not base64url: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("`protected` is not JSON: {e}"))
}

/// The one value `name` has across `headers`: refused when two disagree.
fn one_header(headers: &[&serde_json::Value], name: &str) -> Result<Option<String>, String> {
    let mut found: Option<String> = None;
    for value in headers.iter().filter_map(|h| h.get(name)) {
        let value = value
            .as_str()
            .ok_or_else(|| format!("header `{name}` is not a string"))?;
        match &found {
            Some(seen) if seen != value => {
                return Err(format!("header `{name}` is both {seen} and {value}"));
            }
            _ => found = Some(value.to_owned()),
        }
    }
    Ok(found)
}

/// The base64url member `name` of `value`, decoded.
fn b64u_field(value: &serde_json::Value, name: &str) -> Result<Vec<u8>, String> {
    let text = value[name]
        .as_str()
        .ok_or_else(|| format!("`{name}` is not a string"))?;
    URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|e| format!("`{name}` is not base64url: {e}"))
}

/// A PEM RSA private key, PKCS #8 or PKCS #1.
fn private_key(pem: &str) -> Result<rsa::RsaPrivateKey, String> {
    use rsa::pkcs1::DecodeRsaPrivateKey as _;
    rsa::RsaPrivateKey::from_pkcs8_pem(pem)
        .or_else(|_| rsa::RsaPrivateKey::from_pkcs1_pem(pem))
        .map_err(|e| format!("the private key is not a PEM RSA key: {e}"))
}

/// Every `-----BEGIN <label>-----` block in `text`, decoded.
fn pem_blocks(text: &str) -> Vec<(String, Vec<u8>)> {
    let mut blocks = Vec::new();
    let mut current: Option<(String, String)> = None;
    for line in text.lines().map(str::trim) {
        if let Some(label) = line
            .strip_prefix("-----BEGIN ")
            .and_then(|l| l.strip_suffix("-----"))
        {
            current = Some((label.to_owned(), String::new()));
        } else if line.starts_with("-----END ") {
            if let Some((label, body)) = current.take()
                && let Ok(der) = STANDARD.decode(body)
            {
                blocks.push((label, der));
            }
        } else if let Some((_, body)) = current.as_mut() {
            body.push_str(line);
        }
    }
    blocks
}

/// The DER of every `CERTIFICATE` block in `pem`, in file order.
fn certificates(pem: &str) -> Vec<Vec<u8>> {
    pem_blocks(pem)
        .into_iter()
        .filter(|(label, _)| label == "CERTIFICATE")
        .map(|(_, der)| der)
        .collect()
}

/// One DER element: its tag, its contents, the whole element, and what
/// follows it in the input.
type DerElement<'a> = (u8, &'a [u8], &'a [u8], &'a [u8]);

/// The DER element at the start of `input`.
fn der_element(input: &[u8]) -> Option<DerElement<'_>> {
    let tag = *input.first()?;
    let first = *input.get(1)?;
    let (len, header) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let count = usize::from(first & 0x7F);
        if count == 0 || count > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..count {
            len = (len << 8) | usize::from(*input.get(2 + i)?);
        }
        (len, 2 + count)
    };
    let end = header.checked_add(len)?;
    let whole = input.get(..end)?;
    Some((tag, whole.get(header..)?, whole, input.get(end..)?))
}

/// The SubjectPublicKeyInfo of a DER certificate
/// ([RFC 5280 section 4.1](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1)):
/// the seventh field of `tbsCertificate` when `version` is present.
fn subject_public_key_info(certificate: &[u8]) -> Result<&[u8], String> {
    const BAD: &str = "the certificate is not DER X.509";
    let (0x30, certificate, _, _) = der_element(certificate).ok_or(BAD)? else {
        return Err(BAD.into());
    };
    let (0x30, tbs, _, _) = der_element(certificate).ok_or(BAD)? else {
        return Err(BAD.into());
    };
    let mut rest = tbs;
    if rest.first() == Some(&0xA0) {
        rest = der_element(rest).ok_or(BAD)?.3;
    }
    // serialNumber, signature, issuer, validity, subject
    for _ in 0..5 {
        rest = der_element(rest).ok_or(BAD)?.3;
    }
    match der_element(rest) {
        Some((0x30, _, spki, _)) => Ok(spki),
        _ => Err(BAD.into()),
    }
}

/// The PKCS #1 `RSAPublicKey` inside an `rsaEncryption` SubjectPublicKeyInfo.
fn rsa_public_key(spki: &[u8]) -> Result<&[u8], String> {
    const NOT_RSA: &str = "the certificate's key is not an RSA key (rsaEncryption)";
    let (_, spki, _, _) = der_element(spki).ok_or(NOT_RSA)?;
    let (0x30, algorithm, _, rest) = der_element(spki).ok_or(NOT_RSA)? else {
        return Err(NOT_RSA.into());
    };
    if !algorithm.starts_with(RSA_ENCRYPTION_OID) {
        return Err(NOT_RSA.into());
    }
    match der_element(rest) {
        Some((0x03, [0, key @ ..], _, _)) => Ok(key),
        _ => Err(NOT_RSA.into()),
    }
}

/// Randomness drawn from the system source before RSA-OAEP runs, served to
/// the `rsa` crate's infallible `fill_bytes`. A draw past the end is recorded
/// and [`Prefilled::finish`] then refuses the result, so a short source never
/// passes silently.
struct Prefilled {
    /// The randomness drawn before the encryption.
    bytes: [u8; 128],
    /// How many of `bytes` have been served.
    used: usize,
    /// Whether a draw asked for more than `bytes` held.
    overrun: bool,
}

impl Prefilled {
    /// Draw the randomness from `random`.
    fn new(random: &ring::rand::SystemRandom) -> Result<Self, String> {
        let mut bytes = [0u8; 128];
        random
            .fill(&mut bytes)
            .map_err(|_| "the system random source failed".to_owned())?;
        Ok(Self {
            bytes,
            used: 0,
            overrun: false,
        })
    }

    /// `Err` when a draw ran past the prepared bytes.
    fn finish(self) -> Result<(), String> {
        if self.overrun {
            Err("RSA-OAEP drew more randomness than was prepared".into())
        } else {
            Ok(())
        }
    }
}

impl rsa::rand_core::RngCore for Prefilled {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let end = self.used.saturating_add(dest.len());
        match self.bytes.get(self.used..end) {
            Some(src) => {
                dest.copy_from_slice(src);
                self.used = end;
            }
            None => {
                dest.fill(0);
                self.overrun = true;
            }
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rsa::rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rsa::rand_core::CryptoRng for Prefilled {}

/// What an encrypting `[[vcon.rule]]` seals its containers with.
pub struct Sealing {
    /// The key and chain the signed form is signed with.
    pub signer: Signer,
    /// The certificate the signed form is encrypted to.
    pub recipient: Recipient,
    /// Whether the vCon is gzip compressed inside the signed form.
    pub compression: Compression,
}

/// Names no key material: a debug print of a rule must not carry the
/// signing key.
impl std::fmt::Debug for Sealing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sealing")
            .field("certificates", &self.signer.x5c.len())
            .finish_non_exhaustive()
    }
}

impl Sealing {
    /// The encrypted form of the unsigned container `unsigned`.
    pub fn seal(&self, unsigned: &[u8], uuid: &str) -> Result<Vec<u8>, String> {
        encrypt_compressed(
            &sign_compressed(unsigned, uuid, &self.signer, self.compression)?,
            uuid,
            &self.recipient,
            self.compression,
        )
    }

    /// This sealing, compressing as `compression` says.
    #[must_use]
    pub fn compressed(mut self, compression: Compression) -> Self {
        self.compression = compression;
        self
    }
}

/// Read an encrypting rule's three files: the recipient certificate, the
/// signing key, which must be readable by its owner only, and the signing
/// chain.
pub fn load_sealing(
    encrypt_to: &std::path::Path,
    sign_key: &std::path::Path,
    sign_cert: &std::path::Path,
) -> Result<Sealing, String> {
    let read = |path: &std::path::Path| {
        std::fs::read_to_string(path).map_err(|e| format!("cannot read '{}': {e}", path.display()))
    };
    Ok(Sealing {
        signer: Signer::from_pem(
            &read_private_key("signing key", sign_key)?,
            &read(sign_cert)?,
        )?,
        recipient: Recipient::from_cert_pem(&read(encrypt_to)?)?,
        compression: Compression::None,
    })
}

/// Who must have signed a container for [`Opener::open`] to return it.
#[derive(Debug, Clone, Default)]
pub struct SignerTrust {
    /// The CA certificates (DER) the signing certificate must chain to;
    /// `None` checks no chain.
    anchors: Option<Vec<Vec<u8>>>,
    /// The SHA-256 of the signing certificate's DER; `None` checks none.
    sha256: Option<[u8; 32]>,
}

impl SignerTrust {
    /// Trust the CA certificates in the PEM text `pem`. `strict`: refuse a
    /// certificate that is not usable as a CA, as for a file the operator
    /// named; otherwise pass it over, as for the host's bundle.
    ///
    /// # Errors
    ///
    /// No usable CA certificate, or, with `strict`, any unusable one.
    pub fn from_ca_pem(pem: &str, strict: bool) -> Result<Self, String> {
        let mut anchors = Vec::new();
        for der in certificates(pem) {
            let cert = rustls::pki_types::CertificateDer::from(der.as_slice());
            match webpki::anchor_from_trusted_cert(&cert) {
                Ok(_) => anchors.push(der),
                Err(e) if strict => {
                    return Err(format!("a CA certificate is not usable: {e:?}"));
                }
                Err(_) => {}
            }
        }
        if anchors.is_empty() {
            return Err("no usable CA certificate (PEM `CERTIFICATE`)".into());
        }
        Ok(Self {
            anchors: Some(anchors),
            sha256: None,
        })
    }

    /// This trust, also requiring the signing certificate's SHA-256 to be
    /// `sha256`.
    #[must_use]
    pub fn pinned(mut self, sha256: [u8; 32]) -> Self {
        self.sha256 = Some(sha256);
        self
    }

    /// Whether any check is configured.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.anchors.is_some() || self.sha256.is_some()
    }

    /// Check the `x5c` chain `chain` (DER, signing certificate first) at
    /// `now`, in seconds since the Unix epoch.
    ///
    /// # Errors
    ///
    /// The signing certificate's fingerprint is not the pinned one, or the
    /// chain does not lead to a trusted CA within every certificate's
    /// validity period.
    pub fn check(&self, chain: &[Vec<u8>], now: u64) -> Result<(), String> {
        use sha2::Digest as _;
        let leaf = chain
            .first()
            .ok_or("the signature carries no certificate")?;
        if let Some(pin) = &self.sha256
            && sha2::Sha256::digest(leaf).as_slice() != pin.as_slice()
        {
            return Err(format!(
                "the signing certificate's SHA-256 fingerprint is {}, not the pinned {}",
                colon_hex(&sha2::Sha256::digest(leaf)),
                colon_hex(pin)
            ));
        }
        let Some(anchors) = &self.anchors else {
            return Ok(());
        };
        let anchors: Vec<_> = anchors
            .iter()
            .map(|der| rustls::pki_types::CertificateDer::from(der.as_slice()))
            .collect();
        let anchors = anchors
            .iter()
            .filter_map(|der| webpki::anchor_from_trusted_cert(der).ok())
            .collect::<Vec<_>>();
        let leaf = rustls::pki_types::CertificateDer::from(leaf.as_slice());
        let intermediates: Vec<_> = chain[1..]
            .iter()
            .map(|der| rustls::pki_types::CertificateDer::from(der.as_slice()))
            .collect();
        let end_entity = webpki::EndEntityCert::try_from(&leaf)
            .map_err(|e| format!("the signing certificate does not parse: {e:?}"))?;
        end_entity
            .verify_for_usage(
                webpki::ALL_VERIFICATION_ALGS,
                &anchors,
                &intermediates,
                rustls::pki_types::UnixTime::since_unix_epoch(std::time::Duration::from_secs(now)),
                AnyUsage,
                None,
                None,
            )
            .map(|_| ())
            .map_err(|e| match e {
                webpki::Error::CertExpired { .. } | webpki::Error::CertNotValidYet { .. } => {
                    format!("a certificate in the signer's chain is not valid now ({e:?})")
                }
                other => {
                    format!("the signing certificate does not chain to a trusted CA ({other:?})")
                }
            })
    }
}

/// The signing certificate's extended key usage is not checked: no usage is
/// registered for signing a vCon, so the CA is what decides who may sign.
struct AnyUsage;

impl webpki::ExtendedKeyUsageValidator for AnyUsage {
    fn validate(&self, iter: webpki::KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
        for purpose in iter {
            purpose?;
        }
        Ok(())
    }
}

/// `bytes` as upper-case hex pairs joined by colons, as `openssl x509
/// -fingerprint` prints a fingerprint.
fn colon_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// What opens an encrypted container a store hands back: the recipient's
/// private key, read from a file only its owner can read.
pub struct Opener {
    /// The PEM text of the RSA private key.
    key_pem: String,
    /// Who must have signed what it opens.
    trust: SignerTrust,
}

/// Names no key material.
impl std::fmt::Debug for Opener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Opener").finish_non_exhaustive()
    }
}

/// An encrypted container, opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    /// The unsigned container inside.
    pub unsigned: Vec<u8>,
    /// The SHA-256 fingerprint of the certificate the signature verified
    /// against, as `openssl x509 -noout -fingerprint -sha256` prints it.
    pub signer_sha256: String,
}

impl Opener {
    /// Read the PEM RSA private key at `path`, which must be readable by its
    /// owner only.
    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        let key_pem = read_private_key("decryption key", path)?;
        private_key(&key_pem)?;
        Ok(Self {
            key_pem,
            trust: SignerTrust::default(),
        })
    }

    /// This opener, returning only containers whose signer `trust` accepts.
    #[must_use]
    pub fn trusting(mut self, trust: SignerTrust) -> Self {
        self.trust = trust;
        self
    }

    /// Whether a signer check is configured: a container that is not
    /// encrypted has no signer to check.
    #[must_use]
    pub fn checks_signer(&self) -> bool {
        self.trust.is_active()
    }

    /// Decrypt `jwe`, verify the signed form inside, and return the unsigned
    /// container with the fingerprint of the certificate that signed it. A
    /// gzip payload that inflates to more than `max_unsigned` bytes is
    /// refused ([`verify_capped`]).
    pub fn open(&self, jwe: &[u8], max_unsigned: usize) -> Result<Opened, String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        self.open_at(jwe, max_unsigned, now)
    }

    /// [`Self::open`] at `now`, in seconds since the Unix epoch: the time the
    /// signer's certificates must be valid at.
    pub fn open_at(&self, jwe: &[u8], max_unsigned: usize, now: u64) -> Result<Opened, String> {
        use sha2::Digest as _;
        let signed = decrypt(jwe, &self.key_pem)?;
        let (unsigned, chain) = verify_with_signer(&signed, max_unsigned)?;
        self.trust.check(&chain, now)?;
        let signer = chain.first().cloned().unwrap_or_default();
        let signer_sha256 = colon_hex(&sha2::Sha256::digest(&signer));
        Ok(Opened {
            unsigned,
            signer_sha256,
        })
    }
}

/// The PEM text of the private key at `path`, `what` naming it in errors. On
/// Unix the file must be readable by its owner only, as ssh requires of its
/// keys: a key other users can read has already leaked.
fn read_private_key(what: &str, path: &std::path::Path) -> Result<String, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(path)
            .map_err(|e| format!("cannot read '{}': {e}", path.display()))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(format!(
                "the {what} '{}' can be read by other users (mode {:o}): chmod 600 it",
                path.display(),
                mode & 0o777
            ));
        }
    }
    std::fs::read_to_string(path).map_err(|e| format!("cannot read '{}': {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// The uuid of the test container.
    const UUID: &str = "019a0000-0000-8000-8000-000000000001";

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/vcon-jose");

    fn fixture(name: &str) -> Result<String, Box<dyn std::error::Error>> {
        Ok(std::fs::read_to_string(format!("{FIXTURES}/{name}"))?)
    }

    /// The fixture recipient: the certificate of `fake_grp.key`.
    fn recipient() -> Result<Recipient, Box<dyn std::error::Error>> {
        Ok(Recipient::from_cert_pem(&fixture("fake_grp.crt")?)?)
    }

    /// The fixture signer.
    fn signer() -> Result<Signer, Box<dyn std::error::Error>> {
        Ok(Signer::from_pem(
            &fixture("fake_grp.key")?,
            &fixture("fake_grp.crt")?,
        )?)
    }

    /// An unsigned vCon whose party name repeats, so gzip shrinks it.
    fn unsigned() -> Vec<u8> {
        serde_json::json!({
            "vcon": "0.4.0",
            "uuid": UUID,
            "parties": [{ "name": "Repeated Party ".repeat(400) }],
        })
        .to_string()
        .into_bytes()
    }

    /// The JWS payload of a signed form, decoded.
    fn payload_of(jws: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let value: serde_json::Value = serde_json::from_slice(jws)?;
        Ok(URL_SAFE_NO_PAD.decode(value["payload"].as_str().ok_or("payload")?)?)
    }

    /// The unprotected `cty` of an encrypted form.
    fn cty_of(jwe: &[u8]) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let value: serde_json::Value = serde_json::from_slice(jwe)?;
        Ok(value["unprotected"]["cty"].clone())
    }

    #[test]
    fn compression_names_parse_and_others_are_refused() -> TestResult {
        assert_eq!(Compression::parse("none")?, Compression::None);
        assert_eq!(Compression::parse("gzip")?, Compression::Gzip);
        for bad in ["", "deflate", "DEF", "Gzip", "zlib"] {
            let err = Compression::parse(bad).err().ok_or(bad)?;
            assert!(err.contains("none") && err.contains("gzip"), "{err}");
        }
        Ok(())
    }

    /// core-04 section 5.2: with gzip the JWS payload is the gzip (RFC 1952)
    /// of the unsigned vCon, and the signature covers it; it verifies back
    /// to the unsigned vCon.
    #[test]
    fn gzip_signs_the_gzip_of_the_unsigned_vcon() -> TestResult {
        use std::io::Read as _;
        let signed = sign_compressed(&unsigned(), UUID, &signer()?, Compression::Gzip)?;
        let payload = payload_of(&signed)?;
        assert_eq!(payload[..2], GZIP_MAGIC, "a gzip member");
        let mut inflated = Vec::new();
        flate2::read::GzDecoder::new(payload.as_slice()).read_to_end(&mut inflated)?;
        assert_eq!(inflated, unsigned());
        assert!(payload.len() < unsigned().len());
        assert_eq!(verify(&signed)?, unsigned());

        let plain = sign_compressed(&unsigned(), UUID, &signer()?, Compression::None)?;
        assert_eq!(payload_of(&plain)?, unsigned());
        Ok(())
    }

    /// core-04 section 5.3.1: the `cty` is `application/vcon`, or
    /// `application/vcon+gzip` when the vCon inside is compressed. No JWE
    /// `zip` is written. A gzip container opens to the unsigned vCon.
    #[test]
    fn the_encrypted_form_names_its_content_type_by_section_5_3_1() -> TestResult {
        let seal_with = |c| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            Ok(Sealing {
                signer: signer()?,
                recipient: recipient()?,
                compression: Compression::None,
            }
            .compressed(c)
            .seal(&unsigned(), UUID)?)
        };
        let plain = seal_with(Compression::None)?;
        let packed = seal_with(Compression::Gzip)?;
        assert_eq!(cty_of(&plain)?, "application/vcon");
        assert_eq!(cty_of(&packed)?, "application/vcon+gzip");
        for jwe in [&plain, &packed] {
            let value: serde_json::Value = serde_json::from_slice(jwe)?;
            let protected = decode_header(value["protected"].as_str().unwrap_or(""))?;
            assert_eq!(protected.get("zip"), None, "no JWE zip");
            for place in [&value["unprotected"], &value["recipients"][0]["header"]] {
                assert_eq!(place.get("zip"), None, "no JWE zip");
            }
            let signed = decrypt(jwe, &fixture("fake_grp.key")?)?;
            assert_eq!(verify(&signed)?, unsigned());
        }
        assert!(
            packed.len() < plain.len(),
            "{} {}",
            packed.len(),
            plain.len()
        );
        Ok(())
    }

    /// sipnab never writes a JWE `zip`, and a container that carries one, in
    /// any header, is refused by name rather than read as if it had none.
    #[test]
    fn a_jwe_zip_header_is_refused() -> TestResult {
        let key = fixture("fake_grp.key")?;
        let signed = sign(&unsigned(), UUID, &signer()?)?;
        let zipped = serde_json::json!({ "alg": JWE_ALG, "enc": JWE_ENC, "zip": "DEF" });
        let headers = JweHeaders {
            protected: Some(zipped),
            unprotected: serde_json::json!({ "cty": CONTENT_TYPE, "uuid": UUID }),
            recipient: None,
        };
        let jwe = encrypt_under(&signed, &recipient()?, &headers)?;
        let err = decrypt(&jwe, &key)
            .err()
            .ok_or("zip in protected accepted")?;
        assert!(err.contains("zip"), "{err}");
        let jwe = encrypt(&signed, UUID, &recipient()?)?;
        for place in ["unprotected", "recipient"] {
            let mut value: serde_json::Value = serde_json::from_slice(&jwe)?;
            match place {
                "unprotected" => value["unprotected"]["zip"] = "DEF".into(),
                _ => value["recipients"][0]["header"] = serde_json::json!({ "zip": "DEF" }),
            }
            let err = decrypt(value.to_string().as_bytes(), &key)
                .err()
                .ok_or(format!("zip in {place} accepted"))?;
            assert!(err.contains("zip"), "{err}");
        }
        Ok(())
    }

    /// The gzip header ([RFC 1952 section 2.3](https://www.rfc-editor.org/rfc/rfc1952.html#section-2.3)) for a member with no optional
    /// fields: ID1, ID2, CM = 8 (deflate), FLG = 0, MTIME = 0, XFL = 0,
    /// OS = 255 (unknown).
    const GZIP_HEADER: [u8; 10] = [0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];

    /// One raw DEFLATE block of `len` zero bytes, not marked final, after a
    /// sync flush: repeating it gives a valid stream of any length.
    fn zero_block(len: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut compress = flate2::Compress::new(flate2::Compression::best(), false);
        let mut out = Vec::with_capacity(len / 10 + 64);
        compress.compress_vec(&vec![0u8; len], &mut out, flate2::FlushCompress::Sync)?;
        Ok(out)
    }

    /// A gzip member that never ends: the header, then one DEFLATE block
    /// repeated for ever, so no implementation can hold all of it.
    struct Endless {
        block: Vec<u8>,
        at: usize,
        header_left: usize,
    }

    impl std::io::Read for Endless {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            for byte in buf.iter_mut() {
                if self.header_left > 0 {
                    *byte = GZIP_HEADER[GZIP_HEADER.len() - self.header_left];
                    self.header_left -= 1;
                } else {
                    *byte = self.block[self.at];
                    self.at = (self.at + 1) % self.block.len();
                }
            }
            Ok(buf.len())
        }
    }

    /// A gzip stream that inflates without end is refused once it passes
    /// the cap. The stream has no end, so returning at all shows the
    /// inflation stopped near the cap rather than holding the whole vCon.
    #[test]
    fn an_endless_gzip_stream_is_refused_at_the_cap() -> TestResult {
        let cap = 1024 * 1024;
        let endless = Endless {
            block: zero_block(64 * 1024)?,
            at: 0,
            header_left: GZIP_HEADER.len(),
        };
        let err = gunzip_capped(endless, cap)
            .err()
            .ok_or("an endless stream was accepted")?;
        assert!(err.contains(&cap.to_string()), "{err}");
        Ok(())
    }

    /// The cap is inclusive: a vCon of exactly `cap` bytes inflates, one
    /// byte more is refused.
    #[test]
    fn the_gunzip_cap_is_inclusive() -> TestResult {
        use std::io::Write as _;
        let data = vec![7u8; 5000];
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&data)?;
        let packed = encoder.finish()?;
        assert_eq!(gunzip_capped(packed.as_slice(), 5000)?, data);
        assert!(gunzip_capped(packed.as_slice(), 4999).is_err());
        Ok(())
    }

    /// A signed form whose gzip payload inflates past the cap does not
    /// verify; with a cap that holds it, it does. An uncompressed payload
    /// is not subject to the cap: it is already held whole.
    #[test]
    fn verify_capped_refuses_a_gzip_payload_past_the_cap() -> TestResult {
        let size = unsigned().len();
        let signed = sign_compressed(&unsigned(), UUID, &signer()?, Compression::Gzip)?;
        let err = verify_capped(&signed, size - 1)
            .err()
            .ok_or("a payload past the cap was accepted")?;
        assert!(err.contains(&(size - 1).to_string()), "{err}");
        assert_eq!(verify_capped(&signed, size)?, unsigned());
        let plain = sign(&unsigned(), UUID, &signer()?)?;
        assert_eq!(verify_capped(&plain, 1)?, unsigned());
        Ok(())
    }

    /// `Opener::open` applies its cap to a gzip payload.
    #[test]
    fn the_opener_applies_its_cap() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("k.pem");
        std::fs::write(&path, fixture("fake_grp.key")?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        let opener = Opener::load(&path)?;
        let size = unsigned().len();
        let jwe = encrypt_compressed(
            &sign_compressed(&unsigned(), UUID, &signer()?, Compression::Gzip)?,
            UUID,
            &recipient()?,
            Compression::Gzip,
        )?;
        assert!(opener.open(&jwe, size - 1).is_err());
        assert_eq!(opener.open(&jwe, size)?.unsigned, unsigned());
        Ok(())
    }

    /// A CA, an intermediate CA it issued, and a certificate the
    /// intermediate issued for the fixture signing key, valid from 2020 to
    /// the start of `until_year`.
    struct Pki {
        /// The root CA, PEM.
        ca: String,
        /// The signing certificate then the intermediate, PEM.
        chain: String,
    }

    fn pki(name: &str, until_year: i32) -> Result<Pki, Box<dyn std::error::Error>> {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
        let ca_params = |cn: &str| {
            let mut p = CertificateParams::default();
            p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            p.distinguished_name.push(DnType::CommonName, cn);
            p.not_before = rcgen::date_time_ymd(2020, 1, 1);
            p.not_after = rcgen::date_time_ymd(until_year, 1, 1);
            p
        };
        let root_key = KeyPair::generate()?;
        let root_params = ca_params(&format!("{name} root"));
        let root = root_params.self_signed(&root_key)?;
        let mid_key = KeyPair::generate()?;
        let mid_params = ca_params(&format!("{name} intermediate"));
        let mid = mid_params.signed_by(&mid_key, &Issuer::new(root_params, &root_key))?;
        let leaf_key = KeyPair::from_pem(&fixture("fake_grp.key")?)?;
        let mut leaf_params = CertificateParams::default();
        leaf_params.is_ca = IsCa::ExplicitNoCa;
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, format!("{name} signer"));
        leaf_params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        leaf_params.not_after = rcgen::date_time_ymd(until_year, 1, 1);
        let leaf = leaf_params.signed_by(&leaf_key, &Issuer::new(mid_params, &mid_key))?;
        Ok(Pki {
            ca: root.pem(),
            chain: format!("{}{}", leaf.pem(), mid.pem()),
        })
    }

    /// 2030-01-01T00:00:00Z, in seconds since the Unix epoch.
    const IN_2030: u64 = 1_893_456_000;

    /// The `x5c` chain a signer made from `pki` carries, as DER.
    fn x5c(pki: &Pki) -> Vec<Vec<u8>> {
        certificates(&pki.chain)
    }

    #[test]
    fn a_signer_that_chains_to_the_ca_through_its_intermediate_is_trusted() -> TestResult {
        let pki = pki("good", 2040)?;
        SignerTrust::from_ca_pem(&pki.ca, true)?.check(&x5c(&pki), IN_2030)?;
        Ok(())
    }

    #[test]
    fn a_signer_another_ca_issued_is_refused() -> TestResult {
        let (ours, theirs) = (pki("ours", 2040)?, pki("theirs", 2040)?);
        let trust = SignerTrust::from_ca_pem(&ours.ca, true)?;
        assert!(trust.check(&x5c(&theirs), IN_2030).is_err());
        Ok(())
    }

    /// Without the intermediate the chain does not reach the CA.
    #[test]
    fn a_chain_missing_its_intermediate_is_refused() -> TestResult {
        let pki = pki("short", 2040)?;
        let trust = SignerTrust::from_ca_pem(&pki.ca, true)?;
        assert!(trust.check(&x5c(&pki)[..1], IN_2030).is_err());
        Ok(())
    }

    /// Every certificate must be within its validity period at `now`.
    #[test]
    fn a_signer_outside_its_validity_period_is_refused() -> TestResult {
        let pki = pki("dated", 2031)?;
        let trust = SignerTrust::from_ca_pem(&pki.ca, true)?;
        trust.check(&x5c(&pki), IN_2030)?;
        let in_2032 = IN_2030 + 2 * 366 * 86_400;
        let err = trust
            .check(&x5c(&pki), in_2032)
            .err()
            .ok_or("expired accepted")?;
        assert!(err.contains("valid"), "{err}");
        let in_2019 = 1_546_300_800;
        assert!(trust.check(&x5c(&pki), in_2019).is_err(), "not yet valid");
        Ok(())
    }

    /// The pin compares the signing certificate's SHA-256, alone or with a
    /// CA.
    #[test]
    fn the_pin_compares_the_signing_certificate_fingerprint() -> TestResult {
        use sha2::Digest as _;
        let pki = pki("pinned", 2040)?;
        let chain = x5c(&pki);
        let right: [u8; 32] = sha2::Sha256::digest(&chain[0]).into();
        let mut wrong = right;
        wrong[31] ^= 1;
        SignerTrust::default()
            .pinned(right)
            .check(&chain, IN_2030)?;
        let err = SignerTrust::default()
            .pinned(wrong)
            .check(&chain, IN_2030)
            .err()
            .ok_or("a wrong pin accepted")?;
        assert!(err.contains("fingerprint"), "{err}");
        let both = SignerTrust::from_ca_pem(&pki.ca, true)?.pinned(wrong);
        assert!(both.check(&chain, IN_2030).is_err());
        // The pin is of the signing certificate, not of the intermediate.
        let mid: [u8; 32] = sha2::Sha256::digest(&chain[1]).into();
        assert!(
            SignerTrust::default()
                .pinned(mid)
                .check(&chain, IN_2030)
                .is_err()
        );
        Ok(())
    }

    /// A named CA file with a block that is not a certificate is refused
    /// whole; the host's bundle passes such a block over.
    #[test]
    fn a_named_ca_file_must_be_usable_whole() -> TestResult {
        let pki = pki("mixed", 2040)?;
        let mixed = format!(
            "{}-----BEGIN CERTIFICATE-----\nAAECAwQF\n-----END CERTIFICATE-----\n",
            pki.ca
        );
        assert!(SignerTrust::from_ca_pem(&mixed, true).is_err());
        SignerTrust::from_ca_pem(&mixed, false)?.check(&x5c(&pki), IN_2030)?;
        Ok(())
    }

    #[test]
    fn a_ca_file_without_a_certificate_is_refused() {
        assert!(SignerTrust::from_ca_pem("not a certificate", true).is_err());
        assert!(SignerTrust::from_ca_pem("", false).is_err());
    }

    /// The opener applies its trust after the signature verifies.
    #[test]
    fn the_opener_returns_only_what_its_trust_accepts() -> TestResult {
        let (ours, theirs) = (pki("ours", 2040)?, pki("theirs", 2040)?);
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("k.pem");
        std::fs::write(&path, fixture("fake_grp.key")?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        let jwe = seal(
            &unsigned(),
            UUID,
            &Signer::from_pem(&fixture("fake_grp.key")?, &theirs.chain)?,
            &recipient()?,
        )?;
        let opener = Opener::load(&path)?.trusting(SignerTrust::from_ca_pem(&ours.ca, true)?);
        assert!(opener.checks_signer());
        assert!(opener.open_at(&jwe, usize::MAX, IN_2030).is_err());
        let opener = Opener::load(&path)?.trusting(SignerTrust::from_ca_pem(&theirs.ca, true)?);
        assert_eq!(
            opener.open_at(&jwe, usize::MAX, IN_2030)?.unsigned,
            unsigned()
        );
        assert!(!Opener::load(&path)?.checks_signer());
        Ok(())
    }

    #[test]
    fn a_fingerprint_is_read_plain_or_with_colons_in_either_case() -> TestResult {
        let hex = "409743610cc747bd4082e2281c53a6548874ebe7a72be4a3c8cb1bcac897bcd6";
        let want = crate::config::parse_sha256_fingerprint(hex)?;
        assert_eq!(want[0], 0x40);
        assert_eq!(want[31], 0xd6);
        let colons: Vec<String> = hex
            .as_bytes()
            .chunks(2)
            .map(|p| String::from_utf8_lossy(p).to_uppercase())
            .collect();
        assert_eq!(
            crate::config::parse_sha256_fingerprint(&colons.join(":"))?,
            want
        );
        assert_eq!(
            crate::config::parse_sha256_fingerprint(&format!(" {} ", hex.to_uppercase()))?,
            want
        );
        for bad in [
            "",
            &hex[..62],
            &format!("{hex}00"),
            &hex.replace('4', "g"),
            "40:97:43",
            &format!(":{hex}"),
            &colons.join("::"),
            &format!("{}:{}{}", &hex[..1], &hex[1..4], colons[2..].concat()),
            &format!("4:097{}", &colons.join(":")[5..]),
            &format!("+1{}", &hex[2..]),
        ] {
            assert!(
                crate::config::parse_sha256_fingerprint(bad).is_err(),
                "{bad:?} accepted"
            );
        }
        Ok(())
    }

    /// The signed form as sipnab 0.5.217 and 0.5.218 wrote it: `alg` and
    /// `x5c` in the protected header, `uuid` alone in `header`.
    fn old_signed(signer: &Signer) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let protected = URL_SAFE_NO_PAD
            .encode(serde_json::json!({ "alg": JWS_ALG, "x5c": signer.x5c }).to_string());
        let payload = URL_SAFE_NO_PAD.encode(unsigned());
        let signature = signer.rs256(format!("{protected}.{payload}").as_bytes())?;
        Ok(serde_json::to_vec(&serde_json::json!({
            "payload": payload,
            "signatures": [{
                "protected": protected,
                "header": { "uuid": UUID },
                "signature": URL_SAFE_NO_PAD.encode(signature),
            }],
        }))?)
    }

    /// The encrypted form as sipnab 0.5.217 and 0.5.218 wrote it: `alg` and
    /// `enc` protected, `cty` and `uuid` unprotected, no recipient header.
    fn old_encrypted(signed: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let headers = JweHeaders {
            protected: Some(serde_json::json!({ "alg": JWE_ALG, "enc": JWE_ENC })),
            unprotected: serde_json::json!({ "cty": "application/vcon+json", "uuid": UUID }),
            recipient: None,
        };
        Ok(encrypt_under(signed, &recipient()?, &headers)?)
    }

    /// The names of a JSON object.
    fn names(value: &serde_json::Value) -> std::collections::BTreeSet<String> {
        value
            .as_object()
            .map(|o| o.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// core-04 section 5.2 and its Appendix C CDDL: each signature carries
    /// `header`, `protected` and `signature`; `x5c` (an array of strings)
    /// and `uuid` travel in the unprotected `header`; `alg` is protected.
    /// [RFC 7515 section 7.2.1](https://www.rfc-editor.org/rfc/rfc7515.html#section-7.2.1): the protected and unprotected names are
    /// disjoint.
    #[test]
    fn the_signed_form_places_its_headers_as_core_04_says() -> TestResult {
        let signed = sign(&unsigned(), UUID, &signer()?)?;
        let value: serde_json::Value = serde_json::from_slice(&signed)?;
        assert_eq!(
            names(&value),
            ["payload", "signatures"].map(String::from).into()
        );
        for signature in value["signatures"].as_array().ok_or("signatures")? {
            assert_eq!(
                names(signature),
                ["header", "protected", "signature"]
                    .map(String::from)
                    .into()
            );
            let protected = decode_header(signature["protected"].as_str().ok_or("protected")?)?;
            assert_eq!(protected, serde_json::json!({ "alg": JWS_ALG }));
            let header = &signature["header"];
            let x5c = header["x5c"].as_array().ok_or("x5c in header")?;
            assert!(!x5c.is_empty() && x5c.iter().all(serde_json::Value::is_string));
            assert_eq!(header["uuid"], UUID);
            assert!(names(&protected).is_disjoint(&names(header)));
        }
        assert_eq!(verify(&signed)?, unsigned());
        Ok(())
    }

    /// core-04 section 5.3, 5.3.1 and 5.3.2 and the Appendix C CDDL: `cty`,
    /// `enc` and `uuid` in the shared `unprotected` object, `alg` in each
    /// recipient's `header`. Nothing is left to protect, so RFC 7516
    /// section 7.2.1 has the `protected` member absent. RFC 7516 section
    /// 7.2.1: the header names are disjoint.
    #[test]
    fn the_encrypted_form_places_its_headers_as_core_04_says() -> TestResult {
        let jwe = seal(&unsigned(), UUID, &signer()?, &recipient()?)?;
        let value: serde_json::Value = serde_json::from_slice(&jwe)?;
        assert_eq!(
            names(&value),
            ["ciphertext", "iv", "recipients", "tag", "unprotected"]
                .map(String::from)
                .into()
        );
        let unprotected = &value["unprotected"];
        assert_eq!(unprotected["cty"], CONTENT_TYPE);
        assert_eq!(unprotected["enc"], JWE_ENC);
        assert_eq!(unprotected["uuid"], UUID);
        for one in value["recipients"].as_array().ok_or("recipients")? {
            assert_eq!(
                names(one),
                ["encrypted_key", "header"].map(String::from).into()
            );
            assert_eq!(one["header"], serde_json::json!({ "alg": JWE_ALG }));
            assert!(names(unprotected).is_disjoint(&names(&one["header"])));
        }
        assert_eq!(
            verify(&decrypt(&jwe, &fixture("fake_grp.key")?)?)?,
            unsigned()
        );
        Ok(())
    }

    /// A container in the placement sipnab 0.5.217 and 0.5.218 wrote still
    /// decrypts and verifies, and the opener names the same signer.
    #[test]
    fn a_container_the_earlier_placement_wrote_still_opens() -> TestResult {
        let signed = old_signed(&signer()?)?;
        assert_eq!(verify(&signed)?, unsigned());
        let jwe = old_encrypted(&signed)?;
        assert_eq!(
            verify(&decrypt(&jwe, &fixture("fake_grp.key")?)?)?,
            unsigned()
        );
        Ok(())
    }

    /// A name in two places with two values is refused: `x5c` in the
    /// protected header and in `header`, `alg` likewise, and `enc` in the
    /// protected and unprotected JWE headers. The same value twice is read.
    #[test]
    fn a_name_in_two_places_with_two_values_is_refused() -> TestResult {
        let ours = signer()?;
        let other = Signer::from_pem(&fixture("other.key")?, &fixture("other.crt")?)?;
        let payload = URL_SAFE_NO_PAD.encode(unsigned());
        let signed_with = |protected: serde_json::Value, header: serde_json::Value| {
            let protected = URL_SAFE_NO_PAD.encode(protected.to_string());
            let signature = ours.rs256(format!("{protected}.{payload}").as_bytes())?;
            Ok::<Vec<u8>, Box<dyn std::error::Error>>(serde_json::to_vec(&serde_json::json!({
                "payload": payload,
                "signatures": [{
                    "protected": protected,
                    "header": header,
                    "signature": URL_SAFE_NO_PAD.encode(signature),
                }],
            }))?)
        };
        let both = signed_with(
            serde_json::json!({ "alg": JWS_ALG, "x5c": ours.x5c }),
            serde_json::json!({ "x5c": other.x5c, "uuid": UUID }),
        )?;
        let err = verify(&both).err().ok_or("two x5c values accepted")?;
        assert!(err.contains("x5c"), "{err}");
        let same = signed_with(
            serde_json::json!({ "alg": JWS_ALG, "x5c": ours.x5c }),
            serde_json::json!({ "x5c": ours.x5c, "uuid": UUID }),
        )?;
        assert_eq!(verify(&same)?, unsigned());
        let algs = signed_with(
            serde_json::json!({ "alg": JWS_ALG }),
            serde_json::json!({ "alg": "PS256", "x5c": ours.x5c }),
        )?;
        assert!(verify(&algs).is_err());

        let signed = sign(&unsigned(), UUID, &ours)?;
        let headers = JweHeaders {
            protected: Some(serde_json::json!({ "enc": "A128CBC-HS256" })),
            unprotected: serde_json::json!({ "cty": CONTENT_TYPE, "enc": JWE_ENC, "uuid": UUID }),
            recipient: Some(serde_json::json!({ "alg": JWE_ALG })),
        };
        let jwe = encrypt_under(&signed, &recipient()?, &headers)?;
        let err = decrypt(&jwe, &fixture("fake_grp.key")?)
            .err()
            .ok_or("two enc values accepted")?;
        assert!(err.contains("enc"), "{err}");
        Ok(())
    }
}
