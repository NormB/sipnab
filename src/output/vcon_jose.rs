// SPDX-License-Identifier: MIT OR Apache-2.0

//! The signed and encrypted forms of a vCon.
//!
//! [draft-ietf-vcon-vcon-core-04 section 5.3](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-5.3)
//! says a vCon "MUST be signed first using JWS ... then encrypted using JWE".
//! So an encrypted container is two layers:
//!
//! - the signed form ([section 5.2](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-5.2)):
//!   a General JWS JSON Serialization ([RFC 7515 section 7.2.1](https://www.rfc-editor.org/rfc/rfc7515.html#section-7.2.1))
//!   whose payload is the unsigned container, signed `RS256` (an RSA key)
//!   or `ES256` (an EC P-256 key) with the signer's certificate chain in
//!   `x5c`;
//! - the encrypted form: a General JWE JSON Serialization
//!   ([RFC 7516 section 7.2.1](https://www.rfc-editor.org/rfc/rfc7516.html#section-7.2.1))
//!   whose plaintext is that signed form, with one content key encrypted to
//!   each recipient's certificate, `RSA-OAEP` for an RSA key and
//!   `ECDH-ES+A256KW` for an EC P-256 key, and the content encrypted
//!   `A256CBC-HS512`, the content encryption the draft names.
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
use rsa::pkcs8::DecodePublicKey as _;
use rsa::traits::PublicKeyParts as _;

/// JWE key encryption, the value core-04 section 5.3.3 names.
pub const JWE_ALG: &str = "RSA-OAEP";
/// JWE content encryption, the value core-04 section 5.3.1 names.
pub const JWE_ENC: &str = "A256CBC-HS512";
/// JWS signature algorithm, the value core-04 section 5.2.2 names.
pub const JWS_ALG: &str = "RS256";
/// JWS signature algorithm of an EC P-256 signer: ECDSA with SHA-256
/// ([RFC 7518 section 3.4](https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4)).
pub const JWS_ALG_ES256: &str = "ES256";
/// JWE key management for an EC P-256 recipient: ECDH-ES with the content
/// key wrapped by AES-256 key wrap
/// ([RFC 7518 section 4.6](https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6)),
/// which, unlike direct `ECDH-ES`, serves one content key to many recipients.
pub const JWE_ALG_ECDH: &str = "ECDH-ES+A256KW";
/// JWE direct key agreement with ECDH-ES: read, never written.
pub const JWE_ALG_ECDH_DIRECT: &str = "ECDH-ES";
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

/// The DER of the `id-ecPublicKey` object identifier, 1.2.840.10045.2.1
/// ([RFC 5480 section 2.1.1](https://www.rfc-editor.org/rfc/rfc5480.html#section-2.1.1)).
const EC_PUBLIC_KEY_OID: &[u8] = &[0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];

/// The DER of the `secp256r1` (P-256) curve identifier, 1.2.840.10045.3.1.7.
const P256_OID: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

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

/// The private key a signature is made with.
enum SigningKey {
    /// An RSA key: `RS256`.
    Rsa(ring::signature::RsaKeyPair),
    /// An EC P-256 key: `ES256`.
    Es256(ring::signature::EcdsaKeyPair),
}

/// The key and certificate chain a container is signed with.
pub struct Signer {
    /// The private key the signature is made with.
    key: SigningKey,
    /// The chain as `x5c` carries it: standard base64 DER, leaf first
    /// ([RFC 7515 section 4.1.6](https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.6)).
    x5c: Vec<String>,
    /// The `https://` URL that serves the chain, written as `x5u`
    /// ([RFC 7515 section 4.1.5](https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.5))
    /// beside `x5c`.
    x5u: Option<String>,
}

impl Signer {
    /// A signer from a PEM private key and a PEM certificate chain, leaf
    /// first. The key is RSA (`PRIVATE KEY` or `RSA PRIVATE KEY`), which signs
    /// `RS256`, or EC P-256 (`PRIVATE KEY` or `EC PRIVATE KEY`), which signs
    /// `ES256`. The leaf must be the key's own certificate.
    pub fn from_pem(key_pem: &str, chain_pem: &str) -> Result<Self, String> {
        let (label, der) = pem_blocks(key_pem)
            .into_iter()
            .find(|(label, _)| {
                ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"].contains(&label.as_str())
            })
            .ok_or(
                "the signing key file holds no PEM `PRIVATE KEY`, `RSA PRIVATE KEY` or \
                 `EC PRIVATE KEY`",
            )?;
        let random = ring::rand::SystemRandom::new();
        let not_usable = |e: &dyn std::fmt::Display| {
            format!(
                "the signing key is neither an RSA key of {MIN_RSA_BITS} to 8192 bits nor an \
                 EC P-256 key that can sign: {e}"
            )
        };
        let key = match label.as_str() {
            "RSA PRIVATE KEY" => SigningKey::Rsa(
                ring::signature::RsaKeyPair::from_der(&der).map_err(|e| not_usable(&e))?,
            ),
            "EC PRIVATE KEY" => SigningKey::Es256(es256_from_sec1(&der, &random)?),
            _ => match ring::signature::RsaKeyPair::from_pkcs8(&der) {
                Ok(rsa) => SigningKey::Rsa(rsa),
                Err(rsa_error) => SigningKey::Es256(
                    ring::signature::EcdsaKeyPair::from_pkcs8(
                        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                        &der,
                        &random,
                    )
                    .map_err(|_| not_usable(&rsa_error))?,
                ),
            },
        };
        let chain = certificates(chain_pem);
        let leaf = chain
            .first()
            .ok_or("the signing certificate file holds no certificate (PEM `CERTIFICATE`)")?;
        let matches = match (&key, public_key(subject_public_key_info(leaf)?)?) {
            (SigningKey::Rsa(rsa), PublicKey::Rsa(public)) => public == rsa.public().as_ref(),
            (SigningKey::Es256(ec), PublicKey::P256(point)) => {
                use ring::signature::KeyPair as _;
                point == ec.public_key().as_ref()
            }
            _ => false,
        };
        if !matches {
            return Err(
                "the signing certificate (the first in its file) does not match the signing key"
                    .into(),
            );
        }
        Ok(Self {
            key,
            x5c: chain.iter().map(|der| STANDARD.encode(der)).collect(),
            x5u: None,
        })
    }

    /// This signer, also naming its chain by the URL `url` in `x5u`.
    ///
    /// # Errors
    ///
    /// A URL that is not `https://`: core-04 section 5.2.2 says x5u "MUST
    /// contain an \[HTTPS\] URL".
    pub fn with_cert_url(mut self, url: &str) -> Result<Self, String> {
        check_x5u(url)?;
        self.x5u = Some(url.to_owned());
        Ok(self)
    }

    /// The JWS `alg` this signer signs with: `RS256` or `ES256`.
    #[must_use]
    pub fn alg(&self) -> &'static str {
        match self.key {
            SigningKey::Rsa(_) => JWS_ALG,
            SigningKey::Es256(_) => JWS_ALG_ES256,
        }
    }

    /// The signature over `input`: `RS256` (RSASSA-PKCS1-v1_5 with
    /// SHA-256) for an RSA key, `ES256` (ECDSA P-256 with SHA-256, the
    /// 64-byte `r || s` [RFC 7518 section 3.4](https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4) defines) for an EC key.
    pub fn sign_input(&self, input: &[u8]) -> Result<Vec<u8>, String> {
        let random = ring::rand::SystemRandom::new();
        match &self.key {
            SigningKey::Rsa(key) => {
                let mut signature = vec![0; key.public().modulus_len()];
                key.sign(
                    &ring::signature::RSA_PKCS1_SHA256,
                    &random,
                    input,
                    &mut signature,
                )
                .map_err(|_| "RS256 signing failed".to_owned())?;
                Ok(signature)
            }
            SigningKey::Es256(key) => Ok(key
                .sign(&random, input)
                .map_err(|_| "ES256 signing failed".to_owned())?
                .as_ref()
                .to_vec()),
        }
    }

    /// [`Self::sign_input`] for an RSA signer.
    pub fn rs256(&self, input: &[u8]) -> Result<Vec<u8>, String> {
        self.sign_input(input)
    }
}

/// An `ES256` key pair from a SEC1 `EC PRIVATE KEY`
/// ([RFC 5915](https://www.rfc-editor.org/rfc/rfc5915.html)), which ring
/// does not parse: p256 reads it, and ring takes the scalar and the point.
fn es256_from_sec1(
    der: &[u8],
    random: &ring::rand::SystemRandom,
) -> Result<ring::signature::EcdsaKeyPair, String> {
    let secret = p256::SecretKey::from_sec1_der(der)
        .map_err(|e| format!("the signing key is not an EC P-256 key: {e}"))?;
    let point = secret.public_key().to_sec1_bytes();
    ring::signature::EcdsaKeyPair::from_private_key_and_public_key(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        secret.to_bytes().as_slice(),
        &point,
        random,
    )
    .map_err(|e| format!("the signing key is not an EC P-256 key that can sign: {e}"))
}

/// The certificate a container is encrypted to.
pub enum Recipient {
    /// An RSA key: the content key is encrypted `RSA-OAEP`.
    Rsa(rsa::RsaPublicKey),
    /// An EC P-256 key, as the uncompressed point: the content key is
    /// wrapped under a key agreed `ECDH-ES+A256KW`.
    P256(Vec<u8>),
}

impl Recipient {
    /// A recipient from a PEM certificate: the first `CERTIFICATE` in `pem`,
    /// which must carry an RSA key of at least [`MIN_RSA_BITS`] or an EC
    /// P-256 key.
    pub fn from_cert_pem(pem: &str) -> Result<Self, String> {
        let certificates = certificates(pem);
        let leaf = certificates
            .first()
            .ok_or("the recipient file holds no certificate (PEM `CERTIFICATE`)")?;
        let spki = subject_public_key_info(leaf)?;
        if let PublicKey::P256(point) = public_key(spki)? {
            p256::PublicKey::from_sec1_bytes(point)
                .map_err(|e| format!("the recipient certificate's EC key does not parse: {e}"))?;
            return Ok(Self::P256(point.to_vec()));
        }
        let key = rsa::RsaPublicKey::from_public_key_der(spki)
            .map_err(|e| format!("the recipient certificate's RSA key does not parse: {e}"))?;
        let bits = key.size().saturating_mul(8);
        if bits < MIN_RSA_BITS {
            return Err(format!(
                "the recipient certificate's RSA key is {bits} bits; at least {MIN_RSA_BITS} are required"
            ));
        }
        Ok(Self::Rsa(key))
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
    let protected = URL_SAFE_NO_PAD.encode(serde_json::json!({ "alg": signer.alg() }).to_string());
    let payload = URL_SAFE_NO_PAD.encode(unsigned);
    let signature = signer.sign_input(format!("{protected}.{payload}").as_bytes())?;
    let mut header = serde_json::json!({ "x5c": signer.x5c, "uuid": uuid });
    if let Some(url) = &signer.x5u {
        header["x5u"] = url.clone().into();
    }
    serde_json::to_vec(&serde_json::json!({
        "payload": payload,
        "signatures": [{
            "protected": protected,
            "header": header,
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
    encrypt_to_all(signed, uuid, std::slice::from_ref(recipient), compression)
}

/// [`encrypt_compressed`] to every one of `recipients`: one content key,
/// encrypted to each, in the `recipients` array of the General JWE JSON
/// Serialization ([RFC 7516 section 7.2.1](https://www.rfc-editor.org/rfc/rfc7516.html#section-7.2.1)).
/// An RSA recipient's `header` names `RSA-OAEP`; an EC P-256 recipient's
/// names `ECDH-ES+A256KW` and carries the `epk` its key was agreed with.
pub fn encrypt_to_all(
    signed: &[u8],
    uuid: &str,
    recipients: &[Recipient],
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
    encrypt_under(signed, recipients, &headers)
}

/// The three header places of a General JWE JSON Serialization
/// ([RFC 7516 section 7.2.1](https://www.rfc-editor.org/rfc/rfc7516.html#section-7.2.1)).
struct JweHeaders {
    /// The JWE Protected Header; `None` writes no `protected` member, and
    /// the additional authenticated data is then empty.
    protected: Option<serde_json::Value>,
    /// The shared `unprotected` header.
    unprotected: serde_json::Value,
    /// An RSA recipient's `header`; `None` writes none. An EC recipient's
    /// header is always `alg` and `epk`.
    recipient: Option<serde_json::Value>,
}

/// Encrypt `signed` to every one of `recipients` with `headers`, a fresh
/// content key and IV.
fn encrypt_under(
    signed: &[u8],
    recipients: &[Recipient],
    headers: &JweHeaders,
) -> Result<Vec<u8>, String> {
    if recipients.is_empty() {
        return Err("the container has no recipient to encrypt to".into());
    }
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
    let mut entries = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        let (header, encrypted_key) = match recipient {
            Recipient::Rsa(key) => {
                let mut seed = Prefilled::new(&random)?;
                let encrypted_key = key
                    .encrypt(&mut seed, rsa::Oaep::new::<sha1_oaep::Sha1>(), &cek)
                    .map_err(|e| format!("RSA-OAEP: {e}"))?;
                seed.finish()?;
                (headers.recipient.clone(), encrypted_key)
            }
            Recipient::P256(point) => {
                let (epk, kek) = ecdh_es_kek_for(point, &random)?;
                (
                    Some(serde_json::json!({ "alg": JWE_ALG_ECDH, "epk": epk })),
                    aes_key_wrap(&kek, &cek)?,
                )
            }
        };
        let mut one = serde_json::Map::new();
        if let Some(header) = header {
            one.insert("header".into(), header);
        }
        one.insert(
            "encrypted_key".into(),
            URL_SAFE_NO_PAD.encode(encrypted_key).into(),
        );
        entries.push(serde_json::Value::Object(one));
    }
    let mut jwe = serde_json::Map::new();
    if let Some(protected) = protected {
        jwe.insert("protected".into(), protected.into());
    }
    jwe.insert("unprotected".into(), headers.unprotected.clone());
    jwe.insert("recipients".into(), entries.into());
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
    let key = decryption_key(key_pem)?;
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
        let known = [JWE_ALG, JWE_ALG_ECDH, JWE_ALG_ECDH_DIRECT];
        if !alg.as_deref().is_some_and(|a| known.contains(&a)) || enc.as_deref() != Some(JWE_ENC) {
            last = format!(
                "a recipient uses alg {alg:?} and enc {enc:?}; sipnab reads {} with {JWE_ENC}",
                known.join(", ")
            );
            continue;
        }
        let encrypted_key = b64u_field(recipient, "encrypted_key")?;
        let opened = match (&key, alg.as_deref()) {
            (DecryptionKey::Rsa(rsa), Some(JWE_ALG)) => rsa
                .decrypt(rsa::Oaep::new::<sha1_oaep::Sha1>(), &encrypted_key)
                .ok(),
            (DecryptionKey::P256(secret), Some(agreement)) if agreement != JWE_ALG => {
                content_key_by_ecdh(secret, &headers, agreement, &encrypted_key)?
            }
            _ => None,
        };
        let Some(cek) = opened else {
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
    verify_with_signer(jws, max_unsigned, None).map(|(unsigned, _)| unsigned)
}

/// What fetches the PEM chain an `x5u` URL serves: the readers' HTTPS
/// client, with its CA and its size and time caps.
pub type X5uFetch = dyn Fn(&str) -> Result<Vec<u8>, String> + Send + Sync;

/// Why a signature that names its chain only by `x5u` was not verified: no
/// fetch was allowed.
pub const X5U_NOT_FETCHED: &str = "the signature names its certificate by `x5u` (a URL) and \
     carries no `x5c`: give --vcon-x5u-ca <FILE|system> to fetch it over https";

/// Refuse an `x5u` that is not an `https://` URL: core-04 section 5.2.2 says
/// x5u "MUST contain an \[HTTPS\] URL".
fn check_x5u(url: &str) -> Result<(), String> {
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("https://") && url.len() > "https://".len() {
        Ok(())
    } else {
        Err(format!(
            "x5u {url:?} is not an https URL, which draft-ietf-vcon-vcon-core-04 section \
             5.2.2 requires"
        ))
    }
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
fn verify_with_signer(
    jws: &[u8],
    max_unsigned: usize,
    x5u: Option<&X5uFetch>,
) -> Result<(Vec<u8>, Vec<Vec<u8>>), String> {
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
        if alg.as_deref() != Some(JWS_ALG) && alg.as_deref() != Some(JWS_ALG_ES256) {
            return Err(format!(
                "a signature uses alg {alg:?}; sipnab verifies {JWS_ALG} and {JWS_ALG_ES256}"
            ));
        }
        let placed: Vec<&serde_json::Value> = headers.iter().filter_map(|h| h.get("x5c")).collect();
        if placed.windows(2).any(|pair| pair[0] != pair[1]) {
            return Err(
                "header `x5c` is in the protected header and in `header` with different values"
                    .into(),
            );
        }
        let chain = match placed.first() {
            Some(x5c) => x5c
                .as_array()
                .filter(|c| !c.is_empty())
                .ok_or("a signature's `x5c` is not a non-empty array")?
                .iter()
                .map(|c| {
                    let text = c.as_str().ok_or("an `x5c` entry is not a string")?;
                    STANDARD
                        .decode(text)
                        .map_err(|e| format!("`x5c` is not base64: {e}"))
                })
                .collect::<Result<Vec<Vec<u8>>, String>>()?,
            // core-04 section 5.2.2: x5c or x5u. The x5u chain is fetched
            // only when the reader allows it, and only over HTTPS.
            None => {
                let url = one_header(&headers, "x5u")?
                    .ok_or("a signature carries no `x5c` or `x5u` certificate")?;
                check_x5u(&url)?;
                let fetch = x5u.ok_or(X5U_NOT_FETCHED)?;
                let pem = fetch(&url)?;
                let chain = certificates(&String::from_utf8_lossy(&pem));
                if chain.is_empty() {
                    return Err(format!(
                        "x5u {url:?} serves no PEM certificate (RFC 7515 section 4.1.5)"
                    ));
                }
                chain
            }
        };
        let leaf = chain
            .first()
            .ok_or("a signature carries no `x5c` certificate")?;
        // The algorithm the key's type allows, and the `alg` must agree:
        // a changed `alg` cannot pick another verification.
        let (algorithm, public): (&dyn ring::signature::VerificationAlgorithm, &[u8]) =
            match (public_key(subject_public_key_info(leaf)?)?, alg.as_deref()) {
                (PublicKey::Rsa(key), Some(JWS_ALG)) => {
                    (&ring::signature::RSA_PKCS1_2048_8192_SHA256, key)
                }
                (PublicKey::P256(point), Some(JWS_ALG_ES256)) => {
                    (&ring::signature::ECDSA_P256_SHA256_FIXED, point)
                }
                _ => {
                    return Err(format!(
                        "a signature's alg {alg:?} is not the algorithm of its certificate's key"
                    ));
                }
            };
        ring::signature::UnparsedPublicKey::new(algorithm, public)
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

/// The private key an encrypted container is opened with.
enum DecryptionKey {
    /// An RSA key, for an `RSA-OAEP` recipient.
    Rsa(Box<rsa::RsaPrivateKey>),
    /// An EC P-256 key, for an `ECDH-ES+A256KW` or `ECDH-ES` recipient.
    P256(p256::SecretKey),
}

/// A PEM private key: RSA (PKCS #8 or PKCS #1) or EC P-256 (PKCS #8 or
/// SEC1 `EC PRIVATE KEY`).
fn decryption_key(pem: &str) -> Result<DecryptionKey, String> {
    use p256::pkcs8::DecodePrivateKey as _;
    use rsa::pkcs1::DecodeRsaPrivateKey as _;
    if let Ok(key) =
        rsa::RsaPrivateKey::from_pkcs8_pem(pem).or_else(|_| rsa::RsaPrivateKey::from_pkcs1_pem(pem))
    {
        return Ok(DecryptionKey::Rsa(Box::new(key)));
    }
    pem_blocks(pem)
        .into_iter()
        .find_map(|(label, der)| match label.as_str() {
            "PRIVATE KEY" => p256::SecretKey::from_pkcs8_der(&der).ok(),
            "EC PRIVATE KEY" => p256::SecretKey::from_sec1_der(&der).ok(),
            _ => None,
        })
        .map(DecryptionKey::P256)
        .ok_or_else(|| "the private key is neither a PEM RSA key nor a PEM EC P-256 key".into())
}

/// The content key of an ECDH-ES recipient whose headers are `headers`,
/// agreed between `secret` and the recipient's `epk`
/// ([RFC 7518 section 4.6](https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6)):
/// unwrapped from `encrypted_key` for `ECDH-ES+A256KW`, the agreed key
/// itself for `ECDH-ES`. `None` when it does not open with this key.
///
/// # Errors
///
/// An `epk`, `apu` or `apv` that is not what [RFC 7518 section 4.6.1](https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.1) says.
fn content_key_by_ecdh(
    secret: &p256::SecretKey,
    headers: &[&serde_json::Value],
    alg: &str,
    encrypted_key: &[u8],
) -> Result<Option<Vec<u8>>, String> {
    let epk = headers
        .iter()
        .find_map(|h| h.get("epk"))
        .ok_or("an ECDH-ES recipient carries no `epk`")?;
    let point = point_of_jwk(epk)?;
    let party = |name: &str| -> Result<Vec<u8>, String> {
        match one_header(headers, name)? {
            Some(text) => URL_SAFE_NO_PAD
                .decode(text)
                .map_err(|e| format!("`{name}` is not base64url: {e}")),
            None => Ok(Vec::new()),
        }
    };
    let (apu, apv) = (party("apu")?, party("apv")?);
    let Some(z) = ecdh_static(secret, &point) else {
        return Ok(None);
    };
    if alg == JWE_ALG_ECDH_DIRECT {
        if !encrypted_key.is_empty() {
            return Err("an ECDH-ES recipient carries an `encrypted_key`".into());
        }
        return Ok(Some(concat_kdf(&z, JWE_ENC, &apu, &apv, 64)));
    }
    let kek: [u8; 32] = concat_kdf(&z, JWE_ALG_ECDH, &apu, &apv, 32)
        .try_into()
        .map_err(|_| "the key-encryption key is not 32 bytes".to_owned())?;
    Ok(aes_key_unwrap(&kek, encrypted_key).ok())
}

/// The ECDH shared secret `Z` of `secret` and the uncompressed P-256
/// `point`, or `None` when the point is not on the curve.
fn ecdh_static(secret: &p256::SecretKey, point: &[u8]) -> Option<Vec<u8>> {
    let public = p256::PublicKey::from_sec1_bytes(point).ok()?;
    let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());
    Some(shared.raw_secret_bytes().to_vec())
}

/// A fresh ephemeral key agreed with the recipient's uncompressed P-256
/// `point`: the ephemeral public key as the JWK `epk`, and the
/// `ECDH-ES+A256KW` key-encryption key derived from the agreement with no
/// `apu` or `apv`.
fn ecdh_es_kek_for(
    point: &[u8],
    random: &ring::rand::SystemRandom,
) -> Result<(serde_json::Value, [u8; 32]), String> {
    use ring::agreement;
    let ephemeral = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, random)
        .map_err(|_| "the system random source failed".to_owned())?;
    let public = ephemeral
        .compute_public_key()
        .map_err(|_| "the ephemeral EC key has no public key".to_owned())?;
    let epk = jwk_of_point(public.as_ref())?;
    let peer = agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, point);
    let kek = agreement::agree_ephemeral(ephemeral, &peer, |z| {
        concat_kdf(z, JWE_ALG_ECDH, &[], &[], 32)
    })
    .map_err(|_| "ECDH with the recipient's EC key failed".to_owned())?;
    let kek: [u8; 32] = kek
        .try_into()
        .map_err(|_| "the key-encryption key is not 32 bytes".to_owned())?;
    Ok((epk, kek))
}

/// The JWK of an uncompressed P-256 point
/// ([RFC 7518 section 6.2.1](https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2.1)).
fn jwk_of_point(point: &[u8]) -> Result<serde_json::Value, String> {
    match point {
        [0x04, rest @ ..] if rest.len() == 64 => Ok(serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(&rest[..32]),
            "y": URL_SAFE_NO_PAD.encode(&rest[32..]),
        })),
        _ => Err("an EC public key is not an uncompressed P-256 point".into()),
    }
}

/// The uncompressed P-256 point of a JWK `epk`.
fn point_of_jwk(jwk: &serde_json::Value) -> Result<Vec<u8>, String> {
    if jwk["kty"] != "EC" || jwk["crv"] != "P-256" {
        return Err(format!(
            "an `epk` is kty {} crv {}; sipnab reads EC P-256",
            jwk["kty"], jwk["crv"]
        ));
    }
    let coordinate = |name: &str| -> Result<Vec<u8>, String> {
        let bytes = b64u_field(jwk, name)?;
        if bytes.len() == 32 {
            Ok(bytes)
        } else {
            Err(format!("the `epk` coordinate `{name}` is not 32 bytes"))
        }
    };
    let mut point = vec![0x04];
    point.extend(coordinate("x")?);
    point.extend(coordinate("y")?);
    Ok(point)
}

/// The Concat KDF of [RFC 7518 section 4.6.2](https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6.2)
/// (NIST SP 800-56A section 5.8.1, SHA-256): `len` bytes from the shared
/// secret `z`, with `AlgorithmID` `alg`, `PartyUInfo` `apu`, `PartyVInfo`
/// `apv` and `SuppPubInfo` the key length in bits.
#[must_use]
pub fn concat_kdf(z: &[u8], alg: &str, apu: &[u8], apv: &[u8], len: usize) -> Vec<u8> {
    use sha2::Digest as _;
    let field = |bytes: &[u8]| {
        let mut out = u32::try_from(bytes.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes()
            .to_vec();
        out.extend_from_slice(bytes);
        out
    };
    let mut other = field(alg.as_bytes());
    other.extend(field(apu));
    other.extend(field(apv));
    let bits = u32::try_from(len.saturating_mul(8)).unwrap_or(u32::MAX);
    other.extend_from_slice(&bits.to_be_bytes());
    let mut out = Vec::with_capacity(len + 32);
    let mut round: u32 = 1;
    while out.len() < len {
        let mut hash = sha2::Sha256::new();
        hash.update(round.to_be_bytes());
        hash.update(z);
        hash.update(&other);
        out.extend_from_slice(&hash.finalize());
        round = round.saturating_add(1);
    }
    out.truncate(len);
    out
}

/// The default initial value of AES key wrap
/// ([RFC 3394 section 2.2.3.1](https://www.rfc-editor.org/rfc/rfc3394.html#section-2.2.3.1)).
const KEY_WRAP_IV: [u8; 8] = [0xA6; 8];

/// AES-256 key wrap ([RFC 3394 section 2.2.1](https://www.rfc-editor.org/rfc/rfc3394.html#section-2.2.1))
/// of `key`, a whole number of 64-bit blocks, at least two, under `kek`.
///
/// # Errors
///
/// A `key` that is not a whole number of at least two 64-bit blocks.
pub fn aes_key_wrap(kek: &[u8; 32], key: &[u8]) -> Result<Vec<u8>, String> {
    use aes::cipher::{BlockCipherEncrypt as _, KeyInit as _};
    if !key.len().is_multiple_of(8) || key.len() < 16 {
        return Err("AES key wrap takes a whole number of at least two 64-bit blocks".into());
    }
    let cipher = aes::Aes256::new_from_slice(kek).map_err(|e| format!("AES-256 key: {e}"))?;
    let mut check = KEY_WRAP_IV;
    let mut blocks: Vec<[u8; 8]> = key.as_chunks::<8>().0.to_vec();
    let count = blocks.len() as u64;
    for round in 0..6u64 {
        for (index, block) in blocks.iter_mut().enumerate() {
            let mut buffer = aes::Block::default();
            buffer[..8].copy_from_slice(&check);
            buffer[8..].copy_from_slice(block);
            cipher.encrypt_block(&mut buffer);
            let step = count * round + (index as u64) + 1;
            for (out, (high, counter)) in check
                .iter_mut()
                .zip(buffer[..8].iter().zip(step.to_be_bytes()))
            {
                *out = high ^ counter;
            }
            block.copy_from_slice(&buffer[8..]);
        }
    }
    let mut wrapped = check.to_vec();
    for block in blocks {
        wrapped.extend_from_slice(&block);
    }
    Ok(wrapped)
}

/// AES-256 key unwrap ([RFC 3394 section 2.2.2](https://www.rfc-editor.org/rfc/rfc3394.html#section-2.2.2)):
/// the key `wrapped` holds under `kek`.
///
/// # Errors
///
/// A length that is not a wrapped key's, or an integrity check that fails:
/// the wrong `kek`, or bytes changed.
pub fn aes_key_unwrap(kek: &[u8; 32], wrapped: &[u8]) -> Result<Vec<u8>, String> {
    use aes::cipher::{BlockCipherDecrypt as _, KeyInit as _};
    if !wrapped.len().is_multiple_of(8) || wrapped.len() < 24 {
        return Err("a wrapped key is a whole number of at least three 64-bit blocks".into());
    }
    let cipher = aes::Aes256::new_from_slice(kek).map_err(|e| format!("AES-256 key: {e}"))?;
    let mut check: [u8; 8] = wrapped[..8].try_into().unwrap_or([0; 8]);
    let mut blocks: Vec<[u8; 8]> = wrapped[8..].as_chunks::<8>().0.to_vec();
    let count = blocks.len() as u64;
    for round in (0..6u64).rev() {
        for (index, block) in blocks.iter_mut().enumerate().rev() {
            let step = count * round + (index as u64) + 1;
            let mut buffer = aes::Block::default();
            for (out, (high, counter)) in buffer[..8]
                .iter_mut()
                .zip(check.iter().zip(step.to_be_bytes()))
            {
                *out = high ^ counter;
            }
            buffer[8..].copy_from_slice(block);
            cipher.decrypt_block(&mut buffer);
            check.copy_from_slice(&buffer[..8]);
            block.copy_from_slice(&buffer[8..]);
        }
    }
    if check != KEY_WRAP_IV {
        return Err("the wrapped key's integrity check fails".into());
    }
    Ok(blocks.concat())
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

/// The public key a certificate carries.
enum PublicKey<'a> {
    /// The PKCS #1 `RSAPublicKey` of an `rsaEncryption` key.
    Rsa(&'a [u8]),
    /// The uncompressed point of an `id-ecPublicKey` key on P-256.
    P256(&'a [u8]),
}

/// The key inside a SubjectPublicKeyInfo: RSA, or EC on P-256
/// ([RFC 5480 section 2](https://www.rfc-editor.org/rfc/rfc5480.html#section-2)).
fn public_key(spki: &[u8]) -> Result<PublicKey<'_>, String> {
    const NOT_KNOWN: &str =
        "the certificate's key is neither an RSA key (rsaEncryption) nor an EC P-256 key";
    let (_, spki, _, _) = der_element(spki).ok_or(NOT_KNOWN)?;
    let (0x30, algorithm, _, rest) = der_element(spki).ok_or(NOT_KNOWN)? else {
        return Err(NOT_KNOWN.into());
    };
    let Some((0x03, [0, key @ ..], _, _)) = der_element(rest) else {
        return Err(NOT_KNOWN.into());
    };
    if algorithm.starts_with(RSA_ENCRYPTION_OID) {
        return Ok(PublicKey::Rsa(key));
    }
    match algorithm.strip_prefix(EC_PUBLIC_KEY_OID) {
        Some(P256_OID) if key.len() == 65 && key[0] == 0x04 => Ok(PublicKey::P256(key)),
        _ => Err(NOT_KNOWN.into()),
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

/// What a sealing `[[vcon.rule]]` seals its containers with: an encrypting
/// rule signs and encrypts, a `sign_only` rule signs.
pub struct Sealing {
    /// The key and chain the signed form is signed with.
    pub signer: Signer,
    /// The certificates the signed form is encrypted to, each a recipient
    /// of the one JWE; none writes the signed form alone
    /// ([core-04 section 5.2](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-5.2)).
    pub recipients: Vec<Recipient>,
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
    /// The sealed form of the unsigned container `unsigned`: the encrypted
    /// form, or the signed form when there is no recipient.
    pub fn seal(&self, unsigned: &[u8], uuid: &str) -> Result<Vec<u8>, String> {
        let signed = sign_compressed(unsigned, uuid, &self.signer, self.compression)?;
        if self.recipients.is_empty() {
            return Ok(signed);
        }
        encrypt_to_all(&signed, uuid, &self.recipients, self.compression)
    }

    /// A file an encrypting rule writes beside its container (a `url`
    /// rule's recording), encrypted to the same recipients as the container,
    /// one `recipients` entry each: a General JWE JSON Serialization whose
    /// plaintext is `file` and whose `cty` is
    /// `mediatype`, with the headers placed as [`encrypt_compressed`] places
    /// them.
    ///
    /// Encrypted, not signed: the sealed container is signed, and it names
    /// this file's `content_hash`, which covers these bytes. No `uuid`: the
    /// file is not a vCon, and [`decrypt`] compares an unprotected `uuid`
    /// with the signed vCon inside.
    pub fn encrypt_file(&self, file: &[u8], mediatype: &str) -> Result<Vec<u8>, String> {
        let headers = JweHeaders {
            protected: None,
            unprotected: serde_json::json!({ "cty": mediatype, "enc": JWE_ENC }),
            recipient: Some(serde_json::json!({ "alg": JWE_ALG })),
        };
        encrypt_under(file, &self.recipients, &headers)
    }

    /// This sealing, compressing as `compression` says.
    #[must_use]
    pub fn compressed(mut self, compression: Compression) -> Self {
        self.compression = compression;
        self
    }

    /// This sealing, its signatures also naming the chain by the URL `url`
    /// in `x5u` ([`Signer::with_cert_url`]).
    ///
    /// # Errors
    ///
    /// A URL that is not `https://`.
    pub fn with_cert_url(mut self, url: &str) -> Result<Self, String> {
        self.signer = self.signer.with_cert_url(url)?;
        Ok(self)
    }
}

/// Read an encrypting rule's files: each recipient certificate, the signing
/// key, which must be readable by its owner only, and the signing chain.
pub fn load_sealing(
    encrypt_to: &[std::path::PathBuf],
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
        recipients: encrypt_to
            .iter()
            .map(|path| {
                Recipient::from_cert_pem(&read(path)?)
                    .map_err(|e| format!("'{}': {e}", path.display()))
            })
            .collect::<Result<_, String>>()?,
        compression: Compression::None,
    })
}

/// Read a `sign_only` rule's two files: the signing key, which must be
/// readable by its owner only, and its chain.
pub fn load_signing(
    sign_key: &std::path::Path,
    sign_cert: &std::path::Path,
) -> Result<Sealing, String> {
    let chain = std::fs::read_to_string(sign_cert)
        .map_err(|e| format!("cannot read '{}': {e}", sign_cert.display()))?;
    Ok(Sealing {
        signer: Signer::from_pem(&read_private_key("signing key", sign_key)?, &chain)?,
        recipients: Vec::new(),
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
/// private key, read from a file only its owner can read. Without a key it
/// still verifies a signed container ([`Opener::unwrap`]).
pub struct Opener {
    /// The PEM text of the RSA private key, when one was given.
    key_pem: Option<String>,
    /// Who must have signed what it opens.
    trust: SignerTrust,
    /// What fetches an `x5u` chain; `None` fetches none.
    x5u: Option<std::sync::Arc<X5uFetch>>,
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
        decryption_key(&key_pem)?;
        Ok(Self {
            key_pem: Some(key_pem),
            trust: SignerTrust::default(),
            x5u: None,
        })
    }

    /// An opener with no decryption key: [`Self::unwrap`] verifies a signed
    /// container and refuses an encrypted one.
    #[must_use]
    pub fn without_key() -> Self {
        Self {
            key_pem: None,
            trust: SignerTrust::default(),
            x5u: None,
        }
    }

    /// This opener, returning only containers whose signer `trust` accepts.
    #[must_use]
    pub fn trusting(mut self, trust: SignerTrust) -> Self {
        self.trust = trust;
        self
    }

    /// This opener, fetching the chain of a signature that names it only by
    /// `x5u` with `fetch`.
    #[must_use]
    pub fn fetching_x5u(mut self, fetch: std::sync::Arc<X5uFetch>) -> Self {
        self.x5u = Some(fetch);
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

    /// A file an encrypting rule wrote beside its container
    /// ([`Sealing::encrypt_file`]), decrypted. Its integrity against the
    /// container is the container's `content_hash`, which the caller checks
    /// over `jwe`.
    pub fn open_file(&self, jwe: &[u8]) -> Result<Vec<u8>, String> {
        let key = self.key_pem.as_deref().ok_or(NO_KEY)?;
        decrypt(jwe, key)
    }

    /// [`Self::open`] at `now`, in seconds since the Unix epoch: the time the
    /// signer's certificates must be valid at.
    pub fn open_at(&self, jwe: &[u8], max_unsigned: usize, now: u64) -> Result<Opened, String> {
        use sha2::Digest as _;
        let key = self.key_pem.as_deref().ok_or(NO_KEY)?;
        let signed = decrypt(jwe, key)?;
        let (unsigned, chain) = verify_with_signer(&signed, max_unsigned, self.x5u.as_deref())?;
        self.trust.check(&chain, now)?;
        let signer = chain.first().cloned().unwrap_or_default();
        let signer_sha256 = colon_hex(&sha2::Sha256::digest(&signer));
        Ok(Opened {
            unsigned,
            signer_sha256,
        })
    }
}

/// The most signed layers a reader walks (core-04 section 5.2.3): one per
/// re-signing, so a century of archive at one a decade, with room to spare.
pub const MAX_SIGNED_LAYERS: usize = 16;

/// Re-sign the signed vCon `signed` for a long-term archive, as
/// [core-04 section 5.2.3](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-5.2.3)
/// describes: "Before the expiration of the JWS1 signing certificate, the
/// content of JWS1 (the vCon) is verified and then JWS1 is signed as the
/// payload to construct JWS2."
///
/// - `signed` must be the signed form; `opener` verifies every layer and
///   checks the outermost signer by its trust ([`Opener::unwrap_at`]).
/// - The outermost signing certificate must be within its validity period
///   at `now`, in seconds since the Unix epoch.
/// - The new JWS carries `signed`, byte for byte, as its payload, and the
///   uuid of the vCon inside in its signature's `header`.
///
/// # Errors
///
/// Not the signed form, a signature that does not verify, a signer the
/// trust refuses, a signing certificate outside its validity period, or a
/// signing failure.
pub fn resign_at(
    signed: &[u8],
    signer: &Signer,
    opener: &Opener,
    max_unsigned: usize,
    now: u64,
) -> Result<Vec<u8>, String> {
    let value: serde_json::Value =
        serde_json::from_slice(signed).map_err(|e| format!("not JSON: {e}"))?;
    if form_of(&value) != Form::Signed {
        return Err(
            "the vCon is not signed: draft-ietf-vcon-vcon-core-04 section 5.2.3 re-signs a \
             signed vCon (the signed form, `payload` and `signatures`)"
                .into(),
        );
    }
    let inner = opener.unwrap_at(signed, max_unsigned, now)?;
    let (_, chain) = verify_with_signer(signed, max_unsigned, opener.x5u.as_deref())?;
    let leaf = chain
        .first()
        .ok_or("the signature carries no `x5c` certificate")?;
    let (not_before, not_after) = certificate_validity(leaf)?;
    if now < not_before || now > not_after {
        return Err(format!(
            "the vCon's signing certificate is not valid now: it is valid from {} to {} \
             (seconds since the Unix epoch), and section 5.2.3 re-signs before it expires",
            not_before, not_after
        ));
    }
    let uuid = value["signatures"][0]["header"]["uuid"]
        .as_str()
        .map(str::to_owned)
        .or_else(|| {
            serde_json::from_slice::<serde_json::Value>(&inner.unsigned)
                .ok()
                .and_then(|v| v["uuid"].as_str().map(str::to_owned))
        })
        .ok_or("the vCon carries no uuid")?;
    sign(signed, &uuid, signer)
}

/// The validity period of a DER certificate
/// ([RFC 5280 section 4.1.2.5](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.5)),
/// `notBefore` and `notAfter` in seconds since the Unix epoch.
///
/// # Errors
///
/// A certificate that is not DER X.509, or a time that does not parse.
pub fn certificate_validity(certificate: &[u8]) -> Result<(u64, u64), String> {
    const BAD: &str = "the certificate is not DER X.509";
    let (0x30, body, _, _) = der_element(certificate).ok_or(BAD)? else {
        return Err(BAD.into());
    };
    let (0x30, tbs, _, _) = der_element(body).ok_or(BAD)? else {
        return Err(BAD.into());
    };
    let mut rest = tbs;
    if rest.first() == Some(&0xA0) {
        rest = der_element(rest).ok_or(BAD)?.3;
    }
    // serialNumber, signature, issuer
    for _ in 0..3 {
        rest = der_element(rest).ok_or(BAD)?.3;
    }
    let (0x30, validity, _, _) = der_element(rest).ok_or(BAD)? else {
        return Err(BAD.into());
    };
    let (tag, first, _, after) = der_element(validity).ok_or(BAD)?;
    let (tag2, second, _, _) = der_element(after).ok_or(BAD)?;
    Ok((x509_time(tag, first)?, x509_time(tag2, second)?))
}

/// A `UTCTime` (tag 0x17, `YYMMDDHHMMSSZ`, years 1950 to 2049) or
/// `GeneralizedTime` (tag 0x18, `YYYYMMDDHHMMSSZ`) in seconds since the
/// Unix epoch (RFC 5280 sections 4.1.2.5.1 and 4.1.2.5.2).
fn x509_time(tag: u8, text: &[u8]) -> Result<u64, String> {
    let text = std::str::from_utf8(text).map_err(|_| "a certificate time is not ASCII")?;
    let full = match (tag, text.len()) {
        (0x17, 13) => {
            let year: u32 = text[..2].parse().map_err(|_| "a UTCTime year")?;
            format!("{}{text}", if year >= 50 { "19" } else { "20" })
        }
        (0x18, 15) => text.to_owned(),
        _ => return Err("a certificate time is neither UTCTime nor GeneralizedTime".into()),
    };
    let parsed = chrono::NaiveDateTime::parse_from_str(&full, "%Y%m%d%H%M%SZ")
        .map_err(|e| format!("a certificate time does not parse: {e}"))?;
    u64::try_from(parsed.and_utc().timestamp())
        .map_err(|_| "a certificate time is before 1970".to_owned())
}

/// Why an encrypted container was not opened: no decryption key was given.
pub const NO_KEY: &str = "the container is encrypted (draft-ietf-vcon-vcon-core-04 section 5.3), \
     and no decryption key was given: give --vcon-key, or [vcon_input] key in the config file";

/// Why a container was refused when a signer check is configured and the
/// container carries no signature.
pub const NOT_SIGNED: &str = "the container is not signed, so it has no signer for \
     --vcon-signer-ca or --vcon-signer-sha256 to check";

/// One layer [`Opener::unwrap`] took off a container on its way to the
/// unsigned vCon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Layer {
    /// The gzip format ([core-04 section 6.2](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-6.2)),
    /// inflated.
    Gzip,
    /// The encrypted form, decrypted.
    Encrypted,
    /// The signed form, verified: the SHA-256 fingerprint of the signing
    /// certificate, as `openssl x509 -noout -fingerprint -sha256` prints it.
    Signed(String),
}

impl std::fmt::Display for Layer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Gzip => f.write_str("gzip format, inflated"),
            Self::Encrypted => f.write_str("encrypted form, decrypted"),
            Self::Signed(fingerprint) => {
                write!(f, "signed form, verified, signer SHA-256 {fingerprint}")
            }
        }
    }
}

/// A container in any form, unwrapped to the unsigned vCon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unwrapped {
    /// The unsigned vCon, or the bytes as given when they are not a JSON
    /// form this reads.
    pub unsigned: Vec<u8>,
    /// The layers taken off, outermost first. Empty for an unsigned vCon.
    pub layers: Vec<Layer>,
}

impl Opener {
    /// The unsigned vCon inside `bytes`, whatever form they are in, as
    /// [core-04 section 5.4](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-5.4)
    /// tells the forms apart:
    ///
    /// - bytes that start with the gzip magic ([RFC 1952 section 2.3.1](https://www.rfc-editor.org/rfc/rfc1952.html#section-2.3.1)) are
    ///   inflated first, up to `max_unsigned` bytes;
    /// - the encrypted form is decrypted with this opener's key, and refused
    ///   with [`NO_KEY`] when it has none; its plaintext must be the signed
    ///   form, as section 5.3 requires;
    /// - the signed form is verified, and its signer checked by this
    ///   opener's trust;
    /// - anything else is returned as it is, for the reader to judge.
    ///
    /// With a signer check configured, a container with no signed layer is
    /// refused with [`NOT_SIGNED`].
    ///
    /// # Errors
    ///
    /// Why the container did not inflate, decrypt or verify, or why its
    /// signer was refused.
    pub fn unwrap(&self, bytes: &[u8], max_unsigned: usize) -> Result<Unwrapped, String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        self.unwrap_at(bytes, max_unsigned, now)
    }

    /// [`Self::unwrap`] at `now`, in seconds since the Unix epoch: the time
    /// the signer's certificates must be valid at.
    ///
    /// # Errors
    ///
    /// As [`Self::unwrap`].
    pub fn unwrap_at(
        &self,
        bytes: &[u8],
        max_unsigned: usize,
        now: u64,
    ) -> Result<Unwrapped, String> {
        use sha2::Digest as _;
        let mut layers = Vec::new();
        let mut current = if bytes.starts_with(&GZIP_MAGIC) {
            layers.push(Layer::Gzip);
            gunzip_capped(bytes, max_unsigned)?
        } else {
            bytes.to_vec()
        };
        let form = |bytes: &[u8]| {
            serde_json::from_slice::<serde_json::Value>(bytes)
                .map_or(Form::Unknown, |value| form_of(&value))
        };
        if form(&current) == Form::Encrypted {
            let key = self.key_pem.as_deref().ok_or(NO_KEY)?;
            current = decrypt(&current, key)?;
            layers.push(Layer::Encrypted);
            if form(&current) != Form::Signed {
                return Err(
                    "the encrypted container does not hold the signed form, which \
                     draft-ietf-vcon-vcon-core-04 section 5.3 requires"
                        .into(),
                );
            }
        }
        if form(&current) != Form::Signed && self.trust.is_active() {
            return Err(NOT_SIGNED.into());
        }
        // core-04 section 5.2.3: a signed vCon re-signed for an archive is
        // the payload of the next JWS. Every layer's signature is verified;
        // the outermost signer is the one the trust checks, and the inner
        // ones are "assumed to have valid integrity".
        let mut depth = 0usize;
        while form(&current) == Form::Signed {
            depth += 1;
            if depth > MAX_SIGNED_LAYERS {
                return Err(format!(
                    "the container nests more than {MAX_SIGNED_LAYERS} signed layers"
                ));
            }
            let (unsigned, chain) =
                verify_with_signer(&current, max_unsigned, self.x5u.as_deref())?;
            if depth == 1 {
                self.trust.check(&chain, now)?;
            }
            let signer = chain.first().cloned().unwrap_or_default();
            layers.push(Layer::Signed(colon_hex(&sha2::Sha256::digest(&signer))));
            current = unsigned;
        }
        Ok(Unwrapped {
            unsigned: current,
            layers,
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
                recipients: vec![recipient()?],
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
            "the gzip form is smaller than the uncompressed form"
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
        let jwe = encrypt_under(&signed, std::slice::from_ref(&recipient()?), &headers)?;
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

    /// The gzip of `bytes`.
    fn gzipped(bytes: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        use std::io::Write as _;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(bytes)?;
        Ok(encoder.finish()?)
    }

    /// An opener holding the fixture key, from a private copy.
    fn keyed_opener() -> Result<(Opener, tempfile::TempDir), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("k.pem");
        std::fs::write(&path, fixture("fake_grp.key")?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok((Opener::load(&path)?, dir))
    }

    /// core-04 section 5.4: every form, and the gzip format of each, unwraps
    /// to the unsigned vCon, naming each layer taken off.
    #[test]
    fn unwrap_reads_every_form_and_its_gzip_format() -> TestResult {
        let (opener, _dir) = keyed_opener()?;
        let signed = sign(&unsigned(), UUID, &signer()?)?;
        let sealed = seal(&unsigned(), UUID, &signer()?, &recipient()?)?;
        let cases: [(Vec<u8>, &[&str]); 6] = [
            (unsigned(), &[]),
            (gzipped(&unsigned())?, &["gzip"]),
            (signed.clone(), &["signed"]),
            (gzipped(&signed)?, &["gzip", "signed"]),
            (sealed.clone(), &["encrypted", "signed"]),
            (gzipped(&sealed)?, &["gzip", "encrypted", "signed"]),
        ];
        for (bytes, want) in cases {
            let got = opener.unwrap(&bytes, usize::MAX)?;
            assert_eq!(got.unsigned, unsigned());
            let names: Vec<&str> = got
                .layers
                .iter()
                .map(|l| match l {
                    Layer::Gzip => "gzip",
                    Layer::Encrypted => "encrypted",
                    Layer::Signed(_) => "signed",
                })
                .collect();
            assert_eq!(names, want);
        }
        Ok(())
    }

    /// Without a key an encrypted container is refused with [`NO_KEY`]; a
    /// signed one still verifies.
    #[test]
    fn unwrap_without_a_key_refuses_only_the_encrypted_form() -> TestResult {
        let opener = Opener::without_key();
        let sealed = seal(&unsigned(), UUID, &signer()?, &recipient()?)?;
        assert_eq!(
            opener.unwrap(&sealed, usize::MAX).err().as_deref(),
            Some(NO_KEY)
        );
        let signed = sign(&unsigned(), UUID, &signer()?)?;
        assert_eq!(opener.unwrap(&signed, usize::MAX)?.unsigned, unsigned());
        Ok(())
    }

    /// With a signer check, a container with no signed layer is refused with
    /// [`NOT_SIGNED`], in the gzip format too.
    #[test]
    fn unwrap_with_a_signer_check_refuses_an_unsigned_container() -> TestResult {
        let pki = pki("checked", 2040)?;
        let opener = Opener::without_key().trusting(SignerTrust::from_ca_pem(&pki.ca, true)?);
        for bytes in [unsigned(), gzipped(&unsigned())?] {
            assert_eq!(
                opener
                    .unwrap_at(&bytes, usize::MAX, IN_2030)
                    .err()
                    .as_deref(),
                Some(NOT_SIGNED)
            );
        }
        let ours = Signer::from_pem(&fixture("fake_grp.key")?, &pki.chain)?;
        let signed = sign(&unsigned(), UUID, &ours)?;
        assert_eq!(
            opener.unwrap_at(&signed, usize::MAX, IN_2030)?.unsigned,
            unsigned()
        );
        let theirs = sign(&unsigned(), UUID, &signer()?)?;
        assert!(opener.unwrap_at(&theirs, usize::MAX, IN_2030).is_err());
        Ok(())
    }

    /// core-04 section 5.3: an encrypted container must hold the signed
    /// form; one that holds the unsigned vCon directly is refused.
    #[test]
    fn unwrap_refuses_an_encrypted_container_that_is_not_signed_inside() -> TestResult {
        let (opener, _dir) = keyed_opener()?;
        let jwe = encrypt(&unsigned(), UUID, &recipient()?)?;
        let err = opener
            .unwrap(&jwe, usize::MAX)
            .err()
            .ok_or("an unsigned plaintext was accepted")?;
        assert!(err.contains("signed form"), "{err}");
        Ok(())
    }

    /// The gzip format is inflated within the cap.
    #[test]
    fn unwrap_caps_the_gzip_format() -> TestResult {
        let opener = Opener::without_key();
        let size = unsigned().len();
        assert!(opener.unwrap(&gzipped(&unsigned())?, size - 1).is_err());
        assert_eq!(
            opener.unwrap(&gzipped(&unsigned())?, size)?.unsigned,
            unsigned()
        );
        Ok(())
    }

    /// Hex text to bytes, for the published test vectors.
    fn hex(text: &str) -> Vec<u8> {
        let digits: Vec<u8> = text
            .bytes()
            .filter(u8::is_ascii_hexdigit)
            .map(|b| (b as char).to_digit(16).unwrap_or(0) as u8)
            .collect();
        digits.chunks(2).map(|p| (p[0] << 4) | p[1]).collect()
    }

    /// [RFC 3394 section 4.6](https://www.rfc-editor.org/rfc/rfc3394.html#section-4.6): 256 bits of key data wrapped with a
    /// 256-bit KEK. Unwrap gives the key back; a changed byte or another
    /// KEK fails the integrity check.
    #[test]
    fn aes_key_wrap_matches_rfc_3394_section_4_6() -> TestResult {
        let kek: [u8; 32] = hex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
            .try_into()
            .map_err(|_| "kek")?;
        let key = hex("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F");
        let wrapped = hex(
            "28C9F404C4B810F4 CBCCB35CFB87F826 3F5786E2D80ED326 CBC7F0E71A99F43B FB988B9B7A02DD21",
        );
        assert_eq!(aes_key_wrap(&kek, &key)?, wrapped);
        assert_eq!(aes_key_unwrap(&kek, &wrapped)?, key);
        let mut changed = wrapped.clone();
        changed[20] ^= 1;
        assert!(aes_key_unwrap(&kek, &changed).is_err());
        let mut other = kek;
        other[0] ^= 1;
        assert!(aes_key_unwrap(&other, &wrapped).is_err());
        assert!(aes_key_wrap(&kek, &key[..15]).is_err());
        Ok(())
    }

    /// [RFC 7518 Appendix C](https://www.rfc-editor.org/rfc/rfc7518.html#appendix-C): Bob's static key agreed with Alice's ephemeral
    /// key gives the published `Z`, and the Concat KDF the published key.
    #[test]
    fn ecdh_and_the_concat_kdf_match_rfc_7518_appendix_c() -> TestResult {
        let d = URL_SAFE_NO_PAD.decode("VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw")?;
        let bob = p256::SecretKey::from_slice(&d)?;
        let alice = point_of_jwk(&serde_json::json!({
            "kty": "EC", "crv": "P-256",
            "x": "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
            "y": "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
        }))?;
        let z = ecdh_static(&bob, &alice).ok_or("not on the curve")?;
        assert_eq!(
            z,
            [
                158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49,
                110, 163, 218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196
            ]
        );
        let key = concat_kdf(&z, "A128GCM", b"Alice", b"Bob", 16);
        assert_eq!(URL_SAFE_NO_PAD.encode(key), "VqqN6vgjbSBcIijNcacQGg");
        Ok(())
    }

    /// A fresh EC P-256 key and its self-signed certificate, PEM.
    fn ec_pair() -> Result<(String, String), Box<dyn std::error::Error>> {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let cert = rcgen::CertificateParams::default().self_signed(&key)?;
        Ok((key.serialize_pem(), cert.pem()))
    }

    /// One content key, an RSA and an EC recipient: each key opens the
    /// container, a third does not, and the EC recipient's header carries
    /// `ECDH-ES+A256KW` and its `epk`.
    #[test]
    fn every_recipient_opens_a_container_encrypted_to_several() -> TestResult {
        let (ec_key, ec_cert) = ec_pair()?;
        let (stranger, _) = ec_pair()?;
        let recipients = vec![recipient()?, Recipient::from_cert_pem(&ec_cert)?];
        let signed = sign(&unsigned(), UUID, &signer()?)?;
        let jwe = encrypt_to_all(&signed, UUID, &recipients, Compression::None)?;
        let value: serde_json::Value = serde_json::from_slice(&jwe)?;
        assert_eq!(value["recipients"][0]["header"]["alg"], JWE_ALG);
        assert_eq!(value["recipients"][1]["header"]["alg"], JWE_ALG_ECDH);
        assert_eq!(value["recipients"][1]["header"]["epk"]["crv"], "P-256");
        assert_eq!(decrypt(&jwe, &fixture("fake_grp.key")?)?, signed);
        assert_eq!(decrypt(&jwe, &ec_key)?, signed);
        assert!(decrypt(&jwe, &stranger).is_err());
        Ok(())
    }

    /// A direct `ECDH-ES` recipient ([RFC 7518 section 4.6](https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6), the agreed key is
    /// the content key) is read, as another producer may write one.
    #[test]
    fn a_direct_ecdh_es_recipient_is_read() -> TestResult {
        let (ec_key, ec_cert) = ec_pair()?;
        let Recipient::P256(point) = Recipient::from_cert_pem(&ec_cert)? else {
            return Err("an EC recipient".into());
        };
        let random = ring::rand::SystemRandom::new();
        let ephemeral =
            ring::agreement::EphemeralPrivateKey::generate(&ring::agreement::ECDH_P256, &random)
                .map_err(|_| "random")?;
        let epk = jwk_of_point(ephemeral.compute_public_key().map_err(|_| "epk")?.as_ref())?;
        let peer = ring::agreement::UnparsedPublicKey::new(&ring::agreement::ECDH_P256, &point);
        let cek = ring::agreement::agree_ephemeral(ephemeral, &peer, |z| {
            concat_kdf(z, JWE_ENC, b"", b"", 64)
        })
        .map_err(|_| "agree")?;
        let cek: [u8; 64] = cek.try_into().map_err(|_| "cek")?;
        let iv = [7u8; 16];
        let signed = sign(&unsigned(), UUID, &signer()?)?;
        let (ciphertext, tag) = a256cbc_hs512_seal(&cek, &iv, b"", &signed)?;
        let jwe = serde_json::json!({
            "unprotected": { "enc": JWE_ENC, "cty": CONTENT_TYPE },
            "recipients": [{ "header": { "alg": JWE_ALG_ECDH_DIRECT, "epk": epk }, "encrypted_key": "" }],
            "iv": URL_SAFE_NO_PAD.encode(iv),
            "ciphertext": URL_SAFE_NO_PAD.encode(ciphertext),
            "tag": URL_SAFE_NO_PAD.encode(tag),
        });
        assert_eq!(decrypt(jwe.to_string().as_bytes(), &ec_key)?, signed);
        Ok(())
    }

    /// An EC signer signs `ES256` and verifies; the `alg` must be the one
    /// its certificate's key allows, so `RS256` on an EC certificate is
    /// refused.
    #[test]
    fn an_ec_signer_signs_es256_and_alg_must_match_the_key() -> TestResult {
        let (key, cert) = ec_pair()?;
        let ec = Signer::from_pem(&key, &cert)?;
        assert_eq!(ec.alg(), JWS_ALG_ES256);
        let signed = sign(&unsigned(), UUID, &ec)?;
        assert_eq!(verify(&signed)?, unsigned());
        let payload = URL_SAFE_NO_PAD.encode(unsigned());
        let protected = URL_SAFE_NO_PAD.encode(serde_json::json!({ "alg": JWS_ALG }).to_string());
        let signature = ec.sign_input(format!("{protected}.{payload}").as_bytes())?;
        let lying = serde_json::json!({
            "payload": payload,
            "signatures": [{
                "protected": protected,
                "header": { "x5c": ec.x5c, "uuid": UUID },
                "signature": URL_SAFE_NO_PAD.encode(signature),
            }],
        });
        let err = verify(lying.to_string().as_bytes())
            .err()
            .ok_or("RS256 on an EC certificate was accepted")?;
        assert!(err.contains("not the algorithm"), "{err}");
        let (other_key, _) = ec_pair()?;
        assert!(Signer::from_pem(&other_key, &cert).is_err(), "another key");
        Ok(())
    }

    /// The validity period reads in both encodings RFC 5280 section
    /// 4.1.2.5 allows: `UTCTime` through 2049, `GeneralizedTime` from 2050.
    #[test]
    fn certificate_validity_reads_utc_and_generalized_time() -> TestResult {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let mut params = rcgen::CertificateParams::default();
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2055, 1, 1);
        let cert = params.self_signed(&key)?;
        // 2020-01-01 and 2055-01-01, 00:00:00 UTC.
        assert_eq!(
            certificate_validity(cert.der())?,
            (1_577_836_800, 2_682_374_400)
        );
        assert!(certificate_validity(b"not a certificate").is_err());
        Ok(())
    }

    /// Re-signing nests the signed form, and the reader walks every layer
    /// to the unsigned vCon, naming a signer per layer; one more layer than
    /// [`MAX_SIGNED_LAYERS`] is refused.
    #[test]
    fn unwrap_walks_nested_signed_layers() -> TestResult {
        let opener = Opener::without_key();
        let mut current = sign(&unsigned(), UUID, &signer()?)?;
        for depth in 1..=MAX_SIGNED_LAYERS {
            let got = opener.unwrap_at(&current, usize::MAX, IN_2030)?;
            assert_eq!(got.unsigned, unsigned());
            assert_eq!(got.layers.len(), depth);
            current = sign(&current, UUID, &signer()?)?;
        }
        let err = opener
            .unwrap_at(&current, usize::MAX, IN_2030)
            .err()
            .ok_or("too deep a nesting was accepted")?;
        assert!(err.contains("nests more than"), "{err}");
        Ok(())
    }

    /// The trust checks the outermost signer of an archive, not the inner
    /// ones core-04 section 5.2.3 assumes: an inner signer the CA did not
    /// issue still reads under an outer one it did.
    #[test]
    fn the_trust_checks_the_outermost_signer_only() -> TestResult {
        let ours = pki("archive", 2040)?;
        let opener = Opener::without_key().trusting(SignerTrust::from_ca_pem(&ours.ca, true)?);
        let inner = sign(&unsigned(), UUID, &signer()?)?;
        assert!(opener.unwrap_at(&inner, usize::MAX, IN_2030).is_err());
        let archive = sign(
            &inner,
            UUID,
            &Signer::from_pem(&fixture("fake_grp.key")?, &ours.chain)?,
        )?;
        assert_eq!(
            opener.unwrap_at(&archive, usize::MAX, IN_2030)?.unsigned,
            unsigned()
        );
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
        Ok(encrypt_under(
            signed,
            std::slice::from_ref(&recipient()?),
            &headers,
        )?)
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
        let jwe = encrypt_under(&signed, std::slice::from_ref(&recipient()?), &headers)?;
        let err = decrypt(&jwe, &fixture("fake_grp.key")?)
            .err()
            .ok_or("two enc values accepted")?;
        assert!(err.contains("enc"), "{err}");
        Ok(())
    }
}
