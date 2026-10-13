// SPDX-License-Identifier: MIT OR Apache-2.0

//! The signed and encrypted forms of a vCon.
//!
//! [draft-ietf-vcon-vcon-core-04 section 5.3](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-5.3)
//! says a vCon "MUST be signed first using JWS ... then encrypted using JWE".
//! So an encrypted container is two layers:
//!
//! - the signed form ([section 5.2](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-5.2)):
//!   a General JWS JSON Serialization ([RFC 7515 section 7.2.1](https://www.rfc-editor.org/rfc/rfc7515#section-7.2.1))
//!   whose payload is the unsigned container, signed `RS256` with the
//!   signer's certificate chain in `x5c`;
//! - the encrypted form: a General JWE JSON Serialization
//!   ([RFC 7516 section 7.2.1](https://www.rfc-editor.org/rfc/rfc7516#section-7.2.1))
//!   whose plaintext is that signed form, with the content key encrypted
//!   `RSA-OAEP` to the recipient's certificate and the content encrypted
//!   `A256CBC-HS512`, the algorithms the draft names.
//!
//! Header placement. RFC 7515 and RFC 7516 require the protected and
//! unprotected header names to be disjoint. The signed layer protects `alg`
//! and `x5c`, so the certificate chain is covered by the signature, and puts
//! `uuid` in the unprotected `header`. The encrypted layer protects `alg` and
//! `enc`, as the draft's Appendix A.7 example does, and carries `cty` and
//! `uuid` unprotected, so a store can file the container without the key. That
//! example repeats `enc` in all three of its headers; [`decrypt`] accepts a
//! name repeated with the same value and refuses one repeated with different
//! values.
//!
//! [`verify`] checks the signature against the first certificate in `x5c`. It
//! does not check who issued that certificate: that is a trust decision for
//! whoever reads the container.

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
/// The `cty` of the encrypted form: the media type of the draft's Appendix
/// A.7 example.
pub const CONTENT_TYPE: &str = "application/vcon+json";
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

/// The key and certificate chain a container is signed with.
pub struct Signer {
    /// The RSA private key the signature is made with.
    key: ring::signature::RsaKeyPair,
    /// The chain as `x5c` carries it: standard base64 DER, leaf first
    /// ([RFC 7515 section 4.1.6](https://www.rfc-editor.org/rfc/rfc7515#section-4.1.6)).
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

/// `A256CBC-HS512` encryption ([RFC 7518 section 5.2.5](https://www.rfc-editor.org/rfc/rfc7518#section-5.2.5)):
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

/// The HMAC-SHA-512 of [RFC 7518 section 5.2.2.1](https://www.rfc-editor.org/rfc/rfc7518#section-5.2.2.1), before truncation.
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
    let protected = URL_SAFE_NO_PAD
        .encode(serde_json::json!({ "alg": JWS_ALG, "x5c": signer.x5c }).to_string());
    let payload = URL_SAFE_NO_PAD.encode(unsigned);
    let signature = signer.rs256(format!("{protected}.{payload}").as_bytes())?;
    serde_json::to_vec(&serde_json::json!({
        "payload": payload,
        "signatures": [{
            "protected": protected,
            "header": { "uuid": uuid },
            "signature": URL_SAFE_NO_PAD.encode(signature),
        }],
    }))
    .map_err(|e| format!("the signed form: {e}"))
}

/// The encrypted form of `signed`: a General JWE JSON Serialization with a
/// fresh content key and IV.
pub fn encrypt(signed: &[u8], uuid: &str, recipient: &Recipient) -> Result<Vec<u8>, String> {
    let random = ring::rand::SystemRandom::new();
    let fresh = || "the system random source failed".to_owned();
    let cek: [u8; 64] = ring::rand::generate(&random).map_err(|_| fresh())?.expose();
    let iv: [u8; 16] = ring::rand::generate(&random).map_err(|_| fresh())?.expose();
    let protected =
        URL_SAFE_NO_PAD.encode(serde_json::json!({ "alg": JWE_ALG, "enc": JWE_ENC }).to_string());
    let (ciphertext, tag) = a256cbc_hs512_seal(&cek, &iv, protected.as_bytes(), signed)?;
    let mut seed = Prefilled::new(&random)?;
    let encrypted_key = recipient
        .key
        .encrypt(&mut seed, rsa::Oaep::new::<sha1_oaep::Sha1>(), &cek)
        .map_err(|e| format!("RSA-OAEP: {e}"))?;
    seed.finish()?;
    serde_json::to_vec(&serde_json::json!({
        "protected": protected,
        "unprotected": { "cty": CONTENT_TYPE, "uuid": uuid },
        "recipients": [{ "encrypted_key": URL_SAFE_NO_PAD.encode(encrypted_key) }],
        "iv": URL_SAFE_NO_PAD.encode(iv),
        "ciphertext": URL_SAFE_NO_PAD.encode(ciphertext),
        "tag": URL_SAFE_NO_PAD.encode(tag),
    }))
    .map_err(|e| format!("the encrypted form: {e}"))
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
/// as `RS256` against the first certificate of its `x5c`.
pub fn verify(jws: &[u8]) -> Result<Vec<u8>, String> {
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
        let leaf = headers
            .iter()
            .find_map(|h| h["x5c"].as_array().and_then(|c| c.first()))
            .and_then(|c| c.as_str())
            .ok_or("a signature carries no `x5c` certificate")?;
        let leaf = STANDARD
            .decode(leaf)
            .map_err(|e| format!("`x5c` is not base64: {e}"))?;
        let public = rsa_public_key(subject_public_key_info(&leaf)?)?;
        ring::signature::UnparsedPublicKey::new(
            &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            public,
        )
        .verify(
            format!("{protected_b64}.{payload_b64}").as_bytes(),
            &b64u_field(signature, "signature")?,
        )
        .map_err(|_| "a signature does not verify against its certificate".to_owned())?;
    }
    URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| format!("`payload` is not base64url: {e}"))
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
/// ([RFC 5280 section 4.1](https://www.rfc-editor.org/rfc/rfc5280#section-4.1)):
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
        seal(unsigned, uuid, &self.signer, &self.recipient)
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(sign_key)
            .map_err(|e| format!("cannot read '{}': {e}", sign_key.display()))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(format!(
                "the signing key '{}' can be read by other users (mode {:o}): chmod 600 it",
                sign_key.display(),
                mode & 0o777
            ));
        }
    }
    Ok(Sealing {
        signer: Signer::from_pem(&read(sign_key)?, &read(sign_cert)?)?,
        recipient: Recipient::from_cert_pem(&read(encrypt_to)?)?,
    })
}
