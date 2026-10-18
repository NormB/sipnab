// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The encrypted form of a vCon (draft-ietf-vcon-vcon-core-04 section 5.3):
//! the container is signed with JWS (RS256, the signer's certificate chain in
//! `x5c`), and the signed form is encrypted with JWE (`RSA-OAEP` key
//! encryption, `A256CBC-HS512` content encryption) to the recipient's
//! certificate.
//!
//! The checks that do not depend on sipnab agreeing with itself:
//! - the working group's own encrypted example (Appendix A.7), made by its
//!   reference tool, decrypts with its published key and its signature
//!   verifies;
//! - sipnab's RS256 over that example's signing input, with the same key, is
//!   byte for byte the signature the reference tool wrote (PKCS #1 v1.5 is
//!   deterministic);
//! - the content encryption reproduces the RFC 7518 Appendix B.3 test vector.
#![cfg(all(feature = "native", feature = "vcon"))]

use base64::Engine as _;
use sipnab::output::vcon_jose::{self, Form, Recipient, Signer};

type TestError = Box<dyn std::error::Error>;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/vcon-jose");
const EXAMPLE_UUID: &str = "01a07da8-c2bb-83e5-b9a2-279e0d16bc46";

fn fixture(name: &str) -> Result<String, TestError> {
    Ok(std::fs::read_to_string(format!("{FIXTURES}/{name}"))?)
}

fn b64u(s: &str) -> Result<Vec<u8>, TestError> {
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)?)
}

fn hex(s: &str) -> Vec<u8> {
    s.split_whitespace()
        .filter_map(|b| u8::from_str_radix(b, 16).ok())
        .collect()
}

/// The fixture signer: the key and chain the working group's example was
/// signed with.
fn grp_signer() -> Result<Signer, TestError> {
    let chain = format!(
        "{}{}{}",
        fixture("fake_grp.crt")?,
        fixture("fake_div.crt")?,
        fixture("fake_ca_root.crt")?
    );
    Ok(Signer::from_pem(&fixture("fake_grp.key")?, &chain)?)
}

/// A small unsigned container with a party name to look for in the output.
fn unsigned_container() -> Vec<u8> {
    serde_json::json!({
        "vcon": "0.4.0",
        "uuid": "019a0000-0000-8000-8000-000000000001",
        "created_at": "2026-10-13T12:00:00+00:00",
        "parties": [{ "name": "Unmistakable Party Name", "tel": "+15551230000" }],
        "dialog": [],
    })
    .to_string()
    .into_bytes()
}

#[test]
fn the_content_encryption_reproduces_rfc_7518_b3() -> Result<(), TestError> {
    let key: [u8; 64] = hex(
        "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b \
         1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 36 37 \
         38 39 3a 3b 3c 3d 3e 3f",
    )
    .try_into()
    .map_err(|_| "64-byte key")?;
    let iv: [u8; 16] = hex("1a f3 8c 2d c2 b9 6f fd d8 66 94 09 23 41 bc 04")
        .try_into()
        .map_err(|_| "16-byte iv")?;
    let plaintext = b"A cipher system must not be required to be secret, and it must be able to fall into the hands of the enemy without inconvenience";
    let aad = b"The second principle of Auguste Kerckhoffs";
    let (ciphertext, tag) = vcon_jose::a256cbc_hs512_seal(&key, &iv, aad, plaintext)?;
    assert_eq!(
        ciphertext,
        hex(
            "4a ff aa ad b7 8c 31 c5 da 4b 1b 59 0d 10 ff bd 3d d8 d5 d3 02 42 35 26 91 2d a0 37 \
             ec bc c7 bd 82 2c 30 1d d6 7c 37 3b cc b5 84 ad 3e 92 79 c2 e6 d1 2a 13 74 b7 7f 07 \
             75 53 df 82 94 10 44 6b 36 eb d9 70 66 29 6a e6 42 7e a7 5c 2e 08 46 a1 1a 09 cc f5 \
             37 0d c8 0b fe cb ad 28 c7 3f 09 b3 a3 b7 5e 66 2a 25 94 41 0a e4 96 b2 e2 e6 60 9e \
             31 e6 e0 2c c8 37 f0 53 d2 1f 37 ff 4f 51 95 0b be 26 38 d0 9d d7 a4 93 09 30 80 6d \
             07 03 b1 f6"
        )
    );
    assert_eq!(
        tag.to_vec(),
        hex(
            "4d d3 b4 c0 88 a7 f4 5c 21 68 39 64 5b 20 12 bf 2e 62 69 a8 c5 6a 81 6d bc 1b 26 77 \
             61 95 5b c5"
        )
    );
    assert_eq!(
        vcon_jose::a256cbc_hs512_open(&key, &iv, aad, &ciphertext, &tag)?,
        plaintext.to_vec()
    );
    let mut forged = tag;
    forged[0] ^= 1;
    assert!(vcon_jose::a256cbc_hs512_open(&key, &iv, aad, &ciphertext, &forged).is_err());
    Ok(())
}

#[test]
fn the_working_group_example_decrypts_and_its_signature_verifies() -> Result<(), TestError> {
    let example = fixture("ab_call_ext_rec_encrypted.vcon")?;
    let value: serde_json::Value = serde_json::from_str(&example)?;
    assert_eq!(vcon_jose::form_of(&value), Form::Encrypted);
    let signed = vcon_jose::decrypt(example.as_bytes(), &fixture("fake_grp.key")?)?;
    let signed_value: serde_json::Value = serde_json::from_slice(&signed)?;
    assert_eq!(vcon_jose::form_of(&signed_value), Form::Signed);
    let unsigned = vcon_jose::verify(&signed)?;
    let container: serde_json::Value = serde_json::from_slice(&unsigned)?;
    assert_eq!(vcon_jose::form_of(&container), Form::Unsigned);
    assert_eq!(container["uuid"], EXAMPLE_UUID);
    Ok(())
}

#[test]
fn sipnab_signs_the_example_s_input_exactly_as_the_reference_tool_did() -> Result<(), TestError> {
    let signed = vcon_jose::decrypt(
        fixture("ab_call_ext_rec_encrypted.vcon")?.as_bytes(),
        &fixture("fake_grp.key")?,
    )?;
    let jws: serde_json::Value = serde_json::from_slice(&signed)?;
    let signature = &jws["signatures"][0];
    let input = format!(
        "{}.{}",
        signature["protected"].as_str().ok_or("protected")?,
        jws["payload"].as_str().ok_or("payload")?
    );
    assert_eq!(
        grp_signer()?.rs256(input.as_bytes())?,
        b64u(signature["signature"].as_str().ok_or("signature")?)?
    );
    Ok(())
}

#[test]
fn a_wrong_key_and_a_tampered_container_are_refused() -> Result<(), TestError> {
    let example = fixture("ab_call_ext_rec_encrypted.vcon")?;
    assert!(vcon_jose::decrypt(example.as_bytes(), &fixture("other.key")?).is_err());
    let mut value: serde_json::Value = serde_json::from_str(&example)?;
    let ciphertext = value["ciphertext"].as_str().ok_or("ciphertext")?.to_owned();
    let flipped = if ciphertext.starts_with('A') {
        "B"
    } else {
        "A"
    };
    value["ciphertext"] = format!("{flipped}{}", &ciphertext[1..]).into();
    assert!(vcon_jose::decrypt(value.to_string().as_bytes(), &fixture("fake_grp.key")?).is_err());

    let signed = vcon_jose::decrypt(example.as_bytes(), &fixture("fake_grp.key")?)?;
    let mut jws: serde_json::Value = serde_json::from_slice(&signed)?;
    let payload = jws["payload"].as_str().ok_or("payload")?.to_owned();
    let flipped = if payload.starts_with('e') { "f" } else { "e" };
    jws["payload"] = format!("{flipped}{}", &payload[1..]).into();
    assert!(vcon_jose::verify(jws.to_string().as_bytes()).is_err());
    Ok(())
}

#[test]
fn a_sealed_container_opens_back_to_the_same_bytes_and_shows_nothing_in_clear()
-> Result<(), TestError> {
    let unsigned = unsigned_container();
    let recipient = Recipient::from_cert_pem(&fixture("fake_grp.crt")?)?;
    let sealed = vcon_jose::seal(
        &unsigned,
        "019a0000-0000-8000-8000-000000000001",
        &grp_signer()?,
        &recipient,
    )?;
    let text = String::from_utf8(sealed.clone())?;
    assert!(!text.contains("Unmistakable"), "{text}");
    assert!(!text.contains("5551230000"), "{text}");

    let value: serde_json::Value = serde_json::from_slice(&sealed)?;
    assert_eq!(vcon_jose::form_of(&value), Form::Encrypted);
    assert_eq!(
        value["unprotected"]["uuid"],
        "019a0000-0000-8000-8000-000000000001"
    );
    assert_eq!(
        value["unprotected"]["cty"], "application/vcon",
        "core-04 section 5.3.1"
    );
    // core-04 sections 5.3.1 and 5.3.2: `enc` unprotected, `alg` per
    // recipient, and no protected header left.
    assert_eq!(value["unprotected"]["enc"], "A256CBC-HS512");
    assert_eq!(value["recipients"][0]["header"]["alg"], "RSA-OAEP");
    assert_eq!(value.get("protected"), None);

    let signed = vcon_jose::decrypt(&sealed, &fixture("fake_grp.key")?)?;
    let jws: serde_json::Value = serde_json::from_slice(&signed)?;
    assert_eq!(
        jws["signatures"][0]["header"]["uuid"],
        "019a0000-0000-8000-8000-000000000001"
    );
    let jws_protected: serde_json::Value = serde_json::from_slice(&b64u(
        jws["signatures"][0]["protected"]
            .as_str()
            .ok_or("protected")?,
    )?)?;
    assert_eq!(jws_protected, serde_json::json!({ "alg": "RS256" }));
    // core-04 section 5.2: `x5c` in the unprotected `header`.
    assert_eq!(
        jws["signatures"][0]["header"]["x5c"]
            .as_array()
            .map(Vec::len),
        Some(3),
        "the whole chain, leaf first"
    );
    assert_eq!(vcon_jose::verify(&signed)?, unsigned);

    assert!(vcon_jose::decrypt(&sealed, &fixture("other.key")?).is_err());
    Ok(())
}

#[test]
fn two_seals_of_the_same_container_differ() -> Result<(), TestError> {
    let recipient = Recipient::from_cert_pem(&fixture("fake_grp.crt")?)?;
    let signer = grp_signer()?;
    let a = vcon_jose::seal(&unsigned_container(), "u", &signer, &recipient)?;
    let b = vcon_jose::seal(&unsigned_container(), "u", &signer, &recipient)?;
    let a: serde_json::Value = serde_json::from_slice(&a)?;
    let b: serde_json::Value = serde_json::from_slice(&b)?;
    assert_ne!(a["iv"], b["iv"], "a fresh IV each time");
    assert_ne!(
        a["recipients"][0]["encrypted_key"], b["recipients"][0]["encrypted_key"],
        "a fresh content key each time"
    );
    Ok(())
}

#[test]
fn a_signer_whose_certificate_is_not_its_key_is_refused() -> Result<(), TestError> {
    let err = Signer::from_pem(&fixture("other.key")?, &fixture("fake_grp.crt")?)
        .err()
        .ok_or("refused")?;
    assert!(err.contains("does not match"), "{err}");
    let err = Signer::from_pem(&fixture("fake_grp.key")?, "")
        .err()
        .ok_or("refused")?;
    assert!(err.contains("no certificate"), "{err}");
    let err = Recipient::from_cert_pem("not a certificate")
        .err()
        .ok_or("refused")?;
    assert!(err.contains("no certificate"), "{err}");
    Ok(())
}

/// The unprotected `uuid` is outside the authenticated data, so a container
/// whose outer `uuid` was changed must not decrypt as if it named the call.
#[test]
fn an_outer_uuid_that_disagrees_with_the_signed_one_is_refused() -> Result<(), TestError> {
    let recipient = Recipient::from_cert_pem(&fixture("fake_grp.crt")?)?;
    let sealed = vcon_jose::seal(
        &unsigned_container(),
        "inner-uuid",
        &grp_signer()?,
        &recipient,
    )?;
    let mut value: serde_json::Value = serde_json::from_slice(&sealed)?;
    value["unprotected"]["uuid"] = "outer-uuid".into();
    let err = vcon_jose::decrypt(value.to_string().as_bytes(), &fixture("fake_grp.key")?)
        .err()
        .ok_or("refused")?;
    assert!(
        err.contains("outer-uuid") && err.contains("inner-uuid"),
        "{err}"
    );
    Ok(())
}

/// A signature whose protected header names another algorithm is refused,
/// even when its bytes are a valid RS256 signature: the header is what a
/// reader trusts, so it must say what was done.
#[test]
fn a_signature_whose_header_names_another_algorithm_is_refused() -> Result<(), TestError> {
    let signer = grp_signer()?;
    let leaf = fixture("fake_grp.crt")?;
    let leaf: String = leaf.lines().filter(|l| !l.starts_with("-----")).collect();
    let protected = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::json!({ "alg": "PS256", "x5c": [leaf] }).to_string());
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(unsigned_container());
    let signature = signer.rs256(format!("{protected}.{payload}").as_bytes())?;
    let jws = serde_json::json!({
        "payload": payload,
        "signatures": [{
            "protected": protected,
            "signature": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature),
        }],
    });
    let err = vcon_jose::verify(jws.to_string().as_bytes())
        .err()
        .ok_or("refused")?;
    assert!(err.contains("PS256"), "{err}");
    Ok(())
}
