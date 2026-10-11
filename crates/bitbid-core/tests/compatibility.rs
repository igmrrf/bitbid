use bitbid_core::{address, crypto, protocol, token};
use k256::{SecretKey, elliptic_curve::sec1::ToEncodedPoint};
fn vector() -> serde_json::Value {
    serde_json::from_str(include_str!("vectors/ipfs-v1.json")).unwrap()
}
fn secret(n: u8) -> [u8; 32] {
    let mut key = [0; 32];
    key[31] = n;
    key
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn frozen_native_wasm_vector_and_registry_link() {
    let v = vector();
    let canonical = v["canonical_payload"].as_str().unwrap();
    let payload = protocol::decode_payload(canonical.as_bytes()).unwrap();
    assert_eq!(
        protocol::canonical_bytes(&payload).unwrap(),
        canonical.as_bytes()
    );
    assert_eq!(protocol::to_share_string(&payload).unwrap(), v["token"]);
    assert_eq!(
        token::unseal_to_string(v["token"].as_str().unwrap(), &secret(2)).unwrap(),
        v["plaintext"]
    );
    assert_eq!(
        token::unseal_to_string(canonical, &secret(2)).unwrap(),
        v["plaintext"]
    );
    assert_eq!(
        address::bytes_to_hex(
            &bitbid_core::registry::encode_bytes32(v["secret_id"].as_str().unwrap()).unwrap()
        ),
        format!("0x{}", v["registry_key_hex"].as_str().unwrap())
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn legacy_cli_json_remains_readable() {
    let v = vector();
    let mut json: serde_json::Value =
        serde_json::from_str(v["canonical_payload"].as_str().unwrap()).unwrap();
    json.as_object_mut().unwrap().remove("protocol_version");
    assert_eq!(
        token::unseal_to_string(&json.to_string(), &secret(2)).unwrap(),
        v["plaintext"]
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn production_entropy_and_binary_round_trip() {
    let public = address::bytes_to_hex(
        SecretKey::from_slice(&secret(2))
            .unwrap()
            .public_key()
            .to_encoded_point(false)
            .as_bytes(),
    );
    for plain in [b"".as_slice(), b"hello", &[0, 255, 128, 1]] {
        let a = token::seal_to_share_string(plain, &public).unwrap();
        let b = token::seal_to_share_string(plain, &public).unwrap();
        assert_ne!(a, b);
        assert_eq!(token::unseal(&a, &secret(2)).unwrap(), plain);
        assert_eq!(token::unseal(&b, &secret(2)).unwrap(), plain);
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rejects_unknown_version_bad_nonce_wrong_key_and_tampering() {
    let v = vector();
    let canonical = v["canonical_payload"].as_str().unwrap();
    assert!(
        protocol::decode_payload(
            canonical
                .replace("\"protocol_version\":1", "\"protocol_version\":2")
                .as_bytes()
        )
        .is_err()
    );
    assert!(token::unseal(v["token"].as_str().unwrap(), &secret(3)).is_err());
    for field in ["content", "content_key"] {
        let mut p = protocol::decode_payload(canonical.as_bytes()).unwrap();
        let body = if field == "content" {
            &mut p.content
        } else {
            &mut p.content_key
        };
        let mut bytes = body.as_bytes().to_vec();
        let last = bytes.len() - 3;
        bytes[last] = if bytes[last] == b'A' { b'B' } else { b'A' };
        *body = String::from_utf8(bytes).unwrap();
        assert!(token::unseal(&protocol::to_share_string(&p).unwrap(), &secret(2)).is_err());
    }
    let mut missing_content = protocol::decode_payload(canonical.as_bytes()).unwrap();
    missing_content.content.clear();
    assert!(
        token::unseal(
            &protocol::to_share_string(&missing_content).unwrap(),
            &secret(2)
        )
        .is_err()
    );
    for nonce in ["", "AA==", "AAAAAAAAAAAAAAAAAA=="] {
        assert!(
            crypto::decrypt_text(&format!("{nonce}:AAAAAAAAAAAAAAAAAAAAAA=="), &[0x42; 32])
                .is_err()
        );
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn bundle_metadata_and_public_mode_preserve_cli_semantics() {
    let recipient = SecretKey::from_slice(&secret(2)).unwrap();
    let mut payload = protocol::IpfsPayload::text("MAIN=secret".into());
    payload.no_export = true;
    payload.kind = Some(protocol::SecretKind::Env);
    payload.members = Some(vec![protocol::BundleMember {
        kind: protocol::SecretKind::Pem,
        filename: "cert.pem".into(),
        content: "synthetic certificate".into(),
        encoding: "utf8".into(),
        env: Some("TLS_CERT".into()),
    }]);
    let encrypted = crypto::seal_payload(payload.clone(), Some(&recipient.public_key())).unwrap();
    assert!(
        !String::from_utf8(protocol::canonical_bytes(&encrypted).unwrap())
            .unwrap()
            .contains("synthetic certificate")
    );
    assert!(token::unseal(&protocol::to_share_string(&encrypted).unwrap(), &secret(2)).is_err());
    let opened = crypto::open_payload(encrypted, Some(&secret(2)), false).unwrap();
    assert_eq!(opened.content, payload.content);
    assert!(opened.no_export);
    assert_eq!(opened.members.unwrap()[0].content, "synthetic certificate");
    let public =
        crypto::seal_payload(protocol::IpfsPayload::text("public example".into()), None).unwrap();
    assert!(crypto::open_payload(public.clone(), Some(&secret(2)), false).is_err());
    assert_eq!(
        crypto::open_payload(public, None, true).unwrap().content,
        "public example"
    );
}
