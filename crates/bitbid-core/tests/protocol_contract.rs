//! Literal wire contracts run unchanged on native and WASM.
use base64::prelude::{BASE64_STANDARD, Engine as _};
use bitbid_core::{legacy_seal, protocol, token};
use protocol::{BundleMember, IpfsPayload, ProtocolError, SecretKind};

const LEGACY_TOKEN: &str = "bitbid1:AQAFYWxpY2VBBHm+Zn753LusVaBilc6HCwcCm/zbLc4o2VnygVsW+BeYSDradyajxGVdpPv8DhEIqP0XtEimhVQZnEfQj/sQ1LgBAQEBAQEBAQEBAQEAMPcx6YkasDdkcXVIz1Uu6cYGRywV2pcOTmOa6SbII3/gTfAI0d9fUlVeXP7kDEN79AICAgICAgICAgICApCMcmC1mHflxNL2VeqQ1py7cWPk8kzTYJYM+zm4aWxwPQJM";

fn secret(n: u8) -> [u8; 32] {
    let mut key = [0; 32];
    key[31] = n;
    key
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn full_metadata_has_frozen_field_order_escaping_and_member_order() {
    let mut payload = IpfsPayload::text("line\n\"🔒\\".into());
    payload.content_key = "wrapped".into();
    payload.ephemeral_pubkey = Some("0x04".into());
    payload.kind = Some(SecretKind::Env);
    payload.filename = Some("config.env".into());
    payload.no_export = true;
    payload.members = Some(vec![
        BundleMember {
            kind: SecretKind::Pem,
            filename: "key.pem".into(),
            content: "cipher-a".into(),
            encoding: "utf8".into(),
            env: Some("TLS_KEY".into()),
        },
        BundleMember {
            kind: SecretKind::Json,
            filename: "data.json".into(),
            content: "cipher-b".into(),
            encoding: "base64".into(),
            env: None,
        },
    ]);
    payload.content_encoding = Some("base64".into());
    let expected = r#"{"protocol_version":1,"content":"line\n\"🔒\\","content_key":"wrapped","ephemeral_pubkey":"0x04","kind":"env","filename":"config.env","no_export":true,"members":[{"kind":"pem","filename":"key.pem","content":"cipher-a","encoding":"utf8","env":"TLS_KEY"},{"kind":"json","filename":"data.json","content":"cipher-b","encoding":"base64"}],"content_encoding":"base64"}"#;
    assert_eq!(
        protocol::canonical_bytes(&payload).unwrap(),
        expected.as_bytes()
    );
    assert_eq!(
        protocol::to_share_string(&payload).unwrap(),
        format!("bitbid2:{}", BASE64_STANDARD.encode(expected))
    );
    let decoded = protocol::decode_payload(expected.as_bytes()).unwrap();
    assert_eq!(
        protocol::canonical_bytes(&decoded).unwrap(),
        expected.as_bytes()
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn legacy_defaults_nulls_and_reordered_json_normalize_to_frozen_bytes() {
    let minimal = r#"{"protocol_version":1,"content":"","content_key":"","ephemeral_pubkey":null}"#;
    assert_eq!(
        protocol::canonical_bytes(&IpfsPayload::text(String::new())).unwrap(),
        minimal.as_bytes()
    );
    let legacy = br#"{ "future_hint": 9, "no_export": false, "filename": null,
        "content_key": "", "content": "", "members": null, "kind": null,
        "content_encoding": null }"#;
    let decoded = protocol::decode_payload(legacy).unwrap();
    assert_eq!(
        protocol::canonical_bytes(&decoded).unwrap(),
        minimal.as_bytes()
    );
    let member_defaults = br#"{"content":"","content_key":"","members":[{"content":"x","filename":"c","kind":"cred"}]}"#;
    assert_eq!(
        protocol::canonical_bytes(&protocol::decode_payload(member_defaults).unwrap()).unwrap(),
        br#"{"protocol_version":1,"content":"","content_key":"","ephemeral_pubkey":null,"members":[{"kind":"cred","filename":"c","content":"x","encoding":"utf8"}]}"#
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn explicit_versions_and_malformed_json_fail_closed_on_both_transports() {
    for version in [0, 2, 255] {
        let json = format!(r#"{{"protocol_version":{version},"content":"","content_key":""}}"#);
        for input in [
            json.clone(),
            format!("bitbid2:{}", BASE64_STANDARD.encode(&json)),
        ] {
            assert!(
                matches!(protocol::from_share_string(&input), Err(ProtocolError::Version(v)) if v == version)
            );
        }
    }
    for json in [
        r#"{"protocol_version":null,"content":"","content_key":""}"#,
        r#"{"protocol_version":"1","content":"","content_key":""}"#,
        r#"{"protocol_version":256,"content":"","content_key":""}"#,
        r#"{"protocol_version":1.0,"content":"","content_key":""}"#,
        r#"{"protocol_version":1,"protocol_version":2,"content":"","content_key":""}"#,
        r#"{"content":"","content":"other","content_key":""}"#,
        r#"{"content":""}"#,
        r#"{"content":null,"content_key":""}"#,
        r#"{"content":"","content_key":"","no_export":"true"}"#,
        r#"{"content":"","content_key":"","kind":"unknown"}"#,
        r#"{"content":"","content_key":"","members":[{}]}"#,
        r#"{"content":"","content_key":""} trailing"#,
        "{",
    ] {
        assert!(
            matches!(
                protocol::decode_payload(json.as_bytes()),
                Err(ProtocolError::Json(_))
            ),
            "{json}"
        );
        let share = format!("bitbid2:{}", BASE64_STANDARD.encode(json));
        assert!(token::unseal(&share, &secret(2)).is_err(), "{json}");
    }
    for share in ["bitbid3:AAAA", "BITBID2:AAAA", "garbage"] {
        assert!(matches!(
            protocol::from_share_string(share),
            Err(ProtocolError::Prefix)
        ));
    }
    for share in ["bitbid2:%%%", "bitbid2:e30", "bitbid2:_w=="] {
        assert!(matches!(
            protocol::from_share_string(share),
            Err(ProtocolError::Base64(_))
        ));
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn raw_and_encoded_inputs_enforce_the_wire_size_limit() {
    let oversized = vec![b' '; protocol::MAX_WIRE_BYTES + 1];
    assert!(matches!(
        protocol::decode_payload(&oversized),
        Err(ProtocolError::Size)
    ));
    drop(oversized);
    let oversized_token = format!(
        "bitbid2:{}",
        "A".repeat(protocol::MAX_WIRE_BYTES.div_ceil(3) * 4 + 1)
    );
    assert!(matches!(
        protocol::from_share_string(&oversized_token),
        Err(ProtocolError::Size)
    ));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn canonical_writer_accepts_the_exact_limit_and_rejects_one_byte_more() {
    let mut payload = IpfsPayload::text(String::new());
    let overhead = protocol::canonical_bytes(&payload).unwrap().len();
    payload.content = "a".repeat(protocol::MAX_WIRE_BYTES - overhead);
    let bytes = protocol::canonical_bytes(&payload).unwrap();
    assert_eq!(bytes.len(), protocol::MAX_WIRE_BYTES);
    assert!(protocol::decode_payload(&bytes).is_ok());
    drop(bytes);
    payload.content.push('a');
    assert!(matches!(
        protocol::canonical_bytes(&payload),
        Err(ProtocolError::Size)
    ));
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn unified_reader_retains_literal_browser_v1_and_rejects_truncated_envelopes() {
    assert_eq!(
        token::unseal(&format!(" \n{LEGACY_TOKEN}\n"), &secret(2)).unwrap(),
        b"bitbid fixed vector"
    );
    assert!(token::unseal(LEGACY_TOKEN, &secret(3)).is_err());
    assert!(token::unseal(LEGACY_TOKEN, &[0; 31]).is_err());
    let bytes = BASE64_STANDARD
        .decode(LEGACY_TOKEN.strip_prefix("bitbid1:").unwrap())
        .unwrap();
    // Every truncation is rejected by structural checks or AEAD, including tag truncation.
    for end in 0..bytes.len() {
        let truncated = format!("bitbid1:{}", BASE64_STANDARD.encode(&bytes[..end]));
        assert!(
            token::unseal(&truncated, &secret(2)).is_err(),
            "length {end}"
        );
    }
    assert!(matches!(
        legacy_seal::SealedEnvelope::from_share_string("bitbid1:Ag=="),
        Err(legacy_seal::SealError::BadVersion(2))
    ));
    assert!(token::unseal("bitbid1:%%%", &secret(2)).is_err());
}
