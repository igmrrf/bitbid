//! Isolated qualification executable, not a production team-vault API.
pub mod codec;
pub mod crypto;
pub mod protocol;
pub mod suite;
use wasm_bindgen::prelude::*;
#[wasm_bindgen]
pub fn qualify() -> std::result::Result<String, JsValue> {
    suite::run(false)
        .map(|v| v.to_string())
        .map_err(|e| JsValue::from_str(&e))
}
#[wasm_bindgen]
pub fn profile_kdf() -> std::result::Result<String, JsValue> {
    let corpus: serde_json::Value =
        serde_json::from_str(suite::CORPUS).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let a = &corpus["primitives"]["argon2"];
    let parse = |k: &str| {
        hex::decode(a[k].as_str().unwrap_or("")).map_err(|_| JsValue::from_str("KDF fixture"))
    };
    let key = crypto::kdf(&parse("pass")?, &parse("salt")?, 64 * 1024 * 1024)
        .map_err(|e| JsValue::from_str(&e))?;
    if key.as_slice() != parse("output")? {
        return Err(JsValue::from_str("KDF reference mismatch"));
    }
    Ok(serde_json::json!({"pass":true,"profile":"argon2id19/m65536/t3/p4/salt16/out32","scratch_bytes":65536*1024,"reference_match":true}).to_string())
}
#[cfg(test)]
mod tests {
    #[test]
    fn native_reference_and_transcripts() {
        let report = crate::suite::run(true).expect("qualification");
        println!("{report}");
    }
}
pub mod backup;
pub mod client_state;
