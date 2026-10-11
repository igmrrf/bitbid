//! EIP-1193 wallet access via `window.ethereum`.
//!
//! The connected address is used only to filter registry results. We request
//! accounts only; no signing, and nothing leaves the page except the JSON-RPC
//! read calls issued by the registry panel.

use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

/// Ask an injected EIP-1193 provider for its accounts and return the first.
pub async fn request_account() -> Result<String, String> {
    let window = web_sys::window().ok_or_else(|| "no browser window".to_string())?;
    let ethereum = js_sys::Reflect::get(&window, &JsValue::from_str("ethereum"))
        .map_err(|e| format!("{e:?}"))?;
    if ethereum.is_undefined() || ethereum.is_null() {
        return Err("No EIP-1193 provider (window.ethereum) detected".into());
    }

    let request = js_sys::Reflect::get(&ethereum, &JsValue::from_str("request"))
        .map_err(|e| format!("{e:?}"))?;
    let request: js_sys::Function = request
        .dyn_into()
        .map_err(|_| "window.ethereum.request is not callable".to_string())?;

    let params = js_sys::Array::new();
    let arg = js_sys::Object::new();
    js_sys::Reflect::set(
        &arg,
        &JsValue::from_str("method"),
        &JsValue::from_str("eth_requestAccounts"),
    )
    .map_err(|e| format!("{e:?}"))?;
    params.push(&arg);

    let promise = request
        .call1(&ethereum, &params)
        .map_err(|e| format!("wallet request failed: {e:?}"))?;
    let result = JsFuture::from(js_sys::Promise::from(promise))
        .await
        .map_err(|e| format!("wallet rejected: {e:?}"))?;

    let accounts: js_sys::Array = result
        .dyn_into()
        .map_err(|_| "provider returned a non-array".to_string())?;
    let first = accounts
        .get(0)
        .as_string()
        .ok_or_else(|| "provider returned no accounts".to_string())?;
    Ok(first)
}
