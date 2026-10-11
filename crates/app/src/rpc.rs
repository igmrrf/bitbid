//! Browser JSON-RPC transport.
//!
//! Every request goes to the single configured JSON-RPC endpoint. No secret,
//! private key, or mnemonic is ever placed in a request body or sent anywhere.

use serde_json::{json, Value};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};

fn js_err(value: JsValue) -> String {
    value.as_string().unwrap_or_else(|| format!("{value:?}"))
}

/// POST a JSON-RPC 2.0 call and return the raw response body.
///
/// The raw body is returned deliberately, even when it carries a JSON-RPC error,
/// so the core decoder is the single place that decides success vs. failure.
pub async fn rpc_raw(url: &str, method: &str, params: Value) -> Result<String, String> {
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    let opts = RequestInit::new();
    opts.set_method("POST");
    opts.set_mode(RequestMode::Cors);
    opts.set_body(&JsValue::from_str(&body.to_string()));

    let request =
        Request::new_with_str_and_init(url, &opts).map_err(|e| format!("bad request: {}", js_err(e)))?;
    request
        .headers()
        .set("Content-Type", "application/json")
        .map_err(|e| format!("bad header: {}", js_err(e)))?;

    let window = web_sys::window().ok_or_else(|| "no browser window".to_string())?;
    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|e| format!("RPC unreachable at {url}: {}", js_err(e)))?;
    let resp: Response = resp_value
        .dyn_into()
        .map_err(|_| "fetch did not resolve to a Response".to_string())?;

    let text_value = JsFuture::from(resp.text().map_err(|e| format!("read failed: {}", js_err(e)))?)
        .await
        .map_err(|e| format!("read failed: {}", js_err(e)))?;
    let text = text_value
        .as_string()
        .ok_or_else(|| "RPC response was not text".to_string())?;

    if !resp.ok() {
        return Err(format!("RPC endpoint returned HTTP {}: {}", resp.status(), text));
    }
    Ok(text)
}
