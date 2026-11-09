//! Blocking JSON-RPC transport; ABI encoding and interpretation remain in core.
use std::time::Duration;

use bitbid_core::{Rpc, RpcError};
use reqwest::blocking::Client;
use serde_json::{Value, json};

const RPC_TIMEOUT: Duration = Duration::from_secs(20);

pub struct BlockingRpc {
    rpc_url: String,
}

impl BlockingRpc {
    pub fn new(rpc_url: String) -> Self {
        Self { rpc_url }
    }
}

impl Rpc for BlockingRpc {
    fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let client = Client::builder()
            .timeout(RPC_TIMEOUT)
            .build()
            .map_err(|e| RpcError::Request(format!("failed to build HTTP client: {e}")))?;
        let response = client
            .post(&self.rpc_url)
            .json(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}))
            .send()
            .map_err(|e| {
                RpcError::Request(format!("RPC connection error to {}: {e}", self.rpc_url))
            })?;
        // Compatibility: interpret the JSON envelope even on a non-success HTTP
        // status. Do not introduce status rejection or transport retries.
        let parsed: Value = response.json().map_err(|e| {
            RpcError::Decode(format!(
                "RPC response decode error from {}: {e}",
                self.rpc_url
            ))
        })?;
        if let Some(error) = parsed.get("error") {
            return Err(RpcError::Provider(format!(
                "RPC error from {}: {error}",
                self.rpc_url
            )));
        }
        Ok(parsed.get("result").cloned().unwrap_or(Value::Null))
    }
}
