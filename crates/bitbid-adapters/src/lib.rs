//! Native I/O implementations. The core and browser do not depend on this crate.
#[cfg(not(target_arch = "wasm32"))]
pub mod rpc;
#[cfg(not(target_arch = "wasm32"))]
pub mod store;
