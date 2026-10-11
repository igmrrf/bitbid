use std::sync::Arc;

use bitbid_adapters::{BlockingIpfs, BlockingRpc, NativeStore, OsRandom, SystemClock};
use bitbid_core::Host;

fn main() {
    let host = Host {
        store: Arc::new(NativeStore),
        ipfs: Arc::new(BlockingIpfs),
        rpc: Arc::new(BlockingRpc),
        clock: Arc::new(SystemClock),
        random: Arc::new(OsRandom),
    };

    let _ = &host;
    println!("{}", bitbid_core::bipplaceholder());
    let _ = bitbid_adapters::staging_pid();
}
