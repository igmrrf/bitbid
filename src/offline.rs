//! Stdio/file adapters for offline tokens; never opens a wallet or contacts a backend.
use anyhow::{Result, anyhow};
use std::{
    io::{Read, Write},
    path::Path,
};
use zeroize::Zeroizing;
fn read_input(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    let input: Box<dyn Read> = if path == Path::new("-") {
        Box::new(std::io::stdin())
    } else {
        Box::new(std::fs::File::open(path)?)
    };
    let mut bytes = Zeroizing::new(Vec::new());
    input.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(anyhow!("input file exceeds size limit"));
    }
    Ok(bytes)
}
pub fn seal(input: &Path, recipient: &str) -> Result<()> {
    let plain = read_input(input, 10 * 1024 * 1024)?;
    let token = bitbid_core::token::seal_to_share_string(&plain, recipient)?;
    writeln!(std::io::stdout().lock(), "{token}")?;
    Ok(())
}
pub fn unseal(input: &Path, key_file: &Path) -> Result<()> {
    if key_file == Path::new("-") {
        return Err(anyhow!(
            "recipient private key must be read from a key file"
        ));
    }
    let share = read_input(
        input,
        bitbid_core::protocol::MAX_WIRE_BYTES.div_ceil(3) * 4 + 16,
    )?;
    let share = std::str::from_utf8(&share)?;
    let key = read_input(key_file, 256)?;
    let key = std::str::from_utf8(&key)?;
    let key = Zeroizing::new(
        bitbid_core::address::hex_to_bytes(key.trim())
            .map_err(|_| anyhow!("invalid private key file"))?,
    );
    let plain = Zeroizing::new(bitbid_core::token::unseal(share, &key)?);
    std::io::stdout().lock().write_all(&plain)?;
    Ok(())
}
