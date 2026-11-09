# Cargo source installation

The native virtual workspace contains `bitbid-core`, native `bitbid-adapters`,
and package `bitbid-cli` (0.1.0). Its only executable is `bitbid`.
Run from the native root:

```sh
cargo build --locked --release -p bitbid-cli --bin bitbid
./target/release/bitbid --help
cargo package --locked --list -p bitbid-cli --allow-dirty
cargo install --locked --path crates/bitbid-cli
bitbid --help
bitbid completion bash
```

For an isolated install, add `--root /path/to/install` and run
`/path/to/install/bin/bitbid --help`. Local path installation uses sibling core
and adapters and the native lockfile. The manifest is
`crates/bitbid-cli/Cargo.toml`; `../../README.md` resolves to the root README.

Core and adapters are unpublished path dependencies without registry versions.
Listing package contents does not establish a standalone crates.io archive can
resolve them. Registry publication and other distribution channels remain future
work. No publishing credentials or deployment settings are required here.
See [cutover](rename-cutover.md) before replacing an earlier owned installation.
