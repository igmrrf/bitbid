# Cargo source installation

The native root is a virtual workspace containing `bitbid-core`, native
`bitbid-adapters` and package `bitbid-cli` (version 0.1.0). The executable remains
`bsec`; no `bitbid` alias is installed. Run these commands from the native root:

```sh
cargo build --locked --release -p bitbid-cli --bin bsec
./target/release/bsec --help
cargo package --locked --list -p bitbid-cli --allow-dirty
cargo install --locked --path crates/bitbid-cli
bsec --help
bsec completion bash
```

For an isolated install, add `--root /path/to/install` and run
`/path/to/install/bin/bsec --help`. Local path installation builds the CLI with
its sibling core and adapters using the native root lockfile. Package metadata
and the explicit `bsec` binary live in `crates/bitbid-cli/Cargo.toml`;
`../../README.md` resolves to the native root README. Source and integration
tests live under `crates/bitbid-cli/{src,tests}`; contracts and scripts stay at
the repository root.

This is a local delivery boundary. Core and adapters are unpublished path
dependencies without registry versions, so listing package contents does not
establish a standalone crates.io archive can resolve them. Registry publication,
release automation and any package/binary rename require a separate decision.
No publishing credentials or deployment settings are needed for these commands.
