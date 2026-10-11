# BSEC Documentation & Rebuilding Guides

This directory contains architectural reviews, step-by-step guides for rebuilding `bsec` from scratch, and deployment flows across platforms.

---

## 📚 Master Index

| Subject / Category | Description | Guide |
| :--- | :--- | :--- |
| **Architectural Code Review** | In-depth security analysis, resilience fallbacks, and design evaluation | [`code_review.md`](file:///Users/igmrrf/Desktop/tmp/bitsec/code_review.md) |
| **From-Scratch Rebuilding Guide** | 7-part complete tutorial to code the application from scratch with snippets | [`from-scratch-guide/`](file:///Users/igmrrf/Desktop/tmp/bitsec/docs/from-scratch-guide/README.md) |
| **Cargo (crates.io)** | Publishing `bsec` as an open-source Rust crate | [`cargo.md`](file:///Users/igmrrf/Desktop/tmp/bitsec/docs/cargo.md) |
| **Homebrew** | Distributing `bsec` via Homebrew Formulae & Taps for macOS / Linux | [`homebrew.md`](file:///Users/igmrrf/Desktop/tmp/bitsec/docs/homebrew.md) |
| **GitHub Binary Releases** | Standalone cross-platform binaries (macOS, Linux, Windows) with `cargo-dist` | [`binary_releases.md`](file:///Users/igmrrf/Desktop/tmp/bitsec/docs/binary_releases.md) |
| **Docker & Containers** | Containerizing `bsec` and publishing to Docker Hub & GHCR | [`docker.md`](file:///Users/igmrrf/Desktop/tmp/bitsec/docs/docker.md) |
| **Linux Package Managers** | Packaging for Debian/Ubuntu (`.deb`), Fedora/RHEL (`.rpm`), Arch (`AUR`), snap | [`linux_packages.md`](file:///Users/igmrrf/Desktop/tmp/bitsec/docs/linux_packages.md) |
| **Windows Package Managers** | Packaging for Windows Package Manager (`winget`), Chocolatey, Scoop | [`windows_packages.md`](file:///Users/igmrrf/Desktop/tmp/bitsec/docs/windows_packages.md) |
| **NPM Engine** | Wrapping Rust binary for execution via `npx bsec` / `npm install -g bsec` | [`npm.md`](file:///Users/igmrrf/Desktop/tmp/bitsec/docs/npm.md) |
| **Smart Contracts & EVM** | Deploying `BsecSecretRegistry.sol` to Anvil, Polygon, Base, Sepolia & IPFS | [`smart_contracts.md`](file:///Users/igmrrf/Desktop/tmp/bitsec/docs/smart_contracts.md) |

---

## 🛠 Quick Overview of `bsec` Architecture

* **CLI Application**: Rust crate (`bsec`) built with `clap`, `k256`, `argon2`, `zeroize`, and `aes-gcm`.
* **Smart Contract**: Solidity contract ([`BsecSecretRegistry.sol`](file:///Users/igmrrf/Desktop/tmp/bitsec/contracts/BsecSecretRegistry.sol)) managed with Foundry.
* **Storage Layer**: IPFS integration (Local Kubo node / Pinata gateway / fallback cache).


## Possible renames
- chainome 
- aikusecurity
- bitsec
