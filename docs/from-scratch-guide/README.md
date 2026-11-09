> Historical design/tutorial record. Old names and topology below are retained for provenance.
> Current commands, compatibility and delivery: [cutover](../rename-cutover.md).

# BSEC Secret Manager - Building from Scratch Guide

Welcome to the comprehensive, step-by-step master guide for building **`bsec`** (Blockchain Secret Manager) from scratch.

This guide is designed to enable any developer to reconstruct the entire production application, including cryptography engines, environment processing tools, smart contracts, IPFS storage, EVM integration, CLI interface, and automated test suite.

---

## 📚 Guide Modules Index

| Module | Subject | Key Concepts & Crates | Guide Link |
| :--- | :--- | :--- | :--- |
| **Part 1** | **Project Setup & Architecture** | Cargo workspace, dependencies (`clap`, `serde`, `k256`, `argon2`), error enums (`thiserror`) | [`01_PREREQUISITES_AND_PROJECT_SETUP.md`](file:///Users/igmrrf/Desktop/tmp/bitsec/docs/from-scratch-guide/01_PREREQUISITES_AND_PROJECT_SETUP.md) |
| **Part 2** | **Cryptography & Wallet Engine** | BIP-39 mnemonics, BIP-32 HD derivation, Secp256k1 keypairs, Argon2 KDF, AES-256-GCM, zeroization, POSIX permissions | [`02_CRYPTOGRAPHY_AND_WALLET.md`](file:///Users/igmrrf/Desktop/tmp/bitsec/docs/from-scratch-guide/02_CRYPTOGRAPHY_AND_WALLET.md) |
| **Part 3** | **Env Parsing & Process Injection** | Quoted string parser, format conversion (`.env`, `JSON`, `YAML`), schema validator, template generator, `std::process::Command` injection | [`03_ENV_PARSING_AND_COMMAND_INJECTION.md`](file:///Users/igmrrf/Desktop/tmp/bitsec/docs/from-scratch-guide/03_ENV_PARSING_AND_COMMAND_INJECTION.md) |
| **Part 4** | **Decentralized Storage & Blockchain** | IPFS daemon RPC / mock gateway, EVM RPC client (`reqwest`), Keccak-256, checksum address derivation, local fallback registry | [`04_STORAGE_AND_BLOCKCHAIN.md`](file:///Users/igmrrf/Desktop/tmp/bitsec/docs/from-scratch-guide/04_STORAGE_AND_BLOCKCHAIN.md) |
| **Part 5** | **EVM Smart Contract** | Solidity 0.8.24 `BsecSecretRegistry.sol`, custom error definitions, access control, event logging | [`05_SMART_CONTRACT.md`](file:///Users/igmrrf/Desktop/tmp/bitsec/docs/from-scratch-guide/05_SMART_CONTRACT.md) |
| **Part 6** | **Hybrid Ephemeral Secret Sharing** | Secp256k1 ECDH (`diffie_hellman`), payload wrapping, public vs private target secrets, TTL duration parser, max-reads enforcement | [`06_SECRET_SHARING_AND_VIEWING.md`](file:///Users/igmrrf/Desktop/tmp/bitsec/docs/from-scratch-guide/06_SECRET_SHARING_AND_VIEWING.md) |
| **Part 7** | **CLI Interface & Test Suite** | Clap subcommand architecture, interactive password prompts (`rpassword`), shell completion, integration tests (`assert_cmd`, `proptest`) | [`07_CLI_INTERFACE_AND_TESTING.md`](file:///Users/igmrrf/Desktop/tmp/bitsec/docs/from-scratch-guide/07_CLI_INTERFACE_AND_TESTING.md) |

---

## 🏗️ Recommended Execution Order

Follow the modules sequentially from Part 1 to Part 7. Each module contains exact code snippets, explanations of complex concepts, links to official documentation for crates, and verification instructions.

---

## 🔗 Architecture Diagram

```
+-------------------------------------------------------------------+
|                           bsec CLI                                |
| (main.rs, clap, rpassword, clap_complete, errors.rs, config.rs)   |
+--------------------------------─┬─────────────────────────────────+
                                  |
         +------------------------+------------------------+
         |                                                 |
+────────▼──────────────+                         +────────▼──────────────+
|  Environment Engine   |                         |  Cryptography & Wallet|
|  - env_file.rs        |                         |  - wallet.rs          |
|  - project_config.rs  |                         |  - bip39_words.rs     |
|  - manager.rs         |                         |  - Argon2 & AES-GCM   |
+────────┬──────────────+                         +────────┬──────────────+
         |                                                 |
         +------------------------+------------------------+
                                  |
                     +────────────▼────────────+
                     |  Secret Sharing Engine  |
                     |  - secrets.rs           |
                     |  - Secp256k1 ECDH       |
                     +────────────┬────────────+
                                  |
         +------------------------+------------------------+
         |                                                 |
+────────▼──────────────+                         +────────▼──────────────+
|    IPFS Storage       |                         |  EVM Blockchain      |
|    - ipfs.rs          |                         |  - blockchain.rs      |
|    - Local / Gateway  |                         |  - network_config.rs  |
+───────────────────────+                         +───────────────────────+
```
