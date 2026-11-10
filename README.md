# bitbid

A powerful, high-performance CLI tool written in Rust for secure, decentralized environment variable management, file encryption, format conversion, schema validation, process environment injection, and secret sharing.

---

## Key Features

- 🔒 **Blockchain & Wallet Management**: Wallet generation (`init`), mnemonic recovery, password protection, and public address management.
- 👥 **Ephemeral Secret Sharing**: Share encrypted secrets with configurable time-to-live (`--ttl`), maximum read limits (`--max-reads`), retrieval (`view`), listing (`list`), revocation (`revoke`), and hiding (`hide`).
- 🚀 **Process Environment Injection**: Run commands (`run -- <command>`) with secrets injected directly into process memory without creating plaintext files on disk.
- 🔄 **Format Conversion**: Convert between `.env`, `JSON`, and `YAML` files with support for custom prefixes (`--prefix`), suffixes (`--suffix`), and JavaScript object embedding (`--embed`).
- 📝 **Schema Validation & Templates**: Validate `.env` files against `.env.schema`, auto-fix missing keys, and generate `.env.template` files (`generate`).
- 🔐 **End-to-End File Encryption**: Encrypt (`encrypt`) and decrypt (`decrypt`) `.env` files using `$DOTENV_PASS`, `$DOTENV_<ENV>_PASS`, or `.env.pass` files.
- 📋 **Environment Variable Logging**: Inspect single variable values (`log`).
- 🔎 **Pattern Search**: Substring search within files (`search`).

---

## Security Model & Limitations

Read this before relying on `bitbid` for sensitive data.

- **Confidentiality is cryptographic; access controls are advisory.** Secret payloads are
  encrypted with AES-256-GCM under a per-secret random key, which is wrapped for the
  recipient via ECDH (secp256k1) + HKDF-SHA256. Only the holder of the recipient private key
  can decrypt. The on-chain `expiresAt`, `maxReads`, and `revoked` fields gate *listing and
  the recorded read count* — they do **not** cryptographically prevent a recipient who has
  already fetched the IPFS payload from decrypting it again offline. Treat TTL / max-reads /
  revocation as best-effort lifecycle signals, not hard guarantees against a past recipient.
- **`--to public` provides no confidentiality.** Public secrets are wrapped with a fixed,
  well-known key so anyone can read them. Use it only for non-sensitive content.
- **Real backends required.** `share`/`view` perform real on-chain transactions (a funded
  wallet + deployed `BsecSecretRegistry`) and real IPFS storage (a Pinata JWT or a reachable
  IPFS daemon). With no backend reachable, commands fail with a clear error — they never fake
  success. See `scripts/e2e-setup.sh` for a local anvil + IPFS stack.
- **Wallet at rest.** Always create wallets with `--password` (Argon2id + AES-256-GCM).
  Without a password the private key and mnemonic are stored unencrypted (mode 0600) and
  `init` prints a warning.
- **`--no-export` is an in-tool control, not a cryptographic guarantee.** Sealing a secret
  makes `bitbid` refuse to write it to a file (`materialize`, `materialize --as schema`, and
  `view --output` are all blocked); terminal `view` and `run --secret` staging still work.
  But a recipient holds the plaintext after decrypt and can persist it by any other means.
  Treat the seal as a guard rail against accidental file writes, not as DRM.
- **Materialized files are plaintext on disk.** `materialize` and `run --secret` write real
  secret files at mode `0600` under `0700` directories. `run --secret` stages into a temp
  dir wiped on exit (including SIGINT/SIGTERM, best-effort); `materialize` files persist —
  delete them when done. `materialize --as schema` discloses key *names* (values withheld).

---

## Shared browser/CLI tokens

The browser console and native CLI now compile the same `bitbid-core` library.
Offline `seal` writes a versioned share string to stdout; `unseal` accepts that
string or an IPFS payload JSON and writes the original bytes to stdout:

```bash
bitbid seal --to <recipient-SEC1-public-key-hex> --input message.txt
bitbid unseal --input token.txt --key-file recipient-private-key.txt
```

Input defaults to stdin. Private keys are read from a file, never an inline flag.
These commands use no wallet/backend and do not register a token or record an
on-chain read. Existing `share`/`view` retain their registry/IPFS lifecycle.
See [implemented shared protocol](docs/split-core/implemented-shared-protocol.md)
for exact serialization, legacy compatibility and the deferred full split.

## Installation

```bash
# Build from source
cargo build --locked --release -p bitbid-cli --bin bitbid

# Install the bitbid-cli package locally; the executable is bitbid
cargo install --locked --path crates/bitbid-cli

# Run binary
./target/release/bitbid --help
```

---

## 🚀 Deployment & Distribution Guides

Source-path Cargo installation is supported. Other distribution guides are prospective templates, not published packages or hosted artifacts. For details, see the [Documentation Index](docs/README.md):

* 📦 **Cargo (local source installation)**: [`docs/cargo.md`](docs/cargo.md)
* 🍺 **Homebrew**: [`docs/homebrew.md`](docs/homebrew.md)
* 🖥️ **GitHub Binary Releases**: [`docs/binary_releases.md`](docs/binary_releases.md)
* 🐳 **Docker & GHCR**: [`docs/docker.md`](docs/docker.md)
* 🐧 **Linux Packages (.deb, .rpm, AUR, snap)**: [`docs/linux_packages.md`](docs/linux_packages.md)
* 🪟 **Windows Packages (winget, choco, scoop)**: [`docs/windows_packages.md`](docs/windows_packages.md)
* 🟢 **NPM / NPX Engine**: [`docs/npm.md`](docs/npm.md)
* ⛓️ **Smart Contracts & EVM**: [`docs/smart_contracts.md`](docs/smart_contracts.md)

---

## Usage Guide

### 1. Wallet & Identity Management

```bash
# Initialize a new wallet
bitbid init

# Initialize with password protection
bitbid init --password "your_password"

# Import an existing wallet from mnemonic
bitbid init --import-mnemonic "word1 word2 ... word12"

# View wallet details
bitbid wallet info
```

### 2. Process Environment Injection (`bitbid run`)

```bash
# Run command with environment variables injected from .env.local (default)
bitbid run -- npm run dev

# Run command with injected environment variables from a custom or encrypted file
bitbid run -e .env.prod.enc -- python app.py
```

### 3. Secret Sharing & Ephemeral Storage

```bash
# Share secret text (expires in 24h by default, 1 max read)
bitbid share --content "my-secret-api-key"

# Share secret with custom TTL and max reads limit
bitbid share --content "database-password" --ttl 1h --max-reads 5 --to 0x123...

# Share secret from file
bitbid share --file secret.txt --ttl 7d

# View a secret (auto-destructs upon reaching max reads or expiry)
bitbid view <secret_id>

# Save decrypted secret directly to a file
bitbid view <secret_id> --output decrypted.txt

# List active or expired secrets
bitbid list --active
bitbid list --expired

# Revoke a shared secret immediately
bitbid revoke <secret_id>

# Hide secret(s)
bitbid hide <secret_id>
```

### 3b. Materializing Secrets to Files

Some apps need a real file at a path (TLS `key.pem`, a Google `service-account.json`, a
`kubeconfig`) rather than env vars. Tag a shared secret with its file kind, then materialize
it — or stage it for a command with `run --secret`.

```bash
# Share a file as a tagged, materializable secret (kind inferred from extension, or --as)
bitbid share --file ./cert.pem --to 0x04<recipient-pubkey>
bitbid share --file ./creds.json --as json --filename service-account.json --to 0x04...

# Seal it: bitbid will refuse every file write (terminal view only)
bitbid share --file ./cert.pem --no-export --to 0x04...

# Pack several files into one secret via a bundle manifest
cat > bundle.json <<'JSON'
{ "members": [
  { "path": "./cert.pem",  "as": "pem",  "filename": "cert.pem" },
  { "path": "./creds.json", "as": "json", "filename": "creds.json",
    "env": "GOOGLE_APPLICATION_CREDENTIALS" },
  { "path": "./.env.prod",  "as": "env",  "filename": ".env" }
] }
JSON
bitbid share --bundle bundle.json --to 0x04...

# Materialize a single secret to a file or directory (mode 0600). One call = one read.
bitbid materialize <secret_id> --file ./out/cert.pem
bitbid materialize <secret_id> --dir ./out            # uses the sender's suggested filename

# Materialize a bundle: every member is written under --dir
bitbid materialize <secret_id> --dir ./secrets

# Extract just the KEY names (no values) as a .env.schema
bitbid materialize <secret_id> --as schema --file .env.schema

# Stage files into a wiped-on-exit temp dir and run a command. For each member, bitbid injects
# <STEM>_FILE=<abspath> (plus any manifest "env" alias); env members also inject KEY=VAL.
bitbid run --secret <secret_id> -- sh -c 'echo "$GOOGLE_APPLICATION_CREDENTIALS"; cat "$CERT_FILE"'
```

Notes: sender-supplied filenames are sanitized to plain basenames (no `..`, no separators).
Binary bodies (keystores, DER) are stored base64 and restored to raw bytes on write.
`--force` is required to overwrite an existing file.

### 4. Network Configuration

```bash
# Display current network configuration
bitbid config --show

# Configure network (polygon, base, amoy, sepolia, base-sepolia, local)
bitbid config --network amoy

# Set custom network and RPC endpoint
bitbid config --network sepolia --rpc "https://rpc.sepolia.org"
```

### 5. Testnets & Free Faucets Guide

For team development, testing, or zero-cost execution, configure `bitbid` to use a testnet or local node:

| Network | Chain ID | `bitbid` Network Flag | Free Token Faucet Links |
| :--- | :---: | :--- | :--- |
| **Polygon Amoy Testnet** | `80002` | `bitbid config --network amoy` | • <https://faucet.polygon.technology/> |
| **Ethereum Sepolia Testnet** | `11155111` | `bitbid config --network sepolia` | • <https://sepoliafaucet.com/><br>• <https://sepolia-faucet.pk910.de/><br>• <https://faucets.chain.link/> |
| **Base Sepolia Testnet** | `84532` | `bitbid config --network base-sepolia` | • <https://www.bwarelabs.com/faucets/base-sepolia><br>• <https://faucets.chain.link/base-sepolia> |
| **Local Docker Compose Node** | `31337` | `bitbid config --network local` | • **Auto Pre-Funded** (10,000 test ETH on `docker compose up`) |

#### Using Local Docker Testnet

```bash
# Spin up local EVM node (Anvil) & IPFS gateway in Docker
docker compose up -d

# Switch bitbid to local testnet
bitbid config --network local
```

### 6. Format Conversion & Utilities

```bash
# Convert JSON to .env format
bitbid convert config.json .env.local --format env

# Convert with prefix
bitbid convert config.json .env.local --prefix "NEXT_PUBLIC_"

# Embed JavaScript object properties
bitbid convert config.json config.js --embed "VUE_APP_"
```

### 7. Schema Validation & Templates

```bash
# Validate .env.local against .env.schema
bitbid validate -e .env.local -s .env.schema

# Generate .env.template from existing .env file
bitbid generate -e .env -o .env.template

# Inspect single environment variable value
bitbid log MONGO_URL -f .env.local
```

### 8. File-Level Encryption

```bash
# Set encryption key
echo "my_secure_password" > .env.pass

# Encrypt .env file
bitbid encrypt .env -o .env.enc

# Decrypt .env.enc file
bitbid decrypt .env.enc -o .env.dec
```

### 9. Legacy Key-Value Storage

```bash
# Store encrypted key-value pair
bitbid set MONGO_URI "mongodb://localhost:27017"

# Retrieve key-value pair
bitbid get MONGO_URI

# Search for pattern in file
bitbid search "API_KEY" --path .env
```

---

## Authors & Acknowledgments

- <https://github.com/fuyutarow/convert-json-env.git>
- <https://github.com/nathanagez/env-cli>
- <https://github.com/jaydenwindle/senv>
- <https://github.com/chempogonzalez/dotenv-checker>

See [rename cutover and compatibility](docs/rename-cutover.md) for canonical-only environment/path selection, explicit migration, installation upgrades, and scoped rollback.
