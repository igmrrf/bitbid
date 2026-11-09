> Prospective packaging template only. This channel has not been published or verified.
> Package names, registry namespaces, taps, URLs, hashes and workflows below require
> separate selection, validation and publication authorization. Do not use the
> illustrated installation commands as available releases. Use [source installation](cargo.md).

# Linux Native Packaging Guide (.deb, .rpm, Arch AUR, Snap)

This guide covers building native Linux package formats for **Debian/Ubuntu**, **Fedora/RHEL**, **Arch Linux**, and **Canonical Snapcraft**.

---

## 📦 1. Debian / Ubuntu Package (`.deb`) via `cargo-deb`

### Step 1: Install `cargo-deb`

```bash
cargo install cargo-deb
```

### Step 2: Configure [`Cargo.toml`](../Cargo.toml)

Add `package.metadata.deb` section to [`Cargo.toml`](../Cargo.toml):

```toml
[package.metadata.deb]
maintainer = "Francis Igbiriki <francis.igbiriki@gmail.com>"
copyright = "2026, Francis Igbiriki <francis.igbiriki@gmail.com>"
extended-description = """\
A secure CLI tool to manage and encrypt environment variables using \
AES-GCM encryption, ECDSA identity verification, and IPFS storage."""
depends = "$auto"
section = "utility"
priority = "optional"
assets = [
    ["target/release/bitbid", "usr/bin/bitbid", "755"],
    ["README.md", "usr/share/doc/bitbid/README.md", "644"],
]
```

### Step 3: Build `.deb` Package

```bash
cargo deb
```

Generated artifact path: `target/debian/bsec_0.1.0_amd64.deb`

### Step 4: Installation Test

```bash
sudo dpkg -i target/debian/bsec_0.1.0_amd64.deb
```

---

## 📦 2. Fedora / RHEL Package (`.rpm`) via `cargo-generate-rpm`

### Step 1: Install `cargo-generate-rpm`

```bash
cargo install cargo-generate-rpm
```

### Step 2: Build RPM Package

```bash
cargo build --locked --release -p bitbid-cli --bin bitbid
cargo generate-rpm
```

Generated artifact path: `target/generate-rpm/bitbid-0.1.0-1.x86_64.rpm`

### Step 3: Installation Test

```bash
sudo dnf install target/generate-rpm/bitbid-0.1.0-1.x86_64.rpm
```

---

## 📦 3. Arch Linux User Repository (AUR) `PKGBUILD`

Create a `PKGBUILD` for Arch Linux users:

```bash
# Maintainer: Francis Igbiriki <francis.igbiriki@gmail.com>
pkgname=bitbid
pkgver=0.1.0
pkgrel=1
pkgdesc="Secure CLI tool to manage and encrypt environment variables"
arch=('x86_64' 'aarch64')
url="https://github.com/igmrrf/clienv"
license=('MIT' 'Apache-2.0')
depends=('gcc-libs')
makedepends=('cargo')
source=("$pkgname-$pkgver.tar.gz::$url/archive/refs/tags/v$pkgver.tar.gz")
sha256sums=('SKIP')

build() {
  cd "$pkgname-$pkgver"
  cargo build --locked --release -p bitbid-cli --bin bitbid --locked
}

package() {
  cd "$pkgname-$pkgver"
  install -Dm755 "target/release/$pkgname" "$pkgdir/usr/bin/$pkgname"
}
```

---

## 📦 4. Snapcraft Package (`snap`)

Create `snap/snapcraft.yaml`:

```yaml
name: bitbid
base: core22
version: '0.1.0'
summary: Secure CLI tool to manage and encrypt environment variables
description: |
  bitbid manages local environment variables and encrypted secret sharing.

grade: stable
confinement: strict

apps:
  bitbid:
    command: bin/bitbid
    plugs: [network, home]

parts:
  bitbid:
    plugin: rust
    source: .
```

Build snap locally:

```bash
snapcraft
```
