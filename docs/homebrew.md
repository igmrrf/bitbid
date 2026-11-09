> Prospective packaging template only. This channel has not been published or verified.
> Package names, registry namespaces, taps, URLs, hashes and workflows below require
> separate selection, validation and publication authorization. Do not use the
> illustrated installation commands as available releases. Use [source installation](cargo.md).

# Homebrew Formula & Tap Deployment Guide

This guide describes how to publish and maintain a Homebrew Formula for `bitbid`, allowing macOS and Linux users to install the application via `brew install bitbid` or `brew install igmrrf/tap/bitbid`.

---

## 📋 Distribution Options

1. **Custom Homebrew Tap (Recommended for early/independent releases)**:
   Users run `brew install igmrrf/tap/bitbid`.
2. **Homebrew Core (Official repository)**:
   Submitted via pull request to `homebrew/homebrew-core` once the project matures.

---

## 🛠 Step 1: Create a Homebrew Tap Repository

Create a GitHub repository named `homebrew-tap` under your GitHub organization or account (`igmrrf/homebrew-tap`).

Directory structure:
```text
homebrew-tap/
└── Formula/
    └── bitbid.rb
```

---

## 🛠 Step 2: Prepare Binary and Generate Archive SHA-256

When a new version is ready, build the optimized release binary, compress it into a TAR archive, and calculate its SHA-256 hash:

```bash
cargo build --locked --release -p bitbid-cli --bin bitbid
cd target/release
tar -czf bitbid-mac.tar.gz bitbid
shasum -a 256 bitbid-mac.tar.gz
```

Upload the `bitbid-mac.tar.gz` archive to your GitHub Releases as an asset.

---

## 🛠 Step 3: Write Homebrew Formula (`bitbid.rb`)

Create `Formula/bitbid.rb` in your `homebrew-tap` repository:

```ruby
class Bitbid < Formula
  desc "Secure CLI tool to manage and encrypt environment variables"
  homepage "https://github.com/igmrrf/clienv"
  url "<VERIFIED_RELEASE_ASSET_URL>"
  sha256 "<VERIFIED_ARCHIVE_SHA256>"
  version "0.1.0"
  license "MIT"

  def install
    bin.install "bitbid"
  end

  test do
    assert_match "bitbid", shell_output("#{bin}/bitbid --version")
  end
end
```

---

## 🔄 Automated Homebrew Updates via GitHub Actions

Use `mislav/bump-homebrew-formula-action` in `.github/workflows/brew-bump.yml`:

```yaml
name: Update Homebrew Formula

on:
  release:
    types: [published]

jobs:
  homebrew:
    runs-on: ubuntu-latest
    steps:
      - name: Update Homebrew Formula
        uses: mislav/bump-homebrew-formula-action@v2
        with:
          formula-name: bitbid
          homebrew-tap: igmrrf/homebrew-tap
          download-url: <VERIFIED_RELEASE_ASSET_URL>
        env:
          COMMITTER_TOKEN: ${{ secrets.HOMEBREW_TAP_GITHUB_TOKEN }}
```

---

## 🧪 User Installation Steps

```bash
# Tap repository
brew tap igmrrf/tap

# Install bitbid
brew install bitbid

# Test execution
bitbid --help
```
