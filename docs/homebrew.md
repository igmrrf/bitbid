# Homebrew Formula & Tap Deployment Guide

This guide describes how to publish and maintain a Homebrew Formula for `bsec`, allowing macOS and Linux users to install the application via `brew install bsec` or `brew install igmrrf/tap/bsec`.

---

## 📋 Distribution Options

1. **Custom Homebrew Tap (Recommended for early/independent releases)**:
   Users run `brew install igmrrf/tap/bsec`.
2. **Homebrew Core (Official repository)**:
   Submitted via pull request to `homebrew/homebrew-core` once the project matures.

---

## 🛠 Step 1: Create a Homebrew Tap Repository

Create a GitHub repository named `homebrew-tap` under your GitHub organization or account (`igmrrf/homebrew-tap`).

Directory structure:
```text
homebrew-tap/
└── Formula/
    └── bsec.rb
```

---

## 🛠 Step 2: Prepare Binary and Generate Archive SHA-256

When a new version is ready, build the optimized release binary, compress it into a TAR archive, and calculate its SHA-256 hash:

```bash
cargo build --release
cd target/release
tar -czf bsec-mac.tar.gz bsec
shasum -a 256 bsec-mac.tar.gz
```

Upload the `bsec-mac.tar.gz` archive to your GitHub Releases as an asset.

---

## 🛠 Step 3: Write Homebrew Formula (`bsec.rb`)

Create `Formula/bsec.rb` in your `homebrew-tap` repository:

```ruby
class Bsec < Formula
  desc "Secure CLI tool to manage and encrypt environment variables"
  homepage "https://github.com/igmrrf/bsec"
  url "https://github.com/igmrrf/bsec/releases/download/v0.1.0/bsec-mac.tar.gz"
  sha256 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  version "0.1.0"
  license "MIT"

  def install
    bin.install "bsec"
  end

  test do
    assert_match "bsec", shell_output("#{bin}/bsec --version")
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
          formula-name: bsec
          homebrew-tap: igmrrf/homebrew-tap
          download-url: https://github.com/igmrrf/bsec/releases/download/${{ github.ref_name }}/bsec-mac.tar.gz
        env:
          COMMITTER_TOKEN: ${{ secrets.HOMEBREW_TAP_GITHUB_TOKEN }}
```

---

## 🧪 User Installation Steps

```bash
# Tap repository
brew tap igmrrf/tap

# Install bsec
brew install bsec

# Test execution
bsec --help
```
