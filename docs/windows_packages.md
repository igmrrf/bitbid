> Prospective packaging template only. This channel has not been published or verified.
> Package names, registry namespaces, taps, URLs, hashes and workflows below require
> separate selection, validation and publication authorization. Do not use the
> illustrated installation commands as available releases. Use [source installation](cargo.md).

# Windows Package Managers Guide (Winget, Chocolatey, Scoop)

This guide covers distributing `bitbid` across popular Windows package management systems: **Winget** (official Windows Package Manager), **Chocolatey**, and **Scoop**.

---

## 🪟 1. Windows Package Manager (`winget`)

Winget manifests are submitted to the official [microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs) GitHub repository.

### Step 1: Install `wingetcreate` CLI

```powershell
winget install Microsoft.WingetCreate
```

### Step 2: Generate Winget Manifest

```powershell
wingetcreate new <VERIFIED_RELEASE_ASSET_URL>
```

### Step 3: Sample Winget Manifest (`igmrrf.bitbid.yaml`)

```yaml
PackageIdentifier: igmrrf.bitbid
PackageVersion: 0.1.0
PackageName: bitbid
Publisher: Francis Igbiriki
License: MIT
ShortDescription: Secure CLI tool to manage and encrypt environment variables
Installers:
  - Architecture: x64
    InstallerType: zip
    InstallerUrl: <VERIFIED_RELEASE_ASSET_URL>
    InstallerSha256: <CALCULATED_SHA256>
    NestedInstallerFiles:
      - RelativeFilePath: bitbid.exe
ManifestType: singleton
ManifestVersion: 1.6.0
```

### User Installation Test:

```powershell
winget install igmrrf.bitbid
```

---

## 🪟 2. Chocolatey (`choco`)

Chocolatey packages are built as `.nupkg` archives and pushed to [chocolatey.org](https://community.chocolatey.org/).

### Step 1: Create Package Specification (`bitbid.nuspec`)

```xml
<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2015/06/nuspec.xsd">
  <metadata>
    <id>bitbid</id>
    <version>0.1.0</version>
    <title>bitbid CLI</title>
    <authors>Francis Igbiriki</authors>
    <projectUrl>https://github.com/igmrrf/bitbid</projectUrl>
    <licenseUrl>https://github.com/igmrrf/bitbid/blob/main/LICENSE</licenseUrl>
    <requireLicenseAcceptance>false</requireLicenseAcceptance>
    <description>Secure CLI tool to manage and encrypt environment variables</description>
    <summary>bitbid CLI env management tool</summary>
    <tags>cli env security encryption rust</tags>
  </metadata>
  <files>
    <file src="tools\**" target="tools" />
  </files>
</package>
```

### Step 2: Package & Push

```powershell
choco pack
choco push bitbid.0.1.0.nupkg --api-key <YOUR_CHOCO_API_KEY>
```

---

## 🪟 3. Scoop Manifest (`scoop`)

Scoop enables non-admin, portable Windows installations via custom buckets.

### Step 1: Create Scoop Bucket Repository

Create a GitHub repo named `scoop-bucket` containing `bucket/bitbid.json`:

```json
{
    "version": "0.1.0",
    "description": "Secure CLI tool to manage and encrypt environment variables",
    "homepage": "https://github.com/igmrrf/bitbid",
    "license": "MIT",
    "architecture": {
        "64bit": {
            "url": "<VERIFIED_RELEASE_ASSET_URL>",
            "hash": "<CALCULATED_SHA256>"
        }
    },
    "bin": "bitbid.exe",
    "checkver": "github",
    "autoupdate": {
        "architecture": {
            "64bit": {
                "url": "<VERIFIED_RELEASE_ASSET_URL>"
            }
        }
    }
}
```

### User Installation Test:

```powershell
scoop bucket add igmrrf https://github.com/igmrrf/scoop-bucket
scoop install bitbid
```
