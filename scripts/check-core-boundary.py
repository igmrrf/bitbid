"""Reject native adapter dependencies in the shared core's WASM normal graph.

Run from the repository root with Python 3 and Cargo on PATH. Build/dev
dependencies are intentionally excluded; wasm-bindgen's host proc macros are
not native runtime adapters.
"""

import json
import subprocess
import sys


def cargo(*args):
    return subprocess.check_output(["cargo", *args], text=True)


metadata = json.loads(cargo("metadata", "--locked", "--no-deps", "--format-version", "1"))
packages = {package["name"]: package for package in metadata["packages"]}


def runtime_dependencies(package):
    return {dep["name"] for dep in package["dependencies"] if dep["kind"] is None}


# Native dependencies are owned by the CLI and adapters. Keep an explicit guard for
# common native adapters, including ones not yet present in the CLI manifest.
forbidden = (
    (runtime_dependencies(packages["bitbid-cli"])
     | runtime_dependencies(packages["bitbid-adapters"]))
    - runtime_dependencies(packages["bitbid-core"])
    - {"bitbid-core", "bitbid-adapters"}
) | {
    "bitbid-cli", "bitbid-adapters", "reqwest", "tokio", "dirs", "dirs-sys", "rpassword", "rtoolbox",
    "clap", "clap_builder", "clap_complete", "tempfile", "libc", "argon2",
    "bip32", "bip39", "yaml_serde", "alloy-provider",
}
tree = cargo(
    "tree", "--locked", "-p", "bitbid-core", "--target", "wasm32-unknown-unknown",
    "--edges", "normal", "--prefix", "none", "--format", "{p}",
)
names = {line.split()[0] for line in tree.splitlines() if line.strip()}
if "bitbid-core" not in names:
    sys.exit("missing bitbid-core dependency graph")
violations = sorted(names & forbidden)
if violations:
    sys.exit("native adapter dependencies reached bitbid-core: " + ", ".join(violations))
print(tree, end="")
print("shared-core WASM normal dependency boundary: OK")
