#!/usr/bin/env python3
"""Small SOPS catalog gate. Decrypted values stay in memory; output is redacted."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys


REQUIRED_SETTINGS = (
    "BITBID_HOME", "BSEC_HOME", "BITBID_PINATA_JWT", "BSEC_PINATA_JWT",
    "DOTENV_PASS", "DOTENV_<ENV>_PASS",
    "BITBID_WEB_ORIGIN", "BITBID_WEB_AUTH_ENABLED", "BITBID_DB",
    "BITBID_D1_DATABASE_ID", "BITBID_AUTH_GENERATION", "BITBID_TOTP_ENCRYPTION_KEY",
    "BITBID_GOOGLE_CLIENT_ID", "BITBID_GOOGLE_CLIENT_SECRET",
    "BITBID_GITHUB_CLIENT_ID", "BITBID_GITHUB_CLIENT_SECRET",
    "BITBID_MAIL_FROM", "BITBID_MAIL",
)
CONFIG_CREDENTIAL = "ipfs.pinning_jwt"
DEFAULT_CATALOG = "secrets/prod.enc.yaml"


class CatalogError(Exception):
    pass


def empty_catalog():
    """Safe initial values; demo is metadata, never a usable fake credential."""
    return {
        "schema_version": 1,
        "settings": {name: {"status": "unset", "value": None}
                     for name in REQUIRED_SETTINGS},
        "network_config": {CONFIG_CREDENTIAL: {"status": "unset", "value": None}},
    }


def parse_json(raw):
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise CatalogError("duplicate catalog field")
            result[key] = value
        return result

    try:
        return json.loads(raw, object_pairs_hook=unique_object)
    except (ValueError, UnicodeError):
        raise CatalogError("invalid catalog JSON") from None


def validate(catalog):
    if not isinstance(catalog, dict) or set(catalog) != {
        "schema_version", "settings", "network_config"
    } or type(catalog["schema_version"]) is not int or catalog["schema_version"] != 1:
        raise CatalogError("invalid catalog schema")
    settings = catalog["settings"]
    config = catalog["network_config"]
    if not isinstance(settings, dict) or not isinstance(config, dict):
        raise CatalogError("invalid catalog sections")
    for name in REQUIRED_SETTINGS:
        if name not in settings:
            raise CatalogError("missing required entry: " + name)
    # Only known names can enter reports/errors. Concrete DOTENV names supplement
    # the required pattern entry; arbitrary names could themselves contain secrets.
    for name in settings:
        if name not in REQUIRED_SETTINGS and not re.fullmatch(r"DOTENV_[A-Z0-9_]+_PASS", name):
            raise CatalogError("unknown setting name")
    if set(config) != {CONFIG_CREDENTIAL}:
        raise CatalogError("missing or unknown network-config entry")
    entries = list(settings.items()) + list(config.items())
    for name, entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"status", "value"}:
            raise CatalogError("invalid entry: " + name)
        status, value = entry["status"], entry["value"]
        if status not in ("unset", "demo", "configured") or not (
            value is None or isinstance(value, str)
        ):
            raise CatalogError("invalid status/value: " + name)
        nonblank = isinstance(value, str) and bool(value.strip())
        if status in ("unset", "demo") and nonblank:
            raise CatalogError("nonempty unset/demo value rejected: " + name)
        if status == "configured" and not nonblank:
            raise CatalogError("configured value is blank: " + name)
        if name == "DOTENV_<ENV>_PASS" and nonblank:
            raise CatalogError("pattern entry must be unset/demo: " + name)
        if name in ("BITBID_PINATA_JWT", "BSEC_PINATA_JWT", CONFIG_CREDENTIAL) and nonblank:
            if not value.isascii() or any(ord(c) < 33 or ord(c) == 127 for c in value):
                raise CatalogError("invalid credential header: " + name)
    return entries


def sops(args, data=None):
    try:
        result = subprocess.run(
            ["sops", *args], input=data, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=30, check=False,
        )
    except FileNotFoundError:
        raise CatalogError("sops is required") from None
    except subprocess.TimeoutExpired:
        raise CatalogError("sops timed out") from None
    if result.returncode:
        # SOPS diagnostics may include paths, recipients or plaintext parse errors.
        raise CatalogError("sops operation failed; check recipient/decryption access privately")
    return result.stdout


def read_catalog(path):
    if not path.is_file():
        raise CatalogError("encrypted catalog missing; initialize with an approved public age recipient")
    catalog = parse_json(sops([
        "--decrypt", "--input-type", "yaml", "--output-type", "json", str(path),
    ]))
    validate(catalog)
    return catalog


def encrypt_catalog(catalog, recipient, path):
    validate(catalog)
    if not re.fullmatch(r"age1[023456789acdefghjklmnpqrstuvwxyz]{58}", recipient):
        raise CatalogError("approved public age recipient required")
    if path.exists() or path.is_symlink():
        raise CatalogError("catalog already exists; use sops edit to preserve existing values")
    ciphertext = sops([
        "--encrypt", "--age", recipient, "--input-type", "json",
        "--output-type", "yaml", "/dev/stdin",
    ], json.dumps(catalog).encode())
    # Exclusive creation protects an existing catalog even if it appears mid-run.
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise CatalogError("catalog already exists; use sops edit to preserve existing values") from None
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(ciphertext)
    except BaseException:
        path.unlink()
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("init", "encrypt", "check", "report", "validate"))
    parser.add_argument("--catalog", type=Path, default=Path(DEFAULT_CATALOG))
    parser.add_argument("--recipient", default="", help="approved public age recipient for init/encrypt")
    args = parser.parse_args(argv)
    try:
        if args.command in ("init", "encrypt"):
            catalog = empty_catalog() if args.command == "init" else parse_json(sys.stdin.buffer.read())
            encrypt_catalog(catalog, args.recipient, args.catalog)
            print("encrypted catalog created")
        elif args.command == "validate":
            validate(parse_json(sys.stdin.buffer.read()))
            print("catalog valid")
        else:
            catalog = read_catalog(args.catalog)
            if args.command == "check":
                print("catalog complete")
            else:
                for name, entry in sorted(validate(catalog)):
                    print(name + "\t" + entry["status"])
    except (CatalogError, OSError):
        # Never print filesystem exception paths or untrusted catalog values.
        error = sys.exc_info()[1]
        message = str(error) if isinstance(error, CatalogError) else "catalog filesystem operation failed"
        print("secrets-catalog: " + message, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
