#!/usr/bin/env python3
"""Real SOPS/age fixture tests; private fixture identities are deleted on exit."""

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("secrets-catalog.py").resolve()
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("catalog", SCRIPT)
catalog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(catalog)


PRODUCTION_SETTINGS = {
    "BITBID_WEB_ORIGIN", "BITBID_WEB_AUTH_ENABLED", "BITBID_DB",
    "BITBID_D1_DATABASE_ID", "BITBID_AUTH_GENERATION", "BITBID_TOTP_ENCRYPTION_KEY",
    "BITBID_GOOGLE_CLIENT_ID", "BITBID_GOOGLE_CLIENT_SECRET",
    "BITBID_GITHUB_CLIENT_ID", "BITBID_GITHUB_CLIENT_SECRET",
    "BITBID_MAIL_FROM", "BITBID_MAIL",
}
CHAIN_SETTINGS = {
    "BITBID_TEAM_CHAIN_ENABLED", "BITBID_TEAM_CHAIN_ID", "BITBID_TEAM_RPC_URL",
    "BITBID_TEAM_REGISTRY_ADDRESS", "BITBID_TEAM_REGISTRY_VERSION",
    "BITBID_TEAM_REGISTRY_CODE_HASH", "BITBID_TEAM_IPFS_GATEWAY",
    "BITBID_TEAM_RETENTION_PROFILE",
}
LEGACY_SETTINGS = {
    "BITBID_HOME", "BSEC_HOME", "BITBID_PINATA_JWT", "BSEC_PINATA_JWT",
    "DOTENV_PASS", "DOTENV_<ENV>_PASS",
}


class CatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for tool in ("sops", "age-keygen"):
            if not shutil.which(tool):
                raise RuntimeError(tool + " is required; fixture integration tests cannot be skipped")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="bitbid-catalog-fixture-")
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.key = self.root / "fixture-age.key"
        generated = subprocess.run(["age-keygen", "-o", str(self.key)], capture_output=True, check=True)
        self.recipient = generated.stderr.decode().strip().split("Public key: ")[-1]
        # No inherited credentials or default identity directories are consulted.
        self.env = {"PATH": os.environ["PATH"], "HOME": str(self.root), "PYTHONDONTWRITEBYTECODE": "1",
                    "XDG_CONFIG_HOME": str(self.root), "SOPS_AGE_KEY_FILE": str(self.key)}
        self.path = self.root / "fixture.enc.yaml"

    def run_cli(self, command, data=None, env=None, recipient=None):
        args = [sys.executable, str(SCRIPT), command, "--catalog", str(self.path)]
        if recipient is not None:
            args.extend(["--recipient", recipient])
        return subprocess.run(args, input=None if data is None else json.dumps(data).encode(),
                              capture_output=True, env=self.env if env is None else env, check=False)

    def encrypt_unchecked(self, data):
        result = subprocess.run([
            "sops", "--encrypt", "--age", self.recipient, "--input-type", "json",
            "--output-type", "yaml", "/dev/stdin",
        ], input=json.dumps(data).encode(), capture_output=True, env=self.env, check=True)
        self.path.write_bytes(result.stdout)

    def assert_redacted(self, result):
        combined = result.stdout + result.stderr
        for sentinel in (b"CREDENTIAL_SENTINEL", b"PATH_SENTINEL", str(self.root).encode(), b"AGE-SECRET-KEY"):
            self.assertNotIn(sentinel, combined)

    def test_real_roundtrip_and_names_status_only_report(self):
        data = catalog.empty_catalog()
        data["settings"]["BITBID_HOME"] = {"status": "configured", "value": "/PATH_SENTINEL"}
        data["settings"]["DOTENV_PASS"] = {"status": "configured", "value": "CREDENTIAL_SENTINEL"}
        data["settings"]["BSEC_PINATA_JWT"]["status"] = "demo"
        result = self.run_cli("encrypt", data, recipient=self.recipient)
        self.assertEqual(result.returncode, 0, result.stderr)
        plain = subprocess.run(["sops", "--decrypt", "--output-type", "json", str(self.path)],
                               capture_output=True, env=self.env, check=True).stdout
        self.assertEqual(json.loads(plain), data)
        self.assertNotIn(b"CREDENTIAL_SENTINEL", self.path.read_bytes())
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        check = self.run_cli("check")
        self.assertEqual(check.returncode, 0)
        report = self.run_cli("report")
        self.assertEqual(report.returncode, 0)
        self.assertEqual(report.stdout.decode().splitlines(), [
            name + "\t" + entry["status"] for name, entry in sorted(catalog.validate(data))])
        self.assertIn(b"BSEC_PINATA_JWT\tdemo", report.stdout)
        for result in (result, check, report):
            self.assert_redacted(result)
        # On macOS SOPS may create empty Library/Application Support directories.
        self.assertEqual(set(p.name for p in self.root.rglob("*") if p.is_file()),
                         {self.key.name, self.path.name})

    def test_missing_each_required_entry_fails_decrypted_copy(self):
        for name in catalog.REQUIRED_SETTINGS:
            with self.subTest(name=name):
                data = catalog.empty_catalog()
                del data["settings"][name]
                self.encrypt_unchecked(data)
                result = self.run_cli("check")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"missing required entry", result.stderr)
                self.assert_redacted(result)

    def test_production_init_has_exact_disabled_inventory(self):
        self.assertEqual(self.run_cli("init", recipient=self.recipient).returncode, 0)
        plain = subprocess.run(["sops", "--decrypt", "--output-type", "json", str(self.path)],
                               capture_output=True, env=self.env, check=True).stdout
        data = json.loads(plain)
        self.assertEqual(set(data["settings"]), LEGACY_SETTINGS | PRODUCTION_SETTINGS | CHAIN_SETTINGS)
        self.assertEqual(set(data["network_config"]), {"ipfs.pinning_jwt"})
        self.assertEqual(len(catalog.validate(data)), 27)
        for entry in list(data["settings"].values()) + list(data["network_config"].values()):
            self.assertEqual(entry, {"status": "unset", "value": None})
        report = self.run_cli("report")
        self.assertEqual(report.returncode, 0)
        self.assertEqual(set(report.stdout.decode().splitlines()),
                         {name + "\tunset" for name in LEGACY_SETTINGS | PRODUCTION_SETTINGS | CHAIN_SETTINGS
                          | {"ipfs.pinning_jwt"}})
        self.assert_redacted(report)

    def test_production_roundtrip_preserves_existing_values_and_redacts_new_values(self):
        data = catalog.empty_catalog()
        for name in LEGACY_SETTINGS - {"DOTENV_<ENV>_PASS"}:
            data["settings"][name] = {"status": "configured", "value": "CREDENTIAL_SENTINEL"}
        data["settings"]["DOTENV_ENV_STAGING_PASS"] = {
            "status": "configured", "value": "CREDENTIAL_SENTINEL"}
        data["network_config"]["ipfs.pinning_jwt"] = {
            "status": "configured", "value": "CREDENTIAL_SENTINEL"}
        old_entries = {name: dict(entry) for name, entry in data["settings"].items()
                       if name not in PRODUCTION_SETTINGS | CHAIN_SETTINGS}
        for name in PRODUCTION_SETTINGS | CHAIN_SETTINGS:
            data["settings"][name] = {"status": "configured", "value": "CREDENTIAL_SENTINEL"}
        encrypted = self.run_cli("encrypt", data, recipient=self.recipient)
        self.assertEqual(encrypted.returncode, 0)
        plain = subprocess.run(["sops", "--decrypt", "--output-type", "json", str(self.path)],
                               capture_output=True, env=self.env, check=True).stdout
        restored = json.loads(plain)
        self.assertEqual(restored, data)
        self.assertEqual({name: restored["settings"][name] for name in old_entries}, old_entries)
        for command in ("check", "report"):
            result = self.run_cli(command)
            self.assertEqual(result.returncode, 0)
            self.assert_redacted(result)

    def test_production_unset_demo_cannot_contain_values(self):
        for name in PRODUCTION_SETTINGS | CHAIN_SETTINGS:
            for status in ("unset", "demo"):
                with self.subTest(name=name, status=status):
                    data = catalog.empty_catalog()
                    data["settings"][name] = {"status": status, "value": "CREDENTIAL_SENTINEL"}
                    result = self.run_cli("encrypt", data, recipient=self.recipient)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(self.path.exists())
                    self.assert_redacted(result)

    def test_unknown_production_like_names_fail_before_any_report_output(self):
        for name in ("BITBID_CREDENTIAL_SENTINEL", "DATABASE_URL", "HYPERDRIVE",
                     "BITBID_TEAM_RPC_TOKEN", "BITBID_TEAM_REGISTRY",
                     "BITBID_TEAM_RETENTION_KEY"):
            with self.subTest(name=name):
                data = catalog.empty_catalog()
                data["settings"][name] = {"status": "configured", "value": "CREDENTIAL_SENTINEL"}
                self.encrypt_unchecked(data)
                for command in ("check", "report"):
                    result = self.run_cli(command)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, b"")
                    self.assertIn(b"unknown setting name", result.stderr)
                    self.assertNotIn(name.encode(), result.stderr)
                    self.assert_redacted(result)

    def test_chain_metadata_extension_preserves_all_prechain_entries(self):
        data = catalog.empty_catalog()
        # Distinct configured values detect a dropped/overwritten old entry,
        # including the retained aliases and private web settings/bindings.
        for name in (LEGACY_SETTINGS | PRODUCTION_SETTINGS) - {"DOTENV_<ENV>_PASS"}:
            data["settings"][name] = {"status": "configured",
                                      "value": "CREDENTIAL_SENTINEL_" + name}
        data["network_config"][catalog.CONFIG_CREDENTIAL] = {
            "status": "configured", "value": "CREDENTIAL_SENTINEL_NETWORK"}
        old = {name: dict(entry) for name, entry in data["settings"].items()
               if name not in CHAIN_SETTINGS}
        self.assertEqual(set(old), LEGACY_SETTINGS | PRODUCTION_SETTINGS)
        self.assertEqual(len(CHAIN_SETTINGS), 8)
        self.assertEqual(self.run_cli("encrypt", data, recipient=self.recipient).returncode, 0)
        plain = subprocess.run(["sops", "--decrypt", "--output-type", "json", str(self.path)],
                               capture_output=True, env=self.env, check=True).stdout
        restored = json.loads(plain)
        self.assertEqual(restored, data)
        self.assertEqual({name: restored["settings"][name] for name in old}, old)
        for name in CHAIN_SETTINGS:
            self.assertEqual(restored["settings"][name], {"status": "unset", "value": None})
        for command in ("check", "report"):
            result = self.run_cli(command)
            self.assertEqual(result.returncode, 0)
            self.assert_redacted(result)

    def test_each_chain_metadata_missing_or_unsafe_in_encrypted_catalog_fails(self):
        for name in CHAIN_SETTINGS:
            for invalid in (None, "unset", "demo"):
                with self.subTest(name=name, invalid=invalid):
                    data = catalog.empty_catalog()
                    if invalid is None:
                        del data["settings"][name]
                    else:
                        data["settings"][name] = {
                            "status": invalid, "value": "CREDENTIAL_SENTINEL"}
                    self.encrypt_unchecked(data)
                    for command in ("check", "report"):
                        result = self.run_cli(command)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertEqual(result.stdout, b"")
                        self.assert_redacted(result)

    def test_demo_credentials_rejected_before_encryption(self):
        for section, name in [("settings", "BITBID_PINATA_JWT"), ("settings", "BSEC_PINATA_JWT"),
                              ("network_config", catalog.CONFIG_CREDENTIAL)]:
            with self.subTest(name=name):
                data = catalog.empty_catalog()
                data[section][name] = {"status": "demo", "value": "CREDENTIAL_SENTINEL"}
                result = self.run_cli("encrypt", data, recipient=self.recipient)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"nonempty unset/demo value rejected", result.stderr)
                self.assertFalse(self.path.exists())
                self.assert_redacted(result)

    def test_demo_credentials_rejected_in_existing_encrypted_copy(self):
        data = catalog.empty_catalog()
        data["network_config"][catalog.CONFIG_CREDENTIAL] = {
            "status": "demo", "value": "CREDENTIAL_SENTINEL"}
        self.encrypt_unchecked(data)
        for command in ("check", "report"):
            result = self.run_cli(command)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b"")
            self.assert_redacted(result)

    def test_blank_unset_demo_values_and_concrete_dotenv_name(self):
        for value in (None, "", " \t"):
            for status in ("unset", "demo"):
                data = catalog.empty_catalog()
                for entry in data["settings"].values():
                    entry.update(status=status, value=value)
                data["network_config"][catalog.CONFIG_CREDENTIAL].update(status=status, value=value)
                data["settings"]["DOTENV_STAGING_PASS"] = {"status": "configured", "value": "synthetic"}
                self.assertEqual(self.run_cli("validate", data).returncode, 0)

    def test_schema_types_unknown_names_status_and_invalid_header_fail(self):
        variants = []
        for mutation in (
            lambda d: d.update(schema_version=True),
            lambda d: d["settings"].update({"CREDENTIAL_SENTINEL": {"status": "unset", "value": None}}),
            lambda d: d["settings"]["DOTENV_PASS"].update(status="CREDENTIAL_SENTINEL"),
            lambda d: d["settings"]["DOTENV_PASS"].update(value=42),
            lambda d: d["settings"]["BITBID_HOME"].update(status="configured"),
            lambda d: d["network_config"].clear(),
            lambda d: d["settings"]["BITBID_PINATA_JWT"].update(status="configured", value="bad\nCREDENTIAL_SENTINEL"),
        ):
            data = catalog.empty_catalog()
            mutation(data)
            variants.append(data)
        for data in variants:
            result = self.run_cli("validate", data)
            self.assertNotEqual(result.returncode, 0)
            self.assert_redacted(result)

    def test_missing_and_wrong_decryption_key_fail_redacted(self):
        self.assertEqual(self.run_cli("init", recipient=self.recipient).returncode, 0)
        missing = {k: v for k, v in self.env.items() if k != "SOPS_AGE_KEY_FILE"}
        other_key = self.root / "wrong-fixture.key"
        subprocess.run(["age-keygen", "-o", str(other_key)], capture_output=True, check=True)
        wrong = dict(missing, SOPS_AGE_KEY_FILE=str(other_key))
        for env in (missing, wrong):
            result = self.run_cli("check", env=env)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"sops operation failed", result.stderr)
            self.assert_redacted(result)

    def test_missing_catalog_and_sops_and_invalid_ciphertext_fail_redacted(self):
        result = self.run_cli("check")
        self.assertIn(b"encrypted catalog missing", result.stderr)
        self.path.write_text("CREDENTIAL_SENTINEL")
        result = self.run_cli("check")
        self.assertNotEqual(result.returncode, 0)
        self.assert_redacted(result)
        result = self.run_cli("check", env=dict(self.env, PATH=""))
        self.assertIn(b"sops is required", result.stderr)

    def test_init_requires_recipient_and_never_overwrites(self):
        self.assertNotEqual(self.run_cli("init").returncode, 0)
        self.assertEqual(self.run_cli("init", recipient=self.recipient).returncode, 0)
        original = self.path.read_bytes()
        self.assertNotEqual(self.run_cli("init", recipient=self.recipient).returncode, 0)
        self.assertEqual(self.path.read_bytes(), original)

    def test_invalid_json_and_duplicate_fields_do_not_echo_values(self):
        for raw in (b'CREDENTIAL_SENTINEL', b'{"settings": 1, "settings": "CREDENTIAL_SENTINEL"}'):
            result = subprocess.run([sys.executable, str(SCRIPT), "validate"], input=raw,
                                    capture_output=True, env=self.env, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assert_redacted(result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
