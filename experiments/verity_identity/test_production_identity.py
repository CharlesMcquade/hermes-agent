"""Offline recovery/trust validation. No vault, keychain, or production writes."""

import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
import create_production_identity as provision
from cryptography.hazmat.primitives import serialization
from create_production_identity import (
    material,
    validate_recovery,
    validate_trust,
    TITLE,
)


class RecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.values = material()
        cls.item = {
            "id": "item",
            "vault": {"id": "vault"},
            "category": "SECURE_NOTE",
            "title": TITLE,
            "fields": [
                {
                    "id": k,
                    "type": "CONCEALED"
                    if k in {"encrypted_key", "recovery_password"}
                    else "STRING",
                    "value": v,
                }
                for k, v in cls.values.items()
            ],
        }

    def test_encrypted_roundtrip(self):
        self.assertIn("BEGIN ENCRYPTED PRIVATE KEY", self.values["encrypted_key"])
        key, cert = validate_recovery(self.item, "vault", "item", self.values)
        encoding = serialization.Encoding.DER
        fmt = serialization.PublicFormat.SubjectPublicKeyInfo
        self.assertEqual(
            key.public_key().public_bytes(encoding, fmt),
            cert.public_key().public_bytes(encoding, fmt),
        )

    def test_wrong_vault(self):
        with self.assertRaises(ValueError):
            validate_recovery(self.item, "shared", "item", self.values)

    def test_wrong_item(self):
        with self.assertRaises(ValueError):
            validate_recovery(self.item, "vault", "other", self.values)

    def test_corrupt_and_missing_and_unconcealed_fields(self):
        for mode in ("corrupt", "missing", "duplicate", "unconcealed"):
            with self.subTest(mode=mode):
                item = copy.deepcopy(self.item)
                if mode == "corrupt":
                    item["fields"][0]["value"] += "bad"
                if mode == "missing":
                    item["fields"].pop(0)
                if mode == "duplicate":
                    item["fields"].append(item["fields"][0])
                if mode == "unconcealed":
                    item["fields"][0]["type"] = "STRING"
                with self.assertRaises(ValueError):
                    validate_recovery(item, "vault", "item", self.values)


class TrustTests(unittest.TestCase):
    def test_only_codesign(self):
        validate_trust(
            {
                "trustList": {
                    "pin": {
                        "trustSettings": [
                            {
                                "kSecTrustSettingsPolicyName": "CodeSigning",
                                "kSecTrustSettingsPolicy": bytes.fromhex(
                                    "2a864886f763640110"
                                ),
                            }
                        ]
                    }
                }
            },
            "pin",
        )

    def test_missing_empty_broad_or_denied_refused(self):
        for settings in (
            [],
            [{}],
            [
                {
                    "kSecTrustSettingsPolicyName": "SSL",
                    "kSecTrustSettingsPolicy": bytes.fromhex("2a864886f763640110"),
                }
            ],
            [
                {
                    "kSecTrustSettingsPolicyName": "CodeSigning",
                    "kSecTrustSettingsPolicy": bytes.fromhex("2a864886f763640110"),
                    "kSecTrustSettingsResult": 3,
                }
            ],
            [
                {
                    "kSecTrustSettingsPolicyName": "CodeSigning",
                    "kSecTrustSettingsPolicy": bytes.fromhex("2a864886f763640110"),
                },
                {},
            ],
        ):
            with self.subTest(settings=settings):
                with self.assertRaises(ValueError):
                    validate_trust(
                        {"trustList": {"pin": {"trustSettings": settings}}}, "pin"
                    )

    def test_matching_name_with_wrong_oid_refused(self):
        # Canonical CSSMOID_APPLE_TP_CODE_SIGNING versus other/invalid policies.
        for oid in (
            b"oid",
            bytes.fromhex("2a864886f76364010a"),
            "2a864886f763640110",
            b"",
            None,
        ):
            with self.subTest(oid=oid), self.assertRaises(ValueError):
                validate_trust(
                    {
                        "trustList": {
                            "pin": {
                                "trustSettings": [
                                    {
                                        "kSecTrustSettingsPolicyName": "CodeSigning",
                                        "kSecTrustSettingsPolicy": oid,
                                    }
                                ]
                            }
                        }
                    },
                    "pin",
                )


class ImportCleanupTests(unittest.TestCase):
    def test_plaintext_absent_after_write_checkpoint_and_import_outcomes(self):
        # Exercise create() through restoration using fake key bytes and op/security
        # boundaries; all actual filesystem operations stay in a disposable root.
        for phase in (
            "serialize",
            "partial_write",
            "close",
            "checkpoint",
            "import",
            "after_import",
        ):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                root = base / "new-signer"
                key_path = root / "restored-import-only.pem"
                home = base / "home"
                vault, item_id = "v" * 26, "i" * 26
                values = {"sha1": "A" * 40, "certificate": "test certificate"}
                key = Mock()
                key.private_bytes.return_value = b"nonsecret fake key for cleanup test"
                if phase == "serialize":
                    key.private_bytes.side_effect = OSError(
                        "injected serialization failure"
                    )
                original_write_bytes = Path.write_bytes
                original_write_text = Path.write_text
                import_attempted = []

                def write_bytes(path, data):
                    if path == key_path and phase in {"partial_write", "close"}:
                        original_write_bytes(
                            path, data[:3] if phase == "partial_write" else data
                        )
                        raise OSError("injected key write or close failure")
                    return original_write_bytes(path, data)

                def write_text(path, data, *args, **kwargs):
                    if (
                        phase == "checkpoint"
                        and path.name == "identity.next.json"
                        and json.loads(data)["state"] == "key_import_attempted"
                    ):
                        raise OSError("injected checkpoint failure")
                    return original_write_text(path, data, *args, **kwargs)

                def run(argv, data=None):
                    if argv[0] == "/opt/homebrew/bin/op":
                        if argv[3:5] == ["vault", "list"]:
                            return json.dumps([
                                {"id": vault, "name": "Private"}
                            ]).encode()
                        return json.dumps({"id": item_id}).encode()
                    self.assertEqual(argv[:2], ["/usr/bin/security", "import"])
                    if argv[2] == str(key_path):
                        self.assertTrue(key_path.exists())
                        self.assertEqual(key_path.stat().st_mode & 0o777, 0o600)
                        import_attempted.append(True)
                        if phase == "import":
                            raise OSError("injected key import failure")
                        return b""
                    self.assertFalse(key_path.exists())
                    raise OSError("stop before external certificate import")

                previous_umask = os.umask(0o077)
                try:
                    with (
                        patch.object(provision, "run", side_effect=run),
                        patch.object(provision, "material", return_value=values),
                        patch.object(
                            provision, "validate_recovery", return_value=(key, None)
                        ),
                        patch.object(Path, "home", return_value=home),
                        patch.dict(os.environ, {"HERMES_HOME": str(home / ".hermes")}),
                        patch.object(Path, "write_bytes", write_bytes),
                        patch.object(Path, "write_text", write_text),
                    ):
                        with self.assertRaises(OSError):
                            provision.create(root, "test-account", vault)
                    self.assertFalse(
                        key_path.exists(),
                        "plaintext must be removed on every ordinary exit",
                    )
                    self.assertEqual(
                        bool(import_attempted), phase in {"import", "after_import"}
                    )
                finally:
                    os.umask(previous_umask)


if __name__ == "__main__":
    unittest.main()
