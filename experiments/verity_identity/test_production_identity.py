"""Offline recovery/trust validation. No vault, keychain, or production writes."""

import copy
import unittest
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
                                "kSecTrustSettingsPolicy": b"oid",
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
            [{"kSecTrustSettingsPolicyName": "SSL", "kSecTrustSettingsPolicy": b"oid"}],
            [
                {
                    "kSecTrustSettingsPolicyName": "CodeSigning",
                    "kSecTrustSettingsPolicy": b"oid",
                    "kSecTrustSettingsResult": 3,
                }
            ],
            [
                {
                    "kSecTrustSettingsPolicyName": "CodeSigning",
                    "kSecTrustSettingsPolicy": b"oid",
                },
                {},
            ],
        ):
            with self.subTest(settings=settings):
                with self.assertRaises(ValueError):
                    validate_trust(
                        {"trustList": {"pin": {"trustSettings": settings}}}, "pin"
                    )


if __name__ == "__main__":
    unittest.main()
