"""Approved one-shot signer provisioning; encrypted 1Password recovery first.

Never prints command output or secrets. Run inside the user's authorized op TTY.
Refuses an existing root: partial operations require inspection, not blind retries.
Only a key restored from the exact recovery item is ever imported into Keychain.
"""

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import plistlib
import re
import secrets
import shutil
import subprocess

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

NAME = "Verity Production Code Signing"
TITLE = "Verity production signing identity recovery"


def run(argv, data=None):
    try:
        p = subprocess.run(argv, input=data, capture_output=True, timeout=180)
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            f"{Path(argv[0]).name}: timeout; inspect partial state"
        ) from None
    if p.returncode:
        raise RuntimeError(
            f"{Path(argv[0]).name}: exit {p.returncode}; output withheld"
        )
    return p.stdout


def material():
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, NAME)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509
        .CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, False, False, False, False),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), critical=True
        )
        .sign(key, hashes.SHA256())
    )
    password = secrets.token_urlsafe(48)
    encrypted = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password.encode()),
    )
    values = {
        "encrypted_key": encrypted.decode(),
        "recovery_password": password,
        "certificate": cert.public_bytes(serialization.Encoding.PEM).decode(),
        "sha1": cert.fingerprint(hashes.SHA1()).hex().upper(),
    }
    # No unencrypted original key is written to disk.
    return values


def validate_recovery(item, vault, item_id, expected):
    if item.get("id") != item_id or item.get("vault", {}).get("id") != vault:
        raise ValueError("recovery identity mismatch")
    if item.get("category") != "SECURE_NOTE" or item.get("title") != TITLE:
        raise ValueError("recovery item metadata mismatch")
    fields = item.get("fields", [])
    values = {}
    for name, wanted in expected.items():
        matches = [f for f in fields if f.get("id") == name]
        if len(matches) != 1 or not secrets.compare_digest(
            matches[0].get("value", ""), wanted
        ):
            raise ValueError("recovery field mismatch")
        if (
            name in {"encrypted_key", "recovery_password"}
            and matches[0].get("type") != "CONCEALED"
        ):
            raise ValueError("recovery secret field is not concealed")
        values[name] = matches[0]["value"]
    key = serialization.load_pem_private_key(
        values["encrypted_key"].encode(), values["recovery_password"].encode()
    )
    cert = x509.load_pem_x509_certificate(values["certificate"].encode())
    if cert.fingerprint(hashes.SHA1()).hex().upper() != values["sha1"]:
        raise ValueError("recovery certificate pin mismatch")
    public = cert.public_key()
    if not isinstance(key, rsa.RSAPrivateKey) or not isinstance(
        public, rsa.RSAPublicKey
    ):
        raise ValueError("expected RSA signing identity")
    challenge = secrets.token_bytes(64)
    public.verify(
        key.sign(challenge, padding.PKCS1v15(), hashes.SHA256()),
        challenge,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return key, cert


def validate_trust(data, pin):
    entry = data.get("trustList", {}).get(pin, {})
    settings = entry.get("trustSettings", [])
    if len(settings) != 1:
        raise ValueError("expected exactly one trust policy")
    policy = settings[0]
    if policy.get("kSecTrustSettingsPolicyName") != "CodeSigning":
        raise ValueError("trust is not code-signing-only")
    allowed = {
        "kSecTrustSettingsPolicy",
        "kSecTrustSettingsPolicyName",
        "kSecTrustSettingsResult",
    }
    if set(policy) - allowed or not policy.get("kSecTrustSettingsPolicy"):
        raise ValueError("unexpected trust policy constraint")
    if policy.get("kSecTrustSettingsResult", 1) != 1:
        raise ValueError("unexpected trust result")


def create(root, account, vault):
    if not re.fullmatch(r"[a-z0-9]{26}", vault):
        raise ValueError("explicit vault ID required")
    root = root.expanduser().resolve()
    if root.is_relative_to(Path(__file__).resolve().parents[2]):
        raise ValueError("provisioning material must stay outside Git")
    os.umask(0o077)
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    meta: dict = {"name": NAME, "purpose": "production", "state": "preflight"}

    def save(state):
        meta["state"] = state
        temporary = root / "identity.next.json"
        temporary.write_text(json.dumps(meta, indent=2) + "\n")
        temporary.replace(root / "identity.json")

    op = ["/opt/homebrew/bin/op", "--account", account]
    save("vault_preflight")
    vaults = json.loads(run(op + ["vault", "list", "--format", "json"]))
    selected = [v for v in vaults if v.get("id") == vault]
    if len(selected) != 1 or selected[0].get("name") not in {"Private", "Personal"}:
        raise ValueError("explicit personal vault not verified")
    meta["vault_id"] = vault
    values = material()
    pin = values["sha1"]
    meta["sha1"] = pin
    cert_path = root / "certificate.pem"
    cert_path.write_text(values["certificate"])
    meta["certificate"] = str(cert_path)
    fields = [
        {
            "id": k,
            "label": k,
            "type": "CONCEALED"
            if k in {"encrypted_key", "recovery_password"}
            else "STRING",
            "value": v,
        }
        for k, v in values.items()
    ]
    fields.append({
        "id": "notesPlain",
        "type": "STRING",
        "purpose": "NOTES",
        "value": "Dedicated production signer; not the lab key. Encrypted PKCS8 plus its passphrase. "
        "Restore to an owner-only temporary file, import non-extractable with codesign ACL, "
        "delete temporary key, and trust this certificate for code signing ONLY. "
        "Preserve the SHA-1 pin; certificate replacement is a separate migration.",
    })
    payload = {
        "title": TITLE,
        "category": "SECURE_NOTE",
        "vault": {"id": vault},
        "fields": fields,
        "tags": ["verity-signing-recovery"],
    }
    save("recovery_create_attempted")
    created = json.loads(
        run(
            op + ["item", "create", "-", "--vault", vault, "--format", "json"],
            json.dumps(payload).encode(),
        )
    )
    item_id = created.get("id", "")
    if not re.fullmatch(r"[a-z0-9]{26}", item_id):
        raise ValueError("missing recovery item ID; inspect remote before retry")
    meta["recovery_item_id"] = item_id
    save("recovery_created_not_verified")
    retrieved = json.loads(
        run(
            op
            + ["item", "get", item_id, "--vault", vault, "--format", "json", "--reveal"]
        )
    )
    key, cert = validate_recovery(retrieved, vault, item_id, values)
    meta["recovery_readback_verified"] = True
    meta["recovery_signature_challenge_verified"] = True
    save("recovery_verified")
    # Only the separately fetched, decrypted recovery key reaches the importer.
    key_path = root / "restored-import-only.pem"
    keychain = Path.home() / "Library/Keychains/login.keychain-db"
    meta.update(
        keychain=str(keychain),
        private_key_extractable=False,
        acl_application="/usr/bin/codesign",
    )
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    try:
        save("key_import_attempted")
        run([
            "/usr/bin/security",
            "import",
            str(key_path),
            "-k",
            str(keychain),
            "-t",
            "priv",
            "-f",
            "openssl",
            "-x",
            "-T",
            "/usr/bin/codesign",
        ])
    finally:
        key_path.unlink(missing_ok=True)
    save("certificate_import_attempted")
    run([
        "/usr/bin/security",
        "import",
        str(cert_path),
        "-k",
        str(keychain),
        "-t",
        "cert",
    ])
    save("code_signing_trust_attempted")
    run([
        "/usr/bin/security",
        "add-trusted-cert",
        "-r",
        "trustRoot",
        "-p",
        "codeSign",
        "-k",
        str(keychain),
        str(cert_path),
    ])
    trust_path = root / "trust-verification.plist"
    run(["/usr/bin/security", "trust-settings-export", str(trust_path)])
    validate_trust(plistlib.loads(trust_path.read_bytes()), pin)
    meta["trust_verified"] = "user domain; code signing only"
    save("signing_verification")
    artifact = root / "signing-verification"
    shutil.copyfile("/usr/bin/true", artifact)
    artifact.chmod(0o700)
    identifier = "com.charles.verity.signingverification"
    requirement = f'identifier "{identifier}" and certificate leaf = H"{pin}"'
    run([
        "/usr/bin/codesign",
        "--force",
        "--sign",
        pin,
        "--timestamp=none",
        "--identifier",
        identifier,
        "--requirements",
        "=designated => " + requirement,
        str(artifact),
    ])
    run([
        "/usr/bin/codesign",
        "--verify",
        "--strict",
        "-R",
        "=" + requirement,
        str(artifact),
    ])
    run([str(artifact)])
    meta["restored_key_codesign_verified"] = True
    meta["smoke_artifact"] = str(artifact)
    save("complete")
    return meta


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--account", required=True)
    parser.add_argument("--vault", required=True)
    args = parser.parse_args()
    try:
        result = create(args.root, args.account, args.vault)
        print(
            json.dumps({"ok": True, "state": result["state"], "sha1": result["sha1"]})
        )
    except Exception as exc:
        # Deliberately omit exception details that could include sensitive output.
        print(
            json.dumps({
                "ok": False,
                "error_type": type(exc).__name__,
                "inspect": str(args.root / "identity.json"),
            })
        )
        raise SystemExit(1) from None
