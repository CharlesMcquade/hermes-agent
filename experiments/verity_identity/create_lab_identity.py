"""Create one local-only code-signing identity after explicit operator approval.
Private key bytes never go to stdout, argv, Git, or logs. Import as non-extractable;
only codesign receives an ACL grant. Certificate trust is a separate explicit step.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess


def command(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=180)
    if result.returncode:
        safe_error = " ".join(
            line for line in result.stderr.splitlines() if line.startswith("security:")
        )
        raise RuntimeError(
            f"{Path(argv[0]).name} failed ({result.returncode}): {safe_error}"
        )
    return result.stdout


def create(root):
    root = root.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.chmod(root, 0o700)
    old_umask = os.umask(0o077)
    key, cert = root / "private-import-only.pem", root / "certificate.pem"
    keychain = Path.home() / "Library/Keychains/login.keychain-db"
    try:
        # genrsa emits traditional RSA PEM; req -newkey emits PKCS8 that
        # security import -f openssl rejects on this macOS version.
        command(["/usr/bin/openssl", "genrsa", "-out", str(key), "3072"])
        command([
            "/usr/bin/openssl",
            "req",
            "-new",
            "-key",
            str(key),
            "-x509",
            "-sha256",
            "-days",
            "3650",
            "-subj",
            "/CN=Verity Lab Code Signing/",
            "-out",
            str(cert),
            "-addext",
            "basicConstraints=critical,CA:FALSE",
            "-addext",
            "keyUsage=critical,digitalSignature",
            "-addext",
            "extendedKeyUsage=critical,codeSigning",
        ])
        command([
            "/usr/bin/security",
            "import",
            str(key),
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
        key.unlink()  # Never retain an unencrypted signing key outside Keychain.
        command([
            "/usr/bin/security",
            "import",
            str(cert),
            "-k",
            str(keychain),
            "-t",
            "cert",
        ])
        fingerprint = (
            command([
                "/usr/bin/openssl",
                "x509",
                "-in",
                str(cert),
                "-noout",
                "-fingerprint",
                "-sha1",
            ])
            .strip()
            .split("=", 1)[1]
            .replace(":", "")
        )
        metadata = {
            "name": "Verity Lab Code Signing",
            "sha1": fingerprint,
            "certificate": str(cert),
            "keychain": str(keychain),
            "private_key_extractable": False,
            "acl_application": "/usr/bin/codesign",
            "trust": "not changed",
            "purpose": "isolated rebuild-continuity experiment; not production",
        }
        (root / "identity.json").write_text(json.dumps(metadata, indent=2))
        print(json.dumps(metadata, indent=2))
    finally:
        if key.exists():
            key.unlink()
        os.umask(old_umask)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", required=True, type=Path)
    args = p.parse_args()
    create(args.root)
