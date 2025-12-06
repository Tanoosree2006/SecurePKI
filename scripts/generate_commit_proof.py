#!/usr/bin/env python3
"""
generate_commit_proof.py

Outputs:
- Commit Hash (40-char hex)
- Encrypted Signature (base64, single line)

Usage:
  python3 scripts/generate_commit_proof.py
"""

import subprocess
import sys
import base64
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend

# CONFIG — adjust if keys live elsewhere
REPO_ROOT = Path.cwd()
PRIVATE_KEY_PATH = REPO_ROOT / "student_private.pem"
INSTRUCTOR_PUBLIC_KEY_PATH = REPO_ROOT / "instructor_public.pem"

def get_latest_commit_hash():
    """Run git to get the latest commit hash (40-char hex)."""
    try:
        # Use --no-pager to avoid paging issues
        out = subprocess.check_output(["git", "log", "-1", "--format=%H"], cwd=REPO_ROOT)
        commit_hash = out.decode("utf-8").strip()
        if len(commit_hash) != 40:
            raise ValueError(f"Unexpected commit hash length: '{commit_hash}'")
        return commit_hash
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"git command failed: {e}") from e

def load_private_key(path: Path):
    data = path.read_bytes()
    return serialization.load_pem_private_key(data, password=None, backend=default_backend())

def load_public_key(path: Path):
    data = path.read_bytes()
    return serialization.load_pem_public_key(data, backend=default_backend())

def sign_message(message: str, private_key) -> bytes:
    """
    Sign ASCII/UTF-8 bytes of message using RSA-PSS with SHA-256.
    - MGF: MGF1 with SHA-256
    - Salt length: PSS.MAX_LENGTH
    """
    message_bytes = message.encode("utf-8")  # CRITICAL: sign ASCII/UTF-8 string, not raw binary
    signature = private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def encrypt_with_public_key(data: bytes, public_key) -> bytes:
    """
    Encrypt using RSA-OAEP with SHA-256 and MGF1(SHA-256).
    Label is None.
    """
    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def main():
    # checks
    if not PRIVATE_KEY_PATH.exists():
        print(f"ERROR: private key not found at {PRIVATE_KEY_PATH}", file=sys.stderr)
        sys.exit(2)
    if not INSTRUCTOR_PUBLIC_KEY_PATH.exists():
        print(f"ERROR: instructor public key not found at {INSTRUCTOR_PUBLIC_KEY_PATH}", file=sys.stderr)
        sys.exit(2)

    commit_hash = get_latest_commit_hash()
    print(f"Commit Hash: {commit_hash}")

    # load keys
    private_key = load_private_key(PRIVATE_KEY_PATH)
    public_key = load_public_key(INSTRUCTOR_PUBLIC_KEY_PATH)

    # sign
    signature = sign_message(commit_hash, private_key)

    # encrypt signature
    ciphertext = encrypt_with_public_key(signature, public_key)

    # base64 encode ciphertext and print single-line string
    b64 = base64.b64encode(ciphertext).decode("ascii")
    print("Encrypted Signature (base64):")
    print(b64)

    # optionally save to file
    out_file = REPO_ROOT / "commit_proof.b64"
    out_file.write_text(b64, encoding="utf-8")
    print(f"\nSaved base64 to {out_file}")

if __name__ == "__main__":
    main()