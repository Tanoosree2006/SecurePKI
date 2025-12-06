# verify_commit_proof.py
import base64
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend


def load_private_key(path: Path):
    """Load a PEM private key (instructor private key)"""
    data = path.read_bytes()
    return serialization.load_pem_private_key(data, password=None, backend=default_backend())


def load_public_key(path: Path):
    """Load a PEM public key (student public key)"""
    data = path.read_bytes()
    return serialization.load_pem_public_key(data, backend=default_backend())


def decrypt_with_private_key(ciphertext: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """Decrypt RSA/OAEP(SHA-256) ciphertext using private key"""
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return plaintext


def verify_signature(message_ascii: str, signature: bytes, public_key: rsa.RSAPublicKey) -> bool:
    """Verify RSA-PSS(SHA-256) signature of ASCII message"""
    try:
        public_key.verify(
            signature,
            message_ascii.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def main():
    repo = Path(".")
    commit_proof = repo / "commit_proof.txt"
    instructor_priv_pem = repo / "instructor_private.pem"
    student_pub_pem = repo / "student_public.pem"

    if not commit_proof.exists():
        raise FileNotFoundError("❌ commit_proof.txt not found. Please run generate_commit_proof.py first.")
    if not instructor_priv_pem.exists():
        raise FileNotFoundError("❌ instructor_private.pem not found.")
    if not student_pub_pem.exists():
        raise FileNotFoundError("❌ student_public.pem not found.")

    # 1️⃣ Read commit proof
    lines = commit_proof.read_text(encoding="utf-8").strip().splitlines()
    commit_hash = lines[0].split(":", 1)[1].strip()
    proof_b64 = lines[1].split(":", 1)[1].strip()
    encrypted_sig = base64.b64decode(proof_b64)

    print(f"[i] Commit hash: {commit_hash}")
    print(f"[i] Encrypted signature length: {len(encrypted_sig)} bytes")

    # 2️⃣ Load keys
    instructor_priv = load_private_key(instructor_priv_pem)
    student_pub = load_public_key(student_pub_pem)

    # 3️⃣ Decrypt encrypted signature (RSA-OAEP SHA-256)
    signature = decrypt_with_private_key(encrypted_sig, instructor_priv)
    print(f"[i] Decrypted signature length: {len(signature)} bytes")

    # 4️⃣ Verify signature using student’s public key (RSA-PSS SHA-256)
    is_valid = verify_signature(commit_hash, signature, student_pub)

    print("\n=== VERIFICATION RESULT ===")
    if is_valid:
        print("✅ SUCCESS: Commit proof is VALID! The commit hash and signature match.")
    else:
        print("❌ INVALID: The signature does NOT match this commit hash.")


if __name__ == "__main__":
    main()
