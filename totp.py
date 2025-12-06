import base64
import pyotp
import os
from pathlib import Path

def hex_to_base32(hex_seed: str) -> str:
    """Convert a 64-character hex seed to Base32 for TOTP."""
    try:
        seed_bytes = bytes.fromhex(hex_seed.strip())
        return base64.b32encode(seed_bytes).decode("utf-8")
    except ValueError as e:
        raise ValueError("Invalid hex seed. Expected 64 hex chars.") from e

def generate_totp_code(hex_seed: str) -> str:
    """Generate a 6-digit TOTP (30s window, SHA-1 default)."""
    base32_seed = hex_to_base32(hex_seed)
    return pyotp.TOTP(base32_seed, digits=6, interval=30).now()

def verify_totp_code(hex_seed: str, code: str, valid_window: int = 1) -> bool:
    """Verify a TOTP with optional ±window (in 30s steps)."""
    base32_seed = hex_to_base32(hex_seed)
    return pyotp.TOTP(base32_seed, digits=6, interval=30).verify(code, valid_window=valid_window)

def detect_paths():
    """
    Prefer container paths if present; fall back to local paths.
    Allow overrides via env vars: SEED_FILE, CRON_DIR.
    """
    # Seed file
    seed_env = os.getenv("SEED_FILE")
    if seed_env:
        seed_path = Path(seed_env)
    elif Path("/data/seed.txt").is_file():   # container
        seed_path = Path("/data/seed.txt")
    else:                                    # local dev
        seed_path = Path("data/seed.txt")

    # Output dir
    cron_env = os.getenv("CRON_DIR")
    if cron_env:
        out_dir = Path(cron_env)
    elif Path("/cron").is_dir():             # container
        out_dir = Path("/cron")
    else:                                    # local dev
        out_dir = Path("cron")

    out_file = out_dir / "last_code.txt"
    return seed_path, out_dir, out_file

if __name__ == "__main__":
    seed_file_path, output_dir, output_file_path = detect_paths()

    if not seed_file_path.exists():
        raise FileNotFoundError(f"Seed file not found: {seed_file_path}")

    hex_seed = seed_file_path.read_text(encoding="utf-8").strip()
    if not hex_seed:
        raise ValueError(f"Seed file is empty: {seed_file_path}")

    # Generate & print
    current_code = generate_totp_code(hex_seed)
    print(f"✅ Current TOTP code: {current_code}")

    # Verify (sanity)
    ok = verify_totp_code(hex_seed, current_code)
    print(f"🔐 Verification result: {'Valid ✅' if ok else 'Invalid ❌'}")

    # Save to cron dir
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file_path.write_text(current_code, encoding="utf-8")
    print(f"📁 Code saved at: {output_file_path}")
