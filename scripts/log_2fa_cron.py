#!/usr/bin/env python3
import pathlib, datetime
from totp import generate_totp_code

seed_path = pathlib.Path("/app/data/seed.txt")
now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

if not seed_path.exists():
    print(f"{now} - Seed not decrypted yet")
else:
    seed = seed_path.read_text(encoding="utf-8").strip()
    try:
        code = generate_totp_code(seed)
        print(f"{now} - 2FA Code: {code}")
    except Exception as e:
        print(f"{now} - ERROR: {e}")
