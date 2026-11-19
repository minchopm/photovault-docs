#!/usr/bin/env python3
"""
Zero-dependency structural & header inspector for PhotoVault (.pvsecure / PVSHAR01) archives.
Verifies the 72-byte big-endian authenticated header and exact AES-256-GCM block framing
without requiring your archive password or pattern.
"""
import json
import math
import struct
import sys
from pathlib import Path

MAGIC = b"PVSHAR01"
GCM_OVERHEAD = 28  # 12-byte nonce + 16-byte authentication tag


def inspect_pvsecure(path: Path) -> dict:
    size = path.stat().st_size
    if size < 72 + GCM_OVERHEAD * 2:
        raise ValueError(f"File too small ({size} bytes) to be a valid PVSHAR01 archive.")

    with path.open("rb") as f:
        header = f.read(72)

    magic, salt, rounds, block_size, meta_size, movie_size, auth_method = struct.unpack(">8s32sIIQQQ", header)
    if magic != MAGIC:
        raise ValueError(f"Unexpected magic bytes: {magic!r} (expected {MAGIC!r})")

    blocks = (movie_size + block_size - 1) // block_size if block_size > 0 else 0
    expected_size = 72 + (meta_size + GCM_OVERHEAD) + movie_size + (blocks * GCM_OVERHEAD)

    method_label = {1: "password", 2: "pattern"}.get(auth_method, f"unknown({auth_method})")
    return {
        "file": str(path),
        "magic": magic.decode("ascii"),
        "kdf": "PBKDF2-HMAC-SHA256",
        "pbkdf2_rounds": rounds,
        "salt_hex": salt.hex(),
        "cipher": "AES-256-GCM",
        "credential_method": method_label,
        "block_size_bytes": block_size,
        "plaintext_metadata_bytes": meta_size,
        "plaintext_media_bytes": movie_size,
        "media_gcm_blocks": blocks,
        "actual_file_bytes": size,
        "expected_file_bytes": expected_size,
        "framing_valid": size == expected_size,
    }


def main() -> None:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <archive.pvsecure>", file=sys.stderr)
        sys.exit(2)
    info = inspect_pvsecure(Path(sys.argv[1]))
    print(json.dumps(info, indent=2))
    sys.exit(0 if info["framing_valid"] else 1)


if __name__ == "__main__":
    main()
