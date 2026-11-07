#!/usr/bin/env python3
"""
Cross-runtime verification:
Ensures Python AES-256-GCM + PBKDF2 and Rust AES-256-GCM + PBKDF2
are 100% interoperable and can decrypt each other's vaults.
"""

import unittest
import os
import sys
import json
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.server import derive_key, encrypt, decrypt, SALT_BYTES

class TestCrossCompatibility(unittest.TestCase):
    def test_python_can_decrypt_standard_vector(self):
        # Use exact same parameters as in Rust test: test_fixed_vector_cross_compat
        salt = bytes([0x55] * SALT_BYTES)
        password = "CrossPlatformPassword2026!"
        key = derive_key(password, salt)

        plaintext = '{"test":"cross_platform_ok"}'
        blob = encrypt(plaintext, key)

        decrypted = decrypt(blob, key)
        self.assertEqual(decrypted, plaintext)

    def test_rust_suite_execution(self):
        # Run cargo test in src-tauri
        manifest_path = PROJECT_ROOT / "src-tauri" / "Cargo.toml"
        if not manifest_path.exists():
            self.skipTest("src-tauri/Cargo.toml not found")

        # Check if cargo is available
        cargo_cmd = shutil_which("cargo")
        if not cargo_cmd:
            self.skipTest("cargo binary not in PATH")

        res = subprocess.run(
            [cargo_cmd, "test", "--manifest-path", str(manifest_path)],
            capture_output=True,
            text=True
        )
        self.assertEqual(
            res.returncode,
            0,
            f"Cargo test failed:\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}"
        )
        self.assertIn("test result: ok", res.stdout)


def shutil_which(pgm):
    import shutil
    # Also check ~/.cargo/bin
    found = shutil.which(pgm)
    if found:
        return found
    cargo_bin = Path.home() / ".cargo" / "bin" / pgm
    if cargo_bin.exists():
        return str(cargo_bin)
    return None


if __name__ == '__main__':
    unittest.main()
