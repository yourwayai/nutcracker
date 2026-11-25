#!/usr/bin/env python3
"""
Unit tests for Nutcracker's cryptographic functions (AES-256-GCM + PBKDF2).
"""

import unittest
import json
import os
import random
import sys
import tempfile
import time
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.server import derive_key, encrypt, decrypt, SALT_BYTES, PBKDF2_ITERS


class TestCrypto(unittest.TestCase):
    def test_derive_key_deterministic(self):
        salt = b"A" * SALT_BYTES
        k1 = derive_key("master_password_456", salt)
        k2 = derive_key("master_password_456", salt)
        self.assertEqual(k1, k2)
        self.assertEqual(len(k1), 32)

        # Different salt gives different key
        salt_diff = b"B" * SALT_BYTES
        k_diff = derive_key("master_password_456", salt_diff)
        self.assertNotEqual(k1, k_diff)

    def test_encrypt_decrypt_roundtrip(self):
        salt = b"S" * SALT_BYTES
        key = derive_key("pass_secret_xyz", salt)
        sample = '{"entries": [{"id": "1", "title": "GitHub Token", "key": "ghp_xxxxxxxxxxxx", "category": "GitHub"}]}'

        encrypted = encrypt(sample, key)
        # 12 bytes nonce + ciphertext + 16 bytes auth tag
        self.assertGreater(len(encrypted), 12 + 16)

        decrypted = decrypt(encrypted, key)
        self.assertEqual(decrypted, sample)

    def test_decrypt_wrong_key_fails(self):
        salt = b"S" * SALT_BYTES
        k_right = derive_key("correct_pass", salt)
        k_wrong = derive_key("incorrect_pass", salt)

        blob = encrypt("sensitive payload", k_right)
        with self.assertRaises(Exception):
            decrypt(blob, k_wrong)

    def test_decrypt_tampered_ciphertext_fails(self):
        salt = b"S" * SALT_BYTES
        key = derive_key("my_pass", salt)
        blob = bytearray(encrypt("authenticated message", key))

        # Tamper with the last byte
        blob[-1] ^= 0xAA

        with self.assertRaises(Exception):
            decrypt(bytes(blob), key)

    def test_utf8_chinese_and_symbols(self):
        salt = b"U" * SALT_BYTES
        key = derive_key("主密码_🔑_测试", salt)
        text = "平台名称: 阿里云大模型 API 🚀 | 说明: 生产高危调用凭证"

        blob = encrypt(text, key)
        self.assertEqual(decrypt(blob, key), text)

    def test_decrypt_fuzz_malformed_blobs(self):
        rng = random.Random(20261125)
        salt = b"F" * SALT_BYTES
        key = derive_key("fuzz_master_password", salt)

        # Boundary lengths and random malformed payloads must raise clean exceptions
        for length in list(range(0, 65)) + [128, 256, 512]:
            for _ in range(5):
                blob = bytes(rng.getrandbits(8) for _ in range(length))
                with self.assertRaises(Exception):
                    decrypt(blob, key)

        # Truncate and mutate every offset of a valid encrypted payload
        valid_blob = encrypt('{"entries":[{"id":"1","key":"test-val"}]}', key)
        for cut in range(len(valid_blob)):
            with self.assertRaises(Exception):
                decrypt(valid_blob[:cut], key)
        for pos in range(len(valid_blob)):
            mutated = bytearray(valid_blob)
            mutated[pos] ^= 0x01
            with self.assertRaises(Exception):
                decrypt(bytes(mutated), key)

    def test_large_vault_5000_entries_stress(self):
        num_entries = 5500
        entries = [
            {
                "id": f"stress_{i:04d}",
                "title": f"Synthetic Key #{i:04d}",
                "key": f"test-sk-synthetic-{i:04d}-0123456789abcdef",
                "category": "OpenAI" if i % 2 == 0 else "Anthropic",
                "notes": f"Stress entry {i}",
            }
            for i in range(num_entries)
        ]
        payload_str = json.dumps({"entries": entries})

        salt1 = b"1" * SALT_BYTES
        key1 = derive_key("StressPasswordOld!2026", salt1)
        start = time.monotonic()
        encrypted1 = encrypt(payload_str, key1)

        # Simulate master password rotation + atomic write to an isolated temp vault
        with tempfile.TemporaryDirectory(prefix="nutcracker_stress_") as tmpdir:
            vault_path = Path(tmpdir) / "vault.enc"
            tmp_path = Path(tmpdir) / "vault.enc.tmp"
            with open(tmp_path, "wb") as f:
                f.write(salt1 + encrypted1)
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, vault_path)

            raw1 = vault_path.read_bytes()
            decrypted1 = decrypt(raw1[SALT_BYTES:], derive_key("StressPasswordOld!2026", raw1[:SALT_BYTES]))

            salt2 = b"2" * SALT_BYTES
            key2 = derive_key("StressPasswordNew!2026", salt2)
            encrypted2 = encrypt(decrypted1, key2)

            tmp_path2 = Path(tmpdir) / "vault.enc.tmp2"
            with open(tmp_path2, "wb") as f:
                f.write(salt2 + encrypted2)
            os.chmod(tmp_path2, 0o600)
            os.replace(tmp_path2, vault_path)
            elapsed = time.monotonic() - start

            # Verify atomic swap left no temp files and preserved 0600 permissions
            remaining = [p.name for p in Path(tmpdir).iterdir()]
            self.assertEqual(remaining, ["vault.enc"])
            self.assertEqual(os.stat(vault_path).st_mode & 0o777, 0o600)

            raw2 = vault_path.read_bytes()
            decrypted2 = decrypt(raw2[SALT_BYTES:], key2)
            parsed = json.loads(decrypted2)
            self.assertEqual(len(parsed["entries"]), num_entries)
            self.assertEqual(parsed["entries"][0]["id"], "stress_0000")
            self.assertEqual(parsed["entries"][-1]["id"], f"stress_{num_entries - 1:04d}")
            self.assertLess(elapsed, 15.0, f"Large vault rotation took too long: {elapsed:.2f}s")


if __name__ == '__main__':
    unittest.main()
