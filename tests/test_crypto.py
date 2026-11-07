#!/usr/bin/env python3
"""
Unit tests for Nutcracker's cryptographic functions (AES-256-GCM + PBKDF2).
"""

import unittest
import os
import sys
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


if __name__ == '__main__':
    unittest.main()
