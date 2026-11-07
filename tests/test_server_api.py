#!/usr/bin/env python3
"""
Integration tests for Nutcracker's HTTP server API endpoints.
Spins up an isolated server instance with a temporary vault directory.
"""

import unittest
import os
import sys
import json
import time
import shutil
import tempfile
import urllib.request
import urllib.error
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

class TestServerAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp(prefix="nutcracker_test_")
        cls.vault_dir = Path(cls.temp_dir) / ".nutcracker"
        cls.vault_file = cls.vault_dir / "vault.enc"
        cls.port = 17489

        cls.env = os.environ.copy()
        cls.env["NUTCRACKER_VAULT_DIR"] = str(cls.vault_dir)
        cls.env["NUTCRACKER_VAULT_FILE"] = str(cls.vault_file)
        cls.env["NUTCRACKER_PORT"] = str(cls.port)
        cls.env["PYTHONPATH"] = str(PROJECT_ROOT)
        # Prevent opening browser during tests
        cls.env["NUTCRACKER_NO_BROWSER"] = "1"

        # Start server subprocess
        cmd = [sys.executable, str(PROJECT_ROOT / "src" / "server.py")]
        cls.proc = subprocess.Popen(
            cmd,
            env=cls.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Wait for server to be ready
        base_url = f"http://127.0.0.1:{cls.port}"
        cls.base_url = base_url
        ready = False
        for _ in range(30):
            try:
                req = urllib.request.Request(
                    f"{base_url}/api/vault/exists",
                    data=b"{}",
                    headers={"Content-Type": "application/json"}
                )
                with urllib.request.urlopen(req, timeout=1) as resp:
                    if resp.status == 200:
                        ready = True
                        break
            except Exception:
                time.sleep(0.15)
        
        if not ready:
            cls.proc.terminate()
            raise RuntimeError("Failed to start Nutcracker server for tests")

    @classmethod
    def tearDownClass(cls):
        try:
            cls.proc.terminate()
            cls.proc.wait(timeout=2)
        except Exception:
            cls.proc.kill()
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def _post(self, path, payload):
        req = urllib.request.Request(
            f"{self.base_url}{path}",
            data=json.dumps(payload).encode('utf-8'),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode('utf-8'))

    def test_01_vault_not_exists_initially(self):
        res = self._post("/api/vault/exists", {})
        self.assertTrue(res.get("ok"))
        self.assertFalse(res.get("exists"))

    def test_02_create_vault(self):
        res = self._post("/api/vault/create", {"password": "TestPassword123!"})
        self.assertTrue(res.get("ok"), f"Create failed: {res}")
        self.assertTrue(self.vault_file.exists())

        # Verify exists is now True
        res_exists = self._post("/api/vault/exists", {})
        self.assertTrue(res_exists.get("exists"))

    def test_03_unlock_vault(self):
        # Wrong password
        res_wrong = self._post("/api/vault/unlock", {"password": "WrongPassword"})
        self.assertFalse(res_wrong.get("ok"))
        self.assertIn("Wrong master password", res_wrong.get("error", ""))

        # Correct password
        res_ok = self._post("/api/vault/unlock", {"password": "TestPassword123!"})
        self.assertTrue(res_ok.get("ok"))
        self.assertIn("entries", res_ok.get("data", {}))
        self.assertEqual(res_ok["data"]["entries"], [])

    def test_04_save_and_retrieve_entries(self):
        sample_entries = [
            {
                "id": "item_1",
                "title": "OpenAI Production",
                "key": "sk-proj-prod1234567890",
                "category": "OpenAI",
                "notes": "Production GPT-4o key"
            },
            {
                "id": "item_2",
                "title": "Anthropic Claude Key",
                "key": "sk-ant-api03-testkey",
                "category": "Anthropic",
                "notes": "Testing Claude 3.5 Sonnet"
            }
        ]
        save_res = self._post("/api/vault/save", {
            "password": "TestPassword123!",
            "data": {"entries": sample_entries}
        })
        self.assertTrue(save_res.get("ok"))

        # Unlock and verify saved items
        unlock_res = self._post("/api/vault/unlock", {"password": "TestPassword123!"})
        self.assertTrue(unlock_res.get("ok"))
        entries = unlock_res["data"]["entries"]
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]["title"], "OpenAI Production")
        self.assertEqual(entries[1]["key"], "sk-ant-api03-testkey")

    def test_05_change_password(self):
        change_res = self._post("/api/vault/change_password", {
            "old_password": "TestPassword123!",
            "new_password": "NewSecretPassword888!"
        })
        self.assertTrue(change_res.get("ok"), f"Password change failed: {change_res}")

        # Old password must now fail
        res_old = self._post("/api/vault/unlock", {"password": "TestPassword123!"})
        self.assertFalse(res_old.get("ok"))

        # New password must succeed and contain all previous entries
        res_new = self._post("/api/vault/unlock", {"password": "NewSecretPassword888!"})
        self.assertTrue(res_new.get("ok"))
        self.assertEqual(len(res_new["data"]["entries"]), 2)

    def test_06_export_vault(self):
        export_path = Path(self.temp_dir) / "exported_vault.json"
        export_res = self._post("/api/vault/export", {
            "password": "NewSecretPassword888!",
            "path": str(export_path)
        })
        self.assertTrue(export_res.get("ok"))
        self.assertTrue(export_path.exists())

        with open(export_path, "r", encoding="utf-8") as f:
            exported_data = json.load(f)
        self.assertEqual(len(exported_data.get("entries", [])), 2)


if __name__ == '__main__':
    unittest.main()
