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
import socket
import urllib.request
import urllib.error
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

class TestServerAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp(prefix="nutcracker_test_")
        cls.vault_dir = Path(cls.temp_dir) / ".nutcracker"
        cls.vault_file = cls.vault_dir / "vault.enc"
        cls.port = find_free_port()

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
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return json.loads(resp.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            return json.loads(e.read().decode('utf-8'))

    def test_00_port_and_vault_isolation(self):
        # Verify /api/status reports the isolated temporary vault path and allocated dynamic port
        req = urllib.request.Request(f"{self.base_url}/api/status")
        with urllib.request.urlopen(req, timeout=5) as resp:
            status_data = json.loads(resp.read().decode('utf-8'))

        self.assertEqual(status_data.get("vault_path"), str(self.vault_file))
        self.assertEqual(status_data.get("port"), self.port)

        # Verify that the user's home vault path ~/.nutcracker/vault.enc is not touched
        home_vault = Path.home() / ".nutcracker" / "vault.enc"
        self.assertNotEqual(Path(status_data.get("vault_path")), home_vault)

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

    def test_07_headless_auto_detection(self):
        from unittest.mock import patch, MagicMock
        from src.server import is_headless

        # Test explicit NUTCRACKER_NO_BROWSER
        with patch.dict(os.environ, {"NUTCRACKER_NO_BROWSER": "1"}, clear=False):
            self.assertTrue(is_headless())

        # Test explicit NUTCRACKER_HEADLESS
        with patch.dict(os.environ, {"NUTCRACKER_HEADLESS": "true"}, clear=False):
            self.assertTrue(is_headless())

        # Test CI environment variable
        with patch.dict(os.environ, {"CI": "true", "NUTCRACKER_NO_BROWSER": "", "NUTCRACKER_HEADLESS": ""}, clear=False):
            self.assertTrue(is_headless())

        # Test GITHUB_ACTIONS environment variable
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "NUTCRACKER_NO_BROWSER": "", "NUTCRACKER_HEADLESS": ""}, clear=False):
            self.assertTrue(is_headless())

        # Test non-macOS headless environment without display (DISPLAY and WAYLAND_DISPLAY absent)
        clean_env = {k: v for k, v in os.environ.items() if k not in (
            "NUTCRACKER_NO_BROWSER", "NUTCRACKER_HEADLESS", "CI", "GITHUB_ACTIONS", "GITLAB_CI",
            "TRAVIS", "CIRCLECI", "CONTINUOUS_INTEGRATION", "DISPLAY", "WAYLAND_DISPLAY"
        )}
        with patch.dict(os.environ, clean_env, clear=True):
            with patch("sys.platform", "linux"):
                self.assertTrue(is_headless())

        # Test non-interactive stdin pipe / non-tty
        with patch.dict(os.environ, clean_env, clear=True):
            with patch("sys.platform", "darwin"):
                mock_stdin = MagicMock()
                mock_stdin.isatty.return_value = False
                with patch("sys.stdin", mock_stdin):
                    self.assertTrue(is_headless())

    def test_08_cli_headless_flag_and_log(self):
        # Test starting server with --headless CLI flag and check stdout output
        headless_port = find_free_port()
        temp_dir = tempfile.mkdtemp(prefix="nutcracker_headless_test_")
        try:
            env = os.environ.copy()
            env["NUTCRACKER_PORT"] = str(headless_port)
            env["NUTCRACKER_VAULT_DIR"] = str(Path(temp_dir) / ".nutcracker")
            env["PYTHONUNBUFFERED"] = "1"
            # Clear explicit no-browser env var to ensure --headless CLI flag triggers it
            env.pop("NUTCRACKER_NO_BROWSER", None)
            env.pop("NUTCRACKER_HEADLESS", None)

            proc = subprocess.Popen(
                [sys.executable, "-u", str(PROJECT_ROOT / "src" / "server.py"), "--headless", "--port", str(headless_port)],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            # Wait for server to be ready
            url = f"http://127.0.0.1:{headless_port}/api/status"
            server_ready = False
            for _ in range(30):
                try:
                    with urllib.request.urlopen(url, timeout=0.5) as resp:
                        if resp.status == 200:
                            server_ready = True
                            break
                except Exception:
                    time.sleep(0.1)

            self.assertTrue(server_ready, "Server failed to start in --headless mode")

            # Terminate and inspect output
            proc.terminate()
            stdout, stderr = proc.communicate(timeout=2)

            self.assertIn("Headless environment detected", stdout)
            self.assertIn("without GUI", stdout)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_09_api_standardized_error_codes(self):
        # 1. AUTH_FAILED
        res_wrong_pw = self._post("/api/vault/unlock", {"password": "IncorrectPassword999!"})
        self.assertFalse(res_wrong_pw.get("ok"))
        self.assertEqual(res_wrong_pw.get("code"), "AUTH_FAILED")
        self.assertIn("Wrong master password", res_wrong_pw.get("error", ""))

        res_wrong_change = self._post("/api/vault/change_password", {
            "old_password": "IncorrectPassword999!",
            "new_password": "ValidNewPassword123!"
        })
        self.assertFalse(res_wrong_change.get("ok"))
        self.assertEqual(res_wrong_change.get("code"), "AUTH_FAILED")

        res_wrong_export = self._post("/api/vault/export", {
            "password": "IncorrectPassword999!",
            "path": "/tmp/test_export.json"
        })
        self.assertFalse(res_wrong_export.get("ok"))
        self.assertEqual(res_wrong_export.get("code"), "AUTH_FAILED")

        # 2. INVALID_ARGUMENT
        res_empty_create = self._post("/api/vault/create", {"password": ""})
        self.assertFalse(res_empty_create.get("ok"))
        self.assertEqual(res_empty_create.get("code"), "INVALID_ARGUMENT")

        res_empty_unlock = self._post("/api/vault/unlock", {"password": ""})
        self.assertFalse(res_empty_unlock.get("ok"))
        self.assertEqual(res_empty_unlock.get("code"), "INVALID_ARGUMENT")

        res_missing_change = self._post("/api/vault/change_password", {"old_password": "foo"})
        self.assertFalse(res_missing_change.get("ok"))
        self.assertEqual(res_missing_change.get("code"), "INVALID_ARGUMENT")

        # Invalid JSON payload
        req_bad_json = urllib.request.Request(
            f"{self.base_url}/api/vault/unlock",
            data=b"not valid json {{{",
            headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req_bad_json, timeout=5) as resp:
                bad_json_res = json.loads(resp.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            bad_json_res = json.loads(e.read().decode('utf-8'))
        self.assertFalse(bad_json_res.get("ok"))
        self.assertEqual(bad_json_res.get("code"), "INVALID_ARGUMENT")

        # 3. UNKNOWN_ENDPOINT
        res_unknown = self._post("/api/unknown_endpoint", {})
        self.assertFalse(res_unknown.get("ok"))
        self.assertEqual(res_unknown.get("code"), "UNKNOWN_ENDPOINT")

        # 4. VAULT_NOT_FOUND (via direct server function with isolated temp dir)
        from src.server import unlock_vault, ErrorCode
        nonexistent_vault = Path(tempfile.mkdtemp()) / "missing_dir" / "missing_vault.enc"
        with unittest.mock.patch.dict(os.environ, {"NUTCRACKER_VAULT_FILE": str(nonexistent_vault)}):
            res_not_found = unlock_vault("SomePassword123!")
            self.assertFalse(res_not_found.get("ok"))
            self.assertEqual(res_not_found.get("code"), ErrorCode.VAULT_NOT_FOUND)

        # 5. VAULT_CORRUPTED (via direct server function with truncated file)
        corrupted_file = Path(tempfile.mkdtemp()) / "corrupted.enc"
        corrupted_file.write_bytes(b"short bytes")
        with unittest.mock.patch.dict(os.environ, {"NUTCRACKER_VAULT_FILE": str(corrupted_file)}):
            res_corrupted = unlock_vault("SomePassword123!")
            self.assertFalse(res_corrupted.get("ok"))
            self.assertEqual(res_corrupted.get("code"), ErrorCode.VAULT_CORRUPTED)


if __name__ == '__main__':
    unittest.main()
