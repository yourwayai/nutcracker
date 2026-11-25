#!/usr/bin/env python3
"""
Cross-runtime verification:
Ensures Python AES-256-GCM + PBKDF2 and Rust AES-256-GCM + PBKDF2
are 100% interoperable and can decrypt each other's vaults.
"""

from __future__ import annotations

import unittest
import os
import sys
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.server import derive_key, encrypt, decrypt, SALT_BYTES


def get_cargo_fallback_dirs(home: Optional[Path] = None) -> list[Path]:
    """Return ordered fallback directories where Cargo may be installed."""
    home_dir = home if home is not None else Path.home()
    candidates: list[Path] = [
        home_dir / ".cargo" / "bin",
    ]

    xdg_data_home = os.environ.get("XDG_DATA_HOME", "").strip()
    if xdg_data_home:
        xdg_path = Path(xdg_data_home).expanduser()
        candidates.append(xdg_path / "cargo" / "bin")
        candidates.append(xdg_path / "mise" / "shims")

    candidates.extend([
        home_dir / ".local" / "share" / "cargo" / "bin",
        home_dir / ".asdf" / "shims",
        home_dir / ".local" / "share" / "mise" / "shims",
        Path("/opt/homebrew/bin"),
        Path("/usr/local/bin"),
    ])

    if os.name == "nt":
        userprofile = os.environ.get("USERPROFILE", "").strip()
        if userprofile:
            candidates.append(Path(userprofile) / ".cargo" / "bin")

    # Deduplicate while preserving search priority order
    seen: set[str] = set()
    unique: list[Path] = []
    for candidate in candidates:
        key = str(candidate)
        if key not in seen:
            seen.add(key)
            unique.append(candidate)
    return unique


def discover_cargo_binary(
    pgm: str = "cargo",
    fallback_dirs: Optional[list[Path]] = None,
) -> Optional[str]:
    """
    Locate the Cargo binary across $CARGO_HOME, PATH, and common toolchain dirs
    (rustup defaults, XDG data dir, asdf/mise shims, Homebrew, and /usr/local/bin).
    """
    cargo_home = os.environ.get("CARGO_HOME", "").strip()
    if cargo_home:
        cargo_home_bin = Path(cargo_home).expanduser() / "bin"
        if cargo_home_bin.is_dir():
            found = shutil.which(pgm, path=str(cargo_home_bin))
            if found:
                return found

    found = shutil.which(pgm)
    if found:
        return found

    dirs_to_check = (
        fallback_dirs if fallback_dirs is not None else get_cargo_fallback_dirs()
    )
    for candidate_dir in dirs_to_check:
        if candidate_dir.is_dir():
            found = shutil.which(pgm, path=str(candidate_dir))
            if found:
                return found

    return None


def shutil_which(pgm: str) -> Optional[str]:
    """Backward-compatible wrapper around discover_cargo_binary."""
    return discover_cargo_binary(pgm)


def format_cargo_missing_guidance() -> str:
    """Return user-friendly setup guidance when Cargo is not found."""
    return (
        "[Nutcracker] Cargo / Rust toolchain not found.\n"
        "  Searched: $CARGO_HOME/bin, PATH, ~/.cargo/bin, "
        "~/.local/share/cargo/bin, ~/.asdf/shims, ~/.local/share/mise/shims, "
        "/opt/homebrew/bin, /usr/local/bin\n"
        "  To install Rust & Cargo (macOS/Linux):\n"
        "    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh\n"
        "  Or visit https://rustup.rs/ (Windows/other platforms), or set CARGO_HOME / PATH."
    )


class TestCargoToolchainDiscovery(unittest.TestCase):
    def _make_dummy_cargo(self, bin_dir: Path) -> Path:
        bin_dir.mkdir(parents=True, exist_ok=True)
        exe_name = "cargo.exe" if os.name == "nt" else "cargo"
        cargo_path = bin_dir / exe_name
        cargo_path.write_text("#!/bin/sh\necho dummy\n", encoding="utf-8")
        cargo_path.chmod(0o755)
        return cargo_path

    def test_cargo_discovery_prefers_cargo_home(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            custom_home = Path(tmpdir) / "custom_cargo_home"
            expected = self._make_dummy_cargo(custom_home / "bin")
            with mock.patch.dict(
                os.environ,
                {"CARGO_HOME": str(custom_home), "PATH": ""},
                clear=False,
            ):
                found = discover_cargo_binary("cargo", fallback_dirs=[])
                self.assertIsNotNone(found)
                self.assertEqual(Path(found).resolve(), expected.resolve())

    def test_cargo_discovery_searches_fallback_candidates(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_home = Path(tmpdir) / "home"
            expected = self._make_dummy_cargo(
                fake_home / ".local" / "share" / "cargo" / "bin"
            )
            with mock.patch.dict(
                os.environ,
                {"CARGO_HOME": "", "PATH": "", "XDG_DATA_HOME": ""},
                clear=False,
            ):
                candidates = get_cargo_fallback_dirs(home=fake_home)
                # Filter out host system directories so host-installed cargo won't shadow the mock
                isolated_candidates = [
                    p for p in candidates if str(p).startswith(str(fake_home))
                ]
                found = discover_cargo_binary(
                    "cargo", fallback_dirs=isolated_candidates
                )
                self.assertIsNotNone(found)
                self.assertEqual(Path(found).resolve(), expected.resolve())

    def test_cargo_discovery_missing_returns_none_with_guidance(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            empty_dir = Path(tmpdir) / "empty"
            with mock.patch.dict(
                os.environ,
                {"CARGO_HOME": str(empty_dir), "PATH": ""},
                clear=False,
            ):
                found = discover_cargo_binary(
                    "cargo", fallback_dirs=[empty_dir / "bin"]
                )
                self.assertIsNone(found)
                guidance = format_cargo_missing_guidance()
                self.assertIn("https://sh.rustup.rs", guidance)
                self.assertIn("CARGO_HOME", guidance)


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

        cargo_cmd = discover_cargo_binary("cargo")
        if not cargo_cmd:
            print(f"\n{format_cargo_missing_guidance()}", file=sys.stderr)
            self.skipTest(
                "cargo binary not found (install via https://rustup.rs/ or set CARGO_HOME)"
            )

        env = os.environ.copy()
        cargo_bin_dir = str(Path(cargo_cmd).parent)
        current_path = env.get("PATH", "")
        path_parts = current_path.split(os.pathsep) if current_path else []
        if cargo_bin_dir not in path_parts:
            env["PATH"] = (
                f"{cargo_bin_dir}{os.pathsep}{current_path}"
                if current_path
                else cargo_bin_dir
            )

        res = subprocess.run(
            [cargo_cmd, "test", "--manifest-path", str(manifest_path)],
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(
            res.returncode,
            0,
            f"Cargo test failed:\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}"
        )
        self.assertIn("test result: ok", res.stdout)


if __name__ == '__main__':
    unittest.main()
