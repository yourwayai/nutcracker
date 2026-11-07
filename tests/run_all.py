#!/usr/bin/env python3
"""
Nutcracker Unified Test Runner
Executes:
1. Python Cryptographic Unit Tests
2. HTTP Server API Integration Tests
3. Rust AES-256-GCM / PBKDF2 Unit Tests & Cross-Compatibility
"""

import sys
import unittest
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

def main():
    print("=" * 60)
    print("🔐  Nutcracker Comprehensive Test Suite")
    print("=" * 60)

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Discover tests in tests/
    test_dir = PROJECT_ROOT / "tests"
    discovered = loader.discover(start_dir=str(test_dir), pattern="test_*.py")
    suite.addTests(discovered)

    start_time = time.time()
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    duration = time.time() - start_time

    print("\n" + "=" * 60)
    print(f"Tests run: {result.testsRun}")
    print(f"Errors: {len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Skipped: {len(result.skipped)}")
    print(f"Total time: {duration:.2f}s")
    print("=" * 60)

    if result.wasSuccessful():
        print("🎉 ALL TESTS PASSED SUCCESSFULLY!")
        return 0
    else:
        print("❌ SOME TESTS FAILED.")
        return 1

if __name__ == '__main__':
    sys.exit(main())
