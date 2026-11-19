#!/usr/bin/env python3
# ============================================================
# FILE: test_integrity.py
# Offline unit + integration tests for custompath/integrity.py
# Pure standard library • No network • No .env loading • Deterministic
# ============================================================

import hashlib
import os
import sys
import tempfile
import shutil
from pathlib import Path

from custompath import integrity


def _create_temp_project() -> Path:
    """Create a minimal temporary project structure for testing."""
    tmp = Path(tempfile.mkdtemp(prefix="integrity_test_"))
    (tmp / "custompath").mkdir()
    (tmp / "custompath" / "__init__.py").write_text("# init\n", encoding="utf-8")
    (tmp / "main.py").write_text("# main\n", encoding="utf-8")
    (tmp / "custompath" / "config.py").write_text("# config\n", encoding="utf-8")
    (tmp / "custompath" / "crypto.py").write_text("# crypto\n", encoding="utf-8")
    (tmp / "custompath" / "generator.py").write_text("# generator\n", encoding="utf-8")
    (tmp / "custompath" / "pools.py").write_text("# pools\n", encoding="utf-8")
    (tmp / "custompath" / "security.py").write_text("# security\n", encoding="utf-8")
    (tmp / "custompath" / "integrity.py").write_text("# integrity self\n", encoding="utf-8")
    return tmp


def test_self_protection():
    print("[TEST] integrity.py itself is included in critical files...")
    assert "custompath/integrity.py" in integrity.CRITICAL_FILES
    print("  PASS")
    return True


def test_no_env_import_side_effect():
    print("[TEST] Importing integrity does not load any .env* file...")
    source = Path(integrity.__file__).read_text(encoding="utf-8")
    assert "load_dotenv" not in source
    assert "dotenv" not in source.lower()
    print("  PASS – no .env loading code present")
    return True


def test_collect_hashes_basic():
    print("[TEST] collect_hashes on clean temporary project...")
    root = _create_temp_project()
    try:
        hashes = integrity.collect_hashes(root)
        assert isinstance(hashes, dict)
        assert "main.py" in hashes
        assert hashes["main.py"] not in ("MISSING", "FORBIDDEN")
        print("  PASS")
        return True
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_forbidden_env_patterns():
    print("[TEST] Forbidden .env* patterns are rejected...")
    root = _create_temp_project()
    try:
        (root / ".env").write_text("SECRET=1\n", encoding="utf-8")
        (root / ".env.example").write_text("EXAMPLE=1\n", encoding="utf-8")
        (root / "custompath" / ".env.local").write_text("LOCAL=1\n", encoding="utf-8")

        original = integrity.CRITICAL_FILES[:]
        integrity.CRITICAL_FILES.extend([".env", ".env.example", "custompath/.env.local"])

        hashes = integrity.collect_hashes(root)
        integrity.CRITICAL_FILES = original

        assert hashes.get(".env") == "FORBIDDEN"
        assert hashes.get(".env.example") == "FORBIDDEN"
        assert hashes.get("custompath/.env.local") == "FORBIDDEN"
        print("  PASS")
        return True
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_missing_file_detection():
    print("[TEST] Missing critical file is detected...")
    root = _create_temp_project()
    try:
        (root / "main.py").unlink()
        hashes = integrity.collect_hashes(root)
        assert hashes["main.py"] == "MISSING"
        print("  PASS")
        return True
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_modification_detection():
    print("[TEST] File modification is detected...")
    root = _create_temp_project()
    try:
        baseline = integrity.collect_hashes(root)
        (root / "main.py").write_text("# main – modified\n", encoding="utf-8")
        ok, messages = integrity.verify_integrity(expected=baseline, root=root)
        assert ok is False
        assert any("Modified: main.py" in m for m in messages)
        print("  PASS")
        return True
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_clean_baseline_passes():
    print("[TEST] Clean project against its own baseline passes...")
    root = _create_temp_project()
    try:
        baseline = integrity.collect_hashes(root)
        ok, messages = integrity.verify_integrity(expected=baseline, root=root)
        assert ok is True
        assert not any(m.startswith("[FAIL]") for m in messages)
        print("  PASS")
        return True
    finally:
        shutil.rmtree(root, ignore_errors=True)


def main():
    print("=" * 60)
    print(" Integrity Module Tests – MAIN_CLONE")
    print("=" * 60)

    results = [
        test_self_protection(),
        test_no_env_import_side_effect(),
        test_collect_hashes_basic(),
        test_forbidden_env_patterns(),
        test_missing_file_detection(),
        test_modification_detection(),
        test_clean_baseline_passes(),
    ]

    print("\n" + "=" * 60)
    passed = sum(1 for r in results if r)
    total = len(results)
    print(f"Result: {passed}/{total} tests passed")
    if passed != total:
        print("SOME TESTS FAILED")
        sys.exit(1)
    print("ALL TESTS PASSED")
    print("=" * 60)
    sys.exit(0)


if __name__ == "__main__":
    main()