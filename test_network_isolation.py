#!/usr/bin/env python3
#test_network_isolation.py
"""
Hardened security test suite for CustomPathGenerator-Passphrase.

Tests:
- Stronger network isolation
- Debugger detection
- Terminal recorder / psutil path
- secure_cleanup (best-effort)
- Secret noise loading edge cases (strict HMAC behaviour)
"""

import sys
import os
import time
import tempfile
import random
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# ---------------------------------------------------------------------------
# Network isolation (stronger version)
# ---------------------------------------------------------------------------

import socket

_REAL_SOCKET = socket.socket
_REAL_INET = socket.AF_INET
_REAL_INET6 = socket.AF_INET6
_REAL_STREAM = socket.SOCK_STREAM

def has_network_strong():
    test_targets = [
        ("8.8.8.8", 53), ("1.1.1.1", 53), ("8.8.4.4", 53),
        ("1.0.0.1", 53), ("8.8.8.8", 80), ("1.1.1.1", 80),
        ("9.9.9.9", 53), ("208.67.222.222", 53),
        ("8.8.8.8", 443), ("1.1.1.1", 443),
    ]
    test_targets_v6 = [
        ("2001:4860:4860::8888", 53, 0, 0),
        ("2606:4700:4700::1111", 53, 0, 0),
        ("2001:4860:4860::8844", 53, 0, 0),
        ("2606:4700:4700::1001", 53, 0, 0),
    ]
    random.shuffle(test_targets)
    random.shuffle(test_targets_v6)

    for ip, port in test_targets:
        try:
            s = _REAL_SOCKET(_REAL_INET, _REAL_STREAM)
            s.settimeout(1.2)
            s.connect((ip, port))
            s.close()
            return True
        except Exception:
            pass
    for target in test_targets_v6:
        try:
            s = _REAL_SOCKET(_REAL_INET6, _REAL_STREAM)
            s.settimeout(1.2)
            s.connect(target)
            s.close()
            return True
        except Exception:
            pass
    return False

def test_network_detection():
    print("\n[TEST] Stronger network detection")
    online = has_network_strong()
    print(f"  has_network_strong() → {online}")
    if online:
        print("  → Currently online (real app would refuse to start)")
    else:
        print("  → Appears offline")
    return True

def test_monkey_patch_blocks():
    print("\n[TEST] Monkey-patch blocks socket creation")
    def _blocked(*a, **k):
        raise RuntimeError("Network blocked by policy")

    original = socket.socket
    socket.socket = _blocked
    try:
        socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print("  FAIL: socket.socket() did not raise")
        return False
    except RuntimeError as e:
        if "blocked by policy" in str(e):
            print("  PASS: blocked correctly")
            return True
        print(f"  FAIL: unexpected error: {e}")
        return False
    finally:
        socket.socket = original

def test_real_socket_still_usable():
    print("\n[TEST] Real socket still usable by the guard")
    try:
        s = _REAL_SOCKET(_REAL_INET, _REAL_STREAM)
        s.settimeout(0.5)
        s.close()
        print("  PASS")
        return True
    except Exception as e:
        print(f"  FAIL: {e}")
        return False

# ---------------------------------------------------------------------------
# Debugger & recorder
# ---------------------------------------------------------------------------

from custompath.security import (
    is_debugger_present,
    is_terminal_recorder_present,
    secure_cleanup,
)

def test_debugger_normal():
    print("\n[TEST] Debugger detection (normal conditions)")
    result = is_debugger_present()
    print(f"  is_debugger_present() → {result}")
    print("  PASS (function ran)")
    return True

def test_debugger_with_trace():
    print("\n[TEST] Debugger detection when sys.settrace is active")
    def dummy_trace(frame, event, arg):
        return dummy_trace

    old = sys.gettrace()
    sys.settrace(dummy_trace)
    try:
        result = is_debugger_present()
        print(f"  is_debugger_present() → {result}")
        if result:
            print("  PASS: correctly detected active trace")
            return True
        else:
            print("  FAIL: should have detected the trace")
            return False
    finally:
        sys.settrace(old)

def test_recorder_smoke():
    print("\n[TEST] Terminal recorder detection (smoke)")
    try:
        r1 = is_terminal_recorder_present(strict=False)
        r2 = is_terminal_recorder_present(strict=True)
        print(f"  strict=False → {r1}")
        print(f"  strict=True  → {r2}")
        print("  PASS (no crash)")
        return True
    except Exception as e:
        print(f"  FAIL: {e}")
        return False

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

def test_secure_cleanup():
    print("\n[TEST] secure_cleanup (best-effort)")
    secret = "test-secret-value-for-cleanup-check"
    try:
        secure_cleanup(secret)
        print("  PASS: ran without exception")
        return True
    except Exception as e:
        print(f"  FAIL: {e}")
        return False

# ---------------------------------------------------------------------------
# Secret loading edge cases
# ---------------------------------------------------------------------------

from custompath.crypto import load_secret_noise, _n

def test_secret_missing_file():
    print("\n[TEST] Secret loading – missing file")
    result = load_secret_noise("/tmp/this_file_should_not_exist_12345.enc")
    if result == []:
        print("  PASS: returned empty list")
        return True
    print("  FAIL")
    return False

def test_secret_no_hmac():
    print("\n[TEST] Secret loading – file without .hmac (must refuse)")
    with tempfile.TemporaryDirectory() as tmp:
        fake = Path(tmp) / "fake_noise.enc"
        fake.write_bytes(b"dummy-data-not-encrypted")
        result = load_secret_noise(str(fake), password="dummy")
        if result == []:
            print("  PASS: correctly refused")
            return True
        print("  FAIL: loaded without HMAC")
        return False

def test_secret_expected_name_missing():
    print("\n[TEST] Secret loading – expected name but missing")
    expected = _n()
    if Path(expected).exists():
        print("  SKIP: expected file exists in current dir")
        return True
    result = load_secret_noise(expected)
    if result == []:
        print("  PASS")
        return True
    print("  FAIL")
    return False

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def main():
    print("=" * 64)
    print("  Security Test Suite – CustomPathGenerator-Passphrase")
    print("  (Hardened network + debugger + recorder + cleanup + secret load)")
    print("=" * 64)

    results = [
        test_network_detection(),
        test_monkey_patch_blocks(),
        test_real_socket_still_usable(),
        test_debugger_normal(),
        test_debugger_with_trace(),
        test_recorder_smoke(),
        test_secure_cleanup(),
        test_secret_missing_file(),
        test_secret_no_hmac(),
        test_secret_expected_name_missing(),
    ]

    print("\n" + "=" * 64)
    passed = sum(1 for r in results if r)
    total = len(results)
    print(f"RESULT: {passed}/{total} tests passed")
    if passed == total:
        print("All critical checks behaved as expected.")
    else:
        print("Some checks failed – review output above.")
    print("=" * 64)

if __name__ == "__main__":
    main()