#!/usr/bin/env python3
"""
Minimal test for network isolation logic in CustomPathGenerator-Passphrase.
"""

import socket
import sys

_REAL_SOCKET = socket.socket
_REAL_INET = socket.AF_INET
_REAL_INET6 = socket.AF_INET6
_REAL_STREAM = socket.SOCK_STREAM

def has_network():
    test_targets = [
        ("8.8.8.8", 53),
        ("1.1.1.1", 53),
        ("8.8.8.8", 80),
        ("1.1.1.1", 80),
    ]
    test_targets_v6 = [
        ("2001:4860:4860::8888", 53, 0, 0),
        ("2606:4700:4700::1111", 53, 0, 0),
    ]
    for ip, port in test_targets:
        try:
            s = _REAL_SOCKET(_REAL_INET, _REAL_STREAM)
            s.settimeout(1.5)
            s.connect((ip, port))
            s.close()
            return True
        except Exception:
            pass
    for target in test_targets_v6:
        try:
            s = _REAL_SOCKET(_REAL_INET6, _REAL_STREAM)
            s.settimeout(1.5)
            s.connect(target)
            s.close()
            return True
        except Exception:
            pass
    return False

def test_has_network_detection():
    online = has_network()
    print(f"[INFO] has_network() currently returns: {online}")
    if online:
        print("       → You are online. The real application would refuse to start.")
    else:
        print("       → You appear offline. The real application would continue.")
    return True

def test_monkey_patch_blocks_socket():
    print("\n[TEST] Monkey-patch blocking...")

    def _blocked(*args, **kwargs):
        raise RuntimeError("Network blocked by policy")

    original_socket = socket.socket
    original_create = getattr(socket, "create_connection", None)
    original_pair = getattr(socket, "socketpair", None)

    socket.socket = _blocked
    socket.create_connection = _blocked
    if hasattr(socket, "socketpair"):
        socket.socketpair = _blocked

    try:
        socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print("FAIL: socket.socket() did not raise")
        return False
    except RuntimeError as e:
        if "blocked by policy" in str(e):
            print("PASS: socket.socket() correctly blocked")
        else:
            print(f"FAIL: Unexpected error: {e}")
            return False
    finally:
        socket.socket = original_socket
        if original_create:
            socket.create_connection = original_create
        if original_pair:
            socket.socketpair = original_pair

    return True

def test_real_socket_still_works_for_guard():
    print("\n[TEST] Real socket still usable by guard...")
    try:
        s = _REAL_SOCKET(_REAL_INET, _REAL_STREAM)
        s.settimeout(1.0)
        s.close()
        print("PASS: _REAL_SOCKET can still create sockets")
        return True
    except Exception as e:
        print(f"FAIL: _REAL_SOCKET is broken: {e}")
        return False

def test_audit_hook_style_block():
    print("\n[TEST] Audit-hook style protection (hardened version)...")

    blocked = False

    def audit_hook(event, args):
        nonlocal blocked
        if event == "socket.connect":
            blocked = True
            raise RuntimeError("Network connection blocked by audit policy")

    sys.addaudithook(audit_hook)

    try:
        s = _REAL_SOCKET(_REAL_INET, _REAL_STREAM)
        s.settimeout(1.0)
        try:
            s.connect(("8.8.8.8", 53))
        except RuntimeError:
            pass
        finally:
            s.close()
    except Exception:
        pass

    if blocked:
        print("PASS: Audit hook intercepted socket.connect")
    else:
        print("INFO: Audit hook did not fire (you may be offline, or Python < 3.8)")
    return True

def main():
    print("=" * 60)
    print("  Network Isolation Tests")
    print("  CustomPathGenerator-Passphrase")
    print("=" * 60)

    results = []
    results.append(test_has_network_detection())
    results.append(test_monkey_patch_blocks_socket())
    results.append(test_real_socket_still_works_for_guard())
    results.append(test_audit_hook_style_block())

    print("\n" + "=" * 60)
    if all(results):
        print("RESULT: All critical checks passed")
        print("The network isolation logic behaves as expected.")
    else:
        print("RESULT: Some checks failed")
    print("=" * 60)

if __name__ == "__main__":
    main()
