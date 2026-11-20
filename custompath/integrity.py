# ============================================================
# FILE: custompath/integrity.py
# Offline File Integrity Monitor for CustomPathGenerator-Passphrase
# Pure standard library • Air-gapped safe • No network • No .env loading
# ============================================================

import hashlib
import os
import sys
from pathlib import Path
from typing import Dict, List, Tuple

# Critical files that must not change without detection
CRITICAL_FILES = [
    "main.py",
    "custompath/__init__.py",
    "custompath/config.py",
    "custompath/crypto.py",
    "custompath/generator.py",
    "custompath/pools.py",
    "custompath/security.py",
    # "custompath/integrity.py",          # temporarily disabled self-hash
]
# Optional: additional files I may want to protect later
OPTIONAL_FILES = [
    # "custompath/some_other.py",
]

# Never touch or import any .env* files
FORBIDDEN_PATTERNS = (".env", ".env.example", ".env.local", ".env.production")


def _project_root() -> Path:
    """Return the repository root (parent of custompath/)."""
    return Path(__file__).resolve().parent.parent


def _sha3_256_file(path: Path) -> str:
    """Streaming SHA3-256 of a file."""
    h = hashlib.sha3_256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _is_forbidden(path: Path) -> bool:
    name = path.name.lower()
    return any(name.startswith(p) or name == p for p in FORBIDDEN_PATTERNS)


def collect_hashes(root: Path = None) -> Dict[str, str]:
    """
    Compute current SHA3-256 hashes of all critical files.
    Returns dict: relative_path -> hexdigest
    """
    if root is None:
        root = _project_root()

    hashes = {}
    for rel in CRITICAL_FILES + OPTIONAL_FILES:
        full = root / rel
        if not full.is_file():
            hashes[rel] = "MISSING"
            continue
        if _is_forbidden(full):
            hashes[rel] = "FORBIDDEN"
            continue
        hashes[rel] = _sha3_256_file(full)
    return hashes


def verify_integrity(
    expected: Dict[str, str] = None,
    root: Path = None,
    strict: bool = True,
) -> Tuple[bool, List[str]]:
    """
    Compare current hashes against expected baseline.
    Returns (ok: bool, messages: list[str])
    """
    if root is None:
        root = _project_root()

    current = collect_hashes(root)
    messages = []

    if expected is None or len(expected) == 0:
        # No baseline → only check existence + forbidden patterns
        for rel, digest in current.items():
            if digest == "MISSING":
                messages.append(f"[FAIL] Missing critical file: {rel}")
            elif digest == "FORBIDDEN":
                messages.append(f"[FAIL] Forbidden file pattern detected: {rel}")
        ok = len(messages) == 0
        return ok, messages

    # Full comparison against provided baseline
    for rel, expected_digest in expected.items():
        current_digest = current.get(rel, "MISSING")
        if current_digest == "MISSING":
            messages.append(f"[FAIL] Missing: {rel}")
        elif current_digest == "FORBIDDEN":
            messages.append(f"[FAIL] Forbidden file touched: {rel}")
        elif current_digest != expected_digest:
            messages.append(f"[FAIL] Modified: {rel}")
            messages.append(f"       expected {expected_digest[:16]}…")
            messages.append(f"       got      {current_digest[:16]}…")

    # Detect unexpected extra critical files
    for rel in current:
        if rel not in expected and current[rel] not in ("MISSING", "FORBIDDEN"):
            messages.append(f"[WARN] Unexpected file in critical set: {rel}")

    ok = not any(m.startswith("[FAIL]") for m in messages)
    return ok, messages


def print_baseline(root: Path = None) -> None:
    """Helper to generate a fresh baseline (run once on a trusted machine)."""
    hashes = collect_hashes(root)
    print("# === INTEGRITY BASELINE (copy into EXPECTED_HASHES) ===")
    print("EXPECTED_HASHES = {")
    for rel, digest in sorted(hashes.items()):
        print(f'    "{rel}": "{digest}",')
    print("}")
    print("# =====================================================")



EXPECTED_HASHES = {
    "custompath/__init__.py": "4e55f47f527dc052dd55d5262b7c5656c6334cb98a302de648d69ed9657fa024",
    "custompath/config.py": "b53e35566926bacbd26ba235e642fefda8f5dcbf99be9d4cad3b63b68615419d",
    "custompath/crypto.py": "59889f2c32286b1a9076a3e05a45161ad4eeea7f4da32839089c488711d0211a",
    "custompath/generator.py": "198d1e092162025ca85382ada63d783c26125f8198af4e6478b82ee386d4ce3f",
    "custompath/pools.py": "8e81938bb7c3ae6ed1a9e3b82bf8345e824d16a67055fb2da9d4c760663f25cc",
    "custompath/security.py": "53756e4b1ffac9e54445614efcb5b13a65ea711b3a15abf4c9414937f9ab22ee",
    "main.py": "8c563083f3a96a660a26c4eab1dbe4e6a47c701a17b37ec11387710b3787e1c9",
}


def security_integrity_check(abort_on_fail: bool = True) -> bool:
    """
    Convenience entry point for main.py.
    Returns True if integrity is OK.
    """
    ok, messages = verify_integrity(EXPECTED_HASHES if EXPECTED_HASHES else None)

    if not ok:
        print("\n" + "=" * 60)
        print("[!] FILE INTEGRITY FAILURE")
        print("=" * 60)
        for m in messages:
            print(m)
        print("=" * 60)
        print("Critical source files have been modified or are missing.")
        print("Aborting for safety. Restore from a known-good copy.")
        print("=" * 60)
        if abort_on_fail:
            sys.exit(1)
        return False

    # Optional quiet success – uncomment if you want a message every run
    # print("[OK] Integrity check passed.")
    return True


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Offline integrity monitor")
    parser.add_argument("--baseline", action="store_true", help="Print current baseline")
    parser.add_argument("--check", action="store_true", help="Run integrity check")
    args = parser.parse_args()

    if args.baseline:
        print_baseline()
    else:
        ok, msgs = verify_integrity(EXPECTED_HASHES if EXPECTED_HASHES else None)
        for m in msgs:
            print(m)
        print("Result:", "PASS" if ok else "FAIL")
        sys.exit(0 if ok else 1)