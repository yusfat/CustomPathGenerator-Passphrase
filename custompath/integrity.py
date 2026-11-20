# ============================================================
# FILE: custompath/integrity.py
# Offline File Integrity Monitor for CustomPathGenerator-Passphrase
# Pure standard library • Air-gapped safe • No network • No .env loading
# ============================================================

import hashlib
import os
import sys
import secrets
import string
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
    "custompath/integrity.py",          # self-hash (canonical)
]

OPTIONAL_FILES = [
    # "custompath/some_other.py",
]

FORBIDDEN_PATTERNS = (".env", ".env.example", ".env.local", ".env.production")


def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _sha3_256_file(path: Path) -> str:
    h = hashlib.sha3_256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _is_forbidden(path: Path) -> bool:
    name = path.name.lower()
    return any(name.startswith(p) or name == p for p in FORBIDDEN_PATTERNS)


def _canonical_integrity_bytes(path: Path) -> bytes:
    """Canonical form of integrity.py (ignores blank lines, comments, and the self-hash line)."""
    text = path.read_text(encoding="utf-8", errors="ignore")
    lines = [
        ln.rstrip()
        for ln in text.splitlines()
        if ln.strip()
        and not ln.lstrip().startswith("#")
        and '"custompath/integrity.py"' not in ln
    ]
    return "\n".join(lines).encode("utf-8") + b"\n"


def _sha3_256_canonical(path: Path) -> str:
    return hashlib.sha3_256(_canonical_integrity_bytes(path)).hexdigest()


def collect_hashes(root: Path = None) -> Dict[str, str]:
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
        if rel == "custompath/integrity.py":
            hashes[rel] = _sha3_256_canonical(full)
        else:
            hashes[rel] = _sha3_256_file(full)
    return hashes


def verify_integrity(
    expected: Dict[str, str] = None,
    root: Path = None,
    strict: bool = True,
) -> Tuple[bool, List[str]]:
    if root is None:
        root = _project_root()

    current = collect_hashes(root)
    messages = []

    if expected is None or len(expected) == 0:
        for rel, digest in current.items():
            if digest == "MISSING":
                messages.append(f"[FAIL] Missing critical file: {rel}")
            elif digest == "FORBIDDEN":
                messages.append(f"[FAIL] Forbidden file pattern detected: {rel}")
        return len(messages) == 0, messages

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

    for rel in current:
        if rel not in expected and current[rel] not in ("MISSING", "FORBIDDEN"):
            messages.append(f"[WARN] Unexpected file in critical set: {rel}")

    ok = not any(m.startswith("[FAIL]") for m in messages)
    return ok, messages


def print_baseline(root: Path = None) -> None:
    hashes = collect_hashes(root)
    print("# === INTEGRITY BASELINE (copy into EXPECTED_HASHES) ===")
    print("EXPECTED_HASHES = {")
    for rel, digest in sorted(hashes.items()):
        print(f'    "{rel}": "{digest}",')
    print("}")
    print("# =====================================================")


def _combined_fingerprint(hashes: Dict[str, str]) -> str:
    combined = "".join(hashes[k] for k in sorted(hashes) if hashes[k] not in ("MISSING", "FORBIDDEN"))
    full = hashlib.sha3_256(combined.encode("utf-8")).hexdigest()
    return f"{full[:4]}-{full[4:8]}-{full[8:12]}-{full[12:16]}"


def _check_dangerous_startup_files() -> List[str]:
    """
    Detect genuinely dangerous startup files that can run before main.
    Ignores common benign packaging .pth files.
    """
    # Known benign .pth files that are part of normal Python packaging
    BENIGN_PTH = {
        "distutils-precedence.pth",
        "setuptools.pth",           # sometimes present
        "_virtualenv.pth",          # virtualenv
    }

    dangers = []
    for entry in sys.path:
        p = Path(entry)
        if not p.is_dir():
            continue

        # These two are always dangerous if present
        for name in ("sitecustomize.py", "usercustomize.py"):
            candidate = p / name
            if candidate.is_file():
                dangers.append(str(candidate))

        # .pth files – only flag unknown / suspicious ones
        for pth in p.glob("*.pth"):
            if pth.name not in BENIGN_PTH:
                dangers.append(str(pth))

    return dangers


def clear_signing_and_second_device(hashes: Dict[str, str]) -> bool:
    # Random challenge instead of static "RUN"
    challenge = "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(6))

    print("\n" + "=" * 60)
    print("[CLEAR SIGNING]")
    print("You are about to run CustomPathGenerator-Passphrase.")
    print("The following critical files have been verified:")
    for rel in sorted(hashes):
        if hashes[rel] not in ("MISSING", "FORBIDDEN"):
            print(f"  • {rel}")
    print()
    print("No network will be used for secret generation.")
    print(f'Type the challenge word "{challenge}" (exactly) to continue:')
    answer = input("> ").strip()
    if answer != challenge:
        print("[CLEAR SIGNING] Incorrect challenge – aborted.")
        return False

    # Second-device fingerprint (shown by default)
    fingerprint = _combined_fingerprint(hashes)
    print("\n" + "-" * 60)
    print("[OPTIONAL SECOND DEVICE CHECK]")
    print(f"Fingerprint:  {fingerprint}")
    print("Compare this value with the same fingerprint on your phone")
    print("or second device (if you saved it previously).")
    print("Press Enter to skip, or type YES if it matches:")
    ans2 = input("> ").strip().upper()
    if ans2 and ans2 != "YES":
        print("[SECOND DEVICE] Unexpected input – aborting.")
        return False
    if ans2 == "YES":
        print("[SECOND DEVICE] Confirmed by user.")
    else:
        print("[SECOND DEVICE] Skipped.")

    print("=" * 60)
    return True


# === INTEGRITY BASELINE ===
# NOTE: After pasting this file you MUST update the integrity.py hash below
EXPECTED_HASHES = {
    "custompath/__init__.py": "4e55f47f527dc052dd55d5262b7c5656c6334cb98a692de648d69ed9657fa024",
    "custompath/config.py": "b53e35566926bacbd26ba235e642fefda8f5dcbf99be9d4cad3b63b68615419d",
    "custompath/crypto.py": "59889f2c32286b1a9076a3e05a45161ad4eeea7f4da32839089c488711d0211a",
    "custompath/generator.py": "b4de2ae379f328f46e88a523fad8e6c2702a485eacc79a5b0d6da8337ea0688b",
    "custompath/integrity.py": "2461c7a3a1b15f58a20c644d1f27a36a0b342947bf10c8334cea905457c622db",  # will change
    "custompath/pools.py": "8e81938bb7c3ae6ed1a9e3b82bf8345e824d16a67055fb2da9d4c760663f25cc",
    "custompath/security.py": "53756e4b1ffac9e54445614efcb5b13a65ea711b3a15abf4c9414937f9ab22ee",
    "main.py": "8c563083f3a96a660a26c4eab1dbe4e6a47c701a17b37ec11387710b3787e1c9",
}


def security_integrity_check(abort_on_fail: bool = True) -> bool:
    # 1. Detect dangerous startup files first
    dangers = _check_dangerous_startup_files()
    if dangers:
        print("\n" + "=" * 60)
        print("[!] DANGEROUS STARTUP FILES DETECTED")
        print("=" * 60)
        for d in dangers:
            print(f"  • {d}")
        print("These files can execute code before integrity checks.")
        print("Remove them or run in a clean environment.")
        print("=" * 60)
        if abort_on_fail:
            sys.exit(1)
        return False

    # 2. Normal hash verification
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

    # 3. Clear-signing + second-device check
    current_hashes = collect_hashes()
    if not clear_signing_and_second_device(current_hashes):
        if abort_on_fail:
            sys.exit(1)
        return False

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