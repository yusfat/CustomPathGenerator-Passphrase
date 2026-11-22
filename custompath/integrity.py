# ============================================================
# FILE: custompath/integrity.py
# Offline File Integrity Monitor for CustomPathGenerator-Passphrase
# Pure standard library • Air-gapped safe • No network • No .env loading
# Branch: security/integrity-layers-clear-signing-fingerprint
# Additive: independent hashes + critical chain root + external baseline.json
# ============================================================

import hashlib
import json
import os
import re
import sys
import secrets
import string
import random
from pathlib import Path
from typing import Dict, List, Tuple, Optional

_RNG = random.SystemRandom()

# Critical files that must not change without detection
# NOTE: Secret noise pool files (.enc / .age / .hmac) are INTENTIONALLY NOT here.
# They are user data, not source code. crypto.py loads them AFTER this check passes.
# If you add them here, integrity will fail every time you re-encrypt.
CRITICAL_FILES = [
    "main.py",
    "custompath/__init__.py",
    "custompath/config.py",
    "custompath/crypto.py",
    "custompath/generator.py",
    "custompath/pools.py",
    "custompath/security.py",
    "custompath/integrity.py",
]

OPTIONAL_FILES = [
    # "custompath/some_other.py",
]

# Only these three are chained (fixed order). integrity.py is intentionally excluded.
CRITICAL_CHAIN = [
    "custompath/crypto.py",
    "custompath/generator.py",
    "custompath/security.py",
]

FORBIDDEN_PATTERNS = (".env", ".env.example", ".env.local", ".env.production")

BENIGN_PTH = frozenset({
    "distutils-precedence.pth",
    "setuptools.pth",
    "_virtualenv.pth",
    "setuptools-precedence.pth",
})

def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent

def _baseline_json_path(root: Path = None) -> Path:
    if root is None:
        root = _project_root()
    return root / "baseline.json"

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
    """
    Canonical form of integrity.py = CODE ONLY.
    Skips the entire EXPECTED_HASHES dict + EXPECTED_CRITICAL_ROOT line.
    Formatting / hash values inside the baseline must NEVER affect the hash.
    """
    text = path.read_text(encoding="utf-8", errors="ignore")
    out = []
    in_baseline = False
    for ln in text.splitlines():
        stripped = ln.strip()
        if stripped.startswith("EXPECTED_HASHES"):
            in_baseline = True
            continue
        if in_baseline:
            if stripped.startswith("}"):
                in_baseline = False
            continue
        if stripped.startswith("EXPECTED_CRITICAL_ROOT"):
            continue
        # Do NOT strip comments / blank lines here - that loosens security.
        # Just normalize line endings and trailing spaces.
        out.append(ln.rstrip())
    return ("\n".join(out) + "\n").encode("utf-8")

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

def _critical_root(hashes: Dict[str, str]) -> str:
    """
    Fixed-order chain of the three most sensitive files.
    Uses the already-computed raw hashes (no extra canonicalization).
    """
    h = hashlib.sha3_256()
    for rel in CRITICAL_CHAIN:
        digest = hashes.get(rel, "MISSING")
        if digest in ("MISSING", "FORBIDDEN"):
            # Force failure if any chained file is missing
            h.update(b"MISSING_OR_FORBIDDEN")
        else:
            h.update(digest.encode("utf-8"))
        h.update(b"\x00")  # domain separator
    return h.hexdigest()

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

# ============================================================
# EXTERNAL BASELINE - OUT-OF-BAND ROOT OF TRUST
# baseline.json lives OUTSIDE the checked files.
# Keep a copy on your phone / USB / paper. If attacker edits
# EXPECTED_HASHES inside integrity.py, baseline.json still fails.
# ============================================================

def build_baseline(root: Path = None) -> Dict:
    if root is None:
        root = _project_root()
    hashes = collect_hashes(root)
    return {
        "hashes": {k: hashes[k] for k in sorted(hashes)},
        "critical_root": _critical_root(hashes),
        "fingerprint": _combined_fingerprint(hashes),
    }

def save_baseline_json(root: Path = None) -> Path:
    if root is None:
        root = _project_root()
    data = build_baseline(root)
    p = _baseline_json_path(root)
    p.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return p

def load_baseline_json(root: Path = None) -> Optional[Dict]:
    p = _baseline_json_path(root)
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None

def verify_external_baseline(root: Path = None) -> Tuple[bool, List[str]]:
    """Compare current files against baseline.json if it exists. No-op if missing."""
    if root is None:
        root = _project_root()
    data = load_baseline_json(root)
    if data is None:
        return True, ["[INFO] No baseline.json found - skipping external check"]
    current = collect_hashes(root)
    current_root = _critical_root(current)
    messages = []
    expected_hashes = data.get("hashes", {})
    for rel, exp in expected_hashes.items():
        cur = current.get(rel, "MISSING")
        if cur != exp:
            messages.append(f"[FAIL] External baseline mismatch: {rel}")
            messages.append(f"       expected {str(exp)[:16]}…")
            messages.append(f"       got      {str(cur)[:16]}…")
    if data.get("critical_root") != current_root:
        messages.append("[FAIL] External baseline CRITICAL_ROOT mismatch")
        messages.append(f"       expected {str(data.get('critical_root'))[:16]}…")
        messages.append(f"       got      {current_root[:16]}…")
    ok = not any(m.startswith("[FAIL]") for m in messages)
    if ok:
        messages.append("[OK] External baseline.json matches")
    return ok, messages

def print_baseline(root: Path = None) -> None:
    hashes = collect_hashes(root)
    print("# === INTEGRITY BASELINE (copy into EXPECTED_HASHES) ===")
    print("EXPECTED_HASHES = {")
    for rel, digest in sorted(hashes.items()):
        print(f'    "{rel}": "{digest}",')
    print("}")
    print()
    print("# === CRITICAL CHAIN ROOT (copy into EXPECTED_CRITICAL_ROOT) ===")
    print(f'EXPECTED_CRITICAL_ROOT = "{_critical_root(hashes)}"')
    print("# =====================================================")

def _combined_fingerprint(hashes: Dict[str, str]) -> str:
    combined = "".join(
        hashes[k] for k in sorted(hashes)
        if hashes[k] not in ("MISSING", "FORBIDDEN")
    )
    full = hashlib.sha3_256(combined.encode("utf-8")).hexdigest()
    return f"{full[:4]}-{full[4:8]}-{full[8:12]}-{full[12:16]}"

def _check_dangerous_startup_files() -> List[str]:
    dangers = []
    for entry in sys.path:
        p = Path(entry)
        if not p.is_dir():
            continue
        for name in ("sitecustomize.py", "usercustomize.py"):
            candidate = p / name
            if candidate.is_file():
                dangers.append(str(candidate))
        for pth in p.glob("*.pth"):
            if pth.name not in BENIGN_PTH:
                dangers.append(str(pth))
    return dangers

def clear_signing_and_second_device(hashes: Dict[str, str]) -> bool:
    # Ask first - emoji is optional, default No
    use_emoji = input("Include one emoji in challenge? (y/N): ").strip().lower() == "y"

    if use_emoji:
        n_emoji = secrets.choice([0, 1, 1, 2])
    else:
        n_emoji = 0
    n_space = secrets.choice([0, 0, 1])
    while 5 - 1 - n_emoji - n_space < 2:
        if n_space:
            n_space = 0
        else:
            n_emoji -= 1
    n_base = 5 - 1 - n_emoji - n_space

    special = secrets.choice(list("-_!@#$%&*+=?"))
    base = [secrets.choice(string.ascii_lowercase + string.digits) for _ in range(n_base)]

    while True:
        chars = base.copy()
        n_upper = secrets.choice([1, 2])
        if n_upper > n_base:
            n_upper = n_base
        positions = _RNG.sample(range(n_base), n_upper)
        for pos in positions:
            if chars[pos].islower():
                chars[pos] = chars[pos].upper()
        n_real = sum(1 for c in chars if c.isupper())
        if 1 <= n_real <= 2:
            break

    pos = secrets.randbelow(len(chars) + 1)
    chars.insert(pos, special)
    challenge = "".join(chars)

    if n_emoji:
        EMOJIS = [
            "😀", "😃", "😄", "😁", "😆", "😅", "😂", "🤣", "😊", "😇",
            "🙂", "🙃", "😉", "😌", "😍", "🥰", "😘", "😗", "😙", "😚",
            "😋", "😛", "😝", "😜", "🤪", "🤨", "🧐", "🤓", "😎", "🥸",
            "🤩", "🥳", "😏", "😒", "😞", "😔", "😟", "😕", "🙁", "☹️",
            "😣", "😖", "😫", "😩", "🥺", "😢", "😭", "😤", "😠", "😡",
            "🤬", "🤯", "😳", "🥵", "🥶", "😱", "😨", "😰", "😥", "😓",
            "🤗", "🤔", "🤭", "🤫", "🤥", "😶", "😐", "😑", "😬", "🙄",
            "😯", "😦", "😧", "😮", "😲", "🥱", "😴", "🤤", "😪", "😵",
            "🤐", "🥴", "🤢", "🤮", "🤧", "😷", "🤒", "🤕", "🫡", "🫢",
            "🫣", "👍", "👎", "👏", "🙌", "🙏", "💪", "🔥", "⭐", "❤️",
        ]
        for emoji in _RNG.sample(EMOJIS, n_emoji):
            pos = secrets.randbelow(len(challenge) + 1)
            challenge = challenge[:pos] + emoji + challenge[pos:]

    if n_space:
        pos = secrets.randbelow(len(challenge) - 1) + 1
        challenge = challenge[:pos] + " " + challenge[pos:]

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
    print("Tip: for convenience, you can copy and paste the challenge word above.")

    for attempt in (1, 2):
        answer = input("> ").strip()
        if answer == challenge:
            break
        if attempt == 1:
            print()
            print("[CLEAR SIGNING] That did not match. Please try again.")
            print("You have 1 attempt remaining.")
            print("This check is for your own protection — it confirms")
            print("you are present and can see what is about to run.")
            print(f'Type the challenge word "{challenge}" (exactly) to continue:')
            print("Tip: for convenience, you can copy and paste the challenge word above.")
            continue
        print()
        print("[CLEAR SIGNING] Challenge failed after 2 attempts — aborted.")
        print("This is for your own security protection: the program")
        print("will not continue without a correct confirmation,")
        print("so that no one else can run it on your behalf.")
        print("Please run the program again when you are ready.")
        return False

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

# ============================================================
# INTEGRITY BASELINE
# After pasting this file you MUST update the integrity.py hash
# and the EXPECTED_CRITICAL_ROOT.
# Run:  python -m custompath.integrity --baseline
# ============================================================
EXPECTED_HASHES = {
    "custompath/__init__.py": "4e55f47f527dc052dd55d5262b7c5656c6334cb98a692de648d69ed9657fa024",
    "custompath/config.py": "b53e35566926bacbd26ba235e642fefda8f5dcbf99be9d4cad3b63b68615419d",
    "custompath/crypto.py": "8d971190f4aaae9950f30311bff7454485b8348464a3bfcc2fcf891a66dca571",
    "custompath/generator.py": "198d1e092162025ca85382ada63d783c26125f8198af4e6478b82ee386d4ce3f",
    "custompath/integrity.py": "0aede505aee8fe6236d78c64e16727ea661fd34d04bf8f5f7a5c177d6f4aed54",
    "custompath/pools.py": "8e81938bb7c3ae6ed1a9e3b82bf8345e824d16a67055fb2da9d4c760663f25cc",
    "custompath/security.py": "53756e4b1ffac9e54445614efcb5b13a65ea711b3a15abf4c9414937f9ab22ee",
    "main.py": "3e77476c4fe3967602974a0a2556ce349133c51da13a537112c72b04b2980630",
}

# Will be filled by --baseline. Placeholder until re-baseline.
EXPECTED_CRITICAL_ROOT = "82ea1cd7dbcb8863f9a4233df3d877261578c02890babd3e13e98fa4a7eae978"

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

    # 2. Normal individual hash verification (existing behaviour)
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

    # 3. Critical chain root - in-file
    current_hashes = collect_hashes()
    current_root = _critical_root(current_hashes)
    if current_root != EXPECTED_CRITICAL_ROOT:
        print("\n" + "=" * 60)
        print("[!] CRITICAL CORE CHAIN FAILURE")
        print("=" * 60)
        print("The chained root of crypto.py + generator.py + security.py")
        print("does not match the expected value.")
        print(f"  expected: {EXPECTED_CRITICAL_ROOT[:16]}…")
        print(f"  got:      {current_root[:16]}…")
        print("This indicates tampering of the most sensitive core files.")
        print("Aborting for safety.")
        print("=" * 60)
        if abort_on_fail:
            sys.exit(1)
        return False

    # 3b. External baseline.json - out-of-band, if it exists
    ext_ok, ext_msgs = verify_external_baseline()
    for m in ext_msgs:
        print(m)
    if not ext_ok:
        print("\n" + "=" * 60)
        print("[!] EXTERNAL BASELINE FAILURE")
        print("=" * 60)
        for m in ext_msgs:
            print(m)
        print("baseline.json does not match current files.")
        print("Either files were tampered, or baseline.json is stale.")
        print("If YOU changed code intentionally, re-export baseline.json")
        print("=" * 60)
        if abort_on_fail:
            sys.exit(1)
        return False

    # 4. Clear-signing + second-device check (existing)
    if not clear_signing_and_second_device(current_hashes):
        if abort_on_fail:
            sys.exit(1)
        return False

    return True

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Offline integrity monitor")
    parser.add_argument("--baseline", action="store_true", help="Print current baseline for pasting into EXPECTED_HASHES")
    parser.add_argument("--export-baseline", action="store_true", help="Write baseline.json (external out-of-band copy)")
    parser.add_argument("--check", action="store_true", help="Run FULL integrity check: individual + chain + external")
    args = parser.parse_args()

    if args.baseline:
        print_baseline()
    elif args.export_baseline:
        p = save_baseline_json()
        print(f"Wrote {p}")
        print("Copy this file to your phone / USB / paper. Do NOT commit it if you don't want it public.")
        print("Fingerprint:", build_baseline()["fingerprint"])
    elif args.check:
        # FULL check - same as security_integrity_check but without clear-signing prompt
        ok, msgs = verify_integrity(EXPECTED_HASHES if EXPECTED_HASHES else None)
        for m in msgs:
            print(m)
        current = collect_hashes()
        cur_root = _critical_root(current)
        if cur_root != EXPECTED_CRITICAL_ROOT:
            print(f"[FAIL] CRITICAL_ROOT mismatch: expected {EXPECTED_CRITICAL_ROOT[:16]}… got {cur_root[:16]}…")
            ok = False
        else:
            print("[OK] CRITICAL_ROOT matches")
        ext_ok, ext_msgs = verify_external_baseline()
        for m in ext_msgs:
            print(m)
        ok = ok and ext_ok
        print("Result:", "PASS" if ok else "FAIL")
        sys.exit(0 if ok else 1)
    else:
        ok, msgs = verify_integrity(EXPECTED_HASHES if EXPECTED_HASHES else None)
        for m in msgs:
            print(m)
        print("Result:", "PASS" if ok else "FAIL")
        sys.exit(0 if ok else 1)