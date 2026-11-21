# ============================================================
# FILE: custompath/integrity.py
# Offline File Integrity Monitor for CustomPathGenerator-Passphrase
# Pure standard library • Air-gapped safe • No network • No .env loading
# Branch: security/integrity-layers-clear-signing-fingerprint
# ============================================================

import hashlib
import os
import re
import sys
import secrets
import string
import random
from pathlib import Path
from typing import Dict, List, Tuple

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

FORBIDDEN_PATTERNS = (".env", ".env.example", ".env.local", ".env.production")

BENIGN_PTH = frozenset({
    "distutils-precedence.pth",
    "setuptools.pth",
    "_virtualenv.pth",
    "setuptools-precedence.pth",
})

# Strict match for the self-hash line in EXPECTED_HASHES.
# Only a line that is exactly:
#   "custompath/integrity.py": "<64 hex chars>",
# with optional leading whitespace, trailing comma, and trailing comment
# is skipped. Any code before or after it does NOT match, so it stays hashed.
_SELF_HASH_LINE = re.compile(
    r'^\s*"custompath/integrity\.py"\s*:\s*"[0-9a-fA-F]{64}"\s*,?\s*(#.*)?$'
)

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
    """
    Canonical form of integrity.py used for self-hash.
    - Removes blank lines
    - Removes comment lines
    - Removes the line that contains the self-hash entry
      (so the hash does not depend on its own value)
    This fixes the egg-and-chicken problem: integrity.py can
    contain its own hash and still verify itself. THIS DECISION AND DESIGN IS INTENTIONALLY TO MAKE IT DIFFICULT FOR ATTACKERS TO MANIPULATE THESE SENSITIVE FILES
    """
    text = path.read_text(encoding="utf-8", errors="ignore")
    lines = []
    for ln in text.splitlines():
        stripped = ln.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            continue
        if _SELF_HASH_LINE.match(ln):
            continue
        lines.append(ln.rstrip())
    return ("\n".join(lines) + "\n").encode("utf-8")

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

    # Challenge is max 5 chars total, counting emoji as 1 and space as 1.
    # Max 2 emojis, max 1 space, always 1 special.
    # The rest is letters/digits. Mix is picked fresh every run.
    if use_emoji:
        n_emoji = secrets.choice([0, 1, 1, 2])
    else:
        n_emoji = 0
    n_space = secrets.choice([0, 0, 1])
    # Keep at least 2 letters/digits, so there is something to uppercase.
    # If emoji + space would leave too little room, drop the space first.
    while 5 - 1 - n_emoji - n_space < 2:
        if n_space:
            n_space = 0
        else:
            n_emoji -= 1
    n_base = 5 - 1 - n_emoji - n_space

    # 1. Pick ONE special character, non-deterministically, per challenge
    # All are on any laptop keyboard, no Shift confusion except ! @ # etc.
    special = secrets.choice(list("-_!@#$%&*+=?"))

    # 2. Base: letters/digits, length depends on emoji/space picked above
    base = [secrets.choice(string.ascii_lowercase + string.digits) for _ in range(n_base)]

    # 3. Non-deterministically make 1 or 2 of them UPPERCASE, at random positions
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

    # 4. Insert the randomly chosen special once, at a random position
    pos = secrets.randbelow(len(chars) + 1)
    chars.insert(pos, special)
    challenge = "".join(chars)

    # 5. Non-deterministically add up to 2 emojis, at random positions, no repetition
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
        # sample = no repetition, picks distinct emojis
        for emoji in _RNG.sample(EMOJIS, n_emoji):
            pos = secrets.randbelow(len(challenge) + 1)
            challenge = challenge[:pos] + emoji + challenge[pos:]

    # 6. At most one space, never at start/end, or strip() would eat it
    if n_space:
        # challenge is a list of chars here, emoji counts as 1 char in Python
        # only if it is one code point - most are, the few with variation
        # selector are still typed as one emoji by the user, so keep it simple:
        # insert in the middle only.
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
    # For convenience, you can copy and paste the challenge word above.
    # No need to retype it by hand.
    print("Tip: for convenience, you can copy and paste the challenge word above.")

    # 2 attempts, then abort. Same challenge for both tries,
    # so a typo does not force you to start over.
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

# ============================================================
# INTEGRITY BASELINE
# After pasting this file you MUST update the integrity.py hash.
# Run:  python -m custompath.integrity --baseline
# then copy the new value for "custompath/integrity.py" below.
# Canonical hash ignores its own line, so it stays stable.
# ============================================================
EXPECTED_HASHES = {
    "custompath/__init__.py": "4e55f47f527dc052dd55d5262b7c5656c6334cb98a692de648d69ed9657fa024",
    "custompath/config.py": "b53e35566926bacbd26ba235e642fefda8f5dcbf99be9d4cad3b63b68615419d",
    "custompath/crypto.py": "74569a9974ed39fec90fd187cc3847ea26c67fa455410239b935f4c6298f9b38",
    "custompath/generator.py": "198d1e092162025ca85382ada63d783c26125f8198af4e6478b82ee386d4ce3f",
    "custompath/integrity.py": "3d49f780123153b544d848e3e21f5bac088ba02c0f7dce23ef1f92862f289fc8",
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
    # This runs BEFORE any secret is loaded. crypto.py is verified here,
    # then main.py is allowed to call load_secret_noise() in crypto.py.
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