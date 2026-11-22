# ============================================================
# FILE: custompath/crypto.py
# Secret-noise loading – openssl + age support
# Pure standard library preferred • Air-gapped safe
# Hardened subprocess • distinct failure reasons
# OpenSSL: -pbkdf2 only, -iter 2000000 | 4000000 (project high-tier)
# ============================================================

import secrets
import hashlib
import hmac
import string
import getpass
import subprocess
import shutil
import os
from pathlib import Path
from .pools import *

BANNED = {'/', '\\', '"', "'"}
SAFE_PUNCT = ''.join(c for c in string.punctuation if c not in BANNED)
YUSFAT_ASCII_NOISE = list(string.ascii_letters + string.digits + SAFE_PUNCT)

YUSFAT_NOISE_POOL = (
    YUSFAT_ASCII_NOISE
    + EMOJI_POOL
    + EXTRA_UNIQUE_EMOJIS
    + SCRIPTS
    + INVISIBLES
    + SAFE_EMOJIS
    + NON_ASCII_LETTERS
    + SCRIPT_1
    + SCRIPT_2
    + SCRIPT_3
    + SPACES
    + inviSible_70
    + (SCRIPT_4 if 'SCRIPT_4' in globals() else [])
    + EMOJI_POOL_3
)

def smart_flatten(pool):
    result = []
    for item in pool:
        result.extend(list(item))
    return result

FLAT_INVISIBLES = tuple(set(smart_flatten(INVISIBLES + inviSible_70)))
FLAT_SPACES     = tuple(set(smart_flatten(SPACES)))
FLAT_EMOJI      = tuple(set(smart_flatten(EMOJI_POOL + EMOJI_POOL_3 + SAFE_EMOJIS)))
FLAT_EXTRA      = tuple(set(smart_flatten(EXTRA_UNIQUE_EMOJIS)))
FLAT_SCRIPTS    = tuple(set(smart_flatten(
    SCRIPTS + SCRIPT_1 + SCRIPT_2 + SCRIPT_3 +
    (SCRIPT_4 if 'SCRIPT_4' in globals() else [])
)))
FLAT_NON_ASCII  = tuple(set(smart_flatten(NON_ASCII_LETTERS)))
FLAT_YUSFAT     = tuple(set(smart_flatten(YUSFAT_NOISE_POOL)))
FLAT_STANDARD   = tuple(set(YUSFAT_ASCII_NOISE))

SECRET_NOISE_POOL = []
FLAT_SECRET = tuple()

# Project high-tier openssl PBKDF2 iters — exact match to existing tree values.
# _v() uses 2_000_000; make_system_salt() uses 4_000_000.
# Never use OpenSSL default 10000 as this project's baseline.
_OPENSSL_PBKDF2_ITERS = (2_000_000, 4_000_000)


def _t(s: bytes, k: int = 0x5A) -> bytes:
    return bytes(c ^ k for c in s)


def _n() -> str:
    raw = _t(bytes([41, 63, 57, 40, 63, 46, 5, 52, 53, 51, 41, 63, 5, 109, 60, 105, 59, 99, 57]))
    h = hashlib.sha3_256(raw).hexdigest()[:4]
    return raw.decode() + h + ".enc"


def _v(password: str, salt: bytes) -> bytes:
    # Existing work factor — do not reduce
    info = _t(bytes([25, 47, 41, 46, 53, 55, 10, 59, 46, 50, 20, 53, 51, 41, 63, 18, 23, 27, 25, 44, 107]))
    return hashlib.pbkdf2_hmac(
        "sha3_512",
        password.encode("utf-8"),
        salt + info,
        2_000_000,
        dklen=64,
    )


def _find_openssl() -> str | None:
    candidates = [
        "/usr/bin/openssl",
        "/bin/openssl",
        "/usr/local/bin/openssl",
        "/data/data/com.termux/files/usr/bin/openssl",  # Termux
    ]
    for c in candidates:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return shutil.which("openssl")


def _find_age() -> str | None:
    return shutil.which("age") or shutil.which("rage")


def _clean_env() -> dict:
    path_parts = ["/usr/bin", "/bin", "/usr/local/bin"]
    termux_bin = "/data/data/com.termux/files/usr/bin"
    if os.path.isdir(termux_bin):
        path_parts.append(termux_bin)
    env = {
        "PATH": ":".join(path_parts),
        "HOME": os.environ.get("HOME", ""),
        "LANG": "C",
    }
    for bad in (
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "PYTHONPATH",
        "PYTHONHOME",
        "OPENSSL_CONF",
        "AGE_PASSPHRASE",
    ):
        env.pop(bad, None)
    return env


def _looks_like_openssl_salted(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(8) == b"Salted__"
    except Exception:
        return False


def _try_age_decrypt(path: Path, password: str) -> str | None:
    """Optional age support. Returns decrypted text or None."""
    age_bin = _find_age()
    if not age_bin:
        return None
    try:
        env = _clean_env()
        env["AGE_PASSPHRASE"] = password
        result = subprocess.run(
            [age_bin, "--decrypt", str(path)],
            capture_output=True,
            timeout=30,
            env=env,
        )
        env["AGE_PASSPHRASE"] = ""
        if result.returncode == 0:
            return result.stdout.decode("utf-8", errors="strict")
    except Exception:
        pass
    return None


def _try_openssl_decrypt(path: Path, password: str) -> str | None:
    """
    openssl enc decrypt — project policy only:
      -aes-256-cbc -pbkdf2 -iter {2_000_000 | 4_000_000}
    Never MD5. Never legacy non-pbkdf2. Never OpenSSL default 10000.
    """
    openssl_bin = _find_openssl()
    if not openssl_bin:
        return None

    pass_bytes = (password + "\n").encode()
    env = _clean_env()

    for iters in _OPENSSL_PBKDF2_ITERS:
        try:
            result = subprocess.run(
                [
                    openssl_bin, "enc", "-d",
                    "-aes-256-cbc",
                    "-pbkdf2",
                    "-iter", str(iters),
                    "-in", str(path),
                    "-pass", "stdin",
                ],
                input=pass_bytes,
                capture_output=True,
                timeout=300,
                env=env,
            )
            if result.returncode != 0:
                continue
            try:
                text = result.stdout.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                continue
            if text == "":
                continue
            return text
        except Exception:
            continue
    return None


def load_secret_noise(encrypted_path: str | None = None, password: str | None = None) -> list:
    """
    Load secret noise pool (fail-closed, additive).

    Distinct outcomes:
      a) file missing
      b) user skipped (Enter)
      c) wrong password / decrypt failure
      d) bad HMAC / missing HMAC (legacy YES only)

    OpenSSL path: -pbkdf2 only, -iter in {2_000_000, 4_000_000}.
    Prefers openssl when file header is Salted__; else age then openssl.
    """
    global SECRET_NOISE_POOL, FLAT_SECRET
    SECRET_NOISE_POOL = []
    FLAT_SECRET = tuple()

    expected = _n()
    path = Path(encrypted_path or expected)

    if not path.is_file():
        print(f"[!] Secret noise file not found: {path}")
        print("    Continuing without secret noise pool.")
        return []

    if password is None:
        try:
            password = getpass.getpass(
                "Enter password for secret noise file (or press Enter to skip): "
            )
        except Exception:
            print("[!] Could not read password – secret noise skipped.")
            return []
    if not password:
        print("[i] Secret noise skipped by user.")
        return []

    content = None
    openssl_first = _looks_like_openssl_salted(path)

    if openssl_first:
        content = _try_openssl_decrypt(path, password)
        if content is None:
            content = _try_age_decrypt(path, password)
    else:
        content = _try_age_decrypt(path, password)
        if content is None:
            content = _try_openssl_decrypt(path, password)

    if content is None:
        print("[!] Decryption failed (wrong password or KDF mismatch).")
        print("    Project policy accepts openssl enc only with:")
        print("      -aes-256-cbc -pbkdf2 -iter 2000000   (or 4000000)")
        print("    (no MD5, no legacy non-pbkdf2, not OpenSSL default 10000).")
        print("    Re-encrypt on an air-gapped device if needed:")
        print("      openssl enc -aes-256-cbc -salt -pbkdf2 -iter 2000000 \\")
        print("        -in pool.txt -out SECRETNOISEPOOL.txt.age")
        print("    Secret noise not loaded.")
        return []

    # HMAC verification
    hmac_path = path.with_name(path.name + ".hmac")
    if not hmac_path.is_file():
        hmac_path = path.with_suffix(path.suffix + ".hmac")
    if not hmac_path.is_file():
        hmac_path = path.with_suffix(".hmac")

    if hmac_path.is_file():
        try:
            data = hmac_path.read_bytes()
            if len(data) < 16 + 32:
                print("[!] HMAC file too short – refusing.")
                return []
            salt = data[:16]
            expected_mac = data[16:]
            key = _v(password, salt)
            actual_mac = hmac.new(key, content.encode("utf-8"), hashlib.sha3_512).digest()
            if not hmac.compare_digest(actual_mac, expected_mac):
                print("[!] HMAC verification failed – wrong password or tampered file.")
                print("    Secret noise not loaded.")
                return []
        except Exception:
            print("[!] HMAC check error – refusing.")
            return []
    else:
        print("[!] No .hmac file found.")
        print("    Loading WITHOUT integrity verification (legacy mode).")
        print("    This is less secure. Prefer creating a .hmac file.")
        confirm = input("Type YES to continue with unverified noise pool: ").strip()
        if confirm != "YES":
            print("Aborted. Secret noise not loaded.")
            return []

    chars = list(content)
    SECRET_NOISE_POOL = list(dict.fromkeys(chars))
    FLAT_SECRET = tuple(SECRET_NOISE_POOL)
    print(f"[OK] Secret noise pool loaded ({len(SECRET_NOISE_POOL)} unique chars).")
    return SECRET_NOISE_POOL


def create_hmac_file(path_str: str, password: str, content: str) -> Path | None:
    path = Path(path_str)
    hmac_path = path.with_name(path.name + ".hmac")
    if hmac_path.exists():
        print(f"[!] {hmac_path} already exists – not overwriting.")
        return None
    salt = secrets.token_bytes(16)
    key = _v(password, salt)
    mac = hmac.new(key, content.encode("utf-8"), hashlib.sha3_512).digest()
    hmac_path.write_bytes(salt + mac)
    print(f"[OK] Wrote {hmac_path}")
    return hmac_path


def make_system_salt():
    salt = secrets.token_bytes(64)
    # Existing work factor — do not reduce
    stretched = hashlib.pbkdf2_hmac(
        "sha3_512",
        salt,
        secrets.token_bytes(64),
        4_000_000,
    )
    return stretched, stretched.hex()


def make_random_salt(min_len=60, max_len=180, pool=None):
    if pool is None:
        pool = YUSFAT_NOISE_POOL
    if not pool:
        pool = FLAT_STANDARD
    length = secrets.randbelow(max_len - min_len + 1) + min_len
    return "".join(secrets.choice(pool) for _ in range(length))


def make_session_pools():
    def _shuf(seq):
        lst = list(seq)
        secrets.SystemRandom().shuffle(lst)
        return tuple(lst)

    return {
        "invisibles": _shuf(FLAT_INVISIBLES),
        "spaces":     _shuf(FLAT_SPACES),
        "emoji":      _shuf(FLAT_EMOJI),
        "extra":      _shuf(FLAT_EXTRA),
        "scripts":    _shuf(FLAT_SCRIPTS),
        "non_ascii":  _shuf(FLAT_NON_ASCII),
        "yusfat":     _shuf(FLAT_YUSFAT),
        "secret":     _shuf(FLAT_SECRET) if FLAT_SECRET else tuple(),
        "standard":   _shuf(FLAT_STANDARD),
    }


def make_noise(salt_bytes, counter, min_len=1, max_len=4, session_pools=None):
    if session_pools is None:
        session_pools = make_session_pools()

    length = secrets.randbelow(max_len - min_len + 1) + min_len
    parts = []
    candidates = []
    candidates.extend(session_pools["invisibles"])
    candidates.extend(session_pools["spaces"])
    candidates.extend(session_pools["emoji"])
    candidates.extend(session_pools["extra"])
    candidates.extend(session_pools["scripts"])
    candidates.extend(session_pools["non_ascii"])
    if session_pools["secret"]:
        candidates.extend(session_pools["secret"])
    candidates.extend(session_pools["yusfat"])

    if not candidates:
        candidates = list(FLAT_STANDARD)

    for _ in range(length):
        char = secrets.choice(candidates)
        parts.append(char)
        counter += 1

    return "".join(parts), counter


def build_password_pool(
    allow_emoji=True,
    allow_invisible=True,
    allow_space=True,
    standard_only=False,
    session_pools=None,
):
    if session_pools is None:
        session_pools = make_session_pools()

    if standard_only:
        pool = list(session_pools["standard"])
    else:
        pool = list(session_pools["standard"])
        if allow_emoji:
            pool.extend(session_pools["emoji"])
            pool.extend(session_pools["extra"])
            pool.extend(session_pools["scripts"])
            pool.extend(session_pools["non_ascii"])
        if allow_invisible:
            pool.extend(session_pools["invisibles"])
        if allow_space:
            pool.extend(session_pools["spaces"])
        if session_pools["secret"] and allow_emoji and allow_invisible:
            pool.extend(session_pools["secret"])

    seen = set()
    clean = []
    for c in pool:
        if c not in seen:
            seen.add(c)
            clean.append(c)
    return clean if clean else list(FLAT_STANDARD)


def make_password(
    max_len,
    allow_emoji=True,
    allow_invisible=True,
    allow_space=True,
    standard_only=False,
):
    session_pools = make_session_pools()
    pool = build_password_pool(
        allow_emoji, allow_invisible, allow_space, standard_only, session_pools
    )
    min_len = max(16, int(max_len * 0.95))
    return make_random_salt(min_len=min_len, max_len=max_len, pool=pool)